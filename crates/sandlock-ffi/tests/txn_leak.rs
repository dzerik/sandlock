//! Leak check for the transaction handle, in a test binary of its own.
//!
//! `sandlock_txn_run` takes ownership of the handle before the core validates
//! the stage set, so a rearrangement that returned early without taking it
//! would leak the whole stage list, every cloned policy included, on every
//! call. A service that builds and rejects transactions in a loop would then
//! grow without bound, and nothing else in the suite would see it: every other
//! test runs a transaction once.
//!
//! Two shapes were available. `tests/popen.rs` samples the process fd count,
//! which works there because the resource in question is an fd; here it is
//! heap, and a resident-set sample is host dependent and noisy. A counting
//! allocator is exact instead, and it lives in its own binary so the number it
//! reads belongs to this loop and to nothing running beside it.

use std::alloc::{GlobalAlloc, Layout, System};
use std::os::raw::{c_char, c_int};
use std::ptr;
use std::sync::atomic::{AtomicIsize, Ordering};

use sandlock_ffi::{
    sandlock_sandbox_build, sandlock_sandbox_builder_fs_read, sandlock_sandbox_builder_new,
    sandlock_sandbox_builder_workdir, sandlock_sandbox_free, sandlock_sandbox_t,
    sandlock_string_free, sandlock_txn_add_stage, sandlock_txn_new, sandlock_txn_run,
};

/// Bytes currently handed out by the allocator. Signed because a deallocation
/// of something allocated before this counter was installed would otherwise
/// wrap; nothing here does that, but the assertion is about a difference and a
/// wrapped subtrahend would hide a leak rather than report one.
static LIVE: AtomicIsize = AtomicIsize::new(0);

struct Counting;

// `realloc` and `alloc_zeroed` are left at their defaults, which are written in
// terms of `alloc` and `dealloc`, so accounting for those two is enough.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc(layout);
        if !p.is_null() {
            LIVE.fetch_add(layout.size() as isize, Ordering::Relaxed);
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size() as isize, Ordering::Relaxed);
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

const TXN_INVALID: c_int = 1;

fn build_policy() -> *mut sandlock_sandbox_t {
    let mut b = sandlock_sandbox_builder_new();
    for p in ["/usr", "/lib", "/lib64", "/bin", "/etc"] {
        if !std::path::Path::new(p).exists() {
            continue;
        }
        let c = std::ffi::CString::new(p).unwrap();
        b = unsafe { sandlock_sandbox_builder_fs_read(b, c.as_ptr()) };
    }
    let wd = std::ffi::CString::new("/tmp").unwrap();
    b = unsafe { sandlock_sandbox_builder_workdir(b, wd.as_ptr()) };
    let mut err: c_int = 0;
    let policy = unsafe { sandlock_sandbox_build(b, &mut err, ptr::null_mut()) };
    assert_eq!(err, 0, "policy build failed");
    assert!(!policy.is_null());
    policy
}

/// Build a one-stage transaction and let the core reject it. Nothing runs, so
/// the only thing the round can leave behind is the handle itself.
fn build_and_reject(policy: *const sandlock_sandbox_t) {
    let txn = sandlock_txn_new();
    let owned = std::ffi::CString::new("true").unwrap();
    let ptrs: [*const c_char; 1] = [owned.as_ptr()];
    unsafe {
        sandlock_txn_add_stage(txn, policy, ptrs.as_ptr(), 1);
        let mut err: c_int = -99;
        let mut err_msg: *mut c_char = ptr::null_mut();
        let outcome = sandlock_txn_run(txn, 0, &mut err, &mut err_msg);
        assert!(outcome.is_null());
        assert_eq!(err, TXN_INVALID, "the round must reject, not run");
        assert!(!err_msg.is_null());
        sandlock_string_free(err_msg);
    }
}

#[test]
fn txn_run_releases_the_handle_it_refused_to_run() {
    let policy = build_policy();

    // Warm up: the thread's tokio runtime, the core's lazily built statics and
    // the allocator's own bookkeeping are one-time costs, and they are not what
    // this is measuring.
    for _ in 0..200 {
        build_and_reject(policy);
    }

    const ROUNDS: usize = 2_000;
    let before = LIVE.load(Ordering::Relaxed);
    for _ in 0..ROUNDS {
        build_and_reject(policy);
    }
    let grew = LIVE.load(Ordering::Relaxed) - before;

    unsafe { sandlock_sandbox_free(policy) };

    // A leaked handle carries a cloned policy, which is hundreds of bytes at
    // the smallest, so a per-round leak lands in the hundreds of kilobytes over
    // this many rounds. The bound is well under that and well over the nothing
    // a correct run leaves: steady state here is exactly zero.
    assert!(
        grew < 64 * 1024,
        "{ROUNDS} refused transactions leaked {grew} bytes: sandlock_txn_run \
         must consume the handle on the validation path too",
    );
}
