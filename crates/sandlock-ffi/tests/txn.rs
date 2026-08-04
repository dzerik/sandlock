//! Integration tests for the C ABI transaction surface (RFC #65 Phase 1).
//!
//! These drive the FFI symbols directly, as `tests/popen.rs` does.
//!
//! The builder half of the surface is deliberately write-only: a transaction
//! under construction exposes no getters, exactly like `sandlock_pipeline_t`.
//! What this file can therefore pin down from outside the crate is the
//! pointer contract: every entry point tolerates a null handle, and a handle
//! that is built and never run is releasable. The accumulation semantics
//! themselves are covered by the unit tests in `src/txn.rs`, which can read
//! the private fields without publishing an accessor into a permanent ABI.

use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_uint};
use std::ptr;

use sandlock_ffi::{
    sandlock_sandbox_build, sandlock_sandbox_builder_fs_read, sandlock_sandbox_builder_new,
    sandlock_sandbox_free, sandlock_sandbox_t, sandlock_txn_add_stage,
    sandlock_txn_commit_lock_wait_ms, sandlock_txn_free, sandlock_txn_new,
};

/// Own the CStrings and hand back the `*const c_char` vector they back.
fn argv(cmd: &[&str]) -> (Vec<CString>, Vec<*const c_char>) {
    let owned: Vec<CString> = cmd.iter().map(|s| CString::new(*s).unwrap()).collect();
    let ptrs: Vec<*const c_char> = owned.iter().map(|c| c.as_ptr()).collect();
    (owned, ptrs)
}

/// A policy that can exec the usual coreutils in a minimal rootfs.
fn build_policy() -> *mut sandlock_sandbox_t {
    let mut b = sandlock_sandbox_builder_new();
    for p in ["/usr", "/lib", "/lib64", "/bin"] {
        // `/lib64` is absent on RISC-V glibc / musl; granting a nonexistent
        // path makes the build fail.
        if p == "/lib64" && !std::path::Path::new("/lib64").exists() {
            continue;
        }
        let c = CString::new(p).unwrap();
        b = unsafe { sandlock_sandbox_builder_fs_read(b, c.as_ptr()) };
    }
    let mut err: c_int = 0;
    let policy = unsafe { sandlock_sandbox_build(b, &mut err, ptr::null_mut()) };
    assert_eq!(err, 0, "policy build failed");
    assert!(!policy.is_null());
    policy
}

#[test]
fn txn_handle_takes_stages_and_is_freeable_without_running() {
    let policy = build_policy();

    let txn = sandlock_txn_new();
    assert!(!txn.is_null(), "sandlock_txn_new must not return null");

    let (_owned, ptrs) = argv(&["sh", "-c", "true"]);
    unsafe {
        sandlock_txn_add_stage(txn, policy, ptrs.as_ptr(), ptrs.len() as c_uint);
        sandlock_txn_add_stage(txn, policy, ptrs.as_ptr(), ptrs.len() as c_uint);
        sandlock_txn_commit_lock_wait_ms(txn, 250);
        // The policy is cloned per stage, so the caller's handle is still
        // its own and must be released separately from the transaction.
        sandlock_sandbox_free(policy);
        sandlock_txn_free(txn);
    }
}

#[test]
fn txn_new_hands_out_independent_handles() {
    // Two transactions built in the same process must not alias: freeing one
    // may not disturb the other.
    let a = sandlock_txn_new();
    let b = sandlock_txn_new();
    assert!(!a.is_null() && !b.is_null());
    assert_ne!(a, b, "each transaction needs its own allocation");
    unsafe {
        sandlock_txn_free(a);
        sandlock_txn_commit_lock_wait_ms(b, 1);
        sandlock_txn_free(b);
    }
}

#[test]
fn txn_builders_ignore_null_handles() {
    // A null handle must be a no-op, never a segfault: bindings pass null on
    // their own allocation failure and the ABI has to survive it.
    let (_owned, ptrs) = argv(&["true"]);
    unsafe {
        sandlock_txn_add_stage(
            ptr::null_mut(),
            ptr::null(),
            ptrs.as_ptr(),
            ptrs.len() as c_uint,
        );
        sandlock_txn_commit_lock_wait_ms(ptr::null_mut(), 100);
        sandlock_txn_free(ptr::null_mut());
    }
}

#[test]
fn txn_add_stage_rejects_each_null_argument_on_its_own() {
    // A live transaction plus one null argument is the shape a binding hits
    // when it forgets a check; none of the three may be dereferenced.
    let policy = build_policy();
    let txn = sandlock_txn_new();
    let (_owned, ptrs) = argv(&["true"]);

    unsafe {
        // Null policy, valid argv.
        sandlock_txn_add_stage(txn, ptr::null(), ptrs.as_ptr(), ptrs.len() as c_uint);
        // Valid policy, null argv with a nonzero count: the count must not be
        // trusted over the pointer.
        sandlock_txn_add_stage(txn, policy, ptr::null(), 3);
        // Valid policy and argv, zero count: an empty command vector is not a
        // runnable stage, so it is dropped here rather than carried to the
        // core.
        sandlock_txn_add_stage(txn, policy, ptrs.as_ptr(), 0);

        sandlock_sandbox_free(policy);
        sandlock_txn_free(txn);
    }
}
