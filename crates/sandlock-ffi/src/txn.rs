//! C ABI for transactional pipelines (RFC #65 Phase 1).
//!
//! A transaction is accumulated on an opaque handle and then consumed by a
//! run. This module owns the construction half of that surface; the run
//! entry points and the outcome accessors live alongside it.
//!
//! The handle mirrors `sandlock_pipeline_t`: it stores policies and argument
//! vectors rather than `sandlock_core::pipeline::Stage` values, because
//! `Stage` is not `Clone` while `Sandbox` is, and the core `Transaction`
//! takes ownership of the stage list. Materialising `Stage` is therefore
//! deferred to the moment of the run.

use std::ffi::{c_char, c_uint};
use std::time::Duration;

use sandlock_core::Sandbox;

use crate::{argv_from_c, sandlock_sandbox_t};

/// Opaque handle wrapping a transaction under construction.
///
/// Create it with [`sandlock_txn_new`]. It is consumed by a run; a
/// transaction that is built and then abandoned must be released with
/// [`sandlock_txn_free`].
#[allow(non_camel_case_types)]
pub struct sandlock_txn_t {
    pub(crate) stages: Vec<(Sandbox, Vec<String>)>,
    /// `None` leaves the core default in place. An `Option` rather than a
    /// plain `Duration` because the default is a core constant this layer
    /// cannot read, so "unset" has to be representable without naming a
    /// number here.
    ///
    /// `Some(Duration::ZERO)` is not reachable through the ABI:
    /// [`sandlock_txn_commit_lock_wait_ms`] reads 0 as "unset". A zero wait is
    /// a meaningful setting in the core (one non-blocking attempt at the lock),
    /// and this surface cannot express it.
    pub(crate) commit_lock_wait: Option<Duration>,
}

/// Create an empty transaction.
///
/// Free it with [`sandlock_txn_free`] unless it is consumed by a run.
#[no_mangle]
pub extern "C" fn sandlock_txn_new() -> *mut sandlock_txn_t {
    Box::into_raw(Box::new(sandlock_txn_t {
        stages: Vec::new(),
        commit_lock_wait: None,
    }))
}

/// Append a stage. The policy is cloned; the caller retains ownership.
///
/// Stages run in the order they are added, sequentially, over one shared
/// copy-on-write upper.
///
/// A stage this layer cannot read is DROPPED: nothing is appended and nothing
/// is reported. That is the case for a null `txn` or `policy`, for a null
/// `argv` or a null pointer inside it, for an `argc` of 0 or above 4096, and
/// for an argument whose bytes are not valid UTF-8. Dropping is the same no-op
/// a null handle already gets, and it is preferred to the alternative of
/// substituting an empty string for an argument that could not be decoded,
/// which would run a command the caller never asked for and report success.
/// A transaction that lost a stage this way does not commit silently: the core
/// sees the stage set it was actually given and refuses it.
///
/// The cross-stage requirements (at least two stages, one shared workdir, no
/// chroot, matching storage settings) are checked by the core when the
/// transaction runs, not here, so that the caller gets the core's own
/// explanation instead of a verdict invented in this layer.
///
/// # Safety
/// `txn` must be a valid transaction handle or null; `policy` a valid policy
/// handle or null; `argv` must be null or point to `argc` pointers, each of
/// which must itself be null or a valid C string.
#[no_mangle]
pub unsafe extern "C" fn sandlock_txn_add_stage(
    txn: *mut sandlock_txn_t,
    policy: *const sandlock_sandbox_t,
    argv: *const *const c_char,
    argc: c_uint,
) {
    if txn.is_null() || policy.is_null() {
        return;
    }
    let Some(args) = argv_from_c(argv, argc) else {
        return;
    };
    let policy = (*policy)._private.clone();
    (*txn).stages.push((policy, args));
}

/// Set how long the commit may wait for the workdir lock, in milliseconds.
///
/// Passing 0 restores the core default of 30 seconds; it does not mean "do
/// not wait". The default is a core constant that this layer cannot read, so
/// the number is spelled out here for documentation only: the value is never
/// materialised in the binding, the core supplies it.
///
/// A consequence worth stating plainly: a zero wait, meaning one non-blocking
/// attempt at the workdir lock, cannot be asked for through this ABI. The
/// shortest wait it can express is 1.
///
/// A null `txn` is a no-op.
///
/// # Safety
/// `txn` must be a valid transaction handle or null.
#[no_mangle]
pub unsafe extern "C" fn sandlock_txn_commit_lock_wait_ms(txn: *mut sandlock_txn_t, ms: u64) {
    if txn.is_null() {
        return;
    }
    (*txn).commit_lock_wait = if ms == 0 {
        None
    } else {
        Some(Duration::from_millis(ms))
    };
}

/// Release a transaction that was never run. A null handle is a no-op.
///
/// # Safety
/// `txn` must be a handle from [`sandlock_txn_new`] that was not consumed by
/// a run, or null. A run consumes the handle, so calling this afterwards is a
/// double free.
#[no_mangle]
pub unsafe extern "C" fn sandlock_txn_free(txn: *mut sandlock_txn_t) {
    if !txn.is_null() {
        drop(Box::from_raw(txn));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    /// The builder half of the C ABI publishes no getters, by design: a
    /// stage counter would be a permanent exported symbol whose only caller
    /// is a test, and `sandlock_pipeline_t` sets the precedent of exposing
    /// none. These unit tests reach the private fields instead.
    fn policy() -> sandlock_sandbox_t {
        let sb = Sandbox::builder()
            .fs_read("/usr")
            .build()
            .expect("minimal policy must build");
        sandlock_sandbox_t { _private: sb }
    }

    fn argv(cmd: &[&str]) -> (Vec<CString>, Vec<*const c_char>) {
        let owned: Vec<CString> = cmd.iter().map(|s| CString::new(*s).unwrap()).collect();
        let ptrs: Vec<*const c_char> = owned.iter().map(|c| c.as_ptr()).collect();
        (owned, ptrs)
    }

    #[test]
    fn stages_accumulate_in_the_order_they_were_added() {
        let p = policy();
        let txn = sandlock_txn_new();
        unsafe {
            for cmd in [["sh", "-c", "first"], ["sh", "-c", "second"]] {
                let (_o, ptrs) = argv(&cmd);
                sandlock_txn_add_stage(txn, &p, ptrs.as_ptr(), ptrs.len() as c_uint);
            }
            // Bind the borrow before indexing: indexing through a raw
            // pointer dereference trips the `dangerous_implicit_autorefs`
            // lint, which is deny by default.
            let stages = &(*txn).stages;
            assert_eq!(stages.len(), 2);
            assert_eq!(stages[0].1, vec!["sh", "-c", "first"]);
            assert_eq!(stages[1].1, vec!["sh", "-c", "second"]);
            sandlock_txn_free(txn);
        }
    }

    #[test]
    fn a_rejected_stage_does_not_land_in_the_transaction() {
        // Every guard must skip the push, not merely avoid the dereference: a
        // silently empty or truncated stage would surface much later as a
        // confusing core validation error, or worse, would run.
        let p = policy();
        let txn = sandlock_txn_new();
        let (_o, ptrs) = argv(&["true"]);
        // An argument whose bytes are not UTF-8. Reading it as an empty string
        // would hand the core a command the caller did not write.
        let bad = CString::new(b"caf\xff".to_vec()).unwrap();
        let with_bad: Vec<*const c_char> = vec![ptrs[0], bad.as_ptr()];
        // An argv with a hole in it, the shape a caller produces by counting
        // the execv terminator into `argc`.
        let with_hole: Vec<*const c_char> = vec![ptrs[0], std::ptr::null()];
        unsafe {
            sandlock_txn_add_stage(txn, std::ptr::null(), ptrs.as_ptr(), 1);
            sandlock_txn_add_stage(txn, &p, std::ptr::null(), 1);
            sandlock_txn_add_stage(txn, &p, ptrs.as_ptr(), 0);
            sandlock_txn_add_stage(txn, &p, with_hole.as_ptr(), 2);
            sandlock_txn_add_stage(txn, &p, with_bad.as_ptr(), 2);
            // An argc no argv can back. The cap has to be checked before the
            // walk, or this dereferences four billion slots.
            sandlock_txn_add_stage(txn, &p, ptrs.as_ptr(), u32::MAX);
            assert_eq!((*txn).stages.len(), 0, "no call above may add a stage");
            sandlock_txn_add_stage(txn, &p, ptrs.as_ptr(), 1);
            // Bind the borrow before indexing: see the comment in
            // `stages_accumulate_in_the_order_they_were_added`.
            let stages = &(*txn).stages;
            assert_eq!(stages.len(), 1);
            assert_eq!(stages[0].1, vec!["true"]);
            sandlock_txn_free(txn);
        }
    }

    #[test]
    fn commit_lock_wait_zero_means_the_core_default_not_zero_wait() {
        let txn = sandlock_txn_new();
        unsafe {
            assert_eq!((*txn).commit_lock_wait, None, "unset by default");
            sandlock_txn_commit_lock_wait_ms(txn, 250);
            assert_eq!((*txn).commit_lock_wait, Some(Duration::from_millis(250)));
            sandlock_txn_commit_lock_wait_ms(txn, 0);
            assert_eq!(
                (*txn).commit_lock_wait,
                None,
                "0 has to clear the override so the core supplies its default"
            );
            sandlock_txn_free(txn);
        }
    }
}
