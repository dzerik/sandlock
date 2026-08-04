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

use std::ffi::{c_char, c_int, c_uint, CString};
use std::ptr;
use std::time::Duration;

use sandlock_core::{Change, ChangeKind, Sandbox, Stage, Transaction, TxnDisposition, TxnError};

use crate::runtime::with_runtime;
use crate::{argv_from_c, sandlock_result_t, sandlock_sandbox_t};

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

// ----------------------------------------------------------------
// Running a transaction
// ----------------------------------------------------------------

// Discriminants reported through the `err` out-parameter of
// `sandlock_txn_run` and `sandlock_txn_dry_run`.
//
// Non-negative values name a way the core refused to carry the transaction
// out; the list is append only, so a published value never changes meaning.
// Negative values are not transaction verdicts at all: they say the call
// could not be made, and they carry no message.

/// The transaction ran. An outcome handle was returned; its disposition says
/// whether it committed.
const TXN_OK: c_int = 0;
/// The handle was null: a bug in the calling binding, not a failed
/// transaction.
const TXN_NULL_HANDLE: c_int = -1;
/// This thread's Tokio runtime could not be built, or it panicked while
/// driving the transaction. Nothing can be said about the workdir from here;
/// `crate::runtime` has already reported the cause on stderr.
const TXN_NO_RUNTIME: c_int = -2;
/// The stage set is not a valid transaction. Checked before anything runs.
const TXN_INVALID: c_int = 1;
/// The shared copy-on-write branch could not be created. No stage ran.
const TXN_BRANCH: c_int = 2;
/// A stage could not be started or driven to completion. This is not a stage
/// that *failed*: a non-zero exit is an aborted outcome, not an error.
const TXN_STAGE: c_int = 3;
/// Contention: another commit held the workdir lock for longer than
/// [`sandlock_txn_commit_lock_wait_ms`]. The workdir is untouched and the whole
/// change set was preserved. Retrying is the expected response.
const TXN_CONFLICT: c_int = 4;
/// The workdir commit lock could not be taken for a reason other than
/// contention (the workdir could not be opened, or `flock` failed). As with
/// `TXN_CONFLICT` the workdir is untouched and the change set was preserved.
const TXN_COMMIT_LOCK: c_int = 5;
/// The commit merge failed. The merge is not rolled back, so the workdir may
/// be partially merged, and what did not land was preserved when a marker
/// could be written for it. Failing to write that marker is itself one of the
/// ways this failure is reached, and in that case the workdir was not touched
/// at all; the message says which happened.
const TXN_MERGE: c_int = 6;
/// The commit phase never ran to completion because the runtime was shut down
/// under it. This is the one failure that cannot say what state the workdir
/// and the change set are in.
const TXN_COMMIT_ABANDONED: c_int = 7;
/// A failure this version of the ABI has no name for. The core failure set is
/// open, so a binding built against an older header can meet a newer one; the
/// message still carries the core's own explanation.
const TXN_UNKNOWN: c_int = 8;

/// Opaque handle holding the outcome of a transaction.
///
/// Produced by [`sandlock_txn_run`] and [`sandlock_txn_dry_run`], released
/// with [`sandlock_txn_outcome_free`]. It owns the per-stage results and the
/// change list, so every pointer handed out by
/// [`sandlock_txn_outcome_stage_at`] dies with it.
#[allow(non_camel_case_types)]
pub struct sandlock_txn_outcome_t {
    disposition: TxnDisposition,
    /// Pre-wrapped so that `stage_at` can hand out a borrow of the public
    /// handle type directly. Casting a `&RunResult` to a
    /// `*const sandlock_result_t` would instead rest on the layout of a
    /// single-field `#[repr(C)]` struct, which is not a guarantee worth
    /// taking for an accessor.
    stages: Vec<sandlock_result_t>,
    changes: Vec<Change>,
}

/// Map a core failure onto its stable discriminant.
///
/// The numbering follows the core's own variant order. Two of them are easy
/// to swap and mean opposite things to a caller: `Conflict` is the retryable
/// one (another commit held the lock), `CommitLock` is not (the lock could not
/// be taken at all).
fn txn_err_code(e: &TxnError) -> c_int {
    match e {
        TxnError::Invalid(_) => TXN_INVALID,
        TxnError::Branch { .. } => TXN_BRANCH,
        TxnError::Stage { .. } => TXN_STAGE,
        TxnError::Conflict { .. } => TXN_CONFLICT,
        TxnError::CommitLock { .. } => TXN_COMMIT_LOCK,
        TxnError::Merge { .. } => TXN_MERGE,
        TxnError::CommitAbandoned(_) => TXN_COMMIT_ABANDONED,
        // The core failure set is `#[non_exhaustive]`: a variant added by a
        // later phase must not be silently reported as one of the above.
        _ => TXN_UNKNOWN,
    }
}

/// Store `msg` in `*out` as an owned C string, or leave `*out` null when the
/// message cannot be represented as one (an interior NUL). Never invents a
/// substitute: the text belongs to the core.
///
/// # Safety
/// `out` must be null or point to writable storage for one `*mut c_char`.
unsafe fn set_err_msg(out: *mut *mut c_char, msg: String) {
    if out.is_null() {
        return;
    }
    *out = match CString::new(msg) {
        Ok(c) => c.into_raw(),
        Err(_) => ptr::null_mut(),
    };
}

/// Shared body of run and dry run. `dry` selects the core entry point.
///
/// # Safety
/// See [`sandlock_txn_run`].
unsafe fn txn_execute(
    txn: *mut sandlock_txn_t,
    timeout_ms: u64,
    err: *mut c_int,
    err_msg: *mut *mut c_char,
    dry: bool,
) -> *mut sandlock_txn_outcome_t {
    if !err_msg.is_null() {
        *err_msg = ptr::null_mut();
    }
    if txn.is_null() {
        // A null handle is a bug in the binding layer, not a policy failure:
        // report the code but invent no message, as `sandlock_sandbox_build`
        // does. There is nothing user-actionable to say and saying it here
        // would put a hard-coded sentence in the wrong layer.
        if !err.is_null() {
            *err = TXN_NULL_HANDLE;
        }
        return ptr::null_mut();
    }
    let txn = *Box::from_raw(txn);

    let stages: Vec<Stage> = txn
        .stages
        .iter()
        .map(|(policy, args)| {
            let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            Stage::new(policy, &refs)
        })
        .collect();

    let mut t = Transaction::new(stages);
    if let Some(wait) = txn.commit_lock_wait {
        t = t.commit_lock_wait(wait);
    }
    let timeout = if timeout_ms > 0 {
        Some(Duration::from_millis(timeout_ms))
    } else {
        None
    };

    let ran = with_runtime(|rt| {
        rt.block_on(async {
            if dry {
                t.dry_run(timeout).await
            } else {
                t.run(timeout).await
            }
        })
    });

    match ran {
        Some(Ok(outcome)) => {
            if !err.is_null() {
                *err = TXN_OK;
            }
            Box::into_raw(Box::new(sandlock_txn_outcome_t {
                disposition: outcome.disposition,
                stages: outcome
                    .stages
                    .into_iter()
                    .map(sandlock_result_t::from_run_result)
                    .collect(),
                changes: outcome.changes,
            }))
        }
        Some(Err(e)) => {
            if !err.is_null() {
                *err = txn_err_code(&e);
            }
            set_err_msg(err_msg, e.to_string());
            ptr::null_mut()
        }
        None => {
            if !err.is_null() {
                *err = TXN_NO_RUNTIME;
            }
            ptr::null_mut()
        }
    }
}

/// Run the transaction: every stage in turn over one shared copy-on-write
/// upper, then merge that upper into the workdir if and only if every stage
/// exited 0.
///
/// On success returns an outcome handle and sets `*err` to 0. On failure
/// returns null, sets `*err` to a discriminant and, when `err_msg` is
/// non-null, stores an owned message the caller releases with
/// `sandlock_string_free`.
///
/// The handle is consumed on EVERY path, including every failure, and
/// including `SANDLOCK_TXN_INVALID`, which is decided before anything runs.
/// Passing it to [`sandlock_txn_free`] afterwards is a double free and adding
/// a stage to it is a use after free; [`sandlock_txn_free`] is for the
/// build-then-abandon path only. Recovering from a rejected stage set means
/// building a new transaction, not repairing this one.
///
/// A positive `*err` names one of the ways the core refused to carry the
/// transaction out, and always comes with a message. The two negative values
/// are not transaction verdicts and carry no message: -1 means the handle was
/// null, and -2 means this thread's async runtime could not be built or
/// panicked. Both are bugs in the caller or in its environment.
///
/// A stage exiting non-zero, and a run that times out, are NOT failures: they
/// are an outcome whose disposition is "aborted", with `*err` still 0. The
/// workdir is untouched in both cases.
///
/// `timeout_ms` bounds the stage phase only, never the commit; 0 means no
/// timeout. The commit phase cannot be cancelled from this ABI at all.
///
/// Each stage's standard error is written through to this process's file
/// descriptor 2 as it is produced, as well as being captured (bounded) into
/// the stage result. Standard input and output are inherited by every stage,
/// so a stage result never carries captured stdout.
///
/// The outcome must be released with [`sandlock_txn_outcome_free`].
///
/// # Safety
/// `txn` must be a handle from [`sandlock_txn_new`] that has not been run or
/// freed, or null; it is consumed by this call and must not be used again.
/// `err` and `err_msg` may both be null. When `err_msg` is non-null it must
/// point to writable storage for one `*mut c_char`; it is cleared on entry.
#[no_mangle]
pub unsafe extern "C" fn sandlock_txn_run(
    txn: *mut sandlock_txn_t,
    timeout_ms: u64,
    err: *mut c_int,
    err_msg: *mut *mut c_char,
) -> *mut sandlock_txn_outcome_t {
    txn_execute(txn, timeout_ms, err, err_msg, false)
}

/// Run every stage exactly as [`sandlock_txn_run`] does, then report the
/// change set and discard it.
///
/// The stages really execute; only the disposition of the shared upper
/// differs. The workdir is never written to and the commit lock is never
/// taken, so a dry run cannot conflict with anything.
///
/// # Safety
/// As [`sandlock_txn_run`].
#[no_mangle]
pub unsafe extern "C" fn sandlock_txn_dry_run(
    txn: *mut sandlock_txn_t,
    timeout_ms: u64,
    err: *mut c_int,
    err_msg: *mut *mut c_char,
) -> *mut sandlock_txn_outcome_t {
    txn_execute(txn, timeout_ms, err, err_msg, true)
}

/// Which of the three terminal states the transaction ended in: 0 committed,
/// 1 dry run, 2 aborted. Returns -1 for a null outcome.
///
/// The three-set is total, so a caller can switch on it exhaustively.
///
/// Why an abort happened is not published as a value here, but the two causes
/// are still tellable apart from what the outcome carries. A stage that
/// exited non-zero is reported and no later stage runs, so it is the last
/// result: walk [`sandlock_txn_outcome_stage_at`] and look for
/// `sandlock_result_success` returning false. A timeout kills the in-flight
/// stage and reports no result for it, so an aborted outcome in which every
/// reported stage succeeded is a timeout, and nothing else is.
///
/// # Safety
/// `o` must be null or an outcome pointer that has not been freed.
#[no_mangle]
pub unsafe extern "C" fn sandlock_txn_outcome_disposition(
    o: *const sandlock_txn_outcome_t,
) -> c_int {
    if o.is_null() {
        return -1;
    }
    match (*o).disposition {
        TxnDisposition::Committed => 0,
        TxnDisposition::DryRun => 1,
        TxnDisposition::Aborted(_) => 2,
    }
}

/// Number of stage results. Returns 0 for a null outcome.
///
/// Every stage that ran is reported, including on an abort and including the
/// stages that had finished before a timeout stopped the run, so this can be
/// smaller than the number of stages that were added.
///
/// # Safety
/// `o` must be null or an outcome pointer that has not been freed.
#[no_mangle]
pub unsafe extern "C" fn sandlock_txn_outcome_stages_len(
    o: *const sandlock_txn_outcome_t,
) -> usize {
    if o.is_null() {
        return 0;
    }
    (*o).stages.len()
}

/// The i-th stage result, in execution order, BORROWED from the outcome.
///
/// The pointer stays valid until [`sandlock_txn_outcome_free`] and must never
/// be passed to `sandlock_result_free`. Handing out an owned clone instead
/// would copy every stage's captured output for no benefit.
///
/// Returns null for a null outcome or an index that is out of range.
///
/// # Safety
/// `o` must be null or an outcome pointer that has not been freed. The
/// returned pointer must not outlive `o`.
#[no_mangle]
pub unsafe extern "C" fn sandlock_txn_outcome_stage_at(
    o: *const sandlock_txn_outcome_t,
    i: usize,
) -> *const sandlock_result_t {
    if o.is_null() {
        return ptr::null();
    }
    let stages = &(*o).stages;
    match stages.get(i) {
        Some(r) => r as *const sandlock_result_t,
        None => ptr::null(),
    }
}

/// Number of filesystem changes the shared upper held at the end of the run.
/// Returns 0 for a null outcome.
///
/// This is what the commit merged, or, for a dry run and for an abort, what
/// was discarded instead.
///
/// # Safety
/// `o` must be null or an outcome pointer that has not been freed.
#[no_mangle]
pub unsafe extern "C" fn sandlock_txn_outcome_changes_len(
    o: *const sandlock_txn_outcome_t,
) -> usize {
    if o.is_null() {
        return 0;
    }
    (*o).changes.len()
}

/// Kind of the i-th change: 'A' added, 'M' modified, 'D' deleted. Returns 0
/// for a null outcome or an index that is out of range.
///
/// # Safety
/// `o` must be null or an outcome pointer that has not been freed.
#[no_mangle]
pub unsafe extern "C" fn sandlock_txn_outcome_change_kind(
    o: *const sandlock_txn_outcome_t,
    i: usize,
) -> c_char {
    if o.is_null() {
        return 0;
    }
    let changes = &(*o).changes;
    match changes.get(i) {
        Some(c) => match c.kind {
            ChangeKind::Added => b'A' as c_char,
            ChangeKind::Modified => b'M' as c_char,
            ChangeKind::Deleted => b'D' as c_char,
        },
        None => 0,
    }
}

/// Path of the i-th change, relative to the workdir. The string is owned by
/// the caller and is released with `sandlock_string_free`. Returns null for a
/// null outcome or an index that is out of range.
///
/// Path bytes that are not valid UTF-8 are replaced rather than preserved,
/// exactly as `sandlock_dry_run_result_change_path` does, so this is a name to
/// show a user and not always a name to open.
///
/// # Safety
/// `o` must be null or an outcome pointer that has not been freed.
#[no_mangle]
pub unsafe extern "C" fn sandlock_txn_outcome_change_path(
    o: *const sandlock_txn_outcome_t,
    i: usize,
) -> *mut c_char {
    if o.is_null() {
        return ptr::null_mut();
    }
    let changes = &(*o).changes;
    let path = match changes.get(i) {
        Some(c) => c.path.to_string_lossy(),
        None => return ptr::null_mut(),
    };
    match CString::new(path.as_bytes()) {
        Ok(c) => c.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Release an outcome. A null handle is a no-op.
///
/// Every pointer obtained from [`sandlock_txn_outcome_stage_at`] is invalid
/// afterwards.
///
/// # Safety
/// `o` must be null or an outcome pointer from a run that has not already
/// been freed.
#[no_mangle]
pub unsafe extern "C" fn sandlock_txn_outcome_free(o: *mut sandlock_txn_outcome_t) {
    if !o.is_null() {
        drop(Box::from_raw(o));
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

    /// Every failure discriminant is a permanent number in the C ABI, and two
    /// of them mean opposite things to a caller: `Conflict` says retry,
    /// `Merge` says stop and inspect the workdir. Reproducing the core paths
    /// that raise them costs fault injection; pinning the mapping costs a
    /// table, and without the table swapping two arms is invisible.
    ///
    /// The `_` arm cannot be reached from here. `TxnError` is
    /// `#[non_exhaustive]`, so the failure this ABI has no name for is by
    /// definition one the core does not have yet; its number is pinned on its
    /// own instead.
    #[test]
    fn every_failure_maps_to_its_own_published_discriminant() {
        use sandlock_core::error::BranchError;
        use sandlock_core::SandlockError;

        let p = || std::path::PathBuf::from("/txn-discriminant-test");
        let cases: Vec<(TxnError, c_int)> = vec![
            (TxnError::Invalid("rejected".into()), 1),
            (
                TxnError::Branch {
                    workdir: p(),
                    source: BranchError::Operation("no branch".into()),
                },
                2,
            ),
            (
                TxnError::Stage {
                    index: 0,
                    source: SandlockError::MemoryProtect("not driven".into()),
                },
                3,
            ),
            (
                TxnError::Conflict {
                    workdir: p(),
                    waited: Duration::from_millis(1),
                    preserved_upper: p(),
                },
                4,
            ),
            (
                TxnError::CommitLock {
                    workdir: p(),
                    preserved_upper: p(),
                    source: std::io::Error::other("no lock"),
                },
                5,
            ),
            (
                TxnError::Merge {
                    workdir: p(),
                    preserved_upper: p(),
                    source: BranchError::Operation("half merged".into()),
                },
                6,
            ),
            (TxnError::CommitAbandoned("shut down".into()), 7),
        ];
        for (e, code) in &cases {
            assert_eq!(
                txn_err_code(e),
                *code,
                "{e} must keep the discriminant the header publishes",
            );
        }
        assert_eq!(TXN_OK, 0);
        assert_eq!(
            TXN_UNKNOWN, 8,
            "reserved for a core failure this version of the ABI cannot name",
        );
        assert_eq!(TXN_NULL_HANDLE, -1);
        assert_eq!(TXN_NO_RUNTIME, -2);
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
