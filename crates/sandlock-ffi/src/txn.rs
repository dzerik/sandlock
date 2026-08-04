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

use std::ffi::{c_char, c_int, c_uint, CStr, CString, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::ptr;
use std::time::Duration;

use sandlock_core::recovery::{list_preserved, read_preserved, PreserveReason, PreservedBranch};
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

/// How a transaction ended, as reported through the `err` out-parameter of
/// [`sandlock_txn_run`] and [`sandlock_txn_dry_run`].
///
/// The list is append only: a published value never changes meaning, and a
/// caller that meets a value it does not know must treat it as a failure it
/// cannot classify rather than as success.
///
/// Two of these are easy to mistake for each other and mean opposite things.
/// `SANDLOCK_TXN_CONFLICT` is the retryable one (another commit held the
/// lock); `SANDLOCK_TXN_COMMIT_LOCK` is not (the lock could not be taken at
/// all).
///
/// The two negative codes that can also appear in `err` are deliberately not
/// members: they are not verdicts on a transaction, so they must not be
/// switched on alongside these. See `SANDLOCK_TXN_NULL_HANDLE` and
/// `SANDLOCK_TXN_NO_RUNTIME`.
// `#[repr(u32)]` (not `#[repr(C)]`) pins the discriminant width, matching the
// sibling FFI enums; a bare C enum's width is implementation-defined
// (`-fshort-enums`). The functions keep returning `int`, because `err` also
// carries the negative codes, which no `uint32_t` can hold.
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum sandlock_txn_err_t {
    /// The transaction ran. An outcome handle was returned; its disposition
    /// says whether it committed.
    Ok = 0,
    /// The stage set is not a valid transaction. Checked before anything runs.
    Invalid = 1,
    /// The shared copy-on-write branch could not be created. No stage ran.
    Branch = 2,
    /// A stage could not be started or driven to completion. This is not a
    /// stage that FAILED: a non-zero exit is an aborted outcome, not an error.
    Stage = 3,
    /// Contention: another commit held the workdir lock for longer than
    /// [`sandlock_txn_commit_lock_wait_ms`]. The workdir is untouched and the
    /// whole change set was preserved. Retrying is the expected response.
    Conflict = 4,
    /// The workdir commit lock could not be taken for a reason other than
    /// contention (the workdir could not be opened, or `flock` failed). As
    /// with `SANDLOCK_TXN_CONFLICT` the workdir is untouched and the change
    /// set was preserved.
    CommitLock = 5,
    /// The commit merge failed. The merge is not rolled back, so the workdir
    /// may be partially merged, and what did not land was preserved WHEN a
    /// marker could be written for it. Failing to write that marker is itself
    /// one of the ways this failure is reached, and in that case the workdir
    /// was not touched at all and no sweep will ever find the change set. The
    /// message says which of the two happened, so read it before acting.
    Merge = 6,
    /// The commit phase never ran to completion because the runtime was shut
    /// down under it. This is the one failure that cannot say what state the
    /// workdir and the change set are in.
    CommitAbandoned = 7,
    /// A failure this version of the ABI has no name for. The core failure set
    /// is open, so a binding built against an older header can meet a newer
    /// core; the message still carries the core's own explanation.
    Unknown = 8,
}

/// `err` value meaning the transaction handle was null: a bug in the calling
/// binding, not a failed transaction. No message accompanies it.
///
/// Negative, and so outside `sandlock_txn_err_t`, on purpose: nothing was
/// attempted, so there is no verdict on a workdir to report.
pub const SANDLOCK_TXN_NULL_HANDLE: c_int = -1;

/// `err` value meaning this thread's async runtime could not be built, or it
/// panicked while driving the transaction. No message accompanies it; the
/// cause has already been reported on this process's file descriptor 2.
///
/// Negative for the same reason as `SANDLOCK_TXN_NULL_HANDLE`, though here the
/// transaction may well have run: nothing can be said about the workdir from
/// here, which is precisely why it is not one of the named verdicts.
pub const SANDLOCK_TXN_NO_RUNTIME: c_int = -2;

/// Which terminal state a transaction that ran ended in, as reported by
/// [`sandlock_txn_outcome_disposition`].
///
/// Unlike `sandlock_txn_err_t` this set is not append only, it is TOTAL: a
/// transaction that ran ended in exactly one of these three, so a caller may
/// switch on it exhaustively and need no default arm. The core keeps it that
/// way on purpose, by funnelling future abort causes through the reason an
/// abort carries rather than through a fourth state.
///
/// `sandlock_txn_outcome_disposition` returns -1 for a null outcome, which is
/// not a member: it says there was no transaction to have a disposition.
// `#[repr(u32)]` for the same reason as `sandlock_txn_err_t`: a bare C enum's
// width is implementation-defined. The function keeps returning `int` because
// of the -1.
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum sandlock_txn_disposition_t {
    /// Every stage exited 0 and the shared upper was merged into the workdir.
    Committed = 0,
    /// Every stage exited 0 and the upper was discarded on purpose: the run
    /// was a dry run, so the workdir was never written to.
    DryRun = 1,
    /// A stage exited non-zero, or the stage phase timed out. The upper was
    /// discarded and the workdir is untouched. Which of the two happened is
    /// not published as a value; see [`sandlock_txn_outcome_disposition`].
    Aborted = 2,
}

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
    let code = match e {
        TxnError::Invalid(_) => sandlock_txn_err_t::Invalid,
        TxnError::Branch { .. } => sandlock_txn_err_t::Branch,
        TxnError::Stage { .. } => sandlock_txn_err_t::Stage,
        TxnError::Conflict { .. } => sandlock_txn_err_t::Conflict,
        TxnError::CommitLock { .. } => sandlock_txn_err_t::CommitLock,
        TxnError::Merge { .. } => sandlock_txn_err_t::Merge,
        TxnError::CommitAbandoned(_) => sandlock_txn_err_t::CommitAbandoned,
        // The core failure set is `#[non_exhaustive]`: a variant added by a
        // later phase must not be silently reported as one of the above.
        _ => sandlock_txn_err_t::Unknown,
    };
    code as c_int
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
            *err = SANDLOCK_TXN_NULL_HANDLE;
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
                *err = sandlock_txn_err_t::Ok as c_int;
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
                *err = SANDLOCK_TXN_NO_RUNTIME;
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

/// Which of the three terminal states the transaction ended in, as one of the
/// `SANDLOCK_TXN_DISPOSITION_*` values. Returns -1 for a null outcome.
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
    let d = match (*o).disposition {
        TxnDisposition::Committed => sandlock_txn_disposition_t::Committed,
        TxnDisposition::DryRun => sandlock_txn_disposition_t::DryRun,
        TxnDisposition::Aborted(_) => sandlock_txn_disposition_t::Aborted,
    };
    d as c_int
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

// ----------------------------------------------------------------
// Recovery: preserved change sets
// ----------------------------------------------------------------

/// Why a change set was left in branch storage instead of being reclaimed, as
/// reported by [`sandlock_preserved_reason`].
///
/// This is what says how far the workdir got, so it decides what a recovery
/// may do rather than merely describing history. The list is append only.
///
/// `sandlock_preserved_reason` returns -1 for a null record, which is not a
/// member: it says the question was not asked of a record at all.
// `#[repr(u32)]` for the same reason as `sandlock_txn_err_t`: a bare C enum's
// width is implementation-defined.
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum sandlock_preserve_reason_t {
    /// A merge started and did not finish, so the workdir may be partly
    /// merged. A merge that is STILL RUNNING is indistinguishable from this:
    /// the marker is written before the first destructive step. Check
    /// [`sandlock_preserved_pid`] before acting on such a record.
    MergeInterrupted = 0,
    /// A commit could not take the workdir lock. The workdir is untouched and
    /// the whole change set is here.
    CommitDeferred = 1,
    /// The caller asked for the branch to be kept.
    Kept = 2,
}

/// Opaque handle holding one preserved change set: work that was left in
/// branch storage instead of being reclaimed, because a commit could not take
/// the workdir lock, a merge stopped partway, or the caller asked for it to be
/// kept.
///
/// There are two producers and they have DIFFERENT release rules.
/// [`sandlock_preserved_read`] returns an OWNED handle that the caller
/// releases with [`sandlock_preserved_free`].
/// [`sandlock_preserved_list_at`] returns a BORROW of an entry inside a list,
/// which must never reach [`sandlock_preserved_free`]: it is released by
/// [`sandlock_preserved_list_free`] together with the rest of the list.
///
/// Every accessor below works on either kind, and every string it returns is
/// owned by the caller in both cases.
#[allow(non_camel_case_types)]
pub struct sandlock_preserved_t {
    _private: PreservedBranch,
}

/// Opaque handle holding one sweep of a storage base.
///
/// Owns its entries, so every pointer handed out by
/// [`sandlock_preserved_list_at`] dies with it. Release it with
/// [`sandlock_preserved_list_free`].
#[allow(non_camel_case_types)]
pub struct sandlock_preserved_list_t {
    /// Pre-wrapped in the published handle type so that `list_at` can hand out
    /// a borrow directly. Casting a `&PreservedBranch` instead would tie the
    /// accessor to the layout of a single-field struct.
    items: Vec<sandlock_preserved_t>,
}

/// Read a C string as a filesystem path. `None` only for a null pointer.
///
/// The bytes go through unchanged. A path is bytes on this platform, and these
/// arguments name directories to walk and to open, so narrowing them to UTF-8
/// here would make a sweep unable to reach storage that another caller
/// created.
///
/// # Safety
/// `p` must be null or a valid C string.
unsafe fn path_arg(p: *const c_char) -> Option<PathBuf> {
    if p.is_null() {
        return None;
    }
    Some(PathBuf::from(OsString::from_vec(
        CStr::from_ptr(p).to_bytes().to_vec(),
    )))
}

/// Hand a path back as an owned C string, byte for byte.
///
/// Unlike the change report, whose paths are names to show, these are
/// addresses to open and to remove: a lossy conversion would name a directory
/// that does not exist, and the change set it points at could never be
/// recovered. A path read off the filesystem cannot contain a NUL, so the one
/// failure mode is unreachable; it is reported as null rather than papered
/// over with a substitute.
fn path_out(p: &Path) -> *mut c_char {
    match CString::new(p.as_os_str().as_bytes()) {
        Ok(c) => c.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Sweep `storage_base` for preserved change sets.
///
/// Returns a list handle the caller releases with
/// [`sandlock_preserved_list_free`]. Finding nothing is an EMPTY LIST, not
/// null: a base that holds no preserved work and a base that could not be read
/// (it does not exist, or is not readable) both sweep to nothing, and neither
/// is a failure of this call. Null is returned only for a null argument.
///
/// Entries that cannot be parsed are skipped rather than failing the sweep, so
/// one broken branch directory cannot hide the rest.
///
/// `storage_base` is read as a sequence of BYTES and is not narrowed to UTF-8:
/// a path is bytes on this platform, and this one names a directory to walk,
/// so a base another caller created is reachable whatever it is called. The
/// same holds for every path this family hands back. That is the opposite of
/// [`sandlock_txn_outcome_change_path`], which is lossy on purpose because it
/// is a name to show rather than an address to open.
///
/// Knowing WHICH base to sweep is the caller's problem, and this ABI cannot
/// answer it: a failed commit names the preserved upper in its message and
/// nowhere else, and the default base is derived inside the core from the
/// environment. A caller that means to recover programmatically should set
/// `sandlock_sandbox_builder_fs_storage` on its policies and sweep that same
/// path, rather than parsing the message or guessing the default.
///
/// A merge that is STILL RUNNING looks exactly like one that was interrupted:
/// the marker is written before the first destructive step. Anything that acts
/// on an entry, rather than only reporting it, must first check that
/// [`sandlock_preserved_pid`] is not a live process.
///
/// # Safety
/// `storage_base` must be null or a valid C string.
#[no_mangle]
pub unsafe extern "C" fn sandlock_preserved_list(
    storage_base: *const c_char,
) -> *mut sandlock_preserved_list_t {
    let Some(base) = path_arg(storage_base) else {
        return ptr::null_mut();
    };
    let items = list_preserved(&base)
        .into_iter()
        .map(|b| sandlock_preserved_t { _private: b })
        .collect();
    Box::into_raw(Box::new(sandlock_preserved_list_t { items }))
}

/// Number of preserved change sets in the sweep. 0 for a null list.
///
/// # Safety
/// `l` must be null or a list pointer that has not been freed.
#[no_mangle]
pub unsafe extern "C" fn sandlock_preserved_list_len(l: *const sandlock_preserved_list_t) -> usize {
    if l.is_null() {
        return 0;
    }
    (*l).items.len()
}

/// The i-th preserved change set, BORROWED from the list.
///
/// The pointer stays valid until [`sandlock_preserved_list_free`] and must
/// NEVER be passed to [`sandlock_preserved_free`]: it is not a separate
/// allocation, and freeing it would free memory the list still owns. Only a
/// handle from [`sandlock_preserved_read`] is freed that way.
///
/// Returns null for a null list or an index that is out of range.
///
/// # Safety
/// `l` must be null or a list pointer that has not been freed. The returned
/// pointer must not outlive `l`.
#[no_mangle]
pub unsafe extern "C" fn sandlock_preserved_list_at(
    l: *const sandlock_preserved_list_t,
    i: usize,
) -> *const sandlock_preserved_t {
    if l.is_null() {
        return ptr::null();
    }
    let items = &(*l).items;
    match items.get(i) {
        Some(p) => p as *const sandlock_preserved_t,
        None => ptr::null(),
    }
}

/// Read one preserved change set from its branch directory.
///
/// Returns an OWNED handle the caller releases with
/// [`sandlock_preserved_free`], which is the one handle that may be freed that
/// way.
///
/// Null means the directory is not a usable preserved branch: it is null or
/// unreadable, it holds no marker, it is the live storage of a running
/// process, or its marker was cut short by a crash. Those cases are not
/// distinguishable here, deliberately: a half-parsed record is worse than none
/// at all, because acting on it would target the wrong workdir.
///
/// `branch_dir` is read as a sequence of BYTES, not narrowed to UTF-8, so what
/// [`sandlock_preserved_branch_dir`] reported can be fed straight back here.
///
/// # Safety
/// `branch_dir` must be null or a valid C string.
#[no_mangle]
pub unsafe extern "C" fn sandlock_preserved_read(
    branch_dir: *const c_char,
) -> *mut sandlock_preserved_t {
    let Some(dir) = path_arg(branch_dir) else {
        return ptr::null_mut();
    };
    match read_preserved(&dir) {
        Some(b) => Box::into_raw(Box::new(sandlock_preserved_t { _private: b })),
        None => ptr::null_mut(),
    }
}

/// The branch's private storage directory: what to remove once the change set
/// has been recovered, and what [`sandlock_preserved_read`] takes.
///
/// The string is OWNED by the caller and is released with
/// `sandlock_string_free`, whether the record came from a list borrow or from
/// a read. Freeing the record does not free strings already handed out, and
/// freeing a string does not touch the record. Returns null for a null record.
///
/// It carries the path's BYTES verbatim and may therefore not be valid UTF-8.
/// A binding must keep those bytes rather than decode them: this is the string
/// that goes back into [`sandlock_preserved_read`] and that names the directory
/// to remove once the change set has been recovered, so a substituted character
/// would name a directory that does not exist. Every path this family returns
/// works the same way, and none of them is like
/// [`sandlock_txn_outcome_change_path`], which is lossy because it is a name to
/// show rather than an address to open.
///
/// # Safety
/// `p` must be null or a record pointer that has not been freed.
#[no_mangle]
pub unsafe extern "C" fn sandlock_preserved_branch_dir(
    p: *const sandlock_preserved_t,
) -> *mut c_char {
    if p.is_null() {
        return ptr::null_mut();
    }
    path_out(&(*p)._private.branch_dir)
}

/// The upper holding the preserved additions and modifications.
///
/// This is only half of the change set: the deletions have no representation
/// here at all, so copying this upper over the workdir and nothing else would
/// resurrect every file the run removed. See
/// [`sandlock_preserved_deleted_at`], and apply deletions FIRST.
///
/// Owned string, released with `sandlock_string_free`, carrying the path's
/// bytes verbatim (see [`sandlock_preserved_branch_dir`]). Null for a null
/// record.
///
/// # Safety
/// `p` must be null or a record pointer that has not been freed.
#[no_mangle]
pub unsafe extern "C" fn sandlock_preserved_upper(p: *const sandlock_preserved_t) -> *mut c_char {
    if p.is_null() {
        return ptr::null_mut();
    }
    path_out(&(*p)._private.upper)
}

/// The workdir the change set belongs to, canonicalized when the branch was
/// created.
///
/// Owned string, released with `sandlock_string_free`, carrying the path's
/// bytes verbatim (see [`sandlock_preserved_branch_dir`]). Null for a null
/// record.
///
/// # Safety
/// `p` must be null or a record pointer that has not been freed.
#[no_mangle]
pub unsafe extern "C" fn sandlock_preserved_workdir(p: *const sandlock_preserved_t) -> *mut c_char {
    if p.is_null() {
        return ptr::null_mut();
    }
    path_out(&(*p)._private.workdir)
}

/// Why the change set was preserved, as one of the
/// `SANDLOCK_PRESERVE_*` values. Returns -1 for a null record.
///
/// This is what says how far the workdir got, so a recovery has to read it
/// before it reads anything else; `SANDLOCK_PRESERVE_MERGE_INTERRUPTED` is
/// also what a merge that is still running looks like, and see
/// [`sandlock_preserved_pid`] for why that matters.
///
/// # Safety
/// `p` must be null or a record pointer that has not been freed.
#[no_mangle]
pub unsafe extern "C" fn sandlock_preserved_reason(p: *const sandlock_preserved_t) -> c_int {
    if p.is_null() {
        return -1;
    }
    let reason = match (*p)._private.reason {
        PreserveReason::MergeInterrupted => sandlock_preserve_reason_t::MergeInterrupted,
        PreserveReason::CommitDeferred => sandlock_preserve_reason_t::CommitDeferred,
        PreserveReason::Kept => sandlock_preserve_reason_t::Kept,
    };
    reason as c_int
}

/// The process that preserved the change set. 0 for a null record, which is
/// not a process id anything here can have.
///
/// Load-bearing for one thing: a merge writes its marker BEFORE its first
/// destructive step, so a merge in flight and a merge that was interrupted are
/// the same record, and this pid is the only thing that tells them apart.
/// Anything that acts on such a record must check that the pid is not live
/// first. Beyond that it is triage only: the process may be long gone and its
/// pid reused.
///
/// # Safety
/// `p` must be null or a record pointer that has not been freed.
#[no_mangle]
pub unsafe extern "C" fn sandlock_preserved_pid(p: *const sandlock_preserved_t) -> u32 {
    if p.is_null() {
        return 0;
    }
    (*p)._private.pid
}

/// Number of paths the run deleted. 0 for a null record.
///
/// # Safety
/// `p` must be null or a record pointer that has not been freed.
#[no_mangle]
pub unsafe extern "C" fn sandlock_preserved_deleted_len(p: *const sandlock_preserved_t) -> usize {
    if p.is_null() {
        return 0;
    }
    (*p)._private.deleted.len()
}

/// The i-th deleted path, relative to the workdir, in sorted order.
///
/// These are the outstanding deletions as of the last write of the record, and
/// they are the half of the change set that the upper cannot carry. A recovery
/// applies them BEFORE the upper: an addition under a path the run also
/// deleted only lands correctly once that path has been emptied.
///
/// Owned string, released with `sandlock_string_free`, carrying the path's
/// bytes verbatim (see [`sandlock_preserved_branch_dir`]). Null for a null
/// record or an index that is out of range.
///
/// # Safety
/// `p` must be null or a record pointer that has not been freed.
#[no_mangle]
pub unsafe extern "C" fn sandlock_preserved_deleted_at(
    p: *const sandlock_preserved_t,
    i: usize,
) -> *mut c_char {
    if p.is_null() {
        return ptr::null_mut();
    }
    let deleted = &(*p)._private.deleted;
    match deleted.get(i) {
        Some(path) => path_out(path),
        None => ptr::null_mut(),
    }
}

/// Release a sweep. A null list is a no-op.
///
/// Every pointer obtained from [`sandlock_preserved_list_at`] is invalid
/// afterwards. Strings already handed out by the accessors are not: they are
/// separate allocations the caller still owns and still has to free.
///
/// This does not remove anything from disk. The preserved storage outlives the
/// sweep, and removing it is the caller's decision once the change set has
/// been recovered.
///
/// # Safety
/// `l` must be null or a list from [`sandlock_preserved_list`] that has not
/// already been freed.
#[no_mangle]
pub unsafe extern "C" fn sandlock_preserved_list_free(l: *mut sandlock_preserved_list_t) {
    if !l.is_null() {
        drop(Box::from_raw(l));
    }
}

/// Release a record from [`sandlock_preserved_read`]. A null record is a
/// no-op.
///
/// ONLY for a handle from [`sandlock_preserved_read`]. A pointer from
/// [`sandlock_preserved_list_at`] borrows from its list and passing it here is
/// a double free; that list is released by [`sandlock_preserved_list_free`]
/// instead.
///
/// This does not remove anything from disk, for the same reason
/// [`sandlock_preserved_list_free`] does not.
///
/// # Safety
/// `p` must be null or a record from [`sandlock_preserved_read`] that has not
/// already been freed.
#[no_mangle]
pub unsafe extern "C" fn sandlock_preserved_free(p: *mut sandlock_preserved_t) {
    if !p.is_null() {
        drop(Box::from_raw(p));
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
        assert_eq!(sandlock_txn_err_t::Ok as c_int, 0);
        assert_eq!(
            sandlock_txn_err_t::Unknown as c_int,
            8,
            "reserved for a core failure this version of the ABI cannot name",
        );
        assert_eq!(SANDLOCK_TXN_NULL_HANDLE, -1);
        assert_eq!(SANDLOCK_TXN_NO_RUNTIME, -2);
    }

    /// The preservation reasons are permanent numbers too, and the one that
    /// decides the most is the one no test can produce: an interrupted merge
    /// needs a crash between the marker and the end of the merge. Reported as
    /// `Kept` or `CommitDeferred` it would tell a recovery tool the workdir is
    /// untouched when it may be half merged, and the tool would replay the
    /// whole upper onto a workdir that already holds part of it.
    #[test]
    fn every_preserve_reason_maps_to_its_own_published_value() {
        let record = |reason| sandlock_preserved_t {
            _private: PreservedBranch {
                branch_dir: PathBuf::from("/preserve-reason-test/branch"),
                upper: PathBuf::from("/preserve-reason-test/branch/upper"),
                workdir: PathBuf::from("/preserve-reason-test/work"),
                deleted: Vec::new(),
                reason,
                pid: 1,
            },
        };
        for (reason, value) in [
            (PreserveReason::MergeInterrupted, 0),
            (PreserveReason::CommitDeferred, 1),
            (PreserveReason::Kept, 2),
        ] {
            let r = record(reason);
            assert_eq!(
                unsafe { sandlock_preserved_reason(&r) },
                value,
                "{reason:?} must keep the value the header publishes",
            );
        }
        assert_eq!(
            unsafe { sandlock_preserved_reason(ptr::null()) },
            -1,
            "not a member of the set: the question was not asked of a record",
        );
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
