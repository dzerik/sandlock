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
//!
//! The run half is observable from outside, so it is tested from outside: the
//! three dispositions, the failure discriminants, and the workdir state that
//! makes "all or nothing" mean something.

use std::ffi::CString;
use std::os::fd::AsRawFd;
use std::os::raw::{c_char, c_int, c_uint};
use std::path::Path;
use std::ptr;

use sandlock_ffi::{
    sandlock_result_exit_code, sandlock_result_free, sandlock_result_success, sandlock_run,
    sandlock_sandbox_build, sandlock_sandbox_builder_cwd, sandlock_sandbox_builder_fs_read,
    sandlock_sandbox_builder_fs_storage, sandlock_sandbox_builder_fs_write,
    sandlock_sandbox_builder_new, sandlock_sandbox_builder_workdir, sandlock_sandbox_free,
    sandlock_sandbox_t, sandlock_string_free, sandlock_txn_add_stage,
    sandlock_txn_commit_lock_wait_ms, sandlock_txn_dry_run, sandlock_txn_free, sandlock_txn_new,
    sandlock_txn_outcome_change_kind, sandlock_txn_outcome_change_path,
    sandlock_txn_outcome_changes_len, sandlock_txn_outcome_disposition, sandlock_txn_outcome_free,
    sandlock_txn_outcome_stage_at, sandlock_txn_outcome_stages_len, sandlock_txn_outcome_t,
    sandlock_txn_run,
};

const DISPOSITION_COMMITTED: c_int = 0;
const DISPOSITION_DRY_RUN: c_int = 1;
const DISPOSITION_ABORTED: c_int = 2;

const TXN_OK: c_int = 0;
const TXN_NULL_HANDLE: c_int = -1;
const TXN_INVALID: c_int = 1;
const TXN_CONFLICT: c_int = 4;

/// Own the CStrings and hand back the `*const c_char` vector they back.
fn argv(cmd: &[&str]) -> (Vec<CString>, Vec<*const c_char>) {
    let owned: Vec<CString> = cmd.iter().map(|s| CString::new(*s).unwrap()).collect();
    let ptrs: Vec<*const c_char> = owned.iter().map(|c| c.as_ptr()).collect();
    (owned, ptrs)
}

fn cstr(p: &Path) -> CString {
    CString::new(p.to_str().expect("test paths are UTF-8")).unwrap()
}

/// A policy shaped like the one the core transaction suite uses: read the
/// system, write and copy-on-write the workdir, and run with the workdir as
/// cwd so a stage's relative paths resolve into the shared upper.
///
/// `workdir` and `storage` are optional so the same helper serves the
/// pointer-contract tests, which never run anything.
fn build_policy(workdir: Option<&Path>, storage: Option<&Path>) -> *mut sandlock_sandbox_t {
    let mut b = sandlock_sandbox_builder_new();
    for p in ["/usr", "/lib", "/lib64", "/bin", "/etc", "/proc"] {
        // Granting a nonexistent path makes the build fail, and not every
        // grant here exists everywhere: `/lib64` is absent on RISC-V glibc
        // and on musl. The C ABI has no `fs_read_if_exists`, so the check
        // happens here.
        if !Path::new(p).exists() {
            continue;
        }
        let c = CString::new(p).unwrap();
        b = unsafe { sandlock_sandbox_builder_fs_read(b, c.as_ptr()) };
    }
    if let Some(wd) = workdir {
        let c = cstr(wd);
        b = unsafe { sandlock_sandbox_builder_fs_write(b, c.as_ptr()) };
        b = unsafe { sandlock_sandbox_builder_workdir(b, c.as_ptr()) };
        b = unsafe { sandlock_sandbox_builder_cwd(b, c.as_ptr()) };
    }
    if let Some(st) = storage {
        let c = cstr(st);
        b = unsafe { sandlock_sandbox_builder_fs_storage(b, c.as_ptr()) };
    }
    let mut err: c_int = 0;
    let policy = unsafe { sandlock_sandbox_build(b, &mut err, ptr::null_mut()) };
    assert_eq!(err, 0, "policy build failed");
    assert!(!policy.is_null());
    policy
}

/// Whether this environment can actually run a sandbox (Landlock + seccomp).
///
/// The core transaction suite guards its behavioural tests the same way, and
/// for the same reason: skipping the test whole keeps a real regression a hard
/// failure instead of hiding it behind a tolerated error.
fn sandbox_available() -> bool {
    let policy = build_policy(None, None);
    let (_owned, ptrs) = argv(&["true"]);
    let r = unsafe { sandlock_run(policy, ptr::null(), ptrs.as_ptr(), ptrs.len() as c_uint) };
    let ok = !r.is_null() && unsafe { sandlock_result_success(r) };
    unsafe {
        if !r.is_null() {
            sandlock_result_free(r);
        }
        sandlock_sandbox_free(policy);
    }
    ok
}

/// Every change the outcome reports, as `(kind, path)` pairs, sorted.
unsafe fn changes_of(o: *const sandlock_txn_outcome_t) -> Vec<(char, String)> {
    let n = sandlock_txn_outcome_changes_len(o);
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let kind = sandlock_txn_outcome_change_kind(o, i) as u8 as char;
        let path = sandlock_txn_outcome_change_path(o, i);
        assert!(!path.is_null(), "change {i} must carry a path");
        let s = std::ffi::CStr::from_ptr(path)
            .to_string_lossy()
            .into_owned();
        sandlock_string_free(path);
        out.push((kind, s));
    }
    out.sort();
    out
}

#[test]
fn txn_handle_takes_stages_and_is_freeable_without_running() {
    let policy = build_policy(None, None);

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
    let policy = build_policy(None, None);
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

        // Rejected has to mean rejected, not "added with a hole in it". The
        // only thing a C caller can observe about the stage list is what the
        // core says about it, so ask the core: three dropped stages leave a
        // transaction of none, which is below the two-stage minimum. A layer
        // that pushed any of them would draw a different complaint out of the
        // core, which is why the message is checked and not only the code.
        let mut err: c_int = -99;
        let mut err_msg: *mut c_char = ptr::null_mut();
        let outcome = sandlock_txn_run(txn, 0, &mut err, &mut err_msg);
        assert!(outcome.is_null());
        assert_eq!(err, TXN_INVALID, "no stage may have survived");
        assert!(!err_msg.is_null());
        let msg = std::ffi::CStr::from_ptr(err_msg)
            .to_string_lossy()
            .into_owned();
        assert!(
            msg.contains("at least 2 stages"),
            "the core must have been handed an empty stage set, got {msg:?}",
        );
        sandlock_string_free(err_msg);
        sandlock_sandbox_free(policy);
    }
}

/// The RFC #65 Phase 1 acceptance case, driven through the C ABI: three
/// sequential stages over one shared upper, a later stage reading what an
/// earlier one wrote, and both files landing in the real workdir on commit.
///
/// The workdir is seeded first so the commit has all three kinds of change to
/// report and to apply. An addition is the only kind a transaction that starts
/// from an empty workdir can ever produce, and a merge that resurrected a
/// deleted file, or that reported a deletion as a modification, would be
/// invisible without the other two.
#[test]
fn txn_commits_every_stage_and_reports_the_change_set() {
    if !sandbox_available() {
        eprintln!("txn commit test skipped: sandbox unavailable");
        return;
    }
    let workdir = tempfile::tempdir().unwrap();
    let storage = tempfile::tempdir().unwrap();
    std::fs::write(workdir.path().join("keep.txt"), "ORIGINAL").unwrap();
    std::fs::write(workdir.path().join("gone.txt"), "DOOMED").unwrap();
    let policy = build_policy(Some(workdir.path()), Some(storage.path()));

    let txn = sandlock_txn_new();
    for cmd in [
        "echo plan > a.txt",
        "cat a.txt && echo built > b.txt",
        "cat a.txt b.txt && echo edited > keep.txt && rm gone.txt",
    ] {
        let (_owned, ptrs) = argv(&["sh", "-c", cmd]);
        unsafe { sandlock_txn_add_stage(txn, policy, ptrs.as_ptr(), ptrs.len() as c_uint) };
    }

    let mut err: c_int = -99;
    let mut err_msg: *mut c_char = ptr::null_mut();
    let outcome = unsafe { sandlock_txn_run(txn, 0, &mut err, &mut err_msg) };

    assert_eq!(err, TXN_OK, "expected success, got discriminant {err}");
    assert!(err_msg.is_null(), "err_msg must stay null on success");
    assert!(!outcome.is_null());

    unsafe {
        assert_eq!(
            sandlock_txn_outcome_disposition(outcome),
            DISPOSITION_COMMITTED
        );
        assert_eq!(sandlock_txn_outcome_stages_len(outcome), 3);
        for i in 0..3 {
            let r = sandlock_txn_outcome_stage_at(outcome, i);
            assert!(!r.is_null(), "stage {i} result missing");
            assert_eq!(sandlock_result_exit_code(r), 0, "stage {i} must exit 0");
        }
        // Out of range is null, not a panic and not the last element.
        assert!(sandlock_txn_outcome_stage_at(outcome, 3).is_null());

        assert_eq!(
            changes_of(outcome),
            vec![
                ('A', "a.txt".to_string()),
                ('A', "b.txt".to_string()),
                ('D', "gone.txt".to_string()),
                ('M', "keep.txt".to_string()),
            ],
            "the outcome must report what the commit merged, each with its own kind",
        );
        assert_eq!(sandlock_txn_outcome_change_kind(outcome, 4), 0);
        assert!(sandlock_txn_outcome_change_path(outcome, 4).is_null());

        sandlock_txn_outcome_free(outcome);
        sandlock_sandbox_free(policy);
    }

    assert_eq!(
        std::fs::read_to_string(workdir.path().join("a.txt")).unwrap(),
        "plan\n",
        "stage 0's write must be committed to the real workdir",
    );
    assert_eq!(
        std::fs::read_to_string(workdir.path().join("b.txt")).unwrap(),
        "built\n",
        "stage 1's write must be committed to the real workdir",
    );
    assert_eq!(
        std::fs::read_to_string(workdir.path().join("keep.txt")).unwrap(),
        "edited\n",
        "the modification must reach the real file, not only the report",
    );
    assert!(
        !workdir.path().join("gone.txt").exists(),
        "the deletion must reach the real workdir: nothing in the upper carries it",
    );
}

/// A stage exiting non-zero is the feature working, not a failure of the ABI:
/// it is an outcome with the aborted disposition, not an `err`.
#[test]
fn txn_abort_is_an_outcome_not_an_error_and_commits_nothing() {
    if !sandbox_available() {
        eprintln!("txn abort test skipped: sandbox unavailable");
        return;
    }
    let workdir = tempfile::tempdir().unwrap();
    let storage = tempfile::tempdir().unwrap();
    let policy = build_policy(Some(workdir.path()), Some(storage.path()));

    let txn = sandlock_txn_new();
    for cmd in ["echo plan > a.txt", "exit 3"] {
        let (_owned, ptrs) = argv(&["sh", "-c", cmd]);
        unsafe { sandlock_txn_add_stage(txn, policy, ptrs.as_ptr(), ptrs.len() as c_uint) };
    }

    let mut err: c_int = -99;
    let mut err_msg: *mut c_char = ptr::null_mut();
    let outcome = unsafe { sandlock_txn_run(txn, 0, &mut err, &mut err_msg) };

    assert_eq!(err, TXN_OK, "an aborted transaction must not be an error");
    assert!(err_msg.is_null());
    assert!(!outcome.is_null());
    unsafe {
        assert_eq!(
            sandlock_txn_outcome_disposition(outcome),
            DISPOSITION_ABORTED
        );
        assert_eq!(
            sandlock_txn_outcome_stages_len(outcome),
            2,
            "both stages ran, so both results are reported",
        );
        assert_eq!(
            sandlock_result_exit_code(sandlock_txn_outcome_stage_at(outcome, 1)),
            3,
            "the failing stage keeps its own exit code",
        );
        assert_eq!(
            changes_of(outcome),
            vec![('A', "a.txt".to_string())],
            "the discarded change set is still reported",
        );
        sandlock_txn_outcome_free(outcome);
        sandlock_sandbox_free(policy);
    }
    assert!(
        !workdir.path().join("a.txt").exists(),
        "an abort must leave the workdir untouched",
    );
}

/// A dry run really executes every stage and reports what they changed, then
/// throws the upper away.
///
/// The header promises three things about it and this pins all three: the
/// workdir is not written to, the commit lock is never taken (so a dry run
/// cannot conflict with anything), and the upper is discarded rather than
/// preserved. The last one is what stops a plan-then-inspect loop from filling
/// branch storage with one kept upper per dry run.
#[test]
fn txn_dry_run_reports_changes_without_committing() {
    if !sandbox_available() {
        eprintln!("txn dry-run test skipped: sandbox unavailable");
        return;
    }
    let workdir = tempfile::tempdir().unwrap();
    let storage = tempfile::tempdir().unwrap();
    let policy = build_policy(Some(workdir.path()), Some(storage.path()));

    let txn = sandlock_txn_new();
    for cmd in ["echo plan > a.txt", "cat a.txt && echo built > b.txt"] {
        let (_owned, ptrs) = argv(&["sh", "-c", cmd]);
        unsafe { sandlock_txn_add_stage(txn, policy, ptrs.as_ptr(), ptrs.len() as c_uint) };
    }
    // Bound the wait so a dry run that DID reach for the lock fails in a
    // fraction of a second instead of stalling on the core's 30 second default.
    unsafe { sandlock_txn_commit_lock_wait_ms(txn, 300) };

    // Hold the workdir lock across the whole dry run: another transaction
    // mid-commit must not be able to make a dry run wait, let alone fail.
    let held = std::fs::File::open(workdir.path()).unwrap();
    assert_eq!(
        unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0,
        "test setup: could not take the workdir lock",
    );

    let mut err: c_int = -99;
    // Both out-parameters are optional; passing null for `err_msg` must not
    // change the outcome.
    let outcome = unsafe { sandlock_txn_dry_run(txn, 0, &mut err, ptr::null_mut()) };
    drop(held);
    assert_eq!(
        err, TXN_OK,
        "a dry run takes no commit lock, so a held one cannot fail it",
    );
    assert!(!outcome.is_null());

    unsafe {
        assert_eq!(
            sandlock_txn_outcome_disposition(outcome),
            DISPOSITION_DRY_RUN
        );
        assert_eq!(sandlock_txn_outcome_stages_len(outcome), 2);
        assert_eq!(
            changes_of(outcome),
            vec![('A', "a.txt".to_string()), ('A', "b.txt".to_string())],
            "a dry run reports the whole change set it then discards",
        );
        sandlock_txn_outcome_free(outcome);
        sandlock_sandbox_free(policy);
    }
    assert!(
        !workdir.path().join("a.txt").exists(),
        "a dry run must not touch the workdir",
    );
    assert!(!workdir.path().join("b.txt").exists());
    let left: Vec<std::path::PathBuf> = std::fs::read_dir(storage.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert!(
        left.is_empty(),
        "a dry run discards its upper rather than preserving it; found {left:?}",
    );
}

/// `timeout_ms` bounds the stage phase, and hitting it is an outcome rather
/// than an error: the disposition is aborted, `err` stays 0, and the workdir is
/// untouched.
///
/// It is also the only place the two abort causes are told apart. The stage
/// that was still running when the clock ran out reports no result at all, so
/// an aborted outcome whose every reported stage succeeded is a timeout, which
/// is what the header tells a caller to look for.
#[test]
fn txn_timeout_aborts_the_stage_phase_and_is_not_an_error() {
    if !sandbox_available() {
        eprintln!("txn timeout test skipped: sandbox unavailable");
        return;
    }
    let workdir = tempfile::tempdir().unwrap();
    let storage = tempfile::tempdir().unwrap();
    let policy = build_policy(Some(workdir.path()), Some(storage.path()));

    let txn = sandlock_txn_new();
    for cmd in ["echo plan > a.txt", "sleep 300"] {
        let (_owned, ptrs) = argv(&["sh", "-c", cmd]);
        unsafe { sandlock_txn_add_stage(txn, policy, ptrs.as_ptr(), ptrs.len() as c_uint) };
    }

    let started = std::time::Instant::now();
    let mut err: c_int = -99;
    let mut err_msg: *mut c_char = ptr::null_mut();
    let outcome = unsafe { sandlock_txn_run(txn, 1_500, &mut err, &mut err_msg) };
    let waited = started.elapsed();

    // The bound separates "the timeout was applied" from "the second stage ran
    // to completion", not one host from another: the stage sleeps for five
    // minutes and the timeout is a second and a half.
    assert!(
        waited < std::time::Duration::from_secs(60),
        "timeout_ms did not reach the core: the run took {waited:?}",
    );
    assert_eq!(
        err, TXN_OK,
        "a run that times out is an outcome, not a failure",
    );
    assert!(err_msg.is_null());
    assert!(!outcome.is_null());

    unsafe {
        assert_eq!(
            sandlock_txn_outcome_disposition(outcome),
            DISPOSITION_ABORTED
        );
        assert_eq!(
            sandlock_txn_outcome_stages_len(outcome),
            1,
            "the stage that was killed mid-flight produces no result",
        );
        let r = sandlock_txn_outcome_stage_at(outcome, 0);
        assert!(
            sandlock_result_success(r),
            "every stage the outcome does report had finished, and finished well: \
             that is what separates a timeout from a stage failure",
        );
        assert_eq!(
            changes_of(outcome),
            vec![('A', "a.txt".to_string())],
            "the stages really ran, and the change set they built is still reported",
        );
        sandlock_txn_outcome_free(outcome);
        sandlock_sandbox_free(policy);
    }
    assert!(
        !workdir.path().join("a.txt").exists(),
        "a timeout must leave the workdir untouched",
    );
}

/// The cross-stage guardrails belong to the core, and their verdict has to
/// reach the caller with the core's own words rather than a null pointer.
#[test]
fn txn_invalid_stage_set_reports_a_discriminant_and_a_message() {
    let workdir = tempfile::tempdir().unwrap();
    let policy = build_policy(Some(workdir.path()), None);

    // One stage: below the two-stage minimum. This is rejected before
    // anything runs, so it needs no sandbox.
    let txn = sandlock_txn_new();
    let (_owned, ptrs) = argv(&["true"]);
    unsafe { sandlock_txn_add_stage(txn, policy, ptrs.as_ptr(), ptrs.len() as c_uint) };

    let mut err: c_int = -99;
    let mut err_msg: *mut c_char = ptr::null_mut();
    let outcome = unsafe { sandlock_txn_run(txn, 0, &mut err, &mut err_msg) };

    assert!(outcome.is_null());
    assert_eq!(err, TXN_INVALID);
    assert!(
        !err_msg.is_null(),
        "a validation failure must carry a message"
    );
    let msg = unsafe { std::ffi::CStr::from_ptr(err_msg) }
        .to_string_lossy()
        .into_owned();
    assert!(
        msg.contains("stage"),
        "the message must be the core's explanation, got {msg:?}",
    );
    unsafe {
        sandlock_string_free(err_msg);
        sandlock_sandbox_free(policy);
    }
}

/// The discriminant that justifies the whole design: a commit that cannot take
/// the workdir lock is distinguishable from every other failure, and the change
/// set is still on disk.
///
/// Contention is `SANDLOCK_TXN_CONFLICT` (4), not `SANDLOCK_TXN_COMMIT_LOCK`
/// (5): the core reserves the latter for a lock that failed for a reason other
/// than another commit holding it.
#[test]
fn txn_commit_lock_contention_is_its_own_discriminant() {
    if !sandbox_available() {
        eprintln!("txn conflict test skipped: sandbox unavailable");
        return;
    }
    let workdir = tempfile::tempdir().unwrap();
    let storage = tempfile::tempdir().unwrap();
    let policy = build_policy(Some(workdir.path()), Some(storage.path()));

    let txn = sandlock_txn_new();
    for cmd in ["echo plan > a.txt", "cat a.txt && echo built > b.txt"] {
        let (_owned, ptrs) = argv(&["sh", "-c", cmd]);
        unsafe { sandlock_txn_add_stage(txn, policy, ptrs.as_ptr(), ptrs.len() as c_uint) };
    }
    unsafe { sandlock_txn_commit_lock_wait_ms(txn, 300) };

    // Stand in for another transaction mid-merge by holding the workdir lock,
    // exactly as the core suite does.
    let held = std::fs::File::open(workdir.path()).unwrap();
    assert_eq!(
        unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0,
        "test setup: could not take the workdir lock",
    );

    let started = std::time::Instant::now();
    let mut err: c_int = -99;
    let mut err_msg: *mut c_char = ptr::null_mut();
    let outcome = unsafe { sandlock_txn_run(txn, 0, &mut err, &mut err_msg) };
    let waited = started.elapsed();
    drop(held);

    // The 300 ms bound set above has to reach the core: unset, the core waits
    // its own default of 30 seconds. The threshold is generous because the
    // stages themselves have to run first and that cost is host dependent;
    // what it separates is 300 ms from 30 s, not one host from another.
    assert!(
        waited < std::time::Duration::from_secs(10),
        "the commit-lock wait set on the handle was not applied: gave up after {waited:?}",
    );

    assert!(outcome.is_null());
    assert_eq!(
        err, TXN_CONFLICT,
        "losing the commit lock to contention must report the retryable discriminant",
    );
    assert!(!err_msg.is_null());
    let msg = unsafe { std::ffi::CStr::from_ptr(err_msg) }
        .to_string_lossy()
        .into_owned();
    unsafe { sandlock_string_free(err_msg) };

    // The one thing the caller cannot reconstruct from anywhere else is where
    // the change set went, so the message has to name it and it has to exist.
    let branches: Vec<std::path::PathBuf> = std::fs::read_dir(storage.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(
        branches.len(),
        1,
        "a fully successful run whose commit failed must keep its upper; found {branches:?}",
    );
    let upper = branches[0].join("upper");
    assert!(
        msg.contains(upper.to_str().unwrap()),
        "the message must name the preserved upper; got {msg:?}",
    );
    assert_eq!(
        std::fs::read_to_string(upper.join("b.txt")).unwrap(),
        "built\n",
        "the preserved upper must still hold the last stage's write",
    );
    assert!(
        !workdir.path().join("a.txt").exists(),
        "nothing may be merged when the lock was never taken",
    );
    unsafe { sandlock_sandbox_free(policy) };
}

/// A null handle is a bug in the binding layer, not a transaction verdict, so
/// it gets a code and deliberately no message, exactly as
/// `sandlock_sandbox_build` does.
#[test]
fn txn_run_reports_a_null_handle_without_inventing_a_message() {
    let sentinel = CString::new("must be overwritten").unwrap();
    for dry in [false, true] {
        let mut err: c_int = -99;
        let mut err_msg: *mut c_char = sentinel.as_ptr() as *mut c_char;
        let outcome = unsafe {
            if dry {
                sandlock_txn_dry_run(ptr::null_mut(), 0, &mut err, &mut err_msg)
            } else {
                sandlock_txn_run(ptr::null_mut(), 0, &mut err, &mut err_msg)
            }
        };
        assert!(outcome.is_null(), "dry={dry}");
        assert_eq!(err, TXN_NULL_HANDLE, "dry={dry}");
        assert!(
            err_msg.is_null(),
            "err_msg must be cleared on entry, not left as the caller found it",
        );
    }
    // Both out-parameters are optional even on the null-handle path.
    unsafe {
        assert!(sandlock_txn_run(ptr::null_mut(), 0, ptr::null_mut(), ptr::null_mut()).is_null());
        assert!(
            sandlock_txn_dry_run(ptr::null_mut(), 0, ptr::null_mut(), ptr::null_mut()).is_null()
        );
    }
}

#[test]
fn txn_outcome_accessors_tolerate_a_null_outcome() {
    unsafe {
        assert_eq!(sandlock_txn_outcome_disposition(ptr::null()), -1);
        assert_eq!(sandlock_txn_outcome_stages_len(ptr::null()), 0);
        assert!(sandlock_txn_outcome_stage_at(ptr::null(), 0).is_null());
        assert_eq!(sandlock_txn_outcome_changes_len(ptr::null()), 0);
        assert_eq!(sandlock_txn_outcome_change_kind(ptr::null(), 0), 0);
        assert!(sandlock_txn_outcome_change_path(ptr::null(), 0).is_null());
        sandlock_txn_outcome_free(ptr::null_mut());
    }
}
