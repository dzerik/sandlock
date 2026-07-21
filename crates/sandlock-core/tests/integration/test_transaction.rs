//! Transaction tests (RFC #65 Phase 1).
//!
//! Sequential stages share one COW upper over a common workdir: a later stage
//! sees an earlier stage's writes (read-committed), and the whole transaction
//! commits all-or-nothing. Data is exchanged through the shared workspace, not
//! inter-stage pipes.

use sandlock_core::sandbox::BranchAction;
use sandlock_core::{Sandbox, Stage, Transaction};
use std::fs;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sandlock-test-txn-{}-{}", name, std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let _ = fs::create_dir_all(&dir);
    dir
}

/// Base policy shared by every stage: read the system, write+COW the workdir,
/// and run with the workdir as cwd so relative paths resolve into the upper.
/// `on_exit`/`on_error` are left at their defaults (the transaction owns commit).
fn stage_policy(workdir: &Path) -> Sandbox {
    Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc")
        .fs_write(workdir)
        .workdir(workdir)
        .cwd(workdir)
        .build()
        .unwrap()
}

/// Whether this environment can actually run a sandbox (Landlock + seccomp). Used
/// to skip the behavioral tests EXPLICITLY, so a real regression in the
/// transaction logic hard-fails instead of hiding behind a tolerated error.
async fn sandbox_available() -> bool {
    let mut sb = Sandbox::builder().fs_read("/usr").fs_read("/bin").build().unwrap();
    matches!(sb.run(&["true"]).await, Ok(r) if r.success())
}

/// Number of branch subdirectories under a `fs_storage` dir. Zero means every COW
/// branch's upper has been reclaimed (committed or aborted or dropped).
fn branch_count(storage: &Path) -> usize {
    fs::read_dir(storage).map(|rd| rd.count()).unwrap_or(0)
}

/// Full success: stage 1 writes `a.txt`, stage 2 reads it (proving read-committed)
/// and writes `b.txt`, stage 3 reads both. On commit both files land in workdir.
#[tokio::test]
async fn test_txn_commits_on_success() {
    if !sandbox_available().await {
        eprintln!("commit test skipped: sandbox unavailable");
        return;
    }
    let workdir = temp_dir("commit");
    let policy = stage_policy(&workdir);

    let txn = Transaction::new([
        Stage::new(&policy, &["sh", "-c", "echo plan > a.txt"]),
        Stage::new(&policy, &["sh", "-c", "cat a.txt && echo built > b.txt"]),
        Stage::new(&policy, &["sh", "-c", "cat a.txt b.txt"]),
    ]);

    let outcome = txn.run(None).await.expect("transaction should run");
    assert!(outcome.committed, "transaction should commit; abort_reason: {:?}", outcome.abort_reason);
    assert_eq!(outcome.stages.len(), 3, "all three stages should have run");
    assert!(workdir.join("a.txt").exists(), "a.txt must be committed to workdir");
    assert!(workdir.join("b.txt").exists(), "b.txt must be committed to workdir");
    assert_eq!(fs::read_to_string(workdir.join("a.txt")).unwrap(), "plan\n");

    let _ = fs::remove_dir_all(&workdir);
}

/// The commit merge is serialized against another transaction's merge, and a
/// transaction that finds the workdir locked WAITS for it rather than
/// discarding a full run's work. The lock is released mid-run, so the
/// transaction must still commit.
#[tokio::test]
async fn test_txn_waits_for_a_concurrent_commit_lock() {
    if !sandbox_available().await {
        eprintln!("commit-lock-wait test skipped: sandbox unavailable");
        return;
    }
    let workdir = temp_dir("commit-lock-wait");
    let policy = stage_policy(&workdir);

    // Stand in for another transaction mid-merge by holding the workdir lock,
    // then releasing it while this transaction's stages are still running.
    let held = std::fs::File::open(&workdir).unwrap();
    assert_eq!(
        unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0,
        "test setup: could not take the workdir lock"
    );
    let releaser = tokio::task::spawn_blocking(move || {
        std::thread::sleep(Duration::from_millis(400));
        drop(held);
    });

    let outcome = Transaction::new([
        Stage::new(&policy, &["sh", "-c", "echo plan > a.txt"]),
        Stage::new(&policy, &["sh", "-c", "cat a.txt && echo built > b.txt"]),
    ])
    .run(None)
    .await
    .expect("transaction should run");
    releaser.await.unwrap();

    assert!(
        outcome.committed,
        "a transaction must wait out a concurrent commit, not lose its work; abort_reason: {:?}",
        outcome.abort_reason
    );
    assert!(workdir.join("a.txt").exists() && workdir.join("b.txt").exists());

    let _ = fs::remove_dir_all(&workdir);
}

/// Any stage failing aborts the whole transaction: earlier stages' writes are
/// discarded and the workdir is byte-identical to before the run.
#[tokio::test]
async fn test_txn_aborts_on_stage_failure() {
    if !sandbox_available().await {
        eprintln!("abort test skipped: sandbox unavailable");
        return;
    }
    let workdir = temp_dir("abort");
    fs::write(workdir.join("existing.txt"), "original\n").unwrap();
    let policy = stage_policy(&workdir);

    // Stage 2 writes b.txt but the final stage exits non-zero → abort all.
    let txn = Transaction::new([
        Stage::new(&policy, &["sh", "-c", "echo plan > a.txt"]),
        Stage::new(&policy, &["sh", "-c", "cat a.txt && echo built > b.txt"]),
        Stage::new(&policy, &["sh", "-c", "exit 1"]),
    ]);

    let outcome = txn.run(None).await.expect("transaction should run");
    assert!(!outcome.committed, "a failing stage must abort the transaction");
    assert!(outcome.abort_reason.is_some(), "abort must carry a reason");
    assert!(!workdir.join("a.txt").exists(), "a.txt must NOT leak after abort");
    assert!(!workdir.join("b.txt").exists(), "b.txt must NOT leak after abort");
    assert_eq!(fs::read_to_string(workdir.join("existing.txt")).unwrap(), "original\n");

    let _ = fs::remove_dir_all(&workdir);
}

/// The shared upper is reclaimed from disk after BOTH abort and commit — the
/// end-to-end check that a failed/completed transaction never orphans its upper.
#[tokio::test]
async fn test_txn_reclaims_upper() {
    if !sandbox_available().await {
        eprintln!("reclaim test skipped: sandbox unavailable");
        return;
    }
    let workdir = temp_dir("reclaim-wd");
    let storage = temp_dir("reclaim-st");
    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc")
        .fs_write(&workdir).workdir(&workdir).cwd(&workdir)
        .fs_storage(&storage)
        .build()
        .unwrap();

    // Abort path: the upper must be gone from the storage dir.
    let aborted = Transaction::new([
        Stage::new(&policy, &["sh", "-c", "echo x > a.txt"]),
        Stage::new(&policy, &["sh", "-c", "exit 1"]),
    ])
        .run(None).await.expect("transaction should run");
    assert!(!aborted.committed);
    assert_eq!(branch_count(&storage), 0, "aborted transaction must reclaim its upper from the storage dir");

    // Commit path: also reclaimed after the merge.
    let committed = Transaction::new([
        Stage::new(&policy, &["sh", "-c", "echo y > b.txt"]),
        Stage::new(&policy, &["sh", "-c", "cat b.txt"]),
    ])
        .run(None).await.expect("transaction should run");
    assert!(committed.committed);
    assert_eq!(branch_count(&storage), 0, "committed transaction must reclaim its upper from the storage dir");

    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_dir_all(&storage);
}

/// A transaction timeout aborts the whole transaction without leaking earlier
/// stages' writes into the workdir.
#[tokio::test]
async fn test_txn_timeout_aborts() {
    if !sandbox_available().await {
        eprintln!("timeout test skipped: sandbox unavailable");
        return;
    }
    let workdir = temp_dir("timeout");
    let policy = stage_policy(&workdir);

    let txn = Transaction::new([
        Stage::new(&policy, &["sh", "-c", "echo plan > a.txt"]),
        Stage::new(&policy, &["sh", "-c", "sleep 30"]),
    ]);

    let outcome = txn
        .run(Some(Duration::from_millis(600)))
        .await
        .expect("transaction should run");
    assert!(!outcome.committed, "a timed-out transaction must abort");
    assert!(
        outcome.abort_reason.as_deref().unwrap_or("").contains("timed out"),
        "abort reason should mention the timeout, got: {:?}",
        outcome.abort_reason
    );
    assert!(!workdir.join("a.txt").exists(), "a.txt must NOT leak after a timeout abort");

    let _ = fs::remove_dir_all(&workdir);
}

/// Guardrail: a non-default `on_exit`/`on_error` conflicts with the transaction
/// owning commit/abort, and is rejected before anything runs. (No sandbox needed.)
#[tokio::test]
async fn test_txn_rejects_branch_action() {
    let workdir = temp_dir("guard-action");
    let plain = stage_policy(&workdir);
    let with_action = Sandbox::builder()
        .fs_read("/usr").fs_write(&workdir).workdir(&workdir)
        .on_exit(BranchAction::Keep)
        .build()
        .unwrap();

    let txn = Transaction::new([Stage::new(&plain, &["true"]), Stage::new(&with_action, &["true"])]);
    let err = txn.run(None).await.unwrap_err().to_string();
    assert!(err.contains("on_exit/on_error"), "expected the on_exit guardrail, got: {err}");

    let _ = fs::remove_dir_all(&workdir);
}

/// Guardrail: every stage must set a workdir (the shared transaction dir).
#[tokio::test]
async fn test_txn_rejects_missing_workdir() {
    let workdir = temp_dir("guard-workdir");
    let with_wd = stage_policy(&workdir);
    let no_wd = Sandbox::builder().fs_read("/usr").build().unwrap();

    let txn = Transaction::new([Stage::new(&with_wd, &["true"]), Stage::new(&no_wd, &["true"])]);
    let err = txn.run(None).await.unwrap_err().to_string();
    assert!(err.contains("no workdir"), "expected the workdir guardrail, got: {err}");

    let _ = fs::remove_dir_all(&workdir);
}

/// Guardrail: fewer than two stages is rejected, not a panic. `Transaction::new`
/// accepts any stage list, so this check is the only thing between a one-stage
/// transaction and an out-of-bounds index in the coordinator.
#[tokio::test]
async fn test_txn_rejects_too_few_stages() {
    let workdir = temp_dir("guard-count");
    let policy = stage_policy(&workdir);
    let single = Transaction::new([Stage::new(&policy, &["true"])]);
    let err = single.run(None).await.unwrap_err().to_string();
    assert!(err.contains("at least 2 stages"), "expected the stage-count guardrail, got: {err}");

    let _ = fs::remove_dir_all(&workdir);
}

/// Guardrail: stages that each set a workdir but a DIFFERENT one are rejected —
/// distinct from the missing-workdir case (they share one COW upper).
#[tokio::test]
async fn test_txn_rejects_mismatched_workdir() {
    let wd1 = temp_dir("guard-wd-a");
    let wd2 = temp_dir("guard-wd-b");
    let s0 = stage_policy(&wd1);
    let s1 = stage_policy(&wd2); // valid workdir, but not the same one
    let txn = Transaction::new([Stage::new(&s0, &["true"]), Stage::new(&s1, &["true"])]);
    let err = txn.run(None).await.unwrap_err().to_string();
    assert!(err.contains("share one workdir"), "expected the shared-workdir guardrail, got: {err}");

    let _ = fs::remove_dir_all(&wd1);
    let _ = fs::remove_dir_all(&wd2);
}

/// Guardrail: a stage running without the supervisor cannot participate in a COW
/// transaction (no notif path to build/commit the shared upper).
#[tokio::test]
async fn test_txn_rejects_no_supervisor() {
    let workdir = temp_dir("guard-nosup");
    let ok = stage_policy(&workdir);
    // Same workdir (so the workdir guardrail doesn't fire first) but no supervisor.
    let nosup = Sandbox::builder()
        .fs_read("/usr").fs_write(&workdir).workdir(&workdir).cwd(&workdir)
        .no_supervisor(true)
        .build()
        .unwrap();
    let txn = Transaction::new([Stage::new(&ok, &["true"]), Stage::new(&nosup, &["true"])]);
    let err = txn.run(None).await.unwrap_err().to_string();
    assert!(err.contains("no_supervisor"), "expected the no_supervisor guardrail, got: {err}");

    let _ = fs::remove_dir_all(&workdir);
}

/// Guardrail: chroot is unsupported with a shared COW workdir (the workdir path
/// can't resolve the same across differing roots).
#[tokio::test]
async fn test_txn_rejects_chroot() {
    let workdir = temp_dir("guard-chroot");
    let rootfs = temp_dir("guard-chroot-root");
    let ok = stage_policy(&workdir);
    let with_chroot = Sandbox::builder()
        .fs_read("/usr").fs_write(&workdir).workdir(&workdir).cwd(&workdir)
        .chroot(&rootfs)
        .build()
        .unwrap();
    let txn = Transaction::new([Stage::new(&ok, &["true"]), Stage::new(&with_chroot, &["true"])]);
    let err = txn.run(None).await.unwrap_err().to_string();
    assert!(err.contains("chroot"), "expected the chroot guardrail, got: {err}");

    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_dir_all(&rootfs);
}

/// Guardrail: stages must share one COW upper, so differing fs_storage/max_disk
/// (here stage 1 sets fs_storage while stage 0 does not) is rejected.
#[tokio::test]
async fn test_txn_rejects_mismatched_fs_storage() {
    let workdir = temp_dir("guard-store-wd");
    let storage = temp_dir("guard-store-st");
    let s0 = stage_policy(&workdir); // no fs_storage
    let s1 = Sandbox::builder()
        .fs_read("/usr").fs_write(&workdir).workdir(&workdir).cwd(&workdir)
        .fs_storage(&storage)
        .build()
        .unwrap();
    let txn = Transaction::new([Stage::new(&s0, &["true"]), Stage::new(&s1, &["true"])]);
    let err = txn.run(None).await.unwrap_err().to_string();
    assert!(err.contains("fs_storage/max_disk"), "expected the fs_storage guardrail, got: {err}");

    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_dir_all(&storage);
}

/// Boundary: the FIRST stage failing aborts, and the transaction STOPS — later
/// stages must not run (outcome.stages holds only the failed stage). Distinct
/// from the last-stage-failure case.
#[tokio::test]
async fn test_txn_aborts_on_first_stage_failure() {
    if !sandbox_available().await {
        eprintln!("first-fail test skipped: sandbox unavailable");
        return;
    }
    let workdir = temp_dir("first-fail");
    let policy = stage_policy(&workdir);
    // Stage 0 writes a.txt then exits non-zero; stages 1 and 2 must NOT run.
    let txn = Transaction::new([
        Stage::new(&policy, &["sh", "-c", "echo a > a.txt; exit 1"]),
        Stage::new(&policy, &["sh", "-c", "echo b > b.txt"]),
        Stage::new(&policy, &["sh", "-c", "echo c > c.txt"]),
    ]);

    let outcome = txn.run(None).await.expect("transaction should run");
    assert!(!outcome.committed, "first-stage failure must abort");
    assert_eq!(outcome.stages.len(), 1, "transaction must stop at the failed stage — later stages must not run");
    assert!(!workdir.join("a.txt").exists(), "a.txt must NOT leak after abort");
    assert!(!workdir.join("b.txt").exists(), "stage 2 must not have run");
    assert!(!workdir.join("c.txt").exists(), "stage 3 must not have run");

    let _ = fs::remove_dir_all(&workdir);
}

/// Combination: a timeout aborts AND reclaims the shared upper (no orphan on the
/// timeout path — the reclaim test only covered clean abort/commit).
#[tokio::test]
async fn test_txn_timeout_reclaims_upper() {
    if !sandbox_available().await {
        eprintln!("timeout-reclaim test skipped: sandbox unavailable");
        return;
    }
    let workdir = temp_dir("to-reclaim-wd");
    let storage = temp_dir("to-reclaim-st");
    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc")
        .fs_write(&workdir).workdir(&workdir).cwd(&workdir)
        .fs_storage(&storage)
        .build()
        .unwrap();

    let outcome = Transaction::new([
        Stage::new(&policy, &["sh", "-c", "echo x > a.txt"]),
        Stage::new(&policy, &["sh", "-c", "sleep 30"]),
    ])
        .run(Some(Duration::from_millis(600)))
        .await
        .expect("transaction should run");
    assert!(!outcome.committed, "timed-out transaction must abort");
    assert_eq!(branch_count(&storage), 0, "timed-out transaction must reclaim its upper from the storage dir");

    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_dir_all(&storage);
}

/// COW deletion (whiteout) semantics through commit AND abort:
///   - commit: a stage deleting a pre-existing workdir file removes it from the
///     workdir, and a later stage sees the deletion (read-committed);
///   - abort: the deletion is discarded — the file survives byte-identical.
#[tokio::test]
async fn test_txn_deletion_commit_applies_abort_preserves() {
    if !sandbox_available().await {
        eprintln!("deletion test skipped: sandbox unavailable");
        return;
    }
    // Commit path.
    let wd_c = temp_dir("del-commit");
    fs::write(wd_c.join("keep.txt"), "orig\n").unwrap();
    let p_c = stage_policy(&wd_c);
    let committed = Transaction::new([
        Stage::new(&p_c, &["sh", "-c", "rm keep.txt"]),
        Stage::new(&p_c, &["sh", "-c", "test ! -e keep.txt"]),
    ])  // stage 2 must SEE the deletion
        .run(None)
        .await
        .expect("transaction should run");
    assert!(committed.committed, "commit expected; abort_reason: {:?}", committed.abort_reason);
    assert!(!wd_c.join("keep.txt").exists(), "committed deletion must remove keep.txt from the workdir");

    // Abort path: same deletion, but the transaction aborts → deletion discarded.
    let wd_a = temp_dir("del-abort");
    fs::write(wd_a.join("keep.txt"), "orig\n").unwrap();
    let p_a = stage_policy(&wd_a);
    let aborted = Transaction::new([
        Stage::new(&p_a, &["sh", "-c", "rm keep.txt"]),
        Stage::new(&p_a, &["sh", "-c", "exit 1"]),
    ])
        .run(None)
        .await
        .expect("transaction should run");
    assert!(!aborted.committed, "abort expected");
    assert_eq!(
        fs::read_to_string(wd_a.join("keep.txt")).unwrap(), "orig\n",
        "aborted deletion must leave keep.txt intact in the workdir",
    );

    let _ = fs::remove_dir_all(&wd_c);
    let _ = fs::remove_dir_all(&wd_a);
}
