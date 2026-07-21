//! Filesystem transactions — sequential sandboxed stages over one shared COW
//! workdir, committed all-or-nothing (RFC #65).
//!
//! A transaction is **not** a pipeline. [`Pipeline`](crate::pipeline::Pipeline)
//! is the `|` operator: N stages running *concurrently*, each stage's stdout
//! wired to the next stage's stdin through a kernel pipe. A [`Transaction`]
//! runs its stages *sequentially* with **no inter-stage pipes and all stdio
//! inherited from the parent**; stages exchange data by reading and writing a
//! shared workspace, not by streaming bytes. The two are separate types
//! precisely so a `|`-built chain cannot be handed to the sequential runner and
//! silently lose its pipes.
//!
//! ```ignore
//! let outcome = Transaction::new([
//!     Stage::new(&policy, &["sh", "-c", "echo plan > a.txt"]),
//!     Stage::new(&policy, &["sh", "-c", "cat a.txt && echo built > b.txt"]),
//! ]).run(None).await?;
//! assert!(outcome.committed);
//! ```

use std::os::unix::io::AsRawFd;
use std::time::Duration;

use crate::error::{SandboxRuntimeError, SandlockError};
use crate::pipeline::Stage;
use crate::result::{ExitStatus, RunResult};

// ============================================================
// Transaction
// ============================================================

/// A set of stages run sequentially over one shared COW workdir, committed
/// all-or-nothing.
///
/// Stages run **in declaration order, one at a time**, sharing a single COW
/// upper layered over their common workdir: stage N+1 sees stage N's writes
/// (read-committed) while the real workdir stays untouched for the duration of
/// the run. If every stage exits 0 the shared upper is merged into the workdir
/// in one step; if any stage fails, or the transaction times out, the upper is
/// discarded and the workdir is byte-identical to before the run.
///
/// **Stages are not connected by pipes.** Each stage inherits the parent's
/// stdin, stdout and stderr; data moves between stages through the shared
/// workspace. This is why a `Transaction` cannot be built with `|` — see the
/// [module docs](self).
///
/// Every stage must set the same `workdir`, run with the supervisor
/// (`no_supervisor == false`), leave `on_exit`/`on_error` at their defaults, set
/// no `chroot`, and set the same `fs_storage`/`max_disk`. The transaction owns
/// the single shared upper and its commit/abort, so a per-stage override would
/// conflict and is rejected before anything runs.
pub struct Transaction {
    stages: Vec<Stage>,
}

impl Transaction {
    /// Build a transaction from an explicit list of stages (at least 2).
    ///
    /// There is deliberately no `From<Pipeline>` and no `BitOr` impl: a
    /// `|`-built chain means "connect these by pipes", which a transaction does
    /// not do.
    pub fn new(stages: impl IntoIterator<Item = Stage>) -> Self {
        Self { stages: stages.into_iter().collect() }
    }

    /// Run every stage, then commit the shared upper if all of them exited 0.
    ///
    /// `timeout` applies to the stage phase as a whole; on expiry the
    /// transaction aborts and the workdir is untouched.
    ///
    /// The final commit is **not crash-atomic**: it merges the shared upper into
    /// the workdir file-by-file, so a crash (or `ENOSPC`) *mid-commit* can leave
    /// the workdir partially merged. The all-or-nothing guarantee holds for a
    /// clean stage failure or timeout (nothing is written until the commit
    /// starts); durable crash-atomic commit is a later phase.
    pub async fn run(self, timeout: Option<Duration>) -> Result<TxnOutcome, SandlockError> {
        validate_txn_stages(&self.stages)?;
        run_txn(self.stages, timeout).await
    }
}

// ============================================================
// Outcome
// ============================================================

/// Outcome of [`Transaction::run`].
#[derive(Debug, Clone)]
pub struct TxnOutcome {
    /// True if every stage exited 0 and the shared upper was committed to the
    /// workdir. False if any stage failed (or the pipeline timed out) and the
    /// upper was discarded, leaving the workdir byte-identical.
    pub committed: bool,
    /// Per-stage results in execution order. On a stage-failure abort this holds
    /// the stages that ran, up to and including the one that failed. On a timeout
    /// or driver-error abort it is empty: the in-flight stage-driver future is
    /// cancelled and its accumulated results are dropped (`committed` and
    /// `abort_reason` still report the outcome).
    pub stages: Vec<RunResult>,
    /// Human-readable reason the transaction aborted; `None` when committed.
    pub abort_reason: Option<String>,
}

/// Reject stage configurations that can't participate in a transaction. The
/// pipeline owns the single shared upper and the single commit/abort, so each
/// stage must set the same workdir, keep the supervisor, and not carry its own
/// branch action.
fn validate_txn_stages(stages: &[Stage]) -> Result<(), SandlockError> {
    fn reject(msg: impl Into<String>) -> SandlockError {
        SandlockError::Runtime(SandboxRuntimeError::Child(msg.into()))
    }

    // `Pipeline::new` enforces >= 2, but the struct is constructible directly;
    // check here so `run_transactional` never indexes `stages[0]` out of bounds.
    if stages.len() < 2 {
        return Err(reject("transaction requires at least 2 stages"));
    }

    let base = &stages[0].sandbox;
    let base_wd = base.workdir.as_ref().ok_or_else(|| {
        reject("transaction: stage 0 has no workdir; every stage must set the shared transaction workdir")
    })?;
    let base_max_disk = base.max_disk.map(|b| b.0).unwrap_or(0);

    for (i, stage) in stages.iter().enumerate() {
        let sb = &stage.sandbox;
        let wd = sb.workdir.as_ref().ok_or_else(|| {
            reject(format!("transaction: stage {i} has no workdir; every stage must set the shared transaction workdir"))
        })?;
        if wd != base_wd {
            return Err(reject(format!(
                "transaction: stages must share one workdir (stage 0 = {}, stage {i} = {})",
                base_wd.display(),
                wd.display()
            )));
        }
        if sb.no_supervisor {
            return Err(reject(format!(
                "transaction: stage {i} has no_supervisor=true; transactions require the COW supervisor"
            )));
        }
        // All stages overlay ONE shared upper, so per-stage COW storage/quota and
        // chroot can't each take effect — reject a stage that sets them differently
        // (or at all, for chroot) rather than silently using only stage 0's.
        if sb.chroot.is_some() {
            return Err(reject(format!(
                "transaction: stage {i} sets chroot, which is unsupported with a shared COW workdir"
            )));
        }
        if sb.fs_storage != base.fs_storage || sb.max_disk.map(|b| b.0).unwrap_or(0) != base_max_disk {
            return Err(reject(format!(
                "transaction: stage {i} sets a different fs_storage/max_disk; all stages share one COW upper, so these must match stage 0"
            )));
        }
        // The builder leaves both actions at `BranchAction::Commit` by default
        // (`unwrap_or_default()`); anything else is an explicit per-stage choice
        // that conflicts with the transaction owning commit/abort.
        if sb.on_exit != crate::sandbox::BranchAction::Commit
            || sb.on_error != crate::sandbox::BranchAction::Commit
        {
            return Err(reject(format!(
                "transaction: stage {i} sets on_exit/on_error, which conflicts with a transaction (the transaction owns commit/abort) — leave them at their defaults"
            )));
        }
    }
    Ok(())
}

/// Create the shared COW branch, drive the stages sequentially over it, then
/// commit-all or abort-all. The branch lives here (outside the driven future)
/// so a timeout that cancels the stage loop can still abort cleanly.
async fn run_txn(
    stages: Vec<Stage>,
    timeout: Option<Duration>,
) -> Result<TxnOutcome, SandlockError> {
    fn child_err(msg: String) -> SandlockError {
        SandlockError::Runtime(SandboxRuntimeError::Child(msg))
    }

    // All stages share the validated workdir; take COW storage/quota from the
    // first stage (they overlay the same lower).
    let base = &stages[0].sandbox;
    let workdir = base.workdir.clone().expect("validated: stage 0 has a workdir");
    let storage = base.fs_storage.clone();
    let max_disk = base.max_disk.map(|b| b.0).unwrap_or(0);

    let branch = crate::cow::seccomp::SeccompCowBranch::create(&workdir, storage.as_deref(), max_disk)
        .map_err(|e| child_err(format!("transaction: failed to create COW branch: {e}")))?;
    let upper_dir = branch.upper_dir().to_path_buf();

    let mut cow_state = crate::seccomp::state::CowState::new();
    cow_state.branch = Some(branch);
    let state = std::sync::Arc::new(tokio::sync::Mutex::new(cow_state));
    let shared = crate::sandbox::SharedCow { state: std::sync::Arc::clone(&state), upper_dir };

    let drive = drive_txn_stages(stages, shared);
    let driven: Result<(bool, Vec<RunResult>, Option<String>), SandlockError> = match timeout {
        Some(dur) => match tokio::time::timeout(dur, drive).await {
            Ok(r) => r,
            Err(_) => Ok((false, Vec::new(), Some("the transaction timed out".to_string()))),
        },
        None => drive.await,
    };

    // Finalize the shared upper in EVERY case — commit only on a clean full run,
    // otherwise discard — before propagating any driver error, so a mid-loop
    // failure never leaves the upper dangling. (`SeccompCowBranch`'s Drop is a
    // further backstop for panics/cancellation; this is the deterministic path.)
    // Take the branch out from under the async mutex first, then commit/abort the
    // owned value so the sync merge doesn't run while holding the guard.
    let taken = { state.lock().await.branch.take() };
    let (all_ok, results, mut reason, drive_err) = match driven {
        Ok((ok, res, rsn)) => (ok, res, rsn, None),
        Err(e) => (false, Vec::new(), Some(format!("{e}")), Some(e)),
    };
    let committed = match taken {
        Some(mut branch) if all_ok => {
            // First-committer-win: take an exclusive, non-blocking lock on the
            // shared workdir for the duration of the merge. commit() rewrites the
            // workdir file-by-file, so two concurrent transactions
            // committing into one workdir would interleave and corrupt it. A
            // transaction that finds the lock held LOSES the race — a benign
            // non-commit outcome (committed=false + abort_reason), not an error,
            // and its upper is aborted. (The lock is scoped to the transactional
            // commit here, not the single-sandbox commit() path.)
            let lock = std::fs::File::open(&workdir).map_err(|e| {
                child_err(format!("transaction: open workdir for commit lock: {e}"))
            })?;
            if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                let err = std::io::Error::last_os_error();
                // EWOULDBLOCK (== EAGAIN on Linux) means another commit holds the
                // lock: lose the race benignly. Any other errno is a real failure.
                if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
                    let _ = branch.abort();
                    reason = Some(
                        "transaction: lost the first-committer-win race \
                         (another commit is in progress on this workdir)"
                            .to_string(),
                    );
                    false
                } else {
                    return Err(child_err(format!(
                        "transaction: commit lock: {err}"
                    )));
                }
            } else {
                branch.commit().map_err(|e| {
                    child_err(format!("transaction: commit failed: {e}"))
                })?;
                drop(lock); // release the workdir lock after the merge
                true
            }
        }
        Some(mut branch) => {
            let _ = branch.abort();
            false
        }
        None => all_ok,
    };
    if let Some(e) = drive_err {
        return Err(e);
    }

    Ok(TxnOutcome {
        committed,
        stages: results,
        abort_reason: if committed { None } else { reason },
    })
}

/// Run each stage to completion in order over the shared upper, with no
/// inter-stage pipes (all stdio inherited). Stops at the first non-zero exit.
async fn drive_txn_stages(
    stages: Vec<Stage>,
    shared: crate::sandbox::SharedCow,
) -> Result<(bool, Vec<RunResult>, Option<String>), SandlockError> {
    let mut results: Vec<RunResult> = Vec::with_capacity(stages.len());
    for (i, stage) in stages.into_iter().enumerate() {
        let cmd_refs: Vec<&str> = stage.args.iter().map(|s| s.as_str()).collect();
        let mut sb = stage.sandbox.with_name(format!("txn-stage-{i}"));
        sb.set_shared_cow(shared.clone())?;
        sb.create_with_io(&cmd_refs, None, None, None).await?;
        sb.start()?;
        let result = sb.wait().await?;

        let status = result.exit_status.clone();
        results.push(result);
        if !matches!(status, ExitStatus::Code(0)) {
            return Ok((
                false,
                results,
                Some(format!("stage {i} did not exit cleanly: {status:?}")),
            ));
        }
    }
    Ok((true, results, None))
}
