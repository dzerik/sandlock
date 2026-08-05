# SPDX-License-Identifier: Apache-2.0
"""Exception hierarchy for Sandlock sandbox operations."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ._sdk import TxnErrorKind  # runtime import would be circular


class SandlockError(Exception):
    """Base exception for all Sandlock errors."""

    pass


class PolicyError(SandlockError):
    """Invalid policy configuration."""

    pass


class SandboxError(SandlockError):
    """Sandbox lifecycle errors."""

    pass


class ForkError(SandboxError):
    """os.fork() failed."""

    pass


class ConfinementError(SandboxError):
    """Landlock/seccomp/chroot confinement failed."""

    pass


class LandlockUnavailableError(ConfinementError):
    """Landlock LSM not available on this kernel."""

    pass


class SeccompError(ConfinementError):
    """seccomp-bpf filter installation failed."""

    pass


class NotifError(SeccompError):
    """Seccomp user notification supervisor error."""

    pass




class ChildError(SandboxError):
    """Child process exited abnormally."""

    pass


class BranchError(SandboxError):
    """COW branch operation failed."""

    pass


class BranchConflictError(BranchError):
    """Commit rejected — a sibling branch already committed (ESTALE)."""

    pass


class TransactionError(SandlockError):
    """A transaction could not be carried out.

    An aborted transaction is *not* this. A stage exiting non-zero, or a run
    that hits its timeout, produces a normal :class:`~sandlock.TxnOutcome`
    whose disposition is ``ABORTED``: the workdir is untouched, which is the
    feature working. This carries the core's named verdicts on a transaction
    it could not carry out at all.

    Two failures deliberately fall outside it and arrive as a plain
    :class:`SandlockError`: a null handle reaching the core, and an async
    runtime that could not be built. Neither is a verdict on a transaction, so
    a retry wrapper that catches only this class will not see them.

    ``kind`` is what makes the failure actionable without parsing English.
    ``CONFLICT`` means another commit held the workdir lock, the change set is
    intact and a retry is the expected response; ``COMMIT_LOCK`` means the lock
    could not be taken for some other reason, so retrying is not. Deciding
    between those two must not require reading the message.

    ``MERGE`` and ``COMMIT_ABANDONED`` are the two where it is not enough, and
    the core says so itself. ``MERGE`` covers both a half-merged workdir with
    the rest preserved and a workdir never touched whose change set no sweep
    will find; only the message separates them. ``COMMIT_ABANDONED`` says less
    still: the commit was cut short and its state is unknown.
    """

    def __init__(self, message: str, kind: "TxnErrorKind"):
        super().__init__(message)
        self.kind = kind


class MemoryProtectError(SandlockError):
    """mprotect(2) failed."""

    pass
