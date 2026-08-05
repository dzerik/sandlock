# SPDX-License-Identifier: Apache-2.0
"""End-to-end coverage for the transaction surface (RFC #65 Phase 1).

These drive real confined processes over a real copy-on-write workdir: the
point of a transaction is what lands on disk, and a mocked commit would prove
nothing about that.

The acceptance case named in RFC #65 is
``test_three_stages_share_one_upper_and_commit_together`` together with
``test_no_file_appears_when_any_stage_exits_non_zero``: the same three-stage
pipeline in its succeeding and its failing half.
"""

from __future__ import annotations

import fcntl
import os
import re
import sys
import time
from pathlib import Path

import pytest

from sandlock import (
    BranchAction,
    Sandbox,
    SandlockError,
    Stage,
    Transaction,
    TransactionError,
    TxnDisposition,
    TxnErrorKind,
)
from sandlock import _sdk


_READABLE = list(dict.fromkeys([
    "/usr", "/lib", "/lib64", "/bin", "/etc", "/proc", "/dev", sys.prefix,
]))


def _sandbox_works() -> bool:
    """Probe whether a sandbox can actually start on this host (Landlock/ABI).

    A host without Landlock cannot answer what a transaction leaves on disk,
    so those tests have to stand down. It says so out loud rather than
    vanishing into a skip count, because a silent skip here would report the
    RFC #65 acceptance case as green without ever having run it.
    """
    try:
        if Sandbox(fs_readable=_READABLE).run(["true"]).success:
            return True
        detail = "a confined `true` did not succeed"
    except Exception as exc:  # noqa: BLE001 - the reason is what gets printed
        detail = f"{type(exc).__name__}: {exc}"
    print(
        f"sandlock transaction tests skipped: no sandbox on this host ({detail}); "
        "the RFC #65 acceptance case did NOT run",
        file=sys.stderr,
    )
    return False


requires_sandbox = pytest.mark.skipif(
    not _sandbox_works(), reason="sandbox cannot start on this host (Landlock/ABI)"
)
"""Applied per test rather than to the module.

The tests that only translate between the ABI and Python (the discriminant
map, the failure codes, the shapes this layer refuses to hand over) need no
sandbox, and a host without Landlock is exactly where a mistranslation would
otherwise go unnoticed for want of anything running at all.
"""


def _workdir(tmp_path):
    """A workdir plus the COW storage its transactions preserve into."""
    workdir, storage = tmp_path / "wd", tmp_path / "st"
    workdir.mkdir()
    storage.mkdir()
    return workdir, storage


def _policy(workdir, storage) -> Sandbox:
    """A stage policy a transaction accepts.

    ``on_error=COMMIT`` is not decoration. The core refuses any stage whose
    ``on_exit``/``on_error`` differ from its own default of ``Commit``, because
    a transaction owns commit and abort for the whole stage set. This
    dataclass defaults ``on_error`` to ``ABORT``, and cannot express "not
    set", so a transaction stage has to say ``COMMIT`` out loud. See
    ``test_a_stage_that_sets_its_own_branch_action_is_rejected``.
    """
    return Sandbox(
        fs_readable=_READABLE,
        workdir=str(workdir),
        fs_storage=str(storage),
        on_error=BranchAction.COMMIT,
    )


# ----------------------------------------------------------------
# RFC #65 acceptance case
# ----------------------------------------------------------------

@requires_sandbox
def test_three_stages_share_one_upper_and_commit_together(tmp_path):
    """Stage 1 writes a.txt, stage 2 reads it and writes b.txt, stage 3 reads both."""
    workdir, storage = _workdir(tmp_path)
    sb = _policy(workdir, storage)

    outcome = Transaction([
        Stage(sb, ["sh", "-c", "echo plan > a.txt"]),
        Stage(sb, ["sh", "-c", "cat a.txt > b.txt"]),
        Stage(sb, ["sh", "-c", "cat a.txt b.txt >&2"]),
    ]).run()

    assert outcome.disposition is TxnDisposition.COMMITTED
    assert outcome.committed is True
    assert [r.exit_code for r in outcome.stages] == [0, 0, 0]
    assert (workdir / "a.txt").read_text() == "plan\n"
    assert (workdir / "b.txt").read_text() == "plan\n", \
        "stage 2 read what stage 1 wrote, so both stages saw one shared upper"
    assert outcome.stages[2].stderr == b"plan\nplan\n", \
        "stage 3 read both files, so the whole set was visible before the commit"


@requires_sandbox
@pytest.mark.parametrize("failing_stage", [1, 2, 3])
def test_no_file_appears_when_any_stage_exits_non_zero(tmp_path, failing_stage):
    """The other half of the acceptance case: all or nothing, whichever stage fails."""
    workdir, storage = _workdir(tmp_path)
    sb = _policy(workdir, storage)

    bodies = [
        "echo plan > a.txt",
        "cat a.txt > b.txt",
        "cat a.txt b.txt > /dev/null",
    ]
    bodies[failing_stage - 1] += "; exit 7"

    outcome = Transaction([Stage(sb, ["sh", "-c", body]) for body in bodies]).run()

    assert outcome.disposition is TxnDisposition.ABORTED
    assert outcome.committed is False
    assert not (workdir / "a.txt").exists()
    assert not (workdir / "b.txt").exists()
    assert list(workdir.iterdir()) == [], "the workdir is exactly as it was"
    assert len(outcome.stages) == failing_stage, \
        "the run stops at the first non-zero stage, and reports every stage that ran"
    assert outcome.stages[-1].exit_code == 7


@requires_sandbox
def test_an_aborted_transaction_does_not_raise(tmp_path):
    """A stage exiting non-zero is the feature working, not an error."""
    workdir, storage = _workdir(tmp_path)
    sb = _policy(workdir, storage)

    outcome = Transaction([
        Stage(sb, ["sh", "-c", "echo plan > a.txt"]),
        Stage(sb, ["sh", "-c", "exit 3"]),
    ]).run()

    assert outcome.disposition is TxnDisposition.ABORTED


@requires_sandbox
def test_stages_sharing_one_sandbox_with_a_policy_fn_all_reach_the_end(tmp_path):
    """One Sandbox across the stages is the documented shape, callback and all.

    ``Sandbox._ensure_native`` rebuilds and overwrites its native policy on
    every call, so building the second stage's policy releases the first one.
    The core clones the policy, but the clone of a ``policy_fn`` keeps a raw
    pointer into the ctypes trampoline that released wrapper owned, so an
    early release is not a wrong answer, it is the interpreter dying on the
    first syscall the first stage makes.
    """
    workdir, storage = _workdir(tmp_path)
    seen: list[str] = []

    def watch(event, ctx):
        seen.append(event.syscall)
        return None  # allow; the point is being called at all, not deciding

    sb = Sandbox(
        fs_readable=_READABLE,
        workdir=str(workdir),
        fs_storage=str(storage),
        on_error=BranchAction.COMMIT,
        policy_fn=watch,
    )

    outcome = Transaction([
        Stage(sb, ["sh", "-c", "echo plan > a.txt"]),
        Stage(sb, ["sh", "-c", "cat a.txt > b.txt"]),
    ]).run()

    assert outcome.committed is True
    assert (workdir / "b.txt").read_text() == "plan\n"
    assert seen, "the callback the stages share was still alive to be called"


# ----------------------------------------------------------------
# Dry run
# ----------------------------------------------------------------

@requires_sandbox
def test_dry_run_reports_the_change_set_and_writes_nothing(tmp_path):
    workdir, storage = _workdir(tmp_path)
    sb = _policy(workdir, storage)

    outcome = Transaction([
        Stage(sb, ["sh", "-c", "echo plan > a.txt"]),
        Stage(sb, ["sh", "-c", "cat a.txt > b.txt"]),
    ]).dry_run()

    assert outcome.disposition is TxnDisposition.DRY_RUN
    assert outcome.committed is False
    assert {(c.kind, c.path) for c in outcome.changes} == {("A", "a.txt"), ("A", "b.txt")}
    assert [r.exit_code for r in outcome.stages] == [0, 0], "the stages really ran"
    assert list(workdir.iterdir()) == [], "a dry run never writes to the workdir"


@requires_sandbox
def test_dry_run_reports_deletions_too(tmp_path):
    workdir, storage = _workdir(tmp_path)
    (workdir / "victim.txt").write_text("bye\n")
    sb = _policy(workdir, storage)

    outcome = Transaction([
        Stage(sb, ["sh", "-c", "rm victim.txt"]),
        Stage(sb, ["sh", "-c", "echo new > n.txt"]),
    ]).dry_run()

    assert ("D", "victim.txt") in {(c.kind, c.path) for c in outcome.changes}
    assert (workdir / "victim.txt").exists(), "the dry run did not carry the deletion out"


# ----------------------------------------------------------------
# Failure discriminants
# ----------------------------------------------------------------

@requires_sandbox
def test_a_rejected_stage_set_raises_with_a_kind(tmp_path):
    workdir, storage = _workdir(tmp_path)
    sb = _policy(workdir, storage)

    with pytest.raises(TransactionError) as ei:
        Transaction([Stage(sb, ["true"])]).run()

    assert ei.value.kind is TxnErrorKind.INVALID
    assert "at least 2 stages" in str(ei.value), "the core's own explanation reaches the caller"


@requires_sandbox
def test_a_stage_that_sets_its_own_branch_action_is_rejected(tmp_path):
    """A plain ``Sandbox`` defaults ``on_error`` to ABORT, and the core says no.

    This is not the binding's verdict: the transaction owns commit and abort,
    so a per-stage branch action is a contradiction the core refuses. The test
    pins the fact that the refusal arrives intact rather than being papered
    over here, because papering over it would run a stage set the caller never
    described.
    """
    workdir, storage = _workdir(tmp_path)
    default = Sandbox(
        fs_readable=_READABLE, workdir=str(workdir), fs_storage=str(storage),
    )

    with pytest.raises(TransactionError) as ei:
        Transaction([
            Stage(default, ["sh", "-c", "true"]),
            Stage(default, ["sh", "-c", "true"]),
        ]).run()

    assert ei.value.kind is TxnErrorKind.INVALID
    assert "on_exit/on_error" in str(ei.value)


@requires_sandbox
def test_a_busy_commit_lock_is_a_conflict(tmp_path):
    """Contention is retryable, and it says so with its own discriminant."""
    workdir, storage = _workdir(tmp_path)
    sb = _policy(workdir, storage)

    held = os.open(str(workdir), os.O_RDONLY)
    try:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(TransactionError) as ei:
            Transaction([
                Stage(sb, ["sh", "-c", "echo plan > a.txt"]),
                Stage(sb, ["sh", "-c", "cat a.txt > b.txt"]),
            ], commit_lock_wait=0.2).run()
    finally:
        os.close(held)

    assert ei.value.kind is TxnErrorKind.CONFLICT, \
        "contention is CONFLICT; COMMIT_LOCK is the lock failing for another reason"
    assert not (workdir / "a.txt").exists(), "the workdir was never touched"


@requires_sandbox
@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory permissions")
def test_a_lock_that_cannot_be_taken_at_all_is_not_a_conflict(tmp_path):
    """The distinction the whole discriminant exists for: retry vs do not retry."""
    workdir, storage = _workdir(tmp_path)
    sb = _policy(workdir, storage)
    os.chmod(workdir, 0o300)  # write and search, but the commit cannot open it
    try:
        with pytest.raises(TransactionError) as ei:
            Transaction([
                Stage(sb, ["sh", "-c", "echo plan > a.txt"]),
                Stage(sb, ["sh", "-c", "true"]),
            ]).run()
    finally:
        os.chmod(workdir, 0o755)

    assert ei.value.kind is TxnErrorKind.COMMIT_LOCK
    assert ei.value.kind is not TxnErrorKind.CONFLICT


@requires_sandbox
def test_the_commit_lock_wait_actually_bounds_the_wait(tmp_path):
    """The parameter has to reach the core, not merely survive validation.

    The core's own default is about 30 seconds on this host, and it also ends
    in CONFLICT, so a wait that is validated and then never sent produces the
    same exception this test would otherwise assert on. The clock is the only
    thing that tells the two apart, which is why the bounds are the assertion.
    """
    workdir, storage = _workdir(tmp_path)
    sb = _policy(workdir, storage)
    wait = 1.0

    held = os.open(str(workdir), os.O_RDONLY)
    started = time.monotonic()
    try:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(TransactionError) as ei:
            Transaction([
                Stage(sb, ["sh", "-c", "true"]),
                Stage(sb, ["sh", "-c", "true"]),
            ], commit_lock_wait=wait).run()
    finally:
        elapsed = time.monotonic() - started
        os.close(held)

    assert ei.value.kind is TxnErrorKind.CONFLICT
    assert elapsed >= wait * 0.8, \
        "giving up sooner than asked means some other duration was sent"
    assert elapsed < 10.0, \
        "the core default is far longer, so this bound is what proves the value arrived"


@requires_sandbox
def test_a_timeout_aborts_instead_of_raising(tmp_path):
    """A run that runs out of time is an aborted outcome, not a failure to run."""
    workdir, storage = _workdir(tmp_path)
    sb = _policy(workdir, storage)

    outcome = Transaction([
        Stage(sb, ["sh", "-c", "echo plan > a.txt"]),
        Stage(sb, ["sleep", "30"]),
    ]).run(timeout=1.0)

    assert outcome.disposition is TxnDisposition.ABORTED
    assert not (workdir / "a.txt").exists()


def test_error_kinds_are_not_interchangeable():
    assert TxnErrorKind.CONFLICT is not TxnErrorKind.COMMIT_LOCK
    assert {k.value for k in TxnErrorKind} == {1, 2, 3, 4, 5, 6, 7, 8}


def test_a_failure_code_this_sdk_does_not_name_arrives_as_unknown():
    """The error taxonomy is append only, so a newer core is a case, not a crash.

    Driven at the translation directly because the reachable path is a core
    newer than this header, which no fixture can conjure: every code the
    installed core can produce is one this SDK already names.
    """
    err = _sdk._txn_failure(len(TxnErrorKind) + 1, b"a reason from a newer core")

    assert isinstance(err, TransactionError)
    assert err.kind is TxnErrorKind.UNKNOWN, \
        "an unnamed code must not be rounded to a plausible neighbour"
    assert str(err) == "a reason from a newer core", \
        "the core's own explanation is what survives when the discriminant does not"


@pytest.mark.parametrize("code,fragment", [
    (-1, "null transaction handle"),
    (-2, "runtime"),
])
def test_the_negative_codes_are_not_transaction_verdicts(code, fragment):
    """Outside the taxonomy on purpose: they say the transaction never ran.

    A retry wrapper keys on ``TransactionError.kind``, so dressing these up as
    a kind would invite a retry of something that has no verdict to retry.
    """
    err = _sdk._txn_failure(code, None)

    assert isinstance(err, SandlockError)
    assert not isinstance(err, TransactionError), \
        "these carry no kind, so they must not arrive wearing one"
    assert fragment in str(err)


# ----------------------------------------------------------------
# Stage shapes the ABI cannot carry
# ----------------------------------------------------------------

@pytest.mark.parametrize("bad,match", [
    ([], "empty argv"),
    ([b"sh", b"-c", b"echo two > \xff.txt"], "not valid UTF-8"),
    (["sh"] * (_sdk._TXN_MAX_ARGC + 1), "at most 4096"),
])
def test_a_stage_the_abi_cannot_carry_is_refused_not_dropped(tmp_path, bad, match):
    """``sandlock_txn_add_stage`` returns void, so a stage it drops says nothing.

    Losing the middle stage of three leaves two valid ones, which the core
    accepts, runs and commits: all-or-nothing broken without a word. So the
    shapes that would be dropped are refused here, naming the stage, instead
    of being handed over and hoping the remainder happens to be invalid.
    """
    workdir, storage = _workdir(tmp_path)
    sb = _policy(workdir, storage)

    with pytest.raises(ValueError, match=match) as ei:
        Transaction([
            Stage(sb, ["sh", "-c", "echo one > a.txt"]),
            Stage(sb, bad),
            Stage(sb, ["sh", "-c", "echo three > c.txt"]),
        ]).run()

    assert "stage 1" in str(ei.value), "the refusal names which stage it is about"
    assert list(workdir.iterdir()) == [], \
        "nothing ran, so nothing partial reached the workdir"


# ----------------------------------------------------------------
# The discriminants must match the C header, not this SDK's memory of it
# ----------------------------------------------------------------

_HEADER = Path(__file__).resolve().parents[2] / "crates/sandlock-ffi/include/sandlock.h"


def _header_constants(prefix: str) -> dict[str, int]:
    text = _HEADER.read_text()
    found = re.findall(rf"^\s*{prefix}([A-Z_]+) = (-?\d+),", text, re.MULTILINE)
    return {name: int(value) for name, value in found}


@pytest.mark.skipif(
    not _HEADER.exists(),
    reason=f"the C header is not in this tree ({_HEADER}); nothing to compare against",
)
@pytest.mark.parametrize("prefix,enum,drop", [
    ("SANDLOCK_TXN_", TxnErrorKind, {"OK"}),
    ("SANDLOCK_TXN_DISPOSITION_", TxnDisposition, set()),
])
def test_discriminants_match_the_c_header(prefix, enum, drop):
    """Guards the one mistake that silently mislabels every failure: a shifted map."""
    from_header = {n: v for n, v in _header_constants(prefix).items() if n not in drop}
    assert from_header, f"no {prefix}* constants found in {_HEADER}"
    if enum is TxnErrorKind:
        # The disposition constants share the SANDLOCK_TXN_ prefix.
        from_header = {n: v for n, v in from_header.items() if not n.startswith("DISPOSITION_")}
    assert {member.name: member.value for member in enum} == from_header


# ----------------------------------------------------------------
# Handle ownership: a run consumes the transaction
# ----------------------------------------------------------------

def _spy_on_txn_free(monkeypatch) -> list[int]:
    calls: list[int] = []
    real = _sdk._lib.sandlock_txn_free

    def spy(handle):
        calls.append(handle)
        return real(handle)

    monkeypatch.setattr(_sdk._lib, "sandlock_txn_free", spy)
    return calls


@requires_sandbox
def test_a_run_never_frees_the_handle_it_handed_over(tmp_path, monkeypatch):
    """``sandlock_txn_run`` consumes the handle on every path; freeing it again is a double free."""
    workdir, storage = _workdir(tmp_path)
    sb = _policy(workdir, storage)
    calls = _spy_on_txn_free(monkeypatch)

    Transaction([
        Stage(sb, ["sh", "-c", "echo plan > a.txt"]),
        Stage(sb, ["sh", "-c", "true"]),
    ]).run()
    assert calls == [], "the successful run took ownership"

    with pytest.raises(TransactionError):
        Transaction([Stage(sb, ["true"])]).run()
    assert calls == [], "a rejected stage set is consumed just the same"


@requires_sandbox
def test_a_transaction_abandoned_before_it_runs_frees_its_handle(tmp_path, monkeypatch):
    """The build-then-abandon path is the only one that may call ``sandlock_txn_free``."""
    workdir, storage = _workdir(tmp_path)
    sb = _policy(workdir, storage)
    calls = _spy_on_txn_free(monkeypatch)

    with pytest.raises(ValueError, match="NUL byte"):
        Transaction([
            Stage(sb, ["sh", "-c", "true"]),
            Stage(sb, ["sh", "-c", "echo \x00"]),
        ]).run()

    assert len(calls) == 1, "the handle nothing consumed was released exactly once"


@requires_sandbox
def test_the_same_transaction_can_be_run_again(tmp_path):
    """Each run builds its own handle, so reuse is not a use after free."""
    workdir, storage = _workdir(tmp_path)
    sb = _policy(workdir, storage)
    txn = Transaction([
        Stage(sb, ["sh", "-c", "echo plan >> a.txt"]),
        Stage(sb, ["sh", "-c", "cat a.txt > b.txt"]),
    ])

    assert txn.run().committed
    assert txn.dry_run().disposition is TxnDisposition.DRY_RUN
    assert txn.run().committed
    assert (workdir / "a.txt").read_text() == "plan\nplan\n", \
        "the second commit appended to what the first one published"


@requires_sandbox
def test_a_rejected_transaction_can_be_rebuilt_and_run(tmp_path):
    workdir, storage = _workdir(tmp_path)
    sb = _policy(workdir, storage)
    rejected = Transaction([Stage(sb, ["true"])])

    for _ in range(2):
        with pytest.raises(TransactionError) as ei:
            rejected.run()
        assert ei.value.kind is TxnErrorKind.INVALID


# ----------------------------------------------------------------
# Durations this ABI cannot express
# ----------------------------------------------------------------

@pytest.mark.parametrize("wait", [0, 0.0, 0.0004, -1])
def test_a_commit_lock_wait_under_a_millisecond_is_refused(tmp_path, wait):
    """0 ms means "use the core default", so a shorter wait must not be silently inflated."""
    workdir, storage = _workdir(tmp_path)
    sb = _policy(workdir, storage)
    txn = Transaction([
        Stage(sb, ["sh", "-c", "true"]),
        Stage(sb, ["sh", "-c", "true"]),
    ], commit_lock_wait=wait)

    with pytest.raises(ValueError, match="commit_lock_wait"):
        txn.run()


@pytest.mark.parametrize("timeout", [0, 0.0004, -1])
def test_a_timeout_under_a_millisecond_is_refused(tmp_path, timeout):
    workdir, storage = _workdir(tmp_path)
    sb = _policy(workdir, storage)
    txn = Transaction([
        Stage(sb, ["sh", "-c", "true"]),
        Stage(sb, ["sh", "-c", "true"]),
    ])

    with pytest.raises(ValueError, match="timeout"):
        txn.run(timeout=timeout)


@requires_sandbox
def test_transaction_error_is_a_sandlock_error(tmp_path):
    workdir, storage = _workdir(tmp_path)
    sb = _policy(workdir, storage)
    with pytest.raises(SandlockError):
        Transaction([Stage(sb, ["true"])]).run()
