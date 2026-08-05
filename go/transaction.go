package sandlock

import (
	"fmt"
	"time"
)

// Stage is one command of a Transaction, bound to the policy it runs under.
//
// A stage's Sandbox is an ordinary policy with two restrictions the core
// enforces across the whole stage set, because a transaction that cannot say
// where its changes go, or that lets one stage decide their fate on its own,
// is not a transaction:
//
//   - Every stage must name the same Workdir, and must leave OnExit and
//     OnError unset. A stage that committed or discarded the shared upper by
//     itself would commit part of the transaction.
//   - FSStorage and MaxDisk must match the first stage's, and Chroot and a
//     supervisor-less policy are refused outright.
//
// The core checks these when the transaction runs and reports its own words
// through TxnError, so a policy that breaks one of them surfaces as
// TxnErrInvalid rather than as a stage that quietly did the wrong thing.
type Stage struct {
	Sandbox *Sandbox
	Args    []string
}

// TxnDisposition is the terminal state of a transaction that ran.
//
// The set is total: a transaction that ran ended in exactly one of these
// three, so a switch over them needs no default arm. Future abort causes are
// funnelled through what an aborted outcome carries, not through a fourth
// state.
type TxnDisposition uint32

const (
	// TxnCommitted: every stage exited 0 and the shared upper was merged into
	// the workdir.
	TxnCommitted TxnDisposition = 0
	// TxnDryRun: every stage exited 0 and the upper was discarded on purpose,
	// so the workdir was never written to.
	TxnDryRun TxnDisposition = 1
	// TxnAborted: a stage exited non-zero, or the stage phase ran out of time.
	// The upper was discarded and the workdir is untouched. Use
	// TxnOutcome.TimedOut to tell the two causes apart.
	TxnAborted TxnDisposition = 2
)

func (d TxnDisposition) String() string {
	switch d {
	case TxnCommitted:
		return "committed"
	case TxnDryRun:
		return "dry-run"
	case TxnAborted:
		return "aborted"
	default:
		return fmt.Sprintf("TxnDisposition(%d)", uint32(d))
	}
}

// TxnErrorKind says why a transaction could not be carried out. It is the
// field to switch on when handling a *TxnError, because the kinds differ in
// what they say about the workdir and about what to do next.
//
// The positive values are append only: a published one never changes meaning,
// and a value this build has no name for must be treated as a failure it
// cannot classify rather than as success. A core whose failure set has grown
// past this build's reports it either as TxnErrUnknown, which is the ABI's own
// catch-all, or as a positive value named in a later ABI and not here. Having a
// name and being a verdict are different properties: the second is the sign.
//
// The two negative values are deliberately not verdicts on a transaction: they
// report that nothing can be said about the workdir at all. Keep them out of a
// switch over the named failures; IsVerdict is the guard.
type TxnErrorKind int

const (
	// TxnErrNoRuntime: this thread's async runtime could not be built, or it
	// panicked while driving the transaction. Not a verdict: the transaction
	// may well have run, and nothing here can say what state it left behind.
	// The cause has already been reported on this process's standard error.
	TxnErrNoRuntime TxnErrorKind = -2
	// TxnErrNullHandle: a bug in this binding rather than a failed
	// transaction. Nothing was attempted. Not a verdict.
	TxnErrNullHandle TxnErrorKind = -1

	// TxnErrInvalid: the stage set is not a valid transaction. Checked before
	// anything runs, so nothing ran.
	TxnErrInvalid TxnErrorKind = 1
	// TxnErrBranch: the shared copy-on-write branch could not be created. No
	// stage ran.
	TxnErrBranch TxnErrorKind = 2
	// TxnErrStage: a stage could not be started or driven to completion. This
	// is not a stage that FAILED: a non-zero exit is an aborted outcome with a
	// nil error, not one of these.
	TxnErrStage TxnErrorKind = 3
	// TxnErrConflict: another commit held the workdir lock for longer than
	// CommitLockWait. The workdir is untouched and the whole change set was
	// preserved under the policy's FSStorage, so retrying is the expected
	// response. This is the retryable one; TxnErrCommitLock, its neighbour, is
	// not.
	//
	// A retry does not reclaim what the failed attempt preserved: it runs a new
	// branch and leaves the old change set where it is, so a loop that retries
	// contention without ever removing one fills the storage base with a full
	// copy of the stages' output per attempt. ListPreserved finds them and
	// removing PreservedBranch.BranchDir is what closes the recovery; nothing
	// in this package does it for the caller.
	TxnErrConflict TxnErrorKind = 4
	// TxnErrCommitLock: the workdir commit lock could not be taken for a
	// reason other than contention (the workdir could not be opened, or the
	// lock call itself failed). As with TxnErrConflict the workdir is
	// untouched and the change set was preserved, but retrying will not help
	// until whatever stopped the lock is fixed.
	TxnErrCommitLock TxnErrorKind = 5
	// TxnErrMerge: the commit merge failed. The merge is not rolled back, so
	// the workdir may be partially merged. What did not land was preserved
	// WHEN a marker could be written for it; failing to write that marker is
	// itself one of the ways this failure is reached, and then the workdir was
	// not touched at all and no sweep will ever find the change set. TxnError
	// carries the core's message, which says which of the two happened, so
	// read it before acting.
	TxnErrMerge TxnErrorKind = 6
	// TxnErrCommitAbandoned: the commit phase never ran to completion because
	// the runtime was shut down under it. This is the one failure that cannot
	// say what state the workdir and the change set are in.
	TxnErrCommitAbandoned TxnErrorKind = 7
	// TxnErrUnknown: a failure the ABI itself has no name for. The core's
	// failure set is open, so an ABI can meet a newer core; the message still
	// carries the core's own explanation. This is not the only unnamed kind a
	// caller can meet, since a newer ABI can also publish a value this build
	// has never heard of, so it is not a value to compare against as a way of
	// asking "did I understand this".
	TxnErrUnknown TxnErrorKind = 8
)

func (k TxnErrorKind) String() string {
	switch k {
	case TxnErrNoRuntime:
		return "no-runtime"
	case TxnErrNullHandle:
		return "null-handle"
	case TxnErrInvalid:
		return "invalid"
	case TxnErrBranch:
		return "branch"
	case TxnErrStage:
		return "stage"
	case TxnErrConflict:
		return "conflict"
	case TxnErrCommitLock:
		return "commit-lock"
	case TxnErrMerge:
		return "merge"
	case TxnErrCommitAbandoned:
		return "commit-abandoned"
	case TxnErrUnknown:
		return "unknown"
	default:
		return fmt.Sprintf("TxnErrorKind(%d)", int(k))
	}
}

// IsVerdict reports whether the kind is one of the core's verdicts on a
// transaction, which is what makes it safe to reason from about the workdir.
//
// Every positive value is one, including a value this build has no name for.
// The failure set is append only and the ABI is loaded rather than compiled in,
// so a binding can meet a kind from a newer ABI; that kind is still a decision
// the core made about this transaction, and treating it as if it were one of
// the two negatives would say the opposite. What an unnamed verdict costs the
// caller is the default arm of a switch, not the guard.
//
// The two negative values are what this excludes, because folding them into a
// named failure would claim a verdict the core never gave: TxnErrNoRuntime in
// particular can be returned by a transaction that really ran.
func (k TxnErrorKind) IsVerdict() bool { return k >= TxnErrInvalid }

// TxnError reports a transaction the core could not carry out.
//
// An aborted transaction is not one of these. A stage exiting non-zero, and a
// run that ran out of time, both yield a *TxnOutcome with Disposition
// TxnAborted and a nil error.
//
// Kind is the field that matters: TxnErrConflict means the change set is
// intact and a retry is the expected response, while TxnErrMerge means the
// workdir may have been partially modified and has to be inspected.
type TxnError struct {
	Kind TxnErrorKind
	Msg  string
}

func (e *TxnError) Error() string {
	if e.Msg == "" {
		return fmt.Sprintf("sandlock: transaction failed (%s)", e.Kind)
	}
	return fmt.Sprintf("sandlock: transaction failed (%s): %s", e.Kind, e.Msg)
}

// TxnOutcome is a transaction that ran to a decision.
type TxnOutcome struct {
	// Disposition is which of the three terminal states the run ended in.
	Disposition TxnDisposition

	// Stages holds one result per stage that ran, in execution order. It can
	// be shorter than the stage set: no later stage runs after one exits
	// non-zero, and a stage killed by a deadline reports nothing at all.
	//
	// Stdout is always empty. Every stage inherits this process's standard
	// input and output, so a stage writes straight to the caller's terminal
	// or pipe; Stderr is captured (bounded) as well as being written through.
	Stages []Result

	// Changes is what the shared upper held at the end of the run: what the
	// commit merged, or, for a dry run and for an abort, what was discarded.
	//
	// A path here is a name to show and not always a name to open: bytes that
	// are not valid UTF-8 are replaced rather than preserved. Use
	// PreservedBranch, whose paths are verbatim, to address a change set on
	// disk.
	Changes []Change
}

// Committed reports whether the change set landed in the workdir.
func (o *TxnOutcome) Committed() bool { return o.Disposition == TxnCommitted }

// TimedOut reports whether an aborted transaction was aborted by its deadline
// rather than by a stage that exited non-zero.
//
// The core does not publish the cause as a value, but the outcome still tells
// them apart: a stage that exits non-zero is reported and stops the run, so it
// is the last result, while a stage killed by the deadline reports no result
// at all. An aborted outcome in which every reported stage succeeded is a
// timeout, and nothing else is.
func (o *TxnOutcome) TimedOut() bool {
	if o.Disposition != TxnAborted {
		return false
	}
	for i := range o.Stages {
		if !o.Stages[i].Success {
			return false
		}
	}
	return true
}

// Transaction runs its stages in order over one shared copy-on-write upper and
// commits every change they made, or none of them.
//
// A Transaction carries no native state: Run and DryRun build a fresh native
// transaction on each call, so a value may be run more than once, and the
// value that failed is the value to retry with. That is deliberate. The C ABI
// consumes its transaction handle on every path including failure, so a handle
// that outlived a call could only be misused.
type Transaction struct {
	// Stages run sequentially in this order. At least two are required.
	Stages []Stage

	// CommitLockWait bounds how long the commit waits for the workdir lock.
	// Zero uses the core's own default (30 seconds at the time of writing).
	//
	// The shortest wait the ABI can express is one millisecond, so a
	// sub-millisecond value is rounded up to it rather than being rounded down
	// to zero, which would mean the opposite of what it says. A single
	// non-blocking attempt cannot be asked for at all.
	CommitLockWait time.Duration
}

// PreserveReason says why a change set was left in branch storage instead of
// being reclaimed, and so how far the workdir got. A recovery reads this before
// it reads anything else. The set is append only.
type PreserveReason int

const (
	// PreserveMergeInterrupted: a merge started and did not finish, so the
	// workdir may be partly merged. A merge that is STILL RUNNING is
	// indistinguishable from this, because the marker is written before the
	// first destructive step; check PreservedBranch.PID before acting.
	PreserveMergeInterrupted PreserveReason = 0
	// PreserveCommitDeferred: a commit could not take the workdir lock. The
	// workdir is untouched and the whole change set is here.
	PreserveCommitDeferred PreserveReason = 1
	// PreserveKept: the caller asked for the branch to be kept.
	PreserveKept PreserveReason = 2
)

func (r PreserveReason) String() string {
	switch r {
	case PreserveMergeInterrupted:
		return "merge-interrupted"
	case PreserveCommitDeferred:
		return "commit-deferred"
	case PreserveKept:
		return "kept"
	default:
		return fmt.Sprintf("PreserveReason(%d)", int(r))
	}
}

// PreservedBranch is one change set that was left in branch storage rather than
// reclaimed. ListPreserved finds them; ReadPreserved reads one by name.
//
// Every path here carries its bytes verbatim, so it may not be valid UTF-8 and
// must not be decoded or reformatted before being used: these are addresses to
// open, and BranchDir in particular is both what ReadPreserved takes and what
// to remove once the change set has been recovered. That is the opposite of
// TxnOutcome.Changes, whose paths are lossy because they are names to show.
type PreservedBranch struct {
	// BranchDir is the branch's private storage directory.
	BranchDir string
	// Upper holds the preserved additions and modifications. It is only half
	// of the change set: nothing in it represents a deletion, so copying it
	// over the workdir and doing nothing else would resurrect every file the
	// run removed. Apply Deleted FIRST.
	Upper string
	// Workdir is the directory the change set belongs to, canonicalized when
	// the branch was created.
	Workdir string
	// Deleted lists the paths the run removed, relative to Workdir, in sorted
	// order. This is the half of the change set the upper cannot carry.
	Deleted []string
	// Reason says what state Workdir is in, which decides what a recovery may
	// do.
	Reason PreserveReason
	// PID is the process that preserved the change set.
	//
	// Load-bearing for one thing: a merge writes its marker BEFORE its first
	// destructive step, so a merge in flight and a merge that was interrupted
	// are the same record, and this is the only thing that tells them apart.
	// Anything that acts on a PreserveMergeInterrupted record rather than only
	// reporting it must first check that this pid is not live. Beyond that it
	// is triage only: the process may be long gone and its pid reused.
	PID uint32
}
