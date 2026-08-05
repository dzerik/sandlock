//go:build linux

package sandlock

/*
// Build flags come from the build-tagged companion files, as in
// sandlock_linux.go; this file only needs the declarations.
#include <stdlib.h>
#include "sandlock.h"
*/
import "C"

import (
	"context"
	"fmt"
	"time"
	"unicode/utf8"
)

// takeString consumes an owned C string from the ABI and releases it. Every
// string getter in the transaction and recovery families allocates, so every
// one of them has to be freed exactly once.
//
// The bytes are taken as they are. For the recovery family that is the whole
// point: those paths are addresses to open and are not narrowed to UTF-8.
func takeString(p *C.char) string {
	if p == nil {
		return ""
	}
	s := C.GoString(p)
	C.sandlock_string_free(p)
	return s
}

// Run executes every stage in order over one shared copy-on-write upper and
// merges their changes into the workdir if and only if every stage exits 0.
//
// A deadline on ctx bounds the STAGE PHASE only. The commit cannot be
// cancelled at all, so a deadline that elapses during the merge does not stop
// it; a deadline that elapses while a stage is running aborts the transaction,
// which is an outcome (Disposition TxnAborted, TimedOut true) and not an error.
// ctx cancellation without a deadline does not preempt a running stage, as
// with Sandbox.Run.
//
// A stage that exits non-zero is likewise an outcome and not an error. Two
// unrelated things do return an error, and only one of them is a verdict on a
// transaction:
//
//   - A transaction the core could not carry out arrives as a *TxnError, whose
//     Kind says what became of the workdir.
//   - A run that never started at all arrives as ctx's own error, or as a
//     stage this binding refused to hand to the ABI. Neither is a *TxnError,
//     because neither says anything about a workdir.
//
// So reach for the Kind through errors.As rather than a type assertion: an
// assertion turns the second group into a panic.
func (t *Transaction) Run(ctx context.Context) (*TxnOutcome, error) {
	return t.execute(ctx, false)
}

// DryRun runs every stage exactly as Run does, then reports the change set and
// discards it. The stages really execute; only the fate of the shared upper
// differs. The workdir is never written to and the commit lock is never taken,
// so a dry run cannot conflict with a commit that is in flight, and the upper
// is thrown away rather than preserved.
func (t *Transaction) DryRun(ctx context.Context) (*TxnOutcome, error) {
	return t.execute(ctx, true)
}

// maxStageArgs is the largest argument vector the C ABI carries. A longer one
// is dropped there, so it is refused here.
//
// The ABI states the bound in prose rather than publishing it as a constant, so
// this is a copy and not a binding. That is survivable in only one direction:
// if the two ever disagree, the disagreement has to show up as this binding
// being the stricter of the two, which is what refusing a vector this long
// gives. It must never be raised above the ABI's own bound, since a vector past
// that is dropped inside the ABI and reaches the caller as a complaint about a
// stage set it did not write.
const maxStageArgs = 4096

// checkStage rejects a stage the C ABI would drop.
//
// The ABI drops a stage it cannot read and says nothing about it, on the
// grounds that substituting something for an argument it could not decode
// would run a command the caller never asked for. The core then refuses the
// stage set it was actually given, so nothing commits silently, but the
// complaint names a transaction the caller did not write. Since a Go string is
// an arbitrary byte sequence, every one of these is reachable from ordinary Go
// code, so the binding refuses the input at the point where the caller can
// still see which stage it was.
//
// Only the transaction family is checked this way. Sandbox.Run and its
// neighbours reach a different ABI entry point, one that substitutes an empty
// string for an argument it cannot decode instead of dropping the command, so
// the same bytes run a command the caller did not ask for rather than being
// refused. That difference belongs to the ABI and is not worth a second,
// divergent copy of the check here.
func checkStage(i int, s Stage) error {
	if s.Sandbox == nil {
		return fmt.Errorf("sandlock: stage %d has no Sandbox", i)
	}
	if len(s.Args) == 0 {
		return fmt.Errorf("sandlock: stage %d has no Args: an empty command is not a runnable stage", i)
	}
	if len(s.Args) > maxStageArgs {
		return fmt.Errorf("sandlock: stage %d has %d arguments, above the limit of %d", i, len(s.Args), maxStageArgs)
	}
	for j, a := range s.Args {
		if !utf8.ValidString(a) {
			return fmt.Errorf("sandlock: stage %d argument %d is not valid UTF-8: the transaction ABI cannot carry it", i, j)
		}
	}
	return nil
}

// commitLockWaitMs renders CommitLockWait for the ABI, where 0 means "use the
// core default" rather than "do not wait". A sub-millisecond wait is therefore
// rounded UP to the shortest the ABI can express: rounding it down to 0 would
// turn the shortest wait a caller can ask for into the longest.
func commitLockWaitMs(d time.Duration) C.uint64_t {
	if d <= 0 {
		return 0
	}
	ms := d.Milliseconds()
	if ms < 1 {
		ms = 1
	}
	return C.uint64_t(ms)
}

// addStage builds one stage's policy and argument vector, hands both to the
// transaction, and releases them again.
//
// It is a function of its own so that those two releases can be deferred: the
// stage clones the policy and copies the arguments, so they are this side's to
// free the moment the stage has been added, and building a policy can panic
// rather than return.
func addStage(txn *C.sandlock_txn_t, i int, stage Stage) error {
	policyPtr, err := stage.Sandbox.buildPolicy()
	if err != nil {
		return fmt.Errorf("sandlock: stage %d: %w", i, err)
	}
	defer C.sandlock_sandbox_free(policyPtr)

	argv, err := cArgv(stage.Args)
	if err != nil {
		return fmt.Errorf("sandlock: stage %d: %w", i, err)
	}
	defer freeArgv(argv)

	ap, ac := argvPtr(argv)
	C.sandlock_txn_add_stage(txn, policyPtr, ap, ac)
	return nil
}

func (t *Transaction) execute(ctx context.Context, dry bool) (*TxnOutcome, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for i, s := range t.Stages {
		if err := checkStage(i, s); err != nil {
			return nil, err
		}
	}

	txn := C.sandlock_txn_new()
	if txn == nil {
		// Documented as impossible: the constructor is an allocation that
		// aborts rather than returning null. Reported honestly all the same,
		// as the code that means this binding produced no handle.
		return nil, &TxnError{Kind: TxnErrNullHandle}
	}

	// Released here on every path that does NOT reach the consuming call,
	// panics included. Building a stage's policy can panic (a policy callback
	// that cannot be registered does), and a caller that recovers and retries
	// would otherwise leak one transaction, with every stage policy already
	// cloned into it, per attempt.
	consumed := false
	defer func() {
		if !consumed {
			C.sandlock_txn_free(txn)
		}
	}()

	for i, stage := range t.Stages {
		if err := addStage(txn, i, stage); err != nil {
			return nil, err
		}
	}
	C.sandlock_txn_commit_lock_wait_ms(txn, commitLockWaitMs(t.CommitLockWait))

	// Both entry points CONSUME txn, on every path including failure, so the
	// handle must not outlive this call: freeing it afterwards is a double
	// free and reusing it is a use after free. That is why a Transaction holds
	// no handle of its own and builds a new one per run.
	var errCode C.int
	var errMsg *C.char
	ms := timeoutMs(ctx)
	var outcome *C.sandlock_txn_outcome_t
	consumed = true
	if dry {
		outcome = C.sandlock_txn_dry_run(txn, ms, &errCode, &errMsg)
	} else {
		outcome = C.sandlock_txn_run(txn, ms, &errCode, &errMsg)
	}
	if outcome == nil {
		// The kind is carried through as the core reported it, negatives
		// included. Folding those into a named failure would claim a verdict
		// on the workdir that was never given; TxnErrorKind.IsVerdict is how a
		// caller keeps them out of a switch over the named ones.
		return nil, &TxnError{Kind: TxnErrorKind(errCode), Msg: takeString(errMsg)}
	}
	defer C.sandlock_txn_outcome_free(outcome)

	out := &TxnOutcome{Disposition: TxnDisposition(C.sandlock_txn_outcome_disposition(outcome))}

	nStages := C.sandlock_txn_outcome_stages_len(outcome)
	out.Stages = make([]Result, 0, int(nStages))
	for i := C.uintptr_t(0); i < nStages; i++ {
		// Borrowed from the outcome and never freed here.
		r := C.sandlock_txn_outcome_stage_at(outcome, i)
		if r == nil {
			continue
		}
		out.Stages = append(out.Stages, *readResult(r))
	}

	nChanges := C.sandlock_txn_outcome_changes_len(outcome)
	out.Changes = make([]Change, 0, int(nChanges))
	for i := C.uintptr_t(0); i < nChanges; i++ {
		out.Changes = append(out.Changes, Change{
			Kind: ChangeKind(C.sandlock_txn_outcome_change_kind(outcome, i)),
			Path: takeString(C.sandlock_txn_outcome_change_path(outcome, i)),
		})
	}
	return out, nil
}
