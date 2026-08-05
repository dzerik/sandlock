//go:build linux

package sandlock_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	sandlock "github.com/multikernel/sandlock/go"
)

// txnSandbox is the policy shape a transaction stage needs: the workdir is
// readable, writable, copy-on-write, and the stage's working directory, so a
// relative path in a stage command resolves inside the shared upper rather
// than next to the test binary. FSStorage pins where a preserved change set
// would land, which is the only way a recovery can find one.
func txnSandbox(workdir, storage string) *sandlock.Sandbox {
	return &sandlock.Sandbox{
		FSReadable: rootfs,
		FSWritable: []string{workdir},
		Workdir:    workdir,
		Cwd:        workdir,
		FSStorage:  storage,
	}
}

// requireSandbox skips a test when this environment cannot run a sandbox at
// all. requireLandlock only reads the kernel's advertised ABI; seccomp,
// unprivileged user namespaces and container policy can still refuse, and a
// transaction test that cannot start a stage would otherwise fail for a reason
// that has nothing to do with transactions. Skipping the test whole keeps a
// real regression a hard failure instead of hiding it behind a tolerated error.
func requireSandbox(t *testing.T) {
	t.Helper()
	requireLandlock(t)
	res, err := (&sandlock.Sandbox{FSReadable: rootfs}).Run(context.Background(), "true")
	if err != nil {
		t.Skipf("sandbox unavailable in this environment: %v", err)
	}
	if !res.Success {
		t.Skipf("sandbox unavailable in this environment: `true` exited %d: %s", res.ExitCode, res.Stderr)
	}
}

// changePairs renders an outcome's change set as sorted "K path" strings so a
// test can compare it whole instead of one field at a time.
func changePairs(out *sandlock.TxnOutcome) []string {
	got := make([]string, 0, len(out.Changes))
	for _, c := range out.Changes {
		got = append(got, string(c.Kind)+" "+c.Path)
	}
	sort.Strings(got)
	return got
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func mustNotExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("%s must not exist in the workdir (stat error was %v)", path, err)
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(b)
}

// TestTransactionThreeStagePipelineCommitsAllOrNothing is the RFC #65 Phase 1
// acceptance criterion driven through the Go SDK: three sequential stages over
// one shared copy-on-write upper, where stage 1 writes a.txt, stage 2 reads
// a.txt and writes b.txt, and stage 3 reads both. On success both files appear
// in the workdir; on a non-zero stage exit neither does.
//
// The two halves differ only in how the last stage exits, and the failing one
// fails LAST on purpose: by then both files exist in the shared upper, so a
// merge that leaked even one of them would be visible.
func TestTransactionThreeStagePipelineCommitsAllOrNothing(t *testing.T) {
	requireSandbox(t)

	// Each reading stage compares what it read, so a stage that saw an empty
	// or missing file fails instead of quietly succeeding: the pipeline is
	// only a pipeline if stage 2 really sees stage 1's write.
	pipeline := func(sb *sandlock.Sandbox, lastExit string) []sandlock.Stage {
		return []sandlock.Stage{
			{Sandbox: sb, Args: []string{"sh", "-c", `echo plan > a.txt`}},
			{Sandbox: sb, Args: []string{"sh", "-c", `[ "$(cat a.txt)" = plan ] && echo built > b.txt`}},
			{Sandbox: sb, Args: []string{"sh", "-c", `[ "$(cat a.txt)" = plan ] && [ "$(cat b.txt)" = built ] && echo 'stage 3 read both' >&2 && ` + lastExit}},
		}
	}

	t.Run("committed", func(t *testing.T) {
		wd, st := t.TempDir(), t.TempDir()
		txn := &sandlock.Transaction{Stages: pipeline(txnSandbox(wd, st), "exit 0")}

		out, err := txn.Run(context.Background())
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if out.Disposition != sandlock.TxnCommitted {
			t.Fatalf("disposition = %v, want committed", out.Disposition)
		}
		if !out.Committed() {
			t.Fatal("Committed() must be true for a committed disposition")
		}
		if len(out.Stages) != 3 {
			t.Fatalf("stage results = %d, want 3", len(out.Stages))
		}
		for i, r := range out.Stages {
			if !r.Success {
				t.Fatalf("stage %d must have exited 0, got %d: %s", i, r.ExitCode, r.Stderr)
			}
		}
		// A stage's standard error is captured as well as tee'd, so the last
		// stage really did read what the first two wrote.
		if !strings.Contains(string(out.Stages[2].Stderr), "stage 3 read both") {
			t.Errorf("stage 3 stderr = %q, want the marker it printed after reading both files", out.Stages[2].Stderr)
		}
		want := []string{"A a.txt", "A b.txt"}
		if got := changePairs(out); !equalStrings(got, want) {
			t.Errorf("changes = %v, want %v", got, want)
		}
		if got := mustRead(t, filepath.Join(wd, "a.txt")); got != "plan\n" {
			t.Errorf("a.txt = %q, want %q: stage 1's write must reach the real workdir", got, "plan\n")
		}
		if got := mustRead(t, filepath.Join(wd, "b.txt")); got != "built\n" {
			t.Errorf("b.txt = %q, want %q: stage 2's write must reach the real workdir", got, "built\n")
		}
	})

	t.Run("aborted", func(t *testing.T) {
		wd, st := t.TempDir(), t.TempDir()
		txn := &sandlock.Transaction{Stages: pipeline(txnSandbox(wd, st), "exit 7")}

		out, err := txn.Run(context.Background())
		// A stage exiting non-zero is the feature working, not a failure of
		// the binding: it is an outcome, and the caller reads its disposition.
		if err != nil {
			t.Fatalf("an aborted transaction must not be an error, got %v", err)
		}
		if out.Disposition != sandlock.TxnAborted {
			t.Fatalf("disposition = %v, want aborted", out.Disposition)
		}
		if out.Committed() {
			t.Fatal("Committed() must be false for an aborted disposition")
		}
		if out.TimedOut() {
			t.Error("TimedOut() must be false when a stage reported a non-zero exit")
		}
		if len(out.Stages) != 3 {
			t.Fatalf("stage results = %d, want 3: every stage that ran is reported", len(out.Stages))
		}
		if out.Stages[2].ExitCode != 7 {
			t.Errorf("failing stage exit = %d, want 7: the stage keeps its own code", out.Stages[2].ExitCode)
		}
		want := []string{"A a.txt", "A b.txt"}
		if got := changePairs(out); !equalStrings(got, want) {
			t.Errorf("changes = %v, want %v: the discarded change set is still reported", got, want)
		}
		mustNotExist(t, filepath.Join(wd, "a.txt"))
		mustNotExist(t, filepath.Join(wd, "b.txt"))
	})
}

// TestTransactionValueIsReusable pins the consequence of the C ABI consuming
// its handle on every path: the binding never lets one escape, so a
// *Transaction is a declaration and not a handle. Running the same value twice
// has to build a second transaction and run it, where a binding that cached
// the handle would abort the process on the second run's double free.
//
// The stage appends rather than overwrites so the second run is provable from
// the workdir alone: a value that was silently not re-run would leave one line
// and report an addition again.
func TestTransactionValueIsReusable(t *testing.T) {
	requireSandbox(t)
	wd, st := t.TempDir(), t.TempDir()
	sb := txnSandbox(wd, st)
	txn := &sandlock.Transaction{Stages: []sandlock.Stage{
		{Sandbox: sb, Args: []string{"sh", "-c", "echo plan >> a.txt"}},
		{Sandbox: sb, Args: []string{"sh", "-c", `[ -s a.txt ]`}},
	}}

	first, err := txn.Run(context.Background())
	if err != nil {
		t.Fatalf("first Run: %v", err)
	}
	if !first.Committed() {
		t.Fatalf("first run disposition = %v, want committed", first.Disposition)
	}
	if got, want := changePairs(first), []string{"A a.txt"}; !equalStrings(got, want) {
		t.Fatalf("first run changes = %v, want %v", got, want)
	}
	if got := mustRead(t, filepath.Join(wd, "a.txt")); got != "plan\n" {
		t.Fatalf("a.txt after first run = %q, want %q", got, "plan\n")
	}

	second, err := txn.Run(context.Background())
	if err != nil {
		t.Fatalf("second Run of the same value: %v", err)
	}
	if !second.Committed() {
		t.Fatalf("second run disposition = %v, want committed", second.Disposition)
	}
	if got, want := changePairs(second), []string{"M a.txt"}; !equalStrings(got, want) {
		t.Errorf("second run changes = %v, want %v: the file the first run committed is modified, not added", got, want)
	}
	if got := mustRead(t, filepath.Join(wd, "a.txt")); got != "plan\nplan\n" {
		t.Errorf("a.txt after second run = %q, want %q: the stages must really have run again", got, "plan\nplan\n")
	}
}

// TestTransactionInvalidStageSetCarriesTheCoreVerdict checks that the
// cross-stage guardrails, which belong to the core, reach the caller as a kind
// plus the core's own words rather than as an opaque failure.
func TestTransactionInvalidStageSetCarriesTheCoreVerdict(t *testing.T) {
	requireLandlock(t)
	wd, st := t.TempDir(), t.TempDir()
	sb := txnSandbox(wd, st)

	// One stage is below the two-stage minimum. This is decided before
	// anything runs, so it needs no working sandbox.
	_, err := (&sandlock.Transaction{Stages: []sandlock.Stage{
		{Sandbox: sb, Args: []string{"true"}},
	}}).Run(context.Background())

	var txnErr *sandlock.TxnError
	if !errors.As(err, &txnErr) {
		t.Fatalf("want *TxnError, got %T: %v", err, err)
	}
	if txnErr.Kind != sandlock.TxnErrInvalid {
		t.Fatalf("kind = %v, want invalid", txnErr.Kind)
	}
	if !txnErr.Kind.IsVerdict() {
		t.Error("a rejected stage set is a verdict on a transaction")
	}
	if !strings.Contains(txnErr.Msg, "stage") {
		t.Errorf("message = %q, want the core's own explanation", txnErr.Msg)
	}
	// The core's own words have to survive the wrapping, since they are the
	// only part that says WHICH rule the stage set broke.
	if !strings.Contains(txnErr.Error(), txnErr.Msg) {
		t.Errorf("Error() = %q, want it to carry the core's message %q", txnErr.Error(), txnErr.Msg)
	}
}

// TestTransactionRefusesStagesTheABIWouldDrop covers the one place where this
// binding has to add a check rather than translate a verdict. The C ABI drops
// a stage it cannot read (no policy, no argv, an argument that is not UTF-8)
// and says nothing, and the core then complains about a stage set the caller
// never wrote. A Go string is an arbitrary byte sequence, so that is reachable
// from ordinary Go code, and the answer is to refuse the input here.
//
// Each case is the SECOND stage of an otherwise valid pair, so what is refused
// is one stage and not the shape of the transaction.
func TestTransactionRefusesStagesTheABIWouldDrop(t *testing.T) {
	requireLandlock(t)
	wd, st := t.TempDir(), t.TempDir()
	sb := txnSandbox(wd, st)
	good := sandlock.Stage{Sandbox: sb, Args: []string{"sh", "-c", "true"}}

	cases := []struct {
		name string
		bad  sandlock.Stage
		is   error
	}{
		{"nil sandbox", sandlock.Stage{Args: []string{"true"}}, nil},
		{"no args", sandlock.Stage{Sandbox: sb}, nil},
		{"NUL in an argument", sandlock.Stage{Sandbox: sb, Args: []string{"echo", "a\x00b"}}, sandlock.ErrInvalidString},
		{"argument is not UTF-8", sandlock.Stage{Sandbox: sb, Args: []string{"echo", "\xff"}}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := (&sandlock.Transaction{Stages: []sandlock.Stage{good, c.bad}}).Run(context.Background())
			if err == nil {
				t.Fatal("want an error naming the stage, got nil")
			}
			// Refused here means the run never happened. A binding that let
			// the stage be dropped instead would surface the core's verdict on
			// the mutilated set, which is a *TxnError.
			var txnErr *sandlock.TxnError
			if errors.As(err, &txnErr) {
				t.Fatalf("the stage reached the core as a dropped stage: %v", err)
			}
			if !strings.Contains(err.Error(), "stage 1") {
				t.Errorf("error = %q, want the offending stage's index", err)
			}
			if c.is != nil && !errors.Is(err, c.is) {
				t.Errorf("error = %v, want it to wrap %v", err, c.is)
			}
		})
	}
}

// TestTransactionDryRunRunsTheStagesAndCommitsNothing pins the three promises a
// dry run makes: the stages really execute and their change set is reported,
// the workdir is never written to, and the commit lock is never taken. The
// workdir lock is held for the whole call, so a dry run that did reach for it
// would fail instead of passing. The storage check is the third promise: the
// upper is discarded, not preserved, so a plan-then-inspect loop cannot fill
// branch storage.
func TestTransactionDryRunRunsTheStagesAndCommitsNothing(t *testing.T) {
	requireSandbox(t)
	wd, st := t.TempDir(), t.TempDir()
	sb := txnSandbox(wd, st)
	txn := &sandlock.Transaction{
		Stages: []sandlock.Stage{
			{Sandbox: sb, Args: []string{"sh", "-c", "echo plan > a.txt"}},
			{Sandbox: sb, Args: []string{"sh", "-c", `[ "$(cat a.txt)" = plan ] && echo built > b.txt`}},
		},
		// Bound the wait so a dry run that did take the lock fails in a
		// fraction of a second instead of stalling on the core's default.
		CommitLockWait: 300 * time.Millisecond,
	}

	release := holdWorkdirLock(t, wd)
	out, err := txn.DryRun(context.Background())
	release()

	if err != nil {
		t.Fatalf("a dry run takes no commit lock, so a held one cannot fail it: %v", err)
	}
	if out.Disposition != sandlock.TxnDryRun {
		t.Fatalf("disposition = %v, want dry-run", out.Disposition)
	}
	if out.Committed() {
		t.Fatal("Committed() must be false for a dry run: nothing reached the workdir")
	}
	if len(out.Stages) != 2 {
		t.Fatalf("stage results = %d, want 2: a dry run really runs the stages", len(out.Stages))
	}
	want := []string{"A a.txt", "A b.txt"}
	if got := changePairs(out); !equalStrings(got, want) {
		t.Errorf("changes = %v, want %v: a dry run reports the whole change set it then discards", got, want)
	}
	mustNotExist(t, filepath.Join(wd, "a.txt"))
	mustNotExist(t, filepath.Join(wd, "b.txt"))

	left, err := os.ReadDir(st)
	if err != nil {
		t.Fatalf("reading the storage base: %v", err)
	}
	if len(left) != 0 {
		t.Errorf("a dry run must discard its upper rather than preserve it; storage holds %d entries", len(left))
	}
}

// holdWorkdirLock stands in for another transaction mid-commit by taking the
// workdir's exclusive lock, and returns the release.
func holdWorkdirLock(t *testing.T, workdir string) func() {
	t.Helper()
	f, err := os.Open(workdir)
	if err != nil {
		t.Fatalf("test setup: opening the workdir: %v", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		t.Fatalf("test setup: could not take the workdir lock: %v", err)
	}
	released := false
	return func() {
		if released {
			return
		}
		released = true
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}
}

// TestTransactionConflictIsNotCommitLockAndIsRetryable covers the discriminant
// that justifies the whole design, and the two things a caller does with it.
//
// Contention is TxnErrConflict and not TxnErrCommitLock: the two are adjacent
// numbers that mean opposite things, and only the first says a retry is the
// expected response. The change set survives on disk under the storage base,
// which is what makes the retry a choice rather than the only option. And the
// retry is of the same *Transaction value, which is the failure-path half of
// handle consumption: the ABI took the handle even though the run failed.
func TestTransactionConflictIsNotCommitLockAndIsRetryable(t *testing.T) {
	requireSandbox(t)
	wd, st := t.TempDir(), t.TempDir()
	sb := txnSandbox(wd, st)
	txn := &sandlock.Transaction{
		Stages: []sandlock.Stage{
			{Sandbox: sb, Args: []string{"sh", "-c", "echo plan > a.txt"}},
			{Sandbox: sb, Args: []string{"sh", "-c", `[ "$(cat a.txt)" = plan ] && echo built > b.txt`}},
		},
		CommitLockWait: 300 * time.Millisecond,
	}

	release := holdWorkdirLock(t, wd)
	started := time.Now()
	_, err := txn.Run(context.Background())
	waited := time.Since(started)
	release()

	var txnErr *sandlock.TxnError
	if !errors.As(err, &txnErr) {
		t.Fatalf("want *TxnError, got %T: %v", err, err)
	}
	if txnErr.Kind == sandlock.TxnErrCommitLock {
		t.Fatalf("losing the lock to another holder is TxnErrConflict; TxnErrCommitLock is reserved for a lock that could not be taken at all, and only the first is retryable")
	}
	if txnErr.Kind != sandlock.TxnErrConflict {
		t.Fatalf("kind = %v, want conflict", txnErr.Kind)
	}
	// The CommitLockWait set on the value has to reach the core: unset, the
	// core waits its own default of 30 seconds. The bound separates 300 ms
	// from 30 s, not one host from another, so it is deliberately generous.
	if waited > 20*time.Second {
		t.Errorf("CommitLockWait did not reach the core: gave up after %v", waited)
	}
	mustNotExist(t, filepath.Join(wd, "a.txt"))

	// The change set is the one thing the caller cannot reconstruct from
	// anywhere else, so the sweep has to find it.
	preserved, err := sandlock.ListPreserved(st)
	if err != nil {
		t.Fatalf("ListPreserved: %v", err)
	}
	if len(preserved) != 1 {
		t.Fatalf("preserved change sets = %d, want 1", len(preserved))
	}
	p := preserved[0]
	if p.Reason != sandlock.PreserveCommitDeferred {
		t.Errorf("reason = %v, want commit-deferred: the merge never started, so the workdir is untouched", p.Reason)
	}
	if p.PID != uint32(os.Getpid()) {
		t.Errorf("PID = %d, want %d: the record names the process that preserved it", p.PID, os.Getpid())
	}
	if len(p.Deleted) != 0 {
		t.Errorf("deleted = %v, want none: the transaction deleted nothing", p.Deleted)
	}
	if got := mustRead(t, filepath.Join(p.Upper, "b.txt")); got != "built\n" {
		t.Errorf("preserved upper b.txt = %q, want %q: the last stage's write must survive", got, "built\n")
	}
	if want := evalSymlinks(t, wd); p.Workdir != want {
		t.Errorf("workdir = %q, want %q", p.Workdir, want)
	}
	if filepath.Dir(p.BranchDir) != evalSymlinks(t, st) {
		t.Errorf("branch dir = %q, want it directly under the storage base %q", p.BranchDir, st)
	}
	// What the sweep reported has to be readable back on its own: that path is
	// the address of the thing to remove once the change set is recovered.
	again, err := sandlock.ReadPreserved(p.BranchDir)
	if err != nil {
		t.Fatalf("ReadPreserved(%q): %v", p.BranchDir, err)
	}
	if again.Reason != p.Reason || again.Upper != p.Upper || again.Workdir != p.Workdir {
		t.Errorf("ReadPreserved returned %+v, want the same record the sweep did: %+v", again, p)
	}

	// Retrying is the expected response to contention, and the value that
	// failed is the value to retry with.
	out, err := txn.Run(context.Background())
	if err != nil {
		t.Fatalf("retry after the lock was released: %v", err)
	}
	if !out.Committed() {
		t.Fatalf("retry disposition = %v, want committed", out.Disposition)
	}
	if got := mustRead(t, filepath.Join(wd, "a.txt")); got != "plan\n" {
		t.Errorf("a.txt after the retry = %q, want %q", got, "plan\n")
	}
	if got := mustRead(t, filepath.Join(wd, "b.txt")); got != "built\n" {
		t.Errorf("b.txt after the retry = %q, want %q", got, "built\n")
	}

	// The retry ran a NEW branch and swept nothing: the failed attempt's change
	// set is still in storage, holding a full copy of what the stages wrote.
	// Nothing in this package removes it, which is what makes a retry loop over
	// a contended workdir fill its storage base one copy per attempt, so the
	// caller has to remove BranchDir itself once the set is accounted for.
	after, err := sandlock.ListPreserved(st)
	if err != nil {
		t.Fatalf("ListPreserved after the retry: %v", err)
	}
	if len(after) != 1 || after[0].BranchDir != p.BranchDir {
		t.Fatalf("preserved after the retry = %+v, want the failed attempt's record %q still there and nothing else", after, p.BranchDir)
	}
	if err := os.RemoveAll(p.BranchDir); err != nil {
		t.Fatalf("removing the recovered change set: %v", err)
	}
	if after, err = sandlock.ListPreserved(st); err != nil || len(after) != 0 {
		t.Fatalf("after removing %q the sweep found %+v (err %v), want nothing: removing BranchDir is what closes a recovery", p.BranchDir, after, err)
	}
}

func evalSymlinks(t *testing.T, path string) string {
	t.Helper()
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatalf("resolving %q: %v", path, err)
	}
	return real
}

// TestTransactionTimeoutIsAnAbortTellableFromAStageFailure covers the context
// deadline, which bounds the stage phase, and the one thing an outcome does not
// publish as a value: why it aborted. A timeout kills the stage in flight and
// reports no result for it, so an aborted outcome whose every reported stage
// succeeded is a timeout and nothing else is. The control in the same test is
// what stops TimedOut() from being a synonym for "aborted".
func TestTransactionTimeoutIsAnAbortTellableFromAStageFailure(t *testing.T) {
	requireSandbox(t)
	wd, st := t.TempDir(), t.TempDir()
	sb := txnSandbox(wd, st)

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()

	// A deadline that never reaches the core does not make this test fail, it
	// makes it HANG: the stage sleeps a minute and the run would wait it out,
	// so an assertion placed after the call could never run. The wait is
	// bounded here instead, which turns a dropped deadline into this test
	// failing with the reason rather than into go test killing the package on
	// its own timeout, minutes later, with a stack dump for every goroutine.
	//
	// The stage sleeps forty times longer than the deadline, so the bound
	// separates "the deadline was applied" from "the stage ran to completion",
	// not one host from another.
	type runResult struct {
		out *sandlock.TxnOutcome
		err error
	}
	done := make(chan runResult, 1)
	started := time.Now()
	go func() {
		out, err := (&sandlock.Transaction{Stages: []sandlock.Stage{
			{Sandbox: sb, Args: []string{"sh", "-c", "echo plan > a.txt"}},
			{Sandbox: sb, Args: []string{"sh", "-c", "sleep 60"}},
		}}).Run(ctx)
		done <- runResult{out, err}
	}()

	var got runResult
	select {
	case got = <-done:
	case <-time.After(20 * time.Second):
		t.Fatalf("the context deadline did not reach the core: a run with a 1.5s deadline was still going after %v", time.Since(started))
	}
	out, err := got.out, got.err

	if err != nil {
		t.Fatalf("a run that times out is an outcome, not a failure: %v", err)
	}
	if out.Disposition != sandlock.TxnAborted {
		t.Fatalf("disposition = %v, want aborted", out.Disposition)
	}
	if len(out.Stages) != 1 {
		t.Fatalf("stage results = %d, want 1: the stage killed mid-flight produces no result", len(out.Stages))
	}
	if !out.TimedOut() {
		t.Error("every reported stage succeeded, so this abort was a timeout")
	}
	if got, want := changePairs(out), []string{"A a.txt"}; !equalStrings(got, want) {
		t.Errorf("changes = %v, want %v: the stages really ran", got, want)
	}
	mustNotExist(t, filepath.Join(wd, "a.txt"))

	// Control: an abort caused by a stage that failed must not read as a
	// timeout, or the predicate would say nothing.
	failed, err := (&sandlock.Transaction{Stages: []sandlock.Stage{
		{Sandbox: sb, Args: []string{"sh", "-c", "true"}},
		{Sandbox: sb, Args: []string{"sh", "-c", "exit 3"}},
	}}).Run(context.Background())
	if err != nil {
		t.Fatalf("control Run: %v", err)
	}
	if failed.Disposition != sandlock.TxnAborted {
		t.Fatalf("control disposition = %v, want aborted", failed.Disposition)
	}
	if failed.TimedOut() {
		t.Error("an abort with a failing stage result is not a timeout")
	}
}

// TestPreservedRecordCarriesDeletionsAndTheWritingPID covers the half of a
// preserved change set that is not visible as files. Deletions live in the
// record and nowhere else: nothing in the upper represents them, so a recovery
// driven by the upper alone would resurrect every file the run removed.
//
// A plain run whose branch action is Keep is the cheapest way to produce a
// record; it needs neither a failure nor contention. That is also why this
// case is not a transaction: the core refuses a stage whose branch action was
// changed, precisely so a transaction cannot commit half of itself.
func TestPreservedRecordCarriesDeletionsAndTheWritingPID(t *testing.T) {
	requireSandbox(t)
	wd, st := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(wd, "victim.txt"), []byte("ORIGINAL"), 0o644); err != nil {
		t.Fatal(err)
	}
	sb := txnSandbox(wd, st)
	sb.OnExit = sandlock.BranchActionKeep

	res, err := sb.Run(context.Background(), "sh", "-c", "rm victim.txt && echo NEW > added.txt")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Success {
		t.Fatalf("the kept run's child must have written and deleted: exit=%d stderr=%s", res.ExitCode, res.Stderr)
	}

	preserved, err := sandlock.ListPreserved(st)
	if err != nil {
		t.Fatalf("ListPreserved: %v", err)
	}
	if len(preserved) != 1 {
		t.Fatalf("preserved change sets = %d, want 1", len(preserved))
	}
	p := preserved[0]
	if p.Reason != sandlock.PreserveKept {
		t.Errorf("reason = %v, want kept", p.Reason)
	}
	if p.PID != uint32(os.Getpid()) {
		t.Errorf("PID = %d, want %d", p.PID, os.Getpid())
	}
	if got, want := p.Deleted, []string{"victim.txt"}; !equalStrings(got, want) {
		t.Errorf("deleted = %v, want %v: the record is the only place a deletion exists", got, want)
	}
	if got := mustRead(t, filepath.Join(p.Upper, "added.txt")); got != "NEW\n" {
		t.Errorf("upper added.txt = %q, want %q", got, "NEW\n")
	}
	mustNotExist(t, filepath.Join(p.Upper, "victim.txt"))

	// What the sweep reports must be readable back on its own, deletions and
	// all: that path is the address of the thing to remove once recovered.
	owned, err := sandlock.ReadPreserved(p.BranchDir)
	if err != nil {
		t.Fatalf("ReadPreserved(%q): %v", p.BranchDir, err)
	}
	if !equalStrings(owned.Deleted, p.Deleted) || owned.Reason != p.Reason || owned.PID != p.PID {
		t.Errorf("ReadPreserved returned %+v, want the same record the sweep did: %+v", owned, p)
	}
}

// TestPreservedSweepDistinguishesNothingToFindFromCouldNotLook: finding nothing
// is an empty sweep and not a failure, for a base that is empty and for one
// that does not exist alike. A directory that is not a preserved branch is a
// failure of ReadPreserved, because acting on a half-read record would target
// the wrong workdir.
func TestPreservedSweepDistinguishesNothingToFindFromCouldNotLook(t *testing.T) {
	empty := t.TempDir()

	got, err := sandlock.ListPreserved(empty)
	if err != nil {
		t.Fatalf("an empty sweep is not a failure: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("preserved = %d, want 0", len(got))
	}

	got, err = sandlock.ListPreserved(filepath.Join(empty, "nope"))
	if err != nil {
		t.Fatalf("a base that does not exist sweeps to nothing: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("preserved = %d, want 0", len(got))
	}

	if _, err := sandlock.ReadPreserved(empty); err == nil {
		t.Error("a directory with no marker is not a preserved branch")
	}

	// A path this binding cannot pass through intact is refused rather than
	// truncated at the NUL, which would sweep a different directory.
	if _, err := sandlock.ListPreserved("/a\x00b"); !errors.Is(err, sandlock.ErrInvalidString) {
		t.Errorf("ListPreserved with an interior NUL: err = %v, want ErrInvalidString", err)
	}
	if _, err := sandlock.ReadPreserved("/a\x00b"); !errors.Is(err, sandlock.ErrInvalidString) {
		t.Errorf("ReadPreserved with an interior NUL: err = %v, want ErrInvalidString", err)
	}
}

// TestTxnErrorKindIsVerdict keeps the two values that are not verdicts out of
// the set a caller switches on. -1 and -2 say nothing was decided about a
// workdir, so folding them into a named failure would report a verdict the ABI
// never gave. The sign is what decides that, not the name: an unnamed positive
// kind, which is what a newer ABI's failure looks like from here, is still the
// core's decision about a transaction.
func TestTxnErrorKindIsVerdict(t *testing.T) {
	verdicts := []sandlock.TxnErrorKind{
		sandlock.TxnErrInvalid, sandlock.TxnErrBranch, sandlock.TxnErrStage,
		sandlock.TxnErrConflict, sandlock.TxnErrCommitLock, sandlock.TxnErrMerge,
		sandlock.TxnErrCommitAbandoned, sandlock.TxnErrUnknown,
	}
	for _, k := range verdicts {
		if !k.IsVerdict() {
			t.Errorf("%v must be a verdict", k)
		}
		if strings.Contains(k.String(), "(") {
			t.Errorf("%d has no name, but every published kind needs one", int(k))
		}
	}
	for _, k := range []sandlock.TxnErrorKind{sandlock.TxnErrNullHandle, sandlock.TxnErrNoRuntime} {
		if k.IsVerdict() {
			t.Errorf("%v is not a verdict on a transaction", k)
		}
	}
	// A kind from a newer ABI: no name here, but a verdict all the same. The
	// guard exists to keep the two negatives out, and nothing else.
	if k := sandlock.TxnErrorKind(99); !k.IsVerdict() {
		t.Error("an unnamed positive kind is still a verdict; only the negatives are not")
	}
	if got, want := sandlock.TxnErrorKind(99).String(), "TxnErrorKind(99)"; got != want {
		t.Errorf("String() = %q, want %q: an unnamed kind prints its number rather than borrowing a name", got, want)
	}
	// Zero is success at the ABI and never reaches a TxnError, so it must not
	// pass a guard whose whole job is to say a failure can be reasoned from.
	if k := sandlock.TxnErrorKind(0); k.IsVerdict() {
		t.Error("zero is not a failure at all")
	}

	// Error() spells the kind out. The numbers are adjacent and two of them
	// mean opposite things, so a bare number in a log is a trap; conflict is
	// the one to check with, since its name appears in no core message.
	if got, want := (&sandlock.TxnError{Kind: sandlock.TxnErrConflict, Msg: "workdir busy"}).Error(),
		"sandlock: transaction failed (conflict): workdir busy"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	// A kind with no message must not leave a dangling separator behind.
	if got, want := (&sandlock.TxnError{Kind: sandlock.TxnErrNoRuntime}).Error(),
		"sandlock: transaction failed (no-runtime)"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}
