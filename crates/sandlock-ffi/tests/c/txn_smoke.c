/* Canonical C example for sandlock's transaction ABI (RFC #65 Phase 1).
 *
 * Drives a whole transaction lifecycle through the C ABI rather than only
 * linking against it: a stage set the core rejects, a dry run that reports a
 * change set without touching the workdir, a commit whose later stages read
 * what earlier ones wrote, an abort that leaves the workdir alone, and a sweep
 * of branch storage that finds a preserved change set and reads it back on its
 * own.
 *
 * Downstream consumers writing C/Python/etc. bindings can copy this file as a
 * starting point.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <ftw.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "sandlock.h"

/* sandlock_sandbox_builder_on_exit() actions. */
#define ON_EXIT_COMMIT 0
#define ON_EXIT_KEEP 2

/* ---------------------------------------------------------------- */
/* Scaffolding                                                        */
/* ---------------------------------------------------------------- */

static int unlink_one(const char *path, const struct stat *sb, int type,
                      struct FTW *ftw) {
    (void)sb;
    (void)type;
    (void)ftw;
    return remove(path);
}

/* Best effort cleanup of a temporary tree. A failure here cannot fail the
 * test: it would report a full /tmp as a broken ABI. */
static void remove_tree(const char *path) {
    (void)nftw(path, unlink_one, 16, FTW_DEPTH | FTW_PHYS);
}

/* A workdir plus the branch storage its copy-on-write upper lives in. Every
 * check gets its own pair so none of them can observe another's leftovers. */
struct dirs {
    char work[64];
    char store[64];
};

static int dirs_make(struct dirs *d) {
    strcpy(d->work, "/tmp/sandlock-txn-work-XXXXXX");
    strcpy(d->store, "/tmp/sandlock-txn-store-XXXXXX");
    if (mkdtemp(d->work) == NULL) {
        fprintf(stderr, "txn: mkdtemp workdir: %s\n", strerror(errno));
        return 1;
    }
    if (mkdtemp(d->store) == NULL) {
        fprintf(stderr, "txn: mkdtemp storage: %s\n", strerror(errno));
        remove_tree(d->work);
        return 1;
    }
    return 0;
}

static void dirs_drop(struct dirs *d) {
    remove_tree(d->work);
    remove_tree(d->store);
}

/* Shaped like the policy the core transaction suite uses: read the system,
 * write and copy-on-write the workdir, and run with the workdir as cwd so a
 * stage's relative paths resolve into the shared upper. */
static sandlock_sandbox_t *build_policy(const struct dirs *d, uint8_t on_exit) {
    static const char *const reads[] = {"/usr", "/lib", "/lib64",
                                        "/bin", "/etc", "/proc"};
    sandlock_builder_t *b = sandlock_sandbox_builder_new();
    for (size_t i = 0; i < sizeof reads / sizeof reads[0]; i++) {
        /* Granting a path that does not exist makes the build fail, and not
         * every grant here exists everywhere: /lib64 is absent on RISC-V
         * glibc and on musl. The ABI has no fs_read_if_exists, so the check
         * happens here. */
        if (access(reads[i], F_OK) == 0) {
            b = sandlock_sandbox_builder_fs_read(b, reads[i]);
        }
    }
    b = sandlock_sandbox_builder_fs_write(b, d->work);
    b = sandlock_sandbox_builder_workdir(b, d->work);
    b = sandlock_sandbox_builder_cwd(b, d->work);
    b = sandlock_sandbox_builder_fs_storage(b, d->store);
    if (on_exit != ON_EXIT_COMMIT) {
        b = sandlock_sandbox_builder_on_exit(b, on_exit);
    }

    int err = 0;
    char *msg = NULL;
    sandlock_sandbox_t *p = sandlock_sandbox_build(b, &err, &msg);
    if (p == NULL) {
        fprintf(stderr, "txn: policy build failed: err=%d msg=%s\n", err,
                msg == NULL ? "(none)" : msg);
        sandlock_string_free(msg);
    }
    return p;
}

static void add_shell_stage(sandlock_txn_t *t, const sandlock_sandbox_t *p,
                            const char *script) {
    const char *argv[] = {"sh", "-c", script};
    sandlock_txn_add_stage(t, p, argv, 3);
}

static int file_says(const char *dir, const char *name, const char *want) {
    char path[256];
    char buf[256];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        fprintf(stderr, "txn: %s is missing, wanted %s\n", path, want);
        return 0;
    }
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    buf[n] = '\0';
    if (strcmp(buf, want) != 0) {
        fprintf(stderr, "txn: %s holds \"%s\", want \"%s\"\n", path, buf, want);
        return 0;
    }
    return 1;
}

static int file_absent(const char *dir, const char *name) {
    char path[256];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    if (access(path, F_OK) == 0) {
        fprintf(stderr, "txn: %s exists but nothing should have written it\n",
                path);
        return 0;
    }
    return 1;
}

/* Whether every stage that ran exited with the code the caller expected. */
static int stages_exited(const sandlock_txn_outcome_t *o, const int *want,
                         uintptr_t n) {
    uintptr_t len = sandlock_txn_outcome_stages_len(o);
    if (len != n) {
        fprintf(stderr, "txn: %" PRIuPTR " stage results, want %" PRIuPTR "\n",
                len, n);
        return 0;
    }
    for (uintptr_t i = 0; i < n; i++) {
        const sandlock_result_t *r = sandlock_txn_outcome_stage_at(o, i);
        if (r == NULL) {
            fprintf(stderr, "txn: stage %" PRIuPTR " result missing\n", i);
            return 0;
        }
        int code = sandlock_result_exit_code(r);
        if (code != want[i]) {
            fprintf(stderr, "txn: stage %" PRIuPTR " exited %d, want %d\n", i,
                    code, want[i]);
            return 0;
        }
    }
    /* One past the end is null, not the last element. */
    if (sandlock_txn_outcome_stage_at(o, n) != NULL) {
        fprintf(stderr, "txn: stage_at past the end must be null\n");
        return 0;
    }
    return 1;
}

/* Whether the change set is exactly `n` additions of the named paths, in any
 * order. Every path handed out here is owned by this caller. */
static int changes_are_additions_of(const sandlock_txn_outcome_t *o,
                                    const char *const *want, uintptr_t n) {
    int seen[4] = {0};
    uintptr_t len = sandlock_txn_outcome_changes_len(o);
    int ok = 1;

    if (n > sizeof seen / sizeof seen[0]) {
        fprintf(stderr, "txn: too many expected changes for this helper\n");
        return 0;
    }
    if (len != n) {
        fprintf(stderr, "txn: %" PRIuPTR " changes, want %" PRIuPTR "\n", len,
                n);
        return 0;
    }
    for (uintptr_t i = 0; i < len; i++) {
        char kind = sandlock_txn_outcome_change_kind(o, i);
        char *path = sandlock_txn_outcome_change_path(o, i);
        if (path == NULL) {
            fprintf(stderr, "txn: change %" PRIuPTR " carries no path\n", i);
            ok = 0;
            continue;
        }
        int matched = 0;
        for (uintptr_t j = 0; j < n; j++) {
            if (kind == 'A' && seen[j] == 0 && strcmp(path, want[j]) == 0) {
                seen[j] = 1;
                matched = 1;
                break;
            }
        }
        if (!matched) {
            fprintf(stderr, "txn: unexpected change '%c' %s\n", kind, path);
            ok = 0;
        }
        sandlock_string_free(path);
    }
    /* Out of range reports nothing rather than clamping to the last entry. */
    if (sandlock_txn_outcome_change_kind(o, len) != 0 ||
        sandlock_txn_outcome_change_path(o, len) != NULL) {
        fprintf(stderr, "txn: change accessors past the end must report none\n");
        ok = 0;
    }
    return ok;
}

/* ---------------------------------------------------------------- */
/* Checks                                                             */
/* ---------------------------------------------------------------- */

/* The cross-stage guardrails belong to the core, and the C ABI reports its
 * verdict rather than inventing one: a single stage is not a transaction. */
static int check_invalid_stage_set(void) {
    struct dirs d;
    if (dirs_make(&d) != 0) {
        return 1;
    }
    sandlock_sandbox_t *p = build_policy(&d, ON_EXIT_COMMIT);
    if (p == NULL) {
        dirs_drop(&d);
        return 1;
    }

    sandlock_txn_t *t = sandlock_txn_new();
    add_shell_stage(t, p, "true");

    int err = -99;
    char *msg = NULL;
    /* The run consumes the handle even when it refuses to carry it out, so
     * there is nothing left to free here. */
    sandlock_txn_outcome_t *o = sandlock_txn_run(t, 0, &err, &msg);

    int rc = 0;
    if (o != NULL) {
        fprintf(stderr, "txn: a one stage transaction must not produce an "
                        "outcome\n");
        sandlock_txn_outcome_free(o);
        rc = 1;
    }
    if (err != SANDLOCK_TXN_INVALID) {
        fprintf(stderr, "txn: err=%d, want SANDLOCK_TXN_INVALID (%d)\n", err,
                SANDLOCK_TXN_INVALID);
        rc = 1;
    }
    if (msg == NULL) {
        fprintf(stderr, "txn: a refusal must carry the core's explanation\n");
        rc = 1;
    }
    sandlock_string_free(msg);
    sandlock_sandbox_free(p);
    dirs_drop(&d);
    return rc;
}

/* A null handle is a bug in the caller, not a verdict on a transaction: it
 * gets a negative code from outside the enum and no message, and it must
 * still clear err_msg so the caller never frees a stale pointer. */
static int check_null_handle_is_not_a_verdict(void) {
    int err = -99;
    char *msg = (char *)(uintptr_t)0x1;
    sandlock_txn_outcome_t *o = sandlock_txn_run(NULL, 0, &err, &msg);
    int rc = 0;

    if (o != NULL) {
        fprintf(stderr, "txn: a null handle must not produce an outcome\n");
        rc = 1;
    }
    if (err != SANDLOCK_TXN_NULL_HANDLE) {
        fprintf(stderr, "txn: err=%d, want SANDLOCK_TXN_NULL_HANDLE (%d)\n",
                err, SANDLOCK_TXN_NULL_HANDLE);
        rc = 1;
    }
    if (msg != NULL) {
        fprintf(stderr, "txn: err_msg must be cleared on entry\n");
        rc = 1;
    }

    /* Every other entry point tolerates a null handle too. */
    sandlock_txn_add_stage(NULL, NULL, NULL, 0);
    sandlock_txn_commit_lock_wait_ms(NULL, 100);
    sandlock_txn_free(NULL);
    sandlock_txn_outcome_free(NULL);
    if (sandlock_txn_outcome_disposition(NULL) != -1 ||
        sandlock_txn_outcome_stages_len(NULL) != 0 ||
        sandlock_txn_outcome_stage_at(NULL, 0) != NULL) {
        fprintf(stderr, "txn: null outcome accessors must report nothing\n");
        rc = 1;
    }
    return rc;
}

/* A dry run really executes every stage and reports what the shared upper
 * held, then throws that upper away: the workdir never sees it. */
static int check_dry_run_leaves_the_workdir_alone(void) {
    struct dirs d;
    if (dirs_make(&d) != 0) {
        return 1;
    }
    sandlock_sandbox_t *p = build_policy(&d, ON_EXIT_COMMIT);
    if (p == NULL) {
        dirs_drop(&d);
        return 1;
    }

    sandlock_txn_t *t = sandlock_txn_new();
    add_shell_stage(t, p, "echo plan > a.txt");
    add_shell_stage(t, p, "cat a.txt && echo built > b.txt");

    int err = -99;
    char *msg = NULL;
    sandlock_txn_outcome_t *o = sandlock_txn_dry_run(t, 0, &err, &msg);

    int rc = 0;
    if (o == NULL) {
        fprintf(stderr, "txn: dry run failed: err=%d msg=%s\n", err,
                msg == NULL ? "(none)" : msg);
        sandlock_string_free(msg);
        sandlock_sandbox_free(p);
        dirs_drop(&d);
        return 1;
    }
    if (err != SANDLOCK_TXN_OK || msg != NULL) {
        fprintf(stderr, "txn: dry run err=%d, msg must stay null on success\n",
                err);
        rc = 1;
    }
    if (sandlock_txn_outcome_disposition(o) !=
        SANDLOCK_TXN_DISPOSITION_DRY_RUN) {
        fprintf(stderr, "txn: disposition=%d, want dry run\n",
                sandlock_txn_outcome_disposition(o));
        rc = 1;
    }

    const int want_codes[] = {0, 0};
    if (!stages_exited(o, want_codes, 2)) {
        rc = 1;
    }

    /* The second stage read what the first wrote, so both files are in the
     * change set even though neither reached the workdir. */
    const char *const want_paths[] = {"a.txt", "b.txt"};
    if (!changes_are_additions_of(o, want_paths, 2)) {
        rc = 1;
    }
    if (!file_absent(d.work, "a.txt") || !file_absent(d.work, "b.txt")) {
        rc = 1;
    }

    sandlock_txn_outcome_free(o);
    sandlock_sandbox_free(p);
    dirs_drop(&d);
    return rc;
}

/* The acceptance case: stages run in order over one shared upper, a later
 * stage sees what an earlier one wrote, and the commit lands all of it. */
static int check_commit_lands_every_stage(void) {
    struct dirs d;
    if (dirs_make(&d) != 0) {
        return 1;
    }
    sandlock_sandbox_t *p = build_policy(&d, ON_EXIT_COMMIT);
    if (p == NULL) {
        dirs_drop(&d);
        return 1;
    }

    sandlock_txn_t *t = sandlock_txn_new();
    add_shell_stage(t, p, "echo plan > a.txt");
    add_shell_stage(t, p, "cat a.txt && echo built > b.txt");
    add_shell_stage(t, p, "cat a.txt b.txt");
    /* Bound the wait for the workdir lock instead of taking the core's
     * default, so a stuck commit fails this run rather than stalling it. */
    sandlock_txn_commit_lock_wait_ms(t, 10000);

    int err = -99;
    char *msg = NULL;
    sandlock_txn_outcome_t *o = sandlock_txn_run(t, 0, &err, &msg);

    int rc = 0;
    if (o == NULL) {
        fprintf(stderr, "txn: commit failed: err=%d msg=%s\n", err,
                msg == NULL ? "(none)" : msg);
        sandlock_string_free(msg);
        sandlock_sandbox_free(p);
        dirs_drop(&d);
        return 1;
    }
    if (err != SANDLOCK_TXN_OK || msg != NULL) {
        fprintf(stderr, "txn: commit err=%d, msg must stay null on success\n",
                err);
        rc = 1;
    }
    if (sandlock_txn_outcome_disposition(o) !=
        SANDLOCK_TXN_DISPOSITION_COMMITTED) {
        fprintf(stderr, "txn: disposition=%d, want committed\n",
                sandlock_txn_outcome_disposition(o));
        rc = 1;
    }

    const int want_codes[] = {0, 0, 0};
    if (!stages_exited(o, want_codes, 3)) {
        rc = 1;
    }
    const char *const want_paths[] = {"a.txt", "b.txt"};
    if (!changes_are_additions_of(o, want_paths, 2)) {
        rc = 1;
    }

    sandlock_txn_outcome_free(o);
    sandlock_sandbox_free(p);

    if (!file_says(d.work, "a.txt", "plan\n") ||
        !file_says(d.work, "b.txt", "built\n")) {
        rc = 1;
    }
    dirs_drop(&d);
    return rc;
}

/* A stage exiting non-zero is not a failure of the call: it is an outcome
 * whose disposition is "aborted", with err still 0 and the workdir untouched.
 * All or nothing means the earlier stage's write is discarded too. */
static int check_a_failing_stage_aborts_the_whole_transaction(void) {
    struct dirs d;
    if (dirs_make(&d) != 0) {
        return 1;
    }
    sandlock_sandbox_t *p = build_policy(&d, ON_EXIT_COMMIT);
    if (p == NULL) {
        dirs_drop(&d);
        return 1;
    }

    sandlock_txn_t *t = sandlock_txn_new();
    add_shell_stage(t, p, "echo one > kept.txt");
    add_shell_stage(t, p, "exit 3");

    int err = -99;
    char *msg = NULL;
    sandlock_txn_outcome_t *o = sandlock_txn_run(t, 0, &err, &msg);

    int rc = 0;
    if (o == NULL) {
        fprintf(stderr, "txn: an aborted transaction is still an outcome: "
                        "err=%d msg=%s\n",
                err, msg == NULL ? "(none)" : msg);
        sandlock_string_free(msg);
        sandlock_sandbox_free(p);
        dirs_drop(&d);
        return 1;
    }
    if (err != SANDLOCK_TXN_OK) {
        fprintf(stderr, "txn: abort err=%d, want 0\n", err);
        rc = 1;
    }
    if (sandlock_txn_outcome_disposition(o) !=
        SANDLOCK_TXN_DISPOSITION_ABORTED) {
        fprintf(stderr, "txn: disposition=%d, want aborted\n",
                sandlock_txn_outcome_disposition(o));
        rc = 1;
    }

    const int want_codes[] = {0, 3};
    if (!stages_exited(o, want_codes, 2)) {
        rc = 1;
    }
    if (!file_absent(d.work, "kept.txt")) {
        rc = 1;
    }

    sandlock_txn_outcome_free(o);
    sandlock_string_free(msg);
    sandlock_sandbox_free(p);
    dirs_drop(&d);
    return rc;
}

/* The other half of the error contract: when the ABI says a change set was
 * preserved, it has to be findable. A run that keeps its branch produces the
 * same record a deferred commit would, without needing contention to set up.
 *
 * This is also where the release asymmetry shows: the entry from the sweep is
 * a borrow released by sandlock_preserved_list_free, while the record from
 * sandlock_preserved_read is owned and released by sandlock_preserved_free. */
static int check_preserved_change_set_is_reachable(void) {
    struct dirs d;
    if (dirs_make(&d) != 0) {
        return 1;
    }
    /* Something for the run to delete: deletions are the half of the change
     * set that has no representation in the upper at all. */
    char victim[256];
    snprintf(victim, sizeof victim, "%s/victim.txt", d.work);
    FILE *f = fopen(victim, "w");
    if (f == NULL || fputs("ORIGINAL", f) == EOF) {
        fprintf(stderr, "txn: could not seed the workdir\n");
        if (f != NULL) {
            fclose(f);
        }
        dirs_drop(&d);
        return 1;
    }
    fclose(f);

    sandlock_sandbox_t *p = build_policy(&d, ON_EXIT_KEEP);
    if (p == NULL) {
        dirs_drop(&d);
        return 1;
    }

    const char *argv[] = {"sh", "-c", "rm victim.txt && echo NEW > added.txt"};
    sandlock_result_t *r = sandlock_run(p, NULL, argv, 3);
    if (r == NULL || !sandlock_result_success(r)) {
        fprintf(stderr, "txn: the run that keeps its branch did not succeed\n");
        if (r != NULL) {
            sandlock_result_free(r);
        }
        sandlock_sandbox_free(p);
        dirs_drop(&d);
        return 1;
    }
    sandlock_result_free(r);
    sandlock_sandbox_free(p);

    int rc = 0;
    sandlock_preserved_list_t *l = sandlock_preserved_list(d.store);
    if (l == NULL) {
        fprintf(stderr, "txn: a sweep of real storage must not be null\n");
        dirs_drop(&d);
        return 1;
    }
    if (sandlock_preserved_list_len(l) != 1) {
        fprintf(stderr, "txn: swept %" PRIuPTR " branches, want 1\n",
                sandlock_preserved_list_len(l));
        sandlock_preserved_list_free(l);
        dirs_drop(&d);
        return 1;
    }

    const sandlock_preserved_t *entry = sandlock_preserved_list_at(l, 0);
    if (entry == NULL || sandlock_preserved_list_at(l, 1) != NULL) {
        fprintf(stderr, "txn: list_at must yield entry 0 and nothing past it\n");
        sandlock_preserved_list_free(l);
        dirs_drop(&d);
        return 1;
    }
    if (sandlock_preserved_reason(entry) != SANDLOCK_PRESERVE_KEPT) {
        fprintf(stderr, "txn: reason=%d, want SANDLOCK_PRESERVE_KEPT (%d)\n",
                sandlock_preserved_reason(entry), SANDLOCK_PRESERVE_KEPT);
        rc = 1;
    }
    if (sandlock_preserved_pid(entry) != (uint32_t)getpid()) {
        fprintf(stderr, "txn: pid=%" PRIu32 ", want this process (%d)\n",
                sandlock_preserved_pid(entry), (int)getpid());
        rc = 1;
    }
    if (sandlock_preserved_deleted_len(entry) != 1) {
        fprintf(stderr, "txn: %" PRIuPTR " deletions, want 1\n",
                sandlock_preserved_deleted_len(entry));
        rc = 1;
    } else {
        char *gone = sandlock_preserved_deleted_at(entry, 0);
        if (gone == NULL || strcmp(gone, "victim.txt") != 0) {
            fprintf(stderr, "txn: deletion is \"%s\", want victim.txt\n",
                    gone == NULL ? "(null)" : gone);
            rc = 1;
        }
        sandlock_string_free(gone);
    }

    char *upper = sandlock_preserved_upper(entry);
    char *branch_dir = sandlock_preserved_branch_dir(entry);
    if (upper == NULL || branch_dir == NULL) {
        fprintf(stderr, "txn: a record must name its branch dir and upper\n");
        sandlock_string_free(upper);
        sandlock_string_free(branch_dir);
        sandlock_preserved_list_free(l);
        dirs_drop(&d);
        return 1;
    }
    if (strncmp(upper, branch_dir, strlen(branch_dir)) != 0) {
        fprintf(stderr, "txn: upper %s is not inside branch dir %s\n", upper,
                branch_dir);
        rc = 1;
    }
    if (!file_says(upper, "added.txt", "NEW\n")) {
        rc = 1;
    }

    /* The branch dir the sweep reported is what a recovery reads on its own,
     * and what it removes afterwards. */
    sandlock_preserved_t *owned = sandlock_preserved_read(branch_dir);
    if (owned == NULL) {
        fprintf(stderr, "txn: the swept branch dir must be readable alone\n");
        rc = 1;
    }

    /* Freeing the list invalidates `entry`, but not the strings it handed
     * out: those are separate allocations this caller still owns. */
    sandlock_preserved_list_free(l);

    if (owned != NULL) {
        if (sandlock_preserved_reason(owned) != SANDLOCK_PRESERVE_KEPT ||
            sandlock_preserved_deleted_len(owned) != 1) {
            fprintf(stderr, "txn: the owned record must carry the same change "
                            "set the sweep did\n");
            rc = 1;
        }
        /* Only this handle may be freed this way; the borrow above may not. */
        sandlock_preserved_free(owned);
    }

    sandlock_string_free(upper);
    sandlock_string_free(branch_dir);

    /* A sweep of a base that holds nothing is an empty list, not an error. */
    sandlock_preserved_list_t *empty = sandlock_preserved_list(d.work);
    if (empty == NULL || sandlock_preserved_list_len(empty) != 0) {
        fprintf(stderr, "txn: an empty sweep must be an empty list\n");
        rc = 1;
    }
    sandlock_preserved_list_free(empty);
    if (sandlock_preserved_list(NULL) != NULL ||
        sandlock_preserved_read(NULL) != NULL) {
        fprintf(stderr, "txn: a null path must not be swept or read\n");
        rc = 1;
    }
    sandlock_preserved_list_free(NULL);
    sandlock_preserved_free(NULL);

    dirs_drop(&d);
    return rc;
}

int main(void) {
    if (check_null_handle_is_not_a_verdict() != 0) {
        return 1;
    }
    if (check_invalid_stage_set() != 0) {
        return 1;
    }
    if (check_dry_run_leaves_the_workdir_alone() != 0) {
        return 1;
    }
    if (check_commit_lands_every_stage() != 0) {
        return 1;
    }
    if (check_a_failing_stage_aborts_the_whole_transaction() != 0) {
        return 1;
    }
    if (check_preserved_change_set_is_reachable() != 0) {
        return 1;
    }
    return 0;
}
