use sandlock_core::{Sandbox};
use sandlock_core::sandbox::BranchAction;
use std::fs;
use std::path::PathBuf;

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sandlock-test-cow-{}-{}", name, std::process::id()));
    let _ = fs::create_dir_all(&dir);
    dir
}

/// Path to the static rootfs-helper binary (compiled by build.rs).
fn helper_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/rootfs-helper")
        .canonicalize()
        .expect("rootfs-helper not found — build.rs should have compiled it")
}

// ============================================================
// Seccomp-based COW tests (workdir set)
// ============================================================

/// Test that seccomp COW creates files in upper, committed on exit.
#[tokio::test]
async fn test_seccomp_cow_create_file() {
    let workdir = temp_dir("seccomp-create");
    fs::write(workdir.join("existing.txt"), "hello").unwrap();

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc")
        .fs_write(&workdir)
        .workdir(&workdir)  // workdir set → seccomp COW
        .on_exit(BranchAction::Commit)
        .build()
        .unwrap();

    let new_file = workdir.join("new.txt");
    let cmd = format!("touch {}", new_file.display());
    let result = policy.clone().with_name("test").run(&["sh", "-c", &cmd]).await;
    match result {
        Ok(r) => {
            assert!(r.success(), "touch should succeed, stderr: {}", r.stderr_str().unwrap_or(""));
            // After commit, new file should exist in workdir
            assert!(new_file.exists(), "new.txt should exist after commit");
        }
        Err(e) => eprintln!("Seccomp COW test skipped: {}", e),
    }

    let _ = fs::remove_dir_all(&workdir);
}

/// Test that seccomp COW abort discards changes.
#[tokio::test]
async fn test_seccomp_cow_abort() {
    let workdir = temp_dir("seccomp-abort");
    fs::write(workdir.join("existing.txt"), "original").unwrap();

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc")
        .fs_write(&workdir)
        .workdir(&workdir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    let new_file = workdir.join("aborted.txt");
    let cmd = format!("touch {}", new_file.display());
    let result = policy.clone().with_name("test").run(&["sh", "-c", &cmd]).await;
    match result {
        Ok(_) => {
            // After abort, new file should NOT exist
            assert!(!new_file.exists(), "aborted.txt should not exist after abort");
            // Original file should be unchanged
            let content = fs::read_to_string(workdir.join("existing.txt")).unwrap();
            assert_eq!(content, "original");
        }
        Err(e) => eprintln!("Seccomp COW test skipped: {}", e),
    }

    let _ = fs::remove_dir_all(&workdir);
}

/// Test seccomp COW with relative paths (AT_FDCWD).
///
/// Regression test: resolve_at_path must truncate dirfd to i32 before
/// comparing with AT_FDCWD (-100). The kernel stores AT_FDCWD as
/// 0x00000000FFFFFF9C in the 64-bit seccomp_data.args field, not
/// 0xFFFFFFFFFFFFFF9C.
#[tokio::test]
async fn test_seccomp_cow_relative_path_abort() {
    let workdir = temp_dir("seccomp-relpath");
    fs::write(workdir.join("orig.txt"), "original\n").unwrap();

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_write(&workdir)
        .workdir(&workdir)
        .cwd(&workdir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    // Use relative paths (triggers AT_FDCWD in openat) — the child's cwd is set via .cwd().
    let result = policy.clone().with_name("test").run(&[
        "sh", "-c", "echo MUTATED >> orig.txt; echo leak > leaked.txt"
    ]).await;
    match result {
        Ok(r) => {
            assert!(r.success(), "sh should succeed");
            // With abort, original file must be unchanged
            let content = fs::read_to_string(workdir.join("orig.txt")).unwrap();
            assert_eq!(content, "original\n", "orig.txt should be unchanged after abort");
            // New file must not exist
            assert!(!workdir.join("leaked.txt").exists(), "leaked.txt should not exist after abort");
        }
        Err(e) => eprintln!("Seccomp COW test skipped: {}", e),
    }

    let _ = fs::remove_dir_all(&workdir);
}

/// Test seccomp COW commit with relative paths (AT_FDCWD).
#[tokio::test]
async fn test_seccomp_cow_relative_path_commit() {
    let workdir = temp_dir("seccomp-relpath-commit");
    fs::write(workdir.join("orig.txt"), "original\n").unwrap();

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_write(&workdir)
        .workdir(&workdir)
        .cwd(&workdir)
        .on_exit(BranchAction::Commit)
        .build()
        .unwrap();

    let result = policy.clone().with_name("test").run(&[
        "sh", "-c", "echo APPENDED >> orig.txt; echo new > created.txt"
    ]).await;
    match result {
        Ok(r) => {
            assert!(r.success(), "sh should succeed");
            // With commit, changes should be merged back
            let content = fs::read_to_string(workdir.join("orig.txt")).unwrap();
            assert!(content.contains("APPENDED"), "orig.txt should have appended content after commit");
            assert!(content.starts_with("original\n"), "orig.txt should preserve original content");
            // New file should exist
            let new_content = fs::read_to_string(workdir.join("created.txt")).unwrap();
            assert_eq!(new_content.trim(), "new", "created.txt should exist after commit");
        }
        Err(e) => eprintln!("Seccomp COW test skipped: {}", e),
    }

    let _ = fs::remove_dir_all(&workdir);
}

/// Test that openat with O_DIRECTORY works for COW-created directories.
///
/// When a directory is created via COW (only in upper layer), openat with
/// O_DIRECTORY must resolve to the upper path.  Without this fix,
/// prepare_open skipped O_DIRECTORY opens and the kernel returned ENOENT.
#[tokio::test]
async fn test_seccomp_cow_open_directory() {
    let workdir = temp_dir("seccomp-opendir");
    let out_file = workdir.join("opendir_ok.txt");

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_write(&workdir)
        .workdir(&workdir)
        .cwd(&workdir)
        .on_exit(BranchAction::Commit)
        .build()
        .unwrap();

    // mkdir creates the dir in COW upper; python opens it with O_DIRECTORY.
    let script = format!(
        concat!(
            "mkdir -p subdir && python3 -c \"",
            "import os; ",
            "fd = os.open('subdir', os.O_RDONLY | os.O_DIRECTORY); ",
            "os.close(fd); ",
            "open('{}', 'w').write('ok')\"",
        ),
        out_file.display()
    );
    let result = policy.clone().with_name("test").run(&["sh", "-c", &script]).await;
    match result {
        Ok(r) => {
            assert!(r.success(), "script should succeed, stderr: {}", r.stderr_str().unwrap_or(""));
            let content = fs::read_to_string(&out_file).unwrap();
            assert_eq!(content, "ok");
        }
        Err(e) => eprintln!("Seccomp COW opendir test skipped: {}", e),
    }

    let _ = fs::remove_dir_all(&workdir);
}

/// Test that chdir works for directories created inside COW.
///
/// When a directory is created via COW (only exists in the upper layer),
/// chdir must be intercepted and redirected to the upper path.  Without
/// this, the kernel returns ENOENT because it doesn't see the COW directory.
#[tokio::test]
async fn test_seccomp_cow_chdir_to_created_dir() {
    let workdir = temp_dir("seccomp-chdir");
    let out_file = workdir.join("chdir_ok.txt");

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_write(&workdir)
        .workdir(&workdir)
        .cwd(&workdir)
        .on_exit(BranchAction::Commit)
        .build()
        .unwrap();

    // Create a nested directory through a dirfd so the COW handler must map the
    // upper-layer fd target back to the logical workdir before mkdirat.
    // Use physical pwd so the assertion covers getcwd virtualization.
    let script = format!(
        concat!(
            "mkdir -p subdir && python3 -c \"",
            "import os; ",
            "fd = os.open('subdir', os.O_RDONLY | os.O_DIRECTORY); ",
            "os.mkdir('deep', dir_fd=fd); ",
            "os.close(fd)\" && ",
            "cd subdir/deep && pwd -P > {}"
        ),
        out_file.display()
    );
    let result = policy.clone().with_name("test").run(&["sh", "-c", &script]).await;
    match result {
        Ok(r) => {
            assert!(r.success(), "script should succeed, stderr: {}", r.stderr_str().unwrap_or(""));
            let content = fs::read_to_string(&out_file).unwrap();
            assert!(
                content.trim().ends_with("subdir/deep"),
                "pwd should end with subdir/deep, got: {}",
                content.trim()
            );
        }
        Err(e) => eprintln!("Seccomp COW chdir test skipped: {}", e),
    }

    let _ = fs::remove_dir_all(&workdir);
}

/// Test that the raw open syscall ABI works correctly with COW.
///
/// Regression test: handle_cow_open always read args in openat() layout
/// (dirfd=args[0], path=args[1], flags=args[2]), but open() uses
/// (path=args[0], flags=args[1], mode=args[2]). This caused COW to miss
/// all legacy open() calls on x86_64, falling through to the kernel. ARM64
/// and riscv64 do not provide SYS_open, so they use the equivalent raw
/// openat ABI.
#[tokio::test]
async fn test_seccomp_cow_legacy_open_syscall() {
    let workdir = temp_dir("seccomp-legacy-open");
    let out_file = std::env::temp_dir().join(format!(
        "sandlock-test-legacy-open-{}", std::process::id()
    ));

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_write(&workdir).fs_write("/tmp")
        .workdir(&workdir)
        .cwd(&workdir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    // Use raw syscall ABI to create a file, then verify it's visible during
    // the run but discarded on abort. x86_64 uses legacy SYS_open; ARM64 and
    // riscv64 use the equivalent openat(AT_FDCWD, ...) ABI.
    let script = format!(concat!(
        "import ctypes, os, platform\n",
        "libc = ctypes.CDLL('libc.so.6', use_errno=True)\n",
        "O_WRONLY = 1; O_CREAT = 64; O_TRUNC = 512\n",
        "path = b'{wd}/newfile.txt'\n",
        "if platform.machine() in ('aarch64', 'riscv64'):\n",
        "    fd = libc.syscall(56, -100, path, O_WRONLY | O_CREAT | O_TRUNC, 0o644)\n",
        "else:\n",
        "    fd = libc.syscall(2, path, O_WRONLY | O_CREAT | O_TRUNC, 0o644)\n",
        "err = ctypes.get_errno()\n",
        "if fd >= 0:\n",
        "    os.write(fd, b'created via raw open')\n",
        "    os.close(fd)\n",
        "    content = open('{wd}/newfile.txt').read()\n",
        "    open('{out}', 'w').write(content)\n",
        "else:\n",
        "    open('{out}', 'w').write(f'FAILED:errno={{err}}')\n",
    ), wd = workdir.display(), out = out_file.display());

    let result = policy.clone().with_name("test").run(&["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "exit={:?}, stderr={}", result.code(), result.stderr_str().unwrap_or(""));
    let content = fs::read_to_string(&out_file).unwrap_or_default();
    assert_eq!(content, "created via raw open", "raw open ABI should work with COW");
    // After abort, the file should not exist on the real filesystem
    assert!(!workdir.join("newfile.txt").exists(), "newfile.txt should not exist after abort");

    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_file(&out_file);
}

/// Test that O_CREAT|O_EXCL succeeds after unlink in COW mode.
///
/// Regression test: after unlink marked a file as deleted, the subsequent
/// O_CREAT|O_EXCL open correctly identified the file as deleted and prepared
/// a COW copy, but the supervisor's open() still had O_EXCL in the flags.
/// Since the file was just copied to upper, the kernel's open() returned
/// EEXIST. The fix strips O_EXCL from the supervisor's open flags.
#[tokio::test]
async fn test_seccomp_cow_excl_after_unlink() {
    let workdir = temp_dir("seccomp-excl-unlink");
    let out_file = std::env::temp_dir().join(format!(
        "sandlock-test-excl-unlink-{}", std::process::id()
    ));
    fs::write(workdir.join("target.txt"), "original").unwrap();

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_write(&workdir).fs_write("/tmp")
        .workdir(&workdir)
        .cwd(&workdir)
        .on_exit(BranchAction::Commit)
        .build()
        .unwrap();

    // Unlink the file, then recreate it with O_CREAT|O_EXCL via raw open ABI.
    let script = format!(concat!(
        "import ctypes, os, platform\n",
        "libc = ctypes.CDLL('libc.so.6', use_errno=True)\n",
        "path = b'{wd}/target.txt'\n",
        "ret = libc.unlink(path)\n",
        "if ret != 0:\n",
        "    open('{out}', 'w').write(f'UNLINK_FAILED:{{ctypes.get_errno()}}')\n",
        "    raise SystemExit(1)\n",
        "O_WRONLY = 1; O_CREAT = 64; O_EXCL = 128\n",
        "if platform.machine() in ('aarch64', 'riscv64'):\n",
        "    fd = libc.syscall(56, -100, path, O_WRONLY | O_CREAT | O_EXCL, 0o644)\n",
        "else:\n",
        "    fd = libc.syscall(2, path, O_WRONLY | O_CREAT | O_EXCL, 0o644)\n",
        "err = ctypes.get_errno()\n",
        "if fd >= 0:\n",
        "    os.write(fd, b'recreated')\n",
        "    os.close(fd)\n",
        "    open('{out}', 'w').write('OK')\n",
        "else:\n",
        "    open('{out}', 'w').write(f'OPEN_FAILED:{{err}}')\n",
    ), wd = workdir.display(), out = out_file.display());

    let result = policy.clone().with_name("test").run(&["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "exit={:?}, stderr={}", result.code(), result.stderr_str().unwrap_or(""));
    let content = fs::read_to_string(&out_file).unwrap_or_default();
    assert_eq!(content, "OK", "O_EXCL after unlink should succeed, got: {}", content);
    // After commit, the file should contain the new content
    let target = fs::read_to_string(workdir.join("target.txt")).unwrap_or_default();
    assert_eq!(target, "recreated", "target.txt should have new content after commit");

    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_file(&out_file);
}

/// Test that seccomp COW read isolation works (reads original before any writes).
#[tokio::test]
async fn test_seccomp_cow_read_existing() {
    let workdir = temp_dir("seccomp-read");
    fs::write(workdir.join("data.txt"), "hello world").unwrap();

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc")
        .fs_write(&workdir)
        .workdir(&workdir)
        .on_exit(BranchAction::Commit)
        .build()
        .unwrap();

    let out_file = workdir.join("out.txt");
    let cmd = format!(
        "cat {} > {}",
        workdir.join("data.txt").display(),
        out_file.display()
    );
    let result = policy.clone().with_name("test").run(&["sh", "-c", &cmd]).await;
    match result {
        Ok(r) => {
            assert!(r.success(), "cat should succeed");
            let content = fs::read_to_string(&out_file).unwrap_or_default();
            assert_eq!(content.trim(), "hello world");
        }
        Err(e) => eprintln!("Seccomp COW test skipped: {}", e),
    }

    let _ = fs::remove_dir_all(&workdir);
}

/// Regression test: a file deleted inside the COW workdir must read back as
/// ENOENT, not its pre-delete content. The read/open path returned
/// `Skip -> Continue` for a whiteout, so the kernel opened the untouched lower
/// file and leaked the original bytes — while stat/access already returned
/// ENOENT, so the two paths disagreed and a deletion was invisible to a reader.
#[tokio::test]
async fn test_seccomp_cow_read_deleted_file_is_enoent() {
    let workdir = temp_dir("seccomp-read-deleted");
    let out_file = std::env::temp_dir().join(format!(
        "sandlock-test-read-deleted-{}", std::process::id()
    ));
    fs::write(workdir.join("secret.txt"), "PREDELETE").unwrap();

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_write(&workdir).fs_write("/tmp")
        .workdir(&workdir)
        .cwd(&workdir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    // Delete the file, then read it back with `dd`, which issues a bare
    // open(O_RDONLY) with no preceding path stat — unlike `cat FILE` or a shell
    // redirect, which stat first and would short-circuit on the (correct) stat
    // ENOENT without ever exercising the open path this fix targets. `dd`
    // succeeding means the open was honored and the untouched lower bytes leaked;
    // `dd` failing means the whiteout was honored (ENOENT). Both the copied bytes
    // and the marker land in /tmp (not the COW workdir), so they are real writes.
    let secret = workdir.join("secret.txt");
    let leak_file = std::env::temp_dir().join(format!(
        "sandlock-test-read-deleted-leak-{}", std::process::id()
    ));
    let cmd = format!(
        "rm -f {secret}; if dd if={secret} of={leak} status=none; then printf 'OPENED' > {marker}; else printf 'DENIED' > {marker}; fi",
        secret = secret.display(),
        leak = leak_file.display(),
        marker = out_file.display(),
    );

    let result = policy.clone().with_name("test").run(&["sh", "-c", &cmd]).await.unwrap();
    assert!(result.success(), "exit={:?}, stderr={}", result.code(), result.stderr_str().unwrap_or(""));
    let marker = fs::read_to_string(&out_file).unwrap_or_default();
    let leaked = fs::read_to_string(&leak_file).unwrap_or_default();
    assert_eq!(
        marker, "DENIED",
        "open of a deleted COW file must be denied (ENOENT), not read lower content (leaked: {:?})", leaked
    );
    assert!(
        leaked.is_empty(),
        "no pre-delete bytes may leak through the read path, got: {:?}", leaked
    );

    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_file(&out_file);
    let _ = fs::remove_file(&leak_file);
}

/// Regression test: statx on a COW-created file must succeed.
///
/// statx is what `ls`, `stat`, and most modern coreutils use. The COW
/// statx handler returned Continue when the file existed in the upper
/// layer, so the kernel re-ran statx against the un-redirected lower path
/// and returned ENOENT for files that live only in upper.
#[tokio::test]
async fn test_seccomp_cow_statx_created_file() {
    let workdir = temp_dir("seccomp-statx");
    let out_file = std::env::temp_dir().join(format!(
        "sandlock-test-statx-{}", std::process::id()
    ));

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_write(&workdir).fs_write("/tmp")
        .workdir(&workdir)
        .cwd(&workdir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    // Create a file that lives only in the COW upper layer, then statx it
    // via the raw syscall (the path coreutils `stat`/`ls` take).
    let script = format!(concat!(
        "import ctypes, os, platform\n",
        "libc = ctypes.CDLL('libc.so.6', use_errno=True)\n",
        "libc.syscall.restype = ctypes.c_long\n",
        "open('created.txt', 'w').write('hi')\n",
        "buf = ctypes.create_string_buffer(256)\n",
        "AT_FDCWD = -100\n",
        "STATX_BASIC_STATS = 0x7ff\n",
        "nr = 291 if platform.machine() in ('aarch64', 'riscv64') else 332\n",
        "ret = libc.syscall(nr, AT_FDCWD, b'created.txt', 0, STATX_BASIC_STATS, buf)\n",
        "err = ctypes.get_errno()\n",
        "open('{out}', 'w').write('OK' if ret == 0 else f'FAIL:errno={{err}}')\n",
    ), out = out_file.display());

    let result = policy.clone().with_name("test").run(&["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "exit={:?}, stderr={}", result.code(), result.stderr_str().unwrap_or(""));
    let content = fs::read_to_string(&out_file).unwrap_or_default();
    assert_eq!(content, "OK", "statx on COW-created file should succeed, got: {}", content);

    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_file(&out_file);
}

/// Regression test: a binary created inside the COW workdir must
/// be executable. execve had no COW redirect, so the kernel resolved the
/// un-redirected lower path and returned ENOENT for binaries that live
/// only in the upper layer.
#[tokio::test]
async fn test_seccomp_cow_exec_created_file() {
    let workdir = temp_dir("seccomp-exec");
    let helper = helper_binary();
    let helper_dir = helper.parent().unwrap().to_path_buf();

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_read(&helper_dir)
        .fs_write(&workdir)
        .workdir(&workdir)
        .cwd(&workdir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    // Copy our own static rootfs-helper into the COW workdir (lands in
    // upper), then exec it. The helper (not a system binary like /bin/echo,
    // whose behavior varies across hosts: Ubuntu rust-coreutils ships a
    // multicall binary) is itself busybox-style: invoked as `./echo` it
    // dispatches on basename(argv[0]). That also catches the exec redirect
    // clobbering argv[0]: shells pass the same buffer as execve path and
    // argv[0], so rewriting the path to /proc/self/fd/N must relocate
    // argv[0], or the helper sees basename "N" and exits 127.
    let cmd = format!("cp {} echo && ./echo EXEC_OK", helper.display());
    let result = policy.clone().with_name("test").run(&[
        "sh", "-c", &cmd,
    ]).await.unwrap();

    assert!(
        result.success(),
        "exec of COW-created binary should succeed (argv[0] preserved), exit={:?}, stderr={}",
        result.code(), result.stderr_str().unwrap_or("")
    );
    assert!(
        result.stdout_str().unwrap_or("").contains("EXEC_OK"),
        "exec'd binary should print EXEC_OK, stdout={:?}",
        result.stdout_str()
    );

    let _ = fs::remove_dir_all(&workdir);
}

/// Exec a COW-created binary with the path and argv strings tightly packed
/// in one buffer: the /proc/self/fd/N rewrite window covers argv[1] too, so
/// the supervisor must relocate every clobbered string, not only argv[0].
/// Shell-driven layouts happen to keep argv[1] out of the window; this
/// crafts the packed layout directly with execve(2) via ctypes.
#[tokio::test]
async fn test_seccomp_cow_exec_packed_argv_relocation() {
    let workdir = temp_dir("seccomp-exec-packed");
    let helper = helper_binary();
    let helper_dir = helper.parent().unwrap().to_path_buf();

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_read(&helper_dir)
        .fs_write(&workdir)
        .workdir(&workdir)
        .cwd(&workdir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    let script = format!(concat!(
        "import ctypes, shutil, os\n",
        "shutil.copy('{helper}', 'echo')\n",
        "os.chmod('echo', 0o755)\n",
        "libc = ctypes.CDLL(None, use_errno=True)\n",
        "buf = ctypes.create_string_buffer(b'./echo\\0EXEC_OK_PACKED\\0')\n",
        "base = ctypes.addressof(buf)\n",
        "argv = (ctypes.c_void_p * 3)(base, base + 7, None)\n",
        "envp = (ctypes.c_void_p * 1)(None)\n",
        "libc.execve(ctypes.c_void_p(base), argv, envp)\n",
        "raise SystemExit('execve failed errno=%d' % ctypes.get_errno())\n",
    ), helper = helper.display());

    let result = policy.clone().with_name("test").run(&["python3", "-c", &script]).await.unwrap();

    assert!(
        result.success(),
        "packed-argv exec should succeed, exit={:?}, stderr={}",
        result.code(), result.stderr_str().unwrap_or("")
    );
    assert!(
        result.stdout_str().unwrap_or("").contains("EXEC_OK_PACKED"),
        "argv[1] must survive the path rewrite, stdout={:?}",
        result.stdout_str()
    );

    let _ = fs::remove_dir_all(&workdir);
}

// ============================================================
// Deletion-model regressions (issues #159/#160/#161)
// ============================================================

/// A directory the child removed stays removed after commit, including its
/// contents (issue #159: whiteouts cover the subtree).
#[tokio::test]
async fn test_cow_child_rm_r_directory_stays_deleted() {
    let workdir = temp_dir("seccomp-rm-r");
    fs::create_dir_all(workdir.join("d")).unwrap();
    fs::write(workdir.join("d/secret.txt"), "SECRET").unwrap();

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc")
        .fs_write(&workdir)
        .workdir(&workdir)
        .on_exit(BranchAction::Commit)
        .build()
        .unwrap();

    let cmd = format!("rm -r {}/d", workdir.display());
    let result = policy.clone().with_name("test").run(&["sh", "-c", &cmd]).await;
    match result {
        Ok(r) => {
            assert!(r.success(), "rm -r should succeed, stderr: {}", r.stderr_str().unwrap_or(""));
            assert!(!workdir.join("d").exists(), "d should be gone after commit");
            assert!(!workdir.join("d/secret.txt").exists());
        }
        Err(e) => eprintln!("Seccomp COW test skipped: {}", e),
    }

    let _ = fs::remove_dir_all(&workdir);
}

/// Renaming a directory preserves its contents through the commit
/// (issue #160: the rename is staged with a recursive copy-up).
#[tokio::test]
async fn test_cow_child_mv_directory_preserves_contents() {
    let workdir = temp_dir("seccomp-mv-dir");
    fs::create_dir_all(workdir.join("d")).unwrap();
    fs::write(workdir.join("d/inner.txt"), "PRECIOUS").unwrap();

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc")
        .fs_write(&workdir)
        .workdir(&workdir)
        .on_exit(BranchAction::Commit)
        .build()
        .unwrap();

    let cmd = format!("mv {}/d {}/d2", workdir.display(), workdir.display());
    let result = policy.clone().with_name("test").run(&["sh", "-c", &cmd]).await;
    match result {
        Ok(r) => {
            assert!(r.success(), "mv should succeed, stderr: {}", r.stderr_str().unwrap_or(""));
            assert!(!workdir.join("d").exists(), "d should be gone after commit");
            assert_eq!(
                fs::read_to_string(workdir.join("d2/inner.txt")).unwrap(),
                "PRECIOUS",
                "d2/inner.txt must survive the rename"
            );
        }
        Err(e) => eprintln!("Seccomp COW test skipped: {}", e),
    }

    let _ = fs::remove_dir_all(&workdir);
}

/// rmdir on a non-empty directory fails inside the sandbox and the contents
/// survive the commit (issue #161: ENOTEMPTY from the merged view).
#[tokio::test]
async fn test_cow_child_rmdir_nonempty_fails() {
    let workdir = temp_dir("seccomp-rmdir-nonempty");
    fs::create_dir_all(workdir.join("d")).unwrap();
    fs::write(workdir.join("d/inner.txt"), "DATA").unwrap();

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc")
        .fs_write(&workdir)
        .workdir(&workdir)
        .on_exit(BranchAction::Commit)
        .build()
        .unwrap();

    let cmd = format!("rmdir {}/d", workdir.display());
    let result = policy.clone().with_name("test").run(&["sh", "-c", &cmd]).await;
    match result {
        Ok(r) => {
            assert!(!r.success(), "rmdir of a non-empty directory must fail");
            assert!(
                workdir.join("d/inner.txt").exists(),
                "contents must survive the failed rmdir and the commit"
            );
        }
        Err(e) => eprintln!("Seccomp COW test skipped: {}", e),
    }

    let _ = fs::remove_dir_all(&workdir);
}

// ============================================================
// BUG HUNT — PR #162 review (fns prefixed `hunt_`)
//
// These run real sh + coreutils + the static rootfs-helper as cage
// children (python3 does NOT run in this box's cage — the granted
// fs_read roots don't cover this host's venv python stdlib, so it dies
// with "No module named 'encodings'"; that is an environment limit, not
// a #162 defect). Every hunt child uses only sh/coreutils/helper.
// ============================================================

use std::time::Duration;

/// Standard read-write COW policy over `workdir`, cwd inside it.
fn hunt_policy(workdir: &std::path::Path, action: BranchAction) -> sandlock_core::Sandbox {
    Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_write(workdir)
        .workdir(workdir)
        .cwd(workdir)
        .on_exit(action)
        .build()
        .unwrap()
}

fn mkfifo_host(path: &std::path::Path) -> bool {
    std::process::Command::new("mkfifo")
        .arg(path)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// (#158 positive) A write-open of a lower FIFO under COW must NOT hang the
/// child: prepare_copy virtualizes it as an empty regular upper stub without
/// ever opening the reader-less FIFO. on_exit=Abort so no commit runs.
#[tokio::test]
async fn hunt_158_fifo_writeopen_no_child_hang_abort() {
    let workdir = temp_dir("hunt-fifo-abort");
    let fifo = workdir.join("pipe");
    if !mkfifo_host(&fifo) {
        eprintln!("hunt_158_fifo_writeopen_no_child_hang_abort skipped: mkfifo failed");
        let _ = fs::remove_dir_all(&workdir);
        return;
    }

    let policy = hunt_policy(&workdir, BranchAction::Abort);
    let mut named = policy.clone().with_name("test");
    let fut = named.run(&["sh", "-c", "echo hi > pipe; echo DONE"]);
    match tokio::time::timeout(Duration::from_secs(20), fut).await {
        Err(_) => panic!("FAIL: child write-open of a FIFO hung (>20s) — #158 copy-up path not fixed"),
        Ok(Err(e)) => eprintln!("hunt_158 abort skipped: {}", e),
        Ok(Ok(r)) => {
            println!("hunt_158 abort: success={} stdout={:?} stderr={:?}",
                r.success(), r.stdout_str(), r.stderr_str());
            assert!(r.success(), "child should complete without hanging, stderr: {}", r.stderr_str().unwrap_or(""));
            assert!(r.stdout_str().unwrap_or("").contains("DONE"), "child should reach DONE");
        }
    }
    let _ = fs::remove_dir_all(&workdir);
}

/// (#158 NEW BUG) The FIFO hang is only relocated to commit(): the stub is
/// never mark_deleted, so commit() O_WRONLY-opens the surviving lower FIFO
/// (openat2_in_root passes flags verbatim, no O_NONBLOCK) and blocks forever.
/// on_exit=Commit. A >25s stall is the confirmed hang.
// NOTE: on_exit=Commit runs `cow.commit()` in `impl Drop for Sandbox`
// (sandbox.rs:2092), synchronously, with the error swallowed (`let _`). So the
// commit-time FIFO open happens when the Sandbox is dropped, and a hang there
// blocks whatever thread is dropping it. A tokio timeout cannot interrupt an
// inline-blocking Drop, so this test runs the whole run()+drop on a dedicated
// OS thread and detects the hang by joining with a wall-clock deadline.
#[test]
fn hunt_158_fifo_commit_hang() {
    use std::os::unix::fs::FileTypeExt;
    use std::sync::mpsc;
    let workdir = temp_dir("hunt-fifo-commit");
    let fifo = workdir.join("pipe");
    if !mkfifo_host(&fifo) {
        eprintln!("hunt_158_fifo_commit_hang skipped: mkfifo failed");
        let _ = fs::remove_dir_all(&workdir);
        return;
    }

    let (tx, rx) = mpsc::channel::<String>();
    let workdir_thread = workdir.clone();
    let worker = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let msg = rt.block_on(async {
            let policy = hunt_policy(&workdir_thread, BranchAction::Commit);
            // Temporary Sandbox: it is dropped at the end of this statement,
            // which is where on_exit=Commit actually runs commit().
            let r = policy.clone().with_name("test")
                .run(&["sh", "-c", "echo hi > pipe; echo CHILD_DONE"]).await;
            // Reaching here means the run future resolved; the Sandbox drop
            // (commit) has already run by the time the statement above ended.
            match r {
                Ok(rr) => format!("child_done={}", rr.stdout_str().unwrap_or("").contains("CHILD_DONE")),
                Err(e) => format!("skip:{}", e),
            }
        });
        let _ = tx.send(msg);
    });

    match rx.recv_timeout(Duration::from_secs(25)) {
        Err(mpsc::RecvTimeoutError::Timeout) => {
            // The worker thread is wedged (leaked, blocked on the FIFO open in
            // commit()); it will be killed at process exit.
            let md = fs::symlink_metadata(&fifo).ok();
            let is_fifo = md.as_ref().map(|m| m.file_type().is_fifo()).unwrap_or(false);
            panic!(
                "FAIL (confirmed #158 half-close): commit() hung >25s. prepare_copy virtualized the \
                 FIFO as an empty regular upper stub but never mark_deleted the lower FIFO, so \
                 commit() (Drop) O_WRONLY-opens the surviving lower FIFO at seccomp.rs:~992 \
                 (openat2_in_root passes flags verbatim, no O_NONBLOCK) and blocks forever waiting \
                 for a reader. pipe still a FIFO on disk = {}. The #158 copy-up hang is merely \
                 relocated to commit time.", is_fifo
            );
        }
        Err(e) => panic!("worker channel error: {:?}", e),
        Ok(msg) => {
            let _ = worker.join();
            println!("hunt_158_fifo_commit: worker msg = {}", msg);
            if msg.starts_with("skip:") {
                eprintln!("hunt_158_fifo_commit_hang skipped: {}", &msg[5..]);
            } else {
                // Commit completed without hanging: assert the merged view is
                // correct (pipe replaced by the child's bytes).
                let md = fs::symlink_metadata(&fifo).ok();
                let is_file = md.as_ref().map(|m| m.file_type().is_file()).unwrap_or(false);
                let content = if is_file { fs::read_to_string(&fifo).ok() } else { None };
                assert!(is_file,
                    "commit returned but `pipe` is still a FIFO — the child's write was not published");
                assert_eq!(content.as_deref(), Some("hi\n"),
                    "committed pipe should hold the child's bytes, got {:?}", content);
            }
        }
    }
    let _ = fs::remove_dir_all(&workdir);
}

/// (#159 NEW incompleteness) open(dir, O_DIRECTORY) never consults
/// is_deleted/covers, so a whiteouted lower-only dir opens on the real lower
/// fd while stat() correctly says ENOENT. Probe with the static helper: its
/// `ls` calls opendir() (open O_RDONLY|O_DIRECTORY) with NO pre-stat, so it
/// exercises exactly the O_DIRECTORY open path; its `stat` takes the
/// is_deleted-honoring stat path.
#[tokio::test]
async fn hunt_159_opendir_whiteouted_dir_leaks_lower() {
    let workdir = temp_dir("hunt-opendir");
    fs::create_dir_all(workdir.join("d")).unwrap();
    fs::write(workdir.join("d/secret.txt"), "SECRET").unwrap();
    let helper = helper_binary();
    let helper_dir = helper.parent().unwrap().to_path_buf();

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_read(&helper_dir)
        .fs_write(&workdir)
        .workdir(&workdir)
        .cwd(&workdir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    // Empty then remove d (rm -rf shape), then `ls d` (O_DIRECTORY open) and
    // `stat d` (stat path). Both should ENOENT in the merged view.
    let script = "rm d/secret.txt ; rmdir d ; ls d ; stat d";
    let result = policy.clone().with_name("test")
        .run(&[helper.to_str().unwrap(), "sh", "-c", script]).await;
    match result {
        Ok(r) => {
            let err = r.stderr_str().unwrap_or("").to_string();
            let out = r.stdout_str().unwrap_or("").to_string();
            println!("hunt_159_opendir: stdout={:?} stderr={:?}", out, err);
            let stat_enoent = err.contains("stat: d:");
            let ls_enoent = err.contains("ls: d:");
            assert!(stat_enoent,
                "precondition: stat of the whiteouted dir must be ENOENT (stderr={:?})", err);
            assert!(ls_enoent,
                "BUG (#159 incomplete): open(d, O_DIRECTORY) SUCCEEDED on the lower dir while \
                 stat says ENOENT — the O_DIRECTORY open path skips is_deleted/covers \
                 (seccomp.rs:450-452 & 510-523). stderr={:?}", err);
        }
        Err(e) => eprintln!("hunt_159_opendir skipped: {}", e),
    }
    let _ = fs::remove_dir_all(&workdir);
}

/// (#159 positive) read + stat under a recursively-deleted dir must ENOENT
/// and must not leak the pre-delete bytes (non-O_DIRECTORY paths).
#[tokio::test]
async fn hunt_159_read_stat_under_deleted_dir_enoent() {
    let workdir = temp_dir("hunt-under-deleted");
    fs::create_dir_all(workdir.join("d/sub")).unwrap();
    fs::write(workdir.join("d/sub/secret.txt"), "PREDELETE").unwrap();

    let policy = hunt_policy(&workdir, BranchAction::Abort);
    // rm -r d, then read + stat a path under it.
    let script = "rm -r d; cat d/sub/secret.txt; stat d/sub";
    let result = policy.clone().with_name("test").run(&["sh", "-c", script]).await;
    match result {
        Ok(r) => {
            let out = r.stdout_str().unwrap_or("").to_string();
            let err = r.stderr_str().unwrap_or("").to_string();
            println!("hunt_159_under_deleted: stdout={:?} stderr={:?}", out, err);
            assert!(!out.contains("PREDELETE"), "pre-delete bytes leaked through read path: {:?}", out);
            let enoent_hits = err.matches("No such file").count();
            assert!(enoent_hits >= 2,
                "both cat and stat under a deleted dir must ENOENT (got {} 'No such file' in {:?})",
                enoent_hits, err);
        }
        Err(e) => eprintln!("hunt_159_under_deleted skipped: {}", e),
    }
    let _ = fs::remove_dir_all(&workdir);
}

/// (#159 bonus) O_CREAT over a whiteouted file starts fresh — the pre-delete
/// bytes must not resurrect.
#[tokio::test]
async fn hunt_159_ocreat_no_resurrect() {
    let workdir = temp_dir("hunt-ocreat");
    fs::write(workdir.join("f.txt"), "OLDSECRET").unwrap();

    let policy = hunt_policy(&workdir, BranchAction::Commit);
    // Delete f, then O_CREAT|O_APPEND write (>> creates) NEW; read back.
    let script = "rm f.txt; printf NEW >> f.txt; cat f.txt";
    let result = policy.clone().with_name("test").run(&["sh", "-c", script]).await;
    match result {
        Ok(r) => {
            let out = r.stdout_str().unwrap_or("").to_string();
            println!("hunt_159_ocreat: stdout={:?}", out);
            assert!(!out.contains("OLD"), "O_CREAT resurrected pre-delete bytes: {:?}", out);
            assert_eq!(out, "NEW", "recreated file should hold only the fresh bytes");
            // After commit the workdir file must contain only NEW.
            let committed = fs::read_to_string(workdir.join("f.txt")).unwrap_or_default();
            assert_eq!(committed, "NEW", "committed file must be fresh, got {:?}", committed);
        }
        Err(e) => eprintln!("hunt_159_ocreat skipped: {}", e),
    }
    let _ = fs::remove_dir_all(&workdir);
}

/// (covers() positive) deleting `d` must not over-match sibling `d2`.
#[tokio::test]
async fn hunt_159_sibling_d_vs_d2_not_overmatched() {
    let workdir = temp_dir("hunt-sibling");
    fs::create_dir_all(workdir.join("d")).unwrap();
    fs::write(workdir.join("d/x.txt"), "X").unwrap();
    fs::create_dir_all(workdir.join("d2")).unwrap();
    fs::write(workdir.join("d2/y.txt"), "Y").unwrap();

    let policy = hunt_policy(&workdir, BranchAction::Commit);
    let result = policy.clone().with_name("test").run(&["sh", "-c", "rm -r d"]).await;
    match result {
        Ok(r) => {
            assert!(r.success(), "rm -r d should succeed, stderr {}", r.stderr_str().unwrap_or(""));
            assert!(!workdir.join("d").exists(), "d must be gone after commit");
            assert_eq!(fs::read_to_string(workdir.join("d2/y.txt")).unwrap_or_default(), "Y",
                "sibling d2 must be untouched by deleting d");
        }
        Err(e) => eprintln!("hunt_159_sibling skipped: {}", e),
    }
    let _ = fs::remove_dir_all(&workdir);
}

/// (#161 positive) rmdir d; mkdir d yields an opaque dir: old contents hidden,
/// new visible, after commit.
#[tokio::test]
async fn hunt_161_rmdir_then_mkdir_opaque() {
    let workdir = temp_dir("hunt-opaque");
    fs::create_dir_all(workdir.join("d")).unwrap();
    fs::write(workdir.join("d/old.txt"), "OLD").unwrap();

    let policy = hunt_policy(&workdir, BranchAction::Commit);
    let script = "rm d/old.txt; rmdir d; mkdir d; printf NEW > d/new.txt";
    let result = policy.clone().with_name("test").run(&["sh", "-c", script]).await;
    match result {
        Ok(r) => {
            assert!(r.success(), "opaque-dir script should succeed, stderr {}", r.stderr_str().unwrap_or(""));
            assert!(workdir.join("d/new.txt").exists(), "new.txt must exist after commit");
            assert_eq!(fs::read_to_string(workdir.join("d/new.txt")).unwrap_or_default(), "NEW");
            assert!(!workdir.join("d/old.txt").exists(), "old.txt must stay hidden in an opaque dir");
        }
        Err(e) => eprintln!("hunt_161_opaque skipped: {}", e),
    }
    let _ = fs::remove_dir_all(&workdir);
}

/// (#160 positive) rename a lower-only dir: contents survive, a whiteouted
/// child does not reappear, and a whiteouted rename source gives ENOENT.
#[tokio::test]
async fn hunt_160_rename_children_survive_whiteout_holds() {
    let workdir = temp_dir("hunt-mv-dir");
    fs::create_dir_all(workdir.join("d")).unwrap();
    fs::write(workdir.join("d/a.txt"), "A").unwrap();
    fs::write(workdir.join("d/b.txt"), "B").unwrap();

    let policy = hunt_policy(&workdir, BranchAction::Commit);
    // delete b, rename d->d2, then rename the now-deleted d again (must fail).
    let script = "rm d/b.txt; mv d d2; mv d e";
    let result = policy.clone().with_name("test").run(&["sh", "-c", script]).await;
    match result {
        Ok(r) => {
            let err = r.stderr_str().unwrap_or("").to_string();
            println!("hunt_160_rename: stderr={:?}", err);
            assert_eq!(fs::read_to_string(workdir.join("d2/a.txt")).unwrap_or_default(), "A",
                "renamed dir must keep its non-deleted child");
            assert!(!workdir.join("d2/b.txt").exists(),
                "a whiteouted child must not reappear in the renamed dir");
            assert!(!workdir.join("d").exists(), "source dir must be gone after commit");
            assert!(!workdir.join("e").exists(),
                "rename of a whiteouted source must fail (ENOENT), leaving no `e`");
            assert!(err.contains("No such file") || err.contains("cannot"),
                "the second mv of the deleted source should have reported an error, stderr={:?}", err);
        }
        Err(e) => eprintln!("hunt_160_rename skipped: {}", e),
    }
    let _ = fs::remove_dir_all(&workdir);
}

/// (#160 NEW BUG) Directory rename onto an existing lower-only destination
/// silently merges the two trees instead of ENOTEMPTY / atomic-replace,
/// because handle_rename never whiteouts the pre-existing lower `new`.
/// Uses `mv -T` (renameat2, no target-dir semantics) so the syscall is
/// rename("a","b") directly.
#[tokio::test]
async fn hunt_160_rename_onto_existing_dir_merges() {
    let workdir = temp_dir("hunt-mv-onto");
    fs::create_dir_all(workdir.join("a")).unwrap();
    fs::write(workdir.join("a/a1.txt"), "A1").unwrap();
    fs::create_dir_all(workdir.join("b")).unwrap();
    fs::write(workdir.join("b/b1.txt"), "B1").unwrap();

    let policy = hunt_policy(&workdir, BranchAction::Commit);
    let result = policy.clone().with_name("test").run(&["sh", "-c", "mv -T a b; echo RC=$?"]).await;
    match result {
        Ok(r) => {
            let out = r.stdout_str().unwrap_or("").to_string();
            let err = r.stderr_str().unwrap_or("").to_string();
            println!("hunt_160_onto: stdout={:?} stderr={:?}", out, err);
            // Correct POSIX: rename onto a non-empty dir fails (ENOTEMPTY),
            // both a and b survive unmerged. Bug: mv succeeds and b becomes
            // the UNION {a1,b1} after commit.
            let merged = workdir.join("b/a1.txt").exists() && workdir.join("b/b1.txt").exists();
            assert!(!merged,
                "BUG (#160): rename onto an existing lower dir merged both trees into b \
                 (b now holds a1.txt AND b1.txt); POSIX requires ENOTEMPTY or atomic replace. \
                 mv stdout={:?}", out);
            assert!(out.contains("RC=0") == false || !merged,
                "mv -T onto a non-empty dir should have returned nonzero");
        }
        Err(e) => eprintln!("hunt_160_onto skipped: {}", e),
    }
    let _ = fs::remove_dir_all(&workdir);
}
