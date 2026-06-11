//! Integration tests for sandlock-oci.
//!
//! These tests exercise the OCI lifecycle commands (create/start/state/kill/delete)
//! against a real bundle on the local filesystem.
//!
//! To run: `cargo test -p sandlock-oci -- --test-threads=1`
//!
//! **Note**: the lifecycle commands that fork a sandboxed child need root or a
//! Landlock-capable kernel, but the smoke tests here only exercise argument
//! handling and error paths, so they run unprivileged (including in CI).

use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;

/// Path to the sandlock-oci binary under test. Cargo builds it before running
/// the integration target and exposes its path here, so this resolves to the
/// correct profile (debug or release) automatically.
fn oci_bin() -> &'static str {
    env!("CARGO_BIN_EXE_sandlock-oci")
}

/// Create a minimal OCI bundle with a rootfs and config.json.
fn create_bundle(dir: &Path, cmd: &[&str]) {
    let rootfs = dir.join("rootfs");
    fs::create_dir_all(&rootfs).unwrap();
    // Minimal config.json that satisfies oci-spec-rs
    let config = serde_json::json!({
        "ociVersion": "1.0.2",
        "root": { "path": "rootfs", "readonly": false },
        "process": {
            "terminal": false,
            "user": { "uid": 0, "gid": 0 },
            "cwd": "/",
            "args": cmd,
            "env": ["PATH=/usr/bin:/bin"]
        },
        "mounts": [],
        "linux": {
            "resources": {
                "devices": [
                    { "allow": false, "access": "rwm" }
                ]
            },
            "namespaces": [
                { "type": "mount" }
            ]
        }
    });
    fs::write(
        dir.join("config.json"),
        serde_json::to_string_pretty(&config).unwrap(),
    )
    .unwrap();
}

// ── spec / state unit tests (always run) ────────────────────────────────────

#[test]
fn spec_load_and_policy_mapping() {
    let dir = tempdir().unwrap();
    create_bundle(dir.path(), &["sh", "-c", "exit 0"]);

    // Load spec via the library API.
    let spec = sandlock_oci::spec::load_spec(dir.path())
        .map_err(|e| panic!("load_spec failed: {}", e))
        .unwrap();
    assert_eq!(spec.version(), "1.0.2");

    let policy = sandlock_oci::spec::spec_to_policy(&spec, dir.path(), "test").unwrap();
    // PATH env is forwarded
    assert!(policy.env.contains_key("PATH"));
    // Cwd is forwarded
    assert_eq!(policy.cwd.as_deref(), Some(Path::new("/")));
    // Default rootfs is set
    assert!(policy.rootfs.is_some());
}

#[test]
fn state_created_lifecycle() {
    use sandlock_oci::state::{SandboxState, Status};

    let dir = tempdir().unwrap();
    let mut state = SandboxState::new("test-lifecycle", dir.path(), "1.0.2");
    // new() starts in Creating; set_created() advances to Created.
    assert_eq!(state.status, Status::Creating);

    state.set_created(9999);
    assert_eq!(state.status, Status::Created);
    assert_eq!(state.pid, 9999);

    state.set_running();
    assert_eq!(state.status, Status::Running);

    state.set_stopped(Some(sandlock_oci::state::ExitInfo {
        code: Some(0),
        signal: None,
    }));
    assert_eq!(state.status, Status::Stopped);
    assert!(state.exit_info.is_some());
    assert_eq!(state.exit_info.as_ref().unwrap().code, Some(0));
}

#[test]
fn policy_from_spec_builds_sandbox() {
    let dir = tempdir().unwrap();
    create_bundle(dir.path(), &["sh", "-c", "exit 0"]);

    let spec = sandlock_oci::spec::load_spec(dir.path()).unwrap();
    let policy = sandlock_oci::spec::spec_to_policy(&spec, dir.path(), "test").unwrap();

    // Can convert to sandbox config
    let sandbox = policy.to_sandbox().unwrap();
    assert!(sandbox.chroot.is_some());
}

// ── CLI binary integration tests (require binary to be built) ────────────────

/// Helper: run the sandlock-oci binary with the given args.
fn run_oci(args: &[&str]) -> std::process::Output {
    Command::new(oci_bin())
        .args(args)
        .output()
        .expect("failed to run sandlock-oci")
}

#[test]
fn oci_check_exits_zero() {
    let out = run_oci(&["check"]);
    assert!(
        out.status.success(),
        "check failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn oci_state_unknown_sandbox_errors() {
    let out = run_oci(&["state", "this-does-not-exist-xyz-12345"]);
    assert!(!out.status.success(), "expected failure for unknown sandbox");
}

#[test]
fn oci_list_no_sandboxes() {
    // List should succeed even with no state dir.
    let out = run_oci(&["list"]);
    assert!(out.status.success());
}

#[test]
fn oci_kill_unknown_sandbox_errors() {
    let out = run_oci(&["kill", "no-such-sandbox-xyz", "SIGTERM"]);
    assert!(!out.status.success());
}

#[test]
fn oci_delete_nonexistent_is_ok() {
    // Deleting a sandbox that doesn't exist should not fail.
    let out = run_oci(&["delete", "ghost-sandbox-xyz-99"]);
    assert!(out.status.success());
}

#[test]
fn oci_create_rejects_duplicate_id() {
    // The uniqueness guard fires before any fork, so a pre-existing state.json
    // under --root is enough to trigger it — no rootfs or Landlock needed.
    let root = tempdir().unwrap();
    let id = "dup-id-test";
    let cdir = root.path().join(id);
    fs::create_dir_all(&cdir).unwrap();
    fs::write(
        cdir.join("state.json"),
        r#"{"ociVersion":"1.0.2","id":"dup-id-test","status":"created","pid":12345,"bundle":"/tmp","created":0}"#,
    )
    .unwrap();

    let out = Command::new(oci_bin())
        .args([
            "--root",
            root.path().to_str().unwrap(),
            "create",
            id,
            "-b",
            "/tmp",
        ])
        .output()
        .expect("failed to run sandlock-oci");

    assert!(!out.status.success(), "duplicate create should fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("already exists"),
        "expected 'already exists' error, got: {}",
        stderr
    );
}