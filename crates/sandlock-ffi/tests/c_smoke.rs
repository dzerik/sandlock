//! Compile and run the pure-C smoke tests against the cdylib.

use std::path::PathBuf;
use std::process::Command;

/// Compile `tests/c/<source>` against the generated header and the cdylib,
/// then run it and require a zero exit.
///
/// This is the only check that the committed `include/sandlock.h` is usable
/// from plain C at all: everything else in the crate reaches the symbols
/// through Rust declarations and would keep passing with an unbuildable
/// header. `-Werror` therefore matters as much as the run does.
fn compile_and_run(source: &str, bin_name: &str) {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let out_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let bin = out_dir.join(bin_name);
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };

    // Cargo links integration tests against the crate's *rlib*, and does not
    // treat the *cdylib* as a build prerequisite, so `cargo test` never
    // (re)builds `libsandlock_ffi.so`. Build it ourselves so we always link the
    // current artifact instead of a stale one left in `target/` (which fails
    // with "undefined reference" when the symbol set has changed). `--lib`
    // builds the cdylib/staticlib/rlib; the recursive `cargo` is safe because
    // the outer build lock is released before tests run.
    let mut build = Command::new(env!("CARGO"));
    build.args(["build", "-p", "sandlock-ffi", "--lib"]);
    if profile == "release" {
        build.arg("--release");
    }
    let build_status = build.status().expect("invoke cargo build for cdylib");
    assert!(
        build_status.success(),
        "failed to build sandlock-ffi cdylib"
    );

    let target_dir = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            manifest_dir
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join("target")
        });
    let profile_dir = target_dir.join(profile);
    let cdylib_dir = [
        profile_dir.clone(),
        profile_dir.join("deps"),
        target_dir.join("release"),
        target_dir.join("release").join("deps"),
    ]
    .into_iter()
    .find(|dir| {
        dir.join("libsandlock_ffi.so").exists() || dir.join("libsandlock_ffi.dylib").exists()
    })
    .expect("libsandlock_ffi cdylib should exist in target output");

    let rpath_arg = format!("-Wl,-rpath,{}", cdylib_dir.to_str().unwrap());
    let include_dir = manifest_dir.join("include");
    let c_file = manifest_dir.join("tests").join("c").join(source);

    let status = Command::new("cc")
        .args([
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            include_dir.to_str().unwrap(),
            c_file.to_str().unwrap(),
            "-L",
            cdylib_dir.to_str().unwrap(),
            &rpath_arg,
            "-lsandlock_ffi",
            "-o",
            bin.to_str().unwrap(),
        ])
        .status()
        .expect("cc invocation");
    assert!(status.success(), "C compile of {source} failed");

    let out = Command::new(&bin)
        .output()
        .unwrap_or_else(|e| panic!("run {bin_name}: {e}"));
    assert!(
        out.status.success(),
        "{bin_name} exited non-zero: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn c_smoke_compiles_and_runs() {
    compile_and_run("handler_smoke.c", "handler_smoke");
}

#[test]
fn c_txn_smoke_compiles_and_runs() {
    compile_and_run("txn_smoke.c", "txn_smoke");
}
