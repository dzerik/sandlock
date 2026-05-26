//! Integration tests for the C ABI `Protection` enum + builder setters.
//!
//! These tests drive the FFI symbols directly (no C compilation step)
//! and read back state through the public Rust `Sandbox` API to verify
//! the setters mutate the underlying `ProtectionPolicy`.

use sandlock_core::{Protection, ProtectionState, Sandbox};
use sandlock_ffi::{
    sandlock_protection_min_abi, sandlock_protection_t,
    sandlock_sandbox_builder_allow_degraded, sandlock_sandbox_builder_disable,
    sandlock_sandbox_builder_new,
};

#[test]
fn protection_min_abi_returns_kernel_documented_floors() {
    // Discriminants in the C ABI must agree with Landlock's
    // documented per-feature ABI floor. Drifting these numbers is a
    // contract break with every external binding.
    assert_eq!(
        sandlock_protection_min_abi(sandlock_protection_t::FsRefer),
        2,
        "FsRefer requires Landlock ABI v2",
    );
    assert_eq!(
        sandlock_protection_min_abi(sandlock_protection_t::FsTruncate),
        3,
        "FsTruncate requires Landlock ABI v3",
    );
    assert_eq!(
        sandlock_protection_min_abi(sandlock_protection_t::NetTcp),
        4,
        "NetTcp requires Landlock ABI v4",
    );
    assert_eq!(
        sandlock_protection_min_abi(sandlock_protection_t::FsIoctlDev),
        5,
        "FsIoctlDev requires Landlock ABI v5",
    );
    assert_eq!(
        sandlock_protection_min_abi(sandlock_protection_t::SignalScope),
        6,
        "SignalScope requires Landlock ABI v6",
    );
    assert_eq!(
        sandlock_protection_min_abi(sandlock_protection_t::AbstractUnixScopeSocket),
        6,
        "AbstractUnixScope requires Landlock ABI v6",
    );
}

#[test]
fn protection_discriminants_match_rust_enum_order() {
    // `sandlock_protection_t` discriminants MUST mirror
    // `Protection::all()` iteration order so external callers (Python
    // ctypes, etc.) can convert via raw integer values.
    let rust_order: Vec<Protection> = Protection::all().collect();
    let c_order = [
        Protection::from(sandlock_protection_t::FsRefer),
        Protection::from(sandlock_protection_t::FsTruncate),
        Protection::from(sandlock_protection_t::NetTcp),
        Protection::from(sandlock_protection_t::FsIoctlDev),
        Protection::from(sandlock_protection_t::SignalScope),
        Protection::from(sandlock_protection_t::AbstractUnixScopeSocket),
    ];
    assert_eq!(rust_order, c_order);

    // And the discriminants themselves must be the index in that
    // sequence (0..=5), which Python/ctypes wrappers rely on.
    assert_eq!(sandlock_protection_t::FsRefer as u32, 0);
    assert_eq!(sandlock_protection_t::FsTruncate as u32, 1);
    assert_eq!(sandlock_protection_t::NetTcp as u32, 2);
    assert_eq!(sandlock_protection_t::FsIoctlDev as u32, 3);
    assert_eq!(sandlock_protection_t::SignalScope as u32, 4);
    assert_eq!(sandlock_protection_t::AbstractUnixScopeSocket as u32, 5);
}

/// Run a build sequence through the FFI: builder_new + the supplied
/// closure (typically chaining `allow_degraded` / `disable` setters)
/// + `build()`. Returns the resulting Sandbox so the caller can
/// inspect `protection_policy`.
fn build_via_ffi<F>(configure: F) -> Sandbox
where
    F: FnOnce(*mut sandlock_core::sandbox::SandboxBuilder) -> *mut sandlock_core::sandbox::SandboxBuilder,
{
    let b = sandlock_sandbox_builder_new();
    assert!(!b.is_null(), "builder_new returned null");
    let b = configure(b);
    assert!(!b.is_null(), "configure returned null builder");
    // SAFETY: `b` is a valid Box pointer produced by builder_new and
    // possibly relocated through builder setters.
    let builder = unsafe { *Box::from_raw(b) };
    builder.build().expect("build failed")
}

#[test]
fn builder_allow_degraded_marks_protection_degradable() {
    let sandbox = build_via_ffi(|b| unsafe {
        sandlock_sandbox_builder_allow_degraded(b, sandlock_protection_t::SignalScope)
    });
    assert_eq!(
        sandbox.protection_policy.state(Protection::SignalScope),
        ProtectionState::Degradable,
    );
    // Other protections stay strict (default).
    assert_eq!(
        sandbox.protection_policy.state(Protection::FsRefer),
        ProtectionState::Strict,
    );
}

#[test]
fn builder_disable_marks_protection_disabled() {
    let sandbox = build_via_ffi(|b| unsafe {
        sandlock_sandbox_builder_disable(b, sandlock_protection_t::AbstractUnixScopeSocket)
    });
    assert_eq!(
        sandbox.protection_policy.state(Protection::AbstractUnixScope),
        ProtectionState::Disabled,
    );
    assert_eq!(
        sandbox.protection_policy.state(Protection::FsRefer),
        ProtectionState::Strict,
    );
}

#[test]
fn builder_setters_chain_and_last_call_wins() {
    // disable after allow_degraded must end in Disabled (last writer
    // wins, mirroring `ProtectionPolicy::set` semantics).
    let sandbox = build_via_ffi(|b| unsafe {
        let b = sandlock_sandbox_builder_allow_degraded(b, sandlock_protection_t::SignalScope);
        let b = sandlock_sandbox_builder_disable(b, sandlock_protection_t::SignalScope);
        // And opt-out two more protections in one chain.
        let b = sandlock_sandbox_builder_allow_degraded(b, sandlock_protection_t::FsTruncate);
        sandlock_sandbox_builder_disable(b, sandlock_protection_t::NetTcp)
    });

    assert_eq!(
        sandbox.protection_policy.state(Protection::SignalScope),
        ProtectionState::Disabled,
        "last-writer-wins: disable after allow_degraded",
    );
    assert_eq!(
        sandbox.protection_policy.state(Protection::FsTruncate),
        ProtectionState::Degradable,
    );
    assert_eq!(
        sandbox.protection_policy.state(Protection::NetTcp),
        ProtectionState::Disabled,
    );
    // Untouched protection stays Strict.
    assert_eq!(
        sandbox.protection_policy.state(Protection::FsIoctlDev),
        ProtectionState::Strict,
    );
}

#[test]
fn builder_setters_tolerate_null_builder() {
    // Null in, null out — no panic. Matches the convention of every
    // other `sandlock_sandbox_builder_*` setter.
    let out = unsafe {
        sandlock_sandbox_builder_allow_degraded(
            std::ptr::null_mut(),
            sandlock_protection_t::SignalScope,
        )
    };
    assert!(out.is_null(), "allow_degraded(null, _) must return null");

    let out = unsafe {
        sandlock_sandbox_builder_disable(
            std::ptr::null_mut(),
            sandlock_protection_t::FsRefer,
        )
    };
    assert!(out.is_null(), "disable(null, _) must return null");
}
