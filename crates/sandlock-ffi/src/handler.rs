//! FFI surface for the sandlock `Handler` trait. See `docs/extension-handlers.md`.
//!
//! This module is intentionally split out of `lib.rs` because it contains a
//! self-contained adapter pair: a C-callable surface (`sandlock_handler_*`,
//! `sandlock_action_*`, `sandlock_mem_*`, `sandlock_run_with_handlers`) and a
//! Rust-internal type (`FfiHandler`) that implements `Handler` by calling
//! through to a C function pointer.

/// Sentinel symbol used by build smoke tests to confirm the module is
/// reachable from the cdylib's public surface.
pub const SANDLOCK_HANDLER_MODULE_BUILT: bool = true;
