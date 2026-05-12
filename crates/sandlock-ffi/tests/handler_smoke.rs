//! Integration smoke test for the FFI handler ABI introduced in PR 1.
//! Subsequent tasks expand this file as the surface is built up.

#[test]
fn handler_module_is_exposed() {
    // This forces the `handler` module to be referenced from the cdylib
    // public surface. Replaced by real tests in later tasks.
    let _ = sandlock_ffi::handler::SANDLOCK_HANDLER_MODULE_BUILT;
}
