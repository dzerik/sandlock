//! Integration smoke test for the FFI handler ABI introduced in PR 1.
//! Subsequent tasks expand this file as the surface is built up.

#[test]
fn handler_module_is_exposed() {
    // This forces the `handler` module to be referenced from the cdylib
    // public surface. Replaced by real tests in later tasks.
    let _ = sandlock_ffi::handler::SANDLOCK_HANDLER_MODULE_BUILT;
}

use sandlock_ffi::notif_repr::sandlock_notif_data_t;

#[test]
fn notif_data_layout_matches_documented_size() {
    // 8 + 4 + 4 + 4 + 4 + 8 + 6*8 = 80 bytes. If this changes, the C header
    // and any external consumers need to be updated together.
    assert_eq!(std::mem::size_of::<sandlock_notif_data_t>(), 80);
    assert_eq!(std::mem::align_of::<sandlock_notif_data_t>(), 8);
}

#[test]
fn notif_data_from_seccomp_notif_copies_all_fields() {
    use sandlock_core::{SeccompData, SeccompNotif};

    let notif = SeccompNotif {
        id: 0xDEAD_BEEF_CAFE_F00D,
        pid: 4242,
        flags: 7,
        data: SeccompData {
            nr: 21, // SYS_access on x86_64
            arch: 0xC000_003E,
            instruction_pointer: 0x7FFF_FFFF_AAAA,
            args: [1, 2, 3, 4, 5, 6],
        },
    };
    let snap = sandlock_notif_data_t::from(&notif);
    assert_eq!(snap.id, 0xDEAD_BEEF_CAFE_F00D);
    assert_eq!(snap.pid, 4242);
    assert_eq!(snap.flags, 7);
    assert_eq!(snap.syscall_nr, 21);
    assert_eq!(snap.arch, 0xC000_003E);
    assert_eq!(snap.instruction_pointer, 0x7FFF_FFFF_AAAA);
    assert_eq!(snap.args, [1, 2, 3, 4, 5, 6]);
}

use sandlock_ffi::handler::{
    sandlock_mem_read, sandlock_mem_read_cstr, sandlock_mem_write,
};

#[test]
fn mem_accessors_reject_null_arguments() {
    // Verifies the null-pointer guards in each accessor. Happy-path
    // coverage comes in Task 7 with a live notif_fd.
    let mut buf = [0u8; 4];
    let mut out_len: usize = 0;
    let p = std::ptr::null();
    unsafe {
        assert_eq!(
            sandlock_mem_read_cstr(p, 0, buf.as_mut_ptr(), buf.len(), &mut out_len),
            -1,
            "read_cstr should reject null handle",
        );
        assert_eq!(
            sandlock_mem_read(p, 0, buf.as_mut_ptr(), buf.len(), &mut out_len),
            -1,
            "read should reject null handle",
        );
        assert_eq!(
            sandlock_mem_write(p, 0, buf.as_ptr(), buf.len()),
            -1,
            "write should reject null handle",
        );
    }
}

use sandlock_ffi::handler::{
    sandlock_action_kind_t, sandlock_action_out_t, sandlock_action_set_continue,
    sandlock_action_set_errno, sandlock_action_set_hold, sandlock_action_set_kill,
    sandlock_action_set_return_value,
};

#[test]
fn action_setters_record_kind_and_payload() {
    let mut a = sandlock_action_out_t::zeroed();
    unsafe { sandlock_action_set_continue(&mut a) };
    assert_eq!(a.kind, sandlock_action_kind_t::Continue as u32);

    unsafe { sandlock_action_set_errno(&mut a, 13) };
    assert_eq!(a.kind, sandlock_action_kind_t::Errno as u32);
    assert_eq!(unsafe { a.payload.errno }, 13);

    unsafe { sandlock_action_set_return_value(&mut a, -1) };
    assert_eq!(a.kind, sandlock_action_kind_t::ReturnValue as u32);
    assert_eq!(unsafe { a.payload.return_value }, -1);

    unsafe { sandlock_action_set_hold(&mut a) };
    assert_eq!(a.kind, sandlock_action_kind_t::Hold as u32);

    unsafe { sandlock_action_set_kill(&mut a, libc::SIGKILL, 4321) };
    assert_eq!(a.kind, sandlock_action_kind_t::Kill as u32);
    assert_eq!(unsafe { a.payload.kill.sig }, libc::SIGKILL);
    assert_eq!(unsafe { a.payload.kill.pgid }, 4321);
}

#[test]
fn action_out_layout_is_stable() {
    // kind(4) + pad(4) + payload(16) = 24 bytes; alignment driven by the
    // u64 inside the union. Layout drift between Rust and the C header
    // would corrupt caller-allocated buffers.
    assert_eq!(std::mem::size_of::<sandlock_action_out_t>(), 24);
    assert_eq!(std::mem::align_of::<sandlock_action_out_t>(), 8);
}

use sandlock_ffi::handler::{
    sandlock_exception_policy_t, sandlock_handler_free, sandlock_handler_fn_t,
    sandlock_handler_new, sandlock_handler_t,
};

extern "C" fn test_handler(
    _ud: *mut std::ffi::c_void,
    _notif: *const sandlock_ffi::notif_repr::sandlock_notif_data_t,
    _mem: *mut sandlock_ffi::handler::sandlock_mem_handle_t,
    out: *mut sandlock_ffi::handler::sandlock_action_out_t,
) -> i32 {
    unsafe { sandlock_ffi::handler::sandlock_action_set_continue(out) };
    0
}

extern "C" fn dropper(ud: *mut std::ffi::c_void) {
    // Reconstitute the Box we leaked in the test below.
    unsafe { drop(Box::from_raw(ud as *mut u32)); }
}

#[test]
fn handler_new_and_free_round_trip() {
    let ud = Box::into_raw(Box::new(0xABCDu32)) as *mut std::ffi::c_void;
    let on_ex = sandlock_exception_policy_t::Kill as u32;
    let h: *mut sandlock_handler_t = unsafe {
        sandlock_handler_new(
            Some(test_handler as sandlock_handler_fn_t),
            ud,
            Some(dropper),
            on_ex,
        )
    };
    assert!(!h.is_null());
    unsafe { sandlock_handler_free(h) };
    // `dropper` runs and frees the Box; if it does not, leak-sanitizer
    // (when enabled) will flag this test.
}

#[test]
fn handler_new_rejects_invalid_exception_policy() {
    let h = unsafe {
        sandlock_handler_new(
            Some(test_handler as sandlock_handler_fn_t),
            std::ptr::null_mut(),
            None,
            99u32, // out of range
        )
    };
    assert!(h.is_null(), "expected null handle on invalid on_exception");
}

use sandlock_core::seccomp::dispatch::{Handler, HandlerCtx};
use sandlock_core::seccomp::notif::NotifAction;
use sandlock_core::{SeccompData, SeccompNotif};
use sandlock_ffi::handler::FfiHandler;

fn fake_ctx() -> HandlerCtx {
    HandlerCtx {
        notif: SeccompNotif {
            id: 1, pid: std::process::id(), flags: 0,
            data: SeccompData { nr: 39, arch: 0xC000003E,
                                instruction_pointer: 0, args: [0; 6] },
        },
        notif_fd: -1,
    }
}

extern "C" fn return_value_42(
    _ud: *mut std::ffi::c_void,
    _notif: *const sandlock_ffi::notif_repr::sandlock_notif_data_t,
    _mem: *mut sandlock_ffi::handler::sandlock_mem_handle_t,
    out: *mut sandlock_ffi::handler::sandlock_action_out_t,
) -> i32 {
    unsafe { sandlock_ffi::handler::sandlock_action_set_return_value(out, 42) };
    0
}

extern "C" fn returns_error_with_unset_action(
    _ud: *mut std::ffi::c_void,
    _notif: *const sandlock_ffi::notif_repr::sandlock_notif_data_t,
    _mem: *mut sandlock_ffi::handler::sandlock_mem_handle_t,
    _out: *mut sandlock_ffi::handler::sandlock_action_out_t,
) -> i32 {
    -1
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ffi_handler_translates_return_value() {
    let raw = unsafe {
        sandlock_ffi::handler::sandlock_handler_new(
            Some(return_value_42),
            std::ptr::null_mut(),
            None,
            sandlock_exception_policy_t::Kill as u32,
        )
    };
    let h = unsafe { FfiHandler::from_raw(raw) };
    let cx = fake_ctx();
    let action = h.handle(&cx).await;
    assert!(matches!(action, NotifAction::ReturnValue(42)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ffi_handler_applies_exception_policy_on_failure() {
    let raw = unsafe {
        sandlock_ffi::handler::sandlock_handler_new(
            Some(returns_error_with_unset_action),
            std::ptr::null_mut(),
            None,
            sandlock_exception_policy_t::DenyEperm as u32,
        )
    };
    let h = unsafe { FfiHandler::from_raw(raw) };
    let cx = fake_ctx();
    let action = h.handle(&cx).await;
    assert!(matches!(action, NotifAction::Errno(e) if e == libc::EPERM));
}

use std::ffi::CString;
use sandlock_ffi::handler::{
    sandlock_handler_registration_t, sandlock_run_with_handlers,
};

extern "C" fn force_getpid_to_777(
    _ud: *mut std::ffi::c_void,
    _notif: *const sandlock_ffi::notif_repr::sandlock_notif_data_t,
    _mem: *mut sandlock_ffi::handler::sandlock_mem_handle_t,
    out: *mut sandlock_ffi::handler::sandlock_action_out_t,
) -> i32 {
    unsafe { sandlock_ffi::handler::sandlock_action_set_return_value(out, 777) };
    0
}

#[test]
fn run_with_handlers_intercepts_getpid() {
    use sandlock_ffi::*; // bring in builder + result symbols

    let builder = sandlock_sandbox_builder_new();
    // Allow the runtime bits the child needs. The exact mounts mirror
    // sandlock's own integration tests — read-only access to the system
    // libraries and the python interpreter, plus a writable /tmp.
    let builder = unsafe {
        let p = CString::new("/usr").unwrap();
        sandlock_sandbox_builder_fs_read(builder, p.as_ptr())
    };
    let builder = unsafe {
        let p = CString::new("/bin").unwrap();
        sandlock_sandbox_builder_fs_read(builder, p.as_ptr())
    };
    let builder = unsafe {
        let p = CString::new("/lib").unwrap();
        sandlock_sandbox_builder_fs_read(builder, p.as_ptr())
    };
    let builder = unsafe {
        let p = CString::new("/lib64").unwrap();
        sandlock_sandbox_builder_fs_read(builder, p.as_ptr())
    };
    let builder = unsafe {
        let p = CString::new("/etc").unwrap();
        sandlock_sandbox_builder_fs_read(builder, p.as_ptr())
    };
    let builder = unsafe {
        let p = CString::new("/tmp").unwrap();
        sandlock_sandbox_builder_fs_write(builder, p.as_ptr())
    };

    let policy = {
        let mut err: i32 = 0;
        unsafe { sandlock_sandbox_build(builder, &mut err, std::ptr::null_mut()) }
    };
    assert!(!policy.is_null(), "policy build failed");

    let handler = unsafe {
        handler::sandlock_handler_new(
            Some(force_getpid_to_777),
            std::ptr::null_mut(),
            None,
            handler::sandlock_exception_policy_t::Kill as u32,
        )
    };
    assert!(!handler.is_null(), "handler_new returned null");
    let registrations = [sandlock_handler_registration_t {
        syscall_nr: libc::SYS_getpid,
        handler,
    }];

    let script = CString::new(
        "import os, sys; sys.stdout.write(str(os.getpid()))",
    ).unwrap();
    // Use the system python3 directly. Running through `/usr/bin/env
    // python3` would pick up any venv shim in $PATH whose pyvenv.cfg
    // sits outside the sandbox's read allowlist and fail before our
    // handler ever gets a chance to fire.
    let arg0 = CString::new("/usr/bin/python3").unwrap();
    let arg1 = CString::new("-c").unwrap();
    let argv = [
        arg0.as_ptr(),
        arg1.as_ptr(),
        script.as_ptr(),
    ];

    let rr = unsafe {
        sandlock_run_with_handlers(
            policy,
            argv.as_ptr(),
            argv.len() as u32,
            registrations.as_ptr(),
            registrations.len(),
        )
    };
    assert!(!rr.is_null(), "sandlock_run_with_handlers returned null");
    let stdout = unsafe {
        let mut len: usize = 0;
        let p = sandlock_result_stdout_bytes(rr, &mut len);
        if p.is_null() { Vec::new() } else { std::slice::from_raw_parts(p, len).to_vec() }
    };
    let stderr = unsafe {
        let mut len: usize = 0;
        let p = sandlock_result_stderr_bytes(rr, &mut len);
        if p.is_null() { Vec::new() } else { std::slice::from_raw_parts(p, len).to_vec() }
    };
    let stdout_str = String::from_utf8_lossy(&stdout);
    let stderr_str = String::from_utf8_lossy(&stderr);
    let exit_code = unsafe { sandlock_result_exit_code(rr) };
    assert!(stdout_str.contains("777"),
            "expected getpid to be intercepted; exit={} stdout={:?} stderr={:?}",
            exit_code, stdout_str, stderr_str);

    unsafe { sandlock_result_free(rr); }
    unsafe { sandlock_sandbox_free(policy); }
}
