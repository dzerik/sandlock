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
