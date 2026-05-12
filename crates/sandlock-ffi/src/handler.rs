//! FFI surface for the sandlock `Handler` trait. See `docs/extension-handlers.md`.

use std::os::unix::io::RawFd;
use std::slice;

use sandlock_core::seccomp::notif::{read_child_cstr, read_child_mem, write_child_mem};

pub const SANDLOCK_HANDLER_MODULE_BUILT: bool = true;

/// Opaque child-memory accessor handed to a C handler callback.
///
/// Constructed on the stack inside the Rust adapter just before the
/// callback fires, invalidated when the callback returns. C handlers
/// must not store the pointer beyond the callback's return.
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct sandlock_mem_handle_t {
    notif_fd: RawFd,
    notif_id: u64,
    pid: u32,
}

impl sandlock_mem_handle_t {
    pub(crate) fn new(notif_fd: RawFd, notif_id: u64, pid: u32) -> Self {
        Self { notif_fd, notif_id, pid }
    }
}

/// Read up to `max_len-1` bytes of a NUL-terminated string at `addr` from the
/// traced child. On success the destination buffer is NUL-terminated and
/// `*out_len` holds the byte count copied (excluding the NUL); returns 0.
/// On failure returns -1 and leaves `*out_len` untouched. `max_len` must be
/// at least 1 to fit the NUL terminator.
///
/// # Safety
/// `handle` must point to a live `sandlock_mem_handle_t` provided by the
/// supervisor; `buf` must be writable for `max_len` bytes; `out_len` must
/// be a valid `size_t*`.
#[no_mangle]
pub unsafe extern "C" fn sandlock_mem_read_cstr(
    handle: *const sandlock_mem_handle_t,
    addr: u64,
    buf: *mut u8,
    max_len: usize,
    out_len: *mut usize,
) -> i32 {
    if handle.is_null() || buf.is_null() || out_len.is_null() || max_len == 0 {
        return -1;
    }
    let h = &*handle;
    // `max_len` is the caller-supplied buffer size including space for the
    // trailing NUL; reserve one byte so we can always terminate the string.
    let cap = max_len - 1;
    let s = match read_child_cstr(h.notif_fd, h.notif_id, h.pid, addr, cap) {
        Some(s) => s,
        None => return -1,
    };
    let bytes = s.as_bytes();
    let n = bytes.len().min(cap);
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, n);
    *buf.add(n) = 0;
    *out_len = n;
    0
}

/// Raw byte read at `addr` of exactly `len` bytes. Writes byte count
/// actually read to `*out_len`. Returns 0 on success, -1 on failure.
///
/// # Safety
/// Same constraints as `sandlock_mem_read_cstr`.
#[no_mangle]
pub unsafe extern "C" fn sandlock_mem_read(
    handle: *const sandlock_mem_handle_t,
    addr: u64,
    buf: *mut u8,
    len: usize,
    out_len: *mut usize,
) -> i32 {
    if handle.is_null() || buf.is_null() || out_len.is_null() {
        return -1;
    }
    let h = &*handle;
    let v = match read_child_mem(h.notif_fd, h.notif_id, h.pid, addr, len) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let n = v.len();
    std::ptr::copy_nonoverlapping(v.as_ptr(), buf, n);
    *out_len = n;
    0
}

/// Write `len` bytes from `buf` into the child at `addr`. Returns 0 on
/// success, -1 on failure.
///
/// # Safety
/// Same constraints as `sandlock_mem_read_cstr`; `buf` must be readable
/// for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn sandlock_mem_write(
    handle: *const sandlock_mem_handle_t,
    addr: u64,
    buf: *const u8,
    len: usize,
) -> i32 {
    if handle.is_null() || buf.is_null() {
        return -1;
    }
    let h = &*handle;
    let data = slice::from_raw_parts(buf, len);
    match write_child_mem(h.notif_fd, h.notif_id, h.pid, addr, data) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}
