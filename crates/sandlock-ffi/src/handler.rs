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

/// Tag distinguishing payload variants of `sandlock_action_out_t`.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum sandlock_action_kind_t {
    /// No action set yet; the supervisor treats this as "fall through to
    /// the handler's on_exception policy" (Task 6 wires this up).
    Unset = 0,
    Continue = 1,
    Errno = 2,
    ReturnValue = 3,
    InjectFdSend = 4,
    InjectFdSendTracked = 5,
    Hold = 6,
    Kill = 7,
}

#[repr(C)]
#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
pub struct sandlock_action_kill_t {
    pub sig: i32,
    pub pgid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
pub struct sandlock_action_inject_t {
    /// Owned by the C caller; ownership transfers to the supervisor on
    /// successful invocation of the corresponding setter.
    pub srcfd: i32,
    pub newfd_flags: u32,
}

/// Token used by `InjectFdSendTracked` so the C side can correlate the
/// callback that fires after `SECCOMP_IOCTL_NOTIF_ADDFD` returns the
/// child-side fd number. Wired through to a Rust `OnInjectSuccess`
/// closure built in Task 6.
#[allow(non_camel_case_types)]
pub type sandlock_inject_tracker_t = u64;

#[repr(C)]
#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
pub struct sandlock_action_inject_tracked_t {
    pub srcfd: i32,
    pub newfd_flags: u32,
    pub tracker: sandlock_inject_tracker_t,
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub union sandlock_action_payload_t {
    pub none: u64,
    pub errno: i32,
    pub return_value: i64,
    pub inject_send: sandlock_action_inject_t,
    pub inject_send_tracked: sandlock_action_inject_tracked_t,
    pub kill: sandlock_action_kill_t,
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct sandlock_action_out_t {
    pub kind: u32,
    pub payload: sandlock_action_payload_t,
}

impl sandlock_action_out_t {
    /// Construct an `Unset` action with all payload bytes zero. The payload
    /// union has variants up to 16 bytes; this ensures all bytes are
    /// initialised before the C handler writes its decision.
    pub fn zeroed() -> Self {
        // Safety: `sandlock_action_payload_t` is `#[repr(C)]` with only
        // integer-and-integer-aggregate variants; the zero bit-pattern is
        // valid for all of them.
        Self {
            kind: sandlock_action_kind_t::Unset as u32,
            payload: unsafe { std::mem::MaybeUninit::zeroed().assume_init() },
        }
    }
}

/// Mark the action as `Continue` (let the syscall proceed unchanged).
///
/// # Safety
/// `out` must be a valid pointer to a `sandlock_action_out_t` writable
/// for the duration of the call, or null (in which case the call is a
/// no-op).
#[no_mangle]
pub unsafe extern "C" fn sandlock_action_set_continue(out: *mut sandlock_action_out_t) {
    if out.is_null() { return; }
    (*out).kind = sandlock_action_kind_t::Continue as u32;
}

/// Fail the syscall with `errno`.
///
/// # Safety
/// Same constraints as `sandlock_action_set_continue`.
#[no_mangle]
pub unsafe extern "C" fn sandlock_action_set_errno(out: *mut sandlock_action_out_t, errno: i32) {
    if out.is_null() { return; }
    (*out).kind = sandlock_action_kind_t::Errno as u32;
    (*out).payload.errno = errno;
}

/// Return a specific value from the syscall without entering the kernel.
///
/// # Safety
/// Same constraints as `sandlock_action_set_continue`.
#[no_mangle]
pub unsafe extern "C" fn sandlock_action_set_return_value(
    out: *mut sandlock_action_out_t,
    value: i64,
) {
    if out.is_null() { return; }
    (*out).kind = sandlock_action_kind_t::ReturnValue as u32;
    (*out).payload.return_value = value;
}

/// Inject the supervisor-side fd `srcfd` into the traced child as a new
/// fd (number chosen by the kernel via `SECCOMP_IOCTL_NOTIF_ADDFD`).
///
/// # Safety
/// Same constraints as `sandlock_action_set_continue`; `srcfd` must be
/// a valid open fd in the supervisor process at the moment of the
/// supervisor's dispatch.
#[no_mangle]
pub unsafe extern "C" fn sandlock_action_set_inject_fd_send(
    out: *mut sandlock_action_out_t,
    srcfd: RawFd,
    newfd_flags: u32,
) {
    if out.is_null() { return; }
    (*out).kind = sandlock_action_kind_t::InjectFdSend as u32;
    (*out).payload.inject_send = sandlock_action_inject_t { srcfd, newfd_flags };
}

/// Tracked variant of `sandlock_action_set_inject_fd_send` — the
/// supervisor will fire a Rust-side callback identified by `tracker`
/// once the kernel reports the child-side fd number.
///
/// # Safety
/// Same constraints as `sandlock_action_set_inject_fd_send`.
#[no_mangle]
pub unsafe extern "C" fn sandlock_action_set_inject_fd_send_tracked(
    out: *mut sandlock_action_out_t,
    srcfd: RawFd,
    newfd_flags: u32,
    tracker: sandlock_inject_tracker_t,
) {
    if out.is_null() { return; }
    (*out).kind = sandlock_action_kind_t::InjectFdSendTracked as u32;
    (*out).payload.inject_send_tracked = sandlock_action_inject_tracked_t {
        srcfd, newfd_flags, tracker,
    };
}

/// Hold the syscall pending until the supervisor explicitly releases it.
///
/// # Safety
/// Same constraints as `sandlock_action_set_continue`.
#[no_mangle]
pub unsafe extern "C" fn sandlock_action_set_hold(out: *mut sandlock_action_out_t) {
    if out.is_null() { return; }
    (*out).kind = sandlock_action_kind_t::Hold as u32;
}

/// Kill the target (`pgid > 0` for the whole process group, or the pid
/// the supervisor records for the notification) with signal `sig`.
///
/// # Safety
/// Same constraints as `sandlock_action_set_continue`.
#[no_mangle]
pub unsafe extern "C" fn sandlock_action_set_kill(
    out: *mut sandlock_action_out_t,
    sig: i32,
    pgid: i32,
) {
    if out.is_null() { return; }
    (*out).kind = sandlock_action_kind_t::Kill as u32;
    (*out).payload.kill = sandlock_action_kill_t { sig, pgid };
}
