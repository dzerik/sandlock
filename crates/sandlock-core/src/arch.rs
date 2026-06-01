//! Architecture-specific syscall and seccomp helpers.

use syscalls::Sysno;

// Syscall numbers sourced from the `syscalls` crate (generated from the kernel
// ABI tables), replacing hand-maintained per-architecture magic numbers. Each
// of these syscalls exists on every architecture Sandlock targets, so a single
// definition resolves to the correct per-arch number at compile time. The
// `tests` module below pins the resolved values to the historical constants.
pub const SYS_FACCESSAT2: i64 = Sysno::faccessat2 as i64;
pub const SYS_OPENAT2: i64 = Sysno::openat2 as i64;
pub const SYS_SECCOMP: i64 = Sysno::seccomp as i64;
pub const SYS_MEMFD_CREATE: i64 = Sysno::memfd_create as i64;
pub const SYS_PIDFD_OPEN: i64 = Sysno::pidfd_open as i64;
pub const SYS_PIDFD_GETFD: i64 = Sysno::pidfd_getfd as i64;

#[cfg(target_arch = "x86_64")]
mod imp {
    pub const AUDIT_ARCH: u32 = 0xC000_003E;

    pub const SYS_OPEN: Option<i64> = Some(libc::SYS_open);
    pub const SYS_STAT: Option<i64> = Some(libc::SYS_stat);
    pub const SYS_LSTAT: Option<i64> = Some(libc::SYS_lstat);
    pub const SYS_ACCESS: Option<i64> = Some(libc::SYS_access);
    pub const SYS_READLINK: Option<i64> = Some(libc::SYS_readlink);
    pub const SYS_GETDENTS: Option<i64> = Some(libc::SYS_getdents);
    pub const SYS_UNLINK: Option<i64> = Some(libc::SYS_unlink);
    pub const SYS_RMDIR: Option<i64> = Some(libc::SYS_rmdir);
    pub const SYS_MKDIR: Option<i64> = Some(libc::SYS_mkdir);
    pub const SYS_RENAME: Option<i64> = Some(libc::SYS_rename);
    pub const SYS_SYMLINK: Option<i64> = Some(libc::SYS_symlink);
    pub const SYS_LINK: Option<i64> = Some(libc::SYS_link);
    pub const SYS_CHMOD: Option<i64> = Some(libc::SYS_chmod);
    pub const SYS_CHOWN: Option<i64> = Some(libc::SYS_chown);
    pub const SYS_LCHOWN: Option<i64> = Some(libc::SYS_lchown);
    pub const SYS_VFORK: Option<i64> = Some(libc::SYS_vfork);
    pub const SYS_FORK: Option<i64> = Some(libc::SYS_fork);

    /// Every syscall the kernel will dispatch through `handle_fork`.
    /// Single source of truth for callers that enumerate fork-class
    /// syscalls (BPF notif registration in `seccomp::dispatch`,
    /// classification in `resource::is_process_creation_notif`).
    pub const FORK_LIKE_SYSCALLS: &[i64] = &[
        libc::SYS_clone,
        libc::SYS_clone3,
        libc::SYS_vfork,
        libc::SYS_fork,
    ];
}

#[cfg(target_arch = "aarch64")]
mod imp {
    pub const AUDIT_ARCH: u32 = 0xC000_00B7;

    pub const SYS_OPEN: Option<i64> = None;
    pub const SYS_STAT: Option<i64> = None;
    pub const SYS_LSTAT: Option<i64> = None;
    pub const SYS_ACCESS: Option<i64> = None;
    pub const SYS_READLINK: Option<i64> = None;
    pub const SYS_GETDENTS: Option<i64> = None;
    pub const SYS_UNLINK: Option<i64> = None;
    pub const SYS_RMDIR: Option<i64> = None;
    pub const SYS_MKDIR: Option<i64> = None;
    pub const SYS_RENAME: Option<i64> = None;
    pub const SYS_SYMLINK: Option<i64> = None;
    pub const SYS_LINK: Option<i64> = None;
    pub const SYS_CHMOD: Option<i64> = None;
    pub const SYS_CHOWN: Option<i64> = None;
    pub const SYS_LCHOWN: Option<i64> = None;
    pub const SYS_VFORK: Option<i64> = None;
    pub const SYS_FORK: Option<i64> = None;

    /// Every syscall the kernel will dispatch through `handle_fork`.
    /// aarch64 has no `fork`/`vfork` (glibc emulates via `clone`).
    pub const FORK_LIKE_SYSCALLS: &[i64] = &[
        libc::SYS_clone,
        libc::SYS_clone3,
    ];
}

#[cfg(target_arch = "riscv64")]
mod imp {
    // AUDIT_ARCH_RISCV64 = EM_RISCV(243) | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE.
    pub const AUDIT_ARCH: u32 = 0xC000_00F3;

    // riscv64 uses the generic syscall ABI: no legacy open/stat/fork/etc.
    pub const SYS_OPEN: Option<i64> = None;
    pub const SYS_STAT: Option<i64> = None;
    pub const SYS_LSTAT: Option<i64> = None;
    pub const SYS_ACCESS: Option<i64> = None;
    pub const SYS_READLINK: Option<i64> = None;
    pub const SYS_GETDENTS: Option<i64> = None;
    pub const SYS_UNLINK: Option<i64> = None;
    pub const SYS_RMDIR: Option<i64> = None;
    pub const SYS_MKDIR: Option<i64> = None;
    pub const SYS_RENAME: Option<i64> = None;
    pub const SYS_SYMLINK: Option<i64> = None;
    pub const SYS_LINK: Option<i64> = None;
    pub const SYS_CHMOD: Option<i64> = None;
    pub const SYS_CHOWN: Option<i64> = None;
    pub const SYS_LCHOWN: Option<i64> = None;
    pub const SYS_VFORK: Option<i64> = None;
    pub const SYS_FORK: Option<i64> = None;

    /// Every syscall the kernel will dispatch through `handle_fork`.
    /// riscv64 has no `fork`/`vfork` (glibc emulates via `clone`).
    pub const FORK_LIKE_SYSCALLS: &[i64] = &[
        libc::SYS_clone,
        libc::SYS_clone3,
    ];
}

pub use imp::*;

/// True if `nr` is a real syscall number on the current architecture.
/// Used by [`crate::seccomp::syscall::Syscall::checked`] to reject foot-gun
/// cases like negative or arch-mismatched numbers.
///
/// Exact: backed by the `syscalls` crate's per-arch table, so unassigned
/// numbers within the table's range are rejected too (unlike a bare range
/// check against the highest known number).
pub fn is_known_syscall(nr: i64) -> bool {
    nr >= 0 && Sysno::new(nr as usize).is_some()
}

pub fn push_optional_syscall(v: &mut Vec<u32>, nr: Option<i64>) {
    if let Some(nr) = nr {
        v.push(nr as u32);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the crate-sourced syscall numbers to the values Sandlock used
    /// before adopting the crate, per architecture. A divergence here means a
    /// crate upgrade changed an ABI number out from under the seccomp filters.
    #[test]
    fn crate_sourced_consts_match_historical_values() {
        #[cfg(target_arch = "x86_64")]
        {
            assert_eq!(SYS_SECCOMP, 317);
            assert_eq!(SYS_MEMFD_CREATE, 319);
            assert_eq!(SYS_PIDFD_OPEN, 434);
            assert_eq!(SYS_PIDFD_GETFD, 438);
            assert_eq!(SYS_OPENAT2, 437);
            assert_eq!(SYS_FACCESSAT2, 439);
        }
        #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
        {
            assert_eq!(SYS_SECCOMP, 277);
            assert_eq!(SYS_MEMFD_CREATE, 279);
            assert_eq!(SYS_PIDFD_OPEN, 434);
            assert_eq!(SYS_PIDFD_GETFD, 438);
            assert_eq!(SYS_OPENAT2, 437);
            assert_eq!(SYS_FACCESSAT2, 439);
        }
    }

    #[test]
    fn is_known_syscall_accepts_real_and_rejects_bogus() {
        assert!(is_known_syscall(libc::SYS_openat));
        assert!(is_known_syscall(libc::SYS_clone));
        assert!(!is_known_syscall(-1));
        assert!(!is_known_syscall(99_999));
    }
}
