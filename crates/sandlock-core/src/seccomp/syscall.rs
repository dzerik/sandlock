//! Syscall identity: name-to-number resolution and the checked `Syscall`
//! number newtype.
//!
//! The newtype closes the footgun where `add_handler(-5, h)` would compile but
//! silently never fire because the cBPF filter cannot emit a JEQ for an
//! architecture-unknown syscall number.

use thiserror::Error;

/// Map a syscall name to its number on the current architecture.
///
/// Returns `None` for names that are not syscalls on this architecture (for
/// example legacy `open`/`stat` on the generic-ABI arches) or are not syscall
/// names at all. Backed by the `syscalls` crate's kernel-ABI tables, so this
/// covers every syscall, not a curated subset.
pub fn syscall_name_to_nr(name: &str) -> Option<u32> {
    name.parse::<syscalls::Sysno>().ok().map(|s| s.id() as u32)
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SyscallError {
    #[error("syscall number {0} is negative")]
    Negative(i64),
    #[error("syscall number {0} is unknown for the current architecture")]
    UnknownForArch(i64),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Syscall(i64);

impl Syscall {
    /// Validates that `nr` is non-negative and known on the current architecture.
    pub fn checked(nr: i64) -> Result<Self, SyscallError> {
        if nr < 0 {
            return Err(SyscallError::Negative(nr));
        }
        if !crate::arch::is_known_syscall(nr) {
            return Err(SyscallError::UnknownForArch(nr));
        }
        Ok(Self(nr))
    }

    pub fn raw(self) -> i64 {
        self.0
    }
}

impl TryFrom<i64> for Syscall {
    type Error = SyscallError;
    fn try_from(nr: i64) -> Result<Self, Self::Error> {
        Self::checked(nr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_accepts_valid_openat() {
        let s = Syscall::checked(libc::SYS_openat).expect("openat is valid");
        assert_eq!(s.raw(), libc::SYS_openat);
    }

    #[test]
    fn checked_rejects_negative() {
        match Syscall::checked(-5) {
            Err(SyscallError::Negative(-5)) => {}
            other => panic!("expected Negative(-5), got {:?}", other),
        }
    }

    #[test]
    fn checked_rejects_arch_unknown() {
        // 99_999 is not a real syscall number on any supported arch.
        match Syscall::checked(99_999) {
            Err(SyscallError::UnknownForArch(99_999)) => {}
            other => panic!("expected UnknownForArch(99_999), got {:?}", other),
        }
    }

    #[test]
    fn try_from_i64_delegates_to_checked() {
        let s: Syscall = libc::SYS_openat.try_into().expect("openat valid");
        assert_eq!(s.raw(), libc::SYS_openat);
        let bad: Result<Syscall, _> = (-1i64).try_into();
        assert!(matches!(bad, Err(SyscallError::Negative(-1))));
    }

    /// Independent cross-check that the crate's ABI tables agree with the
    /// system `libc::SYS_*` constants for names libc exposes on every arch
    /// Sandlock targets. Guards against the crate and the headers diverging.
    #[test]
    fn name_to_nr_matches_libc_for_stable_names() {
        let cases: &[(&str, i64)] = &[
            ("mount", libc::SYS_mount),
            ("openat", libc::SYS_openat),
            ("connect", libc::SYS_connect),
            ("clone", libc::SYS_clone),
            ("clone3", libc::SYS_clone3),
            ("execve", libc::SYS_execve),
            ("ioctl", libc::SYS_ioctl),
            ("ptrace", libc::SYS_ptrace),
            ("userfaultfd", libc::SYS_userfaultfd),
            ("bpf", libc::SYS_bpf),
            ("newfstatat", libc::SYS_newfstatat),
            ("statx", libc::SYS_statx),
            ("getrandom", libc::SYS_getrandom),
            ("io_uring_setup", libc::SYS_io_uring_setup),
        ];
        for &(name, expected) in cases {
            assert_eq!(
                syscall_name_to_nr(name),
                Some(expected as u32),
                "{name} should resolve to libc::SYS_{name} = {expected}"
            );
        }
    }

    #[test]
    fn name_to_nr_rejects_non_syscall_names() {
        assert_eq!(syscall_name_to_nr("definitely_not_a_syscall"), None);
        assert_eq!(syscall_name_to_nr(""), None);
    }
}
