use crate::checkpoint::{FdInfo, MemoryMap, MemorySegment};

/// One planned memory-restore action for a saved region.
#[allow(dead_code)] // used by the restore path (added in a later change)
#[derive(Debug)]
pub(crate) enum RestoreRegion {
    /// mmap MAP_FIXED from `path` at `offset`, prot from `perms`.
    RemapFromFile { start: u64, end: u64, perms: String, offset: u64, path: String },
    /// mmap MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE, then write `data`.
    WriteBytes { start: u64, end: u64, perms: String, data: Vec<u8> },
}

/// Classify saved regions into restore actions. Special kernel maps
/// ([vdso]/[vvar]/[vsyscall]) are skipped: the kernel provides them in the
/// fresh process and they must not be overwritten. A region with captured
/// bytes becomes WriteBytes; otherwise a path-backed region becomes
/// RemapFromFile. Regions that are neither are left to the kernel/ABI.
#[allow(dead_code)] // used by the restore path (added in a later change)
pub(crate) fn build_memory_plan(
    maps: &[MemoryMap],
    data: &[MemorySegment],
) -> Vec<RestoreRegion> {
    let mut plan = Vec::new();
    for m in maps {
        if m.is_special() { continue; }
        if let Some(seg) = data.iter().find(|s| s.start == m.start) {
            plan.push(RestoreRegion::WriteBytes {
                start: m.start, end: m.end, perms: m.perms.clone(), data: seg.data.clone(),
            });
        } else if let Some(ref p) = m.path {
            if p.starts_with('/') {
                plan.push(RestoreRegion::RemapFromFile {
                    start: m.start, end: m.end, perms: m.perms.clone(),
                    offset: m.offset, path: p.clone(),
                });
            }
        }
    }
    plan
}

/// Return true only for paths that refer to a reopenable regular file.
/// memfd and "(deleted)" paths start with '/' but are not reopenable, so they
/// are skipped.
fn is_restorable_file_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.starts_with("/memfd:")
        && !path.ends_with(" (deleted)")
}

/// Split the saved fd table into transparently restorable regular files and a
/// list of skipped non-regular fds (sockets, pipes, eventfd, ...). The skipped
/// list is logged by the caller; those resources fall to the app_state hatch.
/// memfd and "(deleted)" paths start with '/' but are not reopenable, so they
/// are skipped.
#[allow(dead_code)] // used by the restore path (added in a later change)
pub(crate) fn build_fd_plan(fds: &[FdInfo]) -> (Vec<FdInfo>, Vec<String>) {
    let mut restorable = Vec::new();
    let mut skipped = Vec::new();
    for f in fds {
        if is_restorable_file_path(&f.path) {
            restorable.push(f.clone());
        } else {
            skipped.push(f.path.clone());
        }
    }
    (restorable, skipped)
}

#[allow(dead_code)] // used by the restore path (added in a later change)
fn prot_from_perms(perms: &str) -> libc::c_int {
    let mut prot = 0;
    if perms.as_bytes().first() == Some(&b'r') { prot |= libc::PROT_READ; }
    if perms.as_bytes().get(1) == Some(&b'w') { prot |= libc::PROT_WRITE; }
    if perms.as_bytes().get(2) == Some(&b'x') { prot |= libc::PROT_EXEC; }
    if prot == 0 { prot = libc::PROT_NONE; }
    prot
}

/// A memory region prepared for restore, with the path pre-converted to a
/// CString so the post-fork child performs no allocation.
#[allow(dead_code)] // used by the restore path (added in a later change)
pub(crate) enum PreparedRegion {
    /// anonymous: mmap RW|FIXED|PRIVATE|ANON, copy `bytes`, then mprotect to `prot`.
    Anon { start: u64, len: usize, prot: libc::c_int, bytes: Vec<u8> },
    /// file-backed: open `path`, mmap `prot`|FIXED|PRIVATE at `offset`, close.
    File { start: u64, len: usize, prot: libc::c_int, offset: i64, path: std::ffi::CString },
}

/// An fd prepared for restore (path pre-converted to CString).
#[allow(dead_code)] // used by the restore path (added in a later change)
pub(crate) struct PreparedFd {
    pub fd: i32,
    pub flags: i32,
    pub offset: i64,
    pub path: std::ffi::CString,
}

/// All restore actions, with every allocation done up front. Build this BEFORE
/// forking the restore child; the child then calls `apply_prepared_child` which
/// allocates nothing (only mmap/mprotect/open/close/dup2/lseek/_exit, all
/// async-signal-safe).
#[allow(dead_code)] // used by the restore path (added in a later change)
pub(crate) struct PreparedRestore {
    pub regions: Vec<PreparedRegion>,
    pub fds: Vec<PreparedFd>,
}

/// Convert plans into a PreparedRestore. Runs in the parent before fork.
/// Returns an error if any path cannot be converted to a CString (contains an
/// interior NUL); paths from /proc never do, but we fail loud rather than drop.
#[allow(dead_code)] // used by the restore path (added in a later change)
pub(crate) fn prepare_restore(
    plan: &[RestoreRegion],
    fds: &[FdInfo],
) -> Result<PreparedRestore, crate::error::SandlockError> {
    use crate::error::{SandboxRuntimeError, SandlockError};
    let cstr = |s: &str| -> Result<std::ffi::CString, SandlockError> {
        std::ffi::CString::new(s).map_err(|e| {
            SandlockError::Runtime(SandboxRuntimeError::Child(format!("bad restore path {s:?}: {e}")))
        })
    };
    let mut regions = Vec::with_capacity(plan.len());
    for r in plan {
        match r {
            RestoreRegion::WriteBytes { start, end, perms, data } => {
                regions.push(PreparedRegion::Anon {
                    start: *start,
                    len: (end - start) as usize,
                    prot: prot_from_perms(perms),
                    bytes: data.clone(),
                });
            }
            RestoreRegion::RemapFromFile { start, end, perms, offset, path } => {
                regions.push(PreparedRegion::File {
                    start: *start,
                    len: (end - start) as usize,
                    prot: prot_from_perms(perms),
                    offset: *offset as i64,
                    path: cstr(path)?,
                });
            }
        }
    }
    let mut prepared_fds = Vec::with_capacity(fds.len());
    for f in fds {
        prepared_fds.push(PreparedFd {
            fd: f.fd, flags: f.flags, offset: f.offset as i64, path: cstr(&f.path)?,
        });
    }
    Ok(PreparedRestore { regions, fds: prepared_fds })
}

/// Apply a PreparedRestore inside the post-fork child. ALLOCATION-FREE: only
/// async-signal-safe syscalls. On ANY failure it `_exit`s with a distinct code
/// so the supervising parent observes a failed restore.
///
/// Exit codes: 101 anon mmap, 105 mprotect, 104 file mmap, 103 file open,
/// 106 fd open, 108 lseek.
#[allow(dead_code)] // used by the restore path (added in a later change)
pub(crate) fn apply_prepared_child(prepared: &PreparedRestore) -> ! {
    for region in &prepared.regions {
        match region {
            PreparedRegion::Anon { start, len, prot, bytes } => {
                let p = unsafe {
                    libc::mmap(*start as *mut libc::c_void, *len,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED, -1, 0)
                };
                if p == libc::MAP_FAILED { unsafe { libc::_exit(101); } }
                let n = core::cmp::min(bytes.len(), *len);
                unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), *start as *mut u8, n); }
                if unsafe { libc::mprotect(*start as *mut libc::c_void, *len, *prot) } != 0 {
                    unsafe { libc::_exit(105); }
                }
            }
            PreparedRegion::File { start, len, prot, offset, path } => {
                let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY) };
                if fd < 0 { unsafe { libc::_exit(103); } }
                let p = unsafe {
                    libc::mmap(*start as *mut libc::c_void, *len, *prot,
                        libc::MAP_PRIVATE | libc::MAP_FIXED, fd, *offset)
                };
                unsafe { libc::close(fd); }
                if p == libc::MAP_FAILED { unsafe { libc::_exit(104); } }
            }
        }
    }
    for f in &prepared.fds {
        let opened = unsafe { libc::open(f.path.as_ptr(), f.flags) };
        if opened < 0 { unsafe { libc::_exit(106); } }
        if opened != f.fd {
            unsafe { libc::dup2(opened, f.fd); libc::close(opened); }
        }
        if unsafe { libc::lseek(f.fd, f.offset, libc::SEEK_SET) } < 0 {
            unsafe { libc::_exit(108); }
        }
    }
    unsafe { libc::_exit(0); }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::{FdInfo, MemoryMap, MemorySegment};

    #[test]
    fn fd_plan_keeps_regular_files_only() {
        let fds = vec![
            FdInfo { fd: 3, path: "/etc/hostname".into(), flags: 0, offset: 5 },
            FdInfo { fd: 4, path: "socket:[12345]".into(), flags: 0, offset: 0 },
            FdInfo { fd: 5, path: "pipe:[6789]".into(), flags: 0, offset: 0 },
        ];
        let (restorable, skipped) = build_fd_plan(&fds);
        assert_eq!(restorable.len(), 1);
        assert_eq!(restorable[0].fd, 3);
        assert_eq!(skipped, vec!["socket:[12345]".to_string(), "pipe:[6789]".to_string()]);
    }

    #[test]
    fn fd_plan_skips_deleted_and_memfd() {
        let fds = vec![
            FdInfo { fd: 3, path: "/etc/hostname".into(), flags: 0, offset: 5 },
            FdInfo { fd: 6, path: "/tmp/gone (deleted)".into(), flags: 0, offset: 0 },
            FdInfo { fd: 7, path: "/memfd:scratch (deleted)".into(), flags: 0, offset: 0 },
        ];
        let (restorable, skipped) = build_fd_plan(&fds);
        assert_eq!(restorable.len(), 1);
        assert_eq!(restorable[0].fd, 3);
        assert!(restorable.iter().all(|f| f.fd != 6 && f.fd != 7),
            "deleted and memfd fds must not appear in restorable");
        assert!(skipped.contains(&"/tmp/gone (deleted)".to_string()));
        assert!(skipped.contains(&"/memfd:scratch (deleted)".to_string()));
    }

    #[test]
    fn plan_classifies_regions() {
        let maps = vec![
            MemoryMap { start: 0x1000, end: 0x2000, perms: "r-xp".into(), offset: 0,
                        path: Some("/bin/app".into()) },          // code: remap from file
            MemoryMap { start: 0x3000, end: 0x4000, perms: "rw-p".into(), offset: 0,
                        path: None },                              // anon writable: write bytes
            MemoryMap { start: 0x5000, end: 0x6000, perms: "r--p".into(), offset: 0,
                        path: Some("[vvar]".into()) },             // special: skip
        ];
        let data = vec![MemorySegment { start: 0x3000, data: vec![7u8; 0x1000] }];
        let plan = build_memory_plan(&maps, &data);
        assert!(matches!(plan[0], RestoreRegion::RemapFromFile { .. }));
        assert!(matches!(plan[1], RestoreRegion::WriteBytes { .. }));
        assert_eq!(plan.len(), 2, "special regions are skipped, not planned");
    }

    #[test]
    fn child_restore_applies_plan_exit_zero() {
        let addr: u64 = 0x4000_0000;
        let plan = vec![RestoreRegion::WriteBytes {
            start: addr, end: addr + 4096, perms: "rw-p".into(), data: vec![0xABu8; 4096],
        }];
        let prepared = prepare_restore(&plan, &[]).expect("prepare");
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            apply_prepared_child(&prepared); // never returns; _exit(0) on success
        }
        let mut st = 0i32;
        unsafe { libc::waitpid(pid, &mut st, 0); }
        // Decode wait status manually: low 7 bits 0 means exited normally.
        let exited = (st & 0x7f) == 0;
        let code = (st >> 8) & 0xff;
        assert!(exited, "restore child should have exited normally; raw status {st:#x}");
        assert_eq!(code, 0, "restore child should exit 0; got exit code {code}");
    }
}
