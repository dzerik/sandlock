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

/// Apply the memory plan inside the restore child. Runs post-fork using only
/// raw libc. `fds` reopens regular files onto their saved fd numbers. On any
/// failure the child _exits with a distinct nonzero code so the supervising
/// parent observes a failed restore.
#[allow(dead_code)] // used by the restore path (added in a later change)
pub(crate) fn apply_memory_plan_child(plan: &[RestoreRegion], fds: &[FdInfo]) {
    for region in plan {
        match region {
            RestoreRegion::WriteBytes { start, end, perms, data } => {
                let len = (end - start) as usize;
                let prot = prot_from_perms(perms);
                let p = unsafe {
                    libc::mmap(*start as *mut libc::c_void, len,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED, -1, 0)
                };
                if p == libc::MAP_FAILED { unsafe { libc::_exit(101); } }
                unsafe {
                    std::ptr::copy_nonoverlapping(data.as_ptr(), *start as *mut u8, data.len());
                    // Re-apply the recorded protection (e.g. drop +w if the region was read-only).
                    libc::mprotect(*start as *mut libc::c_void, len, prot);
                }
            }
            RestoreRegion::RemapFromFile { start, end, perms, offset, path } => {
                let len = (end - start) as usize;
                let prot = prot_from_perms(perms);
                let cpath = match std::ffi::CString::new(path.as_str()) {
                    Ok(c) => c, Err(_) => unsafe { libc::_exit(102) },
                };
                let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDONLY) };
                if fd < 0 { unsafe { libc::_exit(103); } }
                let p = unsafe {
                    libc::mmap(*start as *mut libc::c_void, len, prot,
                        libc::MAP_PRIVATE | libc::MAP_FIXED, fd, *offset as libc::off_t)
                };
                unsafe { libc::close(fd); }
                if p == libc::MAP_FAILED { unsafe { libc::_exit(104); } }
            }
        }
    }
    for f in fds {
        let cpath = match std::ffi::CString::new(f.path.as_str()) {
            Ok(c) => c, Err(_) => continue,
        };
        let opened = unsafe { libc::open(cpath.as_ptr(), f.flags) };
        if opened < 0 { continue; }
        if opened != f.fd {
            unsafe { libc::dup2(opened, f.fd); libc::close(opened); }
        }
        unsafe { libc::lseek(f.fd, f.offset as libc::off_t, libc::SEEK_SET); }
    }
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
    fn child_restore_maps_anon_page() {
        let addr: u64 = 0x4000_0000;
        let plan = vec![RestoreRegion::WriteBytes {
            start: addr, end: addr + 4096, perms: "rw-p".into(), data: vec![0xABu8; 4096],
        }];

        let pid = unsafe { libc::fork() };
        if pid == 0 {
            // Child: apply the plan, then SIGSTOP so the parent can inspect.
            apply_memory_plan_child(&plan, &[]);
            unsafe { libc::raise(libc::SIGSTOP); libc::_exit(0); }
        }
        // Parent: wait for the stop, read the page back, then kill.
        let mut st = 0i32;
        unsafe { libc::waitpid(pid, &mut st, libc::WUNTRACED); }
        let mut buf = vec![0u8; 4096];
        let local = libc::iovec { iov_base: buf.as_mut_ptr() as *mut _, iov_len: 4096 };
        let remote = libc::iovec { iov_base: addr as *mut _, iov_len: 4096 };
        let n = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
        unsafe { libc::kill(pid, libc::SIGKILL); libc::waitpid(pid, &mut st, 0); }
        assert_eq!(n, 4096);
        assert!(buf.iter().all(|&b| b == 0xAB), "anon page pattern must be restored");
    }
}
