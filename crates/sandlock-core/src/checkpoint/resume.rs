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
}
