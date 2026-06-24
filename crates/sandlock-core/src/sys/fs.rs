//! Filesystem syscall helpers shared by the chroot and COW supervisors.
//!
//! `openat2_in_root` is the single confined-open primitive: it asks the
//! kernel to resolve a path with `RESOLVE_IN_ROOT`, so symlinks and `..`
//! cannot escape the given root. Both supervisors route child-controlled
//! path opens through it (see issue #112).

use std::ffi::CString;
use std::os::unix::io::RawFd;
use std::path::Path;

/// openat2 syscall number, sourced from the `syscalls` crate via `arch`.
const SYS_OPENAT2: libc::c_long = crate::arch::SYS_OPENAT2 as libc::c_long;

/// RESOLVE_IN_ROOT: treat the dirfd as the filesystem root for resolution.
const RESOLVE_IN_ROOT: u64 = 0x10;

/// Kernel `struct open_how` for openat2().
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

fn last_errno(fallback: i32) -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(fallback)
}

/// Open a path confined within `root` using `openat2(RESOLVE_IN_ROOT)`.
///
/// The kernel handles symlink resolution, `..` traversal, and prevents
/// escapes above the root, eliminating TOCTOU races and the edge cases
/// inherent in userspace path walking.
pub(crate) fn openat2_in_root(
    root: &Path,
    path: &str,
    flags: i32,
    mode: u32,
) -> Result<RawFd, i32> {
    let c_root = CString::new(root.to_str().unwrap_or("")).map_err(|_| libc::EINVAL)?;
    let root_fd = unsafe {
        libc::open(
            c_root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if root_fd < 0 {
        return Err(last_errno(libc::EIO));
    }

    let rel_path = path.strip_prefix('/').unwrap_or(path);
    let rel_path = if rel_path.is_empty() { "." } else { rel_path };
    let c_path = CString::new(rel_path).map_err(|_| {
        unsafe { libc::close(root_fd) };
        libc::EINVAL
    })?;

    let how = OpenHow {
        flags: flags as u64,
        mode: mode as u64,
        resolve: RESOLVE_IN_ROOT,
    };

    let fd = unsafe {
        libc::syscall(
            SYS_OPENAT2,
            root_fd,
            c_path.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    } as i32;

    unsafe { libc::close(root_fd) };

    if fd < 0 {
        Err(last_errno(libc::ENOENT))
    } else {
        Ok(fd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    #[test]
    fn openat2_in_root_confines_absolute_symlink() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::write(root.join("etc/shadow"), "confined").unwrap();
        // Absolute symlink to the host /etc/shadow: kernel keeps it in root.
        symlink("/etc/shadow", root.join("evil")).unwrap();

        match openat2_in_root(root, "/evil", libc::O_PATH, 0) {
            Ok(fd) => {
                let resolved =
                    std::fs::read_link(format!("/proc/self/fd/{}", fd)).unwrap();
                unsafe { libc::close(fd) };
                assert!(resolved.starts_with(root), "escaped root: {:?}", resolved);
            }
            Err(libc::ENOSYS) => {} // kernel without openat2
            Err(e) => panic!("unexpected error: {}", e),
        }
    }

    #[test]
    fn openat2_in_root_clamps_parent_escape() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        match openat2_in_root(root, "/../../../etc/group", libc::O_PATH, 0) {
            Err(libc::ENOENT) => {} // clamped to <root>/etc/group, absent
            Err(libc::ENOSYS) => {}
            Ok(fd) => {
                let resolved =
                    std::fs::read_link(format!("/proc/self/fd/{}", fd)).unwrap();
                unsafe { libc::close(fd) };
                assert!(resolved.starts_with(root), "escaped root: {:?}", resolved);
            }
            Err(e) => panic!("unexpected error: {}", e),
        }
    }
}
