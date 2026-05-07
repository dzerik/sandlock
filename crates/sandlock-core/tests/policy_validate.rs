use sandlock_core::policy::{FsIsolation, Policy};

#[test]
fn validate_overlayfs_without_workdir_fails() {
    let p = Policy::builder()
        .fs_isolation(FsIsolation::OverlayFs)
        .build_unchecked()
        .unwrap();
    let err = p.validate().unwrap_err();
    assert!(format!("{err}").to_lowercase().contains("workdir"));
}

#[test]
fn validate_none_without_workdir_succeeds() {
    let p = Policy::builder()
        .fs_isolation(FsIsolation::None)
        .build_unchecked()
        .unwrap();
    assert!(p.validate().is_ok());
}
