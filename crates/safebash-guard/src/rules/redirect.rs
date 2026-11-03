//! File redirections: disk devices, secrets and protected files.

use crate::analyze::{Analyzer, Cx, Stage};
use crate::model::{Access, Word};
use crate::verdict::{Finding, Intent};

const BLOCK_DEVICE: &str = "This output redirect overwrites a disk device. Ask the user to run device writes manually after confirming the target.";

/// A disk device path (cc-safety-net `redirect.block-device`).
pub fn is_block_device(path: &str) -> bool {
    let re = regex::Regex::new(
        r"^/dev/(?:r?disk\d|sd[a-z]|hd[a-z]|vd[a-z]|xvd[a-z]|nvme\d|mmcblk\d|md\d|dm-\d|loop\d|mapper/|disk/)",
    )
    .expect("pattern");
    re.is_match(path)
}

pub fn check(
    an: &Analyzer<'_>,
    cx: &Cx,
    fd: Option<u32>,
    access: Access,
    target: &Word,
    argv: &[Word],
) {
    let _ = fd;
    if access.writes() {
        if let Some(path) = target.as_lit() {
            if is_block_device(path) {
                an.rule(
                    cx,
                    Finding::deny("redirect.block-device", Intent::ManualOnly, BLOCK_DEVICE),
                );
            }
        }
    }
    crate::rules::secrets::check_redirect(an, cx, access, target, argv);
    crate::rules::guards::check_redirect(an, cx, access, target);
    let _ = Stage::Rule;
}
