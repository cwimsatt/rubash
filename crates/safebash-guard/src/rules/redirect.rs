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

/// A Windows raw disk/volume device named as the **whole** operand:
/// `\\.\PhysicalDrive0`, `\\.\C:` (a volume by drive letter), and a GUID
/// volume `\\.\Volume{...}` or its extended `\\?\Volume{...}` form. Matching
/// the whole operand (a bare device handle, optionally one trailing
/// separator) — never a prefix — keeps an ordinary file *under* a volume
/// path (`\\.\C:\dir\file`) from matching. Shared by the redirect check and
/// the device-write command operands (`dd of=`, `Clear-Content`), so a
/// direct device write is caught, not only a shell `>` redirect.
pub fn is_windows_block_device(path: &str) -> bool {
    let lowered = path.replace('\\', "/").to_ascii_lowercase();
    let whole = lowered.strip_suffix('/').unwrap_or(&lowered);
    let Some(rest) = whole
        .strip_prefix("//./")
        .or_else(|| whole.strip_prefix("//?/"))
    else {
        return false;
    };
    if let Some(n) = rest.strip_prefix("physicaldrive") {
        return !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit());
    }
    let rb = rest.as_bytes();
    if rb.len() == 2 && rb[0].is_ascii_alphabetic() && rb[1] == b':' {
        return true;
    }
    if let Some(inner) = rest
        .strip_prefix("volume{")
        .and_then(|g| g.strip_suffix('}'))
    {
        // A bare GUID volume only; a descendant such as
        // `volume{...}/backup{old}` (further separators or braces) is a file
        // on the volume, not the raw device.
        return !inner.contains(['/', '{', '}']);
    }
    false
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
            if is_block_device(path) || is_windows_block_device(path) {
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
