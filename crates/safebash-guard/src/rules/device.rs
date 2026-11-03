//! Disk and device commands, and `unshare` (cc-safety-net `device.ts`,
//! `namespace.ts`).

use crate::analyze::{Analyzer, Cx};
use crate::model::Word;
use crate::verdict::{Finding, Intent};

const DD: &str = "dd writing to a /dev device can destroy a disk or partition. Ask the user to run device writes manually after confirming the target.";
const MKFS: &str = "mkfs formatting a /dev device erases everything on it. Ask the user to run the format manually after confirming the target.";
const DISK: &str = "This erases or repartitions a disk. Ask the user to run disk erase and partition commands manually after confirming the target.";
const SHRED: &str = "shred permanently destroys the given target. Use rm for ordinary deletes, or ask the user to run shred manually.";
const UNSHARE: &str = "unshare creating a user namespace grants root inside it, a common step toward privilege escalation. Ask the user to run it manually if it is needed.";

fn is_mkfs(name: &str) -> bool {
    name == "mke2fs"
        || name == "mkfs"
        || name.starts_with("mkfs.")
        || name == "newfs"
        || name.starts_with("newfs_")
}

pub fn check(an: &Analyzer<'_>, cx: &Cx, name: &str, argv: &[Word]) {
    let ops = || argv[1..].iter().map(Word::text);
    let names_dev = || ops().any(|t| t.starts_with("/dev/"));
    match name {
        "dd" => {
            if ops().any(|t| {
                t.strip_prefix("of=/dev/")
                    .is_some_and(|d| !d.is_empty() && !matches!(d, "null" | "zero" | "full"))
            }) {
                an.rule(cx, Finding::deny("dd.device-write", Intent::ManualOnly, DD));
            }
        }
        n if is_mkfs(n) => {
            if names_dev() {
                an.rule(cx, Finding::deny("mkfs.device", Intent::ManualOnly, MKFS));
            }
        }
        "shred" => {
            if argv.len() > 1 {
                an.rule(
                    cx,
                    Finding::deny("shred.target", Intent::UseAlternative, SHRED),
                );
            }
        }
        "diskutil" => {
            const VERBS: &[&str] = &[
                "erasedisk",
                "erasevolume",
                "reformat",
                "partitiondisk",
                "zerodisk",
                "randomdisk",
                "secureerase",
            ];
            if ops()
                .find(|t| !t.starts_with('-'))
                .is_some_and(|v| VERBS.contains(&v.to_ascii_lowercase().as_str()))
            {
                an.rule(cx, Finding::deny("disk.erase", Intent::ManualOnly, DISK));
            }
        }
        "wipefs" => {
            let destructive = ops().any(|t| {
                t == "--all"
                    || t.starts_with("--offset")
                    || (t.starts_with('-') && !t.starts_with("--") && t.contains(['a', 'o']))
            });
            if destructive && names_dev() {
                an.rule(cx, Finding::deny("disk.erase", Intent::ManualOnly, DISK));
            }
        }
        "sgdisk" => {
            const READ_ONLY: &[&str] = &[
                "-p",
                "--print",
                "-i",
                "--info",
                "-v",
                "--verify",
                "-O",
                "--print-mbr",
                "-E",
                "--end-of-largest",
                "-F",
                "--first-in-largest",
                "-f",
                "--first-aligned-in-largest",
                "-D",
                "--display-alignment",
                "-L",
                "--list-types",
                "-P",
                "--pretend",
                "-b",
                "--backup",
                "-V",
                "--version",
                "-?",
                "--help",
                "--usage",
            ];
            let writes = ops().filter(|t| t.starts_with('-')).any(|t| {
                let base = t.split('=').next().unwrap_or(t);
                !(READ_ONLY.contains(&base)
                    || (!t.starts_with("--") && t[1..].chars().all(|c| "pvOEFfDLPV?".contains(c)))
                    || t.starts_with("-i")
                    || t.starts_with("-b"))
            });
            if writes && names_dev() {
                an.rule(cx, Finding::deny("disk.erase", Intent::ManualOnly, DISK));
            }
        }
        "parted" => {
            const EDITS: &[&str] = &["mklabel", "mktable", "mkpart", "rm", "resizepart"];
            if names_dev() && ops().any(|t| EDITS.contains(&t.to_ascii_lowercase().as_str())) {
                an.rule(cx, Finding::deny("disk.erase", Intent::ManualOnly, DISK));
            }
        }
        _ => {}
    }
}

/// `unshare` creating a user namespace; the program it runs is analyzed.
pub fn unshare(an: &Analyzer<'_>, cx: &Cx, argv: &[Word], depth: usize) {
    const VALUE_LONG: &[&str] = &[
        "--propagation",
        "--setgroups",
        "--root",
        "--wd",
        "--setuid",
        "--setgid",
        "--map-user",
        "--map-group",
        "--map-users",
        "--map-groups",
        "--owner",
        "--whitelist-env",
        "--load-interp",
    ];
    let user_long = regex::Regex::new(
        r"^--(user|map-root-user|map-current-user|map-auto|map-subids|map-users?|map-groups?|owner|mount-binfmt|load-interp)(=|$)",
    )
    .expect("pattern");
    let mut i = 1;
    let mut user = false;
    while let Some(w) = argv.get(i) {
        let t = w.text();
        if t == "--" {
            i += 1;
            break;
        }
        if !t.starts_with('-') {
            break;
        }
        if t.starts_with("--") {
            user |= user_long.is_match(t);
            if VALUE_LONG.contains(&t) {
                i += 1;
            }
        } else {
            for c in t[1..].chars() {
                if "Urcl".contains(c) {
                    user = true;
                }
                if "RwSGl".contains(c) {
                    if t.ends_with(c) {
                        i += 1;
                    }
                    break;
                }
            }
        }
        i += 1;
    }
    if user {
        an.rule(
            cx,
            Finding::deny("unshare.user-namespace", Intent::ManualOnly, UNSHARE),
        );
    }
    if i < argv.len() {
        an.command(&argv[i..], cx, depth);
    }
}
