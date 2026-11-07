//! safebash library surface: the rubash-to-guard adapters, shared by the
//! `safebash` binary and its tests.

pub mod brush_convert;
pub mod convert;
pub mod gate;
pub mod setup;

use safebash_guard::Guard;
use std::ffi::OsStr;
use std::path::Path;

/// The environment variable that forces non-interactive mode. It is exported
/// to child processes when the mode engages, so a nested safebash or a
/// background respawn inherits it.
pub const NONINTERACTIVE_ENV: &str = "SAFEBASH_NONINTERACTIVE";

/// Whether this invocation runs unattended, so a `Confirm` verdict must deny
/// rather than prompt. Pure and fully testable: it reads no process state, only
/// the two inputs.
///
///   * `file_name` is the binary's own `argv[0]` file name; a file stem of
///     `safebash-pi` selects the mode (a dedicated build, or a renamed copy /
///     hardlink / symlink of `safebash`).
///   * `env_val` is the raw value of [`NONINTERACTIVE_ENV`]; any non-empty
///     value other than exactly `0` selects the mode. The value is **not**
///     trimmed, so `" 0"` (a space then zero) is not `0` and still selects.
///
/// The two selectors are ORed: either one alone engages the mode. Selection is
/// never a command-line flag (the pi coding agent passes only `-c` and the
/// command, so the executable must select the mode itself).
pub fn non_interactive(file_name: Option<&OsStr>, env_val: Option<&OsStr>) -> bool {
    let by_name = file_name
        .and_then(|n| Path::new(n).file_stem())
        .is_some_and(|s| s == "safebash-pi");
    let by_env = env_val.is_some_and(|v| !v.is_empty() && v != "0");
    by_name || by_env
}

/// Apply the non-interactive selection to `guard`, reading the process
/// environment for [`NONINTERACTIVE_ENV`]. When the mode engages, export the
/// marker (so children inherit it) and turn off terminal confirmation, so a
/// `Confirm` verdict denies instead of prompting. Returns whether the mode
/// engaged.
///
/// This is the single place the selection flips [`Guard::interactive_confirm`];
/// the binary's `main` only calls this. A test that asserts the flip therefore
/// fails if this assignment is removed (code review round 1, finding 2).
pub fn apply_non_interactive(guard: &mut Guard, file_name: Option<&OsStr>) -> bool {
    let engaged = non_interactive(file_name, std::env::var_os(NONINTERACTIVE_ENV).as_deref());
    if engaged {
        std::env::set_var(NONINTERACTIVE_ENV, "1");
        guard.interactive_confirm = false;
    }
    engaged
}

#[cfg(test)]
mod tests {
    use super::non_interactive;
    use std::ffi::OsStr;

    /// Evaluate the pure selector from string inputs.
    fn sel(name: Option<&str>, env: Option<&str>) -> bool {
        non_interactive(name.map(OsStr::new), env.map(OsStr::new))
    }

    #[test]
    fn name_stem_selects_with_or_without_extension() {
        assert!(sel(Some("safebash-pi"), None));
        assert!(sel(Some("safebash-pi.exe"), None));
    }

    #[test]
    fn name_selects_even_when_env_would_not() {
        // The env unset, empty, or exactly "0" never selects on its own, yet
        // the name still engages the mode.
        assert!(sel(Some("safebash-pi"), None));
        assert!(sel(Some("safebash-pi"), Some("")));
        assert!(sel(Some("safebash-pi"), Some("0")));
    }

    #[test]
    fn ordinary_names_do_not_select() {
        assert!(!sel(Some("safebash"), None));
        assert!(!sel(Some("safebash.exe"), None));
        assert!(!sel(Some("sh"), None));
        assert!(!sel(None, None));
    }

    #[test]
    fn env_selects_regardless_of_name() {
        assert!(sel(Some("safebash"), Some("1")));
        assert!(sel(Some("sh"), Some("true")));
        assert!(sel(None, Some("yes")));
    }

    #[test]
    fn env_value_is_not_trimmed() {
        // " 0" and "0 " are not exactly "0", so they still select.
        assert!(sel(Some("safebash"), Some(" 0")));
        assert!(sel(Some("safebash"), Some("0 ")));
    }

    #[test]
    fn env_unset_empty_or_zero_does_not_select() {
        assert!(!sel(Some("safebash"), None));
        assert!(!sel(Some("safebash"), Some("")));
        assert!(!sel(Some("safebash"), Some("0")));
    }

    #[test]
    fn selectors_are_ored() {
        // The name wins over a non-selecting env value.
        assert!(sel(Some("safebash-pi"), Some("0")));
        // The env wins over a non-selecting name.
        assert!(sel(Some("safebash"), Some("1")));
        // Neither selects.
        assert!(!sel(Some("safebash"), Some("0")));
    }
}
