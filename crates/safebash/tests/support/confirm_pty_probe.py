#!/usr/bin/env python3
"""Execution-level driver for the interactive-terminal distinction test
(DESIGN SAFEBASH-CONPTY). It drives the real safebash binary under a REAL
controlling terminal - a POSIX pty (pty.fork) on Unix, a ConPTY (pywinpty)
on Windows - the only arrangement in which the distinction this test exists
to prove is observable:

  * ordinary safebash prompts on the terminal for a confirmable command and
    runs it when the one-time token is typed back;
  * safebash with SAFEBASH_NONINTERACTIVE=1 denies the SAME command, under
    the SAME terminal, WITHOUT ever prompting.

The non-terminal SAFEBASH-PI tests cannot tell pi mode from an ordinary
no-terminal denial; this driver can, because a terminal is present and
answerable (the approval control proves that on each host).

The command for every leg is `rm -rf ../victim` run from `work`, with a
disposable sibling `victim` directory holding a sentinel. `../victim` is
outside the workspace and its `..` component makes it ineligible for the
trusted-temp allowance (targets.rs), so it reaches the non-fixed
rm.recursive-force-outside-cwd rule and is confirmable; its last component is
`victim`, so the engine's `.`/`..` recursive-removal refusal does not apply and
an approved run actually deletes it.

Legs (fresh fixture each; the trap is paired with both controls):
  interactive-approve   ordinary safebash prompts; answering the token runs
                        the command and deletes the victim (exit 0). FAILS,
                        never skips, if no prompt appears.
  interactive-decline   ordinary safebash prompts; a wrong answer declines, so
                        the command does not run and the victim survives
                        (exit non-zero).
  pi-no-prompt-deny     SAFEBASH_NONINTERACTIVE=1 denies WITHOUT prompting: no
                        `Type "confirm` anywhere in the transcript, the
                        CONFIRMATION-REQUIRED diagnostic present, the victim
                        survives, exit non-zero.

Exit code 0 = every requested leg passed; 1 = a leg failed; 2 = the platform
pseudo-terminal module is unavailable (prints a SKIP line). Output is read to
terminal end-of-stream including anything buffered after the child exits; a
leg is bounded by a timeout and a timed-out or killed child is a FAILURE, never
a successful denial.

Usage: python confirm_pty_probe.py <safebash-binary> [leg ...]
Prints one `leg=PASS` / `leg=FAIL detail` line per requested leg.
"""
import errno
import os
import re
import sys
import tempfile
import threading
import time

ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[=>]")
PROMPT = 'Type "confirm'
TOKEN = re.compile(r"confirm ([0-9A-F]{6})")
DENIAL = "CONFIRMATION REQUIRED"
CANCELLED = "cancelled by user"  # safebash's Declined diagnostic (guard.rs)
DENIAL_CODE = 126  # safebash's exit code for a denied/declined command
CMD = "rm -rf ../victim"
IS_WINDOWS = os.name == "nt"

if IS_WINDOWS:
    try:
        from winpty import PtyProcess  # noqa: F401
    except ImportError:
        print("SKIP pywinpty missing")
        sys.exit(2)
else:
    try:
        import pty  # noqa: F401
    except ImportError:
        print("SKIP pty module missing")
        sys.exit(2)


class Fixture:
    """A fresh scratch tree: work (cwd/workspace anchor), a sibling victim with
    a sentinel, and home/config/state kept OUTSIDE victim."""

    def __init__(self):
        # DESIGN 4.2: the scratch root goes under the cargo target dir when the
        # launcher passes it (SB_SCRATCH_BASE = CARGO_TARGET_TMPDIR); fall back to
        # the system temp dir only when run standalone.
        base = os.environ.get("SB_SCRATCH_BASE")
        base = base if base and os.path.isdir(base) else None
        self.root = tempfile.mkdtemp(prefix="sb-confirm-", dir=base)
        self.work = os.path.join(self.root, "work")
        self.victim = os.path.join(self.root, "victim")
        self.home = os.path.join(self.root, "home")
        self.config = os.path.join(self.root, "config")
        self.state = os.path.join(self.root, "state")
        for d in (self.work, self.victim, self.home, self.config, self.state):
            os.makedirs(d, exist_ok=True)
        self.sentinel = os.path.join(self.victim, "sentinel.txt")
        with open(self.sentinel, "w") as fh:
            fh.write("keep me")

    def victim_survives(self):
        return os.path.exists(self.sentinel)

    def env(self, pi_mode):
        """A clean environment: every ambient SAFEBASH_* policy/mode variable
        removed (SAFEBASH_LEVEL/STRICT/PARANOID/FLOOR raise the level and at
        Strict+ set ConfirmMode::Never, which would make a control deny without
        prompting; SAFEBASH_WORKSPACE/FLOOR/NONINTERACTIVE change anchoring and
        mode), BASH_ENV dropped so no outside startup file runs, and home/config/
        state pointed at scratch so no real user state is touched. The pi leg
        then sets SAFEBASH_NONINTERACTIVE=1; the controls leave it unset."""
        env = {k: v for k, v in os.environ.items() if not k.upper().startswith("SAFEBASH")}
        env.pop("BASH_ENV", None)
        if IS_WINDOWS:
            env["USERPROFILE"] = self.home
            env["APPDATA"] = self.config
            env["LOCALAPPDATA"] = self.state
        else:
            env["HOME"] = self.home
            env["XDG_CONFIG_HOME"] = self.config
            env["XDG_STATE_HOME"] = self.state
        if pi_mode:
            env["SAFEBASH_NONINTERACTIVE"] = "1"
        return env

    def cleanup(self):
        import shutil

        shutil.rmtree(self.root, ignore_errors=True)


class Session:
    """safebash -c CMD under a real controlling terminal, with a reader thread
    that drains to end-of-stream (including output after the child exits)."""

    def __init__(self, exe, fx, pi_mode):
        self.chunks = []
        self._exit = None
        self._drain_error = None  # an UNEXPECTED read error (not a clean EOF)
        self._drain_ended = False
        env = fx.env(pi_mode)
        if IS_WINDOWS:
            self.proc = PtyProcess.spawn(
                [exe, "-c", CMD], cwd=fx.work, env=env, dimensions=(50, 200)
            )
            self._win = True
            self._pid = None
        else:
            self._win = False
            pid, fd = pty.fork()
            if pid == 0:  # child: controlling tty is the pty slave (pty.fork)
                try:
                    os.chdir(fx.work)
                    os.execvpe(exe, [exe, "-c", CMD], env)
                except Exception:
                    pass
                os._exit(127)
            self._pid = pid
            self._fd = fd
        self._pump = threading.Thread(target=self._drain, daemon=True)
        self._pump.start()

    def _drain(self):
        """Read to end-of-stream. A clean end (ConPTY EOFError, Unix empty read
        or the EIO the pty master raises once the slave closes) is normal; any
        other error is recorded so wait_exit can FAIL the leg rather than treat a
        truncated transcript as complete (a missed denial must never pass)."""
        try:
            if self._win:
                while True:
                    try:
                        data = self.proc.read(4096)
                    except EOFError:
                        break  # clean end of the ConPTY stream
                    if not data:
                        break
                    self.chunks.append(data)
            else:
                while True:
                    try:
                        data = os.read(self._fd, 4096)
                    except OSError as err:
                        if err.errno == errno.EIO:
                            break  # pty master EOF after the slave closed (clean)
                        raise
                    if not data:
                        break  # clean EOF
                    self.chunks.append(data.decode("utf-8", "backslashreplace"))
        except Exception as err:  # noqa: BLE001 - recorded, surfaced by wait_exit
            self._drain_error = err
        finally:
            self._drain_ended = True

    def text(self):
        return ANSI.sub("", "".join(self.chunks))

    def write_line(self, s):
        payload = s + "\r"
        if self._win:
            self.proc.write(payload)
        else:
            os.write(self._fd, payload.encode())

    def wait_for_token(self, timeout=15.0):
        """Return the six-hex confirm token once the WHOLE prompt line has been
        drained, or None if it never appears. Polls instead of searching once:
        the prompt prefix and the token can arrive in separate reads (likely on a
        loaded ConPTY), so a single search right after the prefix would race."""
        deadline = time.time() + timeout
        while True:
            out = self.text()
            m = TOKEN.search(out)
            if m and PROMPT in out:
                return m.group(1)
            if not self._alive() or time.time() >= deadline:
                out = self.text()
                m = TOKEN.search(out)
                return m.group(1) if (m and PROMPT in out) else None
            time.sleep(0.05)

    def _alive(self):
        if self._win:
            return self.proc.isalive()
        return self._exit is None and self._reap(block=False) is None

    def _reap(self, block):
        if self._win:
            if self.proc.isalive():
                return None
            self._exit = self.proc.exitstatus
            return self._exit
        if self._exit is not None:
            return self._exit
        flags = 0 if block else os.WNOHANG
        try:
            pid, status = os.waitpid(self._pid, flags)
        except ChildProcessError:
            self._exit = self._exit if self._exit is not None else 0
            return self._exit
        if pid == 0:
            return None
        self._exit = os.waitstatus_to_exitcode(status)
        return self._exit

    def wait_exit(self, timeout=15.0):
        """Return the child's exit code, or None if it did not exit within the
        bound. Before returning, confirm the transcript is FULLY drained: join the
        reader thread and fail (raise) if it did not finish or hit an unexpected
        error, so a buffered denial/prompt can never be missed and counted as a
        pass."""
        deadline = time.time() + timeout
        rc = None
        while time.time() < deadline:
            rc = self._reap(block=False)
            if rc is not None:
                break
            time.sleep(0.05)
        if rc is None:
            return None  # child did not exit in time -> the leg fails
        self._pump.join(timeout=5.0)
        if self._pump.is_alive() or not self._drain_ended:
            raise RuntimeError("transcript drain did not finish after the child exited")
        if self._drain_error is not None:
            raise RuntimeError(f"unexpected read error while draining: {self._drain_error!r}")
        return rc

    def close(self):
        try:
            if self._win:
                if self.proc.isalive():
                    self.proc.terminate(force=True)
            else:
                if self._exit is None:
                    try:
                        os.kill(self._pid, 9)
                    except OSError:
                        pass
                    self._reap(block=True)
                try:
                    os.close(self._fd)
                except OSError:
                    pass
        except Exception:
            pass


def leg_interactive_approve(exe):
    fx = Fixture()
    s = Session(exe, fx, pi_mode=False)
    try:
        token = s.wait_for_token()
        assert token, f"no prompt/token under the controlling terminal; tail={s.text()[-300:]!r}"
        s.write_line("confirm " + token)
        rc = s.wait_exit()
        assert rc is not None, "approved command did not finish before timeout"
        assert rc == 0, f"approved command exited {rc}; tail={s.text()[-300:]!r}"
        assert not fx.victim_survives(), "approved rm did not delete the victim"
    finally:
        s.close()
        fx.cleanup()


def leg_interactive_decline(exe):
    fx = Fixture()
    s = Session(exe, fx, pi_mode=False)
    try:
        # Wait for the full prompt (so safebash is at the read) before answering.
        token = s.wait_for_token()
        assert token, f"no prompt/token under the controlling terminal; tail={s.text()[-300:]!r}"
        s.write_line("no")  # anything that is not the token cancels
        rc = s.wait_exit()
        assert rc is not None, "declined command did not finish before timeout"
        # The exact denial code and the cancellation diagnostic together rule out
        # a child killed after the prompt counting as a decline.
        assert rc == DENIAL_CODE, f"declined command should exit {DENIAL_CODE}, got {rc}; tail={s.text()[-300:]!r}"
        assert CANCELLED in s.text(), f"declined command must print the cancellation diagnostic; tail={s.text()[-300:]!r}"
        assert fx.victim_survives(), "declined command must not delete the victim"
    finally:
        s.close()
        fx.cleanup()


def leg_pi_no_prompt_deny(exe):
    fx = Fixture()
    s = Session(exe, fx, pi_mode=True)
    try:
        rc = s.wait_exit()
        assert rc is not None, "pi-mode command did not finish before timeout (did it prompt?)"
        out = s.text()
        assert PROMPT not in out, f"pi mode must NOT prompt; found a prompt: tail={out[-300:]!r}"
        assert DENIAL in out, f"pi mode must print the confirmation-required denial; tail={out[-300:]!r}"
        # The exact denial code distinguishes a genuine denial from a killed child.
        assert rc == DENIAL_CODE, f"denied command should exit {DENIAL_CODE}, got {rc}; tail={out[-300:]!r}"
        assert fx.victim_survives(), "pi-mode denial must not delete the victim"
    finally:
        s.close()
        fx.cleanup()


LEGS = {
    "interactive-approve": leg_interactive_approve,
    "interactive-decline": leg_interactive_decline,
    "pi-no-prompt-deny": leg_pi_no_prompt_deny,
}


def main():
    # The leg checks are Python assertions; under `python -O` / PYTHONOPTIMIZE
    # they are stripped and every leg would pass vacuously. Refuse to run then,
    # so an optimized interpreter can never report a false PASS.
    if not __debug__:
        print("FAIL assertions are disabled (python -O / PYTHONOPTIMIZE); refusing to run")
        return 1
    if len(sys.argv) < 2:
        print("usage: confirm_pty_probe.py <safebash-binary> [leg ...]")
        return 2
    exe = os.path.abspath(sys.argv[1])
    if not os.path.isfile(exe):
        print(f"SKIP safebash binary missing: {exe}")
        return 2
    wanted = sys.argv[2:] or list(LEGS)
    unknown = [leg for leg in wanted if leg not in LEGS]
    if unknown:
        print(f"FAIL unknown legs: {unknown}")
        return 1

    failed = []
    for leg in wanted:
        try:
            LEGS[leg](exe)
            print(f"{leg}=PASS", flush=True)
        except Exception as err:  # one leg failing must not kill the sweep
            failed.append(leg)
            detail = repr(err).splitlines()[0][:200]
            print(f"{leg}=FAIL {detail}", flush=True)
        time.sleep(0.1)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
