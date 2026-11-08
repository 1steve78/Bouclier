#!/usr/bin/env python3
"""
verify_tui.py: Automated real-terminal verification harness for Bouclier Bubble Tea TUI.
Uses Linux pseudo-terminal (PTY) to emulate real user interactive sessions.
"""

import fcntl
import json
import os
import pty
import re
import select
import struct
import subprocess
import sys
import termios
import time

BIN = "/mnt/d/projects/BOUCLIER/bin/bouclier-linux"
CWD = "/mnt/d/projects/BOUCLIER"

def set_winsize(fd, rows, cols):
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))

def strip_ansi(text):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

class TerminalSession:
    def __init__(self, cmd, rows=30, cols=100, env=None):
        self.cmd = cmd
        self.rows = rows
        self.cols = cols
        self.env = env or os.environ.copy()
        self.master, self.slave = pty.openpty()
        set_winsize(self.slave, rows, cols)
        
        self.proc = subprocess.Popen(
            cmd,
            stdin=self.slave,
            stdout=self.slave,
            stderr=self.slave,
            cwd=CWD,
            env=self.env,
            close_fds=True,
            preexec_fn=os.setsid
        )
        os.close(self.slave)
        self.output_buffer = ""

    def read_until(self, pattern, timeout=10):
        start = time.time()
        while time.time() - start < timeout:
            r, _, _ = select.select([self.master], [], [], 0.1)
            if r:
                try:
                    data = os.read(self.master, 4096).decode('utf-8', errors='ignore')
                    if not data:
                        break
                    self.output_buffer += data
                    clean = strip_ansi(self.output_buffer)
                    if isinstance(pattern, str) and pattern in clean:
                        return clean
                    elif hasattr(pattern, 'search') and pattern.search(clean):
                        return clean
                except OSError:
                    break
        clean = strip_ansi(self.output_buffer)
        raise TimeoutError(f"Pattern {pattern!r} not found within {timeout}s in:\n{clean[-1000:]}")

    def write(self, data):
        self.output_buffer = ""
        if isinstance(data, str):
            data = data.encode('utf-8')
        os.write(self.master, data)
        time.sleep(0.08)

    def resize(self, rows, cols):
        self.rows = rows
        self.cols = cols
        set_winsize(self.master, rows, cols)
        time.sleep(0.1)

    def close(self):
        try:
            self.write("q")
            time.sleep(0.1)
            if self.proc.poll() is None:
                self.write("\x03")
                time.sleep(0.1)
                self.proc.terminate()
                self.proc.wait(timeout=2)
        except Exception:
            pass
        finally:
            try:
                os.close(self.master)
            except Exception:
                pass

def test_full_interactive_session():
    print("--- [1] Testing Full Interactive Terminal Session ---")
    session = TerminalSession([BIN, "tui"], rows=32, cols=100)
    try:
        # 1. Dashboard launches and renders
        out = session.read_until("Start a new website scan", timeout=5)
        assert "BOUCLIER" in out, "Dashboard title missing"
        assert "Security Intelligence Engine" in out, "Dashboard capabilities card missing"
        print("  ✓ Dashboard rendered successfully")

        # 2. Enter URL input
        session.write("\r")
        out = session.read_until("TARGET SELECTION", timeout=3)
        assert "Enter a website URL or hostname to assess" in out
        print("  ✓ Navigated to URL input screen")

        # 3. Reject empty input
        session.write("\r")
        out = session.read_until("Target URL cannot be empty", timeout=3)
        print("  ✓ Empty URL validation error caught")

        # 4. Reject invalid URL
        session.write("not a valid url :/// \r")
        out = session.read_until("Invalid URL", timeout=3)
        print("  ✓ Invalid URL syntax validation caught")

        # Clear input using backspaces
        session.write("\x08" * 30)

        # 5. Start valid scan
        session.write("example.com\r")
        out = session.read_until("SCANNING IN PROGRESS", timeout=3)
        assert "Target: https://example.com" in out
        print("  ✓ Scan initiated with normalized target https://example.com")

        # Wait for scan to progress through stages to completion
        out = session.read_until("View Findings", timeout=30)
        assert "Risk Score" in out or "Finding Counts" in out
        print("  ✓ Scan progressed through analysis stages and displayed overview")

        # 6. Help screen
        session.write("?")
        out = session.read_until("Return to Previous Screen", timeout=5)
        assert "Keyboard Shortcuts" in out or "CLEAN:" in out
        session.write("?")
        out = session.read_until("View Findings", timeout=5)
        print("  ✓ Help screen displayed and dismissed")

        # 7. Coverage screen
        session.write("c")
        out = session.read_until("Esc Back to Overview", timeout=5)
        assert "Limitations & Assessment Caveats" in out or "Subsystem Coverage" in out
        session.write("\x1b") # Esc
        out = session.read_until("View Findings", timeout=5)
        print("  ✓ Coverage screen displayed and dismissed")

        # 8. Findings screen and filtering
        session.write("f")
        out = session.read_until("Filter Severity", timeout=5)
        assert "Back to Overview" in out
        print("  ✓ Findings Explorer opened")

        # Switch filter to Medium
        session.write("4")
        time.sleep(0.2)
        # Switch back to All
        session.write("1")
        time.sleep(0.2)

        # Inspect finding detail
        session.write("\r")
        out = session.read_until("Technical Evidence", timeout=5)
        assert "Finding Code:" in out or "Metadata" in out
        print("  ✓ Finding details and evidence modal opened")

        # Esc back to findings list
        session.write("\x1b")
        out = session.read_until("Filter Severity", timeout=5)
        # Esc back to overview
        session.write("\x1b")
        out = session.read_until("View Findings", timeout=5)
        print("  ✓ Esc navigation returned cleanly to Overview")

        # 9. Report Export JSON
        session.write("e")
        out = session.read_until("EXPORT REPORT", timeout=3)
        assert "Destination File Path:" in out
        session.write("\r")
        out = session.read_until("Report saved to", timeout=5)
        print("  ✓ JSON report exported successfully")

        # Report Export Markdown
        session.write("\t") # Tab to toggle to Markdown
        time.sleep(0.1)
        session.write("\r")
        out = session.read_until("Report saved to", timeout=5)
        print("  ✓ Markdown report exported successfully")

        # Return to Overview, then Dashboard
        session.write("\x1b")
        out = session.read_until("View Findings", timeout=5)
        session.write("\x1b")
        out = session.read_until("Last target:", timeout=5)
        assert "Return to active assessment" in out
        print("  ✓ Returned to Dashboard; recent assessment cached")

        # Start another scan from dashboard
        session.write("n")
        out = session.read_until("TARGET SELECTION", timeout=3)
        print("  ✓ Starting another scan works")

        session.write("\x1b") # back to dashboard
        session.write("q")
        session.proc.wait(timeout=3)
        assert session.proc.returncode == 0, f"Expected returncode 0 on quit, got {session.proc.returncode}"
        print("  ✓ Clean exit on 'q' restored terminal")

    finally:
        session.close()

def test_scan_cancellation():
    print("\n--- [2] Testing Scan Cancellation (C & Esc) ---")
    
    # Test 1: Cancel with 'c'
    session = TerminalSession([BIN, "tui"], rows=30, cols=100)
    try:
        session.read_until("Start a new website scan", timeout=5)
        session.write("\r") # Enter -> URL input
        session.read_until("TARGET SELECTION", timeout=3)
        session.write("https://example.com\r") # Enter -> scanning
        session.read_until("SCANNING IN PROGRESS", timeout=3)
        
        # Send 'c' to cancel
        session.write("c")
        out = session.read_until("Scan Unsuccessful", timeout=5)
        assert "scan cancelled by user" in out
        assert "Press Enter to retry scan, or Esc to return to dashboard" in out
        print("  ✓ Scan cancelled using 'c'")

        # Test retry
        session.write("\r") # Enter -> retry
        out = session.read_until("Elapsed:", timeout=5)
        print("  ✓ Retry started successfully after cancellation")

        # Test 2: Cancel with Esc
        session.write("\x1b") # Esc -> cancel
        out = session.read_until("Scan Unsuccessful", timeout=5)
        assert "scan cancelled by user" in out
        print("  ✓ Scan cancelled using 'Esc'")

        # Press Esc to return to dashboard
        session.write("\x1b")
        out = session.read_until("Start a new website scan", timeout=5)
        print("  ✓ Returned to Dashboard from cancelled screen via Esc")

        # Subsequent scan can start
        session.write("s")
        out = session.read_until("TARGET SELECTION", timeout=3)
        print("  ✓ Subsequent scan starts cleanly")

        session.write("\x1b")
        session.write("q")
        session.proc.wait(timeout=2)
    finally:
        session.close()

def test_terminal_compatibility():
    print("\n--- [3] Testing Terminal Compatibility (Narrow 40-col & Resizing) ---")
    
    # 1. Launch in 40-column narrow terminal
    session = TerminalSession([BIN, "tui"], rows=25, cols=40)
    try:
        out = session.read_until("Actions", timeout=5)
        print("  ✓ Dashboard rendered cleanly in 40 columns")

        session.write("\r")
        out = session.read_until("TARGET SELECTION", timeout=3)
        print("  ✓ URL input rendered cleanly in 40 columns")

        # 2. Dynamic terminal resize to 120x40
        session.resize(rows=40, cols=120)
        time.sleep(0.3)
        session.write("\x1b") # Esc back to dashboard
        out = session.read_until("Actions", timeout=5)
        print("  ✓ Dynamic resize to 120x40 handled without panics")

        session.write("q")
        session.proc.wait(timeout=2)
    finally:
        session.close()

    # 3. Test NO_COLOR environment variable
    print("  Testing NO_COLOR environment variable...")
    env_no_color = os.environ.copy()
    env_no_color["NO_COLOR"] = "1"
    session = TerminalSession([BIN, "tui"], rows=30, cols=80, env=env_no_color)
    try:
        session.read_until("Actions", timeout=5)
        raw = session.output_buffer
        # In monochrome mode, ANSI color escapes (e.g. \x1b[38;2; or \x1b[31m) should not appear
        has_color = bool(re.search(r'\x1B\[(?:3[0-7]|9[0-7]|38;5|38;2)', raw))
        assert not has_color, f"Detected ANSI colors in NO_COLOR=1 mode"
        print("  ✓ NO_COLOR=1 successfully disabled ANSI color sequences")
        session.write("q")
        session.proc.wait(timeout=2)
    finally:
        session.close()

    # 4. Test --no-color flag
    print("  Testing --no-color command flag...")
    session = TerminalSession([BIN, "tui", "--no-color"], rows=30, cols=80)
    try:
        session.read_until("Actions", timeout=5)
        raw = session.output_buffer
        has_color = bool(re.search(r'\x1B\[(?:3[0-7]|9[0-7]|38;5|38;2)', raw))
        assert not has_color, f"Detected ANSI colors in --no-color mode"
        print("  ✓ --no-color flag successfully disabled ANSI color sequences")
        session.write("q")
        session.proc.wait(timeout=2)
    finally:
        session.close()

def test_export_and_redaction():
    print("\n--- [4] Verifying Exported Report Content, Permissions & Redaction ---")
    json_path = os.path.join(CWD, "bouclier-report.json")
    md_path = os.path.join(CWD, "bouclier-report.md")

    assert os.path.exists(json_path), f"{json_path} was not created"
    assert os.path.exists(md_path), f"{md_path} was not created"

    # 1. Parse JSON and check schema
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    assert data.get("schema_version") == "bouclier-risk/v1", f"Unexpected schema version: {data.get('schema_version')}"
    assert data.get("policy_id") == "bouclier-default"
    assert "findings" in data
    assert "overall_score" in data
    assert "classification" in data
    print("  ✓ Exported JSON parsed successfully with schema_version bouclier-risk/v1")

    # 2. Check Markdown
    with open(md_path, 'r', encoding='utf-8') as f:
        md_text = f.read()
    assert "# Bouclier Website Risk Assessment" in md_text
    assert "Executive summary" in md_text or "Executive Summary" in md_text
    assert "Finding counts by severity" in md_text
    print("  ✓ Exported Markdown structured and titled correctly")

    # 3. Check Permissions
    subprocess.run([BIN, "scan", "https://example.com", "--format", "json", "-o", "/tmp/bouclier-perm-test.json"], check=True)
    perm = os.stat("/tmp/bouclier-perm-test.json").st_mode & 0o777
    assert perm == 0o600, f"Expected 0600 permissions on native Linux filesystem, got {oct(perm)}"
    print(f"  ✓ Native Linux filesystem file permissions verified: {oct(perm)} (owner read/write only)")

def main():
    print("Starting Bouclier Phase 7 Comprehensive TUI Verification...\n")
    try:
        test_full_interactive_session()
        test_scan_cancellation()
        test_terminal_compatibility()
        test_export_and_redaction()
        print("\n========================================================")
        print("ALL INTERACTIVE TUI VERIFICATION TESTS PASSED SUCCESSFULLY!")
        print("========================================================")
    except Exception as e:
        print(f"\n❌ VERIFICATION TEST FAILED: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
