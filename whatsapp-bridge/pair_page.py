#!/usr/bin/env -S uv run --no-project --script
# /// script
# requires-python = ">=3.11"
# ///
"""Show the bridge's pairing QR as a self-refreshing page, until the bridge is paired.

WhatsApp rotates the pairing code every ~20 s and the bridge rewrites store/qr_code.txt each
time, so a one-off PNG is stale before anyone can scan it. This renders the current code into
an HTML page that reloads itself every 2 s, opens it once, and stops when whatsmeow_device has
a row (paired) or after --timeout seconds.

Pairing is on demand. An unpaired bridge stops after one unscanned batch of codes (clean exit,
and its LaunchAgent only restarts it on a non-zero exit), so it is not asking WhatsApp for new
codes every few minutes around the clock. This page starts it again whenever it is not running.

Scan from the phone: WhatsApp -> Settings -> Linked devices -> Link a device.

    uv run pair_page.py [--timeout 900] [--no-open]
"""
import argparse, html, os, re, sqlite3, subprocess, sys, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
QR_TXT = HERE / "store" / "qr_code.txt"
DEVICE_DB = HERE / "store" / "whatsapp.db"
PAGE = Path("/tmp/whatsapp-personal-pair.html")


def paired() -> bool:
    con = sqlite3.connect(f"file:{DEVICE_DB}?mode=ro", uri=True)
    try:
        return con.execute("SELECT count(*) FROM whatsmeow_device").fetchone()[0] > 0
    finally:
        con.close()


LABEL = "com.whatsapp.bridge"


def bridge_running() -> bool:
    r = subprocess.run(["launchctl", "list", LABEL], capture_output=True, text=True)
    return r.returncode == 0 and '"PID" =' in r.stdout


def start_bridge() -> None:
    subprocess.run(["launchctl", "kickstart", f"gui/{os.getuid()}/{LABEL}"], check=True)


def write_page(body: str) -> None:
    PAGE.write_text(
        "<!doctype html><meta charset=utf-8><meta http-equiv=refresh content=2>"
        "<title>Link personal WhatsApp</title>"
        "<body style='font-family:-apple-system;text-align:center;margin-top:30px'>"
        + body + "</body>")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--no-open", action="store_true")
    a = ap.parse_args()
    opened, last_code, deadline = False, None, time.time() + a.timeout
    while time.time() < deadline:
        if paired():
            write_page("<h1>Paired ✓</h1><p>The personal bridge is linked. You can close this tab.</p>")
            print("paired")
            return 0
        if not bridge_running():
            start_bridge()
        code = QR_TXT.read_text().strip() if QR_TXT.exists() else ""
        age = time.time() - QR_TXT.stat().st_mtime if QR_TXT.exists() else 1e9
        if code and code != last_code and age < 60:
            svg = subprocess.run(["qrencode", "-t", "SVG", "-s", "8", "-m", "2", "-o", "-", code],
                                 capture_output=True, text=True, check=True).stdout
            # qrencode writes a fixed size in cm; pin it to the box so the whole code is on screen.
            svg = re.sub(r'(<svg[^>]*?)\swidth="[^"]*"\s+height="[^"]*"', r'\1 width="380" height="380"', svg, count=1)
            write_page("<h2>Link the personal WhatsApp bridge</h2>"
                       "<p>Phone: WhatsApp → Settings → Linked devices → Link a device</p>"
                       f"<div style='width:420px;margin:auto'>{svg}</div>"
                       f"<p style='color:#888'>code refreshed {html.escape(time.strftime('%H:%M:%S'))}"
                       " · page reloads every 2 s</p>")
            last_code = code
            if not opened and not a.no_open:
                subprocess.run(["open", str(PAGE)], check=True)
                opened = True
        elif not code or age >= 60:
            write_page("<h2>Waiting for the bridge to issue a fresh pairing code…</h2>")
        time.sleep(1)
    print("timeout: not paired", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
