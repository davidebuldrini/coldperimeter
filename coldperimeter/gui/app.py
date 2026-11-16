"""Start the local API and open the interface.

By default a native window is used (WebKit on macOS, WebView2 on Windows). If
that is not available the interface opens in the default web browser instead.
"""

from __future__ import annotations

import secrets
import socket
import sys
import threading
import time
import webbrowser

import uvicorn

from .api import create_api

WINDOW_TITLE = "ColdPerimeter"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _wait_until_listening(port: int, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def run(browser: bool = False, port: int = 0) -> int:
    port = port or _free_port()
    token = secrets.token_urlsafe(32)
    app = create_api(
        token=token,
        allowed_hosts={f"127.0.0.1:{port}", f"localhost:{port}"},
    )
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", access_log=False)
    )
    threading.Thread(target=server.run, daemon=True).start()
    if not _wait_until_listening(port):
        print("error: the local engine did not start.", file=sys.stderr)
        return 1

    # The token travels in the URL fragment, which is never sent to a server.
    url = f"http://127.0.0.1:{port}/#token={token}"

    if not browser:
        try:
            import webview

            webview.create_window(WINDOW_TITLE, url, width=1120, height=800, min_size=(420, 560))
            webview.start()
            server.should_exit = True
            return 0
        except Exception as exc:  # no usable web view on this machine
            print(f"Native window unavailable ({exc}); opening the browser.", file=sys.stderr)

    webbrowser.open(url)
    print(f"ColdPerimeter is open in your browser: {url}")
    print("Keep this window open while you work. Press Ctrl+C to quit.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.should_exit = True
    return 0


def main() -> int:
    """Entry point of the packaged application."""
    return run(browser="--browser" in sys.argv)


if __name__ == "__main__":
    sys.exit(main())
