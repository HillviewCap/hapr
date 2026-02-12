"""Detect HAProxy version via socket, binary, or stats page."""

from __future__ import annotations

import logging
import re
import socket
import subprocess

log = logging.getLogger(__name__)

_VERSION_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?(?:-[a-zA-Z0-9.]+)?)")


def detect_version(
    socket_path: str | None = None,
    binary_path: str | None = None,
    stats_url: str | None = None,
) -> str | None:
    """Try to detect the HAProxy version using available methods.

    Tries each method in order: socket, binary, stats page.
    Returns the version string or None if detection fails.
    """
    # Method 1: HAProxy runtime API via Unix socket
    if socket_path:
        version = _detect_via_socket(socket_path)
        if version:
            log.info("Detected HAProxy version via socket: %s", version)
            return version

    # Method 2: haproxy -v binary output
    if binary_path:
        version = _detect_via_binary(binary_path)
        if version:
            log.info("Detected HAProxy version via binary: %s", version)
            return version

    # Try default binary path
    if not binary_path:
        for default_bin in ("/usr/sbin/haproxy", "/usr/local/sbin/haproxy", "haproxy"):
            version = _detect_via_binary(default_bin)
            if version:
                log.info("Detected HAProxy version via binary (%s): %s", default_bin, version)
                return version

    # Method 3: Stats page scraping
    if stats_url:
        version = _detect_via_stats(stats_url)
        if version:
            log.info("Detected HAProxy version via stats page: %s", version)
            return version

    log.warning("Could not detect HAProxy version via any method")
    return None


def _detect_via_socket(socket_path: str) -> str | None:
    """Query HAProxy runtime API via Unix socket with 'show info'."""
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(socket_path)
        sock.sendall(b"show info\n")

        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk

        sock.close()
        text = data.decode("utf-8", errors="replace")

        for line in text.splitlines():
            if line.startswith("Version:"):
                version_str = line.split(":", 1)[1].strip()
                m = _VERSION_RE.search(version_str)
                if m:
                    return m.group(1)
            elif line.startswith("Release_date:"):
                continue

        log.warning("Socket responded but no version found in output")
        return None

    except FileNotFoundError:
        log.warning("Socket path does not exist: %s", socket_path)
        return None
    except PermissionError:
        log.warning("Permission denied accessing socket: %s", socket_path)
        return None
    except (ConnectionRefusedError, OSError) as exc:
        log.warning("Failed to connect to HAProxy socket %s: %s", socket_path, exc)
        return None


def _detect_via_binary(binary_path: str) -> str | None:
    """Run 'haproxy -v' and parse the version from output."""
    try:
        result = subprocess.run(
            [binary_path, "-v"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = result.stdout + result.stderr

        # Look for version pattern like "HAProxy version 2.8.1-1"
        # or "HA-Proxy version 2.6.14"
        for line in output.splitlines():
            if "version" in line.lower() or "haproxy" in line.lower():
                m = _VERSION_RE.search(line)
                if m:
                    return m.group(1)

        return None
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        log.warning("Timeout running %s -v", binary_path)
        return None
    except OSError as exc:
        log.debug("Failed to run %s: %s", binary_path, exc)
        return None


def _detect_via_stats(stats_url: str) -> str | None:
    """Scrape the HAProxy stats page for version info."""
    try:
        import urllib.request
        import urllib.error

        req = urllib.request.Request(stats_url, headers={"User-Agent": "hapr/0.1"})
        with urllib.request.urlopen(req, timeout=10) as resp:  # nosec B310 — user-provided stats URL
            html = resp.read().decode("utf-8", errors="replace")

        # Stats page typically shows version in a header or footer
        # Pattern: "HAProxy version 2.8.1"
        m = re.search(r"HAProxy\s+version\s+(\d+\.\d+(?:\.\d+)?)", html, re.IGNORECASE)
        if m:
            return m.group(1)

        # Also check for version in page title or info section
        m = _VERSION_RE.search(html)
        if m:
            return m.group(1)

        log.warning("Stats page accessible but no version found")
        return None

    except ImportError:
        log.error("urllib not available")
        return None
    except Exception as exc:
        log.warning("Failed to fetch stats page %s: %s", stats_url, exc)
        return None
