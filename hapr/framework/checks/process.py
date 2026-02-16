"""Process security checks for parsed HAProxy config.

These checks verify that the HAProxy process is configured to run with
reduced privileges and proper OS-level isolation.
"""

from __future__ import annotations

from ...models import Finding, HAProxyConfig, Severity, Status


# ---------------------------------------------------------------------------
# HAPR-PROC-001  chroot
# ---------------------------------------------------------------------------

def check_chroot(config: HAProxyConfig) -> Finding:
    """Check that the global section has a ``chroot`` directive.

    Running HAProxy inside a chroot jail limits what an attacker can access
    if the process is compromised.

    Returns PASS if present, FAIL if missing.
    """
    value = config.global_section.get_value("chroot")

    if value is not None:
        return Finding(
            check_id="HAPR-PROC-001",
            status=Status.PASS,
            message=f"chroot is configured: {value.strip()}",
            evidence=f"chroot {value.strip()}",
        )

    return Finding(
        check_id="HAPR-PROC-001",
        status=Status.FAIL,
        message="chroot directive is missing from the global section.",
        evidence="not found",
    )


# ---------------------------------------------------------------------------
# HAPR-PROC-002  Non-root user
# ---------------------------------------------------------------------------

def check_non_root_user(config: HAProxyConfig) -> Finding:
    """Check that the global section specifies a non-root ``user`` or ``uid``.

    HAProxy should drop privileges after binding to privileged ports.
    Running as *root* unnecessarily expands the blast radius of any
    vulnerability.  Both ``user <name>`` and ``uid <number>`` are accepted.

    Returns PASS if a non-root user/uid is set, FAIL if missing or set to
    ``root`` / uid 0.
    """
    user_value = config.global_section.get_value("user")
    uid_value = config.global_section.get_value("uid")

    if user_value is not None:
        username = user_value.strip()
        if username.lower() == "root":
            return Finding(
                check_id="HAPR-PROC-002",
                status=Status.FAIL,
                message="HAProxy is configured to run as root.",
                evidence=f"user {username}",
            )
        return Finding(
            check_id="HAPR-PROC-002",
            status=Status.PASS,
            message=f"HAProxy is configured to run as non-root user '{username}'.",
            evidence=f"user {username}",
        )

    if uid_value is not None:
        uid_str = uid_value.strip()
        if uid_str == "0":
            return Finding(
                check_id="HAPR-PROC-002",
                status=Status.FAIL,
                message="HAProxy is configured to run as uid 0 (root).",
                evidence=f"uid {uid_str}",
            )
        return Finding(
            check_id="HAPR-PROC-002",
            status=Status.PASS,
            message=f"HAProxy is configured to run as non-root uid {uid_str}.",
            evidence=f"uid {uid_str}",
        )

    return Finding(
        check_id="HAPR-PROC-002",
        status=Status.FAIL,
        message="No 'user' or 'uid' directive found in the global section.",
        evidence="not found",
    )


# ---------------------------------------------------------------------------
# HAPR-PROC-003  Group directive
# ---------------------------------------------------------------------------

def check_user_group(config: HAProxyConfig) -> Finding:
    """Check that the global section specifies a ``group`` or ``gid`` directive.

    Setting an explicit group ensures the process runs with a restricted
    group, complementing the ``user`` directive.  Both ``group <name>``
    and ``gid <number>`` are accepted.

    Returns PASS if present, FAIL if missing.
    """
    group_value = config.global_section.get_value("group")
    gid_value = config.global_section.get_value("gid")

    if group_value is not None:
        group_name = group_value.strip()
        return Finding(
            check_id="HAPR-PROC-003",
            status=Status.PASS,
            message=f"group directive is configured: {group_name}",
            evidence=f"group {group_name}",
        )

    if gid_value is not None:
        gid_str = gid_value.strip()
        return Finding(
            check_id="HAPR-PROC-003",
            status=Status.PASS,
            message=f"gid directive is configured: {gid_str}",
            evidence=f"gid {gid_str}",
        )

    return Finding(
        check_id="HAPR-PROC-003",
        status=Status.FAIL,
        message="No 'group' or 'gid' directive found in the global section.",
        evidence="not found",
    )


# ---------------------------------------------------------------------------
# HAPR-PROC-004  ulimit-n
# ---------------------------------------------------------------------------

def check_ulimits(config: HAProxyConfig) -> Finding:
    """Check that ``ulimit-n`` is set in the global section.

    Explicitly setting ``ulimit-n`` ensures HAProxy has enough file
    descriptors for the expected workload and prevents silent failures
    under high concurrency.

    Returns PASS if set, FAIL if missing.
    """
    value = config.global_section.get_value("ulimit-n")

    if value is not None:
        return Finding(
            check_id="HAPR-PROC-004",
            status=Status.PASS,
            message=f"ulimit-n is configured: {value.strip()}",
            evidence=f"ulimit-n {value.strip()}",
        )

    return Finding(
        check_id="HAPR-PROC-004",
        status=Status.FAIL,
        message="ulimit-n is not set in the global section.",
        evidence="not found",
    )


# ---------------------------------------------------------------------------
# HAPR-PROC-005  Daemon mode
# ---------------------------------------------------------------------------

def check_daemon_mode(config: HAProxyConfig) -> Finding:
    """Check that ``daemon`` or ``master-worker`` exists in the global section.

    Running HAProxy in the foreground is useful for debugging but not
    recommended for production deployments.  The ``daemon`` directive
    ensures the process forks into the background.  ``master-worker``
    mode (HAProxy 1.9+) is the modern recommended alternative.

    Returns PASS if either is present, FAIL if missing.
    """
    if config.global_section.has("daemon"):
        return Finding(
            check_id="HAPR-PROC-005",
            status=Status.PASS,
            message="HAProxy is configured to run as a daemon.",
            evidence="daemon",
        )

    if config.global_section.has("master-worker"):
        return Finding(
            check_id="HAPR-PROC-005",
            status=Status.PASS,
            message="HAProxy is configured in master-worker mode.",
            evidence="master-worker",
        )

    return Finding(
        check_id="HAPR-PROC-005",
        status=Status.FAIL,
        message=(
            "No 'daemon' or 'master-worker' directive found in global section. "
            "Running in foreground mode is not recommended for production."
        ),
        evidence="not found",
    )
