"""Live TLS probing via sslyze.

Scans TLS endpoints to extract protocol versions, cipher suites,
certificate details, and known vulnerabilities.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from .models import CertInfo, HAProxyConfig, ScanResult

if TYPE_CHECKING:
    pass

log = logging.getLogger(__name__)


def scan_targets(
    targets: list[str],
    config: HAProxyConfig | None = None,
) -> list[ScanResult]:
    """Run TLS scans against the given targets.

    Parameters
    ----------
    targets:
        List of ``host:port`` strings to scan.
    config:
        Optional parsed config for auto-discovering additional targets.

    Returns
    -------
    list[ScanResult]
        One result per target.
    """
    try:
        from sslyze import (
            Scanner,
            ServerScanRequest,
            ServerNetworkLocation,
            ScanCommand,
        )
    except ImportError:
        log.error("sslyze is not installed — run: pip install sslyze")
        return [ScanResult(error="sslyze library not installed")]

    all_targets = list(targets)

    # Auto-discover from config bind lines
    if config:
        for bind in config.all_binds:
            if bind.ssl and bind.port:
                addr = bind.address or "127.0.0.1"
                if addr in ("0.0.0.0", "*", ""):
                    addr = "127.0.0.1"
                t = f"{addr}:{bind.port}"
                if t not in all_targets:
                    all_targets.append(t)

    if not all_targets:
        log.warning("No scan targets specified or discovered from config")
        return []

    results: list[ScanResult] = []
    scan_commands = {
        ScanCommand.CERTIFICATE_INFO,
        ScanCommand.SSL_2_0_CIPHER_SUITES,
        ScanCommand.SSL_3_0_CIPHER_SUITES,
        ScanCommand.TLS_1_0_CIPHER_SUITES,
        ScanCommand.TLS_1_1_CIPHER_SUITES,
        ScanCommand.TLS_1_2_CIPHER_SUITES,
        ScanCommand.TLS_1_3_CIPHER_SUITES,
        ScanCommand.HEARTBLEED,
        ScanCommand.ROBOT,
        ScanCommand.OPENSSL_CCS_INJECTION,
        ScanCommand.TLS_COMPRESSION,
        ScanCommand.TLS_FALLBACK_SCSV,
        ScanCommand.SESSION_RENEGOTIATION,
        ScanCommand.ELLIPTIC_CURVES,
        ScanCommand.HTTP_HEADERS,
    }

    # Build scan requests
    scan_requests = []
    for target_str in all_targets:
        host, _, port_str = target_str.rpartition(":")
        if not host:
            host = target_str
            port_str = "443"
        try:
            port = int(port_str)
        except ValueError:
            port = 443

        try:
            location = ServerNetworkLocation(hostname=host, port=port)
            scan_requests.append(
                ServerScanRequest(
                    server_location=location,
                    scan_commands=scan_commands,
                )
            )
        except Exception as exc:
            log.warning("Failed to create scan request for %s: %s", target_str, exc)
            results.append(ScanResult(target=host, port=port, error=str(exc)))

    if not scan_requests:
        return results

    # Execute scans
    scanner = Scanner()
    scanner.queue_scans(scan_requests)

    for server_scan_result in scanner.get_results():
        loc = server_scan_result.server_location
        sr = ScanResult(target=loc.hostname, port=loc.port)

        if server_scan_result.scan_status.value != "COMPLETED":
            sr.error = f"Scan did not complete: {server_scan_result.scan_status}"
            results.append(sr)
            continue

        try:
            _extract_protocols(server_scan_result, sr)
            _extract_ciphers(server_scan_result, sr)
            _extract_cert_info(server_scan_result, sr)
            _extract_vulnerabilities(server_scan_result, sr)
            _extract_renegotiation(server_scan_result, sr)
            _extract_curves(server_scan_result, sr)
            _extract_hsts(server_scan_result, sr)
            _extract_fallback_scsv(server_scan_result, sr)
        except Exception as exc:
            log.warning("Error extracting scan data for %s:%d: %s", loc.hostname, loc.port, exc)
            sr.error = str(exc)

        results.append(sr)

    return results


def _extract_protocols(server_result, sr: ScanResult) -> None:
    """Extract accepted/rejected protocol versions."""
    from sslyze import ScanCommand

    proto_map = {
        ScanCommand.SSL_2_0_CIPHER_SUITES: "SSL 2.0",
        ScanCommand.SSL_3_0_CIPHER_SUITES: "SSL 3.0",
        ScanCommand.TLS_1_0_CIPHER_SUITES: "TLS 1.0",
        ScanCommand.TLS_1_1_CIPHER_SUITES: "TLS 1.1",
        ScanCommand.TLS_1_2_CIPHER_SUITES: "TLS 1.2",
        ScanCommand.TLS_1_3_CIPHER_SUITES: "TLS 1.3",
    }

    for cmd, proto_name in proto_map.items():
        try:
            result = server_result.scan_result.__getattribute__(cmd.value)
            if result and result.result:
                accepted = result.result.accepted_cipher_suites
                if accepted:
                    sr.accepted_protocols.append(proto_name)
                else:
                    sr.rejected_protocols.append(proto_name)
            else:
                sr.rejected_protocols.append(proto_name)
        except (AttributeError, Exception):
            sr.rejected_protocols.append(proto_name)


def _extract_ciphers(server_result, sr: ScanResult) -> None:
    """Extract accepted cipher suites per protocol."""
    from sslyze import ScanCommand

    proto_map = {
        ScanCommand.TLS_1_2_CIPHER_SUITES: "TLS 1.2",
        ScanCommand.TLS_1_3_CIPHER_SUITES: "TLS 1.3",
    }

    for cmd, proto_name in proto_map.items():
        try:
            result = server_result.scan_result.__getattribute__(cmd.value)
            if result and result.result:
                sr.accepted_ciphers[proto_name] = [
                    cs.cipher_suite.name
                    for cs in result.result.accepted_cipher_suites
                ]
        except (AttributeError, Exception):
            pass


def _extract_cert_info(server_result, sr: ScanResult) -> None:
    """Extract certificate information."""
    from sslyze import ScanCommand

    try:
        cert_result = server_result.scan_result.certificate_info
        if not cert_result or not cert_result.result:
            return

        deployments = cert_result.result.certificate_deployments
        if not deployments:
            return

        deployment = deployments[0]
        leaf = deployment.received_certificate_chain[0]

        ci = CertInfo(
            subject=leaf.subject.rfc4514_string,
            issuer=leaf.issuer.rfc4514_string,
            not_before=str(leaf.not_valid_before_utc),
            not_after=str(leaf.not_valid_after_utc),
            key_size=leaf.public_key().key_size if hasattr(leaf.public_key(), "key_size") else 0,
            signature_algorithm=leaf.signature_hash_algorithm.name if leaf.signature_hash_algorithm else "unknown",
            is_self_signed=(leaf.subject == leaf.issuer),
        )

        # Check chain validity
        ci.chain_valid = not deployment.verified_certificate_chain is None

        # Check expiry
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        ci.is_expired = leaf.not_valid_after_utc < now

        # SAN entries
        try:
            from cryptography.x509 import SubjectAlternativeName, DNSName
            san_ext = leaf.extensions.get_extension_for_class(SubjectAlternativeName)
            ci.san_entries = san_ext.value.get_values_for_type(DNSName)
        except Exception:
            pass

        sr.cert_info = ci
    except Exception as exc:
        log.warning("Failed to extract cert info: %s", exc)


def _extract_vulnerabilities(server_result, sr: ScanResult) -> None:
    """Extract vulnerability scan results."""
    try:
        hb = server_result.scan_result.heartbleed
        if hb and hb.result:
            sr.vulnerabilities["heartbleed"] = hb.result.is_vulnerable_to_heartbleed
    except (AttributeError, Exception):
        pass

    try:
        robot = server_result.scan_result.robot
        if robot and robot.result:
            sr.vulnerabilities["robot"] = robot.result.robot_result.value in (
                "VULNERABLE_WEAK_ORACLE",
                "VULNERABLE_STRONG_ORACLE",
            )
    except (AttributeError, Exception):
        pass

    try:
        ccs = server_result.scan_result.openssl_ccs_injection
        if ccs and ccs.result:
            sr.vulnerabilities["ccs_injection"] = ccs.result.is_vulnerable_to_ccs_injection
    except (AttributeError, Exception):
        pass

    try:
        comp = server_result.scan_result.tls_compression
        if comp and comp.result:
            sr.vulnerabilities["crime"] = comp.result.supports_compression
    except (AttributeError, Exception):
        pass


def _extract_renegotiation(server_result, sr: ScanResult) -> None:
    """Extract session renegotiation info."""
    try:
        reneg = server_result.scan_result.session_renegotiation
        if reneg and reneg.result:
            sr.secure_renegotiation = (
                reneg.result.supports_secure_renegotiation
                and not reneg.result.is_vulnerable_to_client_renegotiation_dos
            )
    except (AttributeError, Exception):
        pass


def _extract_curves(server_result, sr: ScanResult) -> None:
    """Extract supported elliptic curves."""
    try:
        curves = server_result.scan_result.elliptic_curves
        if curves and curves.result:
            sr.supported_curves = [
                c.name for c in curves.result.supported_curves
            ] if curves.result.supported_curves else []
    except (AttributeError, Exception):
        pass


def _extract_hsts(server_result, sr: ScanResult) -> None:
    """Extract HSTS header from HTTP headers scan."""
    try:
        headers = server_result.scan_result.http_headers
        if headers and headers.result:
            hsts = headers.result.strict_transport_security_header
            if hsts:
                sr.hsts_header = str(hsts.max_age)
    except (AttributeError, Exception):
        pass


def _extract_fallback_scsv(server_result, sr: ScanResult) -> None:
    """Extract TLS_FALLBACK_SCSV support."""
    try:
        fb = server_result.scan_result.tls_fallback_scsv
        if fb and fb.result:
            sr.supports_fallback_scsv = fb.result.supports_fallback_scsv
    except (AttributeError, Exception):
        pass
