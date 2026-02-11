"""Click-based CLI entry point for HAPR."""

from __future__ import annotations

import sys

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from . import __version__

console = Console()


@click.group()
@click.version_option(__version__, prog_name="hapr")
@click.option("--baseline", type=click.Path(exists=True), default=None,
              help="Path to a custom baseline YAML file.")
@click.option("--nvd-api-key", envvar="NVD_API_KEY", default=None,
              help="NVD API key for higher rate-limit CVE lookups.")
@click.option("--socket", "haproxy_socket", default=None,
              help="Path to HAProxy runtime API Unix socket.")
@click.option("--haproxy-bin", default=None,
              help="Path to haproxy binary for version detection.")
@click.option("--stats-url", default=None,
              help="URL to HAProxy stats page for version detection.")
@click.pass_context
def cli(ctx, baseline, nvd_api_key, haproxy_socket, haproxy_bin, stats_url):
    """HAPR — HAProxy Audit & Reporting Tool.

    Security baseline scoring, TLS scanning, CVE checking,
    and interactive reporting for HAProxy configurations.
    """
    ctx.ensure_object(dict)
    ctx.obj["baseline"] = baseline
    ctx.obj["nvd_api_key"] = nvd_api_key
    ctx.obj["haproxy_socket"] = haproxy_socket
    ctx.obj["haproxy_bin"] = haproxy_bin
    ctx.obj["stats_url"] = stats_url


@cli.command()
@click.argument("config_path", type=click.Path(exists=True))
@click.option("-o", "--output", type=click.Path(), default=None,
              help="Output HTML report path.")
@click.option("--scan/--no-scan", default=False,
              help="Enable live TLS scanning (auto-discover targets from config).")
@click.option("--scan-targets", multiple=True,
              help="Explicit host:port targets for TLS scanning.")
@click.option("--version-detect/--no-version-detect", default=False,
              help="Enable HAProxy version detection and CVE checking.")
@click.option("--full", is_flag=True, default=False,
              help="Enable all features (scan + version/CVE detection).")
@click.option("--tier", type=click.Choice(["baseline", "level1", "level2", "level3"],
              case_sensitive=False), default=None,
              help="Only run checks up to this tier (baseline < level1 < level2 < level3).")
@click.pass_context
def audit(ctx, config_path, output, scan, scan_targets, version_detect, full, tier):
    """Run a security audit on a HAProxy configuration file."""
    from .parser import parse_file
    from .framework.engine import run_audit

    if full:
        scan = True
        version_detect = True

    # Parse config
    console.print(f"[bold blue]Parsing config:[/] {config_path}")
    try:
        config = parse_file(config_path)
    except Exception as exc:
        console.print(f"[bold red]Error parsing config:[/] {exc}")
        sys.exit(1)

    for warning in config.warnings:
        console.print(f"[yellow]Warning:[/] {warning}")

    console.print(
        f"  Found: {len(config.frontends)} frontend(s), "
        f"{len(config.backends)} backend(s), "
        f"{len(config.listens)} listen section(s), "
        f"{len(config.all_binds)} bind(s), "
        f"{len(config.all_servers)} server(s)"
    )

    # TLS scanning
    scan_results = None
    if scan or scan_targets:
        console.print("[bold blue]Running TLS scan...[/]")
        try:
            from .scanner import scan_targets as do_scan
            targets = list(scan_targets)
            scan_results = do_scan(targets, config)
            console.print(f"  Scanned {len(scan_results)} target(s)")
        except Exception as exc:
            console.print(f"[yellow]TLS scan error:[/] {exc}")

    # Version detection + CVE check
    cve_results = None
    if version_detect:
        console.print("[bold blue]Detecting HAProxy version...[/]")
        try:
            from .version_detect import detect_version
            version = detect_version(
                socket_path=ctx.obj.get("haproxy_socket"),
                binary_path=ctx.obj.get("haproxy_bin"),
                stats_url=ctx.obj.get("stats_url"),
            )
            if version:
                console.print(f"  Detected version: {version}")
                console.print("[bold blue]Checking CVEs...[/]")
                from .cve_checker import check_cves
                cve_results = check_cves(version, ctx.obj.get("nvd_api_key"))
                if cve_results.error:
                    console.print(f"[yellow]CVE check warning:[/] {cve_results.error}")
                else:
                    console.print(
                        f"  Found {len(cve_results.cves)} CVE(s) "
                        f"(C:{cve_results.critical_count} H:{cve_results.high_count} "
                        f"M:{cve_results.medium_count} L:{cve_results.low_count})"
                    )
            else:
                console.print("[yellow]Could not detect HAProxy version[/]")
        except Exception as exc:
            console.print(f"[yellow]Version detection error:[/] {exc}")

    # Run audit
    if tier:
        console.print(f"[bold blue]Running security audit...[/] (tier: [cyan]{tier}[/])")
    else:
        console.print("[bold blue]Running security audit...[/]")
    result = run_audit(
        config=config,
        baseline_path=ctx.obj.get("baseline"),
        scan_results=scan_results,
        cve_results=cve_results,
        tier=tier,
    )

    # Display results
    _display_results(result)

    # Generate HTML report
    if output:
        console.print(f"\n[bold blue]Generating report:[/] {output}")
        try:
            from .report import generate_report
            generate_report(config, result, output)
            console.print(f"[bold green]Report saved to {output}[/]")
        except Exception as exc:
            console.print(f"[bold red]Report generation error:[/] {exc}")
            sys.exit(1)


@cli.command()
@click.argument("target", nargs=-1, required=True)
def scan(target):
    """Run a standalone TLS scan against host:port target(s)."""
    from .scanner import scan_targets

    console.print(f"[bold blue]Scanning {len(target)} target(s)...[/]")
    results = scan_targets(list(target))

    for sr in results:
        if sr.error:
            console.print(f"[red]{sr.target}:{sr.port} — Error: {sr.error}[/]")
            continue

        console.print(f"\n[bold]{sr.target}:{sr.port}[/]")
        console.print(f"  Accepted protocols: {', '.join(sr.accepted_protocols) or 'none'}")
        console.print(f"  Rejected protocols: {', '.join(sr.rejected_protocols) or 'none'}")

        if sr.cert_info:
            ci = sr.cert_info
            console.print(f"  Certificate: {ci.subject}")
            console.print(f"    Issuer: {ci.issuer}")
            console.print(f"    Valid: {ci.not_before} — {ci.not_after}")
            console.print(f"    Key size: {ci.key_size} bits")
            if ci.is_expired:
                console.print("    [red]EXPIRED[/]")
            if ci.is_self_signed:
                console.print("    [yellow]Self-signed[/]")

        for proto, ciphers in sr.accepted_ciphers.items():
            console.print(f"  {proto} ciphers: {', '.join(ciphers[:5])}"
                          + (f" (+{len(ciphers) - 5} more)" if len(ciphers) > 5 else ""))

        vuln_found = [v for v, is_vuln in sr.vulnerabilities.items() if is_vuln]
        if vuln_found:
            console.print(f"  [red]Vulnerabilities: {', '.join(vuln_found)}[/]")
        else:
            console.print("  [green]No TLS vulnerabilities detected[/]")


@cli.command()
@click.argument("config_path", type=click.Path(exists=True))
@click.option("-o", "--output", type=click.Path(), required=True,
              help="Output HTML file path.")
@click.pass_context
def graph(ctx, config_path, output):
    """Generate a standalone network topology graph."""
    from .parser import parse_file
    from .visualizer import export_topology_html

    config = parse_file(config_path)
    export_topology_html(config, output)
    console.print(f"[bold green]Topology graph saved to {output}[/]")


@cli.command()
@click.argument("config_path", type=click.Path(exists=True))
@click.pass_context
def score(ctx, config_path):
    """Quick score output for a HAProxy configuration."""
    from .parser import parse_file
    from .framework.engine import run_audit

    config = parse_file(config_path)
    result = run_audit(config, baseline_path=ctx.obj.get("baseline"))
    _display_score_summary(result)


@cli.command("list-checks")
@click.pass_context
def list_checks(ctx):
    """List all checks defined in the baseline."""
    from .framework.baseline import load_baseline, get_checks

    baseline = load_baseline(ctx.obj.get("baseline"))
    checks = get_checks(baseline)

    table = Table(title="HAPR Baseline Checks", show_lines=True)
    table.add_column("ID", style="cyan", width=16)
    table.add_column("Title", width=45)
    table.add_column("Category", width=16)
    table.add_column("Severity", width=10)
    table.add_column("Requires", width=10)

    for check in checks:
        sev = check.get("severity", "info")
        sev_style = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "dim",
            "info": "dim blue",
        }.get(sev, "")

        table.add_row(
            check.get("id", ""),
            check.get("title", ""),
            check.get("category", ""),
            Text(sev, style=sev_style),
            check.get("requires", "—"),
        )

    console.print(table)
    console.print(f"\nTotal: {len(checks)} checks")


@cli.command("version-check")
@click.argument("version")
@click.pass_context
def version_check(ctx, version):
    """Check known CVEs for a specific HAProxy version."""
    from .cve_checker import check_cves

    console.print(f"[bold blue]Checking CVEs for HAProxy {version}...[/]")
    result = check_cves(version, ctx.obj.get("nvd_api_key"))

    if result.error:
        console.print(f"[yellow]Warning:[/] {result.error}")

    if not result.cves:
        console.print(f"[bold green]No known CVEs found for HAProxy {version}[/]")
        return

    table = Table(title=f"CVEs for HAProxy {version}")
    table.add_column("CVE ID", style="cyan")
    table.add_column("CVSS", width=6)
    table.add_column("Severity", width=10)
    table.add_column("Published", width=12)
    table.add_column("Description", width=60)

    for cve in result.cves:
        sev_style = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "dim",
        }.get(cve.severity, "")

        desc = cve.description[:80] + "..." if len(cve.description) > 80 else cve.description
        table.add_row(
            cve.cve_id,
            str(cve.cvss_score),
            Text(cve.severity, style=sev_style),
            cve.published_date[:10] if cve.published_date else "",
            desc,
        )

    console.print(table)
    console.print(
        f"\nTotal: {len(result.cves)} CVE(s) — "
        f"Critical: {result.critical_count}, High: {result.high_count}, "
        f"Medium: {result.medium_count}, Low: {result.low_count}"
    )


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def _display_results(result):
    """Display audit results in the terminal."""
    from .models import Status

    _display_score_summary(result)

    # Category breakdown
    console.print("\n[bold]Category Scores:[/]")
    for cat_id, cs in sorted(result.category_scores.items(), key=lambda x: x[1].percentage):
        bar = _score_bar(cs.percentage)
        console.print(
            f"  {cs.category_name:<30} {bar} {cs.percentage:5.1f}% "
            f"({cs.pass_count}P/{cs.fail_count}F/{cs.partial_count}W/{cs.na_count}N)"
        )

    # Failed findings
    failed = [f for f in result.findings if f.status in (Status.FAIL, Status.PARTIAL)]
    if failed:
        console.print(f"\n[bold red]Findings ({len(failed)}):[/]")
        table = Table(show_lines=False, padding=(0, 1))
        table.add_column("ID", style="cyan", width=16)
        table.add_column("Sev", width=9)
        table.add_column("Status", width=8)
        table.add_column("Message", width=60)

        for f in sorted(failed, key=lambda x: x.severity.weight, reverse=True):
            sev_style = {
                "critical": "bold red",
                "high": "red",
                "medium": "yellow",
                "low": "dim",
            }.get(f.severity.value, "")
            status_style = "red" if f.status == Status.FAIL else "yellow"

            table.add_row(
                f.check_id,
                Text(f.severity.value, style=sev_style),
                Text(f.status.value, style=status_style),
                f.message[:80],
            )

        console.print(table)


def _display_score_summary(result):
    """Display the grade and overall score."""
    grade_colors = {"A": "green", "B": "blue", "C": "yellow", "D": "red", "F": "bold red"}
    color = grade_colors.get(result.letter_grade, "white")
    from .models import Status

    total = len(result.findings)
    passed = sum(1 for f in result.findings if f.status == Status.PASS)
    failed = sum(1 for f in result.findings if f.status == Status.FAIL)
    partial = sum(1 for f in result.findings if f.status == Status.PARTIAL)

    panel = Panel(
        f"[{color} bold]{result.letter_grade}[/]  {result.overall_score:.1f}%\n"
        f"Checks: {total} total | {passed} passed | {failed} failed | {partial} partial",
        title="[bold]HAPR Security Score[/]",
        border_style=color,
        width=60,
    )
    console.print(panel)


def _score_bar(score: float, width: int = 20) -> str:
    """Return a colored text bar representing a score."""
    filled = int(score / 100 * width)
    empty = width - filled
    if score >= 80:
        color = "green"
    elif score >= 60:
        color = "yellow"
    else:
        color = "red"
    return f"[{color}]{'█' * filled}[/]{'░' * empty}"
