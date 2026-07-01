"""
CLI entry point for PQC Readiness Scanner.

Usage:
    python -m pqc_scanner scan-url <url>
    python -m pqc_scanner scan-cloud <directory>
    python -m pqc_scanner report --url <url> --cloud-dir <directory>
"""

import sys
from urllib.parse import urlparse

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .tls_scanner import scan_tls, scan_multiple
from .cloud_analyzer import scan_cloud_configs
from .crypto_classify import QuantumThreatLevel
from .reporter import generate_text_report, generate_json_report
from .attestation import (
    Issuer,
    ReadinessCredential,
    verify_credential,
    build_asset_records,
)
from .verification import (
    Verdict,
    run_verification,
)
from .tls_probe import probe_negotiation_space, get_trust_chain
from .datapath import DataPath, verify_path

console = Console()


def _threat_style(level: QuantumThreatLevel) -> str:
    """Map threat level to rich style color."""
    styles = {
        QuantumThreatLevel.CRITICAL: "bold red",
        QuantumThreatLevel.HIGH: "bold yellow",
        QuantumThreatLevel.MEDIUM: "yellow",
        QuantumThreatLevel.LOW: "green",
        QuantumThreatLevel.SAFE: "bold green",
    }
    return styles.get(level, "white")


@click.group()
@click.version_option(version="0.1.0", prog_name="pqc-scanner")
def cli():
    """PQC Readiness Scanner - Assess post-quantum cryptography readiness."""
    pass


@cli.command("scan-url")
@click.argument("url")
@click.option("--port", default=443, help="Target port (default: 443)")
@click.option("--json-output", is_flag=True, help="Output as JSON")
def scan_url(url: str, port: int, json_output: bool):
    """Scan a website's TLS configuration for PQC readiness."""
    # Extract hostname from URL
    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = parsed.hostname or url

    console.print(f"\n[bold]Scanning TLS configuration for [cyan]{host}:{port}[/cyan]...[/bold]\n")

    result = scan_tls(host, port)

    if json_output:
        report = generate_json_report(tls_results=[result])
        console.print(report)
        return

    # Rich formatted output
    if result.errors:
        for err in result.errors:
            console.print(f"  [yellow]⚠ {err}[/yellow]")
        console.print()

    # Connection info
    info_table = Table(show_header=False, box=None, padding=(0, 2))
    info_table.add_column("Key", style="dim")
    info_table.add_column("Value")
    info_table.add_row("Host", f"{result.host}:{result.port}")
    info_table.add_row("TLS Version", result.tls_version or "N/A")
    info_table.add_row("Cipher Suite", result.cipher_suite or "N/A")

    if result.certificate:
        cert = result.certificate
        info_table.add_row("Subject", cert.subject)
        info_table.add_row("Public Key", f"{cert.public_key_algorithm} ({cert.public_key_size}-bit)")
        info_table.add_row("Signature", cert.signature_algorithm)
        info_table.add_row("Expires", cert.not_valid_after.strftime("%Y-%m-%d"))

    console.print(Panel(info_table, title="Connection Details", border_style="blue"))
    console.print()

    # Algorithm analysis
    if result.algorithm_profiles:
        algo_table = Table(title="Algorithm Analysis")
        algo_table.add_column("Algorithm", style="bold")
        algo_table.add_column("Category")
        algo_table.add_column("Threat Level")
        algo_table.add_column("Risk", justify="center")
        algo_table.add_column("Recommendation")

        for profile in result.algorithm_profiles:
            style = _threat_style(profile.threat_level)
            algo_table.add_row(
                profile.name,
                profile.category,
                Text(profile.threat_level.value.upper(), style=style),
                f"{profile.risk_score:.1f}",
                profile.recommendation[:60],
            )

        console.print(algo_table)
        console.print()

    # Risk summary
    risk_style = "bold red" if result.risk_score > 7 else "bold yellow" if result.risk_score > 4 else "bold green"
    console.print(
        Panel(
            f"[{risk_style}]Risk Score: {result.risk_score:.1f}/10[/{risk_style}]\n"
            f"Readiness: {result.readiness_level}",
            title="PQC Readiness",
            border_style="red" if result.risk_score > 7 else "yellow" if result.risk_score > 4 else "green",
        )
    )


@cli.command("scan-cloud")
@click.argument("directory")
@click.option("--json-output", is_flag=True, help="Output as JSON")
def scan_cloud(directory: str, json_output: bool):
    """Analyze cloud infrastructure configs for PQC readiness."""
    console.print(f"\n[bold]Scanning cloud configs in [cyan]{directory}[/cyan]...[/bold]\n")

    result = scan_cloud_configs(directory)

    if json_output:
        report = generate_json_report(cloud_result=result)
        console.print(report)
        return

    # Summary
    console.print(f"  Files scanned: {result.files_scanned}")
    console.print(f"  Findings: {len(result.findings)}")
    console.print()

    if result.findings:
        findings_table = Table(title="Cryptographic Findings")
        findings_table.add_column("Algorithm", style="bold")
        findings_table.add_column("Resource")
        findings_table.add_column("File")
        findings_table.add_column("Threat")
        findings_table.add_column("Risk", justify="center")

        for finding in result.findings:
            if finding.profile:
                style = _threat_style(finding.profile.threat_level)
                findings_table.add_row(
                    finding.profile.name,
                    f"{finding.resource_type}/{finding.resource_name}",
                    f"{finding.file_path}:{finding.line_number}",
                    Text(finding.profile.threat_level.value.upper(), style=style),
                    f"{finding.profile.risk_score:.1f}",
                )

        console.print(findings_table)
        console.print()

    if result.errors:
        for err in result.errors:
            console.print(f"  [yellow]⚠ {err}[/yellow]")
        console.print()

    # Risk summary
    risk_style = "bold red" if result.risk_score > 7 else "bold yellow" if result.risk_score > 4 else "bold green"
    console.print(
        Panel(
            f"[{risk_style}]Risk Score: {result.risk_score:.1f}/10[/{risk_style}]\n"
            f"Readiness: {result.readiness_level}",
            title="Cloud PQC Readiness",
            border_style="red" if result.risk_score > 7 else "yellow" if result.risk_score > 4 else "green",
        )
    )


@cli.command("report")
@click.option("--url", multiple=True, help="URLs to scan (can specify multiple)")
@click.option("--cloud-dir", default=None, help="Cloud config directory to analyze")
@click.option("--format", "output_format", type=click.Choice(["text", "json"]), default="text")
@click.option("--output", "-o", default=None, help="Output file path (default: stdout)")
def report(url: tuple, cloud_dir: str, output_format: str, output: str):
    """Generate a comprehensive PQC readiness report."""
    tls_results = []
    cloud_result = None

    if not url and not cloud_dir:
        console.print("[red]Error: Provide at least --url or --cloud-dir[/red]")
        sys.exit(1)

    # Scan URLs
    if url:
        console.print("[bold]Scanning websites...[/bold]")
        for u in url:
            parsed = urlparse(u if "://" in u else f"https://{u}")
            host = parsed.hostname or u
            console.print(f"  → {host}")
            result = scan_tls(host)
            tls_results.append(result)

    # Scan cloud configs
    if cloud_dir:
        console.print(f"[bold]Scanning cloud configs in {cloud_dir}...[/bold]")
        cloud_result = scan_cloud_configs(cloud_dir)

    # Generate report
    console.print("[bold]Generating report...[/bold]\n")

    if output_format == "json":
        report_content = generate_json_report(tls_results=tls_results or None, cloud_result=cloud_result)
    else:
        report_content = generate_text_report(tls_results=tls_results or None, cloud_result=cloud_result)

    if output:
        with open(output, "w") as f:
            f.write(report_content)
        console.print(f"[green]Report saved to {output}[/green]")
    else:
        console.print(report_content)


@cli.command("attest")
@click.option("--url", multiple=True, help="URLs to include in the attestation")
@click.option("--cloud-dir", default=None, help="Cloud config directory to include")
@click.option("--subject", required=True, help="Entity being attested (e.g. your org name)")
@click.option("--issuer", "issuer_name", default="Self-Assessment", help="Issuer name")
@click.option("--output", "-o", default="readiness.credential.json", help="Output credential file")
def attest(url: tuple, cloud_dir: str, subject: str, issuer_name: str, output: str):
    """Seal scan results into a privacy-preserving readiness credential.

    Produces a signed badge that proves quantum-readiness claims WITHOUT
    exposing the underlying hosts, configs, or weak spots.
    """
    tls_results = []
    cloud_result = None

    if not url and not cloud_dir:
        console.print("[red]Error: Provide at least --url or --cloud-dir[/red]")
        sys.exit(1)

    if url:
        console.print("[bold]Scanning websites...[/bold]")
        for u in url:
            parsed = urlparse(u if "://" in u else f"https://{u}")
            host = parsed.hostname or u
            console.print(f"  → {host}")
            tls_results.append(scan_tls(host))

    if cloud_dir:
        console.print(f"[bold]Scanning cloud configs in {cloud_dir}...[/bold]")
        cloud_result = scan_cloud_configs(cloud_dir)

    # Build the secret per-asset records and seal them
    records, scores = build_asset_records(tls_results or None, cloud_result)

    if not records:
        console.print("[yellow]No assets found to attest.[/yellow]")
        sys.exit(1)

    # Determine overall readiness from the worst asset
    from .crypto_classify import get_overall_readiness, compute_risk_score
    all_profiles = []
    for r in tls_results:
        all_profiles.extend(r.algorithm_profiles)
    if cloud_result:
        all_profiles.extend([f.profile for f in cloud_result.findings if f.profile])
    overall_risk = compute_risk_score(all_profiles)
    readiness = get_overall_readiness(overall_risk)

    issuer = Issuer(name=issuer_name)
    credential = issuer.issue(
        subject=subject,
        asset_records=records,
        risk_scores=scores,
        readiness_level=readiness,
    )

    with open(output, "w") as f:
        f.write(credential.to_json())

    console.print()
    console.print(
        Panel(
            f"[bold]Subject:[/bold] {credential.subject}\n"
            f"[bold]Issuer:[/bold] {credential.issuer}\n"
            f"[bold]Assets assessed:[/bold] {credential.total_assets} "
            f"(committed, not revealed)\n"
            f"[bold]Quantum-safe:[/bold] {credential.quantum_safe_assets}/{credential.total_assets}\n"
            f"[bold]All quantum-safe:[/bold] {'✅ yes' if credential.all_quantum_safe else '❌ no'}\n"
            f"[bold]Readiness:[/bold] {credential.readiness_level}\n"
            f"[bold]Commitment root:[/bold] {credential.commitment_root[:32]}…\n"
            f"[bold]Signed:[/bold] ✅",
            title="🔐 Readiness Credential Issued",
            border_style="green",
        )
    )
    console.print(f"\n[green]Credential saved to {output}[/green]")
    console.print(
        "[dim]This file proves your readiness claims. It contains NO host names, "
        "configs, or weakness locations.[/dim]"
    )


@cli.command("verify")
@click.argument("credential_file")
@click.option("--issuer-key", default=None, help="Pinned issuer public key (base64)")
def verify(credential_file: str, issuer_key: str):
    """Verify a readiness credential as a third party.

    Confirms the badge is authentic and shows ONLY the aggregate claims.
    The verifier never sees the underlying infrastructure data.
    """
    try:
        with open(credential_file, "r") as f:
            credential = ReadinessCredential.from_json(f.read())
    except (IOError, OSError) as e:
        console.print(f"[red]Could not read credential: {e}[/red]")
        sys.exit(1)

    result = verify_credential(credential, expected_issuer_pubkey=issuer_key)

    console.print()
    for msg in result.messages:
        icon = "✓" if result.signature_valid else "✗"
        style = "green" if result.signature_valid else "red"
        console.print(f"  [{style}]{icon} {msg}[/{style}]")
    console.print()

    if result.trusted:
        claims = result.claims
        console.print(
            Panel(
                f"[bold green]✓ VERIFIED[/bold green]\n\n"
                f"[bold]Subject:[/bold] {claims['subject']}\n"
                f"[bold]Issuer:[/bold] {claims['issuer']}\n"
                f"[bold]Issued:[/bold] {claims['issued_at']}\n"
                f"[bold]Assets assessed:[/bold] {claims['total_assets']}\n"
                f"[bold]Quantum-safe:[/bold] {claims['quantum_safe_assets']}/{claims['total_assets']}\n"
                f"[bold]All quantum-safe:[/bold] "
                f"{'✅ yes' if claims['all_quantum_safe'] else '❌ no'}\n"
                f"[bold]Readiness:[/bold] {claims['readiness_level']}",
                title="Attestation Result",
                border_style="green",
            )
        )
        console.print(
            "\n[dim]Verified authentic. Notice: no host names, IPs, configs, or "
            "weakness locations were disclosed — only the signed aggregate claims.[/dim]"
        )
    else:
        console.print(
            Panel(
                "[bold red]✗ NOT VERIFIED[/bold red]\nThis credential could not be "
                "authenticated and should not be trusted.",
                title="Attestation Result",
                border_style="red",
            )
        )
        sys.exit(2)


@cli.command("verify-system")
@click.option("--url", default=None, help="Endpoint URL to verify (host to probe)")
@click.option("--data-path", "data_path_file", default=None,
              help="JSON file declaring the end-to-end data path to verify (PQV-DP)")
@click.option("--subject", default="Target System", help="Name of the system being verified")
@click.option("--no-legacy", is_flag=True, help="Skip probing legacy TLS 1.0/1.1 versions")
@click.option("--json-output", is_flag=True, help="Output verdicts as JSON")
def verify_system_cmd(url: str, data_path_file: str, subject: str, no_legacy: bool, json_output: bool):
    """Verify whether a system is actually quantum-safe (not just scan it).

    Verifies emergent system properties a scanner cannot answer:
      PQV-DG  no quantum-vulnerable downgrade path (negotiation floor)
      PQV-CH  the entire certificate trust chain is quantum-safe
      PQV-DP  the end-to-end data path's weakest hop is quantum-safe

    Each yields verified / partial / not verified / insufficient evidence,
    with plain-language reasoning and a next step.
    """
    if not url and not data_path_file:
        console.print("[red]Error: Provide at least --url or --data-path[/red]")
        sys.exit(1)

    negotiation_space = None
    trust_chain = None
    path_result = None

    if url:
        parsed = urlparse(url if "://" in url else f"https://{url}")
        host = parsed.hostname or url
        console.print(f"[bold]Probing negotiation space of [cyan]{host}[/cyan]...[/bold]")
        negotiation_space = probe_negotiation_space(host, include_legacy=not no_legacy)
        console.print(f"[bold]Retrieving certificate chain...[/bold]")
        trust_chain = get_trust_chain(host)

    if data_path_file:
        console.print(f"[bold]Verifying data path from [cyan]{data_path_file}[/cyan]...[/bold]")
        try:
            path = DataPath.from_json_file(data_path_file)
            path_result = verify_path(path)
        except (IOError, OSError, ValueError) as e:
            console.print(f"[yellow]Could not load data path: {e}[/yellow]")

    report = run_verification(
        subject,
        negotiation_space=negotiation_space,
        trust_chain=trust_chain,
        path_result=path_result,
    )

    if json_output:
        import json as _json
        out = {
            "subject": report.subject,
            "overall_verdict": report.overall_verdict.value,
            "summary": report.summary,
            "checks": [
                {
                    "control_id": c.control_id,
                    "title": c.title,
                    "verdict": c.verdict.value,
                    "rationale": c.rationale,
                    "remediation": c.remediation,
                    "evidence_used": c.evidence_used,
                }
                for c in report.checks
            ],
        }
        console.print(_json.dumps(out, indent=2))
        return

    console.print()
    table = Table(title=f"PQCVerify — Verification Result for {report.subject}")
    table.add_column("Property", style="bold", no_wrap=True)
    table.add_column("Verdict")
    table.add_column("Why / Next step")

    verdict_styles = {
        Verdict.VERIFIED: "green",
        Verdict.PARTIALLY_VERIFIED: "yellow",
        Verdict.NOT_VERIFIED: "red",
        Verdict.INSUFFICIENT_EVIDENCE: "dim",
    }

    for c in report.checks:
        style = verdict_styles[c.verdict]
        why = c.rationale
        if c.remediation and c.remediation != "None." and c.verdict != Verdict.VERIFIED:
            why += f"\n[dim]→ {c.remediation}[/dim]"
        table.add_row(
            f"{c.control_id}\n{c.title}",
            Text(f"{c.verdict.icon} {c.verdict.label}", style=style),
            why,
        )

    console.print(table)
    console.print()

    overall_style = verdict_styles[report.overall_verdict]
    console.print(
        Panel(
            f"[bold {overall_style}]{report.overall_verdict.icon} "
            f"{report.overall_verdict.label.upper()}[/bold {overall_style}]\n\n"
            f"{report.summary}",
            title="Overall Verdict",
            border_style=overall_style if overall_style != "dim" else "white",
        )
    )


if __name__ == "__main__":
    cli()
