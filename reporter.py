"""
PQC Readiness Report Generator.

Consolidates scan results from TLS and cloud analysis into a formatted
readiness report with risk scores and migration recommendations.
"""

import json
from dataclasses import asdict
from datetime import datetime
from typing import Optional

from .crypto_classify import (
    AlgorithmProfile,
    QuantumThreatLevel,
    compute_risk_score,
    get_overall_readiness,
)
from .tls_scanner import TLSScanResult
from .cloud_analyzer import CloudScanResult, CryptoFinding


def _threat_icon(level: QuantumThreatLevel) -> str:
    """Get a terminal-friendly icon for threat level."""
    icons = {
        QuantumThreatLevel.CRITICAL: "🔴",
        QuantumThreatLevel.HIGH: "🟠",
        QuantumThreatLevel.MEDIUM: "🟡",
        QuantumThreatLevel.LOW: "🟢",
        QuantumThreatLevel.SAFE: "✅",
    }
    return icons.get(level, "⚪")


def generate_text_report(
    tls_results: Optional[list[TLSScanResult]] = None,
    cloud_result: Optional[CloudScanResult] = None,
) -> str:
    """Generate a human-readable text report of PQC readiness.

    Args:
        tls_results: List of TLS scan results.
        cloud_result: Cloud infrastructure scan result.

    Returns:
        Formatted text report string.
    """
    lines = []
    all_profiles = []

    lines.append("=" * 70)
    lines.append("  POST-QUANTUM CRYPTOGRAPHY READINESS REPORT")
    lines.append(f"  Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append("=" * 70)
    lines.append("")

    # --- TLS Section ---
    if tls_results:
        lines.append("─" * 70)
        lines.append("  WEBSITE TLS ANALYSIS")
        lines.append("─" * 70)
        lines.append("")

        for result in tls_results:
            lines.append(f"  Target: {result.host}:{result.port}")
            lines.append(f"  TLS Version: {result.tls_version or 'N/A'}")
            lines.append(f"  Cipher Suite: {result.cipher_suite or 'N/A'}")

            if result.certificate:
                cert = result.certificate
                lines.append(f"  Certificate Subject: {cert.subject}")
                lines.append(f"  Public Key: {cert.public_key_algorithm} ({cert.public_key_size}-bit)")
                lines.append(f"  Signature Algorithm: {cert.signature_algorithm}")
                lines.append(f"  Valid Until: {cert.not_valid_after.strftime('%Y-%m-%d')}")

            lines.append("")
            lines.append("  Algorithms Detected:")

            if result.algorithm_profiles:
                for profile in result.algorithm_profiles:
                    icon = _threat_icon(profile.threat_level)
                    lines.append(
                        f"    {icon} {profile.name:20s} "
                        f"Risk: {profile.risk_score:.1f}/10  "
                        f"[{profile.threat_level.value.upper()}]"
                    )
                    lines.append(f"       └─ {profile.recommendation}")
                all_profiles.extend(result.algorithm_profiles)
            else:
                lines.append("    No algorithms identified")

            if result.errors:
                lines.append("")
                lines.append("  ⚠️  Scan Warnings:")
                for err in result.errors:
                    lines.append(f"    - {err}")

            lines.append(f"\n  Site Risk Score: {result.risk_score:.1f}/10 — {result.readiness_level}")
            lines.append("")

    # --- Cloud Section ---
    if cloud_result:
        lines.append("─" * 70)
        lines.append("  CLOUD INFRASTRUCTURE ANALYSIS")
        lines.append("─" * 70)
        lines.append("")
        lines.append(f"  Directory: {cloud_result.scan_directory}")
        lines.append(f"  Files Scanned: {cloud_result.files_scanned}")
        lines.append(f"  Crypto Findings: {len(cloud_result.findings)}")
        lines.append("")

        if cloud_result.findings:
            lines.append("  Findings:")
            for finding in cloud_result.findings:
                if finding.profile:
                    icon = _threat_icon(finding.profile.threat_level)
                    lines.append(
                        f"    {icon} {finding.profile.name:20s} "
                        f"in {finding.resource_type}/{finding.resource_name}"
                    )
                    lines.append(f"       File: {finding.file_path}:{finding.line_number}")
                    lines.append(f"       └─ {finding.profile.recommendation}")
                    all_profiles.append(finding.profile)
                else:
                    lines.append(f"    ⚪ {finding.algorithm:20s} (unclassified)")
                    lines.append(f"       File: {finding.file_path}:{finding.line_number}")

            lines.append(
                f"\n  Cloud Risk Score: {cloud_result.risk_score:.1f}/10 — {cloud_result.readiness_level}"
            )
        else:
            lines.append("  No cryptographic configurations detected in scanned files.")

        if cloud_result.errors:
            lines.append("")
            lines.append("  ⚠️  Scan Errors:")
            for err in cloud_result.errors:
                lines.append(f"    - {err}")

        lines.append("")

    # --- Overall Summary ---
    lines.append("─" * 70)
    lines.append("  OVERALL PQC READINESS SUMMARY")
    lines.append("─" * 70)
    lines.append("")

    if all_profiles:
        overall_risk = compute_risk_score(all_profiles)
        overall_readiness = get_overall_readiness(overall_risk)

        lines.append(f"  Overall Risk Score: {overall_risk:.1f} / 10.0")
        lines.append(f"  Readiness Level: {overall_readiness}")
        lines.append("")

        # Count by threat level
        critical_count = sum(1 for p in all_profiles if p.threat_level == QuantumThreatLevel.CRITICAL)
        high_count = sum(1 for p in all_profiles if p.threat_level == QuantumThreatLevel.HIGH)
        medium_count = sum(1 for p in all_profiles if p.threat_level == QuantumThreatLevel.MEDIUM)
        low_count = sum(1 for p in all_profiles if p.threat_level == QuantumThreatLevel.LOW)
        safe_count = sum(1 for p in all_profiles if p.threat_level == QuantumThreatLevel.SAFE)

        lines.append("  Threat Breakdown:")
        lines.append(f"    🔴 Critical: {critical_count}")
        lines.append(f"    🟠 High:     {high_count}")
        lines.append(f"    🟡 Medium:   {medium_count}")
        lines.append(f"    🟢 Low:      {low_count}")
        lines.append(f"    ✅ Safe:     {safe_count}")
        lines.append("")

        # Migration recommendations
        immediate = set()
        planned = set()
        for p in all_profiles:
            if p.migration_priority == "immediate" and p.nist_replacement:
                immediate.add(f"{p.name} → {p.nist_replacement}")
            elif p.migration_priority == "planned" and p.nist_replacement:
                planned.add(f"{p.name} → {p.nist_replacement}")

        if immediate:
            lines.append("  🚨 Immediate Migration Required:")
            for rec in sorted(immediate):
                lines.append(f"    • {rec}")
            lines.append("")

        if planned:
            lines.append("  📋 Planned Migration Recommended:")
            for rec in sorted(planned):
                lines.append(f"    • {rec}")
            lines.append("")

    else:
        lines.append("  No cryptographic algorithms were detected for analysis.")
        lines.append("")

    lines.append("=" * 70)
    lines.append("  End of Report")
    lines.append("=" * 70)

    return "\n".join(lines)


def generate_json_report(
    tls_results: Optional[list[TLSScanResult]] = None,
    cloud_result: Optional[CloudScanResult] = None,
) -> str:
    """Generate a machine-readable JSON report.

    Args:
        tls_results: List of TLS scan results.
        cloud_result: Cloud infrastructure scan result.

    Returns:
        JSON string of the report.
    """
    all_profiles = []

    report = {
        "report_type": "pqc_readiness_assessment",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "version": "0.1.0",
        "tls_results": [],
        "cloud_result": None,
        "summary": {},
    }

    if tls_results:
        for result in tls_results:
            tls_entry = {
                "host": result.host,
                "port": result.port,
                "tls_version": result.tls_version,
                "cipher_suite": result.cipher_suite,
                "risk_score": result.risk_score,
                "readiness_level": result.readiness_level,
                "algorithms": [
                    {
                        "name": p.name,
                        "category": p.category,
                        "threat_level": p.threat_level.value,
                        "risk_score": p.risk_score,
                        "recommendation": p.recommendation,
                        "nist_replacement": p.nist_replacement,
                    }
                    for p in result.algorithm_profiles
                ],
                "errors": result.errors,
            }
            if result.certificate:
                tls_entry["certificate"] = {
                    "subject": result.certificate.subject,
                    "issuer": result.certificate.issuer,
                    "public_key_algorithm": result.certificate.public_key_algorithm,
                    "public_key_size": result.certificate.public_key_size,
                    "signature_algorithm": result.certificate.signature_algorithm,
                    "valid_until": result.certificate.not_valid_after.isoformat(),
                }
            report["tls_results"].append(tls_entry)
            all_profiles.extend(result.algorithm_profiles)

    if cloud_result:
        report["cloud_result"] = {
            "directory": cloud_result.scan_directory,
            "files_scanned": cloud_result.files_scanned,
            "risk_score": cloud_result.risk_score,
            "readiness_level": cloud_result.readiness_level,
            "findings": [
                {
                    "file": f.file_path,
                    "line": f.line_number,
                    "resource_type": f.resource_type,
                    "resource_name": f.resource_name,
                    "algorithm": f.algorithm,
                    "threat_level": f.profile.threat_level.value if f.profile else "unknown",
                    "risk_score": f.profile.risk_score if f.profile else 0,
                    "recommendation": f.profile.recommendation if f.profile else "",
                }
                for f in cloud_result.findings
            ],
            "errors": cloud_result.errors,
        }
        all_profiles.extend([f.profile for f in cloud_result.findings if f.profile])

    # Overall summary
    if all_profiles:
        overall_risk = compute_risk_score(all_profiles)
        report["summary"] = {
            "overall_risk_score": overall_risk,
            "readiness_level": get_overall_readiness(overall_risk),
            "total_algorithms_found": len(all_profiles),
            "critical_count": sum(1 for p in all_profiles if p.threat_level == QuantumThreatLevel.CRITICAL),
            "high_count": sum(1 for p in all_profiles if p.threat_level == QuantumThreatLevel.HIGH),
            "medium_count": sum(1 for p in all_profiles if p.threat_level == QuantumThreatLevel.MEDIUM),
            "low_count": sum(1 for p in all_profiles if p.threat_level == QuantumThreatLevel.LOW),
            "safe_count": sum(1 for p in all_profiles if p.threat_level == QuantumThreatLevel.SAFE),
        }

    return json.dumps(report, indent=2, default=str)
