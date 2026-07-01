"""
Cloud Infrastructure Config Analyzer for post-quantum readiness.

Parses Terraform (.tf, .tf.json) and CloudFormation (YAML/JSON) configurations
to identify cryptographic resources and assess their quantum vulnerability.
"""

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

from .crypto_classify import (
    AlgorithmProfile,
    classify_algorithm,
    compute_risk_score,
    get_overall_readiness,
    QuantumThreatLevel,
    ALGORITHM_DB,
)


@dataclass
class CryptoFinding:
    """A cryptographic configuration finding in cloud infrastructure."""

    file_path: str
    resource_type: str
    resource_name: str
    algorithm: str
    context: str  # surrounding config context
    profile: Optional[AlgorithmProfile] = None
    line_number: int = 0


@dataclass
class CloudScanResult:
    """Complete result of scanning cloud infrastructure configs."""

    scan_directory: str
    files_scanned: int
    findings: list[CryptoFinding] = field(default_factory=list)
    risk_score: float = 0.0
    readiness_level: str = ""
    errors: list[str] = field(default_factory=list)

    def __post_init__(self):
        if self.findings:
            profiles = [f.profile for f in self.findings if f.profile]
            self.risk_score = compute_risk_score(profiles)
            self.readiness_level = get_overall_readiness(self.risk_score)


# Patterns that indicate cryptographic algorithm usage in cloud configs
CRYPTO_PATTERNS = {
    # Key/certificate algorithms
    r"\brsa[_-]?(\d{4})?\b": "rsa",
    r"\becdsa\b": "ecdsa",
    r"\bed25519\b": "ed25519",
    r"\becdh\b": "ecdh",
    r"\bdsa\b": "dsa",
    # Symmetric encryption
    r"\baes[_-]?128\b": "aes-128",
    r"\baes[_-]?256\b": "aes-256",
    r"\b3des\b": "3des",
    r"\bdes[_-]ede3\b": "3des",
    # Hashing
    r"\bsha[_-]?1\b": "sha-1",
    r"\bsha[_-]?256\b": "sha-256",
    r"\bsha[_-]?384\b": "sha-384",
    r"\bmd5\b": "md5",
}

# Terraform resource types that commonly involve cryptography
TERRAFORM_CRYPTO_RESOURCES = {
    "aws_acm_certificate",
    "aws_kms_key",
    "aws_kms_alias",
    "aws_iam_server_certificate",
    "aws_lb_listener",
    "aws_alb_listener",
    "aws_cloudfront_distribution",
    "aws_elasticsearch_domain",
    "aws_opensearch_domain",
    "aws_rds_cluster",
    "aws_db_instance",
    "aws_s3_bucket",
    "aws_s3_bucket_server_side_encryption_configuration",
    "aws_vpn_gateway",
    "aws_customer_gateway",
    "aws_iot_certificate",
    "tls_private_key",
    "tls_cert_request",
    "tls_self_signed_cert",
    "azurerm_key_vault_key",
    "azurerm_key_vault_certificate",
    "google_kms_crypto_key",
    "google_kms_key_ring",
}

# CloudFormation resource types involving cryptography
CLOUDFORMATION_CRYPTO_RESOURCES = {
    "AWS::ACM::Certificate",
    "AWS::KMS::Key",
    "AWS::KMS::Alias",
    "AWS::ElasticLoadBalancingV2::Listener",
    "AWS::CloudFront::Distribution",
    "AWS::RDS::DBCluster",
    "AWS::RDS::DBInstance",
    "AWS::S3::Bucket",
}


def _scan_text_for_crypto(
    text: str, file_path: str, resource_type: str = "unknown", resource_name: str = "unknown"
) -> list[CryptoFinding]:
    """Scan text content for cryptographic algorithm references.

    Args:
        text: Text content to scan.
        file_path: Path of the source file.
        resource_type: Type of cloud resource.
        resource_name: Name of the resource.

    Returns:
        List of CryptoFinding for each algorithm reference found.
    """
    findings = []
    lines = text.split("\n")
    seen_algos = set()

    for line_num, line in enumerate(lines, start=1):
        line_lower = line.lower()
        for pattern, algo_key in CRYPTO_PATTERNS.items():
            if re.search(pattern, line_lower):
                if algo_key not in seen_algos:
                    seen_algos.add(algo_key)
                    profile = classify_algorithm(algo_key)

                    # Get context (surrounding lines)
                    start = max(0, line_num - 2)
                    end = min(len(lines), line_num + 2)
                    context = "\n".join(lines[start:end])

                    findings.append(
                        CryptoFinding(
                            file_path=file_path,
                            resource_type=resource_type,
                            resource_name=resource_name,
                            algorithm=algo_key,
                            context=context,
                            profile=profile,
                            line_number=line_num,
                        )
                    )

    return findings


def _analyze_terraform_file(file_path: str) -> list[CryptoFinding]:
    """Analyze a Terraform file for cryptographic configurations.

    Handles both HCL (.tf) and JSON (.tf.json) formats.

    Args:
        file_path: Path to the Terraform file.

    Returns:
        List of findings.
    """
    findings = []

    try:
        with open(file_path, "r") as f:
            content = f.read()
    except (IOError, OSError) as e:
        return findings

    if file_path.endswith(".tf.json") or file_path.endswith(".json"):
        # JSON format terraform
        try:
            data = json.loads(content)
            # Look at resource blocks
            resources = data.get("resource", {})
            for resource_type, instances in resources.items():
                if resource_type in TERRAFORM_CRYPTO_RESOURCES:
                    for name, config in instances.items():
                        config_str = json.dumps(config, indent=2)
                        findings.extend(
                            _scan_text_for_crypto(config_str, file_path, resource_type, name)
                        )
        except json.JSONDecodeError:
            pass
    else:
        # HCL format - use regex-based extraction
        # Find resource blocks
        resource_pattern = r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}'
        for match in re.finditer(resource_pattern, content, re.DOTALL):
            resource_type = match.group(1)
            resource_name = match.group(2)
            block_content = match.group(3)

            if resource_type in TERRAFORM_CRYPTO_RESOURCES:
                findings.extend(
                    _scan_text_for_crypto(block_content, file_path, resource_type, resource_name)
                )

        # Also do a general scan for crypto patterns in the whole file
        general_findings = _scan_text_for_crypto(content, file_path, "terraform_config", "general")
        # Only add findings for algorithms not already found
        found_algos = {f.algorithm for f in findings}
        for f in general_findings:
            if f.algorithm not in found_algos:
                findings.append(f)

    return findings


def _analyze_cloudformation_file(file_path: str) -> list[CryptoFinding]:
    """Analyze a CloudFormation template for cryptographic configurations.

    Args:
        file_path: Path to the CloudFormation template.

    Returns:
        List of findings.
    """
    findings = []

    try:
        with open(file_path, "r") as f:
            content = f.read()
    except (IOError, OSError):
        return findings

    # Try YAML first, then JSON
    data = None
    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError:
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            # Fall back to text scanning
            return _scan_text_for_crypto(content, file_path)

    if not isinstance(data, dict):
        return findings

    # Look at Resources section
    resources = data.get("Resources", {})
    for resource_name, resource_def in resources.items():
        if not isinstance(resource_def, dict):
            continue

        resource_type = resource_def.get("Type", "")
        if resource_type in CLOUDFORMATION_CRYPTO_RESOURCES:
            # Serialize properties and scan
            properties = resource_def.get("Properties", {})
            prop_str = json.dumps(properties, indent=2, default=str)
            findings.extend(
                _scan_text_for_crypto(prop_str, file_path, resource_type, resource_name)
            )

    # General scan for any crypto references
    general_findings = _scan_text_for_crypto(content, file_path, "cloudformation", "template")
    found_algos = {f.algorithm for f in findings}
    for f in general_findings:
        if f.algorithm not in found_algos:
            findings.append(f)

    return findings


def scan_cloud_configs(directory: str) -> CloudScanResult:
    """Scan a directory of cloud infrastructure configs for PQC readiness.

    Recursively scans for Terraform and CloudFormation files, identifies
    cryptographic algorithm usage, and assesses quantum vulnerability.

    Args:
        directory: Path to directory containing cloud configs.

    Returns:
        CloudScanResult with all findings and risk assessment.
    """
    findings = []
    files_scanned = 0
    errors = []

    if not os.path.isdir(directory):
        return CloudScanResult(
            scan_directory=directory,
            files_scanned=0,
            errors=[f"Directory not found: {directory}"],
        )

    for root, dirs, files in os.walk(directory):
        # Skip hidden directories and common non-config dirs
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("node_modules", ".terraform")]

        for filename in files:
            file_path = os.path.join(root, filename)

            try:
                if filename.endswith((".tf", ".tf.json")):
                    files_scanned += 1
                    findings.extend(_analyze_terraform_file(file_path))

                elif filename.endswith((".yaml", ".yml", ".json")):
                    # Check if it looks like CloudFormation
                    with open(file_path, "r") as f:
                        header = f.read(500)

                    if "AWSTemplateFormatVersion" in header or "Resources" in header:
                        files_scanned += 1
                        findings.extend(_analyze_cloudformation_file(file_path))

            except Exception as e:
                errors.append(f"Error processing {file_path}: {e}")

    result = CloudScanResult(
        scan_directory=directory,
        files_scanned=files_scanned,
        findings=findings,
        errors=errors,
    )

    # Compute risk
    if findings:
        profiles = [f.profile for f in findings if f.profile]
        result.risk_score = compute_risk_score(profiles)
        result.readiness_level = get_overall_readiness(result.risk_score)
    else:
        result.readiness_level = "No cryptographic configurations detected"

    return result
