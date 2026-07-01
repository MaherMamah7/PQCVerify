"""
TLS Scanner module - Analyzes external websites for post-quantum readiness.

Connects to target hosts, retrieves TLS certificate and cipher suite information,
and classifies the cryptographic algorithms used against quantum threat models.
"""

import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa, dsa, ed25519, ed448

from .crypto_classify import (
    AlgorithmProfile,
    classify_algorithm,
    classify_cipher_suite,
    compute_risk_score,
    get_overall_readiness,
)


@dataclass
class CertificateInfo:
    """Extracted certificate information relevant to PQC analysis."""

    subject: str
    issuer: str
    serial_number: str
    not_valid_before: datetime
    not_valid_after: datetime
    signature_algorithm: str
    public_key_algorithm: str
    public_key_size: int
    san_domains: list[str] = field(default_factory=list)


@dataclass
class TLSScanResult:
    """Complete TLS scan result for a target host."""

    host: str
    port: int
    scan_timestamp: datetime
    tls_version: str
    cipher_suite: str
    certificate: Optional[CertificateInfo]
    algorithm_profiles: list[AlgorithmProfile] = field(default_factory=list)
    risk_score: float = 0.0
    readiness_level: str = ""
    errors: list[str] = field(default_factory=list)

    def __post_init__(self):
        if self.algorithm_profiles and not self.readiness_level:
            self.risk_score = compute_risk_score(self.algorithm_profiles)
            self.readiness_level = get_overall_readiness(self.risk_score)


def _extract_public_key_info(cert: x509.Certificate) -> tuple[str, int]:
    """Extract public key algorithm name and size from certificate.

    Args:
        cert: x509 Certificate object.

    Returns:
        Tuple of (algorithm_name, key_size_bits).
    """
    pub_key = cert.public_key()

    if isinstance(pub_key, rsa.RSAPublicKey):
        return "RSA", pub_key.key_size
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        return "ECDSA", pub_key.key_size
    elif isinstance(pub_key, dsa.DSAPublicKey):
        return "DSA", pub_key.key_size
    elif isinstance(pub_key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    elif isinstance(pub_key, ed448.Ed448PublicKey):
        return "Ed448", 448
    else:
        return "Unknown", 0


def _parse_certificate(der_cert: bytes) -> CertificateInfo:
    """Parse a DER-encoded certificate into structured info.

    Args:
        der_cert: DER-encoded certificate bytes.

    Returns:
        CertificateInfo with extracted fields.
    """
    cert = x509.load_der_x509_certificate(der_cert)

    pk_algo, pk_size = _extract_public_key_info(cert)

    # Extract SAN domains
    san_domains = []
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_domains = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass

    # Get signature algorithm name
    sig_algo = cert.signature_algorithm_oid._name if cert.signature_algorithm_oid else "Unknown"

    return CertificateInfo(
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        serial_number=format(cert.serial_number, "x"),
        not_valid_before=cert.not_valid_before_utc,
        not_valid_after=cert.not_valid_after_utc,
        signature_algorithm=sig_algo,
        public_key_algorithm=pk_algo,
        public_key_size=pk_size,
        san_domains=san_domains,
    )


def scan_tls(host: str, port: int = 443, timeout: float = 10.0) -> TLSScanResult:
    """Scan a host's TLS configuration for post-quantum readiness.

    Connects to the target, retrieves the TLS certificate and negotiated
    cipher suite, then classifies all cryptographic algorithms found.

    Args:
        host: Target hostname (e.g., "example.com").
        port: Target port (default 443).
        timeout: Connection timeout in seconds.

    Returns:
        TLSScanResult with full analysis.
    """
    errors = []
    certificate = None
    cipher_suite = ""
    tls_version = ""
    algorithm_profiles = []

    try:
        # Create SSL context with system CA certificates
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                # Get negotiated cipher info
                cipher_info = tls_sock.cipher()
                if cipher_info:
                    cipher_suite = cipher_info[0]
                    tls_version = cipher_info[1]

                # Get certificate in DER format
                der_cert = tls_sock.getpeercert(binary_form=True)
                if der_cert:
                    certificate = _parse_certificate(der_cert)

    except ssl.SSLCertVerificationError as e:
        errors.append(f"Certificate verification failed: {e}")
        # Try again without verification to still analyze crypto
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                    cipher_info = tls_sock.cipher()
                    if cipher_info:
                        cipher_suite = cipher_info[0]
                        tls_version = cipher_info[1]

                    der_cert = tls_sock.getpeercert(binary_form=True)
                    if der_cert:
                        certificate = _parse_certificate(der_cert)
        except Exception as e2:
            errors.append(f"Fallback scan also failed: {e2}")

    except (socket.timeout, socket.gaierror) as e:
        errors.append(f"Connection failed: {e}")
    except Exception as e:
        errors.append(f"Scan error: {e}")

    # Classify algorithms from cipher suite
    if cipher_suite:
        algorithm_profiles.extend(classify_cipher_suite(cipher_suite))

    # Classify certificate algorithms
    if certificate:
        pk_profile = classify_algorithm(certificate.public_key_algorithm)
        if pk_profile and pk_profile not in algorithm_profiles:
            algorithm_profiles.append(pk_profile)

    # Build result
    risk_score = compute_risk_score(algorithm_profiles)

    return TLSScanResult(
        host=host,
        port=port,
        scan_timestamp=datetime.utcnow(),
        tls_version=tls_version,
        cipher_suite=cipher_suite,
        certificate=certificate,
        algorithm_profiles=algorithm_profiles,
        risk_score=risk_score,
        readiness_level=get_overall_readiness(risk_score),
        errors=errors,
    )


def scan_multiple(hosts: list[str], port: int = 443) -> list[TLSScanResult]:
    """Scan multiple hosts for PQC readiness.

    Args:
        hosts: List of hostnames to scan.
        port: Target port.

    Returns:
        List of TLSScanResult for each host.
    """
    results = []
    for host in hosts:
        result = scan_tls(host, port)
        results.append(result)
    return results
