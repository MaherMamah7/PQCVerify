"""
Active TLS negotiation prober.

This module gathers *wire ground truth* by performing multiple real handshakes
against an endpoint. It is the foundation for property-level verification
(downgrade paths, trust-chain analysis) rather than single-observation scanning.

Two capabilities:
    1. Enumerate the reachable negotiation space (which TLS versions / key
       exchange families a server will actually agree to). This is what makes
       downgrade-path detection possible: a scanner sees the *preferred*
       cipher; verification needs the *floor* of what an attacker can force.
    2. Retrieve and parse the full certificate trust chain (not just the leaf),
       so the chain can be verified end to end.
"""

import socket
import ssl
import warnings
from dataclasses import dataclass, field
from typing import Optional

from cryptography import x509


# Key-exchange families that are broken by Shor's algorithm (all classical
# key exchange falls here). TLS 1.2 and below only offer these.
_CLASSICAL_KEX_TOKENS = ("ECDHE", "DHE", "ECDH", "DH", "RSA")


@dataclass
class NegotiatedConfig:
    """A single reachable TLS configuration discovered by probing."""

    tls_version: str
    cipher: str
    key_exchange: str          # e.g. "ECDHE", "RSA", or "TLS1.3-group-unknown"
    classical_kex: bool        # True if the key exchange is quantum-vulnerable


@dataclass
class NegotiationSpace:
    """The set of TLS configurations a server will actually negotiate."""

    host: str
    port: int
    reachable: list[NegotiatedConfig] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def legacy_versions_reachable(self) -> list[str]:
        """Pre-TLS1.3 versions that completed a handshake."""
        legacy = {"TLSv1", "TLSv1.1", "TLSv1.2"}
        return [c.tls_version for c in self.reachable if c.tls_version in legacy]

    @property
    def has_classical_kex_path(self) -> bool:
        """True if any reachable config uses a classical (breakable) key exchange."""
        return any(c.classical_kex for c in self.reachable)

    @property
    def weakest(self) -> Optional[NegotiatedConfig]:
        """The most attacker-favorable reachable config (a classical one if present)."""
        classical = [c for c in self.reachable if c.classical_kex]
        if classical:
            # Prefer the lowest TLS version among classical options
            order = {"TLSv1": 0, "TLSv1.1": 1, "TLSv1.2": 2, "TLSv1.3": 3}
            return sorted(classical, key=lambda c: order.get(c.tls_version, 9))[0]
        return self.reachable[0] if self.reachable else None


def _classify_kex(tls_version: str, cipher: str) -> tuple[str, bool]:
    """Determine the key-exchange family and whether it is classical.

    For TLS 1.2 and below the key exchange is encoded in the cipher name.
    For TLS 1.3 the key exchange is a separate "group" not exposed by the
    standard library, so it is reported as unconfirmed.
    """
    if tls_version == "TLSv1.3":
        # The negotiated group (e.g. X25519 vs X25519MLKEM768) is not visible
        # via the stdlib. Confirming a PQC group requires a PQC-aware TLS stack.
        return "TLS1.3-group-unknown", False

    upper = cipher.upper()
    for token in _CLASSICAL_KEX_TOKENS:
        if token in upper:
            return token, True
    # TLS <=1.2 with an unrecognized suite: assume classical (no PQC exists pre-1.3)
    return "classical-unknown", True


def probe_negotiation_space(
    host: str,
    port: int = 443,
    timeout: float = 6.0,
    include_legacy: bool = True,
) -> NegotiationSpace:
    """Enumerate which TLS versions and key exchanges a server will negotiate.

    Performs one handshake per TLS version, recording what the server agreed to.

    Args:
        host: Target hostname.
        port: Target port.
        timeout: Per-handshake timeout.
        include_legacy: Also probe TLS 1.0/1.1 (usually blocked, emits warnings).

    Returns:
        NegotiationSpace describing every reachable configuration.
    """
    space = NegotiationSpace(host=host, port=port)

    T = ssl.TLSVersion
    versions = [("TLSv1.2", T.TLSv1_2), ("TLSv1.3", T.TLSv1_3)]
    if include_legacy:
        versions = [("TLSv1", T.TLSv1), ("TLSv1.1", T.TLSv1_1)] + versions

    for name, ver in versions:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                ctx.minimum_version = ver
                ctx.maximum_version = ver
        except ValueError:
            # This Python/OpenSSL build refuses to even offer this version
            continue

        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                    negotiated_version = tls_sock.version() or name
                    cipher_info = tls_sock.cipher()
                    cipher = cipher_info[0] if cipher_info else "unknown"
                    kex, classical = _classify_kex(negotiated_version, cipher)
                    space.reachable.append(
                        NegotiatedConfig(
                            tls_version=negotiated_version,
                            cipher=cipher,
                            key_exchange=kex,
                            classical_kex=classical,
                        )
                    )
        except (ssl.SSLError, socket.timeout, socket.gaierror, ConnectionError, OSError):
            # Version not supported by the server -> not reachable. Expected.
            continue
        except Exception as e:
            space.errors.append(f"{name}: {e}")

    return space


@dataclass
class ChainCertificate:
    """One certificate in a trust chain, with its quantum-relevant fields."""

    subject: str
    issuer: str
    signature_algorithm: str
    public_key_algorithm: str
    is_self_signed: bool
    classical_signature: bool


@dataclass
class TrustChain:
    """The full certificate trust chain retrieved from an endpoint."""

    host: str
    certificates: list[ChainCertificate] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def weakest_classical(self) -> Optional[ChainCertificate]:
        for c in self.certificates:
            if c.classical_signature:
                return c
        return None


def _pubkey_algo(cert: x509.Certificate) -> str:
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448
    pk = cert.public_key()
    if isinstance(pk, rsa.RSAPublicKey):
        return "RSA"
    if isinstance(pk, ec.EllipticCurvePublicKey):
        return "ECDSA"
    if isinstance(pk, dsa.DSAPublicKey):
        return "DSA"
    if isinstance(pk, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(pk, ed448.Ed448PublicKey):
        return "Ed448"
    return "Unknown"


def get_trust_chain(host: str, port: int = 443, timeout: float = 10.0) -> TrustChain:
    """Retrieve and parse the full certificate trust chain (leaf -> root).

    Args:
        host: Target hostname.
        port: Target port.
        timeout: Connection timeout.

    Returns:
        TrustChain with one entry per certificate in the chain.
    """
    chain = TrustChain(host=host)

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                try:
                    der_chain = tls_sock.get_verified_chain()
                except (AttributeError, ssl.SSLError):
                    der_chain = [tls_sock.getpeercert(binary_form=True)]
    except Exception as e:
        chain.errors.append(f"Could not retrieve chain: {e}")
        return chain

    classical_sigs = ("rsa", "ecdsa", "sha1", "sha256with", "sha384with", "sha512with", "ed25519", "ed448")

    for der in der_chain:
        if not der:
            continue
        try:
            cert = x509.load_der_x509_certificate(der)
        except Exception as e:
            chain.errors.append(f"Failed to parse a chain certificate: {e}")
            continue

        sig_name = cert.signature_algorithm_oid._name or "unknown"
        pk_algo = _pubkey_algo(cert)
        is_classical = any(tok in sig_name.lower() for tok in classical_sigs) or pk_algo in (
            "RSA", "ECDSA", "DSA", "Ed25519", "Ed448"
        )

        chain.certificates.append(
            ChainCertificate(
                subject=cert.subject.rfc4514_string(),
                issuer=cert.issuer.rfc4514_string(),
                signature_algorithm=sig_name,
                public_key_algorithm=pk_algo,
                is_self_signed=(cert.subject == cert.issuer),
                classical_signature=is_classical,
            )
        )

    return chain
