"""
Cryptographic algorithm classification for post-quantum readiness.

Classifies algorithms by their vulnerability to quantum attacks and provides
risk scoring with migration recommendations.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class QuantumThreatLevel(Enum):
    """Threat level under a cryptographically relevant quantum computer (CRQC)."""

    CRITICAL = "critical"  # Broken by Shor's algorithm
    HIGH = "high"  # Significantly weakened (e.g., Grover's on small keys)
    MEDIUM = "medium"  # Reduced security margin
    LOW = "low"  # Minimal quantum impact
    SAFE = "safe"  # Post-quantum algorithm or quantum-resistant


@dataclass
class AlgorithmProfile:
    """Profile of a cryptographic algorithm's quantum readiness."""

    name: str
    category: str  # signature, key_exchange, symmetric, hash
    threat_level: QuantumThreatLevel
    risk_score: float  # 0.0 (safe) to 10.0 (critical)
    vulnerability: str
    recommendation: str
    nist_replacement: Optional[str] = None
    migration_priority: str = "low"


# Knowledge base of algorithm quantum vulnerability profiles
ALGORITHM_DB: dict[str, AlgorithmProfile] = {
    # Asymmetric - Key Exchange (broken by Shor's)
    "rsa": AlgorithmProfile(
        name="RSA",
        category="key_exchange",
        threat_level=QuantumThreatLevel.CRITICAL,
        risk_score=9.5,
        vulnerability="Completely broken by Shor's algorithm in polynomial time",
        recommendation="Migrate to ML-KEM (FIPS 203) for key encapsulation",
        nist_replacement="ML-KEM (Kyber)",
        migration_priority="immediate",
    ),
    "ecdh": AlgorithmProfile(
        name="ECDH",
        category="key_exchange",
        threat_level=QuantumThreatLevel.CRITICAL,
        risk_score=9.5,
        vulnerability="Elliptic curve discrete log broken by Shor's algorithm",
        recommendation="Migrate to ML-KEM (FIPS 203) for key exchange",
        nist_replacement="ML-KEM (Kyber)",
        migration_priority="immediate",
    ),
    "dh": AlgorithmProfile(
        name="Diffie-Hellman",
        category="key_exchange",
        threat_level=QuantumThreatLevel.CRITICAL,
        risk_score=9.5,
        vulnerability="Discrete logarithm broken by Shor's algorithm",
        recommendation="Migrate to ML-KEM (FIPS 203)",
        nist_replacement="ML-KEM (Kyber)",
        migration_priority="immediate",
    ),
    # Asymmetric - Signatures (broken by Shor's)
    "ecdsa": AlgorithmProfile(
        name="ECDSA",
        category="signature",
        threat_level=QuantumThreatLevel.CRITICAL,
        risk_score=9.0,
        vulnerability="Elliptic curve discrete log broken by Shor's algorithm",
        recommendation="Migrate to ML-DSA (FIPS 204) for digital signatures",
        nist_replacement="ML-DSA (Dilithium)",
        migration_priority="immediate",
    ),
    "ed25519": AlgorithmProfile(
        name="Ed25519",
        category="signature",
        threat_level=QuantumThreatLevel.CRITICAL,
        risk_score=9.0,
        vulnerability="Elliptic curve discrete log broken by Shor's algorithm",
        recommendation="Migrate to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205)",
        nist_replacement="ML-DSA (Dilithium)",
        migration_priority="immediate",
    ),
    "dsa": AlgorithmProfile(
        name="DSA",
        category="signature",
        threat_level=QuantumThreatLevel.CRITICAL,
        risk_score=9.0,
        vulnerability="Discrete logarithm broken by Shor's algorithm",
        recommendation="Migrate to ML-DSA (FIPS 204)",
        nist_replacement="ML-DSA (Dilithium)",
        migration_priority="immediate",
    ),
    # Symmetric - Reduced security under Grover's
    "aes-128": AlgorithmProfile(
        name="AES-128",
        category="symmetric",
        threat_level=QuantumThreatLevel.MEDIUM,
        risk_score=4.0,
        vulnerability="Grover's algorithm reduces effective security to 64-bit",
        recommendation="Upgrade to AES-256 for quantum-resistant symmetric encryption",
        nist_replacement="AES-256",
        migration_priority="planned",
    ),
    "aes-256": AlgorithmProfile(
        name="AES-256",
        category="symmetric",
        threat_level=QuantumThreatLevel.LOW,
        risk_score=1.0,
        vulnerability="Grover's reduces to 128-bit effective security (still secure)",
        recommendation="Retain - provides adequate post-quantum security margin",
        nist_replacement=None,
        migration_priority="none",
    ),
    "chacha20": AlgorithmProfile(
        name="ChaCha20",
        category="symmetric",
        threat_level=QuantumThreatLevel.LOW,
        risk_score=1.5,
        vulnerability="256-bit key provides adequate post-quantum margin",
        recommendation="Retain - quantum resistant at current key sizes",
        nist_replacement=None,
        migration_priority="none",
    ),
    "3des": AlgorithmProfile(
        name="3DES",
        category="symmetric",
        threat_level=QuantumThreatLevel.HIGH,
        risk_score=7.0,
        vulnerability="Already weak; Grover's further reduces 112-bit to 56-bit",
        recommendation="Migrate to AES-256 immediately (weak even classically)",
        nist_replacement="AES-256",
        migration_priority="immediate",
    ),
    # Hash functions
    "sha-256": AlgorithmProfile(
        name="SHA-256",
        category="hash",
        threat_level=QuantumThreatLevel.LOW,
        risk_score=1.0,
        vulnerability="Grover's reduces collision resistance minimally",
        recommendation="Retain - adequate post-quantum security",
        nist_replacement=None,
        migration_priority="none",
    ),
    "sha-384": AlgorithmProfile(
        name="SHA-384",
        category="hash",
        threat_level=QuantumThreatLevel.LOW,
        risk_score=0.5,
        vulnerability="Strong post-quantum security margin",
        recommendation="Retain",
        nist_replacement=None,
        migration_priority="none",
    ),
    "sha-1": AlgorithmProfile(
        name="SHA-1",
        category="hash",
        threat_level=QuantumThreatLevel.HIGH,
        risk_score=7.5,
        vulnerability="Already broken classically; quantum attacks worsen situation",
        recommendation="Migrate to SHA-256 or SHA-3 immediately",
        nist_replacement="SHA-256 / SHA-3",
        migration_priority="immediate",
    ),
    "md5": AlgorithmProfile(
        name="MD5",
        category="hash",
        threat_level=QuantumThreatLevel.HIGH,
        risk_score=8.0,
        vulnerability="Completely broken classically; trivial with quantum",
        recommendation="Remove immediately - use SHA-256 or SHA-3",
        nist_replacement="SHA-256 / SHA-3",
        migration_priority="immediate",
    ),
    # Post-quantum algorithms (safe)
    "ml-kem": AlgorithmProfile(
        name="ML-KEM (Kyber)",
        category="key_exchange",
        threat_level=QuantumThreatLevel.SAFE,
        risk_score=0.0,
        vulnerability="None known - lattice-based PQC standard",
        recommendation="Already quantum-safe (FIPS 203)",
        nist_replacement=None,
        migration_priority="none",
    ),
    "ml-dsa": AlgorithmProfile(
        name="ML-DSA (Dilithium)",
        category="signature",
        threat_level=QuantumThreatLevel.SAFE,
        risk_score=0.0,
        vulnerability="None known - lattice-based PQC standard",
        recommendation="Already quantum-safe (FIPS 204)",
        nist_replacement=None,
        migration_priority="none",
    ),
    "slh-dsa": AlgorithmProfile(
        name="SLH-DSA (SPHINCS+)",
        category="signature",
        threat_level=QuantumThreatLevel.SAFE,
        risk_score=0.0,
        vulnerability="None known - hash-based PQC standard",
        recommendation="Already quantum-safe (FIPS 205)",
        nist_replacement=None,
        migration_priority="none",
    ),
}

# Mapping of TLS cipher suite components to algorithm names
CIPHER_SUITE_MAPPINGS: dict[str, str] = {
    "RSA": "rsa",
    "ECDHE": "ecdh",
    "ECDH": "ecdh",
    "DHE": "dh",
    "DH": "dh",
    "ECDSA": "ecdsa",
    "AES128": "aes-128",
    "AES256": "aes-256",
    "AES_128": "aes-128",
    "AES_256": "aes-256",
    "CHACHA20": "chacha20",
    "3DES": "3des",
    "SHA256": "sha-256",
    "SHA384": "sha-384",
    "SHA1": "sha-1",
    "SHA": "sha-1",
    "MD5": "md5",
}


def classify_algorithm(algorithm_name: str) -> Optional[AlgorithmProfile]:
    """Classify a cryptographic algorithm by its post-quantum readiness.

    Args:
        algorithm_name: Name of the algorithm (case-insensitive).

    Returns:
        AlgorithmProfile if recognized, None otherwise.
    """
    normalized = algorithm_name.lower().strip().replace(" ", "-").replace("_", "-")
    return ALGORITHM_DB.get(normalized)


def classify_cipher_suite(cipher_suite: str) -> list[AlgorithmProfile]:
    """Break down a TLS cipher suite string and classify each component.

    Args:
        cipher_suite: TLS cipher suite string (e.g., "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")

    Returns:
        List of AlgorithmProfile for each identified component.
    """
    profiles = []
    seen = set()

    # Normalize and split the cipher suite
    parts = cipher_suite.upper().replace("-", "_").split("_")

    for part in parts:
        if part in CIPHER_SUITE_MAPPINGS:
            algo_key = CIPHER_SUITE_MAPPINGS[part]
            if algo_key not in seen:
                seen.add(algo_key)
                profile = ALGORITHM_DB.get(algo_key)
                if profile:
                    profiles.append(profile)

    return profiles


def compute_risk_score(profiles: list[AlgorithmProfile]) -> float:
    """Compute an aggregate PQC risk score from multiple algorithm profiles.

    Uses a weighted approach where the highest-risk algorithm dominates
    but additional vulnerabilities increase the score.

    Args:
        profiles: List of algorithm profiles to score.

    Returns:
        Aggregate risk score from 0.0 to 10.0.
    """
    if not profiles:
        return 0.0

    scores = sorted([p.risk_score for p in profiles], reverse=True)

    # Dominant risk + diminishing contribution from additional risks
    total = scores[0]
    for i, score in enumerate(scores[1:], start=1):
        total += score * (0.3 / i)  # Diminishing weight

    return min(total, 10.0)


def get_overall_readiness(risk_score: float) -> str:
    """Convert a risk score to a human-readable readiness level.

    Args:
        risk_score: Aggregate risk score (0-10).

    Returns:
        Readiness level string.
    """
    if risk_score <= 1.0:
        return "PQC Ready"
    elif risk_score <= 3.0:
        return "Mostly Ready - Minor improvements needed"
    elif risk_score <= 5.0:
        return "Partially Ready - Migration planning required"
    elif risk_score <= 7.0:
        return "At Risk - Active migration needed"
    else:
        return "Critical - Immediate action required"
