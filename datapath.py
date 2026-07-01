"""
End-to-end data-path modeling for weakest-link verification.

A scanner checks endpoints in isolation. But sensitive data travels a *path*:
client -> load balancer -> application -> database -> backup. The whole path
is only as quantum-safe as its weakest hop. A PQC-enabled front door is
worthless if the internal hop to the database is keyed with classical RSA.

This module models that path and computes its weakest link. The path is
declared (loaded from JSON, or derived from infrastructure analysis) because
internal hops are not externally observable -- which is exactly why scanning
cannot answer this and verification must.
"""

import json
from dataclasses import dataclass, field
from typing import Optional

from .crypto_classify import classify_algorithm, AlgorithmProfile, QuantumThreatLevel


@dataclass
class Hop:
    """One leg of a data path and the cryptography protecting it."""

    name: str                       # e.g. "client->ALB"
    description: str = ""
    # Algorithm names protecting this hop (key exchange, signature, symmetric)
    algorithms: list[str] = field(default_factory=list)
    encrypted: bool = True          # False means plaintext (the worst case)


@dataclass
class HopVerdict:
    """Assessment of a single hop."""

    hop: Hop
    worst_profile: Optional[AlgorithmProfile]
    risk_score: float
    quantum_safe: bool
    reason: str


@dataclass
class DataPath:
    """A named end-to-end data path made of ordered hops."""

    name: str
    hops: list[Hop] = field(default_factory=list)

    @classmethod
    def from_json_file(cls, path: str) -> "DataPath":
        with open(path, "r") as f:
            data = json.load(f)
        hops = [
            Hop(
                name=h["name"],
                description=h.get("description", ""),
                algorithms=h.get("algorithms", []),
                encrypted=h.get("encrypted", True),
            )
            for h in data.get("hops", [])
        ]
        return cls(name=data.get("name", "data-path"), hops=hops)


@dataclass
class PathVerification:
    """Result of verifying a data path's weakest link."""

    path_name: str
    hop_verdicts: list[HopVerdict] = field(default_factory=list)
    weakest: Optional[HopVerdict] = None
    quantum_safe: bool = False


def _assess_hop(hop: Hop) -> HopVerdict:
    """Assess a single hop, returning its worst (weakest) algorithm."""
    if not hop.encrypted:
        return HopVerdict(
            hop=hop,
            worst_profile=None,
            risk_score=10.0,
            quantum_safe=False,
            reason="Traffic on this hop is unencrypted (plaintext).",
        )

    if not hop.algorithms:
        return HopVerdict(
            hop=hop,
            worst_profile=None,
            risk_score=5.0,
            quantum_safe=False,
            reason="No cryptography declared for this hop; cannot consider it protected.",
        )

    worst: Optional[AlgorithmProfile] = None
    for algo in hop.algorithms:
        profile = classify_algorithm(algo)
        if profile is None:
            continue
        if worst is None or profile.risk_score > worst.risk_score:
            worst = profile

    if worst is None:
        return HopVerdict(
            hop=hop, worst_profile=None, risk_score=5.0, quantum_safe=False,
            reason="Declared algorithms could not be classified.",
        )

    safe = worst.threat_level in (QuantumThreatLevel.LOW, QuantumThreatLevel.SAFE)
    if safe:
        reason = f"Weakest algorithm on this hop is {worst.name}, which is quantum-resistant."
    else:
        reason = (
            f"Weakest algorithm on this hop is {worst.name} "
            f"({worst.threat_level.value}): {worst.vulnerability}"
        )
    return HopVerdict(
        hop=hop, worst_profile=worst, risk_score=worst.risk_score,
        quantum_safe=safe, reason=reason,
    )


def verify_path(path: DataPath) -> PathVerification:
    """Verify an end-to-end data path using the weakest-link principle.

    Args:
        path: The data path to verify.

    Returns:
        PathVerification with per-hop verdicts and the weakest link.
    """
    verdicts = [_assess_hop(h) for h in path.hops]
    result = PathVerification(path_name=path.name, hop_verdicts=verdicts)

    if not verdicts:
        return result

    # Weakest link = highest risk hop
    result.weakest = max(verdicts, key=lambda v: v.risk_score)
    result.quantum_safe = all(v.quantum_safe for v in verdicts)
    return result
