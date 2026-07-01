"""
PQCVerify verification engine (property-level).

This engine does NOT inventory components. It verifies *emergent properties of
the assembled system* -- properties that can be false even when every
individual component looks fine, and that a scanner structurally cannot answer:

    PQV-DG  No downgrade path: an attacker cannot force the connection onto a
            classical (quantum-breakable) key exchange. Checks the FLOOR of the
            negotiation space, not the preferred cipher.

    PQV-CH  Whole trust chain is quantum-safe: every certificate from leaf to
            root uses a quantum-safe signature. The chain is only as strong as
            its weakest certificate.

    PQV-DP  End-to-end data path is quantum-safe: the weakest hop along the
            real path that sensitive data travels (client -> ... -> backup) is
            quantum-safe. A PQC front door does not help if an internal hop is
            classical or plaintext.

Each control returns a verdict (verified / partially / not verified /
insufficient evidence), a plain-language rationale, and a next step.

The reasoning is transparent and rule-based in this proof of concept, and is
structured so the rationale generation and cross-evidence correlation can be
augmented with an LLM/ML model later without changing the control contracts.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .tls_probe import NegotiationSpace, TrustChain
from .datapath import PathVerification


class Verdict(Enum):
    VERIFIED = "verified"
    PARTIALLY_VERIFIED = "partially_verified"
    NOT_VERIFIED = "not_verified"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"

    @property
    def icon(self) -> str:
        return {
            Verdict.VERIFIED: "✅",
            Verdict.PARTIALLY_VERIFIED: "🟡",
            Verdict.NOT_VERIFIED: "❌",
            Verdict.INSUFFICIENT_EVIDENCE: "❔",
        }[self]

    @property
    def label(self) -> str:
        return {
            Verdict.VERIFIED: "Verified",
            Verdict.PARTIALLY_VERIFIED: "Partially Verified",
            Verdict.NOT_VERIFIED: "Not Verified",
            Verdict.INSUFFICIENT_EVIDENCE: "Insufficient Evidence",
        }[self]


@dataclass
class CheckResult:
    control_id: str
    title: str
    verdict: Verdict
    rationale: str
    remediation: str
    evidence_used: list[str] = field(default_factory=list)


@dataclass
class VerificationReport:
    subject: str
    checks: list[CheckResult] = field(default_factory=list)
    overall_verdict: Verdict = Verdict.INSUFFICIENT_EVIDENCE
    summary: str = ""


# ---------------------------------------------------------------------------
# PQV-DG : Downgrade-path verification (property of the negotiation space)
# ---------------------------------------------------------------------------

def verify_no_downgrade_path(space: Optional[NegotiationSpace]) -> CheckResult:
    cid = "PQV-DG"
    title = "No quantum-vulnerable downgrade path"

    if space is None or not space.reachable:
        return CheckResult(
            cid, title, Verdict.INSUFFICIENT_EVIDENCE,
            rationale=(
                "The endpoint's negotiation space could not be probed, so it is "
                "unknown whether an attacker can force a classical handshake."
            ),
            remediation="Provide a reachable TLS endpoint so its negotiation floor can be measured.",
            evidence_used=["negotiation_space=<not probed>"],
        )

    reachable_desc = [f"{c.tls_version}/{c.key_exchange}" for c in space.reachable]

    if space.has_classical_kex_path:
        weak = space.weakest
        legacy = space.legacy_versions_reachable
        legacy_note = (
            f" Legacy protocol versions are reachable: {', '.join(sorted(set(legacy)))}."
            if legacy else ""
        )
        return CheckResult(
            cid, title, Verdict.NOT_VERIFIED,
            rationale=(
                f"The server will negotiate {weak.tls_version} with a classical "
                f"key exchange ({weak.key_exchange}, cipher {weak.cipher}). Even if a "
                "post-quantum option exists, an attacker can force this weaker path "
                "via a downgrade attack and later decrypt recorded traffic." + legacy_note
            ),
            remediation=(
                "Disable all pre-TLS1.3 versions and any classical-only key exchange so "
                "the negotiation floor is a hybrid PQC group (e.g. X25519MLKEM768)."
            ),
            evidence_used=[f"reachable={reachable_desc}", f"weakest={weak.tls_version}/{weak.key_exchange}"],
        )

    # Only TLS 1.3 reachable, but stdlib cannot confirm the negotiated group is PQC
    return CheckResult(
        cid, title, Verdict.PARTIALLY_VERIFIED,
        rationale=(
            "No pre-TLS1.3 or classical-cipher downgrade path was found, which closes the "
            "most common downgrade attack. However, the TLS 1.3 key-exchange group itself "
            "could not be confirmed as post-quantum from this vantage point."
        ),
        remediation=(
            "Confirm the negotiated TLS 1.3 group is a hybrid PQC group using a "
            "PQC-aware probe to fully close this control."
        ),
        evidence_used=[f"reachable={reachable_desc}"],
    )


# ---------------------------------------------------------------------------
# PQV-CH : Trust-chain verification (property of the whole chain)
# ---------------------------------------------------------------------------

def verify_trust_chain(chain: Optional[TrustChain]) -> CheckResult:
    cid = "PQV-CH"
    title = "Entire certificate trust chain is quantum-safe"

    if chain is None or not chain.certificates:
        return CheckResult(
            cid, title, Verdict.INSUFFICIENT_EVIDENCE,
            rationale="The certificate trust chain could not be retrieved.",
            remediation="Provide a reachable TLS endpoint so the full chain can be analyzed.",
            evidence_used=["trust_chain=<not retrieved>"],
        )

    chain_desc = [
        f"{'root' if c.is_self_signed else 'cert'}:{c.public_key_algorithm}/{c.signature_algorithm}"
        for c in chain.certificates
    ]
    weak = chain.weakest_classical

    if weak is not None:
        position = "root CA" if weak.is_self_signed else "certificate"
        return CheckResult(
            cid, title, Verdict.NOT_VERIFIED,
            rationale=(
                f"The chain has {len(chain.certificates)} certificate(s), but the {position} "
                f"\"{weak.subject}\" uses a classical signature ({weak.public_key_algorithm}/"
                f"{weak.signature_algorithm}). The chain is only as strong as its weakest "
                "certificate, so authentication is forgeable by a quantum attacker."
            ),
            remediation=(
                "A quantum-safe chain requires every certificate -- including intermediate "
                "and root CAs -- to use a PQC signature (ML-DSA / FIPS 204). This depends on "
                "your CA issuing PQC certificates."
            ),
            evidence_used=[f"chain={chain_desc}"],
        )

    return CheckResult(
        cid, title, Verdict.VERIFIED,
        rationale="Every certificate in the chain uses a quantum-safe signature algorithm.",
        remediation="None.",
        evidence_used=[f"chain={chain_desc}"],
    )


# ---------------------------------------------------------------------------
# PQV-DP : End-to-end data-path verification (property of the path)
# ---------------------------------------------------------------------------

def verify_data_path(path_result: Optional[PathVerification]) -> CheckResult:
    cid = "PQV-DP"
    title = "End-to-end data path is quantum-safe"

    if path_result is None or not path_result.hop_verdicts:
        return CheckResult(
            cid, title, Verdict.INSUFFICIENT_EVIDENCE,
            rationale=(
                "No end-to-end data path was provided. Per-endpoint results cannot reveal "
                "whether an internal hop (e.g. app->database, or a backup) breaks the chain."
            ),
            remediation=(
                "Declare the path sensitive data travels (e.g. via --data-path path.json) so "
                "the weakest hop can be verified."
            ),
            evidence_used=["data_path=<not provided>"],
        )

    weak = path_result.weakest
    if path_result.quantum_safe:
        return CheckResult(
            cid, title, Verdict.VERIFIED,
            rationale=(
                f"All {len(path_result.hop_verdicts)} hops along '{path_result.path_name}' "
                "use quantum-resistant cryptography. The weakest link is still quantum-safe."
            ),
            remediation="None.",
            evidence_used=[f"hops={len(path_result.hop_verdicts)}"],
        )

    return CheckResult(
        cid, title, Verdict.NOT_VERIFIED,
        rationale=(
            f"The path '{path_result.path_name}' is broken at its weakest hop "
            f"'{weak.hop.name}': {weak.reason} Securing other hops does not help while "
            "this one remains exposed."
        ),
        remediation=(
            f"Fix the weakest hop first ('{weak.hop.name}'), then re-verify the whole path."
        ),
        evidence_used=[
            f"weakest_hop={weak.hop.name}",
            f"weakest_risk={weak.risk_score}",
        ],
    )


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

def _aggregate_verdict(checks: list[CheckResult]) -> Verdict:
    decided = [c.verdict for c in checks if c.verdict != Verdict.INSUFFICIENT_EVIDENCE]
    if not decided:
        return Verdict.INSUFFICIENT_EVIDENCE
    if any(v == Verdict.NOT_VERIFIED for v in decided):
        return Verdict.NOT_VERIFIED
    if any(v == Verdict.PARTIALLY_VERIFIED for v in decided):
        return Verdict.PARTIALLY_VERIFIED
    if any(c.verdict == Verdict.INSUFFICIENT_EVIDENCE for c in checks):
        return Verdict.PARTIALLY_VERIFIED
    return Verdict.VERIFIED


def _summarize(subject: str, overall: Verdict, checks: list[CheckResult]) -> str:
    n_pass = sum(1 for c in checks if c.verdict == Verdict.VERIFIED)
    n_fail = sum(1 for c in checks if c.verdict == Verdict.NOT_VERIFIED)
    n_partial = sum(1 for c in checks if c.verdict == Verdict.PARTIALLY_VERIFIED)
    n_insuff = sum(1 for c in checks if c.verdict == Verdict.INSUFFICIENT_EVIDENCE)

    if overall == Verdict.VERIFIED:
        lead = f"{subject} is quantum-safe across all verified properties."
    elif overall == Verdict.NOT_VERIFIED:
        lead = (
            f"{subject} is NOT quantum-safe. A system property failed -- the weakest link "
            "(a downgrade path, a classical certificate in the chain, or a weak hop on the "
            "data path) defeats the protection regardless of what else is in place."
        )
    elif overall == Verdict.PARTIALLY_VERIFIED:
        lead = f"{subject} is partially quantum-safe. Some properties hold but gaps remain."
    else:
        lead = f"There was insufficient evidence to verify {subject}."

    return (
        f"{lead} ({n_pass} verified, {n_partial} partial, {n_fail} not verified, "
        f"{n_insuff} insufficient evidence)."
    )


def run_verification(
    subject: str,
    negotiation_space: Optional[NegotiationSpace] = None,
    trust_chain: Optional[TrustChain] = None,
    path_result: Optional[PathVerification] = None,
) -> VerificationReport:
    """Run all property-level verification controls.

    Args:
        subject: Name of the system under verification.
        negotiation_space: Probed TLS negotiation space (for PQV-DG).
        trust_chain: Retrieved certificate chain (for PQV-CH).
        path_result: Verified data path (for PQV-DP).

    Returns:
        VerificationReport with verdicts and an overall result.
    """
    checks = [
        verify_no_downgrade_path(negotiation_space),
        verify_trust_chain(trust_chain),
        verify_data_path(path_result),
    ]
    overall = _aggregate_verdict(checks)
    return VerificationReport(
        subject=subject,
        checks=checks,
        overall_verdict=overall,
        summary=_summarize(subject, overall, checks),
    )
