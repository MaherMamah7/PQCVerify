"""
Privacy-preserving PQC readiness attestation.

This is the core innovation of the platform: it turns a sensitive scan result
into a verifiable "readiness credential" that proves quantum-readiness claims
WITHOUT revealing the underlying infrastructure details (hosts, configs, or
the location of weak spots).

Flow:
    scan  ->  seal (issue credential)  ->  verify

The credential contains:
    - Aggregate, non-identifying claims (e.g. "23 assets, all quantum-safe")
    - A Merkle root commitment over every per-asset finding
    - A digital signature from the issuer

A verifier can confirm the credential is authentic and trust the aggregate
claims, while learning nothing about which assets exist or where the
weaknesses are. The raw asset data never leaves the holder.

Note on cryptography:
    This proof-of-concept uses Ed25519 signatures and SHA-256 Merkle
    commitments. In production the issuer signature would use a post-quantum
    algorithm (ML-DSA / FIPS 204) so that the attestation itself is
    quantum-safe -- "quantum-safe proofs of quantum safety". The structure
    below is designed so that signature scheme can be swapped without changing
    the protocol.
"""

import base64
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature


# ---------------------------------------------------------------------------
# Merkle commitment - lets us commit to a list of secret items and later prove
# facts about them without revealing the whole list.
# ---------------------------------------------------------------------------

def _hash(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _leaf_hash(item: str) -> bytes:
    # Domain-separated leaf hash to prevent second-preimage attacks
    return _hash(b"\x00" + item.encode("utf-8"))


def _node_hash(left: bytes, right: bytes) -> bytes:
    return _hash(b"\x01" + left + right)


@dataclass
class MerkleTree:
    """A simple Merkle tree over a list of string leaves."""

    leaves: list[str]
    _levels: list[list[bytes]] = field(default_factory=list)

    def __post_init__(self):
        self._build()

    def _build(self):
        if not self.leaves:
            self._levels = [[_hash(b"empty")]]
            return

        current = [_leaf_hash(leaf) for leaf in self.leaves]
        self._levels = [current]

        while len(current) > 1:
            nxt = []
            for i in range(0, len(current), 2):
                left = current[i]
                right = current[i + 1] if i + 1 < len(current) else current[i]
                nxt.append(_node_hash(left, right))
            self._levels.append(nxt)
            current = nxt

    @property
    def root(self) -> bytes:
        return self._levels[-1][0]

    def root_hex(self) -> str:
        return self.root.hex()

    def inclusion_proof(self, index: int) -> list[dict]:
        """Produce a Merkle inclusion proof for the leaf at `index`.

        Lets a holder prove that a specific committed item is part of the
        sealed set, without revealing any of the other items.
        """
        if index < 0 or index >= len(self.leaves):
            raise IndexError("leaf index out of range")

        proof = []
        idx = index
        for level in self._levels[:-1]:
            is_right = idx % 2 == 1
            pair_idx = idx - 1 if is_right else idx + 1
            if pair_idx >= len(level):
                pair_idx = idx  # duplicated last node
            proof.append({
                "sibling": level[pair_idx].hex(),
                "position": "left" if is_right else "right",
            })
            idx //= 2
        return proof


def verify_inclusion_proof(item: str, proof: list[dict], root_hex: str) -> bool:
    """Verify that `item` is included under the committed `root_hex`."""
    computed = _leaf_hash(item)
    for step in proof:
        sibling = bytes.fromhex(step["sibling"])
        if step["position"] == "left":
            computed = _node_hash(sibling, computed)
        else:
            computed = _node_hash(computed, sibling)
    return computed.hex() == root_hex


# ---------------------------------------------------------------------------
# Readiness credential - the signed, privacy-preserving badge.
# ---------------------------------------------------------------------------

@dataclass
class ReadinessCredential:
    """A signed, privacy-preserving PQC readiness attestation."""

    issuer: str
    subject: str  # what was assessed, e.g. an org name (not the raw assets)
    issued_at: str
    # Aggregate, non-identifying claims:
    total_assets: int
    quantum_safe_assets: int
    max_risk_score: float
    readiness_level: str
    all_quantum_safe: bool
    # Cryptographic commitment to the (hidden) per-asset findings:
    commitment_root: str
    commitment_count: int
    # Authenticity:
    signature: str = ""
    public_key: str = ""

    def claims_payload(self) -> dict:
        """The exact claim set that gets signed (deterministic ordering)."""
        return {
            "issuer": self.issuer,
            "subject": self.subject,
            "issued_at": self.issued_at,
            "total_assets": self.total_assets,
            "quantum_safe_assets": self.quantum_safe_assets,
            "max_risk_score": self.max_risk_score,
            "readiness_level": self.readiness_level,
            "all_quantum_safe": self.all_quantum_safe,
            "commitment_root": self.commitment_root,
            "commitment_count": self.commitment_count,
        }

    def to_json(self) -> str:
        data = self.claims_payload()
        data["signature"] = self.signature
        data["public_key"] = self.public_key
        return json.dumps(data, indent=2, sort_keys=True)

    @classmethod
    def from_json(cls, raw: str) -> "ReadinessCredential":
        data = json.loads(raw)
        return cls(
            issuer=data["issuer"],
            subject=data["subject"],
            issued_at=data["issued_at"],
            total_assets=data["total_assets"],
            quantum_safe_assets=data["quantum_safe_assets"],
            max_risk_score=data["max_risk_score"],
            readiness_level=data["readiness_level"],
            all_quantum_safe=data["all_quantum_safe"],
            commitment_root=data["commitment_root"],
            commitment_count=data["commitment_count"],
            signature=data.get("signature", ""),
            public_key=data.get("public_key", ""),
        )


def _canonical_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass
class Issuer:
    """Issues signed readiness credentials.

    Holds the signing key. In production this would be an independent,
    trusted assessor and the key would be a post-quantum (ML-DSA) key.
    """

    name: str
    _private_key: ed25519.Ed25519PrivateKey = field(default=None, repr=False)

    def __post_init__(self):
        if self._private_key is None:
            self._private_key = ed25519.Ed25519PrivateKey.generate()

    def public_key_b64(self) -> str:
        from cryptography.hazmat.primitives import serialization
        raw = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return base64.b64encode(raw).decode("ascii")

    def issue(
        self,
        subject: str,
        asset_records: list[str],
        risk_scores: list[float],
        readiness_level: str,
        safe_threshold: float = 1.5,
    ) -> ReadinessCredential:
        """Create a signed readiness credential from raw (secret) asset data.

        Args:
            subject: Name of the entity being attested (e.g. organization).
            asset_records: Per-asset detail strings (these stay SECRET; only
                their Merkle commitment is published).
            risk_scores: Risk score per asset (used for aggregate claims).
            readiness_level: Overall readiness label.
            safe_threshold: Risk score at/below which an asset is "quantum-safe".

        Returns:
            A signed ReadinessCredential containing only aggregate claims and
            a commitment -- never the raw records.
        """
        tree = MerkleTree(asset_records)
        total = len(asset_records)
        safe = sum(1 for s in risk_scores if s <= safe_threshold)
        max_risk = max(risk_scores) if risk_scores else 0.0

        cred = ReadinessCredential(
            issuer=self.name,
            subject=subject,
            issued_at=datetime.now(timezone.utc).isoformat(),
            total_assets=total,
            quantum_safe_assets=safe,
            max_risk_score=round(max_risk, 2),
            readiness_level=readiness_level,
            all_quantum_safe=(safe == total and total > 0),
            commitment_root=tree.root_hex(),
            commitment_count=total,
            public_key=self.public_key_b64(),
        )

        signature = self._private_key.sign(_canonical_bytes(cred.claims_payload()))
        cred.signature = base64.b64encode(signature).decode("ascii")
        return cred


@dataclass
class VerificationResult:
    """Outcome of verifying a readiness credential."""

    signature_valid: bool
    claims: dict
    messages: list[str] = field(default_factory=list)

    @property
    def trusted(self) -> bool:
        return self.signature_valid


def verify_credential(
    credential: ReadinessCredential,
    expected_issuer_pubkey: Optional[str] = None,
) -> VerificationResult:
    """Verify a readiness credential's authenticity.

    Confirms the issuer's signature over the aggregate claims. The verifier
    learns ONLY the aggregate claims (asset counts, readiness level,
    commitment root) -- never the underlying asset identities or configs.

    Args:
        credential: The credential to verify.
        expected_issuer_pubkey: Optionally pin the expected issuer public key
            (base64). If omitted, the embedded key is used (trust-on-first-use).

    Returns:
        VerificationResult with validity and the disclosed claims.
    """
    messages = []
    pubkey_b64 = expected_issuer_pubkey or credential.public_key

    if not pubkey_b64:
        return VerificationResult(False, {}, ["No issuer public key available"])

    if expected_issuer_pubkey and expected_issuer_pubkey != credential.public_key:
        messages.append("Embedded public key does not match the pinned issuer key")
        return VerificationResult(False, credential.claims_payload(), messages)

    try:
        pub = ed25519.Ed25519PublicKey.from_public_bytes(base64.b64decode(pubkey_b64))
        sig = base64.b64decode(credential.signature)
        pub.verify(sig, _canonical_bytes(credential.claims_payload()))
        signature_valid = True
        messages.append("Issuer signature is valid")
    except (InvalidSignature, ValueError, Exception) as e:
        signature_valid = False
        messages.append(f"Signature verification failed: {e}")

    return VerificationResult(signature_valid, credential.claims_payload(), messages)


def build_asset_records(tls_results=None, cloud_result=None) -> tuple[list[str], list[float]]:
    """Turn scan results into (secret) per-asset records and their risk scores.

    The records are the data that stays private. Each record is a compact
    descriptor; only its hash ever leaves the holder via the Merkle root.

    Returns:
        Tuple of (asset_records, risk_scores).
    """
    import secrets

    records = []
    scores = []

    if tls_results:
        for r in tls_results:
            # Salt each record so identical configs don't produce equal hashes
            salt = secrets.token_hex(8)
            records.append(f"tls|{r.host}:{r.port}|{r.cipher_suite}|risk={r.risk_score}|{salt}")
            scores.append(r.risk_score)

    if cloud_result:
        for f in cloud_result.findings:
            salt = secrets.token_hex(8)
            risk = f.profile.risk_score if f.profile else 0.0
            records.append(
                f"cloud|{f.resource_type}/{f.resource_name}|{f.algorithm}|risk={risk}|{salt}"
            )
            scores.append(risk)

    return records, scores
