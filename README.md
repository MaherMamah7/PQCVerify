# PQCVerify

A proof-of-concept AI-assisted verification layer for post-quantum cryptography (PQC) readiness. Is still under construction. Some of the points discussed below are stuff I wanna add to the repo.

Most tools in this space are **scanners** — they answer *"what encryption is here?"* PQCVerify answers a harder, more useful question: *"does this system, taken as a whole, actually deliver quantum-safe protection?"* It verifies **emergent properties of the assembled system** — properties that can be false even when every individual component looks fine — and returns a clear verdict: **Verified, Partially Verified, Not Verified, or Insufficient Evidence**, each with plain-language reasoning and a concrete next step.

## Why this is verification, not scanning

A scanner inventories components in isolation. PQCVerify checks properties that only exist because of how the pieces fit together, and that a scanner structurally cannot answer:

- **Downgrade paths.** A server can offer post-quantum key exchange *and* still allow a classical fallback. A scanner sees PQC present and says "good." An attacker forces the negotiation down to the classical option. PQCVerify probes the **floor** of the negotiation space, not the preferred cipher, and fails the system if a downgrade path exists.
- **Whole trust chains.** A leaf certificate can be quantum-safe while chaining up to a classical root CA. The chain is only as strong as its weakest certificate. PQCVerify verifies every certificate from leaf to root.
- **End-to-end data paths.** A PQC-enabled front door is worthless if the internal hop to the database is classical or plaintext. PQCVerify traces the real path sensitive data travels and verifies its weakest hop.

Each is a relationship or an absence (the weakest link on a path, the absence of a bypass), not the presence of a good component. That is the difference between a scanner and a verification layer.

## What It Does

- **Verification engine** *(core)*: Verifies system-level properties (PQV-DG, PQV-CH, PQV-DP), each producing a verdict, plain-language rationale, and remediation.
- **Active TLS prober**: Performs multiple real handshakes to map the negotiation floor and retrieve the full certificate chain — wire ground truth, not a single observation.
- **Data-path model**: Verifies the weakest link along a declared end-to-end data flow.
- **Privacy-preserving attestation**: Seals a result into a signed credential that proves readiness claims to third parties without exposing internal hosts or configs.

## Quick Start

```bash
pip install -r requirements.txt

# Verify system-level properties of a live endpoint
python -m pqc_scanner verify-system --url example.com --subject "AcmeCorp"

# Add end-to-end data-path verification (internal hops a scanner can't see)
python -m pqc_scanner verify-system --url example.com \
    --data-path ./examples/data_path.json --subject "AcmeCorp"

# Machine-readable verdicts
python -m pqc_scanner verify-system --url example.com --json-output

# Underlying evidence-gathering commands are still available:
python -m pqc_scanner scan-url https://example.com
python -m pqc_scanner scan-cloud ./terraform/
python -m pqc_scanner report --url https://example.com --cloud-dir ./configs/
```

## Verification Controls (system properties)

| ID | Property verified | Why a scanner can't do it |
|----|-------------------|---------------------------|
| PQV-DG | No quantum-vulnerable downgrade path | Requires probing the *floor* of the negotiation space (many handshakes), not the preferred cipher |
| PQV-CH | Entire certificate trust chain is quantum-safe | Requires evaluating the *whole chain* leaf→root, not just the leaf |
| PQV-DP | End-to-end data path's weakest hop is quantum-safe | Requires modeling the *path* data travels, including internal hops not externally observable |

Each control returns `verified` / `partially_verified` / `not_verified` / `insufficient_evidence`. The overall verdict follows the **weakest-link** rule: any failed property fails the system.

## Project Structure

```
pqc_scanner/
├── __init__.py
├── __main__.py          # CLI entry point
├── verification.py      # Verification engine — property-level controls & verdicts (core)
├── tls_probe.py         # Active TLS probing: negotiation floor + full trust chain
├── datapath.py          # End-to-end data-path weakest-link verification
├── tls_scanner.py       # Single-endpoint TLS/certificate evidence
├── cloud_analyzer.py    # Cloud config crypto evidence
├── crypto_classify.py   # Algorithm classification & risk scoring
├── attestation.py       # Privacy-preserving readiness credentials
└── reporter.py          # Report generation
```

## Post-Quantum Context

NIST has standardized post-quantum algorithms (ML-KEM, ML-DSA, SLH-DSA). Current widely-deployed algorithms like RSA, ECDSA, and ECDH are vulnerable to Shor's algorithm on a sufficiently powerful quantum computer. This tool helps organizations understand their cryptographic exposure and plan migration to quantum-safe alternatives.

### Vulnerability Classification

| Algorithm | Type | Quantum Threat | Recommended Replacement |
|-----------|------|---------------|------------------------|
| RSA | Signature/KE | HIGH - Shor's algorithm | ML-DSA (FIPS 204) |
| ECDSA | Signature | HIGH - Shor's algorithm | ML-DSA (FIPS 204) |
| ECDH | Key Exchange | HIGH - Shor's algorithm | ML-KEM (FIPS 203) |
| AES-128 | Symmetric | MEDIUM - Grover's algorithm | AES-256 |
| AES-256 | Symmetric | LOW | Retain |
| SHA-256 | Hash | LOW | Retain |

## Status

**Proof of Concept** — Not intended for production security auditing.

## License

MIT
