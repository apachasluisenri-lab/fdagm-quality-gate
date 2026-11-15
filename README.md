# FDAGM-QualityGate: Privacy-Preserving Federated Semantic Validation

Reproducible benchmark and reference engine for ISO 8000-110/120/130/140 edge validation with RFC 8785 JCS, SHA-256 Merkle proofs, W3C DID Ed25519 signatures, and active W3C DPV Zero-PII inspection.

## Quickstart

    python3 -m venv .venv && source .venv/bin/activate
    pip install cryptography pyshacl rdflib numpy matplotlib
    python benchmark_full.py
