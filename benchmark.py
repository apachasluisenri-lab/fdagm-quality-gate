import copy
import random
import time
import tracemalloc
import numpy as np
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pyshacl import validate as shacl_validate
from rdflib import Graph

from engine import CompiledISOQualityGate, ISOPolicySpec, MerkleTree

SHACL_SHAPES_TTL = """
@prefix sh: <http://www.w3.org/ns/shacl#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix iso8000: <https://standards.iso.org/iso/8000/> .
@prefix prov: <http://www.w3.org/ns/prov#> .
@prefix fdagm: <https://w3id.org/fdagm#> .

fdagm:AssertionShape a sh:NodeShape ;
    sh:targetClass fdagm:DataProductAssertion ;
    sh:property [
        sh:path iso8000:semanticEncodingURI ;
        sh:minCount 1 ;
        sh:pattern "^https://" ;
    ] ;
    sh:property [
        sh:path iso8000:syntacticAccuracy ;
        sh:minCount 1 ;
        sh:minInclusive 0.99 ;
    ] ;
    sh:property [
        sh:path iso8000:completenessScore ;
        sh:minCount 1 ;
        sh:minInclusive 1.0 ;
    ] .
"""

SHAPES_GRAPH = Graph().parse(data=SHACL_SHAPES_TTL, format="turtle")


def run_shacl_baseline(assertion: dict) -> bool:
    ttl_data = f"""
    @prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
    @prefix iso8000: <https://standards.iso.org/iso/8000/> .
    @prefix fdagm: <https://w3id.org/fdagm#> .

    fdagm:item1 a fdagm:DataProductAssertion ;
        iso8000:semanticEncodingURI "{assertion.get('iso8000:semanticEncodingURI', '')}" ;
        iso8000:syntacticAccuracy "{assertion.get('iso8000:qualityMetrics', {}).get('iso8000:syntacticAccuracy', 0)}"^^xsd:decimal ;
        iso8000:completenessScore "{assertion.get('iso8000:qualityMetrics', {}).get('iso8000:completenessScore', 0)}"^^xsd:decimal .
    """
    data_graph = Graph().parse(data=ttl_data, format="turtle")
    conforms, _, _ = shacl_validate(data_graph, shacl_graph=SHAPES_GRAPH, inference="none")
    return bool(conforms)


def build_valid_assertion(did: str, priv_key: Ed25519PrivateKey, idx: int) -> dict:
    records = [
        {
            "contract_id": f"OSCE-2026-{idx:06d}-{j}",
            "sector_code": "80101500",
            "amount_pen": round(15000.0 + j * 125.5, 2),
            "region_ubigeo": "070101",
        }
        for j in range(10)
    ]
    root = MerkleTree.compute_root(records)
    sig = priv_key.sign(bytes.fromhex(root)).hex()

    return {
        "@context": {
            "iso8000": "https://standards.iso.org/iso/8000/",
            "prov": "http://www.w3.org/ns/prov#",
            "dpv": "https://w3id.org/dpv#",
            "fdagm": "https://w3id.org/fdagm#",
        },
        "@type": "fdagm:DataProductAssertion",
        "iso8000:semanticEncodingURI": "https://standards.iso.org/iso/8000/110/public-procurement",
        "prov:wasAttributedTo": {"identifier": did},
        "iso8000:qualityMetrics": {
            "iso8000:syntacticAccuracy": 0.996,
            "iso8000:completenessScore": 1.0,
        },
        "fdagm:aggregatedDataProduct": records,
        "fdagm:cryptographicProof": {
            "hashAlgorithm": "SHA-256",
            "merkleRootHash": root,
            "ed25519Signature": sig,
        },
    }


def inject_fault(assertion: dict, fault_type: str) -> dict:
    corrupted = copy.deepcopy(assertion)
    if fault_type == "SEMANTIC_DRIFT":
        corrupted["iso8000:semanticEncodingURI"] = "http://untrusted-local.org/schema"
    elif fault_type == "DID_SPOOF":
        corrupted["prov:wasAttributedTo"]["identifier"] = "invalid-entity-id"
    elif fault_type == "QUALITY_DEGRADATION":
        corrupted["iso8000:qualityMetrics"]["iso8000:syntacticAccuracy"] = 0.91
    elif fault_type == "COVERT_PII_DNI":
        corrupted["fdagm:aggregatedDataProduct"][0]["notes"] = "Titular DNI 41829304"
    elif fault_type == "DPV_TAG_EXPOSURE":
        corrupted["fdagm:aggregatedDataProduct"][0]["dpv:hasPersonalData"] = "dpv:NationalID"
    elif fault_type == "MERKLE_TAMPERING":
        corrupted["fdagm:aggregatedDataProduct"][0]["amount_pen"] = 9999999.99
    return corrupted


if __name__ == "__main__":
    priv_key = Ed25519PrivateKey.generate()
    pub_key = priv_key.public_key()
    issuer_did = "did:web:gob.pe:osce:node-01"

    gate = CompiledISOQualityGate(
        policy=ISOPolicySpec(),
        trusted_did_keys={issuer_did: pub_key},
    )

    N_BENCH = 500
    dataset = [build_valid_assertion(issuer_did, priv_key, i) for i in range(N_BENCH)]

    tracemalloc.start()
    ours_latencies_ms = []
    for item in dataset:
        t0 = time.perf_counter()
        ok, _ = gate.verify(item)
        t1 = time.perf_counter()
        assert ok
        ours_latencies_ms.append((t1 - t0) * 1000.0)
    _, ours_peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    tracemalloc.start()
    shacl_latencies_ms = []
    for item in dataset:
        t0 = time.perf_counter()
        ok = run_shacl_baseline(item)
        t1 = time.perf_counter()
        assert ok
        shacl_latencies_ms.append((t1 - t0) * 1000.0)
    _, shacl_peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    print("=== TABLA A: RENDIMIENTO COMPUTACIONAL (N=500 ASERCIONES) ===")
    for name, lats, mem in [
        ("W3C SHACL Baseline (pySHACL)", shacl_latencies_ms, shacl_peak_mem),
        ("Ours (Compiled ISO-as-Code + Merkle/Ed25519)", ours_latencies_ms, ours_peak_mem),
    ]:
        p50 = np.percentile(lats, 50)
        p95 = np.percentile(lats, 95)
        p99 = np.percentile(lats, 99)
        tput = 1000.0 / np.mean(lats)
        print(
            f"{name:45s} | P50: {p50:7.3f} ms | P95: {p95:7.3f} ms | "
            f"P99: {p99:7.3f} ms | Throughput: {tput:8.1f} req/s | PeakRAM: {mem/1024:.1f} KB"
        )

    fault_classes = [
        "SEMANTIC_DRIFT",
        "DID_SPOOF",
        "QUALITY_DEGRADATION",
        "COVERT_PII_DNI",
        "DPV_TAG_EXPOSURE",
        "MERKLE_TAMPERING",
    ]
    random.seed(42)
    tp_ours = tp_shacl = 0
    for i in range(600):
        ftype = fault_classes[i % len(fault_classes)]
        bad_item = inject_fault(dataset[i % N_BENCH], ftype)

        ok_ours, _ = gate.verify(bad_item)
        if not ok_ours:
            tp_ours += 1

        ok_shacl = run_shacl_baseline(bad_item)
        if not ok_shacl:
            tp_shacl += 1

    print("\n=== TABLA B: DETECCIÓN DE ANOMALÍAS (600 PAYLOADS CORRUPTOS) ===")
    print(f"W3C SHACL Baseline -> Detectados: {tp_shacl}/600 (Recall: {tp_shacl/600*100:.2f}%)")
    print(f"Ours (ISO-as-Code) -> Detectados: {tp_ours}/600 (Recall: {tp_ours/600*100:.2f}%)")
