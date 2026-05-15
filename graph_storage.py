"""
graph_storage.py
================
Neo4j-style policy-constrained graph database for EHR metadata and a
MinIO-style blob store for ciphertext payloads.

The graph stores:
  - Doctor nodes (did, attrs)
  - Patient nodes (PID)
  - Record nodes (RID, patient_pid, policy_id, phi=metadata digest, uri)
  - Key nodes (RID, ABE ciphertext fingerprint)
  - AccessEvent nodes (session_id, did, RID, t, h_pi)

Edges:
  - Doctor --LOOKS_AFTER--> Patient
  - Patient --HAS_RECORD--> Record
  - Record --SECURED_BY--> Key
  - Doctor --INITIATES--> AccessEvent
  - AccessEvent --SATISFIES_POLICY--> Key

Policy-constrained traversal: only records whose policy is satisfied by the
caller's attributes are returned. This enforces "access-before-discovery"
preventing enumeration of records the caller can't read.
"""
from __future__ import annotations
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


# -----------------------------------------------------------------------------
# Graph entities
# -----------------------------------------------------------------------------
@dataclass
class DoctorNode:
    did: str
    attrs: Set[str]
    domain: str


@dataclass
class PatientNode:
    pid: str
    home_domain: str


@dataclass
class RecordNode:
    rid: str
    patient_pid: str
    policy_id: str           # which policy gates this record
    required_attrs: List[str]  # cached for fast filtering
    phi: bytes               # metadata digest (binds to encrypted content)
    uri: str                 # pointer into blob storage
    created_at: float
    # Phase 3 Step 1: integrity commitment binding all metadata fields.
    # Computed once at insertion time from H(RID ‖ PID ‖ phi ‖ policy ‖ URI).
    # An auditor that later tampers with any field in the graph would
    # produce a different commitment, detecting the mutation (assuming
    # collision resistance of H).
    h_node: bytes = b""


@dataclass
class KeyNode:
    rid: str
    abe_ct_fingerprint: str    # short index for graph traversal / commitments
    # Actual CP-ABE ciphertext (CT_k in the paper). Held by the KMS, used at
    # decryption time. Typed as Any here to avoid a circular import with abe.py.
    abe_ct: Any = None


@dataclass
class AccessEvent:
    session_id: str
    did: str
    rid: str
    timestamp: float
    h_pi: str    # hash of the ZK proof that authorized access


# -----------------------------------------------------------------------------
# Graph database
# -----------------------------------------------------------------------------
class GraphDB:
    def __init__(self):
        self.doctors: Dict[str, DoctorNode] = {}
        self.patients: Dict[str, PatientNode] = {}
        self.records: Dict[str, RecordNode] = {}
        self.keys: Dict[str, KeyNode] = {}
        self.access_events: List[AccessEvent] = []
        # Edges as adjacency
        self.looks_after: Dict[str, Set[str]] = {}     # did -> {pid}
        self.has_record: Dict[str, Set[str]] = {}      # pid -> {rid}
        self._lock = threading.Lock()

    # Node insertions
    def add_doctor(self, d: DoctorNode):
        with self._lock:
            self.doctors[d.did] = d

    def add_patient(self, p: PatientNode):
        with self._lock:
            self.patients[p.pid] = p

    def add_record(self, r: RecordNode, k: KeyNode):
        with self._lock:
            self.records[r.rid] = r
            self.keys[r.rid] = k
            self.has_record.setdefault(r.patient_pid, set()).add(r.rid)

    def link_doctor_patient(self, did: str, pid: str):
        with self._lock:
            self.looks_after.setdefault(did, set()).add(pid)

    def log_access(self, ev: AccessEvent):
        with self._lock:
            self.access_events.append(ev)

    # Policy-constrained traversal
    def policy_constrained_records(self, did: str, pid: str, caller_attrs: Set[str]) -> List[RecordNode]:
        """Return only records whose policy is satisfied by the caller's attrs."""
        with self._lock:
            # First check the doctor-patient edge exists (access-before-discovery)
            if pid not in self.looks_after.get(did, set()):
                return []
            results = []
            for rid in self.has_record.get(pid, set()):
                rec = self.records.get(rid)
                if rec is None:
                    continue
                if set(rec.required_attrs).issubset(caller_attrs):
                    results.append(rec)
            return results

    def get_record(self, rid: str) -> Optional[RecordNode]:
        return self.records.get(rid)

    def get_key(self, rid: str) -> Optional[KeyNode]:
        return self.keys.get(rid)


# -----------------------------------------------------------------------------
# MinIO-style blob store
# -----------------------------------------------------------------------------
class BlobStore:
    """In-memory blob storage. Stores opaque bytes by URI."""

    def __init__(self):
        self._blobs: Dict[str, bytes] = {}
        self._lock = threading.Lock()

    def put(self, data: bytes) -> str:
        uri = f"blob://{secrets.token_hex(16)}"
        with self._lock:
            self._blobs[uri] = data
        return uri

    def get(self, uri: str) -> Optional[bytes]:
        with self._lock:
            return self._blobs.get(uri)

    def size(self) -> int:
        return sum(len(v) for v in self._blobs.values())


# -----------------------------------------------------------------------------
# Redis-style emergency cache (TTL-based hot tier)
# -----------------------------------------------------------------------------
class EmergencyCache:
    """Time-to-live cache for emergency-tier EHR data."""

    def __init__(self):
        # uri -> (data, expiry_timestamp)
        self._cache: Dict[str, Tuple[bytes, float]] = {}
        self._lock = threading.Lock()

    def put(self, uri: str, data: bytes, ttl_seconds: float):
        with self._lock:
            self._cache[uri] = (data, time.time() + ttl_seconds)

    def get(self, uri: str) -> Optional[bytes]:
        with self._lock:
            entry = self._cache.get(uri)
            if entry is None:
                return None
            data, expiry = entry
            if time.time() > expiry:
                del self._cache[uri]
                return None
            return data


if __name__ == "__main__":
    g = GraphDB()
    g.add_doctor(DoctorNode("did:doc:alice", {"doctor", "cardiologist"}, "hospital_A"))
    g.add_doctor(DoctorNode("did:doc:bob", {"doctor"}, "hospital_B"))
    g.add_patient(PatientNode("PID:p42", "hospital_A"))
    g.link_doctor_patient("did:doc:alice", "PID:p42")
    g.link_doctor_patient("did:doc:bob", "PID:p42")
    g.add_record(
        RecordNode(rid="R1", patient_pid="PID:p42", policy_id="cardio_v1",
                   required_attrs=["doctor", "cardiologist"], phi=b"phi1", uri="blob://x", created_at=time.time()),
        KeyNode(rid="R1", abe_ct_fingerprint="abcd"),
    )
    # alice has the right attrs
    rs = g.policy_constrained_records("did:doc:alice", "PID:p42", {"doctor", "cardiologist"})
    assert len(rs) == 1 and rs[0].rid == "R1"
    # bob doesn't
    rs = g.policy_constrained_records("did:doc:bob", "PID:p42", {"doctor"})
    assert len(rs) == 0
    print("graph_storage OK")
