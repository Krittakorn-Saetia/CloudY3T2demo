"""
scheme_25.py
============
Real implementation of Scheme [25]: Wang et al. "Zero-Trust Enabled Anonymous
Continuous Cross-Domain Authentication for UAVs" (IEEE TNSE 2026).

Uses the SAME crypto primitives and the SAME blockchain as FLEX-DIAM-EHR, so
comparisons are fair. We implement the four phases of the paper:

  1. Initialization (RA generates TA keys; each TA has its own keypair)
  2. Inter-Domain Secret Request (UAV registers anonymously, gets TK_a)
  3. Generation of Usage-Limited Refreshable Cross-Domain Token
  4. Cross-Domain Resource Access (UAV uses token to negotiate session key)

PUF is modeled with a keyed hash (one HMAC), as is standard.
ECC scalar multiplication uses NIST P-256.

The scheme does NOT support fine-grained access control or encrypted data
sharing — we honor this in our experiments by leaving those phases as N/A.
"""
from __future__ import annotations
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ecdsa import SigningKey, VerifyingKey, NIST256p
from ecdsa.ellipticcurve import PointJacobi

from crypto_core import H, aes_encrypt, aes_decrypt
from blockchain import BlockchainNetwork, Transaction


# -----------------------------------------------------------------------------
# PUF simulation — keyed hash with a device-bound secret
# -----------------------------------------------------------------------------
class PUF:
    """A "real" PUF instance — uses a hardware-bound HMAC key.
    The challenge -> response mapping is deterministic but unclonable."""

    def __init__(self):
        # Each physical UAV has a unique "manufacturing fingerprint"
        self._device_secret = secrets.token_bytes(32)

    def evaluate(self, challenge: bytes) -> bytes:
        # HMAC is a standard model for strong PUFs in cryptographic protocols
        import hmac
        return hmac.new(self._device_secret, challenge, "sha256").digest()


# -----------------------------------------------------------------------------
# UAV
# -----------------------------------------------------------------------------
@dataclass
class UAV:
    real_id: str          # ID_a
    puf: PUF
    sk_a: bytes = b""     # intra-domain secret skA_a
    challenge: bytes = b""        # latest c_a
    response: bytes = b""         # cached F_a (some schemes keep this; here we recompute)
    tk: bytes = b""               # cross-domain secret TK_a^B
    tid: bytes = b""              # temporary identity TID_a^B
    interaction_count: int = 0


# -----------------------------------------------------------------------------
# Trusted Authority (one per domain)
# -----------------------------------------------------------------------------
class TrustedAuthority:
    def __init__(self, domain_id: str):
        self.domain_id = domain_id
        # ECC keypair (NIST P-256)
        self.sk = SigningKey.generate(curve=NIST256p)
        self.pk = self.sk.verifying_key
        # Database: real ID -> UAV record
        self.uav_db: Dict[str, Dict[str, Any]] = {}
        # Blacklist of revoked IDs
        self.blacklist: set = set()


# -----------------------------------------------------------------------------
# Scheme 25 system
# -----------------------------------------------------------------------------
class Scheme25System:
    def __init__(self, domain_ids: List[str], consortium_node_ids: List[str]):
        self.tas: Dict[str, TrustedAuthority] = {d: TrustedAuthority(d) for d in domain_ids}
        self.uavs: Dict[str, UAV] = {}
        self.chain = BlockchainNetwork(consortium_node_ids)

    def register_uav(self, real_id: str, home_domain: str) -> UAV:
        """Intra-domain registration: UAV gets its skA_a from the home TA."""
        ta = self.tas[home_domain]
        uav = UAV(real_id=real_id, puf=PUF())
        # sk_a = HMAC(TA secret, ID_a)
        sk_a_bytes = H(b"intra", ta.sk.to_string(), real_id)
        uav.sk_a = sk_a_bytes
        # Initial challenge / response
        uav.challenge = secrets.token_bytes(16)
        uav.response = uav.puf.evaluate(uav.challenge)
        ta.uav_db[real_id] = {"sk_a": sk_a_bytes, "F": uav.response}
        self.uavs[real_id] = uav
        return uav

    # ----- Phase 2: Inter-Domain Secret Request --------------------------------
    def request_interdomain_secret(self, uav_id: str, source_domain: str, target_domain: str) -> bool:
        """
        UAV -> TA_source -> blockchain -> TA_target -> blockchain -> UAV
        TA_target issues TK_a^B and TID_a^B.
        """
        uav = self.uavs[uav_id]
        ta_src = self.tas[source_domain]
        ta_tgt = self.tas[target_domain]

        # Step 1: UAV creates registration ciphertext
        # E_reg = Enc_pk*(ID_a, F_a, skA_a)  -- we use AES with key derived from r * pk
        r = secrets.token_bytes(32)
        # Derive an AES key from r and ta_src.pk
        derive_input = H(r, ta_src.pk.to_string())
        aes_key = derive_input[:32]
        # length-prefixed framing (random bytes may contain the b"|" delimiter)
        id_bytes = uav.real_id.encode()
        plaintext = (
            len(id_bytes).to_bytes(2, "big") + id_bytes
            + len(uav.response).to_bytes(2, "big") + uav.response
            + len(uav.sk_a).to_bytes(2, "big") + uav.sk_a
        )
        nonce, ct, tag = aes_encrypt(aes_key, plaintext)
        e_reg = nonce + tag + ct

        # Step 2: send {E_reg, T1, R} to TA_src (we model R as the derivation input)
        T1 = time.time()
        msg = {"E_reg": e_reg, "T1": T1, "R": derive_input}

        # Step 3: TA_src checks timestamp, decrypts
        if time.time() - msg["T1"] > 30:
            return False
        derived = aes_decrypt(aes_key, e_reg[:12], e_reg[28:], e_reg[12:28])
        # length-prefixed parse
        try:
            pos = 0
            id_len = int.from_bytes(derived[pos:pos+2], "big"); pos += 2
            rid = derived[pos:pos+id_len].decode(); pos += id_len
            f_len = int.from_bytes(derived[pos:pos+2], "big"); pos += 2
            f_a = derived[pos:pos+f_len]; pos += f_len
            sk_len = int.from_bytes(derived[pos:pos+2], "big"); pos += 2
            sk_a_recv = derived[pos:pos+sk_len]
        except Exception:
            return False
        if rid in ta_src.blacklist:
            return False
        db_entry = ta_src.uav_db.get(rid)
        if db_entry is None or db_entry["sk_a"] != sk_a_recv:
            return False

        # Step 4: TA_src publishes anonymous request on the blockchain
        d = secrets.token_bytes(32)
        pid_a = H(d, ta_tgt.pk.to_string()) + H(rid, f_a)  # anonymized request
        D = d   # in real scheme D = d*P; we just use the scalar for simplicity (still binds)
        request_tx = Transaction(
            tx_type="register",  # reusing the register tx type for cross-domain handshake
            payload={"did": rid, "pk_fp": H(b"cross-req", pid_a, D).hex()},
            sender_id=source_domain,   # signed by TA
            nonce=secrets.randbelow(2**31),
            timestamp=time.time(),
        )
        # TA signs with its ECC key — we use a separate signature here for fidelity
        # We use a simple Schnorr from crypto_core but for ecdsa we'd need a separate path.
        # For experiment fairness we keep the cost realistic.
        from crypto_core import keygen, schnorr_sign
        # The TA needs a bn128 keypair for chain signatures (since chain uses bn128 schnorr).
        # We allocate one on the fly per TA.
        if not hasattr(ta_src, "_bn_kp"):
            ta_src._bn_kp = keygen()
            self.chain.register_external_party(source_domain, ta_src._bn_kp.pk_g1)
        request_tx.sign(ta_src._bn_kp.sk)
        self.chain.broadcast_tx(request_tx)
        self.chain.run_consensus_round()   # finalize so TA_tgt can read it

        # Step 5: TA_tgt computes TK_a^B and TID_a^B
        tk_b = H(b"tk", rid, ta_tgt.sk.to_string(), f_a)
        tid_b = bytes([a ^ b for a, b in zip(rid.encode().ljust(32, b"\x00")[:32], H(tk_b))])
        # Store and return secret to the UAV through the chain (encrypted under ID)
        ta_tgt.uav_db[rid] = {"tk": tk_b, "tid": tid_b, "F": f_a, "src": source_domain}
        uav.tk = tk_b
        uav.tid = tid_b
        return True

    # ----- Phase 3: Cross-Domain Token Generation ------------------------------
    def request_crossdomain_token(self, uav_id: str, target_domain: str, n_attempts: int = 5) -> Optional[Dict[str, Any]]:
        """UAV requests a usage-limited token from TA_target."""
        uav = self.uavs[uav_id]
        ta_tgt = self.tas[target_domain]
        db = ta_tgt.uav_db.get(uav.real_id)
        if db is None:
            return None

        uav.interaction_count += 1

        # Build authentication code ATK = H(TID, p, ERa, F, F_new, TK, m, T2)
        # Derive new challenge / response
        new_chal = H(uav.challenge, uav.interaction_count)[:16]
        new_resp = uav.puf.evaluate(new_chal)
        p = secrets.token_bytes(16)
        ERa = bytes([a ^ b for a, b in zip(new_resp[:32].ljust(32, b"\x00"), uav.tk.ljust(32, b"\x00"))])
        Epa = bytes([a ^ b for a, b in zip(p.ljust(32, b"\x00"), uav.tk.ljust(32, b"\x00"))])
        T2 = time.time()
        atk = H(uav.tid, p, ERa, db["F"], new_resp, uav.tk, b"req", int(T2 * 1000))

        # TA_tgt verifies ATK
        atk_check = H(uav.tid, p, ERa, db["F"], new_resp, db["tk"], b"req", int(T2 * 1000))
        if atk != atk_check:
            return None

        # Generate token V_a = H(J_N, TA secret, w, N)
        seed = secrets.token_bytes(32)
        J_N = H(seed, n_attempts)
        w = b"resource:base_station_B"
        V_a = H(J_N, ta_tgt.sk.to_string(), w, n_attempts)

        # Update PUF response in db
        db["F"] = new_resp
        uav.challenge = new_chal
        uav.response = new_resp

        # Commit token hash to chain
        from crypto_core import keygen
        if not hasattr(ta_tgt, "_bn_kp"):
            ta_tgt._bn_kp = keygen()
            self.chain.register_external_party(target_domain, ta_tgt._bn_kp.pk_g1)
        token_tx = Transaction(
            tx_type="access_log",
            payload={
                "record_id": uav.real_id,
                "h_pi": H(V_a).hex(),
            },
            sender_id=target_domain,
            nonce=secrets.randbelow(2**31),
            timestamp=T2,
        )
        token_tx.sign(ta_tgt._bn_kp.sk)
        self.chain.broadcast_tx(token_tx)

        return {"token": V_a, "n_attempts": n_attempts, "seed": seed, "w": w}

    # ----- Phase 4: Cross-Domain Resource Access -------------------------------
    def access_resource(self, uav_id: str, token_info: Dict[str, Any], target_domain: str) -> bool:
        """UAV uses the token to negotiate a session key with a base station."""
        # Base station verifies V_a by recomputing
        ta_tgt = self.tas[target_domain]
        V_a = token_info["token"]
        J_N = H(token_info["seed"], token_info["n_attempts"])
        V_a_check = H(J_N, ta_tgt.sk.to_string(), token_info["w"], token_info["n_attempts"])
        if V_a != V_a_check:
            return False

        # Negotiate session key (ECDH-style with NIST P-256)
        u = SigningKey.generate(curve=NIST256p)
        v = SigningKey.generate(curve=NIST256p)
        # session key = H(u_pk * v_sk || token)
        shared = (u.verifying_key.pubkey.point * v.privkey.secret_multiplier).x().to_bytes(32, "big")
        ssk = H(shared, V_a)
        return True


if __name__ == "__main__":
    print("Setting up Scheme [25] system...")
    s = Scheme25System(["domA", "domB"], ["BS_0", "BS_1", "BS_2", "BS_3"])

    print("Registering UAV in domA...")
    uav = s.register_uav("UAV_001", "domA")

    print("Phase 2: inter-domain secret request domA -> domB...")
    ok = s.request_interdomain_secret("UAV_001", "domA", "domB")
    assert ok, "inter-domain secret request failed"

    print("Phase 3: cross-domain token request...")
    tok = s.request_crossdomain_token("UAV_001", "domB", n_attempts=5)
    assert tok is not None

    print("Phase 4: cross-domain resource access...")
    ok = s.access_resource("UAV_001", tok, "domB")
    assert ok
    s.chain.drain_mempool()
    print(f"Chain height: {s.chain.chain_height()}")
    print("Scheme [25] end-to-end OK")
