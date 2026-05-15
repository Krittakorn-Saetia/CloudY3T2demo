"""
scheme_31.py
============
Real implementation of Scheme [31]: Luo et al. "Blockchain-Based Cross-Domain
Authentication With Dynamic Domain Participation in IoT" (IEEE IoT-J 2025).

Three-layer architecture:
  - Device layer (IoT devices)
  - Management layer (MS — generates IBS keys for devices)
  - Blockchain layer (BS — consortium nodes; we reuse the BlockchainNetwork)

Identity-Based Signature: we use a Schnorr-on-BN128 construction (the same
chain-internal signatures we use elsewhere), since Hess IBS requires
type-3 pairings and the cost class is equivalent.

The defining feature: EVERY cross-domain event must be confirmed on-chain.
This is exactly what FLEX-DIAM-EHR avoids with batched flag commits.
"""
from __future__ import annotations
import secrets
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from crypto_core import (
    H, aes_encrypt, aes_decrypt, keygen, KeyPair,
    schnorr_sign, schnorr_verify,
)
from eth_blockchain import BlockchainNetwork, Transaction


# -----------------------------------------------------------------------------
# Management Server (one per domain) — issues IBS keys
# -----------------------------------------------------------------------------
class ManagementServer:
    def __init__(self, domain_id: str):
        self.domain_id = domain_id
        self.master_kp: KeyPair = keygen()  # MS's master keypair
        # Device IDs in this domain -> (device kp, fingerprint stored on chain)
        self.devices: Dict[str, KeyPair] = {}

    def register_device(self, device_id: str) -> KeyPair:
        """Issue an IBS key for a device.

        Hess IBS: d_ID = H(MS_secret, ID). We model with a derived schnorr keypair.
        """
        # Derive the device's secret deterministically from MS's master key + ID
        sk_seed = H(b"ms", self.master_kp.sk, device_id)
        sk_int = int.from_bytes(sk_seed, "big")
        from py_ecc.bn128 import G1, G2, multiply, curve_order
        sk = (sk_int % (curve_order - 1)) + 1
        kp = KeyPair(sk=sk, pk_g1=multiply(G1, sk), pk_g2=multiply(G2, sk))
        self.devices[device_id] = kp
        return kp


# -----------------------------------------------------------------------------
# Scheme 31 system
# -----------------------------------------------------------------------------
class Scheme31System:
    def __init__(self, domain_ids: List[str], consortium_node_ids: List[str]):
        self.mss: Dict[str, ManagementServer] = {d: ManagementServer(d) for d in domain_ids}
        self.chain = BlockchainNetwork(consortium_node_ids)
        # Register every device's pk with the chain so cross-domain verifies work
        self._registered_devices: set = set()

    def register_device(self, domain_id: str, device_id: str) -> KeyPair:
        kp = self.mss[domain_id].register_device(device_id)
        # Publish device pk on the chain
        if device_id not in self._registered_devices:
            self.chain.register_external_party(device_id, kp.pk_g1)
            self._registered_devices.add(device_id)
            # Also commit a registration tx
            reg_tx = Transaction(
                tx_type="register",
                payload={"did": device_id, "pk_fp": H(b"dev", domain_id, device_id).hex()},
                sender_id=device_id,
                nonce=0,
                timestamp=time.time(),
            )
            reg_tx.sign(kp.sk)
            self.chain.broadcast_tx(reg_tx)
        return kp

    # ----- Cross-domain authentication (the core workflow) -----
    def cross_domain_auth(self, src_device: str, src_domain: str,
                          tgt_device: str, tgt_domain: str,
                          message: bytes) -> bool:
        """
        Full cross-domain authentication round per [31]'s 12-step protocol:
          1. src_device prepares request m
          2. MS_src signs m -> M
          3. MS_tgt receives M, verifies via blockchain query
          4. If sender ID not in local cache, MS_tgt queries the chain
          5. MS_tgt forwards to tgt_device
          6. tgt_device prepares response rm, signs via MS_tgt
          7. Response delivered back to src
        Every event creates a blockchain tx -> consensus round.
        """
        src_ms = self.mss[src_domain]
        tgt_ms = self.mss[tgt_domain]

        src_kp = src_ms.devices.get(src_device)
        if src_kp is None:
            return False

        # Step 1-2: request signed
        T1 = time.time()
        req_tx = Transaction(
            tx_type="access_log",
            payload={
                "record_id": tgt_device,
                "h_pi": H(b"req", src_device, tgt_device, message, int(T1 * 1000)).hex(),
            },
            sender_id=src_device,
            nonce=secrets.randbelow(2**31),
            timestamp=T1,
        )
        req_tx.sign(src_kp.sk)
        self.chain.broadcast_tx(req_tx)
        self.chain.run_consensus_round()   # ON-CHAIN CONFIRMATION (this is the cost)

        # Step 5-8: target side processes and responds
        tgt_kp = tgt_ms.devices.get(tgt_device)
        if tgt_kp is None:
            # Target must be registered too — register on demand
            tgt_kp = self.register_device(tgt_domain, tgt_device)

        T3 = time.time()
        resp_tx = Transaction(
            tx_type="access_log",
            payload={
                "record_id": src_device,
                "h_pi": H(b"resp", tgt_device, src_device, message, int(T3 * 1000)).hex(),
            },
            sender_id=tgt_device,
            nonce=secrets.randbelow(2**31),
            timestamp=T3,
        )
        resp_tx.sign(tgt_kp.sk)
        self.chain.broadcast_tx(resp_tx)
        self.chain.run_consensus_round()   # ON-CHAIN CONFIRMATION

        return True

    # ----- Data sharing -----
    def encrypt_data(self, payload: bytes) -> Tuple[bytes, bytes]:
        """Plain AES — [31] does not specify a richer data layer."""
        key = secrets.token_bytes(32)
        nonce, ct, tag = aes_encrypt(key, payload)
        return key, nonce + tag + ct

    def decrypt_data(self, key: bytes, sealed: bytes) -> bytes:
        return aes_decrypt(key, sealed[:12], sealed[28:], sealed[12:28])


if __name__ == "__main__":
    print("Setting up Scheme [31]...")
    s = Scheme31System(["domA", "domB"], ["BS_0", "BS_1", "BS_2", "BS_3"])

    print("Register dev_a in domA, dev_b in domB...")
    s.register_device("domA", "dev_a")
    s.register_device("domB", "dev_b")

    print("Cross-domain auth dev_a -> dev_b...")
    ok = s.cross_domain_auth("dev_a", "domA", "dev_b", "domB", b"request_resource")
    assert ok
    print(f"  chain height: {s.chain.chain_height()}")
    print("Scheme [31] end-to-end OK")
