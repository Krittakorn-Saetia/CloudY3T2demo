"""
crypto_core.py
==============
Real cryptographic primitives shared across all schemes.

Uses py_ecc.bn128 for pairing operations (asymmetric Type-3 pairing). All
schemes that need pairings use the same group, so comparisons are fair.

NOTE on performance: py_ecc is a pure-Python pairing library. A single
pairing op takes ~3-4 sec on this hardware. Production ABE/ZKP libraries
(Charm/PBC/RELIC/mcl in C) are ~100x faster. This affects absolute
timings but NOT the relative comparison across schemes — every pairing
is on the same library.
"""
from __future__ import annotations
import hashlib
import hmac
import os
import secrets
import time
from dataclasses import dataclass
from typing import Tuple, List

from py_ecc.bn128 import (
    G1, G2, multiply, add, neg, pairing, curve_order,
    FQ, FQ2, FQ12, eq,
)
from Crypto.Cipher import AES, ChaCha20_Poly1305

# Order of the BN128 group
P = curve_order


# -----------------------------------------------------------------------------
# Hashing
# -----------------------------------------------------------------------------
def H(*items) -> bytes:
    """Domain-separated SHA-256 over a list of items (bytes / str / int)."""
    h = hashlib.sha256()
    for it in items:
        if isinstance(it, int):
            it = it.to_bytes(32, "big", signed=False) if it >= 0 else (-it).to_bytes(32, "big")
        elif isinstance(it, str):
            it = it.encode()
        elif isinstance(it, bytes):
            pass
        else:
            it = str(it).encode()
        h.update(len(it).to_bytes(4, "big"))
        h.update(it)
    return h.digest()


def H_to_Zp(*items) -> int:
    """Hash to a scalar in Z_p."""
    return int.from_bytes(H(*items), "big") % P


def H_to_G1(*items):
    """Try-and-increment hash to G1."""
    counter = 0
    while True:
        x = H_to_Zp(*items, counter)
        if x != 0:
            return multiply(G1, x)
        counter += 1


# -----------------------------------------------------------------------------
# Random scalars
# -----------------------------------------------------------------------------
def rand_zp() -> int:
    return secrets.randbelow(P - 1) + 1


# -----------------------------------------------------------------------------
# Group-element serialization (for hashing / fingerprinting only)
# -----------------------------------------------------------------------------
def g1_fingerprint(pt) -> bytes:
    if pt is None:
        return b"\x00" * 32
    x, y = pt
    return H(int(x), int(y))


def gt_fingerprint(gt) -> bytes:
    if gt is None:
        return b"\x00" * 32
    coeffs = gt.coeffs
    return H(*[int(c) for c in coeffs])


# -----------------------------------------------------------------------------
# Symmetric encryption (AES-GCM for bulk, ChaCha20-Poly1305 for edge)
# -----------------------------------------------------------------------------
def aes_encrypt(key: bytes, plaintext: bytes, ad: bytes = b"") -> Tuple[bytes, bytes, bytes]:
    """Returns (nonce, ciphertext, tag)."""
    nonce = secrets.token_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    if ad:
        cipher.update(ad)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return nonce, ct, tag


def aes_decrypt(key: bytes, nonce: bytes, ct: bytes, tag: bytes, ad: bytes = b"") -> bytes:
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    if ad:
        cipher.update(ad)
    return cipher.decrypt_and_verify(ct, tag)


def chacha_encrypt(key: bytes, plaintext: bytes, ad: bytes = b"") -> Tuple[bytes, bytes, bytes]:
    nonce = secrets.token_bytes(12)
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    if ad:
        cipher.update(ad)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return nonce, ct, tag


def chacha_decrypt(key: bytes, nonce: bytes, ct: bytes, tag: bytes, ad: bytes = b"") -> bytes:
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    if ad:
        cipher.update(ad)
    return cipher.decrypt_and_verify(ct, tag)


# -----------------------------------------------------------------------------
# Schnorr-style signature on BN128 G1 (used for IBS-like signatures)
# -----------------------------------------------------------------------------
@dataclass
class KeyPair:
    sk: int          # secret scalar
    pk_g1: tuple     # public key in G1
    pk_g2: tuple     # public key in G2 (for pairing-based verifications)


def keygen() -> KeyPair:
    sk = rand_zp()
    return KeyPair(sk=sk, pk_g1=multiply(G1, sk), pk_g2=multiply(G2, sk))


def schnorr_sign(sk: int, message: bytes) -> Tuple[int, int]:
    """Schnorr signature in Z_p."""
    k = rand_zp()
    R = multiply(G1, k)
    e = H_to_Zp(g1_fingerprint(R), message)
    s = (k + e * sk) % P
    return (e, s)


def schnorr_verify(pk_g1, message: bytes, sig: Tuple[int, int]) -> bool:
    e, s = sig
    # R' = s*G - e*pk
    sG = multiply(G1, s)
    epk = multiply(pk_g1, e)
    R_prime = add(sG, neg(epk))
    e_prime = H_to_Zp(g1_fingerprint(R_prime), message)
    return e_prime == e


# -----------------------------------------------------------------------------
# Timing helper
# -----------------------------------------------------------------------------
class Timer:
    def __enter__(self):
        self.t0 = time.perf_counter()
        return self

    def __exit__(self, *a):
        self.ms = (time.perf_counter() - self.t0) * 1000

    @property
    def elapsed_ms(self) -> float:
        return (time.perf_counter() - self.t0) * 1000


if __name__ == "__main__":
    # quick sanity test
    kp = keygen()
    m = b"hello world"
    sig = schnorr_sign(kp.sk, m)
    assert schnorr_verify(kp.pk_g1, m, sig)
    print("schnorr sign/verify ok")

    k = secrets.token_bytes(32)
    n, c, t = aes_encrypt(k, b"secret data")
    assert aes_decrypt(k, n, c, t) == b"secret data"
    print("aes-gcm ok")

    print("crypto_core OK")
