"""
eth_blockchain.py
=================
Real Ethereum-backed replacement for the simulated PBFT chain in
``blockchain.py``. Same public surface (``BlockchainNetwork``, ``Transaction``,
``ChainState``) so the rest of the FLEX-DIAM-EHR codebase, the three baseline
schemes, and the experiment runners can switch with one import.

Concretely:

  * On construction, ``BlockchainNetwork`` launches a local Anvil node
    (Foundry) on 127.0.0.1:8545, compiles ``contracts/FlexDiamEHR.sol`` via
    ``py-solc-x``, and deploys it. The pre-funded Anvil account[0] becomes
    the relayer that submits every transaction.

  * Anvil's auto-mining is **disabled** at startup. ``broadcast_tx`` only
    queues the tx in Anvil's mempool. ``run_consensus_round`` calls the
    Anvil-specific ``evm_mine`` RPC, which mines every pending tx into one
    block. So **one consensus round = one Ethereum block**, mirroring the
    PBFT semantics scheme_31 depends on.

  * Each ``Transaction`` (the Python dataclass) is dispatched to a contract
    function by ``tx_type``: ``register`` → ``registerDID``, ``flag`` →
    ``recordFlag``, ``access_log`` → ``logAccess``, ``policy_commit`` →
    ``commitPolicy``, ``delegation`` → ``createDelegation``. Any unknown
    tx_type falls through to ``logCustomTx``, so generic logging from the
    scheme files still costs a real on-chain write.

  * App-layer Schnorr signatures (the BN128 ones the paper uses for
    identity binding) are still verified by ``broadcast_tx`` before
    submission — that cost is preserved. They are NOT used to authenticate
    the Ethereum tx itself; the relayer account (Anvil account[0]) signs
    every Ethereum tx with secp256k1. This mirrors a real consortium
    deployment where a hospital gateway relays signed payloads to chain.

  * ``total_chain_state()`` returns a ``ChainState`` mirrored in-memory as
    txs are applied. The mirror is updated *after* a successful receipt so
    that ``state`` only reflects what's been mined.

To re-target Sepolia (or any real RPC) instead of local Anvil:
    net = BlockchainNetwork(node_ids=[...],
                            rpc_url="https://sepolia.infura.io/v3/<key>",
                            relayer_private_key="0x...",
                            spawn_anvil=False,
                            automine=True)
"""
from __future__ import annotations
# IMPORTANT: import the py_ecc recursion patch BEFORE anything triggers a
# py_ecc import. blockchain.Transaction -> crypto_core -> py_ecc.bn128, so the
# patch must run before the `from blockchain import ...` below.
import py_ecc_patch  # noqa: F401  — monkey-patches FQP.__pow__ to be iterative

import atexit
import json
import os
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from web3 import Web3, HTTPProvider
from web3.middleware import construct_sign_and_send_raw_middleware
from eth_account import Account
import solcx

# We keep using the original Transaction dataclass + Schnorr-signing flow.
# Only the network layer changes.
from blockchain import Transaction, ChainState  # noqa: F401  (re-exported)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DEFAULT_ANVIL_PATH = os.environ.get(
    "ANVIL_PATH",
    str(Path.home() / ".tools" / "foundry" / "anvil.exe")
    if sys.platform.startswith("win")
    else "anvil",
)
DEFAULT_RPC_URL = "http://127.0.0.1:8545"
DEFAULT_SOLC_VERSION = "0.8.24"

# Anvil's first deterministic account (well-known mnemonic). Funded with
# 10000 ETH on every fresh Anvil start.
ANVIL_DEFAULT_PRIVKEY = (
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
)

CONTRACT_SOURCE_PATH = Path(__file__).parent / "contracts" / "FlexDiamEHR.sol"


# ---------------------------------------------------------------------------
# Minimal "block" object returned by run_consensus_round so callers that
# expect a Block-like value still get one. The original blockchain.Block has
# height + tx list + hash; we mirror the same shape, not the PBFT fields.
# ---------------------------------------------------------------------------
@dataclass
class EthBlock:
    height: int
    txs: List[Transaction]
    block_hash_hex: str  # Ethereum block hash, hex (with 0x)
    tx_hashes: List[str] = field(default_factory=list)

    def block_hash(self) -> bytes:
        return bytes.fromhex(self.block_hash_hex.removeprefix("0x"))


# ---------------------------------------------------------------------------
# Compile contract once per process — cached across BlockchainNetwork instances
# ---------------------------------------------------------------------------
_compiled_cache: Optional[Tuple[List[Dict], str]] = None


def _compile_contract() -> Tuple[List[Dict], str]:
    """Returns (abi, bytecode_hex). Caches across calls in the same process."""
    global _compiled_cache
    if _compiled_cache is not None:
        return _compiled_cache

    # Ensure solc is available
    try:
        solcx.set_solc_version(DEFAULT_SOLC_VERSION)
    except solcx.exceptions.SolcNotInstalled:
        solcx.install_solc(DEFAULT_SOLC_VERSION, show_progress=False)
        solcx.set_solc_version(DEFAULT_SOLC_VERSION)

    src = CONTRACT_SOURCE_PATH.read_text()
    standard_input = {
        "language": "Solidity",
        "sources": {"FlexDiamEHR.sol": {"content": src}},
        "settings": {
            "viaIR": True,
            "optimizer": {"enabled": True, "runs": 200},
            "outputSelection": {
                "*": {"*": ["abi", "evm.bytecode.object"]}
            },
        },
    }
    out = solcx.compile_standard(standard_input, solc_version=DEFAULT_SOLC_VERSION)
    contracts = out["contracts"]["FlexDiamEHR.sol"]
    abi = contracts["FlexDiamEHR"]["abi"]
    bytecode = contracts["FlexDiamEHR"]["evm"]["bytecode"]["object"]
    _compiled_cache = (abi, bytecode)
    return _compiled_cache


# ---------------------------------------------------------------------------
# Anvil process management
# ---------------------------------------------------------------------------
def _pick_free_port(host: str, preferred: int, max_offset: int = 20) -> int:
    """Return `preferred` if free, otherwise the next free port within
    `preferred + max_offset`. Raises if no port found.
    """
    for offset in range(max_offset + 1):
        port = preferred + offset
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((host, port))
            return port
        except OSError:
            continue
    raise RuntimeError(
        f"No free port found in {preferred}..{preferred + max_offset} on {host}"
    )


class _AnvilProcess:
    """One Anvil subprocess. Auto-shuts-down at interpreter exit.

    If the requested ``port`` is already bound (e.g. another Anvil from an
    earlier ``BlockchainNetwork`` in the same process), an unused port is
    chosen automatically. This is what makes ``run_real_experiments.py``
    (four scheme harnesses, four independent chains) work.
    """

    def __init__(
        self,
        anvil_path: str = DEFAULT_ANVIL_PATH,
        host: str = "127.0.0.1",
        port: int = 8545,
        block_time_secs: Optional[int] = None,  # None => manual mining only
        accounts: int = 10,
    ):
        self.host = host
        # Auto-resolve a port collision so multiple BlockchainNetwork instances
        # can coexist in the same Python process.
        self.port = _pick_free_port(host, port)
        self.url = f"http://{host}:{self.port}"
        args = [
            anvil_path,
            "--host", host,
            "--port", str(self.port),
            "--accounts", str(accounts),
            "--silent",
        ]
        if block_time_secs is not None:
            args += ["--block-time", str(block_time_secs)]
        else:
            # No auto-mine: txs sit in mempool until evm_mine is called
            args += ["--no-mining"]
        # Pipe stdout/stderr to DEVNULL so they don't clutter test output.
        self.proc = subprocess.Popen(
            args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        atexit.register(self.shutdown)
        self._wait_until_ready(timeout=15.0)

    def _wait_until_ready(self, timeout: float):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with socket.create_connection((self.host, self.port), timeout=0.5):
                    return
            except OSError:
                time.sleep(0.1)
        self.shutdown()
        raise RuntimeError(
            f"Anvil failed to start on {self.url} within {timeout}s. "
            f"Is the anvil binary at {DEFAULT_ANVIL_PATH}?"
        )

    def shutdown(self):
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=5)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass


# ---------------------------------------------------------------------------
# BlockchainNetwork — drop-in replacement
# ---------------------------------------------------------------------------
class BlockchainNetwork:
    """Ethereum-backed equivalent of ``blockchain.BlockchainNetwork``.

    Public methods preserved (used elsewhere in the codebase):
      - register_external_party(did, pk_g1)
      - lookup_pk(sender_id)
      - broadcast_tx(tx)
      - run_consensus_round(leader=None, max_txs=N)
      - drain_mempool(max_rounds=N)
      - chain_height()
      - total_chain_state()

    Constructor kept compatible with old call sites:
      BlockchainNetwork([node_id, ...])
    """

    def __init__(
        self,
        node_ids: List[str],
        *,
        rpc_url: Optional[str] = None,
        relayer_private_key: Optional[str] = None,
        spawn_anvil: bool = True,
        anvil_port: int = 8545,
        automine: bool = False,
        verbose: bool = False,
    ):
        self._node_ids = list(node_ids)
        self.verbose = verbose

        # Spin up Anvil (or connect to a remote RPC like Sepolia)
        self._anvil: Optional[_AnvilProcess] = None
        if spawn_anvil:
            self._anvil = _AnvilProcess(port=anvil_port)
            rpc_url = rpc_url or self._anvil.url
            relayer_private_key = relayer_private_key or ANVIL_DEFAULT_PRIVKEY
        else:
            if rpc_url is None or relayer_private_key is None:
                raise ValueError(
                    "When spawn_anvil=False you must pass rpc_url and "
                    "relayer_private_key explicitly."
                )

        self.w3 = Web3(HTTPProvider(rpc_url, request_kwargs={"timeout": 30}))
        if not self.w3.is_connected():
            raise RuntimeError(f"Could not connect to RPC at {rpc_url}")

        # Relayer account (Anvil account[0] by default)
        self._relayer = Account.from_key(relayer_private_key)
        self.w3.middleware_onion.add(
            construct_sign_and_send_raw_middleware(self._relayer)
        )
        self.w3.eth.default_account = self._relayer.address

        self._automine = automine
        if not automine and spawn_anvil:
            # No-op on Anvil (already started with --no-mining), but harmless
            # to confirm; on a public network we leave the network's own
            # mining behavior alone.
            try:
                self.w3.provider.make_request("evm_setAutomine", [False])
            except Exception:
                pass

        # Compile + deploy the contract
        abi, bytecode = _compile_contract()
        self.abi = abi
        if verbose:
            print(f"[eth_blockchain] deploying FlexDiamEHR.sol to {rpc_url}...")
        Contract = self.w3.eth.contract(abi=abi, bytecode=bytecode)
        deploy_tx_hash = Contract.constructor().transact({"from": self._relayer.address})
        # Deployment must be mined before we can interact
        if not automine:
            self.w3.provider.make_request("evm_mine", [])
        receipt = self.w3.eth.wait_for_transaction_receipt(deploy_tx_hash, timeout=60)
        self.contract_address = receipt.contractAddress
        self.contract = self.w3.eth.contract(address=self.contract_address, abi=abi)
        if verbose:
            print(f"[eth_blockchain] deployed at {self.contract_address}")

        # Pending Python-side mempool (mirrors original semantics)
        self._mempool: List[Transaction] = []
        # App-layer Schnorr public-key table (BN128, used for Schnorr verify)
        self._pk_table: Dict[str, Any] = {}
        # In-memory ChainState mirror, updated as txs are mined
        self.state = ChainState()
        # Track height: count only blocks we mined ourselves so values match
        # what the in-memory state reflects.
        self._height = 0
        # Latest mined block (for chain_height/head consumers)
        self._last_block: Optional[EthBlock] = None
        # Track sender nonce locally so we can issue many txs in the same round
        # without a round-trip per tx (Web3 5/6 only auto-increments after a tx
        # is mined, which doesn't work in our buffered-mining mode).
        self._local_nonce = self.w3.eth.get_transaction_count(self._relayer.address)

    # -----------------------------------------------------------------------
    # Compatibility methods used by the rest of the codebase
    # -----------------------------------------------------------------------
    def register_external_party(self, did: str, pk_g1):
        self._pk_table[did] = pk_g1

    def lookup_pk(self, sender_id: str):
        return self._pk_table.get(sender_id)

    def broadcast_tx(self, tx: Transaction) -> bool:
        """Queue a tx for the next consensus round.

        The original semantics were: validate the Schnorr signature against
        the registered sender public key, then add to mempool. We preserve
        the signature check (cost-wise it dominates anyway) and queue.
        """
        # Verify Schnorr signature if sender pk is known (skip the very first
        # registration of that DID, which is self-signed in the original).
        sender_pk = self._pk_table.get(tx.sender_id)
        if sender_pk is not None:
            if not tx.verify(sender_pk):
                return False
        elif tx.tx_type != "register":
            # Unknown sender, not a self-bootstrap register: reject
            return False
        self._mempool.append(tx)
        return True

    def run_consensus_round(
        self,
        leader=None,  # kept for API compat — Ethereum has no leader concept here
        max_txs: int = 16,
    ) -> Optional[EthBlock]:
        """Drain up to ``max_txs`` from the mempool into one mined block."""
        if not self._mempool:
            return None
        batch = self._mempool[:max_txs]
        self._mempool = self._mempool[max_txs:]

        # Submit every tx in the batch; collect Ethereum tx hashes.
        tx_hashes: List[str] = []
        accepted: List[Transaction] = []
        for tx in batch:
            try:
                th = self._submit_tx_to_contract(tx)
                if th is not None:
                    tx_hashes.append(th)
                    accepted.append(tx)
            except Exception as e:
                if self.verbose:
                    print(f"[eth_blockchain] tx dispatch failed: {e}")

        # Mine all pending txs into a single Ethereum block.
        if not self._automine:
            self.w3.provider.make_request("evm_mine", [])

        # Wait for every receipt to confirm inclusion, then mirror state.
        for th, tx in zip(tx_hashes, accepted):
            self.w3.eth.wait_for_transaction_receipt(th, timeout=60)
            self.state.apply(tx)

        # Build EthBlock summary
        latest_eth_block = self.w3.eth.get_block("latest")
        self._height += 1
        block = EthBlock(
            height=self._height,
            txs=accepted,
            block_hash_hex=latest_eth_block.hash.hex(),
            tx_hashes=tx_hashes,
        )
        self._last_block = block
        return block

    def drain_mempool(self, max_rounds: int = 100) -> int:
        rounds = 0
        while rounds < max_rounds and self._mempool:
            blk = self.run_consensus_round()
            if blk is None:
                break
            rounds += 1
        return rounds

    def chain_height(self) -> int:
        return self._height

    def total_chain_state(self) -> ChainState:
        return self.state

    @property
    def head(self) -> Optional[EthBlock]:
        return self._last_block

    # -----------------------------------------------------------------------
    # Internal: dispatch a Python Transaction to the right contract function
    # -----------------------------------------------------------------------
    def _submit_tx_to_contract(self, tx: Transaction) -> Optional[str]:
        p = tx.payload
        c = self.contract.functions

        if tx.tx_type == "register":
            fn = c.registerDID(str(p["did"]), str(p.get("pk_fp", "")))
        elif tx.tx_type == "flag":
            fn = c.recordFlag(
                str(p["patient_pid"]),
                str(p["flag_id"]),
                str(p.get("h_a", "")),
                str(p.get("h_b", "")),
                str(p.get("purpose", "")),
                str(tx.sender_id),
            )
        elif tx.tx_type == "policy_commit":
            fn = c.commitPolicy(
                str(p["h_pi"]),
                str(p.get("policy_id", "")),
                str(tx.sender_id),
            )
        elif tx.tx_type == "access_log":
            fn = c.logAccess(
                str(tx.sender_id),
                str(p.get("record_id", "")),
                str(p.get("h_pi", "")),
            )
        elif tx.tx_type == "delegation":
            fn = c.createDelegation(
                str(p["token_id"]),
                str(tx.sender_id),
                str(p.get("delegate_did", "")),
                str(p.get("scope", "")),
                int(p.get("expiry", 0) or 0),
            )
        else:
            payload_bytes = json.dumps(p, sort_keys=True, default=str).encode()
            fn = c.logCustomTx(str(tx.tx_type), str(tx.sender_id), payload_bytes)

        nonce = self._local_nonce
        self._local_nonce += 1
        tx_dict = fn.build_transaction({
            "from": self._relayer.address,
            "nonce": nonce,
            # 0 gas price works on Anvil; on a real network web3 would fill in
            "gas": 1_500_000,
        })
        signed = self._relayer.sign_transaction(tx_dict)
        # Web3.py 6.x exposes raw bytes as `.rawTransaction` (or `.raw_transaction` in v7)
        raw = getattr(signed, "rawTransaction", None) or getattr(signed, "raw_transaction")
        tx_hash = self.w3.eth.send_raw_transaction(raw)
        return tx_hash.hex()

    # -----------------------------------------------------------------------
    # Cleanup
    # -----------------------------------------------------------------------
    def shutdown(self):
        if self._anvil is not None:
            self._anvil.shutdown()
            self._anvil = None


if __name__ == "__main__":
    # Smoke test: spin up Anvil, deploy contract, push a flag tx, read it back.
    from crypto_core import keygen, g1_fingerprint, H
    print("Starting BlockchainNetwork (Anvil + FlexDiamEHR.sol)...")
    net = BlockchainNetwork([f"BS_{i}" for i in range(4)], verbose=True)

    # Register an external doctor (their BN128 Schnorr pk)
    doc_kp = keygen()
    net.register_external_party("did:doctor:alice", doc_kp.pk_g1)

    # Flag tx
    tx = Transaction(
        tx_type="flag",
        payload={
            "patient_pid": H(b"PID:patient42").hex(),
            "flag_id": "FLAG_xyz",
            "h_a": "Hospital_A",
            "h_b": "Hospital_B",
            "purpose": "consultation",
        },
        sender_id="did:doctor:alice",
        nonce=1,
        timestamp=time.time(),
    )
    tx.sign(doc_kp.sk)
    ok = net.broadcast_tx(tx)
    print(f"  broadcast ok={ok}, mempool depth={len(net._mempool)}")

    blk = net.run_consensus_round()
    assert blk is not None
    print(f"  block height={blk.height} eth_hash={blk.block_hash_hex[:16]}...")
    print(f"  state.flags={net.total_chain_state().flags}")

    # Read the count straight from the contract to prove on-chain truth
    total = net.contract.functions.totalFlags().call()
    print(f"  on-chain totalFlags={total}")
    print("eth_blockchain smoke test OK")
    net.shutdown()
