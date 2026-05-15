"""
deploy_sepolia.py
=================
Deploy ``contracts/FlexDiamEHR.sol`` to a real Ethereum network — by default
the Sepolia testnet — and print the contract address + an Etherscan link
suitable for showing the prof.

Prerequisites (set as environment variables):

  SEPOLIA_RPC_URL
      An HTTPS RPC endpoint for the network. Free options that work without
      an account:
        https://ethereum-sepolia-rpc.publicnode.com
        https://rpc.sepolia.org
      Or, for higher reliability, sign up for free at
        https://www.alchemy.com/  (Sepolia Eth API)
        https://www.infura.io/   (Sepolia)
      and use the URL they give you.

  SEPOLIA_PRIVATE_KEY
      Hex private key (with or without leading 0x) of the account that will
      deploy. The account must hold a small amount of Sepolia ETH — get it
      free from one of these faucets:
        https://www.alchemy.com/faucets/ethereum-sepolia
        https://sepolia-faucet.pk910.de/
        https://www.infura.io/faucet/sepolia
      Deployment cost: ~0.001 Sepolia ETH at typical gas prices.

  CHAIN_ID  (optional, defaults to 11155111 = Sepolia)
      The numerical chain ID of the target network. Set to 17000 for Holesky,
      560048 for Hoodi, etc.

Usage:
    set SEPOLIA_RPC_URL=https://...                  (or PowerShell: $env:SEPOLIA_RPC_URL = "...")
    set SEPOLIA_PRIVATE_KEY=0x...
    python deploy_sepolia.py

After deployment the script:
  * prints the contract address,
  * prints an Etherscan link to the contract,
  * writes the address + ABI to ``deployments/sepolia.json`` so the
    experiment harness can re-attach without redeploying.
"""
from __future__ import annotations
# IMPORTANT: import the py_ecc recursion patch BEFORE anything triggers a
# py_ecc import via eth_blockchain.
import py_ecc_patch  # noqa: F401

import json
import os
import sys
import time
from pathlib import Path

from web3 import Web3, HTTPProvider
from eth_account import Account

from eth_blockchain import _compile_contract


ETHERSCAN_BY_CHAIN = {
    1: "https://etherscan.io",
    11155111: "https://sepolia.etherscan.io",
    17000: "https://holesky.etherscan.io",
    560048: "https://hoodi.etherscan.io",
}


def main() -> int:
    rpc_url = os.environ.get("SEPOLIA_RPC_URL")
    privkey = os.environ.get("SEPOLIA_PRIVATE_KEY")
    chain_id = int(os.environ.get("CHAIN_ID", "11155111"))

    if not rpc_url or not privkey:
        print("ERROR: set SEPOLIA_RPC_URL and SEPOLIA_PRIVATE_KEY environment "
              "variables before running. See the module docstring for free "
              "RPC endpoints and faucet links.", file=sys.stderr)
        return 2

    if not privkey.startswith("0x"):
        privkey = "0x" + privkey

    print(f"Connecting to {rpc_url} (chain id {chain_id})...")
    w3 = Web3(HTTPProvider(rpc_url, request_kwargs={"timeout": 60}))
    if not w3.is_connected():
        print(f"ERROR: cannot connect to {rpc_url}", file=sys.stderr)
        return 3

    acct = Account.from_key(privkey)
    balance_wei = w3.eth.get_balance(acct.address)
    balance_eth = balance_wei / 10 ** 18
    print(f"Deployer: {acct.address}")
    print(f"Balance:  {balance_eth:.6f} ETH")
    if balance_wei == 0:
        print("ERROR: deployer balance is 0 — fund it with a Sepolia faucet first.",
              file=sys.stderr)
        return 4

    print("Compiling contracts/FlexDiamEHR.sol with viaIR + optimizer...")
    abi, bytecode = _compile_contract()

    print("Building deployment transaction...")
    Contract = w3.eth.contract(abi=abi, bytecode=bytecode)
    constructor = Contract.constructor()
    nonce = w3.eth.get_transaction_count(acct.address)
    gas_estimate = constructor.estimate_gas({"from": acct.address})
    tx = constructor.build_transaction({
        "from": acct.address,
        "nonce": nonce,
        "gas": int(gas_estimate * 1.2),
        "chainId": chain_id,
    })
    # Fill in fee fields for EIP-1559 if the network supports it; fall back to legacy.
    try:
        latest = w3.eth.get_block("latest")
        base_fee = latest.get("baseFeePerGas")
        if base_fee is None:
            raise RuntimeError("no baseFeePerGas — legacy chain")
        priority_fee = w3.to_wei(2, "gwei")
        # maxFeePerGas must be >= maxPriorityFeePerGas. Headroom for base-fee
        # spikes between now and inclusion: 2 * base + priority.
        tx["maxPriorityFeePerGas"] = priority_fee
        tx["maxFeePerGas"] = int(base_fee * 2 + priority_fee)
    except Exception:
        tx["gasPrice"] = max(w3.eth.gas_price, w3.to_wei(1, "gwei"))

    signed = acct.sign_transaction(tx)
    raw = getattr(signed, "rawTransaction", None) or getattr(signed, "raw_transaction")
    print("Sending deployment tx...")
    tx_hash = w3.eth.send_raw_transaction(raw)
    print(f"  tx hash: {tx_hash.hex()}")
    print("Waiting for confirmation (Sepolia blocks ~12s)...")
    t0 = time.time()
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=600)
    elapsed = time.time() - t0
    if receipt.status != 1:
        print(f"ERROR: deployment reverted (receipt status {receipt.status}).",
              file=sys.stderr)
        return 5

    contract_address = receipt.contractAddress
    explorer = ETHERSCAN_BY_CHAIN.get(chain_id, "")
    print()
    print("=" * 70)
    print(f"DEPLOYED in {elapsed:.1f}s")
    print(f"  Contract address: {contract_address}")
    if explorer:
        print(f"  Explorer:         {explorer}/address/{contract_address}")
        print(f"  Tx:               {explorer}/tx/{tx_hash.hex()}")
    print(f"  Gas used:         {receipt.gasUsed:,}")
    print("=" * 70)

    # Persist for the experiment harness to attach without redeploying.
    out_dir = Path(__file__).parent / "deployments"
    out_dir.mkdir(exist_ok=True)
    out_file = out_dir / f"chain_{chain_id}.json"
    out_file.write_text(json.dumps({
        "chain_id": chain_id,
        "contract_address": contract_address,
        "deployer": acct.address,
        "tx_hash": tx_hash.hex(),
        "block_number": receipt.blockNumber,
        "deployed_at": int(time.time()),
        "abi": abi,
    }, indent=2))
    print(f"  Saved to {out_file.relative_to(Path.cwd())}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
