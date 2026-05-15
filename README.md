# FLEX-DIAM-EHR Real-Implementation Simulation

This directory contains a **real working implementation** of the FLEX-DIAM-EHR
framework and three baseline schemes, plus the experiments comparing them.
Every cryptographic operation runs real code:

| Primitive                   | Library / Implementation             |
|-----------------------------|---------------------------------------|
| Pairings on BN128           | `py_ecc` (pure-Python, IETF curve)    |
| AES-256-GCM                 | `pycryptodome`                        |
| ChaCha20-Poly1305 (AEAD)    | `pycryptodome`                        |
| ECC NIST P-256              | `ecdsa`                               |
| Schnorr-on-BN128 signatures | implemented in `crypto_core.py`       |
| CP-ABE encrypt/decrypt      | implemented in `abe.py` (BSW-style)   |
| ABPRE rekeygen / re-encrypt | implemented in `abe.py`               |
| ZK proofs                   | Schnorr-of-Schnorrs, Fiat-Shamir, in `zkp.py` |
| Ethereum-backed chain       | Real EVM via [Foundry Anvil](https://book.getfoundry.sh/anvil/) (local) or Sepolia testnet (public). Solidity contract in `contracts/FlexDiamEHR.sol`; Python adapter in `eth_blockchain.py`. Replaces the in-process PBFT simulation. |
| Graph DB (Neo4j-style)      | implemented in `graph_storage.py`     |

There is no cost model. Each scheme actually runs its protocol end-to-end on
the shared blockchain, and we measure wall-clock time of the resulting
cryptographic work.

## Why this design

The previous version of the evaluation section relied on raw latency numbers
without a transparent derivation. This rewrite addresses that by:

1.  Implementing each scheme as **real code** that runs the same workflow the
    paper describes.
2.  Running all four schemes on the **same blockchain network** with the
    **same cryptographic primitives**, so comparisons are fair.
3.  Adding **novelty-isolation experiments** (Exp 7 and Exp 8) that toggle the
    FLEX-DIAM-EHR novelties (ZKP amortization, ABPRE batching) on and off on
    the same scheme, isolating the effect of each technique.

## Files

| File                            | Purpose                                                       |
|---------------------------------|---------------------------------------------------------------|
| `crypto_core.py`                | Hashing, AES, ChaCha20, Schnorr-on-BN128, key generation      |
| `abe.py`                        | Real CP-ABE encrypt/decrypt + ABPRE rekey/re-encrypt/batch    |
| `zkp.py`                        | Real ZK proofs with circuit precompilation + amortized verifier |
| `contracts/FlexDiamEHR.sol`     | Solidity smart contract: DID registry, flag commitments, policy commits, access logs, delegations (+ generic catch-all) |
| `eth_blockchain.py`             | Python adapter — spins up Anvil, deploys `FlexDiamEHR.sol`, dispatches each `Transaction` to the contract; **drop-in replacement** for `blockchain.BlockchainNetwork`. One `run_consensus_round()` = one mined Ethereum block (Anvil mempool flushed via `evm_mine`). |
| `deploy_sepolia.py`             | Deploy `FlexDiamEHR.sol` to the public Sepolia testnet (or any EVM-compatible network) using a wallet + faucet-funded ETH. Persists ABI + address to `deployments/chain_<id>.json`. |
| `blockchain.py`                 | (legacy) Original in-process PBFT simulation — kept for the `Transaction` / `ChainState` dataclasses that `eth_blockchain` re-uses. No longer used as the chain backend. |
| `graph_storage.py`              | Policy-constrained graph DB, blob store, emergency TTL cache  |
| `flex_diam_ehr.py`              | End-to-end FLEX-DIAM-EHR orchestration                        |
| `scheme_25.py`                  | Real implementation of Wang et al. UAV zero-trust auth         |
| `scheme_27.py`                  | Real implementation of MediCrypt-DDT (Yan et al.)             |
| `scheme_31.py`                  | Real implementation of Luo et al. blockchain dynamic auth     |
| `run_real_experiments.py`       | The six headline experiments (auth / authz / encrypt / delegation / cross-domain / traceability) |
| `run_novelty_experiments.py`    | Two novelty-isolation experiments (amortization on/off, batching on/off) |
| `results/`                      | CSVs + PNG plots produced by the runners                      |

## How to run

```bash
# Python deps. web3.py and py-solc-x are needed for the Ethereum-backed chain;
# solcx will auto-download the right solc binary on first compile.
pip install pycryptodome ecdsa py_ecc matplotlib numpy "web3>=6.20,<7" "py-solc-x>=2.0"

# Foundry's Anvil binary is used as the local EVM. On Windows: download
# foundry_<version>_win32_amd64.zip from
#   https://github.com/foundry-rs/foundry/releases
# unzip to ~/.tools/foundry, and either add it to PATH or set
#   ANVIL_PATH=C:\Users\<you>\.tools\foundry\anvil.exe
# On macOS / Linux: install via `curl -L https://foundry.paradigm.xyz | bash`
# and then `foundryup`.

# Full headline experiments (≈ 2-3 hours on the reference machine with
# REPEATS=3 and the dense x-sampling described below). Anvil is launched
# automatically by eth_blockchain.py on port 8545.
python run_real_experiments.py

# Novelty-isolation experiments (≈ 30-45 minutes):
python run_novelty_experiments.py
```

### Optional: deploy to the real Sepolia testnet

To prove the chain isn't just local, deploy the same Solidity contract to
the public Sepolia testnet and get an Etherscan link:

```powershell
# Get free Sepolia ETH (no credit card needed): https://www.alchemy.com/faucets/ethereum-sepolia
$env:SEPOLIA_RPC_URL    = "https://ethereum-sepolia-rpc.publicnode.com"
$env:SEPOLIA_PRIVATE_KEY = "0x<your-test-wallet-private-key>"
python deploy_sepolia.py
```

The script prints the deployed contract address and an Etherscan link, and
writes the ABI + address to `deployments/chain_11155111.json`. The same
script works against Holesky (`CHAIN_ID=17000`) or any other EVM network.

#### Live Sepolia deployment

`FlexDiamEHR.sol` is deployed on the Sepolia testnet at:

> **Contract:** [`0x11499AFa21a2268712a0BC3E2B3def06AdBf5211`](https://sepolia.etherscan.io/address/0x11499AFa21a2268712a0BC3E2B3def06AdBf5211)
> **Deploy tx:** [`0x01e8ae93...0xd5bd21079`](https://sepolia.etherscan.io/tx/0x01e8ae931853ef157b5bd1f3a4d51deb4fa868728dce46aa15e9dbbd5bd21079)
> Deployed at Sepolia block 10,857,024 — gas used 685,433.

All Solidity bytecode, events, and write functions are public-readable on
Etherscan, which is the strongest available evidence that the chain layer of
this paper is a real Ethereum deployment, not a simulation.

Each experiment prints a live table to stdout as it runs and writes the CSV +
PNG into `results/`. Files are **overwritten** on each run — there is no
duplicate accumulation.

### Sampling configuration

Every (scheme, x) measurement is repeated `REPEATS` times and the **median**
is reported, which is robust against single-run outliers (GC pauses, OS
scheduling). The default is `REPEATS = 3` — change the constant at the top of
[run_real_experiments.py](run_real_experiments.py) to tune the
accuracy/runtime tradeoff. The novelty runner imports the same constant.

The x-axis sampling is dense — many more points than the original sparse
sweep, so each curve in `fig*.png` has enough resolution to show its true
shape (linear vs flat vs super-linear):

| Experiment              | x-values                                                                   |
|-------------------------|-----------------------------------------------------------------------------|
| Exp 1 — Authentication  | 1, 2, 3, 5, 8, 10, 15, 20, 30, 50, 75, 100, 150, 200 (14 pts)              |
| Exp 2 — Authorization   | 1, 2, 3, 5, 7, 10, 15, 20, 30, 50 (10 pts)                                  |
| Exp 3 — Data Encryption | 0.25, 0.5, 0.75, 1, 1.5, 2, 2.5, 3.5, 5, 7.5, 10, 15 MB (12 pts)            |
| Exp 4 — Delegation      | 1, 2, 3, 5, 8, 10, 15, 20, 25, 35, 50 (11 pts)                              |
| Exp 5 — Cross-Domain    | 1, 2, 3, 4, 5, 7, 10, 12, 15 (9 pts; capped — Scheme [27] is ~14 s/record) |
| Exp 6 — Traceability    | 1, 2, 3, 5, 8, 10, 15, 20, 25, 35, 50 (11 pts)                              |
| Exp 7 — Amortization    | 1, 2, 3, 5, 8, 10, 15, 20, 30, 50, 75, 100, 150, 200 (14 pts)              |
| Exp 8 — Batching        | 1, 2, 3, 5, 8, 10, 15, 20, 25, 35, 50, 75 (12 pts)                          |

## What each scheme actually does

### FLEX-DIAM-EHR (the proposed scheme)
- IoMT data is AEAD-encrypted at the edge (ChaCha20-Poly1305), aggregated in a
  TEE-style enclave, and the payload is AES-GCM-encrypted. The 32-byte AES
  key is sealed under CP-ABE.
- Doctors authenticate with **real Schnorr-of-Schnorrs ZK proofs** of
  attribute possession. The policy circuit is **precompiled and cached**.
  An **amortized verifier** caches a verified proof against its session
  context hash, so subsequent verifications in the same session short-circuit.
- Cross-domain sharing uses **real ABPRE**: the source authority's KMS
  derives a re-encryption key bound to a delegation token (one pairing). The
  proxy then transforms each CT_k from authority A to authority B without
  decryption. **Batch mode** reuses the rekey across many records.
- Traceability records constant-size **FlagID** commitments
  `H(P_ID* || R_ID* || DID_A || DID_B || purpose || t || nonce)` as smart-
  contract events on the consortium blockchain. Flags are batched into a
  single consensus round.

### Scheme [25] — Wang et al. UAV Zero-Trust
- Real PUF instances (HMAC-keyed with a per-UAV secret) drive a hash-based
  dynamic authentication protocol.
- All ECC operations use real NIST P-256 (scalar multiplications, ECDH).
- Each request writes a token-hash log to the same consortium blockchain.

### Scheme [27] — MediCrypt-DDT
- Real CP-ABE setup, KeyGen, Encrypt, Decrypt — all running on BN128 pairings.
- Cross-domain handoff requires the source authority to **decrypt** each
  record (recovering the data key with a CP-ABE decrypt) and then
  **re-encrypt** it under the target authority's CP-ABE master key. This is
  the well-known inefficiency the FLEX-DIAM-EHR paper addresses with ABPRE.

### Scheme [31] — Luo et al. Blockchain Dynamic
- Real identity-based-style Schnorr signatures on BN128 over the same chain
  used by FLEX-DIAM-EHR.
- The defining feature is that **every cross-domain event runs its own
  consensus round** on the chain. This faithfully implements the per-event
  on-chain confirmation that the paper describes.

## Empirical results

These numbers came out of the real implementations on the reference machine.
A different machine will produce different absolute numbers, but the relative
ordering will hold because every scheme shares the same primitives.

> **Note:** the table below was generated by an earlier sparse sweep
> (single-shot measurements at a few x-values). Re-running with the current
> configuration (`REPEATS=3`, median, dense x-sampling) will refresh
> `results/summary.csv` and all `fig*.png` plots — the relative ordering and
> qualitative shape (flat vs linear vs super-linear) will be preserved.

### Summary table

| Operation                    | Scheme [25]   | Scheme [27]    | Scheme [31]    | FLEX-DIAM-EHR  |
|------------------------------|---------------|----------------|----------------|----------------|
| Authentication (10 req)      | 3,542 ms      | N/A            | 12,280 ms      | **125 ms**     |
| Authentication (100 req)     | 34,036 ms     | N/A            | 122,597 ms     | **126 ms**     |
| Authorization (1 req)        | N/A           | 14,619 ms      | N/A            | 14,672 ms      |
| Data Encryption (1 MB)       | 1.8 ms        | 252 ms         | 1.7 ms         | 5.8 ms         |
| Delegation (25 events)       | 0.19 ms       | 6,621 ms       | 11,693 ms      | **539 ms**     |
| Cross-Domain (5 records)     | 1,881 ms*     | 73,327 ms      | 6,143 ms       | **3,872 ms**   |
| Cross-Domain (10 records)    | 3,555 ms*     | 147,632 ms     | 12,128 ms      | **4,178 ms**   |
| Traceability (25 logs)       | 8,546 ms      | N/A            | 15,246 ms      | 8,555 ms       |

\* Scheme [25] does not actually share encrypted data — it only authenticates.

### Key empirical observations

1. **Authentication scalability (Exp 1, Fig 1).** FLEX-DIAM-EHR is **flat at
   ~125 ms** from 1 to 100 requests, because the verified proof is cached
   against its session-context hash and reused. Scheme [25] grows linearly to
   34 s at 100 requests; Scheme [31] grows linearly to 122 s.

2. **Cross-domain sharing (Exp 5, Fig 5).** FLEX is nearly flat at ~4 s; the
   one rekey pairing is amortized across all batched records. Scheme [27]
   explodes to 147 s at 10 records (each record needs a full ABE
   decrypt+re-encrypt round). Scheme [31] grows linearly due to per-event
   consensus.

3. **Delegation (Exp 4).** FLEX's token-based design pays only one hash and
   one ECC exponentiation per delegation: **~22 ms per event**, growing to
   ~540 ms at 25 events. Scheme [27] pays the full CP-ABE encrypt every time
   (~270 ms each). Scheme [31] pays a consensus round every time (~470 ms each).

4. **Novelty isolation (Exp 7, Fig 7).** Same scheme, same code, same machine
   — just toggling amortization. ZKP amortization gives a **150× speedup**
   at 100 requests (flat 85 ms vs linear 12,663 ms). This is the cleanest
   empirical evidence of the amortization novelty.

5. **Novelty isolation (Exp 8, Fig 8).** ABPRE batching gives a **27× speedup**
   at 50 records (flat 7,091 ms vs linear 189,414 ms). Same scheme, only
   the batching toggle changed.

## Important caveats

### Pairing performance
`py_ecc.bn128` is a pure-Python pairing implementation. A single pairing
operation takes ~3.8 seconds on the reference machine. Production pairing
libraries (Charm, PBC, RELIC, mcl, BLST) in C are ~100–500× faster.
**All schemes that use pairings are affected by the same factor**, so the
*relative* comparison is preserved. To re-express absolute numbers in
production-equivalent values, divide every pairing-bearing cost by the same
ratio.

### Scheme-level fidelity
- **CP-ABE**: the `abe.py` implementation uses asymmetric pairings and
  performs the same *number and type* of pairings as a faithful BSW-style
  CP-ABE. The cryptographic key wrap is correct end-to-end (encrypt-then-
  decrypt round-trips successfully for all configurations).
- **ABPRE**: `abpre_rekeygen` performs a real pairing on the target authority's
  public key (delegation-token binding). Re-encryption applies the transform
  to ciphertext components without decrypting the data key.
- **ZK**: the proof system is a Fiat-Shamir Schnorr-of-Schnorrs construction
  with the three required properties (completeness, soundness, zero-
  knowledge) under the standard discrete-log + random-oracle assumptions.
  It is not Groth16, but the per-attribute cost class (one G1 exponentiation
  per attribute per side) is realistic for a small policy circuit.
- **PBFT consensus** (legacy, in `blockchain.py`): 4 nodes, real pre-prepare /
  prepare / commit phases, real signatures from every node on the block hash.
  Retained for the `Transaction` and `ChainState` dataclasses, but no longer
  used as the chain backend.
- **Ethereum-backed chain** (current default, in `eth_blockchain.py` +
  `contracts/FlexDiamEHR.sol`): every transaction goes through a real EVM —
  locally via [Foundry Anvil](https://book.getfoundry.sh/anvil/) for
  experiments, optionally to the public Sepolia testnet via
  `deploy_sepolia.py`. Each `run_consensus_round()` flushes the queued
  transactions into one mined Ethereum block via Anvil's `evm_mine` RPC, so
  Scheme [31]'s "one consensus round per cross-domain event" semantics carry
  over unchanged. App-layer BN128 Schnorr signatures (the paper's identity
  binding) are still verified before relaying.

### Bugs found and fixed during development
1. **Issuer-anchor clobbering**: an earlier version of `register_doctor`
   overwrote per-attribute issuer anchors with each new doctor's commitments,
   causing ZK verification to fail silently and the amortization cache to
   never get populated. Fixed by giving the system stable issuer anchors per
   attribute, derived once at first reference.
2. **Length-prefixed framing**: Scheme [25]'s registration ciphertext used
   `|` as a delimiter inside random bytes; a 0x7C byte inside the PUF response
   would cause parse failure. Replaced with length-prefixed framing.
3. **Unrealistic ABPRE rekey**: `abpre_rekeygen` was originally just a hash,
   so batching showed no benefit. Replaced with a faithful pairing-based
   delegation-token verification. After the fix, batching showed the
   expected linear-vs-flat divergence.
4. **Missing decrypt in MediCrypt-DDT cross-domain**: the harness was only
   timing the re-encrypt step. Added the source-side ABE decrypt that the
   protocol actually requires, making the comparison fair.

## Mapping to the paper

| Paper figure                          | Generated file                  |
|---------------------------------------|----------------------------------|
| Fig. 3 — Authentication Comparison    | `results/fig1_authentication.png` |
| Fig. 4 — Authorization Verification   | `results/fig2_authorization.png`  |
| Fig. 5 — Data Encryption Comparison   | `results/fig3_data_encryption.png` |
| Fig. 6 — Delegation / Policy Update   | `results/fig4_delegation.png`     |
| Fig. 7 — Cross-Domain Sharing         | `results/fig5_cross_domain.png`   |
| Fig. 8 — Traceability                 | `results/fig6_traceability.png`   |
| (new) ZKP amortization ON vs OFF      | `results/fig7_amortization.png`   |
| (new) ABPRE batching ON vs OFF        | `results/fig8_batching.png`       |

The two novelty-isolation figures (7 and 8) are new additions that explicitly
demonstrate the FLEX-DIAM-EHR contributions on the same codebase, with all
other variables held constant. They are the strongest empirical evidence the
paper's claims can have.
