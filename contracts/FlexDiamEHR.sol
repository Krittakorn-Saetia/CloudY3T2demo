// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title FlexDiamEHR
/// @notice On-chain ledger for FLEX-DIAM-EHR sharing events, policy
///         commitments, access logs, DID registry, and delegation tokens.
///         Drop-in replacement for the simulated consortium chain in
///         blockchain.py: each tx-type that ChainState.apply handled becomes
///         a function here, emitting an event that eth_blockchain.py replays
///         to rebuild the ChainState view.
///
///         All identifiers are passed as `string` because the Python side
///         mixes hex digests, raw DIDs, and arbitrary record IDs. String
///         storage costs more gas but for this academic deployment fidelity
///         to the original Python dataclasses matters more than gas savings.
contract FlexDiamEHR {
    // ---------------------------------------------------------------------
    // DID registry
    // ---------------------------------------------------------------------
    mapping(string => string) public registry; // did => pk fingerprint (hex)
    event Registered(string did, string pkFp, uint256 timestamp);

    function registerDID(string calldata did, string calldata pkFp) external {
        registry[did] = pkFp;
        emit Registered(did, pkFp, block.timestamp);
    }

    // ---------------------------------------------------------------------
    // Cross-domain sharing flags
    // ---------------------------------------------------------------------
    uint256 public totalFlags;
    event Flagged(
        string patientPid,
        string flagId,
        string hA,
        string hB,
        string purpose,
        string senderDid,
        uint256 timestamp
    );

    function recordFlag(
        string calldata patientPid,
        string calldata flagId,
        string calldata hA,
        string calldata hB,
        string calldata purpose,
        string calldata senderDid
    ) external {
        totalFlags += 1;
        emit Flagged(patientPid, flagId, hA, hB, purpose, senderDid, block.timestamp);
    }

    // ---------------------------------------------------------------------
    // Policy commitments (h_pi from ZK proofs)
    // ---------------------------------------------------------------------
    mapping(string => string) public policyCommitter; // h_pi => sender DID
    event PolicyCommitted(string hPi, string senderDid, string policyId, uint256 timestamp);

    function commitPolicy(
        string calldata hPi,
        string calldata policyId,
        string calldata senderDid
    ) external {
        policyCommitter[hPi] = senderDid;
        emit PolicyCommitted(hPi, senderDid, policyId, block.timestamp);
    }

    // ---------------------------------------------------------------------
    // Access logs
    // ---------------------------------------------------------------------
    uint256 public accessLogCount;
    event Accessed(
        string senderDid,
        string recordId,
        string hPi,
        uint256 timestamp
    );

    function logAccess(
        string calldata senderDid,
        string calldata recordId,
        string calldata hPi
    ) external {
        accessLogCount += 1;
        emit Accessed(senderDid, recordId, hPi, block.timestamp);
    }

    // ---------------------------------------------------------------------
    // Delegation tokens
    // ---------------------------------------------------------------------
    mapping(string => bool) public delegationExists; // token_id => exists
    event Delegated(
        string tokenId,
        string delegatorDid,
        string delegateDid,
        string scope,
        uint256 expiry,
        uint256 timestamp
    );

    function createDelegation(
        string calldata tokenId,
        string calldata delegatorDid,
        string calldata delegateDid,
        string calldata scope,
        uint256 expiry
    ) external {
        delegationExists[tokenId] = true;
        emit Delegated(tokenId, delegatorDid, delegateDid, scope, expiry, block.timestamp);
    }

    // ---------------------------------------------------------------------
    // Generic catch-all for tx-types not modeled above. The schemes use
    // custom tx_type strings (e.g., scheme_25's cross-domain handshake);
    // we still want them recorded on-chain so the consensus cost is real.
    // ---------------------------------------------------------------------
    event GenericTx(string txType, string senderDid, bytes payload, uint256 timestamp);

    function logCustomTx(
        string calldata txType,
        string calldata senderDid,
        bytes calldata payload
    ) external {
        emit GenericTx(txType, senderDid, payload, block.timestamp);
    }
}
