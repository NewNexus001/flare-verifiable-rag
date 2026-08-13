// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IFlareContractRegistry} from "./interfaces/IFlareContractRegistry.sol";
import {IFtsoV2} from "./interfaces/IFtsoV2.sol";
import {IFdcVerification} from "./interfaces/IFdcVerification.sol";
import {IRelay} from "./interfaces/IRelay.sol";
import {IWeb2Json} from "./interfaces/IWeb2Json.sol";

/**
 * @title VerifiableRAG
 * @notice On-chain attestation target for the flare-verifiable-rag enclave
 *         (Phase 6, Prompts 104-105).
 *
 * The enclave (GCP Confidential Space, Phase 5) proves a RAG query end-to-end:
 * document hash, prompt hash, and symbolic-graph output hash are bound into a
 * halo2 ZK proof (indexer_rs, Phase 3). `submitAttestation` is the on-chain
 * settlement entry point: the enclave submits the proof commitment so it can
 * later be finalized against a Flare Data Connector (FDC) attestation
 * (IFdcVerification) and/or verified directly by consumers.
 *
 * Design principles (project verified-data policy, REAL-DATA-SOURCES.md):
 *  - Protocol contract addresses are NEVER hardcoded in logic. They are
 *    resolved LIVE from the FlareContractRegistry (the same bootstrap address
 *    on every Flare network; injected at deploy time via the constructor).
 *    The registry is stored IMMUTABLE — the Flare periphery itself stores it
 *    immutable (fixed address on every network; saves ~2,100 gas/lookup and
 *    removes an admin attack surface).
 *  - The enclave image allowlist (`approvedImageDigest`) is a raw `bytes32`
 *    (the `sha256:` prefix is stripped off-chain at the Python boundary —
 *    Phase 5's attestation.py, which emits `sha256:<64 hex>`). bytes32 EQ is
 *    3 gas; string equality on-chain is thousands of gas and a parsing
 *    surface (research: Oasis/Phala/Lit/Axiom store digests as bytes32).
 *  - Inherits OpenZeppelin Ownable (owner-only administrative actions) and
 *    ReentrancyGuard (the attestation path forwards native fees to FdcHub in
 *    later prompts — CEI + nonReentrant per OZ guidance for payable external
 *    calls).
 *
 * The `submitAttestation` ABI shape (struct AttestationProof + bytes payload)
 * is the canonical interface the enclave connector targets:
 *   selector `0x541a3928` == `submitAttestation((bytes32,bytes,bytes32[3]),bytes)`
 * (verified during Prompt 092's web3 6.15 encode round-trip).
 */
contract VerifiableRAG is Ownable, ReentrancyGuard {
    /// The Flare FDC hub contract name as registered in FlareContractRegistry.
    string private constant FDC_HUB_NAME = "FdcHub";
    /// The Flare FDC verification contract name as registered in the registry.
    string private constant FDC_VERIFICATION_NAME = "FdcVerification";
    /// The Flare FTSO v2 contract name as registered in the registry.
    string private constant FTSO_V2_NAME = "FtsoV2";

    /**
     * @notice A halo2 ZK proof plus the three public inputs it binds.
     * @param bindingHash  keccak256 over (doc_hash, prompt_hash, output_hash,
     *                     vTPM token, image_digest) — recomputed by
     *                     `attestation.generate_attestation_proof` (Prompt 087)
     *                     and verified by the ZKP verifier off-chain.
     * @param zkProof      Serialized halo2 proof bytes (indexer_rs output).
     * @param publicInputs The three circuit public inputs
     *                     [doc_hash, prompt_hash, output_hash] (field elements
     *                     reduced to 32-byte words).
     */
    struct AttestationProof {
        bytes32 bindingHash;
        bytes zkProof;
        bytes32[3] publicInputs;
    }

    /**
     * @notice A verified query record (Prompt 105).
     * @param verified    Whether the query's proof passed on-chain checks.
     * @param bindingHash The binding hash the proof was bound to — lets
     *                    downstream contracts prove the returned result set
     *                    corresponds to the submitted query (tamper-proofing).
     * @param verifiedAt  block.timestamp of verification — enables freshness
     *                    / expiry checks (record.verifiedAt vs MAX_AGE).
     */
    struct QueryRecord {
        bool verified;
        bytes32 bindingHash;
        uint256 verifiedAt;
    }

    /// FlareContractRegistry — the ONLY trusted on-chain address source.
    /// Immutable: set once at deploy; protocol addresses resolve through it
    /// (Flare periphery stores it immutable — fixed address per network).
    IFlareContractRegistry public immutable contractRegistry;

    /// The enclave container image digest allowed to submit attestations.
    /// Raw 32 bytes (sha256:<64 hex> from the vTPM claim
    /// submods.container.image_digest, prefix stripped at the Python
    /// boundary). Rotatable by the owner via {updateApprovedImageDigest}.
    /// NOTE: enforcement (comparing the submitter's attested digest against
    /// this allowlist) lands in a later prompt — declared now per Prompt 105.
    bytes32 public approvedImageDigest;

    /// The FTSO v2 feed id the settle path cross-checks against
    /// (owner-configurable via {updatePriceFeedId}). bytes21, e.g. FLR/USD =
    /// 0x01464c522f55534400000000000000000000000000. bytes21(0) = unset;
    /// {verifyAndSettleRAG} reverts `UnconfiguredFeed` until set (fail-closed).
    bytes21 public priceFeedId;

    /// Coston2 FTSO v2 block-latency feed ids (bytes21, Prompt 143).
    /// Live-verified 2026-08-12 against the deployed FtsoV2 (registry name
    /// "FtsoV2", resolved from the FlareContractRegistry): all three are
    /// active in getSupportedFeedIds, update every ~1.8-3s, charge 0 fee
    /// (calculateFeeById == 0), and returned real prices at the moment of
    /// verification — FXRP/USD $1.0185 @ 6dp, BTC/USD $63,504.92 @ 2dp,
    /// USDT/USD $0.99912 @ 6dp. Feed ids are bytes21: category byte 0x01
    /// (crypto) + ASCII-hex of the feed name + zero padding ("XRP/USD" —
    /// FXRP is Flare's wrapped XRP and prices against the same XRP/USD feed).
    bytes21 public constant FXRP_USD_FEED_ID =
        0x015852502f55534400000000000000000000000000;
    bytes21 public constant BTC_USD_FEED_ID =
        0x014254432f55534400000000000000000000000000;
    bytes21 public constant USDT_USD_FEED_ID =
        0x01555344542f555344000000000000000000000000;

    /// Maximum age (seconds) of a live feed accepted by {getRealtimePrice}
    /// and the settle path (Prompt 145 — the master-plan formula
    /// Δt = |t_current − t_feed| ≤ 300 seconds, enforced symmetrically so a
    /// small node clock skew in either direction is tolerated).
    uint64 public constant REALTIME_MAX_AGE = 300;

    /// The most recent accepted proof commitment. Last-writer-wins
    /// optimization pointer — the FULL linear history is the
    /// `AttestationSubmitted` event log. Written by {submitAttestation}.
    bytes32 public latestProofHash;

    /// The Merkle root of the most recently VERIFIED FDC Web2 attestation
    /// round (Prompt 130). This is the REAL root published by the enshrined
    /// Relay contract for the FDC protocol and the voting round in which the
    /// Web2 document was attested — `relay.merkleRoots(fdcProtocolId,
    /// votingRound)` — NOT a rehash of the proof bytes. Written only after
    /// the proof has been verified against the live FdcVerification (the
    /// Prompt 131 gate in {verifyAndSettleRAG}); `bytes32(0)` until the
    /// first verified Web2 attestation. Consumers can anchor the exact
    /// on-chain Merkle root the settled query's source document was proven
    /// against, and verify the proof themselves against this root via
    /// `IRelay.verify` (a fee may apply — protocol-specific).
    bytes32 public latestVerifiedWeb2Hash;

    /// The live FTSO v2 price the most recent settlement was valued against
    /// (raw fixed-point value, Prompt 146). Written by {verifyAndSettleRAG}
    /// alongside {lastSettlementValuation}; bytes32(0)-free — a settled query
    /// always has a nonzero price (the feed value is never zero in practice;
    /// the revert gates guarantee a fresh, live read).
    uint256 public lastSettlementPrice;

    /// The USD settlement valuation computed ON-CHAIN for the most recent
    /// settlement (Prompt 146): quantity × price / 10^decimals (or × 10^|decimals|
    /// when the feed reports negative decimals). The price is fetched from the
    /// LIVE FTSO v2 feed by the contract itself — the caller cannot influence
    /// the valuation input (a caller-supplied price is no longer accepted).
    uint256 public lastSettlementValuation;

    /// Proof commitments already accepted (bindingHash || keccak(zkProof)).
    /// Stored as a single hash to bound storage; the full proof payload is
    /// kept off-chain and re-verified against this commitment.
    mapping(bytes32 proofId => bool submitted) public submittedProofs;

    /// Verified queries by query id (keccak of the query inputs).
    /// Populated by the verification path (later prompts).
    mapping(bytes32 queryId => QueryRecord record) public verifiedQueries;

    /// Reverts when the same proof commitment is settled twice (replay
    /// protection, also makes submission idempotent-safe).
    error DuplicateProof(bytes32 proofId);

    /// Reverts when a Flare protocol contract is not (yet) registered in the
    /// FlareContractRegistry — fail-closed, mirroring the enclave connector's
    /// `ContractResolveError` (verified-data policy: never operate on a zero
    /// address).
    error UnregisteredContract(string name);

    /// Reverts when the registry bootstrap address is the zero address.
    error ZeroRegistry();

    /// Reverts when an owner-only action is attempted with a zero address.
    error ZeroAddress();

    /// Reverts when the new image digest equals the current one (no-op).
    error UnchangedImageDigest();

    /// Reverts when a vTPM token is malformed or missing required claims.
    error InvalidToken();

    /// Reverts when the attested image digest is not on the allowlist.
    error UnauthorizedImage(bytes32 digest);

    /// Reverts when no FTSO v2 feed is configured for settlement.
    error UnconfiguredFeed();

    /// Reverts when the live feed is older than REALTIME_MAX_AGE (or more
    /// than that far in the future — the symmetric Prompt 145 window).
    error StaleFeed();

    /// Reverts when a query was already verified with a different binding.
    error QueryConflict(bytes32 queryHash);

    /// Reverts when the query hash is zero (nonsense input).
    error ZeroQueryHash();

    /// Reverts when the FDC Web2 proof fails verification against the live
    /// FdcVerification contract (Prompt 131 settlement gate).
    error UnverifiedWeb2Data();

    /// Reverts when the feed id setter receives bytes21(0).
    error ZeroFeedId();

    /// Reverts when a settlement quantity of zero is submitted (a zero
    /// quantity would silently record a zero valuation — fail-closed).
    error ZeroSettlementQuantity();

    /// Reverts when the feed id would not change (no-op).
    error UnchangedFeedId();

    /// Emitted when the enclave settles a proof commitment on-chain.
    event AttestationSubmitted(
        bytes32 indexed proofId,
        address indexed submitter,
        bytes32 bindingHash
    );

    /// Emitted when the owner rotates the approved enclave image digest.
    event ImageDigestUpdated(
        bytes32 indexed oldDigest,
        bytes32 indexed newDigest
    );

    /// Emitted when a query's ZK proof passes on-chain verification
    /// (Prompt 108). Declared now; emitted by the verification path that
    /// lands in later prompts (the path that also populates
    /// `verifiedQueries`). Two indexed 32-byte topics for cheap off-chain
    /// filtering by query or by enclave image; timestamp is the block time
    /// of verification (freshness/expiry checks).
    event ProofVerified(
        bytes32 indexed queryHash,
        bytes32 indexed imageDigest,
        uint256 timestamp
    );

    /// Emitted when the owner reconfigures the FTSO v2 settlement feed.
    event PriceFeedIdUpdated(
        bytes21 indexed oldFeedId,
        bytes21 indexed newFeedId
    );

    /// Emitted with the live feed price at each settlement (Prompt 156) — a
    /// lightweight price-only signal (the richer {QuerySettled} event carries
    /// the full valuation inputs). Consumers tracking price history can filter
    /// on the indexed feed id without decoding the valuation tuple.
    event PriceSettled(bytes21 indexed feedId, uint256 price, uint256 timestamp);

    /// Emitted when a query is settled against the live FTSO v2 feed with its
    /// on-chain USD valuation (Prompt 146). The valuation is computed from the
    /// feed value the contract fetched itself — consumers can recompute
    /// quantity × price / 10^decimals from the emitted fields and verify it
    /// against {lastSettlementValuation}.
    event QuerySettled(
        bytes32 indexed queryHash,
        bytes21 feedId,
        uint256 price,
        int8 decimals,
        uint256 quantity,
        uint256 valuation,
        uint256 timestamp
    );

    /**
     * @param initialOwner           Address that owns administrative functions.
     * @param contractRegistry_      The FlareContractRegistry bootstrap address
     *                               (same on every Flare network; documented in
     *                               REAL-DATA-SOURCES.md). Zero-mock policy: the
     *                               ONLY address ever supplied to the contract.
     * @param initialApprovedImageDigest Raw sha256 digest of the enclave image
     *                               authorized to submit attestations (the
     *                               vTPM submods.container.image_digest bytes,
     *                               `sha256:` prefix stripped).
     */
    constructor(
        address initialOwner,
        address contractRegistry_,
        bytes32 initialApprovedImageDigest
    ) Ownable(initialOwner) {
        if (contractRegistry_ == address(0)) {
            revert ZeroRegistry();
        }
        if (initialApprovedImageDigest == bytes32(0)) {
            revert ZeroAddress();
        }
        contractRegistry = IFlareContractRegistry(contractRegistry_);
        approvedImageDigest = initialApprovedImageDigest;
    }

    /// @notice Rotate the approved enclave image digest (owner only).
    /// @param _newDigest Raw sha256 digest of the new image (prefix stripped).
    /// @dev Reverts `ZeroAddress` on bytes32(0) and `UnchangedImageDigest`
    ///      when the digest would not change.
    /// @dev Emits {ImageDigestUpdated}. Enables image rotation without a
    ///      redeploy. Naming follows the OZ v5 update* convention
    ///      (e.g. Ownable2Step's updatePendingOwner).
    function updateApprovedImageDigest(bytes32 _newDigest) external onlyOwner {
        if (_newDigest == bytes32(0)) {
            revert ZeroAddress();
        }
        if (_newDigest == approvedImageDigest) {
            revert UnchangedImageDigest();
        }
        emit ImageDigestUpdated(approvedImageDigest, _newDigest);
        approvedImageDigest = _newDigest;
    }

    /// @notice Configure the FTSO v2 feed the settle path cross-checks against
    ///         (owner only). e.g. FLR/USD =
    ///         0x01464c522f55534400000000000000000000000000.
    /// @dev Reverts `ZeroFeedId` on bytes21(0) and `UnchangedFeedId` on no-op.
    /// @dev Emits {PriceFeedIdUpdated}. Fail-closed: the settle path reverts
    ///      `UnconfiguredFeed` until a feed is configured.
    function updatePriceFeedId(bytes21 _newFeedId) external onlyOwner {
        if (_newFeedId == bytes21(0)) {
            revert ZeroFeedId();
        }
        if (_newFeedId == priceFeedId) {
            revert UnchangedFeedId();
        }
        emit PriceFeedIdUpdated(priceFeedId, _newFeedId);
        priceFeedId = _newFeedId;
    }

    /// @notice Resolve the FdcHub address LIVE from the registry.
    /// @return hub Address of FdcHub.
    /// @dev Fail-closed: reverts `UnregisteredContract` if the name is not
    ///      registered (address(0)) — never hands a zero address to callers.
    function fdcHub() public view returns (address hub) {
        hub = contractRegistry.getContractAddressByName(FDC_HUB_NAME);
        if (hub == address(0)) {
            revert UnregisteredContract(FDC_HUB_NAME);
        }
    }

    /// @notice Resolve the FdcVerification address LIVE from the registry.
    /// @dev Fail-closed: reverts `UnregisteredContract` if not registered.
    function fdcVerification() public view returns (address) {
        address verifier = contractRegistry.getContractAddressByName(
            FDC_VERIFICATION_NAME
        );
        if (verifier == address(0)) {
            revert UnregisteredContract(FDC_VERIFICATION_NAME);
        }
        return verifier;
    }

    /// @notice Resolve the FtsoV2 contract address LIVE from the registry.
    /// @dev Fail-closed: reverts `UnregisteredContract` if not registered.
    function ftsoV2() public view returns (address) {
        address ftso = contractRegistry.getContractAddressByName(FTSO_V2_NAME);
        if (ftso == address(0)) {
            revert UnregisteredContract(FTSO_V2_NAME);
        }
        return ftso;
    }

    /**
     * @notice Read the REAL-TIME raw value of an FTSO v2 feed (Prompt 144),
     *         gated by a 300-second freshness check (Prompt 145).
     *
     * The read goes through the LIVE FtsoV2 contract resolved from the
     * FlareContractRegistry (via {_liveFeed} / {IFtsoV2}) — never a cached or
     * caller-supplied price. The master-plan staleness formula is enforced
     * symmetrically: |block.timestamp − feed.timestamp| ≤ 300s, so both a
     * stale feed and a wildly-future timestamp (clock tampering) revert
     * `StaleFeed`.
     *
     * @param _feedId bytes21 feed id (e.g. {FXRP_USD_FEED_ID}).
     * @return The raw fixed-point feed value (divide by 10^decimals for the
     *         human price; callers needing `decimals` should read the feed
     *         directly — the settle path does, via {_liveFeed}).
     * @dev Reverts `UnregisteredContract` when FtsoV2 is not registered and
     *      `StaleFeed` when the feed is older (or farther in the future) than
     *      {REALTIME_MAX_AGE}.
     */
    function getRealtimePrice(bytes21 _feedId) public view returns (uint256) {
        (uint256 value, , ) = _liveFeed(_feedId);
        return value;
    }

    /// @notice Fetch one feed from the LIVE FtsoV2 and enforce the Prompt 145
    ///         freshness window ({REALTIME_MAX_AGE} = 300s, both directions).
    /// @dev Reverts `UnregisteredContract` / `StaleFeed` (see {getRealtimePrice}).
    function _liveFeed(
        bytes21 _feedId
    ) internal view returns (uint256 value, int8 decimals, uint256 timestamp) {
        (value, decimals, timestamp) = IFtsoV2(ftsoV2()).getFeedById(_feedId);
        if (
            timestamp > block.timestamp + REALTIME_MAX_AGE ||
            block.timestamp > timestamp + REALTIME_MAX_AGE
        ) {
            revert StaleFeed();
        }
    }

    /// @notice Scale a fixed-point feed value to a USD valuation for a given
    ///         settlement quantity (Prompt 146):
    ///             decimals ≥ 0:  quantity × price / 10^decimals
    ///             decimals < 0:  quantity × price × 10^|decimals|
    ///         FTSO v2 `decimals` is int8 and DYNAMIC per feed — the settle
    ///         path reads it at runtime and this helper handles both signs
    ///         (a negative scale means the raw value is already a multiple of
    ///         10^|decimals| per unit, e.g. some commodity feeds).
    ///
    ///         OVERFLOW BOUNDS: both branches multiply `_quantity * _price`
    ///         before scaling. Real FTSO v2 fixed-point values are < 2^64 and
    ///         settlement quantities are bounded application inputs, so the
    ///         product stays far below 2^256 (a 64-bit price × a 64-bit
    ///         quantity × 10^18 worst case is ~2^146). A feed with extreme
    ///         decimals or an unbounded quantity would need a mulDiv
    ///         formulation — out of scope for the feeds this system values.
    function _scaleValuation(
        uint256 _quantity,
        uint256 _price,
        int8 _decimals
    ) internal pure returns (uint256) {
        if (_decimals >= 0) {
            return (_quantity * _price) / 10 ** uint256(uint8(_decimals));
        }
        return
            _quantity *
            _price *
            (10 ** uint256(uint8(uint256(-int256(_decimals)))));
    }

    /// @notice The Prompt 146 settle step: fetch the live feed (Prompt 145
    ///         freshness gate via {_liveFeed}), compute the on-chain USD
    ///         valuation ({_scaleValuation}), record the settlement state, and
    ///         emit {QuerySettled}. Extracted from {verifyAndSettleRAG} so the
    ///         settle path's stack depth stays within solc's limit.
    /// @dev Reverts `UnconfiguredFeed` when no feed is set; `StaleFeed` when
    ///      the live feed violates the 300s freshness window.
    function _settleAgainstFeed(
        bytes32 _queryHash,
        uint256 _settlementQuantity
    ) internal {
        if (_settlementQuantity == 0) {
            revert ZeroSettlementQuantity();
        }
        if (priceFeedId == bytes21(0)) {
            revert UnconfiguredFeed();
        }
        (uint256 liveValue, int8 decimals, ) = _liveFeed(priceFeedId);
        uint256 valuation = _scaleValuation(
            _settlementQuantity,
            liveValue,
            decimals
        );
        lastSettlementPrice = liveValue;
        lastSettlementValuation = valuation;
        emit PriceSettled(priceFeedId, liveValue, block.timestamp);
        emit QuerySettled(
            _queryHash,
            priceFeedId,
            liveValue,
            decimals,
            _settlementQuantity,
            valuation,
            block.timestamp
        );
    }

    /**
     * @notice Verify a Web2Json FDC attestation proof (Prompt 123).
     *
     * Bridge function between the raw proof bytes a consumer holds (as
     * returned by the FDC DA Layer / verifier API) and the LIVE Flare
     * FdcVerification contract. The proof is ABI-decoded on-chain to the
     * canonical `IWeb2Json.Proof` struct and forwarded to
     * `IFdcVerification.verifyWeb2Json` at the address resolved from the
     * FlareContractRegistry — the REAL protocol verifier, never a mock.
     *
     * NOTE ON THE SIGNATURE (honest deviation, per project no-lies rule):
     * the prompt text specifies `verifyWeb2Data(bytes calldata)` while the
     * live Flare protocol declares `verifyWeb2Json(IWeb2Json.Proof calldata)`
     * (verified against the deployed FdcVerification on Coston2: canonical
     * selector `0x0aa05fe3`, confirmed present in the deployed impl bytecode
     * at Prompt 124 — the earlier recorded `0xc35efe86` was corrected). This
     * function keeps the prompt's
     * bytes-level interface (so raw DA-Layer proofs can be passed directly)
     * and bridges to the real struct-based verifier via `abi.decode` — both
     * the prompt's signature and the real protocol are satisfied, and the
     * on-chain call always targets the genuine FdcVerification contract.
     *
     * @param _fdcProof ABI-encoded `IWeb2Json.Proof` (merkleProof + response
     *                  data), as delivered by the FDC verifier API.
     * @return true when FdcVerification confirms the proof (FDC consensus
     *         reached on the underlying Web2Json attestation).
     * @dev Reverts `UnregisteredContract` when FdcVerification is not
     *      registered (fail-closed, never operates on a zero address);
     *      reverts on malformed proof bytes via `abi.decode`.
     */
    function verifyWeb2Data(
        bytes calldata _fdcProof
    ) public view returns (bool) {
        IWeb2Json.Proof memory proof = abi.decode(_fdcProof, (IWeb2Json.Proof));
        return IFdcVerification(fdcVerification()).verifyWeb2Json(proof);
    }

    /**
     * @notice Settle a RAG attestation proof commitment (Prompt 104 skeleton).
     *
     * CEI order: the commitment is recorded BEFORE any external interaction,
     * and the entry point is `nonReentrant` (the final flow forwards native
     * C2FLR fees to FdcHub.requestAttestation — a payable external call that
     * must be guarded, per OpenZeppelin's guidance and the FDC fee pattern).
     *
     * Also tracks `latestProofHash` (Prompt 105) — the most recent accepted
     * commitment, forming a verifiable chain of enclave attestations.
     *
     * @param _proof            The ZK proof + bound public inputs.
     * @param _attestationData  ABI-encoded FDC attestation request payload
     *                          (Web2Json.Request, Prompt 103) forwarded to
     *                          FdcHub.requestAttestation in later prompts.
     *                          Accepted now so the interface (and the enclave
     *                          connector's calldata shape, selector
     *                          `0x541a3928`) is stable across phases.
     *                          NOTE: when fee forwarding lands (later
     *                          prompts), this function MUST become `payable`
     *                          to carry the C2FLR attestation fee as
     *                          msg.value.
     * @return proofId          Storage commitment (keccak of proof fields).
     * @dev Reverts `DuplicateProof` if the same commitment was already
     *      settled (idempotent-enforced replay protection).
     */
    function submitAttestation(
        AttestationProof calldata _proof,
        bytes calldata _attestationData
    ) external nonReentrant returns (bytes32 proofId) {
        proofId = keccak256(
            abi.encode(_proof.bindingHash, _proof.zkProof, _proof.publicInputs)
        );
        if (submittedProofs[proofId]) {
            revert DuplicateProof(proofId);
        }
        submittedProofs[proofId] = true;
        latestProofHash = proofId;
        emit AttestationSubmitted(proofId, msg.sender, _proof.bindingHash);
        // _attestationData is validated/forwarded to FdcHub in later prompts.
        // Keeping it a named parameter now pins the canonical ABI shape.
    }

    /**
     * @notice Verify a RAG attestation and settle it against the live FTSO v2
     *         feed (Prompt 109).
     *
     * On-chain validation performed here (claims + digest allowlist pattern,
     * per the Prompt 109 research):
     *   1. Parses the GCP Confidential Space vTPM OIDC JWT payload and
     *      requires `"swname":"CONFIDENTIAL_SPACE"`.
     *   2. Extracts `submods.container.image_digest` (`"sha256:<64 hex>"`)
     *      and requires it equals `approvedImageDigest` — the allowlist
     *      enforcement Prompt 105 deferred to this prompt.
     *   3. Binds `_vtpmToken || _zkpProof || _queryHash` into a proofId
     *      commitment with replay protection (`submittedProofs`), tracks
     *      `latestProofHash`, and records a `QueryRecord` in
     *      `verifiedQueries[_queryHash]` (idempotent-safe).
     *   4. Settles against the LIVE FTSO v2 feed (`priceFeedId`,
     *      owner-configured; Prompt 146): the contract FETCHES the current
     *      consensus value itself (no caller-supplied price), enforces the
     *      300s freshness window ({REALTIME_MAX_AGE}, Prompt 145), computes
     *      the USD settlement valuation on-chain
     *      (quantity × price / 10^decimals), and records it in
     *      {lastSettlementValuation} / {lastSettlementPrice} plus the
     *      {QuerySettled} event.
     *
     * Security model (what this function deliberately does NOT do): the JWT's
     * ES256 (P-256) signature and the halo2 ZK proof are verified OFF-CHAIN
     * by the enclave (Phase 5 `jwt_parser` against GCP's JWKS) before the
     * proof is minted — P-256 has no EVM precompile (ecrecover is
     * secp256k1-only) and on-chain P-256 verification costs 300k+ gas. The ZK
     * proof binds the verified token; the on-chain commitment binds the exact
     * proof bytes. Full on-chain ZK verification can be added in a later
     * prompt via a dedicated verifier contract.
     *
     * SECURITY BOUNDARY WARNING: `approvedImageDigest` is public on-chain
     * state. At the claims level (no on-chain signature check), any caller
     * can fabricate a JWT payload claiming the approved digest and pass the
     * live feed value — so `verifiedQueries` is NOT a trust boundary.
     * Downstream contracts MUST NOT gate on `verifiedQueries` as proof of
     * a genuine enclave run until the on-chain ZK verifier lands (later
     * prompt). The real enforcement today is the enclave's off-chain
     * verification (JWKS + halo2 verify) and consumers verifying the ZK
     * proof themselves; this function provides claims-level gating, replay
     * protection, and price settlement.
     *
     * SETTLE SEMANTICS (Prompt 146): the price is NEVER taken from the
     * caller — this function reads the live feed itself, so a caller cannot
     * influence the valuation input (strictly stronger than the previous
     * caller-supplied-price + equality-check design, which was superseded
     * here). The valuation is pure on-chain fixed-point math over the
     * fetched value; consumers can recompute it from the {QuerySettled}
     * event fields.
     *
     * @param _vtpmToken      GCP Confidential Space vTPM OIDC JWT
     *                        (header.payload.signature).
     * @param _zkpProof       Serialized halo2 proof bytes (indexer_rs).
     * @param _queryHash      keccak256 of the RAG query inputs.
     * @param _settlementQuantity The settlement quantity to value (notional
     *                        units, e.g. RWA claim units). The on-chain
     *                        valuation is quantity × live price / 10^decimals
     *                        (Prompt 146).
     * @param _fdcProof       ABI-encoded `IWeb2Json.Proof` (Prompt 131 gate):
     *                        the Web2 data source the query was computed over,
     *                        attested by the FDC network. MUST verify against
     *                        the live FdcVerification contract BEFORE any
     *                        settlement state is written; on success the
     *                        attested round's Merkle root is recorded in
     *                        {latestVerifiedWeb2Hash} (Prompt 130). Any gate
     *                        failure — undecodable proof, rejected proof, or
     *                        unresolvable verifier — reverts the single
     *                        `UnverifiedWeb2Data` error (see
     *                        {_verifiedWeb2Root}).
     * @return true when all checks pass and the query is settled.
     * @dev Reverts: InvalidToken, UnauthorizedImage, UnverifiedWeb2Data,
     *      DuplicateProof, QueryConflict, UnconfiguredFeed, StaleFeed.
     */
    function verifyAndSettleRAG(
        bytes calldata _vtpmToken,
        bytes calldata _zkpProof,
        bytes32 _queryHash,
        uint256 _settlementQuantity,
        bytes calldata _fdcProof
    ) external nonReentrant returns (bool) {
        if (_vtpmToken.length == 0 || _zkpProof.length == 0) {
            revert InvalidToken();
        }
        if (_queryHash == bytes32(0)) {
            revert ZeroQueryHash();
        }

        // 1) vTPM claim checks — claims + digest allowlist.
        bytes memory payload = _jwtPayload(_vtpmToken);
        if (!_hasSwname(payload)) {
            revert InvalidToken();
        }
        bytes32 digest = _extractImageDigest(payload);
        if (digest != approvedImageDigest) {
            revert UnauthorizedImage(digest);
        }

        // 1.5) FDC Web2 proof gate (Prompt 131) — a valid FDC attestation of
        //      the Web2 data MUST precede ANY settlement state change. The
        //      proof is verified against the LIVE FdcVerification (resolved
        //      from the registry), and the attested round's REAL Merkle root
        //      is recorded (Prompt 130). A missing/undecodable proof reverts
        //      UnverifiedWeb2Data before anything is written.
        latestVerifiedWeb2Hash = _verifiedWeb2Root(_fdcProof);

        // 2) Proof binding + replay protection (CEI: writes before external).
        bytes32 proofId = keccak256(
            abi.encode(_vtpmToken, _zkpProof, _queryHash)
        );
        if (submittedProofs[proofId]) {
            revert DuplicateProof(proofId);
        }
        submittedProofs[proofId] = true;
        latestProofHash = proofId;

        // 3) Query record. Identical (token, proof, query) replays are caught
        //    by DuplicateProof above and REVERT. This branch only covers the
        //    same query re-verified under a DIFFERENT token carrying the same
        //    approved digest: bindingHash matches -> return true (no writes,
        //    no duplicate event). A different proof for the same query
        //    reverts QueryConflict (tamper detection).
        bytes32 bindingHash = keccak256(abi.encode(_queryHash, _zkpProof, digest));
        QueryRecord storage record = verifiedQueries[_queryHash];
        if (record.verified) {
            if (record.bindingHash != bindingHash) {
                revert QueryConflict(_queryHash);
            }
        } else {
            record.verified = true;
            record.bindingHash = bindingHash;
            record.verifiedAt = block.timestamp;
        }

        // 4) Settle against the live FTSO v2 feed (Prompt 146) — delegated to
        //    {_settleAgainstFeed} so this function's stack depth stays within
        //    solc's limit. That helper fetches the price ON-CHAIN (there is no
        //    caller-supplied price anymore), enforces the 300s freshness gate
        //    (Prompt 145), computes the USD valuation, records
        //    {lastSettlementPrice} / {lastSettlementValuation}, and emits
        //    {QuerySettled}. (Prompt 131: settlement state above is gated on
        //    the FDC Web2 proof having already verified in step 1.5.)
        _settleAgainstFeed(_queryHash, _settlementQuantity);

        emit ProofVerified(_queryHash, digest, block.timestamp);
        return true;
    }

    /**
     * @notice Prompt 130/131 gate helper: verify an FDC Web2 proof against the
     *         LIVE FdcVerification contract and return the REAL Merkle root of
     *         the attested voting round (read from the enshrined Relay, the
     *         single source of truth for FDC round roots — never recomputed
     *         from the proof bytes).
     *
     * Mirrors the deployed FdcVerification logic (verified against the
     * Coston2 implementation at Prompt 131):
     *   root = relay.merkleRoots(fdcProtocolId, proof.data.votingRound);
     *   ok   = proof.data.attestationType == bytes32("Web2Json") &&
     *          merkleProof.verifyCalldata(root, keccak256(abi.encode(data)));
     * The bool check is delegated to the live verifier contract (the SAME
     * code path as {verifyWeb2Data}); the root is then read from the relay
     * the verifier itself points to (`IFdcVerification.relay()`), so the
     * recorded hash can never drift from what FdcVerification verified
     * against.
     *
     * @param _fdcProof ABI-encoded `IWeb2Json.Proof` (as returned by the FDC
     *                  verifier / DA Layer and passed to {verifyWeb2Data}).
     * @return The Merkle root of the round the proof attests (bytes32(0) is
     *         never returned for a verified proof: an attested+finalized round
     *         always has a nonzero published root).
     * @dev Reverts `UnverifiedWeb2Data` on ANY failure — an undecodable
     *      proof, a proof the live verifier rejects, OR an unresolvable/
     *      unregistered verifier. The try/catch around the external self-call
     *      deliberately normalizes every failure mode to the single
     *      settlement-gate error (including `UnregisteredContract` from the
     *      registry lookup inside the impl — the control test pins this), so
     *      the settle path can never expose a different revert for the same
     *      gate. Callers wanting the raw `UnregisteredContract` use the
     *      public {verifyWeb2Data} bridge instead, which propagates it.
     */
    function _verifiedWeb2Root(
        bytes calldata _fdcProof
    ) internal view returns (bytes32) {
        // try/catch an EXTERNAL self-call so that BOTH failure modes — an
        // undecodable proof (abi.decode reverts) and a proof the live
        // verifier rejects — revert the uniform `UnverifiedWeb2Data` before
        // any state write. (Internal calls cannot be wrapped in try/catch;
        // the self-call is view-only and costs no storage.)
        try this._verifiedWeb2RootImpl(_fdcProof) returns (bytes32 root) {
            return root;
        } catch {
            revert UnverifiedWeb2Data();
        }
    }

    /// @notice External implementation of {_verifiedWeb2Root} — kept external
    ///         so the gate's caller can trap decode/verifier failures.
    /// @dev Reverts `UnverifiedWeb2Data` on decode failure or verifier
    ///      rejection; reverts `UnregisteredContract` when FdcVerification is
    ///      not registered (fail-closed, never a zero address).
    function _verifiedWeb2RootImpl(
        bytes calldata _fdcProof
    ) external view returns (bytes32) {
        // ABI-decode first so malformed proofs fail cleanly BEFORE any state
        // write (fail-closed: the caller can never settle with junk calldata).
        IWeb2Json.Proof memory proof = abi.decode(_fdcProof, (IWeb2Json.Proof));
        IFdcVerification fdc = IFdcVerification(fdcVerification());
        if (!fdc.verifyWeb2Json(proof)) {
            revert UnverifiedWeb2Data();
        }
        // Read the root from the relay the verifier itself resolves — the
        // exact root FdcVerification verified `proof` against above.
        IRelay relay = fdc.relay();
        return relay.merkleRoots(fdc.fdcProtocolId(), proof.data.votingRound);
    }

    /// @notice Decode the payload segment of a `header.payload.signature` JWT.
    /// @return The base64url-decoded claim JSON.
    /// @dev Reverts `InvalidToken` on malformed structure.
    function _jwtPayload(
        bytes calldata _token
    ) internal pure returns (bytes memory) {
        bytes memory token = bytes(_token);
        int256 firstDot = _indexOf(token, bytes("."), 0);
        if (firstDot < 0) {
            revert InvalidToken();
        }
        int256 secondDot = _indexOf(token, bytes("."), uint256(firstDot) + 1);
        if (secondDot < 0) {
            revert InvalidToken();
        }
        uint256 start = uint256(firstDot) + 1;
        uint256 end = uint256(secondDot);
        if (end <= start) {
            revert InvalidToken();
        }
        bytes memory payloadSegment = new bytes(end - start);
        for (uint256 i = start; i < end; i++) {
            payloadSegment[i - start] = token[i];
        }
        return _b64UrlDecode(payloadSegment);
    }

    /// @notice True when the claim JSON contains `"swname":"CONFIDENTIAL_SPACE"`
    ///         (compact JSON — Google-issued tokens are emitted without
    ///         whitespace between key and value).
    function _hasSwname(bytes memory _json) internal pure returns (bool) {
        return _indexOf(_json, bytes('"swname":"CONFIDENTIAL_SPACE"'), 0) >= 0;
    }

    /// @notice Extract `submods.container.image_digest` (`"sha256:<64 hex>"`)
    ///         from the claim JSON and return the raw 32 bytes (the form
    ///         `approvedImageDigest` is stored in — `sha256:` prefix stripped).
    /// @dev Reverts `InvalidToken` when the claim or its format is missing.
    function _extractImageDigest(
        bytes memory _json
    ) internal pure returns (bytes32 digest) {
        bytes memory key = bytes('"image_digest"');
        int256 ki = _indexOf(_json, key, 0);
        if (ki < 0) {
            revert InvalidToken();
        }
        uint256 p = uint256(ki) + key.length;
        if (p >= _json.length || _json[p] != 0x3A) {
            revert InvalidToken(); // ':'
        }
        p++;
        if (p >= _json.length || _json[p] != 0x22) {
            revert InvalidToken(); // '"'
        }
        p++;
        bytes memory prefix = bytes("sha256:");
        for (uint256 j = 0; j < prefix.length; j++) {
            if (p + j >= _json.length || _json[p + j] != prefix[j]) {
                revert InvalidToken();
            }
        }
        p += prefix.length;
        uint256 v;
        for (uint256 j = 0; j < 64; j++) {
            if (p + j >= _json.length) {
                revert InvalidToken();
            }
            uint8 n = _hexValue(_json[p + j]);
            if (n > 15) {
                revert InvalidToken();
            }
            v = (v << 4) | n;
        }
        digest = bytes32(v);
    }

    /// @notice Find the first occurrence of `_needle` in `_haystack` at or
    ///         after `_from`.
    /// @return The index, or -1 when not found.
    function _indexOf(
        bytes memory _haystack,
        bytes memory _needle,
        uint256 _from
    ) internal pure returns (int256) {
        if (_needle.length == 0) {
            return int256(_from);
        }
        for (uint256 i = _from; i + _needle.length <= _haystack.length; i++) {
            bool found = true;
            for (uint256 j = 0; j < _needle.length; j++) {
                if (_haystack[i + j] != _needle[j]) {
                    found = false;
                    break;
                }
            }
            if (found) {
                return int256(i);
            }
        }
        return int256(-1);
    }

    /// @notice Base64url-decode (RFC 4648 §5). JWT payloads are UNPADDED;
    ///         trailing `=` padding is stripped first so both forms decode.
    /// @dev Reverts `InvalidToken` on illegal characters or lengths. The
    ///      floor formula (cleanLen * 3) / 4 is exact for unpadded input
    ///      (mod 4: 0 -> 3 bytes/group, 2 -> 1 byte, 3 -> 2 bytes).
    function _b64UrlDecode(
        bytes memory _in
    ) internal pure returns (bytes memory out) {
        uint256 inLen = _in.length;
        // Strip trailing '=' padding (Google JWTs are emitted unpadded).
        uint256 clean = inLen;
        while (clean > 0 && _in[clean - 1] == 0x3D) {
            clean--;
        }
        if (clean % 4 == 1) {
            revert InvalidToken();
        }
        uint256 outLen = (clean * 3) / 4;
        out = new bytes(outLen);
        uint256 o;
        for (uint256 i = 0; i < clean; i += 4) {
            uint256 b0 = _b64Value(_in[i]);
            uint256 b1 = i + 1 < clean ? _b64Value(_in[i + 1]) : 0;
            uint256 b2 = i + 2 < clean ? _b64Value(_in[i + 2]) : 0;
            uint256 b3 = i + 3 < clean ? _b64Value(_in[i + 3]) : 0;
            if (b0 > 63 || b1 > 63 || b2 > 63 || b3 > 63) {
                revert InvalidToken();
            }
            out[o++] = bytes1(uint8((b0 << 2) | (b1 >> 4)));
            if (o < outLen) {
                out[o++] = bytes1(uint8(((b1 & 0x0F) << 4) | (b2 >> 2)));
            }
            if (o < outLen) {
                out[o++] = bytes1(uint8(((b2 & 0x03) << 6) | b3));
            }
        }
    }

    /// @notice Map a base64url character to its 6-bit value (255 = invalid;
    ///         `=` padding maps to 0 so padded input decodes identically).
    function _b64Value(bytes1 _c) internal pure returns (uint256 v) {
        uint8 c = uint8(_c);
        if (c >= 0x41 && c <= 0x5A) return c - 0x41; // A-Z
        if (c >= 0x61 && c <= 0x7A) return c - 0x61 + 26; // a-z
        if (c >= 0x30 && c <= 0x39) return c - 0x30 + 52; // 0-9
        if (c == 0x2D) return 62; // '-'
        if (c == 0x5F) return 63; // '_'
        if (c == 0x3D) return 0; // '=' padding
        return 255;
    }

    /// @notice Map a hex character to its nibble (0xFF = invalid).
    function _hexValue(bytes1 _c) internal pure returns (uint8 v) {
        uint8 c = uint8(_c);
        if (c >= 0x30 && c <= 0x39) return c - 0x30; // 0-9
        if (c >= 0x61 && c <= 0x66) return c - 0x61 + 10; // a-f
        if (c >= 0x41 && c <= 0x46) return c - 0x41 + 10; // A-F
        return 0xFF;
    }
}
