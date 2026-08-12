// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IFtsoV2
 * @notice Minimal FTSO v2 block-latency feed reader (Phase 8, Prompts 141-142).
 *
 * Declares exactly the two functions the master plan specifies:
 *   getFeedById(bytes21)  -> (uint256 value, int8 decimals, uint256 timestamp)
 *   getFeedsById(bytes21[]) -> (uint256[] values, int8[] decimals, uint256 timestamp)
 *
 * HONEST NOTE ON THE DEPLOYED VARIANT (live-verified 2026-08-12): the real
 * Coston2 FtsoV2 (registry name "FtsoV2", resolved from the FlareContractRegistry
 * to 0xC4e9c78E...6B304d) implements the fee-capable long-term interface
 * `FtsoV2Interface` (see ./FtsoV2Interface.sol): its `getFeedById` is
 * `external payable` returning (uint256, int8, uint64). This interface is
 * ABI-COMPATIBLE with that implementation:
 *   - the function SELECTOR depends only on the name + parameter types
 *     (`getFeedById(bytes21)`), which are identical here;
 *   - the return words are laid out identically (uint256/int8/uint64 all
 *     occupy one 32-byte word), so decoding through either shape yields the
 *     same values;
 *   - the block-latency crypto feeds used by this system (FXRP/USD, BTC/USD,
 *     USDT/USD) charge 0 fee (`calculateFeeById` == 0, live-verified), so the
 *     `view`/STATICCALL reads this interface produces succeed on the payable
 *     implementation without value.
 * The timestamp is widened to `uint256` per the master plan; the on-chain
 * value is uint64 and occupies the low 64 bits of the same word.
 */
interface IFtsoV2 {
    /**
     * @notice Returns the current value of a single feed.
     * @param _feedId The bytes21 feed id (e.g. FXRP/USD =
     *                0x015852502f55534400000000000000000000000000).
     * @return _value The fixed-point price (raw consensus value).
     * @return _decimals The feed's decimal scale — DYNAMIC per feed (FXRP/USD
     *                   6, BTC/USD 2, USDT/USD 6 on Coston2, live-verified):
     *                   price_usd = value / 10^decimals. Never hardcode it;
     *                   always read it from the feed.
     * @return _timestamp Unix timestamp of the last feed update.
     */
    function getFeedById(
        bytes21 _feedId
    ) external view returns (uint256 _value, int8 _decimals, uint256 _timestamp);

    /**
     * @notice Returns the current values of several feeds in ONE call.
     * @param _feedIds The list of bytes21 feed ids.
     * @return _values The fixed-point prices, one per requested feed.
     * @return _decimals The decimal scale of each feed (see {getFeedById}).
     * @return _timestamp The timestamp of the last update (shared by the
     *                    batched reads).
     */
    function getFeedsById(
        bytes21[] calldata _feedIds
    )
        external
        view
        returns (
            uint256[] memory _values,
            int8[] memory _decimals,
            uint256 _timestamp
        );
}
