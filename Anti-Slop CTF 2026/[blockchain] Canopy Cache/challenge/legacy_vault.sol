// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

/*
 * Public-facing reference contract. The deployed service emulates a 7702-style
 * delegate uplink that only blesses preview lanes, then profiles a separate
 * canopy cache before allowing the delegate to touch the legacy vault.
 */
contract LegacyVault {
    address public owner;
    uint256 public reward;

    constructor(address _owner, uint256 _reward) {
        owner = _owner;
        reward = _reward;
    }

    function sweep() external returns (uint256 amount) {
        require(msg.sender == owner, "owner only");
        amount = reward;
        reward = 0;
    }

    function preview() external view returns (uint256) {
        return reward;
    }
}
