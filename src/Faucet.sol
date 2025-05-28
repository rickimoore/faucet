// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

/// @notice Thrown when the Merkle root has not yet been set by the owner.
error Faucet_RootNotSet();

/// @notice Thrown when Merkle verification fails.
error Faucet_NotWhitelisted();

/// @notice Thrown when sender attempts to dispense above allowed limit or send 0 amount.
error Faucet_InvalidAmount();

/// @notice Thrown when sender attempts to dispense funds when Faucet is too low.
error Faucet_InsufficientFunds();

/// @notice Thrown when sender attempts to exceed their allowed daily limit.
error Faucet_AlreadyClaimedToday();

/// @notice Thrown when Faucet fails to transfer funds to sender.
error Faucet_DispenseFailed();

/// @notice Thrown when Faucet fails to transfer entire balance to owner.
error Faucet_WithdrawalFailed();

/// @notice Thrown when owner attempts to withdraw with no funds in Faucet.
error Faucet_NoFundsAvailable();

/// @notice Thrown when sender attempts to verify proof with incorrect length.
error Faucet_InvalidProofLength();

/// @notice Thrown when owner attempts to update Merkle root with incorrect length.
error Faucet_InvalidMerkleRoot();

/// @title Faucet
/// @author Ricki Moore (Mavrik)
/// @notice A simple ETH Faucet supporting Merkle-tree whitelisting and daily claim limits. The owner can set the daily limit to 0 to “freeze” all claims until ready.
/**
 * @dev Inherits OpenZeppelin’s Ownable and ReentrancyGuard for access control and reentrancy protection.
 *     `updateRoot` allows owner to update the merkleRoot whitelist allowing new users to dispense until reaching daily max.
 *     `dispense` keeps track and updates `lastClaimDay` and `claimedToday` allowing protection from excess claims in one day.
 *     `setDailyLimit` allows for 0 as `_newLimit`, this will allow owner to freeze/unfreeze the faucet as needed.
 */
contract Faucet is Ownable, ReentrancyGuard {
    bytes32 public merkleRoot;
    uint256 public treeDepth;
    uint256 public dailyLimit; // max wei per address per day.

    mapping(address => uint256) public lastClaimDay;
    mapping(address => uint256) public claimedToday;

    /// @notice Emitted when someone deposits ETH into the faucet.
    /// @param sender The address which sent ETH.
    /// @param amount The amount of ETH deposited.
    event Deposited(address indexed sender, uint256 amount);

    /// @notice Emitted when the faucet dispenses ETH to a user.
    /// @param to The recipient address.
    /// @param amount The amount of ETH dispensed.
    event Dispensed(address indexed to, uint256 amount);

    /// @notice Emitted when the owner withdraws all ETH from the faucet.
    /// @param to The address receiving the withdrawn ETH.
    /// @param amount The amount of ETH withdrawn.
    event Withdrawn(address indexed to, uint256 amount);

    /// @notice Emitted when the owner changes the daily limit.
    /// @param newLimit The new daily limit in wei.
    event DailyLimitChanged(uint256 newLimit);

    /// @notice Emitted when the owner updates the Merkle root.
    /// @param newRoot The new Merkle root.
    /// @param newDepth The new treeDepth for valid proofs.
    event WhiteListUpdated(bytes32 newRoot, uint256 newDepth);

    /// @notice Initializes the faucet with a given daily limit.
    /// @param _dailyLimit The initial per-address daily claim cap; Can be set to 0 to prevent dispense until ready.
    constructor(uint256 _dailyLimit) Ownable(msg.sender) {
        dailyLimit = _dailyLimit;
    }

    /// @notice Updates the Merkle root whitelist.
    /// @dev Only callable by the owner.
    /// @param newRoot The new Merkle root; cannot be zero.
    /// @param newDepth The new treeDepth for valid proofs.
    /// @custom:revert Faucet_InvalidMerkleRoot If `newRoot` is zero.
    function updateRoot(bytes32 newRoot, uint256 newDepth) external onlyOwner {
        if (newRoot == bytes32(0)) revert Faucet_InvalidMerkleRoot();
        merkleRoot = newRoot;
        treeDepth = newDepth;
        emit WhiteListUpdated(newRoot, newDepth);
    }

    /// @notice Allows anyone to deposit ETH into the faucet.
    /// @dev Emits a {Deposited} event on non-zero deposits.
    receive() external payable {
        if (msg.value > 0) {
            emit Deposited(msg.sender, msg.value);
        }
    }

    /// @notice Sets a new daily limit for claims.
    /// @dev Only callable by the owner.
    /// @param _newLimit The new daily limit in wei; Can be set to 0 to freeze faucet preventing dispenses.
    function setDailyLimit(uint256 _newLimit) external onlyOwner {
        dailyLimit = _newLimit;
        emit DailyLimitChanged(_newLimit);
    }

    /// @notice Claim up to `dailyLimit` wei if whitelisted.
    /// @dev
    ///   - The Merkle leaf is `keccak256(abi.encodePacked(msg.sender))`.
    ///   - Resets the daily counter on a new UTC day (`block.timestamp / 1 days`).
    ///   - Protected against reentrancy via `nonReentrant`.
    /// @param amount The wei amount to claim; must be > 0 and ≤ `dailyLimit`.
    /// @param proof The Merkle proof confirming inclusion of `msg.sender` in the whitelist.
    /// @custom:revert Faucet_RootNotSet       If `merkleRoot` has not been set by owner.
    /// @custom:revert Faucet_InvalidProofLength If `proof` array is empty.
    /// @custom:revert Faucet_InvalidAmount     If `amount` is zero or exceeds `dailyLimit`.
    /// @custom:revert Faucet_InsufficientFunds If contract balance < `amount`.
    /// @custom:revert Faucet_NotWhitelisted   If Merkle proof verification fails.
    /// @custom:revert Faucet_AlreadyClaimedToday If claimant would exceed their daily limit.
    /// @custom:revert Faucet_DispenseFailed   If ETH transfer to `msg.sender` fails.
    function dispense(uint256 amount, bytes32[] calldata proof) external nonReentrant {
        if (merkleRoot == bytes32(0)) revert Faucet_RootNotSet();
        if (proof.length != treeDepth) revert Faucet_InvalidProofLength();
        if (amount == 0 || amount > dailyLimit) revert Faucet_InvalidAmount();
        if (address(this).balance < amount) revert Faucet_InsufficientFunds();

        bytes32 leaf = keccak256(abi.encodePacked(msg.sender));
        if (!MerkleProof.verify(proof, merkleRoot, leaf)) {
            revert Faucet_NotWhitelisted();
        }

        uint256 today = block.timestamp / 1 days;
        if (lastClaimDay[msg.sender] < today) {
            lastClaimDay[msg.sender] = today;
            claimedToday[msg.sender] = 0;
        }

        if (claimedToday[msg.sender] + amount > dailyLimit) {
            revert Faucet_AlreadyClaimedToday();
        }

        claimedToday[msg.sender] += amount;

        (bool success,) = payable(msg.sender).call{value: amount}("");
        if (!success) revert Faucet_DispenseFailed();

        emit Dispensed(msg.sender, amount);
    }

    /// @notice Withdraws the entire contract balance to the specified address.
    /// @dev Only callable by the owner.
    /// @param to The recipient address for withdrawal.
    /// @custom:revert Faucet_NoFundsAvailable If the contract balance is zero.
    /// @custom:revert Faucet_WithdrawalFailed If the ETH transfer fails.
    function withdrawAll(address payable to) external onlyOwner {
        uint256 balance = address(this).balance;
        if (balance == 0) revert Faucet_NoFundsAvailable();

        (bool success,) = to.call{value: balance}("");
        if (!success) revert Faucet_WithdrawalFailed();

        emit Withdrawn(to, balance);
    }
}
