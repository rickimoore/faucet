// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {Faucet} from "../src/Faucet.sol";
import {Merkle} from "murky/src/Merkle.sol";

contract FaucetTest is Test {
    Faucet public faucet;
    Merkle public merkle;
    // Test addresses
    address public constant OWNER = address(0xABCD);
    address public constant SENDER = address(0xCAFE);
    address public constant ALICE = address(0x1111);
    address public constant BOB = address(0x2222);
    address public constant CAROL = address(0x3333);
    address public constant HACKER = address(0x4444);

    // Merkle tree data
    bytes32[] public leaves;
    bytes32 public root;

    event WhiteListUpdated(bytes32 newRoot, uint256 newDepth);
    event Deposited(address indexed sender, uint256 amount);
    event DailyLimitChanged(uint256 newLimit);
    event Dispensed(address indexed to, uint256 amount);

    function setUp() public {
        merkle = new Merkle();
        leaves = new bytes32[](3);
        leaves[0] = keccak256(abi.encodePacked(ALICE));
        leaves[1] = keccak256(abi.encodePacked(BOB));
        leaves[2] = keccak256(abi.encodePacked(CAROL));
        root = merkle.getRoot(leaves);
        bytes32[] memory proof = merkle.getProof(leaves, 0);

        vm.prank(OWNER);
        faucet = new Faucet(0);
        vm.prank(OWNER);
        faucet.updateRoot(root, proof.length);
    }

    /// @dev Returns the selector for the given error signature,
    /// e.g. "Faucet_NotWhitelisted()" → 0x<first-4-bytes-of-keccak256>
    function errorSelector(string memory sig) internal pure returns (bytes4) {
        return bytes4(keccak256(bytes(sig)));
    }

    function test_owner_updateRoot(bytes32 newRoot, uint256 newDepth) public {
        vm.assume(newRoot != bytes32(0));

        vm.expectEmit(false, false, false, true);
        emit WhiteListUpdated(newRoot, newDepth);

        vm.prank(OWNER);
        faucet.updateRoot(newRoot, newDepth);

        // Verify storage slot updated
        assertEq(faucet.merkleRoot(), newRoot);
        assertEq(faucet.treeDepth(), newDepth);
    }

    function test_owner_empty_updateRoot() public {
        bytes32 newRoot = bytes32(0);

        vm.expectRevert(errorSelector("Faucet_InvalidMerkleRoot()"));
        vm.prank(OWNER);
        faucet.updateRoot(newRoot, 0);

        assertEq(faucet.merkleRoot(), root);
    }

    function test_sender_updateRoot_revert() public {
        bytes32 newRoot = keccak256("whitelist!");

        vm.prank(HACKER);
        vm.expectRevert();
        faucet.updateRoot(newRoot, 0);

        assertNotEq(faucet.merkleRoot(), newRoot);
    }

    function test_receive_fuzzPositiveAmount(uint256 amount) public {
        vm.deal(address(this), 100000 ether);

        uint256 sendAmount = bound(amount, 1, address(this).balance);

        vm.expectEmit(true, false, false, true);
        emit Deposited(address(this), sendAmount);

        (bool success,) = address(faucet).call{value: sendAmount}("");
        assertTrue(success, "Call to receive() with fuzzed value should succeed");
    }

    function test_receive_zeroAmount() public {
        (bool success,) = address(faucet).call{value: 0}("");
        assertTrue(success, "Call to receive() with fuzzed value should succeed");
    }

    function test_owner_fuzzSetDailyLimit(uint256 limit) public {
        vm.expectEmit(true, true, true, true);
        emit DailyLimitChanged(limit);

        vm.prank(OWNER);
        faucet.setDailyLimit(limit);
    }

    function test_sender_fuzzSetDailyLimit(uint256 limit) public {
        vm.prank(SENDER);
        vm.expectRevert();
        faucet.setDailyLimit(limit);
    }

    function test_owner_withdrawal() public {
        vm.deal(address(faucet), 5 ether);
        address payable payableOwner = payable(OWNER);
        uint256 prevBal = payableOwner.balance;

        vm.prank(OWNER);
        faucet.withdrawAll(payableOwner);

        assertEq(payableOwner.balance, prevBal + 5 ether);
    }

    function test_owner_insufficient_withdrawal() public {
        vm.deal(address(faucet), 0 ether);
        address payable payableOwner = payable(OWNER);
        uint256 prevBal = payableOwner.balance;

        vm.expectRevert(errorSelector("Faucet_NoFundsAvailable()"));
        vm.prank(OWNER);
        faucet.withdrawAll(payableOwner);

        assertEq(payableOwner.balance, prevBal);
    }

    function test_sender_withdrawal_revert() public {
        vm.deal(address(faucet), 5 ether);
        address payable payableOwner = payable(HACKER);
        uint256 prevBal = payableOwner.balance;

        vm.expectRevert();
        vm.prank(HACKER);
        faucet.withdrawAll(payableOwner);

        assertEq(payableOwner.balance, prevBal);
    }

    function test_dispense_noRoot_revert() public {
        Faucet fresh = new Faucet(0);
        bytes32[] memory proof = merkle.getProof(leaves, 0);
        vm.prank(ALICE);
        vm.expectRevert(errorSelector("Faucet_RootNotSet()"));
        fresh.dispense(0.1 ether, proof);
    }

    function test_dispense_invalidProofLength_revert(uint256 proofLength) public {
        uint256 depth = faucet.treeDepth();
        vm.assume(proofLength != depth);
        vm.assume(proofLength < depth + 1);

        bytes32[] memory proof = new bytes32[](proofLength);

        vm.prank(ALICE);
        vm.expectRevert(errorSelector("Faucet_InvalidProofLength()"));
        faucet.dispense(0.1 ether, proof);
    }

    function test_dispense_invalidAmount_aboveLimit_revert(uint256 amount) public {
        uint256 limit = 0.5 ether;
        vm.assume(amount > limit);

        vm.prank(OWNER);
        faucet.setDailyLimit(limit);

        bytes32[] memory proof = merkle.getProof(leaves, 0);
        vm.prank(ALICE);
        vm.expectRevert(errorSelector("Faucet_InvalidAmount()"));
        faucet.dispense(amount, proof);
    }

    function test_dispense_insufficientFunds_revert(uint256 amount) public {
        vm.deal(address(this), 2 ether);
        uint256 limit = 5 ether;

        vm.assume(amount > 0 && amount < limit);
        vm.prank(OWNER);
        faucet.setDailyLimit(limit);

        bytes32[] memory proof = merkle.getProof(leaves, 0);
        vm.prank(ALICE);
        vm.expectRevert(errorSelector("Faucet_InsufficientFunds()"));
        faucet.dispense(amount, proof);
    }

    function test_dispense_notWhitelisted_revert() public {
        uint256 limit = 1 ether;
        vm.prank(OWNER);
        faucet.setDailyLimit(limit);

        vm.deal(address(faucet), limit + 1 ether);
        bytes32[] memory proof = merkle.getProof(leaves, 0);
        vm.prank(HACKER);
        vm.expectRevert(errorSelector("Faucet_NotWhitelisted()"));
        faucet.dispense(0.1 ether, proof);
    }

    function test_dispense_alreadyClaimedToday_revert() public {
        vm.prank(OWNER);
        faucet.setDailyLimit(0.7 ether);

        vm.deal(address(faucet), 5 ether);
        bytes32[] memory proof = merkle.getProof(leaves, 0);
        vm.prank(ALICE);
        faucet.dispense(0.7 ether, proof);
        vm.prank(ALICE);
        vm.expectRevert(errorSelector("Faucet_AlreadyClaimedToday()"));
        faucet.dispense(0.4 ether, proof);
    }

    function test_dispense_success() public {
        vm.deal(address(faucet), 2 ether);
        uint256 amountLimit = 1 ether;
        vm.prank(OWNER);
        faucet.setDailyLimit(amountLimit);
        bytes32[] memory proof = merkle.getProof(leaves, 0);
        uint256 prevBal = ALICE.balance;
        vm.prank(ALICE);
        vm.expectEmit(false, true, false, true);
        emit Dispensed(ALICE, amountLimit);
        faucet.dispense(amountLimit, proof);
        assertEq(ALICE.balance, prevBal + amountLimit);
        assertEq(faucet.claimedToday(ALICE), amountLimit);
        assertEq(faucet.lastClaimDay(ALICE), block.timestamp / 1 days);
    }
}
