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
    address public constant BOB   = address(0x2222);
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

    function test_owner_updateRoot() public {
        bytes32 newRoot = keccak256("whitelist!");
        uint256 newDepth = 0;

        vm.expectEmit(false, false, false, true);
        emit WhiteListUpdated(newRoot, newDepth);

        vm.prank(OWNER);
        faucet.updateRoot(newRoot, newDepth);

        // Verify storage slot updated
        assertEq(faucet.merkleRoot(), newRoot);
        assertEq(faucet.treeDepth(), newDepth);
    }

    function test_owner_empty_updateRoot() public {
        bytes32 initialRoot = keccak256("some real merkle root");
        vm.prank(OWNER);
        faucet.updateRoot(initialRoot, 0);

        bytes32 newRoot = bytes32(0);

        vm.expectRevert();
        vm.prank(OWNER);
        faucet.updateRoot(newRoot, 0);

        // Verify storage slot updated
        assertEq(faucet.merkleRoot(), initialRoot);
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

        (bool success, ) = address(faucet).call{value: sendAmount}("");
        assertTrue(success, "Call to receive() with fuzzed value should succeed");
    }

    function test_receive_zeroAmount() public {
        (bool success, ) = address(faucet).call{value: 0}("");
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

        vm.expectRevert();
        vm.prank(OWNER);
        faucet.withdrawAll(payableOwner);

        assertEq(payableOwner.balance, prevBal);
    }

    function test_sender_withdrawal() public {
        vm.deal(address(faucet), 5 ether);
        address payable payableOwner = payable(SENDER);
        uint256 prevBal = payableOwner.balance;

        vm.expectRevert();
        vm.prank(SENDER);
        faucet.withdrawAll(payableOwner);

        assertEq(payableOwner.balance, prevBal);
    }

    function test_dispense_noRoot_revert() public {
        vm.prank(OWNER);
        faucet.updateRoot(root, 0);
        bytes32[] memory proof = merkle.getProof(leaves, 0);
        vm.prank(ALICE);
        vm.expectRevert();
        faucet.dispense(0.1 ether, proof);
    }

    function test_dispense_invalidProofLength_revert() public {
        vm.prank(ALICE);
        vm.expectRevert();
        faucet.dispense(0.1 ether, new bytes32[](0));
    }

    function test_dispense_invalidAmount_aboveLimit_revert() public {
        vm.prank(OWNER);
        faucet.setDailyLimit(0.5 ether);

        bytes32[] memory proof = merkle.getProof(leaves, 0);
        vm.prank(ALICE);
        vm.expectRevert();
        faucet.dispense(1 ether, proof);
    }

    function test_dispense_insufficientFunds_revert() public {
        vm.prank(OWNER);
        faucet.setDailyLimit(1 ether);

        bytes32[] memory proof = merkle.getProof(leaves, 0);
        vm.prank(ALICE);
        vm.expectRevert();
        faucet.dispense(0.5 ether, proof);
    }

    function test_dispense_notWhitelisted_revert() public {
        vm.prank(OWNER);
        faucet.setDailyLimit(1 ether);

        vm.deal(address(faucet), 1 ether);
        bytes32[] memory proof = merkle.getProof(leaves, 0);
        vm.prank(HACKER);
        vm.expectRevert();
        faucet.dispense(0.1 ether, proof);
    }

    function test_dispense_alreadyClaimedToday_revert() public {
        vm.prank(OWNER);
        faucet.setDailyLimit(0.7 ether);

        vm.deal(address(faucet), 1 ether);
        bytes32[] memory proof = merkle.getProof(leaves, 0);
        vm.prank(ALICE);
        faucet.dispense(0.7 ether, proof);
        vm.prank(ALICE);
        vm.expectRevert();
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