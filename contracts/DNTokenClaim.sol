// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * DNTokenClaim
 *
 * Two-round Merkle based token claim contract for Linea mainnet.
 * - Each round has its own ERC20 claim token and Merkle root.
 * - Owner can pause/unpause globally or per round.
 * - Owner can update each round's token address and Merkle root.
 * - Users can only claim the exact amount proven by the Merkle proof.
 * - Users can only claim once per round.
 *
 * Merkle leaf format used by the frontend/generator:
 * keccak256(bytes.concat(keccak256(abi.encode(roundId, account, amount))))
 */

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 value) external returns (bool);
}

library SafeERC20 {
    function safeTransfer(IERC20 token, address to, uint256 value) internal {
        (bool success, bytes memory data) = address(token).call(
            abi.encodeWithSelector(token.transfer.selector, to, value)
        );
        require(success && (data.length == 0 || abi.decode(data, (bool))), "TOKEN_TRANSFER_FAILED");
    }
}

library MerkleProof {
    function verify(bytes32[] memory proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {
        return processProof(proof, leaf) == root;
    }

    function processProof(bytes32[] memory proof, bytes32 leaf) internal pure returns (bytes32 computedHash) {
        computedHash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            computedHash = _hashPair(computedHash, proof[i]);
        }
    }

    function _hashPair(bytes32 a, bytes32 b) private pure returns (bytes32) {
        return a < b ? _efficientHash(a, b) : _efficientHash(b, a);
    }

    function _efficientHash(bytes32 a, bytes32 b) private pure returns (bytes32 value) {
        assembly {
            mstore(0x00, a)
            mstore(0x20, b)
            value := keccak256(0x00, 0x40)
        }
    }
}

abstract contract ReentrancyGuard {
    uint256 private constant NOT_ENTERED = 1;
    uint256 private constant ENTERED = 2;
    uint256 private _status = NOT_ENTERED;

    modifier nonReentrant() {
        require(_status != ENTERED, "REENTRANT_CALL");
        _status = ENTERED;
        _;
        _status = NOT_ENTERED;
    }
}

abstract contract Ownable {
    address public owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    modifier onlyOwner() {
        require(msg.sender == owner, "NOT_OWNER");
        _;
    }

    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "ZERO_OWNER");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}

contract DNTokenClaim is Ownable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    struct Round {
        IERC20 token;
        bytes32 merkleRoot;
        bool paused;
        uint256 totalClaimed;
    }

    mapping(uint256 => Round) public rounds;
    mapping(uint256 => mapping(address => bool)) public hasClaimed;

    bool public paused;

    event Claimed(uint256 indexed roundId, address indexed account, address indexed token, uint256 amount);
    event GlobalPauseSet(bool paused);
    event RoundPauseSet(uint256 indexed roundId, bool paused);
    event RoundConfigured(uint256 indexed roundId, address indexed token, bytes32 merkleRoot);
    event RescueTokens(address indexed token, address indexed to, uint256 amount);

    constructor(address round1Token, bytes32 round1Root, address round2Token, bytes32 round2Root) {
        _configureRound(1, round1Token, round1Root);
        _configureRound(2, round2Token, round2Root);
    }

    function claim(uint256 roundId, uint256 amount, bytes32[] calldata proof) external nonReentrant {
        require(!paused, "CLAIMS_PAUSED");
        Round storage round = rounds[roundId];
        require(!round.paused, "ROUND_PAUSED");
        require(address(round.token) != address(0), "TOKEN_NOT_SET");
        require(round.merkleRoot != bytes32(0), "ROOT_NOT_SET");
        require(amount > 0, "ZERO_AMOUNT");
        require(!hasClaimed[roundId][msg.sender], "ALREADY_CLAIMED");

        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(roundId, msg.sender, amount))));
        require(MerkleProof.verify(proof, round.merkleRoot, leaf), "INVALID_PROOF");

        hasClaimed[roundId][msg.sender] = true;
        round.totalClaimed += amount;
        round.token.safeTransfer(msg.sender, amount);

        emit Claimed(roundId, msg.sender, address(round.token), amount);
    }

    function isClaimable(uint256 roundId, address account, uint256 amount, bytes32[] calldata proof) external view returns (bool) {
        Round storage round = rounds[roundId];
        if (paused || round.paused || hasClaimed[roundId][account] || amount == 0) return false;
        if (address(round.token) == address(0) || round.merkleRoot == bytes32(0)) return false;
        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(roundId, account, amount))));
        return MerkleProof.verify(proof, round.merkleRoot, leaf);
    }

    function configureRound(uint256 roundId, address token, bytes32 merkleRoot) external onlyOwner {
        _configureRound(roundId, token, merkleRoot);
    }

    function setGlobalPaused(bool value) external onlyOwner {
        paused = value;
        emit GlobalPauseSet(value);
    }

    function setRoundPaused(uint256 roundId, bool value) external onlyOwner {
        rounds[roundId].paused = value;
        emit RoundPauseSet(roundId, value);
    }

    function rescueTokens(address token, address to, uint256 amount) external onlyOwner {
        require(to != address(0), "ZERO_TO");
        IERC20(token).safeTransfer(to, amount);
        emit RescueTokens(token, to, amount);
    }

    function contractTokenBalance(uint256 roundId) external view returns (uint256) {
        IERC20 token = rounds[roundId].token;
        if (address(token) == address(0)) return 0;
        return token.balanceOf(address(this));
    }

    function _configureRound(uint256 roundId, address token, bytes32 merkleRoot) internal {
        require(roundId == 1 || roundId == 2, "ROUND_MUST_BE_1_OR_2");
        require(token != address(0), "ZERO_TOKEN");
        require(merkleRoot != bytes32(0), "ZERO_ROOT");
        rounds[roundId].token = IERC20(token);
        rounds[roundId].merkleRoot = merkleRoot;
        emit RoundConfigured(roundId, token, merkleRoot);
    }
}
