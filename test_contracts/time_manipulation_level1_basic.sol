// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * TIME MANIPULATION LEVEL 1: BASIC
 * Purpose: Test basic time manipulation vulnerabilities - obvious block.timestamp usage
 * Vulnerability: 10 basic time manipulation vulnerabilities
 */
contract TimeManipulationLevel1 {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public lockTime;
    uint256 public totalSupply;
    address public owner;
    
    constructor() {
        owner = msg.sender;
        totalSupply = 1000000;
    }
    
    // VULNERABLE #1: Direct time comparison without validation
    function withdraw() public {
        require(block.timestamp > lockTime[msg.sender], "Still locked");
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(amount); // Miner can manipulate timestamp
    }
    
    // VULNERABLE #2: Time-based calculation that can be manipulated
    function calculateReward() public view returns (uint256) {
        uint256 timeElapsed = block.timestamp - lockTime[msg.sender];
        return timeElapsed * 100; // Can be manipulated by miners
    }
    
    // VULNERABLE #3: Direct assignment to time variable
    function setLockTime(uint256 newTime) public {
        lockTime[msg.sender] = block.timestamp; // No validation, uses current block time
    }
    
    // VULNERABLE #4: Time check with external call
    function claimReward() public {
        require(block.timestamp > lockTime[msg.sender], "Too early");
        payable(msg.sender).call{value: 1 ether}(""); // External call after time check
    }
    
    // VULNERABLE #5: Time-based loop condition
    function processClaims() public {
        uint256 currentTime = block.timestamp;
        while (currentTime < block.timestamp + 3600) { // Dangerous loop with time
            currentTime++;
        }
    }
    
    // VULNERABLE #6: Time-based reward calculation
    function getReward() public view returns (uint256) {
        return (block.timestamp - lockTime[msg.sender]) * 10; // Direct time multiplication
    }
    
    // VULNERABLE #7: Time comparison in require
    function unlock() public {
        require(block.timestamp >= lockTime[msg.sender], "Not unlocked yet");
        balances[msg.sender] = balances[msg.sender] * 2; // Reward based on time
    }
    
    // VULNERABLE #8: Time-based interest calculation
    function calculateInterest() public view returns (uint256) {
        uint256 daysLocked = (block.timestamp - lockTime[msg.sender]) / 86400;
        return balances[msg.sender] * daysLocked / 100; // Interest based on time
    }
    
    // VULNERABLE #9: Time check without proper validation
    function earlyWithdraw() public {
        if (block.timestamp > lockTime[msg.sender] - 86400) { // Can be manipulated
            payable(msg.sender).transfer(balances[msg.sender]);
        }
    }
    
    // VULNERABLE #10: Time-based access control
    function adminFunction() public {
        require(block.timestamp > 1000000000, "Too early"); // Weak time check
        // Admin operations
        totalSupply = 0;
    }
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
        lockTime[msg.sender] = block.timestamp + 86400; // 24 hours
    }
    
    receive() external payable {
        deposit();
    }
}

