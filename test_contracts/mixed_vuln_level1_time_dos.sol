// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * MIXED VULNERABILITY LEVEL 1: TIME MANIPULATION ONLY (100%)
 * Purpose: Test detection when contract contains ONLY time manipulation vulnerabilities (basic level)
 * Vulnerability: Basic time manipulation vulnerabilities ONLY
 */
contract MixedVulnLevel1TimeDoS {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public lockTime;
    mapping(address => uint256) public depositTime;
    
    // TIME MANIPULATION VULNERABILITIES ONLY
    
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
    
    // VULNERABLE #5: Time-based reward calculation
    function getReward() public view returns (uint256) {
        return (block.timestamp - lockTime[msg.sender]) * 10; // Direct time multiplication
    }
    
    // VULNERABLE #6: Time-based interest calculation
    function calculateInterest() public view returns (uint256) {
        uint256 daysLocked = (block.timestamp - depositTime[msg.sender]) / 86400;
        return balances[msg.sender] * daysLocked / 100; // Time-based calculation
    }
    
    // VULNERABLE #7: Time check in if statement
    function earlyWithdraw() public {
        if (block.timestamp > lockTime[msg.sender] - 86400) { // Can be manipulated
            payable(msg.sender).transfer(balances[msg.sender]);
        }
    }
    
    // VULNERABLE #8: Time-based access control
    function adminFunction() public {
        require(block.timestamp > 1000000000, "Too early"); // Weak time check
        balances[msg.sender] = balances[msg.sender] * 2;
    }
    
    // VULNERABLE #9: Time comparison with external call
    function claimTimeBasedReward() public {
        require(block.timestamp > lockTime[msg.sender], "Too early");
        payable(msg.sender).transfer(1 ether); // External call after time check
    }
    
    // VULNERABLE #10: Time-based multiplier
    function getMultiplier() public view returns (uint256) {
        uint256 elapsed = block.timestamp - depositTime[msg.sender];
        return 1 + (elapsed / 3600); // Time-based multiplier
    }
    
    // VULNERABLE #11: Time check with OR condition
    function unlock() public {
        require(block.timestamp >= lockTime[msg.sender] || msg.sender == address(0x1), "Not unlocked");
        balances[msg.sender] = balances[msg.sender] * 2;
    }
    
    // VULNERABLE #12: Time-based penalty calculation
    function calculatePenalty() public view returns (uint256) {
        uint256 timeSinceLock = block.timestamp - lockTime[msg.sender];
        if (timeSinceLock < 86400) {
            return balances[msg.sender] * 10 / 100; // Penalty based on time
        }
        return 0;
    }
    
    // VULNERABLE #13: Time-based reward rate
    function getRewardRate() public view returns (uint256) {
        uint256 daysLocked = (block.timestamp - depositTime[msg.sender]) / 86400;
        return 100 + (daysLocked * 10); // Rate based on time
    }
    
    // VULNERABLE #14: Time-based expiration check
    function checkExpiration() public view returns (bool) {
        return block.timestamp > depositTime[msg.sender] + 31536000; // 1 year
    }
    
    // VULNERABLE #15: Time-based unlock percentage
    function getUnlockPercentage() public view returns (uint256) {
        uint256 elapsed = block.timestamp - lockTime[msg.sender];
        uint256 total = 86400; // 24 hours
        return (elapsed * 100) / total;
    }
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
        depositTime[msg.sender] = block.timestamp;
        lockTime[msg.sender] = block.timestamp + 86400; // 24 hours
    }
    
    receive() external payable {
        deposit();
    }
}
