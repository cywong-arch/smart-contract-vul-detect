// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * TIME MANIPULATION LEVEL 2: INTERMEDIATE
 * Purpose: Test intermediate time manipulation vulnerabilities - partial validation and complex patterns
 * Vulnerability: 30 intermediate time manipulation vulnerabilities
 */
contract TimeManipulationLevel2 {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public lockTime;
    mapping(address => uint256) public depositTime;
    mapping(address => mapping(uint256 => uint256)) public timeBasedData;
    uint256 public totalSupply;
    address public owner;
    uint256 public constant LOCK_PERIOD = 86400;
    
    constructor() {
        owner = msg.sender;
        totalSupply = 1000000;
    }
    
    // VULNERABLE #1: Time check with weak validation
    function withdraw() public {
        require(block.timestamp > lockTime[msg.sender], "Still locked");
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(amount); // Time can be manipulated
    }
    
    // VULNERABLE #2: Time calculation with division
    function calculateReward() public view returns (uint256) {
        uint256 timeElapsed = block.timestamp - lockTime[msg.sender];
        return timeElapsed * 100; // Can be manipulated
    }
    
    // VULNERABLE #3: Time-based interest with weak check
    function calculateInterest() public view returns (uint256) {
        uint256 daysLocked = (block.timestamp - depositTime[msg.sender]) / 86400;
        return balances[msg.sender] * daysLocked / 100; // Time-based calculation
    }
    
    // VULNERABLE #4: Time check in if statement
    function earlyWithdraw() public {
        if (block.timestamp > lockTime[msg.sender] - 86400) { // Can be manipulated
            payable(msg.sender).transfer(balances[msg.sender]);
        }
    }
    
    // VULNERABLE #5: Time-based access control
    function adminFunction() public {
        require(block.timestamp > 1000000000, "Too early"); // Weak time check
        totalSupply = 0;
    }
    
    // VULNERABLE #6: Time comparison with external call
    function claimReward() public {
        require(block.timestamp > lockTime[msg.sender], "Too early");
        payable(msg.sender).call{value: 1 ether}(""); // External call after time check
    }
    
    // VULNERABLE #7: Time-based loop
    function processClaims() public {
        uint256 currentTime = block.timestamp;
        while (currentTime < block.timestamp + 3600) { // Dangerous loop
            currentTime++;
        }
    }
    
    // VULNERABLE #8: Time assignment without validation
    function setLockTime(uint256 newTime) public {
        lockTime[msg.sender] = block.timestamp; // No validation
    }
    
    // VULNERABLE #9: Time-based multiplier
    function getMultiplier() public view returns (uint256) {
        uint256 elapsed = block.timestamp - depositTime[msg.sender];
        return 1 + (elapsed / 3600); // Time-based multiplier
    }
    
    // VULNERABLE #10: Time check with OR condition
    function unlock() public {
        require(block.timestamp >= lockTime[msg.sender] || msg.sender == owner, "Not unlocked");
        balances[msg.sender] = balances[msg.sender] * 2;
    }
    
    // VULNERABLE #11: Time-based penalty calculation
    function calculatePenalty() public view returns (uint256) {
        uint256 timeSinceLock = block.timestamp - lockTime[msg.sender];
        if (timeSinceLock < 86400) {
            return balances[msg.sender] * 10 / 100; // Penalty based on time
        }
        return 0;
    }
    
    // VULNERABLE #12: Time comparison in mapping
    function checkLockStatus(address user) public view returns (bool) {
        return block.timestamp > lockTime[user]; // Direct comparison
    }
    
    // VULNERABLE #13: Time-based reward rate
    function getRewardRate() public view returns (uint256) {
        uint256 daysLocked = (block.timestamp - depositTime[msg.sender]) / 86400;
        return 100 + (daysLocked * 10); // Rate based on time
    }
    
    // VULNERABLE #14: Time check with subtraction
    function canWithdraw() public view returns (bool) {
        return block.timestamp - lockTime[msg.sender] > 0; // Time subtraction
    }
    
    // VULNERABLE #15: Time-based bonus
    function calculateBonus() public view returns (uint256) {
        uint256 hoursLocked = (block.timestamp - depositTime[msg.sender]) / 3600;
        return hoursLocked * 10; // Bonus based on time
    }
    
    // VULNERABLE #16: Time in require with message
    function withdrawWithTime() public {
        require(block.timestamp > lockTime[msg.sender], "Time not reached");
        payable(msg.sender).transfer(balances[msg.sender]);
    }
    
    // VULNERABLE #17: Time-based fee calculation
    function calculateFee() public view returns (uint256) {
        uint256 timeElapsed = block.timestamp - depositTime[msg.sender];
        uint256 fee = timeElapsed / 3600; // Fee based on hours
        return fee * 100;
    }
    
    // VULNERABLE #18: Time check in nested condition
    function complexWithdraw() public {
        if (balances[msg.sender] > 0) {
            if (block.timestamp > lockTime[msg.sender]) {
                payable(msg.sender).transfer(balances[msg.sender]);
            }
        }
    }
    
    // VULNERABLE #19: Time-based unlock percentage
    function getUnlockPercentage() public view returns (uint256) {
        uint256 elapsed = block.timestamp - lockTime[msg.sender];
        uint256 total = LOCK_PERIOD;
        return (elapsed * 100) / total; // Percentage based on time
    }
    
    // VULNERABLE #20: Time comparison with constant
    function checkTime() public view returns (bool) {
        return block.timestamp > 1000000000; // Comparison with constant
    }
    
    // VULNERABLE #21: Time-based voting
    function vote() public {
        require(block.timestamp > 1000000000 && block.timestamp < 2000000000, "Not voting period");
        // Voting logic
    }
    
    // VULNERABLE #22: Time in arithmetic operation
    function calculateValue() public view returns (uint256) {
        return balances[msg.sender] * (block.timestamp - depositTime[msg.sender]); // Time multiplication
    }
    
    // VULNERABLE #23: Time check with external function
    function processWithTime() public {
        if (isTimeValid()) {
            balances[msg.sender] += 100;
        }
    }
    
    // VULNERABLE #24: Time-based discount
    function getDiscount() public view returns (uint256) {
        uint256 daysSince = (block.timestamp - depositTime[msg.sender]) / 86400;
        return daysSince * 5; // Discount based on days
    }
    
    // VULNERABLE #25: Time in loop condition
    function processTimeLoop() public {
        uint256 startTime = block.timestamp;
        while (block.timestamp < startTime + 3600) { // Loop with time
            // Process
        }
    }
    
    // VULNERABLE #26: Time-based tier calculation
    function getTier() public view returns (uint256) {
        uint256 monthsLocked = (block.timestamp - depositTime[msg.sender]) / 2592000;
        return monthsLocked; // Tier based on months
    }
    
    // VULNERABLE #27: Time check with modifier-like logic
    function withdrawIfTime() public {
        bool timeValid = block.timestamp > lockTime[msg.sender];
        if (timeValid) {
            payable(msg.sender).transfer(balances[msg.sender]);
        }
    }
    
    // VULNERABLE #28: Time-based compounding
    function calculateCompound() public view returns (uint256) {
        uint256 periods = (block.timestamp - depositTime[msg.sender]) / 86400;
        return balances[msg.sender] * (100 + periods) / 100; // Compounding
    }
    
    // VULNERABLE #29: Time in mapping key
    function setTimeBasedData(uint256 value) public {
        timeBasedData[msg.sender][block.timestamp] = value; // Time as key
    }
    
    // VULNERABLE #30: Time-based expiration
    function checkExpiration() public view returns (bool) {
        return block.timestamp > depositTime[msg.sender] + 31536000; // 1 year expiration
    }
    
    function isTimeValid() internal view returns (bool) {
        return block.timestamp > lockTime[msg.sender];
    }
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
        depositTime[msg.sender] = block.timestamp;
        lockTime[msg.sender] = block.timestamp + LOCK_PERIOD;
    }
    
    receive() external payable {
        deposit();
    }
}

