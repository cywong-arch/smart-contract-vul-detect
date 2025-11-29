// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * MIXED VULNERABILITY LEVEL 2: TIME MANIPULATION + DoS (INTERMEDIATE)
 * Purpose: Test detection when contract contains time manipulation AND DoS vulnerabilities (intermediate level)
 * Vulnerability: Intermediate time manipulation vulnerabilities AND intermediate DoS vulnerabilities
 */
contract MixedVulnLevel2TimeDoS {
    address[] public users;
    mapping(address => uint256) public balances;
    mapping(address => uint256) public lockTime;
    mapping(address => uint256) public depositTime;
    mapping(address => bool) public isRegistered;
    mapping(address => uint256) public rewards;
    uint256 public totalUsers;
    uint256 public constant LOCK_PERIOD = 86400;
    uint256 public constant MAX_USERS = 1000; // Limit exists but can be exceeded
    
    // TIME MANIPULATION VULNERABILITIES (INTERMEDIATE)
    
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
        totalUsers = 0;
    }
    
    // VULNERABLE #6: Time comparison with external call
    function claimReward() public {
        require(block.timestamp > lockTime[msg.sender], "Too early");
        payable(msg.sender).call{value: 1 ether}(""); // External call after time check
    }
    
    // VULNERABLE #7: Time-based multiplier
    function getMultiplier() public view returns (uint256) {
        uint256 elapsed = block.timestamp - depositTime[msg.sender];
        return 1 + (elapsed / 3600); // Time-based multiplier
    }
    
    // VULNERABLE #8: Time check with OR condition
    function unlock() public {
        require(block.timestamp >= lockTime[msg.sender] || msg.sender == address(0x1), "Not unlocked");
        balances[msg.sender] = balances[msg.sender] * 2;
    }
    
    // VULNERABLE #9: Time-based penalty calculation
    function calculatePenalty() public view returns (uint256) {
        uint256 timeSinceLock = block.timestamp - lockTime[msg.sender];
        if (timeSinceLock < 86400) {
            return balances[msg.sender] * 10 / 100; // Penalty based on time
        }
        return 0;
    }
    
    // VULNERABLE #10: Time-based reward rate
    function getRewardRate() public view returns (uint256) {
        uint256 daysLocked = (block.timestamp - depositTime[msg.sender]) / 86400;
        return 100 + (daysLocked * 10); // Rate based on time
    }
    
    // DENIAL OF SERVICE VULNERABILITIES (INTERMEDIATE)
    
    // VULNERABLE #11: Limit check but can be bypassed
    function batchRegister(address[] memory newUsers) public {
        require(users.length + newUsers.length <= MAX_USERS, "Too many users");
        for (uint256 i = 0; i < newUsers.length; i++) {
            users.push(newUsers[i]); // Still unbounded if called multiple times
        }
    }
    
    // VULNERABLE #12: External call with gas limit but can still fail
    function distributeRewards() public {
        for (uint256 i = 0; i < users.length; i++) {
            address user = users[i];
            uint256 reward = rewards[user];
            if (reward > 0) {
                (bool success, ) = user.call{value: reward, gas: 2300}(""); // Low gas but can still fail
                if (success) {
                    rewards[user] = 0;
                }
            }
        }
    }
    
    // VULNERABLE #13: Loop with break but can still be expensive
    function processUsers(uint256 maxIterations) public {
        uint256 iterations = 0;
        for (uint256 i = 0; i < users.length && iterations < maxIterations; i++) {
            balances[users[i]] += 100;
            iterations++;
        }
    }
    
    // VULNERABLE #14: Array operations with partial limits
    function batchTransfer(address[] memory recipients, uint256[] memory amounts) public {
        require(recipients.length <= 100, "Too many recipients"); // Limit but still expensive
        for (uint256 i = 0; i < recipients.length; i++) {
            users.push(recipients[i]);
            balances[recipients[i]] += amounts[i];
        }
    }
    
    // VULNERABLE #15: State modifications with condition
    function updateBalances(uint256 multiplier) public {
        for (uint256 i = 0; i < users.length; i++) {
            if (balances[users[i]] > 0) { // Condition but still loops all
                balances[users[i]] = balances[users[i]] * multiplier;
            }
        }
    }
    
    // COMBINED VULNERABILITIES (Time + DoS)
    
    // VULNERABLE #16: Time check in loop with external calls
    function processTimeBasedRewards() public {
        for (uint256 i = 0; i < users.length; i++) {
            if (block.timestamp > lockTime[users[i]]) { // Time check in loop
                payable(users[i]).transfer(rewards[users[i]]); // External call in loop
            }
        }
    }
    
    // VULNERABLE #17: Time-based calculation in loop
    function calculateAllRewards() public {
        for (uint256 i = 0; i < users.length; i++) {
            uint256 timeElapsed = block.timestamp - depositTime[users[i]]; // Time calc in loop
            rewards[users[i]] += timeElapsed * 10; // State modification in loop
        }
    }
    
    // VULNERABLE #18: Time-based interest in loop
    function updateAllInterest() public {
        for (uint256 i = 0; i < users.length; i++) {
            uint256 daysLocked = (block.timestamp - depositTime[users[i]]) / 86400; // Time calc
            balances[users[i]] += balances[users[i]] * daysLocked / 100; // State write in loop
        }
    }
    
    // VULNERABLE #19: Time check with external call in loop
    function claimAllRewards() public {
        for (uint256 i = 0; i < users.length; i++) {
            if (block.timestamp > lockTime[users[i]]) { // Time check
                payable(users[i]).call{value: rewards[users[i]]}(""); // External call in loop
            }
        }
    }
    
    // VULNERABLE #20: Time-based multiplier in loop
    function applyMultipliers() public {
        for (uint256 i = 0; i < users.length; i++) {
            uint256 elapsed = block.timestamp - depositTime[users[i]]; // Time calc
            uint256 multiplier = 1 + (elapsed / 3600); // Time-based multiplier
            balances[users[i]] = balances[users[i]] * multiplier; // State write in loop
        }
    }
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
        depositTime[msg.sender] = block.timestamp;
        lockTime[msg.sender] = block.timestamp + LOCK_PERIOD;
    }
    
    function register() public payable {
        require(!isRegistered[msg.sender], "Already registered");
        users.push(msg.sender);
        isRegistered[msg.sender] = true;
        balances[msg.sender] = msg.value;
        totalUsers++;
    }
    
    receive() external payable {
        deposit();
    }
}

