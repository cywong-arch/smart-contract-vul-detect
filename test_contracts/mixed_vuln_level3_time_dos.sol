// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * MIXED VULNERABILITY LEVEL 3: TIME MANIPULATION + DoS + UNPROTECTED SELFDESTRUCT (ADVANCED)
 * Purpose: Test detection when contract contains time manipulation, DoS, AND unprotected selfdestruct vulnerabilities (advanced level)
 * Vulnerability: Advanced time manipulation vulnerabilities AND advanced DoS vulnerabilities AND unprotected selfdestruct vulnerabilities
 */
contract MixedVulnLevel3TimeDoS {
    address[] public users;
    mapping(address => uint256) public balances;
    mapping(address => uint256) public lockTime;
    mapping(address => uint256) public depositTime;
    mapping(address => uint256) public lastActionTime;
    mapping(address => bool) public isRegistered;
    mapping(address => uint256) public rewards;
    mapping(address => mapping(uint256 => uint256)) public timeBasedData;
    address public owner;
    uint256 public totalUsers;
    uint256 public constant LOCK_PERIOD = 86400;
    uint256 public constant REWARD_PERIOD = 3600;
    uint256 public constant MAX_USERS = 1000;
    uint256 public constant BATCH_LIMIT = 100;
    
    constructor() {
        owner = msg.sender;
    }
    
    // TIME MANIPULATION VULNERABILITIES (ADVANCED)
    
    // VULNERABLE #1: Time check with weak validation
    function withdraw() public {
        require(block.timestamp > lockTime[msg.sender], "Still locked");
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }
    
    // VULNERABLE #2: Time-based interest with weak check
    function calculateInterest() public view returns (uint256) {
        uint256 daysLocked = (block.timestamp - depositTime[msg.sender]) / 86400;
        return balances[msg.sender] * daysLocked / 100;
    }
    
    // VULNERABLE #3: Time check in if statement
    function earlyWithdraw() public {
        if (block.timestamp > lockTime[msg.sender] - 86400) {
            payable(msg.sender).transfer(balances[msg.sender]);
        }
    }
    
    // VULNERABLE #4: Time-based access control
    function adminFunction() public {
        require(block.timestamp > 1000000000, "Too early");
        totalUsers = 0;
    }
    
    // VULNERABLE #5: Time comparison with external call
    function claimReward() public {
        require(block.timestamp > lockTime[msg.sender], "Too early");
        payable(msg.sender).call{value: 1 ether}("");
    }
    
    // VULNERABLE #6: Time-based multiplier
    function getMultiplier() public view returns (uint256) {
        uint256 elapsed = block.timestamp - depositTime[msg.sender];
        return 1 + (elapsed / 3600);
    }
    
    // VULNERABLE #7: Time check with OR condition
    function unlock() public {
        require(block.timestamp >= lockTime[msg.sender] || msg.sender == address(0x1), "Not unlocked");
        balances[msg.sender] = balances[msg.sender] * 2;
    }
    
    // VULNERABLE #8: Time-based penalty calculation
    function calculatePenalty() public view returns (uint256) {
        uint256 timeSinceLock = block.timestamp - lockTime[msg.sender];
        if (timeSinceLock < 86400) {
            return balances[msg.sender] * 10 / 100;
        }
        return 0;
    }
    
    // VULNERABLE #9: Time-based reward rate
    function getRewardRate() public view returns (uint256) {
        uint256 daysLocked = (block.timestamp - depositTime[msg.sender]) / 86400;
        return 100 + (daysLocked * 10);
    }
    
    // VULNERABLE #10: Time-based tier calculation
    function getTier() public view returns (uint256) {
        uint256 monthsLocked = (block.timestamp - depositTime[msg.sender]) / 2592000;
        return monthsLocked;
    }
    
    // VULNERABLE #11: Time-based compounding
    function calculateCompound() public view returns (uint256) {
        uint256 periods = (block.timestamp - depositTime[msg.sender]) / 86400;
        return balances[msg.sender] * (100 + periods) / 100;
    }
    
    // VULNERABLE #12: Time in mapping key
    function setTimeBasedData(uint256 value) public {
        timeBasedData[msg.sender][block.timestamp] = value;
    }
    
    // VULNERABLE #13: Time-based expiration
    function checkExpiration() public view returns (bool) {
        return block.timestamp > depositTime[msg.sender] + 31536000;
    }
    
    // VULNERABLE #14: Time-based unlock percentage
    function getUnlockPercentage() public view returns (uint256) {
        uint256 elapsed = block.timestamp - lockTime[msg.sender];
        uint256 total = LOCK_PERIOD;
        return (elapsed * 100) / total;
    }
    
    // VULNERABLE #15: Time-based discount
    function getDiscount() public view returns (uint256) {
        uint256 daysSince = (block.timestamp - depositTime[msg.sender]) / 86400;
        return daysSince * 5;
    }
    
    // DENIAL OF SERVICE VULNERABILITIES (ADVANCED)
    
    // VULNERABLE #16: Limit check but can be exceeded through multiple calls
    function batchRegister(address[] memory newUsers) public {
        require(users.length + newUsers.length <= MAX_USERS, "Too many users");
        for (uint256 i = 0; i < newUsers.length; i++) {
            users.push(newUsers[i]);
        }
    }
    
    // VULNERABLE #17: External call with gas limit but recipient can consume all
    function distributeRewards() public {
        for (uint256 i = 0; i < users.length; i++) {
            address user = users[i];
            uint256 reward = rewards[user];
            if (reward > 0) {
                (bool success, ) = user.call{value: reward, gas: 2300}("");
                if (success) {
                    rewards[user] = 0;
                }
            }
        }
    }
    
    // VULNERABLE #18: Loop with parameter limit but parameter can be large
    function processUsers(uint256 maxIterations) public {
        uint256 iterations = 0;
        for (uint256 i = 0; i < users.length && iterations < maxIterations; i++) {
            balances[users[i]] += 100;
            iterations++;
        }
    }
    
    // VULNERABLE #19: Array operations with limit but nested operations
    function batchTransfer(address[] memory recipients, uint256[] memory amounts) public {
        require(recipients.length <= BATCH_LIMIT, "Too many recipients");
        for (uint256 i = 0; i < recipients.length; i++) {
            users.push(recipients[i]);
            balances[recipients[i]] += amounts[i];
            processUser(recipients[i]);
        }
    }
    
    // VULNERABLE #20: State modifications with condition but still loops all
    function updateBalances(uint256 multiplier) public {
        for (uint256 i = 0; i < users.length; i++) {
            if (balances[users[i]] > 0) {
                balances[users[i]] = balances[users[i]] * multiplier;
                totalUsers++;
            }
        }
    }
    
    // VULNERABLE #21: Gas-consuming operations with limit but expensive
    function calculateHashes(uint256 maxCount) public {
        uint256 count = 0;
        for (uint256 i = 0; i < users.length && count < maxCount; i++) {
            bytes32 hash = keccak256(abi.encodePacked(users[i], block.timestamp, block.number));
            bytes32 hash2 = keccak256(abi.encodePacked(hash, users[i]));
            balances[users[i]] = uint256(hash2) % 1000;
            count++;
        }
    }
    
    // VULNERABLE #22: External call with try-catch but still in loop
    function safeDistribute() public {
        for (uint256 i = 0; i < users.length; i++) {
            try this.transferReward(users[i]) {} catch {}
        }
    }
    
    // VULNERABLE #23: Nested loops with partial limit
    function processNested(uint256 maxOuter) public {
        for (uint256 i = 0; i < users.length && i < maxOuter; i++) {
            for (uint256 j = 0; j < users.length; j++) {
                balances[users[i]] += balances[users[j]] / 100;
                timeBasedData[users[i]][j] += 1;
            }
        }
    }
    
    // VULNERABLE #24: Mapping iteration with state changes
    function processAllRewards() public {
        for (uint256 i = 0; i < users.length; i++) {
            address user = users[i];
            if (rewards[user] > 0) {
                rewards[user] = rewards[user] * 2;
                totalUsers++;
            }
        }
    }
    
    // VULNERABLE #25: Multiple external calls with gas limit
    function distributeMultiple() public {
        for (uint256 i = 0; i < users.length; i++) {
            payable(users[i]).call{value: 0.1 ether, gas: 2300}("");
            payable(users[i]).call{value: 0.05 ether, gas: 2300}("");
        }
    }
    
    // COMBINED VULNERABILITIES (Time + DoS)
    
    // VULNERABLE #26: Time check in loop with external calls
    function processTimeBasedRewards() public {
        for (uint256 i = 0; i < users.length; i++) {
            if (block.timestamp > lockTime[users[i]]) {
                payable(users[i]).transfer(rewards[users[i]]);
            }
        }
    }
    
    // VULNERABLE #27: Time-based calculation in loop
    function calculateAllRewards() public {
        for (uint256 i = 0; i < users.length; i++) {
            uint256 timeElapsed = block.timestamp - depositTime[users[i]];
            rewards[users[i]] += timeElapsed * 10;
        }
    }
    
    // VULNERABLE #28: Time-based interest in loop
    function updateAllInterest() public {
        for (uint256 i = 0; i < users.length; i++) {
            uint256 daysLocked = (block.timestamp - depositTime[users[i]]) / 86400;
            balances[users[i]] += balances[users[i]] * daysLocked / 100;
        }
    }
    
    // VULNERABLE #29: Time check with external call in loop
    function claimAllRewards() public {
        for (uint256 i = 0; i < users.length; i++) {
            if (block.timestamp > lockTime[users[i]]) {
                payable(users[i]).call{value: rewards[users[i]]}("");
            }
        }
    }
    
    // VULNERABLE #30: Time-based multiplier in loop
    function applyMultipliers() public {
        for (uint256 i = 0; i < users.length; i++) {
            uint256 elapsed = block.timestamp - depositTime[users[i]];
            uint256 multiplier = 1 + (elapsed / 3600);
            balances[users[i]] = balances[users[i]] * multiplier;
        }
    }
    
    // VULNERABLE #31: Time-based tier calculation in loop
    function updateAllTiers() public {
        for (uint256 i = 0; i < users.length; i++) {
            uint256 monthsLocked = (block.timestamp - depositTime[users[i]]) / 2592000;
            rewards[users[i]] += monthsLocked * 100;
        }
    }
    
    // VULNERABLE #32: Time-based compounding in loop
    function compoundAllBalances() public {
        for (uint256 i = 0; i < users.length; i++) {
            uint256 periods = (block.timestamp - depositTime[users[i]]) / 86400;
            balances[users[i]] = balances[users[i]] * (100 + periods) / 100;
        }
    }
    
    // VULNERABLE #33: Time check in nested loop
    function processNestedTimeBased() public {
        for (uint256 i = 0; i < users.length; i++) {
            for (uint256 j = 0; j < users.length; j++) {
                if (block.timestamp > lockTime[users[i]]) {
                    balances[users[i]] += balances[users[j]] / 100;
                }
            }
        }
    }
    
    // VULNERABLE #34: Time-based calculation with external call in loop
    function calculateAndDistribute() public {
        for (uint256 i = 0; i < users.length; i++) {
            uint256 timeElapsed = block.timestamp - depositTime[users[i]];
            uint256 reward = timeElapsed * 10;
            if (reward > 0) {
                payable(users[i]).call{value: reward}("");
            }
        }
    }
    
    // VULNERABLE #35: Time-based penalty calculation in loop
    function calculateAllPenalties() public {
        for (uint256 i = 0; i < users.length; i++) {
            uint256 timeSinceLock = block.timestamp - lockTime[users[i]];
            if (timeSinceLock < 86400) {
                balances[users[i]] -= balances[users[i]] * 10 / 100;
            }
        }
    }
    
    // UNPROTECTED SELFDESTRUCT VULNERABILITIES
    
    // VULNERABLE #36: Unprotected selfdestruct call
    function kill() public {
        selfdestruct(payable(owner)); // No access control
    }
    
    // VULNERABLE #37: Selfdestruct with weak condition
    function destroy() public {
        if (totalUsers == 0) {
            selfdestruct(payable(owner)); // Minimal condition
        }
    }
    
    // VULNERABLE #38: Selfdestruct with balance check only
    function emergencyShutdown() public {
        require(address(this).balance > 0, "No balance");
        selfdestruct(payable(owner)); // Weak condition
    }
    
    // VULNERABLE #39: Selfdestruct after external call
    function terminate() public {
        payable(owner).call{value: address(this).balance / 2}(""); // External call
        selfdestruct(payable(owner)); // Selfdestruct after external call
    }
    
    // VULNERABLE #40: Selfdestruct with OR condition
    function close() public {
        require(msg.sender == owner || totalUsers == 0, "Not authorized"); // Weak OR condition
        selfdestruct(payable(owner));
    }
    
    // VULNERABLE #41: Selfdestruct in if statement
    function remove() public {
        if (block.timestamp > 1000000000) { // Weak time check
            selfdestruct(payable(owner));
        }
    }
    
    // VULNERABLE #42: Selfdestruct with recipient as caller
    function deleteContract() public {
        selfdestruct(payable(msg.sender)); // Should be owner, not msg.sender
    }
    
    // VULNERABLE #43: Selfdestruct with weak totalSupply check
    function shutdown() public {
        require(balances[msg.sender] > 0, "No balance"); // Weak condition
        selfdestruct(payable(owner));
    }
    
    // VULNERABLE #44: Selfdestruct in fallback
    receive() external payable {
        if (msg.value > 100 ether) {
            selfdestruct(payable(owner)); // In receive function
        } else {
            deposit();
        }
    }
    
    // VULNERABLE #45: Selfdestruct with time check
    function expire() public {
        require(block.timestamp > depositTime[msg.sender] + 31536000, "Not expired");
        selfdestruct(payable(owner)); // Time-based but unprotected
    }
    
    // VULNERABLE #46: Selfdestruct with balance threshold
    function finalize() public {
        if (address(this).balance < 1 ether) {
            selfdestruct(payable(owner)); // Balance threshold
        }
    }
    
    // VULNERABLE #47: Selfdestruct with user balance check
    function end() public {
        require(balances[msg.sender] > 1000, "Insufficient balance");
        selfdestruct(payable(owner)); // User balance check
    }
    
    // VULNERABLE #48: Selfdestruct in loop
    function batchDestroy() public {
        for (uint256 i = 0; i < users.length; i++) {
            if (i == users.length - 1) {
                selfdestruct(payable(owner)); // In loop
            }
        }
    }
    
    // VULNERABLE #49: Selfdestruct after state change
    function finalizeContract() public {
        totalUsers = 0;
        selfdestruct(payable(owner)); // After state change
    }
    
    // VULNERABLE #50: Selfdestruct with nested condition
    function destroyContract() public {
        if (totalUsers > 0) {
            if (address(this).balance > 0) {
                selfdestruct(payable(owner)); // Nested conditions
            }
        }
    }
    
    function processUser(address user) internal {
        lastActionTime[user] = block.timestamp;
    }
    
    function transferReward(address user) external {
        uint256 reward = rewards[user];
        if (reward > 0) {
            payable(user).transfer(reward);
            rewards[user] = 0;
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
    
    // Note: receive() function is defined in VULNERABLE #44 above
}

