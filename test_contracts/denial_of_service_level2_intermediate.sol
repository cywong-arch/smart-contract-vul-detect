// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * DENIAL OF SERVICE LEVEL 2: INTERMEDIATE
 * Purpose: Test intermediate denial of service vulnerabilities - partial limits and complex patterns
 * Vulnerability: 30 intermediate DOS vulnerabilities
 */
contract DenialOfServiceLevel2 {
    address[] public users;
    mapping(address => uint256) public balances;
    mapping(address => bool) public isRegistered;
    mapping(address => uint256) public rewards;
    uint256 public totalUsers;
    uint256 public constant MAX_USERS = 1000; // Limit exists but can be exceeded
    
    // VULNERABLE #1: Limit check but can be bypassed
    function batchRegister(address[] memory newUsers) public {
        require(users.length + newUsers.length <= MAX_USERS, "Too many users");
        for (uint256 i = 0; i < newUsers.length; i++) {
            users.push(newUsers[i]); // Still unbounded if called multiple times
        }
    }
    
    // VULNERABLE #2: External call with gas limit but can still fail
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
    
    // VULNERABLE #3: Loop with break but can still be expensive
    function processUsers(uint256 maxIterations) public {
        uint256 iterations = 0;
        for (uint256 i = 0; i < users.length && iterations < maxIterations; i++) {
            balances[users[i]] += 100;
            iterations++;
        }
    }
    
    // VULNERABLE #4: Array operations with partial limits
    function batchTransfer(address[] memory recipients, uint256[] memory amounts) public {
        require(recipients.length <= 100, "Too many recipients"); // Limit but still expensive
        for (uint256 i = 0; i < recipients.length; i++) {
            users.push(recipients[i]);
            balances[recipients[i]] += amounts[i];
        }
    }
    
    // VULNERABLE #5: State modifications with condition
    function updateBalances(uint256 multiplier) public {
        for (uint256 i = 0; i < users.length; i++) {
            if (balances[users[i]] > 0) { // Condition but still loops all
                balances[users[i]] = balances[users[i]] * multiplier;
            }
        }
    }
    
    // VULNERABLE #6: Gas-consuming operations with limit
    function calculateHashes(uint256 maxCount) public {
        uint256 count = 0;
        for (uint256 i = 0; i < users.length && count < maxCount; i++) {
            bytes32 hash = keccak256(abi.encodePacked(users[i], block.timestamp));
            balances[users[i]] = uint256(hash) % 1000;
            count++;
        }
    }
    
    // VULNERABLE #7: External call with try-catch but still in loop
    function safeDistribute() public {
        for (uint256 i = 0; i < users.length; i++) {
            try this.transferReward(users[i]) {} catch {} // Still loops all users
        }
    }
    
    // VULNERABLE #8: Nested loops with partial limit
    function processNested(uint256 maxOuter) public {
        for (uint256 i = 0; i < users.length && i < maxOuter; i++) {
            for (uint256 j = 0; j < users.length; j++) { // Inner loop still unbounded
                balances[users[i]] += balances[users[j]] / 100;
            }
        }
    }
    
    // VULNERABLE #9: Mapping iteration pattern
    function processAllRewards() public {
        for (uint256 i = 0; i < users.length; i++) {
            address user = users[i];
            if (rewards[user] > 0) {
                rewards[user] = rewards[user] * 2; // State write in loop
            }
        }
    }
    
    // VULNERABLE #10: Multiple external calls with gas limit
    function distributeMultiple() public {
        for (uint256 i = 0; i < users.length; i++) {
            payable(users[i]).call{value: 0.1 ether, gas: 2300}("");
            payable(users[i]).call{value: 0.05 ether, gas: 2300}(""); // Multiple calls
        }
    }
    
    // VULNERABLE #11: Fallback with expensive operations
    fallback() external payable {
        for (uint256 i = 0; i < users.length && i < 50; i++) { // Partial limit
            balances[users[i]] += 1;
        }
    }
    
    // VULNERABLE #12: While loop with condition
    function processWhile() public {
        uint256 i = 0;
        while (i < users.length && i < 100) { // Limit but still can be expensive
            balances[users[i]] += 100;
            i++;
        }
    }
    
    // VULNERABLE #13: Array push in multiple functions
    function addUser(address user) public {
        users.push(user); // Can be called multiple times
        isRegistered[user] = true;
    }
    
    // VULNERABLE #14: State read in loop
    function calculateTotal() public view returns (uint256) {
        uint256 total = 0;
        for (uint256 i = 0; i < users.length; i++) {
            total += balances[users[i]]; // Expensive reads in loop
        }
        return total;
    }
    
    // VULNERABLE #15: Complex calculation in loop
    function updateComplex() public {
        for (uint256 i = 0; i < users.length; i++) {
            uint256 balance = balances[users[i]];
            uint256 reward = rewards[users[i]];
            balances[users[i]] = balance + (reward * 2) / 3; // Complex calculation
        }
    }
    
    // VULNERABLE #16: External call to contract
    function callContract(address contractAddr) public {
        for (uint256 i = 0; i < users.length; i++) {
            (bool success, ) = contractAddr.call(
                abi.encodeWithSignature("process(address)", users[i])
            ); // External call in loop
            require(success, "Call failed");
        }
    }
    
    // VULNERABLE #17: Storage writes in loop
    function updateStorage() public {
        for (uint256 i = 0; i < users.length; i++) {
            isRegistered[users[i]] = true; // Storage write
            totalUsers++; // Storage write
            balances[users[i]] = balances[users[i]] + 1; // Storage write
        }
    }
    
    // VULNERABLE #18: Event emission in loop
    function emitEvents() public {
        for (uint256 i = 0; i < users.length; i++) {
            emit UserProcessed(users[i], balances[users[i]]); // Event in loop
        }
    }
    
    // VULNERABLE #19: String operations in loop
    function processStrings() public {
        for (uint256 i = 0; i < users.length && i < 20; i++) {
            string memory data = string(abi.encodePacked("user", i)); // String ops
            // Process data
        }
    }
    
    // VULNERABLE #20: Array copy in loop
    function copyArray() public {
        address[] memory temp = new address[](users.length);
        for (uint256 i = 0; i < users.length; i++) {
            temp[i] = users[i]; // Array copy
        }
    }
    
    // VULNERABLE #21: Recursive pattern
    function recursiveProcess(uint256 depth) public {
        if (depth > 0) {
            for (uint256 i = 0; i < users.length && i < 10; i++) {
                recursiveProcess(depth - 1); // Recursive call
            }
        }
    }
    
    // VULNERABLE #22: Delegatecall in loop
    function delegateCallLoop(address target) public {
        for (uint256 i = 0; i < users.length; i++) {
            (bool success, ) = target.delegatecall(
                abi.encodeWithSignature("process(address)", users[i])
            ); // Delegatecall in loop
        }
    }
    
    // VULNERABLE #23: Create contracts in loop
    function createContracts() public {
        for (uint256 i = 0; i < users.length && i < 5; i++) {
            new SimpleContract(); // Contract creation in loop
        }
    }
    
    // VULNERABLE #24: Hash operations in loop
    function hashLoop() public {
        for (uint256 i = 0; i < users.length; i++) {
            bytes32 hash1 = keccak256(abi.encodePacked(users[i]));
            bytes32 hash2 = keccak256(abi.encodePacked(hash1, block.timestamp));
            balances[users[i]] = uint256(hash2) % 10000; // Multiple hashes
        }
    }
    
    // VULNERABLE #25: External call with value
    function transferLoop() public {
        for (uint256 i = 0; i < users.length; i++) {
            payable(users[i]).transfer(0.01 ether); // Transfer in loop
        }
    }
    
    // VULNERABLE #26: Mapping writes in loop
    function updateMappings() public {
        for (uint256 i = 0; i < users.length; i++) {
            rewards[users[i]] = balances[users[i]] / 10; // Mapping write
            isRegistered[users[i]] = true; // Mapping write
        }
    }
    
    // VULNERABLE #27: Conditional external calls
    function conditionalCalls() public {
        for (uint256 i = 0; i < users.length; i++) {
            if (balances[users[i]] > 1000) {
                payable(users[i]).call{value: 1 ether}(""); // Conditional call
            }
        }
    }
    
    // VULNERABLE #28: Array manipulation
    function manipulateArray() public {
        for (uint256 i = 0; i < users.length; i++) {
            users.push(users[i]); // Duplicate in loop
        }
    }
    
    // VULNERABLE #29: Multiple state changes
    function multipleChanges() public {
        for (uint256 i = 0; i < users.length; i++) {
            balances[users[i]] += 100;
            rewards[users[i]] += 50;
            totalUsers += 1; // Multiple changes
        }
    }
    
    // VULNERABLE #30: Complex nested conditions
    function complexNested() public {
        for (uint256 i = 0; i < users.length; i++) {
            if (isRegistered[users[i]]) {
                if (balances[users[i]] > 0) {
                    if (rewards[users[i]] > 0) {
                        balances[users[i]] += rewards[users[i]]; // Nested conditions
                    }
                }
            }
        }
    }
    
    function transferReward(address user) external {
        uint256 reward = rewards[user];
        if (reward > 0) {
            payable(user).transfer(reward);
            rewards[user] = 0;
        }
    }
    
    function register() public payable {
        require(!isRegistered[msg.sender], "Already registered");
        users.push(msg.sender);
        isRegistered[msg.sender] = true;
        balances[msg.sender] = msg.value;
        totalUsers++;
    }
    
    event UserProcessed(address user, uint256 balance);
    
    receive() external payable {
        register();
    }
}

contract SimpleContract {
    constructor() {}
}

