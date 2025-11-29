// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * DENIAL OF SERVICE LEVEL 3: ADVANCED
 * Purpose: Test advanced denial of service vulnerabilities - subtle patterns and complex bypasses
 * Vulnerability: 50 advanced DOS vulnerabilities
 */
contract DenialOfServiceLevel3 {
    address[] public users;
    mapping(address => uint256) public balances;
    mapping(address => bool) public isRegistered;
    mapping(address => uint256) public rewards;
    mapping(address => uint256) public deposits;
    mapping(address => mapping(address => uint256)) public allowances;
    uint256 public totalUsers;
    uint256 public constant MAX_USERS = 1000;
    uint256 public constant BATCH_LIMIT = 100;
    
    // VULNERABLE #1: Limit check but can be exceeded through multiple calls
    function batchRegister(address[] memory newUsers) public {
        require(users.length + newUsers.length <= MAX_USERS, "Too many users");
        for (uint256 i = 0; i < newUsers.length; i++) {
            users.push(newUsers[i]); // Can be called multiple times
        }
    }
    
    // VULNERABLE #2: External call with gas limit but recipient can consume all
    function distributeRewards() public {
        for (uint256 i = 0; i < users.length; i++) {
            address user = users[i];
            uint256 reward = rewards[user];
            if (reward > 0) {
                (bool success, ) = user.call{value: reward, gas: 2300}(""); // Gas limit but can fail
                if (success) {
                    rewards[user] = 0;
                }
            }
        }
    }
    
    // VULNERABLE #3: Loop with parameter limit but parameter can be large
    function processUsers(uint256 maxIterations) public {
        uint256 iterations = 0;
        for (uint256 i = 0; i < users.length && iterations < maxIterations; i++) {
            balances[users[i]] += 100; // maxIterations can be very large
            iterations++;
        }
    }
    
    // VULNERABLE #4: Array operations with limit but nested operations
    function batchTransfer(address[] memory recipients, uint256[] memory amounts) public {
        require(recipients.length <= BATCH_LIMIT, "Too many recipients");
        for (uint256 i = 0; i < recipients.length; i++) {
            users.push(recipients[i]); // Array push in loop
            balances[recipients[i]] += amounts[i];
            processUser(recipients[i]); // Additional processing
        }
    }
    
    // VULNERABLE #5: State modifications with condition but still loops all
    function updateBalances(uint256 multiplier) public {
        for (uint256 i = 0; i < users.length; i++) {
            if (balances[users[i]] > 0) {
                balances[users[i]] = balances[users[i]] * multiplier;
                totalUsers++; // State modification
            }
        }
    }
    
    // VULNERABLE #6: Gas-consuming operations with limit but expensive
    function calculateHashes(uint256 maxCount) public {
        uint256 count = 0;
        for (uint256 i = 0; i < users.length && count < maxCount; i++) {
            bytes32 hash = keccak256(abi.encodePacked(users[i], block.timestamp, block.number));
            bytes32 hash2 = keccak256(abi.encodePacked(hash, users[i]));
            balances[users[i]] = uint256(hash2) % 1000; // Multiple hashes
            count++;
        }
    }
    
    // VULNERABLE #7: External call with try-catch but still in loop
    function safeDistribute() public {
        for (uint256 i = 0; i < users.length; i++) {
            try this.transferReward(users[i]) {} catch {} // Still loops all
        }
    }
    
    // VULNERABLE #8: Nested loops with partial limit
    function processNested(uint256 maxOuter) public {
        for (uint256 i = 0; i < users.length && i < maxOuter; i++) {
            for (uint256 j = 0; j < users.length; j++) { // Inner unbounded
                balances[users[i]] += balances[users[j]] / 100;
                allowances[users[i]][users[j]] += 1; // Mapping write
            }
        }
    }
    
    // VULNERABLE #9: Mapping iteration with state changes
    function processAllRewards() public {
        for (uint256 i = 0; i < users.length; i++) {
            address user = users[i];
            if (rewards[user] > 0) {
                rewards[user] = rewards[user] * 2;
                deposits[user] = deposits[user] + rewards[user]; // Multiple writes
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
        for (uint256 i = 0; i < users.length && i < 50; i++) {
            balances[users[i]] += 1;
            rewards[users[i]] += 1; // Multiple writes
        }
    }
    
    // VULNERABLE #12: While loop with condition
    function processWhile() public {
        uint256 i = 0;
        while (i < users.length && i < 100) {
            balances[users[i]] += 100;
            processUser(users[i]); // Additional call
            i++;
        }
    }
    
    // VULNERABLE #13: Array push in multiple functions
    function addUser(address user) public {
        users.push(user); // Can be called multiple times
        isRegistered[user] = true;
        balances[user] = 0;
    }
    
    // VULNERABLE #14: State read in loop with calculations
    function calculateTotal() public view returns (uint256) {
        uint256 total = 0;
        for (uint256 i = 0; i < users.length; i++) {
            total += balances[users[i]];
            total += rewards[users[i]]; // Multiple reads
            total += deposits[users[i]];
        }
        return total;
    }
    
    // VULNERABLE #15: Complex calculation in loop
    function updateComplex() public {
        for (uint256 i = 0; i < users.length; i++) {
            uint256 balance = balances[users[i]];
            uint256 reward = rewards[users[i]];
            uint256 deposit = deposits[users[i]];
            balances[users[i]] = balance + (reward * 2) / 3 + deposit / 2; // Complex
        }
    }
    
    // VULNERABLE #16: External call to contract with data
    function callContract(address contractAddr) public {
        for (uint256 i = 0; i < users.length; i++) {
            (bool success, ) = contractAddr.call(
                abi.encodeWithSignature("process(address,uint256)", users[i], balances[users[i]])
            ); // External call with data
            require(success, "Call failed");
        }
    }
    
    // VULNERABLE #17: Storage writes in loop
    function updateStorage() public {
        for (uint256 i = 0; i < users.length; i++) {
            isRegistered[users[i]] = true;
            totalUsers++;
            balances[users[i]] = balances[users[i]] + 1;
            rewards[users[i]] = rewards[users[i]] + 1; // Multiple writes
        }
    }
    
    // VULNERABLE #18: Event emission in loop
    function emitEvents() public {
        for (uint256 i = 0; i < users.length; i++) {
            emit UserProcessed(users[i], balances[users[i]], rewards[users[i]]); // Event
        }
    }
    
    // VULNERABLE #19: String operations in loop
    function processStrings() public {
        for (uint256 i = 0; i < users.length && i < 20; i++) {
            string memory data = string(abi.encodePacked("user", i, block.timestamp));
            bytes32 hash = keccak256(bytes(data)); // String to hash
        }
    }
    
    // VULNERABLE #20: Array copy in loop
    function copyArray() public {
        address[] memory temp = new address[](users.length);
        for (uint256 i = 0; i < users.length; i++) {
            temp[i] = users[i];
            balances[temp[i]] += 1; // Access copied array
        }
    }
    
    // VULNERABLE #21: Recursive pattern
    function recursiveProcess(uint256 depth) public {
        if (depth > 0) {
            for (uint256 i = 0; i < users.length && i < 10; i++) {
                recursiveProcess(depth - 1); // Recursive
            }
        }
    }
    
    // VULNERABLE #22: Delegatecall in loop
    function delegateCallLoop(address target) public {
        for (uint256 i = 0; i < users.length; i++) {
            (bool success, ) = target.delegatecall(
                abi.encodeWithSignature("process(address,uint256)", users[i], balances[users[i]])
            ); // Delegatecall
        }
    }
    
    // VULNERABLE #23: Create contracts in loop
    function createContracts() public {
        for (uint256 i = 0; i < users.length && i < 5; i++) {
            SimpleContract newContract = new SimpleContract(); // Contract creation
            balances[address(newContract)] = 100;
        }
    }
    
    // VULNERABLE #24: Hash operations in loop
    function hashLoop() public {
        for (uint256 i = 0; i < users.length; i++) {
            bytes32 hash1 = keccak256(abi.encodePacked(users[i]));
            bytes32 hash2 = keccak256(abi.encodePacked(hash1, block.timestamp));
            bytes32 hash3 = keccak256(abi.encodePacked(hash2, block.number));
            balances[users[i]] = uint256(hash3) % 10000; // Multiple hashes
        }
    }
    
    // VULNERABLE #25: External call with value
    function transferLoop() public {
        for (uint256 i = 0; i < users.length; i++) {
            payable(users[i]).transfer(0.01 ether); // Transfer
        }
    }
    
    // VULNERABLE #26: Mapping writes in nested loop
    function updateMappings() public {
        for (uint256 i = 0; i < users.length; i++) {
            for (uint256 j = 0; j < users.length && j < 10; j++) {
                allowances[users[i]][users[j]] = balances[users[i]]; // Nested mapping
            }
        }
    }
    
    // VULNERABLE #27: Conditional external calls
    function conditionalCalls() public {
        for (uint256 i = 0; i < users.length; i++) {
            if (balances[users[i]] > 1000) {
                payable(users[i]).call{value: 1 ether}("");
                if (rewards[users[i]] > 500) {
                    payable(users[i]).call{value: 0.5 ether}(""); // Nested conditional
                }
            }
        }
    }
    
    // VULNERABLE #28: Array manipulation
    function manipulateArray() public {
        for (uint256 i = 0; i < users.length; i++) {
            users.push(users[i]); // Duplicate
            balances[users[i]] += 100;
        }
    }
    
    // VULNERABLE #29: Multiple state changes
    function multipleChanges() public {
        for (uint256 i = 0; i < users.length; i++) {
            balances[users[i]] += 100;
            rewards[users[i]] += 50;
            deposits[users[i]] += 25;
            totalUsers += 1; // Multiple changes
        }
    }
    
    // VULNERABLE #30: Complex nested conditions
    function complexNested() public {
        for (uint256 i = 0; i < users.length; i++) {
            if (isRegistered[users[i]]) {
                if (balances[users[i]] > 0) {
                    if (rewards[users[i]] > 0) {
                        balances[users[i]] += rewards[users[i]];
                        if (deposits[users[i]] > 0) {
                            rewards[users[i]] += deposits[users[i]]; // Deep nesting
                        }
                    }
                }
            }
        }
    }
    
    // VULNERABLE #31: Loop with function calls
    function processWithCalls() public {
        for (uint256 i = 0; i < users.length; i++) {
            processUser(users[i]);
            calculateReward(users[i]);
            updateDeposit(users[i]); // Multiple function calls
        }
    }
    
    // VULNERABLE #32: Storage reads in nested structure
    function readNestedStorage() public {
        for (uint256 i = 0; i < users.length; i++) {
            for (uint256 j = 0; j < users.length && j < 5; j++) {
                uint256 allowance = allowances[users[i]][users[j]]; // Nested read
                balances[users[i]] += allowance;
            }
        }
    }
    
    // VULNERABLE #33: Array length check but can grow
    function processWithLengthCheck() public {
        uint256 length = users.length;
        for (uint256 i = 0; i < length; i++) {
            users.push(users[i]); // Array grows during iteration
            balances[users[i]] += 100;
        }
    }
    
    // VULNERABLE #34: External call with callback
    function callWithCallback(address target) public {
        for (uint256 i = 0; i < users.length; i++) {
            (bool success, ) = target.call(
                abi.encodeWithSignature("callback(address)", users[i])
            ); // Callback can re-enter
            if (success) {
                balances[users[i]] += 100;
            }
        }
    }
    
    // VULNERABLE #35: Loop with break but expensive before break
    function processUntilBreak() public {
        for (uint256 i = 0; i < users.length; i++) {
            balances[users[i]] += 100;
            if (balances[users[i]] > 10000) {
                break; // Break but expensive before
            }
            rewards[users[i]] += 50;
        }
    }
    
    // VULNERABLE #36: Multiple array operations
    function multipleArrayOps() public {
        address[] memory temp = new address[](users.length);
        for (uint256 i = 0; i < users.length; i++) {
            temp[i] = users[i];
            users.push(users[i]); // Push while iterating
            balances[temp[i]] += 100;
        }
    }
    
    // VULNERABLE #37: Loop with continue
    function processWithContinue() public {
        for (uint256 i = 0; i < users.length; i++) {
            if (balances[users[i]] == 0) {
                continue; // Continue but still loops all
            }
            balances[users[i]] += 100;
            rewards[users[i]] += 50;
        }
    }
    
    // VULNERABLE #38: State changes in multiple mappings
    function updateMultipleMappings() public {
        for (uint256 i = 0; i < users.length; i++) {
            balances[users[i]] += 100;
            rewards[users[i]] += 50;
            deposits[users[i]] += 25;
            isRegistered[users[i]] = true; // Multiple mappings
        }
    }
    
    // VULNERABLE #39: Loop with external view calls
    function processWithViewCalls() public {
        for (uint256 i = 0; i < users.length; i++) {
            uint256 total = calculateTotalForUser(users[i]); // View call
            balances[users[i]] = total;
        }
    }
    
    // VULNERABLE #40: Triple nested loop
    function tripleNested() public {
        for (uint256 i = 0; i < users.length && i < 10; i++) {
            for (uint256 j = 0; j < users.length && j < 10; j++) {
                for (uint256 k = 0; k < users.length && k < 10; k++) {
                    allowances[users[i]][users[j]] += balances[users[k]]; // Triple nested
                }
            }
        }
    }
    
    // VULNERABLE #41: Loop with assembly
    function processWithAssembly() public {
        for (uint256 i = 0; i < users.length; i++) {
            address user = users[i];
            uint256 bal;
            assembly {
                bal := sload(add(balances.slot, user))
            }
            assembly {
                sstore(add(balances.slot, user), add(bal, 100))
            } // Assembly in loop
        }
    }
    
    // VULNERABLE #42: Loop with library calls
    function processWithLibrary() public {
        for (uint256 i = 0; i < users.length; i++) {
            MathLib.add(balances[users[i]], 100); // Library call
        }
    }
    
    // VULNERABLE #43: Loop with modifier logic
    function processWithModifier() public {
        for (uint256 i = 0; i < users.length; i++) {
            require(isRegistered[users[i]], "Not registered"); // Require in loop
            balances[users[i]] += 100;
        }
    }
    
    // VULNERABLE #44: Loop with error handling
    function processWithErrors() public {
        for (uint256 i = 0; i < users.length; i++) {
            try this.processUserExternal(users[i]) {
                balances[users[i]] += 100;
            } catch Error(string memory) {
                rewards[users[i]] += 50;
            } catch {
                deposits[users[i]] += 25; // Error handling in loop
            }
        }
    }
    
    // VULNERABLE #45: Loop with gas measurement
    function processWithGas() public {
        uint256 gasStart = gasleft();
        for (uint256 i = 0; i < users.length; i++) {
            uint256 gasUsed = gasStart - gasleft();
            if (gasUsed > 100000) {
                break; // Gas check but expensive
            }
            balances[users[i]] += 100;
        }
    }
    
    // VULNERABLE #46: Loop with time check
    function processWithTime() public {
        uint256 startTime = block.timestamp;
        for (uint256 i = 0; i < users.length; i++) {
            if (block.timestamp > startTime + 60) {
                break; // Time check but expensive
            }
            balances[users[i]] += 100;
        }
    }
    
    // VULNERABLE #47: Loop with block number
    function processWithBlock() public {
        uint256 startBlock = block.number;
        for (uint256 i = 0; i < users.length; i++) {
            if (block.number > startBlock) {
                break; // Block check but expensive
            }
            balances[users[i]] += 100;
        }
    }
    
    // VULNERABLE #48: Loop with address checks
    function processWithAddressCheck() public {
        for (uint256 i = 0; i < users.length; i++) {
            if (users[i] != address(0)) {
                if (users[i] != address(this)) {
                    balances[users[i]] += 100; // Multiple address checks
                }
            }
        }
    }
    
    // VULNERABLE #49: Loop with balance checks
    function processWithBalanceCheck() public {
        for (uint256 i = 0; i < users.length; i++) {
            uint256 balance = address(users[i]).balance; // External balance check
            if (balance > 0) {
                balances[users[i]] += 100;
            }
        }
    }
    
    // VULNERABLE #50: Loop with code size check
    function processWithCodeCheck() public {
        for (uint256 i = 0; i < users.length; i++) {
            address user = users[i];
            uint256 size;
            assembly {
                size := extcodesize(user)
            }
            if (size > 0) {
                balances[user] += 100; // Code size check in loop
            }
        }
    }
    
    function processUser(address user) internal {
        balances[user] += 1;
    }
    
    function processUserExternal(address user) external {
        processUser(user);
    }
    
    function calculateReward(address user) internal {
        rewards[user] += balances[user] / 10;
    }
    
    function updateDeposit(address user) internal {
        deposits[user] += balances[user] / 20;
    }
    
    function calculateTotalForUser(address user) internal view returns (uint256) {
        return balances[user] + rewards[user] + deposits[user];
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
    
    event UserProcessed(address user, uint256 balance, uint256 reward);
    
    receive() external payable {
        register();
    }
}

contract SimpleContract {
    constructor() {}
}

library MathLib {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        return a + b;
    }
}

