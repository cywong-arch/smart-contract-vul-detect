// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * DENIAL OF SERVICE LEVEL 1: BASIC
 * Purpose: Test basic denial of service vulnerabilities - obvious unbounded loops and external calls
 * Vulnerability: 10 basic DOS vulnerabilities
 */
contract DenialOfServiceLevel1 {
    address[] public users;
    mapping(address => uint256) public balances;
    mapping(address => bool) public isRegistered;
    uint256 public totalUsers;
    
    // VULNERABLE #1: External call in unbounded loop
    function distributeRewards() public {
        for (uint256 i = 0; i < users.length; i++) {
            address user = users[i];
            uint256 reward = balances[user] / 10;
            payable(user).transfer(reward); // External call in loop - can fail and block
        }
    }
    
    // VULNERABLE #2: Unbounded array push in loop
    function batchRegister(address[] memory newUsers) public {
        for (uint256 i = 0; i < newUsers.length; i++) {
            users.push(newUsers[i]); // Unbounded array growth
            isRegistered[newUsers[i]] = true;
        }
    }
    
    // VULNERABLE #3: State modifications in unbounded loop
    function updateAllBalances() public {
        for (uint256 i = 0; i < users.length; i++) {
            balances[users[i]] = balances[users[i]] * 2; // Expensive state write in loop
            totalUsers++; // State modification in loop
        }
    }
    
    // VULNERABLE #4: Gas-consuming operations in loop
    function calculateHashes() public {
        for (uint256 i = 0; i < users.length; i++) {
            bytes32 hash = keccak256(abi.encodePacked(users[i], block.timestamp));
            balances[users[i]] = uint256(hash) % 1000; // Expensive hash in loop
        }
    }
    
    // VULNERABLE #5: External call to unknown contract without limit
    function callUnknownContract(address contractAddr) public {
        (bool success, ) = contractAddr.call{value: 1 ether}(""); // Can consume all gas
        require(success, "Call failed");
    }
    
    // VULNERABLE #6: Fallback with expensive operations
    fallback() external payable {
        for (uint256 i = 0; i < users.length; i++) {
            balances[users[i]] += 1; // Expensive loop in fallback
        }
    }
    
    // VULNERABLE #7: Batch transfer without limits
    function batchTransfer(address[] memory recipients, uint256[] memory amounts) public {
        for (uint256 i = 0; i < recipients.length; i++) {
            users.push(recipients[i]); // Array push in loop
            balances[recipients[i]] += amounts[i];
        }
    }
    
    // VULNERABLE #8: While loop without proper bounds
    function processAllUsers() public {
        uint256 i = 0;
        while (i < users.length) { // Could be very large
            balances[users[i]] += 100;
            i++;
        }
    }
    
    // VULNERABLE #9: Nested loops without limits
    function processNested() public {
        for (uint256 i = 0; i < users.length; i++) {
            for (uint256 j = 0; j < users.length; j++) {
                balances[users[i]] += balances[users[j]]; // O(n^2) complexity
            }
        }
    }
    
    // VULNERABLE #10: Multiple external calls in sequence
    function distributeMultiple() public {
        for (uint256 i = 0; i < users.length; i++) {
            payable(users[i]).transfer(1 ether); // Multiple external calls
            payable(users[i]).transfer(0.5 ether); // Can fail and block
        }
    }
    
    function register() public payable {
        require(!isRegistered[msg.sender], "Already registered");
        users.push(msg.sender);
        isRegistered[msg.sender] = true;
        balances[msg.sender] = msg.value;
        totalUsers++;
    }
    
    receive() external payable {
        register();
    }
}

