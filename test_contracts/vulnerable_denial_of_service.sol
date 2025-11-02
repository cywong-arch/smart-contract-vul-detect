// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

contract VulnerableDenialOfService {
    address[] public users;
    mapping(address => uint256) public balances;
    mapping(address => bool) public isRegistered;
    uint256 public totalUsers;
    
    // Vulnerable: External call in loop without limits
    function distributeRewards() public {
        for (uint256 i = 0; i < users.length; i++) {
            address user = users[i];
            uint256 reward = balances[user] / 10;
            payable(user).transfer(reward); // External call in loop
        }
    }
    
    // Vulnerable: Unbounded loop
    function processAllUsers() public {
        uint256 i = 0;
        while (true) { // Unbounded loop
            if (i >= users.length) break;
            balances[users[i]] += 100;
            i++;
        }
    }
    
    // Vulnerable: Array operations in loop without limits
    function batchTransfer(address[] memory recipients, uint256[] memory amounts) public {
        for (uint256 i = 0; i < recipients.length; i++) {
            users.push(recipients[i]); // Array push in loop
            balances[recipients[i]] += amounts[i];
        }
    }
    
    // Vulnerable: State modifications in loop
    function updateAllBalances() public {
        for (uint256 i = 0; i < users.length; i++) {
            balances[users[i]] = balances[users[i]] * 2; // State modification in loop
            totalUsers++; // State modification in loop
        }
    }
    
    // Vulnerable: Gas-consuming operations in loop
    function calculateHashes() public {
        for (uint256 i = 0; i < users.length; i++) {
            bytes32 hash = keccak256(abi.encodePacked(users[i], block.timestamp)); // Gas-consuming operation
            balances[users[i]] = uint256(hash) % 1000;
        }
    }
    
    // Vulnerable: Batch operation without limits
    function batchRegister(address[] memory newUsers) public {
        for (uint256 i = 0; i < newUsers.length; i++) {
            users.push(newUsers[i]);
            isRegistered[newUsers[i]] = true;
            balances[newUsers[i]] = 1000;
        }
    }
    
    // Vulnerable: External call to unknown contract
    function callUnknownContract(address contractAddr) public {
        (bool success, ) = contractAddr.call{value: 1 ether}(""); // Call to unknown contract
        require(success, "Call failed");
    }
    
    // Vulnerable: Fallback function with expensive operations
    fallback() external payable {
        // Expensive operations in fallback
        for (uint256 i = 0; i < users.length; i++) {
            balances[users[i]] += 1;
        }
        keccak256(abi.encodePacked(msg.sender, block.timestamp));
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
