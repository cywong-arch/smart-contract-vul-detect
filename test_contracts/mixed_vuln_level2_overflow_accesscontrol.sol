// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * MIXED VULNERABILITY LEVEL 2: OVERFLOW + ACCESS CONTROL
 * Purpose: Test detection when contract contains overflow AND access control vulnerabilities
 * Vulnerability: Mix of overflow/underflow vulnerabilities AND missing/wrong access control
 */
contract MixedVulnLevel2 {
    address public owner;
    uint256 public total;
    uint256 public balance;
    mapping(address => uint256) public balances;
    
    constructor() {
        owner = msg.sender;
    }
    
    // VULNERABLE: Basic overflow - addition
    function add(uint256 a, uint256 b) public {
        total = a + b;  // Can overflow in unchecked block
    }
    
    // VULNERABLE: Basic overflow - multiplication
    function multiply(uint256 a, uint256 b) public {
        unchecked {
            total = a * b;  // Unchecked multiplication can overflow!
        }
    }
    
    // VULNERABLE: Basic underflow - subtraction
    function subtract(uint256 a, uint256 b) public {
        unchecked {
            balance = a - b;  // Unchecked subtraction can underflow!
        }
    }
    
    // VULNERABLE: Accumulator overflow + NO ACCESS CONTROL
    function accumulate(uint256 amount) public {
        // Missing: require(msg.sender == owner);
        balance += amount;  // Anyone can accumulate, and can overflow!
    }
    
    // VULNERABLE: Loop with accumulator + NO ACCESS CONTROL
    function batchAdd(address[] memory accounts, uint256[] memory amounts) public {
        require(accounts.length == amounts.length, "Arrays mismatch");
        // Missing: require(msg.sender == owner);
        
        for (uint256 i = 0; i < accounts.length; i++) {
            balances[accounts[i]] += amounts[i];  // Overflow possible
            total += amounts[i];  // Accumulator overflow
        }
    }
    
    // VULNERABLE: Multiplication by constant + WRONG ACCESS CONTROL
    function calculateReward(uint256 amount) public {
        // Wrong check - should check owner, not just any caller
        require(msg.sender != address(0), "Invalid sender");  // Too weak!
        balance += amount * 100;  // Multiplication overflow
    }
    
    // VULNERABLE: Multiple sequential additions + NO ACCESS CONTROL
    function addMultiple(uint256 a, uint256 b, uint256 c) public {
        // Missing access control
        uint256 temp = a + b;  // First addition can overflow
        total = temp + c;      // Second addition can overflow
    }
    
    // VULNERABLE: ACCESS CONTROL - No restriction on critical function
    function withdraw(uint256 amount) public {
        // Missing: require(msg.sender == owner);
        require(balance >= amount, "Insufficient balance");
        payable(msg.sender).transfer(amount);
        balance -= amount;  // Also has underflow risk in unchecked context
    }
    
    // VULNERABLE: ACCESS CONTROL - Anyone can set balance
    function setBalance(uint256 newBalance) public {
        // Missing: require(msg.sender == owner);
        balance = newBalance;  // Anyone can manipulate balance!
    }
    
    // VULNERABLE: ACCESS CONTROL - No restriction on selfdestruct
    function emergencyStop() public {
        // Missing: require(msg.sender == owner);
        selfdestruct(payable(msg.sender));  // Anyone can destroy contract!
    }
    
    // Safe view function
    function getTotal() public view returns (uint256) {
        return total;
    }
}

