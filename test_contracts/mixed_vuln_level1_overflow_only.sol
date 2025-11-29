// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

/**
 * MIXED VULNERABILITY LEVEL 1: OVERFLOW ONLY
 * Purpose: Test detection when contract contains ONLY overflow vulnerabilities (100% overflow)
 * Vulnerability: Pure overflow/underflow vulnerabilities, no other types
 */
contract MixedVulnLevel1 {
    uint256 public total;
    uint256 public balance;
    mapping(address => uint256) public balances;
    
    // VULNERABLE: Basic overflow - addition
    function add(uint256 a, uint256 b) public {
        total = a + b;  // Can overflow in Solidity < 0.8!
    }
    
    // VULNERABLE: Basic overflow - multiplication
    function multiply(uint256 a, uint256 b) public {
        total = a * b;  // Can overflow!
    }
    
    // VULNERABLE: Basic underflow - subtraction
    function subtract(uint256 a, uint256 b) public {
        balance = a - b;  // Can underflow!
    }
    
    // VULNERABLE: Accumulator overflow in function
    function accumulate(uint256 amount) public {
        balance += amount;  // Can overflow with repeated calls!
    }
    
    // VULNERABLE: Loop with accumulator
    function batchAdd(address[] memory accounts, uint256[] memory amounts) public {
        require(accounts.length == amounts.length, "Arrays mismatch");
        
        for (uint256 i = 0; i < accounts.length; i++) {
            balances[accounts[i]] += amounts[i];  // Mapping addition can overflow
            total += amounts[i];  // Accumulator can overflow
        }
    }
    
    // VULNERABLE: Multiplication by constant
    function calculateReward(uint256 amount) public {
        balance += amount * 100;  // Multiplication can overflow
    }
    
    // VULNERABLE: Multiple sequential additions
    function addMultiple(uint256 a, uint256 b, uint256 c) public {
        uint256 temp = a + b;  // First addition can overflow
        total = temp + c;      // Second addition can overflow
    }
    
    // Safe view function for comparison
    function getTotal() public view returns (uint256) {
        return total;
    }
}

