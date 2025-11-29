// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

/**
 * OVERFLOW LEVEL 2: INTERMEDIATE
 * Purpose: Test intermediate overflow vulnerability - more subtle patterns
 * Vulnerability: Arithmetic operations in loops and with user inputs
 */
contract OverflowLevel2 {
    uint256 public balance;
    mapping(address => uint256) public balances;
    
    // VULNERABLE: Loop counter may overflow
    function batchTransfer(address[] memory recipients, uint256[] memory amounts) public {
        require(recipients.length == amounts.length, "Arrays length mismatch");
        
        for (uint256 i = 0; i < recipients.length; i++) {  // Loop counter can overflow
            balances[recipients[i]] += amounts[i];  // Addition can overflow
            balance += amounts[i];  // Accumulator can overflow
        }
    }
    
    // VULNERABLE: Multiple additions in sequence
    function addMultiple(uint256 a, uint256 b, uint256 c) public {
        uint256 temp = a + b;  // First addition can overflow
        total = temp + c;      // Second addition can overflow
    }
    
    // VULNERABLE: Multiplication by constant that may cause overflow
    function calculateReward(uint256 amount) public {
        balance += amount * 100;  // Multiplication can overflow
    }
    
    uint256 public total;
}

