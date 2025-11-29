// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

/**
 * OVERFLOW LEVEL 1: BASIC
 * Purpose: Test basic overflow vulnerability - obvious unsafe arithmetic
 * Vulnerability: Simple addition without SafeMath or Solidity 0.8+ protection
 */
contract OverflowLevel1 {
    uint256 public total;
    
    // VULNERABLE: Basic overflow - direct addition without protection
    function add(uint256 a, uint256 b) public {
        total = a + b;  // Can overflow in Solidity < 0.8!
    }
    
    // VULNERABLE: Basic multiplication overflow
    function multiply(uint256 a, uint256 b) public {
        total = a * b;  // Can overflow!
    }
    
    // VULNERABLE: Basic subtraction underflow
    function subtract(uint256 a, uint256 b) public {
        total = a - b;  // Can underflow!
    }
}

