// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

// Vulnerable contract with overflow/underflow issues
contract VulnerableOverflow {
    uint256 public balance;
    
    // Vulnerable: No overflow protection
    function addBalance(uint256 amount) public {
        balance = balance + amount;  // Potential overflow
    }
    
    // Vulnerable: No underflow protection
    function subtractBalance(uint256 amount) public {
        balance = balance - amount;  // Potential underflow
    }
    
    // Vulnerable: Multiplication without protection
    function multiplyBalance(uint256 factor) public {
        balance = balance * factor;  // Potential overflow
    }
    
    // Vulnerable: Division without checks
    function divideBalance(uint256 divisor) public {
        balance = balance / divisor;  // Potential division by zero
    }
}




