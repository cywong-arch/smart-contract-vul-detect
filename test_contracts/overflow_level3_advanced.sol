// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * OVERFLOW LEVEL 3: ADVANCED
 * Purpose: Test advanced overflow vulnerability - using unchecked blocks
 * Vulnerability: Solidity 0.8+ has built-in overflow protection, but unchecked blocks bypass it
 */
contract OverflowLevel3 {
    uint256 public total;
    mapping(address => uint256) public balances;
    
    // VULNERABLE: Unchecked block bypasses Solidity 0.8+ overflow protection
    function uncheckedAdd(uint256 a, uint256 b) public {
        unchecked {
            total = a + b;  // Overflow protection disabled!
        }
    }
    
    // VULNERABLE: Complex calculation in unchecked block
    function complexCalculation(uint256 base, uint256 multiplier, uint256 bonus) public {
        unchecked {
            uint256 temp = base * multiplier;  // Can overflow
            total = temp + bonus;              // Can overflow
        }
    }
    
    // VULNERABLE: Loop with unchecked arithmetic
    function uncheckedLoop(address[] memory addresses, uint256[] memory amounts) public {
        require(addresses.length == amounts.length, "Arrays mismatch");
        
        for (uint256 i = 0; i < addresses.length; i++) {
            unchecked {
                balances[addresses[i]] += amounts[i];  // Unchecked addition
            }
        }
    }
    
    // VULNERABLE: Mixed checked and unchecked operations
    function mixedOperations(uint256 a, uint256 b) public {
        uint256 safeResult = a + b;  // Protected by Solidity 0.8+
        
        unchecked {
            total = safeResult * 10;  // But this multiplication can overflow
        }
    }
}

