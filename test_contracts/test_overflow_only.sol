// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * TEST OVERFLOW ONLY
 * Purpose: Test bytecode overflow detection (MUL pattern)
 */
contract TestOverflowOnly {
    uint256 public value;
    
    // VULNERABLE: Unsafe multiplication without overflow check
    function multiply(uint256 a, uint256 b) public returns (uint256) {
        value = a * b;  //  Can overflow!
        return value;
    }
    
    // Safe function for comparison
    function getValue() public view returns (uint256) {
        return value;
    }
}
