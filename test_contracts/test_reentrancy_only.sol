// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * TEST REENTRANCY ONLY
 * Purpose: Test bytecode reentrancy detection (CALL  SSTORE pattern)
 */
contract TestReentrancyOnly {
    mapping(address => uint256) public balances;
    
    // VULNERABLE: External call before state update
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // External call BEFORE state update - REENTRANCY
        payable(msg.sender).call{value: amount}("");
        
        // State update AFTER call - vulnerable!
        balances[msg.sender] -= amount;
    }
    
    // Deposit function
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
}
