// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * REENTRANCY LEVEL 1: BASIC
 * Purpose: Test basic reentrancy vulnerability - classic withdraw pattern
 * Vulnerability: External call before state update (Checks-Effects-Interactions violation)
 */
contract ReentrancyLevel1 {
    mapping(address => uint256) public balances;
    
    // VULNERABLE: Classic reentrancy - external call before state update
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // External call BEFORE state update - REENTRANCY VULNERABILITY
        payable(msg.sender).transfer(amount);
        
        // State update AFTER external call - vulnerable!
        balances[msg.sender] -= amount;
    }
    
    // Deposit function
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    // Get balance
    function getBalance(address account) public view returns (uint256) {
        return balances[account];
    }
}

