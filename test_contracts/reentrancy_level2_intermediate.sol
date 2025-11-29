// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * REENTRANCY LEVEL 2: INTERMEDIATE
 * Purpose: Test intermediate reentrancy vulnerability - cross-function reentrancy
 * Vulnerability: State update in one function, external call in another
 */
contract ReentrancyLevel2 {
    mapping(address => uint256) public balances;
    mapping(address => bool) public locked;
    
    // VULNERABLE: External call before lock is set
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        require(!locked[msg.sender], "Account locked");
        
        // External call BEFORE lock is set
        payable(msg.sender).call{value: amount}("");
        
        // State updates AFTER external call
        balances[msg.sender] -= amount;
        locked[msg.sender] = true;  // Lock set too late!
    }
    
    // VULNERABLE: Unlock can be called during reentrancy
    function unlock() public {
        locked[msg.sender] = false;  // No access control, can unlock during reentrancy
    }
    
    // VULNERABLE: Cross-function reentrancy - uses same state variable
    function transfer(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // State update in transfer
        balances[msg.sender] -= amount;
        balances[to] += amount;
        
        // External call after state update - but can reenter through withdraw
        payable(to).call{value: 0}("");  // Potential reentrancy entry point
    }
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
}

