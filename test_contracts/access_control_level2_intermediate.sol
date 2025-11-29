// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * ACCESS CONTROL LEVEL 2: INTERMEDIATE
 * Purpose: Test intermediate access control vulnerability - partial/incomplete protection
 * Vulnerability: Functions with weak or incomplete access control checks
 */
contract AccessControlLevel2 {
    address public owner;
    address public admin;
    mapping(address => bool) public authorized;
    uint256 public balance;
    
    constructor() {
        owner = msg.sender;
        admin = msg.sender;
    }
    
    // VULNERABLE: Checks admin but should check owner
    function transferOwnership(address newOwner) public {
        require(msg.sender == admin, "Not admin");  // Wrong check!
        owner = newOwner;  // Admin can change owner, not just owner
    }
    
    // VULNERABLE: Public function that should be restricted
    function setBalance(uint256 newBalance) public {
        // Missing: require(msg.sender == owner);
        balance = newBalance;  // Anyone can set balance!
    }
    
    // VULNERABLE: Authorization check exists but can be bypassed
    function authorizedTransfer(address to, uint256 amount) public {
        require(authorized[msg.sender] || msg.sender == owner, "Not authorized");
        // Problem: authorized mapping can be set by anyone (see below)
        payable(to).transfer(amount);
        balance -= amount;
    }
    
    // VULNERABLE: Anyone can authorize themselves
    function authorize(address account) public {
        authorized[account] = true;  // No access control!
    }
    
    // VULNERABLE: Dangerous external call without proper check
    function executeCall(address target, bytes memory data) public {
        require(msg.sender == admin, "Not admin");  // Admin can execute arbitrary calls
        (bool success, ) = target.call(data);
        require(success, "Call failed");
    }
}

