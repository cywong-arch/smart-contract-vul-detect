// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * ACCESS CONTROL LEVEL 1: BASIC
 * Purpose: Test basic access control vulnerability - obvious missing modifiers
 * Vulnerability: Critical functions without any access control
 */
contract AccessControlLevel1 {
    address public owner;
    uint256 public funds;
    
    constructor() {
        owner = msg.sender;
    }
    
    // VULNERABLE: No access control on critical withdraw function
    function withdraw(uint256 amount) public {
        require(funds >= amount, "Insufficient funds");
        payable(msg.sender).transfer(amount);
        funds -= amount;
    }
    
    // VULNERABLE: No access control on selfdestruct
    function emergencyStop() public {
        selfdestruct(payable(msg.sender));  // Anyone can destroy contract!
    }
    
    // VULNERABLE: No access control on owner change
    function setOwner(address newOwner) public {
        owner = newOwner;  // Anyone can change owner!
    }
    
    // Safe function for comparison
    function getFunds() public view returns (uint256) {
        return funds;
    }
}

