// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * TEST ACCESS CONTROL ONLY
 * Purpose: Test bytecode access control detection (SELFDESTRUCT pattern)
 */
contract TestAccessControlOnly {
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }
    
    // VULNERABLE: No access control on SELFDESTRUCT
    function emergencyStop() public {
        // Should have: require(msg.sender == owner, "Not owner");
        selfdestruct(payable(owner));  //  Anyone can destroy contract!
    }
    
    // Safe function for comparison
    function getOwner() public view returns (address) {
        return owner;
    }
}
