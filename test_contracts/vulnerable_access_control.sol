// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Vulnerable contract with access control issues
contract VulnerableAccessControl {
    uint256 public totalSupply;
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }
    
    // Vulnerable: No access control on critical function
    function mint(address to, uint256 amount) public {
        totalSupply = totalSupply + amount;
        // Missing: onlyOwner modifier
    }
    
    // Vulnerable: Public function that should be restricted
    function withdraw() public {
        // Anyone can withdraw - no access control
        payable(msg.sender).transfer(address(this).balance);
    }
    
    // Vulnerable: Dangerous function without protection
    function emergencyStop() public {
        // Should only be callable by owner
        selfdestruct(payable(owner));
    }
    
    // Vulnerable: External call without access control
    function callExternal(address target, bytes calldata data) public {
        target.call(data);  // Anyone can make external calls
    }
}




