// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * UNPROTECTED SELFDESTRUCT LEVEL 1: BASIC
 * Purpose: Test basic unprotected selfdestruct vulnerabilities - obvious missing access control
 * Vulnerability: 10 basic unprotected selfdestruct vulnerabilities
 */
contract UnprotectedSelfDestructLevel1 {
    mapping(address => uint256) public balances;
    address public owner;
    uint256 public totalSupply;
    
    constructor() {
        owner = msg.sender;
        totalSupply = 1000000;
    }
    
    // VULNERABLE #1: Unprotected selfdestruct call
    function kill() public {
        selfdestruct(payable(owner)); // No access control - anyone can destroy
    }
    
    // VULNERABLE #2: Selfdestruct without proper conditions
    function destroy() public {
        selfdestruct(payable(owner)); // No conditions or access control
    }
    
    // VULNERABLE #3: Selfdestruct without owner check
    function remove() public {
        selfdestruct(payable(msg.sender)); // No owner verification
    }
    
    // VULNERABLE #4: Selfdestruct with weak conditions
    function deleteContract() public {
        require(balances[msg.sender] > 0, "No balance"); // Weak condition
        selfdestruct(payable(msg.sender));
    }
    
    // VULNERABLE #5: Selfdestruct in public function
    function terminate() public {
        selfdestruct(payable(owner)); // Public function, no access control
    }
    
    // VULNERABLE #6: Selfdestruct without multi-signature
    function close() public {
        selfdestruct(payable(owner)); // No multi-signature requirement
    }
    
    // VULNERABLE #7: Selfdestruct with minimal check
    function shutdown() public {
        if (totalSupply > 0) { // Minimal condition
            selfdestruct(payable(owner));
        }
    }
    
    // VULNERABLE #8: Selfdestruct in fallback
    fallback() external payable {
        selfdestruct(payable(owner)); // Anyone can trigger via fallback
    }
    
    // VULNERABLE #9: Selfdestruct without proper recipient check
    function emergencyStop() public {
        selfdestruct(payable(msg.sender)); // Recipient is caller, not owner
    }
    
    // VULNERABLE #10: Selfdestruct with only balance check
    function destroyIfEmpty() public {
        require(address(this).balance == 0, "Has balance"); // Only balance check
        selfdestruct(payable(owner));
    }
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    receive() external payable {
        deposit();
    }
}

