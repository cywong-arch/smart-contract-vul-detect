// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

contract VulnerableUnprotectedSelfDestruct {
    mapping(address => uint256) public balances;
    address public owner;
    uint256 public totalSupply;
    
    constructor() {
        owner = msg.sender;
        totalSupply = 1000000;
    }
    
    // Vulnerable: Unprotected selfdestruct call
    function kill() public {
        selfdestruct(payable(owner)); // No access control
    }
    
    // Vulnerable: Selfdestruct without proper conditions
    function destroy() public {
        // No conditions or access control
        suicide(payable(owner)); // Deprecated but still vulnerable
    }
    
    // Vulnerable: Selfdestruct in loop
    function batchDestroy() public {
        for (uint256 i = 0; i < 10; i++) {
            if (i == 5) {
                selfdestruct(payable(owner)); // Selfdestruct in loop
            }
        }
    }
    
    // Vulnerable: Selfdestruct with external call
    function emergencyShutdown() public {
        payable(owner).call{value: address(this).balance}(""); // External call
        selfdestruct(payable(owner)); // Selfdestruct after external call
    }
    
    // Vulnerable: Selfdestruct without multi-signature
    function terminate() public {
        // No multi-signature requirement
        selfdestruct(payable(owner));
    }
    
    // Vulnerable: Selfdestruct in constructor
    constructor(address _owner) {
        owner = _owner;
        selfdestruct(payable(_owner)); // Selfdestruct in constructor
    }
    
    // Vulnerable: Selfdestruct with minimal conditions
    function close() public {
        if (totalSupply == 0) {
            selfdestruct(payable(owner)); // Minimal condition
        }
    }
    
    // Vulnerable: Selfdestruct without owner check
    function remove() public {
        // No owner verification
        selfdestruct(payable(msg.sender));
    }
    
    // Vulnerable: Selfdestruct with weak conditions
    function deleteContract() public {
        require(balances[msg.sender] > 0, "No balance"); // Weak condition
        selfdestruct(payable(msg.sender));
    }
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    receive() external payable {
        deposit();
    }
}
