// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Vulnerable contract with reentrancy issues
contract VulnerableReentrancy {
    mapping(address => uint256) public balances;
    
    // Vulnerable: External call before state update
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // External call before updating balance - REENTRANCY VULNERABILITY
        payable(msg.sender).call{value: amount}("");
        
        // State update after external call - vulnerable!
        balances[msg.sender] -= amount;
    }
    
    // Vulnerable: Multiple external calls in loop
    function batchWithdraw(address[] calldata recipients, uint256[] calldata amounts) public {
        for (uint256 i = 0; i < recipients.length; i++) {
            // External call in loop - potential DoS
            payable(recipients[i]).transfer(amounts[i]);
        }
    }
    
    // Vulnerable: External call without reentrancy guard
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    // Vulnerable: External call before state modification
    function transfer(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // External call before updating balances
        payable(to).call{value: amount}("");
        
        // State updates after external call
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}




