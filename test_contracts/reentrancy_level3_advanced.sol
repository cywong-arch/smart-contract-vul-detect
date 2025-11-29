// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * REENTRANCY LEVEL 3: ADVANCED
 * Purpose: Test advanced reentrancy vulnerability - read-only reentrancy and complex patterns
 * Vulnerability: Subtle reentrancy through read-only external calls and complex state interactions
 */
contract ReentrancyLevel3 {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public rewards;
    address public oracle;
    bool public paused;
    
    // VULNERABLE: Read-only reentrancy through external view call
    function claimReward() public {
        require(!paused, "Contract paused");
        require(rewards[msg.sender] > 0, "No rewards");
        
        uint256 reward = rewards[msg.sender];
        rewards[msg.sender] = 0;  // State update first
        
        // External call to oracle - can be reentered through getTotalValue
        require(getOraclePrice() > 0, "Invalid oracle");
        
        // External call after state update but before all state is consistent
        payable(msg.sender).transfer(reward);
        
        // Problem: balances might be read during oracle call via getTotalValue
    }
    
    // VULNERABLE: Can be called during reentrancy to read inconsistent state
    function getTotalValue() public view returns (uint256) {
        // This can be called during reentrancy to get inconsistent state
        return balances[msg.sender] + rewards[msg.sender];
    }
    
    // Simulated oracle call that could trigger reentrancy
    function getOraclePrice() public view returns (uint256) {
        // In real scenario, this might call another contract
        // which could call back into this contract
        return 100;
    }
    
    // VULNERABLE: Complex state interaction with external call in loop
    function batchWithdraw(address[] memory recipients, uint256[] memory amounts) public {
        require(recipients.length == amounts.length, "Arrays mismatch");
        require(!paused, "Contract paused");
        
        for (uint256 i = 0; i < recipients.length; i++) {
            require(balances[recipients[i]] >= amounts[i], "Insufficient balance");
            
            // External call in loop before state update
            payable(recipients[i]).call{value: amounts[i]}("");
            
            // State update after external call
            balances[recipients[i]] -= amounts[i];
        }
    }
    
    // VULNERABLE: External call to unknown contract
    function callExternal(address target, bytes memory data) public {
        require(!paused, "Contract paused");
        // External call to unknown contract - potential reentrancy
        (bool success, ) = target.call(data);
        require(success, "Call failed");
        
        // State update after external call
        paused = true;  // Too late if reentrancy occurred
    }
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    function addReward(address account, uint256 amount) public {
        rewards[account] += amount;
    }
}

