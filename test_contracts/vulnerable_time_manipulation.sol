// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

contract VulnerableTimeManipulation {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public lockTime;
    uint256 public totalSupply;
    address public owner;
    
    constructor() {
        owner = msg.sender;
        totalSupply = 1000000;
    }
    
    // Vulnerable: Direct time comparison without validation
    function withdraw() public {
        require(block.timestamp > lockTime[msg.sender], "Still locked");
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }
    
    // Vulnerable: Time-based calculation that can be manipulated
    function calculateReward() public view returns (uint256) {
        uint256 timeElapsed = block.timestamp - lockTime[msg.sender];
        return timeElapsed * 100; // Can be manipulated by miners
    }
    
    // Vulnerable: Time-based loop condition
    function processClaims() public {
        uint256 currentTime = block.timestamp;
        while (currentTime < block.timestamp + 3600) { // Dangerous loop
            // Process claims
            currentTime++;
        }
    }
    
    // Vulnerable: Direct assignment to time variable
    function setLockTime(uint256 newTime) public {
        lockTime[msg.sender] = block.timestamp; // No validation
    }
    
    // Vulnerable: Time check with external call
    function claimReward() public {
        require(block.timestamp > lockTime[msg.sender], "Too early");
        payable(msg.sender).call{value: 1 ether}(""); // External call after time check
    }
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
        lockTime[msg.sender] = block.timestamp + 86400; // 24 hours
    }
    
    receive() external payable {
        deposit();
    }
}
