// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Secure contract with proper protections
contract SecureContract {
    mapping(address => uint256) public balances;
    address public owner;
    bool private locked;
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }
    
    modifier nonReentrant() {
        require(!locked, "Reentrancy guard: function is locked");
        locked = true;
        _;
        locked = false;
    }
    
    constructor() {
        owner = msg.sender;
    }
    
    // Secure: Proper access control
    function mint(address to, uint256 amount) public onlyOwner {
        balances[to] += amount;  // Safe with Solidity 0.8+
    }
    
    // Secure: Reentrancy guard and proper order
    function withdraw(uint256 amount) public nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Update state before external call
        balances[msg.sender] -= amount;
        
        // External call after state update
        payable(msg.sender).transfer(amount);
    }
    
    // Secure: Access control on critical function
    function emergencyStop() public onlyOwner {
        selfdestruct(payable(owner));
    }
    
    // Secure: No external calls, just state updates
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    // Secure: Internal transfer without external calls
    function transfer(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // State updates only
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}




