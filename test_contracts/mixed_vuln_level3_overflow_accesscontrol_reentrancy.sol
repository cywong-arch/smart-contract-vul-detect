// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * MIXED VULNERABILITY LEVEL 3: OVERFLOW + ACCESS CONTROL + REENTRANCY
 * Purpose: Test detection when contract contains ALL THREE vulnerability types
 * Vulnerability: Mix of overflow, access control, AND reentrancy vulnerabilities
 */
contract MixedVulnLevel3 {
    address public owner;
    uint256 public total;
    uint256 public balance;
    mapping(address => uint256) public balances;
    
    constructor() {
        owner = msg.sender;
    }
    
    // VULNERABLE: Basic overflow - addition
    function add(uint256 a, uint256 b) public {
        unchecked {
            total = a + b;  // Unchecked addition can overflow!
        }
    }
    
    // VULNERABLE: Basic overflow - multiplication
    function multiply(uint256 a, uint256 b) public {
        unchecked {
            total = a * b;  // Unchecked multiplication can overflow!
        }
    }
    
    // VULNERABLE: Basic underflow - subtraction
    function subtract(uint256 a, uint256 b) public {
        unchecked {
            balance = a - b;  // Unchecked subtraction can underflow!
        }
    }
    
    // VULNERABLE: Accumulator overflow + NO ACCESS CONTROL
    function accumulate(uint256 amount) public {
        // Missing: require(msg.sender == owner);
        balance += amount;  // Anyone can accumulate, and can overflow!
    }
    
    // VULNERABLE: Loop with accumulator + NO ACCESS CONTROL
    function batchAdd(address[] memory accounts, uint256[] memory amounts) public {
        require(accounts.length == amounts.length, "Arrays mismatch");
        // Missing: require(msg.sender == owner);
        
        for (uint256 i = 0; i < accounts.length; i++) {
            balances[accounts[i]] += amounts[i];  // Overflow possible
            total += amounts[i];  // Accumulator overflow
        }
    }
    
    // VULNERABLE: Multiplication by constant + WRONG ACCESS CONTROL
    function calculateReward(uint256 amount) public {
        require(msg.sender != address(0), "Invalid sender");  // Too weak!
        balance += amount * 100;  // Multiplication overflow
    }
    
    // VULNERABLE: Multiple sequential additions + NO ACCESS CONTROL
    function addMultiple(uint256 a, uint256 b, uint256 c) public {
        // Missing access control
        uint256 temp = a + b;  // First addition can overflow
        total = temp + c;      // Second addition can overflow
    }
    
    // VULNERABLE: ACCESS CONTROL - No restriction + REENTRANCY - External call before state update
    function withdraw(uint256 amount) public {
        // Missing: require(msg.sender == owner);  // ACCESS CONTROL VULN
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // External call BEFORE state update - REENTRANCY VULN
        payable(msg.sender).transfer(amount);
        
        // State update AFTER external call - vulnerable!
        balances[msg.sender] -= amount;  // Also underflow risk
    }
    
    // VULNERABLE: ACCESS CONTROL - Anyone can set balance
    function setBalance(uint256 newBalance) public {
        // Missing: require(msg.sender == owner);
        balance = newBalance;  // Anyone can manipulate balance!
    }
    
    // VULNERABLE: ACCESS CONTROL - No restriction on selfdestruct
    function emergencyStop() public {
        // Missing: require(msg.sender == owner);
        selfdestruct(payable(msg.sender));  // Anyone can destroy contract!
    }
    
    // VULNERABLE: REENTRANCY - Cross-function reentrancy + NO ACCESS CONTROL
    function transfer(address to, uint256 amount) public {
        // Missing: require(msg.sender == owner);  // ACCESS CONTROL VULN
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // State update in transfer
        balances[msg.sender] -= amount;
        balances[to] += amount;
        
        // External call after state update - but can reenter through withdraw - REENTRANCY VULN
        payable(to).call{value: 0}("");
    }
    
    // VULNERABLE: REENTRANCY - Batch withdraw with external calls in loop + NO ACCESS CONTROL
    function batchWithdraw(address[] memory recipients, uint256[] memory amounts) public {
        require(recipients.length == amounts.length, "Arrays mismatch");
        // Missing: require(msg.sender == owner);  // ACCESS CONTROL VULN
        
        for (uint256 i = 0; i < recipients.length; i++) {
            require(balances[recipients[i]] >= amounts[i], "Insufficient balance");
            
            // External call in loop BEFORE state update - REENTRANCY VULN
            payable(recipients[i]).call{value: amounts[i]}("");
            
            // State update after external call
            balances[recipients[i]] -= amounts[i];  // Also underflow risk
            total += amounts[i];  // Also overflow risk in unchecked context
        }
    }
    
    // Deposit function (safe)
    function deposit() public payable {
        balances[msg.sender] += msg.value;
        balance += msg.value;
    }
    
    // Safe view function
    function getTotal() public view returns (uint256) {
        return total;
    }
}

