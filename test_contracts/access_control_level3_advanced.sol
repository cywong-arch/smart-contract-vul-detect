// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * ACCESS CONTROL LEVEL 3: ADVANCED
 * Purpose: Test advanced access control vulnerability - subtle bypass patterns
 * Vulnerability: Complex access control logic with potential bypasses
 */
contract AccessControlLevel3 {
    address public owner;
    address public pendingOwner;
    mapping(address => uint256) public roles;  // Role-based system
    uint256 public constant OWNER_ROLE = 1;
    uint256 public constant ADMIN_ROLE = 2;
    uint256 public balance;
    
    constructor() {
        owner = msg.sender;
        roles[msg.sender] = OWNER_ROLE | ADMIN_ROLE;
    }
    
    // VULNERABLE: Complex ownership transfer with race condition
    function proposeOwner(address newOwner) public {
        require(msg.sender == owner, "Not owner");
        pendingOwner = newOwner;
    }
    
    function acceptOwnership() public {
        require(msg.sender == pendingOwner, "Not pending owner");
        owner = pendingOwner;  // Problem: No clearing of pendingOwner
        pendingOwner = address(0);  // Should be here, but easily forgotten
    }
    
    // VULNERABLE: Role check but role can be self-assigned
    function grantRole(address account, uint256 role) public {
        // Missing: require(hasRole(msg.sender, OWNER_ROLE));
        roles[account] = roles[account] | role;  // Anyone can grant roles!
    }
    
    // VULNERABLE: State modification without proper access control
    function updateBalance(uint256 newBalance) public {
        require(hasRole(msg.sender, ADMIN_ROLE), "Not admin");
        // But hasRole can be bypassed if grantRole is vulnerable
        balance = newBalance;
    }
    
    function hasRole(address account, uint256 role) public view returns (bool) {
        return (roles[account] & role) != 0;
    }
    
    // VULNERABLE: Fallback function without access control
    fallback() external payable {
        balance += msg.value;  // Anyone can send funds
        // But withdrawal might have access control, creating inconsistency
    }
    
    // VULNERABLE: Withdraw requires owner but fallback allows anyone to deposit
    function withdraw() public {
        require(msg.sender == owner, "Not owner");
        payable(owner).transfer(balance);
        balance = 0;
    }
}

