// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * UNPROTECTED SELFDESTRUCT LEVEL 3: ADVANCED
 * Purpose: Test advanced unprotected selfdestruct vulnerabilities - subtle patterns and complex bypasses
 * Vulnerability: 50 advanced unprotected selfdestruct vulnerabilities
 */
contract UnprotectedSelfDestructLevel3 {
    mapping(address => uint256) public balances;
    mapping(address => bool) public authorized;
    mapping(address => uint256) public roles;
    address public owner;
    address public admin;
    address public pendingOwner;
    uint256 public totalSupply;
    bool public paused;
    uint256 public constant OWNER_ROLE = 1;
    uint256 public constant ADMIN_ROLE = 2;
    
    constructor() {
        owner = msg.sender;
        admin = msg.sender;
        totalSupply = 1000000;
        roles[msg.sender] = OWNER_ROLE | ADMIN_ROLE;
    }
    
    // VULNERABLE #1: Selfdestruct with weak owner check
    function kill() public {
        require(msg.sender == admin, "Not admin"); // Should check owner
        selfdestruct(payable(owner));
    }
    
    // VULNERABLE #2: Selfdestruct with minimal condition
    function destroy() public {
        if (totalSupply > 0) { // Minimal condition
            selfdestruct(payable(owner));
        }
    }
    
    // VULNERABLE #3: Selfdestruct with balance check only
    function deleteContract() public {
        require(address(this).balance == 0, "Has balance"); // Only balance check
        selfdestruct(payable(owner));
    }
    
    // VULNERABLE #4: Selfdestruct with weak pause check
    function shutdown() public {
        require(!paused, "Paused"); // Weak check
        selfdestruct(payable(owner));
    }
    
    // VULNERABLE #5: Selfdestruct after external call
    function emergencyStop() public {
        payable(owner).call{value: address(this).balance}(""); // External call
        selfdestruct(payable(owner));
    }
    
    // VULNERABLE #6: Selfdestruct with OR condition
    function terminate() public {
        require(msg.sender == owner || msg.sender == admin, "Not authorized"); // OR allows admin
        selfdestruct(payable(owner));
    }
    
    // VULNERABLE #7: Selfdestruct in if statement
    function close() public {
        if (msg.sender == admin) { // If instead of require
            selfdestruct(payable(owner));
        }
    }
    
    // VULNERABLE #8: Selfdestruct with recipient as caller
    function remove() public {
        require(msg.sender == owner, "Not owner");
        selfdestruct(payable(msg.sender)); // Should be owner
    }
    
    // VULNERABLE #9: Selfdestruct with weak totalSupply check
    function destroyIfEmpty() public {
        require(totalSupply == 0, "Not empty"); // Can be manipulated
        selfdestruct(payable(owner));
    }
    
    // VULNERABLE #10: Selfdestruct in fallback
    fallback() external payable {
        if (msg.sender == admin) { // Weak check in fallback
            selfdestruct(payable(owner));
        }
    }
    
    // VULNERABLE #11: Selfdestruct with time check
    function destroyAfterTime() public {
        require(block.timestamp > 1000000000, "Too early"); // Weak time check
        selfdestruct(payable(owner));
    }
    
    // VULNERABLE #12: Selfdestruct with balance threshold
    function destroyIfLowBalance() public {
        if (address(this).balance < 1 ether) { // Low threshold
            selfdestruct(payable(owner));
        }
    }
    
    // VULNERABLE #13: Selfdestruct with user balance check
    function destroyIfNoUsers() public {
        require(balances[msg.sender] == 0, "Has balance"); // Wrong check
        selfdestruct(payable(owner));
    }
    
    // VULNERABLE #14: Selfdestruct in loop
    function batchDestroy() public {
        for (uint256 i = 0; i < 10; i++) {
            if (i == 5) {
                selfdestruct(payable(owner)); // In loop
            }
        }
    }
    
    // VULNERABLE #15: Selfdestruct with modifier-like check
    function destroyWithCheck() public {
        bool isAuthorized = msg.sender == admin;
        if (isAuthorized) {
            selfdestruct(payable(owner));
        }
    }
    
    // VULNERABLE #16: Selfdestruct after state change
    function destroyAfterUpdate() public {
        totalSupply = 0; // State change
        selfdestruct(payable(owner));
    }
    
    // VULNERABLE #17: Selfdestruct with nested condition
    function complexDestroy() public {
        if (msg.sender == owner) {
            if (totalSupply == 0) {
                selfdestruct(payable(owner)); // Nested conditions
            }
        }
    }
    
    // VULNERABLE #18: Selfdestruct with external function call
    function destroyViaFunction() public {
        if (canDestroy()) {
            selfdestruct(payable(owner));
        }
    }
    
    // VULNERABLE #19: Selfdestruct with recipient parameter
    function destroyTo(address recipient) public {
        require(msg.sender == owner, "Not owner");
        selfdestruct(payable(recipient)); // Recipient can be manipulated
    }
    
    // VULNERABLE #20: Selfdestruct with pause check
    function destroyIfPaused() public {
        require(paused, "Not paused"); // Anyone can pause
        selfdestruct(payable(owner));
    }
    
    // VULNERABLE #21: Selfdestruct with multiple conditions
    function destroyWithMultiple() public {
        require(msg.sender == admin, "Not admin");
        require(totalSupply < 1000, "Too much supply"); // Multiple weak conditions
        selfdestruct(payable(owner));
    }
    
    // VULNERABLE #22: Selfdestruct in receive function
    receive() external payable {
        if (msg.sender == admin && address(this).balance > 1000 ether) {
            selfdestruct(payable(owner)); // In receive
        } else {
            deposit();
        }
    }
    
    // VULNERABLE #23: Selfdestruct with mapping check
    function destroyIfNoBalance() public {
        require(balances[msg.sender] == 0, "Has balance"); // Wrong mapping check
        selfdestruct(payable(owner));
    }
    
    // VULNERABLE #24: Selfdestruct with gas limit
    function destroyWithGas() public {
        require(msg.sender == owner, "Not owner");
        selfdestruct(payable(owner)); // Gas limit but still vulnerable
    }
    
    // VULNERABLE #25: Selfdestruct with try-catch
    function destroySafely() public {
        require(msg.sender == admin, "Not admin"); // Wrong check
        try this.internalDestroy() {} catch {
            selfdestruct(payable(owner));
        }
    }
    
    // VULNERABLE #26: Selfdestruct after transfer
    function destroyAfterTransfer() public {
        payable(owner).transfer(address(this).balance / 2);
        selfdestruct(payable(owner)); // After partial transfer
    }
    
    // VULNERABLE #27: Selfdestruct with delegatecall
    function destroyViaDelegate(address target) public {
        require(msg.sender == owner, "Not owner");
        (bool success, ) = target.delegatecall(
            abi.encodeWithSignature("destroy()")
        ); // Delegatecall can contain selfdestruct
    }
    
    // VULNERABLE #28: Selfdestruct with event
    function destroyWithEvent() public {
        require(msg.sender == admin, "Not admin"); // Wrong check
        emit ContractDestroyed();
        selfdestruct(payable(owner));
    }
    
    // VULNERABLE #29: Selfdestruct with return value
    function destroyAndReturn() public returns (bool) {
        if (msg.sender == owner) {
            selfdestruct(payable(owner));
            return true;
        }
        return false;
    }
    
    // VULNERABLE #30: Selfdestruct with storage update
    function destroyAndUpdate() public {
        owner = address(0); // Update before destroy
        selfdestruct(payable(msg.sender)); // Wrong recipient
    }
    
    // VULNERABLE #31: Selfdestruct with role check
    function destroyWithRole() public {
        require(hasRole(msg.sender, ADMIN_ROLE), "Not admin"); // Should check owner role
        selfdestruct(payable(owner));
    }
    
    // VULNERABLE #32: Selfdestruct with authorization check
    function destroyIfAuthorized() public {
        if (authorized[msg.sender]) { // Authorization can be self-granted
            selfdestruct(payable(owner));
        }
    }
    
    // VULNERABLE #33: Selfdestruct with pending owner
    function destroyWithPending() public {
        require(msg.sender == pendingOwner, "Not pending owner"); // Wrong check
        selfdestruct(payable(owner));
    }
    
    // VULNERABLE #34: Selfdestruct with assembly
    function destroyWithAssembly() public {
        assembly {
            let sender := caller()
            let ownerSlot := owner.slot
            let ownerValue := sload(ownerSlot)
            if eq(sender, ownerValue) {
                selfdestruct(ownerValue)
            }
        } // Assembly selfdestruct
    }
    
    // VULNERABLE #35: Selfdestruct with library call
    function destroyViaLibrary(address libraryAddr) public {
        require(msg.sender == admin, "Not admin"); // Wrong check
        (bool success, ) = libraryAddr.delegatecall(
            abi.encodeWithSignature("destroy()")
        ); // Library can contain selfdestruct
    }
    
    // VULNERABLE #36: Selfdestruct with modifier pattern
    function destroyWithModifier() public onlyAdmin { // Modifier checks admin, not owner
        selfdestruct(payable(owner));
    }
    
    // VULNERABLE #37: Selfdestruct with inheritance
    function destroyInherited() public {
        require(msg.sender == admin, "Not admin"); // Wrong check
        selfdestruct(payable(owner));
    }
    
    // VULNERABLE #38: Selfdestruct with interface call
    function destroyViaInterface(address target) public {
        require(msg.sender == owner, "Not owner");
        IDestroyable(target).destroy(); // Interface can contain selfdestruct
    }
    
    // VULNERABLE #39: Selfdestruct with proxy pattern
    function destroyProxy() public {
        require(msg.sender == admin, "Not admin"); // Wrong check
        selfdestruct(payable(owner));
    }
    
    // VULNERABLE #40: Selfdestruct with upgrade pattern
    function destroyUpgrade() public {
        require(msg.sender == admin, "Not admin"); // Wrong check
        selfdestruct(payable(owner));
    }
    
    // VULNERABLE #41: Selfdestruct with multi-sig pattern (but single check)
    function destroyMultiSig() public {
        require(msg.sender == owner || msg.sender == admin, "Not authorized"); // Should be multi-sig
        selfdestruct(payable(owner));
    }
    
    // VULNERABLE #42: Selfdestruct with time-based check
    function destroyAfterTime(uint256 time) public {
        require(block.timestamp > time, "Too early"); // Time can be manipulated
        selfdestruct(payable(owner));
    }
    
    // VULNERABLE #43: Selfdestruct with block-based check
    function destroyAfterBlock(uint256 blockNum) public {
        require(block.number > blockNum, "Too early"); // Block can be manipulated
        selfdestruct(payable(owner));
    }
    
    // VULNERABLE #44: Selfdestruct with balance-based check
    function destroyIfBalanceLow() public {
        if (address(this).balance < 0.1 ether) { // Very low threshold
            selfdestruct(payable(owner));
        }
    }
    
    // VULNERABLE #45: Selfdestruct with supply-based check
    function destroyIfSupplyLow() public {
        require(totalSupply < 100, "Too much supply"); // Low threshold
        selfdestruct(payable(owner));
    }
    
    // VULNERABLE #46: Selfdestruct with recipient from mapping
    function destroyToMapped() public {
        require(msg.sender == owner, "Not owner");
        address recipient = getRecipient(); // Can be manipulated
        selfdestruct(payable(recipient));
    }
    
    // VULNERABLE #47: Selfdestruct with conditional recipient
    function destroyConditional() public {
        require(msg.sender == admin, "Not admin"); // Wrong check
        address recipient = msg.sender == owner ? owner : admin; // Conditional
        selfdestruct(payable(recipient));
    }
    
    // VULNERABLE #48: Selfdestruct with error handling
    function destroyWithError() public {
        require(msg.sender == admin, "Not admin"); // Wrong check
        try this.internalDestroy() {
            // Success
        } catch Error(string memory) {
            selfdestruct(payable(owner));
        } catch {
            selfdestruct(payable(owner));
        }
    }
    
    // VULNERABLE #49: Selfdestruct with reentrancy guard (but wrong check)
    function destroyWithGuard() public {
        require(!paused, "Paused"); // Guard but wrong check
        paused = true;
        selfdestruct(payable(owner));
    }
    
    // VULNERABLE #50: Selfdestruct with complex authorization
    function destroyComplex() public {
        bool isOwner = msg.sender == owner;
        bool isAdmin = msg.sender == admin;
        bool hasAdminRole = hasRole(msg.sender, ADMIN_ROLE);
        if (isOwner || (isAdmin && hasAdminRole)) { // Complex but still allows admin
            selfdestruct(payable(owner));
        }
    }
    
    function canDestroy() internal view returns (bool) {
        return msg.sender == admin; // Should check owner
    }
    
    function internalDestroy() external {
        selfdestruct(payable(owner));
    }
    
    function hasRole(address account, uint256 role) internal view returns (bool) {
        return (roles[account] & role) != 0;
    }
    
    function getRecipient() internal view returns (address) {
        return authorized[msg.sender] ? owner : admin; // Can be manipulated
    }
    
    function setPaused(bool _paused) public {
        paused = _paused; // No access control
    }
    
    function authorize(address account) public {
        authorized[account] = true; // No access control
    }
    
    function grantRole(address account, uint256 role) public {
        roles[account] = roles[account] | role; // No access control
    }
    
    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    event ContractDestroyed();
}

interface IDestroyable {
    function destroy() external;
}

