// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * UNPROTECTED SELFDESTRUCT LEVEL 2: INTERMEDIATE
 * Purpose: Test intermediate unprotected selfdestruct vulnerabilities - partial protection and complex patterns
 * Vulnerability: 30 intermediate unprotected selfdestruct vulnerabilities
 */
contract UnprotectedSelfDestructLevel2 {
    mapping(address => uint256) public balances;
    address public owner;
    address public admin;
    uint256 public totalSupply;
    bool public paused;
    
    constructor() {
        owner = msg.sender;
        admin = msg.sender;
        totalSupply = 1000000;
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
        require(!paused, "Paused"); // Weak check, anyone can unpause
        selfdestruct(payable(owner));
    }
    
    // VULNERABLE #5: Selfdestruct after external call
    function emergencyStop() public {
        payable(owner).call{value: address(this).balance}(""); // External call
        selfdestruct(payable(owner)); // After external call
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
        selfdestruct(payable(msg.sender)); // Should be owner, not msg.sender
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
        selfdestruct(payable(owner)); // After state change
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
    
    function canDestroy() internal view returns (bool) {
        return msg.sender == admin; // Should check owner
    }
    
    function internalDestroy() external {
        selfdestruct(payable(owner));
    }
    
    function setPaused(bool _paused) public {
        paused = _paused; // No access control
    }
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    event ContractDestroyed();
}

