
from typing import List, Dict, Any
from .base_detector import VulnerabilityDetector


class BytecodeUnprotectedSelfDestructDetector(VulnerabilityDetector):
    """Detects unprotected selfdestruct vulnerabilities in bytecode."""
    
    def __init__(self):
        super().__init__(
            name="BytecodeUnprotectedSelfDestructDetector",
            description="Detects unprotected selfdestruct vulnerabilities in bytecode"
        )
        
        # SELFDESTRUCT opcode
        self.selfdestruct_opcode = "SELFDESTRUCT"
        
    def detect(self, bytecode_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect unprotected selfdestruct vulnerabilities in bytecode."""
        vulnerabilities = []
        opcodes = bytecode_analysis.get("opcodes", [])
        
        if not opcodes:
            return vulnerabilities
        
        # Find runtime bytecode start (skip constructor)
        runtime_start = self._find_runtime_start(opcodes)
        
        # Check for unprotected selfdestruct calls
        for op in opcodes:
            if op["name"] == self.selfdestruct_opcode:
                pos = op["position"]
                
                # Skip if in constructor
                if pos < runtime_start:
                    continue
                
                # Check if protected by access control
                is_protected = self._is_protected(opcodes, pos)
                
                if not is_protected:
                    vulnerabilities.append(self._create_vulnerability(
                        vuln_type="Unprotected Selfdestruct",
                        severity="Critical",
                        description=f"Unprotected SELFDESTRUCT opcode detected at position {pos}",
                        line_number=pos,
                        code_snippet=f"Position {pos}: SELFDESTRUCT",
                        recommendation="Add proper access control (onlyOwner modifier) or multi-signature requirements before selfdestruct calls."
                    ))
        
        return vulnerabilities
    
    def _find_runtime_start(self, opcodes: List[Dict]) -> int:
        """Find the start of runtime bytecode by looking for the first RETURN."""
        # Look for the first RETURN opcode which marks end of constructor
        for op in opcodes:
            if op["name"] == "RETURN":
                # Runtime typically starts shortly after constructor RETURN
                return op["position"] + 100
        
        # Fallback: assume runtime starts at position 2000
        return 2000
    
    def _is_protected(self, opcodes: List[Dict], selfdestruct_pos: int) -> bool:
        """Check if selfdestruct is protected by access control."""
        # Find the function entry point for this selfdestruct
        entry_pos = self._find_function_entry(opcodes, selfdestruct_pos)
        
        if entry_pos == 0:
            return False
        
        # Check first 300 opcodes from function entry for access control pattern
        entry_idx = next((i for i, op in enumerate(opcodes) if op["position"] == entry_pos), None)
        if entry_idx is None:
            return False
        
        window = opcodes[entry_idx:min(entry_idx + 300, len(opcodes))]
        
        # Look for access control pattern: CALLER -> SLOAD -> EQ -> JUMPI -> REVERT
        # This pattern indicates onlyOwner check
        has_caller = any(op["name"] == "CALLER" for op in window)
        has_sload = any(op["name"] == "SLOAD" for op in window)
        has_eq = any(op["name"] == "EQ" for op in window)
        has_jumpi = any(op["name"] == "JUMPI" for op in window[5:])
        has_revert = any(op["name"] == "REVERT" for op in window[10:])
        
        # Check for pattern: CALLER followed by SLOAD, EQ, JUMPI, REVERT
        if has_caller and has_sload and has_eq and has_jumpi and has_revert:
            # Verify the pattern sequence
            caller_idx = next((i for i, op in enumerate(window) if op["name"] == "CALLER"), None)
            if caller_idx is not None:
                # Check if there's SLOAD, EQ, JUMPI, REVERT after CALLER
                sub_window = window[caller_idx:min(caller_idx + 50, len(window))]
                op_names = [op["name"] for op in sub_window]
                
                # Look for pattern: CALLER ... SLOAD ... EQ ... JUMPI ... REVERT
                if "SLOAD" in op_names and "EQ" in op_names and "JUMPI" in op_names and "REVERT" in op_names:
                    return True
        
        return False
    
    def _find_function_entry(self, opcodes: List[Dict], op_pos: int) -> int:
        """Find the function entry point (JUMPDEST) before the given position."""
        # Look backwards for the nearest JUMPDEST before this position
        for i in range(len(opcodes) - 1, -1, -1):
            if opcodes[i]["position"] > op_pos:
                continue
            if opcodes[i]["name"] == "JUMPDEST":
                # Check if this JUMPDEST is likely a function entry
                # Function entries are typically after selector checks
                if i > 0:
                    # Check if there's a JUMPI before this JUMPDEST (function selector pattern)
                    for j in range(max(0, i - 20), i):
                        if opcodes[j]["name"] == "JUMPI":
                            return opcodes[i]["position"]
                return opcodes[i]["position"]
        
        return 0

