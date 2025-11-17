

from typing import List, Dict, Any, Optional
from .base_detector import VulnerabilityDetector


class BytecodeReentrancyDetector(VulnerabilityDetector):
    def __init__(self):
        super().__init__(
            name="BytecodeReentrancyDetector",
            description="Detects real reentrancy risks in bytecode"
        )
        self.call_opcodes = {"CALL", "DELEGATECALL", "CALLCODE"}
        self.state_ops = {"SSTORE"}
        self.safe_selectors = {
            "0x70a08231",  # balanceOf
            "0x18160ddd",  # totalSupply
            "0x06fdde03",  # name
            "0x95d89b41",  # symbol
            "0x313ce567",  # decimals
        }

    def detect(self, bytecode_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Detect reentrancy vulnerabilities in bytecode.
        
        Improved approach: Direct CALL -> SSTORE pattern detection
        without complex function boundary analysis.
        """
        vulnerabilities = []
        opcodes = bytecode_analysis.get("opcodes", [])
        
        # Track reported positions to avoid duplicates
        reported_call_positions = set()
        # Track reported function contexts to group by function
        reported_function_contexts = set()
        
        # Method 1: Simple direct pattern detection (more reliable)
        for i, op in enumerate(opcodes):
            if op["name"] in self.call_opcodes:
                call_pos = op["position"]
                # Skip if already reported
                if call_pos in reported_call_positions:
                    continue
                    
                # Look for SSTORE after this CALL
                for j in range(i+1, len(opcodes)):
                    if opcodes[j]["name"] == "SSTORE":
                        sstore_pos = opcodes[j]["position"]
                        # Check if there's a guard before the CALL
                        has_guard = self._has_reentrancy_guard(opcodes[:i])
                        if not has_guard:
                            # Find function context to avoid reporting same function multiple times
                            func_context = self._find_function_context(opcodes, i)
                            
                            # If we've already reported a reentrancy from this function, skip
                            if func_context and func_context in reported_function_contexts:
                                continue
                            
                            vulnerabilities.append(self._create_vulnerability(
                                vuln_type="Missing Reentrancy Guard",
                                severity="High",
                                description="External call before state update without guard",
                                line_number=call_pos,
                                code_snippet=f"CALL at {call_pos} -> SSTORE at {sstore_pos}",
                                recommendation="Follow Checks-Effects-Interactions pattern + use nonReentrant modifier"
                            ))
                            reported_call_positions.add(call_pos)
                            if func_context:
                                reported_function_contexts.add(func_context)
                        break
        
        # Method 2: Function-based detection (original approach - kept as fallback)
        # Skip if Method 1 already found all vulnerabilities
        selectors = {s["selector"] for s in bytecode_analysis.get("function_selectors", [])}
        func_entries = self._find_function_entries(opcodes, selectors)
        
        for entry_pos, sel in func_entries.items():
            if sel in self.safe_selectors:
                continue
            func_opcodes = self._extract_function_opcodes(opcodes, entry_pos)
            if self._has_reentrancy_risk(func_opcodes):
                call_idx = self._find_first_call(func_opcodes)
                if call_idx is not None:
                    call_pos = func_opcodes[call_idx]["position"]
                    # Only add if not already detected by method 1
                    if call_pos not in reported_call_positions:
                        vulnerabilities.append(self._create_vulnerability(
                            vuln_type="Missing Reentrancy Guard",
                            severity="High",
                            description="External call before state update without guard",
                            line_number=call_pos,
                            code_snippet=f"Function {sel}: CALL -> SSTORE",
                            recommendation="Follow Checks-Effects-Interactions pattern + use nonReentrant modifier"
                        ))
                        reported_call_positions.add(call_pos)

        return vulnerabilities

    def _find_function_entries(self, opcodes: List[Dict], selectors: set) -> dict:
        """
        Find actual function entry points by tracing JUMPI targets.
        Improved: Follows JUMPI to find real function JUMPDEST.
        """
        entries = {}
        for i, op in enumerate(opcodes):
            if op["name"] == "PUSH4" and op["arguments"]:
                sel = hex(op["arguments"][0])[2:].zfill(8)
                if f"0x{sel}" in selectors:
                    # Find JUMPI after this selector check
                    for j in range(i+1, min(i+20, len(opcodes))):
                        if opcodes[j]["name"] == "JUMPI":
                            # Get the jump target from PUSH before JUMPI
                            if j > 0 and opcodes[j-1]["name"].startswith("PUSH"):
                                target_pos = opcodes[j-1].get("arguments", [0])[0]
                                # Find the actual JUMPDEST at that position
                                for k, target_op in enumerate(opcodes):
                                    if target_op["position"] == target_pos and target_op["name"] == "JUMPDEST":
                                        # This is the real function entry
                                        entries[target_op["position"]] = f"0x{sel}"
                                        break
                            break
        return entries

    def _extract_function_opcodes(self, opcodes: List[Dict], entry_pos: int) -> List[Dict]:
        start_idx = next(i for i, op in enumerate(opcodes) if op["position"] == entry_pos)
        end_idx = len(opcodes)
        for i in range(start_idx, len(opcodes)):
            if opcodes[i]["name"] in ["JUMP", "RETURN", "REVERT", "STOP"]:
                end_idx = i
                break
        return opcodes[start_idx:end_idx]

    def _has_reentrancy_risk(self, func_opcodes: List[Dict]) -> bool:
        call_idx = self._find_first_call(func_opcodes)
        if call_idx is None:
            return False
        # Check if SSTORE after CALL
        has_sstore = any(op["name"] == "SSTORE" for op in func_opcodes[call_idx:])
        # Check if guard is set before
        has_guard = self._has_reentrancy_guard(func_opcodes[:call_idx])
        return has_sstore and not has_guard

    def _find_first_call(self, opcodes: List[Dict]) -> int:
        """Return index of first call opcode, not position."""
        for i, op in enumerate(opcodes):
            if op["name"] in self.call_opcodes:
                return i  # Return index, not position
        return None

    def _has_reentrancy_guard(self, opcodes: List[Dict]) -> bool:
        # Look for: SLOAD -> EQ -> JUMPI -> REVERT (nonReentrant pattern)
        for i in range(len(opcodes) - 5):
            if (opcodes[i]["name"] == "SLOAD" and
                opcodes[i+1]["name"] == "PUSH1" and
                opcodes[i+1]["arguments"][0] == 0 and
                opcodes[i+2]["name"] == "EQ" and
                opcodes[i+3]["name"] == "JUMPI"):
                return True
        return False
    
    def _find_function_context(self, opcodes: List[Dict], op_idx: int) -> Optional[str]:
        """
        Find the function context for an opcode to group vulnerabilities by function.
        
        Returns:
            Function selector or entry position identifier, or None if not in a function
        """
        # Look backwards to find the nearest function entry (JUMPDEST after PUSH4+JUMPI)
        for i in range(op_idx - 1, max(0, op_idx - 100), -1):
            if opcodes[i]["name"] == "PUSH4" and i + 1 < len(opcodes):
                # PUSH4 usually contains function selector
                next_op = opcodes[i + 1]
                if next_op["name"] == "JUMPI":
                    # Check if there's a JUMPDEST after this (function entry)
                    for j in range(i + 2, min(len(opcodes), i + 20)):
                        if opcodes[j]["name"] == "JUMPDEST":
                            # Found function entry - use selector as context
                            if opcodes[i].get("arguments"):
                                # Format selector as hex
                                sel_int = opcodes[i]["arguments"][0]
                                selector = f"0x{sel_int:08x}"
                                return selector
                            break
                    # Return position-based context if selector not found
                    return f"func_{opcodes[i]['position']}"
        
        return None