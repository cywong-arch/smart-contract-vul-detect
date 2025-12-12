
from typing import List, Dict, Any
from .base_detector import VulnerabilityDetector


class BytecodeDenialOfServiceDetector(VulnerabilityDetector):
    """Detects denial of service vulnerabilities in bytecode."""
    
    def __init__(self):
        super().__init__(
            name="BytecodeDenialOfServiceDetector",
            description="Detects denial of service vulnerabilities in bytecode"
        )
        
        # External call opcodes that can cause DoS
        self.external_call_opcodes = {"CALL", "DELEGATECALL", "CALLCODE", "STATICCALL"}
        
        # Gas-consuming opcodes
        self.gas_consuming_opcodes = {"SHA3", "CREATE", "CREATE2"}
        
        # Storage operations
        self.storage_opcodes = {"SLOAD", "SSTORE"}
        
    def detect(self, bytecode_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect denial of service vulnerabilities in bytecode."""
        vulnerabilities = []
        opcodes = bytecode_analysis.get("opcodes", [])
        
        if not opcodes:
            return vulnerabilities
        
        # Check for external calls in loops
        loop_call_vulns = self._check_external_calls_in_loops(opcodes)
        vulnerabilities.extend(loop_call_vulns)
        
        # Check for unbounded loops
        unbounded_loop_vulns = self._check_unbounded_loops(opcodes)
        vulnerabilities.extend(unbounded_loop_vulns)
        
        # Check for gas-consuming operations in loops
        gas_loop_vulns = self._check_gas_consuming_in_loops(opcodes)
        vulnerabilities.extend(gas_loop_vulns)
        
        # Check for storage operations in loops
        storage_loop_vulns = self._check_storage_in_loops(opcodes)
        vulnerabilities.extend(storage_loop_vulns)
        
        return vulnerabilities
    
    def _check_external_calls_in_loops(self, opcodes: List[Dict]) -> List[Dict[str, Any]]:
        """Check for external calls inside loops."""
        vulnerabilities = []
        reported_positions = set()
        
        # Find loops by looking for JUMP/JUMPI patterns
        loops = self._find_loops(opcodes)
        
        for loop_start, loop_end in loops:
            # Check if loop contains external calls
            loop_opcodes = [op for op in opcodes if loop_start <= op["position"] < loop_end]
            
            for op in loop_opcodes:
                if op["name"] in self.external_call_opcodes:
                    if op["position"] in reported_positions:
                        continue
                    vulnerabilities.append(self._create_vulnerability(
                        vuln_type="Denial of Service",
                        severity="High",
                        description=f"External call in loop detected: {op['name']} at position {op['position']}",
                        line_number=op["position"],
                        code_snippet=f"Position {op['position']}: {op['name']} in loop",
                        recommendation="Avoid external calls in loops. Use pull payment pattern or batch operations instead."
                    ))
                    reported_positions.add(op["position"])
                    break  # Only report once per loop
        
        return vulnerabilities
    
    def _check_unbounded_loops(self, opcodes: List[Dict]) -> List[Dict[str, Any]]:
        """Check for unbounded loops."""
        vulnerabilities = []
        
        loops = self._find_loops(opcodes)
        
        for loop_start, loop_end in loops:
            loop_opcodes = [op for op in opcodes if loop_start <= op["position"] < loop_end]
            
            # Check if loop has clear termination condition
            has_termination = self._has_termination_condition(loop_opcodes)
            
            if not has_termination:
                vulnerabilities.append(self._create_vulnerability(
                    vuln_type="Denial of Service",
                    severity="High",
                    description=f"Unbounded loop detected starting at position {loop_start}",
                    line_number=loop_start,
                    code_snippet=f"Loop from position {loop_start} to {loop_end}",
                    recommendation="Add clear termination conditions to prevent DoS attacks. Limit loop iterations."
                ))
        
        return vulnerabilities
    
    def _check_gas_consuming_in_loops(self, opcodes: List[Dict]) -> List[Dict[str, Any]]:
        """Check for gas-consuming operations in loops."""
        vulnerabilities = []
        reported_positions = set()
        
        loops = self._find_loops(opcodes)
        
        for loop_start, loop_end in loops:
            loop_opcodes = [op for op in opcodes if loop_start <= op["position"] < loop_end]
            
            for op in loop_opcodes:
                if op["name"] in self.gas_consuming_opcodes:
                    if op["position"] in reported_positions:
                        continue
                    vulnerabilities.append(self._create_vulnerability(
                        vuln_type="Denial of Service",
                        severity="Medium",
                        description=f"Gas-consuming operation in loop: {op['name']} at position {op['position']}",
                        line_number=op["position"],
                        code_snippet=f"Position {op['position']}: {op['name']} in loop",
                        recommendation="Be cautious with gas-consuming operations in loops. Consider gas limits and operation complexity."
                    ))
                    reported_positions.add(op["position"])
                    break
        
        return vulnerabilities
    
    def _check_storage_in_loops(self, opcodes: List[Dict]) -> List[Dict[str, Any]]:
        """Check for excessive storage operations in loops."""
        vulnerabilities = []
        
        loops = self._find_loops(opcodes)
        
        for loop_start, loop_end in loops:
            loop_opcodes = [op for op in opcodes if loop_start <= op["position"] < loop_end]
            
            # Count storage operations
            storage_count = sum(1 for op in loop_opcodes if op["name"] in self.storage_opcodes)
            
            # If too many storage operations in loop, it could cause DoS
            if storage_count > 10:
                vulnerabilities.append(self._create_vulnerability(
                    vuln_type="Denial of Service",
                    severity="Medium",
                    description=f"Excessive storage operations in loop: {storage_count} operations from position {loop_start}",
                    line_number=loop_start,
                    code_snippet=f"Loop with {storage_count} storage operations",
                    recommendation="Be cautious with storage operations in loops. Consider gas limits and operation complexity."
                ))
        
        return vulnerabilities
    
    def _find_loops(self, opcodes: List[Dict]) -> List[tuple]:
        """Find loops by identifying JUMP/JUMPI patterns."""
        loops = []
        
        # Look for JUMPI patterns that create loops
        # A loop typically has: JUMPDEST -> ... -> JUMP/JUMPI back to JUMPDEST
        jumpdests = {}
        for i, op in enumerate(opcodes):
            if op["name"] == "JUMPDEST":
                jumpdests[op["position"]] = i
        
        # Find JUMP/JUMPI that jump back to previous JUMPDEST
        for i, op in enumerate(opcodes):
            if op["name"] in ["JUMP", "JUMPI"]:
                # Get jump target from previous PUSH
                if i > 0 and opcodes[i-1]["name"].startswith("PUSH"):
                    target = opcodes[i-1].get("arguments", [0])[0]
                    
                    # Check if target is a JUMPDEST we've seen before
                    if target in jumpdests:
                        target_idx = jumpdests[target]
                        if target_idx < i:  # Jumping backwards = loop
                            loop_start = opcodes[target_idx]["position"]
                            loop_end = op["position"] + 1
                            loops.append((loop_start, loop_end))
        
        return loops
    
    def _has_termination_condition(self, loop_opcodes: List[Dict]) -> bool:
        """Check if loop has a clear termination condition."""
        # Look for comparison operations followed by conditional jumps
        # This indicates a termination condition
        
        for i, op in enumerate(loop_opcodes):
            # Look for: comparison -> JUMPI pattern
            if op["name"] in ["LT", "GT", "EQ", "ISZERO"]:
                # Check if followed by JUMPI
                if i + 1 < len(loop_opcodes) and loop_opcodes[i + 1]["name"] == "JUMPI":
                    # Check if there's a RETURN/STOP after the jump (exit condition)
                    for j in range(i + 2, min(i + 20, len(loop_opcodes))):
                        if loop_opcodes[j]["name"] in ["RETURN", "STOP", "REVERT"]:
                            return True
        
        # Also check for counter-based loops (PUSH -> ADD/SUB -> comparison)
        for i in range(len(loop_opcodes) - 5):
            if (loop_opcodes[i]["name"].startswith("PUSH") and
                loop_opcodes[i+1]["name"] in ["ADD", "SUB"] and
                loop_opcodes[i+2]["name"] in ["LT", "GT", "EQ"] and
                loop_opcodes[i+3]["name"] == "JUMPI"):
                return True
        
        return False

