
from typing import List, Dict, Any
from .base_detector import VulnerabilityDetector


class BytecodeTimeManipulationDetector(VulnerabilityDetector):
    """Detects time manipulation vulnerabilities in bytecode."""
    
    def __init__(self):
        super().__init__(
            name="BytecodeTimeManipulationDetector",
            description="Detects time manipulation vulnerabilities in bytecode"
        )
        
        # Time-related opcodes that can be manipulated
        self.time_opcodes = {
            "TIMESTAMP",  # block.timestamp (0x42)
            "NUMBER",     # block.number (0x43)
            "DIFFICULTY", # block.difficulty (0x44)
            "GASLIMIT",   # block.gaslimit (0x45)
            "COINBASE"    # block.coinbase (0x41)
        }
        
        # Arithmetic opcodes that can be used with time
        self.arithmetic_opcodes = {"ADD", "SUB", "MUL", "DIV", "MOD"}
        
        # Comparison opcodes
        self.comparison_opcodes = {"LT", "GT", "SLT", "SGT", "EQ"}
        
    def detect(self, bytecode_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect time manipulation vulnerabilities in bytecode."""
        vulnerabilities = []
        opcodes = bytecode_analysis.get("opcodes", [])
        
        if not opcodes:
            return vulnerabilities
        
        # Check for time-based operations
        time_vulns = self._check_time_operations(opcodes)
        vulnerabilities.extend(time_vulns)
        
        # Check for time-based comparisons
        comparison_vulns = self._check_time_comparisons(opcodes)
        vulnerabilities.extend(comparison_vulns)
        
        # Check for time-based arithmetic
        arithmetic_vulns = self._check_time_arithmetic(opcodes)
        vulnerabilities.extend(arithmetic_vulns)
        
        return vulnerabilities
    
    def _check_time_operations(self, opcodes: List[Dict]) -> List[Dict[str, Any]]:
        """Check for time opcode usage."""
        vulnerabilities = []
        
        for op in opcodes:
            if op["name"] in self.time_opcodes:
                # TIMESTAMP is most commonly manipulated
                if op["name"] == "TIMESTAMP":
                    vulnerabilities.append(self._create_vulnerability(
                        vuln_type="Time Manipulation",
                        severity="High",
                        description=f"block.timestamp usage detected: {op['name']} at position {op['position']}",
                        line_number=op["position"],
                        code_snippet=f"Position {op['position']}: {op['name']}",
                        recommendation="Use block.timestamp with caution. Miners can manipulate it by ±15 seconds. Consider using block.number for more reliable time measurements."
                    ))
                elif op["name"] == "NUMBER":
                    vulnerabilities.append(self._create_vulnerability(
                        vuln_type="Time Manipulation",
                        severity="Medium",
                        description=f"block.number usage detected: {op['name']} at position {op['position']}",
                        line_number=op["position"],
                        code_snippet=f"Position {op['position']}: {op['name']}",
                        recommendation="block.number is more reliable than block.timestamp but still has variance. Consider proper validation."
                    ))
        
        return vulnerabilities
    
    def _check_time_comparisons(self, opcodes: List[Dict]) -> List[Dict[str, Any]]:
        """Check for time-based comparisons without validation."""
        vulnerabilities = []
        
        for i, op in enumerate(opcodes):
            if op["name"] in self.time_opcodes:
                # Look for comparison operations after time opcode
                # Check next 10 opcodes for comparison
                window = opcodes[i+1:min(i+11, len(opcodes))]
                
                for j, next_op in enumerate(window):
                    if next_op["name"] in self.comparison_opcodes:
                        # Found time comparison - check if there's validation
                        has_validation = self._has_validation_pattern(opcodes, i)
                        
                        if not has_validation:
                            vulnerabilities.append(self._create_vulnerability(
                                vuln_type="Time Manipulation",
                                severity="High",
                                description=f"Time-based comparison without validation: {op['name']} {next_op['name']}",
                                line_number=op["position"],
                                code_snippet=f"Position {op['position']}: {op['name']} -> {next_op['name']}",
                                recommendation="Add proper validation for time-based conditions. Consider the 15-second block time variance when using block.timestamp."
                            ))
                        break
        
        return vulnerabilities
    
    def _check_time_arithmetic(self, opcodes: List[Dict]) -> List[Dict[str, Any]]:
        """Check for arithmetic operations with time values."""
        vulnerabilities = []
        
        for i, op in enumerate(opcodes):
            if op["name"] in self.time_opcodes:
                # Look for arithmetic operations after time opcode
                # Check next 10 opcodes for arithmetic
                window = opcodes[i+1:min(i+11, len(opcodes))]
                
                for j, next_op in enumerate(window):
                    if next_op["name"] in self.arithmetic_opcodes:
                        # Found time arithmetic
                        vulnerabilities.append(self._create_vulnerability(
                            vuln_type="Time Manipulation",
                            severity="High",
                            description=f"Time-based calculation detected: {op['name']} {next_op['name']}",
                            line_number=op["position"],
                            code_snippet=f"Position {op['position']}: {op['name']} -> {next_op['name']}",
                            recommendation="Be cautious with time calculations. Miners can manipulate block.timestamp by ±15 seconds. Consider using block.number for more reliable time measurements."
                        ))
                        break
        
        return vulnerabilities
    
    def _has_validation_pattern(self, opcodes: List[Dict], time_op_idx: int) -> bool:
        """Check if there's validation before time operation."""
        # Look backwards for validation patterns
        # Check for bounds checking or require statements
        start_idx = max(0, time_op_idx - 20)
        
        for i in range(start_idx, time_op_idx):
            op = opcodes[i]
            # Look for validation patterns like:
            # - GT/LT comparisons (bounds checking)
            # - ISZERO -> JUMPI (require pattern)
            if op["name"] in ["GT", "LT", "ISZERO"]:
                # Check if followed by JUMPI (conditional check)
                if i + 1 < len(opcodes) and opcodes[i + 1]["name"] == "JUMPI":
                    return True
        
        return False

