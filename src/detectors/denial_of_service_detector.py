"""
Detector for denial of service vulnerabilities.
"""

import re
from typing import List, Dict, Any
from .base_detector import VulnerabilityDetector


class DenialOfServiceDetector(VulnerabilityDetector):
    """Detects denial of service vulnerabilities."""
    
    def __init__(self):
        super().__init__(
            name="DenialOfServiceDetector",
            description="Detects denial of service vulnerabilities"
        )
        
        # External call patterns that can cause DoS
        self.external_call_patterns = [
            r'\.call\s*\{[^}]*\}\s*\(',  # .call{value: amount}()
            r'\.call\s*\(',              # .call()
            r'\.delegatecall\s*\{[^}]*\}\s*\(',  # .delegatecall{gas: 1000}()
            r'\.delegatecall\s*\(',      # .delegatecall()
            r'\.send\s*\(',              # .send()
            r'\.transfer\s*\(',          # .transfer()
            r'\.callcode\s*\('           # .callcode()
        ]
        
        # Loop patterns that can cause DoS
        self.loop_patterns = [
            r'for\s*\(\s*[^;]+;\s*[^;]+;\s*[^)]+\)',
            r'while\s*\(\s*[^)]+\)',
            r'do\s*\{[^}]*\}\s*while\s*\('
        ]
        
        # Array operations that can cause DoS
        self.array_patterns = [
            r'\.push\s*\(',
            r'\.pop\s*\(\)',
            r'\.length\s*[><=!]',
            r'\.length\s*[+\-*/]',
            r'delete\s+\w+\[',
            r'\w+\[.*?\]\s*='
        ]
        
        # Gas-consuming operations
        self.gas_consuming_patterns = [
            r'keccak256\s*\(',
            r'sha256\s*\(',
            r'ripemd160\s*\(',
            r'ecrecover\s*\(',
            r'\.call\s*\{[^}]*gas:\s*\d+[^}]*\}',
            r'\.delegatecall\s*\{[^}]*gas:\s*\d+[^}]*\}'
        ]
        
        # State variable modifications in loops
        self.state_modification_patterns = [
            r'(\w+)\s*=\s*[^=]',  # Assignment
            r'(\w+)\[.*?\]\s*=\s*',  # Array/mapping assignment
            r'(\w+)\s*\+=\s*',  # Addition assignment
            r'(\w+)\s*-=\s*',  # Subtraction assignment
            r'(\w+)\s*\*=\s*',  # Multiplication assignment
            r'(\w+)\s*/=\s*',  # Division assignment
            r'(\w+)\s*\+\+',  # Increment
            r'(\w+)\s*--',  # Decrement
        ]
        
        # Common state variables that are often modified
        self.common_state_vars = [
            'balance', 'totalSupply', 'allowance', 'owner', 'admin',
            'paused', 'locked', 'frozen', 'active', 'enabled',
            'users', 'members', 'participants', 'holders'
        ]
        
        # Function patterns that might cause DoS
        self.dos_function_patterns = [
            r'function\s+\w*transfer\w*',  # Transfer functions
            r'function\s+\w*withdraw\w*',  # Withdraw functions
            r'function\s+\w*distribute\w*',  # Distribute functions
            r'function\s+\w*batch\w*',  # Batch functions
            r'function\s+\w*process\w*',  # Process functions
            r'function\s+\w*claim\w*',  # Claim functions
        ]
    
    def detect(self, ast: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect denial of service vulnerabilities."""
        vulnerabilities = []
        content = ast.get('content', '')
        functions = ast.get('functions', [])
        
        # Check for external calls in loops
        external_loop_vulns = self._check_external_calls_in_loops(content)
        vulnerabilities.extend(external_loop_vulns)
        
        # Check for unbounded loops
        unbounded_loop_vulns = self._check_unbounded_loops(content)
        vulnerabilities.extend(unbounded_loop_vulns)
        
        # Check for array operations in loops
        array_loop_vulns = self._check_array_operations_in_loops(content)
        vulnerabilities.extend(array_loop_vulns)
        
        # Check for state modifications in loops
        state_loop_vulns = self._check_state_modifications_in_loops(content)
        vulnerabilities.extend(state_loop_vulns)
        
        # Check for gas-consuming operations in loops
        gas_loop_vulns = self._check_gas_consuming_operations(content)
        vulnerabilities.extend(gas_loop_vulns)
        
        # Check for batch operations without limits
        batch_vulns = self._check_batch_operations(functions, content)
        vulnerabilities.extend(batch_vulns)
        
        # Check for external calls to unknown contracts
        unknown_contract_vulns = self._check_unknown_contract_calls(functions, content)
        vulnerabilities.extend(unknown_contract_vulns)
        
        # Check for fallback function DoS
        fallback_vulns = self._check_fallback_dos(functions, content)
        vulnerabilities.extend(fallback_vulns)
        
        return vulnerabilities
    
    def _check_external_calls_in_loops(self, content: str) -> List[Dict[str, Any]]:
        """Check for external calls inside loops."""
        vulnerabilities = []
        
        # Find all loops
        for loop_pattern in self.loop_patterns:
            loop_matches = re.finditer(loop_pattern, content, re.IGNORECASE)
            for loop_match in loop_matches:
                loop_start = loop_match.start()
                loop_end = self._find_loop_end(content, loop_start)
                
                if loop_end > loop_start:
                    loop_body = content[loop_start:loop_end]
                    
                    # Check if loop body contains external calls
                    for call_pattern in self.external_call_patterns:
                        call_matches = re.finditer(call_pattern, loop_body)
                        for call_match in call_matches:
                            vuln = self._create_vulnerability(
                                vuln_type="Denial of Service",
                                severity="High",
                                description=f"External call in loop detected: {call_match.group(0)}",
                                line_number=self._get_line_number(content, loop_start + call_match.start()),
                                code_snippet=self._get_code_snippet(content, loop_start + call_match.start()),
                                recommendation="Avoid external calls in loops. Use pull payment pattern or batch operations instead."
                            )
                            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_unbounded_loops(self, content: str) -> List[Dict[str, Any]]:
        """Check for unbounded loops."""
        vulnerabilities = []
        
        # Look for loops without clear bounds
        unbounded_patterns = [
            r'while\s*\(\s*true\s*\)',  # while(true)
            r'while\s*\(\s*1\s*\)',  # while(1)
            r'for\s*\(\s*[^;]*;\s*[^;]*;\s*[^)]*\)\s*\{[^}]*while\s*\(\s*true\s*\)',  # nested while(true)
        ]
        
        for pattern in unbounded_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                vuln = self._create_vulnerability(
                    vuln_type="Denial of Service",
                    severity="High",
                    description=f"Unbounded loop detected: {match.group(0)}",
                    line_number=self._get_line_number(content, match.start()),
                    code_snippet=self._get_code_snippet(content, match.start()),
                    recommendation="Avoid unbounded loops. Always set clear termination conditions."
                )
                vulnerabilities.append(vuln)
        
        # Check for loops that depend on external data without limits
        external_dependent_patterns = [
            r'for\s*\(\s*[^;]*;\s*[^;]*\.length[^;]*;\s*[^)]*\)',  # Loop based on array length
            r'while\s*\(\s*[^)]*\.length[^)]*\)',  # While based on array length
        ]
        
        for pattern in external_dependent_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                vuln = self._create_vulnerability(
                    vuln_type="Denial of Service",
                    severity="Medium",
                    description=f"Loop dependent on external data without limits: {match.group(0)}",
                    line_number=self._get_line_number(content, match.start()),
                    code_snippet=self._get_code_snippet(content, match.start()),
                    recommendation="Add limits to loops that depend on external data to prevent DoS attacks."
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_array_operations_in_loops(self, content: str) -> List[Dict[str, Any]]:
        """Check for array operations inside loops."""
        vulnerabilities = []
        
        # Find all loops
        for loop_pattern in self.loop_patterns:
            loop_matches = re.finditer(loop_pattern, content, re.IGNORECASE)
            for loop_match in loop_matches:
                loop_start = loop_match.start()
                loop_end = self._find_loop_end(content, loop_start)
                
                if loop_end > loop_start:
                    loop_body = content[loop_start:loop_end]
                    
                    # Check if loop body contains array operations
                    for array_pattern in self.array_patterns:
                        array_matches = re.finditer(array_pattern, loop_body)
                        for array_match in array_matches:
                            vuln = self._create_vulnerability(
                                vuln_type="Denial of Service",
                                severity="Medium",
                                description=f"Array operation in loop detected: {array_match.group(0)}",
                                line_number=self._get_line_number(content, loop_start + array_match.start()),
                                code_snippet=self._get_code_snippet(content, loop_start + array_match.start()),
                                recommendation="Be cautious with array operations in loops. Consider gas limits and array size limits."
                            )
                            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_state_modifications_in_loops(self, content: str) -> List[Dict[str, Any]]:
        """Check for state modifications inside loops."""
        vulnerabilities = []
        
        # Find all loops
        for loop_pattern in self.loop_patterns:
            loop_matches = re.finditer(loop_pattern, content, re.IGNORECASE)
            for loop_match in loop_matches:
                loop_start = loop_match.start()
                loop_end = self._find_loop_end(content, loop_start)
                
                if loop_end > loop_start:
                    loop_body = content[loop_start:loop_end]
                    
                    # Check if loop body contains state modifications
                    for state_pattern in self.state_modification_patterns:
                        state_matches = re.finditer(state_pattern, loop_body)
                        for state_match in state_matches:
                            var_name = state_match.group(1)
                            
                            # Check if it's likely a state variable
                            if self._is_likely_state_variable(var_name):
                                vuln = self._create_vulnerability(
                                    vuln_type="Denial of Service",
                                    severity="Medium",
                                    description=f"State variable modification in loop detected: {state_match.group(0)}",
                                    line_number=self._get_line_number(content, loop_start + state_match.start()),
                                    code_snippet=self._get_code_snippet(content, loop_start + state_match.start()),
                                    recommendation="Be cautious with state modifications in loops. Consider gas limits and operation complexity."
                                )
                                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_gas_consuming_operations(self, content: str) -> List[Dict[str, Any]]:
        """Check for gas-consuming operations that could cause DoS."""
        vulnerabilities = []
        
        # Find all loops
        for loop_pattern in self.loop_patterns:
            loop_matches = re.finditer(loop_pattern, content, re.IGNORECASE)
            for loop_match in loop_matches:
                loop_start = loop_match.start()
                loop_end = self._find_loop_end(content, loop_start)
                
                if loop_end > loop_start:
                    loop_body = content[loop_start:loop_end]
                    
                    # Check if loop body contains gas-consuming operations
                    for gas_pattern in self.gas_consuming_patterns:
                        gas_matches = re.finditer(gas_pattern, loop_body)
                        for gas_match in gas_matches:
                            vuln = self._create_vulnerability(
                                vuln_type="Denial of Service",
                                severity="Medium",
                                description=f"Gas-consuming operation in loop detected: {gas_match.group(0)}",
                                line_number=self._get_line_number(content, loop_start + gas_match.start()),
                                code_snippet=self._get_code_snippet(content, loop_start + gas_match.start()),
                                recommendation="Be cautious with gas-consuming operations in loops. Consider gas limits and operation complexity."
                            )
                            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_batch_operations(self, functions: List[Dict[str, Any]], content: str) -> List[Dict[str, Any]]:
        """Check for batch operations without proper limits."""
        vulnerabilities = []
        
        for function in functions:
            func_name = function.get('name', '').lower()
            func_body = function.get('body', '')
            
            # Check if function name suggests batch operations
            is_batch_function = any(
                batch_word in func_name for batch_word in 
                ['batch', 'bulk', 'multiple', 'array', 'list']
            )
            
            if is_batch_function and func_body:
                # Check for loops without limits
                has_loop = any(
                    re.search(pattern, func_body, re.IGNORECASE) 
                    for pattern in self.loop_patterns
                )
                
                if has_loop:
                    # Check if there are limits or bounds
                    has_limits = any(
                        re.search(pattern, func_body, re.IGNORECASE) 
                        for pattern in [
                            r'require\s*\(\s*\w+\s*<\s*\d+',
                            r'require\s*\(\s*\w+\s*<=\s*\d+',
                            r'if\s*\(\s*\w+\s*>\s*\d+',
                            r'if\s*\(\s*\w+\s*>=\s*\d+'
                        ]
                    )
                    
                    if not has_limits:
                        vuln = self._create_vulnerability(
                            vuln_type="Denial of Service",
                            severity="High",
                            description=f"Batch function '{function['name']}' lacks proper limits",
                            line_number=self._get_line_number(content, function.get('start_pos', 0)),
                            code_snippet=self._get_code_snippet(content, function.get('start_pos', 0)),
                            recommendation="Add limits to batch operations to prevent DoS attacks."
                        )
                        vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_unknown_contract_calls(self, functions: List[Dict[str, Any]], content: str) -> List[Dict[str, Any]]:
        """Check for external calls to unknown contracts."""
        vulnerabilities = []
        
        for function in functions:
            func_body = function.get('body', '')
            func_name = function.get('name', '')
            
            # Check for external calls
            for call_pattern in self.external_call_patterns:
                call_matches = re.finditer(call_pattern, func_body)
                for call_match in call_matches:
                    call_text = call_match.group(0)
                    
                    # Check if call is to unknown contract
                    if self._is_unknown_contract_call(call_text):
                        vuln = self._create_vulnerability(
                            vuln_type="Denial of Service",
                            severity="Medium",
                            description=f"External call to unknown contract in function '{func_name}': {call_text}",
                            line_number=self._get_line_number(content, call_match.start()),
                            code_snippet=self._get_code_snippet(content, call_match.start()),
                            recommendation="Validate contract addresses and handle potential failures gracefully."
                        )
                        vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_fallback_dos(self, functions: List[Dict[str, Any]], content: str) -> List[Dict[str, Any]]:
        """Check for fallback function DoS vulnerabilities."""
        vulnerabilities = []
        
        for function in functions:
            func_name = function.get('name', '').lower()
            func_body = function.get('body', '')
            
            # Check if it's a fallback or receive function
            is_fallback = func_name in ['fallback', 'receive'] or 'fallback' in func_name or 'receive' in func_name
            
            if is_fallback and func_body:
                # Check for expensive operations
                expensive_operations = [
                    r'\.call\s*\(',
                    r'\.delegatecall\s*\(',
                    r'keccak256\s*\(',
                    r'sha256\s*\(',
                    r'for\s*\(',
                    r'while\s*\('
                ]
                
                has_expensive_ops = any(
                    re.search(pattern, func_body) 
                    for pattern in expensive_operations
                )
                
                if has_expensive_ops:
                    vuln = self._create_vulnerability(
                        vuln_type="Denial of Service",
                        severity="High",
                        description=f"Fallback/receive function '{function['name']}' contains expensive operations",
                        line_number=self._get_line_number(content, function.get('start_pos', 0)),
                        code_snippet=self._get_code_snippet(content, function.get('start_pos', 0)),
                        recommendation="Keep fallback/receive functions simple to prevent DoS attacks."
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _find_loop_end(self, content: str, loop_start: int) -> int:
        """Find the end of a loop."""
        brace_count = 0
        pos = loop_start
        
        while pos < len(content):
            if content[pos] == '{':
                brace_count += 1
            elif content[pos] == '}':
                brace_count -= 1
                if brace_count == 0:
                    return pos
            pos += 1
        
        return len(content)
    
    def _is_likely_state_variable(self, var_name: str) -> bool:
        """Check if variable name suggests it's a state variable."""
        # Check against common state variable names
        if any(common_var in var_name.lower() for common_var in self.common_state_vars):
            return True
        
        # Check if it starts with capital letter (common Solidity convention)
        if var_name[0].isupper():
            return True
        
        # Check if it's a mapping or array (common state variable types)
        if 'mapping' in var_name or 'array' in var_name:
            return True
        
        return False
    
    def _is_unknown_contract_call(self, call: str) -> bool:
        """Check if external call is to an unknown contract."""
        # Look for calls to msg.sender or arbitrary addresses
        unknown_patterns = [
            r'msg\.sender\.call',
            r'msg\.sender\.transfer',
            r'msg\.sender\.send',
            r'address\([^)]+\)\.call',
            r'address\([^)]+\)\.transfer',
            r'address\([^)]+\)\.send'
        ]
        
        for pattern in unknown_patterns:
            if re.search(pattern, call):
                return True
        
        return False
