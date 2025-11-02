"""
Detector for reentrancy vulnerabilities.
"""

import re
from typing import List, Dict, Any
from .base_detector import VulnerabilityDetector


class ReentrancyDetector(VulnerabilityDetector):
    """Detects reentrancy vulnerabilities."""
    
    def __init__(self):
        super().__init__(
            name="ReentrancyDetector",
            description="Detects reentrancy vulnerabilities"
        )
        
        # External call patterns
        self.external_call_patterns = [
            r'\.call\s*\{[^}]*\}\s*\(',  # .call{value: amount}()
            r'\.call\s*\(',              # .call()
            r'\.delegatecall\s*\{[^}]*\}\s*\(',  # .delegatecall{gas: 1000}()
            r'\.delegatecall\s*\(',      # .delegatecall()
            r'\.send\s*\(',              # .send()
            r'\.transfer\s*\(',          # .transfer()
            r'\.callcode\s*\('           # .callcode()
        ]
        
        # State variable patterns that might be modified
        self.state_variable_patterns = [
            r'(\w+)\s*=\s*',          # Assignment
            r'(\w+)\[.*?\]\s*=\s*',   # Array/mapping assignment
            r'(\w+)\s*\+=\s*',        # Addition assignment
            r'(\w+)\s*-=\s*',         # Subtraction assignment
            r'(\w+)\s*\*=\s*',        # Multiplication assignment
            r'(\w+)\s*/=\s*',         # Division assignment
            r'(\w+)\s*\+\+',          # Increment
            r'(\w+)\s*--',            # Decrement
        ]
        
        # Reentrancy guard patterns
        self.reentrancy_guard_patterns = [
            r'nonReentrant',
            r'reentrancyGuard',
            r'mutex',
            r'lock',
            r'ReentrancyGuard'
        ]
        
        # Common state variables that are often modified
        self.common_state_vars = [
            'balance', 'totalSupply', 'allowance', 'owner', 'admin',
            'paused', 'locked', 'frozen', 'active', 'enabled'
        ]
    
    def detect(self, ast: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect reentrancy vulnerabilities."""
        vulnerabilities = []
        content = ast.get('content', '')
        functions = ast.get('functions', [])
        
        # Check each function for reentrancy patterns
        for function in functions:
            func_vulns = self._analyze_function(function, content)
            vulnerabilities.extend(func_vulns)
        
        # Check for cross-function reentrancy
        cross_function_vulns = self._check_cross_function_reentrancy(functions, content)
        vulnerabilities.extend(cross_function_vulns)
        
        # Check for constructor reentrancy
        constructor_vulns = self._check_constructor_reentrancy(functions, content)
        vulnerabilities.extend(constructor_vulns)
        
        # Check for external calls to unknown contracts
        unknown_contract_vulns = self._check_unknown_contract_calls(functions, content)
        vulnerabilities.extend(unknown_contract_vulns)
        
        return vulnerabilities
    
    def _analyze_function(self, function: Dict[str, Any], content: str) -> List[Dict[str, Any]]:
        """Analyze a function for reentrancy vulnerabilities."""
        vulnerabilities = []
        func_body = function.get('body', '')
        func_name = function.get('name', '')
        
        if not func_body:
            return vulnerabilities
        
        # Check if function has reentrancy guard
        has_reentrancy_guard = self._has_reentrancy_guard(func_body)
        
        # Find external calls in the function
        external_calls = self._find_external_calls(func_body)
        
        # Find state modifications in the function
        state_modifications = self._find_state_modifications(func_body)
        
        # Check for reentrancy patterns
        for call in external_calls:
            # Check if there are state modifications after the external call
            modifications_after_call = [
                mod for mod in state_modifications 
                if mod['position'] > call['position']
            ]
            
            if modifications_after_call and not has_reentrancy_guard:
                vuln = self._create_vulnerability(
                    vuln_type="Reentrancy",
                    severity="High",
                    description=f"Potential reentrancy vulnerability in function '{func_name}': external call before state update",
                    line_number=self._get_line_number(content, call['position']),
                    code_snippet=self._get_code_snippet(content, call['position']),
                    recommendation="Follow checks-effects-interactions pattern: update state before external calls, or use reentrancy guard"
                )
                vulnerabilities.append(vuln)
        
        # Check for specific reentrancy patterns
        specific_patterns = self._check_specific_patterns(func_body, func_name, content)
        vulnerabilities.extend(specific_patterns)
        
        return vulnerabilities
    
    def _has_reentrancy_guard(self, func_body: str) -> bool:
        """Check if function has reentrancy guard."""
        for pattern in self.reentrancy_guard_patterns:
            if re.search(pattern, func_body):
                return True
        return False
    
    def _find_external_calls(self, func_body: str) -> List[Dict[str, Any]]:
        """Find external calls in function body."""
        external_calls = []
        
        for pattern in self.external_call_patterns:
            matches = re.finditer(pattern, func_body)
            for match in matches:
                external_calls.append({
                    'type': pattern.split('.')[1].split('(')[0],
                    'call': match.group(0),
                    'position': match.start(),
                    'end_position': match.end()
                })
        
        return external_calls
    
    def _find_state_modifications(self, func_body: str) -> List[Dict[str, Any]]:
        """Find state variable modifications in function body."""
        state_modifications = []
        
        for pattern in self.state_variable_patterns:
            matches = re.finditer(pattern, func_body)
            for match in matches:
                var_name = match.group(1)
                # Check if it's likely a state variable
                if self._is_likely_state_variable(var_name):
                    state_modifications.append({
                        'variable': var_name,
                        'operation': match.group(0),
                        'position': match.start(),
                        'end_position': match.end()
                    })
        
        return state_modifications
    
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
        
        # For reentrancy detection, be more permissive
        # Assume variables like 'balances', 'totalSupply', etc. are state variables
        state_var_indicators = ['balance', 'total', 'supply', 'allowance', 'owner', 'admin', 'paused', 'locked']
        if any(indicator in var_name.lower() for indicator in state_var_indicators):
            return True
        
        return False
    
    def _check_specific_patterns(self, func_body: str, func_name: str, 
                                content: str) -> List[Dict[str, Any]]:
        """Check for specific reentrancy patterns."""
        vulnerabilities = []
        
        # Pattern 1: Withdrawal function without proper checks
        if 'withdraw' in func_name.lower():
            if self._has_withdrawal_pattern(func_body):
                vuln = self._create_vulnerability(
                    vuln_type="Reentrancy",
                    severity="High",
                    description=f"Withdrawal function '{func_name}' may be vulnerable to reentrancy",
                    line_number=self._get_line_number(content, 0),
                    code_snippet=self._get_code_snippet(content, 0),
                    recommendation="Update balance before external transfer, or use reentrancy guard"
                )
                vulnerabilities.append(vuln)
        
        # Pattern 2: External call in loop
        if self._has_external_call_in_loop(func_body):
            vuln = self._create_vulnerability(
                vuln_type="Reentrancy",
                severity="Medium",
                description=f"Function '{func_name}' has external calls in loop - potential DoS",
                line_number=self._get_line_number(content, 0),
                code_snippet=self._get_code_snippet(content, 0),
                recommendation="Consider batching operations or using pull payment pattern"
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _has_withdrawal_pattern(self, func_body: str) -> bool:
        """Check if function has withdrawal pattern without proper protection."""
        # Look for external transfer without balance update first
        has_external_transfer = any(
            re.search(pattern, func_body) 
            for pattern in [r'\.transfer\s*\(', r'\.send\s*\(', r'\.call\s*\(']
        )
        
        # Look for balance update
        has_balance_update = re.search(r'balance.*=', func_body)
        
        # If has external transfer but no balance update, it's suspicious
        return has_external_transfer and not has_balance_update
    
    def _has_external_call_in_loop(self, func_body: str) -> bool:
        """Check if function has external calls inside loops."""
        # Find loops
        loop_patterns = [r'for\s*\(', r'while\s*\(', r'do\s*\{']
        
        for loop_pattern in loop_patterns:
            loop_matches = re.finditer(loop_pattern, func_body)
            for loop_match in loop_matches:
                # Find the end of the loop (simplified)
                loop_start = loop_match.start()
                loop_end = self._find_loop_end(func_body, loop_start)
                
                if loop_end > loop_start:
                    loop_body = func_body[loop_start:loop_end]
                    
                    # Check if loop body contains external calls
                    for call_pattern in self.external_call_patterns:
                        if re.search(call_pattern, loop_body):
                            return True
        
        return False
    
    def _find_loop_end(self, func_body: str, loop_start: int) -> int:
        """Find the end of a loop (simplified implementation)."""
        # This is a simplified implementation
        # In a real parser, you'd want to properly match braces
        brace_count = 0
        pos = loop_start
        
        while pos < len(func_body):
            if func_body[pos] == '{':
                brace_count += 1
            elif func_body[pos] == '}':
                brace_count -= 1
                if brace_count == 0:
                    return pos
            pos += 1
        
        return len(func_body)
    
    def _check_cross_function_reentrancy(self, functions: List[Dict[str, Any]], content: str) -> List[Dict[str, Any]]:
        """Check for cross-function reentrancy vulnerabilities."""
        vulnerabilities = []
        
        # Find functions that make external calls
        external_call_functions = []
        for function in functions:
            func_body = function.get('body', '')
            if self._find_external_calls(func_body):
                external_call_functions.append(function)
        
        # Find functions that modify state variables
        state_modification_functions = []
        for function in functions:
            func_body = function.get('body', '')
            if self._find_state_modifications(func_body):
                state_modification_functions.append(function)
        
        # Check for cross-function reentrancy patterns
        for ext_func in external_call_functions:
            for state_func in state_modification_functions:
                if ext_func['name'] != state_func['name']:
                    # Check if they share common state variables
                    shared_vars = self._get_shared_state_variables(ext_func, state_func)
                    if shared_vars:
                        vuln = self._create_vulnerability(
                            vuln_type="Reentrancy",
                            severity="Medium",
                            description=f"Cross-function reentrancy between '{ext_func['name']}' and '{state_func['name']}'",
                            line_number=self._get_line_number(content, ext_func.get('start_pos', 0)),
                            code_snippet=self._get_code_snippet(content, ext_func.get('start_pos', 0)),
                            recommendation="Ensure proper state management between functions or use reentrancy guards"
                        )
                        vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_constructor_reentrancy(self, functions: List[Dict[str, Any]], content: str) -> List[Dict[str, Any]]:
        """Check for reentrancy vulnerabilities in constructor."""
        vulnerabilities = []
        
        for function in functions:
            func_name = function.get('name', '').lower()
            if func_name == 'constructor' or 'constructor' in func_name:
                func_body = function.get('body', '')
                external_calls = self._find_external_calls(func_body)
                
                if external_calls:
                    vuln = self._create_vulnerability(
                        vuln_type="Reentrancy",
                        severity="Medium",
                        description=f"Constructor '{function['name']}' contains external calls",
                        line_number=self._get_line_number(content, function.get('start_pos', 0)),
                        code_snippet=self._get_code_snippet(content, function.get('start_pos', 0)),
                        recommendation="Avoid external calls in constructor or ensure they're safe"
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_unknown_contract_calls(self, functions: List[Dict[str, Any]], content: str) -> List[Dict[str, Any]]:
        """Check for external calls to unknown contracts."""
        vulnerabilities = []
        
        for function in functions:
            func_body = function.get('body', '')
            external_calls = self._find_external_calls(func_body)
            
            for call in external_calls:
                # Check if the call is to an unknown contract
                if self._is_unknown_contract_call(call['call'], content):
                    vuln = self._create_vulnerability(
                        vuln_type="Reentrancy",
                        severity="High",
                        description=f"External call to unknown contract: {call['call']}",
                        line_number=self._get_line_number(content, call['position']),
                        code_snippet=self._get_code_snippet(content, call['position']),
                        recommendation="Validate contract address or use known contract interfaces"
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _get_shared_state_variables(self, func1: Dict[str, Any], func2: Dict[str, Any]) -> List[str]:
        """Get state variables shared between two functions."""
        func1_vars = set()
        func2_vars = set()
        
        # Extract state variables from function bodies
        func1_body = func1.get('body', '')
        func2_body = func2.get('body', '')
        
        for pattern in self.state_variable_patterns:
            matches1 = re.finditer(pattern, func1_body)
            for match in matches1:
                var_name = match.group(1)
                if self._is_likely_state_variable(var_name):
                    func1_vars.add(var_name)
            
            matches2 = re.finditer(pattern, func2_body)
            for match in matches2:
                var_name = match.group(1)
                if self._is_likely_state_variable(var_name):
                    func2_vars.add(var_name)
        
        return list(func1_vars.intersection(func2_vars))
    
    def _is_unknown_contract_call(self, call: str, content: str) -> bool:
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




