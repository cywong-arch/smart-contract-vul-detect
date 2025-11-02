"""
Detector for time manipulation vulnerabilities.
"""

import re
from typing import List, Dict, Any
from .base_detector import VulnerabilityDetector


class TimeManipulationDetector(VulnerabilityDetector):
    """Detects time manipulation vulnerabilities."""
    
    def __init__(self):
        super().__init__(
            name="TimeManipulationDetector",
            description="Detects time manipulation vulnerabilities"
        )
        
        # Time-related patterns that can be manipulated
        self.time_patterns = [
            r'block\.timestamp',
            r'block\.number',
            r'now\b',  # deprecated but still used
            r'tx\.gasprice',
            r'block\.difficulty',
            r'block\.gaslimit',
            r'block\.coinbase'
        ]
        
        # Dangerous time-based operations
        self.dangerous_time_operations = [
            r'block\.timestamp\s*[+\-*/]',  # Arithmetic with timestamp
            r'now\s*[+\-*/]',  # Arithmetic with now
            r'block\.number\s*[+\-*/]',  # Arithmetic with block number
            r'block\.timestamp\s*>\s*',  # Timestamp comparisons
            r'block\.timestamp\s*<\s*',  # Timestamp comparisons
            r'now\s*>\s*',  # Now comparisons
            r'now\s*<\s*',  # Now comparisons
            r'block\.number\s*>\s*',  # Block number comparisons
            r'block\.number\s*<\s*',  # Block number comparisons
        ]
        
        # Time-based function patterns
        self.time_function_patterns = [
            r'function\s+\w*time\w*',  # Functions with 'time' in name
            r'function\s+\w*deadline\w*',  # Functions with 'deadline' in name
            r'function\s+\w*expire\w*',  # Functions with 'expire' in name
            r'function\s+\w*lock\w*',  # Functions with 'lock' in name
            r'function\s+\w*unlock\w*',  # Functions with 'unlock' in name
            r'function\s+\w*vest\w*',  # Functions with 'vest' in name
            r'function\s+\w*claim\w*',  # Functions with 'claim' in name
        ]
        
        # Vulnerable time patterns
        self.vulnerable_patterns = [
            r'require\s*\(\s*block\.timestamp\s*>\s*',  # Timestamp requirements
            r'require\s*\(\s*now\s*>\s*',  # Now requirements
            r'require\s*\(\s*block\.number\s*>\s*',  # Block number requirements
            r'if\s*\(\s*block\.timestamp\s*>\s*',  # Timestamp conditions
            r'if\s*\(\s*now\s*>\s*',  # Now conditions
            r'if\s*\(\s*block\.number\s*>\s*',  # Block number conditions
        ]
        
        # Time-based state variables
        self.time_state_vars = [
            'deadline', 'expiry', 'expiration', 'lockTime', 'unlockTime',
            'vestingStart', 'vestingEnd', 'claimTime', 'releaseTime',
            'startTime', 'endTime', 'duration', 'period'
        ]
    
    def detect(self, ast: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect time manipulation vulnerabilities."""
        vulnerabilities = []
        content = ast.get('content', '')
        functions = ast.get('functions', [])
        variables = ast.get('variables', [])
        
        # Check for dangerous time operations
        dangerous_vulns = self._check_dangerous_time_operations(content)
        vulnerabilities.extend(dangerous_vulns)
        
        # Check for vulnerable time patterns
        vulnerable_vulns = self._check_vulnerable_time_patterns(content)
        vulnerabilities.extend(vulnerable_vulns)
        
        # Check time-based functions
        time_function_vulns = self._check_time_based_functions(functions, content)
        vulnerabilities.extend(time_function_vulns)
        
        # Check for time-based state variables without proper validation
        time_state_vulns = self._check_time_state_variables(variables, content)
        vulnerabilities.extend(time_state_vulns)
        
        # Check for time-based loops
        time_loop_vulns = self._check_time_based_loops(content)
        vulnerabilities.extend(time_loop_vulns)
        
        # Check for time-based external calls
        time_external_vulns = self._check_time_external_calls(functions, content)
        vulnerabilities.extend(time_external_vulns)
        
        return vulnerabilities
    
    def _check_dangerous_time_operations(self, content: str) -> List[Dict[str, Any]]:
        """Check for dangerous time-based operations."""
        vulnerabilities = []
        
        for pattern in self.dangerous_time_operations:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                vuln = self._create_vulnerability(
                    vuln_type="Time Manipulation",
                    severity="High",
                    description=f"Dangerous time-based operation detected: {match.group(0)}",
                    line_number=self._get_line_number(content, match.start()),
                    code_snippet=self._get_code_snippet(content, match.start()),
                    recommendation="Use block.timestamp with caution. Consider using block.number for more reliable time measurements or implement time-based validation with proper bounds checking."
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_vulnerable_time_patterns(self, content: str) -> List[Dict[str, Any]]:
        """Check for vulnerable time-based patterns."""
        vulnerabilities = []
        
        for pattern in self.vulnerable_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                vuln = self._create_vulnerability(
                    vuln_type="Time Manipulation",
                    severity="Medium",
                    description=f"Vulnerable time-based pattern detected: {match.group(0)}",
                    line_number=self._get_line_number(content, match.start()),
                    code_snippet=self._get_code_snippet(content, match.start()),
                    recommendation="Implement proper time validation with bounds checking and consider the 15-second block time variance."
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_time_based_functions(self, functions: List[Dict[str, Any]], content: str) -> List[Dict[str, Any]]:
        """Check time-based functions for vulnerabilities."""
        vulnerabilities = []
        
        for function in functions:
            func_name = function.get('name', '').lower()
            func_body = function.get('body', '')
            
            # Check if function name suggests time-based functionality
            is_time_function = any(
                time_word in func_name for time_word in 
                ['time', 'deadline', 'expire', 'lock', 'unlock', 'vest', 'claim']
            )
            
            if is_time_function and func_body:
                # Check for time manipulation vulnerabilities
                time_vulns = self._analyze_time_function(function, content)
                vulnerabilities.extend(time_vulns)
        
        return vulnerabilities
    
    def _analyze_time_function(self, function: Dict[str, Any], content: str) -> List[Dict[str, Any]]:
        """Analyze a time-based function for vulnerabilities."""
        vulnerabilities = []
        func_body = function.get('body', '')
        func_name = function.get('name', '')
        
        # Check for direct time comparisons without validation
        direct_time_patterns = [
            r'block\.timestamp\s*[><=!]+\s*\w+',
            r'now\s*[><=!]+\s*\w+',
            r'block\.number\s*[><=!]+\s*\w+'
        ]
        
        for pattern in direct_time_patterns:
            matches = re.finditer(pattern, func_body, re.IGNORECASE)
            for match in matches:
                vuln = self._create_vulnerability(
                    vuln_type="Time Manipulation",
                    severity="Medium",
                    description=f"Direct time comparison in function '{func_name}': {match.group(0)}",
                    line_number=self._get_line_number(content, match.start()),
                    code_snippet=self._get_code_snippet(content, match.start()),
                    recommendation="Add proper validation and consider the 15-second block time variance when using block.timestamp"
                )
                vulnerabilities.append(vuln)
        
        # Check for time-based calculations
        time_calc_patterns = [
            r'block\.timestamp\s*[+\-*/]\s*\d+',
            r'now\s*[+\-*/]\s*\d+',
            r'block\.number\s*[+\-*/]\s*\d+'
        ]
        
        for pattern in time_calc_patterns:
            matches = re.finditer(pattern, func_body, re.IGNORECASE)
            for match in matches:
                vuln = self._create_vulnerability(
                    vuln_type="Time Manipulation",
                    severity="High",
                    description=f"Time-based calculation in function '{func_name}': {match.group(0)}",
                    line_number=self._get_line_number(content, match.start()),
                    code_snippet=self._get_code_snippet(content, match.start()),
                    recommendation="Be cautious with time calculations. Consider using block.number for more reliable time measurements."
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_time_state_variables(self, variables: List[Dict[str, Any]], content: str) -> List[Dict[str, Any]]:
        """Check time-based state variables for vulnerabilities."""
        vulnerabilities = []
        
        for variable in variables:
            var_name = variable.get('name', '').lower()
            
            # Check if variable name suggests time-based functionality
            is_time_var = any(time_word in var_name for time_word in self.time_state_vars)
            
            if is_time_var:
                # Check if variable is used in vulnerable patterns
                var_vulns = self._check_variable_time_usage(var_name, content)
                vulnerabilities.extend(var_vulns)
        
        return vulnerabilities
    
    def _check_variable_time_usage(self, var_name: str, content: str) -> List[Dict[str, Any]]:
        """Check how a time-based variable is used."""
        vulnerabilities = []
        
        # Look for direct assignments to time variables
        assignment_patterns = [
            rf'{var_name}\s*=\s*block\.timestamp',
            rf'{var_name}\s*=\s*now',
            rf'{var_name}\s*=\s*block\.number'
        ]
        
        for pattern in assignment_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                vuln = self._create_vulnerability(
                    vuln_type="Time Manipulation",
                    severity="Medium",
                    description=f"Direct assignment to time variable '{var_name}': {match.group(0)}",
                    line_number=self._get_line_number(content, match.start()),
                    code_snippet=self._get_code_snippet(content, match.start()),
                    recommendation="Consider adding validation when setting time-based variables"
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_time_based_loops(self, content: str) -> List[Dict[str, Any]]:
        """Check for time-based loops that could be vulnerable."""
        vulnerabilities = []
        
        # Look for loops that depend on time
        time_loop_patterns = [
            r'while\s*\(\s*block\.timestamp\s*[<>]',
            r'while\s*\(\s*now\s*[<>]',
            r'while\s*\(\s*block\.number\s*[<>]',
            r'for\s*\([^)]*block\.timestamp',
            r'for\s*\([^)]*now\b',
            r'for\s*\([^)]*block\.number'
        ]
        
        for pattern in time_loop_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                vuln = self._create_vulnerability(
                    vuln_type="Time Manipulation",
                    severity="High",
                    description=f"Time-based loop detected: {match.group(0)}",
                    line_number=self._get_line_number(content, match.start()),
                    code_snippet=self._get_code_snippet(content, match.start()),
                    recommendation="Avoid time-based loops as they can be manipulated by miners. Use alternative control structures."
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_time_external_calls(self, functions: List[Dict[str, Any]], content: str) -> List[Dict[str, Any]]:
        """Check for external calls that depend on time."""
        vulnerabilities = []
        
        for function in functions:
            func_body = function.get('body', '')
            func_name = function.get('name', '')
            
            # Check if function has both time checks and external calls
            has_time_check = any(
                re.search(pattern, func_body, re.IGNORECASE) 
                for pattern in self.time_patterns
            )
            
            has_external_call = any(
                re.search(pattern, func_body) 
                for pattern in [r'\.call\s*\(', r'\.transfer\s*\(', r'\.send\s*\(']
            )
            
            if has_time_check and has_external_call:
                vuln = self._create_vulnerability(
                    vuln_type="Time Manipulation",
                    severity="Medium",
                    description=f"Function '{func_name}' combines time checks with external calls",
                    line_number=self._get_line_number(content, function.get('start_pos', 0)),
                    code_snippet=self._get_code_snippet(content, function.get('start_pos', 0)),
                    recommendation="Be cautious when combining time-based logic with external calls. Consider the impact of time manipulation on external interactions."
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
