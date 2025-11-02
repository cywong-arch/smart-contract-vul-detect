"""
Detector for unprotected selfdestruct vulnerabilities.
"""

import re
from typing import List, Dict, Any
from .base_detector import VulnerabilityDetector


class UnprotectedSelfDestructDetector(VulnerabilityDetector):
    """Detects unprotected selfdestruct vulnerabilities."""
    
    def __init__(self):
        super().__init__(
            name="UnprotectedSelfDestructDetector",
            description="Detects unprotected selfdestruct vulnerabilities"
        )
        
        # Selfdestruct patterns
        self.selfdestruct_patterns = [
            r'selfdestruct\s*\(',
            r'suicide\s*\(',  # deprecated but still used
            r'\.selfdestruct\s*\(',
            r'\.suicide\s*\('
        ]
        
        # Access control modifiers
        self.access_modifiers = [
            'onlyOwner', 'onlyAdmin', 'onlyAuthorized', 'onlyRole',
            'requireOwner', 'requireAdmin', 'requireAuth', 'onlyGovernance',
            'onlyController', 'onlyOperator', 'onlyMinter', 'onlyBurner',
            'onlyPauser', 'onlyUnpauser', 'onlyUpgrader', 'onlyFeeSetter'
        ]
        
        # Ownership check patterns
        self.ownership_patterns = [
            r'require\s*\(\s*msg\.sender\s*==\s*owner',
            r'require\s*\(\s*owner\s*==\s*msg\.sender',
            r'require\s*\(\s*msg\.sender\s*==\s*admin',
            r'require\s*\(\s*admin\s*==\s*msg\.sender',
            r'require\s*\(\s*hasRole\s*\(',
            r'require\s*\(\s*isOwner\s*\(',
            r'require\s*\(\s*isAdmin\s*\(',
            r'require\s*\(\s*msg\.sender\s*==\s*this\.owner',
            r'require\s*\(\s*this\.owner\s*==\s*msg\.sender'
        ]
        
        # Function patterns that might contain selfdestruct
        self.dangerous_function_patterns = [
            r'function\s+\w*kill\w*',  # Functions with 'kill' in name
            r'function\s+\w*destroy\w*',  # Functions with 'destroy' in name
            r'function\s+\w*emergency\w*',  # Functions with 'emergency' in name
            r'function\s+\w*shutdown\w*',  # Functions with 'shutdown' in name
            r'function\s+\w*terminate\w*',  # Functions with 'terminate' in name
            r'function\s+\w*close\w*',  # Functions with 'close' in name
            r'function\s+\w*remove\w*',  # Functions with 'remove' in name
            r'function\s+\w*delete\w*',  # Functions with 'delete' in name
        ]
        
        # State variables that might indicate ownership
        self.ownership_vars = [
            'owner', 'admin', 'authority', 'controller', 'governance',
            'operator', 'minter', 'burner', 'pauser', 'upgrader',
            'feeSetter', 'roleAdmin', 'superAdmin', 'master'
        ]
        
        # Conditional patterns around selfdestruct
        self.conditional_patterns = [
            r'if\s*\(\s*[^)]+\)\s*\{[^}]*selfdestruct',
            r'if\s*\(\s*[^)]+\)\s*\{[^}]*suicide',
            r'require\s*\(\s*[^)]+\)\s*;[^;]*selfdestruct',
            r'require\s*\(\s*[^)]+\)\s*;[^;]*suicide',
            r'assert\s*\(\s*[^)]+\)\s*;[^;]*selfdestruct',
            r'assert\s*\(\s*[^)]+\)\s*;[^;]*suicide'
        ]
        
        # Multi-signature patterns
        self.multisig_patterns = [
            r'require\s*\(\s*\w+\s*>=\s*\d+\)',  # Require multiple signatures
            r'require\s*\(\s*approvals\s*>=\s*\d+\)',  # Require approvals
            r'require\s*\(\s*confirmations\s*>=\s*\d+\)',  # Require confirmations
        ]
    
    def detect(self, ast: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect unprotected selfdestruct vulnerabilities."""
        vulnerabilities = []
        content = ast.get('content', '')
        functions = ast.get('functions', [])
        variables = ast.get('variables', [])
        
        # Check for unprotected selfdestruct calls
        unprotected_vulns = self._check_unprotected_selfdestruct(content)
        vulnerabilities.extend(unprotected_vulns)
        
        # Check functions that might contain selfdestruct
        function_vulns = self._check_dangerous_functions(functions, content)
        vulnerabilities.extend(function_vulns)
        
        # Check for selfdestruct in loops
        loop_vulns = self._check_selfdestruct_in_loops(content)
        vulnerabilities.extend(loop_vulns)
        
        # Check for selfdestruct with external calls
        external_vulns = self._check_selfdestruct_with_external_calls(functions, content)
        vulnerabilities.extend(external_vulns)
        
        # Check for selfdestruct without proper conditions
        condition_vulns = self._check_selfdestruct_conditions(content)
        vulnerabilities.extend(condition_vulns)
        
        # Check for missing multi-signature requirements
        multisig_vulns = self._check_multisig_requirements(content)
        vulnerabilities.extend(multisig_vulns)
        
        # Check for selfdestruct in constructor
        constructor_vulns = self._check_constructor_selfdestruct(functions, content)
        vulnerabilities.extend(constructor_vulns)
        
        return vulnerabilities
    
    def _check_unprotected_selfdestruct(self, content: str) -> List[Dict[str, Any]]:
        """Check for unprotected selfdestruct calls."""
        vulnerabilities = []
        
        for pattern in self.selfdestruct_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                # Check if the selfdestruct call is protected
                is_protected = self._is_selfdestruct_protected(content, match.start())
                
                if not is_protected:
                    vuln = self._create_vulnerability(
                        vuln_type="Unprotected Selfdestruct",
                        severity="Critical",
                        description=f"Unprotected selfdestruct call detected: {match.group(0)}",
                        line_number=self._get_line_number(content, match.start()),
                        code_snippet=self._get_code_snippet(content, match.start()),
                        recommendation="Add proper access control (onlyOwner modifier) or multi-signature requirements before selfdestruct calls."
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_dangerous_functions(self, functions: List[Dict[str, Any]], content: str) -> List[Dict[str, Any]]:
        """Check functions that might contain selfdestruct."""
        vulnerabilities = []
        
        for function in functions:
            func_name = function.get('name', '').lower()
            func_body = function.get('body', '')
            
            # Check if function name suggests it might contain selfdestruct
            is_dangerous_function = any(
                dangerous_word in func_name for dangerous_word in 
                ['kill', 'destroy', 'emergency', 'shutdown', 'terminate', 'close', 'remove', 'delete']
            )
            
            if is_dangerous_function and func_body:
                # Check if function contains selfdestruct
                has_selfdestruct = any(
                    re.search(pattern, func_body, re.IGNORECASE) 
                    for pattern in self.selfdestruct_patterns
                )
                
                if has_selfdestruct:
                    # Check if function has proper access control
                    has_access_control = self._has_access_control(function, content)
                    
                    if not has_access_control:
                        vuln = self._create_vulnerability(
                            vuln_type="Unprotected Selfdestruct",
                            severity="Critical",
                            description=f"Dangerous function '{function['name']}' contains selfdestruct without access control",
                            line_number=self._get_line_number(content, function.get('start_pos', 0)),
                            code_snippet=self._get_code_snippet(content, function.get('start_pos', 0)),
                            recommendation=f"Add access control modifier (onlyOwner) to function '{function['name']}'"
                        )
                        vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_selfdestruct_in_loops(self, content: str) -> List[Dict[str, Any]]:
        """Check for selfdestruct calls inside loops."""
        vulnerabilities = []
        
        # Find all loops
        loop_patterns = [
            r'for\s*\(\s*[^;]+;\s*[^;]+;\s*[^)]+\)',
            r'while\s*\(\s*[^)]+\)',
            r'do\s*\{[^}]*\}\s*while\s*\('
        ]
        
        for loop_pattern in loop_patterns:
            loop_matches = re.finditer(loop_pattern, content, re.IGNORECASE)
            for loop_match in loop_matches:
                loop_start = loop_match.start()
                loop_end = self._find_loop_end(content, loop_start)
                
                if loop_end > loop_start:
                    loop_body = content[loop_start:loop_end]
                    
                    # Check if loop body contains selfdestruct
                    for selfdestruct_pattern in self.selfdestruct_patterns:
                        selfdestruct_matches = re.finditer(selfdestruct_pattern, loop_body, re.IGNORECASE)
                        for selfdestruct_match in selfdestruct_matches:
                            vuln = self._create_vulnerability(
                                vuln_type="Unprotected Selfdestruct",
                                severity="High",
                                description=f"Selfdestruct call in loop detected: {selfdestruct_match.group(0)}",
                                line_number=self._get_line_number(content, loop_start + selfdestruct_match.start()),
                                code_snippet=self._get_code_snippet(content, loop_start + selfdestruct_match.start()),
                                recommendation="Avoid selfdestruct calls in loops. Consider alternative approaches."
                            )
                            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_selfdestruct_with_external_calls(self, functions: List[Dict[str, Any]], content: str) -> List[Dict[str, Any]]:
        """Check for selfdestruct calls combined with external calls."""
        vulnerabilities = []
        
        for function in functions:
            func_body = function.get('body', '')
            func_name = function.get('name', '')
            
            # Check if function has both selfdestruct and external calls
            has_selfdestruct = any(
                re.search(pattern, func_body, re.IGNORECASE) 
                for pattern in self.selfdestruct_patterns
            )
            
            has_external_call = any(
                re.search(pattern, func_body) 
                for pattern in [r'\.call\s*\(', r'\.transfer\s*\(', r'\.send\s*\(']
            )
            
            if has_selfdestruct and has_external_call:
                vuln = self._create_vulnerability(
                    vuln_type="Unprotected Selfdestruct",
                    severity="High",
                    description=f"Function '{func_name}' combines selfdestruct with external calls",
                    line_number=self._get_line_number(content, function.get('start_pos', 0)),
                    code_snippet=self._get_code_snippet(content, function.get('start_pos', 0)),
                    recommendation="Be cautious when combining selfdestruct with external calls. Ensure proper access control."
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_selfdestruct_conditions(self, content: str) -> List[Dict[str, Any]]:
        """Check for selfdestruct calls without proper conditions."""
        vulnerabilities = []
        
        for pattern in self.selfdestruct_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                # Check if selfdestruct is preceded by proper conditions
                has_proper_conditions = self._has_proper_conditions(content, match.start())
                
                if not has_proper_conditions:
                    vuln = self._create_vulnerability(
                        vuln_type="Unprotected Selfdestruct",
                        severity="High",
                        description=f"Selfdestruct call without proper conditions: {match.group(0)}",
                        line_number=self._get_line_number(content, match.start()),
                        code_snippet=self._get_code_snippet(content, match.start()),
                        recommendation="Add proper conditions and access control before selfdestruct calls."
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_multisig_requirements(self, content: str) -> List[Dict[str, Any]]:
        """Check for missing multi-signature requirements."""
        vulnerabilities = []
        
        # Check if contract has selfdestruct but no multisig patterns
        has_selfdestruct = any(
            re.search(pattern, content, re.IGNORECASE) 
            for pattern in self.selfdestruct_patterns
        )
        
        has_multisig = any(
            re.search(pattern, content, re.IGNORECASE) 
            for pattern in self.multisig_patterns
        )
        
        if has_selfdestruct and not has_multisig:
            vuln = self._create_vulnerability(
                vuln_type="Unprotected Selfdestruct",
                severity="Medium",
                description="Contract contains selfdestruct but lacks multi-signature requirements",
                line_number=1,
                code_snippet="Contract definition",
                recommendation="Consider implementing multi-signature requirements for selfdestruct operations."
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_constructor_selfdestruct(self, functions: List[Dict[str, Any]], content: str) -> List[Dict[str, Any]]:
        """Check for selfdestruct calls in constructor."""
        vulnerabilities = []
        
        for function in functions:
            func_name = function.get('name', '').lower()
            if func_name == 'constructor' or 'constructor' in func_name:
                func_body = function.get('body', '')
                has_selfdestruct = any(
                    re.search(pattern, func_body, re.IGNORECASE) 
                    for pattern in self.selfdestruct_patterns
                )
                
                if has_selfdestruct:
                    vuln = self._create_vulnerability(
                        vuln_type="Unprotected Selfdestruct",
                        severity="High",
                        description=f"Constructor '{function['name']}' contains selfdestruct call",
                        line_number=self._get_line_number(content, function.get('start_pos', 0)),
                        code_snippet=self._get_code_snippet(content, function.get('start_pos', 0)),
                        recommendation="Avoid selfdestruct calls in constructor."
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _is_selfdestruct_protected(self, content: str, position: int) -> bool:
        """Check if selfdestruct call is protected."""
        # Look backwards from the selfdestruct call to find the function
        before_position = content[:position]
        
        # Find the function that contains this selfdestruct call
        func_matches = list(re.finditer(r'function\s+\w+', before_position))
        if not func_matches:
            return False
        
        # Get the last function match
        last_func = func_matches[-1]
        func_start = last_func.start()
        
        # Find the opening brace of this function
        brace_pos = content.find('{', func_start)
        if brace_pos == -1 or brace_pos > position:
            return False
        
        # Extract function signature
        func_signature = content[func_start:brace_pos]
        
        # Check if function has access control modifiers
        for modifier in self.access_modifiers:
            if modifier in func_signature:
                return True
        
        # Check if function has ownership checks in its body
        func_body_start = brace_pos
        func_body_end = self._find_function_end(content, func_body_start)
        
        if func_body_end > func_body_start:
            func_body = content[func_body_start:func_body_end]
            
            # Check for ownership patterns before the selfdestruct call
            selfdestruct_pos_in_func = position - func_body_start
            before_selfdestruct = func_body[:selfdestruct_pos_in_func]
            
            for pattern in self.ownership_patterns:
                if re.search(pattern, before_selfdestruct, re.IGNORECASE):
                    return True
        
        return False
    
    def _has_access_control(self, function: Dict[str, Any], content: str) -> bool:
        """Check if function has access control."""
        func_signature = function.get('signature', '')
        func_body = function.get('body', '')
        
        # Check function signature for access control modifiers
        for modifier in self.access_modifiers:
            if modifier in func_signature:
                return True
        
        # Check function body for ownership checks
        for pattern in self.ownership_patterns:
            if re.search(pattern, func_body, re.IGNORECASE):
                return True
        
        return False
    
    def _has_proper_conditions(self, content: str, position: int) -> bool:
        """Check if selfdestruct call has proper conditions."""
        # Look backwards from the selfdestruct call
        before_position = content[:position]
        
        # Check for conditional patterns
        for pattern in self.conditional_patterns:
            if re.search(pattern, before_position, re.IGNORECASE):
                return True
        
        # Check for ownership patterns
        for pattern in self.ownership_patterns:
            if re.search(pattern, before_position, re.IGNORECASE):
                return True
        
        return False
    
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
    
    def _find_function_end(self, content: str, func_start: int) -> int:
        """Find the end of a function."""
        brace_count = 0
        pos = func_start
        
        while pos < len(content):
            if content[pos] == '{':
                brace_count += 1
            elif content[pos] == '}':
                brace_count -= 1
                if brace_count == 0:
                    return pos
            pos += 1
        
        return len(content)
