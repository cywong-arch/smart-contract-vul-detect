"""
Detector for access control vulnerabilities.
"""

import re
from typing import List, Dict, Any
from .base_detector import VulnerabilityDetector


class AccessControlDetector(VulnerabilityDetector):
    """Detects access control vulnerabilities."""
    
    def __init__(self):
        super().__init__(
            name="AccessControlDetector",
            description="Detects access control vulnerabilities"
        )
        
        # Enhanced critical functions that should have access control
        self.critical_functions = [
            'withdraw', 'transfer', 'mint', 'burn', 'pause', 'unpause',
            'setOwner', 'setAdmin', 'setFee', 'setRate', 'emergency',
            'kill', 'selfdestruct', 'suicide', 'destroy', 'upgrade',
            'setPrice', 'setAddress', 'setContract', 'setToken',
            'addUser', 'removeUser', 'banUser', 'unbanUser',
            'setPermission', 'grantRole', 'revokeRole', 'setRole',
            'freeze', 'unfreeze', 'lock', 'unlock', 'seize'
        ]
        
        # Enhanced access control modifiers
        self.access_modifiers = [
            'onlyOwner', 'onlyAdmin', 'onlyAuthorized', 'onlyRole',
            'requireOwner', 'requireAdmin', 'requireAuth', 'onlyGovernance',
            'onlyController', 'onlyOperator', 'onlyMinter', 'onlyBurner',
            'onlyPauser', 'onlyUnpauser', 'onlyUpgrader', 'onlyFeeSetter'
        ]
        
        # Enhanced state variables that might indicate ownership
        self.ownership_vars = [
            'owner', 'admin', 'authority', 'controller', 'governance',
            'operator', 'minter', 'burner', 'pauser', 'upgrader',
            'feeSetter', 'roleAdmin', 'superAdmin'
        ]
        
        # Enhanced dangerous external calls
        self.dangerous_calls = [
            r'\.call\s*\(', r'\.delegatecall\s*\(', r'\.send\s*\(',
            r'\.transfer\s*\(', r'selfdestruct\s*\(', r'suicide\s*\(',
            r'\.callcode\s*\(', r'\.staticcall\s*\('
        ]
        
        # Role-based access control patterns
        self.rbac_patterns = [
            r'hasRole\s*\(', r'grantRole\s*\(', r'revokeRole\s*\(',
            r'renounceRole\s*\(', r'getRoleAdmin\s*\(', r'setRoleAdmin\s*\('
        ]
        
        # Fallback and receive function patterns
        self.fallback_patterns = [
            r'fallback\s*\(\s*\)', r'receive\s*\(\s*\)'
        ]
    
    def detect(self, ast: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect access control vulnerabilities."""
        vulnerabilities = []
        content = ast.get('content', '')
        functions = ast.get('functions', [])
        modifiers = ast.get('modifiers', [])
        variables = ast.get('variables', [])
        
        # Check for missing access control on critical functions
        critical_vulns = self._check_critical_functions(functions, content)
        vulnerabilities.extend(critical_vulns)
        
        # Check for missing ownership variables
        ownership_vulns = self._check_ownership_variables(variables, content)
        vulnerabilities.extend(ownership_vulns)
        
        # Check for dangerous external calls without access control
        external_call_vulns = self._check_dangerous_calls(functions, content)
        vulnerabilities.extend(external_call_vulns)
        
        # Check for public/external functions that should be restricted
        public_vulns = self._check_public_functions(functions, content)
        vulnerabilities.extend(public_vulns)
        
        # Check for unprotected fallback/receive functions
        fallback_vulns = self._check_fallback_functions(functions, content)
        vulnerabilities.extend(fallback_vulns)
        
        # Check for missing RBAC implementation
        rbac_vulns = self._check_rbac_implementation(content, functions)
        vulnerabilities.extend(rbac_vulns)
        
        # Check for state variable modifications without access control
        state_vulns = self._check_state_modifications(functions, content)
        vulnerabilities.extend(state_vulns)
        
        return vulnerabilities
    
    def _check_critical_functions(self, functions: List[Dict[str, Any]], 
                                 content: str) -> List[Dict[str, Any]]:
        """Check if critical functions have proper access control."""
        vulnerabilities = []
        
        for function in functions:
            func_name = function.get('name', '').lower()
            access_modifiers = function.get('access_modifiers', [])
            
            # Check if function name suggests it's critical
            is_critical = any(critical in func_name for critical in self.critical_functions)
            
            if is_critical:
                # Check if function has access control
                has_access_control = self._has_access_control(function, content)
                
                if not has_access_control:
                    vuln = self._create_vulnerability(
                        vuln_type="Access Control",
                        severity="High",
                        description=f"Critical function '{function['name']}' lacks access control",
                        line_number=self._get_line_number(content, function.get('start_pos', 0)),
                        code_snippet=self._get_code_snippet(content, function.get('start_pos', 0)),
                        recommendation=f"Add access control modifier like 'onlyOwner' to function '{function['name']}'"
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_ownership_variables(self, variables: List[Dict[str, Any]], 
                                  content: str) -> List[Dict[str, Any]]:
        """Check if contract has proper ownership variables."""
        vulnerabilities = []
        
        # Check if any ownership variables exist
        has_ownership = any(
            any(owner_var in var.get('name', '').lower() 
                for owner_var in self.ownership_vars)
            for var in variables
        )
        
        if not has_ownership:
            # Check if there are critical functions that would need ownership
            has_critical_functions = any(
                any(critical in func.get('name', '').lower() 
                    for critical in self.critical_functions)
                for func in variables  # This should be functions, but keeping original logic
            )
            
            if has_critical_functions:
                vuln = self._create_vulnerability(
                    vuln_type="Access Control",
                    severity="Medium",
                    description="Contract lacks ownership variables for access control",
                    line_number=1,
                    code_snippet="Contract definition",
                    recommendation="Add owner/admin state variable and corresponding modifiers"
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_dangerous_calls(self, functions: List[Dict[str, Any]], 
                              content: str) -> List[Dict[str, Any]]:
        """Check for dangerous external calls without access control."""
        vulnerabilities = []
        
        for function in functions:
            func_body = function.get('body', '')
            if not func_body:
                continue
            
            # Check for dangerous calls in function body
            for pattern in self.dangerous_calls:
                matches = re.finditer(pattern, func_body)
                for match in matches:
                    # Check if function has access control
                    has_access_control = self._has_access_control(function, content)
                    
                    if not has_access_control:
                        vuln = self._create_vulnerability(
                            vuln_type="Access Control",
                            severity="High",
                            description=f"Dangerous external call '{match.group(0)}' without access control",
                            line_number=self._get_line_number(content, match.start()),
                            code_snippet=self._get_code_snippet(content, match.start()),
                            recommendation="Add access control modifier to restrict who can execute this function"
                        )
                        vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_public_functions(self, functions: List[Dict[str, Any]], 
                               content: str) -> List[Dict[str, Any]]:
        """Check for public/external functions that might need access control."""
        vulnerabilities = []
        
        for function in functions:
            access_modifiers = function.get('access_modifiers', [])
            func_name = function.get('name', '').lower()
            
            # Check if function is public or external
            is_public = 'public' in access_modifiers or 'external' in access_modifiers
            
            if is_public:
                # Check if function name suggests it should be restricted
                should_be_restricted = any(
                    critical in func_name for critical in self.critical_functions
                )
                
                if should_be_restricted:
                    has_access_control = self._has_access_control(function, content)
                    
                    if not has_access_control:
                        vuln = self._create_vulnerability(
                            vuln_type="Access Control",
                            severity="Medium",
                            description=f"Public function '{function['name']}' should have access control",
                            line_number=self._get_line_number(content, function.get('start_pos', 0)),
                            code_snippet=self._get_code_snippet(content, function.get('start_pos', 0)),
                            recommendation=f"Add access control modifier to function '{function['name']}' or make it private/internal"
                        )
                        vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _has_access_control(self, function: Dict[str, Any], content: str) -> bool:
        """Check if function has access control."""
        func_body = function.get('body', '')
        func_signature = function.get('signature', '')
        
        # Check function signature for access control modifiers
        for modifier in self.access_modifiers:
            if modifier in func_signature:
                return True
        
        # Check function body for require statements with ownership checks
        ownership_requires = [
            r'require\s*\(\s*msg\.sender\s*==\s*owner',
            r'require\s*\(\s*owner\s*==\s*msg\.sender',
            r'require\s*\(\s*msg\.sender\s*==\s*admin',
            r'require\s*\(\s*admin\s*==\s*msg\.sender',
            r'require\s*\(\s*hasRole\s*\(',
            r'require\s*\(\s*isOwner\s*\(',
            r'require\s*\(\s*isAdmin\s*\('
        ]
        
        for pattern in ownership_requires:
            if re.search(pattern, func_body):
                return True
        
        return False
    
    def _check_fallback_functions(self, functions: List[Dict[str, Any]], content: str) -> List[Dict[str, Any]]:
        """Check for unprotected fallback and receive functions."""
        vulnerabilities = []
        
        for function in functions:
            func_name = function.get('name', '').lower()
            func_body = function.get('body', '')
            
            # Check if it's a fallback or receive function
            is_fallback = func_name in ['fallback', 'receive'] or 'fallback' in func_name or 'receive' in func_name
            
            if is_fallback and func_body:
                # Check if fallback function has access control or is empty
                has_access_control = self._has_access_control(function, content)
                is_empty = len(func_body.strip()) == 0 or func_body.strip() == '{}'
                
                if not has_access_control and not is_empty:
                    vuln = self._create_vulnerability(
                        vuln_type="Access Control",
                        severity="Medium",
                        description=f"Fallback/receive function '{function['name']}' lacks access control",
                        line_number=self._get_line_number(content, function.get('start_pos', 0)),
                        code_snippet=self._get_code_snippet(content, function.get('start_pos', 0)),
                        recommendation="Add access control to fallback/receive function or make it payable only"
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_rbac_implementation(self, content: str, functions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Check for missing Role-Based Access Control implementation."""
        vulnerabilities = []
        
        # Check if contract has RBAC patterns
        has_rbac = any(re.search(pattern, content) for pattern in self.rbac_patterns)
        
        # Check if contract has critical functions that would benefit from RBAC
        has_critical_functions = any(
            any(critical in func.get('name', '').lower() for critical in self.critical_functions)
            for func in functions
        )
        
        if has_critical_functions and not has_rbac:
            # Check if contract has multiple admin-like functions
            admin_functions = [func for func in functions 
                             if any(admin_word in func.get('name', '').lower() 
                                   for admin_word in ['admin', 'owner', 'manager', 'controller'])]
            
            if len(admin_functions) > 1:
                vuln = self._create_vulnerability(
                    vuln_type="Access Control",
                    severity="Medium",
                    description="Contract has multiple admin functions but lacks RBAC implementation",
                    line_number=1,
                    code_snippet="Contract definition",
                    recommendation="Consider implementing Role-Based Access Control (RBAC) for better permission management"
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_state_modifications(self, functions: List[Dict[str, Any]], content: str) -> List[Dict[str, Any]]:
        """Check for state variable modifications without access control."""
        vulnerabilities = []
        
        # Patterns for state variable modifications
        state_modification_patterns = [
            r'(\w+)\s*=\s*[^=]',  # Assignment
            r'(\w+)\s*\+\+',  # Increment
            r'(\w+)\s*--',  # Decrement
            r'(\w+)\s*\+=',  # Add assignment
            r'(\w+)\s*-=',  # Subtract assignment
            r'(\w+)\s*\*=',  # Multiply assignment
            r'(\w+)\s*/=',  # Divide assignment
        ]
        
        for function in functions:
            func_body = function.get('body', '')
            if not func_body:
                continue
            
            # Check for state modifications
            for pattern in state_modification_patterns:
                matches = re.finditer(pattern, func_body)
                for match in matches:
                    var_name = match.group(1)
                    
                    # Check if this looks like a state variable (not local variable)
                    if self._is_likely_state_variable(var_name, content):
                        has_access_control = self._has_access_control(function, content)
                        
                        if not has_access_control:
                            vuln = self._create_vulnerability(
                                vuln_type="Access Control",
                                severity="Medium",
                                description=f"State variable '{var_name}' modified without access control",
                                line_number=self._get_line_number(content, match.start()),
                                code_snippet=self._get_code_snippet(content, match.start()),
                                recommendation=f"Add access control modifier to function '{function.get('name', 'unknown')}'"
                            )
                            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _is_likely_state_variable(self, var_name: str, content: str) -> bool:
        """Check if a variable is likely a state variable."""
        # Look for variable declaration in contract scope
        var_patterns = [
            rf'{var_name}\s+(public|private|internal|external)',
            rf'{var_name}\s+(mapping|array|struct)',
            rf'{var_name}\s+(uint|int|bool|address|string|bytes)',
        ]
        
        for pattern in var_patterns:
            if re.search(pattern, content):
                return True
        
        return False




