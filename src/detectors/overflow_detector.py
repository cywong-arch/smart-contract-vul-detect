"""
Detector for integer overflow and underflow vulnerabilities.
"""

import re
from typing import List, Dict, Any
from .base_detector import VulnerabilityDetector


class OverflowDetector(VulnerabilityDetector):
    """Detects integer overflow and underflow vulnerabilities."""
    
    def __init__(self):
        super().__init__(
            name="OverflowDetector",
            description="Detects integer overflow and underflow vulnerabilities"
        )
        
        # Enhanced patterns that indicate potential overflow/underflow
        self.arithmetic_patterns = [
            r'(\w+)\s*\+\s*(\w+)',  # Addition
            r'(\w+)\s*-\s*(\w+)',  # Subtraction
            r'(\w+)\s*\*\s*(\w+)',  # Multiplication
            r'(\w+)\s*/\s*(\w+)',  # Division
            r'(\w+)\s*%\s*(\w+)',  # Modulo
            r'(\w+)\s*\*\*\s*(\w+)',  # Exponentiation
            r'(\w+)\s*\+\+',  # Increment
            r'(\w+)\s*--',  # Decrement
            r'\+\+\s*(\w+)',  # Pre-increment
            r'--\s*(\w+)',  # Pre-decrement
            r'(\w+)\s*\+=\s*(\w+)',  # Addition assignment
            r'(\w+)\s*-=\s*(\w+)',  # Subtraction assignment
            r'(\w+)\s*\*=\s*(\w+)',  # Multiplication assignment
            r'(\w+)\s*/=\s*(\w+)',  # Division assignment
            r'(\w+)\s*%=\s*(\w+)',  # Modulo assignment
        ]
        
        # SafeMath usage patterns (including OpenZeppelin) - Enhanced
        self.safemath_patterns = [
            r'SafeMath\.add\s*\(',
            r'SafeMath\.sub\s*\(',
            r'SafeMath\.mul\s*\(',
            r'SafeMath\.div\s*\(',
            r'SafeMath\.mod\s*\(',
            r'@openzeppelin/contracts/utils/math/SafeMath',
            r'using\s+SafeMath\s+for\s+uint256',
            r'using\s+SafeMath\s+for\s+uint',
            r'using\s+SafeMath\s+for\s+uint8',
            r'using\s+SafeMath\s+for\s+uint16',
            r'using\s+SafeMath\s+for\s+uint32',
            r'using\s+SafeMath\s+for\s+uint64',
            r'using\s+SafeMath\s+for\s+uint128',
            r'Math\.add\s*\(',
            r'Math\.sub\s*\(',
            r'Math\.mul\s*\(',
            r'Math\.div\s*\(',
            r'Math\.mod\s*\(',
            r'@openzeppelin/contracts/utils/math/Math',
            r'@openzeppelin/contracts/utils/math/SafeCast',
            r'SafeCast\.toUint256',
            r'SafeCast\.toUint128',
            r'unchecked\s*\{',  # Solidity 0.8+ unchecked block
        ]
        
        # Solidity version patterns
        self.version_pattern = r'pragma\s+solidity\s+([0-9.^>=<]+)'
        
        # Dangerous operation patterns
        self.dangerous_patterns = [
            r'(\w+)\s*\*\s*(\w+)\s*\*\s*(\w+)',  # Multiple multiplications
            r'(\w+)\s*\*\s*\d+',  # Multiplication by constant
            r'(\w+)\s*\+\s*(\w+)\s*\+\s*(\w+)',  # Multiple additions
            r'(\w+)\s*-\s*(\w+)\s*-\s*(\w+)',  # Multiple subtractions
        ]
        
        # Loop counter patterns
        self.loop_patterns = [
            r'for\s*\(\s*(\w+)\s*=\s*(\w+)\s*;\s*(\w+)\s*<\s*(\w+)\s*;\s*(\w+)\s*\+\+',
            r'for\s*\(\s*(\w+)\s*=\s*(\w+)\s*;\s*(\w+)\s*<=\s*(\w+)\s*;\s*(\w+)\s*\+\+',
            r'while\s*\(\s*(\w+)\s*<\s*(\w+)\s*\)',
            r'while\s*\(\s*(\w+)\s*<=\s*(\w+)\s*\)'
        ]
    
    def detect(self, ast: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect overflow/underflow vulnerabilities."""
        vulnerabilities = []
        content = ast.get('content', '')
        functions = ast.get('functions', [])
        
        # Check Solidity version
        solidity_version = self._get_solidity_version(content)
        
        # Check for SafeMath usage
        has_safemath = self._has_safemath_usage(content)
        
        # Check for dangerous patterns
        dangerous_vulns = self._check_dangerous_patterns(content, solidity_version, has_safemath)
        vulnerabilities.extend(dangerous_vulns)
        
        # Check loop counters
        loop_vulns = self._check_loop_counters(content, solidity_version, has_safemath)
        vulnerabilities.extend(loop_vulns)
        
        # Analyze each function
        for function in functions:
            func_vulns = self._analyze_function(function, content, solidity_version, has_safemath)
            vulnerabilities.extend(func_vulns)
        
        # Check global arithmetic operations
        global_vulns = self._check_global_arithmetic(content, solidity_version, has_safemath)
        vulnerabilities.extend(global_vulns)
        
        # Check for user input arithmetic
        input_vulns = self._check_user_input_arithmetic(content, solidity_version, has_safemath)
        vulnerabilities.extend(input_vulns)
        
        return vulnerabilities
    
    def _get_solidity_version(self, content: str) -> str:
        """Extract Solidity version from pragma statement."""
        match = re.search(self.version_pattern, content)
        if match:
            return match.group(1)
        return "unknown"
    
    def _has_safemath_usage(self, content: str) -> bool:
        """Check if SafeMath library is being used."""
        for pattern in self.safemath_patterns:
            if re.search(pattern, content):
                return True
        return False
    
    def _analyze_function(self, function: Dict[str, Any], content: str, 
                         solidity_version: str, has_safemath: bool) -> List[Dict[str, Any]]:
        """Analyze a function for overflow/underflow vulnerabilities."""
        vulnerabilities = []
        func_body = function.get('body', '')
        func_start_pos = function.get('start_pos', 0)
        
        if not func_body:
            return vulnerabilities
        
        # Check for unsafe arithmetic operations
        for pattern in self.arithmetic_patterns:
            matches = re.finditer(pattern, func_body)
            for match in matches:
                # Calculate absolute position in content
                absolute_pos = func_start_pos + match.start()
                
                # Check if in unchecked block (Solidity 0.8+)
                if self._is_solidity_08_plus(solidity_version):
                    if self._is_in_unchecked_block(content, absolute_pos):
                        # Operation in unchecked block - potentially unsafe
                        vuln = self._create_vulnerability(
                            vuln_type="Integer Overflow/Underflow",
                            severity="High",
                            description=f"Arithmetic operation in unchecked block: {match.group(0)}",
                            line_number=self._get_line_number(content, absolute_pos),
                            code_snippet=self._get_code_snippet(content, absolute_pos),
                            recommendation="Operations in unchecked blocks bypass overflow protection. Ensure proper validation."
                        )
                        vulnerabilities.append(vuln)
                        continue
                
                if self._is_unsafe_operation(match, solidity_version, has_safemath):
                    vuln = self._create_vulnerability(
                        vuln_type="Integer Overflow/Underflow",
                        severity="High",
                        description=f"Unsafe arithmetic operation detected: {match.group(0)}",
                        line_number=self._get_line_number(content, absolute_pos),
                        code_snippet=self._get_code_snippet(content, absolute_pos),
                        recommendation=self._get_recommendation(match.group(0), solidity_version, has_safemath)
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_global_arithmetic(self, content: str, solidity_version: str, 
                               has_safemath: bool) -> List[Dict[str, Any]]:
        """Check for arithmetic operations outside functions."""
        vulnerabilities = []
        
        # Find all arithmetic operations in the contract
        for pattern in self.arithmetic_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                # Skip if it's inside a function (already checked)
                if self._is_inside_function(content, match.start()):
                    continue
                
                if self._is_unsafe_operation(match, solidity_version, has_safemath):
                    vuln = self._create_vulnerability(
                        vuln_type="Integer Overflow/Underflow",
                        severity="High",
                        description=f"Unsafe arithmetic operation detected: {match.group(0)}",
                        line_number=self._get_line_number(content, match.start()),
                        code_snippet=self._get_code_snippet(content, match.start()),
                        recommendation=self._get_recommendation(match.group(0), solidity_version, has_safemath)
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _is_unsafe_operation(self, match, solidity_version: str, has_safemath: bool) -> bool:
        """Determine if an arithmetic operation is unsafe."""
        operation = match.group(0)
        
        # Solidity 0.8+ has built-in overflow protection
        if self._is_solidity_08_plus(solidity_version):
            # Check if operation is inside unchecked block
            # This is a simplified check - in full implementation, would need context
            # For now, assume operations in 0.8+ are safe unless in unchecked block
            return False
        
        # Check if SafeMath is being used
        if has_safemath:
            # If SafeMath is available but not used, it's unsafe
            return not self._is_safemath_operation(operation)
        
        # No protection available - unsafe
        return True
    
    def _is_in_unchecked_block(self, content: str, position: int) -> bool:
        """Check if position is inside an unchecked block (Solidity 0.8+)."""
        # Look backwards for unchecked keyword
        before_position = content[:position]
        
        # Find the last unchecked block before this position
        unchecked_pattern = r'unchecked\s*\{'
        unchecked_matches = list(re.finditer(unchecked_pattern, before_position))
        
        if not unchecked_matches:
            return False
        
        # Get the last unchecked block
        last_unchecked = unchecked_matches[-1]
        unchecked_start = last_unchecked.end() - 1  # Position of opening brace
        
        # Count braces to find the end of unchecked block
        brace_count = 0
        pos = unchecked_start
        
        while pos < position and pos < len(content):
            if content[pos] == '{':
                brace_count += 1
            elif content[pos] == '}':
                brace_count -= 1
                if brace_count == 0:
                    return False  # We've exited the unchecked block
            pos += 1
        
        # If brace_count > 0, we're still inside the unchecked block
        return brace_count > 0
    
    def _is_solidity_08_plus(self, version: str) -> bool:
        """Check if Solidity version is 0.8 or higher."""
        try:
            major, minor = version.split('.')[:2]
            return int(major) > 0 or (int(major) == 0 and int(minor) >= 8)
        except:
            return False
    
    def _is_safemath_operation(self, operation: str) -> bool:
        """Check if operation uses SafeMath."""
        safemath_ops = ['SafeMath.add', 'SafeMath.sub', 'SafeMath.mul', 'SafeMath.div', 'SafeMath.mod']
        return any(safemath_op in operation for safemath_op in safemath_ops)
    
    def _is_inside_function(self, content: str, position: int) -> bool:
        """Check if position is inside a function definition."""
        # Simple heuristic: look for function keyword before position
        before_position = content[:position]
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
        
        # Count braces to see if we're still inside the function
        brace_count = 0
        pos = brace_pos
        
        while pos < position and pos < len(content):
            if content[pos] == '{':
                brace_count += 1
            elif content[pos] == '}':
                brace_count -= 1
                if brace_count == 0:
                    return False
            pos += 1
        
        return brace_count > 0
    
    def _get_recommendation(self, operation: str, solidity_version: str, has_safemath: bool) -> str:
        """Get recommendation for fixing the vulnerability."""
        if self._is_solidity_08_plus(solidity_version):
            return "Consider using Solidity 0.8+ which has built-in overflow protection."
        elif has_safemath:
            return f"Use SafeMath library for safe arithmetic: SafeMath.{self._get_safemath_method(operation)}"
        else:
            return "Use SafeMath library or upgrade to Solidity 0.8+ for overflow protection."
    
    def _get_safemath_method(self, operation: str) -> str:
        """Get the corresponding SafeMath method for an operation."""
        if '+' in operation:
            return "add"
        elif '-' in operation:
            return "sub"
        elif '*' in operation:
            return "mul"
        elif '/' in operation:
            return "div"
        elif '%' in operation:
            return "mod"
        else:
            return "add"  # Default
    
    def _check_dangerous_patterns(self, content: str, solidity_version: str, has_safemath: bool) -> List[Dict[str, Any]]:
        """Check for dangerous arithmetic patterns."""
        vulnerabilities = []
        
        for pattern in self.dangerous_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                if self._is_unsafe_operation(match, solidity_version, has_safemath):
                    vuln = self._create_vulnerability(
                        vuln_type="Integer Overflow/Underflow",
                        severity="High",
                        description=f"Dangerous arithmetic pattern detected: {match.group(0)}",
                        line_number=self._get_line_number(content, match.start()),
                        code_snippet=self._get_code_snippet(content, match.start()),
                        recommendation="Use SafeMath library or upgrade to Solidity 0.8+ for overflow protection."
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_loop_counters(self, content: str, solidity_version: str, has_safemath: bool) -> List[Dict[str, Any]]:
        """Check for potential overflow in loop counters."""
        vulnerabilities = []
        
        for pattern in self.loop_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                if not self._is_solidity_08_plus(solidity_version) and not has_safemath:
                    vuln = self._create_vulnerability(
                        vuln_type="Integer Overflow/Underflow",
                        severity="Medium",
                        description=f"Loop counter may overflow: {match.group(0)}",
                        line_number=self._get_line_number(content, match.start()),
                        code_snippet=self._get_code_snippet(content, match.start()),
                        recommendation="Ensure loop bounds are safe or use SafeMath for counter operations."
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_user_input_arithmetic(self, content: str, solidity_version: str, has_safemath: bool) -> List[Dict[str, Any]]:
        """Check for arithmetic operations involving user inputs."""
        vulnerabilities = []
        
        # Look for arithmetic with msg.value, msg.sender, or function parameters
        user_input_patterns = [
            r'msg\.value\s*[\+\-\*\/]',
            r'[\+\-\*\/]\s*msg\.value',
            r'(\w+)\s*[\+\-\*\/]\s*(\w+)\s*//.*parameter',
            r'(\w+)\s*[\+\-\*\/]\s*(\w+)\s*//.*input'
        ]
        
        for pattern in user_input_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                if self._is_unsafe_operation(match, solidity_version, has_safemath):
                    vuln = self._create_vulnerability(
                        vuln_type="Integer Overflow/Underflow",
                        severity="High",
                        description=f"Arithmetic with user input may overflow: {match.group(0)}",
                        line_number=self._get_line_number(content, match.start()),
                        code_snippet=self._get_code_snippet(content, match.start()),
                        recommendation="Validate user inputs and use SafeMath for arithmetic operations."
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities




