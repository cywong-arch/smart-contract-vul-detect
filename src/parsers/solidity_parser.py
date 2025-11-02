"""
Solidity parser for extracting AST and analyzing contract structure.
"""

import re
from typing import Dict, List, Any, Optional
from pathlib import Path


class SolidityParser:
    """Parser for Solidity smart contracts."""
    
    def __init__(self):
        self.contract_patterns = {
            'contract': r'contract\s+(\w+)\s*\{',
            'function': r'function\s+(\w+)\s*\([^)]*\)\s*(?:public|private|internal|external)?\s*(?:view|pure|payable)?\s*(?:returns\s*\([^)]*\))?\s*\{',
            'modifier': r'modifier\s+(\w+)\s*\([^)]*\)\s*\{',
            'variable': r'(?:uint|int|bool|address|string|bytes)\s+(?:\d+)?\s+(\w+)\s*[;=]',
            'mapping': r'mapping\s*\([^)]+\)\s+(\w+)\s*;',
            'struct': r'struct\s+(\w+)\s*\{',
            'event': r'event\s+(\w+)\s*\([^)]*\)\s*;',
            'constructor': r'constructor\s*\([^)]*\)\s*(?:public|private|internal)?\s*\{'
        }
        
        self.arithmetic_operations = ['+', '-', '*', '/', '%', '**']
        self.external_call_patterns = [
            r'\.call\s*\(',
            r'\.delegatecall\s*\(',
            r'\.send\s*\(',
            r'\.transfer\s*\(',
            r'\.callcode\s*\('
        ]
    
    def parse_file(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Parse a Solidity file and return AST-like structure."""
        try:
            # Try UTF-8 first, then fallback to other encodings
            encodings = ['utf-8', 'utf-8-sig', 'latin-1', 'cp1252']
            content = None
            
            for encoding in encodings:
                try:
                    with open(file_path, 'r', encoding=encoding) as f:
                        content = f.read()
                    break
                except UnicodeDecodeError:
                    continue
            
            if content is None:
                print(f"Error: Could not decode file {file_path} with any supported encoding")
                return None
                
            return self.parse_content(content, file_path)
        except Exception as e:
            print(f"Error parsing file {file_path}: {e}")
            return None
    
    def parse_content(self, content: str, file_path: str = "") -> Dict[str, Any]:
        """Parse Solidity content and extract structured information."""
        # Clean and normalize content
        content = self._clean_content(content)
        
        # Extract contract information
        contracts = self._extract_contracts(content)
        
        # Extract functions and their details
        functions = self._extract_functions(content)
        
        # Extract modifiers
        modifiers = self._extract_modifiers(content)
        
        # Extract variables and mappings
        variables = self._extract_variables(content)
        
        # Extract external calls
        external_calls = self._extract_external_calls(content)
        
        # Extract arithmetic operations
        arithmetic_ops = self._extract_arithmetic_operations(content)
        
        return {
            'file_path': file_path,
            'content': content,
            'contracts': contracts,
            'functions': functions,
            'modifiers': modifiers,
            'variables': variables,
            'external_calls': external_calls,
            'arithmetic_operations': arithmetic_ops,
            'lines': content.split('\n')
        }
    
    def _clean_content(self, content: str) -> str:
        """Clean and normalize the contract content."""
        # Remove single-line comments
        content = re.sub(r'//.*$', '', content, flags=re.MULTILINE)
        
        # Remove multi-line comments
        content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        
        # Don't normalize whitespace - keep original structure for proper parsing
        # content = re.sub(r'\s+', ' ', content)
        
        return content
    
    def _extract_contracts(self, content: str) -> List[Dict[str, Any]]:
        """Extract contract definitions."""
        contracts = []
        matches = re.finditer(self.contract_patterns['contract'], content)
        
        for match in matches:
            contracts.append({
                'name': match.group(1),
                'start_pos': match.start(),
                'end_pos': match.end()
            })
        
        return contracts
    
    def _extract_functions(self, content: str) -> List[Dict[str, Any]]:
        """Extract function definitions with their details."""
        functions = []
        
        # Find all function definitions
        func_matches = re.finditer(self.contract_patterns['function'], content)
        
        for match in func_matches:
            func_name = match.group(1)
            func_start = match.start()
            
            # Extract function body (simplified - find matching braces)
            func_body = self._extract_function_body(content, func_start)
            
            # Check for access modifiers
            access_modifiers = self._extract_access_modifiers(match.group(0))
            
            # Check for state mutability
            state_mutability = self._extract_state_mutability(match.group(0))
            
            functions.append({
                'name': func_name,
                'signature': match.group(0),
                'access_modifiers': access_modifiers,
                'state_mutability': state_mutability,
                'body': func_body,
                'start_pos': func_start,
                'end_pos': func_start + len(func_body) if func_body else func_start
            })
        
        return functions
    
    def _extract_modifiers(self, content: str) -> List[Dict[str, Any]]:
        """Extract modifier definitions."""
        modifiers = []
        matches = re.finditer(self.contract_patterns['modifier'], content)
        
        for match in matches:
            modifiers.append({
                'name': match.group(1),
                'signature': match.group(0),
                'start_pos': match.start(),
                'end_pos': match.end()
            })
        
        return modifiers
    
    def _extract_variables(self, content: str) -> List[Dict[str, Any]]:
        """Extract variable declarations."""
        variables = []
        
        # Regular variables
        var_matches = re.finditer(self.contract_patterns['variable'], content)
        for match in var_matches:
            variables.append({
                'name': match.group(1),
                'type': 'variable',
                'declaration': match.group(0),
                'start_pos': match.start(),
                'end_pos': match.end()
            })
        
        # Mappings
        mapping_matches = re.finditer(self.contract_patterns['mapping'], content)
        for match in mapping_matches:
            variables.append({
                'name': match.group(1),
                'type': 'mapping',
                'declaration': match.group(0),
                'start_pos': match.start(),
                'end_pos': match.end()
            })
        
        return variables
    
    def _extract_external_calls(self, content: str) -> List[Dict[str, Any]]:
        """Extract external function calls."""
        external_calls = []
        
        for pattern in self.external_call_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                external_calls.append({
                    'type': pattern.split('.')[1].split('(')[0],
                    'call': match.group(0),
                    'start_pos': match.start(),
                    'end_pos': match.end()
                })
        
        return external_calls
    
    def _extract_arithmetic_operations(self, content: str) -> List[Dict[str, Any]]:
        """Extract arithmetic operations."""
        arithmetic_ops = []
        
        for op in self.arithmetic_operations:
            # Escape special regex characters
            escaped_op = re.escape(op)
            pattern = rf'\w+\s*{escaped_op}\s*\w+'
            matches = re.finditer(pattern, content)
            
            for match in matches:
                arithmetic_ops.append({
                    'operation': op,
                    'expression': match.group(0),
                    'start_pos': match.start(),
                    'end_pos': match.end()
                })
        
        return arithmetic_ops
    
    def _extract_function_body(self, content: str, start_pos: int) -> str:
        """Extract function body by finding matching braces."""
        # Find the opening brace
        brace_pos = content.find('{', start_pos)
        if brace_pos == -1:
            return ""
        
        # Count braces to find the matching closing brace
        brace_count = 0
        pos = brace_pos
        
        while pos < len(content):
            if content[pos] == '{':
                brace_count += 1
            elif content[pos] == '}':
                brace_count -= 1
                if brace_count == 0:
                    return content[brace_pos:pos + 1]
            pos += 1
        
        return ""
    
    def _extract_access_modifiers(self, function_sig: str) -> List[str]:
        """Extract access modifiers from function signature."""
        modifiers = []
        access_modifiers = ['public', 'private', 'internal', 'external']
        
        for modifier in access_modifiers:
            if modifier in function_sig:
                modifiers.append(modifier)
        
        return modifiers
    
    def _extract_state_mutability(self, function_sig: str) -> List[str]:
        """Extract state mutability from function signature."""
        mutability = []
        state_modifiers = ['view', 'pure', 'payable']
        
        for modifier in state_modifiers:
            if modifier in function_sig:
                mutability.append(modifier)
        
        return mutability




