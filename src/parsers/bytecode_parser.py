"""
EVM Bytecode Parser for Smart Contract Analysis
This module parses Ethereum bytecode and extracts opcodes for vulnerability analysis.
"""

import re
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass


@dataclass
class Opcode:
    """Represents a single EVM opcode."""
    name: str
    code: int
    position: int
    arguments: List[int] = None
    description: str = ""


class BytecodeParser:
    """
    Parser for Ethereum Virtual Machine (EVM) bytecode.
    
    This parser can:
    - Extract opcodes from bytecode
    - Identify function selectors
    - Analyze control flow
    - Detect common patterns
    """
    
    # EVM Opcodes mapping (hex code -> name)
    OPCODES = {
        0x00: "STOP", 0x01: "ADD", 0x02: "MUL", 0x03: "SUB", 0x04: "DIV",
        0x05: "SDIV", 0x06: "MOD", 0x07: "SMOD", 0x08: "ADDMOD", 0x09: "MULMOD",
        0x0a: "EXP", 0x0b: "SIGNEXTEND", 0x10: "LT", 0x11: "GT", 0x12: "SLT",
        0x13: "SGT", 0x14: "EQ", 0x15: "ISZERO", 0x16: "AND", 0x17: "OR",
        0x18: "XOR", 0x19: "NOT", 0x1a: "BYTE", 0x1b: "SHL", 0x1c: "SHR",
        0x1d: "SAR", 0x20: "SHA3", 0x30: "ADDRESS", 0x31: "BALANCE", 0x32: "ORIGIN",
        0x33: "CALLER", 0x34: "CALLVALUE", 0x35: "CALLDATALOAD", 0x36: "CALLDATASIZE",
        0x37: "CALLDATACOPY", 0x38: "CODESIZE", 0x39: "CODECOPY", 0x3a: "GASPRICE",
        0x3b: "EXTCODESIZE", 0x3c: "EXTCODECOPY", 0x3d: "RETURNDATASIZE",
        0x3e: "RETURNDATACOPY", 0x3f: "EXTCODEHASH", 0x40: "BLOCKHASH",
        0x41: "COINBASE", 0x42: "TIMESTAMP", 0x43: "NUMBER", 0x44: "DIFFICULTY",
        0x45: "GASLIMIT", 0x46: "CHAINID", 0x47: "SELFBALANCE", 0x50: "POP",
        0x51: "MLOAD", 0x52: "MSTORE", 0x53: "MSTORE8", 0x54: "SLOAD", 0x55: "SSTORE",
        0x56: "JUMP", 0x57: "JUMPI", 0x58: "PC", 0x59: "MSIZE", 0x5a: "GAS",
        0x5b: "JUMPDEST", 0x60: "PUSH1", 0x61: "PUSH2", 0x62: "PUSH3", 0x63: "PUSH4",
        0x64: "PUSH5", 0x65: "PUSH6", 0x66: "PUSH7", 0x67: "PUSH8", 0x68: "PUSH9",
        0x69: "PUSH10", 0x6a: "PUSH11", 0x6b: "PUSH12", 0x6c: "PUSH13", 0x6d: "PUSH14",
        0x6e: "PUSH15", 0x6f: "PUSH16", 0x70: "PUSH17", 0x71: "PUSH18", 0x72: "PUSH19",
        0x73: "PUSH20", 0x74: "PUSH21", 0x75: "PUSH22", 0x76: "PUSH23", 0x77: "PUSH24",
        0x78: "PUSH25", 0x79: "PUSH26", 0x7a: "PUSH27", 0x7b: "PUSH28", 0x7c: "PUSH29",
        0x7d: "PUSH30", 0x7e: "PUSH31", 0x7f: "PUSH32", 0x80: "DUP1", 0x81: "DUP2",
        0x82: "DUP3", 0x83: "DUP4", 0x84: "DUP5", 0x85: "DUP6", 0x86: "DUP7",
        0x87: "DUP8", 0x88: "DUP9", 0x89: "DUP10", 0x8a: "DUP11", 0x8b: "DUP12",
        0x8c: "DUP13", 0x8d: "DUP14", 0x8e: "DUP15", 0x8f: "DUP16", 0x90: "SWAP1",
        0x91: "SWAP2", 0x92: "SWAP3", 0x93: "SWAP4", 0x94: "SWAP5", 0x95: "SWAP6", 0x96: "SWAP7",
        0x97: "SWAP8", 0x98: "SWAP9", 0x99: "SWAP10", 0x9a: "SWAP11", 0x9b: "SWAP12",
        0x9c: "SWAP13", 0x9d: "SWAP14", 0x9e: "SWAP15", 0x9f: "SWAP16", 0xa0: "LOG0",
        0xa1: "LOG1", 0xa2: "LOG2", 0xa3: "LOG3", 0xa4: "LOG4", 0xf0: "CREATE",
        0xf1: "CALL", 0xf2: "CALLCODE", 0xf3: "RETURN", 0xf4: "DELEGATECALL",
        0xf5: "CREATE2", 0xfa: "STATICCALL", 0xfd: "REVERT", 0xfe: "INVALID",
        0xff: "SELFDESTRUCT"
    }
    
    # Dangerous opcodes for vulnerability detection
    DANGEROUS_OPCODES = {
        "CALL": "External call - potential reentrancy",
        "CALLCODE": "External call - potential reentrancy", 
        "DELEGATECALL": "External call - potential reentrancy",
        "STATICCALL": "External call - potential reentrancy",
        "SELFDESTRUCT": "Contract destruction",
        "CREATE": "Contract creation",
        "CREATE2": "Contract creation"
    }
    
    # Arithmetic opcodes that can cause overflow
    ARITHMETIC_OPCODES = {
        "ADD", "SUB", "MUL", "DIV", "SDIV", "MOD", "SMOD", 
        "ADDMOD", "MULMOD", "EXP"
    }
    
    def __init__(self):
        self.bytecode = ""
        self.opcodes = []
        self.function_selectors = []
        
    def parse_file(self, file_path: str) -> Optional[Dict[str, Any]]:
        """
        Parse a bytecode file and return analysis structure.
        
        Args:
            file_path: Path to bytecode file (.bin or hex text file)
            
        Returns:
            Dictionary containing parsed information, or None if error
        """
        try:
            # Try reading as binary first
            try:
                with open(file_path, 'rb') as f:
                    bytecode_bytes = f.read()
                bytecode_hex = bytecode_bytes.hex()
            except:
                # Try reading as text (hex string)
                with open(file_path, 'r') as f:
                    bytecode_hex = f.read().strip()
            
            return self.parse_bytecode(bytecode_hex)
        except Exception as e:
            print(f"Error parsing bytecode file {file_path}: {e}")
            return None
    
    def parse_bytecode(self, bytecode: str) -> Dict[str, Any]:
        """
        Parse EVM bytecode and extract opcodes.
        
        Args:
            bytecode: Hex string of EVM bytecode (with or without 0x prefix)
            
        Returns:
            Dictionary containing parsed information
        """
        # Clean bytecode
        self.bytecode = self._clean_bytecode(bytecode)
        self.opcodes = []
        self.function_selectors = []
        
        # Parse opcodes
        self._parse_opcodes()
        
        # Extract function selectors
        self._extract_function_selectors()
        
        # Analyze patterns
        patterns = self._analyze_patterns()
        
        return {
            "bytecode": self.bytecode,
            "opcodes": [self._opcode_to_dict(op) for op in self.opcodes],
            "function_selectors": self.function_selectors,
            "patterns": patterns,
            "total_opcodes": len(self.opcodes),
            "dangerous_opcodes": self._count_dangerous_opcodes(),
            "arithmetic_opcodes": self._count_arithmetic_opcodes()
        }
    
    def _clean_bytecode(self, bytecode: str) -> str:
        """Clean and validate bytecode input."""
        # Remove 0x prefix if present
        if bytecode.startswith('0x'):
            bytecode = bytecode[2:]
        
        # Remove whitespace
        bytecode = bytecode.replace(' ', '').replace('\n', '').replace('\t', '')
        
        # Validate hex
        if not re.match(r'^[0-9a-fA-F]*$', bytecode):
            raise ValueError("Invalid bytecode: contains non-hex characters")
        
        # Must be even length (each byte is 2 hex chars)
        if len(bytecode) % 2 != 0:
            raise ValueError("Invalid bytecode: odd number of hex characters")
        
        return bytecode.upper()
    
    def _parse_opcodes(self):
        """Parse bytecode into opcodes."""
        i = 0
        while i < len(self.bytecode):
            # Get opcode byte
            opcode_hex = self.bytecode[i:i+2]
            opcode_int = int(opcode_hex, 16)
            opcode_name = self.OPCODES.get(opcode_int, f"UNKNOWN_{opcode_hex}")
            
            position = i // 2  # Position in bytes
            arguments = []
            
            # Handle PUSH opcodes
            if opcode_name.startswith("PUSH"):
                push_size = int(opcode_name[4:])
                arg_start = i + 2
                arg_end = arg_start + push_size * 2
                if arg_end <= len(self.bytecode):
                    arg_hex = self.bytecode[arg_start:arg_end]
                    arguments = [int(arg_hex, 16)]
                else:
                    arguments = [0]
                i = arg_end  # Jump to after args
            else:
                i += 2  # Normal opcode
            
            # Create opcode
            opcode = Opcode(
                name=opcode_name,
                code=opcode_int,
                position=position,
                arguments=arguments
            )
            self.opcodes.append(opcode)
    
    def _extract_function_selectors(self):
        """Extract function selectors from bytecode."""
        # Look for PUSH4 followed by specific patterns
        for i, opcode in enumerate(self.opcodes):
            if opcode.name == "PUSH4" and opcode.arguments:
                # Function selectors are typically 4 bytes
                selector = opcode.arguments[0]
                if selector != 0:  # Skip zero selectors
                    self.function_selectors.append({
                        "selector": f"0x{selector:08x}",
                        "position": opcode.position,
                        "opcode_index": i
                    })
    
    def _analyze_patterns(self) -> Dict[str, Any]:
        """Analyze bytecode for common patterns."""
        patterns = {
            "external_calls": [],
            "storage_access": [],
            "arithmetic_operations": [],
            "jump_destinations": [],
            "constructor_pattern": False,
            "fallback_pattern": False
        }
        
        for i, opcode in enumerate(self.opcodes):
            # External calls
            if opcode.name in ["CALL", "CALLCODE", "DELEGATECALL", "STATICCALL"]:
                patterns["external_calls"].append({
                    "opcode": opcode.name,
                    "position": opcode.position,
                    "index": i
                })
            
            # Storage access
            if opcode.name in ["SLOAD", "SSTORE"]:
                patterns["storage_access"].append({
                    "opcode": opcode.name,
                    "position": opcode.position,
                    "index": i
                })
            
            # Arithmetic operations
            if opcode.name in self.ARITHMETIC_OPCODES:
                patterns["arithmetic_operations"].append({
                    "opcode": opcode.name,
                    "position": opcode.position,
                    "index": i
                })
            
            # Jump destinations
            if opcode.name == "JUMPDEST":
                patterns["jump_destinations"].append({
                    "position": opcode.position,
                    "index": i
                })
        
        # Check for constructor pattern (typically starts with PUSH32)
        if self.opcodes and self.opcodes[0].name == "PUSH32":
            patterns["constructor_pattern"] = True
        
        # Check for fallback pattern (no function selector matching)
        patterns["fallback_pattern"] = len(self.function_selectors) == 0
        
        return patterns
    
    def _count_dangerous_opcodes(self) -> Dict[str, int]:
        """Count occurrences of dangerous opcodes."""
        counts = {}
        for opcode in self.opcodes:
            if opcode.name in self.DANGEROUS_OPCODES:
                counts[opcode.name] = counts.get(opcode.name, 0) + 1
        return counts
    
    def _count_arithmetic_opcodes(self) -> Dict[str, int]:
        """Count occurrences of arithmetic opcodes."""
        counts = {}
        for opcode in self.opcodes:
            if opcode.name in self.ARITHMETIC_OPCODES:
                counts[opcode.name] = counts.get(opcode.name, 0) + 1
        return counts
    
    def _opcode_to_dict(self, opcode: Opcode) -> Dict[str, Any]:
        """Convert Opcode object to dictionary."""
        return {
            "name": opcode.name,
            "code": opcode.code,
            "position": opcode.position,
            "arguments": opcode.arguments or [],
            "description": self.DANGEROUS_OPCODES.get(opcode.name, "")
        }
    
    def get_opcode_sequence(self, start: int = 0, end: int = None) -> List[Opcode]:
        """Get a sequence of opcodes."""
        if end is None:
            end = len(self.opcodes)
        return self.opcodes[start:end]
    
    def find_opcode_pattern(self, pattern: List[str]) -> List[int]:
        """
        Find occurrences of a specific opcode pattern.
        
        Args:
            pattern: List of opcode names to search for
            
        Returns:
            List of starting indices where pattern is found
        """
        matches = []
        for i in range(len(self.opcodes) - len(pattern) + 1):
            match = True
            for j, expected_opcode in enumerate(pattern):
                if self.opcodes[i + j].name != expected_opcode:
                    match = False
                    break
            if match:
                matches.append(i)
        return matches
    
    def is_contract_creation_bytecode(self) -> bool:
        """Check if this is contract creation bytecode."""
        # Contract creation bytecode typically starts with constructor code
        return len(self.opcodes) > 0 and self.opcodes[0].name == "PUSH32"
    
    def get_contract_runtime_bytecode(self) -> str:
        """Extract runtime bytecode from creation bytecode."""
        # This is a simplified version - in reality, you'd need to parse
        # the constructor arguments and metadata
        if not self.is_contract_creation_bytecode():
            return self.bytecode
        
        # For now, return the original bytecode
        # In a full implementation, you'd extract the runtime portion
        return self.bytecode
