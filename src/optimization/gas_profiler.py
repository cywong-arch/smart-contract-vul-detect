"""
Gas Cost Profiler for EVM Opcodes

Maps opcodes to their gas costs based on Ethereum Yellow Paper.
"""

from typing import Dict, List, Any


class GasProfiler:
    """
    Calculates gas costs for EVM opcodes.
    
    Gas costs based on Ethereum Yellow Paper (Istanbul/EIP-1884).
    """
    
    # Base gas costs for opcodes
    OPCODE_GAS_COSTS = {
        # Arithmetic operations
        "ADD": 3, "MUL": 5, "SUB": 3, "DIV": 5, "SDIV": 5,
        "MOD": 5, "SMOD": 5, "ADDMOD": 8, "MULMOD": 8,
        "EXP": 10,  # Base cost, actual cost depends on exponent
        "SIGNEXTEND": 5,
        
        # Comparison operations
        "LT": 3, "GT": 3, "SLT": 3, "SGT": 3, "EQ": 3,
        "ISZERO": 3, "AND": 3, "OR": 3, "XOR": 3, "NOT": 3,
        "BYTE": 3, "SHL": 3, "SHR": 3, "SAR": 3,
        
        # Keccak256
        "SHA3": 30,  # Base, +6 per word
        
        # Environmental information
        "ADDRESS": 2, "BALANCE": 700,  # Cold: 2600, Warm: 100
        "ORIGIN": 2, "CALLER": 2, "CALLVALUE": 2,
        "CALLDATALOAD": 3, "CALLDATASIZE": 2, "CALLDATACOPY": 3,
        "CODESIZE": 2, "CODECOPY": 3, "GASPRICE": 2,
        "EXTCODESIZE": 700,  # Cold: 2600, Warm: 100
        "EXTCODECOPY": 700,  # Cold: 2600, Warm: 100
        "RETURNDATASIZE": 2, "RETURNDATACOPY": 3,
        "EXTCODEHASH": 700,  # Cold: 2600, Warm: 100
        "BLOCKHASH": 20, "COINBASE": 2, "TIMESTAMP": 2,
        "NUMBER": 2, "DIFFICULTY": 2, "GASLIMIT": 2,
        "CHAINID": 2, "SELFBALANCE": 5,
        
        # Stack operations
        "POP": 2, "MLOAD": 3, "MSTORE": 3, "MSTORE8": 3,
        "SLOAD": 800,  # Cold: 2100, Warm: 100
        "SSTORE": 20000,  # Varies: 20000 (set), 2900 (reset), 200 (no-op)
        "JUMP": 8, "JUMPI": 10, "PC": 2, "MSIZE": 2, "GAS": 2,
        "JUMPDEST": 1,
        
        # Push operations (all cost 3)
        "PUSH1": 3, "PUSH2": 3, "PUSH3": 3, "PUSH4": 3,
        "PUSH5": 3, "PUSH6": 3, "PUSH7": 3, "PUSH8": 3,
        "PUSH9": 3, "PUSH10": 3, "PUSH11": 3, "PUSH12": 3,
        "PUSH13": 3, "PUSH14": 3, "PUSH15": 3, "PUSH16": 3,
        "PUSH17": 3, "PUSH18": 3, "PUSH19": 3, "PUSH20": 3,
        "PUSH21": 3, "PUSH22": 3, "PUSH23": 3, "PUSH24": 3,
        "PUSH25": 3, "PUSH26": 3, "PUSH27": 3, "PUSH28": 3,
        "PUSH29": 3, "PUSH30": 3, "PUSH31": 3, "PUSH32": 3,
        
        # Dup operations (all cost 3)
        "DUP1": 3, "DUP2": 3, "DUP3": 3, "DUP4": 3,
        "DUP5": 3, "DUP6": 3, "DUP7": 3, "DUP8": 3,
        "DUP9": 3, "DUP10": 3, "DUP11": 3, "DUP12": 3,
        "DUP13": 3, "DUP14": 3, "DUP15": 3, "DUP16": 3,
        
        # Swap operations (all cost 3)
        "SWAP1": 3, "SWAP2": 3, "SWAP3": 3, "SWAP4": 3,
        "SWAP5": 3, "SWAP6": 3, "SWAP7": 3, "SWAP8": 3,
        "SWAP9": 3, "SWAP10": 3, "SWAP11": 3, "SWAP12": 3,
        "SWAP13": 3, "SWAP14": 3, "SWAP15": 3, "SWAP16": 3,
        
        # Log operations
        "LOG0": 375, "LOG1": 750, "LOG2": 1125, "LOG3": 1500, "LOG4": 1875,
        
        # System operations
        "CREATE": 32000, "CREATE2": 32000,
        "CALL": 700,  # Base, actual cost varies
        "CALLCODE": 700, "DELEGATECALL": 700, "STATICCALL": 700,
        "RETURN": 0, "REVERT": 0, "INVALID": 0,
        "SELFDESTRUCT": 5000,  # +25000 if beneficiary is new
    }
    
    def __init__(self):
        """Initialize the gas profiler."""
        pass
    
    def get_opcode_cost(self, opcode_name: str) -> int:
        """
        Get base gas cost for an opcode.
        
        Args:
            opcode_name: Name of the opcode
            
        Returns:
            Gas cost (0 if unknown)
        """
        return self.OPCODE_GAS_COSTS.get(opcode_name, 0)
    
    def calculate_sequence_cost(self, opcodes: List[Dict[str, Any]]) -> int:
        """
        Calculate total gas cost for a sequence of opcodes.
        
        Args:
            opcodes: List of opcode dictionaries
            
        Returns:
            Total gas cost
        """
        total = 0
        for op in opcodes:
            opcode_name = op.get('name', '')
            total += self.get_opcode_cost(opcode_name)
        return total
    
    def analyze_gas_usage(self, opcodes: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze gas usage patterns in bytecode.
        
        Args:
            opcodes: List of parsed opcodes
            
        Returns:
            Dictionary with gas analysis results
        """
        total_gas = 0
        opcode_counts = {}
        expensive_ops = []
        
        for op in opcodes:
            opcode_name = op.get('name', '')
            cost = self.get_opcode_cost(opcode_name)
            total_gas += cost
            
            # Count opcodes
            opcode_counts[opcode_name] = opcode_counts.get(opcode_name, 0) + 1
            
            # Track expensive operations (>1000 gas)
            if cost > 1000:
                expensive_ops.append({
                    'opcode': opcode_name,
                    'cost': cost,
                    'position': op.get('position', 0)
                })
        
        return {
            'total_gas': total_gas,
            'opcode_counts': opcode_counts,
            'expensive_operations': expensive_ops,
            'total_opcodes': len(opcodes)
        }

