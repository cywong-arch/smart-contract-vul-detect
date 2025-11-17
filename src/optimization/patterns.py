"""
Optimization Pattern Definitions

Defines patterns for detecting gas-wasting code sequences.
"""

from typing import List, Dict, Any, Tuple


class OptimizationPatterns:
    """
    Defines patterns for gas optimization detection.
    """
    
    @staticmethod
    def find_redundant_sload(opcodes: List[Dict[str, Any]]) -> List[Tuple[int, int]]:
        """
        Find redundant SLOAD operations (same storage slot read multiple times).
        
        Args:
            opcodes: List of opcodes
            
        Returns:
            List of (position1, position2) tuples where SLOAD is redundant
        """
        redundant = []
        sload_positions = []
        
        # Find all SLOAD operations
        for i, op in enumerate(opcodes):
            if op.get('name') == 'SLOAD':
                # Try to extract storage slot (simplified - look for PUSH before SLOAD)
                if i > 0:
                    prev_op = opcodes[i-1]
                    # If previous is a PUSH, it might be the storage slot
                    if prev_op.get('name', '').startswith('PUSH'):
                        slot = prev_op.get('arguments', [None])[0] if prev_op.get('arguments') else None
                        sload_positions.append((i, slot))
        
        # Check for duplicates
        seen_slots = {}
        for idx, (pos, slot) in enumerate(sload_positions):
            if slot is not None and slot in seen_slots:
                # Found duplicate SLOAD
                redundant.append((seen_slots[slot], pos))
            if slot is not None:
                seen_slots[slot] = pos
        
        return redundant
    
    @staticmethod
    def find_inefficient_loops(opcodes: List[Dict[str, Any]]) -> List[int]:
        """
        Find potentially inefficient loops (unbounded or with expensive operations).
        
        Args:
            opcodes: List of opcodes
            
        Returns:
            List of positions where inefficient loops start
        """
        inefficient = []
        
        # Look for JUMPI patterns that might indicate loops
        for i, op in enumerate(opcodes):
            if op.get('name') == 'JUMPI':
                # Check if there's a loop pattern (JUMPI with backward jump)
                # This is simplified - full CFG would be better
                if i > 0:
                    # Check for expensive operations in potential loop
                    window_start = max(0, i - 20)
                    window = opcodes[window_start:i]
                    
                    expensive_ops = ['SLOAD', 'SSTORE', 'CALL', 'DELEGATECALL', 'CREATE']
                    expensive_count = sum(1 for op in window if op.get('name') in expensive_ops)
                    
                    if expensive_count > 3:
                        inefficient.append(i)
        
        return inefficient
    
    @staticmethod
    def find_unnecessary_mstore(opcodes: List[Dict[str, Any]]) -> List[int]:
        """
        Find unnecessary MSTORE operations (values that are never used).
        
        Args:
            opcodes: List of opcodes
            
        Returns:
            List of positions with unnecessary MSTORE
        """
        unnecessary = []
        
        # Simplified: Look for MSTORE followed by POP or overwritten
        for i, op in enumerate(opcodes):
            if op.get('name') == 'MSTORE':
                # Check next few operations
                next_ops = opcodes[i+1:min(i+10, len(opcodes))]
                
                # If immediately followed by another MSTORE to same location, first is unnecessary
                if len(next_ops) > 0 and next_ops[0].get('name') == 'MSTORE':
                    unnecessary.append(i)
        
        return unnecessary
    
    @staticmethod
    def find_cacheable_storage(opcodes: List[Dict[str, Any]]) -> List[Tuple[int, int]]:
        """
        Find storage reads that could be cached in memory.
        
        Args:
            opcodes: List of opcodes
            
        Returns:
            List of (sload_pos, usage_pos) tuples where caching would help
        """
        cacheable = []
        
        # Find SLOAD operations
        for i, op in enumerate(opcodes):
            if op.get('name') == 'SLOAD':
                # Look ahead for multiple uses of this value
                # Simplified: check if same storage slot is read again soon
                window = opcodes[i+1:min(i+50, len(opcodes))]
                
                # Count SLOAD operations in window (potential duplicate reads)
                sload_count = sum(1 for op in window if op.get('name') == 'SLOAD')
                
                if sload_count > 0:
                    # Potential caching opportunity
                    cacheable.append((i, i + sload_count))
        
        return cacheable

