"""
Main Bytecode Optimizer

Detects gas optimization opportunities in EVM bytecode.
"""

from typing import List, Dict, Any
from .base_optimizer import OptimizationDetector
from .gas_profiler import GasProfiler
from .patterns import OptimizationPatterns


class BytecodeOptimizer(OptimizationDetector):
    """
    Main optimizer that detects various gas optimization opportunities.
    """
    
    def __init__(self):
        super().__init__(
            name="BytecodeOptimizer",
            description="Detects gas optimization opportunities in bytecode"
        )
        self.gas_profiler = GasProfiler()
        self.patterns = OptimizationPatterns()
    
    def detect(self, opcodes: List[Dict[str, Any]], ast: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Detect optimization opportunities.
        
        Args:
            opcodes: List of parsed opcodes
            ast: Parsed contract AST
            
        Returns:
            List of optimization opportunities
        """
        optimizations = []
        
        if not opcodes:
            return optimizations
        
        # 1. Detect redundant SLOAD operations
        redundant_sloads = self.patterns.find_redundant_sload(opcodes)
        for pos1, pos2 in redundant_sloads:
            optimizations.append(self._create_optimization(
                opt_type="Redundant SLOAD",
                severity="Medium",
                description=f"Storage slot read multiple times (positions {pos1} and {pos2})",
                position=pos1,
                code_snippet=f"SLOAD at {pos1} and {pos2}",
                gas_savings=700,  # Approximate savings from caching
                recommendation="Cache storage value in memory variable to avoid repeated SLOAD (saves ~700 gas per read)"
            ))
        
        # 2. Detect inefficient loops
        inefficient_loops = self.patterns.find_inefficient_loops(opcodes)
        for pos in inefficient_loops:
            optimizations.append(self._create_optimization(
                opt_type="Inefficient Loop",
                severity="High",
                description=f"Loop contains multiple expensive operations at position {pos}",
                position=pos,
                code_snippet=f"JUMPI at {pos}",
                gas_savings=500,  # Approximate savings
                recommendation="Optimize loop by reducing expensive operations (SLOAD, SSTORE, CALL) or breaking early when possible"
            ))
        
        # 3. Detect unnecessary MSTORE
        unnecessary_mstore = self.patterns.find_unnecessary_mstore(opcodes)
        for pos in unnecessary_mstore:
            optimizations.append(self._create_optimization(
                opt_type="Unnecessary MSTORE",
                severity="Low",
                description=f"Memory store at position {pos} is immediately overwritten",
                position=pos,
                code_snippet=f"MSTORE at {pos}",
                gas_savings=3,  # MSTORE cost
                recommendation="Remove unnecessary MSTORE operation or combine with next operation"
            ))
        
        # 4. Detect cacheable storage reads
        cacheable = self.patterns.find_cacheable_storage(opcodes)
        for sload_pos, usage_pos in cacheable:
            optimizations.append(self._create_optimization(
                opt_type="Cacheable Storage Read",
                severity="Medium",
                description=f"Storage read at {sload_pos} could be cached for reuse",
                position=sload_pos,
                code_snippet=f"SLOAD at {sload_pos}",
                gas_savings=700,  # Savings from avoiding repeated SLOAD
                recommendation="Cache storage value in memory after first read, reuse cached value"
            ))
        
        return optimizations
    
    def analyze_gas_usage(self, opcodes: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze gas usage and provide summary.
        
        Args:
            opcodes: List of parsed opcodes
            
        Returns:
            Dictionary with gas analysis
        """
        return self.gas_profiler.analyze_gas_usage(opcodes)
    
    def calculate_potential_savings(self, optimizations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate potential gas savings from optimizations.
        
        Args:
            optimizations: List of detected optimizations
            
        Returns:
            Dictionary with savings summary
        """
        total_savings = sum(opt.get('gas_savings', 0) for opt in optimizations)
        
        return {
            'total_potential_savings': total_savings,
            'optimization_count': len(optimizations),
            'by_severity': {
                'High': sum(1 for opt in optimizations if opt.get('severity') == 'High'),
                'Medium': sum(1 for opt in optimizations if opt.get('severity') == 'Medium'),
                'Low': sum(1 for opt in optimizations if opt.get('severity') == 'Low'),
            }
        }

