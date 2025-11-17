"""
Bytecode Optimization Module

This module provides gas optimization analysis for EVM bytecode.
It detects inefficient patterns and suggests optimizations.

Status: IMPLEMENTING - Basic optimization patterns
"""

from .optimizer import BytecodeOptimizer
from .gas_profiler import GasProfiler

__all__ = ['BytecodeOptimizer', 'GasProfiler']

# Check for optional dependencies
OPTIMIZATION_AVAILABLE = True

try:
    # Future: import pyevmasm for advanced disassembly
    # import pyevmasm
    pass
except ImportError:
    # Basic optimization works without pyevmasm
    OPTIMIZATION_AVAILABLE = True

def is_available():
    """Check if optimization features are available."""
    return OPTIMIZATION_AVAILABLE

