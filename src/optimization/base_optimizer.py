"""
Base class for bytecode optimization detectors.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any


class OptimizationDetector(ABC):
    """Base class for all optimization detectors."""
    
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
    
    @abstractmethod
    def detect(self, opcodes: List[Dict[str, Any]], ast: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Detect optimization opportunities in the given opcodes.
        
        Args:
            opcodes: List of parsed opcodes
            ast: Parsed contract AST
            
        Returns:
            List of detected optimization opportunities
        """
        pass
    
    def _create_optimization(self,
                            opt_type: str,
                            severity: str,
                            description: str,
                            position: int,
                            code_snippet: str,
                            gas_savings: int,
                            recommendation: str = "") -> Dict[str, Any]:
        """Create a standardized optimization report."""
        return {
            'type': opt_type,
            'severity': severity,
            'description': description,
            'position': position,
            'code_snippet': code_snippet,
            'gas_savings': gas_savings,
            'recommendation': recommendation,
            'detector': self.name
        }

