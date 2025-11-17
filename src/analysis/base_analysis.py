"""
Base classes for advanced analysis modules.

This module provides base classes for dynamic analysis, control-flow analysis,
and formal verification components.
"""

from typing import Dict, Any, List, Optional
from abc import ABC, abstractmethod


class BaseAnalysis(ABC):
    """
    Base class for advanced analysis modules.
    """
    
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.enabled = False
    
    def enable(self):
        """Enable this analysis module."""
        self.enabled = True
    
    def disable(self):
        """Disable this analysis module."""
        self.enabled = False
    
    @abstractmethod
    def analyze(self, ast: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        """
        Perform analysis.
        
        Args:
            ast: Parsed contract AST
            **kwargs: Additional parameters
        
        Returns:
            Analysis results dictionary
        """
        pass


class AnalysisResult:
    """
    Container for analysis results.
    """
    
    def __init__(self, analysis_type: str):
        self.analysis_type = analysis_type
        self.metrics: Dict[str, Any] = {}
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.warnings: List[str] = []
        self.errors: List[str] = []
    
    def add_metric(self, key: str, value: Any):
        """Add a metric."""
        self.metrics[key] = value
    
    def add_warning(self, message: str):
        """Add a warning message."""
        self.warnings.append(message)
    
    def add_error(self, message: str):
        """Add an error message."""
        self.errors.append(message)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        result = {
            'analysis_type': self.analysis_type,
            'metrics': self.metrics.copy(),
            'vulnerabilities': self.vulnerabilities.copy(),
        }
        
        if self.warnings:
            result['warnings'] = self.warnings.copy()
        
        if self.errors:
            result['errors'] = self.errors.copy()
            # If there are errors, add an error field for easy access
            result['error'] = '; '.join(self.errors)
        
        return result

