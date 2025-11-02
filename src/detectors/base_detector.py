"""
Base class for vulnerability detectors.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any


class VulnerabilityDetector(ABC):
    """Base class for all vulnerability detectors."""
    
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
    
    @abstractmethod
    def detect(self, ast: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Detect vulnerabilities in the given AST.
        
        Args:
            ast: Parsed contract AST
            
        Returns:
            List of detected vulnerabilities
        """
        pass
    
    def _create_vulnerability(self, 
                            vuln_type: str,
                            severity: str,
                            description: str,
                            line_number: int,
                            code_snippet: str,
                            recommendation: str = "") -> Dict[str, Any]:
        """Create a standardized vulnerability report."""
        # Clean Unicode characters from text fields
        def clean_unicode_text(text):
            if not isinstance(text, str):
                return text
            # Replace common Unicode characters with safe alternatives
            replacements = {
                '→': '->',
                '←': '<-',
                '↑': '^',
                '↓': 'v',
                '✅': '[OK]',
                '❌': '[ERROR]',
                '⚠️': '[WARNING]',
                '🔍': '[INFO]',
                '💡': '[TIP]',
                '🚀': '[START]',
                '📊': '[RESULTS]',
                '🔧': '[TOOLS]',
                '✓': '[CHECK]',
                '🎯': '[TARGET]',
                '🛡️': '[SECURE]',
                '⚡': '[FAST]',
                '🔒': '[LOCKED]',
                '🔓': '[UNLOCKED]'
            }
            cleaned = text
            for unicode_char, replacement in replacements.items():
                cleaned = cleaned.replace(unicode_char, replacement)
            # Remove any remaining problematic characters
            import re
            cleaned = re.sub(r'[^\x00-\x7F]+', '[UNICODE]', cleaned)
            return cleaned
        
        return {
            'type': clean_unicode_text(vuln_type),
            'severity': clean_unicode_text(severity),
            'description': clean_unicode_text(description),
            'line_number': line_number,
            'code_snippet': clean_unicode_text(code_snippet),
            'recommendation': clean_unicode_text(recommendation),
            'detector': self.name
        }
    
    def _get_line_number(self, content: str, position: int) -> int:
        """Get line number from character position."""
        return content[:position].count('\n') + 1
    
    def _get_code_snippet(self, content: str, position: int, context: int = 2) -> str:
        """Get code snippet around a position."""
        lines = content.split('\n')
        line_num = self._get_line_number(content, position)
        
        start_line = max(0, line_num - context - 1)
        end_line = min(len(lines), line_num + context)
        
        snippet_lines = []
        for i in range(start_line, end_line):
            prefix = ">>> " if i == line_num - 1 else "    "
            # Clean Unicode characters from code lines
            line_content = lines[i]
            import re
            line_content = re.sub(r'[^\x00-\x7F]+', '[UNICODE]', line_content)
            snippet_lines.append(f"{prefix}{i+1:3d}: {line_content}")
        
        return '\n'.join(snippet_lines)




