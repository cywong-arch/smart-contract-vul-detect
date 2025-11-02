"""
Vulnerability reporting utilities.
"""

from typing import List, Dict, Any
from tabulate import tabulate
from colorama import init, Fore, Style
import json

# Initialize colorama for cross-platform colored output
init()


class VulnerabilityReporter:
    """Generates vulnerability reports in various formats."""
    
    def __init__(self):
        self.severity_colors = {
            'High': Fore.RED,
            'Medium': Fore.YELLOW,
            'Low': Fore.BLUE,
            'Info': Fore.CYAN
        }
    
    def generate_report(self, vulnerabilities: List[Dict[str, Any]], 
                       contract_file: str) -> Dict[str, Any]:
        """Generate a comprehensive vulnerability report."""
        # Group vulnerabilities by type
        vuln_by_type = self._group_by_type(vulnerabilities)
        
        # Generate summary
        summary = self._generate_summary(vulnerabilities)
        
        # Generate text report
        text_report = self._generate_text_report(vulnerabilities, contract_file, summary)
        
        # Generate JSON report
        json_report = self._generate_json_report(vulnerabilities, contract_file, summary)
        
        return {
            'contract_file': contract_file,
            'summary': summary,
            'vulnerabilities': vulnerabilities,
            'vulnerabilities_by_type': vuln_by_type,
            'text_report': text_report,
            'json_report': json_report
        }
    
    def _group_by_type(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group vulnerabilities by type."""
        grouped = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'Unknown')
            if vuln_type not in grouped:
                grouped[vuln_type] = []
            grouped[vuln_type].append(vuln)
        return grouped
    
    def _generate_summary(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate vulnerability summary statistics."""
        total = len(vulnerabilities)
        
        severity_counts = {}
        type_counts = {}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Unknown')
            vuln_type = vuln.get('type', 'Unknown')
            
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
        
        return {
            'total_vulnerabilities': total,
            'severity_counts': severity_counts,
            'type_counts': type_counts,
            'high_severity': severity_counts.get('High', 0),
            'medium_severity': severity_counts.get('Medium', 0),
            'low_severity': severity_counts.get('Low', 0)
        }
    
    def _generate_text_report(self, vulnerabilities: List[Dict[str, Any]], 
                             contract_file: str, summary: Dict[str, Any]) -> str:
        """Generate human-readable text report."""
        report_lines = []
        
        # Header
        report_lines.append("=" * 80)
        report_lines.append(f"SMART CONTRACT VULNERABILITY ANALYSIS REPORT")
        report_lines.append("=" * 80)
        report_lines.append(f"Contract File: {contract_file}")
        report_lines.append(f"Analysis Date: {self._get_current_timestamp()}")
        report_lines.append("")
        
        # Summary
        report_lines.append("SUMMARY")
        report_lines.append("-" * 40)
        report_lines.append(f"Total Vulnerabilities: {summary['total_vulnerabilities']}")
        report_lines.append(f"High Severity: {summary['high_severity']}")
        report_lines.append(f"Medium Severity: {summary['medium_severity']}")
        report_lines.append(f"Low Severity: {summary['low_severity']}")
        report_lines.append("")
        
        # Vulnerability types
        if summary['type_counts']:
            report_lines.append("VULNERABILITY TYPES")
            report_lines.append("-" * 40)
            for vuln_type, count in summary['type_counts'].items():
                report_lines.append(f"  {vuln_type}: {count}")
            report_lines.append("")
        
        # Detailed vulnerabilities
        if vulnerabilities:
            report_lines.append("DETAILED FINDINGS")
            report_lines.append("-" * 40)
            
            for i, vuln in enumerate(vulnerabilities, 1):
                report_lines.append(f"\n{i}. {vuln['type']}")
                report_lines.append(f"   Severity: {vuln['severity']}")
                report_lines.append(f"   Line: {vuln['line_number']}")
                report_lines.append(f"   Description: {vuln['description']}")
                
                if vuln.get('code_snippet'):
                    report_lines.append("   Code:")
                    for line in vuln['code_snippet'].split('\n'):
                        report_lines.append(f"     {line}")
                
                if vuln.get('recommendation'):
                    report_lines.append(f"   Recommendation: {vuln['recommendation']}")
                
                report_lines.append("")
        else:
            report_lines.append("No vulnerabilities detected!")
        
        # Footer
        report_lines.append("=" * 80)
        report_lines.append("Analysis completed successfully.")
        report_lines.append("=" * 80)
        
        return '\n'.join(report_lines)
    
    def _generate_json_report(self, vulnerabilities: List[Dict[str, Any]], 
                             contract_file: str, summary: Dict[str, Any]) -> str:
        """Generate JSON report."""
        report_data = {
            'contract_file': contract_file,
            'analysis_timestamp': self._get_current_timestamp(),
            'summary': summary,
            'vulnerabilities': vulnerabilities
        }
        
        return json.dumps(report_data, indent=2)
    
    def _get_current_timestamp(self) -> str:
        """Get current timestamp string."""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def print_colored_report(self, vulnerabilities: List[Dict[str, Any]], 
                           contract_file: str):
        """Print a colored version of the report to console."""
        summary = self._generate_summary(vulnerabilities)
        
        # Print header
        print(f"{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}SMART CONTRACT VULNERABILITY ANALYSIS{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")
        print(f"Contract: {Fore.WHITE}{contract_file}{Style.RESET_ALL}")
        print()
        
        # Print summary
        print(f"{Fore.YELLOW}SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'-' * 40}{Style.RESET_ALL}")
        print(f"Total Vulnerabilities: {Fore.WHITE}{summary['total_vulnerabilities']}{Style.RESET_ALL}")
        print(f"High Severity: {Fore.RED}{summary['high_severity']}{Style.RESET_ALL}")
        print(f"Medium Severity: {Fore.YELLOW}{summary['medium_severity']}{Style.RESET_ALL}")
        print(f"Low Severity: {Fore.BLUE}{summary['low_severity']}{Style.RESET_ALL}")
        print()
        
        # Print vulnerabilities
        if vulnerabilities:
            for i, vuln in enumerate(vulnerabilities, 1):
                severity_color = self.severity_colors.get(vuln['severity'], Fore.WHITE)
                
                print(f"{Fore.CYAN}{i}. {vuln['type']}{Style.RESET_ALL}")
                print(f"   Severity: {severity_color}{vuln['severity']}{Style.RESET_ALL}")
                print(f"   Line: {Fore.WHITE}{vuln['line_number']}{Style.RESET_ALL}")
                print(f"   Description: {Fore.WHITE}{vuln['description']}{Style.RESET_ALL}")
                
                if vuln.get('recommendation'):
                    print(f"   Recommendation: {Fore.GREEN}{vuln['recommendation']}{Style.RESET_ALL}")
                
                print()
        else:
            print(f"{Fore.GREEN}No vulnerabilities detected!{Style.RESET_ALL}")
        
        print(f"{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")
    
    def generate_table_report(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Generate a table format report."""
        if not vulnerabilities:
            return "No vulnerabilities found."
        
        # Prepare table data
        table_data = []
        for vuln in vulnerabilities:
            table_data.append([
                vuln.get('type', 'Unknown'),
                vuln.get('severity', 'Unknown'),
                vuln.get('line_number', 'N/A'),
                vuln.get('description', '')[:50] + '...' if len(vuln.get('description', '')) > 50 else vuln.get('description', '')
            ])
        
        headers = ['Type', 'Severity', 'Line', 'Description']
        return tabulate(table_data, headers=headers, tablefmt='grid')




