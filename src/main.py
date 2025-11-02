#!/usr/bin/env python3
"""
Main entry point for the Smart Contract Vulnerability Detection System.
"""

import click
import json
import sys
from pathlib import Path
from typing import List, Dict, Any

from parsers.solidity_parser import SolidityParser
from detectors.overflow_detector import OverflowDetector
from detectors.access_control_detector import AccessControlDetector
from detectors.reentrancy_detector import ReentrancyDetector
from detectors.time_manipulation_detector import TimeManipulationDetector
from detectors.denial_of_service_detector import DenialOfServiceDetector
from detectors.unprotected_selfdestruct_detector import UnprotectedSelfDestructDetector
from utils.reporter import VulnerabilityReporter


@click.command()
@click.argument('contract_file', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output file for results')
@click.option('--format', 'output_format', type=click.Choice(['json', 'text']), 
              default='text', help='Output format')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def main(contract_file: str, output: str, output_format: str, verbose: bool):
    """
    Analyze a smart contract for vulnerabilities.
    
    CONTRACT_FILE: Path to the Solidity contract file to analyze
    """
    try:
        # Initialize parser and detectors
        parser = SolidityParser()
        detectors = [
            OverflowDetector(),
            AccessControlDetector(),
            ReentrancyDetector(),
            TimeManipulationDetector(),
            DenialOfServiceDetector(),
            UnprotectedSelfDestructDetector()
        ]
        reporter = VulnerabilityReporter()
        
        if verbose:
            click.echo(f"Analyzing contract: {contract_file}")
        
        # Parse the contract
        contract_ast = parser.parse_file(contract_file)
        if not contract_ast:
            click.echo("Error: Failed to parse contract", err=True)
            sys.exit(1)
        
        # Run all detectors
        all_vulnerabilities = []
        for detector in detectors:
            vulnerabilities = detector.detect(contract_ast)
            all_vulnerabilities.extend(vulnerabilities)
        
        # Generate report
        report = reporter.generate_report(all_vulnerabilities, contract_file)
        
        # Output results
        if output:
            with open(output, 'w') as f:
                if output_format == 'json':
                    json.dump(report, f, indent=2)
                else:
                    f.write(report['text_report'])
            click.echo(f"Results saved to: {output}")
        else:
            if output_format == 'json':
                print(json.dumps(report, indent=2))
            else:
                print(report['text_report'])
                
    except UnicodeDecodeError as e:
        click.echo(f"Encoding Error: The file contains characters that cannot be decoded.", err=True)
        click.echo("Solution: Save the file with UTF-8 encoding in your text editor.", err=True)
        click.echo(f"Error details: {str(e)}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()




