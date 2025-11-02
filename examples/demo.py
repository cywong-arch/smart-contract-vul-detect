#!/usr/bin/env python3
"""
Demo script showing how to use the Smart Contract Vulnerability Detection System.
"""

import sys
import os
from pathlib import Path

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from parsers.solidity_parser import SolidityParser
from detectors.overflow_detector import OverflowDetector
from detectors.access_control_detector import AccessControlDetector
from detectors.reentrancy_detector import ReentrancyDetector
from utils.reporter import VulnerabilityReporter


def analyze_contract(contract_path: str):
    """Analyze a single contract for vulnerabilities."""
    print(f"\n{'='*60}")
    print(f"ANALYZING: {contract_path}")
    print(f"{'='*60}")
    
    # Initialize components
    parser = SolidityParser()
    detectors = [
        OverflowDetector(),
        AccessControlDetector(),
        ReentrancyDetector()
    ]
    reporter = VulnerabilityReporter()
    
    # Parse the contract
    print("Parsing contract...")
    ast = parser.parse_file(contract_path)
    
    if not ast:
        print("❌ Failed to parse contract")
        return
    
    print("✅ Contract parsed successfully")
    
    # Run all detectors
    all_vulnerabilities = []
    for detector in detectors:
        print(f"Running {detector.name}...")
        vulnerabilities = detector.detect(ast)
        all_vulnerabilities.extend(vulnerabilities)
        print(f"  Found {len(vulnerabilities)} vulnerabilities")
    
    # Generate and display report
    if all_vulnerabilities:
        print(f"\n🚨 Found {len(all_vulnerabilities)} total vulnerabilities!")
        reporter.print_colored_report(all_vulnerabilities, contract_path)
    else:
        print("\n✅ No vulnerabilities detected!")
    
    return all_vulnerabilities


def main():
    """Main demo function."""
    print("🔍 Smart Contract Vulnerability Detection System Demo")
    print("=" * 60)
    
    # Get test contracts directory
    test_contracts_dir = Path(__file__).parent.parent / "test_contracts"
    
    if not test_contracts_dir.exists():
        print(f"❌ Test contracts directory not found: {test_contracts_dir}")
        return
    
    # List of test contracts
    test_contracts = [
        "vulnerable_overflow.sol",
        "vulnerable_access_control.sol", 
        "vulnerable_reentrancy.sol",
        "secure_contract.sol"
    ]
    
    all_results = {}
    
    # Analyze each test contract
    for contract_file in test_contracts:
        contract_path = test_contracts_dir / contract_file
        if contract_path.exists():
            vulnerabilities = analyze_contract(str(contract_path))
            all_results[contract_file] = vulnerabilities
        else:
            print(f"❌ Contract file not found: {contract_path}")
    
    # Summary
    print(f"\n{'='*60}")
    print("DEMO SUMMARY")
    print(f"{'='*60}")
    
    total_vulns = 0
    for contract, vulns in all_results.items():
        vuln_count = len(vulns) if vulns else 0
        total_vulns += vuln_count
        status = "🚨 VULNERABLE" if vuln_count > 0 else "✅ SECURE"
        print(f"{contract}: {status} ({vuln_count} vulnerabilities)")
    
    print(f"\nTotal vulnerabilities found: {total_vulns}")
    print("\nDemo completed! 🎉")


if __name__ == "__main__":
    main()




