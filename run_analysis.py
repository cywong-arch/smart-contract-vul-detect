#!/usr/bin/env python3
"""
Smart Contract Vulnerability Detection System - Runner
This script runs the vulnerability detection system without complex dependencies.
"""

import sys
import os
import json
from pathlib import Path

# Add src to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def analyze_contract(contract_file, verbose=True):
    """
    Analyze a smart contract for vulnerabilities.
    
    Args:
        contract_file (str): Path to the contract file
        verbose (bool): Whether to show detailed output
    
    Returns:
        dict: Analysis results
    """
    try:
        # Import modules
        from parsers.solidity_parser import SolidityParser
        from detectors.overflow_detector import OverflowDetector
        from detectors.access_control_detector import AccessControlDetector
        from detectors.reentrancy_detector import ReentrancyDetector
        from detectors.time_manipulation_detector import TimeManipulationDetector
        from detectors.denial_of_service_detector import DenialOfServiceDetector
        from detectors.unprotected_selfdestruct_detector import UnprotectedSelfDestructDetector
        
        if verbose:
            print(f"🔍 Analyzing contract: {contract_file}")
            print("=" * 60)
        
        # Check if file exists
        if not os.path.exists(contract_file):
            print(f"❌ Error: Contract file not found: {contract_file}")
            return None
        
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
        
        if verbose:
            print("✓ Initialized parser and detectors")
        
        # Parse the contract
        try:
            contract_ast = parser.parse_file(contract_file)
            if verbose:
                print("✓ Contract parsed successfully")
                if contract_ast:
                    print(f"  - Contract name: {contract_ast.get('name', 'Unknown')}")
                    print(f"  - Functions found: {len(contract_ast.get('functions', []))}")
                    print(f"  - Variables found: {len(contract_ast.get('variables', []))}")
        except UnicodeDecodeError as e:
            print(f"❌ Encoding Error: The file contains characters that cannot be decoded.")
            print("💡 Solution: Save the file with UTF-8 encoding in your text editor.")
            print(f"Error details: {e}")
            return None
        except Exception as e:
            print(f"❌ Error parsing contract: {e}")
            return None
        
        # Run all detectors
        all_vulnerabilities = []
        detector_results = {}
        
        for detector in detectors:
            try:
                detector_name = detector.__class__.__name__
                if verbose:
                    print(f"🔍 Running {detector_name}...")
                
                vulnerabilities = detector.detect(contract_ast)
                all_vulnerabilities.extend(vulnerabilities)
                detector_results[detector_name] = len(vulnerabilities)
                
                if verbose:
                    if vulnerabilities:
                        print(f"  ⚠️  Found {len(vulnerabilities)} potential issues")
                        for vuln in vulnerabilities:
                            print(f"    - {vuln.get('type', 'Unknown')}: {vuln.get('description', 'No description')}")
                    else:
                        print(f"  ✅ No issues found")
                        
            except Exception as e:
                print(f"❌ Error in {detector.__class__.__name__}: {e}")
        
        # Generate summary
        results = {
            'contract_file': contract_file,
            'total_vulnerabilities': len(all_vulnerabilities),
            'detector_results': detector_results,
            'vulnerabilities': all_vulnerabilities
        }
        
        if verbose:
            print("\n📊 Analysis Summary:")
            print("=" * 60)
            print(f"Total vulnerabilities found: {len(all_vulnerabilities)}")
            for detector_name, count in detector_results.items():
                print(f"{detector_name}: {count} issues")
            
            if all_vulnerabilities:
                print("\n⚠️  Vulnerabilities Details:")
                for i, vuln in enumerate(all_vulnerabilities, 1):
                    print(f"{i}. {vuln.get('type', 'Unknown')} (Line {vuln.get('line', 'Unknown')})")
                    print(f"   {vuln.get('description', 'No description')}")
                    if vuln.get('recommendation'):
                        print(f"   💡 Fix: {vuln.get('recommendation')}")
                    print()
            else:
                print("✅ No vulnerabilities detected!")
        
        return results
        
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        import traceback
        if verbose:
            traceback.print_exc()
        return None

def main():
    """Main function to run the analysis."""
    print("🚀 Smart Contract Vulnerability Detection System")
    print("=" * 60)
    
    # Test contracts to analyze
    test_contracts = [
        "test_contracts/vulnerable_overflow.sol",
        "test_contracts/vulnerable_access_control.sol",
        "test_contracts/vulnerable_reentrancy.sol",
        "test_contracts/vulnerable_time_manipulation.sol",
        "test_contracts/vulnerable_denial_of_service.sol",
        "test_contracts/vulnerable_unprotected_selfdestruct.sol",
        "test_contracts/secure_contract.sol"
    ]
    
    results = {}
    
    for contract in test_contracts:
        if os.path.exists(contract):
            print(f"\n📁 Analyzing: {contract}")
            result = analyze_contract(contract, verbose=True)
            if result:
                results[contract] = result
            print("\n" + "="*60)
        else:
            print(f"❌ Contract not found: {contract}")
    
    # Save results to file
    if results:
        with open('analysis_results.json', 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n💾 Results saved to: analysis_results.json")
    
    print("\n🎉 Analysis completed!")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Analyze specific contract
        contract_file = sys.argv[1]
        analyze_contract(contract_file, verbose=True)
    else:
        # Run full test suite
        main()
