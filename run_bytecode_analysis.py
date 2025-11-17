#!/usr/bin/env python3
"""
Smart Contract Vulnerability Detection System - Bytecode Analysis Runner
This script runs bytecode analysis on smart contracts.
"""

import sys
import os
import json
import argparse
from pathlib import Path

# Add src to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def analyze_bytecode(bytecode_input, verbose=True):
    """
    Analyze bytecode for vulnerabilities.
    
    Args:
        bytecode_input (str): Bytecode string or file path
        verbose (bool): Whether to show detailed output
    
    Returns:
        dict: Analysis results
    """
    try:
        # Import modules
        from parsers.bytecode_parser import BytecodeParser
        from detectors.bytecode_overflow_detector import BytecodeOverflowDetector
        from detectors.bytecode_access_control_detector import BytecodeAccessControlDetector
        from detectors.bytecode_reentrancy_detector import BytecodeReentrancyDetector
        from detectors.bytecode_time_manipulation_detector import BytecodeTimeManipulationDetector
        from detectors.bytecode_unprotected_selfdestruct_detector import BytecodeUnprotectedSelfDestructDetector
        from detectors.bytecode_denial_of_service_detector import BytecodeDenialOfServiceDetector
        
        if verbose:
            print(f"[INFO] Analyzing bytecode...")
            print("=" * 60)
        
        # Get bytecode
        bytecode = get_bytecode(bytecode_input)
        if not bytecode:
            print(f"❌ Error: Could not get bytecode from input")
            return None
        
        # Initialize parser and detectors
        parser = BytecodeParser()
        detectors = [
            BytecodeOverflowDetector(),
            BytecodeAccessControlDetector(), 
            BytecodeReentrancyDetector(),
            BytecodeTimeManipulationDetector(),
            BytecodeUnprotectedSelfDestructDetector(),
            BytecodeDenialOfServiceDetector()
        ]
        
        if verbose:
            print("[CHECK] Initialized bytecode parser and detectors")
        
        # Parse the bytecode
        try:
            bytecode_analysis = parser.parse_bytecode(bytecode)
            if verbose:
                print("[CHECK] Bytecode parsed successfully")
                print(f"  - Total opcodes: {bytecode_analysis.get('total_opcodes', 0)}")
                print(f"  - Function selectors: {len(bytecode_analysis.get('function_selectors', []))}")
                print(f"  - Dangerous opcodes: {sum(bytecode_analysis.get('dangerous_opcodes', {}).values())}")
        except Exception as e:
            print(f"[ERROR] Error parsing bytecode: {e}")
            return None
        
        # Run all detectors
        all_vulnerabilities = []
        detector_results = {}
        
        for detector in detectors:
            try:
                detector_name = detector.__class__.__name__
                if verbose:
                    print(f"[INFO] Running {detector_name}...")
                
                vulnerabilities = detector.detect(bytecode_analysis)
                all_vulnerabilities.extend(vulnerabilities)
                detector_results[detector_name] = len(vulnerabilities)
                
                if verbose:
                    if vulnerabilities:
                        print(f"  [WARNING] Found {len(vulnerabilities)} potential issues")
                        for vuln in vulnerabilities:
                            print(f"    - {vuln.get('type', 'Unknown')}: {vuln.get('description', 'No description')}")
                    else:
                        print(f"  [OK] No issues found")
                        
            except Exception as e:
                print(f"[ERROR] Error in {detector.__class__.__name__}: {e}")
        
        # Generate summary
        results = {
            'input': bytecode_input,
            'bytecode_length': len(bytecode),
            'total_vulnerabilities': len(all_vulnerabilities),
            'detector_results': detector_results,
            'vulnerabilities': all_vulnerabilities,
            'bytecode_analysis': bytecode_analysis
        }
        
        if verbose:
            print("\n[RESULTS] Analysis Summary:")
            print("=" * 60)
            print(f"Total vulnerabilities found: {len(all_vulnerabilities)}")
            for detector_name, count in detector_results.items():
                print(f"{detector_name}: {count} issues")
            
            if all_vulnerabilities:
                print("\n[WARNING] Vulnerabilities Details:")
                for i, vuln in enumerate(all_vulnerabilities, 1):
                    print(f"{i}. {vuln.get('type', 'Unknown')} (Position {vuln.get('line_number', 'Unknown')})")
                    print(f"   {vuln.get('description', 'No description')}")
                    if vuln.get('recommendation'):
                        print(f"   [TIP] Fix: {vuln.get('recommendation')}")
                    print()
            else:
                print("[OK] No vulnerabilities detected!")
        
        return results
        
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
        import traceback
        if verbose:
            traceback.print_exc()
        return None

def get_bytecode(bytecode_input):
    """
    Get bytecode from various input sources.
    
    Args:
        bytecode_input: Can be:
            - Hex string (with or without 0x)
            - File path to .bin file
            - Contract address (for future web3 integration)
    
    Returns:
        str: Clean bytecode hex string
    """
    # Check if it's a file path
    if os.path.exists(bytecode_input):
        try:
            with open(bytecode_input, 'r') as f:
                content = f.read().strip()
                # Remove 0x prefix if present
                if content.startswith('0x'):
                    return content[2:]
                return content
        except Exception as e:
            print(f"[ERROR] Error reading file {bytecode_input}: {e}")
            return None
    
    # Check if it's a contract address (starts with 0x and is 42 chars)
    if bytecode_input.startswith('0x') and len(bytecode_input) == 42:
        print("[WARNING] Contract address detected. Web3 integration not yet implemented.")
        print("[TIP] Please provide bytecode directly or use a .bin file.")
        return None
    
    # Assume it's bytecode string
    return bytecode_input

def main():
    """Main function to run bytecode analysis."""
    parser = argparse.ArgumentParser(description='Analyze smart contract bytecode for vulnerabilities')
    parser.add_argument('input', help='Bytecode string, file path, or contract address')
    parser.add_argument('--output', '-o', help='Output file for results (JSON)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    print("[START] Smart Contract Bytecode Vulnerability Detection System")
    print("=" * 60)
    
    # Analyze bytecode
    result = analyze_bytecode(args.input, verbose=args.verbose)
    
    if result:
        # Save results if requested
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(result, f, indent=2)
            print(f"\n💾 Results saved to: {args.output}")
        
        print("\n[SUCCESS] Bytecode analysis completed!")
    else:
        print("\n[ERROR] Analysis failed!")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        main()
    else:
        print("[START] Smart Contract Bytecode Vulnerability Detection System")
        print("=" * 60)
        print("\nUsage examples:")
        print("1. Analyze bytecode string:")
        print("   python run_bytecode_analysis.py 608060405234801561001057600080fd5b50...")
        print("\n2. Analyze bytecode file:")
        print("   python run_bytecode_analysis.py contract.bin")
        print("\n3. Save results to file:")
        print("   python run_bytecode_analysis.py contract.bin --output results.json")
        print("\n4. Verbose output:")
        print("   python run_bytecode_analysis.py contract.bin --verbose")
        print("\nFor help:")
        print("   python run_bytecode_analysis.py --help")
