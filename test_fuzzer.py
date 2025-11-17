#!/usr/bin/env python3
"""
Quick test script for the fuzzer module.
"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from analysis.fuzzer import Fuzzer, TestInputGenerator
from parsers.solidity_parser import SolidityParser

def test_fuzzer():
    """Test the fuzzer with a sample contract."""
    print("Testing Fuzzer Module")
    print("=" * 60)
    
    # Test input generator
    print("\n1. Testing TestInputGenerator...")
    generator = TestInputGenerator()
    
    test_types = ['uint256', 'address', 'bool', 'string']
    for param_type in test_types:
        values = generator.generate_boundary_values(param_type)
        print(f"  {param_type}: {values[:3]}...")  # Show first 3
    
    # Test fuzzer
    print("\n2. Testing Fuzzer...")
    fuzzer = Fuzzer()
    fuzzer.enable()
    
    # Parse a test contract
    test_file = 'test_contracts/vulnerable_reentrancy.sol'
    if os.path.exists(test_file):
        parser = SolidityParser()
        ast = parser.parse_file(test_file)
        
        if ast:
            print(f"  Parsed contract: {test_file}")
            print(f"  Functions found: {len(ast.get('functions', []))}")
            
            # Run fuzzer
            results = fuzzer.analyze(ast)
            
            print(f"\n3. Fuzzing Results:")
            print(f"  Vulnerabilities found: {len(results.get('vulnerabilities', []))}")
            print(f"  Functions tested: {results.get('metrics', {}).get('functions_tested', 0)}")
            print(f"  Iterations: {results.get('metrics', {}).get('iterations', 0)}")
            
            if results.get('vulnerabilities'):
                print(f"\n  Vulnerabilities:")
                for i, vuln in enumerate(results['vulnerabilities'][:3], 1):  # Show first 3
                    print(f"    {i}. {vuln.get('type')}: {vuln.get('description')[:60]}...")
        else:
            print("  Failed to parse contract")
    else:
        print(f"  Test file not found: {test_file}")
    
    print("\n" + "=" * 60)
    print("Fuzzer test completed!")

if __name__ == '__main__':
    test_fuzzer()

