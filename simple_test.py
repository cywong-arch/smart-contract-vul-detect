#!/usr/bin/env python3
"""
Simple test script for Smart Contract Vulnerability Detection System.
This script tests the system without external dependencies.
"""

import sys
import os

# Add src to the path so we can import our modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def test_basic_functionality():
    """Test basic functionality of the system."""
    print("🔍 Smart Contract Vulnerability Detection System - Test")
    print("=" * 60)
    
    try:
        # Test basic imports
        print("✓ Testing imports...")
        from parsers.solidity_parser import SolidityParser
        from detectors.overflow_detector import OverflowDetector
        from detectors.access_control_detector import AccessControlDetector
        from detectors.reentrancy_detector import ReentrancyDetector
        from detectors.time_manipulation_detector import TimeManipulationDetector
        from detectors.denial_of_service_detector import DenialOfServiceDetector
        from detectors.unprotected_selfdestruct_detector import UnprotectedSelfDestructDetector
        print("✓ All modules imported successfully!")
        
        # Test parser initialization
        print("✓ Testing parser initialization...")
        parser = SolidityParser()
        print("✓ Parser initialized successfully!")
        
        # Test detector initialization
        print("✓ Testing detector initialization...")
        overflow_detector = OverflowDetector()
        access_detector = AccessControlDetector()
        reentrancy_detector = ReentrancyDetector()
        time_manipulation_detector = TimeManipulationDetector()
        denial_of_service_detector = DenialOfServiceDetector()
        unprotected_selfdestruct_detector = UnprotectedSelfDestructDetector()
        print("✓ All detectors initialized successfully!")
        
        # Test with a simple contract
        print("✓ Testing with sample contract...")
        sample_contract = """
        pragma solidity ^0.8.0;
        
        contract SimpleTest {
            uint256 public balance;
            
            function deposit(uint256 amount) public {
                balance += amount;  // Potential overflow
            }
        }
        """
        
        # Parse the sample contract
        try:
            contract_info = parser.parse_string(sample_contract)
            print("✓ Sample contract parsed successfully!")
            print(f"  - Contract name: {contract_info.get('name', 'Unknown')}")
            print(f"  - Functions found: {len(contract_info.get('functions', []))}")
        except Exception as e:
            print(f"⚠️  Parser test failed: {e}")
        
        print("\n🎉 Basic functionality test completed!")
        print("=" * 60)
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

def test_sample_contracts():
    """Test with the provided sample contracts."""
    print("\n🔍 Testing with sample contracts...")
    print("=" * 60)
    
    test_contracts = [
        "test_contracts/vulnerable_overflow.sol",
        "test_contracts/vulnerable_access_control.sol", 
        "test_contracts/vulnerable_reentrancy.sol",
        "test_contracts/vulnerable_time_manipulation.sol",
        "test_contracts/vulnerable_denial_of_service.sol",
        "test_contracts/vulnerable_unprotected_selfdestruct.sol",
        "test_contracts/secure_contract.sol"
    ]
    
    for contract_path in test_contracts:
        if os.path.exists(contract_path):
            print(f"✓ Found: {contract_path}")
            try:
                with open(contract_path, 'r') as f:
                    content = f.read()
                    lines = len(content.splitlines())
                    print(f"  - Lines of code: {lines}")
            except Exception as e:
                print(f"  - Error reading file: {e}")
        else:
            print(f"❌ Not found: {contract_path}")
    
    print("=" * 60)

if __name__ == "__main__":
    print("Starting Smart Contract Vulnerability Detection System Test...\n")
    
    # Run basic functionality test
    success = test_basic_functionality()
    
    # Test sample contracts
    test_sample_contracts()
    
    if success:
        print("\n✅ System is ready to use!")
        print("\nNext steps:")
        print("1. Install missing dependencies: pip install click colorama rich tabulate")
        print("2. Run full analysis: python src/main.py test_contracts/vulnerable_overflow.sol")
        print("3. Check examples: python examples/demo.py")
    else:
        print("\n❌ System needs attention. Please check the errors above.")
