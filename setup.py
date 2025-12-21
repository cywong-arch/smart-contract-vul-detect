#!/usr/bin/env python3
"""
Setup script for the Smart Contract Vulnerability Detection System.
"""

import subprocess
import sys
import os
from pathlib import Path


def install_requirements():
    """Install required Python packages."""
    print("Installing required packages...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ Requirements installed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install requirements: {e}")
        return False


def create_directories():
    """Create necessary directories."""
    directories = [
        "src/detectors",
        "src/parsers", 
        "src/utils",
        "test_contracts",
        "examples",
        "docs",
        "output"
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"✅ Created directory: {directory}")


def run_tests():
    """Run basic tests to verify installation."""
    print("\nRunning basic tests...")
    
    # Test imports
    try:
        sys.path.insert(0, 'src')
        from parsers.solidity_parser import SolidityParser
        from detectors.overflow_detector import OverflowDetector
        from detectors.access_control_detector import AccessControlDetector
        from detectors.reentrancy_detector import ReentrancyDetector
        from utils.reporter import VulnerabilityReporter
        print("✅ All modules imported successfully!")
        return True
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False


def main():
    """Main setup function."""
    print("🚀 Setting up Smart Contract Vulnerability Detection System")
    print("=" * 60)
    
    # Create directories
    print("\n1. Creating project directories...")
    create_directories()
    
    # Install requirements
    print("\n2. Installing requirements...")
    if not install_requirements():
        print("❌ Setup failed during requirements installation")
        return False
    
    # Run tests
    print("\n3. Running basic tests...")
    if not run_tests():
        print("❌ Setup failed during testing")
        return False
    
    print("\n" + "=" * 60)
    print("🎉 Setup completed successfully!")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Analyze a contract: python src/main.py <contract_file.sol>")
    print("2. Launch GUI: python gui_app.py")
    print("3. Launch Web App: python web_app.py")
    print("4. Check the README.md for more information")
    
    return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)




