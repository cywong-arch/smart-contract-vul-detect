#!/usr/bin/env python3
"""
Script to compile Solidity contracts to bytecode files.
"""

import os
from solcx import compile_files, set_solc_version, install_solc

def compile_contract_to_bytecode(contract_path):
    """Compile a Solidity contract to bytecode."""
    try:
        # Install and set Solidity compiler version
        try:
            install_solc('0.8.0')
            set_solc_version('0.8.0')
        except:
            set_solc_version('0.8.0')
        
        # Compile the contract
        compiled = compile_files(
            [contract_path],
            output_values=['bin-runtime'],
            solc_version='0.8.0'
        )
        
        # Get the contract name from the file
        contract_name = os.path.basename(contract_path).replace('.sol', '')
        
        # Find the compiled contract (key format: path:ContractName)
        bytecode = None
        for key, value in compiled.items():
            if contract_name in key or 'MixedVuln' in key:
                bytecode = value.get('bin-runtime', '')
                break
        
        if not bytecode:
            # Try to get the first contract
            if compiled:
                first_key = list(compiled.keys())[0]
                bytecode = compiled[first_key].get('bin-runtime', '')
        
        if bytecode:
            # Write bytecode to .bin file
            bytecode_path = contract_path.replace('.sol', '.bin')
            with open(bytecode_path, 'w') as f:
                f.write(bytecode)
            print(f"✓ Compiled {contract_path} -> {bytecode_path}")
            return True
        else:
            print(f"✗ Failed to compile {contract_path}: No bytecode found")
            return False
            
    except Exception as e:
        print(f"✗ Error compiling {contract_path}: {e}")
        return False

def main():
    """Compile all mixed vulnerability contracts."""
    contracts = [
        'test_contracts/mixed_vuln_level1_time_dos.sol',
        'test_contracts/mixed_vuln_level2_time_dos.sol',
        'test_contracts/mixed_vuln_level3_time_dos.sol',
    ]
    
    print("Compiling contracts to bytecode...")
    print("=" * 60)
    
    for contract in contracts:
        if os.path.exists(contract):
            compile_contract_to_bytecode(contract)
        else:
            print(f"✗ File not found: {contract}")
    
    print("=" * 60)
    print("Compilation complete!")

if __name__ == '__main__':
    main()

