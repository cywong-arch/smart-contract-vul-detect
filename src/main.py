#!/usr/bin/env python3
"""
Main entry point for the Smart Contract Vulnerability Detection System.
"""

import click
import json
import sys
import tempfile
import re
from pathlib import Path
from typing import List, Dict, Any

# Ensure project root is on sys.path so package imports work when executed via python -m src.main
CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CURRENT_DIR.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.parsers.solidity_parser import SolidityParser
from src.parsers.bytecode_parser import BytecodeParser
from src.detectors.overflow_detector import OverflowDetector
from src.detectors.access_control_detector import AccessControlDetector
from src.detectors.reentrancy_detector import ReentrancyDetector
from src.detectors.time_manipulation_detector import TimeManipulationDetector
from src.detectors.denial_of_service_detector import DenialOfServiceDetector
from src.detectors.unprotected_selfdestruct_detector import UnprotectedSelfDestructDetector
from src.detectors.bytecode_overflow_detector import BytecodeOverflowDetector
from src.detectors.bytecode_access_control_detector import BytecodeAccessControlDetector
from src.detectors.bytecode_reentrancy_detector import BytecodeReentrancyDetector
from src.detectors.bytecode_time_manipulation_detector import BytecodeTimeManipulationDetector
from src.detectors.bytecode_unprotected_selfdestruct_detector import BytecodeUnprotectedSelfDestructDetector
from src.detectors.bytecode_denial_of_service_detector import BytecodeDenialOfServiceDetector
from src.utils.reporter import VulnerabilityReporter
from src.utils.performance import PerformanceMonitor, ASTCache, parallel_detect
from colorama import Fore, Style


@click.command()
@click.argument('contract_file', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output file for results')
@click.option('--format', 'output_format', type=click.Choice(['json', 'text']), 
              default='text', help='Output format')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--enable-fuzzing', is_flag=True, default=False,
              help='Enable dynamic analysis (fuzzing) - EXPERIMENTAL')
@click.option('--enable-cfg', is_flag=True, default=False,
              help='Enable control-flow analysis - EXPERIMENTAL')
@click.option('--enable-formal', is_flag=True, default=False,
              help='Enable formal verification - EXPERIMENTAL')
@click.option('--enable-optimization', is_flag=True, default=False,
              help='Enable bytecode optimization analysis - EXPERIMENTAL')
def main(contract_file: str, output: str, output_format: str, verbose: bool,
         enable_fuzzing: bool, enable_cfg: bool, enable_formal: bool, enable_optimization: bool):
    """
    Analyze a smart contract for vulnerabilities.
    
    CONTRACT_FILE: Path to the Solidity (.sol) or Bytecode (.bin) file to analyze
    """
    try:
        # Auto-detect file type
        file_path = Path(contract_file)
        file_ext = file_path.suffix.lower()
        is_bytecode = file_ext == '.bin'
        
        # Initialize performance monitor
        perf_monitor = PerformanceMonitor()
        perf_monitor.start("total_analysis")
        
        if verbose:
            file_type = "Bytecode" if is_bytecode else "Solidity"
            click.echo(f"Analyzing {file_type} contract: {contract_file}")
        
        # Initialize AST cache (for Solidity files)
        ast_cache = ASTCache() if not is_bytecode else None
        
        temp_sol_path = None
        try:
            # Initialize parser and detectors based on file type
            if is_bytecode:
                # Bytecode analysis (prefer text hex if available, else binary)
                parser = BytecodeParser()
                bytecode_hex = None

                # Try reading as text hex first
                try:
                    with open(contract_file, 'r') as f:
                        text_content = f.read().strip()
                    candidate = text_content.replace('0x', '').replace(' ', '').replace('\n', '').replace('\r', '')
                    if candidate and re.fullmatch(r'[0-9a-fA-F]+', candidate):
                        bytecode_hex = candidate
                except Exception:
                    bytecode_hex = None

                # Fallback to binary read if text hex not valid
                if not bytecode_hex:
                    with open(contract_file, 'rb') as f:
                        bytecode_bytes = f.read()
                    bytecode_hex = bytecode_bytes.hex()
                
                contract_ast = parser.parse_bytecode(bytecode_hex)
                if not contract_ast:
                    click.echo("Error: Failed to parse bytecode", err=True)
                    sys.exit(1)
                
                detectors = [
                    BytecodeOverflowDetector(),
                    BytecodeAccessControlDetector(),
                    BytecodeReentrancyDetector(),
                    BytecodeTimeManipulationDetector(),
                    BytecodeDenialOfServiceDetector(),
                    BytecodeUnprotectedSelfDestructDetector()
                ]
            else:
                # Solidity analysis with cache and Unicode cleaning
                parser = SolidityParser()
                
                perf_monitor.start("parsing")
                contract_ast = None
                if ast_cache:
                    contract_ast = ast_cache.get(contract_file)
                
                if not contract_ast:
                    temp_sol_path = _prepare_solidity_file(contract_file)
                    parse_path = temp_sol_path or contract_file
                    contract_ast = parser.parse_file(parse_path)
                    if not contract_ast:
                        click.echo("Error: Failed to parse contract", err=True)
                        sys.exit(1)
                    if ast_cache:
                        ast_cache.set(contract_file, contract_ast)
                
                perf_monitor.end("parsing")
                
                detectors = [
                    OverflowDetector(),
                    AccessControlDetector(),
                    ReentrancyDetector(),
                    TimeManipulationDetector(),
                    DenialOfServiceDetector(),
                    UnprotectedSelfDestructDetector()
                ]
        finally:
            if temp_sol_path:
                try:
                    Path(temp_sol_path).unlink(missing_ok=True)
                except Exception:
                    pass
        
        reporter = VulnerabilityReporter()
        
        # Run all detectors in parallel for better performance
        perf_monitor.start("detection")
        all_vulnerabilities = parallel_detect(detectors, contract_ast)
        perf_monitor.end("detection")
        
        # Advanced analysis modules (optional - disabled by default)
        advanced_results = {}
        if enable_fuzzing or enable_cfg or enable_formal or enable_optimization:
            if verbose:
                click.echo("\n[INFO] Running advanced analysis modules...")
            
            # Dynamic Analysis (Fuzzing)
            if enable_fuzzing:
                try:
                    from src.analysis.fuzzer import Fuzzer
                    fuzzer = Fuzzer()
                    fuzzer.enable()
                    fuzzing_results = fuzzer.analyze(contract_ast)
                    advanced_results['fuzzing'] = fuzzing_results
                    if 'vulnerabilities' in fuzzing_results:
                        all_vulnerabilities.extend(fuzzing_results['vulnerabilities'])
                    if verbose:
                        click.echo("  [OK] Fuzzing analysis completed")
                except ImportError:
                    if verbose:
                        click.echo("  [WARNING] Fuzzing module not available")
                except Exception as e:
                    if verbose:
                        click.echo(f"  [ERROR] Fuzzing failed: {e}")
            
            # Control-Flow Analysis
            if enable_cfg:
                try:
                    from src.analysis.control_flow import ControlFlowAnalyzer, DataFlowAnalyzer
                    cfg_analyzer = ControlFlowAnalyzer()
                    cfg_analyzer.enable()
                    cfg_results = cfg_analyzer.analyze(contract_ast)
                    advanced_results['control_flow'] = cfg_results
                    
                    # Data-Flow Analysis
                    df_analyzer = DataFlowAnalyzer()
                    df_analyzer.enable()
                    df_results = df_analyzer.analyze(contract_ast)
                    advanced_results['data_flow'] = df_results
                    
                    if verbose:
                        click.echo("  [OK] Control-flow analysis completed")
                except ImportError:
                    if verbose:
                        click.echo("  [WARNING] Control-flow module not available")
                except Exception as e:
                    if verbose:
                        click.echo(f"  [ERROR] Control-flow analysis failed: {e}")
            
            # Bytecode Optimization Analysis
            if enable_optimization:
                try:
                    if is_bytecode:
                        from src.optimization.optimizer import BytecodeOptimizer
                        perf_monitor.start("optimization")
                        optimizer = BytecodeOptimizer()
                        optimization_results = optimizer.detect(contract_ast.get('opcodes', []), contract_ast)
                        
                        # Analyze gas usage
                        gas_analysis = optimizer.analyze_gas_usage(contract_ast.get('opcodes', []))
                        savings = optimizer.calculate_potential_savings(optimization_results)
                        
                        advanced_results['optimization'] = {
                            'optimizations': optimization_results,
                            'gas_analysis': gas_analysis,
                            'potential_savings': savings
                        }
                        perf_monitor.end("optimization")
                        if verbose:
                            click.echo(f"  [OK] Optimization analysis completed: {len(optimization_results)} opportunities found")
                    else:
                        if verbose:
                            click.echo("  [INFO] Optimization analysis is only available for bytecode files")
                except ImportError as e:
                    if verbose:
                        click.echo(f"  [WARNING] Optimization module not available: {e}")
                except Exception as e:
                    if verbose:
                        click.echo(f"  [ERROR] Optimization analysis failed: {e}")
            
            # Formal Verification
            if enable_formal:
                try:
                    # from analysis.formal_verification import FormalVerifier
                    # formal_verifier = FormalVerifier()
                    # formal_verifier.enable()
                    # formal_results = formal_verifier.analyze(contract_ast)
                    # advanced_results['formal'] = formal_results
                    if verbose:
                        click.echo("  [INFO] Formal verification module not yet implemented")
                except ImportError:
                    if verbose:
                        click.echo("  [WARNING] Formal verification module not available")
                except Exception as e:
                    if verbose:
                        click.echo(f"  [ERROR] Formal verification failed: {e}")
        
        # Generate report (includes advanced results if available)
        perf_monitor.start("reporting")
        report = reporter.generate_report(all_vulnerabilities, contract_file)
        if advanced_results:
            report['advanced_analysis'] = advanced_results
        perf_monitor.end("reporting")
        
        # Add performance metrics to report
        perf_monitor.end("total_analysis")
        report['performance'] = perf_monitor.get_metrics()
        
        if verbose:
            click.echo("\n" + perf_monitor.get_summary())
        
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
                # Display optimization results if available
                if enable_optimization and is_bytecode and 'optimization' in advanced_results:
                    _display_optimization_results(advanced_results['optimization'])
                
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


def _display_optimization_results(opt_data: Dict[str, Any]):
    """Display optimization results in CLI."""
    optimizations = opt_data.get('optimizations', [])
    gas_analysis = opt_data.get('gas_analysis', {})
    savings = opt_data.get('potential_savings', {})
    
    if not optimizations:
        click.echo("\n" + "=" * 80)
        click.echo("OPTIMIZATION ANALYSIS")
        click.echo("=" * 80)
        click.echo("[OK] No optimization opportunities found!")
        return
    
    click.echo("\n" + "=" * 80)
    click.echo("OPTIMIZATION ANALYSIS")
    click.echo("=" * 80)
    
    # Gas analysis summary
    if gas_analysis:
        click.echo(f"\n[GAS] Gas Usage Summary:")
        click.echo(f"  Total Estimated Gas: {gas_analysis.get('total_gas', 0):,}")
        click.echo(f"  Total Opcodes: {gas_analysis.get('total_opcodes', 0)}")
    
    # Potential savings
    if savings:
        click.echo(f"\n[SAVINGS] Potential Savings:")
        click.echo(f"  Total Potential Savings: {savings.get('total_potential_savings', 0):,} gas")
        click.echo(f"  Optimization Opportunities: {savings.get('optimization_count', 0)}")
        by_sev = savings.get('by_severity', {})
        if by_sev:
            click.echo(f"    - High: {by_sev.get('High', 0)}")
            click.echo(f"    - Medium: {by_sev.get('Medium', 0)}")
            click.echo(f"    - Low: {by_sev.get('Low', 0)}")
    
    # Optimization details
    click.echo(f"\n[OPTIMIZATIONS] Optimization Opportunities:")
    click.echo("-" * 80)
    for i, opt in enumerate(optimizations, 1):
        severity = opt.get('severity', 'Unknown')
        color = {
            'High': Fore.RED,
            'Medium': Fore.YELLOW,
            'Low': Fore.BLUE
        }.get(severity, '')
        
        click.echo(f"\n{i}. {color}{opt.get('type', 'Unknown')}{Style.RESET_ALL} ({severity})")
        click.echo(f"   Description: {opt.get('description', 'No description')}")
        click.echo(f"   Position: {opt.get('position', 'Unknown')}")
        click.echo(f"   Potential Savings: {opt.get('gas_savings', 0):,} gas")
        if opt.get('recommendation'):
            click.echo(f"   [TIP] Recommendation: {opt.get('recommendation')}")


def _prepare_solidity_file(contract_file: str) -> str:
    """
    Create a cleaned, temporary copy of a Solidity file to avoid decode errors.
    Returns path to the temp file (caller cleans up).
    """
    encodings = ['utf-8', 'utf-8-sig', 'latin-1', 'cp1252']
    content = None
    for encoding in encodings:
        try:
            with open(contract_file, 'r', encoding=encoding) as f:
                content = f.read()
            break
        except UnicodeDecodeError:
            continue
    if content is None:
        raise UnicodeDecodeError("utf-8", b"", 0, 1, "Unable to decode file with known encodings")
    
    # Aggressively remove non-ASCII characters that can break downstream tooling
    cleaned_content = re.sub(r'[^\x00-\x7F]+', '[UNICODE]', content)
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False, encoding='utf-8') as tmp:
        tmp.write(cleaned_content)
        return tmp.name


if __name__ == '__main__':
    main()




