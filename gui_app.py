#!/usr/bin/env python3
"""
Smart Contract Vulnerability Detection System - GUI Application
A user-friendly graphical interface for the vulnerability detection system.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import sys
import os
import json
import threading
import re
from pathlib import Path

# Ensure project root is on sys.path so src.* imports work when launched from any cwd
CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CURRENT_DIR
if (PROJECT_ROOT / "src").exists():
    if str(PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(PROJECT_ROOT))

class VulnerabilityDetectorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Smart Contract Vulnerability Detection System")
        self.root.geometry("900x700")
        self.root.configure(bg='#f0f0f0')
        
        # Variables
        self.selected_file = tk.StringVar()
        self.analysis_running = False
        self.enable_fuzzing = tk.BooleanVar(value=False)
        self.enable_cfg = tk.BooleanVar(value=False)
        self.enable_formal = tk.BooleanVar(value=False)
        self.enable_optimization = tk.BooleanVar(value=False)
        
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the user interface."""
        # Title
        title_frame = tk.Frame(self.root, bg='#2c3e50', height=80)
        title_frame.pack(fill='x', padx=10, pady=10)
        title_frame.pack_propagate(False)
        
        title_label = tk.Label(
            title_frame,
            text="🔍 Smart Contract Vulnerability Detection System",
            font=('Arial', 16, 'bold'),
            fg='white',
            bg='#2c3e50'
        )
        title_label.pack(expand=True)
        
        # File selection frame
        file_frame = tk.LabelFrame(self.root, text="📁 Select Contract File", font=('Arial', 12, 'bold'))
        file_frame.pack(fill='x', padx=10, pady=10)
        
        # File path display
        file_path_frame = tk.Frame(file_frame)
        file_path_frame.pack(fill='x', padx=10, pady=10)
        
        self.file_entry = tk.Entry(
            file_path_frame,
            textvariable=self.selected_file,
            font=('Arial', 10),
            state='readonly',
            width=70
        )
        self.file_entry.pack(side='left', fill='x', expand=True)
        
        browse_btn = tk.Button(
            file_path_frame,
            text="Browse",
            command=self.browse_file,
            bg='#3498db',
            fg='white',
            font=('Arial', 10, 'bold'),
            width=10
        )
        browse_btn.pack(side='right', padx=(10, 0))
        
        # Quick select frame
        quick_frame = tk.Frame(file_frame)
        quick_frame.pack(fill='x', padx=10, pady=(0, 10))
        
        tk.Label(quick_frame, text="Quick Select Test Contracts:", font=('Arial', 10)).pack(anchor='w')
        
        test_contracts = [
            ("Overflow Vulnerable", "test_contracts/vulnerable_overflow.sol"),
            ("Access Control Vulnerable", "test_contracts/vulnerable_access_control.sol"),
            ("Reentrancy Vulnerable", "test_contracts/vulnerable_reentrancy.sol"),
            ("Time Manipulation Vulnerable", "test_contracts/vulnerable_time_manipulation.sol"),
            ("DoS Vulnerable", "test_contracts/vulnerable_denial_of_service.sol"),
            ("Selfdestruct Vulnerable", "test_contracts/vulnerable_unprotected_selfdestruct.sol"),
            ("Secure Contract", "test_contracts/secure_contract.sol")
        ]
        
        quick_btn_frame = tk.Frame(quick_frame)
        quick_btn_frame.pack(fill='x', pady=5)
        
        for name, path in test_contracts:
            if os.path.exists(path):
                btn = tk.Button(
                    quick_btn_frame,
                    text=name,
                    command=lambda p=path: self.select_test_contract(p),
                    bg='#95a5a6',
                    fg='white',
                    font=('Arial', 9),
                    width=20
                )
                btn.pack(side='left', padx=2)
        
        # Analysis options frame
        options_frame = tk.LabelFrame(self.root, text="🔧 Analysis Options", font=('Arial', 12, 'bold'))
        options_frame.pack(fill='x', padx=10, pady=10)
        
        options_inner = tk.Frame(options_frame)
        options_inner.pack(fill='x', padx=10, pady=10)
        
        # Detector checkboxes
        tk.Label(options_inner, text="Select Detectors:", font=('Arial', 10, 'bold')).pack(anchor='w')
        
        self.detector_vars = {}
        detectors = [
            ("overflow", "Integer Overflow/Underflow Detection"),
            ("access_control", "Access Control Detection"),
            ("reentrancy", "Reentrancy Detection"),
            ("time_manipulation", "Time Manipulation Detection"),
            ("denial_of_service", "Denial of Service Detection"),
            ("unprotected_selfdestruct", "Unprotected Selfdestruct Detection")
        ]
        
        detector_frame = tk.Frame(options_inner)
        detector_frame.pack(fill='x', pady=5)
        
        for key, name in detectors:
            var = tk.BooleanVar(value=True)
            self.detector_vars[key] = var
            cb = tk.Checkbutton(
                detector_frame,
                text=name,
                variable=var,
                font=('Arial', 10)
            )
            cb.pack(anchor='w')

        # Advanced analysis toggles (hidden/disabled in GUI)
        self.enable_fuzzing.set(False)
        self.enable_cfg.set(False)
        self.enable_formal.set(False)
        self.enable_optimization.set(False)
        
        # Analysis button
        analyze_btn = tk.Button(
            options_frame,
            text="🚀 Start Analysis",
            command=self.start_analysis,
            bg='#27ae60',
            fg='white',
            font=('Arial', 12, 'bold'),
            height=2,
            width=20
        )
        analyze_btn.pack(pady=10)
        
        # Progress bar
        self.progress = ttk.Progressbar(
            self.root,
            mode='indeterminate',
            length=400
        )
        self.progress.pack(pady=10)
        
        # Results frame
        results_frame = tk.LabelFrame(self.root, text="📊 Analysis Results", font=('Arial', 12, 'bold'))
        results_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Results text area
        self.results_text = scrolledtext.ScrolledText(
            results_frame,
            wrap=tk.WORD,
            font=('Consolas', 12),
            bg='#2c3e50',
            fg='#ecf0f1',
            insertbackground='white',
            height=25  # make the results area taller for better readability
        )
        self.results_text.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready to analyze smart contracts")
        status_bar = tk.Label(
            self.root,
            textvariable=self.status_var,
            relief=tk.SUNKEN,
            anchor='w',
            bg='#ecf0f1',
            font=('Arial', 9)
        )
        status_bar.pack(fill='x', side='bottom')
        
        # Menu bar
        self.create_menu()
        
    def create_menu(self):
        """Create menu bar."""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Open Contract...", command=self.browse_file)
        file_menu.add_separator()
        file_menu.add_command(label="Save Results...", command=self.save_results)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
        
    def browse_file(self):
        """Open file dialog to select a contract file."""
        file_path = filedialog.askopenfilename(
            title="Select Solidity Contract File",
            filetypes=[
                ("Solidity files", "*.sol"),
                ("Bytecode files", "*.bin"),
                ("All files", "*.*")
            ]
        )
        if file_path:
            self.selected_file.set(file_path)
            
    def select_test_contract(self, path):
        """Select a test contract."""
        self.selected_file.set(path)
        
    def start_analysis(self):
        """Start the vulnerability analysis in a separate thread."""
        if not self.selected_file.get():
            messagebox.showerror("Error", "Please select a contract file first!")
            return
            
        if not os.path.exists(self.selected_file.get()):
            messagebox.showerror("Error", "Selected file does not exist!")
            return
            
        if self.analysis_running:
            messagebox.showwarning("Warning", "Analysis is already running!")
            return
            
        # Start analysis in separate thread
        self.analysis_running = True
        self.progress.start()
        self.status_var.set("Analyzing contract...")
        self.results_text.delete(1.0, tk.END)
        
        thread = threading.Thread(target=self.run_analysis)
        thread.daemon = True
        thread.start()
        
    def run_analysis(self):
        """Run the actual analysis."""
        try:
            # Import modules
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
            
            contract_file = self.selected_file.get()
            file_ext = Path(contract_file).suffix.lower()
            is_bytecode = file_ext == '.bin'
            
            perf_monitor = PerformanceMonitor()
            ast_cache = ASTCache()
            reporter = VulnerabilityReporter()
            perf_monitor.start("total_analysis")
            
            # Update UI
            self.root.after(0, self.update_results, f"🔍 Analyzing: {os.path.basename(contract_file)} ({'Bytecode' if is_bytecode else 'Solidity'})\n")
            self.root.after(0, self.update_results, "="*60 + "\n")
            
            if is_bytecode:
                parser = BytecodeParser()
                bytecode_hex = None

                # Prefer text hex (like web_app) to avoid binary misreads
                try:
                    with open(contract_file, 'r') as f:
                        text_content = f.read().strip()
                    candidate = text_content.replace('0x', '').replace(' ', '').replace('\n', '').replace('\r', '')
                    if candidate and re.fullmatch(r'[0-9a-fA-F]+', candidate):
                        bytecode_hex = candidate
                except Exception:
                    bytecode_hex = None

                if not bytecode_hex:
                    try:
                        with open(contract_file, 'rb') as f:
                            bytecode_bytes = f.read()
                        bytecode_hex = bytecode_bytes.hex()
                    except Exception as e:
                        self.root.after(0, self.update_results, f"❌ Failed to read bytecode: {e}\n")
                        return

                contract_ast = parser.parse_bytecode(bytecode_hex)
                if not contract_ast:
                    self.root.after(0, self.update_results, "❌ Failed to parse bytecode\n")
                    return
                
                detectors = [
                    BytecodeOverflowDetector(),
                    BytecodeAccessControlDetector(),
                    BytecodeReentrancyDetector(),
                    BytecodeTimeManipulationDetector(),
                    BytecodeDenialOfServiceDetector(),
                    BytecodeUnprotectedSelfDestructDetector()
                ]
            else:
                parser = SolidityParser()
                self.root.after(0, self.update_results, "✓ Initialized parser\n")
                
                # Parse contract with caching and Unicode cleaning similar to web_app
                perf_monitor.start("parsing")
                contract_ast = ast_cache.get(contract_file)
                if not contract_ast:
                    contract_ast = parser.parse_file(contract_file)
                    if not contract_ast:
                        self.root.after(0, self.update_results, "❌ Failed to parse contract\n")
                        return
                    # Clean potential Unicode artifacts in parsed content for consistency
                    if 'content' in contract_ast:
                        contract_ast['content'] = re.sub(r'[^\x00-\x7F]+', '[UNICODE]', str(contract_ast['content']))
                    ast_cache.set(contract_file, contract_ast)
                perf_monitor.end("parsing")
                
                self.root.after(0, self.update_results, f"✓ Contract parsed successfully\n")
                self.root.after(0, self.update_results, f"  - Functions found: {len(contract_ast.get('functions', []))}\n")
                self.root.after(0, self.update_results, f"  - Variables found: {len(contract_ast.get('variables', []))}\n\n")
                
                # Initialize detectors based on selection
                detectors = []
                if self.detector_vars['overflow'].get():
                    detectors.append(OverflowDetector())
                if self.detector_vars['access_control'].get():
                    detectors.append(AccessControlDetector())
                if self.detector_vars['reentrancy'].get():
                    detectors.append(ReentrancyDetector())
                if self.detector_vars['time_manipulation'].get():
                    detectors.append(TimeManipulationDetector())
                if self.detector_vars['denial_of_service'].get():
                    detectors.append(DenialOfServiceDetector())
                if self.detector_vars['unprotected_selfdestruct'].get():
                    detectors.append(UnprotectedSelfDestructDetector())
            
            # Run detectors in parallel
            perf_monitor.start("detection")
            all_vulnerabilities = parallel_detect(detectors, contract_ast)
            perf_monitor.end("detection")
            
            # Advanced analysis modules
            advanced_results = {}
            
            if self.enable_fuzzing.get():
                if is_bytecode:
                    advanced_results['fuzzing'] = {
                        'error': 'Fuzzing only works with Solidity files, not bytecode',
                        'metrics': {'functions_tested': 0, 'iterations': 0, 'vulnerabilities_found': 0}
                    }
                    self.root.after(0, self.update_results, "ℹ️  Fuzzing is only available for Solidity files\n")
                else:
                    try:
                        from analysis.fuzzer import Fuzzer
                        fuzzer = Fuzzer()
                        fuzzer.enable()
                        fuzzing_results = fuzzer.analyze(contract_ast)
                        advanced_results['fuzzing'] = fuzzing_results
                        if 'vulnerabilities' in fuzzing_results:
                            all_vulnerabilities.extend(fuzzing_results['vulnerabilities'])
                        self.root.after(0, self.update_results, "✓ Fuzzing analysis completed\n")
                    except ImportError:
                        self.root.after(0, self.update_results, "⚠️  Fuzzing module not available\n")
                    except Exception as e:
                        self.root.after(0, self.update_results, f"⚠️  Fuzzing failed: {e}\n")
            
            if self.enable_cfg.get():
                try:
                    from analysis.control_flow import ControlFlowAnalyzer, DataFlowAnalyzer
                    cfg_analyzer = ControlFlowAnalyzer()
                    cfg_analyzer.enable()
                    cfg_results = cfg_analyzer.analyze(contract_ast)
                    
                    df_analyzer = DataFlowAnalyzer()
                    df_analyzer.enable()
                    df_results = df_analyzer.analyze(contract_ast)
                    
                    advanced_results['control_flow'] = cfg_results
                    advanced_results['data_flow'] = df_results
                    self.root.after(0, self.update_results, "✓ Control/Data-flow analysis completed\n")
                except ImportError:
                    self.root.after(0, self.update_results, "⚠️  Control/Data-flow module not available\n")
                except Exception as e:
                    self.root.after(0, self.update_results, f"⚠️  Control/Data-flow failed: {e}\n")
            
            if self.enable_optimization.get():
                if is_bytecode:
                    try:
                        from src.optimization.optimizer import BytecodeOptimizer
                        perf_monitor.start("optimization")
                        optimizer = BytecodeOptimizer()
                        optimization_results = optimizer.detect(contract_ast.get('opcodes', []), contract_ast)
                        gas_analysis = optimizer.analyze_gas_usage(contract_ast.get('opcodes', []))
                        savings = optimizer.calculate_potential_savings(optimization_results)
                        
                        advanced_results['optimization'] = {
                            'optimizations': optimization_results,
                            'gas_analysis': gas_analysis,
                            'potential_savings': savings
                        }
                        perf_monitor.end("optimization")
                        self.root.after(0, self.update_results, f"✓ Optimization analysis completed: {len(optimization_results)} opportunities\n")
                    except ImportError:
                        self.root.after(0, self.update_results, "⚠️  Optimization module not available\n")
                    except Exception as e:
                        self.root.after(0, self.update_results, f"⚠️  Optimization analysis failed: {e}\n")
                else:
                    advanced_results['optimization'] = {
                        'error': 'Optimization analysis is only available for bytecode files, not Solidity',
                        'metrics': {'optimizations_found': 0, 'total_savings': 0}
                    }
                    self.root.after(0, self.update_results, "ℹ️  Optimization available for bytecode (.bin) files only\n")
            
            if self.enable_formal.get():
                self.root.after(0, self.update_results, "ℹ️  Formal verification module not yet implemented\n")
            
            # Generate report
            perf_monitor.start("reporting")
            report = reporter.generate_report(all_vulnerabilities, contract_file)
            if advanced_results:
                report['advanced_analysis'] = advanced_results
            perf_monitor.end("reporting")
            
            perf_monitor.end("total_analysis")
            report['performance'] = perf_monitor.get_metrics()
            
            # Display textual report (hide advanced analysis sections in the UI)
            display_report = dict(report)
            display_report.pop('advanced_analysis', None)
            text_report = json.dumps(display_report, indent=2)
            self.root.after(0, self.update_results, text_report + "\n")
            
            # Store results for saving
            self.last_results = report
            
        except UnicodeDecodeError as e:
            error_msg = f"❌ Encoding Error: The file contains characters that cannot be decoded.\n\n💡 Solution: Try saving the file with UTF-8 encoding in your text editor.\n\nError details: {str(e)}\n"
            self.root.after(0, self.update_results, error_msg)
        except Exception as e:
            self.root.after(0, self.update_results, f"❌ Error during analysis: {str(e)}\n")
            
        finally:
            # Stop progress bar and update status
            self.root.after(0, self.stop_analysis)
            
    def update_results(self, text):
        """Update the results text area."""
        self.results_text.insert(tk.END, text)
        self.results_text.see(tk.END)
        
    def stop_analysis(self):
        """Stop the analysis and update UI."""
        self.progress.stop()
        self.analysis_running = False
        self.status_var.set("Analysis completed")
        
    def save_results(self):
        """Save analysis results to file."""
        if not hasattr(self, 'last_results'):
            messagebox.showwarning("Warning", "No analysis results to save!")
            return
            
        file_path = filedialog.asksaveasfilename(
            title="Save Analysis Results",
            defaultextension=".json",
            filetypes=[
                ("JSON files", "*.json"),
                ("Text files", "*.txt"),
                ("All files", "*.*")
            ]
        )
        
        if file_path:
            try:
                if file_path.endswith('.json'):
                    with open(file_path, 'w') as f:
                        json.dump(self.last_results, f, indent=2)
                else:
                    with open(file_path, 'w') as f:
                        f.write(self.results_text.get(1.0, tk.END))
                        
                messagebox.showinfo("Success", f"Results saved to: {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save results: {str(e)}")
                
    def show_about(self):
        """Show about dialog."""
        about_text = """
Smart Contract Vulnerability Detection System
Version 1.0

A comprehensive tool for detecting common vulnerabilities in Solidity smart contracts:
• Integer Overflow/Underflow Detection
• Access Control Issues
• Reentrancy Vulnerabilities
• Time Manipulation Vulnerabilities
• Denial of Service Vulnerabilities
• Unprotected Selfdestruct Vulnerabilities

Developed for Final Year Project (FYP)
        """
        messagebox.showinfo("About", about_text)

def main():
    """Main function to run the GUI application."""
    root = tk.Tk()
    app = VulnerabilityDetectorGUI(root)
    
    # Center the window
    root.update_idletasks()
    x = (root.winfo_screenwidth() - root.winfo_width()) // 2
    y = (root.winfo_screenheight() - root.winfo_height()) // 2
    root.geometry(f"+{x}+{y}")
    
    root.mainloop()

if __name__ == "__main__":
    main()
