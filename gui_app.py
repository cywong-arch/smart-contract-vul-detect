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
from pathlib import Path

# Add src to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

class VulnerabilityDetectorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Smart Contract Vulnerability Detection System")
        self.root.geometry("900x700")
        self.root.configure(bg='#f0f0f0')
        
        # Variables
        self.selected_file = tk.StringVar()
        self.analysis_running = False
        
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
            font=('Consolas', 10),
            bg='#2c3e50',
            fg='#ecf0f1',
            insertbackground='white'
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
            from parsers.solidity_parser import SolidityParser
            from detectors.overflow_detector import OverflowDetector
            from detectors.access_control_detector import AccessControlDetector
            from detectors.reentrancy_detector import ReentrancyDetector
            from detectors.time_manipulation_detector import TimeManipulationDetector
            from detectors.denial_of_service_detector import DenialOfServiceDetector
            from detectors.unprotected_selfdestruct_detector import UnprotectedSelfDestructDetector
            
            contract_file = self.selected_file.get()
            
            # Update UI
            self.root.after(0, self.update_results, f"🔍 Analyzing: {os.path.basename(contract_file)}\n")
            self.root.after(0, self.update_results, "="*60 + "\n")
            
            # Initialize parser
            parser = SolidityParser()
            self.root.after(0, self.update_results, "✓ Initialized parser\n")
            
            # Parse contract
            contract_ast = parser.parse_file(contract_file)
            if not contract_ast:
                self.root.after(0, self.update_results, "❌ Failed to parse contract\n")
                return
                
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
                
            # Run detectors
            all_vulnerabilities = []
            detector_results = {}
            
            for detector in detectors:
                detector_name = detector.__class__.__name__
                self.root.after(0, self.update_results, f"🔍 Running {detector_name}...\n")
                
                vulnerabilities = detector.detect(contract_ast)
                all_vulnerabilities.extend(vulnerabilities)
                detector_results[detector_name] = len(vulnerabilities)
                
                if vulnerabilities:
                    self.root.after(0, self.update_results, f"  ⚠️  Found {len(vulnerabilities)} issues\n")
                else:
                    self.root.after(0, self.update_results, f"  ✅ No issues found\n")
                    
            # Display summary
            self.root.after(0, self.update_results, f"\n📊 Analysis Summary:\n")
            self.root.after(0, self.update_results, "="*60 + "\n")
            self.root.after(0, self.update_results, f"Total vulnerabilities: {len(all_vulnerabilities)}\n")
            
            for detector_name, count in detector_results.items():
                self.root.after(0, self.update_results, f"{detector_name}: {count} issues\n")
                
            # Display vulnerability details
            if all_vulnerabilities:
                self.root.after(0, self.update_results, f"\n⚠️  Vulnerability Details:\n")
                self.root.after(0, self.update_results, "="*60 + "\n")
                
                for i, vuln in enumerate(all_vulnerabilities, 1):
                    self.root.after(0, self.update_results, f"{i}. {vuln.get('type', 'Unknown')}\n")
                    self.root.after(0, self.update_results, f"   Description: {vuln.get('description', 'No description')}\n")
                    if vuln.get('recommendation'):
                        self.root.after(0, self.update_results, f"   💡 Fix: {vuln.get('recommendation')}\n")
                    self.root.after(0, self.update_results, "\n")
            else:
                self.root.after(0, self.update_results, f"\n✅ No vulnerabilities detected! Contract appears secure.\n")
                
            # Store results for saving
            self.last_results = {
                'contract_file': contract_file,
                'total_vulnerabilities': len(all_vulnerabilities),
                'detector_results': detector_results,
                'vulnerabilities': all_vulnerabilities
            }
            
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
