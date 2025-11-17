#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Smart Contract Vulnerability Detection System - Web Application
A web-based interface for the vulnerability detection system using Flask.
"""

# Force UTF-8 encoding for the entire script
import sys
import os
import locale

# Set UTF-8 encoding before importing anything else
if sys.platform.startswith('win'):
    os.environ['PYTHONIOENCODING'] = 'utf-8'
    os.environ['LC_ALL'] = 'en_US.UTF-8'
    os.environ['LANG'] = 'en_US.UTF-8'
    
    # Force UTF-8 locale
    try:
        locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')
    except:
        try:
            locale.setlocale(locale.LC_ALL, 'C.UTF-8')
        except:
            pass

from flask import Flask, render_template_string, request, jsonify, send_file
from flask_cors import CORS
import json
import re
import tempfile
from pathlib import Path

# Add src to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# Import performance utilities
from utils.performance import PerformanceMonitor, ASTCache, parallel_detect

def clean_unicode_data(data):
    """Clean Unicode characters that might cause encoding issues."""
    if isinstance(data, dict):
        return {key: clean_unicode_data(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [clean_unicode_data(item) for item in data]
    elif isinstance(data, str):
        # Replace problematic Unicode characters with safe alternatives
        replacements = {
            '✅': '[OK]',
            '❌': '[ERROR]',
            '⚠️': '[WARNING]',
            '🔍': '[INFO]',
            '💡': '[TIP]',
            '🚀': '[START]',
            '📊': '[RESULTS]',
            '🔧': '[TOOLS]',
            '→': '->',  # This is the main culprit!
            '←': '<-',
            '↑': '^',
            '↓': 'v',
            '✓': '[CHECK]',
            '🎯': '[TARGET]',
            '🛡️': '[SECURE]',
            '⚡': '[FAST]',
            '🔒': '[LOCKED]',
            '🔓': '[UNLOCKED]',
            '🎉': '[SUCCESS]',
            '🚨': '[ALERT]',
            '📝': '[NOTE]',
            '🔐': '[SECURITY]',
            '⚙️': '[CONFIG]',
            '📈': '[STATS]',
            '🔔': '[NOTIFICATION]',
            '🌟': '[STAR]',
            '💎': '[DIAMOND]',
            '🔥': '[FIRE]',
            '⭐': '[STAR]',
            '🎊': '[CELEBRATION]',
            '🎁': '[GIFT]',
            '🏆': '[TROPHY]',
            '🎪': '[CIRCUS]',
            '🎨': '[ART]',
            '🎭': '[THEATER]',
            '🎬': '[MOVIE]',
            '🎵': '[MUSIC]',
            '🎶': '[MUSIC]',
            '🎸': '[GUITAR]',
            '🎹': '[PIANO]',
            '🎺': '[TRUMPET]',
            '🎻': '[VIOLIN]',
            '🥁': '[DRUM]',
            '🎤': '[MICROPHONE]',
            '🎧': '[HEADPHONES]',
            '📻': '[RADIO]',
            '📺': '[TV]',
            '📷': '[CAMERA]',
            '📹': '[VIDEO]',
            '📱': '[PHONE]',
            '💻': '[LAPTOP]',
            '🖥️': '[COMPUTER]',
            '⌨️': '[KEYBOARD]',
            '🖱️': '[MOUSE]',
            '🖨️': '[PRINTER]',
            '💽': '[DISK]',
            '💾': '[SAVE]',
            '💿': '[CD]',
            '📀': '[DVD]',
            '🧮': '[CALCULATOR]',
            '🎲': '[DICE]',
            '♠️': '[SPADE]',
            '♥️': '[HEART]',
            '♦️': '[DIAMOND]',
            '♣️': '[CLUB]',
            '🃏': '[JOKER]',
            '🀄': '[MAHJONG]',
            '🎴': '[CARDS]',
            '🎯': '[TARGET]',
            '🎳': '[BOWLING]',
            '🎮': '[GAME]',
            '🕹️': '[JOYSTICK]',
            '🎰': '[SLOT]',
            '🧩': '[PUZZLE]',
            '–': '-',  # This is the other culprit at position 31758!
            '—': '-',
            '…': '...',
            '"': '"',
            '"': '"',
            ''': "'",
            ''': "'"
        }
        
        cleaned = data
        for unicode_char, replacement in replacements.items():
            cleaned = cleaned.replace(unicode_char, replacement)
        
        # Remove any remaining problematic characters more aggressively
        cleaned = re.sub(r'[^\x00-\x7F]+', '[UNICODE]', cleaned)
        
        # Double-check: if there are still Unicode characters, replace them all
        if any(ord(char) > 127 for char in cleaned):
            cleaned = re.sub(r'[^\x00-\x7F]+', '[UNICODE]', cleaned)
        
        return cleaned
    else:
        return data

def ensure_ascii_safe(data):
    """Ensure all data is ASCII-safe for JSON encoding."""
    if isinstance(data, dict):
        return {key: ensure_ascii_safe(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [ensure_ascii_safe(item) for item in data]
    elif isinstance(data, str):
        # Convert to ASCII, replacing any non-ASCII characters
        try:
            return data.encode('ascii', 'replace').decode('ascii')
        except:
            return str(data).encode('ascii', 'replace').decode('ascii')
    else:
        return data

app = Flask(__name__)
CORS(app)  # Enable CORS for Remix IDE integration

# Initialize performance cache
ast_cache = ASTCache()
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['JSON_AS_ASCII'] = False  # Allow Unicode in JSON responses
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False  # Disable pretty printing to avoid encoding issues

# Force UTF-8 encoding for JSON responses
import json
from flask import jsonify as original_jsonify

def safe_jsonify(*args, **kwargs):
    """Safe JSON response that handles Unicode properly."""
    # Always clean the data first, regardless of whether there's an error
    if args and len(args) == 1 and isinstance(args[0], dict):
        # Clean the data before attempting to serialize
        cleaned_data = clean_unicode_data(args[0])
        cleaned_data = ensure_ascii_safe(cleaned_data)
        
        try:
            return original_jsonify(cleaned_data, **kwargs)
        except (UnicodeEncodeError, UnicodeDecodeError, UnicodeError):
            # If still fails, use manual JSON encoding
            json_str = json.dumps(cleaned_data, ensure_ascii=True, indent=2)
            from flask import Response
            return Response(json_str, mimetype='application/json; charset=utf-8')
    else:
        # For non-dict arguments, try normal jsonify first
        try:
            return original_jsonify(*args, **kwargs)
        except (UnicodeEncodeError, UnicodeDecodeError, UnicodeError):
            # Fallback to manual JSON encoding
            response_data = args[0] if args else {}
            cleaned_data = clean_unicode_data(response_data)
            cleaned_data = ensure_ascii_safe(cleaned_data)
            json_str = json.dumps(cleaned_data, ensure_ascii=True, indent=2)
            from flask import Response
            return Response(json_str, mimetype='application/json; charset=utf-8')

# Replace the default jsonify with our safe version
import flask
flask.jsonify = safe_jsonify

# HTML template
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Smart Contract Vulnerability Detection System</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header p {
            opacity: 0.9;
            font-size: 1.1em;
        }
        
        .main-content {
            padding: 40px;
        }
        
        .upload-section {
            background: #f8f9fa;
            border-radius: 10px;
            padding: 30px;
            margin-bottom: 30px;
            border: 2px dashed #dee2e6;
            text-align: center;
        }
        
        .upload-section.dragover {
            border-color: #007bff;
            background: #e3f2fd;
        }
        
        .file-input-wrapper {
            position: relative;
            display: inline-block;
            margin: 20px 0;
        }
        
        .file-input {
            position: absolute;
            opacity: 0;
            width: 100%;
            height: 100%;
            cursor: pointer;
        }
        
        .file-input-button {
            background: #007bff;
            color: white;
            padding: 12px 30px;
            border-radius: 25px;
            border: none;
            cursor: pointer;
            font-size: 16px;
            transition: all 0.3s;
        }
        
        .file-input-button:hover {
            background: #0056b3;
            transform: translateY(-2px);
        }
        
        .quick-select {
            margin: 20px 0;
        }
        
        .quick-select h3 {
            margin-bottom: 15px;
            color: #2c3e50;
        }
        
        .test-contract-btn {
            background: #6c757d;
            color: white;
            border: none;
            padding: 8px 16px;
            margin: 5px;
            border-radius: 20px;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .test-contract-btn:hover {
            background: #5a6268;
            transform: translateY(-1px);
        }
        
        .options-section {
            background: #f8f9fa;
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 30px;
        }
        
        .detector-options {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        
        .detector-option {
            background: white;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #007bff;
        }
        
        .detector-option input[type="checkbox"] {
            margin-right: 10px;
            transform: scale(1.2);
        }
        
        .analyze-btn {
            background: linear-gradient(135deg, #28a745 0%, #20c997 100%);
            color: white;
            border: none;
            padding: 15px 40px;
            font-size: 18px;
            border-radius: 30px;
            cursor: pointer;
            transition: all 0.3s;
            display: block;
            margin: 30px auto;
        }
        
        .analyze-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(40, 167, 69, 0.3);
        }
        
        .analyze-btn:disabled {
            background: #6c757d;
            cursor: not-allowed;
            transform: none;
        }
        
        .loading {
            text-align: center;
            padding: 40px;
            display: none;
        }
        
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #007bff;
            border-radius: 50%;
            width: 50px;
            height: 50px;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .results-section {
            margin-top: 30px;
            display: none;
        }
        
        .results-header {
            background: #2c3e50;
            color: white;
            padding: 20px;
            border-radius: 10px 10px 0 0;
        }
        
        .results-content {
            background: #1e1e1e;
            color: #f8f9fa;
            padding: 20px;
            font-family: 'Courier New', monospace;
            white-space: pre-wrap;
            max-height: 500px;
            overflow-y: auto;
            border-radius: 0 0 10px 10px;
        }
        
        .vulnerability-high { color: #dc3545; }
        .vulnerability-medium { color: #ffc107; }
        .vulnerability-low { color: #17a2b8; }
        .success-text { color: #28a745; }
        
        .download-btn {
            background: #17a2b8;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            margin: 10px 5px;
        }
        
        .download-btn:hover {
            background: #138496;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Smart Contract Vulnerability Detection</h1>
            <p>Analyze Solidity smart contracts for common security vulnerabilities</p>
        </div>
        
        <div class="main-content">
            <div class="upload-section" id="uploadSection">
                <h3>📁 Select Contract File</h3>
                <p>Upload a Solidity (.sol) or Bytecode (.bin) file or drag and drop it here</p>
                
                <div class="file-input-wrapper">
                    <input type="file" id="fileInput" class="file-input" accept=".sol,.bin" />
                    <button class="file-input-button">Choose File</button>
                </div>
                
                <div id="selectedFile" style="margin-top: 15px; font-weight: bold;"></div>
                
                <div class="quick-select">
                    <h3>🚀 Quick Select Test Contracts</h3>
                    <button class="test-contract-btn" onclick="selectTestContract('vulnerable_overflow.sol')">Overflow Vulnerable</button>
                    <button class="test-contract-btn" onclick="selectTestContract('vulnerable_access_control.sol')">Access Control Vulnerable</button>
                    <button class="test-contract-btn" onclick="selectTestContract('vulnerable_reentrancy.sol')">Reentrancy Vulnerable</button>
                    <button class="test-contract-btn" onclick="selectTestContract('vulnerable_time_manipulation.sol')">Time Manipulation Vulnerable</button>
                    <button class="test-contract-btn" onclick="selectTestContract('vulnerable_denial_of_service.sol')">DoS Vulnerable</button>
                    <button class="test-contract-btn" onclick="selectTestContract('vulnerable_unprotected_selfdestruct.sol')">Selfdestruct Vulnerable</button>
                    <h4 style="margin-top: 15px; margin-bottom: 10px;">📦 Bytecode Test Contracts</h4>
                    <button class="test-contract-btn" onclick="selectTestContract('test_reentrancy_only.bin')">Bytecode Reentrancy</button>
                    <button class="test-contract-btn" onclick="selectTestContract('test_overflow_only.bin')">Bytecode Overflow</button>
                    <button class="test-contract-btn" onclick="selectTestContract('test_access_control_only.bin')">Bytecode Access Control</button>
                    <button class="test-contract-btn" onclick="selectTestContract('test_time_manipulation_only.bin')">Bytecode Time Manipulation</button>
                    <button class="test-contract-btn" onclick="selectTestContract('test_unprotected_selfdestruct_only.bin')">Bytecode Selfdestruct</button>
                    <button class="test-contract-btn" onclick="selectTestContract('test_denial_of_service_only.bin')">Bytecode DoS</button>
                </div>
            </div>
            
            <div class="options-section">
                <h3>🔧 Detection Options</h3>
                <div class="detector-options">
                    <div class="detector-option">
                        <input type="checkbox" id="overflow" checked>
                        <label for="overflow">
                            <strong>Integer Overflow/Underflow</strong><br>
                            <small>Detects unsafe arithmetic operations</small>
                        </label>
                    </div>
                    <div class="detector-option">
                        <input type="checkbox" id="access_control" checked>
                        <label for="access_control">
                            <strong>Access Control Issues</strong><br>
                            <small>Finds missing access modifiers</small>
                        </label>
                    </div>
                    <div class="detector-option">
                        <input type="checkbox" id="reentrancy" checked>
                        <label for="reentrancy">
                            <strong>Reentrancy Vulnerabilities</strong><br>
                            <small>Identifies reentrancy attack vectors</small>
                        </label>
                    </div>
                    <div class="detector-option">
                        <input type="checkbox" id="time_manipulation" checked>
                        <label for="time_manipulation">
                            <strong>Time Manipulation</strong><br>
                            <small>Detects time-based vulnerabilities</small>
                        </label>
                    </div>
                    <div class="detector-option">
                        <input type="checkbox" id="denial_of_service" checked>
                        <label for="denial_of_service">
                            <strong>Denial of Service</strong><br>
                            <small>Identifies DoS attack vectors</small>
                        </label>
                    </div>
                    <div class="detector-option">
                        <input type="checkbox" id="unprotected_selfdestruct" checked>
                        <label for="unprotected_selfdestruct">
                            <strong>Unprotected Selfdestruct</strong><br>
                            <small>Finds unprotected selfdestruct calls</small>
                        </label>
                    </div>
                </div>
                
                <h3 style="margin-top: 20px; margin-bottom: 10px;">🧪 Advanced Analysis</h3>
                <div class="detector-options">
                    <div class="detector-option">
                        <input type="checkbox" id="enable_fuzzing">
                        <label for="enable_fuzzing">
                            <strong>Fuzzing (Dynamic Analysis)</strong><br>
                            <small>Generate test inputs and detect input-dependent vulnerabilities</small>
                        </label>
                    </div>
                    <div class="detector-option">
                        <input type="checkbox" id="enable_optimization">
                        <label for="enable_optimization">
                            <strong>Bytecode Optimization</strong><br>
                            <small>Detect gas optimization opportunities (bytecode files only)</small>
                        </label>
                    </div>
                </div>
            </div>
            
            <button class="analyze-btn" id="analyzeBtn" onclick="startAnalysis()">
                🚀 Start Analysis
            </button>
            
            <div class="loading" id="loading">
                <div class="spinner"></div>
                <p>Analyzing contract... Please wait</p>
            </div>
            
            <div class="results-section" id="resultsSection">
                <div class="results-header">
                    <h3>📊 Analysis Results</h3>
                    <button class="download-btn" onclick="downloadResults('json')">Download JSON</button>
                    <button class="download-btn" onclick="downloadResults('txt')">Download Text</button>
                </div>
                <div class="results-content" id="resultsContent"></div>
            </div>
        </div>
    </div>
    
    <script>
        let currentFile = null;
        let analysisResults = null;
        
        // File input handling
        document.getElementById('fileInput').addEventListener('change', function(e) {
            if (e.target.files.length > 0) {
                currentFile = e.target.files[0];
                document.getElementById('selectedFile').textContent = `Selected: ${currentFile.name}`;
            }
        });
        
        // Drag and drop handling
        const uploadSection = document.getElementById('uploadSection');
        
        uploadSection.addEventListener('dragover', function(e) {
            e.preventDefault();
            uploadSection.classList.add('dragover');
        });
        
        uploadSection.addEventListener('dragleave', function(e) {
            e.preventDefault();
            uploadSection.classList.remove('dragover');
        });
        
        uploadSection.addEventListener('drop', function(e) {
            e.preventDefault();
            uploadSection.classList.remove('dragover');
            
            if (e.dataTransfer.files.length > 0) {
                currentFile = e.dataTransfer.files[0];
                document.getElementById('selectedFile').textContent = `Selected: ${currentFile.name}`;
                document.getElementById('fileInput').files = e.dataTransfer.files;
            }
        });
        
        function selectTestContract(filename) {
            document.getElementById('selectedFile').textContent = `Selected: ${filename}`;
            currentFile = { name: filename, isTestContract: true };
        }
        
        async function startAnalysis() {
            if (!currentFile) {
                alert('Please select a contract file first!');
                return;
            }
            
            // Show loading
            document.getElementById('analyzeBtn').disabled = true;
            document.getElementById('loading').style.display = 'block';
            document.getElementById('resultsSection').style.display = 'none';
            
            try {
                const formData = new FormData();
                
                if (currentFile.isTestContract) {
                    formData.append('test_contract', currentFile.name);
                } else {
                    formData.append('file', currentFile);
                }
                
                // Get selected detectors
                const detectors = [];
                if (document.getElementById('overflow').checked) detectors.push('overflow');
                if (document.getElementById('access_control').checked) detectors.push('access_control');
                if (document.getElementById('reentrancy').checked) detectors.push('reentrancy');
                if (document.getElementById('time_manipulation').checked) detectors.push('time_manipulation');
                if (document.getElementById('denial_of_service').checked) detectors.push('denial_of_service');
                if (document.getElementById('unprotected_selfdestruct').checked) detectors.push('unprotected_selfdestruct');
                
                formData.append('detectors', JSON.stringify(detectors));
                
                // Get advanced analysis options
                const enable_fuzzing = document.getElementById('enable_fuzzing').checked;
                const enable_optimization = document.getElementById('enable_optimization').checked;
                console.log('Fuzzing enabled:', enable_fuzzing);
                console.log('Optimization enabled:', enable_optimization);
                formData.append('enable_fuzzing', enable_fuzzing ? 'true' : 'false');
                formData.append('enable_optimization', enable_optimization ? 'true' : 'false');
                
                const response = await fetch('/analyze', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                
                if (result.success) {
                    analysisResults = result.data;
                    displayResults(result.data);
                } else {
                    alert('Error: ' + result.error);
                }
                
            } catch (error) {
                alert('Error during analysis: ' + error.message);
            } finally {
                document.getElementById('analyzeBtn').disabled = false;
                document.getElementById('loading').style.display = 'none';
            }
        }
        
        function displayResults(results) {
            const content = document.getElementById('resultsContent');
            const section = document.getElementById('resultsSection');
            
            let output = `🔍 Analysis Results for: ${results.contract_file}\n`;
            output += `${'='.repeat(60)}\n\n`;
            
            output += `📊 Summary:\n`;
            output += `Total Vulnerabilities: ${results.total_vulnerabilities}\n`;
            
            for (const [detector, count] of Object.entries(results.detector_results)) {
                output += `${detector}: ${count} issues\n`;
            }
            
            // Show fuzzing metrics if available (always show if fuzzing was attempted)
            if (results.advanced_analysis && results.advanced_analysis.fuzzing) {
                const fuzzing = results.advanced_analysis.fuzzing;
                const metrics = fuzzing.metrics || {};
                
                output += `\n🧪 Fuzzing Analysis:\n`;
                
                // Show error if fuzzing failed
                if (fuzzing.error) {
                    output += `  ⚠️  ${fuzzing.error}\n`;
                } else {
                    output += `  Functions tested: ${metrics.functions_tested || 0}\n`;
                    output += `  Iterations: ${metrics.iterations || 0}\n`;
                    output += `  Fuzzing vulnerabilities: ${metrics.vulnerabilities_found || 0}\n`;
                    
                    if (metrics.vulnerabilities_found === 0) {
                        output += `  ✅ No input-dependent vulnerabilities found\n`;
                    }
                    
                    // Show warnings if any
                    if (fuzzing.warnings && fuzzing.warnings.length > 0) {
                        fuzzing.warnings.forEach(warning => {
                            output += `  ⚠️  ${warning}\n`;
                        });
                    }
                }
            } else {
                // Show message if fuzzing checkbox was not checked
                output += `\n🧪 Fuzzing Analysis: Not enabled\n`;
                output += `  (Enable "Fuzzing (Dynamic Analysis)" checkbox to use)\n`;
            }
            
            // Show optimization metrics if available
            if (results.advanced_analysis && results.advanced_analysis.optimization) {
                const optimization = results.advanced_analysis.optimization;
                
                output += `\n🔧 Optimization Analysis:\n`;
                
                // Show error if optimization failed
                if (optimization.error) {
                    output += `  ⚠️  ${optimization.error}\n`;
                } else {
                    const gasAnalysis = optimization.gas_analysis || {};
                    const savings = optimization.potential_savings || {};
                    const optimizations = optimization.optimizations || [];
                    
                    if (gasAnalysis.total_gas) {
                        output += `  📊 Gas Usage:\n`;
                        output += `    Total Estimated Gas: ${gasAnalysis.total_gas.toLocaleString()}\n`;
                        output += `    Total Opcodes: ${gasAnalysis.total_opcodes || 0}\n`;
                    }
                    
                    if (savings.total_potential_savings) {
                        output += `  💰 Potential Savings:\n`;
                        output += `    Total: ${savings.total_potential_savings.toLocaleString()} gas\n`;
                        output += `    Opportunities: ${savings.optimization_count || 0}\n`;
                    }
                    
                    if (optimizations.length > 0) {
                        output += `\n  🔧 Optimization Opportunities:\n`;
                        optimizations.forEach((opt, idx) => {
                            output += `    ${idx + 1}. ${opt.type || 'Unknown'} (${opt.severity || 'Unknown'})\n`;
                            output += `       Description: ${opt.description || 'No description'}\n`;
                            output += `       Potential Savings: ${opt.gas_savings || 0} gas\n`;
                            if (opt.recommendation) {
                                output += `       💡 ${opt.recommendation}\n`;
                            }
                        });
                    } else {
                        output += `  ✅ No optimization opportunities found\n`;
                    }
                }
            } else if (results.advanced_analysis) {
                // Show message if optimization checkbox was not checked
                output += `\n🔧 Optimization Analysis: Not enabled\n`;
                output += `  (Enable "Bytecode Optimization" checkbox to use)\n`;
            }
            
            // Show performance metrics if available
            if (results.performance) {
                output += `\n⚡ Performance Metrics:\n`;
                for (const [operation, time] of Object.entries(results.performance)) {
                    output += `  ${operation}: ${time.toFixed(3)}s\n`;
                }
            }
            
            if (results.vulnerabilities.length > 0) {
                output += `\n⚠️  Vulnerability Details:\n`;
                output += `${'='.repeat(60)}\n`;
                
                results.vulnerabilities.forEach((vuln, index) => {
                    output += `${index + 1}. ${vuln.type || 'Unknown'}\n`;
                    output += `   Description: ${vuln.description || 'No description'}\n`;
                    if (vuln.recommendation) {
                        output += `   💡 Fix: ${vuln.recommendation}\n`;
                    }
                    output += `\n`;
                });
            } else {
                output += `\n✅ No vulnerabilities detected! Contract appears secure.\n`;
            }
            
            content.textContent = output;
            section.style.display = 'block';
        }
        
        function downloadResults(format) {
            if (!analysisResults) {
                alert('No analysis results to download!');
                return;
            }
            
            const url = `/download?format=${format}`;
            const link = document.createElement('a');
            link.href = url;
            link.download = `analysis_results.${format}`;
            link.click();
        }
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    """Serve the main page."""
    return render_template_string(HTML_TEMPLATE)

@app.route('/analyze', methods=['POST'])
def analyze():
    """Analyze the uploaded contract."""
    try:
        # Set up Unicode-safe environment
        import os
        import sys
        
        # Set environment variables for Unicode handling
        os.environ['PYTHONIOENCODING'] = 'utf-8'
        
        # Force UTF-8 encoding for the entire request
        import locale
        try:
            locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')
        except:
            pass  # If locale setting fails, continue
        
        # Note: Console encoding is handled by Flask automatically
        # Import modules
        from parsers.solidity_parser import SolidityParser
        from parsers.bytecode_parser import BytecodeParser
        from detectors.overflow_detector import OverflowDetector
        from detectors.access_control_detector import AccessControlDetector
        from detectors.reentrancy_detector import ReentrancyDetector
        from detectors.time_manipulation_detector import TimeManipulationDetector
        from detectors.denial_of_service_detector import DenialOfServiceDetector
        from detectors.unprotected_selfdestruct_detector import UnprotectedSelfDestructDetector
        from detectors.bytecode_overflow_detector import BytecodeOverflowDetector
        from detectors.bytecode_access_control_detector import BytecodeAccessControlDetector
        from detectors.bytecode_reentrancy_detector import BytecodeReentrancyDetector
        from detectors.bytecode_time_manipulation_detector import BytecodeTimeManipulationDetector
        from detectors.bytecode_unprotected_selfdestruct_detector import BytecodeUnprotectedSelfDestructDetector
        from detectors.bytecode_denial_of_service_detector import BytecodeDenialOfServiceDetector
        
        # Get detectors selection
        detectors_json = request.form.get('detectors', '[]')
        selected_detectors = json.loads(detectors_json)
        
        # Get advanced analysis options
        enable_fuzzing_str = request.form.get('enable_fuzzing', 'false')
        enable_fuzzing = enable_fuzzing_str.lower() == 'true'
        enable_optimization_str = request.form.get('enable_optimization', 'false')
        enable_optimization = enable_optimization_str.lower() == 'true'
        print(f"DEBUG: enable_fuzzing form value: '{enable_fuzzing_str}', parsed: {enable_fuzzing}")
        print(f"DEBUG: enable_optimization form value: '{enable_optimization_str}', parsed: {enable_optimization}")
        
        # Get contract file
        contract_content = None
        contract_filename = None
        
        if 'test_contract' in request.form:
            # Use test contract
            test_contract = request.form['test_contract']
            contract_path = os.path.join('test_contracts', test_contract)
            
            if not os.path.exists(contract_path):
                return jsonify({'success': False, 'error': f'Test contract not found: {test_contract}'})
            
            contract_filename = test_contract
            file_ext = os.path.splitext(test_contract)[1].lower()
            
            if file_ext == '.bin':
                # Read bytecode file - try as text first (hex string), then as binary
                try:
                    # Try reading as text (hex string)
                    with open(contract_path, 'r') as f:
                        hex_content = f.read().strip()
                    # Remove 0x prefix if present and clean whitespace
                    hex_content = hex_content.replace('0x', '').replace(' ', '').replace('\n', '').replace('\r', '').replace('\t', '')
                    # Validate it's a valid hex string
                    if all(c in '0123456789abcdefABCDEF' for c in hex_content):
                        contract_content = hex_content
                    else:
                        raise ValueError("Not a valid hex string")
                except:
                    # If text reading fails, try as binary
                    with open(contract_path, 'rb') as f:
                        bytecode_bytes = f.read()
                    contract_content = bytecode_bytes.hex()
            else:
                # Read Solidity file
                with open(contract_path, 'r') as f:
                    contract_content = f.read()
            
        elif 'file' in request.files:
            # Use uploaded file
            file = request.files['file']
            if file.filename == '':
                return jsonify({'success': False, 'error': 'No file selected'})
                
            contract_filename = file.filename
            # Auto-detect file type
            file_ext = os.path.splitext(contract_filename)[1].lower()
            
            if file_ext == '.bin':
                # Bytecode file - read as binary/hex
                contract_content = file.read()
                # Try to decode as hex string
                try:
                    if isinstance(contract_content, bytes):
                        contract_content = contract_content.decode('utf-8', errors='ignore').strip()
                except:
                    # If it's pure binary, convert to hex
                    contract_content = contract_content.hex()
            else:
                # Solidity file - read as text
                contract_content = file.read().decode('utf-8')
        else:
            return jsonify({'success': False, 'error': 'No file provided'})
        
        # Auto-detect file type from filename (already set above for test contracts)
        if 'test_contract' not in request.form:
            file_ext = os.path.splitext(contract_filename)[1].lower() if contract_filename else '.sol'
        
        # Save to temporary file for parsing
        if file_ext == '.bin':
            # Bytecode file - save as binary
            with tempfile.NamedTemporaryFile(mode='wb', suffix='.bin', delete=False) as temp_file:
                # Write hex string as bytes
                try:
                    # Remove 0x prefix if present
                    hex_content = contract_content.replace('0x', '').replace(' ', '').replace('\n', '').replace('\r', '')
                    temp_file.write(bytes.fromhex(hex_content))
                except:
                    # If already bytes, write directly
                    if isinstance(contract_content, bytes):
                        temp_file.write(contract_content)
                    else:
                        temp_file.write(contract_content.encode('utf-8'))
                temp_path = temp_file.name
        else:
            # Solidity file - save as text
            with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as temp_file:
                temp_file.write(contract_content)
                temp_path = temp_file.name
        
        try:
            # Initialize performance monitor
            perf_monitor = PerformanceMonitor()
            perf_monitor.start("total_analysis")
            
            # Auto-detect file type and initialize appropriate parser
            is_bytecode = file_ext == '.bin'
            
            if is_bytecode:
                # Bytecode analysis
                parser = BytecodeParser()
                
                # Get bytecode hex from contract_content (already converted to hex above)
                # Remove 0x prefix and whitespace
                bytecode_hex = contract_content.replace('0x', '').replace(' ', '').replace('\n', '').replace('\r', '').replace('\t', '')
                
                # Parse bytecode
                try:
                    contract_ast = parser.parse_bytecode(bytecode_hex)
                    if not contract_ast:
                        return jsonify({'success': False, 'error': 'Failed to parse bytecode'})
                except Exception as e:
                    return jsonify({'success': False, 'error': f'Error parsing bytecode: {str(e)}'})
                
                # Initialize bytecode detectors
                detectors = []
                if 'overflow' in selected_detectors:
                    detectors.append(BytecodeOverflowDetector())
                if 'access_control' in selected_detectors:
                    detectors.append(BytecodeAccessControlDetector())
                if 'reentrancy' in selected_detectors:
                    detectors.append(BytecodeReentrancyDetector())
                if 'time_manipulation' in selected_detectors:
                    detectors.append(BytecodeTimeManipulationDetector())
                if 'denial_of_service' in selected_detectors:
                    detectors.append(BytecodeDenialOfServiceDetector())
                if 'unprotected_selfdestruct' in selected_detectors:
                    detectors.append(BytecodeUnprotectedSelfDestructDetector())
                
            else:
                # Solidity analysis with caching
                parser = SolidityParser()
                
                # Check cache first (only for uploaded files, not test contracts)
                perf_monitor.start("parsing")
                contract_ast = None
                if 'test_contract' not in request.form and temp_path:
                    contract_ast = ast_cache.get(temp_path)
                
                if not contract_ast:
                    # Clean the uploaded file content before parsing
                    try:
                        # Try multiple encodings to read the file
                        encodings = ['utf-8', 'utf-8-sig', 'latin-1', 'cp1252']
                        original_content = None
                        
                        for encoding in encodings:
                            try:
                                with open(temp_path, 'r', encoding=encoding) as f:
                                    original_content = f.read()
                                break
                            except UnicodeDecodeError:
                                continue
                        
                        if original_content is None:
                            return jsonify({'success': False, 'error': 'Could not read file with any supported encoding'})
                        
                        # Clean Unicode characters from the file content - be very aggressive
                        cleaned_content = clean_unicode_data(original_content)
                        
                        # Double-check: remove any remaining Unicode characters
                        import re
                        cleaned_content = re.sub(r'[^\x00-\x7F]+', '[UNICODE]', cleaned_content)
                        
                        # Write cleaned content back to temp file with UTF-8 encoding
                        with open(temp_path, 'w', encoding='utf-8') as f:
                            f.write(cleaned_content)
                        
                        # Verify the cleaning worked
                        with open(temp_path, 'r', encoding='utf-8') as f:
                            verify_content = f.read()
                            if any(ord(char) > 127 for char in verify_content):
                                print("Warning: Unicode characters still present after cleaning")
                            else:
                                print("Success: All Unicode characters cleaned from file")
                            
                    except Exception as e:
                        return jsonify({'success': False, 'error': f'Error cleaning file content: {str(e)}'})
                    
                    # Parse contract
                    contract_ast = parser.parse_file(temp_path)
                    if not contract_ast:
                        return jsonify({'success': False, 'error': 'Failed to parse contract'})
                    
                    # Cache the result (only for uploaded files)
                    if 'test_contract' not in request.form and temp_path:
                        ast_cache.set(temp_path, contract_ast)
                
                perf_monitor.end("parsing")
                
                # Initialize Solidity detectors
                detectors = []
                if 'overflow' in selected_detectors:
                    detectors.append(OverflowDetector())
                if 'access_control' in selected_detectors:
                    detectors.append(AccessControlDetector())
                if 'reentrancy' in selected_detectors:
                    detectors.append(ReentrancyDetector())
                if 'time_manipulation' in selected_detectors:
                    detectors.append(TimeManipulationDetector())
                if 'denial_of_service' in selected_detectors:
                    detectors.append(DenialOfServiceDetector())
                if 'unprotected_selfdestruct' in selected_detectors:
                    detectors.append(UnprotectedSelfDestructDetector())
            
            # Additional cleaning of parsed content
            if 'content' in contract_ast:
                contract_ast['content'] = clean_unicode_data(contract_ast['content'])
            
            # Run detectors in parallel for better performance
            perf_monitor.start("detection")
            all_vulnerabilities = parallel_detect(detectors, contract_ast)
            perf_monitor.end("detection")
            
            # Calculate detector results for summary
            detector_results = {}
            for vuln in all_vulnerabilities:
                detector_name = vuln.get('detector', 'Unknown')
                detector_results[detector_name] = detector_results.get(detector_name, 0) + 1
            
            # Advanced analysis modules (Fuzzing and Optimization)
            # Note: Fuzzing only works with Solidity files, Optimization only with bytecode
            advanced_results = {}
            
            # Bytecode Optimization Analysis
            if enable_optimization:
                if is_bytecode:
                    try:
                        from optimization.optimizer import BytecodeOptimizer
                        print("Starting optimization analysis...")
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
                        print(f"Optimization analysis completed: {len(optimization_results)} opportunities found")
                    except ImportError as e:
                        error_msg = f"Warning: Optimization module not available: {e}"
                        print(error_msg)
                        advanced_results['optimization'] = {
                            'error': error_msg,
                            'metrics': {'optimizations_found': 0, 'total_savings': 0}
                        }
                    except Exception as e:
                        error_msg = f"Error in optimization: {e}"
                        print(error_msg)
                        import traceback
                        traceback.print_exc()
                        advanced_results['optimization'] = {
                            'error': error_msg,
                            'metrics': {'optimizations_found': 0, 'total_savings': 0}
                        }
                else:
                    print("Note: Optimization analysis is only available for bytecode files")
                    advanced_results['optimization'] = {
                        'error': 'Optimization analysis is only available for bytecode files, not Solidity',
                        'metrics': {'optimizations_found': 0, 'total_savings': 0}
                    }
            
            if enable_fuzzing:
                if is_bytecode:
                    print("Note: Fuzzing is only available for Solidity files, not bytecode")
                    advanced_results['fuzzing'] = {
                        'error': 'Fuzzing only works with Solidity files, not bytecode',
                        'metrics': {'functions_tested': 0, 'iterations': 0, 'vulnerabilities_found': 0}
                    }
                else:
                    try:
                        from analysis.fuzzer import Fuzzer
                        print("Starting fuzzing analysis...")
                        perf_monitor.start("fuzzing")
                        fuzzer = Fuzzer()
                        fuzzer.enable()
                        print(f"Fuzzer enabled, analyzing contract...")
                        fuzzing_results = fuzzer.analyze(contract_ast)
                        perf_monitor.end("fuzzing")
                        advanced_results['fuzzing'] = fuzzing_results
                        
                        # Extract vulnerabilities from fuzzing results
                        fuzzing_vulns = fuzzing_results.get('vulnerabilities', [])
                        if fuzzing_vulns:
                            print(f"Fuzzing found {len(fuzzing_vulns)} vulnerabilities")
                            all_vulnerabilities.extend(fuzzing_vulns)
                        else:
                            print("Fuzzing found no vulnerabilities")
                        
                        print(f"Fuzzing analysis completed. Metrics: {fuzzing_results.get('metrics', {})}")
                    except ImportError as e:
                        error_msg = f"Warning: Fuzzing module not available: {e}"
                        print(error_msg)
                        advanced_results['fuzzing'] = {
                            'error': error_msg,
                            'metrics': {'functions_tested': 0, 'iterations': 0, 'vulnerabilities_found': 0}
                        }
                    except Exception as e:
                        error_msg = f"Error in fuzzing: {e}"
                        print(error_msg)
                        import traceback
                        traceback.print_exc()
                        advanced_results['fuzzing'] = {
                            'error': error_msg,
                            'metrics': {'functions_tested': 0, 'iterations': 0, 'vulnerabilities_found': 0}
                        }
            
            # Add performance metrics
            perf_monitor.end("total_analysis")
            performance_metrics = perf_monitor.get_metrics()
            
            # Prepare results
            print("Preparing results...")
            results = {
                'contract_file': clean_unicode_data(contract_filename),
                'total_vulnerabilities': len(all_vulnerabilities),
                'detector_results': clean_unicode_data(detector_results),
                'performance': performance_metrics,
                'vulnerabilities': all_vulnerabilities
            }
            
            # Add advanced analysis results if available
            if advanced_results:
                results['advanced_analysis'] = advanced_results
            print(f"Results prepared: {len(all_vulnerabilities)} total vulnerabilities")
            
            # Store results for download
            app.config['LAST_RESULTS'] = results
            
            # Ensure all text is properly encoded for JSON response
            # The safe_jsonify function will handle Unicode encoding automatically
            print("Attempting JSON response...")
            try:
                response = jsonify({'success': True, 'data': results})
                print("JSON response successful")
                return response
            except (UnicodeEncodeError, UnicodeDecodeError, UnicodeError) as e:
                print(f"JSON response failed with Unicode error: {e}")
                # Final fallback - return cleaned data
                cleaned_results = ensure_ascii_safe(results)
                print("Using cleaned results fallback")
                return jsonify({'success': True, 'data': cleaned_results})
            
        finally:
            # Clean up temp file
            os.unlink(temp_path)
            
    except UnicodeDecodeError as e:
        return jsonify({
            'success': False, 
            'error': f'Encoding Error: The file contains characters that cannot be decoded. Please save the file with UTF-8 encoding. Error: {str(e)}'
        })
    except (UnicodeEncodeError, UnicodeError) as e:
        error_msg = str(e)
        # Clean any Unicode characters in the error message
        try:
            error_msg = clean_unicode_data(error_msg)
        except:
            error_msg = "Unicode encoding error occurred during analysis"
        
        # Return a simple error response without jsonify to avoid further Unicode issues
        from flask import Response
        error_response = {
            'success': False, 
            'error': f'Unicode Error: {error_msg}. The analysis results contain characters that cannot be encoded properly.'
        }
        json_str = json.dumps(error_response, ensure_ascii=True)
        return Response(json_str, mimetype='application/json; charset=utf-8')
    except Exception as e:
        # Clean any Unicode characters in the error message
        error_msg = str(e)
        try:
            error_msg = clean_unicode_data(error_msg)
        except:
            error_msg = "An error occurred during analysis"
        return jsonify({'success': False, 'error': error_msg})


# ============================================================================
# Remix IDE API Endpoints
# ============================================================================

@app.route('/api/health', methods=['GET'])
def remix_health_check():
    """Health check endpoint for Remix IDE."""
    return jsonify({
        'status': 'healthy',
        'service': 'Smart Contract Vulnerability Detector API',
        'version': '1.0.0'
    })


@app.route('/api/analyze', methods=['POST'])
def remix_analyze():
    """
    Analyze contract for Remix IDE.
    
    Request body:
    {
        "code": "contract code here",
        "fileType": "solidity" | "bytecode",
        "detectors": ["overflow", "reentrancy", ...]  # optional
    }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        code = data.get('code', '')
        file_type = data.get('fileType', 'solidity').lower()
        selected_detectors = data.get('detectors', [])
        
        if not code:
            return jsonify({'success': False, 'error': 'No contract code provided'}), 400
        
        # Create a temporary file with the code
        is_bytecode = file_type == 'bytecode' or file_type == 'bin'
        suffix = '.bin' if is_bytecode else '.sol'
        
        with tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False) as temp_file:
            temp_file.write(code)
            temp_path = temp_file.name
        
        try:
            perf_monitor = PerformanceMonitor()
            perf_monitor.start("total_analysis")
            
            if is_bytecode:
                parser = BytecodeParser()
                bytecode_hex = code.replace('0x', '').replace(' ', '').replace('\n', '').strip()
                contract_ast = parser.parse_bytecode(bytecode_hex)
                
                all_detectors = [
                    BytecodeOverflowDetector(),
                    BytecodeAccessControlDetector(),
                    BytecodeReentrancyDetector(),
                    BytecodeTimeManipulationDetector(),
                    BytecodeDenialOfServiceDetector(),
                    BytecodeUnprotectedSelfDestructDetector()
                ]
            else:
                parser = SolidityParser()
                contract_ast = parser.parse_file(temp_path)
                
                all_detectors = [
                    OverflowDetector(),
                    AccessControlDetector(),
                    ReentrancyDetector(),
                    TimeManipulationDetector(),
                    DenialOfServiceDetector(),
                    UnprotectedSelfDestructDetector()
                ]
            
            if not contract_ast:
                return jsonify({'success': False, 'error': 'Failed to parse contract'}), 400
            
            # Filter detectors if specified
            if selected_detectors:
                detector_map = {
                    'overflow': (OverflowDetector, BytecodeOverflowDetector),
                    'access_control': (AccessControlDetector, BytecodeAccessControlDetector),
                    'reentrancy': (ReentrancyDetector, BytecodeReentrancyDetector),
                    'time_manipulation': (TimeManipulationDetector, BytecodeTimeManipulationDetector),
                    'denial_of_service': (DenialOfServiceDetector, BytecodeDenialOfServiceDetector),
                    'unprotected_selfdestruct': (UnprotectedSelfDestructDetector, BytecodeUnprotectedSelfDestructDetector)
                }
                
                detectors = []
                for det_name in selected_detectors:
                    if det_name in detector_map:
                        det_class = detector_map[det_name][1] if is_bytecode else detector_map[det_name][0]
                        detectors.append(det_class())
            else:
                detectors = all_detectors
            
            # Run detectors in parallel
            perf_monitor.start("detection")
            all_vulnerabilities = parallel_detect(detectors, contract_ast)
            perf_monitor.end("detection")
            perf_monitor.end("total_analysis")
            
            # Format response for Remix
            response = {
                'success': True,
                'vulnerabilities': all_vulnerabilities,
                'summary': {
                    'total': len(all_vulnerabilities),
                    'by_severity': {
                        'Critical': sum(1 for v in all_vulnerabilities if v.get('severity') == 'Critical'),
                        'High': sum(1 for v in all_vulnerabilities if v.get('severity') == 'High'),
                        'Medium': sum(1 for v in all_vulnerabilities if v.get('severity') == 'Medium'),
                        'Low': sum(1 for v in all_vulnerabilities if v.get('severity') == 'Low')
                    },
                    'by_type': {}
                },
                'performance': perf_monitor.get_metrics()
            }
            
            # Group by type
            for vuln in all_vulnerabilities:
                vuln_type = vuln.get('type', 'Unknown')
                response['summary']['by_type'][vuln_type] = response['summary']['by_type'].get(vuln_type, 0) + 1
            
            return jsonify(response)
        
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/detectors', methods=['GET'])
def remix_list_detectors():
    """List all available detectors for Remix IDE."""
    return jsonify({
        'success': True,
        'detectors': [
            {'id': 'overflow', 'name': 'Integer Overflow/Underflow', 'description': 'Detects unsafe arithmetic operations'},
            {'id': 'access_control', 'name': 'Access Control Issues', 'description': 'Finds missing access modifiers'},
            {'id': 'reentrancy', 'name': 'Reentrancy Vulnerabilities', 'description': 'Identifies reentrancy attack vectors'},
            {'id': 'time_manipulation', 'name': 'Time Manipulation', 'description': 'Detects time-based vulnerabilities'},
            {'id': 'denial_of_service', 'name': 'Denial of Service', 'description': 'Identifies DoS vulnerabilities'},
            {'id': 'unprotected_selfdestruct', 'name': 'Unprotected Selfdestruct', 'description': 'Detects unprotected selfdestruct calls'}
        ]
    })


@app.route('/download')
def download():
    """Download analysis results."""
    if 'LAST_RESULTS' not in app.config:
        return "No results to download", 404
    
    results = app.config['LAST_RESULTS']
    format_type = request.args.get('format', 'json')
    
    if format_type == 'json':
        # Create JSON file with proper encoding
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as temp_file:
                json.dump(results, temp_file, indent=2, ensure_ascii=False)
                temp_path = temp_file.name
        except UnicodeEncodeError:
            # If encoding fails, clean the data first
            cleaned_results = clean_unicode_data(results)
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as temp_file:
                json.dump(cleaned_results, temp_file, indent=2, ensure_ascii=False)
                temp_path = temp_file.name
        
        return send_file(temp_path, as_attachment=True, download_name='analysis_results.json')
    
    else:  # text format
        # Create text file
        text_content = f"Analysis Results for: {results['contract_file']}\n"
        text_content += "=" * 60 + "\n\n"
        text_content += f"Total Vulnerabilities: {results['total_vulnerabilities']}\n"
        
        for detector, count in results['detector_results'].items():
            text_content += f"{detector}: {count} issues\n"
        
        if results['vulnerabilities']:
            text_content += "\nVulnerability Details:\n"
            text_content += "=" * 60 + "\n"
            
            for i, vuln in enumerate(results['vulnerabilities'], 1):
                text_content += f"{i}. {vuln.get('type', 'Unknown')}\n"
                text_content += f"   Description: {vuln.get('description', 'No description')}\n"
                if vuln.get('recommendation'):
                    text_content += f"   Fix: {vuln.get('recommendation')}\n"
                text_content += "\n"
        else:
            text_content += "\nNo vulnerabilities detected!\n"
        
        # Clean Unicode characters for text file
        cleaned_text = clean_unicode_data(text_content)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as temp_file:
            temp_file.write(cleaned_text)
            temp_path = temp_file.name
        
        return send_file(temp_path, as_attachment=True, download_name='analysis_results.txt')

if __name__ == '__main__':
    # Set up proper Unicode handling for the entire application
    import sys
    import os
    
    # Set environment variables for Unicode handling
    os.environ['PYTHONIOENCODING'] = 'utf-8'
    os.environ['LC_ALL'] = 'en_US.UTF-8'
    os.environ['LANG'] = 'en_US.UTF-8'
    
    # Force UTF-8 encoding for the entire application
    import locale
    try:
        locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')
    except:
        try:
            locale.setlocale(locale.LC_ALL, 'C.UTF-8')
        except:
            pass  # If locale setting fails, continue
    
    # Configure stdout and stderr for Unicode
    if sys.platform.startswith('win'):
        try:
            import codecs
            sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer)
            sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer)
        except:
            pass  # If already configured, continue
    
    print("🌐 Starting Smart Contract Vulnerability Detection Web App...")
    
    # Get port from environment variable (for deployment) or use default 5000
    port = int(os.environ.get('PORT', 5000))
    
    # Disable debug mode in production (check for production environment)
    debug_mode = os.environ.get('FLASK_ENV', 'development') != 'production'
    
    if not debug_mode:
        print("📍 Production mode - Ready to analyze smart contracts!")
        print("📡 Remix API available at: http://localhost:{}/api/analyze".format(port))
    else:
        print(f"📍 Development mode - Open your browser and go to: http://localhost:{port}")
        print("🔍 Ready to analyze smart contracts!")
        print("📡 Remix API available at: http://localhost:{}/api/analyze".format(port))
    
    app.run(debug=debug_mode, host='0.0.0.0', port=port)
