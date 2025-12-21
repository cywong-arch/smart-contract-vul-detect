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
CORS(app)

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
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            box-shadow: 0 25px 50px rgba(0,0,0,0.15);
            overflow: hidden;
            animation: fadeIn 0.5s ease-in;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 30px;
            text-align: center;
            position: relative;
            overflow: hidden;
        }
        
        .header::before {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(255,255,255,0.1) 0%, transparent 70%);
            animation: pulse 4s ease-in-out infinite;
        }
        
        @keyframes pulse {
            0%, 100% { transform: scale(1); opacity: 0.5; }
            50% { transform: scale(1.1); opacity: 0.8; }
        }
        
        .header h1 {
            font-size: 2.8em;
            margin-bottom: 10px;
            position: relative;
            z-index: 1;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }
        
        .header p {
            opacity: 0.95;
            font-size: 1.2em;
            position: relative;
            z-index: 1;
        }
        
        .main-content {
            padding: 40px;
        }
        
        .upload-section {
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            border-radius: 15px;
            padding: 35px;
            margin-bottom: 30px;
            border: 3px dashed #dee2e6;
            text-align: center;
            transition: all 0.3s ease;
            position: relative;
        }
        
        .upload-section.dragover {
            border-color: #667eea;
            background: linear-gradient(135deg, #e3f2fd 0%, #bbdefb 100%);
            transform: scale(1.02);
            box-shadow: 0 10px 30px rgba(102, 126, 234, 0.3);
        }
        
        .file-input-wrapper {
            position: relative;
            display: inline-block;
            margin: 25px 0;
        }
        
        .file-input {
            position: absolute;
            opacity: 0;
            width: 100%;
            height: 100%;
            cursor: pointer;
        }
        
        .file-input-button {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 14px 35px;
            border-radius: 30px;
            border: none;
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
            transition: all 0.3s;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
        }
        
        .file-input-button:hover {
            transform: translateY(-3px);
            box-shadow: 0 6px 20px rgba(102, 126, 234, 0.5);
        }
        
        .file-input-button:active {
            transform: translateY(-1px);
        }
        
        .selected-file-badge {
            display: inline-block;
            background: linear-gradient(135deg, #28a745 0%, #20c997 100%);
            color: white;
            padding: 10px 20px;
            border-radius: 25px;
            margin-top: 15px;
            font-weight: 600;
            box-shadow: 0 4px 15px rgba(40, 167, 69, 0.3);
            animation: slideIn 0.3s ease-out;
        }
        
        @keyframes slideIn {
            from { opacity: 0; transform: translateY(-10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .quick-select {
            margin: 25px 0;
            background: linear-gradient(135deg, #ffffff 0%, #f8f9fa 100%);
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
        }
        
        .quick-select h3 {
            margin-bottom: 15px;
            color: #2c3e50;
            font-size: 1.5em;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .search-box {
            width: 100%;
            padding: 12px 20px;
            border: 2px solid #dee2e6;
            border-radius: 25px;
            font-size: 14px;
            margin-bottom: 15px;
            transition: all 0.3s;
            background: white;
        }
        
        .search-box:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        
        .file-list-container {
            background: white;
            border-radius: 10px;
            border: 1px solid #e9ecef;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
        }
        
        .file-list-header {
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            padding: 12px 15px;
            font-weight: 600;
            color: #495057;
            border-bottom: 2px solid #dee2e6;
        }
        
        .file-list {
            max-height: 400px;
            overflow-y: auto;
            padding: 10px;
        }
        
        .file-list::-webkit-scrollbar {
            width: 8px;
        }
        
        .file-list::-webkit-scrollbar-track {
            background: #f1f1f1;
            border-radius: 10px;
        }
        
        .file-list::-webkit-scrollbar-thumb {
            background: #667eea;
            border-radius: 10px;
        }
        
        .file-list::-webkit-scrollbar-thumb:hover {
            background: #764ba2;
        }
        
        .test-contract-btn {
            background: linear-gradient(135deg, #6c757d 0%, #5a6268 100%);
            color: white;
            border: none;
            padding: 10px 18px;
            margin: 6px 0;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s;
            width: 100%;
            text-align: left;
            font-size: 14px;
            display: flex;
            align-items: center;
            gap: 10px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        
        .test-contract-btn:hover {
            background: linear-gradient(135deg, #5a6268 0%, #495057 100%);
            transform: translateX(5px);
            box-shadow: 0 4px 10px rgba(0,0,0,0.15);
        }
        
        .test-contract-btn:active {
            transform: translateX(2px);
        }
        
        .test-contract-btn.sol-file {
            background: linear-gradient(135deg, #007bff 0%, #0056b3 100%);
        }
        
        .test-contract-btn.sol-file:hover {
            background: linear-gradient(135deg, #0056b3 0%, #004085 100%);
        }
        
        .test-contract-btn.bin-file {
            background: linear-gradient(135deg, #6c757d 0%, #5a6268 100%);
        }
        
        .test-contract-btn.bin-file:hover {
            background: linear-gradient(135deg, #5a6268 0%, #495057 100%);
        }
        
        .options-section {
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            border-radius: 15px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
        }
        
        .options-section h3 {
            color: #2c3e50;
            font-size: 1.5em;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .detector-options {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        
        .detector-option {
            background: white;
            padding: 20px;
            border-radius: 12px;
            border-left: 5px solid #667eea;
            transition: all 0.3s;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }
        
        .detector-option:hover {
            transform: translateY(-3px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.12);
        }
        
        .detector-option input[type="checkbox"] {
            margin-right: 12px;
            transform: scale(1.3);
            cursor: pointer;
        }
        
        .detector-option label {
            cursor: pointer;
            display: flex;
            align-items: flex-start;
        }
        
        .analyze-btn {
            background: linear-gradient(135deg, #28a745 0%, #20c997 100%);
            color: white;
            border: none;
            padding: 18px 50px;
            font-size: 18px;
            font-weight: 600;
            border-radius: 35px;
            cursor: pointer;
            transition: all 0.3s;
            display: block;
            margin: 35px auto;
            box-shadow: 0 6px 20px rgba(40, 167, 69, 0.4);
            position: relative;
            overflow: hidden;
        }
        
        .analyze-btn::before {
            content: '';
            position: absolute;
            top: 50%;
            left: 50%;
            width: 0;
            height: 0;
            border-radius: 50%;
            background: rgba(255,255,255,0.3);
            transform: translate(-50%, -50%);
            transition: width 0.6s, height 0.6s;
        }
        
        .analyze-btn:hover::before {
            width: 300px;
            height: 300px;
        }
        
        .analyze-btn:hover {
            transform: translateY(-3px);
            box-shadow: 0 8px 25px rgba(40, 167, 69, 0.5);
        }
        
        .analyze-btn:disabled {
            background: #6c757d;
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
        }
        
        .loading {
            text-align: center;
            padding: 50px;
            display: none;
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            border-radius: 15px;
            margin: 30px 0;
        }
        
        .spinner {
            border: 5px solid #f3f3f3;
            border-top: 5px solid #667eea;
            border-radius: 50%;
            width: 60px;
            height: 60px;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .loading-text {
            font-size: 16px;
            color: #495057;
            font-weight: 500;
        }
        
        .results-section {
            margin-top: 30px;
            display: none;
            animation: slideUp 0.5s ease-out;
        }
        
        @keyframes slideUp {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .results-header {
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 25px;
            border-radius: 15px 15px 0 0;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 15px;
        }
        
        .results-header h3 {
            margin: 0;
            font-size: 1.5em;
        }
        
        .results-content {
            background: #1e1e1e;
            color: #f8f9fa;
            padding: 25px;
            font-family: 'Courier New', monospace;
            white-space: pre-wrap;
            max-height: 600px;
            overflow-y: auto;
            border-radius: 0 0 15px 15px;
            line-height: 1.6;
        }
        
        .results-content::-webkit-scrollbar {
            width: 10px;
        }
        
        .results-content::-webkit-scrollbar-track {
            background: #2c2c2c;
        }
        
        .results-content::-webkit-scrollbar-thumb {
            background: #667eea;
            border-radius: 10px;
        }
        
        .vulnerability-high { color: #ff6b6b; font-weight: bold; }
        .vulnerability-medium { color: #ffd93d; font-weight: bold; }
        .vulnerability-low { color: #4ecdc4; }
        .success-text { color: #51cf66; font-weight: bold; }
        
        .download-btn {
            background: linear-gradient(135deg, #17a2b8 0%, #138496 100%);
            color: white;
            border: none;
            padding: 12px 25px;
            border-radius: 8px;
            cursor: pointer;
            margin: 5px;
            font-weight: 600;
            transition: all 0.3s;
            box-shadow: 0 3px 10px rgba(23, 162, 184, 0.3);
        }
        
        .download-btn:hover {
            background: linear-gradient(135deg, #138496 0%, #117a8b 100%);
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(23, 162, 184, 0.4);
        }
        
        .stats-grid {
            display: flex;
            flex-wrap: nowrap;
            gap: 10px;
            margin: 20px 0;
            overflow-x: auto;
            padding-bottom: 5px;
        }
        
        .stats-grid::-webkit-scrollbar {
            height: 6px;
        }
        
        .stats-grid::-webkit-scrollbar-track {
            background: #2c2c2c;
            border-radius: 10px;
        }
        
        .stats-grid::-webkit-scrollbar-thumb {
            background: #667eea;
            border-radius: 10px;
        }
        
        .stat-card {
            background: white;
            padding: 12px 16px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            transition: all 0.3s;
            min-width: 120px;
            flex-shrink: 0;
        }
        
        .stat-card:hover {
            transform: translateY(-3px);
            box-shadow: 0 4px 15px rgba(0,0,0,0.15);
        }
        
        .stat-value {
            font-size: 1.8em;
            font-weight: bold;
            color: #667eea;
            margin: 5px 0;
            line-height: 1.2;
        }
        
        .stat-label {
            color: #6c757d;
            font-size: 0.75em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            line-height: 1.3;
        }
        
        .empty-state {
            text-align: center;
            padding: 40px;
            color: #6c757d;
        }
        
        .empty-state-icon {
            font-size: 4em;
            margin-bottom: 15px;
            opacity: 0.5;
        }
        
        .filter-chip {
            background: white;
            border: 2px solid #dee2e6;
            color: #495057;
            padding: 8px 16px;
            border-radius: 20px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            transition: all 0.3s;
            white-space: nowrap;
        }
        
        .filter-chip:hover {
            border-color: #667eea;
            color: #667eea;
            transform: translateY(-2px);
            box-shadow: 0 3px 10px rgba(102, 126, 234, 0.2);
        }
        
        .filter-chip.active {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-color: #667eea;
            color: white;
            box-shadow: 0 3px 10px rgba(102, 126, 234, 0.3);
        }
        
        .filter-chip.active:hover {
            background: linear-gradient(135deg, #764ba2 0%, #667eea 100%);
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }
        
        @media (max-width: 768px) {
            .main-content {
                padding: 20px;
            }
            
            .header h1 {
                font-size: 2em;
            }
            
            .detector-options {
                grid-template-columns: 1fr;
            }
            
            .stats-grid {
                gap: 8px;
            }
            
            .stat-card {
                min-width: 100px;
                padding: 10px 12px;
            }
            
            .stat-value {
                font-size: 1.5em;
            }
            
            .stat-label {
                font-size: 0.7em;
            }
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
                
                <div id="selectedFile"></div>
                
                <div class="quick-select">
                    <h3>📂 Available Test Contracts</h3>
                    <p style="margin-bottom: 20px; color: #495057; font-size: 0.95em;">Select a test contract from the list below or use filters to narrow down</p>
                    
                    <input type="text" id="fileSearch" class="search-box" placeholder="🔍 Search contracts by name..." onkeyup="filterFiles()">
                    
                    <div style="margin-top: 20px; margin-bottom: 20px;">
                        <div style="display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin-bottom: 15px;">
                            <span style="font-weight: 600; color: #495057; margin-right: 5px;">Filter by:</span>
                            <button class="filter-chip active" data-filter="all" onclick="setFilter('all')">All</button>
                            <button class="filter-chip" data-filter="overflow" onclick="setFilter('overflow')">Overflow</button>
                            <button class="filter-chip" data-filter="reentrancy" onclick="setFilter('reentrancy')">Reentrancy</button>
                            <button class="filter-chip" data-filter="time_manipulation" onclick="setFilter('time_manipulation')">Time Manipulation</button>
                            <button class="filter-chip" data-filter="denial_of_service" onclick="setFilter('denial_of_service')">DoS</button>
                            <button class="filter-chip" data-filter="access_control" onclick="setFilter('access_control')">Access Control</button>
                            <button class="filter-chip" data-filter="selfdestruct" onclick="setFilter('selfdestruct')">Selfdestruct</button>
                        </div>
                        <div style="display: flex; flex-wrap: wrap; gap: 10px; align-items: center;">
                            <span style="font-weight: 600; color: #495057; margin-right: 5px;">Level:</span>
                            <button class="filter-chip active" data-level="all" onclick="setLevelFilter('all')">All Levels</button>
                            <button class="filter-chip" data-level="level1" onclick="setLevelFilter('level1')">Level 1</button>
                            <button class="filter-chip" data-level="level2" onclick="setLevelFilter('level2')">Level 2</button>
                            <button class="filter-chip" data-level="level3" onclick="setLevelFilter('level3')">Level 3</button>
                            <button class="filter-chip" data-level="mixed" onclick="setLevelFilter('mixed')">Mixed</button>
                        </div>
                    </div>
                    
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 15px;">
                        <div>
                            <div class="file-list-container">
                                <div class="file-list-header">
                                    📄 Solidity Files (.sol) - <span id="solCount">0</span> files
                                </div>
                                <div id="solidityFiles" class="file-list">
                                    <div class="empty-state">
                                        <div class="empty-state-icon">⏳</div>
                                        <p>Loading files...</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div>
                            <div class="file-list-container">
                                <div class="file-list-header">
                                    📦 Bytecode Files (.bin) - <span id="binCount">0</span> files
                                </div>
                                <div id="bytecodeFiles" class="file-list">
                                    <div class="empty-state">
                                        <div class="empty-state-icon">⏳</div>
                                        <p>Loading files...</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
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
            </div>
            
            <button class="analyze-btn" id="analyzeBtn" onclick="startAnalysis()">
                🚀 Start Analysis
            </button>
            
            <div class="loading" id="loading">
                <div class="spinner"></div>
                <p class="loading-text">Analyzing contract... Please wait</p>
                <p style="color: #6c757d; font-size: 0.9em; margin-top: 10px;">This may take a few moments depending on contract size</p>
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
                showSelectedFile(currentFile.name);
            }
        });
        
        function showSelectedFile(filename) {
            const selectedDiv = document.getElementById('selectedFile');
            selectedDiv.innerHTML = `<div class="selected-file-badge">✓ Selected: ${filename}</div>`;
        }
        
        let currentFilter = 'all';
        let currentLevelFilter = 'all';
        
        function setFilter(filterType) {
            currentFilter = filterType;
            // Update active state
            document.querySelectorAll('[data-filter]').forEach(btn => {
                btn.classList.remove('active');
            });
            document.querySelector(`[data-filter="${filterType}"]`).classList.add('active');
            applyFilters();
        }
        
        function setLevelFilter(level) {
            currentLevelFilter = level;
            // Update active state
            document.querySelectorAll('[data-level]').forEach(btn => {
                btn.classList.remove('active');
            });
            document.querySelector(`[data-level="${level}"]`).classList.add('active');
            applyFilters();
        }
        
        function matchesFilter(filename) {
            const lowerFilename = filename.toLowerCase();
            
            // Check vulnerability type filter
            if (currentFilter !== 'all') {
                const filterMap = {
                    'overflow': ['overflow'],
                    'reentrancy': ['reentrancy'],
                    'time_manipulation': ['time', 'time_manipulation'],
                    'denial_of_service': ['dos', 'denial', 'denial_of_service'],
                    'access_control': ['access', 'access_control'],
                    'selfdestruct': ['selfdestruct', 'selfdestruct']
                };
                
                const keywords = filterMap[currentFilter];
                if (!keywords || !keywords.some(keyword => lowerFilename.includes(keyword))) {
                    return false;
                }
            }
            
            // Check level filter
            if (currentLevelFilter !== 'all') {
                if (currentLevelFilter === 'mixed') {
                    if (!lowerFilename.includes('mixed') && !lowerFilename.includes('vuln')) {
                        return false;
                    }
                } else {
                    // level1, level2, level3
                    if (!lowerFilename.includes(currentLevelFilter)) {
                        return false;
                    }
                }
            }
            
            return true;
        }
        
        function filterFiles() {
            applyFilters();
        }
        
        function applyFilters() {
            const searchTerm = document.getElementById('fileSearch').value.toLowerCase();
            const solidityButtons = document.querySelectorAll('#solidityFiles .test-contract-btn');
            const bytecodeButtons = document.querySelectorAll('#bytecodeFiles .test-contract-btn');
            
            let solVisible = 0, binVisible = 0;
            
            solidityButtons.forEach(btn => {
                const filename = btn.textContent.toLowerCase().replace('📄', '').trim();
                const matchesSearch = filename.includes(searchTerm);
                const matchesFilterType = matchesFilter(filename);
                
                if (matchesSearch && matchesFilterType) {
                    btn.style.display = 'flex';
                    solVisible++;
                } else {
                    btn.style.display = 'none';
                }
            });
            
            bytecodeButtons.forEach(btn => {
                const filename = btn.textContent.toLowerCase().replace('📦', '').trim();
                const matchesSearch = filename.includes(searchTerm);
                const matchesFilterType = matchesFilter(filename);
                
                if (matchesSearch && matchesFilterType) {
                    btn.style.display = 'flex';
                    binVisible++;
                } else {
                    btn.style.display = 'none';
                }
            });
            
            // Update counts
            document.getElementById('solCount').textContent = solVisible;
            document.getElementById('binCount').textContent = binVisible;
            
            // Show empty state if no files match
            if (solVisible === 0) {
                const solidityDiv = document.getElementById('solidityFiles');
                if (!solidityDiv.querySelector('.empty-state')) {
                    solidityDiv.innerHTML = '<div class="empty-state"><div class="empty-state-icon">🔍</div><p>No files match the current filters</p></div>';
                }
            }
            if (binVisible === 0) {
                const bytecodeDiv = document.getElementById('bytecodeFiles');
                if (!bytecodeDiv.querySelector('.empty-state')) {
                    bytecodeDiv.innerHTML = '<div class="empty-state"><div class="empty-state-icon">🔍</div><p>No files match the current filters</p></div>';
                }
            }
        }
        
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
                showSelectedFile(currentFile.name);
                document.getElementById('fileInput').files = e.dataTransfer.files;
            }
        });
        
        function selectTestContract(filename) {
            showSelectedFile(filename);
            currentFile = { name: filename, isTestContract: true };
        }
        
        // Load available test contracts
        async function loadTestContracts() {
            try {
                const response = await fetch('/list_contracts');
                const data = await response.json();
                
                if (data.success) {
                    const solidityDiv = document.getElementById('solidityFiles');
                    const bytecodeDiv = document.getElementById('bytecodeFiles');
                    
                    // Store original file lists for filtering
                    window.allSolidityFiles = data.solidity_files || [];
                    window.allBytecodeFiles = data.bytecode_files || [];
                    
                    // Display Solidity files
                    if (data.solidity_files && data.solidity_files.length > 0) {
                        solidityDiv.innerHTML = '';
                        data.solidity_files.forEach(filename => {
                            const button = document.createElement('button');
                            button.className = 'test-contract-btn sol-file';
                            button.innerHTML = `<span>📄</span> <span>${filename}</span>`;
                            button.onclick = () => selectTestContract(filename);
                            solidityDiv.appendChild(button);
                        });
                        applyFilters(); // Apply initial filters
                    } else {
                        solidityDiv.innerHTML = '<div class="empty-state"><div class="empty-state-icon">📄</div><p>No Solidity files found</p></div>';
                        document.getElementById('solCount').textContent = '0';
                    }
                    
                    // Display Bytecode files
                    if (data.bytecode_files && data.bytecode_files.length > 0) {
                        bytecodeDiv.innerHTML = '';
                        data.bytecode_files.forEach(filename => {
                            const button = document.createElement('button');
                            button.className = 'test-contract-btn bin-file';
                            button.innerHTML = `<span>📦</span> <span>${filename}</span>`;
                            button.onclick = () => selectTestContract(filename);
                            bytecodeDiv.appendChild(button);
                        });
                        applyFilters(); // Apply initial filters
                    } else {
                        bytecodeDiv.innerHTML = '<div class="empty-state"><div class="empty-state-icon">📦</div><p>No Bytecode files found</p></div>';
                        document.getElementById('binCount').textContent = '0';
                    }
                } else {
                    document.getElementById('solidityFiles').innerHTML = '<div class="empty-state"><div class="empty-state-icon">❌</div><p style="color: #dc3545;">Error loading files</p></div>';
                    document.getElementById('bytecodeFiles').innerHTML = '<div class="empty-state"><div class="empty-state-icon">❌</div><p style="color: #dc3545;">Error loading files</p></div>';
                }
            } catch (error) {
                console.error('Error loading test contracts:', error);
                document.getElementById('solidityFiles').innerHTML = '<div class="empty-state"><div class="empty-state-icon">❌</div><p style="color: #dc3545;">Error loading files</p></div>';
                document.getElementById('bytecodeFiles').innerHTML = '<div class="empty-state"><div class="empty-state-icon">❌</div><p style="color: #dc3545;">Error loading files</p></div>';
            }
        }
        
        // Load contracts when page loads
        window.addEventListener('DOMContentLoaded', function() {
            loadTestContracts();
        });
        
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
                
                // Auto-determine advanced analysis options based on file type
                const filename = currentFile.name;
                const isBytecode = filename.toLowerCase().endsWith('.bin');
                const enable_fuzzing = !isBytecode; // Enable fuzzing for Solidity files
                const enable_optimization = isBytecode; // Enable optimization for bytecode files
                
                console.log('File type:', isBytecode ? 'Bytecode' : 'Solidity');
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
            
            // Create summary stats HTML
            let statsHTML = '<div class="stats-grid" style="margin-bottom: 25px;">';
            statsHTML += `<div class="stat-card"><div class="stat-value">${results.total_vulnerabilities}</div><div class="stat-label">Total Vulnerabilities</div></div>`;
            
            // Add detector results
            for (const [detector, count] of Object.entries(results.detector_results)) {
                const detectorName = detector.replace('Detector', '').replace(/([A-Z])/g, ' $1').trim();
                statsHTML += `<div class="stat-card"><div class="stat-value">${count}</div><div class="stat-label">${detectorName}</div></div>`;
            }
            
            // ALWAYS add fuzzing stats for .sol files (even if there are errors or 0 results)
            const filename = results.contract_file || '';
            const isSolFile = filename.toLowerCase().endsWith('.sol');
            
            if (results.advanced_analysis && results.advanced_analysis.fuzzing) {
                const fuzzing = results.advanced_analysis.fuzzing;
                const metrics = fuzzing.metrics || {};
                const fuzzingVulns = metrics.vulnerabilities_found || 0;
                // Always show fuzzing card for .sol files
                if (isSolFile) {
                    statsHTML += `<div class="stat-card"><div class="stat-value">${fuzzingVulns}</div><div class="stat-label">Fuzzing Vulnerabilities</div></div>`;
                }
            } else if (isSolFile) {
                // If fuzzing wasn't run but it's a .sol file, show 0
                statsHTML += `<div class="stat-card"><div class="stat-value">0</div><div class="stat-label">Fuzzing Vulnerabilities</div></div>`;
            }
            
            statsHTML += '</div>';
            
            // Create text output
            let output = `🔍 Analysis Results for: ${results.contract_file}\n`;
            output += `${'='.repeat(60)}\n\n`;
            
            output += `📊 Summary:\n`;
            output += `Total Vulnerabilities: ${results.total_vulnerabilities}\n`;
            
            for (const [detector, count] of Object.entries(results.detector_results)) {
                output += `${detector}: ${count} issues\n`;
            }
            
            // ALWAYS show fuzzing metrics for .sol files, even if there are errors
            // Display this right after summary, before other advanced analysis
            if (results.advanced_analysis && results.advanced_analysis.fuzzing) {
                const fuzzing = results.advanced_analysis.fuzzing;
                const metrics = fuzzing.metrics || {};
                
                // Always display fuzzing analysis for .sol files
                output += `\n🧪 Fuzzing Analysis:\n`;
                
                // Show error if present
                if (fuzzing.error) {
                    output += `  ⚠️  Error: ${fuzzing.error}\n`;
                }
                
                // Display metrics (will be 0 if there was an error)
                output += `  Functions tested: ${metrics.functions_tested || 0}\n`;
                output += `  Iterations: ${metrics.iterations || 0}\n`;
                output += `  Fuzzing vulnerabilities: ${metrics.vulnerabilities_found || 0}\n`;
                
                // Show success message if no errors and no vulnerabilities
                if (!fuzzing.error && metrics.vulnerabilities_found === 0) {
                    output += `  ✅ No input-dependent vulnerabilities found\n`;
                }
                
                // Show warnings if any
                if (fuzzing.warnings && fuzzing.warnings.length > 0) {
                    fuzzing.warnings.forEach(warning => {
                        output += `  ⚠️  ${warning}\n`;
                    });
                }
            } else {
                // If fuzzing wasn't run but it's a .sol file, show a message
                const filename = results.contract_file || '';
                if (filename.toLowerCase().endsWith('.sol')) {
                    output += `\n🧪 Fuzzing Analysis:\n`;
                    output += `  ⚠️  Fuzzing analysis was not executed\n`;
                    output += `  Functions tested: 0\n`;
                    output += `  Iterations: 0\n`;
                    output += `  Fuzzing vulnerabilities: 0\n`;
                }
            }
            
            // Show optimization metrics only if successfully executed (no errors)
            if (results.advanced_analysis && results.advanced_analysis.optimization) {
                const optimization = results.advanced_analysis.optimization;
                
                // Only show if there's no error (successful execution)
                if (!optimization.error) {
                    const gasAnalysis = optimization.gas_analysis || {};
                    const savings = optimization.potential_savings || {};
                    const optimizations = optimization.optimizations || [];
                    
                    output += `\n🔧 Optimization Analysis:\n`;
                    
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
                // If there's an error, don't show optimization section at all
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
            
            // Combine stats HTML and text output
            content.innerHTML = statsHTML + '<pre style="margin: 0; padding: 0; background: transparent; color: inherit; font-family: inherit; white-space: pre-wrap;">' + output + '</pre>';
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

@app.route('/list_contracts', methods=['GET'])
def list_contracts():
    """List all available test contract files."""
    try:
        test_contracts_dir = os.path.join('test_contracts')
        
        if not os.path.exists(test_contracts_dir):
            return jsonify({'success': False, 'error': 'Test contracts directory not found'})
        
        # Get all files in test_contracts directory
        all_files = os.listdir(test_contracts_dir)
        
        # Filter and sort files
        solidity_files = sorted([f for f in all_files if f.endswith('.sol')])
        bytecode_files = sorted([f for f in all_files if f.endswith('.bin')])
        
        return jsonify({
            'success': True,
            'solidity_files': solidity_files,
            'bytecode_files': bytecode_files
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

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
            
            # ALWAYS run fuzzing for Solidity files (.sol), regardless of enable_fuzzing flag
            # This ensures consistent behavior - fuzzing is auto-enabled for all .sol files
            if is_bytecode:
                # Bytecode files don't support fuzzing
                if enable_fuzzing:
                    print("Note: Fuzzing is only available for Solidity files, not bytecode")
                    advanced_results['fuzzing'] = {
                        'error': 'Fuzzing only works with Solidity files, not bytecode',
                        'metrics': {'functions_tested': 0, 'iterations': 0, 'vulnerabilities_found': 0}
                    }
            else:
                # For Solidity files, ALWAYS run fuzzing (even if enable_fuzzing was false)
                # This ensures all .sol files get fuzzing analysis
                try:
                    from analysis.fuzzer import Fuzzer
                    print("Starting fuzzing analysis for Solidity file...")
                    perf_monitor.start("fuzzing")
                    fuzzer = Fuzzer()
                    fuzzer.enable()
                    print(f"Fuzzer enabled, analyzing contract...")
                    fuzzing_results = fuzzer.analyze(contract_ast)
                    perf_monitor.end("fuzzing")
                    advanced_results['fuzzing'] = fuzzing_results
                    
                    # Only add fuzzing vulnerabilities if fuzzing completed successfully (no errors)
                    # Check for errors in the results
                    has_error = fuzzing_results.get('error') or (fuzzing_results.get('errors') and len(fuzzing_results.get('errors', [])) > 0)
                    
                    if not has_error:
                        # Extract vulnerabilities from fuzzing results only if no error
                        fuzzing_vulns = fuzzing_results.get('vulnerabilities', [])
                        if fuzzing_vulns:
                            print(f"Fuzzing found {len(fuzzing_vulns)} vulnerabilities")
                            all_vulnerabilities.extend(fuzzing_vulns)
                        else:
                            print("Fuzzing found no vulnerabilities")
                    else:
                        # If there's an error, don't add any vulnerabilities and reset metrics
                        error_msg = fuzzing_results.get('error', 'Unknown fuzzing error')
                        print(f"Fuzzing encountered an error: {error_msg}")
                        print("Not adding fuzzing vulnerabilities due to error")
                        # Ensure metrics show 0 vulnerabilities if there was an error
                        if 'metrics' not in fuzzing_results:
                            fuzzing_results['metrics'] = {}
                        fuzzing_results['metrics']['vulnerabilities_found'] = 0
                        # Clear any vulnerabilities that might have been found before the error
                        fuzzing_results['vulnerabilities'] = []
                    
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
            
            # Calculate detector results for summary AFTER all vulnerabilities are added (including fuzzing)
            detector_results = {}
            for vuln in all_vulnerabilities:
                detector_name = vuln.get('detector', 'Unknown')
                # Handle fuzzing vulnerabilities - they might have 'Fuzzer' or 'Fuzzing' as detector
                if 'fuzzing' in detector_name.lower() or 'fuzzer' in detector_name.lower():
                    detector_name = 'Fuzzing'
                detector_results[detector_name] = detector_results.get(detector_name, 0) + 1
            
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
    else:
        print(f"📍 Development mode - Open your browser and go to: http://localhost:{port}")
        print("🔍 Ready to analyze smart contracts!")
    
    app.run(debug=debug_mode, host='0.0.0.0', port=port)
