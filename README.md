# Smart Contract Vulnerability Detection System

## Project Overview
This FYP project focuses on detecting six critical smart contract vulnerabilities:
1. **Overflow/Underflow** - Integer arithmetic vulnerabilities
2. **Access Control** - Unauthorized access to privileged functions
3. **Reentrancy** - External calls before state updates
4. **Time Manipulation** - Vulnerable time-based operations
5. **Denial of Service** - DoS attack vectors and gas issues
6. **Unprotected Selfdestruct** - Dangerous contract destruction calls

## Approach
Instead of training ML models, this system uses **pattern-based static analysis** to detect vulnerabilities by:
- Parsing Solidity smart contracts **and EVM bytecode**
- Identifying vulnerable code patterns
- Analyzing control flow and data flow
- **Dynamic analysis through fuzzing** (optional)
- Reporting potential security issues

## ✨ Key Features

- 🔍 **Dual Analysis**: Supports both Solidity source code (`.sol`) and EVM bytecode (`.bin`)
- ⚡ **Performance Optimized**: Parallel detector execution, AST caching (2-3x faster)
- 🌐 **Multiple Interfaces**: CLI, GUI, Web App, and Remix IDE integration
- 🧪 **Fuzzing Support**: Optional dynamic analysis with test input generation
- 📊 **Performance Metrics**: Built-in performance monitoring and reporting
- 🔌 **IDE Integration**: REST API for Remix IDE plugin
- 🎯 **Accurate Detection**: Context-aware analysis reduces false positives

## Project Structure
```
├── src/
│   ├── detectors/              # Vulnerability detection modules
│   │   ├── *.py                # Solidity detectors
│   │   └── bytecode_*.py       # Bytecode detectors
│   ├── parsers/                # Code parsing modules
│   │   ├── solidity_parser.py  # Solidity source parser
│   │   └── bytecode_parser.py  # EVM bytecode parser
│   ├── analysis/               # Advanced analysis modules
│   │   └── fuzzer.py           # Dynamic analysis (fuzzing)
│   ├── api/                    # API modules
│   │   └── remix_api.py        # Remix IDE API (standalone)
│   ├── utils/                   # Helper utilities
│   │   ├── reporter.py         # Report generation
│   │   └── performance.py      # Performance optimization
│   └── main.py                 # CLI entry point
├── test_contracts/             # Test contracts
│   ├── vulnerable_*.sol        # Vulnerable Solidity contracts
│   └── test_*.bin              # Bytecode test files
├── remix-plugin/               # Remix IDE plugin
│   ├── remix-vulnerability-detector.js
│   └── README.md
├── gui_app.py                  # Desktop GUI application
├── web_app.py                  # Web-based interface (includes Remix API)
├── start_remix_api.py          # Standalone Remix API server
├── test_fuzzer.py              # Fuzzing module test script
└── requirements.txt            # Python dependencies
```

## 🚀 Quick Start

### Prerequisites
- Python 3.7 or higher
- pip (Python package installer)

### 1. Installation

#### Clone or Download the Project
```bash
# If using git
git clone <repository-url>
cd "FYP Smart Contract Vul Detect"

# Or download and extract the project files
```

#### Install Python Dependencies
```bash
# Install all required packages
python -m pip install -r requirements.txt

# Or install individual packages
python -m pip install click colorama rich tabulate flask flask-cors
```

**Note**: `flask-cors` is required for Remix IDE integration.

### 2. Running the System

#### Option 1: Command Line Interface (CLI)
```bash
# Analyze a Solidity contract
python src/main.py test_contracts/vulnerable_overflow.sol

# Analyze bytecode file (auto-detects file type)
python src/main.py test_contracts/test_reentrancy_only.bin

# Analyze with verbose output (shows performance metrics)
python src/main.py test_contracts/vulnerable_overflow.sol --verbose

# Save results to JSON file
python src/main.py test_contracts/vulnerable_overflow.sol --output results.json --format json

# Enable advanced features
python src/main.py contract.sol --enable-fuzzing    # Enable fuzzing
```

#### Option 2: Simple Analysis Runner
```bash
# Analyze a specific contract
python run_analysis.py test_contracts/vulnerable_overflow.sol

# Analyze all test contracts
python run_analysis.py
```

#### Option 3: Desktop GUI Application
```bash
# Launch the desktop application
python gui_app.py
```
- Select contract file using "Browse" button
- Choose detectors to run
- Click "Start Analysis"
- View results in the interface

#### Option 4: Web Application
```bash
# Start the web server (includes Remix API)
python web_app.py

# Open your browser and go to:
# http://localhost:5000
```
- Upload contract file (`.sol` or `.bin`)
- Select detectors
- Click "Analyze Contract"
- View performance metrics
- Download results if needed

**Features:**
- ⚡ Performance optimized (parallel execution, caching)
- 📊 Performance metrics included in results
- 🔌 Remix API endpoints at `/api/*`
- 📦 Bytecode file support

#### Option 5: Remix IDE Integration
```bash
# Start web app (includes Remix API)
python web_app.py

# Or start standalone Remix API server
python start_remix_api.py
```

**Remix Plugin Setup:**
1. Load `remix-plugin/remix-vulnerability-detector.js` in Remix IDE
2. Configure API endpoint: `http://localhost:5000`
3. Click "Scan Contract" in plugin panel
4. View results directly in Remix

**API Endpoints:**
- `GET /api/health` - Health check
- `POST /api/analyze` - Analyze contract
- `GET /api/detectors` - List available detectors

### 3. Testing the System

#### Test with Provided Contracts
```bash
# Test overflow/underflow detection
python run_analysis.py test_contracts/vulnerable_overflow.sol

# Test access control detection
python run_analysis.py test_contracts/vulnerable_access_control.sol

# Test reentrancy detection
python run_analysis.py test_contracts/vulnerable_reentrancy.sol

# Test time manipulation detection
python run_analysis.py test_contracts/vulnerable_time_manipulation.sol

# Test denial of service detection
python run_analysis.py test_contracts/vulnerable_denial_of_service.sol

# Test unprotected selfdestruct detection
python run_analysis.py test_contracts/vulnerable_unprotected_selfdestruct.sol

# Test with your own contract
python run_analysis.py test_contracts/test.sol

#### Test Bytecode Files
```bash
# Test bytecode overflow detection
python src/main.py test_contracts/test_overflow_only.bin

# Test bytecode reentrancy detection
python src/main.py test_contracts/test_reentrancy_only.bin

# Test bytecode access control detection
python src/main.py test_contracts/test_access_control_only.bin

# Test bytecode time manipulation detection
python src/main.py test_contracts/test_time_manipulation_only.bin

# Test bytecode DoS detection
python src/main.py test_contracts/test_denial_of_service_only.bin

# Test bytecode selfdestruct detection
python src/main.py test_contracts/test_unprotected_selfdestruct_only.bin
```
```

#### Run All Tests
```bash
# Analyze all test contracts
python run_analysis.py
```

## 📋 Available Commands

### CLI Commands
```bash
# Basic usage (auto-detects .sol or .bin)
python src/main.py <contract_file>

# With options
python src/main.py <contract_file> [OPTIONS]

# Options:
--output, -o FILE              Output file for results
--format FORMAT                Output format (json, text)
--verbose, -v                  Verbose output (includes performance metrics)
--enable-fuzzing               Enable dynamic analysis (fuzzing)
--enable-cfg                   Enable control-flow analysis
--enable-formal                Enable formal verification
--help                         Show help message
```

### GUI Commands
```bash
# Launch GUI
python gui_app.py

# GUI Features:
- File browser for contract selection
- Detector selection checkboxes
- Real-time analysis progress
- Results display with syntax highlighting
- Save results to file
```

### Web App Commands
```bash
# Start web server (includes Remix API)
python web_app.py

# Web Features:
- File upload interface (.sol and .bin files)
- Detector selection
- Real-time analysis with performance metrics
- JSON/Text download options
- Responsive design
- Performance optimized (caching, parallel execution)
- Remix API endpoints at /api/*
```

### Remix API Commands
```bash
# Start standalone Remix API server
python start_remix_api.py

# Or use web app (includes API)
python web_app.py

# API Endpoints:
GET  /api/health              # Health check
POST /api/analyze             # Analyze contract
GET  /api/detectors           # List detectors
```

## 🧪 Test Contracts

The system includes several test contracts:

### Solidity Test Contracts

| File | Purpose | Expected Vulnerabilities |
|------|---------|-------------------------|
| `vulnerable_overflow.sol` | Tests overflow/underflow detection | Integer overflow, unsafe arithmetic |
| `vulnerable_access_control.sol` | Tests access control detection | Missing access modifiers, public functions |
| `vulnerable_reentrancy.sol` | Tests reentrancy detection | External calls before state updates |
| `vulnerable_time_manipulation.sol` | Tests time manipulation detection | Vulnerable time operations, block.timestamp issues |
| `vulnerable_denial_of_service.sol` | Tests DoS detection | Unbounded loops, external calls in loops |
| `vulnerable_unprotected_selfdestruct.sol` | Tests selfdestruct detection | Unprotected selfdestruct calls |
| `test.sol` | Large contract with multiple issues | Various vulnerability types |

### Bytecode Test Contracts

| File | Purpose | Expected Vulnerabilities |
|------|---------|-------------------------|
| `test_overflow_only.bin` | Tests bytecode overflow detection | Integer overflow in bytecode |
| `test_access_control_only.bin` | Tests bytecode access control | Missing access control in bytecode |
| `test_reentrancy_only.bin` | Tests bytecode reentrancy | Reentrancy patterns in bytecode |
| `test_time_manipulation_only.bin` | Tests bytecode time manipulation | Time-based vulnerabilities |
| `test_denial_of_service_only.bin` | Tests bytecode DoS | DoS patterns in bytecode |
| `test_unprotected_selfdestruct_only.bin` | Tests bytecode selfdestruct | Unprotected selfdestruct |

## 🔧 Troubleshooting

### Common Issues

#### 1. Python Not Found
```bash
# Windows: Install Python from python.org
# Or use Microsoft Store version

# Verify installation
python --version
pip --version
```

#### 2. Missing Dependencies
```bash
# Install missing packages
python -m pip install <package-name>

# Common packages:
python -m pip install click colorama rich tabulate flask
```

#### 3. Unicode Encoding Errors
```bash
# If you see Unicode errors with large contracts:
# The system automatically handles Unicode characters
# If issues persist, save your contract file with UTF-8 encoding
```

#### 4. File Not Found
```bash
# Make sure you're in the correct directory
cd "D:\FYP Smart Contract Vul Detect"

# Check if files exist
dir test_contracts
```

### Getting Help
```bash
# Show help for CLI
python src/main.py --help

# Show help for run_analysis
python run_analysis.py --help
```

## 📊 Expected Output

### Successful Analysis
```
🔍 Analyzing contract: test_contracts/vulnerable_overflow.sol
============================================================
✓ Initialized parser and detectors
✓ Contract parsed successfully
  - Contract name: VulnerableContract
  - Functions found: 5
  - Variables found: 3

🔍 Running OverflowDetector...
  ⚠️  Found 2 potential issues
    - Integer Overflow: Unsafe arithmetic operation
    - Missing SafeMath: No overflow protection detected

🔍 Running AccessControlDetector...
  ✅ No issues found

🔍 Running ReentrancyDetector...
  ✅ No issues found

📊 Analysis Summary:
============================================================
Total vulnerabilities found: 2
OverflowDetector: 2 issues
AccessControlDetector: 0 issues
ReentrancyDetector: 0 issues
```

### No Vulnerabilities Found
```
✅ No vulnerabilities detected! Contract appears secure.
```

## 🎯 Target Vulnerabilities

### 1. Overflow/Underflow
- **Pattern**: Arithmetic operations without SafeMath or Solidity 0.8+ checks
- **Example**: `uint256 a = b + c;` without overflow protection
- **Detection**: Checks for missing SafeMath usage and unsafe arithmetic

### 2. Access Control
- **Pattern**: Missing or incorrect access modifiers
- **Example**: Functions without `onlyOwner` or similar restrictions
- **Detection**: Identifies public functions that should be restricted

### 3. Reentrancy
- **Pattern**: External calls before state updates
- **Example**: `externalContract.call()` before updating balances
- **Detection**: Analyzes call patterns and state modification order

### 4. Time Manipulation
- **Pattern**: Vulnerable time-based operations and comparisons
- **Example**: `block.timestamp` arithmetic without validation
- **Detection**: Identifies dangerous time operations and manipulation vectors

### 5. Denial of Service
- **Pattern**: Unbounded loops and gas-consuming operations
- **Example**: External calls in loops without limits
- **Detection**: Finds DoS attack vectors and gas limit issues

### 6. Unprotected Selfdestruct
- **Pattern**: Selfdestruct calls without proper access control
- **Example**: `selfdestruct()` without `onlyOwner` modifier
- **Detection**: Identifies unprotected contract destruction calls

## 📈 Performance

### Performance Metrics
- **Analysis Time**: 
  - Small contracts (< 100 lines): ~0.2-0.4s (cached: ~0.05s)
  - Medium contracts (100-500 lines): ~0.4-0.8s (cached: ~0.1s)
  - Large contracts (> 500 lines): ~0.8-2.0s (cached: ~0.2s)
- **Speed Improvement**: 2-3x faster with parallel execution and caching
- **Memory Usage**: ~50-100MB for large contracts
- **Supported File Sizes**: Up to 16MB
- **Supported Solidity Versions**: 0.4.0 to 0.8.x
- **Supported Formats**: Solidity (`.sol`) and EVM Bytecode (`.bin`)

### Performance Features
- ⚡ **Parallel Detector Execution**: Detectors run simultaneously
- 💾 **AST Caching**: Parsed ASTs cached in memory and disk
- 📊 **Performance Monitoring**: Built-in metrics tracking
- 🔄 **Optimized Regex**: Pre-compiled patterns for faster matching

## 🔄 Development Status

- [x] Project setup and research
- [x] Implement Solidity parser
- [x] Implement Bytecode parser
- [x] Create vulnerability detectors (6 types for Solidity)
- [x] Create bytecode detectors (6 types for bytecode)
- [x] Build comprehensive test suite
- [x] Create GUI application
- [x] Create web application
- [x] Unicode handling and error fixes
- [x] Enhanced vulnerability detection
- [x] Multi-interface support (CLI, GUI, Web)
- [x] Performance optimization (parallel execution, caching)
- [x] IDE integration (Remix)
- [x] Dynamic analysis (Fuzzing module)
- [x] Documentation

## 🔬 Advanced Features

### Fuzzing (Dynamic Analysis)
The system includes an optional fuzzing module for dynamic analysis:

```bash
# Enable fuzzing in CLI
python src/main.py contract.sol --enable-fuzzing -v

# Test fuzzer module
python test_fuzzer.py
```

**Features:**
- Generates test inputs for function parameters
- Tests with boundary values and random inputs
- Detects input-dependent vulnerabilities
- Works with existing AST structure

### Performance Optimization
Built-in performance optimizations:

- **Parallel Execution**: Detectors run simultaneously
- **AST Caching**: Instant results for cached files
- **Performance Metrics**: Track analysis time per component
- **Optimized Patterns**: Pre-compiled regex for faster matching

View performance metrics with `--verbose` flag or in web app results.

### Remix IDE Integration
Full Remix IDE support through REST API:

- **Plugin**: Load `remix-plugin/remix-vulnerability-detector.js`
- **API Endpoints**: Available at `/api/*` when web app is running
- **Real-time Scanning**: Scan contracts directly from Remix
- **Selective Detection**: Choose which detectors to run

## 📚 Additional Documentation

- `PERFORMANCE_OPTIMIZATION.md` - Performance optimization guide
- `remix-plugin/README.md` - Remix plugin setup instructions
- `FUZZING.md` - Fuzzing module documentation (if available)

## 📝 License

This project is developed for educational purposes as part of a Final Year Project (FYP).

## 🤝 Contributing

This is an academic project. For questions or issues, please contact the project author.

## 🎯 Summary

This Smart Contract Vulnerability Detection System provides:
- ✅ **6 Vulnerability Types** - Comprehensive security coverage
- ✅ **Dual Analysis** - Solidity source code and EVM bytecode
- ✅ **Multiple Interfaces** - CLI, GUI, Web App, Remix IDE
- ✅ **Performance Optimized** - Fast analysis with caching
- ✅ **Advanced Features** - Fuzzing, performance monitoring
- ✅ **Production Ready** - Fully functional and tested




