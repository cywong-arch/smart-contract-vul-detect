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
- **Bytecode optimization analysis** (optional)
- Reporting potential security issues

## ✨ Key Features

- 🔍 **Dual Analysis**: Supports both Solidity source code (`.sol`) and EVM bytecode (`.bin`)
- ⚡ **Performance Optimized**: Parallel detector execution, AST caching (2-3x faster)
- 🌐 **Multiple Interfaces**: CLI, GUI, Web App, and Remix IDE integration
- 🧪 **Fuzzing Support**: Optional dynamic analysis with test input generation (auto-enabled for `.sol` files)
- 🔧 **Bytecode Optimization**: Optional bytecode optimization analysis (auto-enabled for `.bin` files)
- 📊 **Performance Metrics**: Built-in performance monitoring and reporting
- 🔌 **IDE Integration**: REST API for Remix IDE plugin
- 🎯 **Accurate Detection**: Context-aware analysis reduces false positives
- 🎨 **Modern Web UI**: Enhanced user interface with filtering, search, and dynamic contract listing
- 📈 **Statistics Dashboard**: Real-time vulnerability statistics and visualization

## Project Structure
```
├── src/
│   ├── detectors/              # Vulnerability detection modules
│   │   ├── *.py                # Solidity detectors (6 types)
│   │   └── bytecode_*.py       # Bytecode detectors (6 types)
│   ├── parsers/                # Code parsing modules
│   │   ├── solidity_parser.py  # Solidity source parser
│   │   └── bytecode_parser.py  # EVM bytecode parser
│   ├── analysis/               # Advanced analysis modules
│   │   └── fuzzer.py           # Dynamic analysis (fuzzing)
│   ├── optimization/           # Bytecode optimization modules
│   │   └── optimizer.py       # Bytecode optimization analysis
│   ├── api/                    # API modules
│   │   └── remix_api.py        # Remix IDE API (standalone)
│   ├── utils/                   # Helper utilities
│   │   ├── reporter.py         # Report generation
│   │   └── performance.py     # Performance optimization
│   └── main.py                 # CLI entry point
├── test_contracts/             # Comprehensive test contract suite
│   ├── vulnerable_*.sol        # Basic vulnerable contracts
│   ├── *_level1_basic.sol      # Level 1 (basic) test contracts
│   ├── *_level2_intermediate.sol # Level 2 (intermediate) test contracts
│   ├── *_level3_advanced.sol  # Level 3 (advanced) test contracts
│   ├── mixed_vuln_*.sol        # Mixed vulnerability test contracts
│   └── *.bin                   # Compiled bytecode files
├── remix-plugin/               # Remix IDE plugin
│   ├── remix-vulnerability-detector.js
│   └── README.md
├── gui_app.py                  # Desktop GUI application
├── web_app.py                  # Web-based interface (includes Remix API)
├── start_remix_api.py          # Standalone Remix API server
├── requirements.txt            # Python dependencies
├── FUZZING_VS_STATIC_ANALYSIS.md # Fuzzing documentation
└── PERFORMANCE_OPTIMIZATION.md # Performance guide
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
python -m pip install click colorama rich tabulate flask flask-cors py-solc-x
```

**Note**: `flask-cors` is required for Remix IDE integration. `py-solc-x` is required for Solidity compilation.

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
python src/main.py contract.bin --enable-optimization # Enable bytecode optimization
```

#### Option 2: Desktop GUI Application
```bash
# Launch the desktop application
python gui_app.py
```
- Select contract file using "Browse" button
- Choose detectors to run
- Click "Start Analysis"
- View results in the interface

#### Option 3: Web Application (Recommended)
```bash
# Start the web server (includes Remix API)
python web_app.py

# Open your browser and go to:
# http://localhost:5000
```

**Enhanced Web App Features:**
- 📁 **Dynamic Contract Browser**: Browse and select from all available test contracts
- 🔍 **Search & Filter**: Filter contracts by vulnerability type, level, and contract type
- 📊 **Statistics Dashboard**: Real-time vulnerability statistics with visual cards
- ⚡ **Auto-Advanced Analysis**: Fuzzing auto-enabled for `.sol` files, optimization for `.bin` files
- 📥 **Download Results**: Export analysis results in JSON or text format
- 🎨 **Modern UI**: Responsive design with improved visualization
- 📈 **Performance Metrics**: Built-in performance monitoring

**Usage:**
1. Upload contract file (`.sol` or `.bin`) OR select from available test contracts
2. Advanced analysis (fuzzing/optimization) is automatically enabled based on file type
3. Click "Analyze Contract"
4. View detailed results with statistics
5. Download results if needed

### 3. Testing the System

#### Test with Level-Based Contracts
```bash
# Test basic level contracts
python src/main.py test_contracts/overflow_level1_basic.sol
python src/main.py test_contracts/access_control_level1_basic.sol
python src/main.py test_contracts/reentrancy_level1_basic.sol
python src/main.py test_contracts/time_manipulation_level1_basic.sol
python src/main.py test_contracts/denial_of_service_level1_basic.sol
python src/main.py test_contracts/unprotected_selfdestruct_level1_basic.sol

# Test intermediate level contracts
python src/main.py test_contracts/overflow_level2_intermediate.sol
python src/main.py test_contracts/access_control_level2_intermediate.sol
# ... and so on

# Test advanced level contracts
python src/main.py test_contracts/overflow_level3_advanced.sol
python src/main.py test_contracts/access_control_level3_advanced.sol
# ... and so on
```

#### Test with Mixed Vulnerability Contracts
```bash
# Test mixed vulnerability contracts
python src/main.py test_contracts/mixed_vuln_level1_overflow_only.sol
python src/main.py test_contracts/mixed_vuln_level2_overflow_accesscontrol.sol
python src/main.py test_contracts/mixed_vuln_level3_overflow_accesscontrol_reentrancy.sol

# Test progressive time manipulation + DoS contracts
python src/main.py test_contracts/mixed_vuln_level1_time_dos.sol      # Time only
python src/main.py test_contracts/mixed_vuln_level2_time_dos.sol      # Time + DoS
python src/main.py test_contracts/mixed_vuln_level3_time_dos.sol      # Time + DoS + Selfdestruct
```

#### Test with Basic Vulnerable Contracts
```bash
# Test overflow/underflow detection
python src/main.py test_contracts/vulnerable_overflow.sol

# Test access control detection
python src/main.py test_contracts/vulnerable_access_control.sol

# Test reentrancy detection
python src/main.py test_contracts/vulnerable_reentrancy.sol

# Test time manipulation detection
python src/main.py test_contracts/vulnerable_time_manipulation.sol

# Test denial of service detection
python src/main.py test_contracts/vulnerable_denial_of_service.sol

# Test unprotected selfdestruct detection
python src/main.py test_contracts/vulnerable_unprotected_selfdestruct.sol
```

#### Test Bytecode Files
```bash
# Test bytecode overflow detection
python src/main.py test_contracts/test_overflow_only.bin --verbose

# Test bytecode reentrancy detection
python src/main.py test_contracts/test_reentrancy_only.bin --verbose

# Test bytecode access control detection
python src/main.py test_contracts/test_access_control_only.bin --verbose

# Test bytecode time manipulation detection
python src/main.py test_contracts/test_time_manipulation_only.bin --verbose

# Test bytecode DoS detection
python src/main.py test_contracts/test_denial_of_service_only.bin --verbose

# Test bytecode selfdestruct detection
python src/main.py test_contracts/test_unprotected_selfdestruct_only.bin --verbose
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
--enable-fuzzing               Enable dynamic analysis (fuzzing) - auto for .sol
--enable-optimization          Enable bytecode optimization - auto for .bin
--enable-cfg                   Enable control-flow analysis
--enable-formal                Enable formal verification
--help                         Show help message
```

### Web App Features
- **File Upload**: Drag-and-drop or click to upload `.sol` or `.bin` files
- **Contract Browser**: Browse and select from all available test contracts
- **Search & Filter**: 
  - Filter by vulnerability type (Overflow, Reentrancy, Time Manipulation, DoS, Access Control, Selfdestruct)
  - Filter by level (Level 1, Level 2, Level 3, Mixed)
  - Filter by contract type (Solidity, Bytecode)
  - Search by filename
- **Auto-Advanced Analysis**: 
  - Fuzzing automatically enabled for `.sol` files
  - Bytecode optimization automatically enabled for `.bin` files
- **Statistics Dashboard**: Real-time vulnerability counts and statistics
- **Results Display**: Detailed vulnerability reports with recommendations
- **Download Options**: Export results as JSON or text

## 🧪 Test Contracts

The system includes a comprehensive test suite with contracts organized by vulnerability type and complexity level:

### Level-Based Test Contracts

Each vulnerability type has three levels of complexity:

#### Level 1: Basic
- `*_level1_basic.sol` - Basic vulnerability patterns
- Examples: `overflow_level1_basic.sol`, `access_control_level1_basic.sol`, etc.

#### Level 2: Intermediate
- `*_level2_intermediate.sol` - Intermediate complexity patterns
- Examples: `overflow_level2_intermediate.sol`, `access_control_level2_intermediate.sol`, etc.

#### Level 3: Advanced
- `*_level3_advanced.sol` - Advanced and subtle patterns
- Examples: `overflow_level3_advanced.sol`, `access_control_level3_advanced.sol`, etc.

### Mixed Vulnerability Test Contracts

Progressive test contracts that combine multiple vulnerability types:

#### Overflow-Based Mixed Contracts
- `mixed_vuln_level1_overflow_only.sol` - Overflow only
- `mixed_vuln_level2_overflow_accesscontrol.sol` - Overflow + Access Control
- `mixed_vuln_level3_overflow_accesscontrol_reentrancy.sol` - Overflow + Access Control + Reentrancy

#### Time Manipulation + DoS Mixed Contracts
- `mixed_vuln_level1_time_dos.sol` - Time Manipulation only (100%)
- `mixed_vuln_level2_time_dos.sol` - Time Manipulation + DoS
- `mixed_vuln_level3_time_dos.sol` - Time Manipulation + DoS + Unprotected Selfdestruct

### Basic Vulnerable Contracts

| File | Purpose | Expected Vulnerabilities |
|------|---------|-------------------------|
| `vulnerable_overflow.sol` | Tests overflow/underflow detection | Integer overflow, unsafe arithmetic |
| `vulnerable_access_control.sol` | Tests access control detection | Missing access modifiers, public functions |
| `vulnerable_reentrancy.sol` | Tests reentrancy detection | External calls before state updates |
| `vulnerable_time_manipulation.sol` | Tests time manipulation detection | Vulnerable time operations, block.timestamp issues |
| `vulnerable_denial_of_service.sol` | Tests DoS detection | Unbounded loops, external calls in loops |
| `vulnerable_unprotected_selfdestruct.sol` | Tests selfdestruct detection | Unprotected selfdestruct calls |

### Bytecode Test Contracts

All test contracts are also available as compiled bytecode (`.bin` files) for bytecode analysis testing.

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
python -m pip install click colorama rich tabulate flask flask-cors py-solc-x
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
cd "FYP Smart Contract Vul Detect"

# Check if files exist
dir test_contracts
```

### Getting Help
```bash
# Show help for CLI
python src/main.py --help
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

📊 Analysis Summary:
============================================================
Total vulnerabilities found: 2
OverflowDetector: 2 issues
AccessControlDetector: 0 issues
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
- [x] Build comprehensive test suite (level-based and mixed contracts)
- [x] Create GUI application
- [x] Create web application with enhanced UI
- [x] Unicode handling and error fixes
- [x] Enhanced vulnerability detection
- [x] Multi-interface support (CLI, GUI, Web)
- [x] Performance optimization (parallel execution, caching)
- [x] IDE integration (Remix)
- [x] Dynamic analysis (Fuzzing module)
- [x] Bytecode optimization analysis
- [x] Contract browser and filtering in web app
- [x] Auto-selection of advanced analysis features
- [x] Statistics dashboard
- [x] Documentation

## 🔬 Advanced Features

### Fuzzing (Dynamic Analysis)
The system includes an optional fuzzing module for dynamic analysis:

```bash
# Enable fuzzing in CLI (auto-enabled for .sol files in web app)
python src/main.py contract.sol --enable-fuzzing -v
```

**Features:**
- Generates test inputs for function parameters
- Tests with boundary values and random inputs
- Detects input-dependent vulnerabilities
- Works with existing AST structure
- Automatically enabled for Solidity files in web app

**Note**: See `FUZZING_VS_STATIC_ANALYSIS.md` for detailed comparison between static analysis and fuzzing.

### Bytecode Optimization Analysis
Built-in bytecode optimization analysis:

```bash
# Enable optimization in CLI (auto-enabled for .bin files in web app)
python src/main.py contract.bin --enable-optimization -v
```

**Features:**
- Analyzes gas usage patterns
- Identifies optimization opportunities
- Provides gas savings estimates
- Automatically enabled for bytecode files in web app

### Performance Optimization
Built-in performance optimizations:

- **Parallel Execution**: Detectors run simultaneously
- **AST Caching**: Instant results for cached files
- **Performance Metrics**: Track analysis time per component
- **Optimized Patterns**: Pre-compiled regex for faster matching

View performance metrics with `--verbose` flag or in web app results.

## 📚 Additional Documentation

- `PERFORMANCE_OPTIMIZATION.md` - Performance optimization guide
- `FUZZING_VS_STATIC_ANALYSIS.md` - Detailed comparison of static analysis vs fuzzing
- `remix-plugin/README.md` - Remix plugin setup instructions

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
- ✅ **Advanced Features** - Fuzzing, bytecode optimization, performance monitoring
- ✅ **Comprehensive Test Suite** - Level-based and mixed vulnerability contracts
- ✅ **Enhanced Web UI** - Modern interface with filtering, search, and statistics
- ✅ **Production Ready** - Fully functional and tested
