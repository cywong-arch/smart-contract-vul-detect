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
- Parsing Solidity smart contracts
- Identifying vulnerable code patterns
- Analyzing control flow and data flow
- Reporting potential security issues

## Project Structure
```
├── src/
│   ├── detectors/          # Vulnerability detection modules
│   ├── parsers/           # Solidity code parsing
│   └── utils/             # Helper utilities
├── test_contracts/        # Test smart contracts (vulnerable & secure)
├── examples/              # Usage examples
├── gui_app.py            # Desktop GUI application
├── web_app.py            # Web-based interface
├── run_analysis.py       # Simple analysis runner
└── requirements.txt      # Python dependencies
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
python -m pip install click colorama rich tabulate flask
```

### 2. Running the System

#### Option 1: Command Line Interface (CLI)
```bash
# Analyze a single contract
python src/main.py test_contracts/vulnerable_overflow.sol

# Analyze with verbose output
python src/main.py test_contracts/vulnerable_overflow.sol --verbose

# Save results to JSON file
python src/main.py test_contracts/vulnerable_overflow.sol --output results.json --format json
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
# Start the web server
python web_app.py

# Open your browser and go to:
# http://localhost:5000
```
- Upload contract file
- Select detectors
- Click "Analyze Contract"
- Download results if needed

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

# Test secure contract (should find no vulnerabilities)
python run_analysis.py test_contracts/secure_contract.sol

# Test with your own contract
python run_analysis.py test_contracts/test.sol
```

#### Run All Tests
```bash
# Analyze all test contracts
python run_analysis.py
```

## 📋 Available Commands

### CLI Commands
```bash
# Basic usage
python src/main.py <contract_file.sol>

# With options
python src/main.py <contract_file.sol> [OPTIONS]

# Options:
--output, -o FILE     Output file for results
--format FORMAT       Output format (json, text)
--verbose, -v         Verbose output
--help               Show help message
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
# Start web server
python web_app.py

# Web Features:
- File upload interface
- Detector selection
- Real-time analysis
- JSON/Text download options
- Responsive design
```

## 🧪 Test Contracts

The system includes several test contracts:

| File | Purpose | Expected Vulnerabilities |
|------|---------|-------------------------|
| `vulnerable_overflow.sol` | Tests overflow/underflow detection | Integer overflow, unsafe arithmetic |
| `vulnerable_access_control.sol` | Tests access control detection | Missing access modifiers, public functions |
| `vulnerable_reentrancy.sol` | Tests reentrancy detection | External calls before state updates |
| `vulnerable_time_manipulation.sol` | Tests time manipulation detection | Vulnerable time operations, block.timestamp issues |
| `vulnerable_denial_of_service.sol` | Tests DoS detection | Unbounded loops, external calls in loops |
| `vulnerable_unprotected_selfdestruct.sol` | Tests selfdestruct detection | Unprotected selfdestruct calls |
| `secure_contract.sol` | Tests false positive handling | No vulnerabilities (secure patterns) |
| `test.sol` | Large contract with multiple issues | Various vulnerability types |

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

- **Analysis Time**: Typically 1-10 seconds per contract
- **Memory Usage**: ~50-100MB for large contracts
- **Supported File Sizes**: Up to 16MB
- **Supported Solidity Versions**: 0.4.0 to 0.8.x

## 🔄 Development Status

- [x] Project setup and research
- [x] Implement Solidity parser
- [x] Create vulnerability detectors (6 types)
- [x] Build comprehensive test suite
- [x] Create GUI application
- [x] Create web application
- [x] Unicode handling and error fixes
- [x] Enhanced vulnerability detection
- [x] Multi-interface support (CLI, GUI, Web)
- [x] Documentation
- [ ] Performance optimization
- [ ] Additional vulnerability types
- [ ] IDE integration (Remix)

## 📝 License

This project is developed for educational purposes as part of a Final Year Project (FYP).

## 🤝 Contributing

This is an academic project. For questions or issues, please contact the project author.




