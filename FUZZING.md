# 🧪 Fuzzing Function - Usage Guide

## Overview

The fuzzing module provides **dynamic analysis** by generating test inputs and analyzing contract behavior with different input scenarios. This helps detect vulnerabilities that may only appear with specific input values.

---

## 🚀 Quick Start

### Method 1: CLI with Fuzzing Flag

```bash
# Basic usage - enable fuzzing
python src/main.py test_contracts/vulnerable_reentrancy.sol --enable-fuzzing

# With verbose output (shows fuzzing details)
python src/main.py test_contracts/vulnerable_reentrancy.sol --enable-fuzzing -v

# Save results to file
python src/main.py test_contracts/vulnerable_reentrancy.sol --enable-fuzzing -o results.json --format json
```

### Method 2: Test Script

```bash
# Run the fuzzer test script
python test_fuzzer.py
```

This will:
- Test the input generator
- Run fuzzing on a sample contract
- Show results summary

---

### Method 2: Web App with Fuzzing
```bash
python web_app.py
```

### Step 2: Open Web Interface
Go to `http://localhost:5000` in your browser

### Step 3: Enable Fuzzing
1. Upload a Solidity contract file (`.sol`)
2. Scroll down to **"🧪 Advanced Analysis"** section
3. Check the **"Fuzzing (Dynamic Analysis)"** checkbox
4. Click **"🚀 Start Analysis"**

### Step 4: View Results
The results will include:
- Regular static analysis results
- Fuzzing analysis metrics
- Fuzzing-detected vulnerabilities (marked with "(Fuzzing)")
- Performance metrics

---

## 📋 How It Works

### 1. **Function Analysis**
- Identifies testable functions (public/external, non-view)
- Extracts function parameters and types
- Skips constructors and view/pure functions

### 2. **Input Generation**
The fuzzer generates test inputs for each function parameter:

**Boundary Values:**
- `uint256`: 0, 1, 2^256-1, 2^255, 10^18, etc.
- `address`: Zero address, max address, etc.
- `bool`: True, False
- `string`: Empty, short, long strings

**Random Values:**
- Random values within valid ranges
- Unpredictable test scenarios

### 3. **Vulnerability Detection**
The fuzzer analyzes functions with different inputs to detect:

- **Reentrancy** with large input values
- **DoS** with loop-based inputs
- **Overflow** with arithmetic operations
- **Access Control** with edge inputs (0, empty)

---

## 💻 Usage Examples

### Example 1: Basic Fuzzing

```bash
python src/main.py test_contracts/vulnerable_reentrancy.sol --enable-fuzzing -v
```

**Output:**
```
Analyzing Solidity contract: test_contracts/vulnerable_reentrancy.sol

[INFO] Running advanced analysis modules...
  [OK] Fuzzing analysis completed

Fuzzing Results:
  Functions tested: 2
  Iterations: 100
  Vulnerabilities found: 1

Vulnerabilities:
  1. Reentrancy (Fuzzing): Potential reentrancy in 'withdraw' with large input values
```

### Example 2: With Output File

```bash
python src/main.py test_contracts/vulnerable_denial_of_service.sol --enable-fuzzing -o fuzzing_results.json --format json
```

The JSON output will include:
```json
{
  "vulnerabilities": [...],
  "advanced_analysis": {
    "fuzzing": {
      "vulnerabilities": [...],
      "metrics": {
        "functions_tested": 3,
        "iterations": 150,
        "vulnerabilities_found": 2
      }
    }
  }
}
```

### Example 3: Test Fuzzer Module

```bash
python test_fuzzer.py
```

**Output:**
```
Testing Fuzzer Module
============================================================

1. Testing TestInputGenerator...
  uint256: [0, 1, 115792089237316195423570985008687907853269984665640564039457584007913129639935]...
  address: ['0x0000000000000000000000000000000000000000', '0xffffffffffffffffffffffffffffffffffffffff', '0x1111111111111111111111111111111111111111']...
  bool: [True, False]...
  string: ['', 'test', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']...

2. Testing Fuzzer...
  Parsed contract: test_contracts/vulnerable_reentrancy.sol
  Functions found: 3

3. Fuzzing Results:
  Vulnerabilities found: 1
  Functions tested: 2
  Iterations: 100
```

---

## ⚙️ Configuration

### Adjust Fuzzing Parameters

Edit `src/analysis/fuzzer.py`:

```python
class Fuzzer(BaseAnalysis):
    def __init__(self):
        super().__init__(...)
        self.max_iterations = 50  # Max iterations per function
        self.timeout = 30  # Timeout in seconds
```

**To increase thoroughness:**
- Increase `max_iterations` (e.g., 100, 200)
- More iterations = more test inputs = more thorough analysis

**To reduce time:**
- Decrease `max_iterations` (e.g., 25, 30)
- Fewer iterations = faster analysis

---

## 🎯 What Fuzzing Detects

### ✅ Currently Detects:

1. **Reentrancy (Fuzzing)**
   - Large input values that might trigger reentrancy
   - External calls without guards
   - **Example**: `withdraw(very_large_amount)` without reentrancy guard

2. **DoS (Fuzzing)**
   - Large loop-based inputs that cause gas exhaustion
   - Unbounded loops with large iteration counts
   - **Example**: `processPayments(10000)` in a loop

3. **Integer Overflow (Fuzzing)**
   - Very large arithmetic inputs
   - Operations that might overflow
   - **Example**: `multiply(2^200, 2^200)` without overflow protection

4. **Access Control (Fuzzing)**
   - Edge inputs (0, empty) that might bypass checks
   - Critical functions without access control
   - **Example**: `withdraw(0)` or `transfer("")` without checks

---

## 📊 Understanding Results

### Fuzzing-Specific Vulnerabilities

Fuzzing vulnerabilities are marked with `(Fuzzing)` in the type:

```
Reentrancy (Fuzzing) - Found through input testing
DoS (Fuzzing) - Found through input testing
Integer Overflow (Fuzzing) - Found through input testing
Access Control (Fuzzing) - Found through input testing
```

### Performance Metrics

When using `-v` flag, you'll see:

```
Fuzzing Metrics:
  Functions tested: 3
  Iterations: 150
  Vulnerabilities found: 2
```

---

## 🔄 Integration with Static Analysis

Fuzzing **complements** static analysis:

- **Static Detectors**: Find pattern-based vulnerabilities
- **Fuzzing**: Finds input-dependent vulnerabilities
- **Together**: Comprehensive coverage

**Example:**
- Static detector finds: "External call before state update"
- Fuzzing finds: "Reentrancy with large input (1000 ETH)"

---

## 🐛 Troubleshooting

### Issue: No vulnerabilities found
- **Solution**: The contract may be secure, or inputs didn't trigger vulnerabilities
- **Try**: Increase `max_iterations` in fuzzer.py

### Issue: Too many false positives
- **Solution**: Fuzzing is conservative, review manually
- **Note**: Fuzzing flags potential issues that need verification

### Issue: Fuzzing takes too long
- **Solution**: Reduce `max_iterations` in fuzzer.py
- **Default**: 50 iterations per function

### Issue: Import errors
- **Solution**: Make sure you're running from project root
- **Check**: `src/analysis/fuzzer.py` exists

---

## 📝 Best Practices

1. **Use with Static Analysis**: Run both static detectors and fuzzing
2. **Review Results**: Fuzzing finds potential issues, verify manually
3. **Adjust Iterations**: Balance between thoroughness and speed
4. **Test Multiple Contracts**: Fuzzing works best with various contract types

---

## 🎯 Example Workflow

```bash
# Step 1: Run static analysis
python src/main.py contract.sol -v

# Step 2: Run with fuzzing
python src/main.py contract.sol --enable-fuzzing -v

# Step 3: Compare results
# Static: Pattern-based vulnerabilities
# Fuzzing: Input-dependent vulnerabilities

# Step 4: Review and fix
# Address all found vulnerabilities
```

---

## ✅ Summary

**To use fuzzing:**

1. **CLI**: Add `--enable-fuzzing` flag
   ```bash
   python src/main.py contract.sol --enable-fuzzing -v
   ```

2. **Test Script**: Run test script
   ```bash
   python test_fuzzer.py
   ```

3. **Review Results**: Check for `(Fuzzing)` vulnerabilities

**Fuzzing helps find vulnerabilities that only appear with specific inputs!** 🚀

