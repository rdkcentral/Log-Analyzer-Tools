# Log Quality Analyzer

A Python-based tool for analyzing log files to detect noisy logging, sensitive data exposure, and incorrect severity usage. Designed for integration into unit test workflows and CI/CD pipelines.

## Overview

This tool analyzes log files and generates an HTML report identifying three categories of logging issues:

1. **Noisy Logs** - Excessive logging at verbose levels (DEBUG, TRACE, INFO)
2. **Sensitive Data Exposure** - Detection of PII, tokens, passwords, and other sensitive information
3. **Severity Violations** - Failure conditions logged at incorrect severity levels

## Files

- `noisyLogDetector.py` - Main analyzer script
- `rules.yml` - Configuration file defining detection rules

## Requirements

- Python 3.6+
- PyYAML library

## Installation

```bash
pip install pyyaml
```

## Usage

The script supports two modes of operation, selected via the `--mode` argument.

| Mode | Description |
|------|-------------|
| `file` (default) | Analyze an existing log file and produce an HTML report |
| `gtest` | Auto-discover and execute all GoogleTest cases, capture their logs, and analyze each one |

---

### Mode: `file` (Default)

Analyze an existing log file and generate a single HTML report.

```bash
python3 noisylogdetector.py <log_file> <output.html>
# or explicitly:
python3 noisylogdetector.py --mode file <log_file> <output.html>
```

**Arguments:**
- `<log_file>` - Path to the log file to analyze
- `<output.html>` - Path for the generated HTML report

**Example:**
```bash
python3 noisylogdetector.py app.log report.html
```

---

### Mode: `gtest`

Automatically discovers all test cases in a GoogleTest binary, runs each test individually, captures its output as a log file, analyzes the log for quality issues, and generates both per-test and consolidated HTML reports.

```bash
python3 noisylogdetector.py --mode gtest <gtest_binary> [output_dir]
# or using the named flag:
python3 noisylogdetector.py --mode gtest <gtest_binary> --output-dir <dir>
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `<gtest_binary>` | Yes | Path to the compiled GoogleTest executable |
| `[output_dir]` | No | Directory to write all output files (default: `./gtest_analysis`) |
| `--output-dir <dir>` | No | Alternative named flag for output directory |
| `--env VAR=value` | No | Set an environment variable for test execution. Repeatable. |
| `--rules <file>` | No | Path to rules YAML file (default: `rules.yml`) |

**Examples:**

```bash
# Basic usage – run all tests and save reports to ./gtest_analysis/
python3 noisylogdetector.py --mode gtest ./build/my_tests

# Specify a custom output directory
python3 noisylogdetector.py --mode gtest ./build/my_tests ./reports/

# Using --output-dir flag
python3 noisylogdetector.py --mode gtest ./build/my_tests --output-dir ./reports/

# Pass environment variables to the test binary
python3 noisylogdetector.py --mode gtest ./build/my_tests \
    --env RDK_LOG_LEVEL=DEBUG \
    --env MOCK_SERVER=localhost:9090

# Use a custom rules file
python3 noisylogdetector.py --mode gtest ./build/my_tests --rules custom_rules.yml
```

**What gtest mode does:**

1. Runs `<gtest_binary> --gtest_list_tests` to discover all test suites and cases.
2. For each test case, runs `<gtest_binary> --gtest_filter=<TestSuite.TestCase>` and writes stdout/stderr to `gtest_log_<TestSuite_TestCase>.txt` in the output directory.
3. Analyzes each log file using the configured rules.
4. Generates an individual HTML report (`report_<TestSuite_TestCase>.html`) for each test.
5. Generates a **consolidated report** (`consolidated_gtest_report.html`) summarising all tests and total issue counts.

**Output directory structure:**

```
gtest_analysis/
├── gtest_log_MySuite_TestA.txt         # Raw captured log per test
├── report_MySuite_TestA.html           # Per-test log quality report
├── gtest_log_MySuite_TestB.txt
├── report_MySuite_TestB.html
└── consolidated_gtest_report.html      # Summary of all tests
```

**Console summary example:**

```
Discovering test cases in ./build/my_tests...
Found 3 test cases
[1/3] Running MySuite.TestA...
  Status: PASSED | Issues: 2 noisy, 0 sensitive, 0 severity
[2/3] Running MySuite.TestB...
  Status: FAILED | Issues: 0 noisy, 1 sensitive, 1 severity
[3/3] Running MySuite.TestC...
  Status: PASSED | Issues: 0 noisy, 0 sensitive, 0 severity

=== GTest Analysis Summary ===
Total tests run: 3
Passed: 2
Failed: 1
Errors/Timeouts: 0

Total Log Quality Issues:
  Noisy logs: 2
  Sensitive data: 1
  Severity violations: 1

Reports generated in: ./gtest_analysis
Consolidated report: ./gtest_analysis/consolidated_gtest_report.html
```

---

### Integration in Unit Test Workflows

#### GitHub Actions – File Mode

```yaml
name: Log Quality Check

on: [push, pull_request]

jobs:
  analyze-logs:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.x'

      - name: Install dependencies
        run: pip install pyyaml

      - name: Run tests and capture logs
        run: |
          ./run_tests.sh > test.log 2>&1 || true

      - name: Analyze log quality
        run: |
          python3 noisylogdetector.py test.log log-report.html

      - name: Upload report
        uses: actions/upload-artifact@v3
        with:
          name: log-quality-report
          path: log-report.html
```

#### GitHub Actions – GTest Mode

```yaml
name: GTest Log Quality Check

on: [push, pull_request]

jobs:
  gtest-log-analysis:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.x'

      - name: Install dependencies
        run: pip install pyyaml

      - name: Build GTest binary
        run: cmake --build ./build --target my_tests

      - name: Run GTest log analysis
        run: |
          python3 noisylogdetector.py --mode gtest ./build/my_tests \
            --output-dir ./gtest_reports \
            --env RDK_LOG_LEVEL=DEBUG

      - name: Upload reports
        uses: actions/upload-artifact@v3
        with:
          name: gtest-log-quality-reports
          path: gtest_reports/
```

#### Local Test Integration – File Mode

```bash
# Run your tests and save logs
./your_test_command > test_output.log 2>&1

# Analyze the logs
python3 noisylogdetector.py test_output.log report.html

# Open the report
xdg-open report.html  # Linux
open report.html      # macOS
start report.html     # Windows
```

#### Local Test Integration – GTest Mode

```bash
# Run all gtests and analyze their logs
python3 noisylogdetector.py --mode gtest ./build/my_tests --output-dir ./reports

# Open the consolidated report
xdg-open ./reports/consolidated_gtest_report.html  # Linux
open ./reports/consolidated_gtest_report.html      # macOS
start ./reports/consolidated_gtest_report.html     # Windows
```

## Configuration

Edit `rules.yml` to customize detection rules:

### Sensitive Patterns

Add regex patterns to detect sensitive information:

```yaml
sensitive_patterns:
  - '(?i)\btoken\s*[:=]\s*[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b'
  - '(?i)\b(api[_-]?key|apikey)\s*[:=]\s*[A-Za-z0-9]{20,}\b'
  - '(?i)\b(password|passwd|pwd)\s*[:=]\s*\S{6,}\b'
```

### Noisy Log Levels

Define which log levels are considered noisy:

```yaml
noisy_log_levels:
  - DEBUG
  - TRACE
  - INFO
```

### Failure Keywords

Keywords that indicate failure conditions:

```yaml
failure_keywords:
  - 'failed'
  - 'error'
  - 'exception'
  - 'timeout'
```

### Required Severity on Failure

Log levels that must be used when failures occur:

```yaml
required_severity_on_failure:
  - ERROR
  - WARN
```

## Supported Log Formats

The analyzer recognizes log lines with the following timestamp formats:

- `HH:MM:SS` or `HH:MM:SS.ssssss` (e.g., `04:31:14` or `04:31:14.109764`)
- `YYYY-MM-DD HH:MM:SS` or `YYYY-MM-DD HH:MM:SS.sss` (e.g., `2024-11-11 04:31:14`)
- `Mon DD HH:MM:SS` (e.g., `Nov 11 04:31:14`)

Lines without recognized timestamps are ignored.

## Output

The tool generates an HTML report with three sections:

1. **Noisy Logs** - Lines logged at noisy levels
2. **Sensitive / PII Logs** - Lines containing sensitive data (redacted in report)
3. **Severity Violations** - Failures not logged at appropriate severity

Each entry includes:
- Line number in the original log file
- Reason for flagging
- Log content (with sensitive data redacted as `[REDACTED]`)

## Exit Codes

- `0` - Analysis completed successfully
- `1` - Error (missing file, invalid configuration, etc.)

## CI/CD Best Practices

1. **Always run on test logs** - Don't analyze production logs in CI
2. **Archive reports** - Save HTML reports as build artifacts
3. **Set thresholds** - Optionally fail builds if too many issues found
4. **Regular reviews** - Periodically review and update `rules.yml`

## Troubleshooting

### Logs not being detected

- Verify timestamp format matches supported patterns
- Check that timestamps are at the start of each line
- Ensure log lines have proper log level markers (ERROR, WARN, INFO, etc.)

### Configuration errors

```
Error: rules.yml is missing required keys: ...
```

Ensure all required keys are present in `rules.yml`:
- `sensitive_patterns`
- `failure_keywords`
- `noisy_log_levels`
- `required_severity_on_failure`

### File not found

```
Log file not found: <path>
```

Verify the log file path is correct and the file exists.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Update `rules.yml` if adding new detection patterns
5. Submit a pull request


