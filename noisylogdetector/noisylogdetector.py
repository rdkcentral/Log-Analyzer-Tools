#!/usr/bin/env python3
#
# Copyright 2026 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# Log Quality Analyzer for RBUS
#
# This script analyzes log files to detect and report three categories of logging issues:
# 1. Noisy Logs: Excessive logging at verbose levels (DEBUG, TRACE, INFO)
# 2. Sensitive Data Exposure: Detection of PII or sensitive information in logs
# 3. Severity Violations: Failure conditions logged at incorrect severity levels
#
# The script reads configuration from rules.yml and generates an HTML report
# showing all detected issues with line numbers and redacted sensitive content.
#
# Usage: python3 noisylogdetector.py <log_file> <output.html>
# Requirements: rules.yml configuration file and Python 3 with PyYAML library

import re
import sys
import yaml
import argparse
import subprocess
import os
from html import escape
from pathlib import Path

# -----------------------------
def load_rules(path="rules.yml"):
    try:
        with open(path, "r") as f:
            rules= yaml.safe_load(f)
    except FileNotFoundError:
        print(f"Rules file not found: {path}", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(f"Permission denied while reading rules file: {path}", file=sys.stderr)
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"Failed to parse YAML rules file '{path}': {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error while loading rules from '{path}': {e}", file=sys.stderr)
        sys.exit(1)
    # --- Validate rules is a dict ---
    if not isinstance(rules, dict):
        print(f"Error: rules.yml is empty or not a valid YAML mapping.", file=sys.stderr)
        sys.exit(1)
    # --- Validate required keys ---
    required_keys = [
        "sensitive_patterns",
        "failure_keywords",
        "noisy_log_levels",
        "required_severity_on_failure"
    ]
    missing = [k for k in required_keys if k not in rules or rules[k] is None]
    if missing:
        print(f"Error: rules.yml is missing required keys: {', '.join(missing)}", file=sys.stderr)
        sys.exit(1)

    return rules

# -----------------------------
def starts_with_date_and_timestamp(line):
    """
    Matches log lines starting with any of the following timestamp patterns including leading whitespaces:
      - HH:MM:SS or HH:MM:SS.ssssss (e.g. 04:31:14 or 04:31:14.109764)
      - YYYY-MM-DD HH:MM:SS or YYYY-MM-DD HH:MM:SS.sss (e.g. 2024-11-11 04:31:14 or 2024-11-11 04:31:14.109)
      - Mon DD HH:MM:SS (e.g. Nov 11 04:31:14)
    Lines not matching these patterns at the start will be ignored.

    NOTE: If your log lines are not being reported, check:
      - The timestamp is at the very start of the line.
      - The timestamp matches one of the above formats.
      - If there are leading spaces, adjust the regex to allow them.
    """
    # This regex allows optional leading whitespace before the timestamp.
    return bool(re.match(
        r'^\s*(\d{2}:\d{2}:\d{2}(?:\.\d+)?|\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?|'
        r'(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',
        line
    ))

def detect_level(line):
    for lvl in ("FATAL","ERROR", "WARN", "INFO", "DEBUG", "TRACE"):
        if re.search(rf"\b{lvl}\b", line):
            return lvl
    return "UNKNOWN"

def extract_plugin_name(line):
    """Extract plugin name from WPE Framework log line with proper mapping"""
    
    # Pattern 1: [FileName.cpp:line] or [FileName.cpp +line] 
    pattern1 = r'\[([^\]]*\.(?:cpp|h))[:+]\d+\]'
    match = re.search(pattern1, line)
    if match:
        filename = match.group(1)
        # Map specific filenames to their plugin names based on actual log
        plugin_mapping = {
            'LegacyNetworkAPIs.cpp': 'NetworkAPIs',
            'NetworkManagerImplementation.cpp': 'NetworkManager', 
            'NetworkManagerJsonRpc.cpp': 'NetworkManager',
            'NetworkManagerConnectivity.cpp': 'NetworkManager',
            'AuthServiceImplementation.cpp': 'AuthService',
            'HdmiCecSourceImplementation.cpp': 'HdmiCecSource',
            'MaintenanceManager.cpp': 'MaintenanceManager',
            'SystemServices.cpp': 'SystemServices',
            'DisplaySettings.cpp': 'DisplaySettings',
            'RebootController.cpp': 'PowerManager',  # Based on log content 
            'ThermalController.cpp': 'ThermalController',
            'ThermalMfrImpl.h': 'ThermalController',
            'SecManagerSession.cpp': 'SecurityManager',
            'IarmImpl.cpp': 'DeviceSettings',
            'CivetWebWSClient.cpp': 'WebSocket',
            'LinchPinClient.cpp': 'LinchPin',
            'PTimer.cpp': 'Timer',
            'helpers.cpp': 'Utilities',
            'device_files.cpp': 'OCDM',
            'secure_storage_rdk.cpp': 'OCDM',
            'oemcrypto_usage_table_rdk.cpp': 'OCDM',
            'crypto_session.cpp': 'OCDM',
            'MediaSession.cpp': 'OCDM'
        }
        
        if filename in plugin_mapping:
            return plugin_mapping[filename]
        
        # For unmapped files, try to extract plugin name from filename
        base_name = filename.replace('.cpp', '').replace('.h', '')
        # Remove common WPE Framework suffixes in order of specificity  
        suffixes = ['Implementation', 'Controller', 'Manager', 'Service', 'Impl', 'APIs', 'Client', 'Session']
        for suffix in suffixes:
            if base_name.endswith(suffix):
                base_name = base_name[:-len(suffix)]
                break
        return base_name if base_name else 'Unknown'
    
    # Pattern 2: [mod=MODULENAME, ...]
    pattern2 = r'\[mod=([^,\]]+)[,\]]'
    match = re.search(pattern2, line)
    if match:
        return match.group(1)
    
    # Pattern 3: Look for ERROR patterns with file paths (for nested paths)
    error_pattern = r'\[ERROR:[^/]*([^/]*\.cpp)\(\d+'
    match = re.search(error_pattern, line)
    if match:
        filename = match.group(1)
        # Apply same mapping as Pattern 1
        plugin_mapping = {
            'device_files.cpp': 'OCDM',
            'secure_storage_rdk.cpp': 'OCDM',
            'oemcrypto_usage_table_rdk.cpp': 'OCDM',
            'crypto_session.cpp': 'OCDM'
        }
        return plugin_mapping.get(filename, filename.replace('.cpp', ''))
    
    # Pattern 4: Direct plugin mentions in log content
    if 'PowerManager plugin' in line:
        return 'PowerManager'
    elif 'WPE[' in line:
        wpe_pattern = r'WPE\[([^\]]+)\]'
        match = re.search(wpe_pattern, line)
        if match:
            return match.group(1)
    
    # Pattern 5: Process-based patterns
    if 'WvCDMi_LOG' in line or '_WvCDM' in line or 'MediaKeySession' in line:
        return 'OCDM'
    elif 'IARM_event_send' in line or 'IARM_Init' in line:
        return 'IARM'
    elif 'RDKPerf' in line:
        return 'Performance'
    elif 'org.rdk.Network' in line:
        return 'Network'
    
    return "Unknown"


def discover_gtest_cases(gtest_binary):
    """Discover all test cases in a gtest binary"""
    try:
        print(f"Debug: Running command: {gtest_binary} --gtest_list_tests")
        result = subprocess.run(
            [gtest_binary, '--gtest_list_tests'], 
            capture_output=True, 
            text=True, 
            timeout=30
        )
        
        print(f"Debug: Return code: {result.returncode}")
        print(f"Debug: STDOUT length: {len(result.stdout)} chars")
        print(f"Debug: STDERR length: {len(result.stderr)} chars")
        
        if result.returncode != 0:
            print(f"Debug: STDERR content: {repr(result.stderr)}")
            raise Exception(f"Failed to list tests: {result.stderr}")
        
        if result.stdout:
            print(f"Debug: STDOUT content (first 500 chars): {repr(result.stdout[:500])}")
        else:
            print("Debug: STDOUT is empty!")
            
        test_cases = []
        current_suite = None
        
        for line in result.stdout.strip().split('\n'):
            original_line = line
            line = line.strip()
            if not line:
                continue
                
            print(f"Debug: Processing line: {repr(line)}")
            if line.endswith('.'):
                # Test suite name
                current_suite = line[:-1]
                print(f"Debug: Found test suite: {current_suite}")
            elif current_suite and original_line.startswith('  '):
                # Test case name (checking original line for indentation)
                test_name = line  # line is already stripped
                full_test_name = f"{current_suite}.{test_name}"
                test_cases.append(full_test_name)
                print(f"Debug: Found test case: {full_test_name}")
        
        print(f"Debug: Total test cases discovered: {len(test_cases)}")
        return test_cases
    
    except subprocess.TimeoutExpired:
        raise Exception("Timeout while discovering test cases")
    except Exception as e:
        raise Exception(f"Error discovering test cases: {e}")

def run_single_gtest(gtest_binary, test_filter, log_file, env_vars=None):
    """Run a single gtest case and capture logs"""
    try:
        # Set up environment
        env = os.environ.copy()
        if env_vars:
            env.update(env_vars)
        
        # Run the specific test
        cmd = [gtest_binary, f'--gtest_filter={test_filter}']
        
        with open(log_file, 'w') as f:
            result = subprocess.run(
                cmd,
                stdout=f,
                stderr=subprocess.STDOUT,
                env=env,
                timeout=300  # 5 minute timeout per test
            )
        
        return {
            'test_name': test_filter,
            'return_code': result.returncode,
            'log_file': log_file,
            'status': 'PASSED' if result.returncode == 0 else 'FAILED'
        }
    
    except subprocess.TimeoutExpired:
        return {
            'test_name': test_filter,
            'return_code': -1,
            'log_file': log_file,
            'status': 'TIMEOUT'
        }
    except Exception as e:
        return {
            'test_name': test_filter,
            'return_code': -1,
            'log_file': log_file,
            'status': f'ERROR: {e}'
        }


def analyze_gtest_logs(gtest_binary, output_dir, env_vars=None, rules_file="rules.yml"):
    """Run all gtests and analyze their logs"""
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Load rules
    rules = load_rules(rules_file)
    
    # Discover test cases
    print(f"Discovering test cases in {gtest_binary}...")
    try:
        test_cases = discover_gtest_cases(gtest_binary)
        print(f"Found {len(test_cases)} test cases")
    except Exception as e:
        print(f"Error: {e}")
        return
    
    # Results tracking
    all_results = []
    total_issues = {'noisy': 0, 'sensitive': 0, 'severity': 0}
    
    # Run each test case
    for i, test_case in enumerate(test_cases, 1):
        print(f"[{i}/{len(test_cases)}] Running {test_case}...")
        
        # Generate log file name
        safe_test_name = test_case.replace('/', '_').replace('.', '_')
        log_file = os.path.join(output_dir, f"gtest_log_{safe_test_name}.txt")
        
        # Run the test
        test_result = run_single_gtest(gtest_binary, test_case, log_file, env_vars)
        
        # Analyze logs if file exists and has content
        log_analysis = None
        if os.path.exists(log_file) and os.path.getsize(log_file) > 0:
            try:
                noisy, sensitive, severity = analyze(log_file, rules)
                log_analysis = {
                    'noisy_count': len(noisy),
                    'sensitive_count': len(sensitive),
                    'severity_count': len(severity),
                    'noisy_logs': noisy,
                    'sensitive_logs': sensitive,
                    'severity_violations': severity
                }
                
                # Update totals
                total_issues['noisy'] += len(noisy)
                total_issues['sensitive'] += len(sensitive)
                total_issues['severity'] += len(severity)
                
                # Generate individual test report
                test_report_file = os.path.join(output_dir, f"report_{safe_test_name}.html")
                generate_html(noisy, sensitive, severity, test_report_file)
                
            except Exception as e:
                print(f"  Warning: Failed to analyze logs for {test_case}: {e}")
        
        # Store result
        test_result['log_analysis'] = log_analysis
        all_results.append(test_result)
        
        # Print status
        status_msg = f"  Status: {test_result['status']}"
        if log_analysis:
            status_msg += f" | Issues: {log_analysis['noisy_count']} noisy, {log_analysis['sensitive_count']} sensitive, {log_analysis['severity_count']} severity"
        print(status_msg)
    
    # Generate consolidated report
    consolidated_report = os.path.join(output_dir, "consolidated_gtest_report.html")
    generate_consolidated_gtest_report(all_results, total_issues, consolidated_report)
    
    # Generate summary
    print(f"\n=== GTest Analysis Summary ===")
    print(f"Total tests run: {len(test_cases)}")
    print(f"Passed: {len([r for r in all_results if r['status'] == 'PASSED'])}")
    print(f"Failed: {len([r for r in all_results if r['status'] == 'FAILED'])}")
    print(f"Errors/Timeouts: {len([r for r in all_results if r['status'] not in ['PASSED', 'FAILED']])}")
    print(f"\nTotal Log Quality Issues:")
    print(f"  Noisy logs: {total_issues['noisy']}")
    print(f"  Sensitive data: {total_issues['sensitive']}")
    print(f"  Severity violations: {total_issues['severity']}")
    print(f"\nReports generated in: {output_dir}")
    print(f"Consolidated report: {consolidated_report}")


def generate_consolidated_gtest_report(results, total_issues, output_file):
    """Generate a consolidated HTML report for all gtest results"""
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"""
<html>
<head>
<title>GTest Log Quality Analysis Report</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 20px; }}
table {{ border-collapse: collapse; width: 100%; margin-bottom: 30px; }}
th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}
th {{ background: #f0f0f0; font-weight: bold; }}
.summary {{ background: #f9f9f9; padding: 15px; margin-bottom: 20px; border-radius: 5px; }}
.passed {{ background-color: #d4edda; }}
.failed {{ background-color: #f8d7da; }}
.error {{ background-color: #fff3cd; }}
.issues-high {{ color: #dc3545; font-weight: bold; }}
.issues-medium {{ color: #fd7e14; font-weight: bold; }}
.issues-low {{ color: #28a745; }}
</style>
</head>
<body>
<h1>GTest Log Quality Analysis Report</h1>""")
        
        # Summary section
        total_tests = len(results)
        passed_tests = len([r for r in results if r['status'] == 'PASSED'])
        failed_tests = len([r for r in results if r['status'] == 'FAILED'])
        error_tests = total_tests - passed_tests - failed_tests
        
        f.write(f"""
<div class="summary">
    <h3>Summary</h3>
    <p><strong>Total Tests:</strong> {total_tests}</p>
    <p><strong>Passed:</strong> {passed_tests} | <strong>Failed:</strong> {failed_tests} | <strong>Errors/Timeouts:</strong> {error_tests}</p>
    <p><strong>Total Log Quality Issues:</strong> {total_issues['noisy'] + total_issues['sensitive'] + total_issues['severity']}</p>
    <ul>
        <li>Noisy Logs: {total_issues['noisy']}</li>
        <li>Sensitive Data: {total_issues['sensitive']}</li>
        <li>Severity Violations: {total_issues['severity']}</li>
    </ul>
</div>""")
        
        # Test results table  
        f.write("""
<h2>Test Results</h2>
<table>
<tr><th>Test Case</th><th>Status</th><th>Noisy</th><th>Sensitive</th><th>Severity</th><th>Total Issues</th><th>Report</th></tr>""")
        
        for result in results:
            test_name = result['test_name']
            status = result['status']
            analysis = result.get('log_analysis')
            
            # Status styling
            status_class = ""
            if status == 'PASSED':
                status_class = "passed"
            elif status == 'FAILED':
                status_class = "failed"
            else:
                status_class = "error"
            
            if analysis:
                noisy = analysis['noisy_count']
                sensitive = analysis['sensitive_count']
                severity = analysis['severity_count']
                total = noisy + sensitive + severity
                
                # Issue count styling
                issue_class = "issues-low"
                if total > 20:
                    issue_class = "issues-high"
                elif total > 5:
                    issue_class = "issues-medium"
                
                safe_test_name = test_name.replace('/', '_').replace('.', '_')
                report_link = f"report_{safe_test_name}.html"
                
                f.write(f"""
<tr class="{status_class}">
    <td>{escape(test_name)}</td>
    <td>{escape(status)}</td>
    <td>{noisy}</td>
    <td>{sensitive}</td>
    <td>{severity}</td>
    <td class="{issue_class}">{total}</td>
    <td><a href="{report_link}">View Details</a></td>
</tr>""")
            else:
                f.write(f"""
<tr class="{status_class}">
    <td>{escape(test_name)}</td>
    <td>{escape(status)}</td>
    <td>-</td>
    <td>-</td>
    <td>-</td>
    <td>-</td>
    <td>No log data</td>
</tr>""")
        
        f.write("""
</table>
</body>
</html>""")
    
    print(f"Consolidated report generated: {output_file}")

# -----------------------------
def compile_patterns(patterns):
    return [re.compile(p) for p in patterns]

# -----------------------------
def analyze(log_file, rules):
    """
    Analyze a log file for noisy logging, sensitive data exposure, and
    incorrect severity usage based on the provided rules.
    Parameters
    ----------
    log_file : str or pathlib.Path
        Path to the log file to analyze. The file is opened in text mode
        with errors ignored to allow processing partially invalid encodings.
    rules : dict
        Configuration dictionary containing analysis rules. Expected keys:
        - "sensitive_patterns": list of regex patterns that match sensitive
          or PII data that must not appear in logs.
        - "failure_keywords": list of lowercase keywords that indicate a
          failure or error condition in a log line.
        - "noisy_log_levels": iterable of log levels (e.g. "INFO", "DEBUG")
          that are considered noisy.
        - "required_severity_on_failure": iterable of log levels (e.g.
          "ERROR", "WARN") that must be used when a failure keyword is
          present.
    Returns
    -------
    tuple
        A 3-tuple `(noisy_logs, sensitive_logs, severity_violations)` where
        each element is a list of dictionaries describing matching log lines.
        - noisy_logs: entries for logs emitted at noisy log levels.
        - sensitive_logs: entries where sensitive or PII data was detected,
          with similar structure ("line", "log", "reason").
        - severity_violations: entries where a failure keyword was found but
          the log level did not meet the required severity.
    """
    noisy_logs = []
    sensitive_logs = []
    severity_violations = []

    sensitive_res = compile_patterns(rules["sensitive_patterns"])
    failure_keywords = rules["failure_keywords"]

    def redact_sensitive(line):
        # No redaction for Thunder plugin - return original line
        return line

    # - Scan line-by-line
    with open(log_file, "r", errors="ignore") as f:
        for ln, line in enumerate(f, 1):
            line = line.rstrip()
            if not starts_with_date_and_timestamp(line):
                continue
            level = detect_level(line)
            # Report all noisy log levels (DEBUG, TRACE, INFO) as noisy logs
            if level in rules["noisy_log_levels"]:
                plugin_name = extract_plugin_name(line)
                noisy_logs.append({
                    "line": ln,
                    "log": redact_sensitive(line),
                    "plugin": plugin_name,
                    "reason": f"Noisy log level: {level}"
                })
            # Sensitive logs
            for r in sensitive_res:
                if r.search(line):
                    plugin_name = extract_plugin_name(line)
                    sensitive_logs.append({
                        "line": ln,
                        "log": redact_sensitive(line),
                        "plugin": plugin_name,
                        "reason": "Sensitive / PII data detected"
                    })
                    break
            # Severity enforcement
            if any(k in line.lower() for k in failure_keywords):
                if level not in rules["required_severity_on_failure"]:
                    plugin_name = extract_plugin_name(line)
                    severity_violations.append({
                        "line": ln,
                        "log": redact_sensitive(line),
                        "plugin": plugin_name,
                        "reason": (
                            f"Plugin '{plugin_name}': Failure logged without required severity: "
                            + ", ".join(rules["required_severity_on_failure"])
                        )
                    })

    return noisy_logs, sensitive_logs, severity_violations

# -----------------------------
def generate_html(noisy, sensitive, severity, output):
    with open(output, "w", encoding="utf-8") as f:
        f.write("""
<html>
<head>
<title>Log Quality Report</title>
<style>
body { font-family: Arial; }
table { border-collapse: collapse; width: 100%; margin-bottom: 30px; }
th, td { border: 1px solid #ccc; padding: 6px; text-align: left; }
th { background: #f0f0f0; }
</style>
</head>
<body>
<h1>Log Quality Report</h1>
""")

        def write_section(title, rows):
            f.write(f"<h2>{title}</h2>")
            f.write("<table>")
            
            # All sections now include plugin column
            f.write("<tr><th>Line</th><th>Plugin</th><th>Reason</th><th>Log</th></tr>")
            if not rows:
                f.write('<tr><td colspan="4">No issues found in this section.</td></tr>')
            else:
                for r in rows:
                    plugin_name = r.get('plugin', 'Unknown')
                    plugin_color = '#0066cc' if plugin_name != 'Unknown' else '#888888'
                    f.write(
                        f"<tr><td>{r['line']}</td>"
                        f"<td><strong style='color:{plugin_color}'>{escape(plugin_name)}</strong></td>"
                        f"<td>{escape(r['reason'])}</td>"
                        f"<td>{escape(r['log'])}</td></tr>"
                    )
            
            f.write("</table>")

        write_section("Noisy Logs", noisy)
        write_section("Sensitive / PII Logs", sensitive)
        write_section("Severity Violations", severity)

        f.write("</body></html>")

    print(f"Report generated: {output}")

# -----------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Analyze log files for quality issues or run GTest integration'
    )
    
    # Mode selection
    parser.add_argument(
        '--mode', 
        choices=['file', 'gtest'], 
        default='file',
        help='Analysis mode: file (analyze existing log) or gtest (run tests and analyze)'
    )
    
    # File mode arguments
    parser.add_argument(
        'input', 
        nargs='?',
        help='Log file to analyze (file mode) or GTest binary path (gtest mode)'
    )
    
    parser.add_argument(
        'output', 
        nargs='?',
        help='Output HTML file (file mode) or output directory (gtest mode)'
    )
    
    # GTest specific arguments
    parser.add_argument(
        '--output-dir',
        help='Output directory for GTest reports (alternative to positional output)'
    )
    
    parser.add_argument(
        '--env',
        action='append',
        help='Environment variable for GTest execution (format: VAR=value)'
    )
    
    parser.add_argument(
        '--rules',
        default='rules.yml',
        help='Rules YAML file (default: rules.yml)'
    )
    
    args = parser.parse_args()
    
    # Validate arguments based on mode
    if args.mode == 'file':
        if not args.input or not args.output:
            print("Error: File mode requires both input log file and output HTML file")
            print("Usage: python3 noisylogdetector.py <log_file> <output.html>")
            print("   or: python3 noisylogdetector.py --mode file <log_file> <output.html>")
            sys.exit(1)
        
        if not Path(args.input).exists():
            print(f"Error: Log file not found: {args.input}")
            sys.exit(1)
        
        # Run file analysis
        try:
            rules = load_rules(args.rules)
            noisy, sensitive, severity = analyze(args.input, rules)
            generate_html(noisy, sensitive, severity, args.output)
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)
    
    elif args.mode == 'gtest':
        if not args.input:
            print("Error: GTest mode requires GTest binary path")
            print("Usage: python3 noisylogdetector.py --mode gtest <gtest_binary> [output_dir]")
            print("   or: python3 noisylogdetector.py --mode gtest <gtest_binary> --output-dir <dir>")
            sys.exit(1)
        
        if not Path(args.input).exists():
            print(f"Error: GTest binary not found: {args.input}")
            sys.exit(1)
        
        # Determine output directory
        output_dir = args.output or args.output_dir or './gtest_analysis'
        
        # Parse environment variables
        env_vars = {}
        if args.env:
            for env_pair in args.env:
                if '=' in env_pair:
                    key, value = env_pair.split('=', 1)
                    env_vars[key] = value
                else:
                    print(f"Warning: Invalid environment variable format: {env_pair}")
        
        # Run GTest analysis
        try:
            analyze_gtest_logs(args.input, output_dir, env_vars, args.rules)
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)
