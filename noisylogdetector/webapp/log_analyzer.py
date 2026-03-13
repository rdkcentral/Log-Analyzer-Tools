#!/usr/bin/env python3
"""
Log Analysis Utility Module
Contains the core logic for analyzing log files, extracted from the original noisylogdetector.py
"""
import re
import sys
import yaml
from html import escape
from pathlib import Path


def load_rules(path="rules.yml"):
    """Load and validate rules from YAML file"""
    try:
        with open(path, "r") as f:
            rules = yaml.safe_load(f)
    except FileNotFoundError:
        raise Exception(f"Rules file not found: {path}")
    except PermissionError:
        raise Exception(f"Permission denied while reading rules file: {path}")
    except yaml.YAMLError as e:
        raise Exception(f"Failed to parse YAML rules file '{path}': {e}")
    except Exception as e:
        raise Exception(f"Unexpected error while loading rules from '{path}': {e}")
    
    # Validate rules is a dict
    if not isinstance(rules, dict):
        raise Exception("Rules.yml is empty or not a valid YAML mapping.")
    
    # Validate required keys
    required_keys = [
        "sensitive_patterns",
        "failure_keywords", 
        "noisy_log_levels",
        "required_severity_on_failure"
    ]
    missing = [k for k in required_keys if k not in rules or rules[k] is None]
    if missing:
        raise Exception(f"Rules.yml is missing required keys: {', '.join(missing)}")
    
    return rules


def starts_with_date_and_timestamp(line):
    """
    Matches log lines starting with timestamp patterns suitable for WPE Framework and general logs:
      - ISO 8601: 2025-12-17T12:16:47.917Z (WPE Framework main format)
      - HH:MM:SS or HH:MM:SS.ssssss (e.g. 04:31:14 or 12:16:47.916231)
      - YYYY-MM-DD HH:MM:SS or YYYY-MM-DD HH:MM:SS.sss (e.g. 2024-11-11 04:31:14) 
      - YYMMDD-HH:MM:SS.ssssss (WPE specific: 251217-12:16:58.240119)
      - Mon DD HH:MM:SS (e.g. Nov 11 04:31:14)
    Lines not matching these patterns at the start will be ignored.
    """
    # Enhanced regex to handle WPE Framework and general log timestamp patterns
    wpe_patterns = [
        # ISO 8601 format (WPE main): 2025-12-17T12:16:47.917Z
        r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z',
        # WPE inner timestamp with microseconds: 12:16:47.916231
        r'^\s*\d{2}:\d{2}:\d{2}\.\d{6}',
        # WPE module format: 251217-12:16:58.240119
        r'^\s*\d{6}-\d{2}:\d{2}:\d{2}\.\d+',
        # Standard formats
        r'^\s*\d{2}:\d{2}:\d{2}(?:\.\d+)?',
        r'^\s*\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?',
        r'^\s*(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}'
    ]
    
    return any(re.match(pattern, line) for pattern in wpe_patterns)


def detect_level(line):
    """Detect log level from a log line - Enhanced for WPE Framework"""
    # WPE Framework specific patterns  
    wpe_patterns = [
        (r'\[ERROR:', 'ERROR'),          # [ERROR:../../../core/src/device_files.cpp
        (r'\[Info\s*\]', 'INFO'),        # [Info ] (with optional spaces)
        (r'\[WARN\]', 'WARN'),          # Standard WARN in brackets
        (r'\] ERROR ', 'ERROR'),         # ] ERROR [file.cpp:123]
        (r'\] INFO ', 'INFO'),           # ] INFO [file.cpp:123]  
        (r'\] WARN ', 'WARN'),           # ] WARN [file.cpp:123]
        (r'lvl=INFO', 'INFO'),           # [mod=RFCAPI, lvl=INFO]
        (r'lvl=WARN', 'WARN'),           # [mod=RFCAPI, lvl=WARN]
        (r'lvl=ERROR', 'ERROR'),         # [mod=RFCAPI, lvl=ERROR]
        (r'lvl=DEBUG', 'DEBUG'),         # [mod=RFCAPI, lvl=DEBUG]
    ]
    
    # Check WPE-specific patterns first
    for pattern, level in wpe_patterns:
        if re.search(pattern, line):
            return level
    
    # Fallback to standard patterns
    for lvl in ("FATAL", "ERROR", "WARN", "INFO", "DEBUG", "TRACE"):
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

def compile_patterns(patterns):
    """Compile regex patterns"""
    return [re.compile(p) for p in patterns]


def analyze_log_file(log_file, rules):
    """
    Analyze a log file for noisy logging, sensitive data exposure, and
    incorrect severity usage based on the provided rules.
    
    Returns a tuple (noisy_logs, sensitive_logs, severity_violations)
    """
    noisy_logs = []
    sensitive_logs = []
    severity_violations = []

    sensitive_res = compile_patterns(rules["sensitive_patterns"])
    failure_keywords = rules["failure_keywords"]

    def redact_sensitive(line):
        # Replace all sensitive matches with [REDACTED]
#        for r in sensitive_res:
#            line = r.sub("[REDACTED]", line)
        return line

    # Scan line-by-line
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
                            "Failure logged without required severity: "
                            + ", ".join(rules["required_severity_on_failure"])
                        )
                    })

    return noisy_logs, sensitive_logs, severity_violations


def generate_html_report(noisy, sensitive, severity, output=None):
    """Generate HTML report. Returns HTML content as string if output is None, otherwise writes to file."""
    html_content = """
<html>
<head>
<title>Log Quality Report</title>
<style>
body { font-family: Arial, sans-serif; margin: 20px; }
table { border-collapse: collapse; width: 100%; margin-bottom: 30px; }
th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
th { background: #f0f0f0; font-weight: bold; }
.noisy { border-left: 4px solid #ffa500; }
.sensitive { border-left: 4px solid #ff4444; }
.severity { border-left: 4px solid #ff8800; }
.summary { background: #f9f9f9; padding: 15px; margin-bottom: 20px; border-radius: 5px; }
</style>
</head>
<body>
<h1>Log Quality Report</h1>
"""

    # Add summary
    total_issues = len(noisy) + len(sensitive) + len(severity)
    html_content += f"""
<div class="summary">
    <h3>Summary</h3>
    <p><strong>Total Issues Found:</strong> {total_issues}</p>
    <ul>
        <li>Noisy Logs: {len(noisy)}</li>
        <li>Sensitive/PII Logs: {len(sensitive)}</li>
        <li>Severity Violations: {len(severity)}</li>
    </ul>
</div>
"""

    def write_section(title, rows, css_class=""):
        section_html = f"<h2>{title}</h2>"
        section_html += f'<table class="{css_class}">'
        # All sections now include plugin column
        section_html += "<tr><th>Line</th><th>Plugin</th><th>Reason</th><th>Log</th></tr>"
        if not rows:
            section_html += '<tr><td colspan="4">No issues found in this section.</td></tr>'
        else:
            for r in rows:
                plugin_name = r.get('plugin', 'Unknown')
                plugin_color = '#0066cc' if plugin_name != 'Unknown' else '#888888'
                section_html += (
                    f"<tr><td>{r['line']}</td>"
                    f"<td><strong style='color:{plugin_color}'>{escape(plugin_name)}</strong></td>"
                    f"<td>{escape(r['reason'])}</td>"
                    f"<td>{escape(r['log'])}</td></tr>"
                )

        section_html += "</table>"
        return section_html

    html_content += write_section("Noisy Logs", noisy, "noisy")
    html_content += write_section("Sensitive / PII Logs", sensitive, "sensitive")
    html_content += write_section("Severity Violations", severity, "severity")

    html_content += "</body></html>"

    if output:
        with open(output, "w", encoding="utf-8") as f:
            f.write(html_content)
        return f"Report generated: {output}"
    else:
        return html_content
