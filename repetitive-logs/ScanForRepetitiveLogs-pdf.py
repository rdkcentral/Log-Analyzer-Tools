#!/usr/bin/env python3
"""
Duplicate Log Analyzer
Author: (DEEPTHI CHANDRASHEKAR SHETTY )
Date: (19-01-2026)

Description:
   - Handles .tgz/.tar safely without hang 
   - Parses ALL log formats 
   - Ignores timestamp, module, level, TID/PID, hex IDs for duplicate detection 
   - This script analyzes log files to detect and report duplicate log entries.
   - It helps identify redundant or repeated log messages that may indicate issues
    with logging practices or application behavior.

Usage:
    python <scriptname>.py <log_file_path>
    - <scriptname>: Name of this script file.
    - <log_file_path>: Path to the log file to be analyzed.

Output:
    Produces PDF report of duplicate log entries found in the input file.

Requirements:
    Python 3.x
"""
import os
import tarfile
import re
from collections import defaultdict
from reportlab.lib.pagesizes import landscape, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
import glob

MAX_FILE_BYTES = 8 * 1024 * 1024
READ_CHUNK = 64 * 1024
 
# ------------------------------------------------------------
# Rotated log support:
#   abcd.log
#   abcd.log.0
#   abcd.log.1
#   pamlog.txt.2
LOG_FILE_RE = re.compile(
    r".*\.(log|txt|out|sh|bak)(\.\d+)?$",
    re.IGNORECASE
)
 
# ------------------------------------------------------------
def safe_read(f, limit):
    buf, read = [], 0
    while True:
        chunk = f.read(READ_CHUNK)
        if not chunk:
            break
        read += len(chunk)
        if read > limit:
            buf.append(chunk[: limit - (read - len(chunk))])
            break
        buf.append(chunk)
    data = b"".join(buf)
    try:
        return data.decode("utf-8", "replace")
    except:
        return data.decode("latin1", "replace")
 
# ------------------------------------------------------------
# Extract logs WITH filename (tgz / tar / single file)
def extract_logs(path):
    logs = []  # (group_key, line)
    if tarfile.is_tarfile(path):
        with tarfile.open(path, "r:*") as tar:
            for m in tar.getmembers():
                if not m.isfile():
                    continue
                fname = os.path.basename(m.name)
                if not LOG_FILE_RE.match(fname.lower()):
                    continue
                f = tar.extractfile(m)
                if not f:
                    continue
                content = safe_read(f, MAX_FILE_BYTES)
                group = get_group_key(fname)
                for line in content.splitlines():
                    if line.strip():
                        logs.append((group, line))
    else:
        # Find all rotated files matching the input's base name
        base = os.path.basename(path)
        dir_ = os.path.dirname(os.path.abspath(path))
        # Match base, base.0, base.1, etc. for any extension
        pattern = os.path.join(dir_, base + '*')
        files = sorted(glob.glob(pattern))
        # Only keep files that match <base> or <base>.<number>
        base_re = re.compile(rf"^{re.escape(base)}(\.\d+)?$")
        files = [f for f in files if base_re.match(os.path.basename(f))]
        if not files:
            files = [path]
        for fname in files:
            fname_base = os.path.basename(fname)
            if not LOG_FILE_RE.match(fname_base.lower()):
                continue
            with open(fname, "rb") as f:
                content = safe_read(f, MAX_FILE_BYTES)
                group = get_group_key(fname_base)
                for line in content.splitlines():
                    if line.strip():
                        logs.append((group, line))
    return logs
 
# ------------------------------------------------------------
# SAME REMOVE_PAT AS HTML REPORT (handles multiple timestamps)
REMOVE_PAT = re.compile(
    r"""
    # ---- timestamps (support double timestamps) ----
    (?<!\w)(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?)|     # ISO time 1
    (?<!\w)([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})|         # Syslog time
    (?<!\w)(\d{2}:\d{2}:\d{2}(?:\.\d+)?)|                         # HH:MM:SS(.ms)
    # ---- extra repeated timestamp pattern (2nd copy) ----
    (?<!\w)(\d{4}-\d{2}-\d{2})|                                   # date part if lone
    (?<!\w)([A-Z][a-z]{2}\s+\d{1,2})|                             # Month day (2nd syslog)
    # ---- EPOCH/float timestamps ----
    \b\d{10,}\.\d+\b:?|                                           # e.g. 1762247328.373450:
    # ---- TID / PID / thread ----
    tid[:=]?\d+|pid[:=]?\d+|thread[:=]?\d+|
    \bTID\s*\d+\b|\bPID\s*\d+\b|
    # ---- Sequence / line numbers ----
    line[:=]?\d+|lineno[:=]?\d+|ln[:=]?\d+|
    \b\d{4,6}(?=\s)|              # standalone 4–6 digit line/feed indexes
    # ---- Module formatting ----
    [A-Za-z0-9_\-/]+\[\d+\]|
    \[[A-Z]{2,5}\]|               # e.g. [RDK], [CM], etc.
    \b[A-Za-z0-9_\-]+:            # module:
    # ---- Hex IDs ----
    0x[0-9a-fA-F]+|
    \b[0-9a-fA-F]{8,}\b|
    # ---- Log levels ----
    \b(INFO|WARN|WARNING|ERROR|DEBUG|TRACE|CRITICAL|FATAL|NOTICE)\b
    """,
    re.IGNORECASE | re.VERBOSE,
)
WS = re.compile(r"\s+")
 
def normalize(line: str) -> str:
    s = REMOVE_PAT.sub(" ", line)
    s = s.replace("\u00a0"," ")
    s = WS.sub(" ", s)
    return s.strip().lower()
 
# ------------------------------------------------------------
# Per-file duplicate detection
def find_filewise_duplicates(logs):
    group_map = defaultdict(list)
    for group, line in logs:
        group_map[group].append(line)
    result = {}
    for group, lines in group_map.items():
        norm_map = defaultdict(list)
        for line in lines:
            key = normalize(line)
            if key:
                norm_map[key].append(line)
        duplicates = []
        for key, originals in norm_map.items():
            if len(originals) > 1:
                duplicates.append(
                    (len(originals), originals[0])  # count, full original line
                )
        if duplicates:
            result[group] = sorted(duplicates, reverse=True)
    return result
 
# ------------------------------------------------------------
# PDF generation
def generate_pdf(data, out_file):
    styles = getSampleStyleSheet()
    normal = styles["Normal"]
 
    doc = SimpleDocTemplate(
        out_file,
        pagesize=landscape(A4),
        leftMargin=20,
        rightMargin=20,
        topMargin=20,
        bottomMargin=20
    )
 
    story = []
    story.append(Paragraph("<b>Per-File Duplicate Log Report</b>", styles["Title"]))
    story.append(Spacer(1, 12))
 
    for filename, entries in sorted(data.items()):
        story.append(Paragraph(f"<b>{filename}</b>", styles["Heading2"]))
        story.append(Spacer(1, 8))
 
        table_data = [["Count", "Duplicate Log Line"]]
 
        for count, logline in entries:
            clean = (
                logline.replace("&", "&amp;")
                       .replace("<", "&lt;")
                       .replace(">", "&gt;")
            )
            table_data.append([
                str(count),
                Paragraph(clean, normal)
            ])
 
        table = Table(table_data, colWidths=[70, 720])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.lightgrey),
            ("GRID", (0,0), (-1,-1), 0.25, colors.grey),
            ("VALIGN", (0,0), (-1,-1), "TOP"),
            ("ALIGN", (0,0), (0,-1), "CENTER"),
            ("FONTSIZE", (0,0), (-1,-1), 8),
        ]))
 
        story.append(table)
        story.append(Spacer(1, 20))
 
    doc.build(story)
 
# ------------------------------------------------------------
# Grouping: abcd.txt, abcd.txt.0, abcd.txt.1 -> abcd.txt*
def get_group_key(filename):
    # Remove .<number> at the end (rotated log), e.g. abcd.txt.0 -> abcd.txt
    m = re.match(r"^(.*?)(\.\d+)?$", filename)
    return m.group(1) if m else filename
 
def main(path):
    logs = extract_logs(path)
    print(f"Loaded {len(logs)} log lines")
 
    dups = find_filewise_duplicates(logs)
    print(f"Files with duplicates: {len(dups)}")
 
    out = "Per_File_Duplicate_Report.pdf"
    generate_pdf(dups, out)
 
    print(f"PDF generated: {out}")
 
# ------------------------------------------------------------
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python dup_per_file_pdf.py <logfile | tgz | tar>")
        sys.exit(1)
 
    main(sys.argv[1])
