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
    Produces HTML report of duplicate log entries found in the input file.

Requirements:
    Python 3.x
"""

 

import re, os, sys, tarfile, argparse, html, glob 

from collections import defaultdict, Counter 

from datetime import datetime 

 

# ---------------- SAFETY LIMITS ---------------- 

MAX_FILES = 5000 

MAX_BYTES = 200 * 1024 * 1024 

MAX_FILE_BYTES = 8 * 1024 * 1024 

READ_CHUNK = 64 * 1024 

# ------------- Patterns: REMOVE BEFORE DUP CHECK -------------
REMOVE_PAT = re.compile(
    r"""
    # ---- timestamps (support double timestamps) ----
    (?<!\w)(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?)|     # ISO time 1
    (?<!\w)([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})|         # Syslog time
    (?<!\w)(\d{2}:\d{2}:\d{2}(?:\.\d+)?)|                         # HH:MM:SS(.ms)
    
    # ---- extra repeated timestamp pattern (2nd copy) ----
    (?<!\w)(\d{4}-\d{2}-\d{2})|                                   # date part if lone
    (?<!\w)([A-Z][a-z]{2}\s+\d{1,2})|                             # Month day (2nd syslog)
 
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

# ------------- Normalization for duplicate check ------------- 

def normalize(line: str) -> str: 

    s = REMOVE_PAT.sub(" ", line) 

    s = WS.sub(" ", s).strip().lower() 

    return s 

 

# ------------- SAFE STREAM READ ------------- 

def safe_read(f, limit): 

    buf, read = [], 0 

    while True: 

        chunk = f.read(READ_CHUNK) 

        if not chunk: break 

        read += len(chunk) 

        if read > limit: 

            buf.append(chunk[: limit - (read - len(chunk))]) 

            break 

        buf.append(chunk) 

    data = b"".join(buf) 

    try: return data.decode("utf-8", "replace") 

    except: return data.decode("latin1", "replace") 

 

# ------------- LOG LINE PARSER (format agnostic) ------------- 

def parse_line(line): 

    msg = line.strip() 

    if not msg: return None 

    return {"message": msg} 

 

# ------------- PROCESS TEXT FILE ------------- 

def process_text(name, text, out, stats): 

    for ln in text.splitlines(): 

        p = parse_line(ln) 

        if not p:  

            stats["skip"] += 1 

            continue 

        p["file"] = name 

        out.append(p) 

        stats["ok"] += 1 

 

# ------------- PROCESS TAR ------------- 

SKIP_EXT = {".so", ".pem", ".crt", ".der", ".bin",".img",".zip",".gz",".xz"} 

def is_text_file(name):
    # Process only likely text log files
    text_ext = (".log", ".txt", ".trace", ".out", ".sh", ".cfg", ".conf", ".ini", ".msg")
    return any(name.lower().endswith(e) for e in text_ext)

def process_tgz(path, out, stats):
    total = 0
    processed = 0
 
    LOG_EXT = (".log", ".txt", ".out", ".sh", ".bak", ".log.gz", ".gz")
 
    with tarfile.open(path, "r:*") as tar:
        members = tar.getmembers()
 
        for m in members:
            if not m.isfile():
                continue
 
            name = m.name.lower()
 
            # Skip only real binary / cert files
            if any(name.endswith(e) for e in (".so", ".pem", ".crt", ".der", ".bin", ".img")):
                stats["skip_ext"] += 1
                continue
 
            # accept .gz LOG files inside .tgz
            #if not name.endswith(LOG_EXT):
                #stats["skip_nonlog"] += 1
                #continue
 
            # track & print progress
            processed += 1
            if processed % 200 == 0:
                print(f"[TGZ] Scanned {processed} files...")
 
            # file size check only to avoid huge binaries
            if m.size > MAX_FILE_BYTES:
                stats["big"] += 1
                continue
 
            try:
                f = tar.extractfile(m)
                if not f:
                    continue
 
                txt = safe_read(f, MAX_FILE_BYTES)
                total += len(txt)
 
                process_text(m.name, txt, out, stats)
 
                if total > MAX_BYTES:
                    print("Reached global read limit, stopping TGZ parse.")
                    stats["limit"] = True
                    break
 
            except Exception as e:
                stats["error"] += 1
                print(f"Error reading {m.name}: {e}")
 
    print(f"TGZ scan completed: {processed} files processed")
# ------------- DUPLICATE COLLECTION ------------- 

def find_duplicates(entries): 

    d = defaultdict(list) 

    for e in entries: 

        k = normalize(e["message"]) 

        if k: d[k].append(e) 

    return {k:v for k,v in d.items() if len(v) > 1} 

 

# ------------- HTML OUTPUT ------------- 
def html_report(dups, count, stats):
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    if not count:
        body = "<b>No logs found / parsing failed</b>"
    elif not dups:
        body = f"<b>No duplicate logs found.</b><br>Total parsed: {count}"
    else:
        body = f"<h2>Duplicate Log Messages</h2>Total parsed: {count}<br><br>"
        body += "<table border=1 cellpadding=5>"
        body += "<tr><th>Count</th><th>Locations & Example Lines</th></tr>"
 
        # Iterate duplicates by size descending
        for k, lst in sorted(dups.items(), key=lambda x: len(x[1]), reverse=True):
            # Combine file and line info
            examples = ""
            for e in lst[:5]:  # show up to 5 examples
                examples += f"<pre>{html.escape(e['file'])}: {html.escape(e['message'])}</pre>"
            if len(lst) > 5:
                examples += f"<b>... and {len(lst) - 5} more similar lines</b>"
 
            body += f"<tr><td>{len(lst)}</td><td>{examples}</td></tr>"
 
        body += "</table>"
 
    body += f"<hr><small>Stats: {dict(stats)}<br>Generated {ts}</small>"
    return f"<html><body>{body}</body></html>"

# ------------- MAIN ------------- 
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("--out", default="device_duplicates.html")
    a = ap.parse_args()

    ent, stats = [], Counter()

    # --- Merge all <filename>.<number> files and the base file itself ---
    input_dir = os.path.dirname(os.path.abspath(a.input))
    input_base = os.path.basename(a.input)
    # Match files like abcd.log, abcd.log.0, abcd.log.1, etc., and abcd.log itself
    pattern = os.path.join(input_dir, f"{input_base}*")
    files = sorted(glob.glob(pattern))
    # Only keep files that match <filename> or <filename>.<number>
    base_re = re.compile(rf"^{re.escape(input_base)}(\.\d+)?$")
    files = [f for f in files if base_re.match(os.path.basename(f))]
    # If no rotated files found, still process the input file itself (abcd.txt, scd.log, etc.)
    if not files:
        files = [a.input]

    for fname in files:
        try:
            if tarfile.is_tarfile(fname):
                process_tgz(fname, ent, stats)
            else:
                with open(fname, "rb") as f:
                    txt = safe_read(f, MAX_FILE_BYTES)
                    process_text(os.path.basename(fname), txt, ent, stats)
        except Exception as e:
            print(f"Fatal error processing input {fname}:", e)

    # --- ALWAYS run duplicate detection and report ---
    print(f"\nParsed total log lines: {len(ent)}")
    print("[Stats:", dict(stats))

    dups = find_duplicates(ent)
    print(f"Duplicate groups found: {len(dups)}")

    try:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(html_report(dups, len(ent), stats))
        print(f"\n Report saved: {a.out}")
    except Exception as e:
        print("Failed to write HTML report:", e)

if __name__ == "__main__": 
    main()
