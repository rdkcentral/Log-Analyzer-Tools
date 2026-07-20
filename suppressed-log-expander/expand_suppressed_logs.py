#!/usr/bin/env python3
"""
expand_suppressed_logs.py — Reconstruct suppressed log messages.

Reads an RDK log file and expands [SUPPRESS] summary lines back into
individual repeated messages with reconstructed timestamps.

Reconstruction strategy:
  - Sporadic:  Uses exact timestamps from the "At:" line that follows.
  - Periodic:  Interpolates evenly between start and end window times.
  - Burst:     Interpolates at the detected rate between start and end.
  - Multi-msg: Looks backward for the 2 visible pattern cycles, then
               replays the pattern with interpolated timing.

Usage:
  python3 expand_suppressed_logs.py <logfile> [--output <outfile>]
  python3 expand_suppressed_logs.py <logfile>  (writes to stdout)

Example:
  python3 expand_suppressed_logs.py /tmp/Hotspotlog.txt.0 --output /tmp/expanded.log
"""

import re
import sys
import argparse
from datetime import datetime, timedelta


# --- RDK log line pattern ---
# 2026-06-23T10:04:37.765754 [INFO ] [HOTSPOT] [18111] message
LOG_LINE_RE = re.compile(
    r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+)\s+'
    r'\[(\w+\s*)\]\s+'
    r'\[([^\]]+)\]\s+'
    r'\[(\d+)\]\s+'
    r'(.*)$'
)

# [SUPPRESS] "message" repeated N times (behavior detail, HH:MM:SS-HH:MM:SS)
SUPPRESS_SINGLE_RE = re.compile(
    r'\[SUPPRESS\]\s+"(.+?)"\s+repeated\s+(\d+)\s+times\s+'
    r'\((\w+)([^,]*),\s*([^)]+)\)'
)

# [SUPPRESS] L-message pattern repeated N times (behavior detail, HH:MM:SS-HH:MM:SS)
SUPPRESS_MULTI_RE = re.compile(
    r'\[SUPPRESS\]\s+(\d+)-message pattern repeated\s+(\d+)\s+times\s+'
    r'\((\w+)([^,]*),\s*([^)]+)\)'
)

# "At:" timestamp line:  At: [06-23] 10:04:41, 10:04:47, ...
AT_LINE_RE = re.compile(r'^\s*At:\s+(.+)$')

# Multi-message per-string breakdown line:
#   Suppressed: "<message>" repeated N times
# Emitted by the C summary formatter after a multi-message [SUPPRESS] header so
# T1 grep telemetry can count each individual pattern string. The expander
# reconstructs those messages itself, so these lines are consumed (skipped).
SUPPRESS_BREAKDOWN_RE = re.compile(
    r'^\s*Suppressed:\s+"(.+)"\s+repeated\s+(\d+)\s+times\s*$'
)

# Individual timestamps in "At:" line (supports HH:MM:SS and HH:MM:SS.uuuuuu)
TS_RE = re.compile(r'(?:\[(\d{2}-\d{2})\]\s+)?(\d{2}:\d{2}:\d{2})(?:\.(\d+))?')

# [SUPPRESS] "message" repeated N times (no timestamp)
# Emitted by the shell suppressor (log_suppress.sh) for component log files
# whose lines carry no parseable timestamp. Reconstruction just re-emits N
# copies of the message with no timestamp.
SUPPRESS_NOTS_RE = re.compile(
    r'\[SUPPRESS\]\s+"(.+?)"\s+repeated\s+(\d+)\s+times\s+\(no timestamp\)'
)

# General (non-rdk-logger) timestamp formats used by component log files that
# do NOT go through rdk_logger. The shell suppressor emits BARE [SUPPRESS]
# lines into these files, and their visible cycles keep the component's own
# timestamp format. Each entry: (name, anchored regex, strptime fmt, reemit
# prefix, reemit suffix). group(1) = timestamp core; optional group(2) = a
# trailing 'Z' (ISO only). The regex consumes one trailing whitespace so the
# message starts at match end.
GENERIC_TS_FORMATS = [
    ('iso_t_us',  re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+)(Z?)\s'), '%Y-%m-%dT%H:%M:%S.%f', '', ''),
    ('iso_sp_us', re.compile(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)()\s'),    '%Y-%m-%d %H:%M:%S.%f', '', ''),
    ('short_us',  re.compile(r'^(\d{6}-\d{2}:\d{2}:\d{2}\.\d+)()\s'),                '%y%m%d-%H:%M:%S.%f', '', ''),
    ('iso_t',     re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(Z?)\s'),       '%Y-%m-%dT%H:%M:%S', '', ''),
    ('iso_sp',    re.compile(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})()\s'),         '%Y-%m-%d %H:%M:%S', '', ''),
    ('short',     re.compile(r'^(\d{6}-\d{2}:\d{2}:\d{2})()\s'),                     '%y%m%d-%H:%M:%S', '', ''),
    # Non-rdk component formats observed in production logs
    ('ymd8_us',   re.compile(r'^(\d{8} \d{6}\.\d+)()\s'),                            '%Y%m%d %H%M%S.%f', '', ''),
    ('dot_date',  re.compile(r'^(\d{4}\.\d{2}\.\d{2} \d{2}:\d{2}:\d{2})()\s'),       '%Y.%m.%d %H:%M:%S', '', ''),
    ('yr_mon_dd', re.compile(r'^(\d{4} [A-Za-z]{3} \d{2} \d{2}:\d{2}:\d{2})()\s'),   '%Y %b %d %H:%M:%S', '', ''),
    ('ctime_yr',  re.compile(r'^([A-Za-z]{3} [A-Za-z]{3} \d{2} \d{2}:\d{2}:\d{2} \d{4})()\s'), '%a %b %d %H:%M:%S %Y', '', ''),
    ('brk_iso',   re.compile(r'^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]\s'),        '%Y-%m-%d %H:%M:%S', '[', ']'),
    ('brk_ctime', re.compile(r'^\[([A-Za-z]{3} [A-Za-z]{3} \d{2} \d{2}:\d{2}:\d{2} \d{4})\]\s'), '%a %b %d %H:%M:%S %Y', '[', ']'),
    ('syslog_md', re.compile(r'^([A-Za-z]{3} \d{2} \d{2}:\d{2}:\d{2})()\s'),         '%b %d %H:%M:%S', '', ''),
    ('syslog_dm', re.compile(r'^(\d{2} [A-Za-z]{3} \d{2}:\d{2}:\d{2})()\s'),         '%d %b %H:%M:%S', '', ''),
]

# ctime with timezone token: "Fri Jun 12 11:02:06 UTC 2026" (SSHLogins, etc.)
# The TZ (group 2) is baked into the re-emit format as a literal so it survives
# reconstruction without relying on strptime %Z.
CTIME_TZ_RE = re.compile(
    r'^([A-Za-z]{3} [A-Za-z]{3} \d{2} \d{2}:\d{2}:\d{2}) ([A-Z]{2,4}) (\d{4})\s'
)


def parse_generic_ts(line):
    """Try to parse a leading timestamp for a non-rdk-logger line.
    Returns (dt, reemit_fmt, prefix, suffix, message) or None."""
    m = CTIME_TZ_RE.match(line)
    if m:
        try:
            dt = datetime.strptime(f"{m.group(1)} {m.group(3)}", '%a %b %d %H:%M:%S %Y')
            reemit_fmt = f'%a %b %d %H:%M:%S {m.group(2)} %Y'
            return dt, reemit_fmt, '', '', line[m.end():]
        except ValueError:
            pass
    for _name, rx, fmt, pre, post in GENERIC_TS_FORMATS:
        m = rx.match(line)
        if m:
            try:
                dt = datetime.strptime(m.group(1), fmt)
            except ValueError:
                continue
            zsfx = m.group(2) if (m.lastindex and m.lastindex >= 2) else ''
            return dt, fmt, pre, post + zsfx, line[m.end():]
    return None


# OneWifi format: [OneWifi] YYMMDD-HH:MM:SS.µs<L>  message   (L = I/E/W/D)
ONEWIFI_RE = re.compile(
    r'^\[OneWifi\] (\d{6}-\d{2}:\d{2}:\d{2}\.\d+)<([A-Z])>(\s+)(.*)$'
)


def parse_log_line(line):
    """Parse a log line into a unified model.

    Never returns None: every line is classified as one of
      - 'rdk':     rdk_logger prefixed ISO-T  (<ts> [lvl] [mod] [pid] <msg>)
      - 'generic': other component format      (<ts> <msg>)
      - 'bare':    no parseable timestamp      (<msg>)
    so the expander works for rdk_logger AND shell-suppressor output alike.
    """
    raw = line.rstrip('\n')

    # 1. rdk_logger prefixed ISO-T format
    m = LOG_LINE_RE.match(raw)
    if m:
        ts = m.group(1)
        try:
            dt = datetime.strptime(ts[:26], '%Y-%m-%dT%H:%M:%S.%f')
        except ValueError:
            dt = None
        return {
            'raw': raw, 'style': 'rdk', 'dt': dt, 'timestamp': ts,
            'level': m.group(2).strip(), 'module': m.group(3), 'pid': m.group(4),
            'message': m.group(5), 'ts_fmt': '%Y-%m-%dT%H:%M:%S.%f', 'zsfx': '',
        }

    # 2. Generic timestamped component line
    g = parse_generic_ts(raw)
    if g:
        dt, fmt, pre, post, message = g
        return {
            'raw': raw, 'style': 'generic', 'dt': dt, 'timestamp': raw[:len(raw) - len(message)].rstrip(),
            'level': None, 'module': None, 'pid': None,
            'message': message, 'ts_fmt': fmt, 'ts_pre': pre, 'ts_post': post,
        }

    # 3. OneWifi format
    ow = ONEWIFI_RE.match(raw)
    if ow:
        try:
            dt = datetime.strptime(ow.group(1), '%y%m%d-%H:%M:%S.%f')
        except ValueError:
            dt = None
        return {
            'raw': raw, 'style': 'onewifi', 'dt': dt, 'timestamp': ow.group(1),
            'level': ow.group(2), 'module': None, 'pid': None, 'ow_sep': ow.group(3),
            'message': ow.group(4), 'ts_fmt': '%y%m%d-%H:%M:%S.%f', 'zsfx': '',
        }

    # 4. Bare line (no timestamp at all)
    return {
        'raw': raw, 'style': 'bare', 'dt': None, 'timestamp': '',
        'level': None, 'module': None, 'pid': None,
        'message': raw, 'ts_fmt': None, 'zsfx': '',
    }


def parse_window(window_str, reference_date):
    """Parse time window like '10:04:40-10:05:36' or 'at 10:04:40' into (start_dt, end_dt).
    reference_date is the full SUPPRESS line datetime (used to resolve day)."""
    if window_str.startswith('at '):
        t = window_str[3:]
        dt = parse_time_with_date(t, reference_date)
        # If the time is after the SUPPRESS line, it must be previous day
        if dt > reference_date:
            dt -= timedelta(days=1)
        return dt, dt

    parts = window_str.split('-')
    if len(parts) == 2:
        start_dt = parse_time_with_date(parts[0], reference_date)
        end_dt = parse_time_with_date(parts[1], reference_date)
        # If start is after SUPPRESS line time, it's on the previous day
        if start_dt > reference_date:
            start_dt -= timedelta(days=1)
        # End should be >= start; if not, it crossed midnight
        if end_dt < start_dt:
            end_dt += timedelta(days=1)
        return start_dt, end_dt

    return None, None


def parse_time_with_date(time_str, reference_date):
    """Parse HH:MM:SS using reference_date for the date portion."""
    parts = time_str.strip().split(':')
    if len(parts) != 3:
        return reference_date
    h, m, s = int(parts[0]), int(parts[1]), int(parts[2])
    return reference_date.replace(hour=h, minute=m, second=s, microsecond=0)


def parse_at_timestamps(at_text, reference_date):
    """Parse the 'At:' line content into a list of datetime objects.
    Supports both HH:MM:SS (legacy) and HH:MM:SS.uuuuuu (microsecond) formats.
    Adds sub-second offsets when multiple timestamps share the same second."""
    timestamps = []
    current_date = None

    for m in TS_RE.finditer(at_text):
        date_part = m.group(1)  # "06-23" or None
        time_part = m.group(2)  # "10:04:41"
        usec_part = m.group(3)  # "234567" or None

        if date_part:
            mon, day = int(date_part[:2]), int(date_part[3:5])
            current_date = reference_date.replace(month=mon, day=day)

        if current_date is None:
            current_date = reference_date

        h, mi, s = [int(x) for x in time_part.split(':')]
        usec = 0
        if usec_part:
            # Normalize to 6 digits (pad or truncate)
            usec_str = usec_part.ljust(6, '0')[:6]
            usec = int(usec_str)
        dt = current_date.replace(hour=h, minute=mi, second=s, microsecond=usec)
        timestamps.append(dt)

    # Spread duplicates within the same second with synthetic sub-second offsets
    # Only needed when timestamps lack microsecond precision (all .000000)
    if len(timestamps) > 1:
        has_usec = any(t.microsecond != 0 for t in timestamps)
        if not has_usec:
            i = 0
            while i < len(timestamps):
                # Find run of identical timestamps
                j = i + 1
                while j < len(timestamps) and timestamps[j] == timestamps[i]:
                    j += 1
                run_len = j - i
                if run_len > 1:
                    # Spread evenly within that second
                    for k in range(run_len):
                        usec = int((k * 1000000) / run_len)
                        timestamps[i + k] = timestamps[i + k].replace(microsecond=usec)
                i = j

    return timestamps


def interpolate_timestamps(start_dt, end_dt, count, rate=None):
    """Generate evenly-spaced timestamps between start and end.
    If start == end and rate is provided (msg/s), spread using rate."""
    if count <= 0:
        return []
    if count == 1:
        return [start_dt]

    total_seconds = (end_dt - start_dt).total_seconds()
    if total_seconds <= 0:
        # Single-point window — use rate to compute spacing
        if rate and rate > 0:
            interval = 1.0 / rate
        else:
            interval = 0.004  # default 4ms for unknown burst
        return [start_dt + timedelta(seconds=i * interval) for i in range(count)]

    interval = total_seconds / (count - 1)
    return [start_dt + timedelta(seconds=i * interval) for i in range(count)]


def parse_rate(timing_detail):
    """Extract msg/s rate from timing detail like '~250 msg/s'."""
    m = re.search(r'~?(\d+)\s*msg/s', timing_detail)
    return float(m.group(1)) if m else None


def parse_interval(timing_detail):
    """Extract interval from timing detail like '~every 2s' or '~every 3min'."""
    m = re.search(r'~?every\s+(\d+)(min|s|ms)', timing_detail)
    if not m:
        return None
    val = int(m.group(1))
    unit = m.group(2)
    if unit == 'min':
        return val * 60.0
    elif unit == 's':
        return float(val)
    elif unit == 'ms':
        return val / 1000.0
    return None


def format_log_line(dt, level, module, pid, message):
    """Format a reconstructed log line in RDK format."""
    ts_str = dt.strftime('%Y-%m-%dT%H:%M:%S.') + f'{dt.microsecond:06d}'
    return f'{ts_str} [{level:<5}] [{module}] [{pid}] {message}'


def format_expanded_marker(dt, level, module, pid, message, index, total,
                          annotate=False, confidence=None):
    """Format a reconstructed log line in RDK format."""
    msg = message.rstrip('\n')
    line = format_log_line(dt, level, module, pid, msg)
    if annotate and confidence:
        line += f'  [~ {confidence}]'
    return line


def reemit_line(template, dt, message, annotate=False, confidence=None):
    """Reconstruct a suppressed line in the SAME style as `template`.

    `template` is a parsed line (the visible cycle the suppression replaced).
    - 'rdk':     <ISO-T ts> [lvl] [mod] [pid] <msg>
    - 'generic': <ts in original format> <msg>
    - 'bare':    <msg>              (no timestamp available)
    """
    msg = message.rstrip('\n')
    style = template['style'] if template else 'rdk'

    if style == 'rdk' and dt is not None:
        line = format_log_line(
            dt,
            template['level'] if template and template['level'] else 'INFO',
            template['module'] if template and template['module'] else '-',
            template['pid'] if template and template['pid'] else '-',
            msg)
    elif style == 'onewifi' and dt is not None:
        lvl = template['level'] if template and template.get('level') else 'I'
        sep = template.get('ow_sep', '  ') if template else '  '
        line = f"[OneWifi] {dt.strftime(template['ts_fmt'])}<{lvl}>{sep}{msg}"
    elif style == 'generic' and dt is not None:
        pre = template.get('ts_pre', '') if template else ''
        post = template.get('ts_post', '') if template else ''
        line = f"{pre}{dt.strftime(template['ts_fmt'])}{post} {msg}"
    else:
        line = msg  # bare, or no timestamp to place

    if annotate and confidence:
        line += f'  [~ {confidence}]'
    return line


def expand_suppressed_logs(input_lines, annotate=False):
    """Process log lines and expand [SUPPRESS] entries."""
    output = []
    i = 0
    lines = list(input_lines)
    recent_messages = []  # Track recent messages for multi-pattern reconstruction

    while i < len(lines):
        line = lines[i].rstrip('\n')
        parsed = parse_log_line(line)

        if not parsed:
            output.append(line)
            i += 1
            continue

        message = parsed['message']

        # Skip [SUPPRESS] multi-message per-string breakdown lines. The
        # multi-message expansion already reconstructs these individual
        # messages from the visible pattern cycles, so keeping the breakdown
        # lines would duplicate output and pollute the pattern lookback
        # (recent_messages) used for reconstruction.
        if SUPPRESS_BREAKDOWN_RE.match(message):
            i += 1
            continue

        # Check for [SUPPRESS] "(no timestamp)" variant (shell suppressor on
        # component files whose lines carry no timestamp). Re-emit N copies of
        # the message with no timestamp, matching the visible cycles' style.
        m_nots = SUPPRESS_NOTS_RE.search(message)
        if m_nots:
            suppressed_msg = m_nots.group(1)
            repeat_count = int(m_nots.group(2))
            template = recent_messages[-1] if recent_messages else parsed
            for _ in range(repeat_count):
                output.append(reemit_line(
                    template, None, suppressed_msg,
                    annotate=annotate,
                    confidence='no-timestamp' if annotate else None))
            i += 1
            continue

        # Check for [SUPPRESS] single-message
        m_single = SUPPRESS_SINGLE_RE.search(message)
        if m_single:
            suppressed_msg = m_single.group(1)
            repeat_count = int(m_single.group(2))
            behavior = m_single.group(3)
            timing_detail = m_single.group(4).strip()
            window_str = m_single.group(5)

            # Reference datetime: the SUPPRESS line's own timestamp (rdk_logger),
            # or — for a BARE shell-suppressor summary — the last visible cycle's
            # date pushed to end-of-day so window times resolve on the right day
            # without a false "previous day" shift or ref clamp.
            if parsed['dt'] is not None:
                ref_dt = parsed['dt']
                line_has_ts = True
            else:
                _base = recent_messages[-1]['dt'] if (recent_messages and recent_messages[-1]['dt']) else datetime.now()
                ref_dt = _base.replace(hour=23, minute=59, second=59, microsecond=999999)
                line_has_ts = False

            # Emit template: rdk lines carry their own prefix; bare/generic
            # shell-suppressor lines borrow the last visible cycle's format.
            emit_template = parsed if parsed['style'] == 'rdk' else (
                recent_messages[-1] if recent_messages else parsed)

            # Parse window
            start_dt, end_dt = parse_window(window_str, ref_dt)

            # Check if next line is "At:" (sporadic timestamps)
            sporadic_timestamps = None
            if i + 1 < len(lines):
                next_line = lines[i + 1].rstrip('\n')
                next_parsed = parse_log_line(next_line)
                if next_parsed:
                    at_match = AT_LINE_RE.match(next_parsed['message'])
                    if at_match:
                        sporadic_timestamps = parse_at_timestamps(
                            at_match.group(1), ref_dt)
                        i += 1  # consume the At: line

            # Determine timestamps for expansion
            if sporadic_timestamps and len(sporadic_timestamps) > 0:
                # Sporadic: use exact timestamps
                # Guard: ensure first expanded is not before last visible cycle
                if recent_messages and recent_messages[-1]['dt']:
                    last_visible_ts = recent_messages[-1]['dt']
                    for si in range(len(sporadic_timestamps)):
                        if sporadic_timestamps[si] <= last_visible_ts:
                            # Shift to just after last visible
                            sporadic_timestamps[si] = last_visible_ts + timedelta(
                                microseconds=(si + 1) * 1000)
                expand_times = sporadic_timestamps
                # If we have fewer timestamps than repeat_count (due to 1s gate),
                # fill remaining with interpolated times
                if len(expand_times) < repeat_count and start_dt and end_dt:
                    remaining = repeat_count - len(expand_times)
                    last_ts = expand_times[-1] if expand_times else start_dt
                    gap = (end_dt - last_ts).total_seconds() / (remaining + 1)
                    for j in range(1, remaining + 1):
                        expand_times.append(last_ts + timedelta(seconds=j * gap))
            elif start_dt and end_dt:
                # Periodic/Burst: interpolate using rate for proper spacing
                rate = parse_rate(timing_detail)
                if behavior == 'periodic' and start_dt != end_dt and repeat_count > 1:
                    # Window start = detection time (same as last visible cycle).
                    # First suppressed msg is one interval AFTER detection.
                    # Spread N messages evenly from (start + offset) to end.
                    offset = (end_dt - start_dt).total_seconds() / repeat_count
                    actual_start = start_dt + timedelta(seconds=offset)
                    expand_times = interpolate_timestamps(
                        actual_start, end_dt, repeat_count)
                elif behavior == 'periodic' and repeat_count == 1:
                    # Single suppressed periodic message: place at end_dt
                    expand_times = [end_dt]
                else:
                    # Burst or single-point periodic ("at HH:MM:SS"):
                    # All suppressed msgs happened between last_visible and SUPPRESS line.
                    if recent_messages and recent_messages[-1]['dt']:
                        last_visible_ts = recent_messages[-1]['dt']
                        actual_start = last_visible_ts + timedelta(microseconds=100)
                    else:
                        last_visible_ts = None
                        actual_start = start_dt
                    # Cap end at the SUPPRESS line time for rdk_logger (messages
                    # can't be after it). For a bare shell summary there is no
                    # line timestamp, so cap at the window end instead.
                    cap_dt = ref_dt if line_has_ts else (end_dt or ref_dt)
                    actual_end = cap_dt - timedelta(microseconds=100)
                    if actual_end <= actual_start:
                        # Extremely tight window — use minimal spacing
                        actual_start = last_visible_ts + timedelta(microseconds=10) \
                            if last_visible_ts else start_dt
                        actual_end = cap_dt - timedelta(microseconds=10)
                    expand_times = interpolate_timestamps(
                        actual_start, actual_end, repeat_count)
            else:
                expand_times = []

            # Determine confidence level for annotation
            if annotate:
                if sporadic_timestamps and len(sporadic_timestamps) > 0:
                    # Check if timestamps have real microsecond precision
                    has_usec = any(t.microsecond != 0 for t in sporadic_timestamps)
                    confidence = 'exact' if has_usec else 'timestamp ±1s'
                elif behavior == 'periodic':
                    confidence = 'periodic ±interval'
                elif behavior == 'burst':
                    confidence = 'burst ±rate'
                else:
                    confidence = 'interpolated'

            # Expand each repetition (re-emit in the visible cycle's style)
            for idx, dt in enumerate(expand_times, 1):
                output.append(reemit_line(
                    emit_template, dt, suppressed_msg,
                    annotate=annotate,
                    confidence=confidence if annotate else None))

            i += 1
            continue

        # Check for [SUPPRESS] multi-message pattern
        m_multi = SUPPRESS_MULTI_RE.search(message)
        if m_multi:
            pattern_len = int(m_multi.group(1))
            repeat_count = int(m_multi.group(2))
            behavior = m_multi.group(3)
            timing_detail = m_multi.group(4).strip()
            window_str = m_multi.group(5)

            ref_dt = None
            if parsed['dt'] is not None:
                ref_dt = parsed['dt']
                line_has_ts = True
            else:
                _base = recent_messages[-1]['dt'] if (recent_messages and recent_messages[-1]['dt']) else datetime.now()
                ref_dt = _base.replace(hour=23, minute=59, second=59, microsecond=999999)
                line_has_ts = False
            start_dt, end_dt = parse_window(window_str, ref_dt)

            # Check if next line is "At:" (sporadic timestamps — cycle starts)
            sporadic_timestamps = None
            if i + 1 < len(lines):
                next_line = lines[i + 1].rstrip('\n')
                next_parsed = parse_log_line(next_line)
                if next_parsed:
                    at_match = AT_LINE_RE.match(next_parsed['message'])
                    if at_match:
                        sporadic_timestamps = parse_at_timestamps(
                            at_match.group(1), ref_dt)
                        i += 1  # consume the At: line

            # Look backward in recent_messages for the pattern
            # The 2 visible cycles before suppression give us the pattern
            pattern_msgs = []
            intra_offsets = []  # timing offsets within a cycle (learned from visible cycles)
            cycle_entries = []
            if len(recent_messages) >= pattern_len:
                cycle_entries = recent_messages[-pattern_len:]
                pattern_msgs = [m['message'] for m in cycle_entries]
                # Learn intra-cycle timing from the last visible cycle's timestamps
                if cycle_entries[0]['dt']:
                    first_ts = cycle_entries[0]['dt']
                    for entry in cycle_entries:
                        ts = entry['dt'] if entry['dt'] else first_ts
                        intra_offsets.append((ts - first_ts).total_seconds())

            # Generate timestamps: use cycle interval for proper spacing
            # Each cycle starts at interval apart; messages within cycle use learned offsets
            # Window start = detection time; first suppressed cycle is one interval after.
            total_msgs = repeat_count * pattern_len
            if sporadic_timestamps and len(sporadic_timestamps) > 0:
                # Guard: ensure first cycle start is not before last visible cycle
                if recent_messages and recent_messages[-1]['dt']:
                    last_visible_ts = recent_messages[-1]['dt']
                    for si in range(len(sporadic_timestamps)):
                        if sporadic_timestamps[si] <= last_visible_ts:
                            sporadic_timestamps[si] = last_visible_ts + timedelta(
                                microseconds=(si + 1) * 1000)
                # Sporadic multi-message: each At: timestamp is a cycle start
                expand_times = []
                for cycle_idx, cycle_start in enumerate(sporadic_timestamps):
                    if cycle_idx >= repeat_count:
                        break
                    for msg_idx in range(pattern_len):
                        offset = intra_offsets[msg_idx] if msg_idx < len(intra_offsets) else msg_idx * 0.1
                        expand_times.append(
                            cycle_start + timedelta(seconds=offset))
                # Fill remaining cycles if At: had fewer timestamps than repeat_count
                if len(sporadic_timestamps) < repeat_count and start_dt and end_dt:
                    last_cycle_ts = sporadic_timestamps[-1]
                    remaining_cycles = repeat_count - len(sporadic_timestamps)
                    gap = (end_dt - last_cycle_ts).total_seconds() / (remaining_cycles + 1)
                    for rc in range(1, remaining_cycles + 1):
                        cycle_start = last_cycle_ts + timedelta(seconds=rc * gap)
                        for msg_idx in range(pattern_len):
                            offset = intra_offsets[msg_idx] if msg_idx < len(intra_offsets) else msg_idx * 0.1
                            expand_times.append(
                                cycle_start + timedelta(seconds=offset))
            elif start_dt and end_dt:
                cycle_interval = parse_interval(timing_detail)
                if cycle_interval and cycle_interval > 0:
                    # Offset by one cycle interval (window start = detection time)
                    actual_start = start_dt + timedelta(seconds=cycle_interval)
                    expand_times = []
                    for cycle in range(repeat_count):
                        cycle_start = actual_start + timedelta(
                            seconds=cycle * cycle_interval)
                        for msg_idx in range(pattern_len):
                            offset = intra_offsets[msg_idx] if msg_idx < len(intra_offsets) else msg_idx * 0.1
                            expand_times.append(
                                cycle_start + timedelta(seconds=offset))
                elif behavior == 'burst':
                    # Burst multi-message: derive cycle interval from rate
                    # and use learned intra_offsets for non-uniform internal gaps
                    rate = parse_rate(timing_detail)
                    if recent_messages and recent_messages[-1]['dt']:
                        last_visible_ts = recent_messages[-1]['dt']
                        burst_interval = (1.0 / rate) if rate and rate > 0 else 0.004
                        actual_start = last_visible_ts + timedelta(
                            seconds=burst_interval)
                    else:
                        actual_start = start_dt
                    # Cycle interval = pattern_len / rate (time for one full cycle)
                    if rate and rate > 0 and intra_offsets:
                        cycle_time = float(pattern_len) / rate
                        expand_times = []
                        for cycle in range(repeat_count):
                            cycle_start = actual_start + timedelta(
                                seconds=cycle * cycle_time)
                            for msg_idx in range(pattern_len):
                                offset = intra_offsets[msg_idx] if msg_idx < len(intra_offsets) else msg_idx * burst_interval
                                expand_times.append(
                                    cycle_start + timedelta(seconds=offset))
                    else:
                        expand_times = interpolate_timestamps(
                            actual_start, actual_start, total_msgs, rate=rate)
                else:
                    # Fallback: plain interpolation
                    rate = parse_rate(timing_detail)
                    expand_times = interpolate_timestamps(
                        start_dt, end_dt, total_msgs, rate=rate)
            else:
                expand_times = []

            # Clamp: for rdk_logger, all expanded timestamps must be < ref_dt
            # (the SUPPRESS line time). A bare shell summary has no line time, so
            # the clamp is skipped (window end already bounds the reconstruction).
            if line_has_ts and expand_times and expand_times[-1] >= ref_dt:
                # Compress to fit between first expanded and ref_dt
                clamp_start = expand_times[0]
                if recent_messages and recent_messages[-1]['dt']:
                    last_visible_ts = recent_messages[-1]['dt']
                    clamp_start = max(clamp_start,
                        last_visible_ts + timedelta(microseconds=100))
                clamp_end = ref_dt - timedelta(microseconds=100)
                if clamp_end > clamp_start:
                    expand_times = interpolate_timestamps(
                        clamp_start, clamp_end, total_msgs)

            # Determine confidence level for annotation
            if annotate:
                if sporadic_timestamps and len(sporadic_timestamps) > 0:
                    has_usec = any(t.microsecond != 0 for t in sporadic_timestamps)
                    confidence = 'exact' if has_usec else 'timestamp ±1s'
                elif behavior == 'periodic':
                    confidence = 'periodic ±interval'
                elif behavior == 'burst':
                    confidence = 'burst ±rate'
                else:
                    confidence = 'interpolated'

            # Expand (re-emit each slot in its visible cycle's style)
            for idx in range(total_msgs):
                if idx < len(expand_times):
                    dt = expand_times[idx]
                else:
                    dt = end_dt if end_dt else ref_dt

                slot = idx % pattern_len
                if pattern_msgs:
                    msg = pattern_msgs[slot].rstrip('\n')
                else:
                    msg = f'[pattern msg {slot + 1}/{pattern_len}]'

                # Per-slot template: rdk lines use the SUPPRESS line's prefix;
                # bare/generic lines use the matching visible cycle slot.
                if parsed['style'] == 'rdk':
                    slot_template = parsed
                elif slot < len(cycle_entries):
                    slot_template = cycle_entries[slot]
                elif recent_messages:
                    slot_template = recent_messages[-1]
                else:
                    slot_template = parsed

                output.append(reemit_line(
                    slot_template, dt, msg,
                    annotate=annotate,
                    confidence=confidence if annotate else None))

            i += 1
            recent_messages = []
            continue

        # Normal line — output as-is and track for multi-pattern lookback
        output.append(line)
        recent_messages.append(parsed)
        # Keep only last 20 messages for pattern lookback
        if len(recent_messages) > 20:
            recent_messages = recent_messages[-20:]

        i += 1

    return output


def main():
    parser = argparse.ArgumentParser(
        description='Expand [SUPPRESS] log lines back into individual messages.')
    parser.add_argument('logfile', help='Input log file path')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    parser.add_argument('--annotate', '-a', action='store_true',
                        help='Mark reconstructed lines with confidence level')
    args = parser.parse_args()

    try:
        with open(args.logfile, 'r') as f:
            input_lines = f.readlines()
    except FileNotFoundError:
        print(f'Error: File not found: {args.logfile}', file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(f'Error: Permission denied: {args.logfile}', file=sys.stderr)
        sys.exit(1)

    expanded = expand_suppressed_logs(input_lines, annotate=args.annotate)

    if args.output:
        with open(args.output, 'w') as f:
            for line in expanded:
                f.write(line + '\n')
        print(f'Expanded log written to: {args.output}', file=sys.stderr)
        print(f'  Input lines:  {len(input_lines)}', file=sys.stderr)
        print(f'  Output lines: {len(expanded)}', file=sys.stderr)
    else:
        for line in expanded:
            print(line)


if __name__ == '__main__':
    main()
