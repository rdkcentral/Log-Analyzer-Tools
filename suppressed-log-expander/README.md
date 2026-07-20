# Suppressed Log Expander

Reconstruct (de-duplicate in reverse) the individual log messages that the RDK
log suppression feature collapses into `[SUPPRESS]` summary lines.

The RDK log suppressor — both the real-time `rdk_logger` engine and the
offline `log_suppress.sh` (sysint-broadband) script — replaces runs of
repeated log lines with a compact summary, for example:

```
2026-06-29T10:05:00.500000 [INFO ] [HOTSPOT] [18086] [PERIODIC TEST] Health check ping
2026-06-29T10:05:02.500000 [INFO ] [HOTSPOT] [18086] [PERIODIC TEST] Health check ping
2026-06-29T10:05:30.600000 [INFO ] [HOTSPOT] [18086] [SUPPRESS] "[PERIODIC TEST] Health check ping" repeated 13 times (periodic ~every 2s, 10:05:02-10:05:28)
```

This tool expands each `[SUPPRESS]` summary back into the individual messages
with reconstructed timestamps, so existing log-analysis workflows can run over
the full, un-suppressed stream.

## What it handles

- **Single-message** and **multi-message (pattern)** suppression summaries.
- **Timing modes**: sporadic (uses the exact `At:` timestamps), periodic
  (evenly interpolated), burst (rate-based interpolation).
- **Both producers**: `rdk_logger` (prefixed ISO-8601 records) and the shell
  suppressor (bare `[SUPPRESS]` lines in component log files).
- **Many component timestamp formats** — ISO-8601 (`T`/space, optional `Z`),
  `YYMMDD-HH:MM:SS.us`, OneWifi, ctime (with/without timezone), bracketed
  ctime/ISO, syslog `Mon DD`/`DD Mon`, `YYYY.MM.DD`, `YYYYMMDD HHMMSS.us`, and
  no-timestamp files. Reconstructed lines preserve the original format.

## Usage

```bash
# Write expanded log to stdout
python3 expand_suppressed_logs.py <logfile>

# Write to a file
python3 expand_suppressed_logs.py <logfile> --output <outfile>

# Mark reconstructed lines with a confidence annotation
python3 expand_suppressed_logs.py <logfile> --annotate
```

## Requirements

- Python 3.x (standard library only — no external dependencies).
