#!/usr/bin/env python3
"""
File Integrity Monitoring (FIM) Tool
=====================================
Detects unauthorized or accidental changes to files by comparing
cryptographic hashes against a trusted baseline.

Author  : Student Project (Semester 3)
Date    : 2026-10-12
Python  : 3.8+  (standard library only)

Usage examples:
    python fim.py baseline --path ./test_folder
    python fim.py check    --path ./test_folder
    python fim.py monitor  --path ./test_folder --interval 5
"""

# ──────────────────────────────────────────────────────────────
# IMPORTS – all from the Python standard library
# ──────────────────────────────────────────────────────────────
import hashlib      # Cryptographic hash functions (SHA-256, SHA-512, MD5)
import os           # File-system operations (walk, stat, path helpers)
import json         # Read / write the baseline as a JSON file
import time         # Sleep between monitor cycles
import datetime     # Human-readable timestamps for logs & reports
import argparse     # Build the CLI (command-line interface)
import logging      # Structured logging to file and console
import sys          # Exit codes, platform detection
import csv          # Optional CSV report export
import fnmatch      # Unix-style filename pattern matching for ignore list
import io           # Text stream reconfiguration for UTF-8 output

# ── Ensure stdout can handle Unicode (fixes cp1252 on Windows) ──
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout = io.TextIOWrapper(
        sys.stdout.buffer, encoding="utf-8", errors="replace"
    )
    sys.stderr = io.TextIOWrapper(
        sys.stderr.buffer, encoding="utf-8", errors="replace"
    )


# ──────────────────────────────────────────────────────────────
# CONSTANTS
# ──────────────────────────────────────────────────────────────

# Default name for the baseline file stored alongside the tool
DEFAULT_BASELINE = "baseline.json"

# Default log file name
DEFAULT_LOG_FILE = "fim_log.txt"

# Chunk size for reading files (4 KB) – keeps memory low for large files
CHUNK_SIZE = 4096

# Supported hash algorithms (user can pick via --algorithm flag)
SUPPORTED_ALGORITHMS = ("sha256", "sha512", "md5")

# Default patterns to ignore during scanning
DEFAULT_IGNORE_PATTERNS = [
    ".git",         # Git internals
    "__pycache__",  # Python bytecode cache
    "*.tmp",        # Temporary files
    "*.pyc",        # Compiled Python files
    "baseline.json",  # The baseline file itself
    "fim_log.txt",    # Our own log file
]

# ANSI colour codes for console output (works on most modern terminals)
# On Windows legacy terminals these may not render; we detect & disable.
COLORS = {
    "RED":    "\033[91m",
    "GREEN":  "\033[92m",
    "YELLOW": "\033[93m",
    "CYAN":   "\033[96m",
    "BOLD":   "\033[1m",
    "RESET":  "\033[0m",
}


# ──────────────────────────────────────────────────────────────
# HELPER: Enable ANSI colours on Windows 10+ terminals
# ──────────────────────────────────────────────────────────────

def _enable_windows_ansi():
    """
    On Windows, enable VT100 escape-sequence processing so that
    ANSI colour codes render correctly in cmd.exe and PowerShell.
    Silently does nothing on non-Windows or if it fails.
    """
    if sys.platform != "win32":
        return
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        # STD_OUTPUT_HANDLE = -11
        handle = kernel32.GetStdHandle(-11)
        # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        mode = ctypes.c_ulong()
        kernel32.GetConsoleMode(handle, ctypes.byref(mode))
        kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        # If it doesn't work, colours will just not show – no big deal
        pass


def colorize(text, color_name):
    """
    Wrap *text* in ANSI colour codes.

    Parameters
    ----------
    text : str
        The string to colourize.
    color_name : str
        Key from the COLORS dict (RED, GREEN, YELLOW, CYAN, BOLD).

    Returns
    -------
    str
        The colourized string (or plain text if colour is unavailable).
    """
    code = COLORS.get(color_name, "")
    reset = COLORS.get("RESET", "")
    return f"{code}{text}{reset}"


# ──────────────────────────────────────────────────────────────
# LOGGING SETUP
# ──────────────────────────────────────────────────────────────

def setup_logging(log_file=DEFAULT_LOG_FILE):
    """
    Configure the root logger to write events to both the console
    and a persistent log file.

    The log file uses the format:
        2026-10-12 19:55:00 | WARNING | hash changed for secret.txt

    Parameters
    ----------
    log_file : str
        Path to the log file (default: fim_log.txt).

    Returns
    -------
    logging.Logger
        Configured logger instance.
    """
    logger = logging.getLogger("FIM")
    logger.setLevel(logging.DEBUG)  # Capture everything; handlers filter

    # Formatter shared by both handlers
    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # --- File handler (always INFO and above) ---
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(fmt)

    # --- Console handler (INFO and above) ---
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(fmt)

    # Avoid duplicate handlers if setup_logging is called more than once
    if not logger.handlers:
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

    return logger


# ──────────────────────────────────────────────────────────────
# CORE FUNCTION 1: Compute a file's hash
# ──────────────────────────────────────────────────────────────

def compute_file_hash(filepath, algorithm="sha256"):
    """
    Read a file in small chunks and return its cryptographic hash.

    Reading in chunks (CHUNK_SIZE bytes at a time) means even
    multi-gigabyte files won't blow up your RAM.

    Parameters
    ----------
    filepath : str
        Absolute or relative path to the file.
    algorithm : str
        Hash algorithm name: 'sha256', 'sha512', or 'md5'.

    Returns
    -------
    str or None
        Hex-digest string, e.g. 'a3f2…9b1c',
        or None if the file cannot be read.
    """
    try:
        # hashlib.new() lets us pick the algorithm at runtime
        hasher = hashlib.new(algorithm)

        with open(filepath, "rb") as f:          # 'rb' = read bytes
            while True:
                chunk = f.read(CHUNK_SIZE)       # Read 4 KB at a time
                if not chunk:                    # End of file
                    break
                hasher.update(chunk)             # Feed chunk into hasher

        return hasher.hexdigest()                # Return the final hash

    except PermissionError:
        # The OS won't let us read this file (e.g., system files)
        logging.getLogger("FIM").warning(
            f"Permission denied: {filepath}"
        )
        return None

    except OSError as e:
        # Catch-all for file-locked, broken symlink, etc.
        logging.getLogger("FIM").warning(
            f"Cannot read file {filepath}: {e}"
        )
        return None


# ──────────────────────────────────────────────────────────────
# CORE FUNCTION 2: Should we ignore this path?
# ──────────────────────────────────────────────────────────────

def should_ignore(path, ignore_patterns):
    """
    Check whether *path* matches any of the ignore patterns.

    We check each component of the path (directories and filename)
    against every pattern using Unix glob matching (fnmatch).

    Parameters
    ----------
    path : str
        The file or directory path to test.
    ignore_patterns : list[str]
        Shell-glob patterns like '*.tmp', '.git', '__pycache__'.

    Returns
    -------
    bool
        True if the path should be skipped.
    """
    # Normalise to forward slashes for consistent matching
    parts = os.path.normpath(path).replace("\\", "/").split("/")

    for pattern in ignore_patterns:
        for part in parts:
            if fnmatch.fnmatch(part, pattern):
                return True
    return False


# ──────────────────────────────────────────────────────────────
# CORE FUNCTION 3: Scan a directory tree
# ──────────────────────────────────────────────────────────────

def scan_directory(target_path, algorithm="sha256", ignore_patterns=None):
    """
    Recursively walk *target_path* and build a dict of file metadata.

    The returned dict maps each relative file path to:
        {
            "hash":     "<hex digest>",
            "size":     <bytes>,
            "modified": "<ISO 8601 timestamp>"
        }

    Parameters
    ----------
    target_path : str
        Root directory to scan.
    algorithm : str
        Hash algorithm to use.
    ignore_patterns : list[str] or None
        Glob patterns of files/dirs to skip.

    Returns
    -------
    dict
        { relative_path: { "hash", "size", "modified" }, … }
    """
    if ignore_patterns is None:
        ignore_patterns = []

    logger = logging.getLogger("FIM")
    file_data = {}

    # os.walk yields (dirpath, dirnames, filenames) for every sub-folder
    for dirpath, dirnames, filenames in os.walk(target_path):

        # ── Skip ignored directories (modify dirnames in-place) ──
        # Modifying dirnames[:] tells os.walk NOT to descend into them
        dirnames[:] = [
            d for d in dirnames
            if not should_ignore(d, ignore_patterns)
        ]

        for filename in filenames:
            full_path = os.path.join(dirpath, filename)

            # Skip ignored files
            if should_ignore(full_path, ignore_patterns):
                continue

            # Build a relative path so the baseline is portable
            rel_path = os.path.relpath(full_path, target_path)
            # Normalize to forward slashes for cross-platform consistency
            rel_path = rel_path.replace("\\", "/")

            # Compute the hash
            file_hash = compute_file_hash(full_path, algorithm)
            if file_hash is None:
                continue  # Skip files we can't read

            # Grab file metadata from the OS
            try:
                stat = os.stat(full_path)
                file_size = stat.st_size
                modified_time = datetime.datetime.fromtimestamp(
                    stat.st_mtime
                ).isoformat()
            except OSError as e:
                logger.warning(f"Cannot stat {full_path}: {e}")
                continue

            file_data[rel_path] = {
                "hash": file_hash,
                "size": file_size,
                "modified": modified_time,
            }

    logger.info(
        f"Scanned {len(file_data)} file(s) in '{target_path}' "
        f"using {algorithm.upper()}"
    )
    return file_data


# ──────────────────────────────────────────────────────────────
# CORE FUNCTION 4: Save & load the baseline
# ──────────────────────────────────────────────────────────────

def save_baseline(file_data, baseline_path, algorithm="sha256"):
    """
    Write the scanned file metadata to a JSON baseline file.

    The baseline format:
    {
        "metadata": {
            "created":   "...",
            "algorithm": "sha256",
            "file_count": 42,
            "baseline_hash": "abc123..."   ← self-protection
        },
        "files": { ... }
    }

    Parameters
    ----------
    file_data : dict
        Output of scan_directory().
    baseline_path : str
        Where to write the JSON file.
    algorithm : str
        Which hash was used (stored in metadata for later checks).
    """
    baseline = {
        "metadata": {
            "created": datetime.datetime.now().isoformat(),
            "algorithm": algorithm,
            "file_count": len(file_data),
        },
        "files": file_data,
    }

    # ── Self-protection: hash the serialised content (without the hash field) ──
    # We serialise the baseline to bytes, hash those bytes, then embed
    # the hash into metadata and write the final file once.
    content_bytes = json.dumps(
        baseline, indent=2, sort_keys=True
    ).encode("utf-8")

    hasher = hashlib.new(algorithm)
    hasher.update(content_bytes)
    baseline["metadata"]["baseline_hash"] = hasher.hexdigest()

    # Write the final baseline (now includes the self-protection hash)
    with open(baseline_path, "w", encoding="utf-8") as f:
        json.dump(baseline, f, indent=2, sort_keys=True)

    logger = logging.getLogger("FIM")
    logger.info(
        f"Baseline saved to '{baseline_path}' "
        f"({len(file_data)} files, {algorithm.upper()})"
    )


def load_baseline(baseline_path):
    """
    Read and parse the JSON baseline file.

    Parameters
    ----------
    baseline_path : str
        Path to baseline.json.

    Returns
    -------
    dict
        The full baseline dict with 'metadata' and 'files' keys.

    Raises
    ------
    FileNotFoundError
        If the baseline file doesn't exist.
    json.JSONDecodeError
        If the file contains invalid JSON.
    """
    if not os.path.isfile(baseline_path):
        raise FileNotFoundError(
            f"Baseline file not found: '{baseline_path}'. "
            "Run 'baseline' mode first."
        )

    with open(baseline_path, "r", encoding="utf-8") as f:
        baseline = json.load(f)

    logging.getLogger("FIM").info(
        f"Loaded baseline from '{baseline_path}' "
        f"({baseline['metadata']['file_count']} files)"
    )
    return baseline


def verify_baseline_integrity(baseline_path, baseline_data):
    """
    Check that the baseline file itself has not been tampered with.

    We reconstruct the file as it was *before* the baseline_hash was
    inserted, compute its hash, and compare.

    Parameters
    ----------
    baseline_path : str
        Path to the baseline JSON file.
    baseline_data : dict
        Already-loaded baseline data.

    Returns
    -------
    bool
        True if the baseline is intact, False if tampered.
    """
    logger = logging.getLogger("FIM")
    stored_hash = baseline_data["metadata"].get("baseline_hash")

    if stored_hash is None:
        logger.warning("No self-protection hash found in baseline.")
        return True  # Can't verify, assume OK

    algorithm = baseline_data["metadata"].get("algorithm", "sha256")

    # Rebuild the baseline *without* the hash field, exactly as it
    # was when first serialised
    verification_copy = json.loads(json.dumps(baseline_data))
    del verification_copy["metadata"]["baseline_hash"]

    temp_content = json.dumps(
        verification_copy, indent=2, sort_keys=True
    ).encode("utf-8")

    hasher = hashlib.new(algorithm)
    hasher.update(temp_content)
    computed_hash = hasher.hexdigest()

    if computed_hash != stored_hash:
        logger.critical(
            "⚠ BASELINE TAMPERED! The baseline file has been modified "
            "since it was created. Results may be unreliable."
        )
        return False

    logger.info("Baseline integrity verified ✓")
    return True


# ──────────────────────────────────────────────────────────────
# CORE FUNCTION 5: Compare current state against baseline
# ──────────────────────────────────────────────────────────────

def compare_with_baseline(current_data, baseline_data):
    """
    Compare the current scan against the stored baseline.

    Parameters
    ----------
    current_data : dict
        Output of scan_directory() (the live scan).
    baseline_data : dict
        The 'files' sub-dict from the loaded baseline.

    Returns
    -------
    dict
        {
            "modified": [ (path, old_hash, new_hash), … ],
            "new":      [ path, … ],
            "deleted":  [ path, … ],
            "unchanged": int
        }
    """
    results = {
        "modified": [],
        "new": [],
        "deleted": [],
        "unchanged": 0,
    }

    # ── Check every file in the current scan ──
    for filepath, info in current_data.items():
        if filepath in baseline_data:
            if info["hash"] != baseline_data[filepath]["hash"]:
                # Hash changed → file was modified
                results["modified"].append(
                    (filepath,
                     baseline_data[filepath]["hash"],
                     info["hash"])
                )
            else:
                results["unchanged"] += 1
        else:
            # File exists now but wasn't in the baseline → new file
            results["new"].append(filepath)

    # ── Check for deleted files ──
    for filepath in baseline_data:
        if filepath not in current_data:
            results["deleted"].append(filepath)

    return results


# ──────────────────────────────────────────────────────────────
# DISPLAY: Pretty-print results to the console
# ──────────────────────────────────────────────────────────────

def print_results(results):
    """
    Print a colour-coded, human-readable summary of changes.

    Parameters
    ----------
    results : dict
        Output of compare_with_baseline().
    """
    logger = logging.getLogger("FIM")

    print("\n" + "=" * 60)
    print(colorize("  FILE INTEGRITY CHECK RESULTS", "BOLD"))
    print("=" * 60)

    # ── Modified files (CRITICAL – red) ──
    if results["modified"]:
        print(colorize(
            f"\n  ⚠  MODIFIED FILES ({len(results['modified'])})", "RED"
        ))
        print("  " + "-" * 56)
        for filepath, old_hash, new_hash in results["modified"]:
            print(f"  {colorize('MODIFIED', 'RED')}  {filepath}")
            print(f"           Old: {old_hash[:16]}…")
            print(f"           New: {new_hash[:16]}…")
            logger.critical(f"MODIFIED: {filepath}")

    # ── New files (WARNING – yellow) ──
    if results["new"]:
        print(colorize(
            f"\n  ➕ NEW FILES ({len(results['new'])})", "YELLOW"
        ))
        print("  " + "-" * 56)
        for filepath in results["new"]:
            print(f"  {colorize('NEW     ', 'YELLOW')}  {filepath}")
            logger.warning(f"NEW: {filepath}")

    # ── Deleted files (CRITICAL – red) ──
    if results["deleted"]:
        print(colorize(
            f"\n  ✖  DELETED FILES ({len(results['deleted'])})", "RED"
        ))
        print("  " + "-" * 56)
        for filepath in results["deleted"]:
            print(f"  {colorize('DELETED ', 'RED')}  {filepath}")
            logger.critical(f"DELETED: {filepath}")

    # ── Summary table ──
    total_changes = (
        len(results["modified"])
        + len(results["new"])
        + len(results["deleted"])
    )

    print("\n  " + "-" * 56)
    print(f"  {'Category':<20} {'Count':>8}")
    print("  " + "-" * 56)
    print(f"  {'Modified':<20} {len(results['modified']):>8}")
    print(f"  {'New':<20} {len(results['new']):>8}")
    print(f"  {'Deleted':<20} {len(results['deleted']):>8}")
    print(f"  {'Unchanged':<20} {results['unchanged']:>8}")
    print("  " + "-" * 56)

    if total_changes == 0:
        print(colorize(
            "\n  ✓ All files are intact. No changes detected.\n", "GREEN"
        ))
        logger.info("Integrity check PASSED – no changes detected.")
    else:
        print(colorize(
            f"\n  ✗ {total_changes} change(s) detected!\n", "RED"
        ))
        logger.warning(
            f"Integrity check found {total_changes} change(s)."
        )

    print("=" * 60 + "\n")


# ──────────────────────────────────────────────────────────────
# OPTIONAL EXTRA: Export report as CSV
# ──────────────────────────────────────────────────────────────

def export_csv(results, output_path="fim_report.csv"):
    """
    Write the integrity-check results to a CSV file.

    Parameters
    ----------
    results : dict
        Output of compare_with_baseline().
    output_path : str
        Destination CSV file path.
    """
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Status", "File Path", "Old Hash", "New Hash"])

        for filepath, old_h, new_h in results["modified"]:
            writer.writerow(["MODIFIED", filepath, old_h, new_h])
        for filepath in results["new"]:
            writer.writerow(["NEW", filepath, "", ""])
        for filepath in results["deleted"]:
            writer.writerow(["DELETED", filepath, "", ""])

    logging.getLogger("FIM").info(f"CSV report saved to '{output_path}'")
    print(f"  📄 CSV report saved to: {output_path}")


# ──────────────────────────────────────────────────────────────
# OPTIONAL EXTRA: Export report as HTML
# ──────────────────────────────────────────────────────────────

def export_html(results, output_path="fim_report.html"):
    """
    Generate a styled HTML report of the integrity-check results.

    Parameters
    ----------
    results : dict
        Output of compare_with_baseline().
    output_path : str
        Destination HTML file path.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>FIM Report – {timestamp}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif;
               background: #1a1a2e; color: #eee; padding: 2rem; }}
        h1   {{ color: #e94560; }}
        table {{ border-collapse: collapse; width: 100%;
                 margin-top: 1rem; }}
        th, td {{ border: 1px solid #444; padding: 0.6rem 1rem;
                  text-align: left; }}
        th   {{ background: #16213e; }}
        .modified {{ color: #e94560; font-weight: bold; }}
        .new      {{ color: #f0c040; font-weight: bold; }}
        .deleted  {{ color: #ff6b6b; font-weight: bold; }}
        .summary  {{ margin-top: 1.5rem; font-size: 1.1rem; }}
    </style>
</head>
<body>
    <h1>🔒 File Integrity Monitoring Report</h1>
    <p>Generated: {timestamp}</p>
    <table>
        <tr><th>Status</th><th>File Path</th><th>Details</th></tr>
"""

    for filepath, old_h, new_h in results["modified"]:
        html += (
            f'        <tr><td class="modified">MODIFIED</td>'
            f"<td>{filepath}</td>"
            f"<td>Old: {old_h[:20]}…<br>New: {new_h[:20]}…</td></tr>\n"
        )
    for filepath in results["new"]:
        html += (
            f'        <tr><td class="new">NEW</td>'
            f"<td>{filepath}</td><td>—</td></tr>\n"
        )
    for filepath in results["deleted"]:
        html += (
            f'        <tr><td class="deleted">DELETED</td>'
            f"<td>{filepath}</td><td>—</td></tr>\n"
        )

    total = (
        len(results["modified"])
        + len(results["new"])
        + len(results["deleted"])
    )
    status_text = (
        "✓ All files intact" if total == 0
        else f"✗ {total} change(s) detected"
    )

    html += f"""    </table>
    <div class="summary">
        <p><strong>Modified:</strong> {len(results['modified'])} &nbsp;|&nbsp;
           <strong>New:</strong> {len(results['new'])} &nbsp;|&nbsp;
           <strong>Deleted:</strong> {len(results['deleted'])} &nbsp;|&nbsp;
           <strong>Unchanged:</strong> {results['unchanged']}</p>
        <p>{status_text}</p>
    </div>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    logging.getLogger("FIM").info(f"HTML report saved to '{output_path}'")
    print(f"  🌐 HTML report saved to: {output_path}")


# ──────────────────────────────────────────────────────────────
# MODE 1: Create baseline
# ──────────────────────────────────────────────────────────────

def mode_baseline(args):
    """
    Scan the target directory and create a fresh baseline.json.

    Parameters
    ----------
    args : argparse.Namespace
        Parsed CLI arguments (path, algorithm, baseline, ignore).
    """
    logger = logging.getLogger("FIM")
    target = os.path.abspath(args.path)

    # Validate the target directory exists
    if not os.path.isdir(target):
        logger.error(f"Directory not found: '{target}'")
        print(colorize(f"  ✗ Error: '{target}' is not a valid directory.", "RED"))
        sys.exit(1)

    print(colorize("\n  ▶ Creating baseline…", "CYAN"))

    file_data = scan_directory(
        target,
        algorithm=args.algorithm,
        ignore_patterns=args.ignore,
    )

    save_baseline(file_data, args.baseline, algorithm=args.algorithm)

    print(colorize(
        f"  ✓ Baseline created: {len(file_data)} file(s) recorded.\n",
        "GREEN",
    ))


# ──────────────────────────────────────────────────────────────
# MODE 2: Integrity check
# ──────────────────────────────────────────────────────────────

def mode_check(args):
    """
    Scan the target directory and compare against the baseline.

    Parameters
    ----------
    args : argparse.Namespace
        Parsed CLI arguments.
    """
    logger = logging.getLogger("FIM")
    target = os.path.abspath(args.path)

    if not os.path.isdir(target):
        logger.error(f"Directory not found: '{target}'")
        print(colorize(f"  ✗ Error: '{target}' is not a valid directory.", "RED"))
        sys.exit(1)

    # Load the existing baseline
    try:
        baseline = load_baseline(args.baseline)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.error(str(e))
        print(colorize(f"  ✗ {e}", "RED"))
        sys.exit(1)

    # Verify baseline self-integrity
    verify_baseline_integrity(args.baseline, baseline)

    algorithm = baseline["metadata"].get("algorithm", "sha256")

    print(colorize("\n  ▶ Running integrity check…", "CYAN"))

    current_data = scan_directory(
        target,
        algorithm=algorithm,
        ignore_patterns=args.ignore,
    )

    results = compare_with_baseline(current_data, baseline["files"])
    print_results(results)

    # Optional exports
    if args.export_csv:
        export_csv(results, args.export_csv)
    if args.export_html:
        export_html(results, args.export_html)


# ──────────────────────────────────────────────────────────────
# MODE 3: Real-time monitoring
# ──────────────────────────────────────────────────────────────

def mode_monitor(args):
    """
    Continuously re-scan and report changes every N seconds.
    Stops cleanly on Ctrl+C (KeyboardInterrupt).

    Parameters
    ----------
    args : argparse.Namespace
        Parsed CLI arguments (includes 'interval').
    """
    logger = logging.getLogger("FIM")
    target = os.path.abspath(args.path)

    if not os.path.isdir(target):
        logger.error(f"Directory not found: '{target}'")
        print(colorize(f"  ✗ Error: '{target}' is not a valid directory.", "RED"))
        sys.exit(1)

    try:
        baseline = load_baseline(args.baseline)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.error(str(e))
        print(colorize(f"  ✗ {e}", "RED"))
        sys.exit(1)

    verify_baseline_integrity(args.baseline, baseline)
    algorithm = baseline["metadata"].get("algorithm", "sha256")

    print(colorize(
        f"\n  ▶ Monitoring '{target}' every {args.interval}s  "
        f"(Ctrl+C to stop)\n",
        "CYAN",
    ))
    logger.info(
        f"Monitor started: interval={args.interval}s, path='{target}'"
    )

    cycle = 0
    try:
        while True:
            cycle += 1
            now = datetime.datetime.now().strftime("%H:%M:%S")
            print(f"  [{now}] Cycle {cycle}…", end=" ")

            current_data = scan_directory(
                target,
                algorithm=algorithm,
                ignore_patterns=args.ignore,
            )
            results = compare_with_baseline(
                current_data, baseline["files"]
            )

            total_changes = (
                len(results["modified"])
                + len(results["new"])
                + len(results["deleted"])
            )

            if total_changes == 0:
                print(colorize("OK ✓", "GREEN"))
            else:
                print(colorize(
                    f"ALERT – {total_changes} change(s)!", "RED"
                ))
                print_results(results)

                # Optional desktop notification (best-effort)
                _desktop_notify(
                    f"FIM Alert: {total_changes} change(s) detected!"
                )

            time.sleep(args.interval)

    except KeyboardInterrupt:
        print(colorize(
            "\n\n  ■ Monitoring stopped by user (Ctrl+C).\n", "YELLOW"
        ))
        logger.info("Monitor stopped by user.")


# ──────────────────────────────────────────────────────────────
# OPTIONAL EXTRA: Desktop notification (best-effort)
# ──────────────────────────────────────────────────────────────

def _desktop_notify(message):
    """
    Attempt to show a native desktop notification.

    This is best-effort: it uses Windows toast on Win10+, notify-send
    on Linux, or osascript on macOS.  If it fails, it silently
    does nothing – console output is the primary alert channel.

    Parameters
    ----------
    message : str
        Notification body text.
    """
    try:
        if sys.platform == "win32":
            # Use PowerShell to show a Windows toast notification
            import subprocess
            ps_script = (
                "[Windows.UI.Notifications.ToastNotificationManager, "
                "Windows.UI.Notifications, ContentType = WindowsRuntime] "
                "> $null; "
                "$template = [Windows.UI.Notifications.ToastNotificationManager]"
                "::GetTemplateContent("
                "[Windows.UI.Notifications.ToastTemplateType]::ToastText01); "
                "$text = $template.GetElementsByTagName('text'); "
                f"$text.Item(0).AppendChild($template.CreateTextNode('{message}'))"
                " > $null; "
                "$toast = [Windows.UI.Notifications.ToastNotification]"
                "::new($template); "
                "[Windows.UI.Notifications.ToastNotificationManager]"
                "::CreateToastNotifier('FIM Tool').Show($toast)"
            )
            subprocess.Popen(
                ["powershell", "-Command", ps_script],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        elif sys.platform == "darwin":
            import subprocess
            subprocess.Popen([
                "osascript", "-e",
                f'display notification "{message}" with title "FIM Alert"'
            ])
        else:
            # Linux – try notify-send
            import subprocess
            subprocess.Popen(["notify-send", "FIM Alert", message])
    except Exception:
        pass  # Notifications are optional; don't crash the tool


# ──────────────────────────────────────────────────────────────
# CLI: Build the argument parser
# ──────────────────────────────────────────────────────────────

def build_parser():
    """
    Construct and return the argparse.ArgumentParser.

    The CLI has three sub-commands: baseline, check, monitor.

    Returns
    -------
    argparse.ArgumentParser
        Fully configured parser.
    """
    parser = argparse.ArgumentParser(
        prog="fim.py",
        description=(
            "🔒 File Integrity Monitoring Tool – detect unauthorized "
            "changes by comparing cryptographic hashes."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python fim.py baseline --path ./test_folder\n"
            "  python fim.py check    --path ./test_folder\n"
            "  python fim.py monitor  --path ./test_folder --interval 5\n"
            "  python fim.py check    --path ./docs --algorithm sha512 "
            "--export-html report.html\n"
        ),
    )

    # ── Sub-commands ──
    subparsers = parser.add_subparsers(
        dest="mode",
        help="Operating mode",
    )

    # --- Shared arguments (added to each sub-command) ---
    def add_common_args(sub):
        """Add arguments shared by all modes."""
        sub.add_argument(
            "--path", "-p",
            required=True,
            help="Target directory to scan.",
        )
        sub.add_argument(
            "--baseline", "-b",
            default=DEFAULT_BASELINE,
            help=(
                f"Path to the baseline file "
                f"(default: {DEFAULT_BASELINE})."
            ),
        )
        sub.add_argument(
            "--algorithm", "-a",
            choices=SUPPORTED_ALGORITHMS,
            default="sha256",
            help="Hash algorithm (default: sha256).",
        )
        sub.add_argument(
            "--ignore", "-i",
            nargs="*",
            default=DEFAULT_IGNORE_PATTERNS,
            help=(
                "Glob patterns to ignore "
                f"(default: {DEFAULT_IGNORE_PATTERNS})."
            ),
        )
        sub.add_argument(
            "--log-file",
            default=DEFAULT_LOG_FILE,
            help=f"Log file path (default: {DEFAULT_LOG_FILE}).",
        )

    # --- baseline ---
    p_baseline = subparsers.add_parser(
        "baseline",
        help="Create a new trusted baseline.",
    )
    add_common_args(p_baseline)

    # --- check ---
    p_check = subparsers.add_parser(
        "check",
        help="Check file integrity against the baseline.",
    )
    add_common_args(p_check)
    p_check.add_argument(
        "--export-csv",
        metavar="FILE",
        help="Export results to a CSV file.",
    )
    p_check.add_argument(
        "--export-html",
        metavar="FILE",
        help="Export results to an HTML file.",
    )

    # --- monitor ---
    p_monitor = subparsers.add_parser(
        "monitor",
        help="Continuously monitor for changes.",
    )
    add_common_args(p_monitor)
    p_monitor.add_argument(
        "--interval", "-n",
        type=int,
        default=10,
        help="Seconds between scans (default: 10).",
    )

    return parser


# ──────────────────────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────────────────────

def main():
    """
    Parse CLI arguments and dispatch to the chosen mode.
    """
    _enable_windows_ansi()

    parser = build_parser()
    args = parser.parse_args()

    # If no sub-command was given, print help
    if args.mode is None:
        parser.print_help()
        sys.exit(0)

    # Set up logging (use the user's chosen log file)
    setup_logging(args.log_file)
    logger = logging.getLogger("FIM")
    logger.info(f"FIM started in '{args.mode}' mode")

    # Dispatch to the correct mode function
    if args.mode == "baseline":
        mode_baseline(args)
    elif args.mode == "check":
        mode_check(args)
    elif args.mode == "monitor":
        mode_monitor(args)


# This guard ensures main() runs only when the script is executed
# directly (not when imported as a module).
if __name__ == "__main__":
    main()
