# 🔒 File Integrity Monitoring (FIM) Tool

A lightweight, Python-based File Integrity Monitoring tool that detects unauthorized or accidental changes to files by comparing cryptographic hashes against a trusted baseline.

Built with **Python 3 standard library only** — no external dependencies.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)

---

## 📋 Table of Contents

- [Features](#-features)
- [Project Structure](#-project-structure)
- [How It Works](#-how-it-works)
- [Installation](#-installation)
- [Usage](#-usage)
- [Test Scenario](#-test-scenario-walkthrough)
- [Why SHA-256 over MD5?](#-why-sha-256-over-md5)
- [Real-World Applications](#-real-world-applications)
- [Limitations](#-limitations)
- [Future Improvements](#-future-improvements)
- [Viva / Interview Questions](#-viva--interview-questions)
- [License](#-license)

---

## ✨ Features

### Core
| Feature | Description |
|---------|-------------|
| **Baseline Creation** | Recursively scan a folder, compute SHA-256 hashes, save metadata to `baseline.json` |
| **Integrity Check** | Compare current state against baseline; report MODIFIED, NEW, DELETED, UNCHANGED |
| **Real-time Monitor** | Re-scan every N seconds with colour-coded console alerts; clean Ctrl+C stop |
| **Structured Logging** | Every event logged to `fim_log.txt` with timestamp and severity |
| **CLI Interface** | Full `argparse` CLI with sub-commands and help text |

### Optional Extras
| Feature | Flag |
|---------|------|
| Choose hash algorithm | `--algorithm sha512` or `--algorithm md5` |
| Ignore patterns | `--ignore .git __pycache__ "*.tmp"` |
| Baseline self-protection | Automatic (warns if baseline was tampered with) |
| CSV export | `--export-csv report.csv` |
| HTML export | `--export-html report.html` |
| Desktop notifications | Automatic in monitor mode (Windows/Linux/macOS) |

---

## 📁 Project Structure

```
FIM-Tool/
├── fim.py              # Main tool (single-file, all features)
├── baseline.json       # Generated baseline (after first run)
├── fim_log.txt         # Persistent event log
├── fim_report.csv      # Optional CSV report
├── fim_report.html     # Optional HTML report
├── README.md           # This file
└── test_folder/        # Sample directory for testing
    ├── config.txt
    ├── data/
    │   └── users.csv
    ├── logs/
    │   └── app.log
    └── scripts/
        └── hello.py
```

---

## 🔍 How It Works

### The Baseline Concept

```
  ┌──────────────┐      SHA-256       ┌─────────────────┐
  │  config.txt  │  ─────────────►    │  a3f2c9…  (hash)│
  │  users.csv   │  ─────────────►    │  7b1d4e…  (hash)│──► baseline.json
  │  hello.py    │  ─────────────►    │  c8e0f1…  (hash)│
  └──────────────┘                    └─────────────────┘

  Later…

  ┌──────────────┐      SHA-256       ┌─────────────────┐
  │  config.txt  │  ─────────────►    │  a3f2c9…  ✓ OK  │
  │  users.csv   │  ─────────────►    │  ff00ab…  ✗ MOD │──► Compare!
  │  hello.py    │  ─────────────►    │  c8e0f1…  ✓ OK  │
  │  malware.exe │  ─────────────►    │  NEW FILE ⚠     │
  └──────────────┘                    └─────────────────┘
```

1. **Baseline creation**: Walk every file in the target directory, read it in small 4 KB chunks, and feed each chunk to SHA-256. Store the resulting hex digest alongside file size and last-modified timestamp.

2. **Integrity check**: Re-scan the same directory, compute fresh hashes, and compare against the stored baseline:
   - **MODIFIED** — file exists in both but the hash changed
   - **NEW** — file exists now but wasn't in the baseline
   - **DELETED** — file was in the baseline but is now missing
   - **UNCHANGED** — hash matches perfectly

3. **Monitoring**: Run the integrity check in a loop every N seconds. Alert on any change.

### Why Read in Chunks?

```python
with open(filepath, "rb") as f:
    while True:
        chunk = f.read(4096)   # Read 4 KB at a time
        if not chunk:
            break
        hasher.update(chunk)   # Feed to SHA-256
```

If you read the entire file at once (`f.read()`), a 2 GB file would need 2 GB of RAM. Reading in 4 KB chunks keeps memory usage constant regardless of file size.

---

## 🚀 Installation

No installation needed — just Python 3.8+.

```bash
# Clone the repository
git clone https://github.com/yourusername/FIM-Tool.git
cd FIM-Tool

# Verify Python version
python --version   # Should be 3.8 or higher
```

---

## 💻 Usage

### 1. Create a Baseline

```bash
python fim.py baseline --path ./test_folder
```

This scans `test_folder` recursively and saves the hashes to `baseline.json`.

### 2. Check Integrity

```bash
python fim.py check --path ./test_folder
```

Compares the current state of `test_folder` against `baseline.json` and prints a summary.

### 3. Monitor in Real-Time

```bash
python fim.py monitor --path ./test_folder --interval 5
```

Re-checks every 5 seconds. Press **Ctrl+C** to stop cleanly.

### 4. Advanced Options

```bash
# Use SHA-512 instead of SHA-256
python fim.py baseline --path ./test_folder --algorithm sha512

# Custom ignore patterns
python fim.py baseline --path ./test_folder --ignore .git __pycache__ "*.log"

# Export check results
python fim.py check --path ./test_folder --export-csv report.csv --export-html report.html

# Custom baseline file location
python fim.py baseline --path ./test_folder --baseline /secure/my_baseline.json
```

### Full Help

```bash
python fim.py --help
python fim.py baseline --help
python fim.py check --help
python fim.py monitor --help
```

---

## 🧪 Test Scenario Walkthrough

### Step 1: Create the baseline

```bash
python fim.py baseline --path ./test_folder
```

**Expected output:**
```
  ▶ Creating baseline…
  ✓ Baseline created: 4 file(s) recorded.
```

### Step 2: Check with no changes (everything should pass)

```bash
python fim.py check --path ./test_folder
```

**Expected output:**
```
============================================================
  FILE INTEGRITY CHECK RESULTS
============================================================

  --------------------------------------------------------
  Category               Count
  --------------------------------------------------------
  Modified                   0
  New                        0
  Deleted                    0
  Unchanged                  4
  --------------------------------------------------------

  ✓ All files are intact. No changes detected.

============================================================
```

### Step 3: Modify a file

```bash
echo "HACKED! password=12345" >> ./test_folder/config.txt
python fim.py check --path ./test_folder
```

**Expected output:**
```
  ⚠  MODIFIED FILES (1)
  --------------------------------------------------------
  MODIFIED  config.txt
           Old: a3f2c9b1e4d7f8…
           New: ff12ab34cd56ef…
```

### Step 4: Add a new file

```bash
echo "I am malware" > ./test_folder/malware.exe
python fim.py check --path ./test_folder
```

**Expected output:**
```
  ➕ NEW FILES (1)
  --------------------------------------------------------
  NEW       malware.exe
```

### Step 5: Delete a file

```bash
# Windows:
del .\test_folder\scripts\hello.py
# Linux/Mac:
# rm ./test_folder/scripts/hello.py

python fim.py check --path ./test_folder
```

**Expected output:**
```
  ✖  DELETED FILES (1)
  --------------------------------------------------------
  DELETED   scripts/hello.py
```

### Step 6: Monitor mode (combine all changes)

```bash
python fim.py monitor --path ./test_folder --interval 5
```

In another terminal, modify files and watch the alerts appear in real time.

---

## 🛡️ Why SHA-256 over MD5?

| Property | MD5 | SHA-256 |
|----------|-----|---------|
| Output size | 128 bits | 256 bits |
| Speed | Faster | Slightly slower |
| Collision resistance | **Broken** (2004) | Secure (as of 2026) |
| Use in security | ❌ Not recommended | ✅ Industry standard |

**MD5 is cryptographically broken.** Researchers have demonstrated practical collision attacks — two different files can produce the same MD5 hash. This means an attacker could replace a legitimate file with a malicious one that has the same MD5 hash, and your FIM tool would not detect the change.

**SHA-256** is part of the SHA-2 family designed by the NSA and is currently considered secure. It's the standard for:
- TLS/SSL certificates
- Bitcoin blockchain
- Code signing
- File integrity verification

> This tool offers MD5 as an option for backward compatibility and speed in non-security contexts, but **defaults to SHA-256**.

---

## 🌍 Real-World Applications

### Compliance Standards

| Standard | Requirement | How FIM Helps |
|----------|------------|---------------|
| **PCI-DSS** (Payment Card Industry) | Req. 11.5 — Deploy file integrity monitoring | Detects unauthorized changes to payment systems |
| **HIPAA** (Healthcare) | §164.312(b) — Audit controls | Monitors access and changes to patient data files |
| **SOX** (Sarbanes-Oxley) | Section 404 — IT controls | Ensures financial system files aren't tampered |
| **NIST 800-53** | SI-7 — Software integrity | Verifies integrity of system and application files |

### Industry Tools

| Tool | Type | Notes |
|------|------|-------|
| **Tripwire** | Commercial | Pioneer of FIM; enterprise-grade |
| **OSSEC** | Open-source | Host-based IDS with FIM capabilities |
| **AIDE** | Open-source | Advanced Intrusion Detection Environment |
| **Samhain** | Open-source | Cross-platform, stealth FIM |
| **Wazuh** | Open-source | Fork of OSSEC; modern dashboard |

Our tool is a simplified learning version of what these enterprise tools do.

---

## ⚠️ Limitations

1. **No file content encryption** — `baseline.json` stores hashes (not content), but file paths are visible in plaintext.
2. **No database backend** — JSON works for small-to-medium folders; enterprise tools use databases.
3. **Single-threaded scanning** — Large directories with thousands of files will be slow.
4. **No kernel-level hooks** — We poll (re-scan periodically); enterprise tools like Tripwire use OS-level file-system event hooks (`inotify` on Linux, `ReadDirectoryChangesW` on Windows) for instant detection.
5. **Baseline stored locally** — An attacker with file access could modify both the files *and* the baseline. Enterprise tools store baselines on separate, hardened servers.
6. **No user authentication** — Anyone who can run the script can create a new baseline.
7. **Timestamp-based `modified` field** — The `modified` timestamp in the baseline is informational; integrity is determined solely by the hash.

---

## 🚀 Future Improvements

1. **Multi-threading / async scanning** — Use `concurrent.futures.ThreadPoolExecutor` to hash multiple files in parallel.
2. **File-system event hooks** — Use `watchdog` library (or OS-native APIs) for instant change detection instead of polling.
3. **Encrypted baseline** — Encrypt `baseline.json` with a passphrase so attackers can't read or modify it.
4. **Remote baseline storage** — Store the baseline on a separate server or cloud storage (S3, GCS).
5. **Email alerts** — Send email notifications using `smtplib` when critical changes are detected.
6. **Web dashboard** — Build a Flask/Django dashboard for visualising scan history.
7. **Differential baselines** — Store multiple baselines over time to track the evolution of changes.
8. **Binary diffing** — For modified files, show *what* changed (useful for text files).
9. **Scheduled scans** — Integrate with cron (Linux) or Task Scheduler (Windows) for automated periodic scans.
10. **SIEM integration** — Forward logs to Splunk, ELK Stack, or similar for centralised monitoring.

---

## 🎤 Viva / Interview Questions

### Q1: What is file integrity monitoring and why is it important?

**Answer:** File Integrity Monitoring (FIM) is a security process that continuously validates the integrity of operating system and application files by comparing their current state against a known-good baseline. It's important because:
- It detects unauthorized changes (e.g., malware modifying system files)
- It's required by compliance standards (PCI-DSS, HIPAA, SOX)
- It provides an audit trail of file changes
- It's a key component of defense-in-depth security strategies

### Q2: Why do you use SHA-256 instead of MD5? Can you explain collision resistance?

**Answer:** MD5 is cryptographically broken — researchers have demonstrated practical collision attacks where two different inputs produce the same hash. This means an attacker could replace a legitimate file with a malicious one that has the same MD5 hash, bypassing integrity checks. SHA-256, part of the SHA-2 family, has a 256-bit output (vs MD5's 128-bit) and no known practical collision attacks. "Collision resistance" means it should be computationally infeasible to find two different inputs that produce the same hash output.

### Q3: Why do you read files in chunks instead of all at once?

**Answer:** Reading a file entirely into memory with `f.read()` would require as much RAM as the file size. A 4 GB video file would need 4 GB of RAM. By reading in small chunks (4096 bytes = 4 KB), we keep memory usage constant at ~4 KB regardless of file size. The `hashlib` `.update()` method is designed for this incremental feeding — the final hash is identical whether you feed the data all at once or in chunks.

### Q4: How would you protect the baseline file from tampering?

**Answer:** Several strategies:
1. **Self-hashing** (implemented in this tool) — store a hash of the baseline inside itself and verify before each check
2. **Separate storage** — store the baseline on a read-only medium or remote server
3. **Encryption** — encrypt the baseline with a key not stored on the same machine
4. **Digital signatures** — sign the baseline with a private key; verify with the public key
5. **File permissions** — set strict OS-level permissions (read-only, root-owned)

### Q5: What's the difference between polling-based and event-based file monitoring?

**Answer:** 
- **Polling** (our approach): Re-scan the entire directory at fixed intervals. Simple to implement but has a detection delay (up to the interval length) and wastes CPU cycles scanning unchanged files.
- **Event-based**: Register with the OS kernel to receive notifications when files change (Linux: `inotify`, Windows: `ReadDirectoryChangesW`, macOS: `FSEvents`). Provides instant detection with minimal CPU usage, but is more complex to implement and platform-specific.

Enterprise tools like Tripwire and OSSEC use event-based monitoring for production systems.

### Q6: How does this tool relate to real-world security compliance?

**Answer:** PCI-DSS Requirement 11.5 explicitly mandates deploying "change-detection mechanisms (for example, file integrity monitoring tools) to alert personnel to unauthorized modification of critical system files." HIPAA requires audit controls to track access to electronic protected health information (ePHI). This tool demonstrates the core mechanism: creating a trusted baseline, detecting deviations, logging events with timestamps and severity levels, and alerting on critical changes — all fundamental capabilities that enterprise FIM solutions like Tripwire, OSSEC, and Wazuh provide at scale.

---

## 📄 License

This project is released under the [MIT License](https://opensource.org/licenses/MIT).

---

*Built as a Semester 3 mini-project to learn about cybersecurity, cryptographic hashing, and Python programming.*
