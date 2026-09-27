# ForensicAutoCLI

Automated tool for preliminary forensic data analysis - disk images and memory dumps.

## ✨ Features

- 🔍 **Disk Image Analysis** - Performs basic disk image analysis using `pytsk3`
- 💾 **Memory Dump Analysis** - Analyzes selected Windows/Linux memory artifacts using Volatility 3
- 📁 **Recursive Traversal** - Extracts metadata from all files and directories
- 🔒 **YARA Scanning** - Scans file content using configurable YARA rules
- 🧠 **System Intelligence** - Extracts OS information, user profiles, command history, and selected suspicious patterns
- 📊 **Log Analysis** - Parses supported authentication and system logs and summarizes login and IP frequency
- 🪟 **Windows Eventlogs** - Parses selected Security and System event records
- 🌐 **Network Intelligence** - Extracts network-related events and identifies potential brute-force patterns
- 🔐 **Login Tracking** - Summarizes successful/failed logins, SSH connections, and sudo commands
- ⚡ **Quick Mode** - Analysis without YARA scanning
- 📊 **Multiple Output Formats** - JSON, CSV, and table formats
- 🔧 **Configurable** - Custom YARA rules, verbosity levels

## Prerequisites

Before installing, ensure you have the following:

### Required Software

- Python 3.10, 3.11, or 3.12
- uv (Python project and dependency manager)

### Disk Space

- Installation: ~500 MB for virtual environment and dependencies
- Additional: Space for your forensic images and analysis results (varies by usage)

### RAM

- Minimum: 4 GB
- Recommended: 8 GB or more (especially for memory dump analysis)

## Installation

From the project directory, synchronize the environment from `pyproject.toml` and
`uv.lock` by running this command:

```bash
uv sync
```

`uv sync` creates the local `.venv` directory and installs the pinned dependencies.
The environment does not need to be activated manually when using `uv run`.

## 🚀 Usage

### Disk Analysis

The disk analyzer uses `pytsk3` to open the image, detect a partition table or
filesystem, and recursively extract file and directory metadata. YARA scanning
is available as an optional additional step. Supported image and filesystem
formats depend on the installed `pytsk3`/The Sleuth Kit build and should be
verified with representative test images.

```bash
# Full disk analysis (with YARA scanning)
uv run python main.py disk image.dd

# Quick analysis without YARA
uv run python main.py disk image.dd --quick

# Custom YARA rules
uv run python main.py disk image.dd --yara-rules custom/rules.yar

# Different output formats
uv run python main.py disk image.dd --output json
uv run python main.py disk image.dd --output csv
uv run python main.py disk image.dd --output table
```

### Memory Analysis

Memory analysis uses Volatility 3 and currently targets selected Windows and
Linux memory artifacts. The available results depend on the detected operating
system and the Volatility plugins that can be run for the image.

```bash
# Analyze memory dump (auto-detect OS)
uv run python main.py memory dump.vmem

# Specify OS type
uv run python main.py memory dump.vmem --os-type windows
uv run python main.py memory dump.vmem --os-type linux

# Different output formats
uv run python main.py memory dump.vmem --output json
uv run python main.py memory dump.vmem --output csv
uv run python main.py memory dump.vmem --output table
```

### Eventlog Analysis

The eventlog command parses selected Windows EventLog records, including
login, logoff, security, and system events.

```bash
# Analyze Windows Security log
uv run python main.py eventlog Security.evtx

# Analyze Windows System log
uv run python main.py eventlog System.evtx

# Output formats
uv run python main.py eventlog Security.evtx --output json
uv run python main.py eventlog Security.evtx --output csv
uv run python main.py eventlog Security.evtx --output table
```

### Text Log Analysis (Linux/Mac)

The text log command supports the authentication and system log patterns
implemented in `log_analyzer.py`, such as `auth.log` and `syslog`.

```bash
# Analyze authentication log
uv run python main.py logs auth.log

# Analyze system log
uv run python main.py logs syslog

# Output formats
uv run python main.py logs auth.log --output json
uv run python main.py logs auth.log --output csv
uv run python main.py logs auth.log --output table
```

### Verbosity Levels

```bash
# Minimal output (results only)
uv run python main.py disk image.dd

# Info messages (analysis progress)
uv run python main.py -v disk image.dd

# Debug messages (detailed information about each file)
uv run python main.py -vv disk image.dd
```

## 📁 Project Structure

```
ForensicAutoCLI
├── main.py                 # CLI interface (Click)
├── disk_analyzer.py        # Main disk analysis orchestrator
├── memory_analyzer.py      # Memory dump analysis (Volatility 3)
├── filesystem_parser.py    # File system parsing
├── system_intelligence.py  # OS detection, user profiles, command history
├── log_analyzer.py         # Log file analysis (auth.log, syslog)
├── yara_scanner.py         # YARA scanning engine
├── output_formatter.py     # Output formatting (JSON, CSV, table)
├── validators.py           # Input validation
├── rules/
    └── my_rules.yar       # Example YARA rules
```
