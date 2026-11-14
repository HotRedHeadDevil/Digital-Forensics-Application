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

#### Is the analysis complete?

Every part of the disk analysis (filesystem scan, system intelligence, command history,
YARA scan) reports whether it ran completely. The result contains
`analysis_status`, and the table output starts with an **ANALYSIS COMPLETENESS** section.
An empty list of findings is only meaningful when the part that produces it is `[OK]`.

| Status      | Meaning                                                                         |
| ----------- | ------------------------------------------------------------------------------- |
| `[OK]`      | The part ran and covered everything it is designed to cover                     |
| `[PARTIAL]` | It ran, but some input was skipped, cut at a size limit or unreadable           |
| `[FAILED]`  | It hit an error (e.g. YARA rules do not compile) and produced no usable result  |
| `[NOT RUN]` | It could not start (e.g. the filesystem could not be opened, OS not recognised) |
| `[SKIPPED]` | Left out on purpose (`--quick`); does not make the analysis incomplete          |

The top-level `status` is `completed` only when nothing is partial, failed or not run;
otherwise it is `completed_with_warnings` (or `error` when the filesystem cannot be read).
With `--output csv` the problems are written to stderr so that stdout stays valid CSV.

### Memory Analysis

Memory analysis uses Volatility 3 and currently targets selected Windows and
Linux memory artifacts. The available results depend on the detected operating
system and the Volatility plugins that can be run for the image. Windows
analysis includes system information, sessions, processes, network connections,
and loaded DLLs. Linux analysis includes processes, a process tree, network
sockets, loaded kernel modules, and recovered Bash history when the required
kernel symbols and memory structures are available. Recovered Bash commands
are checked for suspicious patterns such as reverse shells, download-and-execute
pipelines, history removal, credential-file access, persistence, and dangerous
permission or file operations. Findings are available in the
`suspicious_command_findings` result and include the command, reason, and
severity. Individual Linux plugin
failures are reported in the `plugin_errors` result while the remaining
plugins continue to run.

#### Result status: failed vs. clean analysis

The memory summary never reports a failed analysis as a clean one. The
`status` field has three values:

| status      | meaning                                                                                                                                                                                                       |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `completed` | Every Volatility plugin ran. Zero findings really means nothing matched.                                                                                                                                      |
| `partial`   | Some plugins failed. Counts for the affected sections are `null` / "NOT ANALYSED" (not `0`) and listed in `sections_not_analysed`.                                                                            |
| `error`     | No plugin could run (e.g. wrong `--os-type`, `UnsatisfiedException`, missing symbols). No results are reported, `os_mismatch_warning` and `next_step` explain what to try, and the command exits with code 1. |

`plugin_summary` shows how many plugins succeeded, failed or were skipped, and
`plugin_errors` lists every failure with its reason.

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
├── analysis_status.py      # Tracks which parts of an analysis failed or were incomplete
├── output_formatter.py     # Output formatting (JSON, CSV, table)
├── validators.py           # Input validation
├── rules/
    └── my_rules.yar       # Example YARA rules
```
