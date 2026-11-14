# memory_analyzer.py - Memory dump analysis with Volatility 3

import logging
import os
import shlex
import sys
import json
import re
import traceback
from pathlib import Path

logger = logging.getLogger(__name__)


SUSPICIOUS_COMMAND_RULES = (
    (
        re.compile(r"(?:curl|wget)\b[^\n|]*\|\s*(?:ba)?sh\b", re.IGNORECASE),
        "Downloads content and pipes it straight into a shell",
        "high",
    ),
    (
        re.compile(r"\b(?:nc|ncat|netcat)\b.*(?:\s-e|\s-e\s*/|\s-c\s+)", re.IGNORECASE),
        "Possible reverse shell via netcat",
        "high",
    ),
    (
        re.compile(r"\brm\s+(?:-[^\n]*f[^\n]*r|-[^\n]*r[^\n]*f)\s+/(?:\s|$)", re.IGNORECASE),
        "Recursive deletion from the filesystem root (rm -rf /)",
        "critical",
    ),
    (
        re.compile(r"\bchmod\s+(?:-R\s+)?(?:[2467][0-7]{3}\b|[ugoa]*\+s\b)", re.IGNORECASE),
        "Permission change that enables privilege escalation (setuid/setgid)",
        "high",
    ),
    (
        re.compile(r"\b(?:history\s+-c|unset\s+HISTFILE|export\s+HISTFILE\s*=\s*/dev/null|shred\b[^\n]*history)", re.IGNORECASE),
        "Attempt to clear or suppress command history",
        "high",
    ),
    (
        re.compile(r"\b(?:cat|less|more|grep)\b[^\n]*/etc/shadow\b", re.IGNORECASE),
        "Access to the password hash file (/etc/shadow)",
        "high",
    ),
    (
        re.compile(r"\b(?:crontab\s+-[ei]|systemctl\s+(?:enable|start))|>>?\s*\S*(?:\.bashrc|\.profile|\.bash_profile|\.zshrc|/var/spool/cron|/etc/cron)", re.IGNORECASE),
        "Possible persistence via cron, systemd or login scripts",
        "medium",
    ),
    (
        re.compile(r"\b(?:python|python3|perl|ruby|php)\s+(?:-c|-e)\b", re.IGNORECASE),
        "Inline script run from the command line",
        "medium",
    ),
    (
        re.compile(r"\b(?:curl|wget)\b[^\n]*(?:/tmp|/var/tmp|/dev/shm)\b", re.IGNORECASE),
        "File downloaded into a temporary or shared directory",
        "medium",
    ),
    (
        re.compile(r"/dev/tcp/|\bbash\s+-i\b|\bsocat\b[^\n]*\bexec:", re.IGNORECASE),
        "Possible reverse shell",
        "high",
    ),
    (
        re.compile(r"\bbase64\s+(?:-d|--decode)\b[^\n]*\|\s*(?:ba)?sh\b", re.IGNORECASE),
        "Decoded content piped into a shell",
        "high",
    ),
    (
        re.compile(r"\b(?:cat|less|more|grep)\b[^\n]*(?:/etc/passwd|\bpassword\b|credentials)", re.IGNORECASE),
        "Search or read of credentials",
        "medium",
    ),
    (
        re.compile(r"\b(?:curl|wget)\b[^\n]*\s(?:-d|--data\S*|-F|-T|--upload-file|--post-file)\s+@", re.IGNORECASE),
        "File sent to a remote server",
        "high",
    ),
    (
        re.compile(r"\b(?:curl|wget)\b[^\n]*\.(?:sh|py|pl|elf|bin|exe|ps1)\b", re.IGNORECASE),
        "Script or program downloaded from the internet",
        "medium",
    ),
    (
        re.compile(r"\b(?:nc|ncat|netcat)\s+(?:-\w*l\w*)", re.IGNORECASE),
        "Network listener opened with netcat",
        "high",
    ),
    (
        re.compile(r"\b(?:base64|xxd|openssl\s+enc)\b[^\n]*(?:/etc/shadow|/etc/passwd|id_rsa)", re.IGNORECASE),
        "Sensitive file encoded or encrypted",
        "high",
    ),
    (
        re.compile(r"\brm\s+(?:-[a-z]*\s+)*-[a-z]*[rf][a-z]*\s+(?:-[a-z]+\s+)*/(?:var/log|etc|boot|usr|bin|home|root)\b", re.IGNORECASE),
        "Recursive deletion of system, home or log directories",
        "high",
    ),
    (
        re.compile(r"\bdd\s+if=/dev/(?:sd|nvme|vd|hd)\w*|\bmkfs(?:\.\w+)?\s+/dev/", re.IGNORECASE),
        "Raw disk copy or filesystem creation on a device",
        "medium",
    ),
    (
        re.compile(r"\bpkexec\b", re.IGNORECASE),
        "Privilege escalation via pkexec",
        "medium",
    ),
    (
        re.compile(r"\balias\b[^\n]*--hide", re.IGNORECASE),
        "Alias that hides files from listings",
        "medium",
    ),
    (
        re.compile(r"\bopenssl\s+enc\b|\bdocker\s+run\b[^\n]*--privileged", re.IGNORECASE),
        "File encryption or privileged container started",
        "medium",
    ),
    (
        re.compile(r"\bchmod\s+(?:-R\s+)?0?777\b", re.IGNORECASE),
        "World-writable permissions set",
        "low",
    ),
)


# Program started from a folder where users and downloads land (not a system folder)
USER_WRITABLE_REASON = "Program started from Desktop, Downloads or a temp folder"
USER_WRITABLE_PATH_RE = re.compile(
    r"^\W*[a-z]:\\(?:users\\[^\\]+\\(?:desktop|downloads|appdata\\local\\temp)|windows\\temp|users\\public)\\",
    re.IGNORECASE,
)

WINDOWS_COMMAND_RULES = (
    (
        re.compile(r"\bpowershell(?:\.exe)?\b.*\s-(?:e|en|enc|enco|encodedcommand)\b", re.IGNORECASE),
        "PowerShell with an encoded command",
        "high",
    ),
    (
        re.compile(r"\b(?:iex|invoke-expression|invoke-webrequest|iwr)\b|downloadstring|downloadfile|net\.webclient", re.IGNORECASE),
        "PowerShell downloads or runs content from the internet",
        "high",
    ),
    (
        re.compile(r"\bpowershell(?:\.exe)?\b.*-(?:w|windowstyle)\s+hidden", re.IGNORECASE),
        "PowerShell with a hidden window",
        "medium",
    ),
    (
        re.compile(r"\bcertutil(?:\.exe)?\b.*-(?:urlcache|decode|encode)", re.IGNORECASE),
        "certutil used to download or decode a file",
        "high",
    ),
    (
        re.compile(r"\bbitsadmin(?:\.exe)?\b.*/transfer", re.IGNORECASE),
        "File download via BITS",
        "high",
    ),
    (
        re.compile(r"\b(?:mshta|regsvr32|rundll32)(?:\.exe)?\b.*(?:https?://|javascript:|scrobj)", re.IGNORECASE),
        "Remote script run through a system tool (mshta/regsvr32/rundll32)",
        "high",
    ),
    (
        re.compile(r"\bnet1?(?:\.exe)?\s+(?:user\b.*\s/add\b|localgroup\s+administrators\b.*\s/add\b)", re.IGNORECASE),
        "User account created or added to administrators",
        "high",
    ),
    (
        re.compile(r"\bvssadmin(?:\.exe)?\b.*delete\s+shadows|\bwbadmin(?:\.exe)?\b.*delete|\bbcdedit(?:\.exe)?\b.*recoveryenabled\s+no", re.IGNORECASE),
        "Backups or shadow copies deleted",
        "critical",
    ),
    (
        re.compile(r"\bwevtutil(?:\.exe)?\b.*\bcl\b|\bclear-eventlog\b", re.IGNORECASE),
        "Event logs cleared",
        "high",
    ),
    (
        re.compile(r"\bschtasks(?:\.exe)?\b.*\s/create\b", re.IGNORECASE),
        "Scheduled task created (persistence)",
        "medium",
    ),
    (
        re.compile(r"\breg(?:\.exe)?\s+add\b.*\\run(?:once)?\b", re.IGNORECASE),
        "Run registry key modified (persistence)",
        "medium",
    ),
    (
        re.compile(r"\bmimikatz|sekurlsa|\bprocdump\b.*lsass|comsvcs\.dll.*minidump", re.IGNORECASE),
        "Credential dumping tool",
        "critical",
    ),
    (
        re.compile(r"\bnc(?:at)?(?:\.exe)?\b.*\s-e\b", re.IGNORECASE),
        "Possible reverse shell via netcat",
        "high",
    ),
    (
        re.compile(r"\bwmic(?:\.exe)?\b.*process\s+call\s+create", re.IGNORECASE),
        "Process started via WMI",
        "medium",
    ),
    (
        re.compile(r"\bicacls\b.*\s/grant\s+everyone:f\b.*\s/t\b", re.IGNORECASE),
        "Full access granted to everyone recursively (icacls Everyone:F)",
        "high",
    ),
    (
        re.compile(r"Start-Process\b[^\n]*(?:-Verb\s+RunAs|-WindowStyle\s+Hidden)", re.IGNORECASE),
        "Program started elevated or with a hidden window",
        "medium",
    ),
    (
        re.compile(r"\b(?:curl|iwr|invoke-webrequest|invoke-restmethod|irm)\b[^\n]*-(?:Method\s+(?:POST|PUT)|Body\b)", re.IGNORECASE),
        "Data sent to a remote server",
        "high",
    ),
    (
        re.compile(r"\breg(?:\.exe)?\s+query\b[^\n]*password|Select-String\b[^\n]*password|\b(?:type|cat|more)\b[^\n]*password", re.IGNORECASE),
        "Search or read of credentials",
        "medium",
    ),
    (
        re.compile(r"\bGet-Credential\b|ConvertTo-SecureString\b[^\n]*-AsPlainText", re.IGNORECASE),
        "Credential handling in plain text",
        "medium",
    ),
    (
        re.compile(r"\breg(?:\.exe)?\s+delete\b[^\n]*\\run\b|Set-ItemProperty\b[^\n]*(?:HKLM|CurrentControlSet\\Services)", re.IGNORECASE),
        "Registry persistence or service configuration changed",
        "medium",
    ),
    (
        re.compile(r"\bdocker\s+run\b[^\n]*--privileged", re.IGNORECASE),
        "Privileged container started",
        "medium",
    ),
    (
        re.compile(r"-ExecutionPolicy\s+Bypass|\bFromBase64String\b", re.IGNORECASE),
        "PowerShell policy bypass or Base64 decoding",
        "medium",
    ),
    (
        re.compile(r"\bpsexec(?:\.exe)?\b|\bEnter-PSSession\b|\bInvoke-Command\b[^\n]*-ComputerName", re.IGNORECASE),
        "Remote execution on another machine",
        "medium",
    ),
    (
        USER_WRITABLE_PATH_RE,
        USER_WRITABLE_REASON,
        "medium",
    ),
)

# Windows process anomaly heuristics ("know normal, find evil")
EXPECTED_PARENTS = {
    'smss.exe': {'system'},
    'services.exe': {'wininit.exe'},
    'lsass.exe': {'wininit.exe'},
    'lsm.exe': {'wininit.exe'},
    'svchost.exe': {'services.exe'},
    'spoolsv.exe': {'services.exe'},
    'taskhost.exe': {'services.exe'},
    'taskhostw.exe': {'services.exe'},
    'wmiprvse.exe': {'svchost.exe'},
    'dllhost.exe': {'svchost.exe', 'services.exe'},
}
SINGLETON_PROCESSES = frozenset({'lsass.exe', 'services.exe', 'wininit.exe', 'lsm.exe'})
SYSTEM_BINARIES = frozenset({
    'svchost.exe', 'lsass.exe', 'csrss.exe', 'services.exe', 'smss.exe', 'winlogon.exe',
    'wininit.exe', 'spoolsv.exe', 'taskhost.exe', 'taskhostw.exe', 'dllhost.exe',
    'wmiprvse.exe', 'conhost.exe', 'lsm.exe',
})
LOOKALIKE_TARGETS = ('svchost', 'lsass', 'csrss', 'services', 'winlogon', 'wininit',
                     'spoolsv', 'explorer', 'taskhost', 'taskhostw', 'dllhost',
                     'conhost', 'wmiprvse', 'audiodg')
DOCUMENT_APPS = frozenset({'winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe',
                           'acrord32.exe', 'acrobat.exe', 'onenote.exe'})
SCRIPT_HOSTS = frozenset({'cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe',
                          'mshta.exe', 'rundll32.exe', 'regsvr32.exe'})
SYSTEM_PATH_RE = re.compile(r"^(?:\\\?\?\\)?[a-z]:\\windows\\(?:system32|syswow64)\\(?:wbem\\)?[^\\]+$")

SUSPICIOUS_PROCESS_NAMES = frozenset({
    'nc', 'ncat', 'netcat', 'socat', 'perl', 'python', 'python3', 'ruby', 'php',
})


def analyze_shell_command(command, rules=SUSPICIOUS_COMMAND_RULES):
    """Return suspicious-command findings for one command (Linux rules by default)."""
    command = command.strip()
    findings = []
    for pattern, reason, severity in rules:
        if pattern.search(command):
            findings.append({"reason": reason, "severity": severity})
    return findings


_SEVERITY_ORDER = {'critical': 3, 'high': 2, 'medium': 1, 'low': 0}


def group_suspicious_commands(findings):
    """Collapse duplicate suspicious-command records into unique findings.

    The Volatility bash plugin returns the same history line several times
    (once per heap copy and once per bash process), and one command can match
    several rules. Records are grouped by the normalized command text; each
    group keeps every reason, the highest severity, the PIDs, the distinct
    timestamps and the number of raw records it replaces.

    Args:
        findings: list of dicts with command, reason, severity, pid, time

    Returns:
        list: unique findings sorted by severity (highest first), then by
        first-seen time
    """
    groups = {}
    for item in findings:
        command = ' '.join(str(item.get('command', '')).split())
        group = groups.setdefault(command, {
            'type': 'command',
            'command': command,
            'reasons': [],
            'severity': 'low',
            'pids': [],
            'processes': [],
            'times': [],
            'sources': [],
            '_hits': 0,
            '_pid_times': {},
        })
        reason = item.get('reason')
        if reason and reason not in group['reasons']:
            group['reasons'].append(reason)
        severity = item.get('severity', 'low')
        if _SEVERITY_ORDER.get(severity, 0) > _SEVERITY_ORDER.get(group['severity'], 0):
            group['severity'] = severity
        pid = item.get('pid')
        if pid not in (None, '') and pid not in group['pids']:
            group['pids'].append(pid)
        process = item.get('process')
        if process and process not in group['processes']:
            group['processes'].append(process)
        time = item.get('time')
        if time not in (None, '') and str(time) not in group['times']:
            group['times'].append(str(time))
        source = item.get('source')
        if source and source not in group['sources']:
            group['sources'].append(source)
        group['_hits'] += 1
        key = (pid, str(time) if time not in (None, '') else '')
        group['_pid_times'][key] = group['_pid_times'].get(key, 0) + 1

    result = []
    for group in groups.values():
        hits = group.pop('_hits')
        # One command matching N rules produced N records per history line.
        group['records'] = max(1, hits // max(1, len(group['reasons'])))
        # Per-PID breakdown: how many records carry which timestamp
        n_reasons = max(1, len(group['reasons']))
        by_pid = {}
        for (pid, time), count in group.pop('_pid_times').items():
            by_pid.setdefault(pid, []).append(
                {'time': time, 'count': max(1, count // n_reasons)}
            )
        group['by_pid'] = [
            {'pid': pid, 'times': sorted(entries, key=lambda e: e['time'])}
            for pid, entries in sorted(by_pid.items(), key=lambda kv: str(kv[0]))
        ]
        group['pids'].sort(key=str)
        group['times'].sort()
        group['reason'] = '; '.join(group['reasons'])
        result.append(group)

    result.sort(key=lambda g: (-_SEVERITY_ORDER.get(g['severity'], 0),
                               g['times'][0] if g['times'] else '',
                               g['command']))
    return result


# --------------------------------------------------------------------------
# Plugin bookkeeping: distinguishes "analysis failed" from "nothing found"
# --------------------------------------------------------------------------

STATUS_COMPLETED = 'completed'   # every plugin ran; zero findings really means zero findings
STATUS_PARTIAL = 'partial'       # some plugins failed; empty sections may mean "not analysed"
STATUS_ERROR = 'error'           # no plugin produced anything; the dump was NOT analysed

# Which report section depends on which plugins (a section counts as "not
# analysed" when its plugins were attempted and none of them succeeded).
SECTION_PLUGINS = {
    'processes': ('windows.pslist.PsList', 'linux.pslist.PsList'),
    'process_tree': ('linux.pstree.PsTree',),
    'hidden_processes': ('windows.psscan.PsScan',),
    'network': ('windows.netscan.NetScan', 'linux.sockstat.Sockstat'),
    'modules': ('windows.dlllist.DllList', 'linux.lsmod.Lsmod'),
    'commands': ('windows.cmdline.CmdLine', 'windows.cmdscan.CmdScan',
                 'windows.consoles.Consoles', 'linux.bash.Bash'),
}

# Fragments of Volatility errors that mean "this dump does not match the
# selected OS / the required symbol table or layer could not be built".
_MISMATCH_MARKERS = ('UnsatisfiedException', 'Unsatisfied', 'Symbol table',
                     'Unknown symbol', 'init_task', 'layer requirement',
                     'translation layer')


def _verbose_hint(memory_file):
    """-v/-vv belong to the main command, so they go BEFORE the "memory" subcommand."""
    target = shlex.quote(memory_file) if memory_file else "<file>"
    return f"For more details run: main.py -vv memory {target}"


def record_plugin_ok(results, plugin):
    """Remember that a plugin ran to completion (even if it returned no rows)."""
    results.setdefault('plugin_status', {})[plugin] = 'ok'


def record_plugin_skipped(results, plugin):
    """Remember that a plugin does not apply to this dump (expected, not an error)."""
    results.setdefault('plugin_status', {})[plugin] = 'skipped'


def record_plugin_error(results, plugin, exc):
    """Remember that a plugin failed and keep the reason for the report."""
    results.setdefault('plugin_status', {})[plugin] = 'failed'
    results.setdefault('plugin_errors', []).append({
        'plugin': plugin,
        'error': f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__,
    })


def sections_not_analysed(results):
    """Report sections whose plugins all failed (so empty means "unknown")."""
    status = results.get('plugin_status', {})
    missing = []
    for section, names in SECTION_PLUGINS.items():
        states = [status[name] for name in names if name in status]
        if 'failed' in states and 'ok' not in states:
            missing.append(section)
    return missing


def assess_analysis(results, os_forced=False, memory_file=None):
    """Decide whether the analysis completed, was partial or failed.

    "completed" is only returned when every plugin that was attempted
    succeeded; a run where Volatility could not analyse the dump at all
    (e.g. UnsatisfiedException after forcing the wrong --os-type) is
    "error", never "completed" with empty results.

    Sets status, status_message, next_step, plugin_summary,
    sections_not_analysed and, when it looks like a wrong OS or missing
    symbols, os_mismatch_warning.
    """
    status_map = results.get('plugin_status', {})
    succeeded = [n for n, s in status_map.items() if s == 'ok']
    failed = [n for n, s in status_map.items() if s == 'failed']
    skipped = [n for n, s in status_map.items() if s == 'skipped']
    attempted = len(succeeded) + len(failed)

    results['plugin_summary'] = {
        'attempted': attempted,
        'succeeded': len(succeeded),
        'failed': len(failed),
        'skipped': len(skipped),
    }
    results['sections_not_analysed'] = sections_not_analysed(results)
    results['os_forced'] = bool(os_forced)

    verbose_hint = _verbose_hint(memory_file)
    os_type = results.get('os_type', 'unknown')
    other_os = 'windows' if os_type == 'linux' else 'linux'

    if attempted == 0 or not succeeded:
        results['status'] = STATUS_ERROR
        results['status_message'] = (
            f"Analysis FAILED: none of the {attempted} Volatility plugins could run on "
            f"this dump as {os_type.upper()}. The dump was not analysed, so this is NOT "
            "a clean result - nothing can be concluded about suspicious activity."
        )
        errors = ' '.join(e.get('error', '') for e in results.get('plugin_errors', []))
        if any(marker in errors for marker in _MISMATCH_MARKERS):
            forced = " (forced with --os-type)" if os_forced else ""
            results['os_mismatch_warning'] = (
                f"The dump was analysed as {os_type.upper()}{forced}, but Volatility could "
                f"not build a matching layer/symbol table. Either this is not a "
                f"{os_type.upper()} dump, or the required symbols are missing"
                + (" (Linux dumps need a kernel symbol file for the exact kernel version)."
                   if os_type == 'linux' else ".")
            )
            if os_forced:
                results['next_step'] = (
                    "Re-run without --os-type to use auto-detection, or try "
                    f"--os-type {other_os}. " + verbose_hint
                )
            else:
                results['next_step'] = (
                    f"Try --os-type {other_os}, and check that the symbol tables for "
                    "this OS/kernel are installed. " + verbose_hint
                )
        else:
            results['next_step'] = (
                "Check plugin_errors for the cause before relying on this result. "
                + verbose_hint
            )
    elif failed:
        results['status'] = STATUS_PARTIAL
        results['status_message'] = (
            f"Analysis INCOMPLETE: {len(failed)} of {attempted} plugins failed "
            f"({', '.join(failed)}). Empty sections that depend on them were not "
            "analysed - they do NOT mean that nothing was found."
        )
        results['next_step'] = (
            "Review plugin_errors and fix the cause (symbols, OS type) before "
            "drawing conclusions from the empty sections. " + verbose_hint
        )
    else:
        results['status'] = STATUS_COMPLETED
        results['status_message'] = (
            f"All {attempted} plugins ran successfully. A section with zero findings "
            "means the checks ran and nothing matched."
        )
    return results


try:
    import volatility3
    import volatility3.plugins
    from volatility3 import framework
    from volatility3.framework import contexts, automagic, plugins, constants
    
    # Configure Volatility logging to reduce duplicate warnings
    vol_logger = logging.getLogger('volatility3')
    vol_logger.setLevel(logging.ERROR) 
    
    VOLATILITY_AVAILABLE = True
except ImportError:
    logger.warning("Volatility 3 not installed. Memory analysis will be unavailable until you run: pip install volatility3")
    VOLATILITY_AVAILABLE = False


def clean_value(value):
    """Convert Volatility special objects to JSON-serializable values."""
    if value is None:
        return None
    
    value_type = type(value).__name__
    if 'NotApplicableValue' in value_type or 'NotAvailableValue' in value_type:
        return None
    
    if isinstance(value, bytes):
        return value.decode('utf-8', errors='ignore')
    
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError):
        return str(value)


def setup_volatility_context(memory_file):
    """Setup Volatility 3 context for analysis.
    
    Args:
        memory_file: Path to memory dump file
        
    Returns:
        tuple: (context, automagics) or (None, None) on error
    """
    try:
        # Initialize Volatility
        constants.PARALLELISM = constants.Parallelism.Off
        
        ctx = contexts.Context()
        framework.require_interface_version(2, 0, 0)

        # The CLI imports all plugins before selecting stackers.  Do the same
        # here so LiME files receive the LimeLayer before Linux detection runs.
        framework.import_files(volatility3.plugins, True)
        
        automagics = automagic.available(ctx)
        
        # Set the memory file location
        abs_path = os.path.abspath(memory_file)
        single_location = Path(abs_path).as_uri()
        
        ctx.config['automagic.LayerStacker.single_location'] = single_location
        
        logger.info(f"Volatility context initialized for: {memory_file}")
        logger.debug(f"Using location: {single_location}")
        return ctx, automagics
        
    except Exception as e:
        logger.error(f"Failed to setup Volatility context: {type(e).__name__}: {e}")
        logger.debug(traceback.format_exc())
        return None, None


def run_volatility_plugin(ctx, automagics, plugin_class):
    """Run a Volatility plugin and return results.
    
    Args:
        ctx: Volatility context
        automagics: Automagic objects
        plugin_class: Plugin class to run
        
    Returns:
        list: Plugin results as list of dictionaries
    """
    try:
        # Create plugin instance
        chosen_automagics = automagic.choose_automagic(automagics, plugin_class)
        plugin = plugins.construct_plugin(
            ctx, chosen_automagics, plugin_class, 'plugins',
            None, None
        )
        
        results = []
        treegrid = plugin.run()
        
        if hasattr(treegrid, '_generator'):
            for level, item in treegrid._generator:
                result_dict = {}
                for i, value in enumerate(item):
                    result_dict[f'col_{i}'] = clean_value(value)
                results.append(result_dict)
        
        logger.info(f"Plugin {plugin_class.__name__} completed: {len(results)} results")
        return results
        
    except Exception as e:
        logger.warning(f"Plugin {plugin_class.__name__} failed: {e}")
        return []


def detect_os_from_memory(memory_file):
    """Attempt to detect OS type from memory dump.
    
    Args:
        memory_file: Path to memory dump
        
    Returns:
        str: 'windows', 'linux', or 'unknown'
    """
    try:
        ctx, automagics = setup_volatility_context(memory_file)
        if not ctx:
            return 'unknown'
        
        # Check for Windows signatures
        try:
            from volatility3.plugins.windows import info
            chosen = automagic.choose_automagic(automagics, info.Info)
            plugin = plugins.construct_plugin(ctx, chosen, info.Info, 'plugins', None, None)
            treegrid = plugin.run()
            if hasattr(treegrid, '_generator'):
                try:
                    next(iter(treegrid._generator))
                    logger.info("Detected Windows memory dump")
                    return 'windows'
                except StopIteration:
                    pass
        except:
            pass
        
        # Check for Linux signatures
        try:
            from volatility3.plugins.linux import pslist
            chosen = automagic.choose_automagic(automagics, pslist.PsList)
            plugin = plugins.construct_plugin(ctx, chosen, pslist.PsList, 'plugins', None, None)
            treegrid = plugin.run()
            if hasattr(treegrid, '_generator'):
                try:
                    next(iter(treegrid._generator))
                    logger.info("Detected Linux memory dump")
                    return 'linux'
                except StopIteration:
                    pass
        except:
            pass
        
        logger.warning("Could not detect OS type from memory dump")
        return 'unknown'
        
    except Exception as e:
        logger.error(f"OS detection failed: {type(e).__name__}: {e}")
        logger.debug(traceback.format_exc())
        return 'unknown'


def _plugin_rows(ctx, automagics, plugin_class):
    """Run a Volatility plugin and yield each row as {column name: value}."""
    chosen = automagic.choose_automagic(automagics, plugin_class)
    plugin = plugins.construct_plugin(ctx, chosen, plugin_class, 'plugins', None, None)
    treegrid = plugin.run()
    column_names = [column.name for column in treegrid.columns]
    if hasattr(treegrid, '_generator'):
        for _, item in treegrid._generator:
            row = {}
            for index, value in enumerate(item):
                if index >= len(column_names):
                    break
                type_name = type(value).__name__
                if any(tag in type_name for tag in ('Unreadable', 'NotApplicable', 'NotAvailable')):
                    value = None
                row[column_names[index]] = clean_value(value)
            yield row


def extract_windows_commands(ctx, automagics, results):
    """Collect Windows command lines and console history, flag suspicious ones.

    Sources: windows.cmdline (command line of every process) and
    windows.cmdscan / windows.consoles (commands typed into a console; these
    two only support Windows 10 and newer and are skipped quietly otherwise).
    The console plugins report the console host PID (conhost.exe/csrss.exe),
    so the application (e.g. cmd.exe) is read from the history entry itself
    and console hosts are never flagged as suspicious processes.
    """
    from collections import Counter

    merged = {}  # (pid, process, command) -> [count, {sources}]
    skipped = []  # console plugins skipped because the Windows version is unsupported

    def merge(local, source):
        for key, count in local.items():
            entry = merged.setdefault(key, [0, set()])
            entry[0] = max(entry[0], count)
            entry[1].add(source)

    # Command line of every process
    try:
        from volatility3.plugins.windows import cmdline
        local = Counter()
        for row in _plugin_rows(ctx, automagics, cmdline.CmdLine):
            command = ' '.join(str(row.get('Args') or '').split())
            if command:
                local[(row.get('PID'), str(row.get('Process', '')), command)] += 1
        merge(local, 'cmdline')
        record_plugin_ok(results, 'windows.cmdline.CmdLine')
    except Exception as e:
        logger.debug(f"Windows command line extraction failed: {type(e).__name__}: {e}")
        logger.debug(traceback.format_exc())
        record_plugin_error(results, 'windows.cmdline.CmdLine', e)

    # Commands typed into a console
    from volatility3.plugins.windows import cmdscan, consoles
    for plugin_class, source in ((cmdscan.CmdScan, 'cmdscan'), (consoles.Consoles, 'consoles')):
        plugin_name = f"windows.{source}.{plugin_class.__name__}"
        try:
            # The plugins would otherwise re-open the registry hives to read
            # the console history size; those layers already exist in this
            # context ("Layer already exists"), so use the plugin defaults.
            ctx.config[f'plugins.{plugin_class.__name__}.no_registry'] = True
            local = Counter()
            application = {}
            for row in _plugin_rows(ctx, automagics, plugin_class):
                prop = str(row.get('Property') or '')
                key = (row.get('PID'), row.get('ConsoleInfo'))
                data = ' '.join(str(row.get('Data') or '').split())
                if prop.endswith('Application'):
                    application[key] = data
                elif '_Command_' in prop and data:
                    process = application.get(key) or str(row.get('Process', ''))
                    local[(row.get('PID'), process, data)] += 1
            merge(local, source)
            record_plugin_ok(results, plugin_name)
        except NotImplementedError as e:
            # The Volatility 3 console plugins only support Windows 10 and
            # newer. On older systems (e.g. Windows 7) this is expected and
            # not an error: those dumps simply have no console history here.
            logger.info(f"Windows {source} skipped (unsupported Windows version): {e}")
            skipped.append(source)
            record_plugin_skipped(results, plugin_name)
        except Exception as e:
            logger.debug(f"Windows {source} extraction failed: {type(e).__name__}: {e}")
            logger.debug(traceback.format_exc())
            record_plugin_error(results, plugin_name, e)

    if skipped:
        results.setdefault('notes', []).append(
            f"Console history ({'/'.join(skipped)}) is not available for this Windows "
            "version (Volatility supports Windows 10 and newer only); "
            "only process command lines were checked.")

    suspicious = []
    for (pid, process, command), (count, sources) in sorted(
            merged.items(), key=lambda kv: (str(kv[0][0]), kv[0][2])):
        source = ', '.join(sorted(sources))
        for _ in range(count):
            results['shell_history'].append({
                'pid': pid, 'process': process, 'time': None,
                'command': command, 'source': source,
            })
            for finding in analyze_shell_command(command, WINDOWS_COMMAND_RULES):
                suspicious.append({
                    'type': 'command', 'pid': pid, 'process': process, 'time': None,
                    'command': command, 'source': f"{source} ({process})",
                    'reason': finding['reason'], 'severity': finding['severity'],
                })
                if 'cmdline' in sources:
                    flag_suspicious_process(results, pid, finding['reason'])

    results['suspicious_commands'] = group_suspicious_commands(suspicious)
    results['suspicious_command_records'] = sum(
        finding['records'] for finding in results['suspicious_commands'])
    results['suspicious_items'].extend(results['suspicious_commands'])
    logger.info(f"Found {len(results['shell_history'])} Windows commands, "
                f"{len(results['suspicious_commands'])} suspicious")


def extract_windows_hidden_processes(ctx, automagics, results):
    """Find processes that psscan sees but pslist does not.

    pslist walks the live process list, so terminated processes (a ransomware
    helper that already exited) and processes unlinked by a rootkit are
    missing from it; psscan scans memory for process structures instead.
    """
    from volatility3.plugins.windows import psscan

    known = {(p['pid'], p['name']) for p in results['processes']}
    hidden = []
    for row in _plugin_rows(ctx, automagics, psscan.PsScan):
        pid, name = row.get('PID'), str(row.get('ImageFileName') or '')
        if (pid, name) in known:
            continue
        hidden.append({
            'pid': pid,
            'ppid': row.get('PPID'),
            'name': name,
            'threads': row.get('Threads'),
            'handles': row.get('Handles'),
            'created': str(row.get('CreateTime') or ''),
            'exited': str(row.get('ExitTime') or ''),
        })
    hidden.sort(key=lambda p: p['created'])
    results['hidden_processes'] = hidden
    logger.info(f"Found {len(hidden)} processes only visible to psscan")


def _is_lookalike(name, target):
    """True if name differs from target by one edit or one adjacent swap."""
    if name == target:
        return False
    if len(name) == len(target):
        diffs = [i for i in range(len(name)) if name[i] != target[i]]
        if len(diffs) == 1:
            return True
        return (len(diffs) == 2 and diffs[1] == diffs[0] + 1
                and name[diffs[0]] == target[diffs[1]] and name[diffs[1]] == target[diffs[0]])
    if abs(len(name) - len(target)) == 1:
        longer, shorter = (name, target) if len(name) > len(target) else (target, name)
        return any(longer[:i] + longer[i + 1:] == shorter for i in range(len(longer)))
    return False


def _executable_path(command):
    """Return the executable path at the start of a command line, or ''."""
    lowered = command.lower()
    end = lowered.find('.exe')
    if end == -1:
        return ''
    return command[:end + 4].strip(' "')


def flag_suspicious_process_behavior(results):
    """Flag Windows processes by behaviour instead of by known names.

    Checks the usual "know normal, find evil" anomalies: system processes with
    the wrong parent, duplicated singleton processes, look-alike names,
    system binaries running outside System32, processes unlinked from the
    process list, Office/PDF apps starting script hosts, programs running
    from user-writable folders and the children those programs start.
    """
    running = results['processes']
    hidden = results.get('hidden_processes', [])
    everything = running + hidden
    by_pid = {}
    for proc in everything:
        by_pid.setdefault(proc['pid'], proc)
    lower = lambda proc: str(proc.get('name', '')).lower()

    # Command line per PID (only the cmdline plugin reports the real process)
    cmdlines = {}
    for entry in results.get('shell_history', []):
        if 'cmdline' in str(entry.get('source', '')):
            cmdlines[entry['pid']] = entry['command']

    # Processes unlinked from the process list but never exited
    for proc in hidden:
        if not proc.get('exited'):
            flag_suspicious_process(results, proc['pid'], 'Hidden from process list (no exit time)')

    counts = {}
    for proc in running:
        counts[lower(proc)] = counts.get(lower(proc), 0) + 1

    for proc in everything:
        name = lower(proc)
        base = name[:-4] if name.endswith('.exe') else name
        parent = by_pid.get(proc.get('ppid'))
        parent_name = lower(parent) if parent else None

        # System process started by the wrong parent (only when the parent is known)
        expected = EXPECTED_PARENTS.get(name)
        if expected and parent_name and parent_name not in expected:
            flag_suspicious_process(
                results, proc['pid'],
                f"Unexpected parent {parent.get('name')} for {proc.get('name')}")

        if name in SINGLETON_PROCESSES and counts.get(name, 0) > 1 and proc in running:
            flag_suspicious_process(results, proc['pid'], f"Duplicate {proc.get('name')} process")

        # Look-alike of a system process name
        if len(base) >= 5 and base not in LOOKALIKE_TARGETS:
            for target in LOOKALIKE_TARGETS:
                if _is_lookalike(base, target):
                    flag_suspicious_process(
                        results, proc['pid'], f"Name resembles system process {target}.exe")
                    break

        # Office/PDF reader starting a shell or script host
        if parent_name in DOCUMENT_APPS and name in SCRIPT_HOSTS:
            flag_suspicious_process(
                results, proc['pid'], f"{proc.get('name')} started by {parent.get('name')}")

        command = cmdlines.get(proc['pid'])
        if command:
            if name in SYSTEM_BINARIES:
                path = _executable_path(command)
                normalized = path.lower().replace('%systemroot%', 'c:\\windows').replace('\\systemroot', 'c:\\windows')
                if '\\' in path and not SYSTEM_PATH_RE.match(normalized):
                    flag_suspicious_process(
                        results, proc['pid'], f"{proc.get('name')} runs outside System32: {path}")
                if name == 'svchost.exe' and ' -k' not in command.lower():
                    flag_suspicious_process(results, proc['pid'], 'svchost.exe without -k argument')

            # Program in a user-writable folder, and what it started
            if USER_WRITABLE_PATH_RE.match(command):
                for child in everything:
                    if child.get('ppid') == proc['pid'] and child['pid'] != proc['pid']:
                        flag_suspicious_process(
                            results, child['pid'],
                            f"Child of {proc.get('name')}, which runs from a user-writable folder")


def analyze_windows_memory(memory_file):
    """Analyze Windows memory dump.
    
    Args:
        memory_file: Path to Windows memory dump
        
    Returns:
        dict: Analysis results
    """
    from collections import defaultdict
    
    results = {
        'os_type': 'windows',
        'hostname': None,
        'logged_in_users': [],
        'processes': [],
        'network_connections': [],
        'network_statistics': {
            'total_connections': 0,
            'established_connections': 0,
            'listening_ports': 0,
            'ip_frequency': {},
            'port_frequency': {},
            'top_remote_ips': [],
            'top_local_ports': []
        },
        'suspicious_processes': [],
        'suspicious_items': [], 
        'suspicious_commands': [],
        'shell_history': [],
        'plugin_errors': [],
        'notes': [],
        'loaded_modules': []
    }
    
    ctx, automagics = setup_volatility_context(memory_file)
    if not ctx:
        return {'error': 'Failed to initialize Volatility context'}
    
    try:
        # Extract system info (hostname, OS version)
        logger.info("Extracting system information...")
        from volatility3.plugins.windows import info
        chosen = automagic.choose_automagic(automagics, info.Info)
        plugin = plugins.construct_plugin(ctx, chosen, info.Info, 'plugins', None, None)
        treegrid = plugin.run()
        
        if hasattr(treegrid, '_generator'):
            for _, item in treegrid._generator:
                if len(item) >= 2:
                    key = str(clean_value(item[0])) if item[0] else ''
                    value = str(clean_value(item[1])) if item[1] else ''
                    
                    if 'computername' in key.lower() or 'hostname' in key.lower():
                        results['hostname'] = value
                        logger.info(f"Found hostname: {value}")
        
    except Exception as e:
        logger.debug(f"System info extraction failed: {type(e).__name__}: {e}")
        record_plugin_error(results, 'windows.info.Info', e)
    else:
        record_plugin_ok(results, 'windows.info.Info')
    
    try:
        # Extract logged-in users (Windows Sessions)
        logger.info("Extracting user sessions...")
        from volatility3.plugins.windows import sessions
        import re
        
        plugin = plugins.construct_plugin(ctx, automagic.choose_automagic(automagics, sessions.Sessions), sessions.Sessions, 'plugins', None, None)
        treegrid = plugin.run()
        
        user_set = set()
        if hasattr(treegrid, '_generator'):
            for _, item in treegrid._generator:
                if len(item) > 0:
                    for field in item:
                        field_str = str(clean_value(field))
                        
                        # Skip empty, None, or null values
                        if not field_str or field_str in ['None', 'N/A', '', 'null']:
                            continue
                        
                        # Skip hex addresses (start with 0x)
                        if field_str.startswith('0x'):
                            continue
                        
                        # Skip pure numbers (PIDs, etc.)
                        if field_str.isdigit():
                            continue
                        
                        # Skip timestamps (contains date/time patterns)
                        if re.match(r'\d{4}-\d{2}-\d{2}', field_str):  # ISO date format
                            continue
                        
                        # Skip process names (ends with .exe, .ex, or has period at end)
                        if field_str.endswith('.exe') or field_str.endswith('.ex') or field_str.endswith('.'):
                            continue
                        
                        # Skip strings that look like truncated process names
                        # e.g., SearchFilterHo, VGAuthService
                        if re.search(r'[a-z][A-Z]', field_str): 
                            continue
                        
                        # Accept only valid username patterns:
                        # 1. DOMAIN\username format (e.g., NT AUTHORITY\LOCAL SERVICE)
                        # 2. MACHINE/user format (e.g., WIN-PC/hacker)
                        # 3. Well-known system accounts: System, Console
                        # 4. Simple usernames starting with letter
                        
                        if '\\' in field_str:
                            # DOMAIN\username format - validate it has letters and spaces/uppercase
                            if re.search(r'[a-zA-Z]', field_str):
                                user_set.add(field_str)
                        elif '/' in field_str and re.search(r'[a-zA-Z]', field_str):
                            # WORKGROUP/MACHINE$ or MACHINE/username format
                            user_set.add(field_str)
                        elif field_str in ['System', 'Console']:
                            # Well-known system accounts
                            user_set.add(field_str)
                        elif re.match(r'^[a-zA-Z][a-zA-Z0-9_\-@]+$', field_str) and len(field_str) <= 30:
                            # Simple username: starts with letter, alphanumeric + _ - @, no periods
                            # Reduced length to 30 to avoid service names
                            user_set.add(field_str)
        
        results['logged_in_users'] = sorted(list(user_set))
        if results['logged_in_users']:
            logger.info(f"Found {len(results['logged_in_users'])} logged-in users")
        
    except Exception as e:
        logger.debug(f"User session extraction failed: {type(e).__name__}: {e}")
        record_plugin_error(results, 'windows.sessions.Sessions', e)
    else:
        record_plugin_ok(results, 'windows.sessions.Sessions')
    
    try:
        # Process list
        logger.info("Extracting process list...")
        from volatility3.plugins.windows import pslist
        chosen = automagic.choose_automagic(automagics, pslist.PsList)
        plugin = plugins.construct_plugin(ctx, chosen, pslist.PsList, 'plugins', None, None)
        treegrid = plugin.run()
        
        # Get column names from TreeGrid
        column_names = [col.name for col in treegrid.columns]
        logger.debug(f"PsList columns: {column_names}")
        
        if hasattr(treegrid, '_generator'):
            for _, item in treegrid._generator:
                # Map columns by name instead of hardcoded indices
                row_dict = {}
                for i, col_name in enumerate(column_names):
                    if i < len(item):
                        row_dict[col_name] = clean_value(item[i])
                
                # Extract process info using column names
                process_info = {
                    'pid': row_dict.get('PID', 0),
                    'ppid': row_dict.get('PPID', 0),
                    'name': str(row_dict.get('ImageFileName', 'Unknown')),
                    'threads': row_dict.get('Threads', 0),
                    'handles': row_dict.get('Handles', 0)
                }
                results['processes'].append(process_info)
                
                # Flag suspicious processes
                name_lower = process_info['name'].lower() if process_info['name'] else ''
                if any(sus in name_lower for sus in ['cmd.exe', 'powershell', 'wscript', 'mshta', 'nc.exe', 'mimikatz']):
                    flag_suspicious_process(results, process_info['pid'], 'Suspicious process name')
        
        logger.info(f"Found {len(results['processes'])} processes")
        
    except Exception as e:
        error_msg = f"{type(e).__name__}: {e}"
        logger.debug(f"Process list extraction failed: {error_msg}")
        logger.debug(traceback.format_exc())
        record_plugin_error(results, 'windows.pslist.PsList', e)
    else:
        record_plugin_ok(results, 'windows.pslist.PsList')
    
    try:
        # Network connections
        logger.info("Extracting network connections...")
        from volatility3.plugins.windows import netscan
        from collections import defaultdict
        
        plugin = plugins.construct_plugin(ctx, automagic.choose_automagic(automagics, netscan.NetScan), netscan.NetScan, 'plugins', None, None)
        treegrid = plugin.run()
        
        suspicious_pids = set() 
        ip_freq = defaultdict(int)
        port_freq = defaultdict(int)
        established_count = 0
        listening_count = 0
        
        if hasattr(treegrid, '_generator'):
            for level, item in treegrid._generator:
                # NetScan columns: Offset, Proto, LocalAddr, LocalPort, ForeignAddr, ForeignPort, State, PID, Owner, Created
                conn_info = {
                    'protocol': str(clean_value(item[1])) if len(item) > 1 else 'Unknown',
                    'local_addr': str(clean_value(item[2])) if len(item) > 2 else '',
                    'local_port': clean_value(item[3]) if len(item) > 3 else 0,
                    'foreign_addr': str(clean_value(item[4])) if len(item) > 4 else '',
                    'foreign_port': clean_value(item[5]) if len(item) > 5 else 0,
                    'state': str(clean_value(item[6])) if len(item) > 6 else '',
                    'pid': clean_value(item[7]) if len(item) > 7 else 0,
                    'owner': str(clean_value(item[8])) if len(item) > 8 else ''
                }
                results['network_connections'].append(conn_info)
                
                # Track statistics
                state = conn_info['state'].upper() if conn_info['state'] else ''
                if 'ESTABLISHED' in state:
                    established_count += 1
                elif 'LISTENING' in state or 'LISTEN' in state:
                    listening_count += 1
                
                # Count IP addresses (remote)
                foreign_addr = conn_info['foreign_addr']
                if foreign_addr and foreign_addr not in ['', '0.0.0.0', '*', '::', '-', 'None', '0', 'N/A']:
                    ip_freq[foreign_addr] += 1
                
                # Count ports (local listening ports and remote ports)
                local_port = conn_info['local_port']
                if local_port and local_port > 0:
                    if 'LISTENING' in state or 'LISTEN' in state:
                        port_freq[local_port] += 1
                
                foreign_port = conn_info['foreign_port']
                if foreign_port and foreign_port > 0:
                    port_freq[foreign_port] += 1
                
                # Flag suspicious connections and track their PIDs
                if (foreign_addr not in ['', '0.0.0.0', '*', '::', '-', 'None']
                        and not _is_loopback(foreign_addr) and foreign_port):
                    # Flag connections to unusual ports (not common HTTP, HTTPS, DNS, etc.)
                    if foreign_port not in [80, 443, 53, 8080, 8443]:
                        suspicious_pids.add(conn_info['pid'])
                        results['suspicious_items'].append({
                            'type': 'network',
                            'pid': conn_info['pid'],
                            'remote': f"{foreign_addr}:{foreign_port}",
                            'reason': 'Unusual port connection'
                        })
        
        # Compile network statistics
        results['network_statistics']['total_connections'] = len(results['network_connections'])
        results['network_statistics']['established_connections'] = established_count
        results['network_statistics']['listening_ports'] = listening_count
        
        # Convert defaultdicts to regular dicts and get top IPs/ports
        results['network_statistics']['ip_frequency'] = dict(ip_freq)
        results['network_statistics']['port_frequency'] = dict(port_freq)
        
        # Top 10 remote IPs
        sorted_ips = sorted(ip_freq.items(), key=lambda x: x[1], reverse=True)[:10]
        results['network_statistics']['top_remote_ips'] = [
            {'ip': ip, 'connection_count': count} for ip, count in sorted_ips
        ]
        
        # Top 10 ports
        sorted_ports = sorted(port_freq.items(), key=lambda x: x[1], reverse=True)[:10]
        results['network_statistics']['top_local_ports'] = [
            {'port': port, 'usage_count': count} for port, count in sorted_ports
        ]
        
        # Flag processes with suspicious network activity
        for pid in sorted(suspicious_pids, key=str):
            flag_suspicious_process(results, pid, 'Unusual port connection')
        
        logger.info(f"Found {len(results['network_connections'])} network connections")
        logger.info(f"Network stats: {established_count} established, {listening_count} listening")
        logger.info(f"Unique IPs: {len(ip_freq)}, Unique ports: {len(port_freq)}")
        logger.info(f"Flagged {len(suspicious_pids)} PIDs with suspicious network activity")
        
    except Exception as e:
        logger.debug(f"Network extraction failed: {type(e).__name__}: {e}")
        logger.debug(traceback.format_exc())
        record_plugin_error(results, 'windows.netscan.NetScan', e)
    else:
        record_plugin_ok(results, 'windows.netscan.NetScan')
    
    try:
        # Loaded modules/DLLs (limited to first 50 for performance)
        logger.info("Extracting loaded modules...")
        from volatility3.plugins.windows import dlllist
        plugin = plugins.construct_plugin(ctx, automagic.choose_automagic(automagics, dlllist.DllList), dlllist.DllList, 'plugins', None, None)
        treegrid = plugin.run()
        
        count = 0
        if hasattr(treegrid, '_generator'):
            for level, item in treegrid._generator:
                if count >= 50:  # Limit results
                    break
                # DllList columns: PID, Process, Base, Size, Name, Path, LoadTime, File output
                module_info = {
                    'pid': clean_value(item[0]) if len(item) > 0 else 0,
                    'process': str(clean_value(item[1])) if len(item) > 1 else '',
                    'base': hex(clean_value(item[2])) if len(item) > 2 and clean_value(item[2]) else '0x0',
                    'size': clean_value(item[3]) if len(item) > 3 else 0,
                    'name': str(clean_value(item[4])) if len(item) > 4 else '',
                    'path': str(clean_value(item[5])) if len(item) > 5 else ''
                }
                results['loaded_modules'].append(module_info)
                count += 1
        
        logger.info(f"Found {len(results['loaded_modules'])} loaded modules")
        
    except Exception as e:
        logger.debug(f"Module extraction failed: {type(e).__name__}: {e}")
        logger.debug(traceback.format_exc())
        record_plugin_error(results, 'windows.dlllist.DllList', e)
    else:
        record_plugin_ok(results, 'windows.dlllist.DllList')

    try:
        logger.info("Running psscan...")
        extract_windows_hidden_processes(ctx, automagics, results)
    except Exception as e:
        error_msg = f"{type(e).__name__}: {e}"
        logger.debug(f"Windows psscan failed: {error_msg}")
        logger.debug(traceback.format_exc())
        record_plugin_error(results, 'windows.psscan.PsScan', e)
    else:
        record_plugin_ok(results, 'windows.psscan.PsScan')

    try:
        logger.info("Extracting Windows command history...")
        extract_windows_commands(ctx, automagics, results)
    except Exception as e:
        error_msg = f"{type(e).__name__}: {e}"
        logger.debug(f"Windows command extraction failed: {error_msg}")
        logger.debug(traceback.format_exc())
        # Individual console/cmdline plugins record themselves; this is an
        # unexpected failure of the whole command-extraction step.
        record_plugin_error(results, 'windows.commands', e)

    flag_suspicious_process_behavior(results)
    return results


def _is_loopback(address):
    """True for the machine's own address (127.0.0.0/8, ::1); such traffic never leaves the host."""
    address = str(address)
    return address.startswith('127.') or address == '::1'


def flag_suspicious_process(results, pid, reason):
    """Add a process to results['suspicious_processes'] (once) and record why.

    A process can be suspicious for several reasons (name, network, command
    history), so reasons are collected on one entry per PID instead of
    adding the process several times.
    """
    for flagged in results['suspicious_processes']:
        if flagged['pid'] == pid:
            reasons = flagged.setdefault('reasons', [])
            if reason not in reasons:
                reasons.append(reason)
            return
    for proc in results['processes']:
        if proc['pid'] == pid:
            results['suspicious_processes'].append(dict(proc, reasons=[reason]))
            return
    for proc in results.get('hidden_processes', []):
        if proc['pid'] == pid:
            reasons = [reason]
            if proc.get('exited'):
                reasons.append('Not in process list (exited)')
            results['suspicious_processes'].append(dict(proc, reasons=reasons))
            return


def analyze_linux_memory(memory_file):
    """Analyze Linux memory dump.
    
    Args:
        memory_file: Path to Linux memory dump
        
    Returns:
        dict: Analysis results
    """
    results = {
        'os_type': 'linux',
        'processes': [],
        'process_tree': [],
        'network_connections': [],
        'network_statistics': {
            'total_connections': 0,
            'established_connections': 0,
            'listening_ports': 0,
            'ip_frequency': {},
            'port_frequency': {},
            'top_remote_ips': [],
            'top_local_ports': []
        },
        'suspicious_processes': [],
        'suspicious_items': [],
        'suspicious_commands': [],
        'kernel_modules': [],
        'shell_history': [],
        'plugin_errors': []
    }
    
    ctx, automagics = setup_volatility_context(memory_file)
    if not ctx:
        return {'error': 'Failed to initialize Volatility context'}
    
    try:
        # Process list
        logger.info("Extracting Linux process list...")
        from volatility3.plugins.linux import pslist
        chosen = automagic.choose_automagic(automagics, pslist.PsList)
        plugin = plugins.construct_plugin(ctx, chosen, pslist.PsList, 'plugins', None, None)
        treegrid = plugin.run()
        
        column_names = [column.name for column in treegrid.columns]

        if hasattr(treegrid, '_generator'):
            for _, item in treegrid._generator:
                # linux.pslist columns: OFFSET, PID, TID, PPID, COMM, ...
                # Look values up by column name; positional indexes shift
                # whenever the plugin adds a column (e.g. TID), which put
                # TID into PPID and PPID into the name column.
                row = {
                    column_names[index]: clean_value(value)
                    for index, value in enumerate(item)
                    if index < len(column_names)
                }
                process_info = {
                    'pid': row.get('PID', 0),
                    'ppid': row.get('PPID', 0),
                    'name': str(row.get('COMM', 'Unknown'))
                }
                results['processes'].append(process_info)

                # Flag suspicious processes (exact names, not substrings)
                if process_info['name'].lower() in SUSPICIOUS_PROCESS_NAMES:
                    flag_suspicious_process(results, process_info['pid'], 'Suspicious process name')

        logger.info(f"Found {len(results['processes'])} processes")
        
    except Exception as e:
        error_msg = f"{type(e).__name__}: {e}"
        logger.debug(f"Linux process list extraction failed: {error_msg}")
        logger.debug(traceback.format_exc())
        record_plugin_error(results, 'linux.pslist.PsList', e)
    else:
        record_plugin_ok(results, 'linux.pslist.PsList')

    try:
        # Process hierarchy
        logger.info("Extracting Linux process tree...")
        from volatility3.plugins.linux import pstree

        chosen = automagic.choose_automagic(automagics, pstree.PsTree)
        plugin = plugins.construct_plugin(
            ctx, chosen, pstree.PsTree, 'plugins', None, None
        )
        treegrid = plugin.run()
        column_names = [column.name for column in treegrid.columns]

        if hasattr(treegrid, '_generator'):
            for level, item in treegrid._generator:
                row = {
                    column_names[index]: clean_value(value)
                    for index, value in enumerate(item)
                    if index < len(column_names)
                }
                results['process_tree'].append({
                    'level': level,
                    'pid': row.get('PID', 0),
                    'tid': row.get('TID', 0),
                    'ppid': row.get('PPID', 0),
                    'name': str(row.get('COMM', 'Unknown'))
                })

    except Exception as e:
        error_msg = f"{type(e).__name__}: {e}"
        logger.debug(f"Linux process tree extraction failed: {error_msg}")
        logger.debug(traceback.format_exc())
        record_plugin_error(results, 'linux.pstree.PsTree', e)
    else:
        record_plugin_ok(results, 'linux.pstree.PsTree')

    try:
        # Network sockets
        logger.info("Extracting Linux network sockets...")
        from collections import Counter
        from volatility3.plugins.linux import sockstat

        chosen = automagic.choose_automagic(automagics, sockstat.Sockstat)
        plugin = plugins.construct_plugin(
            ctx, chosen, sockstat.Sockstat, 'plugins', None, None
        )
        treegrid = plugin.run()
        column_names = [column.name for column in treegrid.columns]
        remote_ips = Counter()
        local_ports = Counter()

        if hasattr(treegrid, '_generator'):
            for _, item in treegrid._generator:
                row = {
                    column_names[index]: clean_value(value)
                    for index, value in enumerate(item)
                    if index < len(column_names)
                }
                connection = {
                    'family': str(row.get('Family', '') or ''),
                    'type': str(row.get('Type', '') or ''),
                    'protocol': str(row.get('Proto', 'Unknown')),
                    'local_addr': str(row.get('Source Addr', '')),
                    'local_port': row.get('Source Port', ''),
                    'foreign_addr': str(row.get('Destination Addr', '')),
                    'foreign_port': row.get('Destination Port', ''),
                    'state': str(row.get('State', '')),
                    'pid': row.get('PID', 0),
                    'owner': str(row.get('Process Name', ''))
                }
                results['network_connections'].append(connection)

                # Flag established TCP connections to remote hosts on unusual ports
                if (connection['family'].upper() in ('AF_INET', 'AF_INET6')
                        and connection['protocol'].upper() == 'TCP'
                        and connection['state'].upper() == 'ESTABLISHED'
                        and connection['foreign_addr'] not in ('', 'None', '0.0.0.0', '::')
                        and not _is_loopback(connection['foreign_addr'])
                        and connection['foreign_port'] not in (80, 443, 53, 8080, 8443)):
                    remote = f"{connection['foreign_addr']}:{connection['foreign_port']}"
                    flag_suspicious_process(
                        results, connection['pid'], f'Unusual port connection to {remote}')
                    results['suspicious_items'].append({
                        'type': 'network',
                        'pid': connection['pid'],
                        'remote': remote,
                        'reason': 'Unusual port connection'
                    })

                state = connection['state'].upper()
                if state == 'ESTABLISHED':
                    results['network_statistics']['established_connections'] += 1
                if state in ('LISTEN', 'LISTENING'):
                    results['network_statistics']['listening_ports'] += 1
                # Count only TCP/UDP endpoints; unix/netlink "addresses" are
                # socket paths and inode numbers, not IPs and ports.
                if connection['family'].upper() in ('AF_INET', 'AF_INET6'):
                    if connection['foreign_addr'] not in ('', 'None', '0.0.0.0', '::'):
                        remote_ips[connection['foreign_addr']] += 1
                    if connection['local_port'] not in ('', None, 'None'):
                        local_ports[str(connection['local_port'])] += 1

        results['network_statistics']['total_connections'] = len(
            results['network_connections']
        )
        results['network_statistics']['ip_frequency'] = dict(remote_ips)
        results['network_statistics']['port_frequency'] = dict(local_ports)
        results['network_statistics']['top_remote_ips'] = [
            {'ip': ip, 'count': count}
            for ip, count in remote_ips.most_common(10)
        ]
        results['network_statistics']['top_local_ports'] = [
            {'port': port, 'count': count}
            for port, count in local_ports.most_common(10)
        ]

    except Exception as e:
        error_msg = f"{type(e).__name__}: {e}"
        logger.debug(f"Linux network socket extraction failed: {error_msg}")
        logger.debug(traceback.format_exc())
        record_plugin_error(results, 'linux.sockstat.Sockstat', e)
    else:
        record_plugin_ok(results, 'linux.sockstat.Sockstat')

    try:
        # Loaded kernel modules
        logger.info("Extracting Linux kernel modules...")
        from volatility3.plugins.linux import lsmod

        chosen = automagic.choose_automagic(automagics, lsmod.Lsmod)
        plugin = plugins.construct_plugin(
            ctx, chosen, lsmod.Lsmod, 'plugins', None, None
        )
        treegrid = plugin.run()
        column_names = [column.name for column in treegrid.columns]

        if hasattr(treegrid, '_generator'):
            for _, item in treegrid._generator:
                row = {
                    column_names[index]: clean_value(value)
                    for index, value in enumerate(item)
                    if index < len(column_names)
                }
                results['kernel_modules'].append({
                    'name': str(row.get('Module Name', '')),
                    'size': row.get('Code Size'),
                    'taints': row.get('Taints'),
                    'load_arguments': row.get('Load Arguments'),
                    'file': row.get('File Output')
                })

    except Exception as e:
        error_msg = f"{type(e).__name__}: {e}"
        logger.debug(f"Linux kernel module extraction failed: {error_msg}")
        logger.debug(traceback.format_exc())
        record_plugin_error(results, 'linux.lsmod.Lsmod', e)
    else:
        record_plugin_ok(results, 'linux.lsmod.Lsmod')

    try:
        # Bash command history
        logger.info("Extracting Linux shell history...")
        from volatility3.plugins.linux import bash

        chosen = automagic.choose_automagic(automagics, bash.Bash)
        plugin = plugins.construct_plugin(
            ctx, chosen, bash.Bash, 'plugins', None, None
        )
        treegrid = plugin.run()
        column_names = [column.name for column in treegrid.columns]

        if hasattr(treegrid, '_generator'):
            for _, item in treegrid._generator:
                row = {
                    column_names[index]: clean_value(value)
                    for index, value in enumerate(item)
                    if index < len(column_names)
                }
                results['shell_history'].append({
                    'pid': row.get('PID', 0),
                    'process': str(row.get('Process', '')),
                    'time': row.get('CommandTime'),
                    'command': str(row.get('Command', '')),
                })
                history_entry = results['shell_history'][-1]
                command_findings = analyze_shell_command(history_entry['command'])
                if command_findings:
                    history_entry['suspicious'] = True
                    history_entry['suspicious_reasons'] = [
                        finding['reason'] for finding in command_findings
                    ]
                    history_entry['severity'] = max(
                        command_findings,
                        key=lambda finding: (
                            {'critical': 3, 'high': 2, 'medium': 1}.get(
                                finding['severity'], 0
                            )
                        )
                    )['severity']
                    for finding in command_findings:
                        suspicious_command = {
                            'type': 'command',
                            'pid': history_entry['pid'],
                            'process': history_entry['process'],
                            'time': history_entry['time'],
                            'command': history_entry['command'],
                            'reason': finding['reason'],
                            'severity': finding['severity'],
                        }
                        results['suspicious_commands'].append(suspicious_command)
                        results['suspicious_items'].append(suspicious_command)

    except Exception as e:
        error_msg = f"{type(e).__name__}: {e}"
        logger.debug(f"Linux shell history extraction failed: {error_msg}")
        logger.debug(traceback.format_exc())
        record_plugin_error(results, 'linux.bash.Bash', e)
    else:
        record_plugin_ok(results, 'linux.bash.Bash')

    # Collapse duplicate history records into unique findings
    results['suspicious_commands'] = group_suspicious_commands(
        results['suspicious_commands']
    )
    results['suspicious_command_records'] = sum(
        finding['records'] for finding in results['suspicious_commands'])
    results['suspicious_items'] = [
        item for item in results['suspicious_items'] if item.get('type') != 'command'
    ] + results['suspicious_commands']

    # Shells whose history contains suspicious commands are suspicious processes
    for finding in results['suspicious_commands']:
        for pid in finding['pids']:
            flag_suspicious_process(results, pid, 'Suspicious command in history')
    
    return results


def analyze_memory_dump(memory_file, os_type=None):
    """Main function to analyze memory dump.
    
    Args:
        memory_file: Path to memory dump file
        os_type: OS type ('windows', 'linux', or None for auto-detect)
        
    Returns:
        dict: Comprehensive analysis results
    """
    if not VOLATILITY_AVAILABLE:
        return {'error': 'Volatility 3 is not installed. Run: pip install volatility3'}

    if not os.path.exists(memory_file):
        return {'error': f'Memory dump file not found: {memory_file}'}
    
    file_size = os.path.getsize(memory_file)
    logger.info(f"Analyzing memory dump: {memory_file} ({file_size / (1024**2):.2f} MB)")
    
    # Remember whether the user forced the OS (affects the failure advice)
    os_forced = bool(os_type)

    # Auto-detect OS if not specified
    if not os_type:
        os_type = detect_os_from_memory(memory_file)
    
    # Analyze based on OS type
    if os_type == 'windows':
        results = analyze_windows_memory(memory_file)
    elif os_type == 'linux':
        results = analyze_linux_memory(memory_file)
    else:
        return {
            'error': 'Could not determine OS type. Please specify with --os-type',
            'os_type': 'unknown'
        }
    
    # Decide completed / partial / error from what the plugins actually did
    if 'error' not in results:
        assess_analysis(results, os_forced=os_forced, memory_file=memory_file)

    # Add metadata
    results['file_path'] = memory_file
    results['file_size'] = file_size
    results['file_size_mb'] = round(file_size / (1024**2), 2)
    
    return results