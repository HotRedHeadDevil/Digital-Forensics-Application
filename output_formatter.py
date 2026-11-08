# output_formatter.py - Output formatting for various formats

import json
import csv
import io
from datetime import datetime


def _translate_windows_status_code(code):
    """Translate Windows security status codes to readable messages.
    
    Args:
        code: Status code string (e.g., '%%2310')
        
    Returns:
        str: Human-readable description
    """
    status_codes = {
        '%%2310': 'Account disabled',
        '%%2311': 'Account expired',
        '%%2312': 'Account locked out',
        '%%2313': 'Account restriction',
        '0xC000006D': 'Bad username or password',
        '0xC000006A': 'Wrong password',
        '0xC0000064': 'User does not exist',
        '0xC000006E': 'Account restriction',
        '0xC000006F': 'Invalid logon hours',
        '0xC0000070': 'Workstation restriction',
        '0xC0000071': 'Password expired',
        '0xC0000072': 'Account disabled',
        '0xC0000193': 'Account expired',
        '0xC0000234': 'Account locked out',
        '0xC0000371': 'Local account restriction',
        '0xC000015B': 'Logon type not granted'
    }
    
    # Return translated message if found, otherwise return original code
    text = str(code)
    if text.startswith('Status:'):
        text = text[len('Status:'):].strip()
    normalized = text.upper().replace('0X', '0x', 1) if text.lower().startswith('0x') else text
    normalized = '0x' + normalized[2:].upper() if normalized.startswith('0x') else normalized
    return status_codes.get(normalized, code)


def format_json(data):
    """Format data as JSON string.
    
    Args:
        data: Dictionary to format
        
    Returns:
        str: Formatted JSON string
    """
    return json.dumps(data, indent=4)


def format_csv(data):
    """Format data as CSV string.

    CSV export is inherently record-oriented, and the three analysis types
    this tool produces have very different shapes, so each gets its own
    exporter rather than forcing everything through one fixed schema.

    Args:
        data: Dictionary containing analysis results

    Returns:
        str: CSV formatted string
    """
    analysis_type = data.get('analysis_type')

    if analysis_type == 'memory_dump':
        return _format_csv_memory(data)

    if analysis_type in ('event_log', 'text_log'):
        return _format_csv_login_events(data)

    return _format_csv_disk_image(data, analysis_type)


def _format_csv_disk_image(data, analysis_type):
    """Format disk-image file/directory listing as CSV.

    Args:
        data: Dictionary containing disk-image analysis results
        analysis_type: The analysis_type value from data, used only to
            produce a clearer message if there's nothing to export

    Returns:
        str: CSV formatted string
    """
    if 'results' not in data or not data['results']:
        return (f"No results to export as CSV for analysis type "
                f"'{analysis_type or 'unknown'}'. Try --output json or --output table instead.")

    # Extract file/directory entries
    results = data['results']

    # Define CSV columns
    fieldnames = ['name', 'path', 'type', 'size', 'inode', 'm_time', 'a_time', 'c_time', 'e_time', 'yara_matches']

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
    writer.writeheader()
    
    for item in results:
        row = item.copy()
        # Convert yara_matches list to comma-separated string
        if 'yara_matches' in row:
            row['yara_matches'] = ', '.join(row['yara_matches'])
        writer.writerow(row)
    
    return output.getvalue()


def _format_csv_memory(data):
    """Format memory-dump process list as CSV.

    Network connections and loaded modules have a different shape (and
    much wider column set) than processes, so they're intentionally left
    out here - use --output json for those.

    Args:
        data: Dictionary containing memory-dump analysis results

    Returns:
        str: CSV formatted string
    """
    processes = data.get('processes', [])
    if not processes:
        return "No processes to export as CSV. Try --output json for full details (including network connections and loaded modules)."

    fieldnames = ['pid', 'ppid', 'name', 'threads', 'handles']

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
    writer.writeheader()

    for proc in processes:
        writer.writerow(proc)

    return output.getvalue()


def _format_csv_login_events(data):
    """Format login events from event_log/text_log analysis as a flat CSV.

    Successful and failed logins are combined into one table with a
    'status' column, since analysts usually want to sort/filter across
    both together (e.g. by IP or user).

    Args:
        data: Dictionary containing event_log or text_log analysis results

    Returns:
        str: CSV formatted string
    """
    login_events = data.get('login_events', {})
    details = login_events.get('details', {}) if isinstance(login_events, dict) else {}

    rows = []
    for event in details.get('successful_logins', []):
        row = dict(event)
        row['status'] = 'success'
        rows.append(row)
    for event in details.get('failed_logins', []):
        row = dict(event)
        row['status'] = 'failed'
        rows.append(row)

    if not rows:
        return "No login events to export as CSV. Try --output json for full details."

    fieldnames = ['status']
    for row in rows:
        for key in row:
            if key not in fieldnames:
                fieldnames.append(key)

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
    writer.writeheader()
    writer.writerows(rows)

    return output.getvalue()


_SEVERITY_RANK = {'critical': 3, 'high': 2, 'medium': 1, 'low': 0}


def _format_command_findings(findings):
    """Render suspicious commands, one block per unique command.

    Accepts both grouped findings (with pids/times/records) and raw
    per-record findings; raw ones are grouped here so duplicates never
    reach the output.
    """
    if findings and 'pids' not in findings[0]:
        from memory_analyzer import group_suspicious_commands
        findings = group_suspicious_commands(findings)

    total_records = sum(f.get('records', 1) for f in findings)
    lines = ["-" * 110,
             f"SUSPICIOUS COMMANDS ({len(findings)} unique, {total_records} records)",
             "-" * 110]

    for f in sorted(findings, key=lambda f: -_SEVERITY_RANK.get(f.get('severity'), 0)):
        lines.append(f"[{f.get('severity', 'unknown').upper()}] {f.get('command', '')}")
        reasons = f.get('reasons') or [f.get('reason', '')]
        for reason in reasons:
            lines.append(f"    Reason : {reason}")
        lines.append(f"    Records: {f.get('records', 1)}")
        if f.get('sources'):
            lines.append(f"    Source : {'; '.join(f['sources'])}")
        if f.get('by_pid'):
            for entry in f['by_pid']:
                parts = [f"{t['time']} ({t['count']}x)" if t['time'] else f"({t['count']}x)"
                         for t in entry['times']]
                lines.append(f"    PID {str(entry['pid']):<6}: " + parts[0])
                for part in parts[1:]:
                    lines.append(f"    {'':<10}  {part}")
        else:
            pids = ', '.join(str(p) for p in f.get('pids', [])) or '?'
            lines.append(f"    PIDs   : {pids}")
            for i, t in enumerate(f.get('times', [])):
                lines.append(f"    {'Times' if i == 0 else '':<7}: {t}")
        lines.append("")
    return lines


def _format_linux_network(data):
    """Summarise Linux sockets; list only inet sockets worth reading."""
    conns = data.get('network') or []
    if not conns:
        return []

    def family(c):
        fam = (c.get('family') or '').upper()
        if fam:
            return fam
        # Older results without family: guess from the address shape
        return 'AF_INET' if ('.' in str(c.get('local_addr', '')) and '/' not in str(c.get('local_addr', ''))) else 'OTHER'

    inet = [c for c in conns if family(c) in ('AF_INET', 'AF_INET6')]
    by_family = {}
    for c in conns:
        by_family[family(c)] = by_family.get(family(c), 0) + 1

    lines = ["-" * 110, "NETWORK CONNECTIONS", "-" * 110,
             f"Total sockets: {len(conns)}  (" +
             ", ".join(f"{k}: {v}" for k, v in sorted(by_family.items(), key=lambda kv: -kv[1])) + ")"]

    stats = data.get('network_statistics', {})
    lines.append(f"Established: {stats.get('established_connections', 0)}   "
                 f"Listening: {stats.get('listening_ports', 0)}")
    top_ips = stats.get('top_remote_ips') or []
    if top_ips:
        lines.append("Top remote IPs: " + ", ".join(f"{i['ip']} ({i['count']})" for i in top_ips[:5]))
    lines.append("")

    if not inet:
        lines.append("No TCP/UDP (AF_INET/AF_INET6) sockets found; "
                     "Unix and netlink sockets omitted (see JSON output).")
        lines.append("")
        return lines

    pid_to_name = {p.get('pid'): p.get('name', '?') for p in data.get('processes', [])}
    lines.append(f"{'Proto':<7} {'Local Address':<26} {'Foreign Address':<26} {'State':<13} {'PID':<7} Process")
    lines.append("-" * 110)
    limit = 40
    for c in inet[:limit]:
        local = f"{c.get('local_addr', '')}:{c.get('local_port', '')}"
        foreign = f"{c.get('foreign_addr', '')}:{c.get('foreign_port', '')}"
        name = c.get('owner') or pid_to_name.get(c.get('pid'), '')
        lines.append(f"{str(c.get('protocol', ''))[:6]:<7} {local[:25]:<26} {foreign[:25]:<26} "
                     f"{str(c.get('state', ''))[:12]:<13} {str(c.get('pid', '')):<7} {name}")
    if len(inet) > limit:
        lines.append(f"... and {len(inet) - limit} more TCP/UDP sockets")
    lines.append(f"(Unix/netlink sockets omitted: {len(conns) - len(inet)}; use --output json)")
    lines.append("")
    return lines


def _format_linux_processes(data):
    """List user-space processes as a tree; hide kernel threads (children of kthreadd)."""
    procs = data.get('processes') or []
    if not procs:
        return []

    by_pid = {p.get('pid'): p for p in procs}
    kernel = {p['pid'] for p in procs if p.get('pid') == 2 or p.get('ppid') == 2}
    user = [p for p in procs if p.get('pid') not in kernel]

    lines = ["-" * 110, f"PROCESSES ({len(user)} user-space, {len(kernel)} kernel threads hidden)", "-" * 110]

    children = {}
    for p in user:
        children.setdefault(p.get('ppid'), []).append(p)
    user_pids = {p['pid'] for p in user}
    roots = [p for p in user if p.get('ppid') not in user_pids or p.get('ppid') == p.get('pid')]

    suspicious = {s.get('pid') for s in data.get('suspicious') or []}
    lines.append(f"{'PID':<8} {'PPID':<8} Name")
    lines.append("-" * 110)

    shown = 0
    limit = 80
    seen = set()

    def walk(p, depth):
        nonlocal shown
        if p['pid'] in seen or shown >= limit:
            return
        seen.add(p['pid'])
        mark = '  <-- suspicious name' if p['pid'] in suspicious else ''
        lines.append(f"{str(p['pid']):<8} {str(p.get('ppid', '')):<8} {'  ' * depth}{p.get('name', '?')}{mark}")
        shown += 1
        for child in sorted(children.get(p['pid'], []), key=lambda c: c['pid']):
            walk(child, depth + 1)

    for root in sorted(roots, key=lambda p: p['pid']):
        walk(root, 0)
    if len(user) > shown:
        lines.append(f"... and {len(user) - shown} more processes (use JSON output for complete list)")
    lines.append("")
    return lines


def _format_generic_network(data):
    """Original flat network table (Windows)."""
    lines = []
    if data.get('network'):
        lines += ["-" * 110, "NETWORK CONNECTIONS", "-" * 110]
        lines.append(f"{'Protocol':<10} {'Local Address':<25} {'Foreign Address':<25} {'State':<15} {'PID':<8}")
        lines.append("-" * 110)
        for conn in data['network'][:30]:
            protocol = str(conn.get('protocol', 'Unknown'))[:9]
            local = f"{conn.get('local_addr', '')}:{conn.get('local_port', 0)}"[:24]
            foreign = f"{conn.get('foreign_addr', '')}:{conn.get('foreign_port', 0)}"[:24]
            state = str(conn.get('state', 'N/A'))[:14]
            lines.append(f"{protocol:<10} {local:<25} {foreign:<25} {state:<15} {conn.get('pid', 0):<8}")
        if len(data['network']) > 30:
            lines.append(f"\n... and {len(data['network']) - 30} more connections")
        lines.append("")
    return lines


def _format_generic_processes(data):
    """Original flat process table (Windows)."""
    lines = []
    if data.get('processes'):
        lines += ["-" * 110, "RUNNING PROCESSES (First 30)", "-" * 110]
        lines.append(f"{'PID':<8} {'PPID':<8} {'Name':<40} {'Threads':<10} {'Handles':<10}")
        lines.append("-" * 110)
        for proc in data['processes'][:30]:
            lines.append(f"{proc.get('pid', 0) or 0:<8} {proc.get('ppid', 0) or 0:<8} "
                         f"{str(proc.get('name', 'Unknown'))[:39]:<40} "
                         f"{proc.get('threads', 0) or 0:<10} {proc.get('handles', 0) or 0:<10}")
        if len(data['processes']) > 30:
            lines.append(f"\n... and {len(data['processes']) - 30} more processes (use JSON output for complete list)")
        lines.append("")
    return lines


def _format_plugin_errors(data):
    errors = data.get('plugin_errors') or []
    if not errors:
        return []
    lines = ["-" * 110, "PLUGIN ERRORS", "-" * 110]
    for e in errors:
        lines.append(f"  {e.get('plugin', '?')}: {e.get('error', '')}")
    lines.append("")
    return lines


def format_memory_table(data):
    """Format memory dump analysis as ASCII table.
    
    Args:
        data: Dictionary containing memory analysis results
        
    Returns:
        str: ASCII table formatted string
    """
    output = []
    
    # Print summary section
    output.append("=" * 110)
    output.append("MEMORY DUMP ANALYSIS SUMMARY")
    output.append("=" * 110)
    output.append(f"Input File: {data.get('input_file', 'N/A')}")
    output.append(f"File Size: {data.get('file_size_mb', 0):.2f} MB")
    output.append(f"OS Type: {data.get('os_type', 'Unknown').upper()}")
    output.append(f"Status: {data.get('status', 'N/A')}")
    
    if data.get('status') == 'error':
        output.append(f"\nError: {data.get('error', 'Unknown error')}")
        output.append("=" * 110)
        return '\n'.join(output)
    
    # Check for OS mismatch warning
    if data.get('os_mismatch_warning'):
        output.append("")
        output.append("WARNING: POSSIBLE OS TYPE MISMATCH")
        output.append("-" * 110)
        output.append(f"   {data['os_mismatch_warning']}")
        output.append("-" * 110)
        output.append("")
    
    output.append(f"Total Processes: {data.get('process_count', 0)}")
    output.append(f"Network Connections: {data.get('network_connections', 0)}")
    output.append(f"Suspicious Findings: {data.get('suspicious_items', 0)}")
    unique_cmds = data.get('suspicious_commands', 0)
    raw_cmds = data.get('suspicious_command_records', unique_cmds)
    if data.get('os_type', '').lower() == 'linux':
        output.append(f"Process Tree Entries: {len(data.get('process_tree', []))}")
        output.append(f"Kernel Modules: {len(data.get('kernel_modules', []))}")
        output.append(f"Shell History Entries: {len(data.get('shell_history', []))}")
    else:
        output.append(f"Command History Entries: {len(data.get('shell_history', []))}")
    output.append(f"Suspicious Commands: {unique_cmds} unique ({raw_cmds} records)")
    if data.get('plugin_errors'):
        output.append(f"Plugin Errors: {len(data['plugin_errors'])}")
    output.append("")
    
    # Print suspicious findings if any
    findings = data.get('suspicious_findings') or []
    command_findings = [f for f in findings if f.get('type') == 'command']
    other_findings = [f for f in findings if f.get('type') != 'command']

    output.append("-" * 110)
    output.append("SUSPICIOUS NETWORK CONNECTIONS")
    output.append("-" * 110)
    if other_findings:
        # Create a PID to process name mapping
        pid_to_name = {p.get('pid'): p.get('name', 'Unknown') for p in data.get('processes', [])}

        for item in other_findings[:20]:
            item_type = item.get('type', 'unknown').upper()
            if item_type == 'NETWORK':
                pid = item.get('pid', '?')
                process_name = pid_to_name.get(pid, 'Unknown')
                output.append(f"  [{item_type}] PID {pid} ({process_name}) -> {item.get('remote', '?')} - {item.get('reason', '')}")
            else:
                output.append(f"  [{item_type}] {item.get('reason', 'Unknown')}")

        if len(other_findings) > 20:
            output.append(f"  ... and {len(other_findings) - 20} more")
    else:
        output.append("  No suspicious network connections found.")
    output.append("")

    if command_findings:
        output.extend(_format_command_findings(command_findings))
    else:
        output.extend(["-" * 110, "SUSPICIOUS COMMANDS", "-" * 110,
                       "  No suspicious commands found.", ""])
    for note in data.get('notes') or []:
        output.append(f"  Note: {note}")
    if data.get('notes'):
        output.append("")

    # Print suspicious processes if any
    if data.get('suspicious') and len(data['suspicious']) > 0:
        output.append("-" * 110)
        output.append("SUSPICIOUS PROCESSES")
        output.append("-" * 110)
        
        linux_proc = data.get('os_type', '').lower() == 'linux'
        header = f"{'PID':<8} {'PPID':<8} {'Name':<30}"
        if not linux_proc:
            header += f" {'Threads':<10} {'Handles':<10}"
        header += " Reason"
        output.append(header)
        output.append("-" * 110)

        for proc in data['suspicious'][:20]:  # Limit to first 20
            row = f"{proc.get('pid') or 0:<8} {proc.get('ppid') or 0:<8} {str(proc.get('name', 'Unknown'))[:29]:<30}"
            if not linux_proc:
                row += f" {proc.get('threads') or 0:<10} {proc.get('handles') or 0:<10}"
            row += " " + "; ".join(proc.get('reasons', []))
            output.append(row)

        if len(data['suspicious']) > 20:
            output.append(f"\n... and {len(data['suspicious']) - 20} more suspicious processes")
        output.append("")
    
    is_linux = data.get('os_type', '').lower() == 'linux'
    if is_linux:
        output.extend(_format_linux_network(data))
        output.extend(_format_linux_processes(data))
    else:
        output.extend(_format_generic_network(data))
        output.extend(_format_generic_processes(data))

    output.extend(_format_plugin_errors(data))

    output.append("=" * 110)
    
    return '\n'.join(output)


def format_eventlog_table(data):
    """Format event log analysis as ASCII table.
    
    Args:
        data: Dictionary containing event log analysis results
        
    Returns:
        str: ASCII table formatted string
    """
    output = []
    
    # Print summary section
    output.append("=" * 110)
    output.append("EVENT LOG ANALYSIS SUMMARY")
    output.append("=" * 110)
    output.append(f"Input File: {data.get('input_file', 'N/A')}")
    output.append(f"Log Type: {data.get('log_type', 'Unknown')}")
    output.append(f"File Size: {data.get('file_size_mb', 0):.2f} MB")
    output.append(f"Status: {data.get('status', 'N/A')}")
    
    if data.get('status') == 'error':
        output.append(f"\nError: {data.get('error', 'Unknown error')}")
        output.append("=" * 110)
        return '\n'.join(output)
    
    output.append(f"Total Events: {data.get('total_events', 0):,}")
    output.append(f"Events Parsed: {data.get('events_parsed', 0):,}")
    output.append("")
    
    # Print security alerts if any
    if 'security_alerts' in data:
        alerts = data['security_alerts']
        critical_count = alerts.get('critical_count', 0)
        warning_count = alerts.get('warning_count', 0)
        info_count = alerts.get('info_count', 0)
        
        if critical_count > 0 or warning_count > 0:
            output.append("-" * 110)
            output.append("SECURITY ALERTS")
            output.append("-" * 110)
            output.append(f"Critical Alerts: {critical_count}")
            output.append(f"Warnings: {warning_count}")
            output.append("")
            
            # Show critical alerts
            if alerts.get('critical'):
                output.append("CRITICAL:")
                for alert in alerts['critical']:
                    output.append(f"  [!] {alert.get('type', 'unknown').upper()}: {alert.get('message', '')}")
                    if 'details' in alert:
                        details = alert['details']
                        for key, value in details.items():
                            if isinstance(value, list):
                                value = ', '.join(str(v) for v in value)
                            output.append(f"      {key}: {value}")
                output.append("")
            
            # Show warnings
            if alerts.get('warnings'):
                output.append("WARNINGS:")
                for alert in alerts['warnings'][:10]:  # Limit to 10
                    output.append(f"  [WARNING] {alert.get('type', 'unknown').upper()}: {alert.get('message', '')}")
                    if 'details' in alert:
                        details = alert['details']
                        for key, value in list(details.items())[:3]:  # Limit details
                            if isinstance(value, list):
                                value = ', '.join(str(v) for v in value[:3])
                            output.append(f"      {key}: {value}")
                if len(alerts.get('warnings', [])) > 10:
                    output.append(f"  ... and {len(alerts['warnings']) - 10} more warnings")
                output.append("")
    
    # Print login events summary if any
    if 'login_events' in data:
        login = data['login_events']
        output.append("-" * 110)
        output.append("LOGIN EVENTS SUMMARY")
        output.append("-" * 110)
        output.append(f"Successful Logins: {login.get('successful_logins', 0)}")
        output.append(f"Failed Logins: {login.get('failed_logins', 0)}")
        output.append(f"Logoffs: {login.get('logoffs', 0)}")
        output.append(f"Unique Users: {login.get('unique_users', 0)}")
        output.append(f"Unique IPs: {login.get('unique_ips', 0)}")
        output.append("")
        
        # Show top users
        if login.get('top_users'):
            output.append("")
            output.append("TOP USERS:")
            header = f"{'User':<50} {'Count':<10}"
            output.append(header)
            output.append("-" * 60)
            for user_info in login['top_users'][:10]:
                user = user_info.get('user', 'Unknown')[:49]
                count = user_info.get('count', 0)
                row = f"{user:<50} {count:<10}"
                output.append(row)
            output.append("-" * 60)
        
        # Show top IPs
        if login.get('top_ips'):
            output.append("")
            output.append("TOP SOURCE IP ADDRESSES:")
            header = f"{'IP Address':<50} {'Count':<10}"
            output.append(header)
            output.append("-" * 60)
            for ip_info in login['top_ips'][:10]:
                ip = ip_info.get('ip', 'Unknown')[:49]
                count = ip_info.get('count', 0)
                row = f"{ip:<50} {count:<10}"
                output.append(row)
            output.append("-" * 60)
        
        # Show recent failed logins
        if login.get('details', {}).get('failed_logins'):
            failed = login['details']['failed_logins']
            if failed:
                output.append("")
                output.append("FAILED LOGIN ATTEMPTS:")
                header = f"{'Timestamp':<28} {'User':<30} {'IP Address':<20} {'Reason':<30}"
                output.append(header)
                output.append("-" * 110)
                for attempt in failed[:10]:  # Show last 10
                    timestamp = str(attempt.get('timestamp', 'Unknown'))[:27]
                    user = attempt.get('user', 'Unknown')[:29]
                    ip = attempt.get('ip_address', '-')[:19]
                    raw_reason = attempt.get('failure_reason', '-')
                    reason = _translate_windows_status_code(raw_reason)[:29]
                    row = f"{timestamp:<28} {user:<30} {ip:<20} {reason:<30}"
                    output.append(row)
                if len(failed) > 10:
                    output.append(f"\n... and {len(failed) - 10} more failed attempts")
                output.append("")
    
    # Print system events if any
    if 'system_events' in data:
        sys_events = data['system_events']
        output.append("-" * 110)
        output.append("SYSTEM EVENTS SUMMARY")
        output.append("-" * 110)
        
        if sys_events.get('errors'):
            output.append(f"Errors: {len(sys_events['errors'])}")
        if sys_events.get('warnings'):
            output.append(f"Warnings: {len(sys_events['warnings'])}")
        if sys_events.get('service_starts'):
            output.append(f"Service Starts: {len(sys_events['service_starts'])}")
        if sys_events.get('service_stops'):
            output.append(f"Service Stops: {len(sys_events['service_stops'])}")
        output.append("")
    
    output.append("=" * 110)
    output.append("TIP: Use --output json for complete details including all login events and timestamps")
    output.append("=" * 110)
    
    return '\n'.join(output)


def format_textlog_table(data):
    """Format text log analysis as ASCII table.
    
    Args:
        data: Dictionary containing text log analysis results
        
    Returns:
        str: ASCII table formatted string
    """
    output = []
    
    # Print summary section
    output.append("=" * 110)
    output.append("TEXT LOG ANALYSIS SUMMARY")
    output.append("=" * 110)
    output.append(f"Input File: {data.get('input_file', 'N/A')}")
    output.append(f"Log Type: {data.get('log_type', 'Unknown').upper()}")
    output.append(f"File Size: {data.get('file_size_mb', 0):.2f} MB")
    output.append(f"Status: {data.get('status', 'N/A')}")
    
    if data.get('status') == 'error':
        output.append(f"\nError: {data.get('error', 'Unknown error')}")
        output.append("=" * 110)
        return '\n'.join(output)
    
    output.append(f"Total Lines: {data.get('total_lines', 0):,}")
    output.append(f"Lines Parsed: {data.get('lines_parsed', 0):,}")
    output.append("")
    
    # Print security alerts if any
    if 'security_alerts' in data:
        alerts = data['security_alerts']
        critical_count = alerts.get('critical_count', 0)
        warning_count = alerts.get('warning_count', 0)
        info_count = alerts.get('info_count', 0)
        
        if critical_count > 0 or warning_count > 0:
            output.append("-" * 110)
            output.append("SECURITY ALERTS")
            output.append("-" * 110)
            output.append(f"Critical Alerts: {critical_count}")
            output.append(f"Warnings: {warning_count}")
            output.append("")
            
            # Show critical alerts
            if alerts.get('critical'):
                output.append("CRITICAL:")
                for alert in alerts['critical']:
                    output.append(f"  [!] {alert.get('type', 'unknown').upper()}: {alert.get('message', '')}")
                    if 'details' in alert:
                        details = alert['details']
                        for key, value in details.items():
                            if isinstance(value, list):
                                value = ', '.join(str(v) for v in value[:5])
                            output.append(f"      {key}: {value}")
                output.append("")
            
            # Show warnings
            if alerts.get('warnings'):
                output.append("WARNINGS:")
                for alert in alerts['warnings'][:10]:
                    output.append(f"  [WARNING] {alert.get('type', 'unknown').upper()}: {alert.get('message', '')}")
                    if 'details' in alert:
                        details = alert['details']
                        for key, value in list(details.items())[:3]:
                            if isinstance(value, list):
                                value = ', '.join(str(v) for v in value[:5])
                            output.append(f"      {key}: {value}")
                if len(alerts.get('warnings', [])) > 10:
                    output.append(f"  ... and {len(alerts['warnings']) - 10} more warnings")
                output.append("")
    
    # Print login events summary if any
    if 'login_events' in data:
        login = data['login_events']
        output.append("-" * 110)
        output.append("LOGIN EVENTS SUMMARY")
        output.append("-" * 110)
        output.append(f"Successful Logins: {login.get('successful_logins', 0)}")
        output.append(f"Failed Logins: {login.get('failed_logins', 0)}")
        output.append(f"Sudo Commands: {login.get('sudo_commands', 0)}")
        output.append(f"Unique Users: {login.get('unique_users', 0)}")
        output.append(f"Unique IPs: {login.get('unique_ips', 0)}")
        output.append("")
        
        # Show top users
        if login.get('top_users'):
            output.append("TOP USERS:")
            header = f"{'User':<30} {'Count':<10}"
            output.append(header)
            output.append("-" * 40)
            for user_info in login['top_users'][:10]:
                user = user_info.get('user', 'Unknown')[:29]
                count = user_info.get('count', 0)
                row = f"{user:<30} {count:<10}"
                output.append(row)
            output.append("-" * 40)
            output.append("")
        
        # Show top IPs
        if login.get('top_ips'):
            output.append("TOP SOURCE IPS:")
            header = f"{'IP Address':<30} {'Count':<10}"
            output.append(header)
            output.append("-" * 40)
            for ip_info in login['top_ips'][:10]:
                ip = ip_info.get('ip', 'Unknown')[:29]
                count = ip_info.get('count', 0)
                row = f"{ip:<30} {count:<10}"
                output.append(row)
            output.append("-" * 40)
            output.append("")
        
        # Show successful logins
        successful = login.get('details', {}).get('successful_logins')
        if successful:
            output.append("SUCCESSFUL LOGINS:")
            header = f"{'Service':<10} {'User':<20} {'IP Address':<20} {'Method':<20}"
            output.append(header)
            output.append("-" * 70)
            for entry in successful[:15]:
                output.append(f"{str(entry.get('service', 'ssh')).upper():<10} "
                              f"{entry.get('user', 'Unknown')[:19]:<20} "
                              f"{entry.get('ip_address', '-')[:19]:<20} "
                              f"{entry.get('method', '-')[:19]:<20}")
            output.append("-" * 70)
            if len(successful) > 15:
                output.append(f"... and {len(successful) - 15} more successful logins")
            output.append("")

        # Show recent failed logins
        if login.get('details', {}).get('failed_logins'):
            failed = login['details']['failed_logins']
            if failed:
                output.append("")
                output.append("FAILED LOGIN ATTEMPTS:")
                header = f"{'Service':<10} {'User':<20} {'IP Address':<20} {'Reason':<20}"
                output.append(header)
                output.append("-" * 70)
                for attempt in failed[:15]:
                    service = str(attempt.get('service', 'ssh')).upper()
                    user = attempt.get('user', 'Unknown')[:19]
                    ip = attempt.get('ip_address', '-')[:19]
                    reason = attempt.get('reason', '-')[:19]
                    row = f"{service:<10} {user:<20} {ip:<20} {reason:<20}"
                    output.append(row)
                output.append("-" * 70)
                if len(failed) > 15:
                    output.append(f"\n... and {len(failed) - 15} more failed attempts")
        
        # Show sample sudo commands
        if login.get('details', {}).get('sudo_commands'):
            sudo = login['details']['sudo_commands']
            if sudo:
                output.append("")
                output.append("SUDO COMMANDS:")
                header = f"{'User':<20} {'Command':<85}"
                output.append(header)
                output.append("-" * 110)
                for cmd in sudo[:10]:
                    user = cmd.get('user', 'Unknown')[:19]
                    command = cmd.get('command', '-')[:84]
                    row = f"{user:<20} {command:<85}"
                    output.append(row)
                if len(sudo) > 10:
                    output.append(f"\n... and {len(sudo) - 10} more sudo commands")
                output.append("")
    
    # Print syslog events if any
    if 'syslog_events' in data:
        sys_events = data['syslog_events']
        output.append("-" * 110)
        output.append("SYSTEM LOG EVENTS SUMMARY")
        output.append("-" * 110)
        output.append(f"Service Starts: {sys_events.get('service_starts', 0)}")
        output.append(f"Service Stops: {sys_events.get('service_stops', 0)}")
        output.append(f"Errors: {sys_events.get('errors', 0)}")
        output.append(f"Network Events: {sys_events.get('network_events', 0)}")
        output.append(f"Unique IPs: {sys_events.get('unique_ips', 0)}")
        output.append("")
        
        if sys_events.get('top_ips'):
            output.append("TOP IPs IN NETWORK EVENTS:")
            for ip in sys_events['top_ips'][:10]:
                output.append(f"  - {ip}")
            output.append("")
        
        if sys_events.get('sample_errors'):
            output.append("SAMPLE ERRORS:")
            for i, error in enumerate(sys_events['sample_errors'][:5], 1):
                output.append(f"  {i}. {error[:100]}...")
            output.append("")
    
    output.append("=" * 110)
    output.append("TIP: Use --output json for complete details including all log entries")
    output.append("=" * 110)
    
    return '\n'.join(output)


def _fmt_epoch(value):
    """Epoch seconds -> 'YYYY-MM-DD HH:MM:SS' (UTC); '-' when missing."""
    import datetime
    if not value:
        return '-'
    try:
        return datetime.datetime.fromtimestamp(int(value), datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError, OverflowError, OSError):
        return '-'


def _fmt_size(size_bytes):
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes / (1024 * 1024):.2f} MB"


def _section(title):
    return ["-" * 110, title, "-" * 110]


def _format_disk_command_history(data):
    sys_data = data.get('system_intelligence') or {}
    history = sys_data.get('command_history')
    if not history:
        return []
    analysis = sys_data.get('command_analysis', {})
    suspicious = analysis.get('suspicious_commands', [])
    out = _section(f"COMMAND HISTORY ANALYSIS")
    out.append(f"Users with history: {len(history)}   Total commands: {analysis.get('total_commands', 0)}")
    for user, info in history.items():
        files = ', '.join(f"{f['filename']} ({f['command_count']})" for f in info['files'])
        out.append(f"  {user}: {info['total_commands']} commands  [{files}]")
    out.append("")

    out.append(f"SUSPICIOUS COMMANDS ({len(suspicious)} unique)")
    if not suspicious:
        out.append("  No suspicious commands found in the history files.")
    for item in suspicious:
        out.append(f"  [{item['severity'].upper()}] {item['command']}")
        out.append(f"      Reason: {item['reason']}")
        out.append(f"      Users : {', '.join(str(u) for u in item['users'])}   Occurrences: {item['records']}")
    out.append("")

    return out


MAX_YARA_PATHS = 10  # paths listed per rule in the table


def _format_disk_yara(data):
    yara = data.get('yara_detection')
    if not yara:
        return []
    out = _section("YARA SCAN")
    out.append(f"Files scanned: {yara.get('total_files_scanned', 0)}   "
               f"Files with matches: {yara.get('files_with_matches', 0)}")
    if yara.get('files_skipped_system_folders'):
        out.append(f"Not scanned (outside user-data folders such as /home, /tmp, /var/www, Users): {yara['files_skipped_system_folders']} files")
    out.append("")
    # Group by rule (finding type): one block per rule with the files it matched
    by_rule = {}
    for det in yara.get('detections', []):
        for rule in det['rules']:
            entry = by_rule.setdefault(rule['rule'], {'rule': rule, 'files': []})
            entry['files'].append(det['file'])
    if not by_rule:
        out.append("  No matches.")
        out.append("")
    order = {'critical': 3, 'high': 2, 'medium': 1, 'low': 0}
    for name, entry in sorted(by_rule.items(),
                              key=lambda kv: (-order.get(kv[1]['rule']['severity'], 0), kv[0])):
        rule = entry['rule']
        out.append(f"[{rule['severity'].upper()}] {name} - {rule['description']} ({len(entry['files'])} file(s))")
        shown = sorted(entry['files'])[:MAX_YARA_PATHS]
        for path in shown:
            out.append(f"    {path}")
        if len(entry['files']) > len(shown):
            out.append(f"    ... and {len(entry['files']) - len(shown)} more files (use --output json for the full list)")
        out.append("")
    return out


def format_table(data):
    """Format data as ASCII table.
    
    Args:
        data: Dictionary containing analysis results
        
    Returns:
        str: ASCII table formatted string
    """
    output = []
    
    # Check if it's memory dump analysis
    if data.get('analysis_type') == 'memory_dump':
        return format_memory_table(data)
    
    # Check if it's event log analysis
    if data.get('analysis_type') == 'event_log':
        return format_eventlog_table(data)
    
    # Check if it's text log analysis
    if data.get('analysis_type') == 'text_log':
        return format_textlog_table(data)
    
    # Print summary section
    output.append("=" * 110)
    output.append("FORENSIC ANALYSIS SUMMARY")
    output.append("=" * 110)
    output.append(f"Analysis Type: {data.get('analysis_type', 'N/A')}")
    output.append(f"Input File: {data.get('input_file', 'N/A')}")
    output.append(f"Status: {data.get('status', 'N/A')}")
    output.append(f"Total Size: {data.get('total_size', '0 bytes')}")
    output.append(f"Files: {data.get('files_scanned', 0)}")
    output.append(f"Directories: {data.get('directories_scanned', 0)}")
    output.append("")
    
    # Print system intelligence if available
    if 'system_intelligence' in data:
        sys_info = data['system_intelligence']
        output.append("-" * 110)
        output.append("SYSTEM INTELLIGENCE")
        output.append("-" * 110)
        output.append(f"OS Type: {sys_info.get('os_type', 'Unknown').upper()}")
        
        if sys_info.get('hostname'):
            output.append(f"Hostname: {sys_info['hostname']}")
        
        if sys_info.get('os_info'):
            os_details = sys_info['os_info']
            if os_details.get('name'):
                output.append(f"OS Name: {os_details['name']}")
            if os_details.get('version'):
                output.append(f"OS Version: {os_details['version']}")
        
        if sys_info.get('user_profiles'):
            users = sys_info['user_profiles']
            output.append(f"User Profiles: {len(users)} found")
            for user in users:
                output.append(f"  - {user}")
        else:
            output.append("User Profiles: None detected")
        
        output.append("")
    
    output.extend(_format_disk_command_history(data))
    output.extend(_format_disk_yara(data))

    output.append("=" * 110)
    
    return '\n'.join(output)


def format_output(data, format_type='json'):
    """Format data according to specified format.
    
    Args:
        data: Dictionary to format
        format_type: Output format ('json', 'csv', 'table')
        
    Returns:
        str: Formatted output string
    """
    formatters = {
        'json': format_json,
        'csv': format_csv,
        'table': format_table
    }
    
    formatter = formatters.get(format_type, format_json)
    return formatter(data)