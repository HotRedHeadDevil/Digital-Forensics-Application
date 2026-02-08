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
        '0xC000006D': 'Bad username',
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
    return status_codes.get(code, code)


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
    
    Args:
        data: Dictionary containing analysis results
        
    Returns:
        str: CSV formatted string
    """
    output = io.StringIO()
    
    if 'results' not in data or not data['results']:
        return "No results to export"
    
    # Extract file/directory entries
    results = data['results']
    
    # Define CSV columns
    fieldnames = ['name', 'path', 'type', 'size', 'inode', 'm_time', 'a_time', 'c_time', 'e_time', 'yara_matches']
    
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
    writer.writeheader()
    
    for item in results:
        row = item.copy()
        # Convert yara_matches list to comma-separated string
        if 'yara_matches' in row:
            row['yara_matches'] = ', '.join(row['yara_matches'])
        writer.writerow(row)
    
    return output.getvalue()


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
        output.append("⚠️  WARNING: POSSIBLE OS TYPE MISMATCH")
        output.append("-" * 110)
        output.append(f"   {data['os_mismatch_warning']}")
        output.append("-" * 110)
        output.append("")
    
    output.append(f"Total Processes: {data.get('process_count', 0)}")
    output.append(f"Network Connections: {data.get('network_connections', 0)}")
    output.append(f"Suspicious Findings: {data.get('suspicious_items', 0)}")
    output.append("")
    
    # Print suspicious findings if any
    if data.get('suspicious_findings') and len(data['suspicious_findings']) > 0:
        output.append("-" * 110)
        output.append("⚠ SUSPICIOUS FINDINGS")
        output.append("-" * 110)
        
        # Create a PID to process name mapping
        pid_to_name = {p.get('pid'): p.get('name', 'Unknown') for p in data.get('processes', [])}
        
        for item in data['suspicious_findings'][:20]:
            item_type = item.get('type', 'unknown').upper()
            if item_type == 'NETWORK':
                pid = item.get('pid', '?')
                process_name = pid_to_name.get(pid, 'Unknown')
                output.append(f"  [{item_type}] PID {pid} ({process_name}) -> {item.get('remote', '?')} - {item.get('reason', '')}")
            else:
                output.append(f"  [{item_type}] {item.get('reason', 'Unknown')}")
        
        if len(data['suspicious_findings']) > 20:
            output.append(f"  ... and {len(data['suspicious_findings']) - 20} more")
        output.append("")
    
    # Print suspicious processes if any
    if data.get('suspicious') and len(data['suspicious']) > 0:
        output.append("-" * 110)
        output.append("SUSPICIOUS PROCESSES")
        output.append("-" * 110)
        
        header = f"{'PID':<8} {'PPID':<8} {'Name':<30} {'Threads':<10} {'Handles':<10}"
        output.append(header)
        output.append("-" * 110)
        
        for proc in data['suspicious'][:20]:  # Limit to first 20
            pid = proc.get('pid', 0)
            ppid = proc.get('ppid', 0)
            name = proc.get('name', 'Unknown')[:29]
            threads = proc.get('threads', 0)
            handles = proc.get('handles', 0)
            
            row = f"{pid:<8} {ppid:<8} {name:<30} {threads:<10} {handles:<10}"
            output.append(row)
        
        if len(data['suspicious']) > 20:
            output.append(f"\n... and {len(data['suspicious']) - 20} more suspicious processes")
        output.append("")
    
    # Print network connections if any
    if data.get('network') and len(data['network']) > 0:
        output.append("-" * 110)
        output.append("NETWORK CONNECTIONS")
        output.append("-" * 110)
        
        header = f"{'Protocol':<10} {'Local Address':<25} {'Foreign Address':<25} {'State':<15} {'PID':<8}"
        output.append(header)
        output.append("-" * 110)
        
        for conn in data['network'][:30]:  # Limit to first 30
            protocol = conn.get('protocol', 'Unknown')[:9]
            local = f"{conn.get('local_addr', '')}:{conn.get('local_port', 0)}"[:24]
            foreign = f"{conn.get('foreign_addr', '')}:{conn.get('foreign_port', 0)}"[:24]
            state = conn.get('state', 'N/A')[:14]
            pid = conn.get('pid', 0)
            
            row = f"{protocol:<10} {local:<25} {foreign:<25} {state:<15} {pid:<8}"
            output.append(row)
        
        if len(data['network']) > 30:
            output.append(f"\n... and {len(data['network']) - 30} more connections")
        output.append("")
    
    # Print process list (limited)
    if data.get('processes') and len(data['processes']) > 0:
        output.append("-" * 110)
        output.append("RUNNING PROCESSES (First 30)")
        output.append("-" * 110)
        
        header = f"{'PID':<8} {'PPID':<8} {'Name':<40} {'Threads':<10} {'Handles':<10}"
        output.append(header)
        output.append("-" * 110)
        
        for proc in data['processes'][:30]:
            pid = proc.get('pid', 0) or 0
            ppid = proc.get('ppid', 0) or 0
            name = proc.get('name', 'Unknown')[:39]
            threads = proc.get('threads', 0) or 0
            handles = proc.get('handles', 0) or 0
            
            row = f"{pid:<8} {ppid:<8} {name:<40} {threads:<10} {handles:<10}"
            output.append(row)
        
        if len(data['processes']) > 30:
            output.append(f"\n... and {len(data['processes']) - 30} more processes (use JSON output for complete list)")
        output.append("")
    
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
        output.append(f"SSH Connections: {login.get('ssh_connections', 0)}")
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
        
        # Show recent failed logins
        if login.get('details', {}).get('failed_logins'):
            failed = login['details']['failed_logins']
            if failed:
                output.append("")
                output.append("FAILED LOGIN ATTEMPTS:")
                header = f"{'User':<20} {'IP Address':<20} {'Reason':<20}"
                output.append(header)
                output.append("-" * 60)
                for attempt in failed[:15]:
                    user = attempt.get('user', 'Unknown')[:19]
                    ip = attempt.get('ip_address', '-')[:19]
                    reason = attempt.get('reason', '-')[:19]
                    row = f"{user:<20} {ip:<20} {reason:<20}"
                    output.append(row)
                output.append("-" * 60)
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
    
    # Print command history if available
    if 'system_intelligence' in data and data['system_intelligence'].get('command_history'):
        cmd_history = data['system_intelligence']['command_history']
        cmd_analysis = data['system_intelligence'].get('command_analysis', {})
        
        output.append("-" * 110)
        output.append("COMMAND HISTORY ANALYSIS")
        output.append("-" * 110)
        
        output.append(f"Users with History: {len(cmd_history)}")
        output.append(f"Total Commands: {cmd_analysis.get('total_commands', 0)}")
        output.append("")
        
        # Show per-user summary
        for user, data_user in cmd_history.items():
            output.append(f"{user}:")
            output.append(f"  Total commands: {data_user['total_commands']}")
            output.append(f"  History files: {len(data_user['files'])}")
            for hist_file in data_user['files']:
                output.append(f"    - {hist_file['filename']}: {hist_file['command_count']} commands")
        
        output.append("")
        
        # Show interesting findings
        if cmd_analysis.get('suspicious_commands'):
            output.append("Suspicious Commands Detected:")
            for item in cmd_analysis['suspicious_commands'][:5]:  # Show top 5
                output.append(f"  [{item['user']}] {item['command']}")
            if len(cmd_analysis['suspicious_commands']) > 5:
                output.append(f"  ... and {len(cmd_analysis['suspicious_commands']) - 5} more")
            output.append("")
        
        if cmd_analysis.get('most_common'):
            output.append("Most Common Commands:")
            for item in cmd_analysis['most_common'][:5]:  # Show top 5
                output.append(f"  {item['command']}: {item['count']} times")
            output.append("")
        
        output.append("")
    
    # Print YARA detection summary if available
    if 'yara_detection' in data:
        yara = data['yara_detection']
        output.append("-" * 110)
        output.append("YARA DETECTION SUMMARY")
        output.append("-" * 110)
        output.append(f"Files Scanned: {yara.get('total_files_scanned', 0)}")
        output.append(f"Files with Matches: {yara.get('files_with_matches', 0)}")
        output.append(f"Total Detections: {yara.get('total_detections', 0)}")
        output.append("")
        
        if yara.get('detections'):
            output.append("Detections:")
            for detection in yara['detections']:
                output.append(f"  • {detection['file']}")
                output.append(f"    Rule: {detection['rule']}")
                output.append(f"    Size: {detection['size']} bytes")
        output.append("")
    
    # Print results table
    if 'results' in data and data['results']:
        output.append("-" * 110)
        output.append("FILES AND DIRECTORIES")
        output.append("-" * 110)
        
        # Table header with fixed column widths
        header = f"{'Type':<8} {'Name':<40} {'Size':<12} {'YARA Matches':<35}"
        output.append(header)
        output.append("-" * 110)
        
        for item in data['results']:
            item_type = item.get('type', 'N/A')
            name = item.get('name', 'N/A')
            
            # Truncate long names with ellipsis
            if len(name) > 39:
                name = name[:36] + '...'
            
            # Format size better
            if item.get('type') == 'file':
                size_bytes = item.get('size', 0)
                if size_bytes < 1024:
                    size = f"{size_bytes} B"
                elif size_bytes < 1024*1024:
                    size = f"{size_bytes/1024:.1f} KB"
                else:
                    size = f"{size_bytes/(1024*1024):.2f} MB"
            else:
                size = '-'
            
            # Format YARA matches with fixed width
            if 'yara_matches' in item and item['yara_matches']:
                yara = ', '.join(item['yara_matches'])
                # Truncate if too long
                if len(yara) > 34:
                    yara = yara[:31] + '...'
            else:
                yara = '-'
            
            row = f"{item_type:<8} {name:<40} {size:<12} {yara:<35}"
            output.append(row)
    
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
