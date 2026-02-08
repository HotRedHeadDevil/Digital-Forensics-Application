# log_analyzer.py - Log file analysis module for login attempts, network connections, and user activity

import pytsk3
import logging
import re
import struct
import os
from datetime import datetime
from collections import defaultdict

logger = logging.getLogger(__name__)


def parse_single_event_log(filepath):
    """Parse a standalone Windows Event Log file (.evtx).
    
    Args:
        filepath: Path to the .evtx file
        
    Returns:
        dict: Parsed event log data with statistics
    """
    result = {
        'log_type': 'unknown',
        'file_size_mb': 0,
        'total_events': 0,
        'events_parsed': 0
    }
    
    # Check if file exists and is readable
    if not os.path.exists(filepath):
        logger.error(f"Event log file not found: {filepath}")
        result['error'] = f"File not found: {filepath}"
        return result
    
    # Get file size
    file_size_bytes = os.path.getsize(filepath)
    result['file_size_mb'] = round(file_size_bytes / (1024 * 1024), 2)
    
    # Determine log type from filename
    filename = os.path.basename(filepath).lower()
    if 'security' in filename:
        result['log_type'] = 'Security'
    elif 'system' in filename:
        result['log_type'] = 'System'
    elif 'application' in filename:
        result['log_type'] = 'Application'
    
    # Try to parse the event log
    try:
        import Evtx.Evtx as evtx
        import xml.etree.ElementTree as ET
        
        with evtx.Evtx(filepath) as log:
            login_events = {
                'successful_logins': [],
                'failed_logins': [],
                'logoffs': [],
                'user_frequency': defaultdict(int),
                'ip_frequency': defaultdict(int)
            }
            
            system_events = {
                'service_starts': [],
                'service_stops': [],
                'errors': [],
                'warnings': []
            }
            
            for record in log.records():
                result['total_events'] += 1
                
                try:
                    xml_str = record.xml()
                    root = ET.fromstring(xml_str)
                    
                    # Extract EventID
                    event_id_elem = root.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}EventID')
                    if event_id_elem is None:
                        continue
                    
                    event_id = int(event_id_elem.text)
                    result['events_parsed'] += 1
                    
                    # Parse Security events
                    if result['log_type'] == 'Security':
                        if event_id == 4624:  # Successful login
                            event_data = _parse_login_event_xml(root, event_id)
                            if event_data:
                                login_events['successful_logins'].append(event_data)
                                if event_data.get('user'):
                                    login_events['user_frequency'][event_data['user']] += 1
                                if event_data.get('ip_address') and event_data['ip_address'] not in ['-', '127.0.0.1', '::1']:
                                    login_events['ip_frequency'][event_data['ip_address']] += 1
                        
                        elif event_id == 4625:  # Failed login
                            event_data = _parse_login_event_xml(root, event_id)
                            if event_data:
                                login_events['failed_logins'].append(event_data)
                                if event_data.get('user'):
                                    login_events['user_frequency'][event_data['user']] += 1
                                if event_data.get('ip_address') and event_data['ip_address'] not in ['-', '127.0.0.1', '::1']:
                                    login_events['ip_frequency'][event_data['ip_address']] += 1
                        
                        elif event_id in [4634, 4647]:  # Logoff
                            event_data = _parse_login_event_xml(root, event_id)
                            if event_data:
                                login_events['logoffs'].append(event_data)
                    
                    # Parse System events
                    elif result['log_type'] == 'System':
                        timestamp_elem = root.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}TimeCreated')
                        timestamp = timestamp_elem.get('SystemTime') if timestamp_elem is not None else 'unknown'
                        
                        if event_id == 7036:  # Service state change
                            # Extract service name and state from message
                            message = _extract_message_from_xml(root)
                            if 'running' in message.lower():
                                system_events['service_starts'].append({
                                    'timestamp': timestamp,
                                    'message': message
                                })
                            elif 'stopped' in message.lower():
                                system_events['service_stops'].append({
                                    'timestamp': timestamp,
                                    'message': message
                                })
                        
                        # Collect errors and warnings
                        level_elem = root.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}Level')
                        if level_elem is not None:
                            level = int(level_elem.text)
                            if level == 2:  # Error
                                system_events['errors'].append({
                                    'event_id': event_id,
                                    'timestamp': timestamp,
                                    'message': _extract_message_from_xml(root)
                                })
                            elif level == 3:  # Warning
                                system_events['warnings'].append({
                                    'event_id': event_id,
                                    'timestamp': timestamp,
                                    'message': _extract_message_from_xml(root)
                                })
                
                except Exception as e:
                    logger.debug(f"Error parsing event record: {e}")
                    continue
            
            # Add parsed data to result
            if result['log_type'] == 'Security':
                result['login_events'] = login_events
                # Detect security threats
                result['security_alerts'] = _detect_security_threats(login_events)
            elif result['log_type'] == 'System':
                result['system_events'] = system_events
        
        logger.info(f"Parsed {result['events_parsed']} out of {result['total_events']} events from {filepath}")
        
    except ImportError:
        logger.error("python-evtx library not installed. Install with: pip install python-evtx")
        result['error'] = "python-evtx library not installed"
    except Exception as e:
        logger.error(f"Error parsing event log {filepath}: {e}")
        result['error'] = str(e)
    
    return result


def _parse_login_event_xml(root, event_id):
    """Parse login event from XML root element.
    
    Args:
        root: XML ElementTree root element
        event_id: Event ID number
        
    Returns:
        dict: Parsed event data or None
    """
    try:
        # Extract timestamp
        timestamp_elem = root.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}TimeCreated')
        timestamp = timestamp_elem.get('SystemTime') if timestamp_elem is not None else 'unknown'
        
        # Extract event data fields
        event_data = {}
        for data_elem in root.findall('.//{http://schemas.microsoft.com/win/2004/08/events/event}Data'):
            name = data_elem.get('Name')
            value = data_elem.text if data_elem.text else ''
            event_data[name] = value
        
        # Build result based on event type
        result = {
            'timestamp': timestamp,
            'event_id': event_id
        }
        
        # Extract user information
        target_user = event_data.get('TargetUserName', '')
        target_domain = event_data.get('TargetDomainName', '')
        if target_user and target_user not in ['-', 'SYSTEM', 'ANONYMOUS LOGON']:
            if target_domain and target_domain not in ['-', 'NT AUTHORITY']:
                result['user'] = f"{target_domain}\\{target_user}"
            else:
                result['user'] = target_user
        
        # Extract IP address
        ip_address = event_data.get('IpAddress', '-')
        if ip_address and ip_address not in ['-', '127.0.0.1', '::1', '']:
            result['ip_address'] = ip_address
        
        # Add logon type for successful logins
        if event_id == 4624:
            logon_type = event_data.get('LogonType', '')
            if logon_type:
                result['logon_type'] = logon_type
        
        # Add failure reason for failed logins
        elif event_id == 4625:
            failure_reason = event_data.get('FailureReason', '')
            status = event_data.get('Status', '')
            if failure_reason:
                result['failure_reason'] = failure_reason
            elif status:
                result['failure_reason'] = f"Status: {status}"
        
        return result if result.get('user') else None
        
    except Exception as e:
        logger.debug(f"Error parsing login event XML: {e}")
        return None


def _extract_message_from_xml(root):
    """Extract message text from event XML.
    
    Args:
        root: XML ElementTree root element
        
    Returns:
        str: Message text or empty string
    """
    try:
        # Try to find message in various possible locations
        message_elem = root.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}Message')
        if message_elem is not None and message_elem.text:
            return message_elem.text.strip()
        
        # Fallback: concatenate all Data elements
        data_parts = []
        for data_elem in root.findall('.//{http://schemas.microsoft.com/win/2004/08/events/event}Data'):
            if data_elem.text:
                data_parts.append(data_elem.text)
        
        return ' '.join(data_parts) if data_parts else ''
        
    except Exception:
        return ''


def parse_standalone_log(filepath):
    """Parse a standalone Linux/Unix text log file.
    
    Args:
        filepath: Path to the log file (auth.log, syslog, secure, etc.)
        
    Returns:
        dict: Parsed log data with statistics
    """
    result = {
        'log_type': 'unknown',
        'file_size_mb': 0,
        'total_lines': 0,
        'lines_parsed': 0
    }
    
    # Check if file exists and is readable
    if not os.path.exists(filepath):
        logger.error(f"Log file not found: {filepath}")
        result['error'] = f"File not found: {filepath}"
        return result
    
    # Get file size
    file_size_bytes = os.path.getsize(filepath)
    result['file_size_mb'] = round(file_size_bytes / (1024 * 1024), 2)
    
    # Determine log type from filename
    filename = os.path.basename(filepath).lower()
    if 'auth' in filename or 'secure' in filename:
        result['log_type'] = 'authentication'
    elif 'syslog' in filename or 'messages' in filename:
        result['log_type'] = 'system'
    elif 'kern' in filename:
        result['log_type'] = 'kernel'
    elif 'access' in filename:
        result['log_type'] = 'access'
    
    # Try to parse the log file
    try:
        login_events = {
            'successful_logins': [],
            'failed_logins': [],
            'ssh_connections': [],
            'sudo_commands': [],
            'user_frequency': defaultdict(int),
            'ip_frequency': defaultdict(int)
        }
        
        syslog_events = {
            'service_starts': [],
            'service_stops': [],
            'errors': [],
            'network_events': [],
            'ip_addresses': set()
        }
        
        with open(filepath, 'r', errors='ignore') as f:
            for line in f:
                result['total_lines'] += 1
                line = line.strip()
                
                if not line:
                    continue
                
                result['lines_parsed'] += 1
                
                # Parse authentication logs
                if result['log_type'] == 'authentication':
                    # SSH successful login
                    if 'Accepted' in line and ('publickey' in line or 'password' in line):
                        match = re.search(r'Accepted (?:publickey|password) for (\S+) from ([\d\.]+)', line)
                        if match:
                            user, ip = match.groups()
                            login_events['successful_logins'].append({
                                'user': user,
                                'ip_address': ip,
                                'method': 'publickey' if 'publickey' in line else 'password',
                                'log_line': line
                            })
                            login_events['user_frequency'][user] += 1
                            login_events['ip_frequency'][ip] += 1
                    
                    # SSH failed login
                    elif 'Failed password' in line or 'Invalid user' in line:
                        # Failed password for user
                        match = re.search(r'Failed password for (?:invalid user )?(\S+) from ([\d\.]+)', line)
                        if match:
                            user, ip = match.groups()
                            login_events['failed_logins'].append({
                                'user': user,
                                'ip_address': ip,
                                'reason': 'failed_password',
                                'log_line': line
                            })
                            login_events['user_frequency'][user] += 1
                            login_events['ip_frequency'][ip] += 1
                        # Invalid user
                        elif 'Invalid user' in line:
                            match = re.search(r'Invalid user (\S+) from ([\d\.]+)', line)
                            if match:
                                user, ip = match.groups()
                                login_events['failed_logins'].append({
                                    'user': user,
                                    'ip_address': ip,
                                    'reason': 'invalid_user',
                                    'log_line': line
                                })
                                login_events['user_frequency'][user] += 1
                                login_events['ip_frequency'][ip] += 1
                    
                    # SSH connections
                    elif 'Connection from' in line or 'Received disconnect' in line:
                        match = re.search(r'([\d\.]+)', line)
                        if match:
                            ip = match.group(1)
                            login_events['ssh_connections'].append({
                                'ip_address': ip,
                                'log_line': line
                            })
                    
                    # Sudo commands
                    elif 'sudo:' in line and 'COMMAND=' in line:
                        match = re.search(r'sudo:\s+(\S+)\s+:.*COMMAND=(.+)', line)
                        if match:
                            user, command = match.groups()
                            login_events['sudo_commands'].append({
                                'user': user,
                                'command': command.strip(),
                                'log_line': line
                            })
                
                # Parse syslog/messages
                elif result['log_type'] == 'system':
                    # Service started
                    if 'started' in line.lower() or 'starting' in line.lower():
                        syslog_events['service_starts'].append(line)
                    
                    # Service stopped
                    elif 'stopped' in line.lower() or 'stopping' in line.lower():
                        syslog_events['service_stops'].append(line)
                    
                    # Errors
                    elif 'error' in line.lower() or 'fail' in line.lower():
                        syslog_events['errors'].append(line)
                    
                    # Extract IP addresses
                    ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                    for ip in ip_matches:
                        # Filter out invalid IPs
                        parts = ip.split('.')
                        if all(0 <= int(p) <= 255 for p in parts):
                            if ip not in ['0.0.0.0', '127.0.0.1', '255.255.255.255']:
                                syslog_events['ip_addresses'].add(ip)
                                syslog_events['network_events'].append({
                                    'ip': ip,
                                    'log_line': line
                                })
        
        # Add parsed data to result
        if result['log_type'] == 'authentication':
            result['login_events'] = login_events
            # Detect security threats
            result['security_alerts'] = _detect_security_threats_textlog(login_events)
        
        elif result['log_type'] == 'system':
            syslog_events['ip_addresses'] = list(syslog_events['ip_addresses'])
            result['syslog_events'] = {
                'service_starts': len(syslog_events['service_starts']),
                'service_stops': len(syslog_events['service_stops']),
                'errors': len(syslog_events['errors']),
                'network_events': len(syslog_events['network_events']),
                'unique_ips': len(syslog_events['ip_addresses']),
                'top_ips': syslog_events['ip_addresses'][:20],
                'sample_errors': syslog_events['errors'][:10]
            }
        
        logger.info(f"Parsed {result['lines_parsed']} out of {result['total_lines']} lines from {filepath}")
        
    except Exception as e:
        logger.error(f"Error parsing log file {filepath}: {e}")
        result['error'] = str(e)
    
    return result


def _detect_security_threats_textlog(login_events):
    """Detect security threats from text log login events.
    
    Args:
        login_events: Dictionary with login event data
        
    Returns:
        dict: Security alerts and warnings
    """
    alerts = {
        'critical': [],
        'warnings': [],
        'info': []
    }
    
    failed_logins = login_events.get('failed_logins', [])
    successful_logins = login_events.get('successful_logins', [])
    
    # Check for failed login attempts
    if failed_logins:
        # First, identify invalid user attempts
        invalid_users = [e for e in failed_logins if e.get('reason') == 'invalid_user']
        
        # Group by IP (excluding invalid user attempts to avoid duplication)
        failed_by_ip = defaultdict(list)
        for event in failed_logins:
            # Skip invalid user attempts as they'll be reported separately
            if event.get('reason') == 'invalid_user':
                continue
            ip = event.get('ip_address', '-')
            if ip != '-':
                failed_by_ip[ip].append(event)
        
        # Detect brute force attempts (only for valid user attempts)
        for ip, events in failed_by_ip.items():
            if len(events) >= 5:
                alerts['critical'].append({
                    'type': 'brute_force_attempt',
                    'severity': 'critical',
                    'message': f"Brute force attack detected: {len(events)} failed attempts from IP {ip}",
                    'details': {
                        'ip_address': ip,
                        'attempt_count': len(events),
                        'targeted_users': list(set(e.get('user', 'unknown') for e in events))
                    }
                })
            elif len(events) >= 3:
                alerts['warnings'].append({
                    'type': 'suspicious_login_attempts',
                    'severity': 'warning',
                    'message': f"Suspicious login attempts ({len(events)}) from IP {ip}",
                    'details': {
                        'ip_address': ip,
                        'attempt_count': len(events),
                        'targeted_users': list(set(e.get('user', 'unknown') for e in events))
                    }
                })
        
        # Check for invalid user attempts (reported separately)
        if invalid_users:
            alerts['warnings'].append({
                'type': 'invalid_user_attempts',
                'severity': 'warning',
                'message': f"Attempts to login with invalid usernames ({len(invalid_users)} attempts)",
                'details': {
                    'attempt_count': len(invalid_users),
                    'usernames': list(set(e.get('user', 'unknown') for e in invalid_users))[:10],
                    'source_ips': list(set(e.get('ip_address', '-') for e in invalid_users))
                }
            })
    
    # Check for root logins
    for event in successful_logins:
        if event.get('user') == 'root':
            alerts['warnings'].append({
                'type': 'root_login',
                'severity': 'warning',
                'message': f"Root user login from IP {event.get('ip_address', 'unknown')}",
                'details': {
                    'ip_address': event.get('ip_address', 'unknown'),
                    'method': event.get('method', 'unknown')
                }
            })
    
    # Summary info
    if failed_logins:
        alerts['info'].append({
            'type': 'failed_login_summary',
            'severity': 'info',
            'message': f"Total failed login attempts: {len(failed_logins)}",
            'details': {
                'total_attempts': len(failed_logins),
                'unique_users': len(set(e.get('user', 'unknown') for e in failed_logins)),
                'unique_ips': len(set(e.get('ip_address', '-') for e in failed_logins if e.get('ip_address') != '-'))
            }
        })
    
    return alerts


def _detect_security_threats(login_events):
    """Detect security threats from login events.
    
    Args:
        login_events: Dictionary with login event data
        
    Returns:
        dict: Security alerts and warnings
    """
    alerts = {
        'critical': [],
        'warnings': [],
        'info': []
    }
    
    failed_logins = login_events.get('failed_logins', [])
    successful_logins = login_events.get('successful_logins', [])
    
    # Check for failed login attempts
    if failed_logins:
        # Group by user
        failed_by_user = defaultdict(list)
        for event in failed_logins:
            user = event.get('user', 'unknown')
            failed_by_user[user].append(event)
        
        # Group by IP
        failed_by_ip = defaultdict(list)
        for event in failed_logins:
            ip = event.get('ip_address', '-')
            if ip not in ['-', '127.0.0.1', '::1']:
                failed_by_ip[ip].append(event)
        
        # Track users with disabled account attempts to avoid duplicate alerts
        disabled_account_users = set()
        for user, events in failed_by_user.items():
            for event in events:
                if '%%2310' in event.get('failure_reason', ''):
                    disabled_account_users.add(user)
                    break
        
        # Detect brute force attempts (skip if it's just disabled account attempts)
        for ip, events in failed_by_ip.items():
            # Check if all events are from disabled accounts
            users_from_ip = set(e.get('user', 'unknown') for e in events)
            all_disabled = users_from_ip.issubset(disabled_account_users)
            
            # Only create IP-based alerts if not all attempts are to disabled accounts
            if not all_disabled:
                if len(events) >= 3:
                    alerts['critical'].append({
                        'type': 'brute_force_attempt',
                        'severity': 'critical',
                        'message': f"Multiple failed login attempts ({len(events)}) from IP {ip}",
                        'details': {
                            'ip_address': ip,
                            'attempt_count': len(events),
                            'targeted_users': list(set(e.get('user', 'unknown') for e in events))
                        }
                    })
                elif len(events) >= 2:
                    alerts['warnings'].append({
                        'type': 'suspicious_login_attempts',
                        'severity': 'warning',
                        'message': f"Suspicious login attempts ({len(events)}) from IP {ip}",
                        'details': {
                            'ip_address': ip,
                            'attempt_count': len(events),
                            'targeted_users': list(set(e.get('user', 'unknown') for e in events))
                        }
                    })
        
        # Detect disabled account attempts (consolidated per user)
        for user in disabled_account_users:
            events = [e for e in failed_by_user[user] if '%%2310' in e.get('failure_reason', '')]
            ips = list(set(e.get('ip_address', '-') for e in events if e.get('ip_address') not in ['-', '127.0.0.1', '::1']))
            
            # Determine if this is a guest account
            is_guest = 'guest' in user.lower()
            
            # Create a single consolidated alert per disabled account
            alerts['critical' if is_guest else 'warnings'].append({
                'type': 'disabled_account_attempt',
                'severity': 'critical' if is_guest else 'warning',
                'message': f"Failed login attempts to disabled account '{user}' ({len(events)} times)",
                'details': {
                    'user': user,
                    'attempt_count': len(events),
                    'source_ips': ips,
                    'timestamps': [e.get('timestamp', 'unknown') for e in events]
                }
            })
    
    # Check for administrator/privileged account logins
    for event in successful_logins:
        user = event.get('user', '').lower()
        if any(priv in user for priv in ['administrator', 'admin', 'root']):
            # Network logon (type 3) for admin accounts is suspicious
            if event.get('logon_type') == '3':
                alerts['warnings'].append({
                    'type': 'privileged_network_logon',
                    'severity': 'warning',
                    'message': f"Network logon for privileged account: {event.get('user')}",
                    'details': {
                        'user': event.get('user'),
                        'logon_type': '3 (Network)',
                        'timestamp': event.get('timestamp', 'unknown'),
                        'ip_address': event.get('ip_address', '-')
                    }
                })
    
    # Summary info
    if failed_logins:
        alerts['info'].append({
            'type': 'failed_login_summary',
            'severity': 'info',
            'message': f"Total failed login attempts: {len(failed_logins)}",
            'details': {
                'total_attempts': len(failed_logins),
                'unique_users': len(set(e.get('user', 'unknown') for e in failed_logins)),
                'unique_ips': len(set(e.get('ip_address', '-') for e in failed_logins if e.get('ip_address') not in ['-', '127.0.0.1', '::1']))
            }
        })
    
    return alerts


def parse_auth_log(fs, file_list):
    """Parse Linux auth.log for login attempts and SSH connections.
    
    Args:
        fs: PyTSK3 FS_Info object
        file_list: List of file metadata dictionaries
        
    Returns:
        dict: Login attempts with statistics
    """
    auth_data = {
        'successful_logins': [],
        'failed_logins': [],
        'ssh_connections': [],
        'sudo_commands': [],
        'user_frequency': defaultdict(int),
        'ip_frequency': defaultdict(int)
    }
    
    # Find auth.log files
    auth_log_paths = []
    for item in file_list:
        if item['type'] == 'file' and item['name'] in ['auth.log', 'secure']:
            if '/var/log/' in item['path']:
                auth_log_paths.append(item['path'])
    
    if not auth_log_paths:
        logger.debug("No auth.log files found")
        return auth_data
    
    # Parse each auth.log file
    for log_path in auth_log_paths:
        try:
            file_obj = fs.open(log_path)
            if file_obj and file_obj.info.meta.size > 0:
                # Read up to 5MB of logs
                size_to_read = min(file_obj.info.meta.size, 5 * 1024 * 1024)
                content = file_obj.read_random(0, size_to_read)
                text = content.decode('utf-8', errors='ignore')
                
                logger.info(f"Parsing {log_path}...")
                
                for line in text.split('\n'):
                    if not line.strip():
                        continue
                    
                    # Successful SSH logins
                    # Example: Jan 15 10:23:45 server sshd[1234]: Accepted password for alice from 192.168.1.100 port 54321 ssh2
                    ssh_success = re.search(r'sshd\[\d+\]:\s+Accepted\s+\w+\s+for\s+(\S+)\s+from\s+([\d.]+)', line)
                    if ssh_success:
                        user = ssh_success.group(1)
                        ip = ssh_success.group(2)
                        auth_data['successful_logins'].append({
                            'user': user,
                            'ip': ip,
                            'method': 'ssh',
                            'log_line': line[:150]
                        })
                        auth_data['user_frequency'][user] += 1
                        auth_data['ip_frequency'][ip] += 1
                        auth_data['ssh_connections'].append({'user': user, 'ip': ip})
                    
                    # Failed SSH logins
                    # Example: Jan 15 10:23:45 server sshd[1234]: Failed password for bob from 192.168.1.101 port 54322 ssh2
                    ssh_fail = re.search(r'sshd\[\d+\]:\s+Failed\s+password\s+for\s+(\S+)\s+from\s+([\d.]+)', line)
                    if ssh_fail:
                        user = ssh_fail.group(1)
                        ip = ssh_fail.group(2)
                        auth_data['failed_logins'].append({
                            'user': user,
                            'ip': ip,
                            'method': 'ssh',
                            'log_line': line[:150]
                        })
                        auth_data['ip_frequency'][ip] += 1
                    
                    # Invalid user attempts (common in brute force attacks)
                    invalid_user = re.search(r'Invalid user\s+(\S+)\s+from\s+([\d.]+)', line)
                    if invalid_user:
                        user = invalid_user.group(1)
                        ip = invalid_user.group(2)
                        auth_data['failed_logins'].append({
                            'user': user,
                            'ip': ip,
                            'method': 'ssh',
                            'reason': 'invalid_user',
                            'log_line': line[:150]
                        })
                        auth_data['ip_frequency'][ip] += 1
                    
                    # Sudo commands
                    # Example: Jan 15 10:23:45 server sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/cat /etc/shadow
                    sudo_cmd = re.search(r'sudo:\s+(\S+)\s+:.*COMMAND=(.+)$', line)
                    if sudo_cmd:
                        user = sudo_cmd.group(1)
                        command = sudo_cmd.group(2).strip()
                        auth_data['sudo_commands'].append({
                            'user': user,
                            'command': command
                        })
                
                logger.info(f"Parsed {len(auth_data['successful_logins'])} successful logins, {len(auth_data['failed_logins'])} failed attempts")
                
        except Exception as e:
            logger.debug(f"Could not parse {log_path}: {e}")
    
    return auth_data


def parse_syslog(fs, file_list):
    """Parse Linux syslog for network connections and system events.
    
    Args:
        fs: PyTSK3 FS_Info object
        file_list: List of file metadata dictionaries
        
    Returns:
        dict: Network connections and system events
    """
    syslog_data = {
        'network_connections': [],
        'service_events': [],
        'ip_frequency': defaultdict(int),
        'port_frequency': defaultdict(int)
    }
    
    # Find syslog files
    syslog_paths = []
    for item in file_list:
        if item['type'] == 'file' and item['name'] in ['syslog', 'messages']:
            if '/var/log/' in item['path']:
                syslog_paths.append(item['path'])
    
    if not syslog_paths:
        logger.debug("No syslog files found")
        return syslog_data
    
    # Parse each syslog file
    for log_path in syslog_paths:
        try:
            file_obj = fs.open(log_path)
            if file_obj and file_obj.info.meta.size > 0:
                # Read up to 5MB of logs
                size_to_read = min(file_obj.info.meta.size, 5 * 1024 * 1024)
                content = file_obj.read_random(0, size_to_read)
                text = content.decode('utf-8', errors='ignore')
                
                logger.info(f"Parsing {log_path}...")
                
                for line in text.split('\n'):
                    if not line.strip():
                        continue
                    
                    # Network service starts/stops
                    service_match = re.search(r'(started|stopped|listening on)\s+.*?(port\s+(\d+)|[\d.]+:(\d+))', line, re.IGNORECASE)
                    if service_match:
                        port = service_match.group(3) or service_match.group(4)
                        if port:
                            syslog_data['service_events'].append({
                                'event': service_match.group(1),
                                'port': int(port),
                                'log_line': line[:150]
                            })
                            syslog_data['port_frequency'][int(port)] += 1
                    
                    # Extract IP addresses from general log lines
                    ip_matches = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', line)
                    for ip in ip_matches:
                        # Filter out invalid IPs and localhost
                        parts = [int(x) for x in ip.split('.')]
                        if all(0 <= p <= 255 for p in parts) and ip not in ['0.0.0.0', '127.0.0.1', '255.255.255.255']:
                            syslog_data['ip_frequency'][ip] += 1
                
                logger.info(f"Found {len(syslog_data['service_events'])} service events")
                
        except Exception as e:
            logger.debug(f"Could not parse {log_path}: {e}")
    
    return syslog_data


def parse_windows_event_logs(fs, file_list):
    """Parse Windows event logs for login events and security information.
    
    Args:
        fs: PyTSK3 FS_Info object
        file_list: List of file metadata dictionaries
        
    Returns:
        dict: Windows event log information with parsed events
    """
    try:
        import Evtx.Evtx as evtx
        import Evtx.Views as evtx_views
        import xml.etree.ElementTree as ET
        has_evtx_library = True
    except ImportError:
        has_evtx_library = False
        logger.warning("python-evtx library not installed. Event log parsing limited.")
    
    event_data = {
        'login_events': {
            'successful_logins': [],
            'failed_logins': [],
            'logoffs': [],
            'user_frequency': defaultdict(int),
            'ip_frequency': defaultdict(int)
        },
        'security_events': [],
        'system_events': [],
        'event_log_files': [],
        'parsing_method': 'full' if has_evtx_library else 'basic'
    }
    
    # Find event log files
    security_logs = []
    system_logs = []
    
    for item in file_list:
        if item['type'] == 'file':
            name_lower = item['name'].lower()
            
            # Security logs (login events)
            if 'security' in name_lower and name_lower.endswith('.evtx'):
                security_logs.append(item)
                event_data['event_log_files'].append({
                    'path': item['path'],
                    'name': item['name'],
                    'type': 'security',
                    'size': item['size']
                })
                logger.info(f"Found Security log: {item['path']}")
            
            # System logs
            elif 'system' in name_lower and name_lower.endswith('.evtx'):
                system_logs.append(item)
                event_data['event_log_files'].append({
                    'path': item['path'],
                    'name': item['name'],
                    'type': 'system',
                    'size': item['size']
                })
                logger.info(f"Found System log: {item['path']}")
    
    if not has_evtx_library:
        event_data['note'] = 'Install python-evtx for full event log parsing: pip install python-evtx'
        return event_data
    
    # Parse Security logs for login events
    for log_item in security_logs:
        try:
            # Extract event log file to temporary location for parsing
            file_obj = fs.open(log_item['path'])
            if file_obj and file_obj.info.meta.size > 0:
                # Read the entire EVTX file (limit to 50MB for safety)
                max_size = min(file_obj.info.meta.size, 50 * 1024 * 1024)
                evtx_data = file_obj.read_random(0, max_size)
                
                # Save to temporary file for python-evtx parsing
                import tempfile
                with tempfile.NamedTemporaryFile(delete=False, suffix='.evtx') as tmp:
                    tmp.write(evtx_data)
                    tmp_path = tmp.name
                
                try:
                    logger.info(f"Parsing Security log: {log_item['path']}")
                    with evtx.Evtx(tmp_path) as log:
                        for record in log.records():
                            try:
                                xml_str = record.xml()
                                root = ET.fromstring(xml_str)
                                
                                # Extract Event ID
                                event_id_elem = root.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}EventID')
                                if event_id_elem is None:
                                    continue
                                
                                event_id = int(event_id_elem.text)
                                
                                # Event ID 4624: Successful login
                                if event_id == 4624:
                                    event_dict = _parse_login_event_4624(root)
                                    if event_dict:
                                        event_data['login_events']['successful_logins'].append(event_dict)
                                        if event_dict.get('user'):
                                            event_data['login_events']['user_frequency'][event_dict['user']] += 1
                                        if event_dict.get('source_ip'):
                                            event_data['login_events']['ip_frequency'][event_dict['source_ip']] += 1
                                
                                # Event ID 4625: Failed login
                                elif event_id == 4625:
                                    event_dict = _parse_login_event_4625(root)
                                    if event_dict:
                                        event_data['login_events']['failed_logins'].append(event_dict)
                                        if event_dict.get('source_ip'):
                                            event_data['login_events']['ip_frequency'][event_dict['source_ip']] += 1
                                
                                # Event ID 4634/4647: Logoff
                                elif event_id in [4634, 4647]:
                                    event_dict = _parse_logoff_event(root)
                                    if event_dict:
                                        event_data['login_events']['logoffs'].append(event_dict)
                                
                                # Other security events (limited to first 100)
                                elif len(event_data['security_events']) < 100:
                                    event_data['security_events'].append({
                                        'event_id': event_id,
                                        'timestamp': _extract_timestamp(root)
                                    })
                                
                            except Exception as e:
                                logger.debug(f"Error parsing event record: {e}")
                                continue
                    
                    logger.info(f"Parsed {len(event_data['login_events']['successful_logins'])} successful logins, "
                              f"{len(event_data['login_events']['failed_logins'])} failed logins")
                    
                finally:
                    # Clean up temp file
                    import os
                    try:
                        os.unlink(tmp_path)
                    except:
                        pass
                        
        except Exception as e:
            logger.warning(f"Could not parse {log_item['path']}: {e}")
    
    return event_data


def _parse_login_event_4624(root):
    """Parse Event ID 4624 (Successful Login)."""
    try:
        ns = {'evt': 'http://schemas.microsoft.com/win/2004/08/events/event'}
        
        # Extract fields from EventData
        data_elements = root.findall('.//evt:Data', ns)
        data_dict = {}
        for elem in data_elements:
            name = elem.get('Name')
            if name:
                data_dict[name] = elem.text or ''
        
        # Get relevant fields
        target_user = data_dict.get('TargetUserName', 'Unknown')
        target_domain = data_dict.get('TargetDomainName', '')
        source_ip = data_dict.get('IpAddress', '-')
        logon_type = data_dict.get('LogonType', '0')
        
        # Skip system accounts
        if target_user.endswith('$') or target_user in ['SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE']:
            return None
        
        full_user = f"{target_domain}\\{target_user}" if target_domain else target_user
        
        return {
            'user': full_user,
            'source_ip': source_ip if source_ip and source_ip != '-' else None,
            'logon_type': logon_type,
            'timestamp': _extract_timestamp(root)
        }
    except Exception as e:
        logger.debug(f"Error parsing 4624 event: {e}")
        return None


def _parse_login_event_4625(root):
    """Parse Event ID 4625 (Failed Login)."""
    try:
        ns = {'evt': 'http://schemas.microsoft.com/win/2004/08/events/event'}
        
        data_elements = root.findall('.//evt:Data', ns)
        data_dict = {}
        for elem in data_elements:
            name = elem.get('Name')
            if name:
                data_dict[name] = elem.text or ''
        
        target_user = data_dict.get('TargetUserName', 'Unknown')
        source_ip = data_dict.get('IpAddress', '-')
        failure_reason = data_dict.get('FailureReason', '')
        status = data_dict.get('Status', '')
        
        return {
            'user': target_user,
            'source_ip': source_ip if source_ip and source_ip != '-' else None,
            'failure_reason': failure_reason,
            'status': status,
            'timestamp': _extract_timestamp(root)
        }
    except Exception as e:
        logger.debug(f"Error parsing 4625 event: {e}")
        return None


def _parse_logoff_event(root):
    """Parse Event ID 4634/4647 (Logoff)."""
    try:
        ns = {'evt': 'http://schemas.microsoft.com/win/2004/08/events/event'}
        
        data_elements = root.findall('.//evt:Data', ns)
        data_dict = {}
        for elem in data_elements:
            name = elem.get('Name')
            if name:
                data_dict[name] = elem.text or ''
        
        target_user = data_dict.get('TargetUserName', 'Unknown')
        
        return {
            'user': target_user,
            'timestamp': _extract_timestamp(root)
        }
    except Exception as e:
        logger.debug(f"Error parsing logoff event: {e}")
        return None


def _extract_timestamp(root):
    """Extract timestamp from event XML."""
    try:
        ns = {'evt': 'http://schemas.microsoft.com/win/2004/08/events/event'}
        time_elem = root.find('.//evt:TimeCreated', ns)
        if time_elem is not None:
            return time_elem.get('SystemTime', '')
    except:
        pass
    return None


def parse_windows_powershell_logs(fs, file_list):
    """Parse Windows PowerShell logs for executed commands.
    
    Args:
        fs: PyTSK3 FS_Info object
        file_list: List of file metadata dictionaries
        
    Returns:
        dict: PowerShell execution logs
    """
    ps_data = {
        'execution_events': [],
        'user_frequency': defaultdict(int)
    }
    
    # Look for PowerShell operational logs
    for item in file_list:
        if item['type'] == 'file':
            # PowerShell logs are typically in Windows/System32/winevt/Logs/
            if 'PowerShell' in item['path'] and item['name'].endswith('.evtx'):
                ps_data['execution_events'].append({
                    'log_file': item['path'],
                    'size': item['size'],
                    'note': 'Requires python-evtx for full parsing'
                })
                logger.info(f"Found PowerShell log: {item['path']}")
    
    return ps_data


def analyze_login_patterns(auth_data, syslog_data, windows_events=None):
    """Analyze login patterns and detect anomalies (Linux and Windows).
    
    Args:
        auth_data: Parsed authentication log data (Linux auth.log)
        syslog_data: Parsed syslog data
        windows_events: Parsed Windows event logs (optional)
        
    Returns:
        dict: Analysis results with statistics and anomalies
    """
    # Merge Windows event data if available
    if windows_events and 'login_events' in windows_events:
        win_login = windows_events['login_events']
        # Merge successful logins
        for login in win_login.get('successful_logins', []):
            auth_data['successful_logins'].append(login)
        # Merge failed logins
        for login in win_login.get('failed_logins', []):
            auth_data['failed_logins'].append(login)
        # Merge frequencies
        for user, count in win_login.get('user_frequency', {}).items():
            auth_data['user_frequency'][user] += count
        for ip, count in win_login.get('ip_frequency', {}).items():
            auth_data['ip_frequency'][ip] += count
    
    analysis = {
        'total_successful_logins': len(auth_data['successful_logins']),
        'total_failed_logins': len(auth_data['failed_logins']),
        'unique_users': len(auth_data['user_frequency']),
        'unique_ips': len(auth_data['ip_frequency']),
        'top_users': [],
        'top_ips': [],
        'suspicious_activity': [],
        'brute_force_candidates': []
    }
    
    # Get top users by login frequency
    sorted_users = sorted(auth_data['user_frequency'].items(), key=lambda x: x[1], reverse=True)
    analysis['top_users'] = [
        {'user': user, 'login_count': count}
        for user, count in sorted_users[:10]
    ]
    
    # Get top IPs by connection frequency
    # Merge IP frequencies from auth and syslog
    combined_ip_freq = defaultdict(int)
    for ip, count in auth_data['ip_frequency'].items():
        combined_ip_freq[ip] += count
    for ip, count in syslog_data['ip_frequency'].items():
        combined_ip_freq[ip] += count
    
    sorted_ips = sorted(combined_ip_freq.items(), key=lambda x: x[1], reverse=True)
    analysis['top_ips'] = [
        {'ip': ip, 'connection_count': count}
        for ip, count in sorted_ips[:10]
    ]
    
    # Detect potential brute force attacks (IPs with many failed login attempts)
    failed_by_ip = defaultdict(int)
    for failed in auth_data['failed_logins']:
        failed_by_ip[failed['ip']] += 1
    
    for ip, fail_count in failed_by_ip.items():
        if fail_count >= 5:  # Threshold for suspicious activity
            successful_count = sum(1 for s in auth_data['successful_logins'] if s['ip'] == ip)
            analysis['brute_force_candidates'].append({
                'ip': ip,
                'failed_attempts': fail_count,
                'successful_attempts': successful_count,
                'risk_level': 'high' if fail_count >= 10 else 'medium'
            })
    
    # Detect logins from unusual IPs (IPs that appear in failed but not successful)
    failed_ips = set(failed_by_ip.keys())
    successful_ips = set(s['ip'] for s in auth_data['successful_logins'])
    
    # IPs with only failed attempts (possible scanning)
    scanning_ips = failed_ips - successful_ips
    for ip in scanning_ips:
        if failed_by_ip[ip] >= 3:
            analysis['suspicious_activity'].append({
                'type': 'scanning',
                'ip': ip,
                'failed_attempts': failed_by_ip[ip],
                'description': 'IP with only failed login attempts (possible scanning/brute force)'
            })
    
    # Detect invalid user attempts (common in attacks)
    invalid_user_count = sum(1 for f in auth_data['failed_logins'] if f.get('reason') == 'invalid_user')
    if invalid_user_count > 0:
        analysis['suspicious_activity'].append({
            'type': 'invalid_users',
            'count': invalid_user_count,
            'description': 'Attempts to login as non-existent users'
        })
    
    logger.info(f"Login analysis: {analysis['total_successful_logins']} successful, {analysis['total_failed_logins']} failed")
    logger.info(f"Found {len(analysis['brute_force_candidates'])} potential brute force attacks")
    
    return analysis


def extract_log_intelligence(fs, file_list, os_type):
    """Main function to extract intelligence from log files.
    
    Args:
        fs: PyTSK3 FS_Info object
        file_list: List of file metadata dictionaries
        os_type: Detected OS type
        
    Returns:
        dict: Comprehensive log analysis
    """
    logger.info("Extracting log intelligence...")
    
    log_intelligence = {
        'os_type': os_type,
        'logs_analyzed': [],
        'login_data': {},
        'network_data': {},
        'pattern_analysis': {},
        'windows_events': {}
    }
    
    if os_type == 'linux':
        # Parse Linux logs
        logger.info("Parsing Linux authentication logs...")
        auth_data = parse_auth_log(fs, file_list)
        log_intelligence['login_data'] = auth_data
        log_intelligence['logs_analyzed'].append('auth.log')
        
        logger.info("Parsing Linux syslog...")
        syslog_data = parse_syslog(fs, file_list)
        log_intelligence['network_data'] = syslog_data
        log_intelligence['logs_analyzed'].append('syslog')
        
        # Analyze patterns
        if auth_data['successful_logins'] or auth_data['failed_logins']:
            logger.info("Analyzing login patterns...")
            pattern_analysis = analyze_login_patterns(auth_data, syslog_data)
            log_intelligence['pattern_analysis'] = pattern_analysis
    
    elif os_type == 'windows':
        # Parse Windows Event Logs
        logger.info("Parsing Windows event logs...")
        event_data = parse_windows_event_logs(fs, file_list)
        log_intelligence['windows_events'] = event_data
        
        if event_data['event_log_files']:
            log_intelligence['logs_analyzed'].extend([e['name'] for e in event_data['event_log_files']])
        
        # Analyze login patterns from Windows events
        if event_data.get('login_events'):
            logger.info("Analyzing Windows login patterns...")
            # Create empty auth_data and syslog_data for compatibility
            empty_auth = {
                'successful_logins': [],
                'failed_logins': [],
                'user_frequency': defaultdict(int),
                'ip_frequency': defaultdict(int)
            }
            empty_syslog = {'ip_frequency': defaultdict(int)}
            
            pattern_analysis = analyze_login_patterns(empty_auth, empty_syslog, windows_events=event_data)
            log_intelligence['pattern_analysis'] = pattern_analysis
        
        # Parse PowerShell logs
        ps_data = parse_windows_powershell_logs(fs, file_list)
        if ps_data['execution_events']:
            log_intelligence['windows_events']['powershell_logs'] = ps_data
    
    logger.info(f"Log intelligence extraction complete. Analyzed: {', '.join(log_intelligence['logs_analyzed']) if log_intelligence['logs_analyzed'] else 'none'}")
    
    return log_intelligence
