# log_analyzer.py - Log file analysis module for login attempts, network connections, and user activity

import logging
import re
import os
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
            if failure_reason and not failure_reason.startswith('%%'):
                result['failure_reason'] = failure_reason
            elif status:
                result['failure_reason'] = f"Status: {status}"
        
        # A failed logon is evidence even when Windows did not record the account name
        # (TargetUserName is "-"), so keep it instead of dropping it
        if event_id == 4625 and not result.get('user'):
            result['user'] = '(unknown account)'
        if event_id == 4625 and event_data.get('LogonType'):
            result['logon_type'] = event_data['LogonType']

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
        
        # sshd writes "Invalid user X" once per connection and then a "Failed password for
        # invalid user X" line for every attempt. Connections that have the latter are
        # counted from those lines only, so each attempt is counted exactly once.
        invalid_pw_pids = set()
        if result['log_type'] == 'authentication':
            with open(filepath, 'r', errors='ignore') as f:
                for raw in f:
                    m = re.search(r'sshd\[(\d+)\]:\s+Failed password for invalid user', raw)
                    if m:
                        invalid_pw_pids.add(m.group(1))

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
                                'service': 'ssh',
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
                                'invalid_user': 'for invalid user' in line,
                                'service': 'ssh',
                                'log_line': line
                            })
                            login_events['user_frequency'][user] += 1
                            login_events['ip_frequency'][ip] += 1
                        # Invalid user
                        elif 'Invalid user' in line:
                            match = re.search(r'sshd\[(\d+)\]:\s+Invalid user (\S+) from ([\d\.]+)', line)
                            if match and match.group(1) in invalid_pw_pids:
                                match = None   # its attempts are counted from the "Failed password" lines
                            if match:
                                _, user, ip = match.groups()
                                login_events['failed_logins'].append({
                                    'user': user,
                                    'ip_address': ip,
                                    'reason': 'invalid_user',
                                    'invalid_user': True,
                                    'service': 'ssh',
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
        invalid_users = [e for e in failed_logins
                         if e.get('invalid_user') or e.get('reason') == 'invalid_user']
        
        # Group by IP: every attempt counts once (each attempt is a single failed_logins entry)
        failed_by_ip = defaultdict(list)
        for event in failed_logins:
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