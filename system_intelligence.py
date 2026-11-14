# system_intelligence.py - Extract system information and user profiles from disk images

import pytsk3
import logging
import re
from analysis_status import report_start, report_partial, report_failed, report_not_run

logger = logging.getLogger(__name__)

MAX_HISTORY_READ = 1024 * 1024  # history files are read up to this size

# The root account has its home outside /home (it is not found as a user profile),
# but its shell history is one of the most interesting ones. Its files are read as user "root".
ROOT_HOME_PREFIX = {'linux': '/root/', 'macos': '/var/root/'}


def detect_os_type(fs):
    """Detect operating system type from filesystem structure.
    
    Args:
        fs: PyTSK3 FS_Info object
        
    Returns:
        str: OS type ('windows', 'linux', 'macos', 'unknown')
    """
    try:
        # Check for Windows indicators
        try:
            fs.open("/Windows")
            return 'windows'
        except:
            pass
        
        try:
            fs.open("/WINDOWS")
            return 'windows'
        except:
            pass
        
        # NTFS is the Windows filesystem (also covers a volume without a Windows folder)
        try:
            if fs.info.ftype in (pytsk3.TSK_FS_TYPE_NTFS, pytsk3.TSK_FS_TYPE_NTFS_DETECT):
                return 'windows'
        except Exception:
            pass

        # Check for macOS indicators
        try:
            fs.open("/Applications")
            # Double-check with another macOS-specific directory
            try:
                fs.open("/Library")
                return 'macos'
            except:
                pass
        except:
            pass
        
        try:
            fs.open("/System/Library")
            return 'macos'
        except:
            pass
        
        # Check for Linux indicators
        try:
            fs.open("/etc")
            # Make sure it's not macOS (which also has /etc)
            try:
                fs.open("/Applications")
                return 'macos'
            except:
                return 'linux'
        except:
            pass
        
        try:
            fs.open("/bin")
            return 'linux'
        except:
            pass
            
        # A Users folder without any Linux/macOS layout points to a Windows data volume
        try:
            fs.open("/Users")
            return 'windows'
        except Exception:
            pass

    except Exception as e:
        logger.debug(f"Error detecting OS type: {e}")
    
    return 'unknown'


def extract_hostname_linux(fs):
    """Extract hostname from Linux/Unix filesystem.
    
    Args:
        fs: PyTSK3 FS_Info object
        
    Returns:
        str or None: Hostname if found
    """
    try:
        # Try /etc/hostname (Linux and modern macOS)
        file_obj = fs.open("/etc/hostname")
        if file_obj and file_obj.info.meta.size > 0:
            content = file_obj.read_random(0, min(file_obj.info.meta.size, 1024))
            hostname = content.decode('utf-8', errors='ignore').strip()
            if hostname:
                logger.info(f"Found hostname: {hostname}")
                return hostname
    except Exception as e:
        logger.debug(f"Could not read /etc/hostname: {e}")
    
    return None


def extract_hostname_windows(fs):
    """Extract hostname from Windows filesystem.
    
    Args:
        fs: PyTSK3 FS_Info object
        
    Returns:
        str or None: Hostname if found
    """
    
    paths_to_check = [
        "/Windows/System32/config/SAM",
        "/WINDOWS/system32/config/SAM",
    ]

    logger.debug("Windows hostname extraction requires registry parsing (not fully implemented)")
    
    return None


def enumerate_user_profiles_windows(fs, file_list):
    """Enumerate Windows user profiles from Users directory.
    
    Args:
        fs: PyTSK3 FS_Info object
        file_list: List of file metadata dictionaries
        
    Returns:
        list: List of username strings
    """
    users = []
    
    # Find directories under /Users
    for item in file_list:
        if item['type'] == 'dir':
            path = item['path'].upper()
            
            # Check for /Users/username pattern
            if path.startswith('/USERS/') and path.count('/') == 2:
                username = item['name']
                
                # Skip system directories
                system_dirs = ['PUBLIC', 'DEFAULT', 'DEFAULT USER', 'ALL USERS']
                if username.upper() not in system_dirs:
                    users.append(username)
                    logger.info(f"Found Windows user profile: {username}")
    
    return sorted(set(users))


def enumerate_user_profiles_linux(fs, file_list):
    """Enumerate Linux user profiles from /home directory.
    
    Args:
        fs: PyTSK3 FS_Info object
        file_list: List of file metadata dictionaries
        
    Returns:
        list: List of username strings
    """
    users = []
    
    # Find directories under /home
    for item in file_list:
        if item['type'] == 'dir':
            path = item['path']
            
            # Check for /home/username pattern
            if path.startswith('/home/') and path.count('/') == 2:
                username = item['name']
                users.append(username)
                logger.info(f"Found Linux user profile: {username}")
    
    return sorted(set(users))


def extract_os_version_linux(fs):
    """Extract Linux OS version from /etc/os-release.
    
    Args:
        fs: PyTSK3 FS_Info object
        
    Returns:
        dict: OS information (name, version, etc.)
    """
    os_info = {}
    
    try:
        file_obj = fs.open("/etc/os-release")
        if file_obj and file_obj.info.meta.size > 0:
            content = file_obj.read_random(0, min(file_obj.info.meta.size, 4096))
            text = content.decode('utf-8', errors='ignore')
            
            for line in text.split('\n'):
                if '=' in line:
                    key, value = line.split('=', 1)
                    value = value.strip().strip('"')
                    if key == 'NAME':
                        os_info['name'] = value
                    elif key == 'VERSION':
                        os_info['version'] = value
                    elif key == 'VERSION_ID':
                        os_info['version_id'] = value
            
            logger.info(f"Found Linux OS info: {os_info.get('name', 'Unknown')}")
            return os_info
            
    except Exception as e:
        logger.debug(f"Could not read /etc/os-release: {e}")
    
    # Try alternative files
    try:
        file_obj = fs.open("/etc/lsb-release")
        if file_obj and file_obj.info.meta.size > 0:
            content = file_obj.read_random(0, min(file_obj.info.meta.size, 4096))
            text = content.decode('utf-8', errors='ignore')
            
            for line in text.split('\n'):
                if 'DISTRIB_DESCRIPTION' in line and '=' in line:
                    value = line.split('=', 1)[1].strip().strip('"')
                    os_info['name'] = value
                    logger.info(f"Found Linux OS from lsb-release: {value}")
                    return os_info
    except Exception as e:
        logger.debug(f"Could not read /etc/lsb-release: {e}")
    
    return os_info


def enumerate_user_profiles_macos(fs, file_list):
    """Enumerate macOS user profiles from /Users directory.
    
    Args:
        fs: PyTSK3 FS_Info object
        file_list: List of file metadata dictionaries
        
    Returns:
        list: List of username strings
    """
    users = []
    
    # Find directories under /Users
    for item in file_list:
        if item['type'] == 'dir':
            path = item['path']
            
            # Check for /Users/username pattern
            if path.startswith('/Users/') and path.count('/') == 2:
                username = item['name']
                
                # Skip system directories
                system_dirs = ['Shared', 'Guest', '.localized']
                if username not in system_dirs:
                    users.append(username)
                    logger.info(f"Found macOS user profile: {username}")
    
    return sorted(set(users))


def extract_os_version_macos(fs):
    """Extract macOS version from SystemVersion.plist.
    
    Args:
        fs: PyTSK3 FS_Info object
        
    Returns:
        dict: OS information (name, version, etc.)
    """
    os_info = {}
    
    try:
        file_obj = fs.open("/System/Library/CoreServices/SystemVersion.plist")
        if file_obj and file_obj.info.meta.size > 0:
            content = file_obj.read_random(0, min(file_obj.info.meta.size, 8192))
            text = content.decode('utf-8', errors='ignore')
            
            # Simple regex parsing of plist
            product_name_match = re.search(r'<key>ProductName</key>\s*<string>([^<]+)</string>', text)
            if product_name_match:
                os_info['name'] = product_name_match.group(1)
            
            version_match = re.search(r'<key>ProductVersion</key>\s*<string>([^<]+)</string>', text)
            if version_match:
                os_info['version'] = version_match.group(1)
            
            build_match = re.search(r'<key>ProductBuildVersion</key>\s*<string>([^<]+)</string>', text)
            if build_match:
                os_info['build'] = build_match.group(1)
            
            if os_info.get('name'):
                logger.info(f"Found macOS info: {os_info.get('name')} {os_info.get('version', '')}")
            return os_info
            
    except Exception as e:
        logger.debug(f"Could not read SystemVersion.plist: {e}")
    
    return os_info


def extract_command_history(fs, file_list, os_type, user_profiles, status=None):
    """Extract command history from shell history files.

    Args:
        fs: PyTSK3 FS_Info object
        file_list: List of file metadata dictionaries
        os_type: Detected OS type
        user_profiles: List of user profile names
        status: Optional AnalysisStatus; receives a report for every history file
            that was skipped, cut or unreadable

    Returns:
        dict: Command history organized by user
    """
    history_data = {}
    report_start(status, 'command_history')

    # Define history file patterns based on OS
    if os_type == 'linux' or os_type == 'macos':
        history_files = ['.bash_history', '.zsh_history', '.history', '.sh_history']
        home_root = '/Users' if os_type == 'macos' else '/home'
    elif os_type == 'windows':
        # PowerShell history location
        history_files = ['ConsoleHost_history.txt']
        home_root = '/Users'
    else:
        report_not_run(status, 'command_history', f"Operating system not recognised ({os_type})")
        return history_data

    # Search for history files in user directories
    for item in file_list:
        if item['type'] != 'file':
            continue

        filename = item['name']
        path = item['path']

        # Check if this is a history file
        if filename not in history_files:
            continue

        # Determine which user this belongs to
        user = None
        for username in user_profiles:
            if os_type == 'windows':
                if f'/Users/{username}/' in path or f'/Users/{username}\\' in path:
                    user = username
                    break
            else:
                if f'{home_root}/{username}/' in path:
                    user = username
                    break

        if not user and os_type in ROOT_HOME_PREFIX and path.startswith(ROOT_HOME_PREFIX[os_type]):
            user = 'root'

        if not user:
            report_partial(status, 'command_history',
                           "History file outside the known user profiles was not analysed",
                           example=path)
            continue

        # Read and parse the history file
        try:
            file_obj = fs.open(path)
            if file_obj and file_obj.info.meta.size > 0:
                # Read up to 1MB of history
                size_to_read = min(file_obj.info.meta.size, MAX_HISTORY_READ)
                if file_obj.info.meta.size > MAX_HISTORY_READ:
                    report_partial(status, 'command_history',
                                   "History file larger than 1 MB: only the first 1 MB was analysed "
                                   "(the newest commands are at the end of the file)",
                                   example=path)
                content = file_obj.read_random(0, size_to_read)
                text = content.decode('utf-8', errors='ignore')
                
                # Parse commands
                commands = []
                for line in text.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        commands.append(line)
                
                if commands:
                    if user not in history_data:
                        history_data[user] = {
                            'windows': os_type == 'windows',
                            'files': [],
                            'commands': [],
                            'total_commands': 0
                        }
                    
                    history_data[user]['files'].append({
                        'path': path,
                        'filename': filename,
                        'command_count': len(commands)
                    })
                    history_data[user]['commands'].extend(commands)
                    history_data[user]['total_commands'] += len(commands)
                    
                    logger.info(f"Found {len(commands)} commands in {path}")
                    
        except Exception as e:
            logger.debug(f"Could not read history file {path}: {e}")
            report_partial(status, 'command_history',
                           "History file could not be read",
                           example=f"{path} ({e})")

    return history_data


def analyze_command_history(history_data):
    """Analyze command history with the same rules the memory analysis uses.

    Args:
        history_data: Command history organized by user

    Returns:
        dict: Analysis results. suspicious_commands is grouped by command
        (each entry lists reasons, severity and the users who ran it).
    """
    # Imported here so the shared rule set stays in memory_analyzer.py
    from memory_analyzer import (SUSPICIOUS_COMMAND_RULES, WINDOWS_COMMAND_RULES,
                                 analyze_shell_command, group_suspicious_commands)

    analysis = {
        'total_users_with_history': len(history_data),
        'total_commands': 0,
        'suspicious_commands': [],
        'network_commands': [],
        'file_operations': [],
        'most_common': []
    }

    network_patterns = [
        r'\b(ssh|scp|ftp|telnet|nc|netcat)\b',
        r'\b(wget|curl)\b',
        r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'  # IP addresses
    ]
    file_op_patterns = [r'\b(rm|mv|cp|mkdir|touch|chmod|chown)\b']

    command_freq = {}
    findings = []

    for user, data in history_data.items():
        rules = WINDOWS_COMMAND_RULES if data.get('windows') else SUSPICIOUS_COMMAND_RULES
        for cmd in data['commands']:
            analysis['total_commands'] += 1

            cmd_name = cmd.split()[0] if cmd.split() else cmd
            command_freq[cmd_name] = command_freq.get(cmd_name, 0) + 1

            for finding in analyze_shell_command(cmd, rules):
                findings.append({
                    'command': cmd,
                    'reason': finding['reason'],
                    'severity': finding['severity'],
                    'pid': user,       # grouping key: who ran it
                })

            if any(re.search(p, cmd, re.IGNORECASE) for p in network_patterns):
                analysis['network_commands'].append({'user': user, 'command': cmd[:100]})
            if any(re.search(p, cmd, re.IGNORECASE) for p in file_op_patterns):
                analysis['file_operations'].append({'user': user, 'command': cmd[:100]})

    grouped = group_suspicious_commands(findings)
    for item in grouped:
        item['users'] = item.pop('pids')
        for key in ('processes', 'times', 'sources', 'by_pid'):
            item.pop(key, None)
    analysis['suspicious_commands'] = grouped

    sorted_commands = sorted(command_freq.items(), key=lambda x: x[1], reverse=True)
    analysis['most_common'] = [
        {'command': cmd, 'count': count}
        for cmd, count in sorted_commands[:10]
    ]

    return analysis


def _run_step(status, stage, description, func, default, *args):
    """Run one extraction step; a failure is reported and replaced by `default`.

    One failing step (for example an unreadable /etc/os-release) must not discard
    what the other steps found, and it must not stay hidden in the log only.
    """
    try:
        return func(*args)
    except Exception as e:
        logger.warning(f"{description} failed: {e}")
        report_failed(status, stage, f"{description} failed", example=f"{type(e).__name__}: {e}")
        return default


def extract_system_intelligence(fs, file_list, status=None):
    """Extract system information and user profiles from filesystem.

    Args:
        fs: PyTSK3 FS_Info object
        file_list: List of file metadata dictionaries
        status: Optional AnalysisStatus; receives a report for every item that
            could not be determined, so that missing data is visible in the output

    Returns:
        dict: System intelligence data
    """
    logger.info("Extracting system intelligence...")
    report_start(status, 'system_intelligence')

    intelligence = {
        'os_type': None,
        'hostname': None,
        'os_info': {},
        'user_profiles': [],
        'command_history': {},
        'command_analysis': {}
    }

    # Detect OS type
    os_type = detect_os_type(fs)
    intelligence['os_type'] = os_type
    logger.info(f"Detected OS type: {os_type}")

    # Extract OS-specific information
    if os_type == 'unknown':
        report_partial(status, 'system_intelligence',
                       "Operating system was not recognised: OS details, user profiles and "
                       "command history could not be extracted")
    elif os_type == 'linux':
        intelligence['hostname'] = _run_step(status, 'system_intelligence', "Reading the hostname",
                                             extract_hostname_linux, None, fs)
        intelligence['os_info'] = _run_step(status, 'system_intelligence', "Reading the OS version",
                                            extract_os_version_linux, {}, fs)
        intelligence['user_profiles'] = _run_step(status, 'system_intelligence', "Listing user profiles",
                                                  enumerate_user_profiles_linux, [], fs, file_list)

    elif os_type == 'windows':
        intelligence['hostname'] = _run_step(status, 'system_intelligence', "Reading the hostname",
                                             extract_hostname_windows, None, fs)
        intelligence['user_profiles'] = _run_step(status, 'system_intelligence', "Listing user profiles",
                                                  enumerate_user_profiles_windows, [], fs, file_list)
    elif os_type == 'macos':
        intelligence['hostname'] = _run_step(status, 'system_intelligence', "Reading the hostname",
                                             extract_hostname_linux, None, fs)  # macOS also uses /etc/hostname
        intelligence['os_info'] = _run_step(status, 'system_intelligence', "Reading the OS version",
                                            extract_os_version_macos, {}, fs)
        intelligence['user_profiles'] = _run_step(status, 'system_intelligence', "Listing user profiles",
                                                  enumerate_user_profiles_macos, [], fs, file_list)

    # Items that the code looked for but did not find (only reported for recognised systems)
    if os_type in ('linux', 'macos'):
        if not intelligence['hostname']:
            report_partial(status, 'system_intelligence', "Hostname not found (/etc/hostname missing or empty)")
        if not intelligence['os_info']:
            report_partial(status, 'system_intelligence',
                           "OS name and version not found (/etc/os-release, /etc/lsb-release or SystemVersion.plist)")
    if os_type != 'unknown' and not intelligence['user_profiles']:
        report_partial(status, 'system_intelligence', "No user profiles found")

    # Extract command history if users were found (on Linux/macOS also when only root exists)
    if intelligence['user_profiles'] or os_type in ROOT_HOME_PREFIX:
        logger.info("Extracting command history...")
        history_data = _run_step(status, 'command_history', "Reading command history",
                                 extract_command_history, {}, fs, file_list, os_type,
                                 intelligence['user_profiles'], status)
        intelligence['command_history'] = history_data

        if history_data:
            intelligence['command_analysis'] = _run_step(
                status, 'command_history', "Analysing command history for suspicious commands",
                analyze_command_history, {}, history_data)
            logger.info(f"Found command history for {len(history_data)} users")
    else:
        reason = ("Operating system not recognised" if os_type == 'unknown'
                  else "No user profiles found, so no history files were searched")
        report_not_run(status, 'command_history', reason)

    # Log summary
    logger.info(f"System intelligence summary: OS={os_type}, Users={len(intelligence['user_profiles'])}")
    
    return intelligence