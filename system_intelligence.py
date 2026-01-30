# system_intelligence.py - Extract system information and user profiles from disk images

import pytsk3
import logging
import re

logger = logging.getLogger(__name__)


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
    # Note: Full Windows registry parsing would require the Registry library
    # For now, we'll try to find it in common text files or use a simplified approach
    
    paths_to_check = [
        "/Windows/System32/config/SAM",
        "/WINDOWS/system32/config/SAM",
    ]
    
    # This is a simplified implementation
    # A full implementation would parse the SYSTEM registry hive
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
        # Try /etc/os-release (modern systems)
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
        # Try /System/Library/CoreServices/SystemVersion.plist
        file_obj = fs.open("/System/Library/CoreServices/SystemVersion.plist")
        if file_obj and file_obj.info.meta.size > 0:
            content = file_obj.read_random(0, min(file_obj.info.meta.size, 8192))
            text = content.decode('utf-8', errors='ignore')
            
            # Simple regex parsing of plist (proper parsing would use plistlib)
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


def extract_command_history(fs, file_list, os_type, user_profiles):
    """Extract command history from shell history files.
    
    Args:
        fs: PyTSK3 FS_Info object
        file_list: List of file metadata dictionaries
        os_type: Detected OS type
        user_profiles: List of user profile names
        
    Returns:
        dict: Command history organized by user
    """
    history_data = {}
    
    # Define history file patterns based on OS
    if os_type == 'linux' or os_type == 'macos':
        history_files = ['.bash_history', '.zsh_history', '.history', '.sh_history']
    elif os_type == 'windows':
        # PowerShell history location
        history_files = ['ConsoleHost_history.txt']
    else:
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
                if f'/home/{username}/' in path:
                    user = username
                    break
        
        if not user:
            continue
        
        # Read and parse the history file
        try:
            file_obj = fs.open(path)
            if file_obj and file_obj.info.meta.size > 0:
                # Read up to 1MB of history
                size_to_read = min(file_obj.info.meta.size, 1024 * 1024)
                content = file_obj.read_random(0, size_to_read)
                text = content.decode('utf-8', errors='ignore')
                
                # Parse commands (each line is typically a command)
                commands = []
                for line in text.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('#'):  # Skip comments
                        commands.append(line)
                
                if commands:
                    if user not in history_data:
                        history_data[user] = {
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
    
    return history_data


def analyze_command_history(history_data):
    """Analyze command history for interesting patterns.
    
    Args:
        history_data: Command history organized by user
        
    Returns:
        dict: Analysis results
    """
    analysis = {
        'total_users_with_history': len(history_data),
        'total_commands': 0,
        'suspicious_commands': [],
        'network_commands': [],
        'file_operations': [],
        'most_common': []
    }
    
    # Patterns for suspicious activities
    suspicious_patterns = [
        # Download/Exfiltration
        r'\b(wget|curl)\s+http',
        r'\brsync\s+',
        r'\bscp\s+.*@',
        r'\bftp\s+',
        r'\bnc\s+',
        r'\bnetcat\s+',
        
        # Remote Access
        r'\bssh\s+',
        r'\btelnet\s+',
        
        # Database Access
        r'\bmysql\s+',
        r'\bpsql\s+',
        r'\bsqlite3\s+',
        
        # Privilege Escalation
        r'\bsu\s+',
        r'\bsudo\s+',
        r'\bpkexec\s+',
        r'\bchmod\s+[4567]\d\d\d',  # SUID/SGID bits
        r'\bchmod\s+\+s\b',
        
        # Encoding/Obfuscation
        r'\bbase64\s+',
        r'\bxxd\s+',
        r'\bopenssl\s+enc',
        
        # Dangerous Operations
        r'\bchmod\s+777',
        r'\brm\s+-rf\s+/',
        r'\bdd\s+if=',
        r'\bmkfs\.',
        
        # History Manipulation
        r'history\s+-c',
        r'export\s+HISTFILE',
        r'unset\s+HISTFILE',
        r'shred\s+.*history',
        
        # Credential Access
        r'cat\s+/etc/shadow',
        r'cat\s+/etc/passwd',
        r'grep\s+.*password',
        r'grep\s+.*passwd',
        
        # Persistence
        r'\bcrontab\s+',
        r'\bsystemctl\s+(enable|start)',
        r'\bchkconfig\s+',
        r'\.bashrc',
        r'\.bash_profile',
        
        # Compilation (potentially malicious)
        r'\bgcc\s+',
        r'\bmake\s+',
        r'python\s+-c\s+',
        r'perl\s+-e\s+',
        r'ruby\s+-e\s+',
        
        # Windows PowerShell suspicious patterns
        r'Invoke-WebRequest',
        r'Invoke-Expression',
        r'IEX\s+',
        r'DownloadString',
        r'DownloadFile',
        r'-ExecutionPolicy\s+Bypass',
        r'-EncodedCommand',
        r'-enc\s+',
        r'FromBase64String',
        r'Start-Process.*-Verb\s+RunAs',
        r'Start-Process.*-WindowStyle\s+Hidden',
        
        # Windows Credentials
        r'net\s+user.*password',
        r'Get-Credential',
        r'ConvertTo-SecureString',
        r'mimikatz',
        r'sekurlsa',
        
        # Windows Registry
        r'reg\s+add',
        r'reg\s+delete',
        r'reg\s+query.*password',
        r'Get-ItemProperty.*HKLM',
        r'Set-ItemProperty.*HKLM',
        
        # Windows Lateral Movement
        r'psexec',
        r'wmic\s+',
        r'Enter-PSSession',
        r'Invoke-Command.*-ComputerName',
        
        # Windows Discovery
        r'Get-Process',
        r'Get-Service',
        r'Get-NetTCPConnection',
        r'Get-NetIPAddress',
        r'whoami\s+/priv',
    ]
    
    network_patterns = [
        r'\b(ssh|scp|ftp|telnet|nc|netcat)\b',
        r'\b(wget|curl)\b',
        r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'  # IP addresses
    ]
    
    file_op_patterns = [
        r'\b(rm|mv|cp|mkdir|touch|chmod|chown)\b'
    ]
    
    command_freq = {}
    
    for user, data in history_data.items():
        for cmd in data['commands']:
            analysis['total_commands'] += 1
            
            # Get first word (command name)
            cmd_name = cmd.split()[0] if cmd.split() else cmd
            command_freq[cmd_name] = command_freq.get(cmd_name, 0) + 1
            
            # Check for suspicious patterns
            for pattern in suspicious_patterns:
                if re.search(pattern, cmd, re.IGNORECASE):
                    analysis['suspicious_commands'].append({
                        'user': user,
                        'command': cmd[:100]  # Truncate long commands
                    })
                    break
            
            # Check for network commands
            for pattern in network_patterns:
                if re.search(pattern, cmd, re.IGNORECASE):
                    analysis['network_commands'].append({
                        'user': user,
                        'command': cmd[:100]
                    })
                    break
            
            # Check for file operations
            for pattern in file_op_patterns:
                if re.search(pattern, cmd, re.IGNORECASE):
                    analysis['file_operations'].append({
                        'user': user,
                        'command': cmd[:100]
                    })
                    break
    
    # Get most common commands (top 10)
    sorted_commands = sorted(command_freq.items(), key=lambda x: x[1], reverse=True)
    analysis['most_common'] = [
        {'command': cmd, 'count': count}
        for cmd, count in sorted_commands[:10]
    ]
    
    return analysis


def extract_system_intelligence(fs, file_list):
    """Extract system information and user profiles from filesystem.
    
    Args:
        fs: PyTSK3 FS_Info object
        file_list: List of file metadata dictionaries
        
    Returns:
        dict: System intelligence data
    """
    logger.info("Extracting system intelligence...")
    
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
    if os_type == 'linux':
        intelligence['hostname'] = extract_hostname_linux(fs)
        intelligence['os_info'] = extract_os_version_linux(fs)
        intelligence['user_profiles'] = enumerate_user_profiles_linux(fs, file_list)
        
    elif os_type == 'windows':
        intelligence['hostname'] = extract_hostname_windows(fs)
        intelligence['user_profiles'] = enumerate_user_profiles_windows(fs, file_list)
    
    elif os_type == 'macos':
        intelligence['hostname'] = extract_hostname_linux(fs)  # macOS also uses /etc/hostname
        intelligence['os_info'] = extract_os_version_macos(fs)
        intelligence['user_profiles'] = enumerate_user_profiles_macos(fs, file_list)
    
    # Extract command history if users were found
    if intelligence['user_profiles']:
        logger.info("Extracting command history...")
        history_data = extract_command_history(fs, file_list, os_type, intelligence['user_profiles'])
        intelligence['command_history'] = history_data
        
        if history_data:
            intelligence['command_analysis'] = analyze_command_history(history_data)
            logger.info(f"Found command history for {len(history_data)} users")
    
    # Log summary
    logger.info(f"System intelligence summary: OS={os_type}, Users={len(intelligence['user_profiles'])}")
    
    return intelligence
