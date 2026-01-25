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
        'user_profiles': []
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
    
    # Log summary
    logger.info(f"System intelligence summary: OS={os_type}, Users={len(intelligence['user_profiles'])}")
    
    return intelligence
