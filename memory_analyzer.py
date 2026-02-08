# memory_analyzer.py - Memory dump analysis with Volatility 3

import logging
import os
import sys
import json
from pathlib import Path

logger = logging.getLogger(__name__)

# Import Volatility 3
try:
    from volatility3 import framework
    from volatility3.framework import contexts, automagic, plugins, constants
    
    # Configure Volatility logging to reduce duplicate warnings
    vol_logger = logging.getLogger('volatility3')
    vol_logger.setLevel(logging.ERROR)  # Only show errors from Volatility, not warnings
    
except ImportError:
    logger.error("Volatility 3 not installed. Run: pip install volatility3")
    raise


def clean_value(value):
    """Convert Volatility special objects to JSON-serializable values."""
    if value is None:
        return None
    
    value_type = type(value).__name__
    if 'NotApplicableValue' in value_type or 'NotAvailableValue' in value_type:
        return None
    
    # Handle bytes
    if isinstance(value, bytes):
        return value.decode('utf-8', errors='ignore')
    
    # Handle other types
    try:
        json.dumps(value)  # Test if serializable
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
        
        # Set up the context
        ctx = contexts.Context()
        framework.require_interface_version(2, 0, 0)
        
        # Configure automagics
        automagics = automagic.available(ctx)
        
        # Set the memory file location - use proper URI format for Windows
        abs_path = os.path.abspath(memory_file)
        # Convert Windows path to proper file URI
        if os.name == 'nt':  # Windows
            # Replace backslashes and create proper file URI
            abs_path = abs_path.replace('\\', '/')
            if abs_path[1] == ':':  # Drive letter
                single_location = f"file:///{abs_path}"
            else:
                single_location = f"file://{abs_path}"
        else:  # Linux/Mac
            single_location = f"file://{abs_path}"
        
        ctx.config['automagic.LayerStacker.single_location'] = single_location
        
        logger.info(f"Volatility context initialized for: {memory_file}")
        logger.debug(f"Using location: {single_location}")
        return ctx, automagics
        
    except Exception as e:
        logger.error(f"Failed to setup Volatility context: {e}")
        return None, None


def run_volatility_plugin(ctx, automagics, plugin_class, **kwargs):
    """Run a Volatility plugin and return results.
    
    Args:
        ctx: Volatility context
        automagics: Automagic objects
        plugin_class: Plugin class to run
        **kwargs: Additional plugin arguments
        
    Returns:
        list: Plugin results as list of dictionaries
    """
    try:
        # Create plugin instance
        plugin = plugins.construct_plugin(
            ctx, automagics, plugin_class, 'plugins',
            None, None
        )
        
        # Run plugin and handle TreeGrid
        results = []
        treegrid = plugin.run()
        
        # TreeGrid objects have _generator attribute with actual data
        if hasattr(treegrid, '_generator'):
            for level, item in treegrid._generator:
                # Convert tuple to dict using clean_value
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
            plugin = plugins.construct_plugin(ctx, automagics, info.Info, 'plugins', None, None)
            treegrid = plugin.run()
            # If we can create the plugin and it has a generator, it's likely Windows
            if hasattr(treegrid, '_generator'):
                # Try to get at least one result
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
            plugin = plugins.construct_plugin(ctx, automagics, pslist.PsList, 'plugins', None, None)
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
        logger.error(f"OS detection failed: {e}")
        return 'unknown'


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
        'loaded_modules': []
    }
    
    ctx, automagics = setup_volatility_context(memory_file)
    if not ctx:
        return {'error': 'Failed to initialize Volatility context'}
    
    try:
        # Extract system info (hostname, OS version)
        logger.info("Extracting system information...")
        from volatility3.plugins.windows import info
        plugin = plugins.construct_plugin(ctx, automagics, info.Info, 'plugins', None, None)
        treegrid = plugin.run()
        
        if hasattr(treegrid, '_generator'):
            for level, item in treegrid._generator:
                # Info plugin typically returns key-value pairs
                # Look for ComputerName or similar fields
                if len(item) >= 2:
                    key = str(clean_value(item[0])) if item[0] else ''
                    value = str(clean_value(item[1])) if item[1] else ''
                    
                    if 'computername' in key.lower() or 'hostname' in key.lower():
                        results['hostname'] = value
                        logger.info(f"Found hostname: {value}")
        
    except Exception as e:
        logger.debug(f"System info extraction failed: {e}")
    
    try:
        # Extract logged-in users (Windows Sessions)
        logger.info("Extracting user sessions...")
        from volatility3.plugins.windows import sessions
        import re
        
        plugin = plugins.construct_plugin(ctx, automagics, sessions.Sessions, 'plugins', None, None)
        treegrid = plugin.run()
        
        user_set = set()
        if hasattr(treegrid, '_generator'):
            for level, item in treegrid._generator:
                # Sessions columns typically include Username
                # Extract username if available
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
        logger.debug(f"User session extraction not available: {e}")
    
    try:
        # Process list
        logger.info("Extracting process list...")
        from volatility3.plugins.windows import pslist
        plugin = plugins.construct_plugin(ctx, automagics, pslist.PsList, 'plugins', None, None)
        treegrid = plugin.run()
        
        # Get column names from TreeGrid
        column_names = [col.name for col in treegrid.columns]
        logger.debug(f"PsList columns: {column_names}")
        
        if hasattr(treegrid, '_generator'):
            for level, item in treegrid._generator:
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
                    results['suspicious_processes'].append(process_info)
        
        logger.info(f"Found {len(results['processes'])} processes")
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Process list extraction failed: {error_msg}")
        
        # Check if this might be a Linux memory dump
        if 'Symbol table' in error_msg or 'No such file' in error_msg or 'layer' in error_msg.lower():
            logger.warning("⚠ This might be a Linux memory dump, not Windows!")
            logger.warning("Try running without --os-type to auto-detect, or specify --os-type linux")
            results['os_mismatch_warning'] = "This might be a Linux memory dump. Try --os-type linux or remove --os-type for auto-detection."
    
    try:
        # Network connections
        logger.info("Extracting network connections...")
        from volatility3.plugins.windows import netscan
        from collections import defaultdict
        
        plugin = plugins.construct_plugin(ctx, automagics, netscan.NetScan, 'plugins', None, None)
        treegrid = plugin.run()
        
        suspicious_pids = set()  # Track PIDs with suspicious network activity
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
                if foreign_addr not in ['', '0.0.0.0', '*', '::', '-', 'None'] and foreign_port:
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
        for proc in results['processes']:
            if proc['pid'] in suspicious_pids:
                # Check if not already in suspicious list (compare by PID)
                if not any(p['pid'] == proc['pid'] for p in results['suspicious_processes']):
                    results['suspicious_processes'].append(proc)
        
        logger.info(f"Found {len(results['network_connections'])} network connections")
        logger.info(f"Network stats: {established_count} established, {listening_count} listening")
        logger.info(f"Unique IPs: {len(ip_freq)}, Unique ports: {len(port_freq)}")
        logger.info(f"Flagged {len(suspicious_pids)} PIDs with suspicious network activity")
        
    except Exception as e:
        logger.error(f"Process list extraction failed: {e}")
    
    try:
        # Network connections
        logger.info("Extracting network connections...")
        from volatility3.plugins.windows import netscan
        plugin = plugins.construct_plugin(ctx, automagics, netscan.NetScan, 'plugins', None, None)
        treegrid = plugin.run()
        
        suspicious_pids = set()  # Track PIDs with suspicious network activity
        
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
                
                # Flag suspicious connections and track their PIDs
                foreign_addr = conn_info['foreign_addr']
                foreign_port = conn_info['foreign_port']
                if foreign_addr not in ['', '0.0.0.0', '*', '::', '-', 'None'] and foreign_port:
                    # Flag connections to unusual ports (not common HTTP, HTTPS, DNS, etc.)
                    if foreign_port not in [80, 443, 53, 8080, 8443]:
                        suspicious_pids.add(conn_info['pid'])
                        results['suspicious_items'].append({
                            'type': 'network',
                            'pid': conn_info['pid'],
                            'remote': f"{foreign_addr}:{foreign_port}",
                            'reason': 'Unusual port connection'
                        })
        
        # Flag processes with suspicious network activity
        for proc in results['processes']:
            if proc['pid'] in suspicious_pids:
                # Check if not already in suspicious list (compare by PID)
                if not any(p['pid'] == proc['pid'] for p in results['suspicious_processes']):
                    results['suspicious_processes'].append(proc)
        
        logger.info(f"Found {len(results['network_connections'])} network connections")
        logger.info(f"Flagged {len(suspicious_pids)} PIDs with suspicious network activity")
        
    except Exception as e:
        logger.error(f"Network extraction failed: {e}")
    
    try:
        # Loaded modules/DLLs (limited to first 50 for performance)
        logger.info("Extracting loaded modules...")
        from volatility3.plugins.windows import dlllist
        plugin = plugins.construct_plugin(ctx, automagics, dlllist.DllList, 'plugins', None, None)
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
        logger.error(f"Module extraction failed: {e}")
    
    return results


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
        'network_connections': [],
        'suspicious_processes': []
    }
    
    ctx, automagics = setup_volatility_context(memory_file)
    if not ctx:
        return {'error': 'Failed to initialize Volatility context'}
    
    try:
        # Process list
        logger.info("Extracting Linux process list...")
        from volatility3.plugins.linux import pslist
        plugin = plugins.construct_plugin(ctx, automagics, pslist.PsList, 'plugins', None, None)
        treegrid = plugin.run()
        
        if hasattr(treegrid, '_generator'):
            for level, item in treegrid._generator:
                # Linux PsList columns vary, but typically: Offset, PID, PPID, COMM
                process_info = {
                    'pid': clean_value(item[1]) if len(item) > 1 else 0,
                    'ppid': clean_value(item[2]) if len(item) > 2 else 0,
                    'name': str(clean_value(item[3])) if len(item) > 3 else 'Unknown'
                }
                results['processes'].append(process_info)
                
                # Flag suspicious processes
                name_lower = process_info['name'].lower()
                if any(sus in name_lower for sus in ['nc', 'ncat', 'bash', 'sh', 'perl', 'python', 'ruby']):
                    results['suspicious_processes'].append(process_info)
        
        logger.info(f"Found {len(results['processes'])} processes")
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Linux process list extraction failed: {error_msg}")
        
        # Check if this might be a Windows memory dump
        if 'Unknown symbol' in error_msg or 'init_task' in error_msg:
            logger.warning("⚠ This appears to be a Windows memory dump, not Linux!")
            logger.warning("Try running without --os-type to auto-detect, or specify --os-type windows")
            results['os_mismatch_warning'] = "This appears to be a Windows memory dump. Try --os-type windows or remove --os-type for auto-detection."
    
    return results


def analyze_memory_dump(memory_file, os_type=None):
    """Main function to analyze memory dump.
    
    Args:
        memory_file: Path to memory dump file
        os_type: OS type ('windows', 'linux', or None for auto-detect)
        
    Returns:
        dict: Comprehensive analysis results
    """
    if not os.path.exists(memory_file):
        return {'error': f'Memory dump file not found: {memory_file}'}
    
    file_size = os.path.getsize(memory_file)
    logger.info(f"Analyzing memory dump: {memory_file} ({file_size / (1024**2):.2f} MB)")
    
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
    
    # Add metadata
    results['file_path'] = memory_file
    results['file_size'] = file_size
    results['file_size_mb'] = round(file_size / (1024**2), 2)
    
    return results
