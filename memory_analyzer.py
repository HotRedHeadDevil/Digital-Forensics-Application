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
    results = {
        'os_type': 'windows',
        'processes': [],
        'network_connections': [],
        'suspicious_processes': [],
        'suspicious_items': [],  # For network-based and other suspicious findings
        'loaded_modules': []
    }
    
    ctx, automagics = setup_volatility_context(memory_file)
    if not ctx:
        return {'error': 'Failed to initialize Volatility context'}
    
    try:
        # Process list
        logger.info("Extracting process list...")
        from volatility3.plugins.windows import pslist
        plugin = plugins.construct_plugin(ctx, automagics, pslist.PsList, 'plugins', None, None)
        treegrid = plugin.run()
        
        if hasattr(treegrid, '_generator'):
            for level, item in treegrid._generator:
                # PsList columns: Offset, PID, PPID, ImageFileName, Offset(s), Threads, Handles, SessionId, Wow64, CreateTime, ExitTime
                # Note: TreeGrid format seems to be [Offset, ImageFileName, Offset(s), PID, PPID, Threads, Handles...]
                # Let's map them correctly based on actual output
                name = str(clean_value(item[1])) if len(item) > 1 else 'Unknown'  # ImageFileName is at index 1
                pid = clean_value(item[3]) if len(item) > 3 else 0  # PID at index 3
                ppid = clean_value(item[4]) if len(item) > 4 else 0  # PPID at index 4
                threads = clean_value(item[5]) if len(item) > 5 else 0
                handles = clean_value(item[6]) if len(item) > 6 else 0
                
                process_info = {
                    'pid': pid,
                    'ppid': ppid,
                    'name': name,
                    'threads': threads,
                    'handles': handles
                }
                results['processes'].append(process_info)
                
                # Flag suspicious processes
                name_lower = str(name).lower() if name else ''
                if any(sus in name_lower for sus in ['cmd.exe', 'powershell', 'wscript', 'mshta', 'nc.exe', 'mimikatz']):
                    results['suspicious_processes'].append(process_info)
        
        logger.info(f"Found {len(results['processes'])} processes")
        
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
        logger.error(f"Linux process list extraction failed: {e}")
    
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
