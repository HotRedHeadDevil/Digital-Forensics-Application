#!/usr/bin/env python3
"""
Simplified memory analyzer for infected.vmem
Provides clear progress and error messages
"""

import os
import sys
import json
from pathlib import Path

def clean_value(value):
    """Convert Volatility special objects to JSON-serializable values."""
    # Handle NotApplicableValue and other Volatility objects
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

print("=" * 70)
print("Memory Dump Analyzer - Infected.vmem")
print("=" * 70)

# Configuration
MEMORY_FILE = "forensic_images/memory_samples/infected.vmem"
OUTPUT_FILE = "infected_analysis_results.json"

# Check file exists
print(f"\n[1/5] Checking memory dump file...")
if not os.path.exists(MEMORY_FILE):
    print(f"ERROR: File not found: {MEMORY_FILE}")
    sys.exit(1)

file_size = os.path.getsize(MEMORY_FILE)
print(f"✓ Found: {MEMORY_FILE}")
print(f"  Size: {file_size:,} bytes ({file_size/(1024**2):.1f} MB)")

# Import Volatility
print(f"\n[2/5] Loading Volatility 3 framework...")
try:
    print("  - Importing framework...")
    from volatility3 import framework
    print("  - Importing contexts...")
    from volatility3.framework import contexts, automagic, plugins, constants
    print("✓ Volatility 3 loaded successfully")
except ImportError as e:
    print(f"ERROR: Cannot import Volatility 3: {e}")
    print("Install with: pip install volatility3")
    import traceback
    traceback.print_exc()
    sys.exit(1)
except Exception as e:
    print(f"ERROR: Unexpected error loading Volatility: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Setup context
print(f"\n[3/5] Initializing analysis context...")
try:
    constants.PARALLELISM = constants.Parallelism.Off
    ctx = contexts.Context()
    framework.require_interface_version(2, 0, 0)
    automagics = automagic.available(ctx)
    
    # Set file location
    abs_path = os.path.abspath(MEMORY_FILE).replace('\\', '/')
    file_url = f"file:///{abs_path}"
    ctx.config['automagic.LayerStacker.single_location'] = file_url
    
    print(f"✓ Context initialized")
    print(f"  Location: {file_url}")
except Exception as e:
    print(f"ERROR: Failed to initialize context: {e}")
    sys.exit(1)

# Prepare results
results = {
    "file": MEMORY_FILE,
    "file_size_mb": round(file_size / (1024**2), 2),
    "os_type": "windows",
    "analysis_status": {},
    "processes": [],
    "network_connections": [],
    "suspicious_items": [],
    "command_history": []
}

print(f"\n[4/5] Running analysis plugins...")

# Plugin 1: Process List
print(f"\n  → Running pslist (process list)...")
try:
    from volatility3.plugins.windows import pslist
    plugin = plugins.construct_plugin(ctx, automagics, pslist.PsList, 'plugins', None, None)
    
    process_count = 0
    treegrid = plugin.run()
    
    # TreeGrid objects have _generator attribute with actual data
    if hasattr(treegrid, '_generator'):
        for level, item in treegrid._generator:
            pid = clean_value(item[1]) if len(item) > 1 else 0
            ppid = clean_value(item[2]) if len(item) > 2 else 0
            name = str(clean_value(item[3])) if len(item) > 3 else 'Unknown'
            threads = clean_value(item[5]) if len(item) > 5 else 0
            handles = clean_value(item[6]) if len(item) > 6 else 0
            
            process_info = {
                "pid": pid,
                "ppid": ppid,
                "name": name,
                "threads": threads,
                "handles": handles
            }
            results["processes"].append(process_info)
            process_count += 1
            
            # Flag suspicious processes
            name_lower = name.lower()
            suspicious_names = ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe', 
                               'mshta.exe', 'nc.exe', 'mimikatz', 'psexec']
            if any(sus in name_lower for sus in suspicious_names):
                results["suspicious_items"].append({
                    "type": "process",
                    "pid": pid,
                    "name": name,
                    "reason": "Suspicious process name"
                })
    
    print(f"    ✓ Found {process_count} processes")
    results["analysis_status"]["pslist"] = "success"
    
except Exception as e:
    print(f"    ✗ Failed: {e}")
    results["analysis_status"]["pslist"] = f"failed: {str(e)}"
    import traceback
    traceback.print_exc()

# Plugin 2: Network Connections
print(f"\n  → Running netscan (network connections)...")
try:
    from volatility3.plugins.windows import netscan
    plugin = plugins.construct_plugin(ctx, automagics, netscan.NetScan, 'plugins', None, None)
    
    conn_count = 0
    treegrid = plugin.run()
    
    if hasattr(treegrid, '_generator'):
        for level, item in treegrid._generator:
            # NetScan columns: Offset, Proto, LocalAddr, LocalPort, ForeignAddr, ForeignPort, State, PID, Owner, Created
            conn_info = {
                "protocol": str(clean_value(item[1])) if len(item) > 1 else 'Unknown',
                "local_addr": str(clean_value(item[2])) if len(item) > 2 else '',
                "local_port": clean_value(item[3]) if len(item) > 3 else 0,
                "foreign_addr": str(clean_value(item[4])) if len(item) > 4 else '',
                "foreign_port": clean_value(item[5]) if len(item) > 5 else 0,
                "state": str(clean_value(item[6])) if len(item) > 6 else '',
                "pid": clean_value(item[7]) if len(item) > 7 else 0,
                "owner": str(clean_value(item[8])) if len(item) > 8 else ''
            }
            results["network_connections"].append(conn_info)
            conn_count += 1
            
            # Flag suspicious connections (non-standard ports, unusual IPs)
            foreign_addr = conn_info["foreign_addr"]
            foreign_port = conn_info["foreign_port"]
            if foreign_addr not in ['', '0.0.0.0', '*', '::', '-'] and foreign_port > 0:
                # Flag connections to unusual ports
                if foreign_port not in [80, 443, 53, 8080, 8443]:
                    results["suspicious_items"].append({
                        "type": "network",
                        "pid": conn_info["pid"],
                        "remote": f"{foreign_addr}:{foreign_port}",
                        "reason": "Unusual port connection"
                    })
    
    print(f"    ✓ Found {conn_count} network connections")
    results["analysis_status"]["netscan"] = "success"
    
except Exception as e:
    print(f"    ✗ Failed: {e}")
    results["analysis_status"]["netscan"] = f"failed: {str(e)}"
    import traceback
    traceback.print_exc()

# Plugin 3: Command Line
print(f"\n  → Running cmdline (command line arguments)...")
try:
    from volatility3.plugins.windows import cmdline
    plugin = plugins.construct_plugin(ctx, automagics, cmdline.CmdLine, 'plugins', None, None)
    
    cmd_count = 0
    treegrid = plugin.run()
    
    if hasattr(treegrid, '_generator'):
        for level, item in treegrid._generator:
            # CmdLine columns: PID, Process, Args
            pid = clean_value(item[0]) if len(item) > 0 else 0
            process_name = str(clean_value(item[1])) if len(item) > 1 else ''
            args = str(clean_value(item[2])) if len(item) > 2 else ''
            
            if args and args.strip():
                results["command_history"].append({
                    "pid": pid,
                    "process": process_name,
                    "command": args
                })
                cmd_count += 1
                
                # Flag suspicious commands
                args_lower = args.lower()
                suspicious_patterns = ['download', 'invoke', 'base64', 'encoded', 'bypass', 
                                      'hidden', 'iex', 'webclient', 'mimikatz', 'password']
                if any(pattern in args_lower for pattern in suspicious_patterns):
                    results["suspicious_items"].append({
                        "type": "command",
                        "pid": pid,
                        "command": args[:100],  # Truncate long commands
                        "reason": "Suspicious command pattern"
                    })
    
    print(f"    ✓ Found {cmd_count} command lines")
    results["analysis_status"]["cmdline"] = "success"
    
except Exception as e:
    print(f"    ✗ Failed: {e}")
    results["analysis_status"]["cmdline"] = f"failed: {str(e)}"
    import traceback
    traceback.print_exc()

# Save results
print(f"\n[5/5] Saving results...")
try:
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"✓ Results saved to: {OUTPUT_FILE}")
except Exception as e:
    print(f"ERROR: Failed to save results: {e}")
    sys.exit(1)

# Summary
print("\n" + "=" * 70)
print("ANALYSIS SUMMARY")
print("=" * 70)
print(f"Total Processes:        {len(results['processes'])}")
print(f"Network Connections:    {len(results['network_connections'])}")
print(f"Command Lines:          {len(results['command_history'])}")
print(f"Suspicious Items:       {len(results['suspicious_items'])}")

if results["suspicious_items"]:
    print(f"\n⚠ SUSPICIOUS FINDINGS:")
    for item in results["suspicious_items"][:10]:  # Show first 10
        print(f"  - [{item['type'].upper()}] {item.get('name', item.get('command', item.get('remote', '')))} - {item['reason']}")
    
    if len(results["suspicious_items"]) > 10:
        print(f"  ... and {len(results['suspicious_items']) - 10} more (see JSON file)")

print(f"\n✓ Full results in: {OUTPUT_FILE}")
print("=" * 70)
