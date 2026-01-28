#!/usr/bin/env python3
"""Display key findings from infected.vmem analysis"""

import json

print("=" * 70)
print("INFECTED.VMEM - FORENSIC ANALYSIS RESULTS")
print("=" * 70)

with open('infected_analysis_results.json', 'r') as f:
    data = json.load(f)

print(f"\nFile: {data['file']}")
print(f"Size: {data['file_size_mb']} MB")
print(f"OS Type: {data['os_type'].upper()}")

# Show processes
print(f"\n{'='*70}")
print(f"PROCESSES ({len(data['processes'])} total)")
print(f"{'='*70}")
print(f"{'PID':<8} {'PPID':<8} {'Name':<30} {'Threads':<8}")
print("-" * 70)
for proc in data['processes'][:15]:  # Show first 15
    print(f"{proc['pid']!s:<8} {proc['ppid']!s:<8} {proc['name']:<30} {proc['threads']!s:<8}")
print(f"... and {len(data['processes']) - 15} more processes")

# Show suspicious network connections
print(f"\n{'='*70}")
print(f"SUSPICIOUS NETWORK CONNECTIONS")
print(f"{'='*70}")
suspicious_net = [s for s in data['suspicious_items'] if s['type'] == 'network']
if suspicious_net:
    for item in suspicious_net:
        print(f"⚠️  PID {item['pid']}: {item['remote']}")
        print(f"   Reason: {item['reason']}")
else:
    print("None detected")

# Show all network connections with external IPs
print(f"\n{'='*70}")
print(f"EXTERNAL NETWORK CONNECTIONS")
print(f"{'='*70}")
print(f"{'PID':<8} {'Protocol':<10} {'Local':<25} {'Remote':<25} {'State':<12}")
print("-" * 70)
for conn in data['network_connections']:
    remote = f"{conn['foreign_addr']}:{conn['foreign_port']}"
    if conn['foreign_addr'] not in ['', '0.0.0.0', '*', '::', '-', 'None']:
        local = f"{conn['local_addr']}:{conn['local_port']}"
        print(f"{conn['pid']!s:<8} {conn['protocol']:<10} {local:<25} {remote:<25} {conn['state']:<12}")

# Show command lines with interesting patterns
print(f"\n{'='*70}")
print(f"COMMAND LINE HISTORY (Sample)")
print(f"{'='*70}")
for cmd in data['command_history'][:10]:
    if cmd['command'] and cmd['command'] != 'None':
        print(f"\nPID {cmd['pid']}: {cmd['process']}")
        print(f"  {cmd['command'][:100]}")

print(f"\n{'='*70}")
print(f"Analysis complete! Full details in: infected_analysis_results.json")
print(f"{'='*70}")
