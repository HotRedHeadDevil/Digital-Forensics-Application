#!/usr/bin/env python3
"""Display all suspicious command detections from disk analysis."""

import json
import sys

# Read from lines 115-250 of test_output.json which has the suspicious commands
with open('test_output.json', 'r') as f:
    content = f.read()
    # Find the start of JSON (after the warning message)
    json_start = content.find('{')
    data = json.loads(content[json_start:])

analysis = data['system_intelligence']['command_analysis']
suspicious = analysis['suspicious_commands']

print("="*80)
print("ENHANCED COMMAND HISTORY DETECTION - Linux Image")
print("="*80)
print(f"\nTotal commands analyzed: {analysis['total_commands']}")
print(f"Suspicious commands detected: {len(suspicious)}")
print(f"Detection rate: {len(suspicious)/analysis['total_commands']*100:.1f}%")

print("\n" + "-"*80)
print("ALL SUSPICIOUS COMMANDS DETECTED:")
print("-"*80)

# Group by user
from collections import defaultdict
by_user = defaultdict(list)
for cmd in suspicious:
    by_user[cmd['user']].append(cmd['command'])

for user, commands in sorted(by_user.items()):
    print(f"\n[{user.upper()}] - {len(commands)} suspicious commands:")
    for i, cmd in enumerate(commands, 1):
        print(f"  {i:2}. {cmd}")

print("\n" + "="*80)
