# YARA Rules Showcase

This directory demonstrates YARA pattern matching capabilities for forensic analysis.

## Quick Start

### 1. Test YARA Rules on Sample Files

```bash
python demo_yara.py
```

This scans files in `test_data/` and shows which YARA rules match.

### 2. Test on Disk Images

```bash
# Quick scan (no YARA)
python main.py disk not_working_disks/dfr-01-fat.dd --quick

# Full scan with YARA
python main.py -v disk not_working_disks/dfr-01-fat.dd
```

## YARA Rules Explained

### rules/my_rules.yar

**1. suspicious_credentials** [HIGH]

- Detects: password, username, api_key, secret, token
- Use case: Find files containing potential credentials
- Example match: `credentials.txt` (contains "Username: admin")

**2. email_addresses** [MEDIUM]

- Detects: email address patterns using regex
- Use case: Find personal information or communication records
- Example match: `email.txt` (contains john.doe@company.com)

**3. ip_addresses** [LOW]

- Detects: IPv4 address patterns
- Use case: Network forensics, connection logs
- Example match: `network_log.txt` (contains 192.168.1.100)

**4. urls_and_links** [LOW]

- Detects: http://, https://, www.
- Use case: Web activity analysis
- Example match: `network_log.txt` (contains http://example.com)

**5. windows_commands** [MEDIUM]

- Detects: cmd.exe, powershell, net user, reg add, taskkill
- Use case: Detect command execution, potential malicious activity
- Example match: `commands.txt` (contains "powershell")

**6. text_file_markers** [INFO]

- Detects: Common text patterns like "Dear", "Hello", "Subject:"
- Use case: Identify document types
- Example match: `email.txt` (contains "Dear Jane")

## Test Files

### test_data/

1. **credentials.txt** - Contains username, password, API keys
   - Triggers: `suspicious_credentials`

2. **network_log.txt** - Network connection logs with IPs and URLs
   - Triggers: `ip_addresses`, `urls_and_links`

3. **email.txt** - Email message with addresses
   - Triggers: `email_addresses`, `text_file_markers`

4. **commands.txt** - Windows command history
   - Triggers: `windows_commands`

5. **clean_file.txt** - Normal text, no suspicious content
   - Triggers: Nothing (demonst
     rates false negative prevention)

## Creating Custom Rules

### YARA Rule Syntax

```yara
rule my_custom_rule {
    meta:
        description = "What this rule detects"
        author = "Your Name"
        severity = "HIGH|MEDIUM|LOW|INFO"

    strings:
        $text1 = "exact text" nocase
        $text2 = "case sensitive"
        $regex = /pattern[0-9]+/
        $hex = { 4D 5A 90 00 }  // PE header example

    condition:
        any of them
        // or: all of them
        // or: 2 of ($text*)
        // or: filesize < 1MB and $text1
}
```

### Common Patterns

**Credit Card Numbers:**

```yara
$cc = /\b[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}\b/
```

**Social Security Numbers:**

```yara
$ssn = /\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b/
```

**Private Keys:**

```yara
$rsa = "-----BEGIN RSA PRIVATE KEY-----"
$ssh = "-----BEGIN OPENSSH PRIVATE KEY-----"
```

**Malware Indicators:**

```yara
$exe = { 4D 5A }  // MZ header
$persistence = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
```

## Expected Output

When running `python demo_yara.py`, you should see:

```
[3] Scanning test files in 'test_data/':
======================================================================

📄 credentials.txt (182 bytes)
   ✓ 1 YARA rule(s) matched:
      → suspicious_credentials [HIGH] Detects files containing credentials
         Matched patterns:
           • $s1: "Password" (at offset 72)
           • $s2: "Username" (at offset 55)
           ...
```

## Integration with Main Tool

The YARA rules are automatically applied when scanning disk images:

```bash
python main.py -v disk image.dd
```

Results include `yara_matches` field in JSON output:

```json
{
  "name": "suspicious_file.txt",
  "path": "/documents/suspicious_file.txt",
  "yara_matches": ["suspicious_credentials", "ip_addresses"]
}
```

## Tips for Forensic Analysis

1. **Start broad, refine later** - Use multiple rules with different severity levels
2. **Combine rules** - Use conditions like `2 of ($cred*)` to reduce false positives
3. **Test before deploying** - Always test rules on known samples
4. **Document your rules** - Good metadata helps during investigation
5. **Layer defenses** - Use multiple detection methods, not just YARA

## Resources

- YARA Documentation: https://yara.readthedocs.io/
- YARA Rule Repositories:
  - Awesome YARA: https://github.com/InQuest/awesome-yara
  - YARA Rules Project: https://github.com/Yara-Rules/rules
- Testing: https://www.virustotal.com/ (supports YARA hunting)
