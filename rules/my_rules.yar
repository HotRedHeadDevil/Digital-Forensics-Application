// YARA Rules for Forensic Analysis Demo

rule suspicious_credentials {
    meta:
        description = "Detects files containing potential credentials"
        author = "ForensicAutoCLI"
        severity = "HIGH"
    strings:
        $s1 = "password" nocase
        $s2 = "username" nocase
        $s3 = "api_key" nocase
        $s4 = "secret" nocase
        $s5 = "token" nocase
    condition:
        filesize < 5MB and 2 of ($s*)
}

rule email_addresses {
    meta:
        description = "Detects files containing email addresses"
        author = "ForensicAutoCLI"
        severity = "MEDIUM"
    strings:
        $email = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/ nocase
    condition:
        $email
}

rule ip_addresses {
    meta:
        description = "Detects files containing IP addresses"
        author = "ForensicAutoCLI"
        severity = "LOW"
    strings:
        $ipv4 = /([0-9]{1,3}\.){3}[0-9]{1,3}/
    condition:
        $ipv4
}

rule urls_and_links {
    meta:
        description = "Detects files containing URLs"
        author = "ForensicAutoCLI"
        severity = "LOW"
    strings:
        $http = "http://" nocase
        $https = "https://" nocase
        $www = "www." nocase
    condition:
        any of them
}

rule windows_commands {
    meta:
        description = "Detects Windows command-line activity"
        author = "ForensicAutoCLI"
        severity = "MEDIUM"
    strings:
        $cmd1 = "cmd.exe" nocase
        $cmd2 = "powershell" nocase
        $cmd3 = "net user" nocase
        $cmd4 = "reg add" nocase
        $cmd5 = "taskkill" nocase
    condition:
        any of them
}

rule text_file_markers {
    meta:
        description = "Common text file indicators"
        author = "ForensicAutoCLI"
        severity = "INFO"
    strings:
        $txt1 = "Dear" nocase
        $txt2 = "Hello" nocase
        $txt3 = "Subject:" nocase
    condition:
        any of them
}
