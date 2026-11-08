// YARA rules for forensic analysis.
//
// Sample rules with harmless markers (credentials, e-mail, IP, URL) plus a few
// generic behaviour-based rules. Add or remove rules freely; no code change needed.

// ------------------------------------------------------------ sample rules

rule email_addresses {
    meta:
        description = "File contains e-mail addresses"
        severity = "medium"
    strings:
        $email = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/
    condition:
        $email
}

rule ip_addresses {
    meta:
        description = "File contains IP addresses"
        severity = "low"
    strings:
        $ipv4 = /\b([0-9]{1,3}\.){3}[0-9]{1,3}\b/
    condition:
        $ipv4
}

rule urls_and_links {
    meta:
        description = "File contains URLs"
        severity = "low"
    strings:
        $url = /https?:\/\/[a-zA-Z0-9._~:\/?#@!$&'()*+,;=%-]+/ nocase
    condition:
        $url
}

// ------------------------------------------------------ generic behaviour rules

rule suspicious_credentials {
    meta:
        description = "File contains credential-like keywords"
        severity = "high"
    strings:
        $s1 = "password" nocase
        $s2 = "username" nocase
        $s3 = "api_key" nocase
        $s4 = "secret" nocase
        $s5 = "token" nocase
    condition:
        filesize < 5MB and 2 of ($s*)
}

rule ransom_note_generic {
    meta:
        description = "Text that looks like a ransom note (files encrypted, payment demanded)"
        severity = "critical"
    strings:
        $a1 = "your files have been encrypted" nocase
        $a2 = "files are encrypted" nocase
        $a3 = "decrypt your files" nocase
        $a4 = "decryption key" nocase
        $b1 = "bitcoin" nocase
        $b2 = "btc wallet" nocase
        $b3 = "send $" nocase
        $b4 = "payment" nocase
    condition:
        filesize < 1MB and 1 of ($a*) and 1 of ($b*)
}

rule backup_destruction_commands {
    meta:
        description = "Commands that delete shadow copies or disable recovery"
        severity = "critical"
    strings:
        $v1 = "delete shadows" nocase
        $v2 = "wbadmin delete" nocase
        $v3 = "recoveryenabled no" nocase
        $v4 = "resize shadowstorage" nocase
    condition:
        any of them
}

rule reverse_shell_script {
    meta:
        description = "Script that opens an interactive shell over the network"
        severity = "high"
    strings:
        $r1 = "/dev/tcp/"
        $r2 = "bash -i" nocase
        $r3 = /nc(at)?\s+(-\w+\s+)*-e\s+\/bin\/(ba)?sh/
        $r4 = "socket.socket" nocase
        $r5 = "pty.spawn" nocase
        $r6 = "TCPClient" nocase
    condition:
        filesize < 1MB and ($r1 or $r3 or ($r2 and ($r1 or $r4 or $r6)) or ($r4 and $r5))
}

rule web_shell_generic {
    meta:
        description = "Server-side script that runs input from the request as code or commands"
        severity = "high"
    strings:
        $input = /\$_(GET|POST|REQUEST|COOKIE)\s*\[/
        $exec1 = "eval(" nocase
        $exec2 = "system(" nocase
        $exec3 = "passthru(" nocase
        $exec4 = "shell_exec(" nocase
        $exec5 = "base64_decode(" nocase
        $exec6 = "assert(" nocase
    condition:
        filesize < 2MB and $input and any of ($exec*)
}

rule powershell_download_or_obfuscation {
    meta:
        description = "PowerShell download cradle, encoded command or hidden execution"
        severity = "high"
    strings:
        $d1 = "DownloadString" nocase
        $d2 = "DownloadFile" nocase
        $d3 = "Net.WebClient" nocase
        $d4 = "Invoke-Expression" nocase
        $d5 = "FromBase64String" nocase
        $e1 = /-(enc|encodedcommand)\s+[A-Za-z0-9+\/=]{20,}/ nocase
        $h1 = /-w(indowstyle)?\s+hidden/ nocase
    condition:
        filesize < 2MB and (($d1 or $d2 or $d3) and ($d4 or $d5 or $e1)) or $e1 or ($h1 and ($d1 or $d2 or $d4))
}

rule credential_dumping_tool {
    meta:
        description = "Strings used by credential dumping tools"
        severity = "critical"
    strings:
        $m1 = "mimikatz" nocase
        $m2 = "sekurlsa" nocase
        $m3 = "lsadump" nocase
        $m4 = "logonpasswords" nocase
    condition:
        2 of them
}

rule windows_injection_api_combo {
    meta:
        description = "Windows executable importing APIs typical for process injection"
        severity = "high"
    strings:
        $a1 = "VirtualAllocEx"
        $a2 = "WriteProcessMemory"
        $a3 = "CreateRemoteThread"
        $a4 = "NtUnmapViewOfSection"
        $a5 = "SetThreadContext"
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule windows_ransomware_behavior_combo {
    meta:
        description = "Windows executable combining file encryption APIs with shadow copy or wallpaper/extension handling"
        severity = "high"
    strings:
        $c1 = "CryptEncrypt"
        $c2 = "CryptGenKey"
        $c3 = "CryptAcquireContext"
        $f1 = "FindFirstFile"
        $f2 = "MoveFileEx"
        $s1 = "vssadmin" nocase
        $s2 = "bcdedit" nocase
        $s3 = "cmd.exe /c" nocase
    condition:
        uint16(0) == 0x5A4D and 2 of ($c*) and all of ($f*) and any of ($s*)
}

rule linux_persistence_or_miner_script {
    meta:
        description = "Shell script that installs persistence or downloads and runs a payload"
        severity = "medium"
    strings:
        $dl = /(curl|wget)\s[^\n]*(\/tmp|\/dev\/shm|\/var\/tmp)/
        $pipe = /(curl|wget)\s[^\n|]*\|\s*(ba)?sh/
        $cron = /crontab\s+-|\/etc\/cron\./
        $chmod = /chmod\s+(\+x|[0-7]*[1357][0-7]{0,2})\s+\/(tmp|dev\/shm|var\/tmp)/
        $miner = "stratum+tcp" nocase
    condition:
        filesize < 1MB and ($pipe or $miner or ($dl and ($cron or $chmod)))
}
