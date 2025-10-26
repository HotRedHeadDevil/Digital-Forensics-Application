rule potential_log_file {
    meta:
        description = "Identifikuje soubory, ktere vypadaji jako logy nebo obsahuji citlivy text."
        author = "AI Assistant"
        severity = "MEDIUM"
    strings:
        $s1 = "username" nocase
        $s2 = "password" nocase
        $s3 = "secret key" nocase
        $s4 = "yara test string" ascii
    condition:
        filesize < 5MB and 2 of ($s*)
}