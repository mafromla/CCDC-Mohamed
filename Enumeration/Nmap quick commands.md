### 1) Quick web check (fast) �?" check 80/443, show versions

```powershell
# Quick web check: SYN scan ports 80 & 443, service versions, show only open
nmap -Pn -sS -p 80,443 -sV -T4 --open -oN "C:\CCDC\Evidence\nmap_quick_80_443.txt" TARGET
# Extract open ports (human-friendly)
Select-String -Pattern '\bopen\b' -Path "C:\CCDC\Evidence\nmap_quick_80_443.txt" | Out-File "C:\CCDC\Evidence\nmap_quick_80_443_open.txt"
```

### 2) Web enumeration (headers, titles, methods, vhosts)

```powershell
# Web enum: http-title, headers, methods, vhost probes
nmap -Pn -p 80,443 -sV -T4 --script "http-title,http-headers,http-methods,http-enum,http-vhosts" -oN "C:\CCDC\Evidence\nmap_http_enum.txt" TARGET
# Save only open-port lines
Select-String -Pattern '\bopen\b' -Path "C:\CCDC\Evidence\nmap_http_enum.txt" | Out-File "C:\CCDC\Evidence\nmap_http_enum_open.txt"
```

### 3) SSL/TLS info (certs & ciphers)

```powershell
# SSL/TLS: cert details and supported ciphers for 443
nmap -Pn -p 443 -sV -T4 --script "ssl-cert,ssl-enum-ciphers" -oN "C:\CCDC\Evidence\nmap_ssl_info.txt" TARGET
Select-String -Pattern '\bopen\b' -Path "C:\CCDC\Evidence\nmap_ssl_info.txt" | Out-File "C:\CCDC\Evidence\nmap_ssl_info_open.txt"
```

### 4) Common admin ports (RDP, SMB, LDAP, etc.)

```powershell
# Admin ports: fingerprint service versions on common admin ports
nmap -Pn -sS -sV -p 21,22,23,25,53,80,110,139,143,389,443,445,3389 -T4 --open -oN "C:\CCDC\Evidence\nmap_common_admin.txt" TARGET
Select-String -Pattern '\bopen\b' -Path "C:\CCDC\Evidence\nmap_common_admin.txt" | Out-File "C:\CCDC\Evidence\nmap_common_admin_open.txt"
```

### 5) Virtual-host discovery (host-header probing; small wordlist)

```powershell
# VHost probe: try host headers from a small wordlist (wordlist.txt)
nmap -Pn -p 80,443 --script http-vhosts --script-args "brute.hosts=wordlist.txt" -oN "C:\CCDC\Evidence\nmap_vhosts.txt" TARGET
Select-String -Pattern '\bopen\b' -Path "C:\CCDC\Evidence\nmap_vhosts.txt" | Out-File "C:\CCDC\Evidence\nmap_vhosts_open.txt"
```

### 6) Full TCP sweep (all ports; deep �?" only if allowed)

```powershell
# Full TCP: all ports, OS & script detection (noisy/slow)
nmap -Pn -p- -T4 -A -oA "C:\CCDC\Evidence\nmap_full_tcp" TARGET
# Extract open ports from the normal .nmap output
Select-String -Pattern '\bopen\b' -Path "C:\CCDC\Evidence\nmap_full_tcp.nmap" | Out-File "C:\CCDC\Evidence\nmap_full_tcp_open.txt"
```

### 7) Quick grepable output (machine-parseable open ports list)

```powershell
# Grepable: produce a grepable output then parse open ports (works well for automation)
nmap -Pn -p- -T4 -oG "C:\CCDC\Evidence\nmap_grepable.txt" TARGET
Select-String -Pattern '/open/' -Path "C:\CCDC\Evidence\nmap_grepable.txt" | Out-File "C:\CCDC\Evidence\nmap_grepable_open.txt"
```

