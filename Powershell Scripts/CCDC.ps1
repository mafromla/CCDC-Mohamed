# ---------------------------
# CCDC: Initial Enumeration
# Paste & run in PowerShell ISE as Administrator
# ---------------------------

# --- Config ---
$target = "TARGET_OR_IP"      # <- replace with the host IP/hostname you'll be enumerating
$base = "C:\CCDC\Findings\Initial-Enumeration"
$nmapExe = "C:\Program Files (x86)\Nmap\nmap.exe"   # adjust if nmap is installed elsewhere
$winPeasPath = "$base\tools\winPEASx64.exe"        # place winPEAS here manually if download blocked
$timestamp = (Get-Date).ToString("yyyy-MM-dd_HH-mm-ss")
$zipOut = "C:\CCDC\Findings\Initial-Enumeration_$timestamp.zip"

# --- Prep folders ---
if (-not (Test-Path $base)) { New-Item -Path $base -ItemType Directory -Force | Out-Null }
if (-not (Test-Path "$base\tools")) { New-Item -Path "$base\tools" -ItemType Directory -Force | Out-Null }

# --- Start transcript (your provided line) ---
Start-Transcript -Path "$base\Transcript.txt" -Append

# --- Quick connectivity checks ---
Write-Output "=== Connectivity / DNS / Gateway ===" | Tee-Object -FilePath "$base\connectivity.txt" -Append
Test-Connection -ComputerName $target -Count 4 | Tee-Object -FilePath "$base\ping_target.txt"
Test-NetConnection -ComputerName $target -CommonTCPPort HTTP,HTTPS -InformationLevel Detailed | Tee-Object -FilePath "$base\test-netconnection_http_https.txt"

# DNS resolution
try { Resolve-DnsName $target | Out-File "$base\dns_resolution.txt" } catch { "Resolve-DnsName failed: $_" | Out-File "$base\dns_resolution_error.txt" }

# --- System info / quick host facts ---
Write-Output "=== System Info ===" | Tee-Object -FilePath "$base\systeminfo_header.txt" -Append
systeminfo | Out-File "$base\systeminfo.txt"

# --- IIS / Web checks (requires WebAdministration module) ---
Try {
  Import-Module WebAdministration -ErrorAction Stop
  Get-ChildItem IIS:\Sites | Select-Object Name,State,Bindings,PhysicalPath | Format-List | Out-File "$base\iis_sites_bindings.txt"
  Get-WebBinding | Format-Table -AutoSize | Out-File "$base\iis_all_bindings.txt"
  Get-ChildItem IIS:\AppPools | Select Name,state,managedRuntimeVersion | Format-Table | Out-File "$base\iis_apppools.txt"
  # copy applicationHost.config for Findings
  $ahc = "$env:windir\system32\inetsrv\config\applicationHost.config"
  if (Test-Path $ahc) { Copy-Item -Path $ahc -Destination "$base\applicationHost.config" -Force }
} Catch {
  "IIS check error: $_" | Out-File "$base\iis_error.txt"
}

# Check HTTPS certificate store and bindings (LocalMachine\My)
Try {
  Get-ChildItem Cert:\LocalMachine\My | Select Thumbprint,Subject,NotBefore,NotAfter | Format-Table | Out-File "$base\localmachine_my_certs.txt"
  Get-WebBinding -Protocol "https" | Select bindingInformation,certificateHash,certificateStoreName | Format-List | Out-File "$base\https_bindings_certs.txt"
} Catch { "Cert check error: $_" | Out-File "$base\cert_error.txt" }

# --- Webroot content & ACL checks ---
$webroots = @("C:\inetpub\wwwroot")  # add more webroots if you have custom paths
foreach ($p in $webroots) {
  if (Test-Path $p) {
    Get-ChildItem -Path $p -Recurse -Force -ErrorAction SilentlyContinue `
      | Where-Object { $_.Extension -match "\.aspx|\.php|\.jsp|\.ps1|\.exe|\.pl|\.bak|\.old|\.config|\.env|\.zip" } `
      | Select FullName,Length,LastWriteTime | Export-Csv -NoTypeInformation "$base\webroot_suspicious_files.csv" -Append

    # Files with Everyone write
    Get-ChildItem -Path $p -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
      try {
        $acl = Get-Acl $_.FullName -ErrorAction Stop
        $acl.Access | Where-Object { $_.IdentityReference -match "Everyone" -and ($_.FileSystemRights -match "Write") } |
          ForEach-Object { [PSCustomObject]@{ File = $_.Path; Identity = $_.IdentityReference; Rights = $_.FileSystemRights } } |
          Export-Csv -NoTypeInformation -Path "$base\webroot_everyone_write.csv" -Append
      } catch { }
    }
  } else { "$p not found" | Out-File "$base\webroot_paths_missing.txt" -Append }
}

# --- Services, processes, users, scheduled tasks ---
Get-Service | Where-Object {$_.Status -eq 'Running'} | Select Name,DisplayName,Status | Export-Csv -NoTypeInformation "$base\running_services.csv"
Get-Service | Select Name,DisplayName,Status | Export-Csv -NoTypeInformation "$base\all_services.csv"

Get-Process | Select-Object ProcessName,Id,CPU,StartTime -ErrorAction SilentlyContinue | Export-Csv -NoTypeInformation "$base\process_list.csv"

# Local users & groups
Try { Get-LocalUser | Select Name,Enabled,LastLogon | Export-Csv -NoTypeInformation "$base\local_users.csv" } Catch { "Get-LocalUser failed: $_" | Out-File "$base\local_users_error.txt" }
Try { Get-LocalGroup | Export-Csv -NoTypeInformation "$base\local_groups.csv" } Catch { "Get-LocalGroup failed: $_" | Out-File "$base\local_groups_error.txt" }

# Scheduled Tasks
Try { Get-ScheduledTask | Select TaskName,TaskPath,State | Export-Csv -NoTypeInformation "$base\scheduled_tasks.csv" } Catch { "ScheduledTask error: $_" | Out-File "$base\scheduled_tasks_error.txt" }

# --- Event logs & IIS logs (copy) ---
Try {
  wevtutil epl Application "$base\Application.evtx"
  wevtutil epl System "$base\System.evtx"
  wevtutil epl Security "$base\Security.evtx"
} Catch { "wevtutil export error: $_" | Out-File "$base\eventlogs_error.txt" }

$logPath = "C:\inetpub\logs\LogFiles"
if (Test-Path $logPath) {
  $dest = Join-Path $base "IIS_Logs"
  Copy-Item -Path $logPath\* -Destination $dest -Recurse -Force -ErrorAction SilentlyContinue
} else {
  "IIS logs not found at $logPath" | Out-File "$base\iis_logs_missing.txt"
}

# --- Netstat & current TCP connections ---
netstat -ano | Out-File "$base\netstat_ano.txt"
Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | Export-Csv -NoTypeInformation "$base\net_tcp_connections.csv"

# --- Nmap scans (use Nmap CLI installed with Zenmap). Save -oN outputs. ---
if (Test-Path $nmapExe) {
  # quick web-only nmap (HTTP/HTTPS)
  & "$nmapExe" -sS -sV -p 80,443 --script=http-title,http-headers,ssl-cert -oN "$base\nmap_web_quick_oN.txt" $target

  # moderate TCP scan for common admin ports
  & "$nmapExe" -sS -sV -p 21,22,23,25,53,80,110,139,143,389,443,445,3389 -oN "$base\nmap_common_tcp_oN.txt" $target

  # full TCP quick (if time) - takes longer
  # & "$nmapExe" -p- -T4 -A -oN "$base\nmap_full_tcp_oN.txt" $target
} else {
  "Nmap not found at $nmapExe. Adjust path or install Zenmap/Nmap." | Out-File "$base\nmap_missing.txt"
}

# --- winPEAS (if present) - run non-interactive and save output ---
if (Test-Path $winPeasPath) {
  Try {
    # ensure it's executable
    & $winPeasPath > "$base\winPEAS_output.txt"
  } Catch {
    "winPEAS run failed: $_" | Out-File "$base\winPEAS_error.txt"
  }
} else {
  "winPEAS not present at $winPeasPath - please copy it to $($winPeasPath) if you want it executed." | Out-File "$base\winpeas_missing.txt"
}

# --- Hash suspicious files (SHA256) ---
$susCSV = "$base\webroot_suspicious_files.csv"
if (Test-Path $susCSV) {
  Import-Csv $susCSV | ForEach-Object {
    $f = $_.FullName
    if (Test-Path $f) {
      Get-FileHash -Path $f -Algorithm SHA256 | Select-Object Path,Hash | Export-Csv -NoTypeInformation -Append "$base\suspicious_hashes.csv"
    }
  }
}

# --- Firewall hardening (COLLECT FIRST; APPLY right after script) ---
"*** FIREWALL HINTS (DO NOT RUN UNLESS run in this script) ***" | Out-File "$base\README_FIREWALL.txt" -Append
@"
# Quick hardening to BLOCK inbound/outbound by default and ALLOW only HTTP/HTTPS:
# 1) Set default policies (blocks everything inbound/outbound)
#    Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block -DefaultOutboundAction Block
# 2) Allow inbound HTTP/HTTPS
#    New-NetFirewallRule -DisplayName 'Allow HTTP (inbound)' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 80
#    New-NetFirewallRule -DisplayName 'Allow HTTPS (inbound)' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 443
# 3) Allow outbound HTTP/HTTPS
#    New-NetFirewallRule -DisplayName 'Allow HTTP (outbound)' -Direction Outbound -Action Allow -Protocol TCP -RemotePort 80
#    New-NetFirewallRule -DisplayName 'Allow HTTPS (outbound)' -Direction Outbound -Action Allow -Protocol TCP -RemotePort 443
# 4) OPTIONAL: allow DNS outbound (UDP 53) if needed
#    New-NetFirewallRule -DisplayName 'Allow DNS (outbound)' -Direction Outbound -Action Allow -Protocol UDP -RemotePort 53
"@ | Out-File "$base\README_FIREWALL.txt" -Append

# If you are ready and want to run it now uncomment the lines below and execute:
<#
Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block -DefaultOutboundAction Block
New-NetFirewallRule -DisplayName 'Allow HTTP (inbound)' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 80
New-NetFirewallRule -DisplayName 'Allow HTTPS (inbound)' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 443
New-NetFirewallRule -DisplayName 'Allow HTTP (outbound)' -Direction Outbound -Action Allow -Protocol TCP -RemotePort 80
New-NetFirewallRule -DisplayName 'Allow HTTPS (outbound)' -Direction Outbound -Action Allow -Protocol TCP -RemotePort 443
# OPTIONAL DNS:
# New-NetFirewallRule -DisplayName 'Allow DNS (outbound)' -Direction Outbound -Action Allow -Protocol UDP -RemotePort 53
#>

# --- Compress findings ---
Try {
  if (Test-Path $zipOut) { Remove-Item $zipOut -Force }
  Compress-Archive -Path "$base\*" -DestinationPath $zipOut -Force
  "Findings archived to $zipOut" | Out-File "$base\archive_note.txt"
} Catch { "Compress failed: $_" | Out-File "$base\zip_error.txt" }

# --- End transcript ---
Stop-Transcript
Write-Output "Initial enumeration complete. Findings saved to: $base (and $zipOut). Review README_FIREWALL.txt before making changes."