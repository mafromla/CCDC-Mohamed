Use this document to run manual, one-by-one checks for IIS/websites.  
Everything writes to `C:\\CCDC\\Evidence\\Web-Enumeration\\` so your transcript and artifacts stay organized.

> **Before you start:** open PowerShell ISE **as Administrator**. Run the `Start-Transcript` command first so each command and its output are recorded.

---

## Setup / Transcript / Evidence folder

```powershell
# Create evidence folder and start transcript (run once at start)
$Base = "C:\\CCDC\\Evidence\\Web-Enumeration"
New-Item -Path $Base -ItemType Directory -Force | Out-Null
Start-Transcript -Path "$Base\\Transcript.txt" -Append
```

### Basic environment checks (run first)

```powershell
# PowerShell bitness, user, basic system info
$env:PROCESSOR_ARCHITECTURE
whoami
$PSVersionTable.PSVersion

# Confirm IIS module available and IIS feature status
Get-Module -ListAvailable WebAdministration | Format-Table -AutoSize
Get-WindowsFeature Web-Server,Web-Scripting-Tools | Format-Table DisplayName,Name,InstallState

# Check W3SVC (IIS) service
Get-Service W3SVC -ErrorAction SilentlyContinue | Format-Table Name,Status
Test-Path IIS:\\Sites
```

If Import-Module WebAdministration fails later, these outputs will help explain why — they should be captured in the transcript.

### Import module & list sites (if available)

```powershell
# Import module (must be 64-bit PS & elevated)
Import-Module WebAdministration -ErrorAction Stop

# List all sites with key info
Get-ChildItem "IIS:\Sites" | Select-Object `
  @{Name='Site';Expression={$_.Name}}, `
  @{Name='State';Expression={$_.State}}, `
  @{Name='Bindings';Expression={($_.Bindings | ForEach-Object {$_.bindingInformation}) -join ', '}}, `
  @{Name='PhysicalPath';Expression={$_.PhysicalPath}} | Format-Table -AutoSize

# Alternate (appcmd)
& "$env:windir\\system32\\inetsrv\\appcmd.exe" list site /text:name,bindings,state > "$Base\\appcmd_sites.txt"
```

### Bindings / host headers / SNI / ports

```powershell
# Show bindings and certificate hashes (http/https)
Get-WebBinding | Select protocol,bindingInformation,certificateHash,certificateStoreName,sslFlags | Format-Table -AutoSize > "$Base\\web_bindings.txt"

# Check SNI flags for HTTPS bindings
Get-WebBinding | Where-Object { $_.protocol -eq 'https' } | Select bindingInformation, sslFlags | Format-Table -AutoSize
```

### Map hostnames to sites (example: replace example.com)

```powershell
# Replace example.com with hostname to check which binding matches
$hostname = "example.com"
Get-WebBinding | Where-Object {
    $_.bindingInformation -like "*:80:$hostname" -or $_.bindingInformation -like "*:443:$hostname"
} | Format-Table protocol,bindingInformation | Out-File "$Base\binding_match_$($hostname).txt"

```

### Find physical site roots, virtual directories & apps

```powershell
# Show physical path for each site
Get-ChildItem IIS:\\Sites | Select Name, PhysicalPath | Format-Table -AutoSize > "$Base\\site_physicalpaths.txt"

# List web applications and virtual directories
Get-WebApplication | Select ApplicationPool, Path, PhysicalPath, PSParentPath | Format-Table -AutoSize > "$Base\\web_applications.txt"
Get-WebVirtualDirectory | Select PSParentPath, Path, PhysicalPath | Format-Table -AutoSize > "$Base\\web_virtualdirs.txt"
```

### Quick local HTTP/HTTPS test (save HTML)

```powershell
# HTTP (local)
Invoke-WebRequest -Uri "http://localhost/" -UseBasicParsing -OutFile "$Base\\localhost_http.html"

# HTTPS (use curl to ignore cert errors if needed)
curl.exe -k -v https://localhost/ 2>&1 | Out-File "$Base\\localhost_https_raw.txt"
```

### Search webroots for suspicious files (web shells, backups, configs)

```powershell
# Build list of roots from sites, then search each
$roots = Get-ChildItem IIS:\\Sites | ForEach-Object { $_.PhysicalPath } | Where-Object { Test-Path $_ } | Sort-Object -Unique
foreach ($r in $roots) {
  Get-ChildItem -Path $r -Recurse -ErrorAction SilentlyContinue -Force -Include *.aspx,*.php,*.jsp,*.ps1,*.pl,*.bak,*.old,*.config,*.env,*.zip |
    Select FullName,Length,LastWriteTime | Export-Csv -NoTypeInformation -Append "$Base\\webroot_suspicious_files.csv"
}
```

### Check file/folder ACLs for "Everyone" write permission

```powershell
foreach ($r in $roots) {
  Get-ChildItem -Path $r -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
    try { $acl = Get-Acl $_.FullName } catch { return }
    $acl.Access | Where-Object { $_.IdentityReference -like "*Everyone*" -and ($_.FileSystemRights -match "Write") } |
      ForEach-Object { [PSCustomObject]@{ Path = $_.Path; Identity = $_.IdentityReference; Rights = $_.FileSystemRights } }
  } | Export-Csv -NoTypeInformation "$Base\\webroot_everyone_write.csv" -Append
}
```

### Authentication & Directory Browsing (check per-site)

```powershell
# Example: check Default Web Site (replace name as needed)
$site = "Default Web Site"

# Anonymous / Windows / Basic
Get-WebConfigurationProperty -pspath "IIS:\\Sites\\$site" -filter "system.webServer/security/authentication/anonymousAuthentication" -name enabled > "$Base\\$site-anonymous.txt"
Get-WebConfigurationProperty -pspath "IIS:\\Sites\\$site" -filter "system.webServer/security/authentication/windowsAuthentication" -name enabled > "$Base\\$site-windowsauth.txt"
Get-WebConfigurationProperty -pspath "IIS:\\Sites\\$site" -filter "system.webServer/security/authentication/basicAuthentication" -name enabled > "$Base\\$site-basicauth.txt"

# Directory browsing
Get-WebConfigurationProperty -pspath "IIS:\\Sites\\$site" -filter "system.webServer/directoryBrowse" -name enabled > "$Base\\$site-directorybrowse.txt"
```

### SSL Certificates (list & match thumbprints)

```powershell
# List certs in LocalMachine\\My
Get-ChildItem Cert:\\LocalMachine\\My | Select Thumbprint, Subject, NotBefore, NotAfter | Format-Table -AutoSize > "$Base\\localmachine_my_certs.txt"

# If binding shows certificateHash, match it (replace THUMBPRINT)
$thumb = "THUMBPRINT"
Get-ChildItem Cert:\\LocalMachine\\My | Where-Object { $_.Thumbprint -eq $thumb } | Format-List Subject, NotBefore, NotAfter, Thumbprint > "$Base\\cert_match_$thumb.txt"
```

### App Pools & Identities (check privilege level)

```powershell
Get-ChildItem IIS:\\AppPools | ForEach-Object {
  $pool = $_.Name
  $idType = (Get-Item "IIS:\\AppPools\\$pool").processModel.identityType
  [PSCustomObject]@{ AppPool = $pool; IdentityType = $idType }
} | Format-Table -AutoSize > "$Base\\app_pools_identities.txt"
```

### Which process owns ports 80/443 (PID -> process)

```powershell
# Netstat + PID mapping
netstat -ano | findstr ":80 " > "$Base\\netstat_80.txt"
netstat -ano | findstr ":443 " > "$Base\\netstat_443.txt"

# Map PIDs to process names
Get-Content "$Base\\netstat_80.txt"
Get-Content "$Base\\netstat_443.txt"
# Inspect specific PID e.g. 1234
Get-Process -Id 1234 | Select Id,ProcessName,Path | Format-Table -AutoSize
```

### IIS logs (copy for analysis)

```powershell
$logPath = "C:\\inetpub\\logs\\LogFiles"
if (Test-Path $logPath) {
  Copy-Item -Path "$logPath\\*" -Destination "$Base\\IIS_Logs" -Recurse -Force
}
```

### Quick remediation commands (only run if authorized)

```powershell
# Disable directory browsing for a site
Set-WebConfigurationProperty -pspath "IIS:\\Sites\\$site" -filter "system.webServer/directoryBrowse" -name "enabled" -value $false

# Disable anonymous authentication (only if alternate auth configured)
Set-WebConfigurationProperty -pspath "IIS:\\Sites\\$site" -filter "system.webServer/security/authentication/anonymousAuthentication" -name "enabled" -value $false

# Remove Everyone write from folder (example)
icacls "C:\\inetpub\\wwwroot\\somefolder" /remove:g Everyone
```

### Firewall: allow only ports 80 & 443 (DO NOT RUN until you are sure you won't lock yourself out)

```powershell
# Add temporary allow for your admin RDP/IP first (replace <ADMIN_IP>)
New-NetFirewallRule -DisplayName "Allow Admin RDP" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 3389 -RemoteAddress <ADMIN_IP>

# Set default to block inbound/outbound
Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block -DefaultOutboundAction Block

# Allow only HTTP/HTTPS
New-NetFirewallRule -DisplayName "Allow HTTP In" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 80
New-NetFirewallRule -DisplayName "Allow HTTPS In" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 443
New-NetFirewallRule -DisplayName "Allow HTTP Out" -Direction Outbound -Action Allow -Protocol TCP -RemotePort 80
New-NetFirewallRule -DisplayName "Allow HTTPS Out" -Direction Outbound -Action Allow -Protocol TCP -RemotePort 443

# Enable logging for blocked packets
Set-NetFirewallProfile -Profile Domain,Private,Public -LogAllowed True -LogBlocked True
```

### Archive & finish

```powershell
# Zip all evidence (run when finished)
$ts = (Get-Date).ToString('yyyy-MM-dd_HH-mm-ss')
Compress-Archive -Path "$Base\\*" -DestinationPath "C:\\CCDC\\Evidence\\Web-Enumeration_$ts.zip" -Force

# Stop transcript when you're done
Stop-Transcript
```

