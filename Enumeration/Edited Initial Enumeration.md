# 🧩 CCDC — Basic Manual Enumeration (PowerShell ISE, Run as Administrator)

This document provides **manual enumeration commands** to run one at a time during the competition. We should run this while downloading winPEAS and Zenmap.

Each command is designed to log into the transcript file for record-keeping.  
All sections use fenced code blocks for easy copying into Obsidian or any Markdown editor.

---

## 🧰 Step 1 — Start Transcript

Record all commands and outputs to a transcript file.

```powershell
Start-Transcript -Path "C:\CCDC\Evidence\Initial-Enumeration\Transcript.txt" -Append
```

## 🌐 Network & System Basics

```powershell
ipconfig /all
whoami
hostname
net config workstation
systeminfo | find "OS"
```

Purpose:
Collect IP configuration, DNS settings, hostname, and OS version/build details.

## 👤 System & Accounts

```powershell
net user
Get-LocalUser
net localgroup administrators
Get-LocalUser | Where-Object { $_.Enabled -eq $true }
```

Purpose:
List local users, identify administrators, and check for enabled/suspicious accounts.

## ⚙️ Services & Processes

```powershell
Get-Service | Where-Object {$_.Status -eq "Running"}
sc query type= service state= all
tasklist
```

Optional:
If Sysinternals tools are available, use Process Explorer for deeper inspection.

Purpose:
Identify running services and processes that may be vulnerable or unnecessary.

## 🧱 Firewall — Export, Review, and Restrict Ports

### 🔹 Export Current Firewall Policy

```powershell
netsh advfirewall export "C:\CCDC\Evidence\fw_policy.wfw"
```

### 🔹 Review Current Profiles

```powershell
netsh advfirewall show allprofiles
```

### 🔹 Set Default Block Policy (Inbound & Outbound)

```powershell
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound
```

### 🔹 Allow Only HTTP & HTTPS (Inbound/Outbound)

```powershell
netsh advfirewall firewall add rule name="Allow HTTP (Inbound)"  dir=in  action=allow protocol=TCP localport=80
netsh advfirewall firewall add rule name="Allow HTTPS (Inbound)" dir=in  action=allow protocol=TCP localport=443
netsh advfirewall firewall add rule name="Allow HTTP (Outbound)" dir=out action=allow protocol=TCP remoteport=80
netsh advfirewall firewall add rule name="Allow HTTPS (Outbound)" dir=out action=allow protocol=TCP remoteport=443
```

### 🔹 Enable Logging of Dropped Connections

```powershell
netsh advfirewall set allprofiles logging droppedconnections enable
```

Purpose:
Export firewall configuration, enforce block-all-by-default, allow only ports 80/443, and enable dropped connection logging.

## 🧩 Patching & Updates

```powershell
Get-HotFix
```

Manual Checks:
- Run winver to confirm Windows version/build.
- Open Control Panel → Windows Update or gpedit.msc to verify update policy.

Purpose:
Review patch level and ensure update configuration is correct.

## 🔌 Network & NTP Configuration

```powershell
ipconfig /all
w32tm /query /status
w32tm /query /peers
```

Purpose:
Review network configuration and time synchronization (NTP) settings.

## 🦠 Malware & Startup Checks

```powershell
Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location | Format-Table -AutoSize
```

Purpose:
Identify startup programs that could indicate persistence or malware.

## 📋 Event Logs (Export Key Logs)

```powershell
wevtutil epl Application "C:\CCDC\Evidence\Logs\Application.evtx"
wevtutil epl System "C:\CCDC\Evidence\Logs\System.evtx"
wevtutil epl Security "C:\CCDC\Evidence\Logs\Security.evtx"

Purpose:
Export Application, System, and Security logs for offline analysis.

## 🧾 Evidence & Notes

```powershell
notepad "C:\CCDC\Evidence\Initial-Enumeration\Notes.txt"
```

Purpose:
Use Notepad to record findings, suspicious accounts, or configuration issues.

## 📦 Archive All Findings

```powershell
$ts = (Get-Date).ToString("yyyy-MM-dd_HH-mm-ss")
Compress-Archive -Path "C:\CCDC\Evidence\Initial-Enumeration\*" -DestinationPath "C:\CCDC\Evidence\Initial-Enumeration_$ts.zip" -Force
```

Purpose:
Compress all collected evidence into a timestamped ZIP file.

## 🛑 Stop Transcript

```powershell
Stop-Transcript
```

Purpose:
End recording once you complete all manual enumeration steps.

💡 Tip:
Run each section manually (in order: Network → Accounts → Services → Firewall → Updates → Logs).
Every command's output will be captured in the transcript file at:
`C:\CCDC\Evidence\Initial-Enumeration\Transcript.txt`

