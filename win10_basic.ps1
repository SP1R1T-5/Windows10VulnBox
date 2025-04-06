#  Vulnerability Simulation Script for Windows

# ------------------------------
# 1. Create User with Weak Password
# ------------------------------
net user vulnuser "Password1" /add
net localgroup administrators vulnuser /add

# ------------------------------
# 2. Disable Windows Firewall
# ------------------------------
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

# ------------------------------
# 3. Enable SMBv1 (vulnerable to EternalBlue)
# ------------------------------
Enable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -All -NoRestart
Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force

# ------------------------------
# 4. Simulate MS17-010 / EternalBlue Conditions
# ------------------------------
# Attempt to uninstall patch (optional - may fail silently)
wusa /uninstall /kb:4012212 /quiet /norestart
# Fake OS version in registry (spoofs for Nessus)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "ReleaseId" -Value "1607"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "CurrentBuild" -Value "14393"

# ------------------------------
# 5. Enable Anonymous Access & Guest SMB
# ------------------------------
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "restrictanonymous" -Value 0
Set-SmbServerConfiguration -EnableSMBGuestAccess $true -Force

# ------------------------------
# 6. Enable RDP and Disable NLA
# ------------------------------
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# ------------------------------
# 7. Install IIS (Default Web Server)
# ------------------------------
Install-WindowsFeature -Name Web-Server
Start-Service W3SVC

# ------------------------------
# 8. Install FTP Server (with open firewall)
# ------------------------------
Install-WindowsFeature Web-Ftp-Server
Set-Service ftpsvc -StartupType Automatic
Start-Service ftpsvc
netsh advfirewall firewall add rule name="FTP" dir=in action=allow protocol=TCP localport=21

# ------------------------------
# 9. Insecure Folder Permissions
# ------------------------------
New-Item -Path "C:\InsecureData" -ItemType Directory -Force
icacls "C:\InsecureData" /grant Everyone:(F)

# ------------------------------
# 10. Disable UAC (User Account Control)
# ------------------------------
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0

# ------------------------------
# 11. Disable Windows Defender Real-Time Protection
# ------------------------------
Set-MpPreference -DisableRealtimeMonitoring $true

# ------------------------------
# 12. Insecure Scheduled Task (Priv Esc)
# ------------------------------
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "Start-Process notepad.exe"
$trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "InsecureTask" -User "vulnuser" -Password "Password1" -RunLevel Highest

# ------------------------------
# 13. Unquoted Service Path (Privilege Escalation)
# ------------------------------
New-Item "C:\Program Files\Bad Service\" -ItemType Directory -Force
Copy-Item "C:\Windows\System32\notepad.exe" "C:\Program Files\Bad Service\bad.exe"
New-Service -Name "BadService" -BinaryPathName "C:\Program Files\Bad Service\bad.exe" -DisplayName "BadService" -StartupType Manual
Start-Service BadService

# ------------------------------
# 14. Enable Telnet (Legacy Protocol)
# ------------------------------
Install-WindowsFeature -Name Telnet-Client
Enable-WindowsOptionalFeature -Online -FeatureName TelnetServer -All -NoRestart

# ------------------------------
# 15. Install SNMP and Set Default Community String
# ------------------------------
Add-WindowsFeature SNMP-Service
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" -Name "public" -Value 4 -Type DWord

# ------------------------------
# 16. Simulate Old Software (Registry & File Bait)
# ------------------------------
New-Item -Path "C:\Program Files (x86)\OldApp\" -ItemType Directory -Force
New-ItemProperty -Path "HKLM:\Software\OldApp" -Name "Version" -Value "1.0.0.0" -PropertyType String -Force

# ------------------------------
# 17. Fake MySQL Installation (to trigger vuln alerts)
# ------------------------------
New-Item -Path "C:\Program Files\MySQL\MySQL Server 5.5" -ItemType Directory -Force
New-ItemProperty -Path "HKLM:\Software\MySQL AB\MySQL Server 5.5" -Name "Version" -Value "5.5.0" -PropertyType String -Force
New-NetFirewallRule -DisplayName "Fake MySQL" -Direction Inbound -Protocol TCP -LocalPort 3306 -Action Allow

# ------------------------------
# All Done!
# ------------------------------
Write-Host "`n[✔] Vulnerabilities simulated successfully!" -ForegroundColor Green
Write-Host "[!] Reboot is recommended to finalize some changes." -ForegroundColor Yellow


#Jon Fortnite
