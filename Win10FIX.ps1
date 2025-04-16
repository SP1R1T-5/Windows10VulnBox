#  Vulnerability Reversal Script for Windows

# ------------------------------
# 1. Remove User with Weak Password
# ------------------------------
net user vulnuser /delete

# ------------------------------
# 2. Enable Windows Firewall
# ------------------------------
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# ------------------------------
# 3. Disable SMBv1 (vulnerable to EternalBlue)
# ------------------------------
Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

# ------------------------------
# 4. Restore correct OS version information
# ------------------------------
# Get actual OS version information
$OSInfo = Get-WmiObject Win32_OperatingSystem
$BuildNumber = $OSInfo.BuildNumber
$Version = $OSInfo.Version

# Reset registry values to correct values
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "CurrentBuild" -Value $BuildNumber
# Get the actual release ID (this command gets the version info that contains the ReleaseId)
$WinVer = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId
# If this fails for any reason, set a reasonable modern value
if (!$WinVer) {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "ReleaseId" -Value "2004"
} else {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "ReleaseId" -Value $WinVer
}

# ------------------------------
# 5. Disable Anonymous Access & Guest SMB
# ------------------------------
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "restrictanonymous" -Value 2
Set-SmbServerConfiguration -EnableSMBGuestAccess $false -Force

# ------------------------------
# 6. Disable RDP and Enable NLA
# ------------------------------
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1
Disable-NetFirewallRule -DisplayGroup "Remote Desktop"
# Remove any custom RDP rules that were added
Remove-NetFirewallRule -DisplayName "RDP-TCP-In" -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName "RDP-UDP-In" -ErrorAction SilentlyContinue

# ------------------------------
# 7. Uninstall IIS (Web Server)
# ------------------------------
Stop-Service W3SVC -Force -ErrorAction SilentlyContinue
Uninstall-WindowsFeature -Name Web-Server

# ------------------------------
# 8. Uninstall FTP Server
# ------------------------------
Stop-Service ftpsvc -Force -ErrorAction SilentlyContinue
Uninstall-WindowsFeature Web-Ftp-Server
netsh advfirewall firewall delete rule name="FTP"

# ------------------------------
# 9. Secure Folder Permissions
# ------------------------------
icacls "C:\InsecureData" /reset
# Remove the insecure folder
Remove-Item -Path "C:\InsecureData" -Force -Recurse -ErrorAction SilentlyContinue

# ------------------------------
# 10. Enable UAC (User Account Control)
# ------------------------------
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1

# ------------------------------
# 11. Enable Windows Defender Real-Time Protection
# ------------------------------
Set-MpPreference -DisableRealtimeMonitoring $false

# ------------------------------
# 12. Remove Insecure Scheduled Task
# ------------------------------
Unregister-ScheduledTask -TaskName "InsecureTask" -Confirm:$false -ErrorAction SilentlyContinue

# ------------------------------
# 13. Remove Unquoted Service Path
# ------------------------------
Stop-Service -Name "BadService" -Force -ErrorAction SilentlyContinue
sc.exe delete BadService
Remove-Item "C:\Program Files\Bad Service\" -Recurse -Force -ErrorAction SilentlyContinue

# ------------------------------
# 14. Disable Telnet
# ------------------------------
Disable-WindowsOptionalFeature -Online -FeatureName TelnetServer -NoRestart
Uninstall-WindowsFeature -Name Telnet-Client -ErrorAction SilentlyContinue

# ------------------------------
# 15. Remove SNMP and Default Community String
# ------------------------------
Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" -Name "public" -ErrorAction SilentlyContinue
Remove-WindowsFeature SNMP-Service -ErrorAction SilentlyContinue

# ------------------------------
# 16. Remove Simulated Old Software
# ------------------------------
Remove-Item -Path "C:\Program Files (x86)\OldApp\" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\Software\OldApp" -Force -Recurse -ErrorAction SilentlyContinue

# ------------------------------
# 17. Remove Fake MySQL Installation
# ------------------------------
Remove-Item -Path "C:\Program Files\MySQL\MySQL Server 5.5" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\Software\MySQL AB\MySQL Server 5.5" -Force -Recurse -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName "Fake MySQL" -ErrorAction SilentlyContinue

# ------------------------------
# All Done!
# ------------------------------
Write-Host "`n[✔] Vulnerabilities remediated successfully!" -ForegroundColor Green
Write-Host "[!] Reboot is recommended to finalize security changes." -ForegroundColor Yellow
