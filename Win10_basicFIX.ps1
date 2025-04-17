# Reversal Script for Vulnerability Simulation Script
# Run as Administrator

# 1. Remove the vulnuser account
net localgroup administrators vulnuser /delete
net user vulnuser /delete

# 2. Enable Windows Firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# 3. Disable SMBv1
Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

# 4. Reinstall MS17-010 patch & revert registry spoof
wusa /install /kb:4012212 /quiet /norestart
# Remove spoofed registry values
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "ReleaseId" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "CurrentBuild" -ErrorAction SilentlyContinue

# 5. Revert anonymous & guest SMB settings
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "restrictanonymous" -Value 1
Set-SmbServerConfiguration -EnableSMBGuestAccess $false -Force

# 6. Disable RDP and re-enable NLA
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1
Disable-NetFirewallRule -DisplayGroup "Remote Desktop"
Get-NetFirewallRule -DisplayName "RDP-TCP-In","RDP-UDP-In" | Remove-NetFirewallRule -Confirm:$false

# 7. Uninstall IIS
Stop-Service W3SVC -ErrorAction SilentlyContinue
Uninstall-WindowsFeature -Name Web-Server

# 8. Uninstall FTP Server
Stop-Service ftpsvc -ErrorAction SilentlyContinue
Uninstall-WindowsFeature -Name Web-Ftp-Server
netsh advfirewall firewall delete rule name="FTP"

# 9. Remove insecure folder
Remove-Item -Path "C:\InsecureData" -Recurse -Force -ErrorAction SilentlyContinue

# 10. Re-enable UAC
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1

# 11. Re-enable Defender real-time protection
Set-MpPreference -DisableRealtimeMonitoring $false

# 12. Remove insecure scheduled task
Unregister-ScheduledTask -TaskName "InsecureTask" -Confirm:$false

# 13. Remove unquoted service & cleanup
Stop-Service -Name "BadService" -ErrorAction SilentlyContinue
sc.exe delete "BadService"
Remove-Item -Path "C:\Program Files\Bad Service\" -Recurse -Force -ErrorAction SilentlyContinue

# 14. Uninstall Telnet
Uninstall-WindowsFeature -Name Telnet-Client
Disable-WindowsOptionalFeature -Online -FeatureName "TelnetServer" -NoRestart

# 15. Uninstall SNMP
Uninstall-WindowsFeature -Name SNMP-Service
Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" -Name "public" -ErrorAction SilentlyContinue

# 16. Remove OldApp bait
Remove-Item -Path "C:\Program Files (x86)\OldApp\" -Recurse -Force -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKLM:\Software\OldApp" -Name "Version" -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\Software\OldApp" -Recurse -Force -ErrorAction SilentlyContinue

# 17. Remove fake MySQL
netsh advfirewall firewall delete rule name="Fake MySQL"
Remove-ItemProperty -Path "HKLM:\Software\MySQL AB\MySQL Server 5.5" -Name "Version" -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Program Files\MySQL\MySQL Server 5.5" -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "`n[✔] Reversal complete! A reboot is recommended to apply all changes." -ForegroundColor Green

#Jon Fortnite
