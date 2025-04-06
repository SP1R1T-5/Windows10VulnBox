#  Alternative Windows Vulnerability Script
# Creates different artifacts for Nessus scans to detect
# Educational purposes only - for security training

# ------------------------------
# 1. Create Registry Evidence of Known CVEs
# ------------------------------
# Create registry entries that mimic specific CVE vulnerabilities
# CVE-2020-0601 (CurveBall / Windows CryptoAPI)
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" -Name "AllowEncryptionOracle" -Value 1 -PropertyType DWord -Force

# CVE-2019-0708 (BlueKeep)
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Force 
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "SecurityLayer" -Value 0 -PropertyType DWord -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "fDisableEncryption" -Value 1 -PropertyType DWord -Force

# CVE-2021-34527 (PrintNightmare)
New-Item -Path "HKLM:\System\CurrentControlSet\Control\Print" -Force
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Print" -Name "RpcAuthnLevelPrivacyEnabled" -Value 0 -PropertyType DWord -Force
Stop-Service -Name Spooler
Set-Service -Name Spooler -StartupType Automatic
Start-Service -Name Spooler

# ------------------------------
# ADDITIONAL CVEs
# ------------------------------

# CVE-2020-0646 (SharePoint Remote Code Execution)
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\16.0\WSS" -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\16.0\WSS" -Name "Version" -Value "16.0.10364.0" -PropertyType String -Force
# Create evidence of vulnerable SharePoint installation
New-Item -Path "C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\16" -ItemType Directory -Force
New-Item -Path "C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\16\ISAPI" -ItemType Directory -Force
New-Item -Path "C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\16\ISAPI\Microsoft.SharePoint.dll" -ItemType File -Force
# Create version file showing vulnerable version
$spVersion = @"
Microsoft SharePoint Server 2019
Version: 16.0.10364.20001
"@
New-Item -Path "C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\16\VERSION.txt" -ItemType File -Value $spVersion -Force
# Open SharePoint ports
New-NetFirewallRule -DisplayName "SharePoint" -Direction Inbound -Protocol TCP -LocalPort 80,443 -Action Allow

# CVE-2021-31979 (Windows Kernel Elevation of Privilege)
# Create kernel driver with vulnerable version info
New-Item -Path "C:\Windows\System32\drivers\win32kfull.sys.old" -ItemType File -Force
$kernelDrv = @"
Microsoft Windows Kernel
Version: 10.0.19041.964
"@
New-Item -Path "C:\Windows\System32\drivers\win32kfull.sys.version" -ItemType File -Value $kernelDrv -Force
# Create registry evidence of vulnerable driver
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Win32kFull" -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Win32kFull" -Name "DisplayVersion" -Value "10.0.19041.964" -PropertyType String -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Win32kFull" -Name "DisplayName" -Value "Windows Kernel Full Win32k" -PropertyType String -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Win32kFull" -Name "ImagePath" -Value "system32\drivers\win32kfull.sys" -PropertyType String -Force

# CVE-2019-1069 (Windows Task Scheduler Elevation of Privilege)
# Create evidence of vulnerable Task Scheduler version
New-Item -Path "C:\Windows\System32\tasks.old" -ItemType Directory -Force
$taskSchedVersion = @"
Windows Task Scheduler
Version: 10.0.17763.503
"@
New-Item -Path "C:\Windows\System32\tasks\version.txt" -ItemType File -Value $taskSchedVersion -Force
# Create registry evidence
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule" -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule" -Name "TaskSchedulerVersion" -Value "10.0.17763.503" -PropertyType String -Force
# Create registry key that enables legacy task format compatibility (vulnerability indicator)
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Configuration" -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Configuration" -Name "EnableLegacyFormatCompatibility" -Value 1 -PropertyType DWord -Force
# Modify service settings
Set-Service -Name Schedule -StartupType Automatic
Restart-Service -Name Schedule -Force

# ------------------------------
# 2. Simulate Insecure Cryptographic Configurations
# ------------------------------
# Enable weak ciphers and hashing algorithms
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56" -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56" -Name "Enabled" -Value 1 -PropertyType DWord -Force

# Add MD5 hashing support
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5" -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5" -Name "Enabled" -Value 1 -PropertyType DWord -Force

# Disable ASLR
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "MoveImages" -Value 0 -Force

# ------------------------------
# 3. Install More Vulnerable Software Versions
# ------------------------------
# Simulate OpenSSL Heartbleed vulnerability (CVE-2014-0160)
New-Item -Path "C:\Program Files\OpenSSL" -ItemType Directory -Force
New-Item -Path "C:\Program Files\OpenSSL\bin" -ItemType Directory -Force
New-Item -Path "C:\Program Files\OpenSSL\bin\openssl.exe" -ItemType File -Force
New-Item -Path "C:\Program Files\OpenSSL\VERSION.txt" -ItemType File -Value "OpenSSL 1.0.1f 6 Jan 2014" -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSL" -Name "Version" -Value "1.0.1f" -PropertyType String -Force

# Simulate JBoss vulnerabilities
New-Item -Path "C:\Program Files\JBoss\version.txt" -ItemType Directory -Force
New-Item -Path "C:\Program Files\JBoss\version.txt" -ItemType File -Value "JBoss Application Server 4.2.3.GA" -Force
New-NetFirewallRule -DisplayName "JBoss" -Direction Inbound -Protocol TCP -LocalPort 8080 -Action Allow

# Simulate Log4j vulnerability (CVE-2021-44228)
New-Item -Path "C:\Program Files\Apache\log4j" -ItemType Directory -Force
New-Item -Path "C:\Program Files\Apache\log4j\log4j-core-2.11.2.jar" -ItemType File -Force
# Create a mock Java properties file
$log4jProps = @"
log4j.rootLogger=DEBUG, CONSOLE
log4j.appender.CONSOLE=org.apache.log4j.ConsoleAppender
log4j.appender.CONSOLE.layout=org.apache.log4j.PatternLayout
log4j.appender.CONSOLE.layout.ConversionPattern=%m%n
"@
New-Item -Path "C:\Program Files\Apache\log4j\log4j.properties" -ItemType File -Value $log4jProps -Force

# Simulate Tomcat with vulnerable version
New-Item -Path "C:\Program Files\Apache Tomcat 7.0.59\VERSION.txt" -ItemType Directory -Force
New-Item -Path "C:\Program Files\Apache Tomcat 7.0.59\VERSION.txt" -ItemType File -Value "Apache Tomcat 7.0.59" -Force
New-NetFirewallRule -DisplayName "Tomcat" -Direction Inbound -Protocol TCP -LocalPort 8080 -Action Allow

# ------------------------------
# 4. Add Insecure Network Services
# ------------------------------
# Install TFTP Server (insecure file transfer)
New-Item -Path "C:\TFTP-Root" -ItemType Directory -Force
New-Item -Path "C:\TFTP-Root\config.txt" -ItemType File -Value "username=admin`npassword=admin123" -Force
New-NetFirewallRule -DisplayName "TFTP" -Direction Inbound -Protocol UDP -LocalPort 69 -Action Allow
# Simulate TFTP service
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TFTP" -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TFTP" -Name "Start" -Value 2 -PropertyType DWord -Force

# Install rsh/rlogin service artifacts
New-Item -Path "C:\Windows\System32\rsh.exe" -ItemType File -Force
New-Item -Path "C:\Windows\System32\rlogin.exe" -ItemType File -Force
New-NetFirewallRule -DisplayName "RSH" -Direction Inbound -Protocol TCP -LocalPort 514 -Action Allow
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RSH" -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RSH" -Name "Start" -Value 2 -PropertyType DWord -Force

# ------------------------------
# 5. DNS Server Vulnerabilities
# ------------------------------
# Install DNS Server role
Install-WindowsFeature -Name DNS -IncludeManagementTools
# Configure insecure DNS settings
Set-DnsServerRecursion -Enable $true
# Allow zone transfers to any server
Set-DnsServerPrimaryZone -Name "." -ZoneFile "root.dns" -DynamicUpdate None -SecureSecondaries TransferToAnyServer

# ------------------------------
# 6. Database Server Vulnerabilities
# ------------------------------
# Simulate MS SQL Server with SA blank password
New-Item -Path "C:\Program Files\Microsoft SQL Server\MSSQL11.SQLEXPRESS\MSSQL" -ItemType Directory -Force
# Create SQL config file with weak settings
$sqlConfig = @"
[MSSQL]
SA_PASSWORD=
ENABLE_SA=true
AUTH_MODE=mixed
"@
New-Item -Path "C:\Program Files\Microsoft SQL Server\MSSQL11.SQLEXPRESS\MSSQL\sql.ini" -ItemType File -Value $sqlConfig -Force
# Open SQL Server ports
New-NetFirewallRule -DisplayName "SQL Server" -Direction Inbound -Protocol TCP -LocalPort 1433 -Action Allow
New-NetFirewallRule -DisplayName "SQL Admin" -Direction Inbound -Protocol TCP -LocalPort 1434 -Action Allow

# ------------------------------
# 7. Unsecured SSL Private Keys
# ------------------------------
New-Item -Path "C:\SSL" -ItemType Directory -Force
# Create fake private key file
$fakePrivateKey = @"
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1DcJJRWLVNwJ8K6S1Z7xQ7K1Z8RKOSD3UD16XJmsDZ8eRVD8
PlytLzdDKLBjVfkAXDEcm2UpDgLUBHPYXiKX9xTRsxZ4QGBPSYykn5FP3/wNSQNd
+idlA8jZ+qqRxnS3pI3pI2lqOb6r4cB9Y6oQ2ZcFIJPbOCv4yWdCQDjKXLPoVxAQ
q/QkdH/AyhBfUC5M1NIz3pkPbzE2zcA91G4qtnx1WPp3aQvLtSIcbcBLdPis1/bR
tsQu3T0xA7+2mk/xV7tQZ3oNuKQEkF4UYTd7hvBXRTsCOCKKYS1a4e9J+YzR1Zb0
CzNw3WDeVuNUQXE3QzQPfxLDDEAXvNIFJgCUkQIDAQABAoIBAQCvUd3No2mJCvMp
CLWj7H+QN66KL7Ny/BY3fdXGWQHc9d9HjpVKSU5XReBJem6HQF/HeXfgOTFaA7Gw
FZt22VkC8GUWfYIeiJelogRmDwPAXeIK2iZ8g0t6A7GCoJE497GSY3vWx0hQgHvJ
+THTjnaPJ1U+NQEpZjKK8EEU4jmHqJyoMfLEhG7RHKw5rEYDlHoh1Kqcp1gS5F3N
5njDvCYcHMvxJMOGGhunXYQZhL0KHH5YgDDyaAMjQYxgk9YA+8ZeBI4RBEuHQQPt
+Yn9LEpRVu4E9yPVNoC0lN+EDYvQsepLk7D2S4PmEjxJN33ppwTFwKlKLVM7GpUC
tJzD3X0BAoGBAPtPmKmF55xJ+fhcFBnZefuKxh5yDQGzOOq3NVIi/jCvYFazBA2W
AQqsAjXdJzUubvS3wUT4ySbgBq6GOVLzsRLJ4WhtbG8x7gWL9oUZzX1yCOV9pyS3
I8bZ3WZWVdAwKxTYtARVXZ0JEhUYOJzJwAJEO/oULbP0S/HdQYw3IbgBAoGBANhL
xpEIInrX97UH0aCUUGi7+0xgWgHMPsqBLB9ygtI3iYH8NNjrwwxXQPqqTJEZIvTG
KXMZvBZBiRHXBJtIJFwGZhxB58C1O+vIKRXitaZGpx8ihQIrFOBAGwxUqFiBCjTv
02QE3QzEs7R+UIOfPMv7LU1/nQJj9SiU2n95rN3RAoGBAOTxvE24GMkC+XIKj6ww
LbFJEF6yFJM2HzZrvsQYF1CXyMPgjjR2/XV+X/Qxs45/JfmV4Uk2QsYQzVfXXi9l
aE3bGGT204G2uFUQD742jfIThcA7UtgYKo1U9RXvD6hL6PoyPGYRXvFKdlRCGKHc
OdbeVCa0AYYdlOR61UPQ5rgBAoGALIJEct56aBv5n54TTXnTLALQv/GYFjsHtGQc
+HN2YsB7+L/mOzwBbKfro5YvHNUGdnwkPAwIwVCCnGEnLTzTtFzL5bb0FVYHx23B
BZqQtcTAQtS7IEtw+zMqXcJgpGbiR5j2WdM6ISr/eBgLj8hRhNKEgjGXdJa57FLp
NG4bFbECgYA1KmTAC49+YKnxdRPVFKIVMBqEkScK9fzK2mUiB7/hGZdC4qdf3hJh
qG3XG0hULPUlgQXEwrp9Q/QChqX4ZcNvTwWUvba63fKHRYdu51mhfYJlFQ93Z6oE
+pR+2rasxQSrLnQVVp+QHgYMnsibKL3KjX7CrQGRIbp1HlbDIBEw9Q==
-----END RSA PRIVATE KEY-----
"@
New-Item -Path "C:\SSL\server.key" -ItemType File -Value $fakePrivateKey -Force
# Set insecure permissions
icacls "C:\SSL\server.key" /grant Everyone:(R)

# ------------------------------
# 8. Windows Defender Exclusions
# ------------------------------
# Add suspicious exclusions
Add-MpPreference -ExclusionPath "C:\Windows\System32"
Add-MpPreference -ExclusionPath "C:\Program Files"
Add-MpPreference -ExclusionPath "C:\Users"
Add-MpPreference -ExclusionProcess "powershell.exe"
Add-MpPreference -ExclusionProcess "cmd.exe"

# ------------------------------
# 9. Simulate Pass-the-Hash Vulnerability
# ------------------------------
# Disable additional security features
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 1 -Type DWord -Force
# Enable NTLM authentication
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value 0 -Type DWord -Force
# Disable Credential Guard
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "RequirePlatformSecurityFeatures" -Value 0 -Type DWord -Force

# ------------------------------
# 10. Windows Update Vulnerabilities
# ------------------------------
# Disable Windows Update completely
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Force
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 1 -Type DWord -Force
# Create evidence of failed updates
New-Item -Path "C:\Windows\WindowsUpdate.log" -ItemType File -Force
$updateLog = @"
WindowsUpdate 2024-04-01 14:32:15:123 ERROR: Failed to download update package KB5034441
WindowsUpdate 2024-04-01 15:22:33:456 ERROR: Installation of security update KB5034765 failed, error code 0x80070643
WindowsUpdate 2024-04-02 09:17:42:789 WARNING: Skipping critical update KB5034951, dependency missing
WindowsUpdate 2024-04-03 11:45:12:345 ERROR: Failed to install security update KB5035232, reverting changes
"@
Set-Content -Path "C:\Windows\WindowsUpdate.log" -Value $updateLog -Force

# ------------------------------
# 11. PowerShell Logging Vulnerabilities
# ------------------------------
# Disable PowerShell script block logging
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 0 -Type DWord -Force
# Disable PowerShell module logging
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 0 -Type DWord -Force
# Disable PowerShell transcription
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 0 -Type DWord -Force

# ------------------------------
# 12. WSUS Configuration Problems
# ------------------------------
# Create insecure WSUS configuration
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer" -Value "http://fakeserver:8530" -Type String -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUStatusServer" -Value "http://fakeserver:8530" -Type String -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "UseWUServer" -Value 1 -Type DWord -Force

# ------------------------------
# 13. Create Suspicious Scheduled Tasks
# ------------------------------
# Create a suspicious scheduled task (mimics persistence technique)
$maliciousAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command `"& {Get-Process | Out-File C:\temp\proc.txt}`""
$trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -Action $maliciousAction -Trigger $trigger -TaskName "SystemDebugger" -Description "System Maintenance Task" -User "SYSTEM"
# Create another suspicious task
$maliciousAction2 = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c net user administrator /active:yes"
$trigger2 = New-ScheduledTaskTrigger -Daily -At "3:00AM"
Register-ScheduledTask -Action $maliciousAction2 -Trigger $trigger2 -TaskName "MaintHelper" -Description "Windows Helper Service" -User "SYSTEM"

# ------------------------------
# 14. Group Policy Setting Vulnerabilities
# ------------------------------
# Disable User Account Control completely
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 0 -Type DWord -Force
# Disable password complexity requirements
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RequireStrongKey" -Value 0 -Type DWord -Force
# Allow storing passwords with reversible encryption
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SAM" -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SAM" -Name "LmCompatibilityLevel" -Value 1 -Type DWord -Force

# ------------------------------
# 15. Registry Persistence Mechanisms
# ------------------------------
# Create run keys for persistence (common malware technique)
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SystemMonitor" -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\Windows\debug.ps1" -Type String -Force
# Create startup script
New-Item -Path "C:\Windows\debug.ps1" -ItemType File -Value "# System monitoring service`nGet-Process | Out-File C:\temp\proc.txt" -Force
# Add run once key
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Name "SecurityUpdate" -Value "regsvr32.exe /s C:\Windows\System32\vbscript.dll" -Type String -Force

# ------------------------------
# 16. Misconfigured IIS SSL/TLS
# ------------------------------
# Install IIS if not already installed
Install-WindowsFeature -Name Web-Server -IncludeManagementTools
# Create insecure SSL binding
$webConfig = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <security>
            <access sslFlags="None" />
        </security>
    </system.webServer>
    <system.web>
        <httpCookies requireSSL="false" />
        <authentication mode="Forms">
            <forms requireSSL="false" />
        </authentication>
    </system.web>
</configuration>
"@
New-Item -Path "C:\inetpub\wwwroot\web.config" -ItemType File -Value $webConfig -Force
# Create self-signed cert
$cert = New-SelfSignedCertificate -DnsName "www.example.com" -CertStoreLocation "cert:\LocalMachine\My"
# Export private key with weak security
$certPath = "C:\inetpub\certs"
New-Item -Path $certPath -ItemType Directory -Force
Export-PfxCertificate -Cert "cert:\LocalMachine\My\$($cert.Thumbprint)" -FilePath "$certPath\iisserver.pfx" -Password (ConvertTo-SecureString -String "password" -Force -AsPlainText)
icacls "$certPath\iisserver.pfx" /grant Everyone:(R)

# ------------------------------
# 17. Create Evidence of Log Clearing
# ------------------------------
# Clear security logs
wevtutil cl Security
# Create suspicious log clearing evidence
$logClearScript = @"
# Log clearing script
wevtutil cl System
wevtutil cl Security
wevtutil cl Application
Write-Host "Logs cleared successfully"
"@
New-Item -Path "C:\Windows\Temp\clear_logs.ps1" -ItemType File -Value $logClearScript -Force
# Disable Windows Event Log service
Set-Service -Name EventLog -StartupType Disabled

# ------------------------------
# 18. Unsecured Internal Certificates
# ------------------------------
# Create fake root CA certificate
New-Item -Path "C:\Certificates" -ItemType Directory -Force
$rootCaCert = @"
-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUE9x6mUQ2OUjKTMK5u/VW7n4RLL0wDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMDA0MDExMjAwMDBaFw0yMTA0
MDExMjAwMDBaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCqA7yKiQPQs19pZ5XAHafGEJeBlA5A32ai5aXTQD6U
I3QeC9qN9M3E1O7UzrfGCEZB3YWkGBwouZ9a+K1bKgT6uMpwHO+5s6tJLgsHGBTH
I6U8y5K1Re6v38JUjQ4DKiM3WYP16ASJB8lVfzsC0WSCMznwXFMwbk8WsXCPK9IQ
VyUUUK6OF3GNElRWIzEWLo+HsNKfAx4XBIuKlXwQgVn5OugNYEDR2Fzz4JQnEzA1
B4y8uIR27Rt9BZyBwEsIFcIVgQRkhHGiLz4QUlYuQcx9BrQfXEkR9R64qiXDOPOw
7H8PpXIgud1Hu1cHwxzA4wErL7xn5qVbTl/8YUZ0f0lXAgMBAAGjUzBRMB0GA1Ud
DgQWBBTQUfdJQIGEGRLO8N9F9TAizZHungAfBgNVHSMEGDAWgBTQUfdJQIGEGRLO
8N9
