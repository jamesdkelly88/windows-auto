# Execution Policy
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope LocalMachine -Force

# Enable RDP
Set-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\' -name 'fDenyTSConnections' -value 0
Set-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name 'UserAuthentication' -value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# Enable Ping
New-NetFirewallRule -DisplayName "ICMP Allow Ping V4" -Direction Inbound -Protocol ICMPv4 -IcmpType 8 -Action Allow

# Disable password complexity
secedit /export /cfg c:\secpol.cfg
(gc C:\secpol.cfg).replace("PasswordComplexity = 1","PasswordComplexity = 0") | Out-File C:\secpol.cfg
secedit /configure /db C:\windows\security\local.sdb /cfg c:\secpol.cfg /areas SECURITYPOLICY
rm -force c:\secpol.cfg -confirm:$false

# Add ansible user
New-LocalUser -Name ansible -Password (ConvertTo-SecureString "ansible" -AsPlainText -Force) -AccountNeverExpires -PasswordNeverExpires
Add-LocalGroupMember -Group Administrators -Member ansible

# Private networks
Foreach($p in Get-NetconnectionProfile) { $p| Set-NetConnectionProfile -NetworkCategory Private }

# WinRM
winrm quickconfig -quiet

# PSRemoting
Enable-PSRemoting

# Install SSH if not present
(Get-WindowsCapability -Online).Where{ $_.Name -like 'OpenSSH*' -and $_.State -eq "NotPresent" } | Add-WindowsCapability -Online

# Set SSH shell to powershell
Set-ItemProperty -Path HKLM:\SOFTWARE\OpenSSH -Name DefaultShell -value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Type String -Force

# Start SSH service & set to automatic
Set-Service -Name sshd -StartupType Automatic -Status Running

# Install NuGet package provider
Install-PackageProvider -Name Nuget -Force
