#############################
# New Server Config File	#
# Created by Dion Walker	#
# On 11/01/2021				#
# Revision 1				#
#############################

Start-Transcript C:\Temp\ServerDeployment.log

[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
[System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") | Out-Null
[System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic') | Out-Null

#Disable remote registry, print spooler services
#masadmin/16 character

#Get today's date
$date=Get-Date -UFormat "%m-%Y"

$usiDC="Domain2 DC FQDN"

$sourceDC="Domain1 DC FQDN"

Set-ExecutionPolicy Unrestricted -Force

#########################
# Set OS Requirements	#
#########################

#Disable IPv6
netsh interface ipv6 6to4 set state state=disabled undoonstop=disabled
netsh interface ipv6 isatap set state state=disabled
netsh interface teredo set state disabled

#Allow RDP through the FireWall
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

#Enable RDP to the server
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server'-name "fDenyTSConnections" -Value 0

#Enforce NLA for RDP
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "UserAuthentication" -Value 1
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "SecurityLayer" -Value 1

#Disable LLMNR
New-Item 'HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient' -PropertyType 'DWord' -name "EnableMulticast" -Value 0 -Force | Out-Null

#Disabled SSL 2.0
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
Write-Host 'SSL 2.0 has been disabled.'

#Disabled SSL 3.0
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
Write-Host 'SSL 3.0 has been disabled.'


#Disabled TLS 1.0
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
Write-Host 'TLS 1.0 has been disabled.'

#Disabled TLS 1.1
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
Write-Host 'TLS 1.1 has been disabled.'

#Disable PCT 1.0
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\' -Name 'Client' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\' -Name 'Server' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client' -Name 'DisabledByDefault' -Value 1 -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client' -Name 'Enabled' -Value 0 -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server' -Name 'DisabledByDefault' -Value 1 -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server' -Name 'Enabled' -Value 0 -Force | Out-Null

#Disable Multi-Protocol Unified Hello
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\' -Name 'Client' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\' -Name 'Server' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client' -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client' -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server' -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server' -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force | Out-Null

#Disable RC4 Ciphers
([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128')
New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\" -Name "RC4 128/128" -Force | Out-Null
New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128" -name "Enabled" -value "0" -PropertyType "DWord" -Force | Out-Null
([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128")
New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\" -Name "RC4 40/128" -Force | Out-Null
New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128" -name "Enabled" -value "0" -PropertyType "DWord" -Force | Out-Null
([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128")
New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\" -Name "RC4 56/128" -Force | Out-Null
New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128" -name "Enabled" -value "0" -PropertyType "DWord" -Force | Out-Null
([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128")
New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\" -Name "RC4 64/128" -Force | Out-Null
New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128" -name "Enabled" -value "0" -PropertyType "DWord" -Force | Out-Null
([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128")
New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\" -Name "RC2 128/128" -Force | Out-Null
New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128" -name "Enabled" -value "0" -PropertyType "DWord" -Force | Out-Null
([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128")
New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\" -Name "RC2 56/128" -Force | Out-Null
New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128" -name "Enabled" -value "0" -PropertyType "DWord" -Force | Out-Null
([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128")
New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\" -Name "RC2 40/128" -Force | Out-Null
New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128" -name "Enabled" -value "0" -PropertyType "DWord" -Force | Out-Null
([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56")
New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\" -Name "DES 56/56" -Force | Out-Null
New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56" -name "Enabled" -value "0" -PropertyType "DWord" -Force | Out-Null
([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168")
New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\" -Name "Triple DES 168" -Force | Out-Null
New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168" -name "Enabled" -value "0" -PropertyType "DWord" -Force | Out-Null
([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$env:COMPUTERNAME)).CreateSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL")
New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\" -Name "NULL" -Force | Out-Null
New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL" -name "Enabled" -value "0" -PropertyType "DWord" -Force | Out-Null

#Update version history on the server
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WinImgVer' -Name "DisplayName" -Value "Golden Image-$date"
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name "WinImgVer" -Value "Golden Image-$date"
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name "SrvComment" -Value "Golden Image"

#Configure BGInfo
Set-Location "C:\Program Files\Common Files\BGInfo"
.\Bginfo64.exe masconfig.bgi /accepteula /silent /timer 0

Set-Location "C:\Windows\System32"
secedit.exe /configure /db C:\Windows\security\local.sdb /cfg C:\Temp\Policies.inf


#########################################
# Configure Domain Specific Settings	#
#########################################
$ipaddress = [Microsoft.VisualBasic.Interaction]::InputBox("Please provide the IP Address for the new computer name","IP Address", "Please add your selection here e.g. 203.x.x.x, 10.x.x.x, 192.x.x.x")
$subnet = [Microsoft.VisualBasic.Interaction]::InputBox("Please provide the subnet mask in CIDR format for the new computer name","Subnet Mask", "Please add your selection here e.g. 20 (for 255.255.240),23 (for 255.255.254.0),24 (for 255.255.255.0)")
$gateway = [Microsoft.VisualBasic.Interaction]::InputBox("Please provide the gateway for the new computer name","Gateway", "Please add your selection here e.g. 203.x.x.x, 10.x.x.x, 10.123.90.x")
$dnsserver = [Microsoft.VisualBasic.Interaction]::InputBox("Please provide the DNS for the new computer name","DNS", "Please add your selection here e.g. 203.x.x.x, 10.x.x.x")
$hostname = [Microsoft.VisualBasic.Interaction]::InputBox("Please provide new computer name","New Machine Name", "Please add your selection here e.g. SCLTESTWNDEV01, SA0001V")
$domain=[Microsoft.VisualBasic.Interaction]::InputBox("Which domain will this server be located in?","Domain Selection", "Please add your selection here e.g. MHBK, MSUSA or Workgroup")

if ($domain -match "MHBK"){
	
	New-NetIPAddress -InterfaceIndex 3 -IPAddress $ipaddress -PrefixLength $subnet -DefaultGateway $gateway
	
	Set-DNSClientServerAddress -InterfaceIndex 3 -ServerAddresses $dnsserver

	Rename-Computer -NewName $hostname.ToUpper()
		
	Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\" -Name Domain -Value "domain1 FQDN"

	Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\" -Name "NV Domain" -Value "domain1 FQDN"

	New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force

	(Get-WmiObject -Class "win32_TSgeneralSetting" -Namespace root\cimv2\terminalservices -ComputerName $env:COMPUTERNAME -Filter "TerminalName= 'RDP-tcp'").UserAuthenticationRequired

	(Get-WmiObject -Class "win32_TSgeneralSetting" -Namespace root\cimv2\terminalservices -ComputerName $env:COMPUTERNAME -Filter "TerminalName= 'RDP-tcp'").SetUserAuthenticationRequired(0)

	Set-DNSClientGlobalSetting -SuffixSearchList @("domain1 FQDN","domain2 FQDN")

	Set-DNSClient -ConnectionSpecificSuffix "domain1 FQDN" -InterfaceIndex 3

	$username = [Microsoft.VisualBasic.Interaction]::InputBox("Please provide your Domain Admin name","Domain Admin Name", "Please add your selection here e.g. Admin Account Name")

	$cred="MD_USANYC\"+$username

	$tempname= $env:computername

	Add-Computer -DomainName domain1 FQDN -ComputerName $tempname -NewName $hostname -Credential $cred -OUPath "Target OU" -Server $sourceDC FQDN -Force -Confirm:$true
	
	Start-Sleep -Seconds 30
	
	Restart-Computer -Force
	
}elseif($domain -match "MSUSA"){

	New-NetIPAddress -InterfaceIndex 3 -IPAddress $ipaddress -PrefixLength $subnet -DefaultGateway $gateway
	
	Set-DNSClientServerAddress -InterfaceIndex 3 -ServerAddresses $dnsserver

	Rename-Computer -NewName $hostname.ToUpper()
	
	Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\" -Name Domain -Value "domain2 FQDN"

	Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\" -Name "NV Domain" -Value "domain2 FQDN"

	New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force

	(Get-WmiObject -Class "win32_TSgeneralSetting" -Namespace root\cimv2\terminalservices -ComputerName $env:COMPUTERNAME -Filter "TerminalName= 'RDP-tcp'").UserAuthenticationRequired

	(Get-WmiObject -Class "win32_TSgeneralSetting" -Namespace root\cimv2\terminalservices -ComputerName $env:COMPUTERNAME -Filter "TerminalName= 'RDP-tcp'").SetUserAuthenticationRequired(0)

	$username = [Microsoft.VisualBasic.Interaction]::InputBox("Please provide your Domain Admin name","Domain Admin Name", "Please add your selection here e.g. Admin Account Name")

	$cred="USI\"+$username

	$tempname= $env:computername

	Add-Computer -DomainName domain2 FQDN -ComputerName $tempname -NewName $hostname -Credential $cred -OUPath "Target OU" -Server $usiDC FQDN -Force -Confirm:$true

	Start-Sleep -Seconds 30
	
	Restart-Computer -Force
	
}elseif($domain -match "Workgroup"){

	New-NetIPAddress -InterfaceIndex 3 -IPAddress $ipaddress -PrefixLength $subnet -DefaultGateway $gateway
	
	Set-DNSClientServerAddress -InterfaceIndex 3 -ServerAddresses $dnsserver
	
	Rename-Computer -ComputerName $tempname -NewName $hostname.ToUpper()-Force -Confirm:$true
	
	Start-Sleep -Seconds 30
	
	Restart-Computer -Force
	
}else{
Write-Host "You have selected an incorrect IP Address. Please confirm and restart this program."
}

Stop-Transcript