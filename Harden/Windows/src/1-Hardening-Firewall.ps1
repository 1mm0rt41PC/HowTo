# Cleaning firewall rules
netsh advfirewall set AllProfiles state on
Set-NetFirewallProfile -DefaultInboundAction Block
echo 'Cleaning old rules ...'
Get-NetFirewallRule | where { -not $_.Name.StartsWith("[AutoHarden-$AutoHarden_version]") -and -not $_.Name.StartsWith("[AutoHarden]") } | Remove-NetFirewallRule
Get-NetFirewallRule -Name '*AutoHarden*' | Enable-NetFirewallRule

# Ref: https://en.wikipedia.org/wiki/Reserved_IP_addresses
$IPForInternet=@('1.0.0.0-9.255.255.255',
'11.0.0.0-100.63.255.255',
'100.128.0.0-126.255.255.255',
'128.0.0.0-169.253.255.255',
'169.255.0.0-172.15.255.255',
'172.32.0.0-191.255.255.255',
'192.0.1.0-192.0.1.255',
'192.0.3.0-192.167.255.255',
'192.169.0.0-198.17.255.255',
'198.20.0.0-198.51.99.255',
'198.51.101.0-203.0.112.255',
'203.0.114.0-255.255.255.254')

function blockExe( $name, $exe, $group, [Parameter(Mandatory=$false)] $allowNonRoutableIP=$false ){
	get-item -ErrorAction Ignore $exe | foreach {
		$bin=$_.Fullname
		if( $allowNonRoutableIP ){	
			New-NetFirewallRule -direction Outbound -Action Block -Program $bin -RemoteAddress $IPForInternet -Group "AutoHarden-$group" -Name ("[AutoHarden-$AutoHarden_version][Except Intranet] "+$name+" : "+$bin) -DisplayName ("[AutoHarden-$AutoHarden_version][Except Intranet] "+$name+" : "+$bin) -ErrorAction Ignore
		}else{
			New-NetFirewallRule -direction Outbound -Action Block -Program $bin -Group "AutoHarden-$group" -Name ("[AutoHarden-$AutoHarden_version] "+$name+" : "+$bin) -DisplayName ("[AutoHarden-$AutoHarden_version] "+$name+" : "+$bin) -ErrorAction Ignore
		}
	}
}

if( (ask "Block communication for evil tools ?" "block-communication-for-powershell,eviltools.ask") -eq $true ){
	blockExe "Powershell" "C:\Windows\WinSxS\*\powershell.exe" "LOLBAS" $true
	blockExe "Powershell" "C:\Windows\WinSxS\*\PowerShell_ISE.exe" "LOLBAS" $true
	blockExe "Powershell" "C:\Windows\*\WindowsPowerShell\v1.0\powershell.exe" "LOLBAS" $true
	blockExe "Powershell" "C:\Windows\*\WindowsPowerShell\v1.0\PowerShell_ISE.exe" "LOLBAS" $true
	
	blockExe "WScript" "C:\Windows\system32\wscript.exe" "LOLBAS" $true
	blockExe "BitsAdmin" "C:\Windows\system32\BitsAdmin.exe" "LOLBAS" $true
	blockExe "Mshta" "C:\Windows\system32\mshta.exe" "LOLBAS" $true
	blockExe "CertUtil" "C:\Windows\System32\certutil.exe" "LOLBAS" $true
	blockExe "HH" "C:\Windows\*\hh.exe" "LOLBAS" $true
	blockExe "HH" "C:\Windows\hh.exe" "LOLBAS" $true
	blockExe "IEexec" "C:\Windows\Microsoft.NET\*\*\ieexec.exe" "LOLBAS" $true
}else{
	"Powershell", "WScript", "BitsAdmin", "Mshta", "CertUtil", "HH", "IEexec" | foreach {
		Get-NetFirewallRule -Name ("*AutoHarden*"+$_+"*") | Remove-NetFirewallRule
	}
}

if( (ask "Block communication for Word and Excel ?" "block-communication-for-excel,word.ask") -eq $true ){
	blockExe "Excel" "C:\Program Files*\Microsoft Office*\root\*\EXCEL.EXE" "Office" $true
	blockExe "Excel" "C:\Program Files*\Microsoft Office*\*\root\*\EXCEL.EXE" "Office" $true
	blockExe "Excel" "C:\Program Files*\Microsoft Office*\*\EXCEL.EXE" "Office" $true
	
	blockExe "Word" "C:\Program Files*\Microsoft Office*\root\*\winword.exe" "Office" $true
	blockExe "Word" "C:\Program Files*\Microsoft Office*\*\root\*\winword.exe" "Office" $true
	blockExe "Word" "C:\Program Files*\Microsoft Office*\*\winword.exe" "Office" $true
	
	blockExe "PowerPoint" "C:\Program Files*\Microsoft Office*\root\*\Powerpnt.exe" "Office" $true
	blockExe "PowerPoint" "C:\Program Files*\Microsoft Office*\*\root\*\Powerpnt.exe" "Office" $true
	blockExe "PowerPoint" "C:\Program Files*\Microsoft Office*\*\Powerpnt.exe" "Office" $true
	
	blockExe "Teams" "${env:localappdata}\Microsoft\Teams\*\Squirrel.exe" "Office" $true
	blockExe "Teams" "${env:localappdata}\Microsoft\Teams\update.exe" "Office" $true
}else{
	Get-NetFirewallRule -Name '*AutoHarden*Excel*' | Remove-NetFirewallRule
	Get-NetFirewallRule -Name '*AutoHarden*Word*' | Remove-NetFirewallRule
	Get-NetFirewallRule -Name '*AutoHarden*PowerPoint*' | Remove-NetFirewallRule
	Get-NetFirewallRule -Name '*AutoHarden*Teams*' | Remove-NetFirewallRule
}

if( (ask "Block communication for InternetExplorer ?" "block-communication-for-InternetExplorer.ask") -eq $true ){
	blockExe "InternetExplorer" "C:\Program Files*\Internet Explorer\iexplore.exe" "InternetExplorer" $true
}else{
	Get-NetFirewallRule -Name '*AutoHarden*InternetExplorer*' | Remove-NetFirewallRule
}

if( (Get-Item "C:\Program Files*\Nmap\nmap.exe") -ne $null ){
	if( (ask "Allow NMAP to bypass the local firewall ?" "Allow-nmap.ask") -eq $true ){
		$nmap = (Get-Item "C:\Program Files*\Nmap\nmap.exe").Fullname
		New-NetFirewallRule -direction Outbound -Action Allow -Program $nmap -Group "AutoHarden-NMap" -Name "[AutoHarden-$AutoHarden_version][OUT] NMAP bypass SNMP & co" -DisplayName "[AutoHarden-$AutoHarden_version][OUT] NMAP bypass SNMP & co" -ErrorAction Ignore
		New-NetFirewallRule -direction Inbound -Action Allow -Program $nmap -Group "AutoHarden-NMap" -Name "[AutoHarden-$AutoHarden_version][IN] NMAP bypass SNMP & co" -DisplayName "[AutoHarden-$AutoHarden_version][IN] NMAP bypass SNMP & co" -ErrorAction Ignore
	}else{
		Get-NetFirewallRule -Name '*AutoHarden*NMAP*' | Remove-NetFirewallRule
	}
}
if( (Get-Item "C:\Program Files*\VMware\*\vmnat.exe") -ne $null ){
	if( (ask "Allow VMWARE to bypass the local firewall ?" "Allow-vmware.ask") -eq $true ){
		$vmware = (Get-Item "C:\Program Files*\VMware\*\vmnat.exe").Fullname
		New-NetFirewallRule -direction Inbound -Action Allow -Program $vmware -Group "AutoHarden-VMWare" -Name "[AutoHarden-$AutoHarden_version][IN] VMWare bypass SNMP & co" -DisplayName "[AutoHarden-$AutoHarden_version][IN] VMWare bypass SNMP & co" -ErrorAction Ignore
		New-NetFirewallRule -direction Outbound -Action Allow -Program $vmware -Group "AutoHarden-VMWare" -Name "[AutoHarden-$AutoHarden_version][OUT] VMWare bypass SNMP & co" -DisplayName "[AutoHarden-$AutoHarden_version][OUT] VMWare bypass SNMP & co" -ErrorAction Ignore
	}else{
		Get-NetFirewallRule -Name '*AutoHarden*VMWare*' | Remove-NetFirewallRule
	}
}
New-NetFirewallRule -direction Outbound -Action Block -Protocol tcp -RemotePort 445 -RemoteAddress $IPForInternet -Group "AutoHarden-SMB" -Name ("[AutoHarden-$AutoHarden_version][Except Intranet] SMB") -DisplayName ("[AutoHarden-$AutoHarden_version][Except Intranet] SMB") -ErrorAction Ignore
