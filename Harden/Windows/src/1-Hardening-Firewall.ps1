# Cleaning firewall rules
netsh advfirewall set AllProfiles state on
Set-NetFirewallProfile -DefaultInboundAction Block
echo 'Cleaning old rules ...'
Get-NetFirewallRule | where { -not $_.Name.StartsWith("[AutoHarden-$AutoHarden_version]") -and -not $_.Name.StartsWith("[AutoHarden]") } | Remove-NetFirewallRule

function blockExe( $name, $exe, [Parameter(Mandatory=$false)] $allowNonRoutableIP=$false ){
	get-item $exe | foreach {
		$bin=$_.Fullname
		if( $allowNonRoutableIP ){	
			New-NetFirewallRule -direction Outbound -Action Block -Program $bin -RemoteAddress "Internet" -Name ("[AutoHarden-$AutoHarden_version][Except Intranet] "+$name+" : "+$bin) -DisplayName ("[AutoHarden-$AutoHarden_version][Except Intranet] "+$name+" : "+$bin) -ErrorAction Ignore
		}else{
			New-NetFirewallRule -direction Outbound -Action Block -Program $bin -Name ("[AutoHarden-$AutoHarden_version] "+$name+" : "+$bin) -DisplayName ("[AutoHarden-$AutoHarden_version] "+$name+" : "+$bin) -ErrorAction Ignore
		}
	}
}

if( (ask "Block communication for evil tools ?" "block-communication-for-powershell,eviltools.ask") -eq $true ){
	blockExe "Powershell" "C:\Windows\WinSxS\*\powershell.exe" $true
	blockExe "Powershell" "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" $true
	blockExe "WScript" "C:\Windows\system32\wscript.exe" $true
	blockExe "BitsAdmin" "C:\Windows\system32\BitsAdmin.exe"
	blockExe "Mshta" "C:\Windows\system32\mshta.exe"
	blockExe "CertUtil" "C:\Windows\System32\certutil.exe"
}else{
	"Powershell", "WScript", "BitsAdmin", "Mshta", "CertUtil" | foreach {
		Get-NetFirewallRule -Name ("*AutoHarden*"+$_+"*") | Remove-NetFirewallRule
	}
}

if( (ask "Block communication for Word and Excel ?" "block-communication-for-excel,word.ask") -eq $true ){
	blockExe "Excel" "C:\Program Files*\Microsoft Office*\root\*\EXCEL.EXE" $true
	blockExe "Excel" "C:\Program Files*\Microsoft Office*\*\root\*\EXCEL.EXE" $true
	blockExe "Excel" "C:\Program Files*\Microsoft Office*\*\EXCEL.EXE" $true
	blockExe "Word" "C:\Program Files*\Microsoft Office\root\*\winword.exe" $true
	blockExe "Word" "C:\Program Files*\Microsoft Office\root\*\winword.exe" $true
	blockExe "Word" "C:\Program Files*\Microsoft Office\root\*\winword.exe" $true
}else{
	Get-NetFirewallRule -Name '*AutoHarden*Excel*' | Remove-NetFirewallRule
	Get-NetFirewallRule -Name '*AutoHarden*Word*' | Remove-NetFirewallRule
}
if( (Get-Item "C:\Program Files*\Nmap\nmap.exe") -ne $null ){
	if( (ask "Allow NMAP to bypass the local firewall ?" "Allow-nmap.ask") -eq $true ){
		$nmap = (Get-Item "C:\Program Files*\Nmap\nmap.exe").Fullname
		New-NetFirewallRule -direction Outbound -Action Allow -Program $nmap -Name "[AutoHarden-$AutoHarden_version][OUT] NMAP bypass SNMP & co" -DisplayName "[AutoHarden-$AutoHarden_version][OUT] NMAP bypass SNMP & co" -ErrorAction Ignore
		New-NetFirewallRule -direction Inbound -Action Allow -Program $nmap -Name "[AutoHarden-$AutoHarden_version][IN] NMAP bypass SNMP & co" -DisplayName "[AutoHarden-$AutoHarden_version][IN] NMAP bypass SNMP & co" -ErrorAction Ignore
	}else{
		Get-NetFirewallRule -Name '*AutoHarden*NMAP*' | Remove-NetFirewallRule
	}
}
if( (Get-Item "C:\Program Files*\VMware\VMware Workstation\vmnat.exe") -ne $null ){
	if( (ask "Allow VMWARE to bypass the local firewall ?" "Allow-vmware.ask") -eq $true ){
		$vmware = (Get-Item "C:\Program Files*\VMware\VMware Workstation\vmnat.exe").Fullname
		New-NetFirewallRule -direction Inbound -Action Allow -Program $vmware -Name "[AutoHarden-$AutoHarden_version][IN] VMWare bypass SNMP & co" -DisplayName "[AutoHarden-$AutoHarden_version][IN] VMWare bypass SNMP & co" -ErrorAction Ignore
		New-NetFirewallRule -direction Outbound -Action Allow -Program $vmware -Name "[AutoHarden-$AutoHarden_version][OUT] VMWare bypass SNMP & co" -DisplayName "[AutoHarden-$AutoHarden_version][OUT] VMWare bypass SNMP & co" -ErrorAction Ignore
	}else{
		Get-NetFirewallRule -Name '*AutoHarden*VMWare*' | Remove-NetFirewallRule
	}
}