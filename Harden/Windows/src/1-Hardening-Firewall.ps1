# Cleaning firewall rules
netsh advfirewall set AllProfiles state on
Set-NetFirewallProfile -DefaultInboundAction Block
Get-NetFirewallRule | where { -not $_.Name.StartsWith("[AutoHarden-$AutoHarden_version]") -and -not $_.Name.StartsWith("[AutoHarden]") } | foreach { 
	echo ('Cleaning old rules '+$_.Name)
	$_ | Disable-NetFirewallRule
	$_ | Remove-NetFirewallRule
}

function blockExe( $name, $exe ){
	get-item $exe | foreach {
		New-NetFirewallRule -direction Outbound -Action Block -Program $_.Fullname -Name ("[AutoHarden-$AutoHarden_version] "+$name+" : "+$_.Fullname) -DisplayName ("[AutoHarden-$AutoHarden_version] "+$name+" : "+$_.Fullname) -ErrorAction Ignore
	}
}

if( (ask "Block communication for evil tools ?" "block-communication-for-powershell,eviltools.ask") -eq $true ){
	blockExe "Powershell" "C:\Windows\WinSxS\*\powershell.exe"
	blockExe "Powershell" "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
	blockExe "WScript" "C:\Windows\system32\wscript.exe"
	blockExe "BitsAdmin" "C:\Windows\system32\BitsAdmin.exe"
	blockExe "Mshta" "C:\Windows\system32\mshta.exe"
	blockExe "CertUtil" "C:\Windows\System32\certutil.exe"
}else{
	"Powershell", "WScript", "BitsAdmin", "Mshta", "CertUtil" | foreach {
		$target=$_
		Get-NetFirewallRule | where { $_.Name.StartsWith("[AutoHarden-$AutoHarden_version] $target :") } | foreach { 
			echo ('Cleaning old rules '+$_.Name)
			$_ | Disable-NetFirewallRule
			$_ | Remove-NetFirewallRule
		}
	}
}

if( (ask "Block communication for Word and Excel ?" "block-communication-for-excel,word.ask") -eq $true ){
	blockExe "Excel" "C:\Program Files*\Microsoft Office*\root\*\EXCEL.EXE"
	blockExe "Excel" "C:\Program Files*\Microsoft Office*\*\root\*\EXCEL.EXE"
	blockExe "Excel" "C:\Program Files*\Microsoft Office*\*\EXCEL.EXE"
	blockExe "Word" "C:\Program Files*\Microsoft Office\root\*\winword.exe"
	blockExe "Word" "C:\Program Files*\Microsoft Office\root\*\winword.exe"
	blockExe "Word" "C:\Program Files*\Microsoft Office\root\*\winword.exe"
}else{
	"Excel", "Word" | foreach {
		$target=$_
		Get-NetFirewallRule | where { $_.Name.StartsWith("[AutoHarden-$AutoHarden_version] $target :") } | foreach { 
			echo ('Cleaning old rules '+$_.Name)
			$_ | Disable-NetFirewallRule
			$_ | Remove-NetFirewallRule
		}
	}
}
if( (Get-Item "C:\Program Files*\Nmap\nmap.exe") -ne $null ){
	if( (ask "Allow NMAP to bypass the local firewall ?" "Allow-nmap.ask") -eq $true ){
		$nmap = (Get-Item "C:\Program Files*\Nmap\nmap.exe").Fullname
		New-NetFirewallRule -direction Outbound -Action Allow -Program $nmap -Name "[AutoHarden-$AutoHarden_version][OUT] NMAP bypass SNMP & co" -DisplayName "[AutoHarden-$AutoHarden_version][OUT] NMAP bypass SNMP & co" -ErrorAction Ignore
		New-NetFirewallRule -direction Inbound -Action Allow -Program $nmap -Name "[AutoHarden-$AutoHarden_version][IN] NMAP bypass SNMP & co" -DisplayName "[AutoHarden-$AutoHarden_version][IN] NMAP bypass SNMP & co" -ErrorAction Ignore
	}else{
		"[OUT] NMAP", "[IN] NMAP" | foreach {
			$target=$_
			Get-NetFirewallRule | where { $_.Name.StartsWith("[AutoHarden-$AutoHarden_version] $target :") } | foreach { 
				echo ('Cleaning old rules '+$_.Name)
				$_ | Disable-NetFirewallRule
				$_ | Remove-NetFirewallRule
			}
		}
	}
}
if( (Get-Item "C:\Program Files*\VMware\VMware Workstation\vmnat.exe") -ne $null ){
	if( (ask "Allow VMWARE to bypass the local firewall ?" "Allow-vmware.ask") -eq $true ){
		$vmware = (Get-Item "C:\Program Files*\VMware\VMware Workstation\vmnat.exe").Fullname
		New-NetFirewallRule -direction Inbound -Action Allow -Program $vmware -Name "[AutoHarden-$AutoHarden_version][IN] VMWare bypass SNMP & co" -DisplayName "[AutoHarden-$AutoHarden_version][IN] VMWare bypass SNMP & co" -ErrorAction Ignore
		New-NetFirewallRule -direction Outbound -Action Allow -Program $vmware -Name "[AutoHarden-$AutoHarden_version][OUT] VMWare bypass SNMP & co" -DisplayName "[AutoHarden-$AutoHarden_version][OUT] VMWare bypass SNMP & co" -ErrorAction Ignore
	}else{
		"[OUT] VMWare", "[IN] VMWare" | foreach {
			$target=$_
			Get-NetFirewallRule | where { $_.Name.StartsWith("[AutoHarden-$AutoHarden_version] $target :") } | foreach { 
				echo ('Cleaning old rules '+$_.Name)
				$_ | Disable-NetFirewallRule
				$_ | Remove-NetFirewallRule
			}
		}	
	}
}