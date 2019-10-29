# Cleaning firewall rules
netsh advfirewall set AllProfiles state on
Set-NetFirewallProfile -DefaultInboundAction Block
Get-NetFirewallRule  | foreach { 
	if( -not $_.Name.StartsWith('[RemoteRules]') ){
		echo ('Cleaning old rules '+$_.Name)
		Remove-NetFirewallRule -Name $_.Name
	}
}


New-NetFirewallRule -direction Outbound -Action Block -Program "powershell.exe" -Name "[RemoteRules] Powershell" -DisplayName "[RemoteRules] Powershell" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Program "wscript.exe" -Name "[RemoteRules] WScript" -DisplayName "[RemoteRules] WScript" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Program "mshta.exe" -Name "[RemoteRules] Mshta" -DisplayName "[RemoteRules] Mshta" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Program "winword.exe" -Name "[RemoteRules] Winword" -DisplayName "[RemoteRules] Winword" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Program "excel.exe" -Name "[RemoteRules] Excel" -DisplayName "[RemoteRules] Excel" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Program "excel.exe" -Name "[RemoteRules] Excel" -DisplayName "[RemoteRules] Excel" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Program "certutil.exe" -Name "[RemoteRules] CertUtil" -DisplayName "[RemoteRules] CertUtil" -ErrorAction Ignore

New-NetFirewallRule -direction Outbound -Action Allow -Program "C:\Program Files (x86)\Nmap\nmap.exe" -Name "[RemoteRules][OUT] NMAP bypass SNMP & co" -DisplayName "[RemoteRules][OUT] NMAP bypass SNMP & co" -ErrorAction Ignore
New-NetFirewallRule -direction Inbound -Action Allow -Program "C:\Program Files (x86)\Nmap\nmap.exe" -Name "[RemoteRules][IN] NMAP bypass SNMP & co" -DisplayName "[RemoteRules][IN] NMAP bypass SNMP & co" -ErrorAction Ignore
New-NetFirewallRule -direction Inbound -Action Allow -Program "C:\Program Files (x86)\VMware\VMware Workstation\vmnat.exe" -Name "[RemoteRules][IN] VMWare bypass SNMP & co" -DisplayName "[RemoteRules][IN] VMWare bypass SNMP & co" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Allow -Program "C:\Program Files (x86)\VMware\VMware Workstation\vmnat.exe" -Name "[RemoteRules][OUT] VMWare bypass SNMP & co" -DisplayName "[RemoteRules][OUT] VMWare bypass SNMP & co" -ErrorAction Ignore
