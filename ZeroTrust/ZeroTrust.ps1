# Cas:
#	1) Installation du script pour la première fois
#		+ Mode Learning
#		=> Doit OPEN tout les ports sauf les ports d'admin
#		=> Doit créer une exception pour les admin
#		=> Clean toutes les rules
#		=>
#		=>
#
#
# [ipaddress]"8.8.8.8" | ft
# https://www.reddit.com/r/PowerShell/comments/azy78h/help_finding_a_script_regarding_ip_range/
# 
#

Start-Transcript -Force -IncludeInvocationHeader -Append ("C:\Windows\AutoHarden_Activities_"+(Get-Date -Format "yyyy-MM-dd")+".log")
$DebugPreference = "Continue"
$VerbosePreference = "Continue"
$InformationPreference = "Continue"

# Close port if not used during....(Exception on admin port)
$LEARNING=30
$LIST_ADMIN_PORT=445,139,33894
$LIST_ADMIN_IP=@(
	'192.168.200.240',
	'192.168.200.241',
	'192.168.200.242',
	'192.168.200.243'
)
# Range des IP routable
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

# From: https://docs.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges?view=o365-worldwide
$IPForOffice365 = (@"
104.146.128.0/17, 104.42.230.91/32, 104.47.0.0/17, 13.107.128.0/22,
13.107.136.0/22, 13.107.140.6/32, 13.107.18.10/31, 13.107.6.152/31,
13.107.6.156/31, 13.107.6.171/32, 13.107.64.0/18, 13.107.7.190/31,
13.107.9.156/31, 13.80.125.22/32, 13.91.91.243/32, 131.253.33.215/32,
132.245.0.0/16, 150.171.32.0/22, 150.171.40.0/22, 157.55.145.0/25,
157.55.155.0/25, 157.55.227.192/26, 20.190.128.0/18, 204.79.197.215/32,
23.103.160.0/20, 40.104.0.0/15, 40.107.0.0/16, 40.108.128.0/17,
40.126.0.0/18, 40.81.156.154/32, 40.90.218.198/32, 40.92.0.0/15,
40.96.0.0/13, 52.100.0.0/14, 52.104.0.0/14, 52.108.0.0/14,
52.112.0.0/14, 52.120.0.0/14, 52.120.0.0/14, 52.174.56.180/32,
52.183.75.62/32, 52.184.165.82/32, 52.238.106.116/32, 52.238.119.141/32,
52.238.78.88/32, 52.244.160.207/32, 52.244.203.72/32,
52.244.207.172/32, 52.244.223.198/32, 52.244.37.168/32,
52.247.150.191/32, 52.247.150.191/32, 52.96.0.0/14
"@).replace("`n","").replace("`r","").replace(" ","").split(",")



echo "####################################################################################################"
head "# Activation des log pour la résolution DNS"
echo "####################################################################################################"
$log = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration 'Microsoft-Windows-DNS-Client/Operational'
$log.IsEnabled=$true
$log.SaveChanges()


echo "####################################################################################################"
head "# IA firewall / Zero Trust: Lecture des logs afin de déterminer quel sont les ports légitimes"
echo "####################################################################################################"
$IS_ZeroTrust = $false
if( $LEARNING -ne $false ){
	echo 'Running'
	# Format pour pfirewall.log
	# <date> <time> <action> <proto> <ip src> <ip dst> <port src> <port dst>
	# 2020-09-02 23:50:07 ALLOW UDP 0.0.0.0 255.255.255.255 68 67 0 - - - - - - - RECEIVE
	# 2020-09-03 00:21:22 ALLOW TCP 192.168.40.1 192.168.40.1 24155 8000 0 - 0 0 0 - - - RECEIVE
	$firewall=cat $env:systemroot\system32\LogFiles\Firewall\pfirewall.log | findstr /C:ALLOW | findstr /C:RECEIVE | findstr /v /c:127.0.0.1 | findstr /v /C:"::1" | findstr /v /c:0.0.0.0 | findstr /v /c:239.255.255.250 | where { -not ($_.Contains(" 53 ") -and $_.Contains(" ALLOW UDP ")) } | Select-Object @{
		Name="Date";
		Expression={$_=$_.Split(' ');([datetime]$_[0])}
	},@{
		Name="Proto";
		Expression={$_=$_.Split(' ');$_[3]}
	},@{
		Name="IPSrc";
		Expression={$_=$_.Split(' ');$_[4]}
	},@{
		Name="IPDst";
		Expression={$_=$_.Split(' ');$_[5]}
	},@{
		Name="PortSrc";
		Expression={$_=$_.Split(' ');$_[6]}
	},@{
		Name="PortDst";
		Expression={$_=$_.Split(' ');$_[7]}
	},@{
		Name="Full";
		Expression={$_}
	} | sort -Unique Full
	if( [System.IO.File]::Exists("C:\Windows\AutoHarden_Firewall.xml") ){
		$imp = Import-CliXML C:\Windows\AutoHarden_Firewall.xml
		$firewall = ($firewall + $imp) | sort -Unique Full
	}
	$firewall | Export-CliXML C:\Windows\AutoHarden_Firewall.xml

	if( [System.IO.File]::Exists("C:\Windows\AutoHarden_Firewall_init.xml") ){
		$d = [datetime] (Import-CliXML C:\Windows\AutoHarden_Firewall_init.xml)
		$d=$d.AddDays($LEARNING)# Attente de XX jours avant de close les ports
		$IS_ZeroTrust=$d -lt (Get-Date)
		if( $IS_ZeroTrust ){
			# Close unused port
			$maxDate = Get-Date
			$maxDate=$maxDate.AddDays($LEARNING*(-1))
			# Ajout des nouvelles rules
			$firewall | where { $_.Date -ge $maxDate } | Group-Object -Property IPDst,PortDst,Proto | foreach {
				$d=($_.Group | measure -Maximum Date).Maximum.ToString('o')
				$r=$_.Group[0]
				$msg="[AutoHarden][AutoRule] "+$r.PortDst+'/'+$r.Proto+" used by "+$r.IPDst+" on "+$d
				New-NetFirewallRule -direction Inbound -Action Allow -Protocol $_.Proto -LocalPort $_.PortDst -RemoteAddress $r.IPDst -Group "AutoHarden-AutoRule" -Name $msg -DisplayName $msg -ErrorAction Ignore
			}
			# Suppression des anciennes rules
			Get-NetFirewallRule -Group "AutoHarden-AutoRule" | foreach { $d=$_.Name.Split(' ')[-1]; $d -lt $maxDate } | Remove-NetFirewallRule
			# Suppression des rules pour remettre propre
			Get-NetFirewallRule | where { $_.Group -ne "AutoHarden-AutoRule" } | Remove-NetFirewallRule
		}
	}else{
		Get-Date | Export-CliXML C:\Windows\AutoHarden_Firewall_init.xml
	}
}else{
	echo 'Ignore'
}


echo "####################################################################################################"
head "# Création de la global rule pour eviter une intéruption de service a cause du firewall"
echo "####################################################################################################"
if( $IS_ZeroTrust -eq $false ){# Si le mode ZeroTrust n'est pas encore actif, alors mode full open avec filtrage des ports d'admin
	echo 'Running...'
	# Listing des ports TCP ouverts
	$OpenPortTCP=(netstat -ano | findstr /c:LISTENING | findstr /v /c:127.0.0.1 | findstr /c:"0.0.0.0:"| foreach { $_.Split(":")[1].split(" ")[0]} | sort -Unique) -Join ","
	# Exclusion des ports d'administration
	$OpenPortTCP=","+$OpenPortTCP+","
	$LIST_ADMIN_PORT.Split(",") | foreach { $OpenPortTCP=$OpenPortTCP.Replace(","+$_+",", ",") }
	$OpenPortTCP=$OpenPortTCP.Trim(",")
	# Création d'une rule pour open tout le trafic sans limite sur les ports sans administration
	New-NetFirewallRule -direction Inbound -Action Allow -Protocol tcp -LocalPort $OpenPortTCP.Split(",") -Group "AutoHarden-FULL-OPEN-UNKOWN" -Name ("[AutoHarden] FULL-OPEN-UNKOWN-TCP") -DisplayName ("[AutoHarden] FULL-OPEN-UNKOWN-TCP") -ErrorAction Continue
	Get-NetFirewallRule | where { $_.Name.StartsWith("[AutoHarden] FULL-OPEN-UNKOWN-TCP") } | Set-NetFirewallRule -LocalPort $OpenPortTCP.Split(",") -ErrorAction Continue
	# UDP
	# Listing des ports UDP ouverts
	$OpenPortUDP=(netstat -ano | findstr /C:UDP | findstr /C:0.0.0.0 | findstr /C:"*:*"| foreach { $_.Split(":")[1].split(" ")[0]} | sort -Unique) -Join ","
	## Exclusion des ports d'administration
	#$OpenPortUDP=","+$OpenPortUDP+","
	#"".Split(",") | foreach { $OpenPortUDP=$OpenPortUDP.Replace(","+$_+",", ",") }
	#$OpenPortUDP=$OpenPortUDP.Trim(",")
	# Création d'une rule pour open tout le trafic sans limite sur les ports sans administration
	New-NetFirewallRule -direction Inbound -Action Allow -Protocol udp -LocalPort $OpenPortUDP.Split(",") -Group "AutoHarden-FULL-OPEN-UNKOWN" -Name ("[AutoHarden] FULL-OPEN-UNKOWN-UDP") -DisplayName ("[AutoHarden] FULL-OPEN-UNKOWN-UDP") -ErrorAction Continue
	Get-NetFirewallRule | where { $_.Name.StartsWith("[AutoHarden] FULL-OPEN-UNKOWN-UDP") } | Set-NetFirewallRule -LocalPort $OpenPortUDP.Split(",") -ErrorAction Continue

	# Suppression des rules pour remettre propre
	Get-NetFirewallRule | where { $_.Group -ne "AutoHarden-FULL-OPEN-UNKOWN" } | Remove-NetFirewallRule
}else{
	echo 'Ignore'
}


echo "####################################################################################################"
head "# Initialisation du firewall"
echo "####################################################################################################"
# Réactivation du firewall
netsh advfirewall set AllProfiles state on
# Mode de base:
# 	In => DROP
# 	Out => ALLOW
netsh advfirewall set AllProfiles firewallpolicy blockinbound,allowoutbound
# Journaliser les connexions rejetées dans tous les profils
netsh advfirewall set allprofiles logging droppedconnections enable
netsh advfirewall set allprofiles logging allowedconnections enable
netsh advfirewall set allprofiles logging maxfilesize 32767
netsh advfirewall set allprofiles logging filename "%systemroot%\system32\LogFiles\Firewall\pfirewall.log"




function blockExe( $name, $exe, $group, [Parameter(Mandatory=$false)] $allowNonRoutableIP=$false ){
	get-item -ErrorAction Continue $exe | foreach {
		$bin=$_.Fullname
		Write-Host "[*] Block $bin"
		if( $allowNonRoutableIP ){
			New-NetFirewallRule -direction Outbound -Action Block -Program $bin -RemoteAddress $IPForInternet -Group "AutoHarden-$group" -Name ("[AutoHarden][Except Intranet] "+$name+" : "+$bin) -DisplayName ("[AutoHarden][Except Intranet] "+$name+" : "+$bin) -ErrorAction Continue
		}else{
			New-NetFirewallRule -direction Outbound -Action Block -Program $bin -Group "AutoHarden-$group" -Name ("[AutoHarden] "+$name+" : "+$bin) -DisplayName ("[AutoHarden] "+$name+" : "+$bin) -ErrorAction Continue
		}
	}
}
function blockOffice365( $name, $exe, $group ){
	get-item -ErrorAction Continue $exe | foreach {
		$bin=$_.Fullname
		Write-Host "[*] Allow O365 for $bin"
		New-NetFirewallRule -direction Outbound -Action Allow -OverrideBlockRules $true -Program $bin -RemoteAddress $IPForOffice365 -Group "AutoHarden-$group" -Name ("[AutoHarden][Except Office365] "+$name+" : "+$bin) -DisplayName ("[AutoHarden][Except Office365] "+$name+" : "+$bin) -ErrorAction Continue
		#blockExe $name $bin $group $true
	}
}
function head( $msg ) {
	Write-Host -BackgroundColor Blue -ForegroundColor White $msg
	echo "$msg"
}

echo "####################################################################################################"
head "# Firewall: Protection contre les malware commun"
echo "####################################################################################################"
# Interdiction a ces outils de téléchager des data sur Internet
# commande au format: blockExe <nom de la règle> <binaire> <groupe> <bool:Authoriser l'accès au réseau interne?>
blockExe "Powershell" "C:\Windows\WinSxS\*\powershell.exe" "LOLBAS" $true
blockExe "Powershell" "C:\Windows\WinSxS\*\PowerShell_ISE.exe" "LOLBAS" $true
blockExe "Powershell" "C:\Windows\*\WindowsPowerShell\v1.0\powershell.exe" "LOLBAS" $true
blockExe "Powershell" "C:\Windows\*\WindowsPowerShell\v1.0\PowerShell_ISE.exe" "LOLBAS" $true
blockExe "WScript" "C:\Windows\system32\wscript.exe" "LOLBAS" $true
blockExe "CScript" "C:\Windows\system32\cscript.exe" "LOLBAS" $true
blockExe "BitsAdmin" "C:\Windows\system32\BitsAdmin.exe" "LOLBAS" $true
blockExe "Mshta" "C:\Windows\system32\mshta.exe" "LOLBAS" $true
blockExe "CertUtil" "C:\Windows\System32\certutil.exe" "LOLBAS" $true
blockExe "HH" "C:\Windows\*\hh.exe" "LOLBAS" $true
blockExe "HH" "C:\Windows\hh.exe" "LOLBAS" $true
blockExe "IEexec" "C:\Windows\Microsoft.NET\*\*\ieexec.exe" "LOLBAS" $true
blockExe "Dfsvc" "C:\Windows\Microsoft.NET\*\*\Dfsvc.exe" "LOLBAS" $true
blockExe "Presentationhost" "C:\Windows\System32\Presentationhost.exe" "LOLBAS" $true
blockExe "Presentationhost" "C:\Windows\SysWOW64\Presentationhost.exe" "LOLBAS" $true

## Protection contre les malware commun
## Interdiction a ces outils de téléchager des data sur Internet
blockOffice365 "Excel" "C:\Program Files*\Microsoft Office*\root\*\EXCEL.EXE" "Office"
blockOffice365 "Excel" "C:\Program Files*\Microsoft Office*\*\root\*\EXCEL.EXE" "Office"
blockOffice365 "Excel" "C:\Program Files*\Microsoft Office*\*\EXCEL.EXE" "Office"
blockOffice365 "Word" "C:\Program Files*\Microsoft Office*\root\*\winword.exe" "Office"
blockOffice365 "Word" "C:\Program Files*\Microsoft Office*\*\root\*\winword.exe" "Office"
blockOffice365 "Word" "C:\Program Files*\Microsoft Office*\*\winword.exe" "Office"
blockOffice365 "PowerPoint" "C:\Program Files*\Microsoft Office*\root\*\Powerpnt.exe" "Office"
blockOffice365 "PowerPoint" "C:\Program Files*\Microsoft Office*\*\root\*\Powerpnt.exe" "Office"
blockOffice365 "PowerPoint" "C:\Program Files*\Microsoft Office*\*\Powerpnt.exe" "Office"
blockOffice365 "Teams" "${env:localappdata}\Microsoft\Teams\*\Squirrel.exe" "Office"
blockOffice365 "Teams" "${env:localappdata}\Microsoft\Teams\update.exe" "Office"

# IE est trop vieux, interdiction de parler sur Internet.
blockExe "InternetExplorer" "C:\Program Files*\Internet Explorer\iexplore.exe" "InternetExplorer" $true

# Interdiction d'envoyer des requêtes SMB sur internet
New-NetFirewallRule -direction Outbound -Action Block -Protocol tcp -RemotePort 445 -RemoteAddress $IPForInternet -Group "AutoHarden-SMB" -Name ("[AutoHarden][Except Intranet] SMB") -DisplayName ("[AutoHarden][Except Intranet] SMB") -ErrorAction Continue

# Authorisation des Admin pour l'admin des machines
New-NetFirewallRule -direction Inbound -Action Allow -RemoteAddress $LIST_ADMIN_IP -Group "AutoHarden-Admin" -Name ("[AutoHarden] Full access for admin") -DisplayName ("[AutoHarden] Full access for admin") -ErrorAction Continue
Get-NetFirewallRule -Group "AutoHarden-Admin" | Set-NetFirewallRule -RemoteAddress $LIST_ADMIN_IP -ErrorAction Continue


echo "####################################################################################################"
head "# Block IPv6"
echo "####################################################################################################"
New-NetFirewallRule -direction Outbound -Action Block -Protocol 41 -Group AutoHarden-IPv6 -Name "[AutoHarden] IPv6" -DisplayName "[AutoHarden] IPv6" -ErrorAction Continue
New-NetFirewallRule -direction Outbound -Action Block -Protocol 43 -Group AutoHarden-IPv6 -Name "[AutoHarden] IPv6-Route" -DisplayName "[AutoHarden] IPv6-Route" -ErrorAction Continue
New-NetFirewallRule -direction Outbound -Action Block -Protocol 44 -Group AutoHarden-IPv6 -Name "[AutoHarden] IPv6-Frag" -DisplayName "[AutoHarden] IPv6-Frag" -ErrorAction Continue
New-NetFirewallRule -direction Outbound -Action Block -Protocol 59 -Group AutoHarden-IPv6 -Name "[AutoHarden] IPv6-NoNxt" -DisplayName "[AutoHarden] IPv6-NoNxt" -ErrorAction Continue
New-NetFirewallRule -direction Outbound -Action Block -Protocol 60 -Group AutoHarden-IPv6 -Name "[AutoHarden] IPv6-Opts" -DisplayName "[AutoHarden] IPv6-Opts" -ErrorAction Continue
New-NetFirewallRule -direction Outbound -Action Block -Protocol 58 -Group AutoHarden-IPv6 -Name "[AutoHarden] ICMPv6" -DisplayName "[AutoHarden] ICMPv6" -ErrorAction Continue
New-NetFirewallRule -direction Outbound -Action Block -Protocol "UDP" -RemotePort "547" -Group AutoHarden-IPv6 -Name "[AutoHarden] DHCPv6" -DisplayName "[AutoHarden] DHCPv6" -ErrorAction Continue


echo "####################################################################################################"
head "# Block LLMNR"
echo "####################################################################################################"
New-NetFirewallRule -direction Outbound -Action Block -Protocol "TCP" -RemotePort "5355" -Group AutoHarden-LLMNR -Name "[AutoHarden] LLMNR-TCP" -DisplayName "[AutoHarden] LLMNR" -ErrorAction Continue
New-NetFirewallRule -direction Outbound -Action Block -Protocol "UDP" -RemotePort "5355" -Group AutoHarden-LLMNR -Name "[AutoHarden] LLMNR-UDP" -DisplayName "[AutoHarden] LLMNR" -ErrorAction Continue
New-NetFirewallRule -direction Outbound -Action Block -Protocol "UDP" -RemotePort "5353" -Group AutoHarden-LLMNR -Name "[AutoHarden] MBNS" -DisplayName "[AutoHarden] MBNS" -ErrorAction Continue


echo "####################################################################################################"
head "# Block NetBios/NBNS"
echo "####################################################################################################"
New-NetFirewallRule -direction Outbound -Action Block -Protocol "TCP" -RemotePort "135" -Group AutoHarden-NetBios -Name "[AutoHarden] NetBios-TCP135" -DisplayName "[AutoHarden] NetBios" -ErrorAction Continue
New-NetFirewallRule -direction Outbound -Action Block -Protocol "UDP" -RemotePort "137" -Group AutoHarden-NetBios -Name "[AutoHarden] NetBios-UDP137" -DisplayName "[AutoHarden] NetBios" -ErrorAction Continue
New-NetFirewallRule -direction Outbound -Action Block -Protocol "UDP" -RemotePort "138" -Group AutoHarden-NetBios -Name "[AutoHarden] NetBios-UDP138" -DisplayName "[AutoHarden] NetBios2" -ErrorAction Continue
New-NetFirewallRule -direction Outbound -Action Block -Protocol "TCP" -RemotePort "139" -Group AutoHarden-NetBios -Name "[AutoHarden] NetBios-TCP139" -DisplayName "[AutoHarden] NetBios3" -ErrorAction Continue


echo "####################################################################################################"
head "# Hardening: Disable Remote Service Management via SMB"
echo "####################################################################################################"
# From: https://twitter.com/JohnLaTwC/status/802218490404798464?s=19
# Empeche la création de service via les RPC/SMB distant. => psexec upload ok mais exec fail
$tmp=(sc.exe sdshow scmanager).split("`r`n")[1].split(":")[1]
if( -not $tmp.Contains("(D;;GA;;;NU)") -and -not $tmp.Contains("(D;;KA;;;NU)") ){
	sc.exe sdset scmanager "D:(D;;GA;;;NU)$tmp"
}else{
	echo "Already patched"
}


echo "####################################################################################################"
head "# Hardening: Protection against Mimikatz"
echo "####################################################################################################"
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v Negotiate /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v TokenLeakDetectDelaySecs /t REG_DWORD /d 30 /f
# This sets up your RDP session to NOT store credentials in the memory of the target host.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA" /v DisableRestrictedAdminOutboundCreds /t REG_DWORD /d 1 /f