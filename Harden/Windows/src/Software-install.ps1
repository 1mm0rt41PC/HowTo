################################################################################
# Installation de choco
#
if( !(Get-Command "choco" -errorAction SilentlyContinue) ){
	echo "==============================================================================="
	echo "Install: choco"
	Get-NetFirewallRule -Name '*AutoHarden*Powershell*' | Disable-NetFirewallRule
    iwr https://chocolatey.org/install.ps1 -UseBasicParsing | iex
	Get-NetFirewallRule -Name '*AutoHarden*Powershell*' | Enable-NetFirewallRule
}

################################################################################
# Installation des soft de base
#
function chocoInstall( $pk )
{
	if( "$global:chocoList" -Match "$pk" ){
		return ;
	}
	echo "==============================================================================="
	echo "Install: $pk"
	choco install $pk -y
}
$global:chocoList = & choco list -localonly 

chocoInstall vcredist-all
chocoInstall 7zip.install
chocoInstall greenshot
chocoInstall vlc
chocoInstall sysinternals
chocoInstall keepass.install

#linkshellextension,veracrypt

choco upgrade all -y
