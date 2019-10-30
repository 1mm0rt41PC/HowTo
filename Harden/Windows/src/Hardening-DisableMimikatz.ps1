reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v TokenLeakDetectDelaySecs /t REG_DWORD /d 30 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v DisableDomainCreds /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA" /v RunAsPPL /t REG_DWORD /d 1 /f

# This sets up your RDP session to NOT store credentials in the memory of the target host.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA" /v DisableRestrictedAdminOutboundCreds /t REG_DWORD /d 1 /f

if( (Get-Item "C:\Program Files*\VMware\*\vmnat.exe") -eq $null ){
	if( ask "Do you want to enable `"Credentials Guard`" and disable VMWare/VirtualBox", "CredentialsGuard.ask" ){
		# Credentials Guard
		reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA" /v LsaCfgFlags /t REG_DWORD /d 1 /f
		reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA" /v LsaCfgFlagsDefault /t REG_DWORD /d 1 /f
		# Credentials Guard bloque VMWare...
		# En cas de blocage, il faut désactive CG via DG_Readiness.ps1 -Disable
		# cf https://stackoverflow.com/questions/39858200/vmware-workstation-and-device-credential-guard-are-not-compatible
		# cf https://www.microsoft.com/en-us/download/details.aspx?id=53337
	}
}