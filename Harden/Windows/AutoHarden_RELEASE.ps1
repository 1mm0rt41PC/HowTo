# 2019-11-04
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'
$PSDefaultParameterValues['*:Encoding'] = 'utf8'
Add-Type -AssemblyName System.Windows.Forms
function ask( $query, $config ){
	$config="C:\Windows\AutoHarden\${config}";
	$ret=cat $config -ErrorAction Ignore;
	echo "# ASK..."
	if( "$ret" -eq "Yes" -Or ([string]::IsNullOrEmpty($ret) -And [System.Windows.Forms.MessageBox]::Show("${query}?","${query}?", "YesNo" , "Question" ) -eq "Yes") ){
		[System.IO.File]::WriteAllLines($config, "Yes", (New-Object System.Text.UTF8Encoding $False));
		echo "# ASK... => YES!"
		return $true;
	}else{
		echo "# ASK... => NO :-("
		[System.IO.File]::WriteAllLines($config, "No", (New-Object System.Text.UTF8Encoding $False));
		return $false;
	}
}
if( ![bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544") ){  Write-Host -BackgroundColor Red -ForegroundColor White "Administrator privileges required ! This terminal has not admin priv. This script ends now !"; pause;exit;}
mkdir C:\Windows\AutoHarden\ -Force -ErrorAction Ignore
Start-Transcript -Append ("C:\Windows\AutoHarden\Activities_"+(Get-Date -Format "yyyy-MM-dd")+".log")

echo "####################################################################################################"
echo "# Install AutoHarden Cert"
echo "####################################################################################################"
$AutoHardenCert = "${env:temp}\"+[System.IO.Path]::GetRandomFileName()+".cer"
[IO.File]::WriteAllBytes($AutoHardenCert, [Convert]::FromBase64String("MIIFGTCCAwGgAwIBAgIQlPiyIshB45hFPPzNKE4fTjANBgkqhkiG9w0BAQ0FADAYMRYwFAYDVQQDEw1BdXRvSGFyZGVuLUNBMB4XDTE5MTAyOTIxNTUxNVoXDTM5MTIzMTIzNTk1OVowFTETMBEGA1UEAxMKQXV0b0hhcmRlbjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALrMv49xZXZjF92Xi3cWVFQrkIF+yYNdU3GSl1NergVq/3WmT8LDpaZ0XSpExZ7soHR3gs8eztnfe07r+Fl+W7l6lz3wUGFt52VY17WCa53tr5dYRPzYt2J6TWT874tqZqlo+lUl8ONK1roAww2flcDajm8VUXM0k0sLM17H9NLykO3DeBuh2PVaXUxGDej+N8PsYF3/7Gv2AW0ZHGflrondcXb2/eh8xwbwRENsGaMXvnGr9RWkufC6bKq31J8BBnP+/65M6541AueBoH8pLbANPZgHKES+8V9UWlYKOeSoeBhtL1k3Rr8tfizRWx1zg/pBNL0WTOLcusmuJkdHkdHbHaW6Jc/vh06Cs6xqz9/Dkg+K3BvOmfwZfAjl+qdgzM8dUU8/GWhswngwLAz64nZ82mZv/Iw6egC0rj5MYV0tpEjIgtVVgHavUfyXoIETNXFQR4SoK6PfeVkEzbRh03xhU65MSgBgWVv1YbOtdgXK0MmCs3ngVPJdVaqBjgcrK++X3Kxasb/bOkcfQjff/EK+BPb/xs+pXEqryYbtbeX0v2rbV9cugPUj+mneucZBLFjuRcXhzVbXLrwXVne7yTD/sIKfe7dztzchg19AY6/qkkRkroaKLASpfCAVx2LuCgeFGn//QaEtCpFxMo2dcnW2a+54pkzrCRTRg1N2wBQFAgMBAAGjYjBgMBMGA1UdJQQMMAoGCCsGAQUFBwMDMEkGA1UdAQRCMECAEPp+TbkVy9u5igk2CqcX2OihGjAYMRYwFAYDVQQDEw1BdXRvSGFyZGVuLUNBghBrxVMud93NnE/XjEko2+2HMA0GCSqGSIb3DQEBDQUAA4ICAQAQLtHeMr2qJnfhha2x2aCIApPjfHiHT4RNPI2Lq71jEbTpzdDFJQkKq4R3brGcpcnuU9VjUwz/BgKer+SFpkwFwTHyJpEFkbGavNo/ez3bqoehvqlTYDJO/i2mK0fvKmShfne6dZT+ftLpZCP4zngcANlp+kHy7mNRMB+LJv+jPc0kJ2oP4nIsLejyfxMj0lXuTJJRhxeZssdh0tq4MZP5MjSeiE5/AMuKT12uJ6klNUFS+OlEpZyHkIpgy4HxflXSvhchJ9U1YXF2IQ47WOrqwCXPUinHKZ8LwB0b0/35IlRCpub5KdRf803+4Okf9fL4rfc1cg9ZbLxuK9neFg1+ESL4aPyoV03TbN7Cdsd/sfx4mJ8jXJD+AXZ1ZofAAapYf9J5C71ChCZlhIGBvVc+dTUCWcUYgNOD9Nw+NiV6mARmVHl9SFL7yEtNYFgo0nWiNklqMqBLDxmrrD27sgBpFUwbMZ52truQwaaSHD7hFb4Tb1B0JVaGoog3QfNOXaFeez/fAt5L+yo78cDm7Q2tXvy2g0xDAL/TXn7bhtDzQunltBzdULrJEQO4zI0h8YgmF88a0zYZ9HRkDUn6dR9+G8TlZuUsWSOdvLdEvad9RqiHKeSrL6qgLBT5kqVt6AFsEtmFNz1s7xpsw/zPZvIXtQTmb4h+GcE/b2sUFZUkRA=="))
Import-Certificate -Filepath $AutoHardenCert -CertStoreLocation Cert:\LocalMachine\TrustedPublisher
$AutoHardenCertCA = "${env:temp}\"+[System.IO.Path]::GetRandomFileName()+".cer"
[IO.File]::WriteAllBytes($AutoHardenCertCA, [Convert]::FromBase64String("MIIFHDCCAwSgAwIBAgIQa8VTLnfdzZxP14xJKNvthzANBgkqhkiG9w0BAQ0FADAYMRYwFAYDVQQDEw1BdXRvSGFyZGVuLUNBMB4XDTE5MTAyOTIxNTUwOVoXDTM5MTIzMTIzNTk1OVowGDEWMBQGA1UEAxMNQXV0b0hhcmRlbi1DQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANlm8tv2IqVairIP90RnIsNlQYPMAvUwRcC6Nw+0Qlv56tWczvMl9IF0+h2vUF5+lnSEkJMGBqeLFaJgSo9lNyHeTfjjqpEcMVBw1nXl6VSfNiirD7fJTkyZ3rl63PsOwbfWCPDW1AvLufYhBiijPlK1k4RJFkiFZbZkpe5ys0uY4QVFj+ZTaW0EA0MncX2YZ775QnX7HJO0HfMcHGGTxOPhAqJ7Pp+IBrs75laaASekJSTVub7jqs5aeApQkUWgKel1fmK0tBv35deE1P5ABXi+KnuzWCZDU8znIDAnj1qz+6c21KKhslEdzYlRSlq4kPcF964GECxRtgq0z1pzhV/WvBJjWjNp3G5e8jUfjuAg2utF/xd/j7GNU8vllDAXFjl4czc1saGZDcU8a/uaweKMjqR4WfyUp/H/mB7JFJlOHBGTRszWaAU/4E0V+bICXNI5augkV29ci0HouBG3WFcQiA5q+1U2vY/scVyMPm8ZecCe2b+SD/ipPtFspcOPStRm5EQgL4CWdVpSmm8+JRO0NcrSnQtNPCwPBT3c7OLOwYLBl8WHcJG1yOJtQvLjv1koMmJkHR0djODx8Ig9fqAFLH0c694E6VJbojDVGp/LRR9LnJnzYlWAYoT3ScPQ9uesgr4x8VSnrM6cMG3ASQD92RVXKCDep/Rq29IXtvjpAgMBAAGjYjBgMBMGA1UdJQQMMAoGCCsGAQUFBwMDMEkGA1UdAQRCMECAEPp+TbkVy9u5igk2CqcX2OihGjAYMRYwFAYDVQQDEw1BdXRvSGFyZGVuLUNBghBrxVMud93NnE/XjEko2+2HMA0GCSqGSIb3DQEBDQUAA4ICAQDBiDwoVi2YhWzlMUTE5JHUUUkGkTaMVKfjYBFiUHeQQIaUuSq3dMRPlfpDRSzt3TW5mfwcPdwwatE0xeGN3r3zyQgnzEG/vMVrxwkgfFekVYvE4Ja551MSkwAA2fuTHGsRB9tEbTrkbGr35bXZYxOpGHpZIifFETFCT6rOpheDdxOEU6YyLeIYgGdGCmKStJ3XSkvqBh7oQ45M0+iqX9yjJNGoUg+XMLnk4K++7rxIk/SGtUBuIpsB3ksmIsXImelUxHw3xe6nGkkncAm9yX7rTU1M1fqrxaoBiGvx9jlqxDVMIzzDga7vKXDsP/iUmb4feeTIoy7+SgqGWsSvRiLt6A5CeIQ5XaTrhWN+mbGq6vvFTZuctY6LzdufwhlbZXFmfU/LnsRprM2EzYfba8VZmmfMBBpnYrw5q/3d5f9OSmNkRQjs0HfVab9b44hWNUd2QJ6yvjM5gdB367ekVagLpVdb/4mwzKOlspDULSlT7rAeuOc1njylu80pbBFCNiB72AmWNbqEK48ENloUr75NhuTKJ74llj+Nt6g9zDzsXuFICyJILvgE8je87GQXp+712aSGqJBLiGTFjuS3UctJ8qdlf5zkXw6mMB52/M3QYg6vI+2AYRc2EQXRvm8ZSlDKYidp9mZF43EcXFVktnK87x+TKYVjnfTGomfLfAXpTg=="))
Import-Certificate -Filepath $AutoHardenCertCA -CertStoreLocation Cert:\LocalMachine\AuthRoot


echo "####################################################################################################"
echo "# 0-AutoUpdate"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "0-AutoUpdate" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running 0-AutoUpdate"
if( ask "Auto update AutoHarden and execute AutoHarden every day at 08h00 AM" "0-AutoUpdate.ask" ){
$Trigger = New-ScheduledTaskTrigger -At 08:00am -Daily
$Action  = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-exec AllSigned -nop -File C:\Windows\AutoHarden\AutoHarden.ps1"
$Setting = New-ScheduledTaskSettingsSet -RestartOnIdle -StartWhenAvailable
Register-ScheduledTask -TaskName "AutoHarden" -Trigger $Trigger -User "NT AUTHORITY\SYSTEM" -Action $Action -RunLevel Highest -Settings $Setting -Force
Invoke-WebRequest -Uri https://raw.githubusercontent.com/1mm0rt41PC/HowTo/master/Harden/Windows/AutoHarden_RELEASE.ps1 -OutFile C:\Windows\AutoHarden\AutoHarden.ps1
}
Write-Progress -Activity AutoHarden -Status "0-AutoUpdate" -Completed


echo "####################################################################################################"
echo "# 1-Hardening-Firewall"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "1-Hardening-Firewall" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running 1-Hardening-Firewall"
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
Write-Progress -Activity AutoHarden -Status "1-Hardening-Firewall" -Completed


echo "####################################################################################################"
echo "# 2-Hardening-HardDriveEncryption"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "2-Hardening-HardDriveEncryption" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running 2-Hardening-HardDriveEncryption"
if( ask "Encrypt the HardDrive C:" "2-Hardening-HardDriveEncryption.ask" ){
# AES 256-bit 
reg add 'HKLM\SOFTWARE\Policies\Microsoft\FVE' /v EncryptionMethod  /t REG_DWORD /d 4 /f

try{
	(Get-BitLockerVolume -MountPoint 'C:').KeyProtector |foreach {
		Write-Host ("C: is protected with: "+$_.KeyProtectorType)
	}
}catch{
	Enable-BitLocker -MountPoint 'C:' -EncryptionMethod Aes256 -UsedSpaceOnly -TpmProtector -ErrorAction Continue
	Enable-BitLocker -MountPoint 'C:' -EncryptionMethod Aes256 -UsedSpaceOnly -RecoveryPasswordProtector -ErrorAction Continue
	(Get-BitLockerVolume -MountPoint 'C:').KeyProtector | foreach {
		if( -not [string]::IsNullOrEmpty($_.RecoveryPassword) ){
			Add-Type -AssemblyName System.Windows.Forms
			[System.Windows.Forms.MessageBox]::Show("Please keep a note of this RecoveryPassword "+$_.RecoveryPassword);
		}
	}
}
}
Write-Progress -Activity AutoHarden -Status "2-Hardening-HardDriveEncryption" -Completed


echo "####################################################################################################"
echo "# Crapware-DisableExplorerAdsense"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Crapware-DisableExplorerAdsense" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Crapware-DisableExplorerAdsense"
# Disable notifications/ads in File Explorer
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSyncProviderNotifications /t REG_DWORD /d 0 /f
# Disable “Suggested Apps” in Windows 10
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v OemPreInstalledAppsEnabled /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEnabled /t REG_DWORD /d 0 /f
Write-Progress -Activity AutoHarden -Status "Crapware-DisableExplorerAdsense" -Completed


echo "####################################################################################################"
echo "# Crapware-DisableTelemetry"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Crapware-DisableTelemetry" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Crapware-DisableTelemetry"
# Disable Windows telemetry
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
# Disable Wifi sense telemetry
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v AutoConnectAllowedOEM /t REG_DWORD /d 0 /f

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SoftLandingEnabled /t REG_DWORD /d 0  /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f
Write-Progress -Activity AutoHarden -Status "Crapware-DisableTelemetry" -Completed


echo "####################################################################################################"
echo "# Crapware-Onedrive"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Crapware-Onedrive" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Crapware-Onedrive"
if( ask "Remove OneDrive" "Crapware-Onedrive.ask" ){
$x86="$env:SYSTEMROOT\System32\OneDriveSetup.exe"
$x64="$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
$onedriverPath = $false
if( [System.IO.File]::Exists($x86) ){
	$onedriverPath = "$x86"
}elseif( [System.IO.File]::Exists($x64) ){
	$onedriverPath = "$x64"
}
if( $onedriverPath ){
	taskkill /f /im OneDrive.exe >$null 2>&1
	# Suppression du fichier
	takeown /F "$onedriverPath" /A
	icacls "$onedriverPath" /grant:r Utilisateurs:F
	icacls "$onedriverPath" /grant:r Administrateurs:F
	Remove-Item -Recurse -Force "$onedriverPath" -ErrorAction SilentlyContinue
	
	Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:USERPROFILE\OneDrive"
	Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:USERPROFILE\OneDrive"
	Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "C:\OneDriveTemp"
	Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:LOCALAPPDATA\Microsoft\OneDrive"
	Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:PROGRAMDATA\Microsoft OneDrive"
	Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:PROGRAMDATA\Microsoft OneDrive"
	echo "Removing OneDrive from the Explorer Side Panel."
	echo .
	reg delete "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f >$null 2>&1
	reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f >$null 2>&1
}
# Suppression du OneDrive de explorer
reg add 'HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' /v System.IsPinnedToNameSpaceTree /t REG_DWORD /d 0 /f
reg add 'HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' /v System.IsPinnedToNameSpaceTree /t REG_DWORD /d 0 /f

# Désactivation de OneDrive
reg add 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\OneDrive' /v PreventNetworkTrafficPreUserSignIn /t REG_DWORD /d 1 /f
reg add 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OneDrive' /v DisableFileSync /t REG_DWORD /d 1 /f
reg add 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OneDrive' /v DisableFileSyncNGSC /t REG_DWORD /d 1 /f
}
Write-Progress -Activity AutoHarden -Status "Crapware-Onedrive" -Completed


echo "####################################################################################################"
echo "# Crapware-RemoveUseLessSoftware"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Crapware-RemoveUseLessSoftware" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Crapware-RemoveUseLessSoftware"
Get-AppxPackage -Name king.com.CandyCrushSaga
Get-AppxPackage *3dbuilder* | Remove-AppxPackage
Get-AppxPackage *officehub* | Remove-AppxPackage
Get-AppxPackage *skypeapp* | Remove-AppxPackage
Get-AppxPackage *getstarted* | Remove-AppxPackage
Get-AppxPackage *zunemusic* | Remove-AppxPackage
Get-AppxPackage *bingfinance* | Remove-AppxPackage
Get-AppxPackage *zunevideo* | Remove-AppxPackage
Get-AppxPackage *onenote* | Remove-AppxPackage
Get-AppxPackage *people* | Remove-AppxPackage -ErrorAction SilentlyContinue
Get-AppxPackage *windowsphone* | Remove-AppxPackage
Get-AppxPackage *bingsports* | Remove-AppxPackage
Get-AppxPackage *xboxapp* | Remove-AppxPackage

reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main /v AllowPrelaunch /d 0 /t REG_DWORD /f

# List: Get-AppxPackage
Write-Progress -Activity AutoHarden -Status "Crapware-RemoveUseLessSoftware" -Completed


echo "####################################################################################################"
echo "# Crapware-Windows10UpgradeOldFolder"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Crapware-Windows10UpgradeOldFolder" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Crapware-Windows10UpgradeOldFolder"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue 'C:\$Windows.~BT'
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue 'C:\Windows.old'
Write-Progress -Activity AutoHarden -Status "Crapware-Windows10UpgradeOldFolder" -Completed


echo "####################################################################################################"
echo "# Hardening-AccountRename"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Hardening-AccountRename" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Hardening-AccountRename"
if( ask "Invert the administrator and guest accounts" "Hardening-AccountRename.ask" ){
try{
if( (New-Object System.Security.Principal.NTAccount('Administrateur')).Translate([System.Security.Principal.SecurityIdentifier]).value.EndsWith('-500') ){
	Rename-LocalUser -Name Administrateur -NewName Adm
	Rename-LocalUser -Name Invité -NewName Administrateur
	Rename-LocalUser -Name Adm -NewName Invité
}
}catch{}
try{
if( (New-Object System.Security.Principal.NTAccount('Administrator')).Translate([System.Security.Principal.SecurityIdentifier]).value.EndsWith('-500') ){
	Rename-LocalUser -Name Administrator -NewName Adm
	Rename-LocalUser -Name Guest -NewName Administrator
	Rename-LocalUser -Name Adm -NewName Guest
}
}catch{}
}
Write-Progress -Activity AutoHarden -Status "Hardening-AccountRename" -Completed


echo "####################################################################################################"
echo "# Hardening-BlockOutgoingSNMP"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Hardening-BlockOutgoingSNMP" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Hardening-BlockOutgoingSNMP"
New-NetFirewallRule -direction Outbound -Action Block -Protocol "TCP" -RemotePort "161" -Name "[RemoteRules] SNMP-TCP" -DisplayName "[RemoteRules] SNMP" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Protocol "UDP" -RemotePort "161" -Name "[RemoteRules] SNMP-UDP" -DisplayName "[RemoteRules] SNMP" -ErrorAction Ignore
Write-Progress -Activity AutoHarden -Status "Hardening-BlockOutgoingSNMP" -Completed


echo "####################################################################################################"
echo "# Hardening-BlockUntrustedFonts"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Hardening-BlockUntrustedFonts" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Hardening-BlockUntrustedFonts"
# https://adsecurity.org/?p=3299
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" /v MitigationOptions /t REG_QWORD /d 0x2000000000000 /f
Write-Progress -Activity AutoHarden -Status "Hardening-BlockUntrustedFonts" -Completed


echo "####################################################################################################"
echo "# Hardening-DisableCABlueCoat"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Hardening-DisableCABlueCoat" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Hardening-DisableCABlueCoat"
# See http://blogs.msmvps.com/alunj/2016/05/26/untrusting-the-blue-coat-intermediate-ca-from-windows/
#Invoke-WebRequest -Uri "https://crt.sh/?id=19538258" -OutFile "${env:temp}/Hardening-DisableCABlueCoat.crt"
echo @'
-----BEGIN CERTIFICATE-----
MIIGTDCCBTSgAwIBAgIQUWMOvf4tj/x5cQN2PXVSwzANBgkqhkiG9w0BAQsFADCB
yjELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQL
ExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJp
U2lnbiwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxW
ZXJpU2lnbiBDbGFzcyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0
aG9yaXR5IC0gRzUwHhcNMTUwOTI0MDAwMDAwWhcNMjUwOTIzMjM1OTU5WjCBhDEL
MAkGA1UEBhMCVVMxIDAeBgNVBAoTF0JsdWUgQ29hdCBTeXN0ZW1zLCBJbmMuMR8w
HQYDVQQLExZTeW1hbnRlYyBUcnVzdCBOZXR3b3JrMTIwMAYDVQQDEylCbHVlIENv
YXQgUHVibGljIFNlcnZpY2VzIEludGVybWVkaWF0ZSBDQTCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAJ/Go2aR50MoHttT0E7g9bDUUzKomaIkCRy5gI8A
BRkAed7v1mKUk/tn7pKxOvYHnd8BG3iT+eQ2P1ha2oB+vymj4b35gOAcYQIEEYCO
vH35pSqRKlmflrI5RwjX/+l9O+YUn2cK0uYeJBXNMfTse6/azxksNQjK1CFqFcWz
XIK12+THFiFQuuCc5lON6nkhpBkGJSCN43nevFigNhW3YWZG/Z1l86Y9Se0Sf96o
fL7VnV2Ri0kSwJuxNYH7ei5ZBG8GVuNFuqPhmfE2YD2yjbXMnnn4hKOWsM8Oe0xL
ocjPgMTGVgvgeqZo8tV2gvaAycPO4PcJ+yHlgXtdyV7qztECAwEAAaOCAnAwggJs
MBIGA1UdEwEB/wQIMAYBAf8CAQAwLwYDVR0fBCgwJjAkoCKgIIYeaHR0cDovL3Mu
c3ltY2IuY29tL3BjYTMtZzUuY3JsMA4GA1UdDwEB/wQEAwIBBjAuBggrBgEFBQcB
AQQiMCAwHgYIKwYBBQUHMAGGEmh0dHA6Ly9zLnN5bWNkLmNvbTCCAVkGA1UdIASC
AVAwggFMMFwGBmeBDAECAjBSMCYGCCsGAQUFBwIBFhpodHRwOi8vd3d3LnN5bWF1
dGguY29tL2NwczAoBggrBgEFBQcCAjAcGhpodHRwOi8vd3d3LnN5bWF1dGguY29t
L3JwYTB1BgorBgEEAfElBAIBMGcwZQYIKwYBBQUHAgIwWRpXSW4gdGhlIGV2ZW50
IHRoYXQgdGhlIEJsdWVDb2F0IENQUyBhbmQgU3ltYW50ZWMgQ1BTIGNvbmZsaWN0
LCB0aGUgU3ltYW50ZWMgQ1BTIGdvdmVybnMuMHUGCisGAQQB8SUEAgIwZzBlBggr
BgEFBQcCAjBZGldJbiB0aGUgZXZlbnQgdGhhdCB0aGUgQmx1ZUNvYXQgQ1BTIGFu
ZCBTeW1hbnRlYyBDUFMgY29uZmxpY3QsIHRoZSBTeW1hbnRlYyBDUFMgZ292ZXJu
cy4wHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMCkGA1UdEQQiMCCkHjAc
MRowGAYDVQQDExFTeW1hbnRlY1BLSS0yLTIxNDAdBgNVHQ4EFgQUR5UKC6ehgqJt
yZuczT7zkELkb5kwHwYDVR0jBBgwFoAUf9Nlp8Ld7LvwMAnzQzn6Aq8zMTMwDQYJ
KoZIhvcNAQELBQADggEBAJjsKAGzmIEavosNMHxJVCidIGF1r3+vmGBoSVU5iT9R
1DKnrQc8KO5l+LgMuyDUMmH5CxbLbOWT/GtEC/ZvyiVTfn2xNE9SXw46zNUz1oOO
DMJLyvTMuRt7LsExqqsg3KZo6esNW5gmCYbLyfcjn7dKbtjkHvOdxJJ7VrDDayeC
Z5rBgiTj1+l09Uxo+2rwfEvHXzVtWSQyuqxRc8DVwCgFGrnJNGJS1coOQdQ91i6Q
zij5S/djgP1rVHH+MkgJcUQ/2km9GC6B6Y3yMGq6XLVjLvi73Ch2G5mUWkeoZibb
yQSxTBWG6GJjyDY7543ZK3FH4Ctih/nFgXrjuY7Ghrk=
-----END CERTIFICATE-----
'@ > $env:temp/Hardening-DisableCABlueCoat.crt
Import-Certificate -Filepath "${env:temp}/Hardening-DisableCABlueCoat.crt" -CertStoreLocation Cert:\LocalMachine\Disallowed
Write-Progress -Activity AutoHarden -Status "Hardening-DisableCABlueCoat" -Completed


echo "####################################################################################################"
echo "# Hardening-DisableIPv6"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Hardening-DisableIPv6" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Hardening-DisableIPv6"
# Block IPv6
New-NetFirewallRule -direction Outbound -Action Block -Protocol 41 -Name "[RemoteRules] IPv6" -DisplayName "[RemoteRules] IPv6" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Protocol 43 -Name "[RemoteRules] IPv6-Route" -DisplayName "[RemoteRules] IPv6-Route" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Protocol 44 -Name "[RemoteRules] IPv6-Frag" -DisplayName "[RemoteRules] IPv6-Frag" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Protocol 59 -Name "[RemoteRules] IPv6-NoNxt" -DisplayName "[RemoteRules] IPv6-NoNxt" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Protocol 60 -Name "[RemoteRules] IPv6-Opts" -DisplayName "[RemoteRules] IPv6-Opts" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Protocol 58 -Name "[RemoteRules] ICMPv6" -DisplayName "[RemoteRules] ICMPv6" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Protocol "UDP" -RemotePort "547" -Name "[RemoteRules] DHCPv6" -DisplayName "[RemoteRules] DHCPv6" -ErrorAction Ignore
Write-Progress -Activity AutoHarden -Status "Hardening-DisableIPv6" -Completed


echo "####################################################################################################"
echo "# Hardening-DisableLLMNR"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Hardening-DisableLLMNR" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Hardening-DisableLLMNR"
# Disable LLMNR
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /t REG_DWORD /v EnableMulticast /d 0 /f
nbtstat.exe /n
New-NetFirewallRule -direction Outbound -Action Block -Protocol "TCP" -RemotePort "5355" -Name "[RemoteRules] LLMNR-TCP" -DisplayName "[RemoteRules] LLMNR" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Protocol "UDP" -RemotePort "5355" -Name "[RemoteRules] LLMNR-UDP" -DisplayName "[RemoteRules] LLMNR" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Protocol "UDP" -RemotePort "5353" -Name "[RemoteRules] MBNS" -DisplayName "[RemoteRules] MBNS" -ErrorAction Ignore

# Disable wpad
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" /v "DefaultConnectionSettings" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" /v "SavedLegacySettings" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" /t REG_DWORD /v WpadOverride /d 0 /f
RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 8
ipconfig /flushdns
$_wpad=cat C:\Windows\System32\drivers\etc\hosts | findstr /c:"0.0.0.0 wpad"
if( [string]::IsNullOrEmpty($_wpad) ){
	echo "`r`n0.0.0.0 wpad" >> C:\Windows\System32\drivers\etc\hosts
}
$_wpad=cat C:\Windows\System32\drivers\etc\hosts | findstr /c:"0.0.0.0 ProxySrv"
if( [string]::IsNullOrEmpty($_wpad) ){
	echo "`r`n0.0.0.0 ProxySrv" >> C:\Windows\System32\drivers\etc\hosts
}
Write-Progress -Activity AutoHarden -Status "Hardening-DisableLLMNR" -Completed


echo "####################################################################################################"
echo "# Hardening-DisableMimikatz"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Hardening-DisableMimikatz" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Hardening-DisableMimikatz"
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA" /v RunAsPPL /t REG_DWORD /d 1 /f

if( (ask "Is this computer is a laptop connected to a domain ?" "Mimikatz-DomainCred.ask") -eq $false ){
	reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v DisableDomainCreds /t REG_DWORD /d 1 /f
	reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v TokenLeakDetectDelaySecs /t REG_DWORD /d 30 /f
}

# This sets up your RDP session to NOT store credentials in the memory of the target host.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA" /v DisableRestrictedAdminOutboundCreds /t REG_DWORD /d 1 /f

if( (Get-Item "C:\Program Files*\VMware\*\vmnat.exe") -eq $null ){
	if( ask "Do you want to enable `"Credentials Guard`" and disable VMWare/VirtualBox" "CredentialsGuard.ask" ){
		# Credentials Guard
		reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA" /v LsaCfgFlags /t REG_DWORD /d 1 /f
		reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA" /v LsaCfgFlagsDefault /t REG_DWORD /d 1 /f
		# Credentials Guard bloque VMWare...
		# En cas de blocage, il faut d�sactive CG via DG_Readiness.ps1 -Disable
		# cf https://stackoverflow.com/questions/39858200/vmware-workstation-and-device-credential-guard-are-not-compatible
		# cf https://www.microsoft.com/en-us/download/details.aspx?id=53337
	}
}
Write-Progress -Activity AutoHarden -Status "Hardening-DisableMimikatz" -Completed


echo "####################################################################################################"
echo "# Hardening-DisableNetbios"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Hardening-DisableNetbios" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Hardening-DisableNetbios"
New-NetFirewallRule -direction Outbound -Action Block -Protocol "TCP" -RemotePort "135" -Name "[RemoteRules] NetBios-TCP135" -DisplayName "[RemoteRules] NetBios" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Protocol "UDP" -RemotePort "137" -Name "[RemoteRules] NetBios-UDP137" -DisplayName "[RemoteRules] NetBios" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Protocol "UDP" -RemotePort "138" -Name "[RemoteRules] NetBios-UDP138" -DisplayName "[RemoteRules] NetBios2" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Protocol "TCP" -RemotePort "139" -Name "[RemoteRules] NetBios-TCP139" -DisplayName "[RemoteRules] NetBios3" -ErrorAction Ignore
set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\tcpip* -Name NetbiosOptions -Value 2
Write-Progress -Activity AutoHarden -Status "Hardening-DisableNetbios" -Completed


echo "####################################################################################################"
echo "# Hardening-DisableRemoteServiceManagement"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Hardening-DisableRemoteServiceManagement" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Hardening-DisableRemoteServiceManagement"
# From: https://twitter.com/JohnLaTwC/status/802218490404798464?s=19
# Empeche la création de service via les RPC/SMB distant. => psexec upload ok mais exec fail
$tmp=(sc.exe sdshow scmanager).split("`r`n")[1].split(":")[1]
if( -not $tmp.Contains("(D;;GA;;;NU)") -and -not $tmp.Contains("(D;;KA;;;NU)") ){
	sc.exe sdset scmanager "D:(D;;GA;;;NU)$tmp"
}else{
	echo "Already patched"
}
Write-Progress -Activity AutoHarden -Status "Hardening-DisableRemoteServiceManagement" -Completed


echo "####################################################################################################"
echo "# Hardening-DisableSMB"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Hardening-DisableSMB" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Hardening-DisableSMB"
# Désactivation des partages administratifs
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareWks /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareServer /t REG_DWORD /d 0 /f

sc.exe config lanmanserver start= disabled
Write-Progress -Activity AutoHarden -Status "Hardening-DisableSMB" -Completed


echo "####################################################################################################"
echo "# Hardening-DisableSMBv1"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Hardening-DisableSMBv1" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Hardening-DisableSMBv1"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\Rdr\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\Rdr\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f
Write-Progress -Activity AutoHarden -Status "Hardening-DisableSMBv1" -Completed


echo "####################################################################################################"
echo "# Hardening-DNSCache"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Hardening-DNSCache" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Hardening-DNSCache"
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v MaxCacheTtl /t REG_DWORD /d 10 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v MaxNegativeCacheTtl /t REG_DWORD /d 10 /f
Write-Progress -Activity AutoHarden -Status "Hardening-DNSCache" -Completed


echo "####################################################################################################"
echo "# Hardening-Wifi"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Hardening-Wifi" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Hardening-Wifi"
& reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /t REG_DWORD /v DontDisplayNetworkSelectionUI /d 1 /f
Write-Progress -Activity AutoHarden -Status "Hardening-Wifi" -Completed


echo "####################################################################################################"
echo "# Optimiz-ClasicExplorerConfig"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Optimiz-ClasicExplorerConfig" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Optimiz-ClasicExplorerConfig"
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v ShowFrequent /t REG_DWORD /d 0x0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v ShowRecent /t REG_DWORD /d 0x0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0x0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarSmallIcons /t REG_DWORD /d 0x1 /f
# Disable Icon Grouping
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarGlomLevel /t REG_DWORD /d 0x1 /f
Write-Progress -Activity AutoHarden -Status "Optimiz-ClasicExplorerConfig" -Completed


echo "####################################################################################################"
echo "# Optimiz-CleanUpWindowFolder"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Optimiz-CleanUpWindowFolder" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Optimiz-CleanUpWindowFolder"
# https://www.malekal.com/comment-reduire-la-taille-du-dossier-windows-de-windows-10/

# Réduire la taille du dossier WinSxS
Dism.exe /online /Cleanup-Image /StartComponentCleanup
# En appliquant ces deux commandes, vous ne pourrez plus désinstaller les mises à jour Windows.
Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase
Dism.exe /online /Cleanup-Image /SPSuperseded
Write-Progress -Activity AutoHarden -Status "Optimiz-CleanUpWindowFolder" -Completed


echo "####################################################################################################"
echo "# Optimiz-CleanUpWindowsName"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Optimiz-CleanUpWindowsName" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Optimiz-CleanUpWindowsName"
$finalUser='Administrateur'
try{
	if( -Not (New-Object System.Security.Principal.NTAccount($finalUser)).Translate([System.Security.Principal.SecurityIdentifier]).value.EndsWith('-500') ){
		$finalUser='Invité'
	}
}catch{
	$finalUser='Administrator'
	if( -Not (New-Object System.Security.Principal.NTAccount($finalUser)).Translate([System.Security.Principal.SecurityIdentifier]).value.EndsWith('-500') ){
		$finalUser='Guest'
	}
}


function killfakename( $file ){
	echo "$file ========="
	#takeown.exe /f $file
	icacls.exe "$file" /setowner $env:username
	remove-item -Force $file
	echo '' | Out-File $file
	icacls.exe "$file" /setowner $finalUser
	attrib +s +h $file
	(Get-Acl $file).Owner
	#(Get-Acl $file).Access
}


killfakename 'C:\Users\desktop.ini'
killfakename 'C:\Program Files\desktop.ini'
killfakename 'C:\Program Files (x86)\desktop.ini'
Write-Progress -Activity AutoHarden -Status "Optimiz-CleanUpWindowsName" -Completed


echo "####################################################################################################"
echo "# Optimiz-DisableAutoReboot"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Optimiz-DisableAutoReboot" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Optimiz-DisableAutoReboot"
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /t REG_DWORD /v NoAutoRebootWithLoggedOnUsers /d 1 /f
schtasks /Change /TN "Microsoft\Windows\UpdateOrchestrator\Schedule Scan" /Disable
if( !(Test-Path -PathType Container "$env:WINDIR\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot") ){
	schtasks /Change /TN "Microsoft\Windows\UpdateOrchestrator\Reboot" /Disable
	ren "$env:WINDIR\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot" "$env:WINDIR\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot.bak"
	md "$env:WINDIR\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot"
}
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /t REG_DWORD /v ActiveHoursStart /d 4 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /t REG_DWORD /v ActiveHoursEnd /d 23 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /t REG_DWORD /v IsActiveHoursEnabled /d 1 /f
Write-Progress -Activity AutoHarden -Status "Optimiz-DisableAutoReboot" -Completed


echo "####################################################################################################"
echo "# Optimiz-DisableAutoUpdate"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Optimiz-DisableAutoUpdate" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Optimiz-DisableAutoUpdate"
if( ask "Disable auto update" "Optimiz-DisableAutoUpdate.ask" ){
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions /t REG_DWORD /d 2 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoRebootWithLoggedOnUsers /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v RebootRelaunchTimeoutEnabled /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v RebootWarningTimeoutEnabled /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v ScheduledInstallDay /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v ScheduledInstallTime /t REG_DWORD /d 3 /f
}
Write-Progress -Activity AutoHarden -Status "Optimiz-DisableAutoUpdate" -Completed


echo "####################################################################################################"
echo "# Optimiz-DisableDefender"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Optimiz-DisableDefender" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Optimiz-DisableDefender"
if( ask "Disable WindowsDefender" "Optimiz-DisableDefender.ask" ){
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
}
Write-Progress -Activity AutoHarden -Status "Optimiz-DisableDefender" -Completed


echo "####################################################################################################"
echo "# Software-install-notepad++"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Software-install-notepad++" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Software-install-notepad++"
if( ask "Replace notepad with notepad++" "Software-install-notepad++.ask" ){
################################################################################
# Installation de choco
#
if( !(Get-Command "choco" -errorAction SilentlyContinue) ){
	echo "==============================================================================="
	echo "Install: choco"
    iwr https://chocolatey.org/install.ps1 -UseBasicParsing | iex
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

chocoInstall notepadplusplus.install
$npp_path=(Get-Item "C:\Program Files*\Notepad++\notepad++.exe").FullName

@'
'// DISCLAIMER
'// THIS COMES WITH NO WARRANTY, IMPLIED OR OTHERWISE. USE AT YOUR OWN RISK
'// IF YOU ARE NOT COMFORTABLE EDITING THE REGISTRY THEN DO NOT USE THIS SCRIPT
'//
'// NOTES:
'// This affects all users.
'// This will prevent ANY executable named notepad.exe from running located anywhere on this computer!!
'//
'// Save this text to your notepad++ folder as a text file named npp.vbs (some AV don't like vbs, get a different AV :-P )
'//
'// USAGE
'// 1)
'// Navigate to registry key HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\
'//
' // 2)
'// Add new subkey called notepad.exe
'// This step is what tells windows to use the notepad++ exe, to undo simply delete this key
'//
'// 3)
'// Create new Sting Value called Debugger
'//
'// 4)
'// Modify value and enter wscript.exe "path to npp.vbs" e.g. wscript.exe "C:\Program Files\Notepad++\npp.vbs"

Option Explicit
Dim sCmd, x
sCmd = """" & LeftB(WScript.ScriptFullName, LenB(WScript.ScriptFullName) - LenB(WScript.ScriptName)) & "notepad++.exe" & """ """
For x = 1 To WScript.Arguments.Count - 1
   sCmd = sCmd & WScript.Arguments(x) & " "
Next
sCmd = sCmd & """"
CreateObject("WScript.Shell").Exec(sCmd)
WScript.Quit
'@ | out-file -encoding ASCII $npp_path

if( [System.IO.File]::Exists($npp_path) ){
	# Create sub folder
	reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v Debugger /t REG_SZ /d x /f
	# Create key
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" -Name Debugger -Value ('wscript.exe "'+$npp_path+'"') -PropertyType String -Force
}
}
Write-Progress -Activity AutoHarden -Status "Software-install-notepad++" -Completed


echo "####################################################################################################"
echo "# Software-install"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Software-install" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Software-install"
################################################################################
# Installation de choco
#
if( !(Get-Command "choco" -errorAction SilentlyContinue) ){
	echo "==============================================================================="
	echo "Install: choco"
    iwr https://chocolatey.org/install.ps1 -UseBasicParsing | iex
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
Write-Progress -Activity AutoHarden -Status "Software-install" -Completed


Stop-Transcript

# SIG # Begin signature block
# MIINoAYJKoZIhvcNAQcCoIINkTCCDY0CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUf/f67+tWHvkSwWCzUOmpR1g4
# xHmgggo9MIIFGTCCAwGgAwIBAgIQlPiyIshB45hFPPzNKE4fTjANBgkqhkiG9w0B
# AQ0FADAYMRYwFAYDVQQDEw1BdXRvSGFyZGVuLUNBMB4XDTE5MTAyOTIxNTUxNVoX
# DTM5MTIzMTIzNTk1OVowFTETMBEGA1UEAxMKQXV0b0hhcmRlbjCCAiIwDQYJKoZI
# hvcNAQEBBQADggIPADCCAgoCggIBALrMv49xZXZjF92Xi3cWVFQrkIF+yYNdU3GS
# l1NergVq/3WmT8LDpaZ0XSpExZ7soHR3gs8eztnfe07r+Fl+W7l6lz3wUGFt52VY
# 17WCa53tr5dYRPzYt2J6TWT874tqZqlo+lUl8ONK1roAww2flcDajm8VUXM0k0sL
# M17H9NLykO3DeBuh2PVaXUxGDej+N8PsYF3/7Gv2AW0ZHGflrondcXb2/eh8xwbw
# RENsGaMXvnGr9RWkufC6bKq31J8BBnP+/65M6541AueBoH8pLbANPZgHKES+8V9U
# WlYKOeSoeBhtL1k3Rr8tfizRWx1zg/pBNL0WTOLcusmuJkdHkdHbHaW6Jc/vh06C
# s6xqz9/Dkg+K3BvOmfwZfAjl+qdgzM8dUU8/GWhswngwLAz64nZ82mZv/Iw6egC0
# rj5MYV0tpEjIgtVVgHavUfyXoIETNXFQR4SoK6PfeVkEzbRh03xhU65MSgBgWVv1
# YbOtdgXK0MmCs3ngVPJdVaqBjgcrK++X3Kxasb/bOkcfQjff/EK+BPb/xs+pXEqr
# yYbtbeX0v2rbV9cugPUj+mneucZBLFjuRcXhzVbXLrwXVne7yTD/sIKfe7dztzch
# g19AY6/qkkRkroaKLASpfCAVx2LuCgeFGn//QaEtCpFxMo2dcnW2a+54pkzrCRTR
# g1N2wBQFAgMBAAGjYjBgMBMGA1UdJQQMMAoGCCsGAQUFBwMDMEkGA1UdAQRCMECA
# EPp+TbkVy9u5igk2CqcX2OihGjAYMRYwFAYDVQQDEw1BdXRvSGFyZGVuLUNBghBr
# xVMud93NnE/XjEko2+2HMA0GCSqGSIb3DQEBDQUAA4ICAQAQLtHeMr2qJnfhha2x
# 2aCIApPjfHiHT4RNPI2Lq71jEbTpzdDFJQkKq4R3brGcpcnuU9VjUwz/BgKer+SF
# pkwFwTHyJpEFkbGavNo/ez3bqoehvqlTYDJO/i2mK0fvKmShfne6dZT+ftLpZCP4
# zngcANlp+kHy7mNRMB+LJv+jPc0kJ2oP4nIsLejyfxMj0lXuTJJRhxeZssdh0tq4
# MZP5MjSeiE5/AMuKT12uJ6klNUFS+OlEpZyHkIpgy4HxflXSvhchJ9U1YXF2IQ47
# WOrqwCXPUinHKZ8LwB0b0/35IlRCpub5KdRf803+4Okf9fL4rfc1cg9ZbLxuK9ne
# Fg1+ESL4aPyoV03TbN7Cdsd/sfx4mJ8jXJD+AXZ1ZofAAapYf9J5C71ChCZlhIGB
# vVc+dTUCWcUYgNOD9Nw+NiV6mARmVHl9SFL7yEtNYFgo0nWiNklqMqBLDxmrrD27
# sgBpFUwbMZ52truQwaaSHD7hFb4Tb1B0JVaGoog3QfNOXaFeez/fAt5L+yo78cDm
# 7Q2tXvy2g0xDAL/TXn7bhtDzQunltBzdULrJEQO4zI0h8YgmF88a0zYZ9HRkDUn6
# dR9+G8TlZuUsWSOdvLdEvad9RqiHKeSrL6qgLBT5kqVt6AFsEtmFNz1s7xpsw/zP
# ZvIXtQTmb4h+GcE/b2sUFZUkRDCCBRwwggMEoAMCAQICEGvFUy533c2cT9eMSSjb
# 7YcwDQYJKoZIhvcNAQENBQAwGDEWMBQGA1UEAxMNQXV0b0hhcmRlbi1DQTAeFw0x
# OTEwMjkyMTU1MDlaFw0zOTEyMzEyMzU5NTlaMBgxFjAUBgNVBAMTDUF1dG9IYXJk
# ZW4tQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDZZvLb9iKlWoqy
# D/dEZyLDZUGDzAL1MEXAujcPtEJb+erVnM7zJfSBdPodr1BefpZ0hJCTBganixWi
# YEqPZTch3k3446qRHDFQcNZ15elUnzYoqw+3yU5Mmd65etz7DsG31gjw1tQLy7n2
# IQYooz5StZOESRZIhWW2ZKXucrNLmOEFRY/mU2ltBANDJ3F9mGe++UJ1+xyTtB3z
# HBxhk8Tj4QKiez6fiAa7O+ZWmgEnpCUk1bm+46rOWngKUJFFoCnpdX5itLQb9+XX
# hNT+QAV4vip7s1gmQ1PM5yAwJ49as/unNtSiobJRHc2JUUpauJD3BfeuBhAsUbYK
# tM9ac4Vf1rwSY1ozadxuXvI1H47gINrrRf8Xf4+xjVPL5ZQwFxY5eHM3NbGhmQ3F
# PGv7msHijI6keFn8lKfx/5geyRSZThwRk0bM1mgFP+BNFfmyAlzSOWroJFdvXItB
# 6LgRt1hXEIgOavtVNr2P7HFcjD5vGXnAntm/kg/4qT7RbKXDj0rUZuREIC+AlnVa
# UppvPiUTtDXK0p0LTTwsDwU93OzizsGCwZfFh3CRtcjibULy479ZKDJiZB0dHYzg
# 8fCIPX6gBSx9HOveBOlSW6Iw1Rqfy0UfS5yZ82JVgGKE90nD0PbnrIK+MfFUp6zO
# nDBtwEkA/dkVVygg3qf0atvSF7b46QIDAQABo2IwYDATBgNVHSUEDDAKBggrBgEF
# BQcDAzBJBgNVHQEEQjBAgBD6fk25FcvbuYoJNgqnF9jooRowGDEWMBQGA1UEAxMN
# QXV0b0hhcmRlbi1DQYIQa8VTLnfdzZxP14xJKNvthzANBgkqhkiG9w0BAQ0FAAOC
# AgEAwYg8KFYtmIVs5TFExOSR1FFJBpE2jFSn42ARYlB3kECGlLkqt3TET5X6Q0Us
# 7d01uZn8HD3cMGrRNMXhjd6988kIJ8xBv7zFa8cJIHxXpFWLxOCWuedTEpMAANn7
# kxxrEQfbRG065Gxq9+W12WMTqRh6WSInxRExQk+qzqYXg3cThFOmMi3iGIBnRgpi
# krSd10pL6gYe6EOOTNPoql/coyTRqFIPlzC55OCvvu68SJP0hrVAbiKbAd5LJiLF
# yJnpVMR8N8XupxpJJ3AJvcl+601NTNX6q8WqAYhr8fY5asQ1TCM8w4Gu7ylw7D/4
# lJm+H3nkyKMu/koKhlrEr0Yi7egOQniEOV2k64Vjfpmxqur7xU2bnLWOi83bn8IZ
# W2VxZn1Py57EaazNhM2H22vFWZpnzAQaZ2K8Oav93eX/TkpjZEUI7NB31Wm/W+OI
# VjVHdkCesr4zOYHQd+u3pFWoC6VXW/+JsMyjpbKQ1C0pU+6wHrjnNZ48pbvNKWwR
# QjYge9gJljW6hCuPBDZaFK++TYbkyie+JZY/jbeoPcw87F7hSAsiSC74BPI3vOxk
# F6fu9dmkhqiQS4hkxY7kt1HLSfKnZX+c5F8OpjAedvzN0GIOryPtgGEXNhEF0b5v
# GUpQymInafZmReNxHFxVZLZyvO8fkymFY530xqJny3wF6U4xggLNMIICyQIBATAs
# MBgxFjAUBgNVBAMTDUF1dG9IYXJkZW4tQ0ECEJT4siLIQeOYRTz8zShOH04wCQYF
# Kw4DAhoFAKB4MBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkD
# MQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJ
# KoZIhvcNAQkEMRYEFOpDZl4IxSV4FokqxPt5X4lVfJGDMA0GCSqGSIb3DQEBAQUA
# BIICAAoFcqsN7xQ4U7kjxyJeBVzlsM0FEBiIFwDt0z8aQ2Z4OSiW2gYjxmwxEXBl
# qreesYafgC167cUbs9lHIl7Jmx+9B2hb3yA+C0NGt/hV4GrFaJK1UvI7VIfZI4i6
# /a51k7nxTspkpla47TeCSJoVQ7ZTyjQNVyY37HIc4FYe9l5ai+3r0PESoSTS48BS
# XnH02y68S+PiKVX9fOCavhK8s7i50S9hFiRsGsFJ/KBYpQMDSIja85eK38UZFLC8
# cKTQpUPc5h/LwxPhOIglU4SriDNoMPuKVy5+dc3flJhurvlF1GsgPwARfiYNqIcy
# /MSvSSN0FJM5iv9Dno5g5JY/wfLvhTUjMzMJP4e2hgA0EE1VxBvQnxyergRKapB6
# 5ooVhs+YVAavRY6evf+IF18rTqQklIBzFrXtdSwb9mRrHqm5mfYuIm0HYMFGvJUa
# UiiqJ1CtCUswfS9B46xmULxVKAvruakso2lSZXpIq0yGBc2By5JEsO2VjiTeBBIm
# IdnzSjctIJMIUbndKyFan/qnUMQlyw1bZE8yTjlV8D9S5HLuyt6dyH6wdUV4CuPu
# QglLvcItMfRF5qj2MO+mJS872S53n1qMDJY3gRRAR/dGXWJl1vFbqQza+sLc7MAj
# 3oozpNI7elg5rMS+yY2QVmNMMgXINi+nikNIQtZlHpRJmasQ
# SIG # End signature block
