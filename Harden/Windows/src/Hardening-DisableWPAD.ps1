# Disable wpad service
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc" /t REG_DWORD /v Start /d 4 /f

reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" /v "DefaultConnectionSettings" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" /v "SavedLegacySettings" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" /t REG_DWORD /v WpadOverride /d 0 /f
RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 8
ipconfig /flushdns
$_wpad=Select-String -Path C:\Windows\System32\drivers\etc\hosts -Pattern "0.0.0.0 wpad"
if( [string]::IsNullOrEmpty($_wpad) ){
	[System.IO.File]::AppendAllText("C:\Windows\System32\drivers\etc\hosts", "`r`n0.0.0.0 wpad", (New-Object System.Text.UTF8Encoding $False));
}
$_wpad=Select-String -Path C:\Windows\System32\drivers\etc\hosts -Pattern "0.0.0.0 ProxySrv"
if( [string]::IsNullOrEmpty($_wpad) ){
	[System.IO.File]::AppendAllText("C:\Windows\System32\drivers\etc\hosts", "`r`n0.0.0.0 ProxySrv", (New-Object System.Text.UTF8Encoding $False));
}