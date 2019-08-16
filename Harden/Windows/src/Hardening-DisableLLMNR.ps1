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
echo "`r`n0.0.0.0 wpad" >> C:\Windows\System32\drivers\etc\hosts
