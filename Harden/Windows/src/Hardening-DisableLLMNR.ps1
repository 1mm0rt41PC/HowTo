# Disable LLMNR
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /t REG_DWORD /v EnableMulticast /d 0 /f
nbtstat.exe /n
New-NetFirewallRule -direction Outbound -Action Block -Protocol "UDP" -RemotePort "5355" -Group AutoHarden-LLMNR -Name "[AutoHarden-$AutoHarden_version] LLMNR-UDP" -DisplayName "[AutoHarden-$AutoHarden_version] LLMNR" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Protocol "UDP" -RemotePort "5353" -Group AutoHarden-LLMNR -Name "[AutoHarden-$AutoHarden_version] MBNS" -DisplayName "[AutoHarden-$AutoHarden_version] MBNS" -ErrorAction Ignore
