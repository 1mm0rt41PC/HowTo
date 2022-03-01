# Block IPv6
New-NetFirewallRule -direction Outbound -Action Block -Protocol 41 -Group AutoHarden-IPv6 -Name "[AutoHarden-$AutoHarden_version] IPv6" -DisplayName "[AutoHarden-$AutoHarden_version] IPv6" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Protocol 43 -Group AutoHarden-IPv6 -Name "[AutoHarden-$AutoHarden_version] IPv6-Route" -DisplayName "[AutoHarden-$AutoHarden_version] IPv6-Route" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Protocol 44 -Group AutoHarden-IPv6 -Name "[AutoHarden-$AutoHarden_version] IPv6-Frag" -DisplayName "[AutoHarden-$AutoHarden_version] IPv6-Frag" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Protocol 59 -Group AutoHarden-IPv6 -Name "[AutoHarden-$AutoHarden_version] IPv6-NoNxt" -DisplayName "[AutoHarden-$AutoHarden_version] IPv6-NoNxt" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Protocol 60 -Group AutoHarden-IPv6 -Name "[AutoHarden-$AutoHarden_version] IPv6-Opts" -DisplayName "[AutoHarden-$AutoHarden_version] IPv6-Opts" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Protocol 58 -Group AutoHarden-IPv6 -Name "[AutoHarden-$AutoHarden_version] ICMPv6" -DisplayName "[AutoHarden-$AutoHarden_version] ICMPv6" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Protocol "UDP" -RemotePort "547" -Group AutoHarden-IPv6 -Name "[AutoHarden-$AutoHarden_version] DHCPv6" -DisplayName "[AutoHarden-$AutoHarden_version] DHCPv6" -ErrorAction Ignore

# reg add "HKLM\SYSTEM\CurrentControlSet\services\tcpip6\parameters" /v DisabledComponents /t REG_DWORD /d 0xFF /f
# Netsh int ipv6 set int 12 routerdiscovery=disabled
# Netsh int ipv6 set int 12 managedaddress=disabled