# Block IPv6
New-NetFirewallRule -direction Outbound -Action Block -Protocol 41 -Name "[AutoHarden-$AutoHarden_version] IPv6" -DisplayName "[AutoHarden-$AutoHarden_version] IPv6" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Protocol 43 -Name "[AutoHarden-$AutoHarden_version] IPv6-Route" -DisplayName "[AutoHarden-$AutoHarden_version] IPv6-Route" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Protocol 44 -Name "[AutoHarden-$AutoHarden_version] IPv6-Frag" -DisplayName "[AutoHarden-$AutoHarden_version] IPv6-Frag" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Protocol 59 -Name "[AutoHarden-$AutoHarden_version] IPv6-NoNxt" -DisplayName "[AutoHarden-$AutoHarden_version] IPv6-NoNxt" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Protocol 60 -Name "[AutoHarden-$AutoHarden_version] IPv6-Opts" -DisplayName "[AutoHarden-$AutoHarden_version] IPv6-Opts" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Protocol 58 -Name "[AutoHarden-$AutoHarden_version] ICMPv6" -DisplayName "[AutoHarden-$AutoHarden_version] ICMPv6" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Protocol "UDP" -RemotePort "547" -Name "[AutoHarden-$AutoHarden_version] DHCPv6" -DisplayName "[AutoHarden-$AutoHarden_version] DHCPv6" -ErrorAction Ignore
