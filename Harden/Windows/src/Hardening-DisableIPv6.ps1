# Block IPv6
New-NetFirewallRule -direction Outbound -Action Block -Protocol 41 -Name "[RemoteRules] IPv6" -DisplayName "[RemoteRules] IPv6" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Protocol 43 -Name "[RemoteRules] IPv6-Route" -DisplayName "[RemoteRules] IPv6-Route" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Protocol 44 -Name "[RemoteRules] IPv6-Frag" -DisplayName "[RemoteRules] IPv6-Frag" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Protocol 59 -Name "[RemoteRules] IPv6-NoNxt" -DisplayName "[RemoteRules] IPv6-NoNxt" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Protocol 60 -Name "[RemoteRules] IPv6-Opts" -DisplayName "[RemoteRules] IPv6-Opts" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Protocol 58 -Name "[RemoteRules] ICMPv6" -DisplayName "[RemoteRules] ICMPv6" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Protocol "UDP" -RemotePort "547" -Name "[RemoteRules] DHCPv6" -DisplayName "[RemoteRules] DHCPv6" -ErrorAction Ignore
