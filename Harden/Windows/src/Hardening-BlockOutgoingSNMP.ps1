New-NetFirewallRule -direction Outbound -Action Block -Protocol "TCP" -RemotePort "161" -Name "[RemoteRules] SNMP-TCP" -DisplayName "[RemoteRules] SNMP" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Protocol "UDP" -RemotePort "161" -Name "[RemoteRules] SNMP-UDP" -DisplayName "[RemoteRules] SNMP" -ErrorAction Ignore