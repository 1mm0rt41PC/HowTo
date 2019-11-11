New-NetFirewallRule -direction Outbound -Action Block -Protocol "TCP" -RemotePort "135" -Name "[AutoHarden-$AutoHarden_version] NetBios-TCP135" -DisplayName "[AutoHarden-$AutoHarden_version] NetBios" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Protocol "UDP" -RemotePort "137" -Name "[AutoHarden-$AutoHarden_version] NetBios-UDP137" -DisplayName "[AutoHarden-$AutoHarden_version] NetBios" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Protocol "UDP" -RemotePort "138" -Name "[AutoHarden-$AutoHarden_version] NetBios-UDP138" -DisplayName "[AutoHarden-$AutoHarden_version] NetBios2" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Protocol "TCP" -RemotePort "139" -Name "[AutoHarden-$AutoHarden_version] NetBios-TCP139" -DisplayName "[AutoHarden-$AutoHarden_version] NetBios3" -ErrorAction Ignore
set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\tcpip* -Name NetbiosOptions -Value 2