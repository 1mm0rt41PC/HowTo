New-NetFirewallRule -direction Outbound -Action Block -Protocol "TCP" -RemotePort "135" -Group AutoHarden-NetBios -Name "[AutoHarden-$AutoHarden_version] NetBios-TCP135" -DisplayName "[AutoHarden-$AutoHarden_version] NetBios" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Protocol "UDP" -RemotePort "137" -Group AutoHarden-NetBios -Name "[AutoHarden-$AutoHarden_version] NetBios-UDP137" -DisplayName "[AutoHarden-$AutoHarden_version] NetBios" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Protocol "UDP" -RemotePort "138" -Group AutoHarden-NetBios -Name "[AutoHarden-$AutoHarden_version] NetBios-UDP138" -DisplayName "[AutoHarden-$AutoHarden_version] NetBios2" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Protocol "TCP" -RemotePort "139" -Group AutoHarden-NetBios -Name "[AutoHarden-$AutoHarden_version] NetBios-TCP139" -DisplayName "[AutoHarden-$AutoHarden_version] NetBios3" -ErrorAction Ignore
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\tcpip* -Name NetbiosOptions -Value 2
# https://admx.help/?Category=KB160177
# This secures the machine by telling Windows to treat itself as a NetBIOS P-node (point-to-point system).
# These systems will only resolve NBT-NS queries using WINS – no broadcasts will take place. Success!
Set-ItemProperty HKLM:\System\CurrentControlSet\Services\NetBT\Parameters -Name NodeType -Value 2