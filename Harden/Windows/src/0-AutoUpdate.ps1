$Trigger = New-ScheduledTaskTrigger -At 08:00am -Daily
$Action  = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "cmd /c `"powershell.exe -exec AllSigned -nop -File C:\Windows\AutoHarden\AutoHarden.ps1`" > C:\Windows\AutoHarden\ScheduledTask.log"
$Setting = New-ScheduledTaskSettingsSet -RestartOnIdle -StartWhenAvailable
Register-ScheduledTask -TaskName "AutoHarden" -Trigger $Trigger -User "NT AUTHORITY\SYSTEM" -Action $Action -RunLevel Highest -Settings $Setting -Force
Get-NetFirewallRule -Name '*AutoHarden*Powershell*' | Disable-NetFirewallRule
Invoke-WebRequest -Uri https://raw.githubusercontent.com/1mm0rt41PC/HowTo/master/Harden/Windows/AutoHarden_RELEASE.ps1 -OutFile C:\Windows\AutoHarden\AutoHarden.ps1
Get-NetFirewallRule -Name '*AutoHarden*Powershell*' | Enable-NetFirewallRule