$Trigger = New-ScheduledTaskTrigger -At 08:00am -Daily
$Action  = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-exec AllSigned -nop -File C:\Windows\AutoHarden\AutoHarden.ps1"
$Setting = New-ScheduledTaskSettingsSet -RestartOnIdle -StartWhenAvailable
Register-ScheduledTask -TaskName "AutoHarden" -Trigger $Trigger -User "NT AUTHORITY\SYSTEM" -Action $Action -RunLevel Highest -Settings $Setting -Force
netsh advfirewall set AllProfiles state off
Invoke-WebRequest -Uri https://raw.githubusercontent.com/1mm0rt41PC/HowTo/master/Harden/Windows/AutoHarden_RELEASE.ps1 -OutFile C:\Windows\AutoHarden\AutoHarden.ps1
netsh advfirewall set AllProfiles state on