$Trigger = New-ScheduledTaskTrigger -At 08:00am -Daily
#$Action  = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-exec AllSigned -nop -File C:\Windows\AutoHarden\AutoHarden.ps1 > C:\Windows\AutoHarden\ScheduledTask.log"
$Action  = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-exec ByPass -nop -File C:\Windows\AutoHarden\AutoHarden.ps1 > C:\Windows\AutoHarden\ScheduledTask.log"
$Setting = New-ScheduledTaskSettingsSet -RestartOnIdle -StartWhenAvailable
Register-ScheduledTask -TaskName "AutoHarden" -Trigger $Trigger -User "NT AUTHORITY\SYSTEM" -Action $Action -RunLevel Highest -Settings $Setting -Force
Get-NetFirewallRule -Name '*AutoHarden*Powershell*' | Disable-NetFirewallRule
Invoke-WebRequest -Uri https://raw.githubusercontent.com/1mm0rt41PC/HowTo/master/Harden/Windows/AutoHarden_RELEASE.ps1 -OutFile C:\Windows\AutoHarden\AutoHarden_temp.ps1
Get-NetFirewallRule -Name '*AutoHarden*Powershell*' | Enable-NetFirewallRule
if( (Get-AuthenticodeSignature C:\Windows\AutoHarden\AutoHarden_temp.ps1).Status -eq [System.Management.Automation.SignatureStatus]::Valid ){
	Write-Host "[*] The downloaded PS1 has a valid signature !"
	move -force C:\Windows\AutoHarden\AutoHarden_temp.ps1 C:\Windows\AutoHarden\AutoHarden.ps1
}else{
	Write-Host "[!] The downloaded PS1 has an invalid signature !"
}
