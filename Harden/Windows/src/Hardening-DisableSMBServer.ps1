# Désactivation des partages administratifs
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareWks /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareServer /t REG_DWORD /d 0 /f

#Set-SmbServerConfiguration -AnnounceServer $false -Force
#Get-SmbServerConfiguration

sc.exe config lanmanserver start= disabled