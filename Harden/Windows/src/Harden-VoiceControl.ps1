reg add "HKEY_CURRENT_USER\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps" /t REG_DWORD /v AgentActivationEnabled /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps" /t REG_DWORD /v AgentActivationOnLockScreenEnabled /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\InputPersonalization" /t REG_DWORD /v AllowInputPersonalization /d 0 /f