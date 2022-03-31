# Enable support for chromecast
reg add HKEY_LOCAL_MACHINE\Software\Policies\Google\Chrome /v EnableMediaRouter /d 1 /f
# Disable password management
reg add HKEY_LOCAL_MACHINE\Software\Policies\Google\Chrome /v PasswordManagerEnabled /d 0 /f

reg add HKEY_LOCAL_MACHINE\Software\Policies\BraveSoftware\Brave /v PasswordManagerEnabled /d 0 /f
reg add HKEY_LOCAL_MACHINE\Software\Policies\BraveSoftware\Brave /v EnableMediaRouter /d 1 /f

reg add HKEY_LOCAL_MACHINE\Software\Policies\Chromium /v PasswordManagerEnabled /d 0 /f
reg add HKEY_LOCAL_MACHINE\Software\Policies\Chromium /v EnableMediaRouter /d 1 /f