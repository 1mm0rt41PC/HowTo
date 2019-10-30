# AES 256-bit 
reg add 'HKLM\SOFTWARE\Policies\Microsoft\FVE' /v EncryptionMethod  /t REG_DWORD /d 4 /f

try{
	(Get-BitLockerVolume -MountPoint 'C:').KeyProtector |foreach {
		Write-Host ("C: is protected with: "+$_.KeyProtectorType)
	}
}catch{
	Enable-BitLocker -MountPoint 'C:' -EncryptionMethod Aes256 -UsedSpaceOnly -TpmProtector -ErrorAction Continue
	Enable-BitLocker -MountPoint 'C:' -EncryptionMethod Aes256 -UsedSpaceOnly -RecoveryPasswordProtector -ErrorAction Continue
	(Get-BitLockerVolume -MountPoint 'C:').KeyProtector | foreach {
		if( -not [string]::IsNullOrEmpty($_.RecoveryPassword) ){
			Add-Type -AssemblyName System.Windows.Forms
			[System.Windows.Forms.MessageBox]::Show("Please keep a note of this RecoveryPassword "+$_.RecoveryPassword);
		}
	}
}
