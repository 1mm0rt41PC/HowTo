$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'
$PSDefaultParameterValues['*:Encoding'] = 'utf8'

$date = Get-Date -Format 'yyyy-MM-dd'
$output = "AutoHarden_RELEASE_${date}.ps1"


echo "`$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'" > $output
echo "`$PSDefaultParameterValues['*:Encoding'] = 'utf8'" >> $output
echo 'if( ![bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544") ){  Write-Host -BackgroundColor Red -ForegroundColor White "Administrator privileges required ! This terminal has not admin priv. This script ends now !"; pause;exit;}' >> $output

Get-ChildItem .\src\*.ps1 | foreach {
	Write-Host $_.Name
	echo '####################################################################################################'
	echo ('# '+$_.Name.Replace('.ps1',''))
	echo '####################################################################################################'
	echo ('Write-Progress -Activity AutoHarden -Status "'+$_.Name.Replace('.ps1','')+'" -PercentComplete 0')
	echo ('Write-Host -BackgroundColor Blue -ForegroundColor White "Running '+$_.Name.Replace('.ps1','')+'"')
	cat $_.FullName
	echo ('Write-Progress -Activity AutoHarden -Status "'+$_.Name.Replace('.ps1','')+'" -Completed')
	echo ''
	echo ''
} >> $output