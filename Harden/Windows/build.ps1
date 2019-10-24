$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'
$PSDefaultParameterValues['*:Encoding'] = 'utf8'

$date = Get-Date -Format 'yyyy-MM-dd'
$output = 'AutoHarden_RELEASE.ps1'

echo ('# '+$date) > $output
echo "`$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'" >> $output
echo "`$PSDefaultParameterValues['*:Encoding'] = 'utf8'" >> $output
echo 'Add-Type -AssemblyName System.Windows.Forms' >> $output
echo 'if( ![bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544") ){  Write-Host -BackgroundColor Red -ForegroundColor White "Administrator privileges required ! This terminal has not admin priv. This script ends now !"; pause;exit;}' >> $output
echo 'mkdir C:\Windows\AutoHarden\ -Force -ErrorAction Ignore' >> $output
echo 'Start-Transcript -Append ("C:\Windows\AutoHarden\Activities_"+(Get-Date -Format "yyyy-MM-dd")+".log")' >> $output

Get-ChildItem .\src\*.ps1 | foreach {
	Write-Host $_.Name
	echo '####################################################################################################'
	echo ('# '+$_.Name.Replace('.ps1',''))
	echo '####################################################################################################'
	echo ('Write-Progress -Activity AutoHarden -Status "'+$_.Name.Replace('.ps1','')+'" -PercentComplete 0')
	echo ('Write-Host -BackgroundColor Blue -ForegroundColor White "Running '+$_.Name.Replace('.ps1','')+'"')
	if( [System.IO.File]::Exists($_.FullName.Replace('.ps1','.ask')) ){
		echo ('$config="C:\Windows\AutoHarden\'+$_.Name.Replace('.ps1','')+'.ask";')
		echo '$ret=cat $config -ErrorAction Ignore;'
		$query=cat $_.FullName.Replace('.ps1','.ask')
		echo ('if( "$ret" -eq "Yes" -Or ([string]::IsNullOrEmpty($ret) -And [System.Windows.Forms.MessageBox]::Show("'+$query+'?","'+$query+'?", "YesNo" , "Question" ) -eq "Yes") ){')
		echo '[System.IO.File]::WriteAllLines($config, "Yes", (New-Object System.Text.UTF8Encoding $False));'
	}
	cat $_.FullName
	if( [System.IO.File]::Exists($_.FullName.Replace('.ps1','.ask')) ){
		echo '}else{ [System.IO.File]::WriteAllLines($config, "Yes", (New-Object System.Text.UTF8Encoding $False)); }'
	}
	echo ('Write-Progress -Activity AutoHarden -Status "'+$_.Name.Replace('.ps1','')+'" -Completed')
	echo ''
	echo ''
} >> $output
echo 'Stop-Transcript' >> $output