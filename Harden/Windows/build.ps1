# AutoHarden - A simple script that automates Windows Hardening
#
# Filename: build.ps1
# Author: 1mm0rt41PC - immortal-pc.info - https://github.com/1mm0rt41PC
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING. If not, write to the
# Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#
$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'
$PSDefaultParameterValues['*:Encoding'] = 'utf8'

$date = Get-Date -Format 'yyyy-MM-dd'
$output = 'AutoHarden_TEST.ps1'

mkdir -Force "${PSScriptRoot}\cert\" > $null
if( -not [System.IO.File]::Exists("${PSScriptRoot}\cert\AutoHarden-CA.pvk") -or -not [System.IO.File]::Exists("${PSScriptRoot}\cert\AutoHarden-CA.cer") ){
	makecert -n "CN=AutoHarden-CA" -a sha512 -len 4096 -eku 1.3.6.1.5.5.7.3.3 -r -ss Root -sr localmachine -sy 1mm0rt41PC -sv ${PSScriptRoot}\cert\AutoHarden-CA.pvk ${PSScriptRoot}\cert\AutoHarden-CA.cer
}
if( -not [System.IO.File]::Exists("${PSScriptRoot}\cert\AutoHarden.pfx") -or -not [System.IO.File]::Exists("${PSScriptRoot}\cert\AutoHarden.cer") ){
	makecert -n "CN=AutoHarden" -a sha512 -len 4096 -eku 1.3.6.1.5.5.7.3.3 -pe -ss MY -iv ${PSScriptRoot}\cert\AutoHarden-CA.pvk -ic ${PSScriptRoot}\cert\AutoHarden-CA.cer -sy 1mm0rt41PC
	$password = (Get-Credential -UserName AutoHarden -Message "Password for certificate").Password
	$cert = ls Cert:\CurrentUser\My\ | where { $_.Subject.ToString() -eq "CN=AutoHarden" }
	Export-PfxCertificate -Cert $cert -FilePath ${PSScriptRoot}\cert\AutoHarden.pfx -Password $password -Force > $null
	Export-Certificate -Cert $cert -FilePath ${PSScriptRoot}\cert\AutoHarden.cer -Force > $null
}
$cert = ls Cert:\CurrentUser\My\ | where { $_.Subject.ToString() -eq "CN=AutoHarden" }
$AutoHardenCertCA = [Convert]::ToBase64String([IO.File]::ReadAllBytes("$PSScriptRoot\cert\AutoHarden-CA.cer"))
$AutoHardenCert = [Convert]::ToBase64String([IO.File]::ReadAllBytes("$PSScriptRoot\cert\AutoHarden.cer"))

echo '# AutoHarden - A simple script that automates Windows Hardening' > $output
echo '#' >> $output
echo '# Filename: AutoHarden.ps1' >> $output
echo '# Author: 1mm0rt41PC - immortal-pc.info - https://github.com/1mm0rt41PC' >> $output
echo '#' >> $output
echo '# This program is free software; you can redistribute it and/or modify' >> $output
echo '# it under the terms of the GNU General Public License as published by' >> $output
echo '# the Free Software Foundation; either version 2 of the License, or' >> $output
echo '# (at your option) any later version.' >> $output
echo '#' >> $output
echo '# This program is distributed in the hope that it will be useful,' >> $output
echo '# but WITHOUT ANY WARRANTY; without even the implied warranty of' >> $output
echo '# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the' >> $output
echo '# GNU General Public License for more details.' >> $output
echo '#' >> $output
echo '# You should have received a copy of the GNU General Public License' >> $output
echo '# along with this program; see the file COPYING. If not, write to the' >> $output
echo '# Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.' >> $output
echo '#' >> $output
echo ('# Update: '+$date) >> $output
echo ('$AutoHarden_version="'+$date+'"') >> $output
echo '$global:AutoHarden_boradcastMsg=$true' >> $output
echo "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass" >> $output
echo "`$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'" >> $output
echo "`$PSDefaultParameterValues['*:Encoding'] = 'utf8'" >> $output
echo 'Add-Type -AssemblyName System.Windows.Forms' >> $output
echo 'function ask( $query, $config ){' >> $output
echo '	$config="C:\Windows\AutoHarden\${config}";' >> $output
echo '	$ret=cat $config -ErrorAction Ignore;' >> $output
echo '	echo "# ASK..."' >> $output
echo '	try{' >> $output
echo '		if( "$ret" -eq "Yes" -Or ([string]::IsNullOrEmpty($ret) -And [System.Windows.Forms.MessageBox]::Show("${query}?","${query}?", "YesNo" , "Question" ) -eq "Yes") ){' >> $output
echo '			[System.IO.File]::WriteAllLines($config, "Yes", (New-Object System.Text.UTF8Encoding $False));' >> $output
echo '			echo "# ASK... => YES!"' >> $output
echo '			return $true;' >> $output
echo '		}else{' >> $output
echo '			echo "# ASK... => NO :-("' >> $output
echo '			[System.IO.File]::WriteAllLines($config, "No", (New-Object System.Text.UTF8Encoding $False));' >> $output
echo '			return $false;' >> $output
echo '		}' >> $output
echo '	}catch{' >> $output
echo '		if( $global:AutoHarden_boradcastMsg ) {' >> $output
echo '			$global:AutoHarden_boradcastMsg=$false' >> $output
echo '			msg * "An update of AutoHarden require an action from the administrator. Please run C:\Windows\AutoHarden\AutoHarden.ps1"' >> $output
echo '		}' >> $output
echo '		return $false;' >> $output
echo '	}' >> $output
echo '}' >> $output
# msg.exe * /V "test"
echo 'if( ![bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544") ){  Write-Host -BackgroundColor Red -ForegroundColor White "Administrator privileges required ! This terminal has not admin priv. This script ends now !"; pause;exit;}' >> $output
echo 'mkdir C:\Windows\AutoHarden\ -Force -ErrorAction Ignore' >> $output
echo 'Start-Transcript -Force -IncludeInvocationHeader -Append ("C:\Windows\AutoHarden\Activities_"+(Get-Date -Format "yyyy-MM-dd")+".log")' >> $output
echo '$DebugPreference = "Continue"' >> $output
echo '$VerbosePreference = "Continue"' >> $output
echo '$InformationPreference = "Continue"' >> $output
echo '' >> $output
echo 'echo "####################################################################################################"' >> $output
echo ('echo "# Install AutoHarden Cert"') >> $output
echo 'echo "####################################################################################################"' >> $output
echo 'if( ask "Auto update AutoHarden and execute AutoHarden every day at 08h00 AM" "0-AutoUpdate.ask" ){' >> $output
echo '	$AutoHardenCert = "${env:temp}\"+[System.IO.Path]::GetRandomFileName()+".cer"' >> $output
echo ('	[IO.File]::WriteAllBytes($AutoHardenCert, [Convert]::FromBase64String("'+$AutoHardenCert+'"))') >> $output
echo '	Import-Certificate -Filepath $AutoHardenCert -CertStoreLocation Cert:\LocalMachine\TrustedPublisher' >> $output
echo '	$AutoHardenCertCA = "${env:temp}\"+[System.IO.Path]::GetRandomFileName()+".cer"' >> $output
echo ('	[IO.File]::WriteAllBytes($AutoHardenCertCA, [Convert]::FromBase64String("'+$AutoHardenCertCA+'"))') >> $output
echo '	Import-Certificate -Filepath $AutoHardenCertCA -CertStoreLocation Cert:\LocalMachine\AuthRoot' >> $output
echo '}' >> $output
echo '' >> $output
echo '' >> $output

Get-ChildItem ${PSScriptRoot}\src\*.ps1 | foreach {
	Write-Host $_.Name
	echo 'echo "####################################################################################################"'
	echo ('echo "# '+$_.Name.Replace('.ps1','')+'"')
	echo 'echo "####################################################################################################"'
	echo ('Write-Progress -Activity AutoHarden -Status "'+$_.Name.Replace('.ps1','')+'" -PercentComplete 0')
	echo ('Write-Host -BackgroundColor Blue -ForegroundColor White "Running '+$_.Name.Replace('.ps1','')+'"')
	if( [System.IO.File]::Exists($_.FullName.Replace('.ps1','.ask')) ){
		echo ('if( ask "'+(cat $_.FullName.Replace('.ps1','.ask'))+'" "'+$_.Name.Replace('.ps1','')+'.ask" ){')
	}
	cat $_.FullName
	if( [System.IO.File]::Exists($_.FullName.Replace('.ps1','.ask')) ){
		echo '}'
	}
	if( [System.IO.File]::Exists($_.FullName.Replace('.ps1','.rollback')) ){
		echo 'else{'
		cat $_.FullName.Replace('.ps1','.rollback')
		echo '}'
	}
	echo ('Write-Progress -Activity AutoHarden -Status "'+$_.Name.Replace('.ps1','')+'" -Completed')
	echo ''
	echo ''
} >> $output
echo 'Stop-Transcript' >> $output

if( Set-AuthenticodeSignature -filepath $output -cert $cert -IncludeChain All ){
	Write-Host 'Signature OK'
	mv -Force $output 'AutoHarden_RELEASE.ps1'
}else{
	rm 'AutoHarden_RELEASE.ps1'
}
