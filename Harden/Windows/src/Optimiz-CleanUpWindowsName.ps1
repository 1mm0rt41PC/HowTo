$finalUser='Administrateur'
try{
	if( -Not (New-Object System.Security.Principal.NTAccount($finalUser)).Translate([System.Security.Principal.SecurityIdentifier]).value.EndsWith('-500') ){
		$finalUser='Invité'
	}
}catch{
	$finalUser='Administrator'
	if( -Not (New-Object System.Security.Principal.NTAccount($finalUser)).Translate([System.Security.Principal.SecurityIdentifier]).value.EndsWith('-500') ){
		$finalUser='Guest'
	}
}


function killfakename( $file ){
	echo "$file ========="
	#takeown.exe /f $file
	icacls.exe "$file" /setowner $env:username
	remove-item -Force $file
	echo '' | Out-File $file
	icacls.exe "$file" /setowner $finalUser
	attrib +s +h $file
	(Get-Acl $file).Owner
	#(Get-Acl $file).Access
}


killfakename 'C:\Users\desktop.ini'
killfakename 'C:\Program Files\desktop.ini'
killfakename 'C:\Program Files (x86)\desktop.ini'
