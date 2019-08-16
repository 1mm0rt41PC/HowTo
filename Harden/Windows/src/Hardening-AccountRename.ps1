try{
if( (New-Object System.Security.Principal.NTAccount('Administrateur')).Translate([System.Security.Principal.SecurityIdentifier]).value.EndsWith('-500') ){
	Rename-LocalUser -Name Administrateur -NewName Adm
	Rename-LocalUser -Name Invité -NewName Administrateur
	Rename-LocalUser -Name Adm -NewName Invité
}
}catch{}
try{
if( (New-Object System.Security.Principal.NTAccount('Administrator')).Translate([System.Security.Principal.SecurityIdentifier]).value.EndsWith('-500') ){
	Rename-LocalUser -Name Administrator -NewName Adm
	Rename-LocalUser -Name Guest -NewName Administrator
	Rename-LocalUser -Name Adm -NewName Guest
}
}catch{}
