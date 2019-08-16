$HashMode = 1000
$HashFile = '.\WORK-password-hash.txt'


function hashcat( $dico='', $rules='' ){
	Write-Host -BackgroundColor Blue -ForegroundColor Black "    $dico with rules=$rules"
	if( $rules -ne '' ){
		$rules = '--rules=' + $rules
	}
	& .\hashcat64.exe --force -m $HashMode $HashFile $dico --workload-profile=4 $rules
	& .\hashcat64.exe --force -m $HashMode --show $HashFile --username | Out-File -Encoding utf8 DICO\loot.txt
	& .\hashcat64.exe --force -m $HashMode --show $HashFile | Out-File -Append -Encoding utf8 DICO\loot.txt
}

function Count-Password-Found(){
	$i=0;
	try {
		cat .\DICO\markov.dico | foreach { ++$i }
	}catch{}
	Write-Host -BackgroundColor Yellow -ForegroundColor Black "    Nb hash to submit: $i"
	echo $i
}

function Make-MarkovDict(){
	Write-Host Make-MarkovDict
	rm DICO\markov.dico
	if( $HashMode -eq 3000 -or $HashMode -eq 1000 ){
		& .\hashcat64.exe --force -m 1000 --show --outfile DICO\markov.dico --outfile-format 2 $HashFile
		#lmbuilder.exe WORK-password-hash.txt DICO\lm
		Write-Host Append LM
		cat DICO\lm | Out-File -Append -Encoding ascii DICO\markov.dico
	}else{
		& .\hashcat64.exe --force -m $HashMode --show --outfile DICO\markov.dico --outfile-format 2 $HashFile
	}
}

function my-Read-Host( $msg, $timeout=5, $default='' ){
	Write-Host -BackgroundColor Red -ForegroundColor Black $msg
	$secondsRunning = 0;
	while( (-not $Host.UI.RawUI.KeyAvailable) -and ($secondsRunning -lt $timeout*100) ){
		Start-Sleep -Seconds 0.1;
		++$secondsRunning;
		Write-Progress -Activity ReadHost -Status "$msg $($secondsRunning*100/($timeout*100))" -PercentComplete $($secondsRunning*100/($timeout*100))
	}
	Write-Progress -Activity ReadHost -Status $msg -Completed
	if( $Host.UI.RawUI.KeyAvailable ){
		$key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyUp");
		if( ($key.Character+"").ToLower() -ne 'y' -and ($key.Character+"").ToLower() -ne 'n' ){
			my-Read-Host -msg $msg -timeout $timeout -default $default
		}else{
			echo $key.Character;
		}
	}else{
		echo $default;
	}
}


if( ($HashMode -eq 3000 -or $HashMode -eq 1000) -and $(my-Read-Host -msg "Run LM attack ? [n/Y]" -default 'y') -eq "y" ){
	Write-Host -BackgroundColor Yellow -ForegroundColor Black "********** LM attack **********"
		& .\hashcat64.exe --force -m 3000 -a3 -i $HashFile ?a?a?a?a?a?a -w 3
		& .\lmbuilder.exe $HashFile DICO\lm
		& .\hashcat64.exe --force -m 3000 -a3 $HashFile ?a?a?a?a?a?a?a -w 3
		& .\lmbuilder.exe $HashFile DICO\lm
		# Pour les password avec des caractères spéciaux
		#& .\hashcat64.exe --force -m 3000 -a3 -i $HashFile ?b?b?b?b?b?b?b
}


if( $(my-Read-Host -msg "Run Password loop reuse ? [n/Y]" -default 'y') -eq "y" ){
	Write-Host -BackgroundColor Yellow -ForegroundColor Black "********** Password Loop reuse **********"
		Make-MarkovDict
		do{
			$begin=Count-Password-Found
			hashcat -dico DICO\markov.dico -rules rules\best64.rule
			hashcat -dico DICO\markov.dico -rules rules\d3ad0ne.rule
			hashcat -dico DICO\markov.dico -rules rules\OneRuleToRuleThemAll.rule
			hashcat -dico DICO\markov.dico -rules rules\d3adhob0.rule
			hashcat -dico DICO\markov.dico -rules rules\hob064.rule
			hashcat -dico DICO\markov.dico -rules rules\rockyou-30000.rule
			hashcat -dico DICO\markov.dico -rules rules\allrules
			Make-MarkovDict
			$end=Count-Password-Found
		}while($begin -ne $end);
}

if( $(my-Read-Host -msg "Run Markov dict ? [N/y]" -default 'n') -eq "y" ){
	Write-Host -BackgroundColor Yellow -ForegroundColor Black "********** Markov **********"
		Write-Host -BackgroundColor Blue -ForegroundColor Black "********** Generate stats and custom dict **********"
		cat DICO\markov.dico | .\hashcat-utils-1.8\bin\hcstatgen.exe ./hashcat.hcstat
		$stats = @{}
		cat .\DICO\markov.dico |foreach {
			try {
				$stats[$_.Length] += 1;
			}catch{
				$stats[$_.Length] = 1;
			}
		}
		$orderedLen = $stats.Keys | sort -Property @{Expression={$stats[$_]};Ascending = $False}
		if( $orderedLen[0] -lt $orderedLen[1] ){
			$pwdMin = $orderedLen[0];
			$pwdMax = $orderedLen[1];
		}else{
			$pwdMin = $orderedLen[1];
			$pwdMax = $orderedLen[0];
		}
		Write-Host -BackgroundColor Blue -ForegroundColor Black "Top worth password length: $pwdMin <= x <= $pwdMax th 200"
		& .\statsprocessor-0.11\sp64.exe --pw-min $pwdMin --pw-max $pwdMax --threshold 200 ./hashcat.hcstat > DICO\markov_gen.dico
		Write-Host -BackgroundColor Blue -ForegroundColor Black "Top worth password length: $pwdMin <= x <= $pwdMax th 210"
		& .\statsprocessor-0.11\sp64.exe --pw-min $pwdMin --pw-max $pwdMax --threshold 210 ./hashcat.hcstat >> DICO\markov_gen.dico
		Write-Host -BackgroundColor Blue -ForegroundColor Black "Top worth password length: $pwdMin <= x <= $pwdMax th 220"
		& .\statsprocessor-0.11\sp64.exe --pw-min $pwdMin --pw-max $pwdMax --threshold 220 ./hashcat.hcstat >> DICO\markov_gen.dico
		Write-Host -BackgroundColor Blue -ForegroundColor Black "Top worth password length: $pwdMin <= x <= $pwdMax th 230"
		& .\statsprocessor-0.11\sp64.exe --pw-min $pwdMin --pw-max $pwdMax --threshold 230 ./hashcat.hcstat >> DICO\markov_gen.dico
		Write-Host -BackgroundColor Blue -ForegroundColor Black "Top worth password length: $pwdMin <= x <= $pwdMax th 240"
		& .\statsprocessor-0.11\sp64.exe --pw-min $pwdMin --pw-max $pwdMax --threshold 240 ./hashcat.hcstat >> DICO\markov_gen.dico
		Write-Host -BackgroundColor Blue -ForegroundColor Black "Top worth password length: $pwdMin <= x <= $pwdMax th 250"
		& .\statsprocessor-0.11\sp64.exe --pw-min $pwdMin --pw-max $pwdMax --threshold 250 ./hashcat.hcstat >> DICO\markov_gen.dico
		Write-Host -BackgroundColor Blue -ForegroundColor Black "********** BruteForce **********"
		#& .\hashcat64.exe --force -m $HashMode -a3 --workload-profile=4 $HashFile ?a?a?a --markov-hcstat ./hashcat.hcstat
		hashcat -dico DICO\markov_gen.dico
		hashcat -dico DICO\markov_gen.dico -rules rules\best64.rule
		hashcat -dico DICO\markov_gen.dico -rules rules\rockyou-30000.rule
		hashcat -dico DICO\markov_gen.dico -rules rules\allrules
}

if( $(my-Read-Host -msg "Run brute force and markov ? [N/y]" -default 'n') -eq "y" ){
	Write-Host -BackgroundColor Yellow -ForegroundColor Black "********** Brute force **********"
		Write-Host -BackgroundColor Blue -ForegroundColor Black "********** Generate stats and custom dict **********"
		cat  DICO\markov.dico | .\hashcat-utils-1.8\bin\hcstatgen.exe ./hashcat.hcstat
		$stats = @{}
		cat .\DICO\markov.dico |foreach {
			try {
				$stats[$_.Length] += 1;
			}catch{
				$stats[$_.Length] = 1;
			}
		}
		$orderedLen = $stats.Keys | sort -Property @{Expression={$stats[$_]};Ascending = $False}
		$orderedLen | foreach {
			Write-Host  -BackgroundColor Blue -ForegroundColor Black "$($stats[$_]) passswords have a length of $_ chars"
		}
		Write-Host -BackgroundColor Red -ForegroundColor Black "Len order ? [$($orderedLen[0]),$($orderedLen[1]),$($orderedLen[2])]"
		$myOrder=Read-Host
		if( $myOrder -eq '' ){
			$myOrder = @($orderedLen[0],$orderedLen[1],$orderedLen[2]);
		}else{
			$myOrder = $myOrder.split(',');
		}
		foreach( $threshold in @(200,210,220,230,240,250) ){
			$myOrder | foreach {
				$topLen = $_;
				Write-Host -BackgroundColor Blue -ForegroundColor Black "Brute force password length $topLen with threshold=$threshold"
				$mask = '';
				for( $i=0; $i -lt $topLen; ++$i ){
					$mask += '?a';
				}
				Write-Host -BackgroundColor Blue -ForegroundColor Black "Mask: $mask"
				& .\hashcat64.exe --force -m $HashMode -a3 --workload-profile=4 $HashFile $mask --markov-hcstat ./hashcat.hcstat --markov-threshold $threshold
			}
		}
}

if( $(my-Read-Host -msg "Run custom dico ? [n/Y]" -default 'y') -eq "y" ){
	Write-Host -BackgroundColor Yellow -ForegroundColor Black "********** CUSTOM DICO **********"
		hashcat -dico DICO\myPassList.dico
		hashcat -dico DICO\myPassList.dico -rules rules\best64.rule
		hashcat -dico DICO\myPassList.dico -rules rules\rockyou-30000.rule
		hashcat -dico DICO\myPassList.dico -rules rules\allrules
}

if( $(my-Read-Host -msg "Run old dico ? [n/Y]" -default 'y') -eq "y" ){
	Write-Host -BackgroundColor Yellow -ForegroundColor Black "********** OLD DICO **********"
		ls .\DICO\*\*.dico | foreach {
			$dico = $_.FullName
			if( $(my-Read-Host -msg "Use dico $dico ? [n/Y]" -default 'y') -eq "y" ){
				Write-Host -BackgroundColor Yellow -ForegroundColor Black "********** Using dico $dico **********"
				hashcat -dico $dico
				hashcat -dico $dico -rules rules\best64.rule
				if( (Get-Item $dico).length -lt 1GB ){
					hashcat -dico $dico -rules rules\rockyou-30000.rule
					hashcat -dico $dico -rules rules\allrules
				}
			}
			if( $(my-Read-Host -msg "Run Password loop reuse ? [n/Y]" -default 'y') -eq "y" ){
				Write-Host -BackgroundColor Yellow -ForegroundColor Black "********** Password Loop reuse **********"
					Make-MarkovDict
					do{
						$begin=Count-Password-Found
						hashcat -dico DICO\markov.dico -rules rules\best64.rule
						hashcat -dico DICO\markov.dico -rules rules\rockyou-30000.rule
						hashcat -dico DICO\markov.dico -rules rules\allrules
						Make-MarkovDict
						$end=Count-Password-Found
					}while($begin -ne $end);
			}
		}
}

if( $(my-Read-Host -msg "Brute force password with month base ? [n/Y]" -default 'y') -eq "y" ){
	Write-Host -BackgroundColor Yellow -ForegroundColor Black "********** MONTH BRUTE FORCE **********"
	$TextInfo = (Get-Culture).TextInfo
	cat DICO\0_Lang_\month.dico | foreach {
		$month = $_.Trim("`r`n`t ").ToLower();
		& .\hashcat64.exe --force -m $HashMode $HashFile -a 3 "${month}?a" -w 4
		& .\hashcat64.exe --force -m $HashMode $HashFile -a 3 "${month}?a?a" -w 4
		& .\hashcat64.exe --force -m $HashMode $HashFile -a 3 "${month}?a?a?a" -w 4
		& .\hashcat64.exe --force -m $HashMode $HashFile -a 3 "${month}?a?a?a?a" -w 4
		& .\hashcat64.exe --force -m $HashMode $HashFile -a 3 "${month}?a?a?a?a?a" -w 4
		& .\hashcat64.exe --force -m $HashMode $HashFile -a 3 "${month}?d?d?d?d?a?a" -w 4
		& .\hashcat64.exe --force -m $HashMode $HashFile -a 3 "?d?d${month}?d?d?d?d" -w 4
		& .\hashcat64.exe --force -m $HashMode $HashFile -a 3 "?d?d${month}?d?d?d?d?a" -w 4
		& .\hashcat64.exe --force -m $HashMode $HashFile -a 3 "?d?d${month}?d?d?d?d?a?a" -w 4
		& .\hashcat64.exe --force -m $HashMode $HashFile -a 3 "?a?a${month}?a?a?a" -w 4
		$month = $TextInfo.ToTitleCase($month);
		& .\hashcat64.exe --force -m $HashMode $HashFile -a 3 "${month}?a" -w 4
		& .\hashcat64.exe --force -m $HashMode $HashFile -a 3 "${month}?a?a" -w 4
		& .\hashcat64.exe --force -m $HashMode $HashFile -a 3 "${month}?a?a?a" -w 4
		& .\hashcat64.exe --force -m $HashMode $HashFile -a 3 "${month}?a?a?a?a" -w 4
		& .\hashcat64.exe --force -m $HashMode $HashFile -a 3 "${month}?a?a?a?a?a" -w 4
		& .\hashcat64.exe --force -m $HashMode $HashFile -a 3 "${month}?d?d?d?d?a?a" -w 4
		& .\hashcat64.exe --force -m $HashMode $HashFile -a 3 "?d?d${month}?d?d?d?d" -w 4
		& .\hashcat64.exe --force -m $HashMode $HashFile -a 3 "?d?d${month}?d?d?d?d?a" -w 4
		& .\hashcat64.exe --force -m $HashMode $HashFile -a 3 "?d?d${month}?d?d?d?d?a?a" -w 4
		& .\hashcat64.exe --force -m $HashMode $HashFile -a 3 "?a?a${month}?a?a?a" -w 4
	}
}


if( $(my-Read-Host -msg "Run pure brute force ? [n/Y]" -default 'y') -eq "y" ){
	Write-Host -BackgroundColor Yellow -ForegroundColor Black "********** BRUTE FORCE **********"
		Make-MarkovDict
		cat DICO\markov.dico | .\hashcat-utils-1.8\bin\hcstatgen.exe ./hashcat.hcstat
		& .\hashcat64.exe --force -m $HashMode -a3 --workload-profile=4 $HashFile --markov-hcstat ./hashcat.hcstat ?a?a?a
		& .\hashcat64.exe --force -m $HashMode -a3 --workload-profile=4 $HashFile --markov-hcstat ./hashcat.hcstat ?a?a?a?a
		& .\hashcat64.exe --force -m $HashMode -a3 --workload-profile=4 $HashFile --markov-hcstat ./hashcat.hcstat ?a?a?a?a?a
		& .\hashcat64.exe --force -m $HashMode -a3 --workload-profile=4 $HashFile --markov-hcstat ./hashcat.hcstat ?a?a?a?a?a?a
		#& .\hashcat64.exe --force -m %HashMode% -a3 --workload-profile=4 $HashFile ?a?a?a?a?a?a?a
		#& .\hashcat64.exe --force -m %HashMode% -a3 --workload-profile=4 $HashFile ?a?a?a?a?a?a?a?a
}
pause
exit
