#!/bin/bash
# pownMyHash - A simple script that automates password cracking with hashcat
#
# Filename: pownMyHash.sh
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

# Folder where hashcat is
export HC=/opt/hashcat-5.1.0/
# Folder where dico are
export DICO_PATH=/opt/dico/
# List of rules. Expected folder: $HC/rules/
export RULES='best64.rule d3ad0ne.rule rockyou-30000.rule OneRuleToRuleThemAll.rule hob064.rule d3adhob0.rule'


# ONLY IF YOU USE CYGWIN - Folder where hashcat is
export HC_CYGWIN=./
# ONLY IF YOU USE CYGWIN - Folder where dico are
export DICO_PATH_CYGWIN=./dico/





####################################################################################################

export HCB=$HC/hashcat64.bin
export HASH_TYPE=$1
export HASHES=`realpath $2 2>/dev/null`
export SCRIPT_PATH=`realpath -s $0`
export SCRIPT_PATH=`dirname $SCRIPT_PATH`
export FINDINGS=$SCRIPT_PATH/.pownMyHash.dico
export TRAINING_NTLM=$SCRIPT_PATH/.training_ntlm.txt
export SESSION_NAME=`echo $HASHES | sed -e 's#[\\/]#_#g'`

####################################################################################################
# FUNCTIONS
####################################################################################################

####################################################################################################
# Print a title in stdout
# @param[in] $1		{string} The title to print
# @param[in,opt] $2	{bool} Ask to the user. (default:true)
# @return {none}
function title
{
	echo -e "\n\033[33m*******************************************************************************\n* ${1^^}\n*******************************************************************************\033[0m"
	if [ "$2" = "" ]; then
		echo "[?] Press any key to bypass this test (autostart in 4sec)"
		read -t 4 -n 1 query >/dev/null
		if [ "${query}" = "" ]; then
			echo '[*] Running the job'
			return 0 # Do the job
		else
			echo '[*] Bypass'
			return 1 # Bypass
		fi
	fi
}


####################################################################################################
# Merge password from the potfile and from {$FINDINGS}
# @param[in] $1 {bool} Force the extraction of the potfile even if {potfile} is older than the dico
# @return {none}
# @note Change {found2dict_a} and {found2dict_b} with the number of password after (found2dict_a) and before (found2dict_b).
export found2dict_a=0
export found2dict_b=0
function found2dict
{
	export _force=$1
	if [ "$_force" = "" ] && [ "$FINDINGS" -nt "$HC/hashcat.potfile" ]; then
		echo '[*] No new password in potfile'
		export found2dict_a=-1
		export found2dict_b=-1
		return 0
	fi
	
	touch $FINDINGS
	
	export T1=`mktemp`
	echo "[*] Extracting password from potfile"
	cat $HC/hashcat.potfile | sort -u | rev | cut -d ':' -f 1 | rev > $T1
	echo '[*] CONVERTING $HEX'
	cat $T1 | grep -F '$HEX' | sed -e 's/\$HEX\[//g' | sed -e 's/\]//g' | xargs -I TTT bash -c 'echo TTT | xxd -r -p; echo -n -e "\n"' | iconv -f cp1252 -t utf8 > $T1.2
	echo '[*] MERGING all password found into dico'
	cp -f $FINDINGS $FINDINGS.`date '+%s'`
	export found2dict_b=`cat $FINDINGS | wc -l`
	echo "[*] BEFORE: $found2dict_b"
	cat $T1 $T1.2 $FINDINGS* | grep -vF '$HEX' | dos2unix | sort -u > $T1.3
	mv -f $T1.3 $FINDINGS
	export found2dict_a=`cat $FINDINGS | wc -l`
	echo "[*] AFTER: $found2dict_a"
	rm $T1 $T1.2
	chmod ugo=rw -- "$FINDINGS"
}


####################################################################################################
# Hashcat loop on potfile {$FINDINGS} only with dico
# @param[in] $1 {bool} Force the loop even if {found2dict} doesn't find new password in potfile
# @return {none}
function loopOnPotfile
{
	export _force=$1
	if [ "$_force" = "" ]; then
		found2dict
	else
		export found2dict_a=1
		export found2dict_b=2
	fi
	while [ $found2dict_a -ne $found2dict_b ]; do
		if title "Using potfile as dico"; then
			hashcat 0 `absPath $FINDINGS`
			for rule in $RULES; do
				title "Using potfile as dico with rule $rule" 0
				hashcat 0 `absPath $FINDINGS` -r `absPath $HC/rules/$rule`
			done
		fi
		found2dict
	done
}


####################################################################################################
# Check if hashcat is running
# @return {bool} 0 if hashcat is running. 1 if hashcat is not runnning
function isProcessHashCat
{
	if [ "`which cygpath`" = "" ] ; then
		[ `ps aux | grep -Fi hashcat | grep -vF grep | wc -l` -eq 0 ] && return 1 || return 0;
	else
		[ `tasklist | grep -Fi hashcat | grep -vF grep | wc -l` -eq 0 ] && return 1 || return 0;
	fi
}


####################################################################################################
# Run hashcat with default arguement for NIX and Windows/Cygwin
# @param[in] *	All arguments are passed to hashcat 
# @return {none}
function hashcat
{
	if [ "`which cygpath`" = "" ] ; then
		$HCB --force -w 4 --session=$SESSION_NAME -m $HASH_TYPE $HASHES -a $*
	else
		export _lastline="`tail -n1 $HC/hashcat.potfile`"
		cmd /c "start ""$HCB"" --force -w 4 --session=$SESSION_NAME -m $HASH_TYPE $HASHES -a $*"
		while isProcessHashCat; do
			sleep 1
			grep -A1000 -F "$_lastline" "$HC/hashcat.potfile" | grep -vF "$_lastline"
			export _lastline="`tail -n1 $HC/hashcat.potfile`"
		done
	fi
}


####################################################################################################
# Allows to obtain a path validated according to the OS
# @param[in] $1 {string} A path to convert
# @return {string}
function absPath
{
	if [ "`which cygpath`" = "" ] ; then
		realpath $1
	else
		cygpath -w $1
	fi
}



####################################################################################################
# PREREQUISITES
####################################################################################################
# For Cygwin
if [ "`which cygpath`" != "" ] ; then
	export HC=`realpath $HC_CYGWIN 2>/dev/null`
	export HCB=$HC/hashcat64.exe
	export DICO_PATH=`realpath $DICO_PATH_CYGWIN 2>/dev/null`
fi

if [ "`which dos2unix`" == "" ] ; then
	echo '[!] "dos2unix" is needed !'
	apt-get install dos2unix
fi

if [ ! -f "$HCB" ]; then
	export HCB=`find . -maxdepth 3 -name 'hashcat64.*' -type f 2>/dev/null | head -n1`
	if [ ! -f "$HCB" ]; then
		echo "[!] Hashcat64 not found !"
		echo "[!] Please put this script either in the same folder as hashcat or a parent folder to hashcat."
		exit 1
	fi
	export HC=`realpath $HCB`
	export HC=`dirname $HC`
	echo "[*] Hashcat64 found at \"$HC\""
	if [ "`which cygpath`" != "" ] ; then
		export HCB=$HC/hashcat64.exe
	else
		export HCB=$HC/hashcat64.bin
	fi
fi

for rule in $RULES; do
	if [ ! -f "$HC/rules/$rule" ]; then
		echo "[!] Rule >$rule< not found in \"$HC/rules/\""
		exit 1
	fi
done

if [ "$1" = "--rebuild" ]; then
	found2dict 1
	exit 0
fi

if [ "$1" = "" ] || [ "$HASHES" = "" ]; then
	echo 'Usage:'
	echo "  $0 <hash-type> <hash-file>"
	echo ''
	echo 'With:'
	echo '  <hash-type>: The type of the hash (ex:1000 for NTLM, 5500 for NetNTLMv1, 5600 for NetNTLMv2). See hashcat --help'
	echo '  <hash-file>: The file that contains the hashed passwords'
	#$HCB --force --example-hashes
	exit
fi

if [ "$DICO_PATH" = "" ] || [ ! -f "`find $DICO_PATH -maxdepth 1 -type f -name '*.dico' 2>/dev/null | head -n1`" ]; then
	export _findme=`find . -maxdepth 3 -name '*.dico' -type f | grep -vF '/.' 2>/dev/null | head -n1`
	if [ ! -f "$_findme" ]; then
		echo "[!] No dico in \"$DICO_PATH\""
		echo "[!] Please put all your dictionaries in \"$DICO_PATH\" and add .dico extension to them"
		exit 1
	fi
	export DICO_PATH=`realpath $_findme`
	export DICO_PATH=`dirname $DICO_PATH`
	echo "[*] Dico found at \"$DICO_PATH\""
fi

if [ ! -f "$HASHES" ]; then
	echo "[!] File for hashes \"$HASHES\" not found"
	exit 1
fi

# Fix all path to be valid in Windows if needed
if [ "`which cygpath`" != "" ] ; then
	#export HC=`cygpath -w $HC 2>/dev/null`
	export HCB=`cygpath -w $HCB 2>/dev/null`
	export DICO_PATH=`cygpath -w $DICO_PATH 2>/dev/null`
	export SCRIPT_PATH=`cygpath -m $SCRIPT_PATH 2>/dev/null`
	export HASHES=`cygpath -w $HASHES 2>/dev/null`
	# In windows hashcat require to be run from his own directory
	cd "$HC"
fi

if isProcessHashCat; then
	echo '[!] Hashcat is already running'
	[ "`ps a | grep -E '[p]ownMyHash' | wc -l`" = "0" ] && exit
	export query='?'
	while [ "$query" != "" ] && [ "$query" != "y" ] && [ "$query" != "n" ]; do
		echo "[?] Split the workspace with \"`ps a | grep -E '[p]ownMyHash' | awk -F '/bin/bash ' '{print $2}'`\" ? [Y/n]"
		read -n 1 query >/dev/null
		export query
	done
	[ "${query^}" = "N" ] && exit;
fi


####################################################################################################
# MAIN
####################################################################################################
[ "${HASH_TYPE^^}" = "NTLM" ] && export HASH_TYPE=1000
([ "${HASH_TYPE^^}" = "NETNTLMV1" ] || [ "${HASH_TYPE^^}" = "NTLMV1" ]) && export HASH_TYPE=5500
([ "${HASH_TYPE^^}" = "NETNTLMV2" ] || [ "${HASH_TYPE^^}" = "NTLMV2" ]) && export HASH_TYPE=5600
[ "${HASH_TYPE^^}" = "PMKID" ] && export HASH_TYPE=16800

if [ "$HASH_TYPE" -lt 0 ] || !([ -n "$HASH_TYPE" ] && [ "$HASH_TYPE" -eq "$HASH_TYPE" ]) || [ ! -f "$HASHES" ]; then
	echo -e '\033[31m*******************************************************************************'
	echo -e 'Invalid Argument !\033[0m'
	echo "Invalid hash type >$HASH_TYPE<"
	echo 'Usage:'
	echo "  $0 <hash-type> <hash-file>"
	echo ''
	echo 'With:'
	echo '  <hash-type>: The type of the hash (ex:1000 for NTLM, 5500 for NetNTLMv1, 5600 for NetNTLMv2). See hashcat --help'
	echo '  <hash-file>: The file that contains the hashed passwords'
	#$HCB --force --example-hashes
	exit
fi


if [ "$HASH_TYPE" = "1000" ]; then
	if title 'Contribute to the local training database'; then
		export mytmp=`mktemp`
		cat $TRAINING_NTLM $HASHES | dos2unix | tr '[:upper:]' '[:lower:]' | sed -E 's/^[^\r\n:]+:[0-9]+:/x:42:/g' | sed -E 's/Disabled=[^\r\n:]+//g' | grep -E 'x:42:[a-f0-9]{32}:[a-f0-9]{32}:::' | sort -u > $mytmp
		mv $mytmp $TRAINING_NTLM
		grep -E '^[a-fA-F0-9]{32}:' $HC/hashcat.potfile | cut -d : -f 1 > $mytmp
		export mytmp2=`mktemp`
		(grep -vf $mytmp $TRAINING_NTLM > $mytmp2 && mv $mytmp2 $TRAINING_NTLM && rm $mytmp) &
	fi

	if title 'LM attack'; then
		export HASH_TYPE=3000 # mode LM
		loopOnPotfile 1
		hashcat 3 -i '?a?a?a?a?a?a'
		hashcat 3 '?a?a?a?a?a?a?a'
		
		export T1="`mktemp`"
		grep -E '^[A-Fa-f0-9]{16}:[^:\r\n]+$' $HC/hashcat.potfile | grep -vE '^$' > $T1
		echo '[*] Merging LM password'
		cat <<'EOD' | python
import os,sys,re;
potfile=open(os.environ['T1'],'r').read().strip('\r\n\t ').replace('\r','').split('\n');
h=open(os.environ['HASHES'],'r').read().strip('\r\n\t ').split('\n');
out=open(os.environ['T1'],'w');
for i in range(0,len(potfile)):
	potfile[i] = potfile[i].split(':',1);
	potfile[i][0] = potfile[i][0].lower();
for i in range(0,len(h)):
	tmp = h[i].split(':')[2].lower();
	c = 0;
	for j in range(0,len(potfile)):
		if tmp != tmp.replace(potfile[j][0], potfile[j][1]):
			tmp = tmp.replace(potfile[j][0], potfile[j][1]);
			c = c+1;
			if c >= 2:
				out.write(tmp+'\n');
				break;
EOD
		cat $T1 >> $FINDINGS
		rm -- $T1
		export HASH_TYPE=1000 # mode NTLM
	fi
fi

found2dict
loopOnPotfile 1
if title "Using dico"; then
	for dico in `echo $DICO_PATH/*.dico`; do
		if title "Using dico $dico"; then
			hashcat 0 `absPath $dico`
			loopOnPotfile
			for rule in $RULES; do
				if title "Using dico $dico with rule $rule"; then
					hashcat 0 `absPath $dico` `absPath $HC/rules/$rule`
					loopOnPotfile
				fi
			done
		fi
	done
fi


for dico in `echo $FINDINGS; find $DICO_PATH/ -size -15M -type f`; do
	if title "Brute force password with $dico base"; then	
		hashcat 6 `absPath $dico` '?a?a?a?a?a'
		hashcat 6 `absPath $dico` '?d?d?d?d?a?a'
		
		for month in `cat $dico`; do
			hashcat 3 "?d?d${month}?d?d?d?d"
			hashcat 3 "?d?d${month}?d?d?d?d?a"
			hashcat 3 "?d?d${month}?d?d?d?d?a?a"
			hashcat 3 "?a?a${month}?a?a?a"

			hashcat 3 -i "${month^^}?a?a?a?a?a"
			hashcat 3 "${month^^}?d?d?d?d?a?a"
			hashcat 3 "?d?d${month^^}?d?d?d?d"
			hashcat 3 "?d?d${month^^}?d?d?d?d?a"
			hashcat 3 "?d?d${month^^}?d?d?d?d?a?a"
			hashcat 3 "?a?a${month^^}?a?a?a"
		done
	fi
done


if title "Working on the NTLM training"; then
	export HASHES="$FINDINGS"
	export HASH_TYPE=3000 # mode LM
	hashcat 3 -i '?a?a?a?a?a?a?a?a'
	export HASH_TYPE=1000 # mode NT
	hashcat 3 -i '?a?a?a?a?a?a?a?a'
fi