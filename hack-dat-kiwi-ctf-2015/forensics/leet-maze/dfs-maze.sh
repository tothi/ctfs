#!/bin/bash
#
# Depth-First Search on Leetmaze DNS TXT records
#

NS="4ed667.hack.dat.kiwi"
S="track.dat.kiwi"

# decode some LEET strings
declare -A dict
dict=(['U||$@C]{']="unsack")
dict+=(['5[-]E1!|34C|<']="shellback")
dict+=(["BA!L'/W/-C"]="ballywack")
dict+=(['GO![}E//B4CK']="goldenback")
dict+=(['RE|3/-CK']="reback")
dict+=(['C04L5@C|<']="coalsack")
dict+=(['G|2IP5/-C]{']="gripsack")
dict+=(['.\\055'"'"'/84C|<']="mossyback")
dict+=([']-[^+|24C']="hatrack")  # missing 'k'
dict+=(['[/}|-|^CK']="hack")  # missing 'k'

declare -A explored

function dfs() {
    local v="$1"
    local t=""
    local label=""
    explored["$v"]=true

    local L0=$(dig @"${NS}" "${v}" TXT)
    local L1=$(echo "${L0}" | grep "\.dat\.kiwi\.\s*38400\s*IN\s*TXT" | \
		      cut -d\" -f2 | sed -e 's/ /_/g' -e 's/\.$//')
    local L2=()
    for w in $L1 ; do
	L2+=("$w")
	t="${dict[${w%.dat.kiwi}]}"
	[ "${t}" != "" ] && L2+=("${t}.dat.kiwi")
    done
    for w in "${L2[@]}" ; do
	echo "\"${v%.dat.kiwi}\" -> \"${w%.dat.kiwi}\";"
	[ ${explored["$w"]+isset} ] || dfs "$w"
    done
}


echo "digraph leetmaze {" > leetmaze.gv
echo "overlap = false;" >> leetmaze.gv
dfs "$S" | tr '_' ' ' | tee -a leetmaze.gv
echo "}" >> leetmaze.gv

cat leetmaze.gv | dot -Tpng -oleetmaze.png

exit 0
