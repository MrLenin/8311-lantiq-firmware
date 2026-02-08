#!/bin/sh
omci="/opt/lantiq/bin/omci_pipe.sh"

_lib_8311_omci() {
	return 0
}

_lib_int &>/dev/null || . /lib/functions/int.sh
_lib_hexbin &>/dev/null || . /lib/functions/hexbin.sh

mibs() {
	if [ -n "$1" ]; then
		local me=$(($1))
		$omci md | awk -F '|' -v me="$me" '{
			gsub(/[[:space:]]/, "", $2)
			gsub(/[[:space:]]/, "", $3)
		} $2 == me { print $3 }'
	else
		$omci md | awk -F '|' '{
			gsub(/[[:space:]]/, "", $2)
			gsub(/[[:space:]]/, "", $3)
		} $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ { print $2, $3 }'
	fi
}

mib() {
	[ -n "$2" ] || return 1
	$omci meg "$(($1))" "$(($2))"
}

mibattr() {
	[ -n "$3" ] || return 1
	local attr=$(($3)) || return 1
	local data=$(mib "$1" "$2") || return $?

	echo "$data" | awk -v attr="$attr" '
/^---/ && !/[^-]/ {
	if (found) { print buf; exit }
	dash = 1
	next
}
dash {
	dash = 0
	if ($1 + 0 == attr + 0) {
		found = 1
		buf = $0
		next
	}
}
found { buf = (buf == "" ? $0 : buf "\n" $0) }
'
}

mibattrdata() {
	local nl=true
	local hexstr=false
	local me=
	local id=
	local attr=

	while [ $# -gt 0 ]; do
		case "$1" in
			-n)
				nl=false;
			;;
			-x)
				hexstr=true
			;;
			*)
				if [ -z "$me" ]; then
					me="$1"
				elif [ -z "$id" ]; then
					id="$1"
				elif [ -z "$attr" ]; then
					attr="$1"
				else
					return 1
				fi
			;;
		esac
		shift
	done

	local mibattr=$(mibattr "$me" "$id" "$attr") || return $?
	local typesize=$(echo "$mibattr" | head -n1 | awk '{ sub(/b$/, "", $2); print $2, $3 }')
	local bytes=$(echo "$typesize" | cut -d' ' -f1)
	local type=$(echo "$typesize" | cut -d' ' -f2)

	local sint=false
	[ "$type" = "SINT" ] && sint=true
	if $sint || [ "$type" = "BF" ] || [ "$type" = "ENUM" ] || [ "$type" = "PTR" ] || [ "$type" = "UINT" ]; then
		local int="0x$(echo "$mibattr" | head -n2 | tail -n1 | grep -oE '0x[0-9a-f]+' | sed 's/0x//g' | tr -d '\n')"
		local inttype="uint"
		$sint && inttype="int"

		local size=$((bytes * 8))

		"$inttype$size" "$int"
	elif [ "$type" = "STR" ]; then
		printf $(echo "$mibattr" | tail -n1) | { $hexstr && str2hex || cat; }
		! $hexstr && $nl && echo
	elif [ "$type" = "TBL" ]; then
		printf $(echo "$mibattr" | tail -n1) | xxd -p -c "$bytes"
	else
		return 1
	fi
}
