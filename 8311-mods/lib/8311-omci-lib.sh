#!/bin/sh
# OMCI Managed Entity (ME) query library.
#
# Provides functions to enumerate, read, and parse OMCI MIB data from
# the ONU's MIB store via the Lantiq omci_pipe.sh utility. Used by
# monitoring and diagnostic scripts to extract typed attribute values
# (UINT, SINT, STR, TBL, etc.) from specific ME instances.
#
# Dependencies:
#   /opt/lantiq/bin/omci_pipe.sh  - low-level OMCI pipe interface
#   /lib/functions/int.sh         - signed/unsigned integer converters
#   /lib/functions/hexbin.sh      - hex/binary string converters

omci="/opt/lantiq/bin/omci_pipe.sh"

# Guard function: allows callers to test if this library is already loaded.
_lib_8311_omci() {
	return 0
}

# Conditionally source helper libraries (skip if already loaded).
_lib_int &>/dev/null || . /lib/functions/int.sh
_lib_hexbin &>/dev/null || . /lib/functions/hexbin.sh

# mibs [me_class]
# List OMCI Managed Entity instances from the MIB dump.
#   With $1: prints instance IDs for the given ME class number.
#   Without $1: prints all "class instance" pairs in the MIB.
# AWK strips whitespace around pipe-delimited fields ($2=class, $3=instance)
# and filters to numeric-only values to skip header/separator lines.
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

# mib <me_class> <instance_id>
# Retrieve the full attribute dump for a specific ME instance.
# Returns the raw multi-line output from "omci_pipe.sh meg".
mib() {
	[ -n "$2" ] || return 1
	$omci meg "$(($1))" "$(($2))"
}

# mibattr <me_class> <instance_id> <attr_index>
# Extract a single attribute block from an ME dump.
# The omci_pipe "meg" output separates attributes with "---" lines.
# AWK scans for the attribute whose first field matches $attr, then
# captures all lines until the next "---" separator (the next attribute).
mibattr() {
	[ -n "$3" ] || return 1
	local attr=$(($3)) || return 1
	local data=$(mib "$1" "$2") || return $?

	echo "$data" | awk -v attr="$attr" '
# A line of only dashes marks an attribute boundary.
/^---/ && !/[^-]/ {
	if (found) { print buf; exit }
	dash = 1
	next
}
# The line immediately after a dash separator is the attribute header;
# compare its numeric index ($1) to the target attribute.
dash {
	dash = 0
	if ($1 + 0 == attr + 0) {
		found = 1
		buf = $0
		next
	}
}
# Accumulate continuation lines for the matched attribute.
found { buf = (buf == "" ? $0 : buf "\n" $0) }
'
}

# mibattrdata [-n] [-x] <me_class> <instance_id> <attr_index>
# Parse and return the typed data value for a specific ME attribute.
#
# Flags:
#   -n  Suppress trailing newline (applies to STR output).
#   -x  Output STR values as hex instead of decoded text.
#
# Type handling:
#   UINT/SINT/BF/ENUM/PTR  Extracts hex bytes from the data line, joins
#                          them into a single hex integer, then calls the
#                          appropriate intN/uintN converter (e.g. uint16).
#   STR                    Prints the raw byte content (or hex with -x).
#   TBL                    Dumps raw bytes as a hex string, one row per
#                          table entry ($bytes columns via xxd).
mibattrdata() {
	local nl=true
	local hexstr=false
	local me=
	local id=
	local attr=

	# Parse flags and positional args (me, id, attr) in any order.
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
	# Header line format: "<index> <size>b <TYPE>"; strip the trailing "b"
	# from the size field to get the byte count and type name.
	local typesize=$(echo "$mibattr" | head -n1 | awk '{ sub(/b$/, "", $2); print $2, $3 }')
	local bytes=$(echo "$typesize" | cut -d' ' -f1)
	local type=$(echo "$typesize" | cut -d' ' -f2)

	local sint=false
	[ "$type" = "SINT" ] && sint=true
	if $sint || [ "$type" = "BF" ] || [ "$type" = "ENUM" ] || [ "$type" = "PTR" ] || [ "$type" = "UINT" ]; then
		# Concatenate all 0xNN hex tokens from the data line into one value,
		# stripping each "0x" prefix so they merge into a contiguous hex string.
		local int="0x$(echo "$mibattr" | head -n2 | tail -n1 | grep -oE '0x[0-9a-f]+' | sed 's/0x//g' | tr -d '\n')"
		local inttype="uint"
		$sint && inttype="int"

		local size=$((bytes * 8))

		# Dynamically call the converter, e.g. "uint16 0xABCD" or "int8 0xFF".
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
