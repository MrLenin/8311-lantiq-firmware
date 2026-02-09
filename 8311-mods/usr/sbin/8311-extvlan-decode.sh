#!/bin/sh
# 8311-extvlan-decode.sh - Extended VLAN Tagging Operation Table Decoder
#
# Decodes ME 171 (Extended VLAN Tagging Operation Configuration Data)
# VLAN tagging rules into human-readable format. Each rule is stored as
# four 32-bit words (16 bytes total) packed into bit fields defined by
# ITU-T G.988 Table 9.3.13-1.
#
# Two output modes:
#   - Human-readable (default): labeled fields with descriptive annotations
#   - Table mode (-t):          tab-separated columns for scripted parsing
#
# Dependencies:
#   /lib/8311-omci-lib.sh   - provides mibs() and mibattrdata() for OMCI MIB access
#
# Usage: 8311-extvlan-decode.sh [-t|--table] [-n|--no-header] [-h|--help]
#
# This is a diagnostic tool intended to be run from the command line
# or called by other scripts that need to inspect active VLAN rules.

_lib_8311_omci &>/dev/null || . /lib/8311-omci-lib.sh

# ── Named constants for special field values (ITU-T G.988 Table 9.3.13-1) ──

# Filter priority special values (4-bit field, 0-7 = literal priority)
FILTER_PRIO_NO_FILTER=8       # Do not filter on this tag's priority
FILTER_PRIO_DEFAULT_RULE=14   # Default rule (fallback when no other rule matches)
FILTER_PRIO_NO_TAG=15         # Inner: no-tag rule; Outer: not a double-tag rule

# Filter VID special value (13-bit field, 0-4094 = literal VID)
FILTER_VID_NO_FILTER=4096     # Do not filter on this tag's VID

# Filter TPID/DEI combined field (3-bit field)
FILTER_TPID_DEI_NO_FILTER=0   # Do not filter on TPID or DEI
FILTER_TPID_DEI_8100=4        # TPID = 0x8100, ignore DEI
FILTER_TPID_DEI_INPUT=5       # TPID = input TPID, ignore DEI
FILTER_TPID_DEI_INPUT_DEI0=6  # TPID = input TPID, DEI = 0
FILTER_TPID_DEI_INPUT_DEI1=7  # TPID = input TPID, DEI = 1

# Treatment priority special values (4-bit field, 0-7 = literal priority)
TREAT_PRIO_COPY_INNER=8       # Copy from inner priority of received frame
TREAT_PRIO_COPY_OUTER=9       # Copy from outer priority of received frame
TREAT_PRIO_DSCP_MAP=10        # Derive from DSCP-to-P-bit mapping
TREAT_PRIO_NO_TAG=15          # Do not add a tag

# Treatment VID special values (13-bit field, 0-4094 = literal VID)
TREAT_VID_COPY_INNER=4096     # Copy from inner VID of received frame
TREAT_VID_COPY_OUTER=4097     # Copy from outer VID of received frame

# Treatment remove tags: value 3 = discard the frame entirely
TREAT_TAGS_DISCARD=3

HEADER=true
TABLE=false

# Print usage information and exit.
# $1: exit code (0 = normal help, 1 = usage error)
_help() {
	printf -- 'Tool for decoding the extended VLAN tables\n\n'

	printf -- 'Usage %s [options]\n\n' "$0"
	printf -- 'Options:\n'
	printf -- '-t --table\tOutput table version instead of user-friendly version\n'
	printf -- '-n --no-header\tDo not output informational headers\n'

	printf -- '-h --help\tThis help text\n'

	exit $1
}

while [ $# -gt 0 ]; do
	case "$1" in
		-t|--table)
			TABLE=true
		;;
		-n|--no-header)
			HEADER=false
		;;
		-h|--help)
			_help 0
		;;

		*)
			_help 1
		;;
	esac
	shift
done

# Expand a single-character tag direction to its full name.
# $1: "i" for inner tag, anything else for outer tag
dir() {
	[ "$1" = "i" ] && echo "inner" || echo "outer"
}

# Decode and display a filter priority field value.
# Values 0-7 are literal 802.1p priorities; higher values are special.
# $1: direction ("i" = inner, "o" = outer)
# $2: priority value (0-15)
filter_priority() {
	local dir=$(dir "$1")

	if [ "$2" -le  7 ]; then
		echo "$2"
	elif [ "$2" -eq 8 ]; then
		echo -e "8\t(Do not filter on the $dir priority)"
	elif [ "$2" -eq 14 ]; then
		if [ "$dir" = "inner" ]; then
			echo -e "14\t(Default filter when no other one-tag rule applies)"
		else
			echo -e "14\t(Default filter when no other two-tag rule applies)"
		fi
	elif [ "$2" -eq 15 ]; then
		if [ "$dir" = "inner" ]; then
			echo -e "15\t(No-tag rule; ignore all other VLAN tag filter fields)"
		else
			echo -e "15\t(Not a double-tag rule; ignore all other outer tag filter fields)"
		fi
	else
		echo -e "$2\t(Reserved)"
	fi
}

# Decode and display a filter VID field value.
# Values 0-4094 are literal VLAN IDs; 4096 means "do not filter."
# $1: direction ("i" = inner, "o" = outer)
# $2: VID value (0-4096)
filter_vid() {
	local dir=$(dir "$1")

	if [ "$2" -lt 4095 ]; then
		echo "$2"
	elif [ "$2" -eq 4096 ]; then
		echo -e "4096\t(Do not filter on the $dir VID)";
	else
		echo -e "$2\t(Reserved)";
	fi
}

# Decode and display a filter TPID/DEI combined field value.
# This 3-bit field encodes both TPID matching and DEI filtering.
# $1: direction ("i" = inner, "o" = outer)
# $2: TPID/DEI value (0-7)
filter_tpid_dei() {
	local dir=$(dir "$1")

	if [ "$2" -eq 0 ]; then
		echo -e "0\t(Do not filter on $dir TPID or DEI)"
	elif [ "$2" -eq 4 ]; then
		echo -e "4\t(TPID = 0x8100, ignore DEI)"
	elif [ "$2" -eq 5 ]; then
		echo -e "5\t(TPID = Input TPID, ignore DEI)"
	elif [ "$2" -eq 6 ]; then
		echo -e "6\t(TPID = Input TPID, DEI = 0)"
	elif [ "$2" -eq 7 ]; then
		echo -e "7\t(TPID = Input TPID, DEI = 1)"
	else
		echo -e "$2\t(Reserved)"
	fi
}

# Decode and display a filter EtherType field value.
# Maps numeric codes to well-known EtherType protocols.
# $1: EtherType code (0-5, higher values reserved)
filter_ethertype() {
	if [ "$1" -eq 0 ]; then
		echo -e "0\t(Do not filter on EtherType)"
	elif [ "$1" -eq 1 ]; then
		echo -e "1\t(0x0800 - IPv4 IPoE)"
	elif [ "$1" -eq 2 ]; then
		echo -e "2\t(0x8863 / 0x8864 - PPPoE)"
	elif [ "$1" -eq 3 ]; then
		echo -e "3\t(0x0806 - ARP)"
	elif [ "$1" -eq 4 ]; then
		echo -e "4\t(0x86DD - IPv6 IPoE)"
	elif [ "$1" -eq 5 ]; then
		echo -e "5\t(0x888E - EAPOL)"
	else
		echo -e "$1\t(Reserved)"
	fi
}

# Decode and display a filter extended-criteria field value.
# Matches higher-layer protocols beyond simple EtherType filtering.
# $1: extended criteria code (0 = none, 1 = DHCPv4, 2 = DHCPv6)
filter_extended_criteria() {
	if [ "$1" -eq 0 ]; then
		echo -e "0\t(Do not filter on extended criteria)"
	elif [ "$1" -eq 1 ]; then
		echo -e "1\t(DHCPv4)"
	elif [ "$1" -eq 2 ]; then
		echo -e "2\t(DHCPv6)"
	else
		echo -e "$1\t(Reserved)"
	fi
}

# Decode and display the treatment "tags to remove" field.
# Values 0-2 indicate how many tags to strip; 3 means discard the frame.
# $1: remove-tags value (0-3)
treatment_remove_tags() {
	if [ "$1" -eq 3 ]; then
		echo -e "3\t(Discard the frame)"
	else
		echo "$1"
	fi
}

# Decode and display a treatment priority field value.
# Values 0-7 set a literal priority; higher values copy or derive.
# $1: direction ("i" = inner, "o" = outer)
# $2: priority value (0-15)
treatment_priority() {
	local dir=$(dir "$1")

	if [ "$2" -le  7 ]; then
		echo "$2"
	elif [ "$2" -eq 8 ]; then
		echo -e "8\t(Copy from the inner priority of received frame)"
	elif [ "$2" -eq 9 ]; then
		echo -e "9\t(Copy from the outer priority of received frame)"
	elif [ "$2" -eq 10 ]; then
		echo -e "10\t(Derive priority based on DSCP to P-bit mapping)"
	elif [ "$2" -eq 15 ]; then
		echo -e "15\t(Do not add an $dir tag)"
	else
		echo -e "$2\t(Reserved)"
	fi
}

# Decode and display a treatment VID field value.
# Values 0-4094 set a literal VID; 4096/4097 copy from inner/outer.
# $1: direction ("i" = inner, "o" = outer) -- unused but kept for call consistency
# $2: VID value (0-4097)
treatment_vid() {
	if [ "$2" -lt 4095 ]; then
		echo "$2"
	elif [ "$2" -eq 4096 ]; then
		echo -e "4096\t(Copy from the inner VID of received frame)"
	elif [ "$2" -eq 4097 ]; then
		echo -e "4097\t(Copy from the outer VID of received frame)"
	else
		echo -e "$2\t(Reserved)"
	fi
}

# Decode and display a treatment TPID/DEI combined field value.
# Controls which TPID and DEI values are written into the outgoing tag.
# $1: direction ("i" = inner, "o" = outer) -- unused but kept for call consistency
# $2: TPID/DEI value (0-7)
treatment_tpid_dei() {
	if [ "$2" -eq 0 ]; then
		echo -e "0\t(TPID = Inner TPID, DEI = Inner DEI)"
	elif [ "$2" -eq 1 ]; then
		echo -e "1\t(TPID = Outer TPID, DEI = Outer DEI)"
	elif [ "$2" -eq 2 ]; then
		echo -e "2\t(TPID = Output TPID, DEI = Inner DEI)"
	elif [ "$2" -eq 3 ]; then
		echo -e "3\t(TPID = Output TPID, DEI = Outer DEI)"
	elif [ "$2" -eq 4 ]; then
		echo -e "4\t(TPID = 0x8100)"
	elif [ "$2" -eq 6 ]; then
		echo -e "6\t(TPID = Output TPID, DEI = 0)"
	elif [ "$2" -eq 7 ]; then
		echo -e "7\t(TPID = Output TPID, DEI = 1)"
	else
		echo -e "$2\t(Reserved)"
	fi
}

# Parse a single 16-byte (4-word) Extended VLAN tagging rule and display it.
#
# Each rule is packed into four 32-bit words per G.988 Table 9.3.13-1:
#   Word 1 ($1): outer-tag filter  (priority[31:28], VID[27:15], TPID/DEI[14:12], pad[11:0])
#   Word 2 ($2): inner-tag filter  (priority[31:28], VID[27:15], TPID/DEI[14:12],
#                                    ext-criteria[11:4], ethertype[3:0])
#   Word 3 ($3): outer-tag treatment (remove-tags[31:30], pad[29:20], priority[19:16],
#                                      VID[15:3], TPID/DEI[2:0])
#   Word 4 ($4): inner-tag treatment (pad[31:20], priority[19:16], VID[15:3], TPID/DEI[2:0])
#
# $1-$4: the four 32-bit hex words (prefixed with 0x) for this rule
vlan_parse() {
	# ── Word 1: Outer-tag filter fields ──
	filter_outer_priority=$((($1 & 0xf0000000) >> 28))   # bits [31:28] - 4-bit priority
	filter_outer_vid=$((($1 & 0x0fff8000) >> 15))         # bits [27:15] - 13-bit VID
	filter_outer_tpid_dei=$((($1 & 0x00007000) >> 12))    # bits [14:12] - 3-bit TPID/DEI

	# ── Word 2: Inner-tag filter fields + protocol filters ──
	filter_inner_priority=$((($2 & 0xf0000000) >> 28))    # bits [31:28] - 4-bit priority
	filter_inner_vid=$((($2 & 0x0fff8000) >> 15))         # bits [27:15] - 13-bit VID
	filter_inner_tpid_dei=$((($2 & 0x00007000) >> 12))    # bits [14:12] - 3-bit TPID/DEI
	filter_extended_criteria=$((($2 & 0x00000ff0) >> 4))  # bits [11:4]  - 8-bit extended criteria
	filter_ethertype=$(($2 & 0x0000000f))                  # bits [3:0]   - 4-bit EtherType code

	# ── Word 3: Outer-tag treatment fields ──
	treatment_remove_tags=$((($3 & 0xc0000000) >> 30))    # bits [31:30] - 2-bit tag removal
	treatment_outer_priority=$((($3 & 0x000f0000) >> 16)) # bits [19:16] - 4-bit priority
	treatment_outer_vid=$((($3 & 0x0000fff8) >> 3))       # bits [15:3]  - 13-bit VID
	treatment_outer_tpid_dei=$(($3 & 0x00000007))          # bits [2:0]   - 3-bit TPID/DEI

	# ── Word 4: Inner-tag treatment fields ──
	treatment_inner_priority=$((($4 & 0x000f0000) >> 16)) # bits [19:16] - 4-bit priority
	treatment_inner_vid=$((($4 & 0x0000fff8) >> 3))       # bits [15:3]  - 13-bit VID
	treatment_inner_tpid_dei=$(($4 & 0x00000007))          # bits [2:0]   - 3-bit TPID/DEI

	if $TABLE; then
		echo -ne "${filter_outer_priority}\t${filter_outer_vid}\t${filter_outer_tpid_dei}\t"
		echo -ne "${filter_inner_priority}\t${filter_inner_vid}\t${filter_inner_tpid_dei}\t${filter_ethertype}\t${filter_extended_criteria}\t"
		echo -ne "${treatment_remove_tags}\t${treatment_outer_priority}\t${treatment_outer_vid}\t${treatment_outer_tpid_dei}\t"
		echo -ne "${treatment_inner_priority}\t${treatment_inner_vid}\t${treatment_inner_tpid_dei}"
		echo
	else
		echo -ne "Filter Outer Priority:\t\t"
		filter_priority o $filter_outer_priority
		echo -ne "Filter Outer VID:\t\t"
		filter_vid o $filter_outer_vid
		echo -ne "Filter Outer TPID/DEI:\t\t"
		filter_tpid_dei o $filter_outer_tpid_dei

		echo -ne "Filter Inner Priority:\t\t"
		filter_priority i $filter_inner_priority
		echo -ne "Filter Inner VID:\t\t"
		filter_vid i $filter_inner_vid
		echo -ne "Filter Inner TPID/DEI:\t\t"
		filter_tpid_dei i $filter_inner_tpid_dei

		echo -ne "Filter EtherType:\t\t"
		filter_ethertype $filter_ethertype
		echo -ne "Filter Extended Criteria:\t"
		filter_extended_criteria $filter_extended_criteria

		echo -ne "Treatment tags to remove:\t"
		treatment_remove_tags $treatment_remove_tags
		echo -ne "Treatment outer priority:\t"
		treatment_priority o $treatment_outer_priority
		echo -ne "Treatment outer VID:\t\t"
		treatment_vid o $treatment_outer_vid
		echo -ne "Treatment outer TPID/DEI:\t"
		treatment_tpid_dei o $treatment_outer_tpid_dei

		echo -ne "Treatment inner priority:\t"
		treatment_priority i $treatment_inner_priority
		echo -ne "Treatment inner VID:\t\t"
		treatment_vid i $treatment_inner_vid
		echo -ne "Treatment inner TPID/DEI:\t"
		treatment_tpid_dei i $treatment_inner_tpid_dei
	fi
}


# ── Main: enumerate and decode all ME 171 Extended VLAN tables ──

# mibs 171 returns the list of ME 171 instance IDs present in the MIB
ext_vlan_tables=$(mibs 171)
if [ -z "$ext_vlan_tables" ]; then
	echo "No Extended VLAN Tables Detected" >&2
	exit 1
fi

i=0
for ext_vlan_table in $ext_vlan_tables; do
	if $HEADER; then
		echo "Extended VLAN table $ext_vlan_table"
		echo "------------------------"
		if $TABLE; then
			echo -e "Filter Outer\t\tFilter Inner\t\tFilter Other\tTreatment Outer\t\t\tTreatment Inner"
			echo -e "Prio\tVID\tTPIDDEI\tPrio\tVID\tTPIDDEI\tEthTyp\tExtCrit\tTagRem\tPrio\tVID\tTPIDDEI\tPrio\tVID\tTPIDDEI"
		fi
	fi
	[ "$i" -gt 0 ] && echo

	# Attribute 6 = "received frame VLAN tagging operation table" (the rule data)
	data=$(mibattrdata 171 $ext_vlan_table 6)
	for vlan_filter in $data; do
		# Each rule is a 32-hex-char string (16 bytes); split into four 0x-prefixed 32-bit words
		w=$(echo $vlan_filter | sed -r 's/(.{8})/0x\1 /g')
		vlan_parse $w
		$TABLE || echo
	done
	i=$((i + 1))
done
