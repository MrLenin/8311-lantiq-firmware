#!/bin/sh
# vlanexec.sh — VLAN service daemon for 8311 firmware mod
#
# Runs as a persistent background service (started by vlan-svc.sh init script
# via procd). Monitors ONU PLOAM state and, once O5 (associated) is reached:
#   1. Collects OLT type, bridge topology, and ME 171 (ExtVLAN) instance data
#   2. Configures bridge ports and creates ME 171 if missing
#   3. Applies user-configured VLAN translations and multicast settings
#   4. Detects and fixes dual-VLAN downstream conflicts (Bell Aliant/Canada)
#   5. Monitors for MIB data sync changes and re-applies as needed
#
# The main loop sleeps 5s during initial association, then 15s once stable.
# If association fails and reboot_on_association_fail is enabled, schedules
# progressive reboot attempts.
#
# Dependencies: omci_pipe.sh, onu CLI, gtop, optic, 8311-omci-lib.sh
# Key globals set during collect: olt_type, me171_instance_id, bridge_count,
#   spanning_tree_data, mapper_ports, mapper_ptrs

onu="/opt/lantiq/bin/onu"
uci="/sbin/uci"
omci="/opt/lantiq/bin/omci_pipe.sh"
gtop="/opt/lantiq/bin/gtop"
optic="/opt/lantiq/bin/optic"

_lib_8311_omci 2>/dev/null || . /lib/8311-omci-lib.sh

# Main loop state counters
init_check_count=0    # Number of initial configuration passes completed (max 5)
change_count=0        # Tracks MIB/FSM/config changes; triggers re-apply when >= 1
collect_check_count=0 # Number of collect() calls completed (runs twice for stability)
ploam_check_count=0   # O5 poll iterations; controls sleep_interval (5s < 20, else 15s)
log_check_count=0     # Limits repetitive log messages (reset on O5 entry)
reboot_delay_interval=0

# Transaction ID counter for ONU-initiated OMCI creates (0xFF01-0xFFFE range
# avoids collision with OLT-assigned TXN IDs which start from low values)
_txn_id=0xff01

_saved_mib_data_sync=""  # Saved before ONU-initiated OMCI ops, restored after
spanning_tree_data=""    # ME 45 attr 1 (spanning tree config), applied to bridge ports

# Dual-VLAN conflict fix state (populated by query_bridge_ports / detect_vid_conflict)
mapper_ports=""       # ME 47 bridge port instances with tp_type=03 (mapper)
mapper_ptrs=""        # ME 130 mapper instance IDs corresponding to mapper_ports
conflict_vids=""      # Space-separated "filter_vid:treatment_vid" conflict pairs
conflict_tvid=""      # The shared treatment VID causing the conflict
vid_conflict_fixed=0  # Gate flag: 1 = fix already applied this O5 session

reboots_count=$(cat /tmp/reboots_count 2>&-)

# UCI configuration — read once at startup
reboot_on_association_fail=$($uci -q get 8311.config.tryreboot)
max_reboot_delay_intervals=$($uci -q get 8311.config.max_reboot_delay_intervals)
max_reboots=$($uci -q get 8311.config.max_reboots)
persist_log_on_reboot=$($uci -q get 8311.config.persist_log_on_reboot)

us_vlan_id=$($uci -q get 8311.config.us_vlan_id)       # Upstream VLAN ID or "u" for untagged
n_to_1_vlan=$($uci -q get 8311.config.n_to_1_vlan)     # N:1 VLAN translation mode (GPE)
vlan_tag_ops=$($uci -q get 8311.config.vlan_tag_ops)    # Custom VLAN translations (vid:vid,...)
ds_mc_tci=$($uci -q get 8311.config.ds_mc_tci)         # Downstream multicast TCI (vid@pcp)
us_mc_vid=$($uci -q get 8311.config.us_mc_vid)         # Upstream multicast VID
igmp_version=$($uci -q get 8311.config.igmp_version)
force_me_create=$($uci -q get 8311.config.force_me_create)
force_me309_create=$($uci -q get 8311.config.force_me309_create)
force_us_vlan_id=$($uci -q get 8311.config.force_us_vlan_id)
vlan_svc_log=$($uci -q get 8311.config.vlan_svc_log)   # Enable verbose logging

# Regex matching valid VID values 0-4096
vid_pattern='4096|409[0-4]|(40[0-8]|[1-3][[:digit:]][[:digit:]]|[1-9][[:digit:]]|[1-9])[[:digit:]]|[0-9]'

# Return the current PLOAM state (single digit: 1-5, where 5 = O5 associated).
get_ploam_state() {
	$onu ploam_state_get |
		cut -b 24
}

# Perform a forced reboot, saving debug logs if configured.
do_reboot() {
	if [ "$reboots_count" -lt "$max_reboots" ]; then
		if [ "$persist_log_on_reboot" = "1" ]; then
			/opt/lantiq/bin/debug
			cp /tmp/log/one_click /root
		fi

		reboots_count=$((reboots_count + 1))

		fw_setenv reboot_attempt "$reboots_count"
		fw_setenv rebootcause 1

		reboot -f
		exit 0
	fi
}

reset_reboot_attempt() {
	fw_setenv reboot_attempt 0
}

# Wait one sleep interval and increment the delay counter toward max.
delay_reboot() {
	if [ "$reboot_delay_interval" -lt "$max_reboot_delay_intervals" ] &&
		[ "$reboots_count" -lt "$max_reboots" ]; then
		reboot_delay_interval=$((reboot_delay_interval + 1))
		sleep_interval
	fi
}

reset_reboot_delay() {
	reboot_delay_interval=0
}

reset_log_check_count() {
	log_check_count=0
}

# Detect new FSM O5 transitions in dmesg and trigger re-apply via change_count.
check_onu_fsm_o5() {
	local prev_status
	local curr_status

	if [ ! -f /tmp/oltstatus1 ]; then
		touch /tmp/oltstatus1
	fi

	prev_status=$(cat /tmp/oltstatus1)
	curr_status=$(dmesg | grep -c "FSM O5")

	if [ "$prev_status" != "$curr_status" ]; then
		logger -t "[vlanexec]" "FSM O5 detected..."
		change_count=$((change_count + 1))
	fi

	echo "$curr_status" >/tmp/oltstatus1
}

# Detect PLOAM message loss events in dmesg and trigger re-apply.
check_onu_rx_msg_lost() {
	local prev_status
	local curr_status

	if [ ! -f /tmp/oltstatus2 ]; then
		touch /tmp/oltstatus2
	fi

	prev_status=$(cat /tmp/oltstatus2)
	curr_status=$(dmesg | grep -c "PLOAM Rx - message lost")

	if [ "$prev_status" != "$curr_status" ]; then
		logger -t "[vlanexec]" "PLOAM Rx - message lost detected..."
		change_count=$((change_count + 1))
	fi

	echo "$curr_status" >/tmp/oltstatus2
}

# Sleep 5s during early association (first 20 polls), then 15s once stable.
sleep_interval() {
	local time

	if [ $ploam_check_count -lt 20 ]; then
		time=5
	else
		time=15
	fi
	sleep $time
}

# Reset all state when leaving O5 (PLOAM deassociation). Clears counters,
# dual-VLAN fix state, and cached VLAN translation temp files.
reset_tracked_parameters() {
	local vlans_seq
	local vlan_a_seq
	local vlan_b_seq
	local vlan_tagging_ops_num

	init_check_count=0
	change_count=0
	ploam_check_count=0
	_saved_mib_data_sync=""
	spanning_tree_data=""
	mapper_ports=""
	mapper_ptrs=""
	conflict_vids=""
	conflict_tvid=""
	vid_conflict_fixed=0
	rm -f /tmp/me47_bridge_ports

	[ -e /tmp/us_vlan_data ] && rm -f /tmp/us_vlan_data
	[ -e /tmp/ds_mc_tci_data ] && rm -f /tmp/ds_mc_tci_data
	[ -e /tmp/us_mc_vid_data ] && rm -f /tmp/us_mc_vid_data
	[ -e /tmp/mibcounter ] && rm -f /tmp/mibcounter

	vlans_seq=0
	vlan_tagging_ops_num=$(
		echo "$vlan_tag_ops" |
			grep -o ":" |
			grep -c ":"
	)

	for i in $(seq 1 "$vlan_tagging_ops_num"); do
		vlan_a_seq=$((i + vlans_seq))

		vlans_seq=$i

		vlan_b_seq=$((i + vlans_seq))

		if [ -e "/tmp/vlan$vlan_a_seq" ] || [ -e "/tmp/vlan$vlan_b_seq" ]; then
			rm -f "/tmp/vlan$vlan_a_seq"
			rm -f "/tmp/vlan$vlan_b_seq"
		fi
	done
}

# Query ME 131 (ONU data) attr 1 for OLT vendor type (4-byte ASCII) and ME 45
# (spanning tree) attr 1. Retries up to 30 times (60s) waiting for OLT data.
# Sets globals: olt_type (hex-encoded vendor, e.g. "414c434c" for ALCL/Nokia)
collect_olt_type() {
	local spanning_tree

	for i in $(seq 1 30); do
		olt_type=$(
			$omci managed_entity_attr_data_get 131 0 1 |
				sed -n 's/\(attr\_data\=\)/\1/p' |
				cut -f 3 -d '=' |
				sed s/[[:space:]]//g
		)

		spanning_tree=$(
			$omci managed_entity_attr_data_get 45 1 1 |
				sed -n 's/\(attr\_data\=\)/\1/p' |
				sed s/[[:space:]]//g
		)

		if [ "$olt_type" != "20202020" ] && [ -n "$spanning_tree" ]; then
			break
		else
			logger -t "[vlanexec]" "OLT type and spanning tree not detected, waiting..."
			sleep 2
		fi
	done

	echo "OLT type: $olt_type" >/tmp/collect
}

# Find the UNI-associated ME 171 instance (assoc_me_ptr = 0x0101 = PPTP UNI).
# When multiple ME 171 instances exist (common with dual-VLAN or multicast),
# iterates to find the one pointing at the UNI port.
# Sets global: me171_instance_id
find_me171_uni_instance() {
	local instances instance_count me_ptr

	instances=$(
		$omci mib_dump |
			grep "Extended VLAN conf data" |
			sed -n 's/\(0x\)/\1/p' |
			cut -f 3 -d '|' |
			cut -f 1 -d '(' |
			sed s/[[:space:]]//g
	)

	instance_count=$(
		$omci mib_dump |
			grep -c "Extended VLAN conf data"
	)

	if [ "$instance_count" -gt 1 ]; then
		for i in $instances; do
			me_ptr=$(
				$omci managed_entity_attr_data_get 171 "$i" 7 |
					sed -n 's/\(attr\_data\=\)/\1/p' |
					sed s/[[:space:]]//g
			)

			if [ "$me_ptr" = "0101" ]; then
				me171_instance_id=$i
				return 0
			fi
		done
		me171_instance_id=""
		return 1
	else
		me171_instance_id=$instances
		[ -n "$me171_instance_id" ]
	fi
}

# Log and record the UNI ME 171 instance ID to /tmp/collect.
collect_extended_vlan() {
	find_me171_uni_instance

	if [ -z "$me171_instance_id" ]; then
		echo "ME 171 instance id is null." >>/tmp/collect
	else
		if [ -n "$vlan_svc_log" ]; then
			logger -t "[vlan]" "ME 171 exists with instance id: $me171_instance_id"
		fi
		echo "ME 171 instance id: $me171_instance_id" >>/tmp/collect
	fi
}

# Query all ME 47 (bridge port config) instances and cache to /tmp/me47_bridge_ports.
# Each line: "instance_id tp_type tp_ptr"
#   tp_type: 01=PPTP UNI, 03=mapper (ME 130), 0b=VEIP
# Also populates mapper_ports/mapper_ptrs for dual-VLAN conflict fix.
# Sets globals: bridge_count, spanning_tree_data, mapper_ports, mapper_ptrs
query_bridge_ports() {
	local me47_instances i tp_type tp_ptr

	bridge_count=$($omci mib_dump | grep -c "Bridge config data")

	spanning_tree_data=$(
		$omci managed_entity_attr_data_get 45 1 1 |
			sed -n 's/\(attr\_data\=\)/\1/p' |
			cut -f 3 -d '=' |
			sed s/[[:space:]]//g
	)

	me47_instances=$(
		$omci mib_dump | grep "Bridge port config data" |
			sed -n 's/\(0x\)/\1/p' |
			cut -f 3 -d '|' |
			cut -f 1 -d '(' |
			sed s/[[:space:]]//g
	)

	: >/tmp/me47_bridge_ports

	for i in $me47_instances; do
		tp_type=$(
			$omci managed_entity_attr_data_get 47 "$i" 3 |
				sed -n 's/\(attr\_data\=\)/\1/p' |
				cut -f 3 -d '=' |
				sed s/[[:space:]]//g
		)
		tp_ptr=$(
			$omci managed_entity_attr_data_get 47 "$i" 4 |
				sed -n 's/\(attr\_data\=\)/\1/p' |
				cut -f 3 -d '=' |
				sed s/[[:space:]]//g
		)
		echo "$i $tp_type $tp_ptr" >>/tmp/me47_bridge_ports
	done

	# Extract mapper bridge ports (tp_type=03 -> IEEE 802.1p mapper, ME 130)
	mapper_ports=""
	mapper_ptrs=""
	while read -r inst tp_type tp_ptr; do
		if [ "$tp_type" = "03" ]; then
			mapper_ports="${mapper_ports}${inst} "
			mapper_ptrs="${mapper_ptrs}${tp_ptr} "
		fi
	done </tmp/me47_bridge_ports

	if [ -n "$vlan_svc_log" ]; then
		logger -t "[vlan]" "Bridge ports: $(tr '\n' '; ' </tmp/me47_bridge_ports)"
		[ -n "$mapper_ports" ] && logger -t "[vlan]" "Mapper ports: $mapper_ports"
	fi
}

# Log bridge topology to /tmp/collect. Checks for UNI (PPTP/VEIP) bridge port.
collect_bridge() {
	echo "Bridge count is: $bridge_count" >>/tmp/collect

	while read -r inst tp_type tp_ptr; do
		echo "Bridge port config data: $tp_type, $tp_ptr" >>/tmp/collect

		if [ "$tp_type" = "01" ] && [ "$tp_ptr" = "0101" ]; then
			echo "PPTP UNI bridge port exists." >>/tmp/collect
			return
		elif [ "$tp_type" = "0b" ]; then
			echo "VEIP bridge port exists." >>/tmp/collect
			return
		fi
	done </tmp/me47_bridge_ports

	echo "WARNING: No VEIP/PPTP UNI bridge port exists." >>/tmp/collect
}

# Master collection function — gathers OLT type, bridge topology, and ME 171 data.
# Called twice after O5 entry (collect_check_count < 2) for stability.
collect() {
	collect_olt_type
	query_bridge_ports
	collect_extended_vlan
	collect_bridge
}

# Monitor ME 2 attr 1 (MIB data sync counter) for OLT-side changes.
# A change in the sync counter indicates the OLT has re-provisioned MEs,
# triggering a configuration re-apply via change_count.
get_mib_data_sync() {
	local curr_mib_data_sync
	local prev_mib_data_sync

	if [ ! -e /tmp/mibcounter ]; then
		$omci managed_entity_attr_data_get 2 0 1 |
			sed -n 's/\(attr\_data\=\)/\1/p' |
			cut -f 3 -d '=' |
			sed s/[[:space:]]//g >/tmp/mibcounter
	else
		curr_mib_data_sync=$(
			$omci managed_entity_attr_data_get 2 0 1 |
				sed -n 's/\(attr\_data\=\)/\1/p' |
				cut -f 3 -d '=' |
				sed s/[[:space:]]//g
		)

		prev_mib_data_sync=$(cat /tmp/mibcounter)

		if [ "$curr_mib_data_sync" != "$prev_mib_data_sync" ]; then
			logger -t "[vlanexec]" "MIB data sync: $curr_mib_data_sync ($prev_mib_data_sync)"
			echo "$curr_mib_data_sync" >/tmp/mibcounter
			change_count=$((change_count + 1))
		fi
	fi
}

# Configure ME 171 (ExtVLAN) based on OLT vendor type. Each vendor has different
# bridge port setup requirements:
#   HWTC (Huawei): set_pptp_uni_bridge + create ME 171 flag=0 + check/restore rules
#   ALCL (Nokia):  set_alcl_uni_bridge + create ME 171 flag=1
#   ZTE/other:     set_pptp_uni_bridge + create ME 171 flag=1
set_me_171() {
	# OLT vendor IDs (ME 131 attr 1, hex-encoded ASCII)
	local OLT_TYPE_HWTC="48575443"  # "HWTC" = Huawei
	local OLT_TYPE_ALCL="414c434c"  # "ALCL" = Alcatel-Lucent / Nokia
	local OLT_TYPE_ZTE="5a544547"   # "ZTEG" = ZTE
	local OLT_TYPE_UNSET="20202020" # Spaces = not yet detected

	if [ "$olt_type" = "$OLT_TYPE_UNSET" ]; then
		olt_type=$(
			$omci managed_entity_attr_data_get 131 0 1 |
				sed -n 's/\(attr\_data\=\)/\1/p' |
				cut -f 3 -d '=' |
				sed s/[[:space:]]//g
		)

		sed -i '/^OLT\ type:*/c\OLT\ type:\ '"$olt_type"'/' /tmp/collect
	fi

	if [ -n "$vlan_svc_log" ]; then
		logger -t "[vlan]" "OLT type: $olt_type"
	fi

	case $olt_type in
	"$OLT_TYPE_HWTC")
		set_pptp_uni_bridge
		create_me_171 0
		check_me_171
		;;
	"$OLT_TYPE_ALCL")
		set_alcl_uni_bridge
		create_me_171 1
		;;
	"$OLT_TYPE_ZTE")
		set_pptp_uni_bridge
		create_me_171 1
		;;
	*)
		set_pptp_uni_bridge
		create_me_171 1
		;;
	esac
}

# Detect runtime changes to us_vlan_id UCI config; triggers re-apply via change_count.
check_us_vlan() {
	local curr_us_vlan_id
	local prev_us_vlan_id

	if [ ! -e /tmp/us_vlan_data ]; then
		us_vlan_id=$($uci get 8311.config.us_vlan_id 2>&-)

		if [ -n "$us_vlan_id" ]; then
			echo "$us_vlan_id" >/tmp/us_vlan_data
			change_count=$((change_count + 1))
		fi
	else
		curr_us_vlan_id=$($uci get 8311.config.us_vlan_id 2>&-)
		prev_us_vlan_id=$(cat /tmp/us_vlan_data)

		if [ "$curr_us_vlan_id" != "$prev_us_vlan_id" ]; then
			logger -t "[vlanexec]" "Detected change to us_vlan_id."
			echo "$curr_us_vlan_id" >/tmp/us_vlan_data
			change_count=$((change_count + 1))
		fi
	fi
}

# Apply upstream VLAN ID as an ME 171 table entry on the UNI ME 171.
# Supports: unset (discard-untagged default), "u" (untagged passthrough),
# or a VID (tagged with TPID 0x8100). Checks for existing match before writing.
set_us_vlan() {
	local vid_tpid_dei
	local vlan_tagging_op
	local vlan_tagging_op_hex
	local vlan_tagging_op_match

	local vid="^($vid_pattern|[u])$"

	if [ -z "$us_vlan_id" ]; then
		if [ -n "$vlan_svc_log" ]; then
			logger -t "[vlan]" "No us_vlan_id is configured."
		fi
		# Default: discard untagged frames (filter: no-tag, treatment: discard)
		# f8000000 = outer pri=15 (no double-tag), f8000000 = inner pri=15 (no-tag)
		# c00f0000 = rm_tags=3 (discard), outer_pri=15, 000f0000 = inner_pri=15
		$omci managed_entity_attr_data_set 171 "$me171_instance_id" 6 f8 00 00 00 f8 00 00 00 c0 0f \
			00 00 00 0f 00 00
		return

	elif [ "$(echo "$us_vlan_id" | grep -c "$vid")" -eq 0 ]; then
		if [ -n "$vlan_svc_log" ]; then
			logger -t "[vlan]" "There was an errror parsing us_vlan_id: $us_vlan_id."
		fi
		return
	fi

	if [ "$us_vlan_id" = "u" ]; then
		# Untagged passthrough: filter no-tag, treatment passthrough (no add/remove)
		logger -t "[vlan]" "Configuration for us_vlan_id is: untagged."
		vlan_tagging_op="f8 00 00 00 f8 00 00 00 00 0f 00 00 00 0f 00 00"
	else
		logger -t "[vlan]" "Configuration for us_vlan_id is: $us_vlan_id."

		# Encode treatment inner VID with TPID=4 (0x8100):
		# vid*8 shifts VID into bits [15:3], +4 sets TPID/DEI field to 4
		vid_tpid_dei=$(
			printf "%04x" $((us_vlan_id * 8 + 4)) |
				sed 's/../& /g'
		)

		# Filter: no-tag. Treatment: rm_tags=0, add outer pri=15 (no outer),
		# inner pri=8 (copy from received), VID=us_vlan_id, TPID=0x8100
		vlan_tagging_op="f8 00 00 00 f8 00 00 00 00 0f 80 00 00 00 $vid_tpid_dei"
	fi

	vlan_tagging_op_hex=$(
		echo "$vlan_tagging_op" |
			sed s/[[:space:]]//g |
			sed 's/\(..\)/0x\1/g' |
			sed 's/\(....\)/ \1/g'
	)

	vlan_tagging_op_match=$(
		$omci managed_entity_get 171 "$me171_instance_id" |
			grep "$vlan_tagging_op_hex"
	)

	if [ -n "$vlan_tagging_op_match" ] || [ -z "$force_us_vlan_id" ]; then
		if [ -n "$vlan_svc_log" ]; then
			logger -t "[vlan]" "Match detected for us_vlan_id, or force us_vlan_id is not enabled."
		fi
	else
		if [ -n "$vlan_svc_log" ]; then
			logger -t "[vlan]" "Configuring us_vlan_id..."
		fi
		$omci managed_entity_attr_data_set 171 "$me171_instance_id" 6 "$vlan_tagging_op"
	fi
}

# Detect runtime changes to ds_mc_tci and us_mc_vid UCI configs.
check_mc_vlans() {
	local curr_ds_mc_tci
	local prev_ds_mc_tci
	local curr_us_mc_vid
	local prev_us_mc_vid

	if [ ! -e /tmp/ds_mc_tci_data ]; then
		if [ -n "$ds_mc_tci" ]; then
			echo "$ds_mc_tci" >/tmp/ds_mc_tci_data
			change_count=$((change_count + 1))
		fi
	elif [ ! -e /tmp/us_mc_vid_data ]; then
		if [ -n "$us_mc_vid" ]; then
			echo "$us_mc_vid" >/tmp/us_mc_vid_data
			change_count=$((change_count + 1))
		fi
	else

		curr_ds_mc_tci=$($uci -q get 8311.config.ds_mc_tci)
		prev_ds_mc_tci=$(cat /tmp/ds_mc_tci_data)
		curr_us_mc_vid=$($uci -q get 8311.config.us_mc_vid)
		prev_us_mc_vid=$(cat /tmp/us_mc_vid_data)

		if [ "$curr_ds_mc_tci" != "$prev_ds_mc_tci" ]; then
			logger -t "[vlanexec]" "Detected change to ds_mc_tci."
			echo "$curr_ds_mc_tci" >/tmp/ds_mc_tci_data
			change_count=$((change_count + 1))
		fi

		if [ "$curr_us_mc_vid" != "$prev_us_mc_vid" ]; then
			logger -t "[vlanexec]" "Detected change to us_mc_vid."
			echo "$curr_us_mc_vid" >/tmp/us_mc_vid_data
			change_count=$((change_count + 1))
		fi
	fi
}

# Configure multicast VLANs: ME 309 (multicast operations profile) for downstream
# TCI and upstream multicast VID. Creates ME 309/310/311 if missing, sets the
# downstream multicast TCI and upstream multicast GEM port mapping.
set_mc_vlans() {
	local ds_mc_pcp
	local ds_mc_tci_hex
	local ds_mc_vid
	local gem_port_id
	local gem_port_nw_ctp_con_ptr
	local mc_gem_iw_tp
	local message
	local new_ds_mc_tci
	local old_ds_mc_tci
	local us_mc_vid_hex

	local tci="^($vid_pattern)(@([0-7]))?$"
	local vid="^($vid_pattern)$"

	if [ -z "$ds_mc_tci" ]; then
		if [ -n "$vlan_svc_log" ]; then
			logger -t "[vlan]" "No ds_mc_tci configured."
		fi
		return

	elif [ "$(echo "$ds_mc_tci" | grep -c "$tci")" -eq 0 ]; then
		if [ -n "$vlan_svc_log" ]; then
			logger -t "[vlan]" "Error parsing ds_mc_tci: $ds_mc_tci."
		fi
		return
	fi

	ds_mc_pcp=$(
		echo "$ds_mc_tci" |
			grep '@' |
			cut -f 2 -d "@"
	)

	ds_mc_vid=$(
		echo "$ds_mc_tci" |
			cut -f 1 -d '@'
	)

	create_me_309

	# Encode TCI: PCP in bits [15:13] (PCP * 8192 = PCP << 13), VID in bits [11:0]
	ds_mc_tci_hex=$((${ds_mc_pcp:=0} * 8192 | ds_mc_vid))

	# ME 309 attr 16 format: 04 (control type) + 2-byte TCI
	new_ds_mc_tci="04 $(printf "%04x" "$ds_mc_tci_hex" | sed 's/../& /g')"

	old_ds_mc_tci=$(
		$omci managed_entity_attr_data_get 309 "$me309_instance_id" 16 2>&- |
			cut -f 3 -d '='
	)

	if [ "$old_ds_mc_tci" = "$new_ds_mc_tci" ]; then
		if [ -n "$vlan_svc_log" ]; then
			logger -t "[vlan]" "Match detected for ds_mc_tci."
		fi
	else
		if [ -n "$vlan_svc_log" ]; then
			logger -t "[vlan]" "Configuring ds_mc_tci..."
		fi
		$omci managed_entity_attr_data_set 309 "$me309_instance_id" 16 "$new_ds_mc_tci"
	fi

	if [ -z "$us_mc_vid" ]; then
		if [ -n "$vlan_svc_log" ]; then
			logger -t "[vlan]" "No us_mc_vid is configured."
		fi
		return
	elif [ "$(echo "$us_mc_vid" | grep -c "$vid")" -eq 0 ]; then
		if [ -n "$vlan_svc_log" ]; then
			logger -t "[vlan]" "Error configuring us_mc_vid: $us_mc_vid."
		fi
		return
	fi

	us_mc_vid_hex=$(
		printf "%04x" "$us_mc_vid" |
			sed 's/../& /g'
	)

	mc_gem_iw_tp=$(
		$omci mib_dump |
			grep "Multicast GEM TP" |
			sed -n 's/\(0x\)/\1/p' |
			cut -f 3 -d '|' |
			cut -f 1 -d '(' |
			sed s/[[:space:]]//g
	)

	if [ -n "$mc_gem_iw_tp" ]; then
		gem_port_nw_ctp_con_ptr=$(
			$omci managed_entity_attr_data_get "281 $mc_gem_iw_tp 1" |
				sed -n 's/\(attr\_data\=\)/\1/p' |
				cut -f 3 -d '=' | cut -f 1 -d '(' |
				sed s/[[:space:]]//g
		)

		gem_port_id=$(
			$omci managed_entity_attr_data_get "268 0x$gem_port_nw_ctp_con_ptr 1" |
				cut -f 3 -d '='
		)

		if [ -n "$vlan_svc_log" ]; then
			logger -t "[vlan]" "Detected multicast GEM interworking TP, multicast GEM port id: $gem_port_id, configuring..."
		fi

		$omci managed_entity_attr_data_set 309 "$me309_instance_id" 7 40 00 "$gem_port_id" \
			"$us_mc_vid_hex" 00 00 00 00 e0 00 01 00 ef ff ff ff 00 00 00 00 00 00
	fi
}

# Delete a single-tag VLAN rule from the UNI ME 171 by writing the filter bytes
# with all treatment fields set to max (G.988 §9.3.13 delete convention).
# $1 = filter VID to delete
delete_vlan_translation() {
	local filter_inner_word
	local vlan_tagging_op

	# Encode filter inner word: pri=8 (any), VID=$1, TPID/DEI=0
	# "8" prefix = priority 8, vid*8 shifts into bits [15:3], "0" suffix = TPID/DEI
	filter_inner_word=$(
		echo "8$(printf "%04x" $(($1 * 8)))0" |
			sed 's/../& /g'
	)

	# G.988 delete: matching filter bytes + all-ones treatment = delete entry
	vlan_tagging_op="f8 00 00 00 $filter_inner_word 00 ff ff ff ff ff ff ff ff"
	logger -t "[vlanexec]" "Deleting VLAN tagging operation $1."
	$omci managed_entity_attr_data_set "171 $me171_instance_id 6 $vlan_tagging_op"
}

# Detect runtime changes to vlan_tag_ops UCI config (custom VLAN translations).
# Compares each vid_a:vid_b pair against cached values and triggers re-apply.
check_vlan_translations() {
	local vlans_seq
	local vlan_a_seq
	local vlan_b_seq
	local vlan_tagging_ops_num

	# Pattern: "vid[@pcp]:vid[@pcp]" pairs, comma-separated
	local tci_a="($vid_pattern)(@([0-7]))?"
	local tci_b="([u]|$vid_pattern)(@([0-7]))?"
	local pattern="^($tci_a\\:$tci_b)(,$tci_a\\:$tci_b)*$"

	if [ -z "$vlan_tag_ops" ]; then
		if [ -n "$vlan_svc_log" ]; then
			logger -t "[vlan]" "No vlan_tag_ops is configured."
		fi
		return

	elif [ "$(echo "$vlan_tag_ops" | grep -c "$pattern")" -eq 0 ]; then
		if [ -n "$vlan_svc_log" ]; then
			logger -t "[vlan]" "Error parsing vlan_tag_ops: \"$vlan_tag_ops\"."
		fi
		return
	fi

	vlan_tagging_ops_num=$(
		echo "$vlan_tag_ops" |
			grep -o ":" |
			grep -c ":"
	)

	vlans_seq=0

	for i in $(seq 1 "$vlan_tagging_ops_num"); do
		vlan_a=$(
			echo "$vlan_tag_ops" |
				cut -f "$i" -d ',' |
				cut -f 1 -d ':' |
				cut -f 1 -d '@'
		)

		vlan_b=$(
			echo "$vlan_tag_ops" |
				cut -f "$i" -d ',' |
				cut -f 2 -d ':' |
				cut -f 1 -d '@'
		)

		vlan_a_seq=$((i + vlans_seq))

		vlans_seq=$i

		vlan_b_seq=$((i + vlans_seq))

		if [ -e "/tmp/vlan$vlan_a_seq" ] && [ -e "/tmp/vlan$vlan_b_seq" ]; then
			prev_vlan_a=$(cat "/tmp/vlan$vlan_a_seq")
			prev_vlan_b=$(cat "/tmp/vlan$vlan_b_seq")

			if [ "$vlan_a" != "$prev_vlan_a" ] || [ "$vlan_b" != "$prev_vlan_b" ]; then
				logger -t "[vlanexec]" "Change detected for VLAN translation $i: vlan$vlan_a_seq:vlan$vlan_b_seq $vlan_a:$vlan_b ($prev_vlan_a:$prev_vlan_b)."
				delete_vlan_translation "$prev_vlan_a"
				echo "$vlan_a" >"/tmp/vlan$vlan_a_seq"
				echo "$vlan_b" >"/tmp/vlan$vlan_b_seq"
				change_count=$((change_count + 1))
			fi
		else
			if [ -n "$vlan_a" ] && [ -n "$vlan_b" ]; then
				echo "$vlan_a" >"/tmp/vlan$vlan_a_seq"
				echo "$vlan_b" >"/tmp/vlan$vlan_b_seq"
				change_count=$((change_count + 1))
			fi
		fi
	done
}

# Enable/disable N:1 VLAN translation mode on all downstream GEM ports.
# When enabled, multiple VLANs map to a single GEM port (GPE hardware feature).
set_n_to_1_vlan() {
	local gem_port_idx
	local gpe_vlan_mode

	gem_port_idx=$(
		$gtop -b -g "GPE DS GEM port" |
			awk 'BEGIN{FS=";"} NR>5  {print $1}' |
			sed s/[[:space:]]//g
	)

	if [ "$n_to_1_vlan" = "1" ]; then
		if [ -n "$vlan_svc_log" ]; then
			logger -t "[vlan]" "N:1 VLAN translation enabled."
		fi
		gpe_vlan_mode=1
	else
		if [ -n "$vlan_svc_log" ]; then
			logger -t "[vlan]" "N:1 VLAN translation disabled."
		fi
		gpe_vlan_mode=0
	fi

	for i in $gem_port_idx; do
		$onu gpe_vlan_mode_set "$i" 0 "$gpe_vlan_mode"
	done
}

# Apply custom VLAN translations (vlan_tag_ops) as ME 171 table entries.
# Format: "filter_vid[@pcp]:treatment_vid[@pcp],..." where treatment "u" = untag.
# Each pair becomes a single-tag filter → single-tag treatment ME 171 rule.
# Checks for existing match before writing to avoid unnecessary OMCI writes.
set_vlan_translations() {
	local priority_a
	local priority_b
	local vlan_a
	local vlan_b
	local vlan_tagging_op
	local vlan_tagging_ops_num
	local vlan_tagging_op_hex
	local vlan_tagging_op_match

	local tci_a="($vid_pattern)(@([0-7]))?"
	local tci_b="([u]|$vid_pattern)(@([0-7]))?"
	local pattern="^($tci_a\\:$tci_b)(,$tci_a\\:$tci_b)*$"

	if [ -z "$vlan_tag_ops" ]; then
		if [ -n "$vlan_svc_log" ]; then
			logger -t "[vlan]" "No vlan_tag_ops is configured."
		fi
		return

	elif [ "$(echo "$vlan_tag_ops" | grep -c "$pattern")" -eq 0 ]; then
		if [ -n "$vlan_svc_log" ]; then
			logger -t "[vlan]" "Error parsing vlan_tag_ops: $vlan_tag_ops."
		fi
		return
	fi

	vlan_tagging_ops_num=$(
		echo "$vlan_tag_ops" |
			grep -o ":" | grep -c ":"
	)

	for i in $(seq 1 "$vlan_tagging_ops_num"); do
		vlan_a=$(
			echo "$vlan_tag_ops" |
				cut -f "$i" -d ',' |
				cut -f 1 -d ':' |
				cut -f 1 -d '@'
		)

		vlan_b=$(
			echo "$vlan_tag_ops" |
				cut -f "$i" -d ',' |
				cut -f 2 -d ':' |
				cut -f 1 -d '@'
		)

		priority_a=$(
			echo "$vlan_tag_ops" |
				cut -f "$i" -d ',' |
				cut -f 1 -d ':' |
				grep '@' |
				cut -f 2 -d "@"
		)

		priority_b=$(
			echo "$vlan_tag_ops" |
				cut -f "$i" -d ',' |
				cut -f 2 -d ':' |
				grep '@' |
				cut -f 2 -d "@"
		)

		# Encode filter inner VID: vid*8 shifts VID into bits [15:3]
		filter_inner=$(
			printf "%04x" "$((vlan_a * 8))"
		)

		# Encode treatment inner VID: vid*8 shifts VID into bits [15:3]
		treatment_inner=$(
			printf "%04x" "$((vlan_b * 8))" |
				sed 's/../& /g'
		)

		# Build filter inner word: priority (default 8=any) + VID + TPID/DEI=0
		filter_inner_word=$(
			echo "${priority_a:=8}${filter_inner}0" |
				sed 's/../& /g'
		)

		# Build treatment inner word: priority (default 8=copy from received)
		treatment_inner_word="00 0${priority_b:=8} $treatment_inner"

		if [ "$vlan_b" = "u" ]; then
			# Untagged: inner pri=15 (don't add inner tag), VID=0, TPID=0
			treatment_inner_word="00 0f 00 00"
		fi

		# Full 16-byte ME 171 rule: filter outer=no-double-tag, filter inner,
		# treatment rm_tags=1 + outer_pri=15 (no outer), treatment inner
		vlan_tagging_op="f8 00 00 00 $filter_inner_word 00 40 0f 00 00 $treatment_inner_word"

		vlan_tagging_op_hex=$(
			echo "$vlan_tagging_op" |
				sed s/[[:space:]]//g |
				sed 's/\(..\)/0x\1/g' |
				sed 's/\(....\)/ \1/g'
		)

		vlan_tagging_op_match=$(
			$omci managed_entity_get 171 "$me171_instance_id" |
				grep "$vlan_tagging_op_hex"
		)

		if [ -n "$vlan_tagging_op_match" ]; then
			if [ -n "$vlan_svc_log" ]; then
				logger -t "[vlan]" "Match detected for VLAN tagging operation $i: $vlan_a:$vlan_b."
			fi
		else
			if [ -n "$vlan_svc_log" ]; then
				logger -t "[vlan]" "Configuring VLAN tagging operation $i: $vlan_a:$vlan_b"
			fi
			$omci managed_entity_attr_data_set 171 "$me171_instance_id 6 $vlan_tagging_op"
		fi
	done
}

# Configure or create a PPTP UNI bridge port (ME 47) with tp_type=01, tp_ptr=0x0101.
# Used by Huawei, ZTE, and default OLT paths. If no existing PPTP UNI bridge port
# is found, deletes any conflicting ME 47 instance 1 and creates a new one.
# Sets global: pptp_uni_bridge
set_pptp_uni_bridge() {
	local bridge_instance
	local me47_tp_type
	local found=false

	while read -r inst tp_type tp_ptr; do
		if [ "$tp_type" = "01" ] && [ "$tp_ptr" = "0101" ]; then
			if [ -n "$vlan_svc_log" ]; then
				logger -t "[vlan]" "PPTP UNI bridge port exists with instance id: $inst"
			fi

			pptp_uni_bridge=$inst

			$omci managed_entity_attr_data_set 47 "$inst" 3 1
			$omci managed_entity_attr_data_set 47 "$inst" 4 01 01
			$omci managed_entity_attr_data_set 47 "$inst" 7 "$spanning_tree_data"

			found=true
			break
		fi
	done </tmp/me47_bridge_ports

	if ! $found; then
		me47_tp_type=$(
			$omci managed_entity_attr_data_get 47 1 3 |
				sed -n 's/\(attr\_data\=\)/\1/p' |
				cut -f 3 -d '=' |
				sed s/[[:space:]]//g
		)

		if [ -n "$me47_tp_type" ]; then
			$omci managed_entity_delete 47 1
		fi

		bridge_instance=$(
			$omci mib_dump |
				grep "Bridge config data" |
				sed -n 's/\(0x\)/\1/p' |
				cut -f 3 -d '|' |
				cut -f 1 -d '(' |
				tail -n 1 |
				sed s/[[:space:]]//g
		)

		if [ -n "$vlan_svc_log" ]; then
			logger -t "[vlan]" "No PPTP UNI bridge port detected, creating with instance id 1."
		fi

		$omci managed_entity_create 47 1 "$bridge_instance" 1 1 257 0 1 \
			"$(echo "$spanning_tree_data" | cut -c 2-3)" 1 1

		pptp_uni_bridge=1
	fi
}

# Return next transaction ID (4-char hex) for ONU-initiated OMCI creates.
# Wraps around within 0xFF01-0xFFFE to avoid OLT TXN ID space.
next_txn_id() {
	printf "%04x" $_txn_id
	_txn_id=$((_txn_id + 1))
	[ $_txn_id -gt 65535 ] && _txn_id=0xff01
}

# Save the current MIB data sync counter (ME 2 attr 1) before ONU-initiated
# OMCI operations. Restored after to prevent OLT from detecting our writes
# as MIB changes.
save_mib_data_sync() {
	_saved_mib_data_sync=$(
		$omci managed_entity_attr_data_get 2 0 1 |
			sed -n 's/\(attr\_data\=\)/\1/p' |
			cut -f 3 -d '=' |
			sed s/[[:space:]]//g
	)
}

# Restore the MIB data sync counter to the value saved by save_mib_data_sync.
restore_mib_data_sync() {
	[ -z "$_saved_mib_data_sync" ] && return
	$omci managed_entity_attr_data_set 2 0 1 "$_saved_mib_data_sync"
	if [ -n "$vlan_svc_log" ]; then
		logger -t "[vlan]" "MIB data sync restored: $_saved_mib_data_sync."
	fi
}

# Detect many-to-one downstream VID mappings in ME 171 table.
# Sets globals: conflict_vids (space-sep "fvid:tvid" pairs), conflict_tvid
# Returns 0 if conflict found, 1 if no conflict.
detect_vid_conflict() {
	local data entry w2 w3 w4
	local filter_vid treatment_vid treatment_remove_tags
	local pairs="" pair tvid fvid prev_tvid="" prev_fvid=""
	local found_treatment="" found_vids=""

	[ -z "$me171_instance_id" ] && return 1

	data=$(mibattrdata 171 "$me171_instance_id" 6) || return 1

	# Pass 1: Collect treatment_vid:filter_vid pairs
	for entry in $data; do
		w2=0x${entry:8:8}
		w3=0x${entry:16:8}
		w4=0x${entry:24:8}

		filter_vid=$((($w2 & 0x0fff8000) >> 15))
		treatment_remove_tags=$((($w3 & 0xc0000000) >> 30))
		treatment_vid=$((($w4 & 0x0000fff8) >> 3))

		# Skip non-VID rules (default/discard/no-tag)
		[ "$filter_vid" -ge 4095 ] && continue
		[ "$treatment_remove_tags" -eq 3 ] && continue

		pairs="${pairs}${treatment_vid}:${filter_vid} "
	done

	# Pass 2: Sort by treatment VID, find many-to-one mappings
	for pair in $(printf '%s\n' $pairs | sort -t: -k1,1n); do
		tvid=${pair%%:*}
		fvid=${pair#*:}
		if [ "$tvid" = "$prev_tvid" ]; then
			if [ "$tvid" != "$found_treatment" ]; then
				found_vids="${found_vids}${prev_fvid}:${tvid} "
				found_treatment="$tvid"
			fi
			found_vids="${found_vids}${fvid}:${tvid} "
		fi
		prev_tvid="$tvid"
		prev_fvid="$fvid"
	done

	if [ -n "$found_vids" ]; then
		conflict_vids="$found_vids"
		conflict_tvid="$found_treatment"
		return 0
	fi
	return 1
}

# Create ME 171 with assoc_type=1 (mapper association).
# $1 = mapper instance (ME 130, 4-char hex e.g. "1102")
# $2 = new ME 171 instance ID (4-char hex)
create_mapper_me_171() {
	local mapper="$1" me171_id="$2"
	local txn

	txn=$(next_txn_id)

	$omci rmr \
		${txn:0:2} ${txn:2:2} 44 0a 00 ab \
		${me171_id:0:2} ${me171_id:2:2} \
		01 ${mapper:0:2} ${mapper:2:2} \
		00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
		00 00 00 00 00 00 00 00 00 00 00 00 00
	sleep 1
}

# Add VID translation rule to a per-mapper ME 171.
# $1 = ME 171 instance (4-char hex), $2 = filter VID, $3 = treatment VID
add_mapper_vid_rule() {
	local me171="$1" fvid="$2" tvid="$3"
	local filter_inner treatment_inner

	filter_inner=$(printf "%08x" $(( (8 << 28) | (fvid << 15) )))
	treatment_inner=$(printf "%08x" $(( (8 << 16) | (tvid << 3) | 4 )))

	$omci managed_entity_attr_data_set 171 "0x$me171" 6 \
		f8 00 00 00 \
		${filter_inner:0:2} ${filter_inner:2:2} ${filter_inner:4:2} ${filter_inner:6:2} \
		40 0f 00 00 \
		${treatment_inner:0:2} ${treatment_inner:2:2} ${treatment_inner:4:2} ${treatment_inner:6:2}
}

# Resolve many-to-one VID conflicts by creating per-mapper ME 171 instances.
# No-op when no conflict detected (single-VLAN ISPs).
fix_vid_conflict() {
	local pair vid mapper me171_id
	local conflict_filter_vids="" vid_mapper_map
	local user_map

	detect_vid_conflict || return 0

	logger -t "[vlan]" "VID conflict detected: $conflict_vids"

	if [ -z "$mapper_ports" ]; then
		logger -t "[vlan]" "No mapper bridge ports found, cannot resolve conflict."
		return 1
	fi

	# Parse conflict filter VIDs
	for pair in $conflict_vids; do
		conflict_filter_vids="${conflict_filter_vids}${pair%%:*} "
	done

	# VID->mapper assignment:
	# 1. User config (guaranteed correct)
	# 2. Fallback: instance order heuristic
	user_map=$($uci -q get 8311.config.vlan_mapper_map)
	if [ -n "$user_map" ]; then
		vid_mapper_map=$(echo "$user_map" | tr ',' ' ')
	else
		local sorted_vids sorted_mappers vi
		sorted_vids=$(printf '%s\n' $conflict_filter_vids | sort -n | tr '\n' ' ')
		sorted_mappers=$(printf '%s\n' $mapper_ptrs | sort | tr '\n' ' ')
		vid_mapper_map=""
		vi=1; for vid in $sorted_vids; do
			mapper=$(echo "$sorted_mappers" | cut -d' ' -f"$vi")
			[ -z "$mapper" ] && break
			vid_mapper_map="${vid_mapper_map}${vid}:${mapper} "
			vi=$((vi + 1))
		done
	fi

	logger -t "[vlan]" "VID->mapper assignment: $vid_mapper_map"

	save_mib_data_sync

	for entry in $vid_mapper_map; do
		vid=${entry%%:*}
		mapper=${entry#*:}
		me171_id=$(printf "%04x" "$((0x$mapper))")

		# Create ME 171 for mapper if not already present
		if ! mibs 171 | grep -q "^$((0x$me171_id))$"; then
			logger -t "[vlan]" "Creating ME 171 on mapper 0x${mapper} for VID ${vid}"
			create_mapper_me_171 "$mapper" "$me171_id"
		fi

		# Add VID rule to mapper's ME 171
		add_mapper_vid_rule "$me171_id" "$vid" "$conflict_tvid"

		# Delete conflicting rule from UNI ME 171
		delete_vlan_translation "$vid"
	done

	restore_mib_data_sync

	logger -t "[vlan]" "VID conflict fix applied."

	if [ -n "$vlan_svc_log" ]; then
		logger -t "[vlan]" "GPE ExtVLAN tables after fix:"
		$onu xml_table gpe_table_extvlan -1 2>&- | logger -t "[vlan]"
	fi
}

# Create UNI ME 171 if missing.
# $1 = create_flag: 0 = expect it exists (Huawei), 1 = create if missing (ALCL/ZTE)
# Uses rmr (raw message relay) for the create since managed_entity_create doesn't
# support ME 171's set-by-create attributes (assoc_type, assoc_me_ptr).
# Sets global: me171_instance_id
create_me_171() {
	local create_flag
	local me47_instance_id

	create_flag=$1

	find_me171_uni_instance

	me47_instance_id=$pptp_uni_bridge

	case $create_flag in
	0)
		# Huawei: OLT should have created ME 171; warn if missing
		if [ -z "$me171_instance_id" ] && [ -n "$vlan_svc_log" ]; then
			logger -t "[vlan]" "ME 171 instance id should not be null."
		fi
		;;
	1)
		# ALCL/ZTE/default: create ME 171 if OLT didn't provision one
		if [ -z "$me171_instance_id" ]; then
			local id txn
			id=$(printf "%04x" "$((me47_instance_id))")

			if [ -n "$vlan_svc_log" ]; then
				logger -t "[vlan]" "Creating ME 171 with instance id: 0x$id"
			fi

			save_mib_data_sync

			# OMCI create (baseline, 40 bytes via rmr):
			#   44 0a = AR/create, device_id=0x0a (baseline)
			#   00 ab = ME class 171 (ExtVLAN)
			#   02 = assoc_type=2 (PPTP UNI), 01 01 = assoc_me_ptr=0x0101
			txn=$(next_txn_id)
			$omci rmr \
				${txn:0:2} ${txn:2:2} 44 0a 00 ab \
				${id:0:2} ${id:2:2} \
				02 01 01 \
				00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
				00 00 00 00 00 00 00 00 00 00 00 00 00
			sleep 1

			# Add discard-untagged default rule (same as set_us_vlan with no config)
			$omci managed_entity_attr_data_set 171 "0x$id" 6 \
				f8 00 00 00 f8 00 00 00 c0 0f 00 00 00 0f 00 00

			restore_mib_data_sync

			me171_instance_id=$((0x$id))
		fi
		;;
	*)
		if [ -n "$vlan_svc_log" ]; then
			logger -t "[vlan]" "ME 171 create_flag value error."
		fi
		;;
	esac
}

# Create ME 309 (multicast operations profile) + ME 310/311 if missing or
# if force_me309_create is set. Sets IGMP version and basic multicast config.
# Sets global: me309_instance_id
create_me_309() {
	local me309_instance_count

	me309_instance_id=$(
		$omci mib_dump |
			grep 309 |
			sed -n 's/\(0x\)/\1/p' |
			cut -f 3 -d '|' |
			cut -f 1 -d '(' |
			head -n 1 |
			sed s/[[:space:]]//g
	)

	me309_instance_count=$(
		$omci mib_dump |
			grep -c 309
	)

	if [ -z "$me309_instance_id" ] ||
		{ [ -n "$force_me309_create" ] &&
			[ "$me309_instance_count" -ge 2 ]; }; then

		me309_instance_id=$pptp_uni_bridge

		if [ -n "$vlan_svc_log" ]; then
			logger -t "[vlan]" "ME 309 does not exist or force_me309_create enabled, creating with instance id: $me309_instance_id"
		fi

		$omci managed_entity_create 309 "$me309_instance_id" "${igmp_version:=3}" 0 1 0 0 32
		$omci managed_entity_attr_data_set 309 "$me309_instance_id" 10 02
		$omci managed_entity_attr_data_set 309 "$me309_instance_id" 12 00 00 00 7d
		$omci managed_entity_attr_data_set 309 "$me309_instance_id" 13 00 00 00 64
		$omci managed_entity_attr_data_set 309 "$me309_instance_id" 15 01
		$omci managed_entity_create 310 "$me309_instance_id" 0 "$me309_instance_id" 64 0 1
		$omci managed_entity_create 311 "$me309_instance_id" 0
		sleep 5
	else
		if [ -n "$vlan_svc_log" ]; then
			logger -t "[vlan]" "ME 309 already exists with instance id: $me309_instance_id"
		fi
		$omci managed_entity_attr_data_set 309 "$me309_instance_id" 1 "0$igmp_version"
	fi
}

# Configure UNI bridge port for Nokia (ALCL) OLTs. Handles both PPTP (tp_type=01)
# and VEIP (tp_type=0b). Unlike set_pptp_uni_bridge, only sets tp_type/tp_ptr when
# force_me_create is enabled (Nokia OLTs typically provision these correctly).
# Sets global: pptp_uni_bridge
set_alcl_uni_bridge() {
	while read -r inst tp_type tp_ptr; do
		if [ "$tp_type" = "01" ] && [ "$tp_ptr" = "0101" ]; then
			if [ -n "$vlan_svc_log" ]; then
				logger -t "[vlan]" "PPTP UNI bridge port exists with instance id: $inst"
			fi

			if [ -n "$force_me_create" ]; then
				$omci managed_entity_attr_data_set 47 "$inst" 3 1
				$omci managed_entity_attr_data_set 47 "$inst" 4 01 01
			fi

			$omci managed_entity_attr_data_set 47 "$inst" 7 "$spanning_tree_data"

			pptp_uni_bridge=$inst

			return
		elif [ "$tp_type" = "0b" ]; then
			if [ -n "$vlan_svc_log" ]; then
				logger -t "[vlan]" "VEIP bridge port exists with instance id: $inst"
			fi

			$omci managed_entity_attr_data_set 47 "$inst" 3 1
			$omci managed_entity_attr_data_set 47 "$inst" 4 01 01
			$omci managed_entity_attr_data_set 47 "$inst" 7 "$spanning_tree_data"

			pptp_uni_bridge=$inst

			return
		fi
	done </tmp/me47_bridge_ports
}

# Huawei-only: verify ME 171 has correct default single/double-tag passthrough
# rules and re-apply any custom rules from /tmp/me171_rule if they were lost.
# The Huawei OLT may overwrite default rules during MIB sync.
check_me_171() {
	local current_single_tag_op
	local current_double_tag_op
	local vlan_tagging_op
	local vlan_tagging_ops_num

	# Expected default passthrough rules (hex with 0x prefixes, no spaces)
	# Single-tag: filter outer=15 (no double), inner=14 (default), treatment=passthrough
	local default_single_tag_op="0xf80x000x000x000xe80x000x000x000x000x0f0x000x000x000x0f0x000x00"
	# Double-tag: filter outer=14 (default), inner=14 (default), treatment=passthrough
	local default_double_tag_op="0xe80x000x000x000xe80x000x000x000x000x0f0x000x000x000x0f0x000x00"

	current_single_tag_op=$(
		$omci managed_entity_get 171 "$me171_instance_id" |
			grep "0xf8 0x00 0x00 0x00 0xe8" |
			tail -n 1 |
			sed s/[[:space:]]//g
	)

	current_double_tag_op=$(
		$omci managed_entity_get 171 "$me171_instance_id" |
			grep "0xe8 0x00 0x00 0x00 0xe8" |
			tail -n 1 |
			sed s/[[:space:]]//g
	)

	$omci managed_entity_get 171 "$me171_instance_id" |
		sed -n '/^ 5 RX frame VLAN table/,$p' |
		sed '/^ 6 Associated ME ptr/,$d' |
		grep '^   0x' |
		grep -v "0xf8 0x00 0x00 0x00 0xe8" |
		grep -v "0xe8 0x00 0x00 0x00 0xe8" |
		sed 's/^   //g' |
		sed 's/0x//g' >/tmp/me171_rule

	vlan_tagging_ops_num=$(
		$omci managed_entity_get 171 1 |
			sed -n '/^ 5 RX frame VLAN table/,$p' |
			sed '/^ 6 Associated ME ptr/,$d' |
			grep '^   0x' |
			grep -v "0xf8 0x00 0x00 0x00 0xe8" |
			grep -vc "0xf8 0x00 0x00 0x00 0xe8"
	)

	if [ "$vlan_tagging_ops_num" -ge 1 ] && [ -n "$vlan_svc_log" ]; then
		for i in $(seq 1 "$vlan_tagging_ops_num"); do
			vlan_tagging_op=$(tail -n "$i" /tmp/me171_rule | head -n 1)
			logger -t "[vlan]" "ME 171 VLAN tagging operation $i: $vlan_tagging_op"
		done
	fi

	if [ -n "$force_me_create" ] ||
		{ [ "$current_single_tag_op" != "$default_single_tag_op" ] ||
			[ "$current_double_tag_op" != "$default_double_tag_op" ]; }; then
		if [ -n "$vlan_svc_log" ]; then
			logger -t "[vlan]" "Default VLAN tagging operation does not match or force_me_create enabled, creating..."
		fi

		$omci managed_entity_attr_data_set 171 "$me171_instance_id" 6 f8 00 00 00 e8 00 00 00 00 0f 00 00 00 0f 00 00
		$omci managed_entity_attr_data_set 171 "$me171_instance_id" 6 e8 00 00 00 e8 00 00 00 00 0f 00 00 00 0f 00 00

		if [ "$vlan_tagging_ops_num" -ge 1 ]; then
			for i in $(seq 1 "$vlan_tagging_ops_num"); do
				vlan_tagging_op=$(tail -n "$i" /tmp/me171_rule | head -n 1)
				$omci managed_entity_attr_data_set 171 "$me171_instance_id" 6 "$vlan_tagging_op"
			done
		fi
	fi
}

# Main loop body — called repeatedly by vlan_svc().
#
# State machine:
#   PLOAM != 5 (not associated): reset state, handle reboot logic or wait
#   PLOAM == 5 (O5 associated):
#     - First 2 iterations: collect OLT/bridge/ME data
#     - First 5 iterations (init_check_count < 5): apply all config
#     - After init: re-apply only when change_count >= 1 (MIB sync, FSM, UCI)
#     - Dual-VLAN fix runs once per O5 session (vid_conflict_fixed gate)
main() {
	local los_state
	local ploam_state

	ploam_state=$(get_ploam_state)

	los_state=$(
		$optic bosa_rx_status_get |
			cut -f 8 -d ' ' |
			cut -f 2 -d '=' |
			sed s/[[:space:]]//g
	)

	if [ "$ploam_state" != "5" ]; then
		reset_tracked_parameters

		if [ "$reboot_on_association_fail" = "1" ] && [ -n "$max_reboot_delay_intervals" ] &&
			[ -n "$max_reboots" ] && [ "$los_state" != "1" ] &&
			[ "$reboots_count" -lt "$max_reboots" ]; then

			if [ "$reboot_delay_interval" -eq "$max_reboot_delay_intervals" ]; then
				logger -t "[vlanexec]" "reboot_on_association_fail enabled and max_reboot_delay_intervals reached, current reboots count: $reboots_count, rebooting..."
				do_reboot
			else
				if [ -z "$max_reboot_delay_intervals" ] || [ -z "$max_reboots" ]; then
					if [ $log_check_count -lt 1 ]; then
						logger -t "[vlanexec]" "WARNING: max_reboot_delay_intervals and/or max_reboots is not set, waiting..."
						log_check_count=$((log_check_count + 1))
					fi
					sleep_interval
				else
					logger -t "[vlanexec]" "reboot_on_association_fail enabled, current reboot delay interval: $reboot_delay_interval, waiting for reboot..."
					delay_reboot
				fi
			fi
		elif [ "$los_state" = "1" ]; then
			if [ $log_check_count -lt 1 ]; then
				logger -t "[vlanexec]" "WARNING: Loss of Signal detected, waiting..."
				log_check_count=$((log_check_count + 1))
			fi
			sleep_interval
		else
			if [ $log_check_count -lt 1 ]; then
				logger -t "[vlanexec]" "reboot_delay_interval not enabled or max_reboots reached, current reboots count: $reboots_count, giving up..."
				log_check_count=$((log_check_count + 1))
			fi
			sleep_interval
		fi
	else
		if [ $ploam_check_count -le 20 ]; then
			ploam_check_count=$((ploam_check_count + 1))
		fi

		ploam_state=$(get_ploam_state)

		if [ "$ploam_state" = "5" ]; then
			if [ $collect_check_count -lt 2 ]; then
				collect
				collect_check_count=$((collect_check_count + 1))
			fi

			reset_log_check_count
			reset_reboot_delay
			reset_reboot_attempt

			get_mib_data_sync

			check_onu_fsm_o5
			check_onu_rx_msg_lost
			check_us_vlan
			check_mc_vlans
			check_vlan_translations

			if [ $init_check_count -lt 5 ]; then
				set_me_171
				if [ "$vid_conflict_fixed" -lt 1 ]; then
					fix_vid_conflict && vid_conflict_fixed=1
				fi
				set_us_vlan
				set_mc_vlans
				set_n_to_1_vlan
				set_vlan_translations
				init_check_count=$((init_check_count + 1)) # this is only incremented here
			elif [ $change_count -ge 1 ]; then
				set_me_171
				if [ "$vid_conflict_fixed" -lt 1 ]; then
					fix_vid_conflict && vid_conflict_fixed=1
				fi
				set_us_vlan
				set_mc_vlans
				set_n_to_1_vlan
				set_vlan_translations
				change_count=0
			fi

			sleep_interval
		fi
	fi
}

# Entry point — infinite loop calling main() on each iteration.
vlan_svc() {
	while true; do
		main
	done
}

vlan_svc
