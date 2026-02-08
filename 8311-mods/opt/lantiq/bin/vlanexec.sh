#!/bin/sh
#************************************************#
# vlanexec.sh #
# written by kenny #
# Nov 20, 2021 Init #
# #
# OLT IOP. #
#************************************************#
# Script start
# exec variable

onu="/opt/lantiq/bin/onu"
uci="/sbin/uci"
omci="/opt/lantiq/bin/omci_pipe.sh"
gtop="/opt/lantiq/bin/gtop"
optic="/opt/lantiq/bin/optic"

_lib_8311_omci 2>/dev/null || . /lib/8311-omci-lib.sh

init_check_count=0
change_count=0
collect_check_count=0
ploam_check_count=0
log_check_count=0
reboot_delay_interval=0
_txn_id=0xff01
_saved_mib_data_sync=""
spanning_tree_data=""
mapper_ports=""
mapper_ptrs=""
conflict_vids=""
conflict_tvid=""
vid_conflict_fixed=0

reboots_count=$(cat /tmp/reboots_count 2>&-)

reboot_on_association_fail=$($uci -q get 8311.config.tryreboot)
max_reboot_delay_intervals=$($uci -q get 8311.config.max_reboot_delay_intervals)
max_reboots=$($uci -q get 8311.config.max_reboots)
persist_log_on_reboot=$($uci -q get 8311.config.persist_log_on_reboot)

us_vlan_id=$($uci -q get 8311.config.us_vlan_id)
n_to_1_vlan=$($uci -q get 8311.config.n_to_1_vlan)
vlan_tag_ops=$($uci -q get 8311.config.vlan_tag_ops)
ds_mc_tci=$($uci -q get 8311.config.ds_mc_tci)
us_mc_vid=$($uci -q get 8311.config.us_mc_vid)
igmp_version=$($uci -q get 8311.config.igmp_version)
force_me_create=$($uci -q get 8311.config.force_me_create)
force_me309_create=$($uci -q get 8311.config.force_me309_create)
force_us_vlan_id=$($uci -q get 8311.config.force_us_vlan_id)
vlan_svc_log=$($uci -q get 8311.config.vlan_svc_log)

vid_pattern='4096|409[0-4]|(40[0-8]|[1-3][[:digit:]][[:digit:]]|[1-9][[:digit:]]|[1-9])[[:digit:]]|[0-9]'

get_ploam_state() {
	$onu ploam_state_get |
		cut -b 24
}

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

sleep_interval() {
	local time

	if [ $ploam_check_count -lt 20 ]; then
		time=5
	else
		time=15
	fi
	sleep $time
}

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

collect() {
	collect_olt_type
	query_bridge_ports
	collect_extended_vlan
	collect_bridge
}

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

set_me_171() {
	local OLT_TYPE_HWTC="48575443"
	local OLT_TYPE_ALCL="414c434c"
	local OLT_TYPE_ZTE="5a544547"
	local OLT_TYPE_UNSET="20202020"

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
		logger -t "[vlan]" "Configuration for us_vlan_id is: untagged."
		vlan_tagging_op="f8 00 00 00 f8 00 00 00 00 0f 00 00 00 0f 00 00"
	else
		logger -t "[vlan]" "Configuration for us_vlan_id is: $us_vlan_id."

		vid_tpid_dei=$(
			printf "%04x" $((us_vlan_id * 8 + 4)) |
				sed 's/../& /g'
		)

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

	ds_mc_tci_hex=$((${ds_mc_pcp:=0} * 8192 | ds_mc_vid))

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

delete_vlan_translation() {
	local filter_inner_word
	local vlan_tagging_op

	filter_inner_word=$(
		echo "8$(printf "%04x" $(($1 * 8)))0" |
			sed 's/../& /g'
	)

	vlan_tagging_op="f8 00 00 00 $filter_inner_word 00 ff ff ff ff ff ff ff ff"
	logger -t "[vlanexec]" "Deleting VLAN tagging operation $1."
	$omci managed_entity_attr_data_set "171 $me171_instance_id 6 $vlan_tagging_op"
}

check_vlan_translations() {
	local vlans_seq
	local vlan_a_seq
	local vlan_b_seq
	local vlan_tagging_ops_num

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

		filter_inner=$(
			printf "%04x" "$((vlan_a * 8))"
		)

		treatment_inner=$(
			printf "%04x" "$((vlan_b * 8))" |
				sed 's/../& /g'
		)

		filter_inner_word=$(
			echo "${priority_a:=8}${filter_inner}0" |
				sed 's/../& /g'
		)

		treatment_inner_word="00 0${priority_b:=8} $treatment_inner"

		if [ "$vlan_b" = "u" ]; then
			treatment_inner_word="00 0f 00 00"
		fi

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

next_txn_id() {
	printf "%04x" $_txn_id
	_txn_id=$((_txn_id + 1))
	[ $_txn_id -gt 65535 ] && _txn_id=0xff01
}

save_mib_data_sync() {
	_saved_mib_data_sync=$(
		$omci managed_entity_attr_data_get 2 0 1 |
			sed -n 's/\(attr\_data\=\)/\1/p' |
			cut -f 3 -d '=' |
			sed s/[[:space:]]//g
	)
}

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

create_me_171() {
	local create_flag
	local me47_instance_id

	create_flag=$1

	find_me171_uni_instance

	me47_instance_id=$pptp_uni_bridge

	case $create_flag in
	0)
		if [ -z "$me171_instance_id" ] && [ -n "$vlan_svc_log" ]; then
			logger -t "[vlan]" "ME 171 instance id should not be null."
		fi
		;;
	1)
		if [ -z "$me171_instance_id" ]; then
			local id txn
			id=$(printf "%04x" "$((me47_instance_id))")

			if [ -n "$vlan_svc_log" ]; then
				logger -t "[vlan]" "Creating ME 171 with instance id: 0x$id"
			fi

			save_mib_data_sync

			# Create ME 171 with assoc_type=2 (PPTP UNI), ptr=0x0101
			txn=$(next_txn_id)
			$omci rmr \
				${txn:0:2} ${txn:2:2} 44 0a 00 ab \
				${id:0:2} ${id:2:2} \
				02 01 01 \
				00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
				00 00 00 00 00 00 00 00 00 00 00 00 00
			sleep 1

			# Add discard-untagged rule
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

check_me_171() {
	local current_single_tag_op
	local current_double_tag_op
	local vlan_tagging_op
	local vlan_tagging_ops_num

	local default_single_tag_op="0xf80x000x000x000xe80x000x000x000x000x0f0x000x000x000x0f0x000x00"
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

vlan_svc() {
	while true; do
		main
	done
}

vlan_svc
# Script end
