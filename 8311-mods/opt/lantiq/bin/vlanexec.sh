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
omci_simulate="/opt/lantiq/bin/omci_simulate"
gtop="/opt/lantiq/bin/gtop"
optic="/opt/lantiq/bin/optic"

init_flag=0
totalizer_flag=0
collect_flag=0
state_flag=0
log_flag=0
reboot_delay_interval=0

reboots_count=$(cat /tmp/reboots_count 2>&-)

reboot_on_association_fail=$($uci -q get 8311.config.reboot_on_association_fail)
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
		rest
	fi
}

reset_reboot_delay() {
	reboot_delay_interval=0
}

reset_log_flag() {
	log_flag=0
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
		totalizer_flag=$((totalizer_flag + 1))
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
		totalizer_flag=$((totalizer_flag + 1))
	fi

	echo "$curr_status" >/tmp/oltstatus2
}

rest() {
	local time

	if [ $state_flag -lt 20 ]; then
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

	init_flag=0
	totalizer_flag=0
	state_flag=0

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

		if [ -e "/tmp/vlan$vlan_a_seq" ] || [ -e "/tmp/vlan$vlan_a_seq" ]; then
			rm -f /tmp/vlan$vlan_a_seq
			rm -f /tmp/vlan$vlan_a_seq
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

collect_extended_vlan() {
	local me171_associated_me_ptr
	local me171_instances
	local me171_instance_count

	me171_instances=$(
		$omci mib_dump |
			grep "Extended VLAN conf data" |
			sed -n 's/\(0x\)/\1/p' |
			cut -f 3 -d '|' |
			cut -f 1 -d '(' |
			head -n 1 |
			sed s/[[:space:]]//g
	)

	me171_instance_count=$(
		$omci mib_dump |
			grep -c "Extended VLAN conf data"
	)

	if [ "$me171_instance_count" -gt 1 ]; then
		for i in $me171_instances; do
			me171_associated_me_ptr=$(
				$omci managed_entity_attr_data_get 171 "$i" 7 |
					sed -n 's/\(attr\_data\=\)/\1/p' |
					sed s/[[:space:]]//g
			)

			if [ "$me171_associated_me_ptr" = "0101" ]; then
				me171_instance_id=$i
				if [ -n "$vlan_svc_log" ]; then
					logger -t "[vlan]" "ME 171 exists with instance id: $me171_instance_id"
				fi
				break
			fi
		done
	else
		me171_instance_id=$me171_instances
	fi

	if [ -z "$me171_instance_id" ]; then
		echo "ME 171 instance id is null." >>/tmp/collect
	else
		echo "ME 171 instance id: $me171_instance_id" >>/tmp/collect
	fi
}

collect_bridge() {
	local me47_instances
	local me47_tp_type
	local me47_tp_ptr
	local bridge_count

	bridge_count=$(
		$omci mib_dump |
			grep -c "Bridge config data"
	)

	echo "Bridge count is: $bridge_count" >>/tmp/collect

	me47_instances=$(
		$omci mib_dump | grep "Bridge port config data" |
			sed -n 's/\(0x\)/\1/p' |
			cut -f 3 -d '|' |
			cut -f 1 -d '(' |
			sed s/[[:space:]]//g
	)

	for i in $me47_instances; do
		me47_tp_type=$(
			$omci managed_entity_attr_data_get 47 "$i" 3 |
				sed -n 's/\(attr\_data\=\)/\1/p' |
				cut -f 3 -d '=' |
				sed s/[[:space:]]//g
		)

		me47_tp_ptr=$(
			$omci managed_entity_attr_data_get 47 "$i" 4 |
				sed -n 's/\(attr\_data\=\)/\1/p' |
				cut -f 3 -d '=' |
				sed s/[[:space:]]//g
		)

		echo "Bridge port config data: $me47_tp_type, $me47_tp_ptr" >>/tmp/collect

		if [ "$me47_tp_type" = "01" ] && [ "$me47_tp_ptr" = "0101" ]; then
			echo "PPTP UNI brige port exists." >>/tmp/collect
			return
		elif [ "$me47_tp_type" = "0b" ]; then
			echo "VEIP bridge port exists." >>/tmp/collect
			return
		fi
	done

	echo "WARNING: No VEIP/PPTP UNI brige port exists." >>/tmp/collect
}

collect() {
	collect_olt_type
	collect_extended_vlan
	collect_bridge
}

get_mib_data_sync() {
	local curr_mib_data_sync
	local prev_mib_data_sync

	if [ ! -e /tmp/mibcounter ]; then
		$omci managed_entity_attr_data_get 2 0 1 |
			cut -f 3 -d '=' |
			sed -n 's/\(attr\_data\=\)/\1/p' |
			sed s/[[:space:]]//g >/tmp/mibcounter
	else
		curr_mib_data_sync=$(
			$omci managed_entity_attr_data_get 2 0 1 |
				cut -f 3 -d '=' |
				sed -n 's/\(attr\_data\=\)/\1/p' |
				sed s/[[:space:]]//g
		)

		prev_mib_data_sync=$(cat /tmp/mibcounter)

		if [ "$curr_mib_data_sync" != "$prev_mib_data_sync" ]; then
			logger -t "[vlanexec]" "MIB data sync: $curr_mib_data_sync ($prev_mib_data_sync)"
			echo "$curr_mib_data_sync" >/tmp/mibcounter
			totalizer_flag=$((totalizer_flag + 1))
		fi
	fi
}

set_me_171() {
	local hw="48575443"
	local alcl="414c434c"
	local zte="5a544547"
	local unset="20202020"

	if [ "$olt_type" = "$unset" ]; then
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
	"$hw")
		set_pptp_uni_bridge
		create_me_171 0
		check_me_171
		;;
	"$alcl")
		set_alcl_uni_bridge
		create_me_171 1
		;;
	"$zte")
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
			totalizer_flag=$((totalizer_flag + 1))
		fi
	else
		curr_us_vlan_id=$($uci get 8311.config.us_vlan_id 2>&-)
		prev_us_vlan_id=$(cat /tmp/us_vlan_data)

		if [ "$curr_us_vlan_id" != "$prev_us_vlan_id" ]; then
			logger -t "[vlanexec]" "Detected change to us_vlan_id."
			echo "$curr_us_vlan_id" >/tmp/us_vlan_data
			totalizer_flag=$((totalizer_flag + 1))
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
			sed -r 's/(..)/0x\1/g' |
			sed -r 's/(....)/ \1/g'
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
			totalizer_flag=$((totalizer_flag + 1))
		fi
	elif [ ! -e /tmp/us_mc_vid_data ]; then
		if [ -n "$us_mc_vid" ]; then
			echo "$us_mc_vid" >/tmp/us_mc_vid_data
			totalizer_flag=$((totalizer_flag + 1))
		fi
	else

		curr_ds_mc_tci=$($uci -q get 8311.config.ds_mc_tci)
		prev_ds_mc_tci=$(cat /tmp/ds_mc_tci_data)
		curr_us_mc_vid=$($uci -q get 8311.config.us_mc_vid)
		prev_us_mc_vid=$(cat /tmp/us_mc_vid_data)

		if [ "$curr_ds_mc_tci" != "$prev_ds_mc_tci" ]; then
			logger -t "[vlanexec]" "Detected change to ds_mc_tci."
			echo "$curr_ds_mc_tci" >/tmp/ds_mc_tci_data
			totalizer_flag=$((totalizer_flag + 1))
		fi

		if [ "$curr_us_mc_vid" != "$prev_us_mc_vid" ]; then
			logger -t "[vlanexec]" "Detected change to us_mc_vid."
			echo "$curr_us_mc_vid" >/tmp/us_mc_vid_data
			totalizer_flag=$((totalizer_flag + 1))
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
			message=$(cat "Detected multicast GEM interworking TP, multicast GEM port id: " \
				"$gem_port_id, configuring...")
			logger -t "[vlan]" "$message"
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
			if [ -n "$vlan_a" ] && [ -n "$vlan_b" ]; then
				echo "$vlan_a" >"/tmp/vlan$vlan_a_seq"
				echo "$vlan_b" >"/tmp/vlan$vlan_b_seq"
				totalizer_flag=$((totalizer_flag + 1))
			fi
		else
			prev_vlan_a=$(cat "/tmp/vlan$vlan_a_seq")
			prev_vlan_b=$(cat "/tmp/vlan$vlan_b_seq")

			if [ "$vlan_a" != "$prev_vlan_a" ] || [ "$vlan_b" != "$prev_vlan_b" ]; then
				logger -t "[vlanexec]" "Change detected for VLAN translation $i: vlan$vlan_a_seq:vlan$vlan_b_seq $vlan_a:$vlan_b ($prev_vlan_a:$prev_vlan_b)."
				delete_vlan_translation "$prev_vlan_a"
				echo "$vlan_a" >"/tmp/vlan$vlan_a_seq"
				echo "$vlan_b" >"/tmp/vlan$vlan_b_seq"
				totalizer_flag=$((totalizer_flag + 1))
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
			treatment_inner_word="0x00 0x0f 0x00 0x00"
		fi

		vlan_tagging_op="f8 00 00 00 $filter_inner_word 00 40 0f 00 00 $treatment_inner_word"

		vlan_tagging_op_hex=$(
			echo "$vlan_tagging_op" |
				sed s/[[:space:]]//g |
				sed -r 's/(..)/0x\1/g' |
				sed -r 's/(....)/ \1/g'
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
	local me47_instances
	local me47_tp_type
	local me47_tp_ptr
	local message
	local spanning_tree

	me47_instances=$(
		$omci mib_dump | grep "Bridge port config data" |
			sed -n 's/\(0x\)/\1/p' |
			cut -f 3 -d '|' |
			cut -f 1 -d '(' |
			sed s/[[:space:]]//g
	)

	spanning_tree=$(
		$omci managed_entity_attr_data_get 45 1 1 |
			sed -n 's/\(attr\_data\=\)/\1/p' |
			cut -f 3 -d '=' |
			sed s/[[:space:]]//g
	)

	if [ -n "$vlan_svc_log" ]; then
		logger -t "[vlan]" "ME 47 instances: $me47_instances"
	fi

	for i in $me47_instances; do
		me47_tp_type=$(
			$omci managed_entity_attr_data_get 47 "$i" 3 |
				sed -n 's/\(attr\_data\=\)/\1/p' |
				cut -f 3 -d '=' |
				sed s/[[:space:]]//g
		)

		me47_tp_ptr=$(
			$omci managed_entity_attr_data_get 47 "$i" 4 |
				sed -n 's/\(attr\_data\=\)/\1/p' |
				cut -f 3 -d '=' |
				sed s/[[:space:]]//g
		)

		if [ "$me47_tp_type" = "01" ] && [ "$me47_tp_ptr" = "0101" ]; then
			if [ -n "$vlan_svc_log" ]; then
				logger -t "[vlan]" "PPTP UNI bridge port exists with instance id: $i"
			fi

			pptp_uni_bridge=$i

			$omci managed_entity_attr_data_set 47 "$i" 3 1
			$omci managed_entity_attr_data_set 47 "$i" 4 01 01
			$omci managed_entity_attr_data_set 47 "$i" 7 "$spanning_tree"

			return
		fi
	done

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
		message="No PPTP UNI bridge port detected, creating with instance id 1."
		logger -t "[vlan]" "$message"
	fi

	$omci managed_entity_create 47 1 "$bridge_instance" 1 1 257 0 1 \
		"$(echo "$spanning_tree" | cut -c 2-3)" 1 1

	pptp_uni_bridge=1
}

rollback_mib_data_sync() {
	local mib_data_sync

	mib_data_sync=$(
		$omci managed_entity_attr_data_get 2 0 1 |
			sed -n 's/\(attr\_data\=\)/\1/p' |
			cut -f 3 -d '=' |
			sed s/[[:space:]]//g
	)

	mib_data_sync=$(printf "%x" "$((0x$mib_data_sync - 0x3))")

	$omci managed_entity_attr_data_set 2 0 1 "$mib_data_sync"

	if [ -n "$vlan_svc_log" ]; then
		logger -t "[vlan]" "MIB data sync: $mib_data_sync."
	fi
}

create_me_171() {
	local me171_associated_me_ptr
	local create_flag
	local instance_id
	local me171_instances
	local me171_instance_count
	local me47_instance_id
	local original
	local replacment

	create_flag=$1

	me171_instances=$(
		$omci mib_dump |
			grep "Extended VLAN conf data" |
			sed -n 's/\(0x\)/\1/p' |
			cut -f 3 -d '|' |
			cut -f 1 -d '(' |
			sed s/[[:space:]]//g
	)

	me171_instance_count=$(
		$omci mib_dump |
			grep -c "Extended VLAN conf data"
	)

	if [ "$me171_instance_count" -gt 1 ]; then
		for i in $me171_instances; do
			me171_associated_me_ptr=$(
				$omci managed_entity_attr_data_get 171 "$i" 7 |
					sed -n 's/\(attr\_data\=\)/\1/p' |
					sed s/[[:space:]]//g
			)

			if [ "$me171_associated_me_ptr" = "0101" ]; then
				me171_instance_id=$i
				if [ -n "$vlan_svc_log" ]; then
					logger -t "[vlan]" "ME 171 exists with instance id: $me171_instance_id"
				fi
				break
			fi
		done
	else
		me171_instance_id=$me171_instances
	fi

	me47_instance_id=$pptp_uni_bridge

	case $create_flag in
	0)
		if [ -z "$me171_instance_id" ] && [ -n "$vlan_svc_log" ]; then
			logger -t "[vlan]" "ME 171 instance id should not be null."
		fi
		;;
	1)
		if [ -z "$me171_instance_id" ]; then
			# new create me171,untag discard,tag transparent
			instance_id=$(
				printf "%04x" "$((me47_instance_id))" |
					sed 's/../& /g' |
					sed 's/[ ]*$//g'
			)

			original=$(
				sed -n '2p' /etc/me171 |
					cut -c 43-50
			)

			replacment="ab $instance_id"

			sed -i "s/$original/$replacment/" /etc/me171
			$omci_simulate /etc/me171
			sleep 5
			rollback_mib_data_sync

			if [ -n "$vlan_svc_log" ]; then
				logger -t "[vlan]" "Creating ME 171 with instance id: $me47_instance_id"
			fi

			me171_instance_id=$me47_instance_id
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
	local me47_instances
	local me47_tp_type
	local me47_tp_ptr
	local spanning_tree

	me47_instances=$(
		$omci mib_dump |
			grep "Bridge port config data" |
			sed -n 's/\(0x\)/\1/p' |
			cut -f 3 -d '|' |
			cut -f 1 -d '(' |
			sed s/[[:space:]]//g
	)

	spanning_tree=$(
		$omci managed_entity_attr_data_get 45 1 1 |
			sed -n 's/\(attr\_data\=\)/\1/p' |
			cut -f 3 -d '=' |
			sed s/[[:space:]]//g
	)

	for i in $me47_instances; do
		me47_tp_type=$(
			$omci managed_entity_attr_data_get 47 "$i" 3 |
				sed -n 's/\(attr\_data\=\)/\1/p' |
				cut -f 3 -d '=' |
				sed s/[[:space:]]//g
		)

		me47_tp_ptr=$(
			$omci managed_entity_attr_data_get 47 "$i" 4 |
				sed -n 's/\(attr\_data\=\)/\1/p' |
				cut -f 3 -d '=' |
				sed s/[[:space:]]//g
		)

		if [ "$me47_tp_type" = "01" ] && [ "$me47_tp_ptr" = "0101" ]; then
			if [ -n "$vlan_svc_log" ]; then
				logger -t "[vlan]" "PPTP UNI bridge port exists with instance id: $i"
			fi

			if [ -n "$force_me_create" ]; then
				$omci managed_entity_attr_data_set 47 "$i" 3 1
				$omci managed_entity_attr_data_set 47 "$i" 4 01 01
			fi

			$omci managed_entity_attr_data_set 47 "$i" 7 "$spanning_tree"

			pptp_uni_bridge=$i

			return
		elif [ "$me47_tp_type" = "0b" ]; then
			if [ -n "$vlan_svc_log" ]; then
				logger -t "[vlan]" "VEIP bridge port exists with instance id: $i"
			fi

			$omci managed_entity_attr_data_set 47 "$i" 3 1
			$omci managed_entity_attr_data_set 47 "$i" 4 01 01
			$omci managed_entity_attr_data_set 47 "$i" 7 "$spanning_tree"

			pptp_uni_bridge=$i

			return
		fi
	done
}

check_me_171() {
	local current_single_tag_value
	local current_double_tag_value
	local vlan_tagging_op
	local vlan_tagging_ops_num

	local single_tag_value="0xf80x000x000x000xe80x000x000x000x000x0f0x000x000x000x0f0x000x00"
	local double_tag_value="0xe80x000x000x000xe80x000x000x000x000x0f0x000x000x000x0f0x000x00"

	current_single_tag_value=$(
		$omci managed_entity_get 171 "$me171_instance_id" |
			grep "0xf8 0x00 0x00 0x00 0xe8" |
			tail -n 1 |
			sed s/[[:space:]]//g
	)

	current_double_tag_value=$(
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
			logger -t "[vlan]" "ME 171 VLAN tagging operation: $vlan_tagging_op"
		done
	fi

	if [ -n "$force_me_create" ] ||
		{ [ "$current_single_tag_value" != "$single_tag_value" ] ||
			[ "$current_double_tag_value" != "$double_tag_value" ]; }; then
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
					if [ $log_flag -lt 1 ]; then
						logger -t "[vlanexec]" "WARNING: max_reboot_delay_intervals and/or max_reboots is not set, waiting..."
						log_flag=$((log_flag + 1))
					fi
					rest
				else
					logger -t "[vlanexec]" "reboot_on_association_fail enabled, current reboot delay interval: $reboot_delay_interval, waiting for reboot..."
					delay_reboot
				fi
			fi
		elif [ "$los_state" = "1" ]; then
			if [ $log_flag -lt 1 ]; then
				logger -t "[vlanexec]" "WARNING: Loss of Signal detected, waiting..."
				log_flag=$((log_flag + 1))
			fi
			rest
		else
			if [ $log_flag -lt 1 ]; then
				logger -t "[vlanexec]" "reboot_delay_interval not enabled or max_reboots reached, current reboots count: $reboots_count, giving up..."
				log_flag=$((log_flag + 1))
			fi
			rest
		fi
	else
		if [ $state_flag -le 20 ]; then
			state_flag=$((state_flag + 1))
		fi

		ploam_state=$(get_ploam_state)

		if [ "$ploam_state" = "5" ]; then
			if [ $collect_flag -lt 2 ]; then
				collect
				collect_flag=$((collect_flag + 1))
			fi

			reset_log_flag
			reset_reboot_delay
			reset_reboot_attempt
			get_mib_data_sync
			check_onu_fsm_o5
			check_onu_rx_msg_lost

			check_us_vlan
			check_mc_vlans
			check_vlan_translations

			if [ $init_flag -lt 5 ]; then
				set_me_171
				set_us_vlan
				set_mc_vlans
				set_n_to_1_vlan
				set_vlan_translations
				init_flag=$((init_flag + 1)) # this is only incremented here
			elif [ $totalizer_flag -ge 1 ]; then
				set_me_171
				set_us_vlan
				set_mc_vlans
				set_n_to_1_vlan
				set_vlan_translations
				totalizer_flag=0
			fi

			rest
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
