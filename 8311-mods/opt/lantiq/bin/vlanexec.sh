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
otop="/opt/lantiq/bin/otop"
optic="/opt/lantiq/bin/optic"
initflag=0
totalizerflag=0
collectflag=0
stateflag=0
logflag=0
reboot_wait_interval=0
reboots_count=$(cat /tmp/reboots_count 2>&-)
tryreboot=$($uci -q get 8311.config.tryreboot)
max_reboot_wait_intervals=$($uci -q get 8311.config.totalrebootwait)
max_reboots=$($uci -q get 8311.config.max_reboots)
rebootlog=$($uci -q get 8311.config.rebootlog)

us_vlan_id=$($uci -q get 8311.config.us_vlan_id)
n_to_1_vlan=$($uci -q get 8311.config.n_to_1_vlan)
vlan_tag_ops=$($uci -q get 8311.config.vlan_tag_ops)
ds_mc_tci=$($uci -q get 8311.config.ds_mc_tci)
us_mc_vlan_id=$($uci -q get 8311.config.us_mc_vlan_id)
igmp_version=$($uci -q get 8311.config.igmp_version)
force_me_create=$($uci -q get 8311.config.force_me_create)
force_me309_create=$($uci -q get 8311.config.force_me309_create)
force_us_vlan_id=$($uci -q get 8311.config.force_us_vlan_id)
vlan_svc_log=$($uci -q get 8311.config.vlan_svc_log)

ploam_state_get() {
	$onu ploam_state_get |
	cut -b 24
}

reboottry() {
	if [ "$reboots_count" -lt "$max_reboots" ]; then
		if [ "$rebootlog" = "1" ]; then
			/opt/lantiq/bin/debug
			cp /tmp/log/one_click /root
		fi

		let reboots_count++

		fw_setenv reboottry "$reboots_count"
		fw_setenv rebootcause 1
		
		reboot -f
		exit 0
	fi
}

resetreboottry() {
	fw_setenv reboottry 0
}

reboot_wait() {
	if [ "$reboot_wait_interval" -lt "$max_reboot_wait_intervals" ] &&
			[ "$reboots_count" -lt "$max_reboots" ]; then
		let reboot_wait_interval++
		rest
	fi
}

reset_reboot_wait() {
	reboot_wait_interval=0
}

resetlogflag() {
	logflag=0
}

oltstatus1() {
	local prev_status
	local curr_status

	if [ ! -f /tmp/oltstatus1 ]; then
		touch /tmp/oltstatus1
	fi

	prev_status=$(cat /tmp/oltstatus1)
	curr_status=$(dmesg | grep -c "FSM O5")

	if [ "$prev_status" != "$curr_status" ]; then
		logger -t "[vlanexec]" "FSM O5 detected ..."
		let totalizerflag++
	fi

	echo "$curr_status" >/tmp/oltstatus1
}

oltstatus2() {
	local prev_status
	local curr_status
	
	if [ ! -f /tmp/oltstatus2 ]; then
		touch /tmp/oltstatus2
	fi

	prev_status=$(cat /tmp/oltstatus2)
	curr_status=$(dmesg | grep -c "PLOAM Rx - message lost")

	if [ "$prev_status" != "$curr_status" ]; then
		logger -t "[vlanexec]" "PLOAM Rx - message lost detected ..."
		let totalizerflag++
	fi
	
	echo "$curr_status" >/tmp/oltstatus2
}

rest() {
	local time

	if [ $stateflag -lt 20 ]; then
		time=5
	else
		time=15
	fi
	sleep $time
}


resetparameter() {
	initflag=0
	totalizerflag=0
	stateflag=0
	vlanflag=0

	[ -e /tmp/uvlandata ] && rm -f /tmp/uvlandata
	[ -e /tmp/mvlandata ] && rm -f /tmp/mvlandata
	[ -e /tmp/mvlansourcedata ] && rm -f /tmp/mvlansourcedata
	[ -e /tmp/mibcounter ] && rm -f /tmp/mibcounter

	tvlanseq=0
	tvlannum=$(\
		echo "$vlan_tag_ops" |
		grep -o ":" |
		grep -c ":")
	
	for i in $(seq 1 "$tvlannum")
	do
		tvlanseqa=$((i + tvlanseq))
		tvlanseq=$i
		tvlanseqb=$((i + tvlanseq))

		if [ -e "/tmp/vlan$tvlanseqa" ] || [ -e "/tmp/vlan$tvlanseqa" ]; then
			rm -f /tmp/vlan$tvlanseqa
			rm -f /tmp/vlan$tvlanseqa
		fi
	done
}

olt_type() {
	for i in $(seq 1 30)
	do
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
			logger -t "[vlanexec]" "olt type and spanning tree not detected, waiting ..."
			sleep 2
		fi
	done

	echo "olt type:$olt_type" >/tmp/collect
}

extendvlan() {
	me171=$(
		$omci mib_dump |
		grep "Extended VLAN conf data" |
		sed -n 's/\(0x\)/\1/p' |
		cut -f 3 -d '|' |
		cut -f 1 -d '(' |
		head -n 1 |
		sed s/[[:space:]]//g
	)
	
	if [ -z "$me171" ]; then
		echo "extendvlan null" >>/tmp/collect  
	else
		echo "extendvlan instance:$me171" >>/tmp/collect
	fi
}

bridgeget() {
	local number
	local me47_tp_type
	local me47_tp_ptr

	number=$(
		$omci mib_dump |
		grep -c "Bridge config data"
	)

	echo "bridge number is: $number" >>/tmp/collect

	for i in $me47_instance_number
	do
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
			echo "pptp uni brige port already created" >>/tmp/collect
			return
		elif [ "$me47_tp_type" = "0b" ]; then
			echo "veip bridge port created" >>/tmp/collect
			return
		fi
	done

	echo "warning: pptp uni brige port or veip bridge port not created!!!!" >>/tmp/collect
}

collect() {
	olt_type
	extendvlan
	bridgeget
} 

mib_data() {
	if [ ! -e /tmp/mibcounter ]; then
		$omci managed_entity_attr_data_get 2 0 1 |
			cut -f 3 -d '=' |
			sed -n 's/\(attr\_data\=\)/\1/p' |
			sed s/[[:space:]]//g >/tmp/mibcounter
	else
		data=$(
			$omci managed_entity_attr_data_get 2 0 1 |
			cut -f 3 -d '=' |
			sed -n 's/\(attr\_data\=\)/\1/p' |
			sed s/[[:space:]]//g
		)

		last=$(cat /tmp/mibcounter)

		if [ "$data" != "$last" ]; then
			logger -t "[vlanexec]" "mib data unsync"
			echo "$data" >/tmp/mibcounter
			let totalizerflag++
		fi
	 fi
}

me_rule_set() {
	hw="48575443"
	alcl="414c434c"
	zte="5a544547"
	other="20202020"

	if [ "$olt_type" = "20202020"  ]; then
		olt_type=$(
			$omci managed_entity_attr_data_get 131 0 1 |
			sed -n 's/\(attr\_data\=\)/\1/p' |
			cut -f 3 -d '=' |
			sed s/[[:space:]]//g
		)

		sed -i '/.*olt\ type*/c\olt\ type:'"$olt_type"'' /tmp/collect
	fi

	if [ -n "$vlan_svc_log" ]; then
		logger -t "[vlan]" "olt type:$olt_type"
	fi

	if [ "$olt_type" = "$hw" ]; then
		me47_pptp_uni_bridge
		me171_create 0
		me171rulecheck
	elif [ "$olt_type" = "$alcl" ]; then
		tp_type_alcl
		me171_create 1
	elif [ "$olt_type" = "$zte" ]; then
		me47_pptp_uni_bridge
		me171_create 1
	else
		me47_pptp_uni_bridge
		me171_create 1
	fi
}

us_vlan_check() {
	if [ ! -e /tmp/uvlandata ]; then
		us_vlan_id=$($uci get 8311.config.us_vlan_id 2>&-)

		if [ -n "$us_vlan_id" ]; then
			echo "$us_vlan_id" >/tmp/uvlandata
			let totalizerflag++
		fi
	else
		uvlandata2=$($uci get 8311.config.us_vlan_id 2>&-)
		ulastdata=$(cat /tmp/uvlandata)
		
		if [ "$uvlandata2" != "$ulastdata" ]; then
			logger -t "[vlanexec]" "us_vlan_id rule changed."
			echo "$uvlandata2" >/tmp/uvlandata
			let totalizerflag++
		fi
	fi
}

us_vlan_set() {
	if [ -z "$us_vlan_id" ]; then
			if [ -n "$vlan_svc_log" ]; then
				logger -t "[vlan]" "no us_vlan_id configed."
			fi
		
			$omci managed_entity_attr_data_set 171 "$me171" 6 f8 00 00 00 f8 00 00 00 c0 0f 00 00 00 0f 00 00
		
			return
	elif [ "$(echo "$us_vlan_id" | grep -c 'u')" != "0" ] && 
		[ "$(echo "$us_vlan_id" | grep -c '^[u]$')" != "1" ]; then
		
		if [ -n "$vlan_svc_log" ]; then
			logger -t "[vlan]" "us_vlan_id $us_vlan_id configuration error."
		fi
		
		return
	elif [ "$(echo "$us_vlan_id" | grep -c 'u')" = "0" ] &&
		[ "$us_vlan_id" -gt 4094 ] || 
		[ "$(echo "$us_vlan_id" | grep -c 'u')" = "0" ] &&
		[ "$(echo "$us_vlan_id" | grep -c '^[1-9][0-9]*$')" = "0" ]; then
		
		if [ -n "$vlan_svc_log" ]; then
			logger -t "[vlan]" "us_vlan_id $us_vlan_id configuration error."
		fi
		
		return
	fi
	
	if [ "$us_vlan_id" = "u" ]; then
		logger -t "[vlan]" "untagged configed."
		match171="f8 00 00 00 f8 00 00 00 00 0f 00 00 00 0f 00 00"
	else
		tmp171=$((us_vlan_id * 8 + 4))
		a171=$(printf "%04x" $tmp171)
		b171=$(echo "$a171" | sed 's/../& /g')
		match171="f8 00 00 00 f8 00 00 00 00 0f 80 00 00 00 $b171"
	fi

	word_171=$(
		echo "$match171" |
		sed s/[[:space:]]//g |
		sed -r 's/(..)/0x\1/g' |
		sed -r 's/(....)/ \1/g'
	)

	flag171=$(
		$omci managed_entity_get 171 "$me171" |
		grep "$word_171"
	)
	
	if [ -n "$flag171" ] && [ -z "$force_us_vlan_id" ]; then
		if [ -n "$vlan_svc_log" ]; then
			logger -t "[vlan]" "us_vlan_id rule match or force us_vlan_id not enabled."
		fi
	else
		if [ -n "$vlan_svc_log" ]; then
				logger -t "[vlan]" "us_vlan_id configuring ..."
		fi
		$omci managed_entity_attr_data_set 171 "$me171" 6 "$match171"
	fi
}

mc_vlans_check() {
	if [ ! -e /tmp/mvlandata ]; then
		if [ -n "$ds_mc_tci" ]; then
			echo "$ds_mc_tci" >/tmp/mvlandata
			let totalizerflag++
		fi
	elif [ ! -e /tmp/mvlansourcedata ]; then
		if [ -n "$us_mc_vlan_id" ]; then
			echo "$us_mc_vlan_id" >/tmp/mvlansourcedata
			let totalizerflag++
		fi
	else
		mvlandata2=$($uci -q get 8311.config.ds_mc_tci)
		mlastdata=$(cat /tmp/mvlandata)
		mvlansourcedata2=$($uci -q get 8311.config.us_mc_vlan_id)
		mlastsourcedata=$(cat /tmp/mvlansourcedata)

		if [ "$mvlandata2" != "$mlastdata" ]; then
			logger -t "[vlanexec]" "ds_mc_tci rule changed."
			echo "$mvlandata2" >/tmp/mvlandata
			let totalizerflag++
		elif [ "$mvlansourcedata2" != "$mlastsourcedata" ]; then
			logger -t "[vlanexec]" "us_mc_vlan_id rule changed."
			echo "$mvlansourcedata2" >/tmp/mvlansourcedata
			let totalizerflag++
		fi
	fi
}

mc_vlans_set() {
	if [ -z "$ds_mc_tci" ]; then
		if [ -n "$vlan_svc_log" ]; then
			logger -t "[vlan]" "no ds_mc_tci configed."
		fi
		return
	elif [ "$ds_mc_tci" -gt 4094 ] ||
		[ "$(echo "$ds_mc_tci" | grep -c '^[1-9][0-9]*$')" = "0" ]; then
		if [ -n "$vlan_svc_log" ]; then
			logger -t "[vlan]" "ds_mc_tci $ds_mc_tci configuration error."
		fi

		return
	else
		me309_create
	fi
	
	a309=$(printf "%04x" "$ds_mc_tci")

	b309=$(
		echo "$a309" |
		sed 's/../& /g'
	)

	match309="04 $b309"

	flag309=$(
		$omci managed_entity_attr_data_get 309 "$me309" 16 2>&- |
		cut -f 3 -d '='
	)

	if [ "$flag309" = "$match309" ]; then
		if [ -n "$vlan_svc_log" ]; then
			logger -t "[vlan]" "ds_mc_tci rule match."
		fi
	else
		if [ -n "$vlan_svc_log" ]; then
			logger -t "[vlan]" "ds_mc_tci configuring."
		fi

		$omci managed_entity_attr_data_set "309 $me309 16 $match309"
	fi

	if [ -z "$us_mc_vlan_id" ]; then
		if [ -n "$vlan_svc_log" ]; then
			logger -t "[vlan]" "no us_mc_vlan_id configured."
		fi

		return
	else
		if [ "$us_mc_vlan_id" -gt 4094 ] ||
			[ "$(echo "$us_mc_vlan_id" | grep -c '^[1-9][0-9]*$')" = "0" ]; then
			if [ -n "$vlan_svc_log" ]; then
				logger -t "[vlan]" "us_mc_vlan_id $us_mc_vlan_id configuration error."
			fi

			return
		fi
	fi

	sa309=$(printf "%04x" "$us_mc_vlan_id")
	sb309=$(echo "$sa309" | sed 's/../& /g')

	muti_gem_tp_instance=$(
		$omci mib_dump |
		grep "Multicast GEM TP" |
		sed -n 's/\(0x\)/\1/p' |
		cut -f 3 -d '|' |
		cut -f 1 -d '(' |
		sed s/[[:space:]]//g
	)
	
	if [ -n "$muti_gem_tp_instance" ]; then
		gpnctp_ptr=$(
			$omci managed_entity_attr_data_get "281 $muti_gem_tp_instance 1" |
			sed -n 's/\(attr\_data\=\)/\1/p' |
			cut -f 3 -d '=' | cut -f 1 -d '(' |
			sed s/[[:space:]]//g
		)
		
		muti_port=$(
			$omci managed_entity_attr_data_get "268 0x$gpnctp_ptr 1" |
			cut -f 3 -d '='
		)

		if [ -n "$vlan_svc_log" ]; then
			logger -t "[vlan]" "got muticast gem tp, muticast port: $muti_port, configuring ..."
		fi

		$omci managed_entity_attr_data_set "309 $me309 7 40 00 $muti_port $sb309 00 00 00 00 e0 00 01 00 ef ff ff ff 00 00 00 00 00 00"
	fi
}

deletetrans() {
	filter_inner_1=$(($1 * 8))
	filter_inner_2=$(printf "%04x" $filter_inner_1)
	patten="0"
	filter_inner_3="8$filter_inner_2$patten"
	word2=$(echo "$filter_inner_3" | sed 's/../& /g')
	wordset="f8 00 00 00 $word2 00 ff ff ff ff ff ff ff ff"
	logger -t "[vlanexec]" "Deleting vlantrans rule $1"
	$omci managed_entity_attr_data_set "171 $me171 6 $wordset"
}

vlantranscheck() {
	tvlannum=$(echo "$vlan_tag_ops" | grep -o ":" | grep -c ":")
	tvlanseq=0

	for i in $(seq 1 "$tvlannum")
	do
		vlana=$(echo "$vlan_tag_ops" | cut -f "$i" -d ',' | cut -f 1 -d ':' | cut -f 1 -d '@')
		vlanb=$(echo "$vlan_tag_ops" | cut -f "$i" -d ',' | cut -f 2 -d ':' | cut -f 1 -d '@')
		tvlanseqa=$((i + tvlanseq))
		tvlanseq=$i
		tvlanseqb=$((i + tvlanseq))

		if [ -e "/tmp/vlan$tvlanseqa" ] && [ -e "/tmp/vlan$tvlanseqb" ]; then
			if [ -n "$vlana" ] && [ -n "$vlanb" ]; then
				echo "$vlana" >"/tmp/vlan$tvlanseqa"
				echo "$vlanb" >"/tmp/vlan$tvlanseqb"
				let totalizerflag++
			fi
		else
			vlana_lastdata=$(cat "/tmp/vlan$tvlanseqa")
			vlanb_lastdata=$(cat "/tmp/vlan$tvlanseqb")
			
			if [ "$vlana" != "$vlana_lastdata" ] || [ "$vlanb" != "$vlanb_lastdata" ]; then
				logger -t "[vlanexec]" "vlantrans$i vlan$tvlanseqa:vlan$tvlanseqb $vlana:$vlanb ($vlana_lastdata:$vlanb_lastdata) changed."
				deletetrans "$vlana_lastdata"
				echo "$vlana" >"/tmp/vlan$tvlanseqa"
				echo "$vlanb" >"/tmp/vlan$tvlanseqb"
				let totalizerflag++
			fi
		fi
	done
}

n_to_1_vlan_set() {
	gem_port_idx=$(
		$gtop -b -g "GPE DS GEM port" |
		awk 'BEGIN{FS=";"} NR>5  {print $1}' |
		sed s/[[:space:]]//g
	)

	if [ "$n_to_1_vlan" = "1" ]; then
		if [ -n "$vlan_svc_log" ]; then
			logger -t "[vlan]" "multi vlan trans enabled."
		fi
		gpe_vlanmode=1
	else
		if [ -n "$vlan_svc_log" ]; then
			logger -t "[vlan]" "multi vlan trans disabled."
		fi
		gpe_vlanmode=0
	fi

	for i in $gem_port_idx
	do
		$onu gpe_vlan_mode_set "$i" 0 "$gpe_vlanmode"
	done
}

vlantransset() {
	tvlannum=$(
		echo "$vlan_tag_ops" |
		grep -o ":" | grep -c ":"
	)

	for i in $(seq 1 "$tvlannum")
	do
		vlana=$(
			echo "$vlan_tag_ops" |
			cut -f "$i" -d ',' |
			cut -f 1 -d ':' |
			cut -f 1 -d '@'
		)

		vlanb=$(
			echo "$vlan_tag_ops" |
			cut -f "$i" -d ',' |
			cut -f 2 -d ':' |
			cut -f 1 -d '@'
		)

		prioritya=$(
			echo "$vlan_tag_ops" |
			cut -f "$i" -d ',' |
			cut -f 1 -d ':' |
			grep '@' |
			cut -f 2 -d "@"
		)
		
		priorityb=$(
			echo "$vlan_tag_ops" |
			cut -f "$i" -d ',' |
			cut -f 2 -d ':' |
			grep '@' |
			cut -f 2 -d "@"
		)
		
		if [ -z "$vlana" ] || [ "$vlana" -gt 4094 ] ||
			[ "$(echo "$vlana" | grep -c '^[1-9][0-9]*$')" = "0" ] ||
			[ -z "$vlanb" ] ||
			[ "$(echo "$vlanb" | grep -c '^[u1-9][0-9]*$')" = "0" ]; then
			if [ -n "$vlan_svc_log" ]; then
				logger -t "[vlan]" "vlantrans$i $vlana:$vlanb configuration error."
			fi
			continue
		elif [ "$(echo "$vlanb" | grep -c 'u')" != "0" ] &&
			[ "$(echo "$vlanb" | grep -c '^[u]$')" != "1" ]; then
			if [ -n "$vlan_svc_log" ]; then
				logger -t "[vlan]" "vlantrans$i $vlana:$vlanb configuration error."
			fi
			continue
		elif [ "$(echo "$vlanb" | grep -c 'u')" = "0" ] && [ "$vlanb" -gt 4094 ]; then
			if [ -n "$vlan_svc_log" ]; then
				logger -t "[vlan]" "vlantrans$i $vlana:$vlanb configuration error."
			fi
			continue
		fi
		
		if [ -n "$prioritya" ] &&
			[ "$(echo "$prioritya" | grep -c '^[0-7]$')" = "0" ] ||
			[ -n "$priorityb" ] && 
			[ "$(echo "$priorityb" | grep -c '^[0-7]$')" = "0" ]; then
			if [ -n "$vlan_svc_log" ]; then
				logger -t "[vlan]" "vlantrans$i $vlana@$prioritya:$vlanb@$priorityb priority configuration error."
			fi
			continue
		fi

		if [ -z "$prioritya" ]; then
			prioritya=8
		fi

		if [ -z "$priorityb" ]; then
			priorityb=8
		fi
		
		filter_inner_1=$((vlana * 8))
		filter_inner_2=$(printf "%04x" "$filter_inner_1")
		patten="0"
		filter_inner_3="$prioritya$filter_inner_2$patten"
		word2=$(echo "$filter_inner_3" | sed 's/../& /g')
		treate_inner_1=$((vlanb * 8))
		treate_inner_2=$(printf "%04x" "$treate_inner_1")
		treate_inner_3=$(echo "$treate_inner_2" | sed 's/../& /g')
		word4="00 0$priorityb $treate_inner_3"

		if [ "$vlanb" = "u" ]; then
			word4="0x00 0x0f 0x00 0x00"
		fi

		wordset="f8 00 00 00 $word2 00 40 0f 00 00 $word4"
		
		word_c=$(
			echo "$wordset" |
			sed s/[[:space:]]//g |
			sed -r 's/(..)/0x\1/g' |
			sed -r 's/(....)/ \1/g'
		)
		
		wordget=$(
			$omci managed_entity_get 171 "$me171" |
			grep "$word_c"
		)
		
		if [ -n "$wordget" ];then
			if [ -n "$vlan_svc_log" ]; then
				logger -t "[vlan]" "vlantrans$i $vlana:$vlanb rule match."
			fi
		else
			if [ -n "$vlan_svc_log" ]; then
				logger -t "[vlan]" "vlantrans$i $vlana:$vlanb configuring ..."
			fi
			$omci managed_entity_attr_data_set 171 "$me171 6 $wordset"
		fi
	done
}

me47_pptp_uni_bridge() {
	local me47_instance_number
	local spanning_tree
	local me47_tp_type
	local me47_tp_ptr
	local bridge_instance
	
	me47_instance_number=$(
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
		logger -t "[vlan]" "me47_instance_number: $me47_instance_number"
	fi

	for i in $me47_instance_number
	do
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
				logger -t "[vlan]" "pptp uni bridge port: $i existed."
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

	if [ -n "$me47_tp_type" ];then
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
		logger -t "[vlan]" "no pptp uni bridge port, creating it and instance is fixed 1."
	fi

	$omci managed_entity_create 47 1 "$bridge_instance" 1 1 257 0 1 "${spanning_tree:1:2}" 1 1

	pptp_uni_bridge=1
}

me_counter() {
	current=$(
		$omci managed_entity_attr_data_get 2 0 1 |
		sed -n 's/\(attr\_data\=\)/\1/p' |
		cut -f 3 -d '=' |
		sed s/[[:space:]]//g
	)
	
	current_1=0x$current
	current_2=$(printf "0x%x" "$current_1")
	current_3=$(awk 'BEGIN{printf("%#x",'"$current_2"'-3)}')
	current_4=$(printf "%x" "$current_3")
	
	$omci managed_entity_attr_data_set 2 0 1 "$current_4"

	if [ -n "$vlan_svc_log" ]; then
		logger -t "[vlan]" "meconunter: $current_4 ."
	fi
}

me171_create() {
	createflag=$1
	
	me171=$(
		$omci mib_dump |
		grep "Extended VLAN conf data" |
		sed -n 's/\(0x\)/\1/p' |
		cut -f 3 -d '|' |
		cut -f 1 -d '(' |
		head -n 1 |
		sed s/[[:space:]]//g
	)

	me171_line=$(
		$omci mib_dump |
		grep -c "Extended VLAN conf data"
	)

	if [ "$me171_line" -gt 1 ]; then
		for i in $me171
		do
			Associated_ME_ptr=$(
				$omci managed_entity_attr_data_get 171 "$i" 7 |
				sed -n 's/\(attr\_data\=\)/\1/p' |
				sed s/[[:space:]]//g
			)

			if [ "$Associated_ME_ptr" = "0101" ]; then
				me171=$i
				if [ -n "$vlan_svc_log" ]; then
					logger -t "[vlan]" "me171 value: $me171"
				fi
				break
			fi
		done
	fi

	me47_instance=$pptp_uni_bridge

	case $createflag in
		0)  if [ -z "$me171" ] && [ -n "$vlan_svc_log" ]; then
				logger -t "[vlan]" "me171 value should not be null."
			fi
		;;
		1)  if [ -z "$me171" ]; then
				# new create me171,untag discard,tag transparnet
				me171_instance_1=$me47_instance
				me171_instance_2=$(printf "%04x" "$me171_instance_1")

				me171_instance_3=$(
					echo "$me171_instance_2" |
					sed 's/../& /g' |
					sed 's/[ ]*$//g'
				)

				source=$(
					sed -n '2p' /etc/me171 |
					cut -c 43-50
				)
				
				dst="ab $me171_instance_3"
				
				sed -i "s/$source/$dst/" /etc/me171
				$omci_simulate /etc/me171
				sleep 5
				me_counter

				if [ -n "$vlan_svc_log" ]; then
					logger -t "[vlan]" "me171 value: $me47_instance, creating ..."
				fi

				me171=$me47_instance
			fi
		;;
		*)  if [ -n "$vlan_svc_log" ]; then
				logger -t "[vlan]" "create me171 value error."
			fi
		;;
	esac
}

me309_create() {
	me309=$(
		$omci mib_dump |
		grep 309 |
		sed -n 's/\(0x\)/\1/p' |
		cut -f 3 -d '|' |
		cut -f 1 -d '(' |
		head -n 1 |
		sed s/[[:space:]]//g
	)
	
	me309line=$(
		$omci mib_dump |
		grep -c 309
	)

	if [ -z "$me309" ] ||
		[ -n "$force_me309_create" ] &&
			[ "$me309line" != "2" ]; then
		
		if [ -n "$vlan_svc_log" ]; then
			logger -t "[vlan]" "creating me309 ..."
		fi

		if [ -z "$igmp_version" ]; then
			igmp_version=3
		fi

		me309=$pptp_uni_bridge

		$omci managed_entity_create 309 "$me309" "$igmp_version" 0 1 0 0 32
		$omci managed_entity_attr_data_set 309 "$me309" 10 02
		$omci managed_entity_attr_data_set 309 "$me309" 12 00 00 00 7d
		$omci managed_entity_attr_data_set 309 "$me309" 13 00 00 00 64
		$omci managed_entity_attr_data_set 309 "$me309" 15 01
		$omci managed_entity_create 310 "$me309" 0 "$me309" 64 0 1
		$omci managed_entity_create 311 "$me309" 0
		sleep 5
	else
		if [ -n "$vlan_svc_log" ]; then
			logger -t "[vlan]" "me309 rule existed."
		fi
		$omci managed_entity_attr_data_set 309 "$me309" 1 "0$igmp_version"
	fi
}

tp_type_alcl() {
	local me47_instance_number
	local spanning_tree
	local me47_tp_type
	local me47_tp_ptr

	me47_instance_number=$(
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

	for i in $me47_instance_number
	do
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
				logger -t "[vlan]" "pptp uni bridge port: $i existed."
			fi

			if [ -n "$force_me_create" ]; then
				$omci managed_entity_attr_data_set 47 "$i" 3 1
				$omci managed_entity_attr_data_set 47 "$i" 4 01 01
			fi

			$omci managed_entity_attr_data_set 47 "$i" 7 "$spanning_tree"

			pptp_uni_bridge=$i

			return
		elif [ "$me47_tp_type" = "0b" ]; then
			$omci managed_entity_attr_data_set 47 "$i" 3 1
			$omci managed_entity_attr_data_set 47 "$i" 4 01 01
			$omci managed_entity_attr_data_set 47 "$i" 7 "$spanning_tree"

			pptp_uni_bridge=$i

			return
		fi
	done
}

me171rulecheck() {
	local single_tag_value
	local double_tag_value
	local current_single_tag_value
	local current_double_tag_value
	local rule_line
	local rule

	single_tag_value="0xf80x000x000x000xe80x000x000x000x000x0f0x000x000x000x0f0x000x00"
	double_tag_value="0xe80x000x000x000xe80x000x000x000x000x0f0x000x000x000x0f0x000x00"

	current_single_tag_value=$(
		$omci managed_entity_get 171 "$me171" | 
		grep "0xf8 0x00 0x00 0x00 0xe8" |
		tail -n 1 | 
		sed s/[[:space:]]//g
	)

	current_double_tag_value=$(
		$omci managed_entity_get 171 "$me171" | 
		grep "0xe8 0x00 0x00 0x00 0xe8" |	
		tail -n 1 |
		sed s/[[:space:]]//g
	)

	$omci managed_entity_get 171 "$me171" |
		sed -n '/^ 5 RX frame VLAN table/,$p' |
		sed '/^ 6 Associated ME ptr/,$d' |
		grep '^   0x' |
		grep -v "0xf8 0x00 0x00 0x00 0xe8" |
		grep -v "0xe8 0x00 0x00 0x00 0xe8" |
		sed 's/^   //g' |
		sed 's/0x//g' >/tmp/me171_rule
	
	rule_line=$(
		$omci managed_entity_get 171 1 |
		sed -n '/^ 5 RX frame VLAN table/,$p' |
		sed '/^ 6 Associated ME ptr/,$d' |
		grep '^   0x' |
		grep -v "0xf8 0x00 0x00 0x00 0xe8" |
		grep -vc "0xf8 0x00 0x00 0x00 0xe8"
	)

	rule=$(tail -n "$i" /tmp/me171_rule | head -n 1)
	
	if [ "$rule_line" -ge 1 ] && [ -n "$vlan_svc_log" ]; then
		for i in $(seq 1 "$rule_line")
		do
			logger -t "[vlan]" "me171 rule: $rule"
		done
	fi

	if [ "$current_single_tag_value" != "$single_tag_value" ] ||
		[ "$current_double_tag_value" != "$double_tag_value" ] ||
		[ -n "$force_me_create" ]; then

		if [ -n "$vlan_svc_log" ]; then
			logger -t "[vlan]" "defualt rule not match or force_me_create enabled, creating ..."
		fi

		$omci managed_entity_attr_data_set 171 "$me171" 6 f8 00 00 00 e8 00 00 00 00 0f 00 00 00 0f 00 00
		$omci managed_entity_attr_data_set 171 "$me171" 6 e8 00 00 00 e8 00 00 00 00 0f 00 00 00 0f 00 00
		
		if [ "$rule_line" -ge 1 ]; then
			for i in $(seq 1 "$rule_line")
			do
				$omci managed_entity_attr_data_set 171 "$me171" 6 "$rule"
			done
		fi
	fi
}

main() {
	ploam_state=$(ploam_state_get)

	signal_state=$(
		$optic bosa_rx_status_get |
		cut -f 8 -d ' ' |
		cut -f 2 -d '=' |
		sed s/[[:space:]]//g
	)

	if [ "$ploam_state" != "5" ]; then
		resetparameter

		if [ "$tryreboot" = "1" ] && [ -n "$max_reboot_wait_intervals" ] &&
			[ -n "$max_reboots" ] && [ "$signal_state" != "1" ] &&
				[ "$reboots_count" -lt "$max_reboots" ]; then

			if [ "$reboot_wait_interval" -eq "$max_reboot_wait_intervals" ]; then
				logger -t "[vlanexec]" "reboot try enabled, total reboot wait times reached, current reboot try times: $reboots_count, rebooting ..."
				reboottry
			else
				if [ -z "$max_reboot_wait_intervals" ] || [ -z "$max_reboots" ]; then
					if [ $logflag -lt 1 ]; then
						logger -t "[vlanexec]" "rebootwait($max_reboot_wait_intervals) or reboottry($max_reboots) not set, waiting ..."
						let logflag++
					fi
					rest
				else
					logger -t "[vlanexec]" "reboot try enabled, current reboot wait times: $reboot_wait_interval, waiting for reboot ..."
					reboot_wait
				fi
			fi
		elif [ "$signal_state" = "1" ]; then
			if [ $logflag -lt 1 ]; then
				logger -t "[vlanexec]" "current loss_of_signal state: $signal_state, waiting ..."
				let logflag++
			fi
			rest
		else
			if [ $logflag -lt 1 ]; then
				logger -t "[vlanexec]" "reboot try not enabled or total reboot trys reached, current reboot try times: $reboots_count, giving up ..."
				let logflag++
			fi
			rest
		fi
	else
		if [ $stateflag -le 20 ]; then
			let stateflag++
		fi

		ploam_state=$(ploam_state_get)

		if [ "$ploam_state" = "5" ]; then
			if [ $collectflag -lt 2 ]; then
				collect
				let collectflag++
			fi

			resetlogflag
			reset_reboot_wait
			resetreboottry
			mib_data
			oltstatus1
			oltstatus2

			us_vlan_check
			mc_vlans_check
			vlantranscheck

			if [ $initflag -lt 5 ]; then
				me_rule_set
				us_vlan_set
				mc_vlans_set
				n_to_1_vlan_set
				vlantransset
				let initflag++
			elif [ $totalizerflag -ge 1 ]; then
				me_rule_set
				us_vlan_set
				mc_vlans_set
				n_to_1_vlan_set
				vlantransset
				totalizerflag=0
			fi

			rest

		fi
	fi
}

mibdatacheck() {
	while true
	do
		main
	done 
}

mibdatacheck
# Script end
