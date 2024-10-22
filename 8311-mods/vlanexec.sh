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
rebootwaitnum=0
reboottrynum=`cat /tmp/reboottrynum 2>&-`
tryreboot=`$uci -q get gpon.onu.tryreboot`
totalrebootwait=`$uci -q get gpon.onu.totalrebootwait`
totalreboottry=`$uci -q get gpon.onu.totalreboottry`
rebootlog=`$uci -q get gpon.onu.rebootlog`

uvlan=`$uci -q get gpon.onu.uvlan`
mtvlan=`$uci -q get gpon.onu.mtvlan`
tvlan=`$uci -q get gpon.onu.tvlan`
mvlan=`$uci -q get gpon.onu.mvlan`
mvlansource=`$uci -q get gpon.onu.mvlansource`
igmpversion=`$uci -q get gpon.onu.igmp_version`
forcemerule=`$uci -q get gpon.onu.forcemerule`
forceme309=`$uci -q get gpon.onu.forceme309`
forceuvlan=`$uci -q get gpon.onu.forceuvlan`
vlandebug=`$uci -q get gpon.onu.vlandebug`

status() {
	ploamstate=`$onu ploamsg | cut -b 24`
	echo $ploamstate
}

reboottry() {
	if [ $reboottrynum -lt $totalreboottry ]; then
		if [ "$rebootlog" == "1" ]; then
			/opt/lantiq/bin/debug
			cp /tmp/log/one_click /root
		fi
		let reboottrynum++
		fw_setenv reboottry $reboottrynum
		fw_setenv rebootcause 1
		reboot -f
		exit 0
	fi
}

resetreboottry() {
	fw_setenv reboottry 0
}

rebootwait() {
	if [ $rebootwaitnum -lt $totalrebootwait ] && [ $reboottrynum -lt $totalreboottry ]; then
		let rebootwaitnum++
		rest
	fi
}

resetrebootwarit() {
	rebootwaitnum=0
}

resetlogflag() {
	logflag=0
}

oltstatus1() {
	if [ ! -f /tmp/oltstatus1 ]; then
		touch /tmp/oltstatus1
	fi
	oltlast1=`cat /tmp/oltstatus1`
	oltstatus1=`dmesg | grep -c "FSM O5"`
	if [ "$oltlast1" != "$oltstatus1" ]; then
		logger -t "[vlanexec]" "FSM O5 detected ..."
		let totalizerflag+
	fi
	echo $oltstatus1 > /tmp/oltstatus1
}

oltstatus2() {
	if [ ! -f /tmp/oltstatus2 ]; then
		touch /tmp/oltstatus2
	fi
	oltlast2=`cat /tmp/oltstatus2`
	oltstatus2=`dmesg | grep -c "PLOAM Rx - message lost"`
	if [ "$oltlast2" != "$oltstatus2" ]; then
		logger -t "[vlanexec]" "PLOAM Rx - message lost detected ..."
		let totalizerflag++
	fi
	echo $oltstatus2 > /tmp/oltstatus2
}

rest() {
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
	uvlandata=`ls /tmp | grep uvlandata`
	if [ -n "$uvlandata" ]; then
		rm -f /tmp/uvlandata
	fi
	mvlandata=`ls /tmp | grep mvlandata`
	if [ -n "$mvlandata" ]; then
		rm -f /tmp/mvlandata
	fi
	mvlansourcedata=`ls /tmp | grep mvlansourcedata`
	if [ -n "$mvlansourcedata" ]; then
		rm -f /tmp/mvlansourcedata
	fi
	mibcounter=`ls /tmp | grep mibcounter`
	if [ -n "$mibcounter" ]; then
		rm -f /tmp/mibcounter
	fi
	tvlannum=$(echo "$tvlan" | grep -o ":" | grep -c ":")
	tvlanseq=0
	for i in $(seq 1 $tvlannum)
	do
		tvlanseqa=$(expr $i \+ $tvlanseq)
		tvlanseq=$i
		tvlanseqb=$(expr $i \+ $tvlanseq)
		vlantransdata=`ls /tmp | grep vlan$tvlanseqa || ls /tmp | grep vlan$tvlanseqb`
		if [ -n "$vlantransdata" ]; then
			rm -f /tmp/vlan$tvlanseqa
			rm -f /tmp/vlan$tvlanseqa
		fi
	done
}

olttype() {
	for i in `seq 1 30`
	do
		olt_type=`$omci meadg 131 0 1 | sed -n 's/\(attr\_data\=\)/\1/p' | cut -f 3 -d '=' | sed s/[[:space:]]//g`
		spanning_tree=`$omci meadg 45 1 1 | sed -n 's/\(attr\_data\=\)/\1/p' | sed s/[[:space:]]//g`
		if [ "$olt_type" != "20202020" ] && [ -n "$spanning_tree" ]; then
			break
		else
			logger -t "[vlanexec]" "olt type and spanning tree not detected, waiting ..."
			sleep 2
		fi
	done
	echo "olt type:$olt_type"  > /tmp/collect
}

extendvlan() {
	me171=`$omci md | grep "Extended VLAN conf data" | sed -n 's/\(0x\)/\1/p' | cut -f 3 -d '|' | cut -f 1 -d '(' | head -n 1 | sed s/[[:space:]]//g`
	if [ -z "$me171" ]; then
		echo "extendvlan null" >> /tmp/collect  
	else
		echo "extendvlan instance:$me171" >> /tmp/collect
	fi
}

bridgeget() {
	number=`$omci md | grep -c "Bridge config data"`
	echo "bridge number is:$number" >> /tmp/collect
	for i in `echo $me47_instance_number` 
	do
		me47_tptype=`$omci meadg 47 $i 3 | sed -n 's/\(attr\_data\=\)/\1/p' | cut -f 3 -d '=' | sed s/[[:space:]]//g`
		me47_tpptr=`$omci meadg 47 $i 4 | sed -n 's/\(attr\_data\=\)/\1/p' | cut -f 3 -d '=' | sed s/[[:space:]]//g`
		echo "Bridge port config data:$me47_tptype,$me47_tpptr" >> /tmp/collect
		if [ "$me47_tptype" == "01" ] && [ "$me47_tpptr" == "0101" ]; then 
			echo "pptp uni brige port already created" >> /tmp/collect
			return
		elif [ "$me47_tptype" == "0b" ]; then
			echo "veip bridge port created" >> /tmp/collect
			return
		fi
	done
	echo "warning: pptp uni brige port or veip bridge port not created!!!!" >> /tmp/collect
}

collect() {
	olttype
	extendvlan
	bridgeget
} 

mibdata() {
	mibcounter=`ls /tmp | grep mibcounter`
	if [ -z "$mibcounter" ]; then
		data1=`$omci meadg 2 0 1 | cut -f 3 -d '=' | sed -n 's/\(attr\_data\=\)/\1/p' | sed s/[[:space:]]//g > /tmp/mibcounter`
	else
		data2=`$omci meadg 2 0 1 | cut -f 3 -d '=' | sed -n 's/\(attr\_data\=\)/\1/p' | sed s/[[:space:]]//g`
		last=`cat /tmp/mibcounter`
		if [ "$data2" != "$last" ]; then
			logger -t "[vlanexec]" "mib data unsync"
			echo $data2 > /tmp/mibcounter
			let totalizerflag++
		fi
	 fi
}

meruleset() {
	hw="48575443"
	alcl="414c434c"
	zte="5a544547"
	other="20202020"
	if [ "$olt_type" == "20202020"  ]; then
		olt_type=`$omci meadg 131 0 1 | sed -n 's/\(attr\_data\=\)/\1/p' | cut -f 3 -d '=' | sed s/[[:space:]]//g`
		sed -i '/.*olt\ type*/c\olt\ type:'$olt_type'' /tmp/collect
	fi
	if [ -n "$vlandebug" ]; then
		logger -t "[vlan]" "olt type:$olt_type"
	fi
	if [ "$olt_type" == "$hw" ]; then
		me47pptpunibridge
		me171create 0
		me171rulecheck
	elif [ "$olt_type" == "$alcl" ]; then
		tptypealcl
		me171create 1
	elif [ "$olt_type" == "$zte" ]; then
		me47pptpunibridge
		me171create 1
	else
		me47pptpunibridge
		me171create 1
	fi
}

uvlancheck() {
	uvlandata=`ls /tmp | grep uvlandata`
	if [ -z "$uvlandata" ]; then
		uvlan=`$uci get gpon.onu.uvlan 2>&-`
		if [ -n "$uvlan" ]; then
			echo $uvlan > /tmp/uvlandata
			let totalizerflag++
		fi
	else
		uvlandata2=`$uci get gpon.onu.uvlan 2>&-`
		ulastdata=`cat /tmp/uvlandata`
		if [ "$uvlandata2" != "$ulastdata" ]; then
			logger -t "[vlanexec]" "uvlan rule changed."
			echo $uvlandata2 > /tmp/uvlandata
			let totalizerflag++
		fi
	fi
}

uvlanset() {
	if [ -z "$uvlan" ]; then
			if [ -n "$vlandebug" ]; then
				logger -t "[vlan]" "no uvlan configed."
			fi
			$omci meads 171 $me171 6 f8 00 00 00 f8 00 00 00 c0 0f 00 00 00 0f 00 00
			return
	elif [ "`echo $uvlan | grep -c 'u'`" != "0" ] && [ "`echo $uvlan | grep -c '^[u]$'`" != "1" ]; then
		if [ -n "$vlandebug" ]; then
			logger -t "[vlan]" "uvlan $uvlan configuration error."
		fi
		return
	elif [ "`echo $uvlan | grep -c 'u'`" == "0" ] && [ "$uvlan" -gt 4094 ] || [ "`echo $uvlan | grep -c 'u'`" == "0" ] && [ "`echo $uvlan | grep -c '^[1-9][0-9]*$'`" == "0" ]; then
		if [ -n "$vlandebug" ]; then
			logger -t "[vlan]" "uvlan $uvlan configuration error."
		fi
		return
	fi
	if [ "$uvlan" == "u" ]; then
		logger -t "[vlan]" "untagged configed."
		match171="f8 00 00 00 f8 00 00 00 00 0f 00 00 00 0f 00 00"
	else
		tmp171=`expr $uvlan \* 8 + 4`
		a171=`printf "%04x" $tmp171`
		b171=`echo $a171 | sed 's/../& /g'`
		match171="f8 00 00 00 f8 00 00 00 00 0f 80 00 00 00 $b171"
	fi
	word_171=`echo $match171 | sed s/[[:space:]]//g | sed -r 's/(..)/0x\1/g' | sed -r 's/(....)/ \1/g'`
	flag171=`$omci meg 171 $me171 | grep "$word_171"`
	if [ -n "$flag171" ] && [ -z "$forceuvlan" ]; then
		if [ -n "$vlandebug" ]; then
			logger -t "[vlan]" "uvlan rule match or force uvlan not enabled."
		fi
	else
		if [ -n "$vlandebug" ]; then
				logger -t "[vlan]" "uvlan configuring ..."
		fi
		$omci meads 171 $me171 6 $match171
	fi
}

mvlancheck() {
	mvlandata=`ls /tmp | grep mvlandata`
	mvlansourcedata=`ls /tmp | grep mvlansourcedata`
	if [ -z "$mvlandata" ]; then
		if [ -n "$mvlan" ]; then
			echo $mvlan > /tmp/mvlandata
			let totalizerflag++
		fi
	elif [ -z "$mvlansourcedata" ]; then
		if [ -n "$mvlansource" ]; then
			echo $mvlansource > /tmp/mvlansourcedata
			let totalizerflag++
		fi
	else
		mvlandata2=`$uci -q get gpon.onu.mvlan`
		mlastdata=`cat /tmp/mvlandata`
		mvlansourcedata2=`$uci -q get gpon.onu.mvlansource`
		mlastsourcedata=`cat /tmp/mvlansourcedata`
		if [ "$mvlandata2" != "$mlastdata" ]; then
			logger -t "[vlanexec]" "mvlan rule changed."
			echo $mvlandata2 > /tmp/mvlandata
			let totalizerflag++
		elif [ "$mvlansourcedata2" != "$mlastsourcedata" ]; then
			logger -t "[vlanexec]" "mvlansource rule changed."
			echo $mvlansourcedata2 > /tmp/mvlansourcedata
			let totalizerflag++
		fi
	fi
}

mvlanset() {
	if [ -z "$mvlan" ]; then
		if [ -n "$vlandebug" ]; then
			logger -t "[vlan]" "no mvlan configed."
		fi
		return
	elif [ "$mvlan" -gt 4094 ] || [ "`echo $mvlan | grep -c '^[1-9][0-9]*$'`" == "0" ]; then
		if [ -n "$vlandebug" ]; then
			logger -t "[vlan]" "mvlan $mvlan configuration error."
		fi
		return
	else
		me309create
	fi
	a309=`printf "%04x" $mvlan`
	b309=`echo $a309 | sed 's/../& /g'`
	match309="04 $b309"
	flag309=`$omci meadg 309 $me309 16 2>&- | cut -f 3 -d '='`
	if [ "$flag309" == "$match309" ]; then
		if [ -n "$vlandebug" ]; then
			logger -t "[vlan]" "mvlan rule match."
		fi
	else
		if [ -n "$vlandebug" ]; then
			logger -t "[vlan]" "mvlan configuring."
		fi
		$omci meads 309 $me309 16 $match309
	fi
	if [ -z "$mvlansource" ]; then
		if [ -n "$vlandebug" ]; then
			logger -t "[vlan]" "no mvlansource configed."
		fi
		return
	else
		if [ "$mvlansource" -gt 4094 ] || [ "`echo $mvlansource | grep -c '^[1-9][0-9]*$'`" == "0" ]; then
			if [ -n "$vlandebug" ]; then
				logger -t "[vlan]" "mvlansource $mvlansource configuration error."
			fi
			return
		fi
	fi
	sa309=`printf "%04x" $mvlansource`
	sb309=`echo $sa309 | sed 's/../& /g'`
	muti_gem_tp_instance=`$omci md | grep "Multicast GEM TP" | sed -n 's/\(0x\)/\1/p' | cut -f 3 -d '|' | cut -f 1 -d '(' | sed s/[[:space:]]//g`
	if [ -n "$muti_gem_tp_instance" ]; then
		gpnctp_ptr=`$omci meadg 281 $muti_gem_tp_instance 1 | sed -n 's/\(attr\_data\=\)/\1/p' | cut -f 3 -d '=' | cut -f 1 -d '(' | sed s/[[:space:]]//g`
		muti_port=`$omci meadg 268 0x$gpnctp_ptr 1 | cut -f 3 -d '='`
		if [ -n "$vlandebug" ]; then
			logger -t "[vlan]" "got muticast gem tp, muticast port: $muti_port, configuring ..."
		fi
		$omci meads 309 $me309 7 40 00 $muti_port $sb309 00 00 00 00 e0 00 01 00 ef ff ff ff 00 00 00 00 00 00
	fi
}

deletetrans() {
	filter_inner_1=`expr $1 \* 8`
	filter_inner_2=`printf "%04x" $filter_inner_1`
	patten="0"
	filter_inner_3="8$filter_inner_2$patten"
	word2=`echo $filter_inner_3 | sed 's/../& /g'`
	wordset="f8 00 00 00 $word2 00 ff ff ff ff ff ff ff ff"
	logger -t "[vlanexec]" "Deleting vlantrans rule $1"
	$omci meads 171 $me171 6 $wordset
}

vlantranscheck() {
	tvlannum=`echo $tvlan | grep -o ":" | grep -c ":"`
	tvlanseq=0
	for i in `seq 1 $tvlannum`
	do
		vlana=`echo $tvlan | cut -f $i -d ',' | cut -f 1 -d ':' | cut -f 1 -d '@'`
		vlanb=`echo $tvlan | cut -f $i -d ',' | cut -f 2 -d ':' | cut -f 1 -d '@'`
		tvlanseqa=`expr $i \+ $tvlanseq`
		tvlanseq=$i
		tvlanseqb=`expr $i \+ $tvlanseq`
		vlantransdata=`ls /tmp | grep vlan$tvlanseqa && ls /tmp | grep vlan$tvlanseqb`
		if [ -z "$vlantransdata" ]; then
			if [ -n "$vlana" ] && [ -n "$vlanb" ]; then
				echo $vlana > /tmp/vlan$tvlanseqa
				echo $vlanb > /tmp/vlan$tvlanseqb
				let totalizerflag++
			fi
		else
			vlana_lastdata=`cat /tmp/vlan$tvlanseqa`
			vlanb_lastdata=`cat /tmp/vlan$tvlanseqb`
			if [ "$vlana" != "$vlana_lastdata" ] || [ "$vlanb" != "$vlanb_lastdata" ]; then
				logger -t "[vlanexec]" "vlantrans$i vlan$tvlanseqa:vlan$tvlanseqb $vlana:$vlanb ($vlana_lastdata:$vlanb_lastdata) changed."
				deletetrans $vlana_lastdata
				echo $vlana > /tmp/vlan$tvlanseqa
				echo $vlanb > /tmp/vlan$tvlanseqb
				let totalizerflag++
			fi
		fi
	done
}

mtvlanset() {
	gem_port_idx=`$gtop  -b -g "GPE DS GEM port" | awk 'BEGIN{FS=";"} NR>5  {print $1}' | sed s/[[:space:]]//g`
	if [ "$mtvlan" == "1" ]; then
		if [ -n "$vlandebug" ]; then
			logger -t "[vlan]" "multi vlan trans enabled."
		fi
		gpe_vlanmode=1
	else
		if [ -n "$vlandebug" ]; then
			logger -t "[vlan]" "multi vlan trans disabled."
		fi
		gpe_vlanmode=0
	fi
	for i in `echo $gem_port_idx`
	do
		$onu gpe_vlan_mode_set $i 0 $gpe_vlanmode
	done
}

vlantransset() {
	tvlannum=`echo $tvlan | grep -o ":" | grep -c ":"`
	for i in `seq 1 $tvlannum`
	do
		vlana=`echo $tvlan | cut -f $i -d ',' | cut -f 1 -d ':' | cut -f 1 -d '@'`
		vlanb=`echo $tvlan | cut -f $i -d ',' | cut -f 2 -d ':' | cut -f 1 -d '@'`
		prioritya=`echo $tvlan | cut -f $i -d ',' | cut -f 1 -d ':' | grep '@'  | cut -f 2 -d "@"`
		priorityb=`echo $tvlan | cut -f $i -d ',' | cut -f 2 -d ':' | grep '@'  | cut -f 2 -d "@"`
		if [ -z "$vlana" ] || [ "$vlana" -gt 4094 ] || [ "`echo $vlana | grep -c '^[1-9][0-9]*$'`" == "0" ] || [ -z "$vlanb" ] || [ "`echo $vlanb | grep -c '^[u1-9][0-9]*$'`" == "0" ]; then
			if [ -n "$vlandebug" ]; then
				logger -t "[vlan]" "vlantrans$i $vlana:$vlanb configuration error."
			fi
			continue
		elif [ "`echo $vlanb | grep -c 'u'`" != "0" ] && [ "`echo $vlanb | grep -c '^[u]$'`" != "1" ]; then
			if [ -n "$vlandebug" ]; then
				logger -t "[vlan]" "vlantrans$i $vlana:$vlanb configuration error."
			fi
			continue
		elif [ "`echo $vlanb | grep -c 'u'`" == "0" ] && [ $vlanb -gt 4094 ]; then
			if [ -n "$vlandebug" ]; then
				logger -t "[vlan]" "vlantrans$i $vlana:$vlanb configuration error."
			fi
			continue
		fi
		if [ -n "$prioritya" ] && [ "`echo $prioritya | grep -c '^[0-7]$'`" == "0" ] || [ -n "$priorityb" ] && [ "`echo $priorityb | grep -c '^[0-7]$'`" == "0" ]; then
			if [ -n "$vlandebug" ]; then
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
		filter_inner_1=`expr $vlana \* 8`
		filter_inner_2=`printf "%04x" $filter_inner_1`
		patten="0"
		filter_inner_3="$prioritya$filter_inner_2$patten"
		word2=`echo $filter_inner_3 | sed 's/../& /g'`
		treate_inner_1=`expr $vlanb \* 8`
		treate_inner_2=`printf "%04x" $treate_inner_1`
		treate_inner_3=`echo $treate_inner_2 | sed 's/../& /g'`
		word4="00 0$priorityb $treate_inner_3"
		if [ "$vlanb" == "u" ]; then
			word4="0x00 0x0f 0x00 0x00"
		fi
		wordset="f8 00 00 00 $word2 00 40 0f 00 00 $word4"
		word_c=`echo $wordset | sed s/[[:space:]]//g | sed -r 's/(..)/0x\1/g' | sed -r 's/(....)/ \1/g'`
		wordget=`$omci meg 171 $me171 | grep "$word_c"`
		if [ -n "$wordget" ];then
			if [ -n "$vlandebug" ]; then
				logger -t "[vlan]" "vlantrans$i $vlana:$vlanb rule match."
			fi
		else
			if [ -n "$vlandebug" ]; then
				logger -t "[vlan]" "vlantrans$i $vlana:$vlanb configuring ..."
			fi
			$omci meads 171 $me171 6 $wordset
		fi
	done
}

me47pptpunibridge() {
	me47_instance_number=`$omci md | grep "Bridge port config data" | sed -n 's/\(0x\)/\1/p' | cut -f 3 -d '|' | cut -f 1 -d '(' | sed s/[[:space:]]//g`
	spanning_tree=`$omci meadg 45 1 1 | sed -n 's/\(attr\_data\=\)/\1/p' | cut -f 3 -d '=' | sed s/[[:space:]]//g`
	if [ -n "$vlandebug" ]; then
		logger -t "[vlan]" "me47_instance_number: `echo $me47_instance_number`"
	fi
	for i in `echo $me47_instance_number`
	do
		me47_tptype=`$omci meadg 47 $i 3 | sed -n 's/\(attr\_data\=\)/\1/p' | cut -f 3 -d '=' | sed s/[[:space:]]//g`
		me47_tpptr=`$omci meadg 47 $i 4 | sed -n 's/\(attr\_data\=\)/\1/p' | cut -f 3 -d '=' | sed s/[[:space:]]//g`
		if [ "$me47_tptype" == "01" ] && [ "$me47_tpptr" == "0101" ]; then
			if [ -n "$vlandebug" ]; then
				logger -t "[vlan]" "pptp uni bridge port: $i existed."
			fi
			pptp_uni_bridge=$i
			$omci meads 47 $i 3 1
			$omci meads 47 $i 4 01 01
			$omci meads 47 $i 7 $spanning_tree
			return
		fi
	done
	me47_tptype=`$omci meadg 47 1 3 | sed -n 's/\(attr\_data\=\)/\1/p' | cut -f 3 -d '=' | sed s/[[:space:]]//g`
	if [ -n "$me47_tptype" ];then
		$omci med 47 1
	fi
	bridge_instance=`$omci md | grep "Bridge config data" | sed -n 's/\(0x\)/\1/p' | cut -f 3 -d '|' | cut -f 1 -d '(' | tail -n 1 | sed s/[[:space:]]//g`
	if [ -n "$vlandebug" ]; then
		logger -t "[vlan]" "no pptp uni bridge port, creating it and instance is fixed 1."
	fi
	$omci mec 47 1 $bridge_instance 1 1 257 0 1 ${spanning_tree:1:2} 1 1
	pptp_uni_bridge=1
}

mecounter() {
	current=`$omci meadg 2 0 1 | sed -n 's/\(attr\_data\=\)/\1/p' | cut -f 3 -d '=' | sed s/[[:space:]]//g`
	current_1=0x$current
	current_2=`printf "0x%x" $current_1`
	current_3=$(awk 'BEGIN{printf("%#x",'$current_2'-3)}')
	current_4=`printf "%x" $current_3`
	$omci meads 2 0 1 $current_4
	if [ -n "$vlandebug" ]; then
		logger -t "[vlan]" "meconunter: $current_4 ."
	fi
}

me171create() {
	createflag=$1
	me171=`$omci md | grep "Extended VLAN conf data" | sed -n 's/\(0x\)/\1/p' | cut -f 3 -d '|' | cut -f 1 -d '(' | head -n 1 | sed s/[[:space:]]//g`
	me171_line=`$omci md | grep "Extended VLAN conf data" | wc -l`
	if [ $me171_line -gt 1 ]; then
		for i in `echo $me171`
		do
			Associated_ME_ptr=`$omci meadg 171 $i 7 | sed -n 's/\(attr\_data\=\)/\1/p' | sed s/[[:space:]]//g`
			if [ "$Associated_ME_ptr" = "0101" ]; then
				me171=$i
				if [ -n "$vlandebug" ]; then
					logger -t "[vlan]" "me171 value: $me171"
				fi
				break
			fi
		done
	fi
	me47_instance=$pptp_uni_bridge
	case $createflag in
		0)  if [ -z "$me171" ] && [ -n "$vlandebug" ]; then
				logger -t "[vlan]" "me171 value should not be null."
			fi
		;;
		1)  if [ -z "$me171" ]; then
				# new create me171,untag discard,tag transparnet
				me171_instance_1=`expr $me47_instance`
				me171_instance_2=`printf "%04x" $me171_instance_1`
				me171_instance_3=`echo $me171_instance_2 | sed 's/../& /g' | sed 's/[ ]*$//g'`
				source=`cat /etc/me171 | sed -n '2p' | cut -c 43-50`
				dst="ab $me171_instance_3"
				sed -i "s/$source/$dst/" /etc/me171
				$omci_simulate /etc/me171
				sleep 5
				mecounter
				if [ -n "$vlandebug" ]; then
					logger -t "[vlan]" "me171 value: $me47_instance, creating ..."
				fi
				me171=$me47_instance
			fi
		;;
		*)  if [ -n "$vlandebug" ]; then
				logger -t "[vlan]" "create me171 value error."
			fi
		;;
	esac
}

me309create() {
	me309=`$omci md | grep 309 | sed -n 's/\(0x\)/\1/p' | cut -f 3 -d '|' | cut -f 1 -d '(' | head -n 1 | sed s/[[:space:]]//g`
	me309line=`$omci md | grep 309 | wc -l`
	if [ -z "$me309" ] || [ -n "$forceme309" ] && [ "$me309line" != "2" ]; then
		if [ -n "$vlandebug" ]; then
			logger -t "[vlan]" "creating me309 ..."
		fi
		if [ -z "$igmpversion" ]; then
			igmpversion=3
		fi
		me309=$pptp_uni_bridge
		$omci mec 309 $me309 $igmpversion 0 1 0 0 32
		$omci meads 309 $me309 10 02
		$omci meads 309 $me309 12 00 00 00 7d
		$omci meads 309 $me309 13 00 00 00 64
		$omci meads 309 $me309 15 01
		$omci mec 310 $me309 0 $me309 64 0 1
		$omci mec 311 $me309 0
		sleep 5
	else
		if [ -n "$vlandebug" ]; then
			logger -t "[vlan]" "me309 rule existed."
		fi
		$omci meads 309 $me309 1 0$igmpversion
	fi
}

tptypealcl() {
	me47_instance_number=`$omci md | grep "Bridge port config data" | sed -n 's/\(0x\)/\1/p' | cut -f 3 -d '|' | cut -f 1 -d '(' | sed s/[[:space:]]//g`
	spanning_tree=`$omci meadg 45 1 1 | sed -n 's/\(attr\_data\=\)/\1/p' | cut -f 3 -d '=' | sed s/[[:space:]]//g`
	for i in `echo $me47_instance_number`
	do
		me47_tptype=`$omci meadg 47 $i 3 | sed -n 's/\(attr\_data\=\)/\1/p' | cut -f 3 -d '=' | sed s/[[:space:]]//g`
		me47_tpptr=`$omci meadg 47 $i 4 | sed -n 's/\(attr\_data\=\)/\1/p' | cut -f 3 -d '=' | sed s/[[:space:]]//g`
		if [ "$me47_tptype" == "01" ] && [ "$me47_tpptr" == "0101" ]; then
			if [ -n "$vlandebug" ]; then
				logger -t "[vlan]" "pptp uni bridge port: $i existed."
			fi
			if [ -n "$forcemerule" ]; then
				$omci meads 47 $i 3 1
				$omci meads 47 $i 4 01 01
			fi
			$omci meads 47 $i 7 $spanning_tree
			pptp_uni_bridge=$i
			return
		elif [ "$me47_tptype" == "0b" ]; then
			$omci meads 47 $i 3 1
			$omci meads 47 $i 4 01 01
			$omci meads 47 $i 7 $spanning_tree
			pptp_uni_bridge=$i
			return
		fi
	done
}

me171rulecheck() {
	me171_singtag="0xf80x000x000x000xe80x000x000x000x000x0f0x000x000x000x0f0x000x00"
	me171_doubletag="0xe80x000x000x000xe80x000x000x000x000x0f0x000x000x000x0f0x000x00"
	me171_singtagget=`$omci meg 171 $me171 | grep "0xf8 0x00 0x00 0x00 0xe8" | tail -n 1 | sed s/[[:space:]]//g`
	me171_doubletagget=`$omci meg 171 $me171 | grep "0xe8 0x00 0x00 0x00 0xe8" | tail -n 1 | sed s/[[:space:]]//g`
	$omci meg 171 $me171 | sed -n '/^ 5 RX frame VLAN table/,$p' | sed '/^ 6 Associated ME ptr/,$d' | grep '^   0x' | grep -v "0xf8 0x00 0x00 0x00 0xe8" | grep -v "0xe8 0x00 0x00 0x00 0xe8" | sed 's/^   //g' | sed 's/0x//g' > /tmp/me171_rule
	me171_rule_line=`$omci meg 171 1 | sed -n '/^ 5 RX frame VLAN table/,$p' | sed '/^ 6 Associated ME ptr/,$d' | grep '^   0x' | grep -v "0xf8 0x00 0x00 0x00 0xe8" | grep -v "0xf8 0x00 0x00 0x00 0xe8" | wc -l`
	if [ $me171_rule_line -ge 1 ] && [ -n "$vlandebug" ]; then
		for i in `seq 1 $me171_rule_line`
		do
			logger -t "[vlan]" "me171 rule: `cat /tmp/me171_rule | tail -n $i | head -n 1`"
		done
	fi
	if [ "$me171_singtagget" != "$me171_singtag" ] || [ "$me171_doubletagget" != "$me171_doubletag" ] ||  [ -n "$forcemerule" ]; then
		if [ -n "$vlandebug" ]; then
			logger -t "[vlan]" "defualt rule not match or forcemerule enabled, creating ..."
		fi
		$omci meads 171 $me171 6 f8 00 00 00 e8 00 00 00 00 0f 00 00 00 0f 00 00
		$omci meads 171 $me171 6 e8 00 00 00 e8 00 00 00 00 0f 00 00 00 0f 00 00
		if [ $me171_rule_line -ge 1 ]; then
			for i in `seq 1 $me171_rule_line`
			do
				$omci meads 171 $me171 6 `cat /tmp/me171_rule | tail -n $i | head -n 1`
			done
		fi
	fi
}

main() {
	state=`echo $(status)`
	sigstate=`$optic bosa_rx_status_get | cut -f 8 -d ' ' | cut -f 2 -d '=' | sed s/[[:space:]]//g`
	if [ "$state" != "5" ]; then
		resetparameter

		if [ "$tryreboot" == "1" ] && [ -n $totalrebootwait ] && [ -n $totalreboottry ] && [ "$sigstate" != "1" ] && [ $reboottrynum -lt $totalreboottry ]; then
			if [ $rebootwaitnum -eq $totalrebootwait ]; then
				logger -t "[vlanexec]" "reboot try enabled, total rebootwait times reached, current reboot try times: $reboottrynum, rebooting ..."
				reboottry
			else
				if [ -z "$totalrebootwait" ] || [ -z "$totalreboottry" ]; then
					if [ $logflag -lt 1 ]; then
						logger -t "[vlanexec]" "rebootwait($totalrebootwait) or reboottry($totalreboottry) not set, waiting ..."
						let logflag++
					fi
					rest
				else
					logger -t "[vlanexec]" "reboot try enabled, current reboot wait times: $rebootwaitnum, waiting for reboot ..."
					rebootwait
				fi
			fi
		elif [ "$sigstate" == "1" ]; then
			if [ $logflag -lt 1 ]; then
				logger -t "[vlanexec]" "current loss_of_signal state: $sigstate, waiting ..."
				let logflag++
			fi
			rest
		else
			if [ $logflag -lt 1 ]; then
				logger -t "[vlanexec]" "reboot try not enabled or total reboot trys reached, current reboot try times: $reboottrynum, giving up ..."
				let logflag++
			fi
			rest
		fi
	else
		if [ $stateflag -le 20 ]; then
			let stateflag++
		fi
		state=`echo $(status)`
		if [ "$state" == "5" ]; then
			if [ $collectflag -lt 2 ]; then
				collect
				let collectflag++
			fi
			resetlogflag
			resetrebootwarit
			resetreboottry
			mibdata
			oltstatus1
			oltstatus2

			uvlancheck
			mvlancheck
			vlantranscheck

			if [ $initflag -lt 5 ]; then
				meruleset
				uvlanset
				mvlanset
				mtvlanset
				vlantransset
				let initflag++
			elif [ $totalizerflag -ge 1 ]; then
				meruleset
				uvlanset
				mvlanset
				mtvlanset
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
