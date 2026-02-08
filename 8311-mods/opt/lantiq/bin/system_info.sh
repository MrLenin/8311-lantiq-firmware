#!/bin/sh
command=$1

onu="/opt/lantiq/bin/onu"
omci="/opt/lantiq/bin/omci_pipe.sh"
omcid="/opt/lantiq/bin/omcid"
omci_simulate="/opt/lantiq/bin/omci_simulate"
uci="/sbin/uci"
gtop="/opt/lantiq/bin/gtop"
otop="/opt/lantiq/bin/otop"
sfp_i2c="/opt/lantiq/bin/sfp_i2c"
fw_printenv="/usr/sbin/fw_printenv"
fw_setenv="/usr/sbin/fw_setenv"

olttype() {
	local olt_type
	olt_type=$(grep "olt type" /tmp/collect | cut -f 2 -d ':')
	if [ "$olt_type" = "48575443" ]; then
		echo "HWTC ($olt_type)"
	elif [ "$olt_type" = "414c434c" ]; then
		echo "ALCL ($olt_type)"
	elif [ "$olt_type" = "5a544547" ]; then
		echo "ZTE ($olt_type)"
	else
		echo "Other ($olt_type)"
	fi
}

vlaninfo() {
	local vlan_info
	local fid_info
	local vlan_output

	vlan_info=$($gtop -b -g 'GPE VLAN' | sed '1,5d' | cut -f 4 -d ';' | sed '/^[  ]*$/d')
	fid_info=$($gtop -b -g 'GPE FID assignment' | sed '1,5d' | cut -f 2 -d ';' | sed '/^[  ]*$/d')
	vlan_output=$(printf '%s\n%s' "$vlan_info" "$fid_info" | sed '/^[  ]*$/d' | sort -un | sed 's/$/&,/g' | sed 's/ //g' | sed 's/.$//g')
	echo "$vlan_output"
}

status() {
	local ploam_state
	local signal_state

	ploam_state=$($onu ploamsg | cut -b 24)
	signal_state=$($otop -b -g s | grep 'Signal detect' | head -n 2 | cut -b 52-56)
	echo "$ploam_state / $signal_state"
}

optic() {
	local rx
	local tx

	rx=$($otop -b -g s | grep 'power' | grep 'RSSI'| cut -c 52-70)
	tx=$($otop -b -g s | grep 'power' | grep 'tx' | cut -c 52-70)
	echo "$rx / $tx"
}

temperature(){
	local cpu
	local laser

	cpu=$(($($otop -b -g s | grep 'temperature' | grep 'die' | cut -c 52-54) - 273 ))
	laser=$(($($otop -b -g s | grep 'temperature' | grep 'laser' | cut -c 52-54) - 273))
	echo "$cpu℃ / $laser℃"
}

rebootcause() {
	local cause
	local onu_cause
	local reboot_cause

	cause=$(cat /tmp/rebootcause 2>&-)
	onu_cause=$($onu onurg 32 0x1f20000c | cut -f 3 -d ' ' | cut -c 9)

	case $onu_cause in
		1)
			reboot_cause="Power-On Reset"
		;;
		2)
			reboot_cause="RST Pin"
		;;
		3)
			reboot_cause="Watchdog"
		;;
		4)
			if [ -z "$cause" ] || [ "$cause" = "0" ]; then
				reboot_cause="Software"
			elif [ "$cause" = "1" ]; then
				reboot_cause="Software, Non-O5 Reboottry"
			elif [ "$cause" = "2" ]; then
				reboot_cause="Software, FIFO Overflow Reboottry"
			elif [ "$cause" = "3" ]; then
				reboot_cause="Software, OMCID Restarttry"
			elif [ "$cause" = "4" ]; then
				reboot_cause="Software, COP Error Reboottry"
			fi
		;;
		5)
			reboot_cause="PLOAM message"
		;;
		6)
			reboot_cause="Unknown"
	esac

	echo "$reboot_cause"
}

rebootnum() {
	local reboot_try_count
	local omcid_reboot_count

	reboot_try_count=$(cat /tmp/reboottrynum 2>&-)
	omcid_reboot_count=$(cat /tmp/omcidrebootnum 2>&-)
	echo "Non-O5: $reboot_try_count , OMCID: $omcid_reboot_count"
}

omcid_version() {
	local omcid_ver
	local is_default_ver

	omcid_ver=$($omcid -v | tail -n 1 | cut -c 18-75)
	is_default_ver=$(echo "$omcid_ver" | grep -c '6BA1896SPE2C05')

	if [ "$is_default_ver" = "1" ]; then
		omcid_ver=6BA1896SPE2C05
	fi

	echo "$omcid_ver"
}

version() {
	echo "Final_v2021_12_28_c2 / 2023.10.20 / 8311 Remix v1"
}

linkstatus() {
	local link_status
	local link_duplex
	local link_speed
	local duplex_state

	link_status=$($onu lanpsg 0 | cut -f 5 -d " " | sed 's/\(.*\)\(.\)$/\2/')
	link_duplex=$($onu lanpsg 0 | cut -f 6 -d " " | sed 's/\(.*\)\(.\)$/\2/')

	case $link_status in
		4)
		if [ "$link_duplex" = "1" ]; then
			link_speed=1000M
			duplex_state="Full Duplex"
		else
			link_speed=1000M
			duplex_state="Half Duplex"
		fi
		echo "$link_speed , $duplex_state"
		;;
		5)
		if [ "$link_duplex" = "1" ]; then
			link_speed=2500M
			duplex_state="Full Duplex"
		else
			link_speed=2500M
			duplex_state="Half Duplex"
		fi
		echo "$link_speed , $duplex_state"
		;;
		*)
		echo "- , -"
		;;
	esac
}

committed() {
	local image
	local committed_image

	image=$(grep image /proc/mtd | cut -c 31)
	committed_image=$((1 - image))
	echo "image$committed_image"
}

vendor() {
	local is_huawei
	local is_nokia
	local vendor_name

	#i2cvar=`$sfp_i2c -r | grep 00000010 | grep -c "48 55 41 57 45 49"`
	is_huawei=$($fw_printenv gSerial | grep -c HWTC)
	is_nokia=$($fw_printenv ver | grep -c 2015.04)

	if [ "$is_huawei" = "1" ]; then
		vendor_name="HUAWEI"
	elif [ "$is_nokia" = "1" ]; then
		vendor_name="Nokia"
	else
		vendor_name="Alcatel-Lucent"
	fi

	echo "$vendor_name" >/tmp/vendorname
}

model() {
	local vendor_name
	local model_name

	vendor
	vendor_name=$(cat /tmp/vendorname)

	if [ "$vendor_name" = "HUAWEI" ]; then
		model_name="SmartAX MA5671A"
	elif [ "$vendor_name" = "Nokia" ]; then
		model_name="G-010S-A"
	else
		model_name="G-010S-P"
	fi

	echo "$model_name"
}

case $command in
committed)
	committed
	;;
olttype)
	olttype
	;;
vlaninfo)
	vlaninfo
	;;
linkstatus)
	linkstatus
	;;
status)
	status
	;;
rebootcause)
	rebootcause
	;;
rebootnum)
	rebootnum
	;;
omcid_version)
	omcid_version
	;;
version)
	version
	;;
optic)
	optic
	;;
temperature)
	temperature
	;;
vendor)
	vendor
	;;
model)
	model
	;;
*)
	echo "Error Command $command"
	;;
esac
