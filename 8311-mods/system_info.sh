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
fw_setenv="/usr/sbin/fw_printenv"

olttype() {
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
	info1=$($gtop -b -g 'GPE VLAN' | sed '1,5d' | cut -f 4 -d ';' | sed '/^[  ]*$/d')
	info2=$($gtop -b -g 'GPE FID assignment' | sed '1,5d' | cut -f 2 -d ';' | sed '/^[  ]*$/d')
	vlaninfo=$(print '%s\n%s' "$info1" "$info2" | sed '/^[  ]*$/d' | sort -un | sed 's/$/&,/g' | sed 's/ //g' | sed 's/.$//g')
	echo "$vlaninfo"
}

status() {
	ploamstate=$($onu ploamsg | cut -b 24)
	signalstate=$($otop -b -g s | grep 'Signal detect' | head -n 2 | cut -b 52-56)
	echo "$ploamstate / $signalstate"
}

optic() {
	rx=$($otop -b -g s | grep 'power' | grep 'RSSI'| cut -c 52-70)
	tx=$($otop -b -g s | grep 'power' | grep 'tx' | cut -c 52-70)
	echo "$rx / $tx"
}

temperature(){
	cpu=$(($($otop -b -g s | grep 'temperature' | grep 'die' | cut -c 52-54) - 273 ))
	laser=$(($($otop -b -g s | grep 'temperature' | grep 'laser' | cut -c 52-54) - 273))
	echo "$cpu℃ / $laser℃"
}

rebootcause() {
	cause=$(cat /tmp/rebootcause 2>&-)
	onu_cause=$($onu onurg 32 0x1f20000c | cut -f 3 -d ' ' | cut -c 9)

	case $onu_cause in
		1)
			rebootcause="Power-On Reset"
		;;
		2)
			rebootcause="RST Pin"
		;;
		3)
			rebootcause="Watchdog"
		;;
		4) 
			if [ -z "$cause" ] || [ "$cause" = "0" ]; then
				rebootcause="Software"
			elif [ "$cause" = "1" ]; then
				rebootcause="Software, Non-O5 Reboottry"
			elif [ "$cause" = "2" ]; then
				rebootcause="Software, FIFO Overflow Reboottry"
			elif [ "$cause" = "3" ]; then
				rebootcause="Software, OMCID Restarttry"
			elif [ "$cause" = "4" ]; then
				rebootcause="Software, COP Error Reboottry"
			fi
		;;
		5)
			rebootcause="PLOAM message"
		;;
		6)
			rebootcause="Unknown"
	esac

	echo "$rebootcause"
}

rebootnum() {
	reboottrynum=$(cat /tmp/reboottrynum 2>&-)
	omcidrebootnum=$(cat /tmp/omcidrebootnum 2>&-)
	echo "Non-O5: $reboottrynum , OMCID: $omcidrebootnum"
}

omcid_version() {
	ver=$($omcid -v | tail -n 1 | cut -c 18-75)
	ver_o=$(echo "$ver" | grep -c '6BA1896SPE2C05')

	if [ "$ver_o" = "1" ]; then
		ver=6BA1896SPE2C05
	fi
	
	echo "$ver"
}

version() {
	echo "Final_v2021_12_28_c2 / 2023.10.20 / 8311 Remix v1"
}

linkstatus() {
	link_status=$($onu lanpsg 0 | cut -f 5 -d " " | sed 's/\(.*\)\(.\)$/\2/')
	link_duplex=$($onu lanpsg 0 | cut -f 6 -d " " | sed 's/\(.*\)\(.\)$/\2/')

	case $link_status in
		4)
		if [ "$link_duplex" = "1" ]; then
			linkspeed=1000M
			duplexstate="Full Duplex"
		else
			linkspeed=1000M
			duplexstate="Half Duplex"
		fi
		echo "$linkspeed , $duplexstate"
		;;
		5)
		if [ "$link_duplex" = "1" ]; then
			linkspeed=2500M
			duplexstate="Full Duplex"
		else
			linkspeed=2500M
			duplexstate="Half Duplex"
		fi
		echo "$linkspeed , $duplexstate"
		;;
		*)
		echo "- , -"
		;;
	esac
}

committed() {
	image=$(grep image /proc/mtd | cut -c 31)
	cimage=$((1 - image))
	echo "image$cimage"
}

vendor() {
	#i2cvar=`$sfp_i2c -r | grep 00000010 | grep -c "48 55 41 57 45 49"`
	envvar1=$($fw_printenv gSerial | grep -c HWTC)
	envvar2=$($fw_printenv ver | grep -c 2015.04)
	
	if [ "$envvar1" = "1" ]; then
		vendorname="HUAWEI"
	elif [ "$envvar2" = "1" ]; then
		vendorname="Nokia"
	else
		vendorname="Alcatel-Lucent"
	fi

	echo "$vendorname" > /tmp/vendorname
}

model() {
	vendor
	vendorname=$(cat /tmp/vendorname)

	if [ "$vendorname" = "HUAWEI" ]; then
		modelname="SmartAX MA5671A"
	elif [ "$vendorname" = "Nokia" ]; then
		modelname="G-010S-A"
	else
		modelname="G-010S-P"
	fi

	echo "$modelname"
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
