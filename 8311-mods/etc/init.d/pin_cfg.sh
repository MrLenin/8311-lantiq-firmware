#!/bin/sh /etc/rc.common
# Copyright (C) 2013 OpenWrt.org
# Copyright (C) 2013 lantiq.com

. $IPKG_INSTROOT/lib/falcon.sh
. $IPKG_INSTROOT/opt/lantiq/bin/gpio_setup.sh
LTQ_BIN=/opt/lantiq/bin

START=63

load_sfp_pins() {

	config_get name $1 name
	config_get pin $1 pin
	config_get restriction $1 restriction

	#echo "$name: <$pin> - $restriction"
	[ -z "$restriction" ] || {
		for r in $restriction_list; do
			if [ "$r" == "$restriction" ]; then
				#printf "*** Restrictions for %s apply!\n\n" $name
				return
			fi
		done
	}
	#printf "Use settings for %s\n" $name
	eval "${name}_pin=$pin"
}

get_restrictions() {
	case $(falcon_asc0_pin_mode) in
	3)
		restriction_list=""
		;;
	2)
		restriction_list="ASC_TX"
		;;
	1)
		restriction_list="ASC_RX"
		;;
	*)
		# assume that the full UART is required
		restriction_list="ASC_RX ASC_TX"
		;;
	esac
}

apply_pins() {
	#local tx_fault_pin_set
	# apply pinconf for asc0
	#$LTQ_BIN/onu onu_asc0_pin_cfg_set `expr 1 + $(falcon_asc0_pin_mode)`

	#tx_fault_pin_set=`fw_printenv tx_fault_pin 2>&- | cut -f 2 -d '='`

	$LTQ_BIN/optic optic_pin_cfg_set $tx_disable_pin 255 > /dev/null

	local disable_rx_los_status=`uci -q get gpon.onu.disable_rx_los_status`
	local rx_los_status_current1=`$LTQ_BIN/onu onu_los_pin_cfg_get > /dev/null | cut -f 3 -d '='`
	local rx_los_status_current2=`cat /sys/kernel/debug/gpio | grep "gpio-$los_pin" | grep -c "lo"`
	if [ "$disable_rx_los_status" == "1" ]; then
		if [ "$rx_los_status_current1" != "-1" ] || [ "$rx_los_status_current2" != "1" ]; then
			logger -t "[pin_cfg]" "Disabling rx_los status ..."
			$LTQ_BIN/onu onu_los_pin_cfg_set -1 > /dev/null
			$LTQ_BIN/gpio_setup.sh $los_pin low > /dev/null
			rx_los_status_current2=`cat /sys/kernel/debug/gpio | grep "gpio-$los_pin" | grep -c "lo"`
			if [ "$rx_los_status_current2" != "1" ]; then
				logger -t "[pin_cfg]" "Disable rx_los status failed, resync system config ..."
				uci -q delete gpon.onu.disable_rx_los_status
				uci commit gpon.onu
			fi
		fi
	elif [ -z "$disable_rx_los_status" ]; then
		if [ "$rx_los_status_current1" == "-1" ] || [ "$rx_los_status_current2" == "1" ]; then
			logger -t "[pin_cfg]" "Enabling rx_los status ..."
			$LTQ_BIN/onu onu_los_pin_cfg_set $los_pin > /dev/null
		fi
	fi
	# set pin to LOW (module availability indication)
	#[ -z "$mod_def_pin" ] || gpio_setup $mod_def_pin low
}

start() {
	get_restrictions
	#echo "asc: $restriction_list"

	# all pins are disabled per default
	tx_fault_pin="255"
	tx_disable_pin="255"
	los_pin="-1"
	mod_def_pin=""

	config_load sfp_pins

	config_foreach load_sfp_pins pin

	apply_pins
}
