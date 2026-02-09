#!/bin/sh /etc/rc.common
# Copyright (C) 2013 OpenWrt.org
# Copyright (C) 2013 lantiq.com
#
# pin_cfg.sh -- SFP GPIO Pin Configuration (init priority 63)
#
# Configures the GPIO pins that back the standard SFP/SFP+ control signals:
#   TX_FAULT, TX_DISABLE, RX_LOS (Loss of Signal), MOD_DEF (module detect)
#
# Pin assignments come from UCI "sfp_pins" config.  Certain pins may be
# unavailable when the ASC0 UART shares GPIOs (see get_restrictions).
#
# Dependencies:
#   /lib/falcon.sh                  - falcon_asc0_pin_mode helper
#   /opt/lantiq/bin/gpio_setup.sh   - GPIO direction/value helper
#   /opt/lantiq/bin/optic           - Optic pin config CLI
#   /opt/lantiq/bin/onu             - ONU LOS pin config CLI
#   /etc/config/sfp_pins            - UCI pin mapping config
#   /etc/config/8311                - 8311 UCI (rx_los toggle)
#
# Boot flow position: START=63, runs right after onu.sh (61).

. "$IPKG_INSTROOT/lib/falcon.sh"
. "$IPKG_INSTROOT/opt/lantiq/bin/gpio_setup.sh"

LTQ_BIN=/opt/lantiq/bin

START=63

# ---------------------------------------------------------------------------
# Default pin values: "disabled" sentinels
# ---------------------------------------------------------------------------
TX_FAULT_PIN_DISABLED=255      # 255 = no GPIO assigned (optic subsystem)
TX_DISABLE_PIN_DISABLED=255    # 255 = no GPIO assigned (optic subsystem)
LOS_PIN_DISABLED=-1            # -1  = LOS reporting disabled (onu subsystem)

# load_sfp_pins -- UCI callback: load a single SFP pin entry.
#   $1 : UCI section name (iterated by config_foreach)
#
# Each UCI section has: name (e.g. "tx_disable"), pin (GPIO number),
# and an optional restriction tag (e.g. "ASC_TX").
#
# If the pin's restriction tag appears in the current restriction_list
# (populated by get_restrictions), the pin is skipped -- that GPIO is
# reserved for the UART and must not be repurposed.
#
# Otherwise, sets a shell variable <name>_pin=<pin> (e.g. tx_disable_pin=13).
load_sfp_pins() {

	config_get name "$1" name
	config_get pin "$1" pin
	config_get restriction "$1" restriction

	#echo "$name: <$pin> - $restriction"
	# If this pin has a restriction tag, check it against the active list
	[ -z "$restriction" ] || {
		for r in $restriction_list; do
			if [ "$r" = "$restriction" ]; then
				#printf "*** Restrictions for %s apply!\n\n" $name
				return
			fi
		done
	}
	#printf "Use settings for %s\n" $name
	eval "${name}_pin=$pin"
}

# get_restrictions -- Determine which GPIOs are reserved by the ASC0 UART.
#
# falcon_asc0_pin_mode returns:
#   3 = UART fully disabled   -> no restrictions (all GPIOs free)
#   2 = only TX active        -> ASC_TX pin is reserved
#   1 = only RX active        -> ASC_RX pin is reserved
#   0 / other = full UART     -> both ASC_RX and ASC_TX reserved
#
# The resulting restriction_list is checked by load_sfp_pins to skip
# any SFP pin that would conflict with an active UART signal.
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

# apply_pins -- Programme the resolved GPIO pins into hardware.
#
# TX_DISABLE is always configured (255 = no pin assigned).
# RX_LOS handling has two branches depending on the UCI rx_los toggle:
#
#   rx_los unset -> DISABLE LOS reporting:
#     Set the ONU LOS pin to -1 (disabled) and force the GPIO low so the
#     host sees "signal present".  If the GPIO refuses to go low, resync
#     UCI to reflect reality.
#
#   rx_los = 1 -> ENABLE LOS reporting:
#     Release the GPIO from sysfs (unexport) so the ONU driver can own it,
#     then configure it as the LOS indicator pin.
#
# Two status checks (rx_los_status1 from onu driver, rx_los_status2 from
# sysfs debugfs) are compared to detect whether the current hardware state
# already matches the desired configuration -- avoiding redundant changes.
apply_pins() {
	#local tx_fault_pin_set
	local rx_los
	local rx_los_status1
	local rx_los_status2

	# apply pinconf for asc0
	#$LTQ_BIN/onu onu_asc0_pin_cfg_set `expr 1 + $(falcon_asc0_pin_mode)`

	#tx_fault_pin_set=`fw_printenv tx_fault_pin 2>&- | cut -f 2 -d '='`

	# Configure TX_DISABLE pin; second arg 255 = TX_FAULT pin unused
	$LTQ_BIN/optic optic_pin_cfg_set "$tx_disable_pin" $TX_FAULT_PIN_DISABLED >/dev/null

	rx_los=$(uci -q get 8311.config.rx_los)
	# status1: ONU driver's current LOS pin (-1 = disabled)
	rx_los_status1=$($LTQ_BIN/onu onu_los_pin_cfg_get | tee /dev/null | cut -f 3 -d '=')
	# status2: sysfs GPIO state -- count of "lo" matches (1 = low = no LOS)
	rx_los_status2=$(grep "gpio-$los_pin " /sys/kernel/debug/gpio | grep -c "lo")

	if [ -z "$rx_los" ] &&
		{ [ "$rx_los_status1" -ne "$LOS_PIN_DISABLED" ] ||
		  [ "$rx_los_status2" -ne 1 ]; }; then

		logger -t "[pin_cfg]" "Disabling rx_los status ..."

		# Disable driver-level LOS and force GPIO low (signal present)
		$LTQ_BIN/onu onu_los_pin_cfg_set $LOS_PIN_DISABLED >/dev/null
		$LTQ_BIN/gpio_setup.sh "$los_pin" low >/dev/null

		# Re-read to confirm the GPIO actually went low
		rx_los_status2=$(grep "gpio-$los_pin " /sys/kernel/debug/gpio | grep -c "lo")

		if [ "$rx_los_status2" -ne 1 ]; then
			# GPIO didn't go low -- resync UCI so config matches reality
			logger -t "[pin_cfg]" "Disable rx_los status failed, resync system config ..."
			uci -q delete 8311.config.rx_los
			uci commit 8311.config
		fi
	elif [ "$rx_los" = "1" ] &&
		{ [ "$rx_los_status1" -eq "$LOS_PIN_DISABLED" ] ||
		  [ "$rx_los_status2" -eq 1 ]; }; then

		logger -t "[pin_cfg]" "Enabling rx_los status ..."

		# Release GPIO from userspace so the ONU driver can claim it
		echo "$los_pin" >/sys/class/gpio/unexport
		$LTQ_BIN/onu onu_los_pin_cfg_set "$los_pin" >/dev/null
	fi
	# set pin to LOW (module availability indication)
	#[ -z "$mod_def_pin" ] || gpio_setup $mod_def_pin low

}

# start -- Main entry point (rc.common hook).
#
# 1. Determine UART pin restrictions (which GPIOs are off-limits)
# 2. Set all SFP pins to safe disabled defaults
# 3. Load pin assignments from UCI, skipping restricted pins
# 4. Apply the resolved pin configuration to hardware
start() {
	get_restrictions
	#echo "asc: $restriction_list"

	# All pins disabled by default -- overridden by load_sfp_pins if available
	tx_fault_pin="$TX_FAULT_PIN_DISABLED"
	tx_disable_pin="$TX_DISABLE_PIN_DISABLED"
	los_pin="$LOS_PIN_DISABLED"
	mod_def_pin=""

	config_load sfp_pins

	config_foreach load_sfp_pins pin

	apply_pins
}
