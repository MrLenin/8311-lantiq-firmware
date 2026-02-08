#!/bin/sh

. /lib/falcon.sh

default_lct=$(falcon_default_lct_get)

optic="/opt/lantiq/bin/optic"
i2c="/opt/lantiq/bin/sfp_i2c"
uci="/sbin/uci"
sig_loss_count=0

sig_status() {
	local disable_sig_monitor
	local sig_state

	disable_sig_monitor=$($uci -q get 8311.config.disable_sigstatus)
	if [ -z "$disable_sig_monitor" ]; then
		sig_state=$($optic bosa_rx_status_get | cut -f 8 -d ' ' | cut -f 2 -d '=' | sed s/[[:space:]]//g)
		if [ "$sig_state" = "0" ]; then
			sleep 1
			sig_state=$($optic bosa_rx_status_get | cut -f 8 -d ' ' | cut -f 2 -d '=' | sed s/[[:space:]]//g)
			if [ "$sig_state" = "1" ] && [ "$sig_loss_count" -lt 5 ]; then
				sig_loss_count=$((sig_loss_count + 1))
				return
			elif [ "$sig_loss_count" = "5" ]; then
				sleep 1
				sig_state=$($optic bosa_rx_status_get | cut -f 8 -d ' ' | cut -f 2 -d '=' | sed s/[[:space:]]//g)
				if [ "$sig_state" = "1" ]; then
					logger -t "[monit_optic]" "Cancelling restore default settings ..."
					sig_loss_count=0
					return
				else
					logger -t "[monit_optic]" "Restoring default settings and rebooting ..."
					fw_setenv ipaddr '192.168.1.10'
					fw_setenv netmask '255.255.255.0'
					fw_setenv gatewayip '192.168.2.0'
					fw_setenv ethaddr 'ac:9a:96:00:00:00'
					uci set network.lct.macaddr="$(falcon_mac_get "$default_lct")"
					uci set network.host.macaddr="$(falcon_mac_get host)"
					uci commit network
					passwd -d root
					reboot -f
				fi
			fi
		fi
	fi
}

tx_status() {
	local enable_tx_monitor
	local tx_state

	enable_tx_monitor=$($uci -q get 8311.config.enable_txstatus)
	if [ "$enable_tx_monitor" = "1" ]; then
		tx_state=$($optic bosa_tx_status_get | cut -f 2 -d ' ' | cut -f 2 -d '=' | sed s/[[:space:]]//g)
		if [ "$tx_state" != "1" ]; then
			$optic bosa_tx_enable 2>&-
			logger -t "[monit_optic]" "optic tx disabled detected, re-enabled tx ..."
		fi
	fi
}

while true
do
	sig_status
	tx_status
	sleep 1
done
