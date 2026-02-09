#!/bin/sh
# monitoptic.sh — Background daemon that monitors optical transceiver signal
# status (RX signal loss and TX enable state).
#
# Responsibilities:
#   1. RX signal loss detection with factory-reset trigger: If the RX signal
#      is lost and then flickers back repeatedly (reaching SIG_LOSS_THRESHOLD
#      transitions), the device interprets this as an operator-initiated
#      factory reset sequence — it restores default network settings,
#      removes the root password, and force-reboots.
#   2. TX status monitoring: When enabled, detects if the optical transmitter
#      has been disabled (e.g. by firmware fault) and re-enables it.
#
# Dependencies:
#   /lib/falcon.sh              — Falcon SoC platform helpers (MAC, LCT defaults)
#   /opt/lantiq/bin/optic        — optical transceiver (BOSA) control CLI
#   /opt/lantiq/bin/onu          — ONU/PLOAM state query CLI
#   /opt/lantiq/bin/sfp_i2c      — SFP I2C bus interface
#   /sbin/uci                   — OpenWrt Unified Configuration Interface
#   fw_printenv / fw_setenv      — U-Boot environment variable access
#
# Runtime:
#   Started as a background daemon during boot. The main loop polls every
#   MAIN_LOOP_INTERVAL second indefinitely.

. /lib/falcon.sh

default_lct=$(falcon_default_lct_get)

optic="/opt/lantiq/bin/optic"
onu="/opt/lantiq/bin/onu"
i2c="/opt/lantiq/bin/sfp_i2c"
uci="/sbin/uci"

# ---------------------------------------------------------------------------
# Named constants
# ---------------------------------------------------------------------------

# Number of loss-then-recovery transitions required to trigger a factory
# reset.  The operator intentionally toggles the fiber to produce this
# specific pattern, distinguishing it from normal signal flap.
SIG_LOSS_THRESHOLD=5

# Factory-reset default network values written to U-Boot environment.
# These restore the device to a known-good state after the reset reboot.
DEFAULT_IPADDR='192.168.1.10'
DEFAULT_NETMASK='255.255.255.0'
DEFAULT_GATEWAYIP='192.168.2.0'
DEFAULT_ETHADDR='ac:9a:96:00:00:00'

# Seconds to sleep between iterations of the main monitoring loop.
MAIN_LOOP_INTERVAL=1

# ---------------------------------------------------------------------------
# Runtime state
# ---------------------------------------------------------------------------

# Counts consecutive loss-then-recovery signal transitions.
# Resets to 0 when the reset is cancelled (signal remains stable).
sig_loss_count=0

# ---------------------------------------------------------------------------
# sig_status — Monitor RX signal for loss events and factory-reset pattern.
#
# Uses `optic bosa_rx_status_get` to read the BOSA RX signal state.
# sig_state: 0 = signal lost, 1 = signal present.
#
# State machine (evaluated each call):
#   1. If sig_state=0 (loss detected), wait 1s and re-read.
#   2. If signal recovers to 1 within that window and sig_loss_count has not
#      yet reached SIG_LOSS_THRESHOLD, count it as one loss-recovery cycle
#      and return (debounce / accumulate).
#   3. If sig_loss_count reaches SIG_LOSS_THRESHOLD, do a final 1s
#      confirmation read:
#        - If signal recovered (1): cancel the reset — the pattern was
#          incomplete or accidental.
#        - If signal still lost (0): execute factory reset — restore
#          default U-Boot env vars, reset MAC addresses via UCI, remove
#          root password, and force-reboot.
#
# Disabled when UCI option 8311.config.disable_sigstatus is set.
# ---------------------------------------------------------------------------
sig_status() {
	local disable_sig_monitor
	local sig_state

	disable_sig_monitor=$($uci -q get 8311.config.disable_sigstatus)
	if [ -z "$disable_sig_monitor" ]; then
		sig_state=$($optic bosa_rx_status_get | cut -f 8 -d ' ' | cut -f 2 -d '=' | sed s/[[:space:]]//g)
		if [ "$sig_state" = "0" ]; then
			# Signal lost — wait briefly then re-check to see if it recovered
			sleep 1
			sig_state=$($optic bosa_rx_status_get | cut -f 8 -d ' ' | cut -f 2 -d '=' | sed s/[[:space:]]//g)
			if [ "$sig_state" = "1" ] && [ "$sig_loss_count" -lt "$SIG_LOSS_THRESHOLD" ]; then
				# Signal recovered quickly — count as one loss-recovery toggle
				sig_loss_count=$((sig_loss_count + 1))
				return
			elif [ "$sig_loss_count" = "$SIG_LOSS_THRESHOLD" ]; then
				# Threshold reached — final confirmation before factory reset
				sleep 1
				sig_state=$($optic bosa_rx_status_get | cut -f 8 -d ' ' | cut -f 2 -d '=' | sed s/[[:space:]]//g)
				if [ "$sig_state" = "1" ]; then
					# Signal came back — false alarm; cancel reset sequence
					logger -t "[monit_optic]" "Cancelling restore default settings ..."
					sig_loss_count=0
					return
				else
					# Signal still absent — execute factory reset
					logger -t "[monit_optic]" "Restoring default settings and rebooting ..."
					fw_setenv ipaddr "$DEFAULT_IPADDR"
					fw_setenv netmask "$DEFAULT_NETMASK"
					fw_setenv gatewayip "$DEFAULT_GATEWAYIP"
					fw_setenv ethaddr "$DEFAULT_ETHADDR"
					uci set network.lct.macaddr="$(falcon_mac_get "$default_lct")"
					uci set network.host.macaddr="$(falcon_mac_get host)"
					uci commit network
					# Remove root password so the device is accessible post-reset
					passwd -d root
					reboot -f
				fi
			fi
		fi
	fi
}

# ---------------------------------------------------------------------------
# tx_status — Re-enable the optical transmitter if disabled unexpectedly.
#
# WARNING: Forcing the laser back on is potentially dangerous on a shared
# PON.  TX may have been disabled for a legitimate safety reason (OLT
# rogue-ONU shutdown, hardware overcurrent, emergency stop).  Blindly
# re-enabling it can interfere with other subscribers and get the ONU's
# serial number blacklisted by the ISP.
#
# To mitigate this, we only re-enable TX when ALL of the following hold:
#   1. UCI option 8311.config.enable_txstatus is "1" (user opted in)
#   2. PLOAM state is O5 (operational / associated with the OLT)
#   3. The OLT has not emergency-stopped us (rogue ONU detection)
#   4. Downstream RX signal is present (fiber is connected and lit)
#
# If any check fails, TX is left disabled and the reason is logged.
#
# Only active when UCI option 8311.config.enable_txstatus is set to "1".
# ---------------------------------------------------------------------------
tx_status() {
	local enable_tx_monitor
	local tx_state
	local ploam_state
	local emergency_stop
	local rx_state

	enable_tx_monitor=$($uci -q get 8311.config.enable_txstatus)
	if [ "$enable_tx_monitor" != "1" ]; then
		return
	fi

	tx_state=$($optic bosa_tx_status_get | cut -f 2 -d ' ' | cut -f 2 -d '=' | sed s/[[:space:]]//g)
	if [ "$tx_state" = "1" ]; then
		return
	fi

	# TX is disabled — check whether it is safe to re-enable

	# Check 1: PLOAM must be in O5 (associated).  If not, the ONU has no
	# bandwidth allocation and must not transmit.
	ploam_state=$($onu ploam_state_get | cut -b 24)
	if [ "$ploam_state" != "5" ]; then
		logger -t "[monit_optic]" "TX disabled, not re-enabling: PLOAM state $ploam_state (not O5)"
		return
	fi

	# Check 2: Emergency stop must not be active.  If the OLT flagged us as
	# a rogue ONU, re-enabling would make things worse.
	emergency_stop=$(fw_printenv ploam_emergency_stop_state 2>&- | cut -f 2 -d '=')
	if [ "$emergency_stop" = "1" ]; then
		logger -t "[monit_optic]" "TX disabled, not re-enabling: emergency stop active (rogue ONU)"
		return
	fi

	# Check 3: Downstream RX signal must be present.  No downstream means
	# the fiber is disconnected or the OLT port is dark — transmitting
	# upstream into this state is pointless and potentially harmful.
	rx_state=$($optic bosa_rx_status_get | cut -f 8 -d ' ' | cut -f 2 -d '=' | sed s/[[:space:]]//g)
	if [ "$rx_state" != "1" ]; then
		logger -t "[monit_optic]" "TX disabled, not re-enabling: no downstream RX signal"
		return
	fi

	# All safety checks passed — likely a transient BOSA fault
	# stderr suppressed (2>&-) because bosa_tx_enable may emit
	# harmless warnings when TX is already in a transitional state
	$optic bosa_tx_enable 2>&-
	logger -t "[monit_optic]" "TX disabled detected (O5, RX ok, no emergency stop) — re-enabled"
}

# ---------------------------------------------------------------------------
# Main loop — polls signal and transmitter status each cycle.
# ---------------------------------------------------------------------------
while true
do
	sig_status
	tx_status
	sleep "$MAIN_LOOP_INTERVAL"
done
