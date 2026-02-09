#!/bin/sh
# monitomcid.sh — Background daemon that monitors the omcid (OMCI daemon) for
# critical error conditions and manages LCT (Local Craft Terminal) port health.
#
# Responsibilities:
#   1. Detects kernel FIFO overflow errors and force-reboots if they exceed a
#      safe threshold (indicates a hardware/driver-level bus fault).
#   2. Monitors COP (Customer Ordered Premises) error counters reported by the
#      ONU GPE table; triggers a diagnostic dump, raises an OMCI alarm, and
#      reboots when a COP protocol error is detected.
#   3. Periodically pings two configured track IPs to verify LCT port
#      connectivity; if both are unreachable for a sustained period, the LCT
#      Ethernet port is power-cycled (disabled then re-enabled).
#
# Dependencies:
#   /opt/lantiq/bin/onu        — ONU hardware control CLI
#   /opt/lantiq/bin/debug      — diagnostic log collection
#   /opt/lantiq/bin/omci_pipe.sh — OMCI managed entity alarm interface
#   /sbin/uci                  — OpenWrt Unified Configuration Interface
#   fw_setenv                  — U-Boot environment variable writer
#
# Runtime:
#   Started as a background daemon during boot. The main loop runs every
#   MAIN_LOOP_INTERVAL seconds indefinitely, calling each health check in turn.

onu="/opt/lantiq/bin/onu"
uci="/sbin/uci"

# ---------------------------------------------------------------------------
# Named constants
# ---------------------------------------------------------------------------

# Number of kernel "FIFO[device] overflow" messages in dmesg that triggers a
# forced reboot. This threshold guards against a runaway hardware/DMA fault
# that would otherwise corrupt data silently.
FIFO_OVERFLOW_THRESHOLD=50

# The ONU TSE (Transaction Sequence Error) error base value. COP status error
# codes are computed as: ONU_TSE_ERROR_BASE - COP_STATUS_ERR.  Any composite
# error_code below this base therefore indicates a COP protocol failure.
# Reference: ONU_TSE_ERROR_BASE = -4000, so e.g. COP_STATUS_ERR_RESP_LEN (512)
# yields error_code = -4000 - 512 = -4512.
COP_ERROR_BASE=-4000

# Seconds to sleep between iterations of the main monitoring loop.
MAIN_LOOP_INTERVAL=15

# ---------------------------------------------------------------------------
# Runtime state
# ---------------------------------------------------------------------------

lct_wait_count=0
lct_try_count=0

# UCI-configured tunables (may be empty if not set by user):
#   lct_restart_try  — master enable (1) for LCT port restart feature
#   total_lct_wait   — consecutive failed-ping cycles before restarting LCT
#   total_lct_try    — max number of LCT port restarts before giving up
#   trackip1/2       — two IP addresses used to probe LCT connectivity
lct_restart_try=$($uci -q get 8311.config.lct_restart_try)
total_lct_wait=$($uci -q get 8311.config.total_lct_wait)
total_lct_try=$($uci -q get 8311.config.total_lct_try)
trackip1=$($uci -q get 8311.config.trackip1)
trackip2=$($uci -q get 8311.config.trackip2)
persist_log_on_reboot=$($uci -q get 8311.config.persist_log_on_reboot)

# ---------------------------------------------------------------------------
# check_onu_status — Detect kernel FIFO overflow and force-reboot if critical.
#
# Scans dmesg for "FIFO[device] overflow" messages.  If the count exceeds
# FIFO_OVERFLOW_THRESHOLD the device is in a degraded hardware state that
# cannot be recovered at runtime, so we capture diagnostics (when configured)
# and perform an immediate forced reboot.
# ---------------------------------------------------------------------------
check_onu_status() {
	local fifo_overflow_count
	fifo_overflow_count=$(dmesg | grep -c "FIFO\[device\] overflow")
	if [ "$fifo_overflow_count" -gt "$FIFO_OVERFLOW_THRESHOLD" ]; then
		if [ "$persist_log_on_reboot" = "1" ]; then
			/opt/lantiq/bin/debug
			cp /tmp/log/one_click /root
		fi
		# rebootcause=2 signals "FIFO overflow" to the boot environment
		fw_setenv rebootcause 2
		reboot -f
	fi
}

# ---------------------------------------------------------------------------
# check_cop_error — Read COP error counters and reboot on protocol failure.
#
# Uses `onu gpetr 10 1` to read GPE (Generic Processing Engine) table row 10,
# column 1, which holds the COP error counter/status.  The returned string is
# in "nReturn=<code> ..." format; we extract the numeric code.
#
# If error_code < COP_ERROR_BASE (-4000) the ONU has experienced a COP
# protocol-level failure (e.g. response length mismatch = -4512).  In that
# case we:
#   1. Dump diagnostics to persistent storage.
#   2. Raise OMCI alarm 6 ("ONU self-test failure") on ME 256 (ONU-G) to
#      notify the OLT.
#   3. Record rebootcause and force-reboot.
#
# After reboot the alarm sequence number resets; the OLT reconciles alarm
# state via "get all alarms", so no explicit alarm-clear is needed here.
# ---------------------------------------------------------------------------
check_cop_error() {
	local cop_result
	local cop_status
	local error_code

	# Read GPE table: row 10 = COP error counter, column 1 = status value
	cop_result=$($onu gpetr 10 1)

	# cop_result format: "nReturn=<code> <other fields ...>"
	# Strip everything after the first space, then everything before '='
	cop_status=${cop_result%% *}
	error_code=${cop_status#*=}

	# Any code below COP_ERROR_BASE means a COP protocol error occurred.
	# (e.g. -4512 = ONU_TSE_ERROR_BASE - COP_STATUS_ERR_RESP_LEN)
	if [ "$error_code" -lt "$COP_ERROR_BASE" ]; then
		/opt/lantiq/bin/debug
		cp /tmp/log/one_click /root

		# Raise OMCI alarm: ME class 256 (ONU-G), instance 0,
		# alarm number 6 ("ONU self-test failure"), state 1 (active)
		/opt/lantiq/bin/omci_pipe.sh managed_entity_alarm_set 256 0 6 1
		sleep 10

		# rebootcause=4 signals "COP error" to the boot environment
		fw_setenv rebootcause 4
		reboot -f

		# Post-reboot note: The OLT reconciles alarm state when it detects
		# a gap in the alarm sequence number (which resets on reboot), so
		# there is no need to explicitly clear the COP alarm before rebooting.
	fi
}

# ---------------------------------------------------------------------------
# reset_lct_wait — Reset the LCT ping-failure wait counter to zero.
#
# Called when connectivity is restored (at least one track IP responds) or
# after an LCT port restart, so the wait cycle begins fresh.
# ---------------------------------------------------------------------------
reset_lct_wait() {
	lct_wait_count=0
}

# ---------------------------------------------------------------------------
# restart_lct_port — Power-cycle the LCT Ethernet port (port 0).
#
# Disables and re-enables LAN port 0 with a 5-second pause between each
# step to allow the PHY to fully settle.  Increments lct_try_count and
# resets the wait counter.  Stops attempting after total_lct_try restarts
# to avoid an infinite restart loop if the fault is permanent.
# ---------------------------------------------------------------------------
restart_lct_port() {
	if [ "$lct_try_count" -lt "$total_lct_try" ]; then
		# Power-cycle sequence: disable → wait → enable → wait
		$onu lan_port_disable 0
		sleep 5
		$onu lan_port_enable 0
		sleep 5
		lct_try_count=$((lct_try_count + 1))
		reset_lct_wait
	else
		logger -t "[monitomcid]" "LCT total restart reached, current lct try times: $lct_try_count, giving up ..."
	fi
}

# ---------------------------------------------------------------------------
# check_lct_status — Monitor LCT port connectivity via dual-IP ping probes.
#
# Requires all of the following UCI settings to be configured and non-empty:
#   lct_restart_try=1, total_lct_wait, total_lct_try, trackip1, trackip2
#
# State machine:
#   - Both IPs unreachable: increment lct_wait_count toward total_lct_wait.
#   - Either IP reachable:  reset lct_wait_count (link is healthy).
#   - lct_wait_count reaches total_lct_wait: trigger restart_lct_port.
#
# Params (implicit, via globals):
#   trackip1, trackip2    — IP addresses to ping
#   total_lct_wait        — wait cycles before restart
#   total_lct_try         — max restart attempts
# ---------------------------------------------------------------------------
check_lct_status() {
	local ping_status_1
	local ping_status_2
	if [ "$lct_restart_try" = "1" ] && [ -n "$total_lct_wait" ] && [ -n "$total_lct_try" ] && [ -n "$trackip1" ] && [ -n "$trackip2" ]; then
		# grep -c "100% packet loss" returns 1 when ping fails completely
		ping_status_1=$(ping -W 1 -c 3 "$trackip1" | grep -c "100% packet loss")
		ping_status_2=$(ping -W 1 -c 3 "$trackip2" | grep -c "100% packet loss")
		if [ "$ping_status_1" = "1" ] && [ "$ping_status_2" = "1" ] && [ "$lct_wait_count" -lt "$total_lct_wait" ]; then
			logger -t "[monitomcid]" "LCT port link error detected, current lct wait times: $lct_wait_count ,waiting ..."
			lct_wait_count=$((lct_wait_count + 1))
		fi
		# If either IP is reachable, link is functional — reset wait counter
		if [ "$ping_status_1" != "1" ] || [ "$ping_status_2" != "1" ]; then
			reset_lct_wait
		fi
		# Wait threshold reached — attempt a port restart
		if [ "$lct_wait_count" -eq "$total_lct_wait" ]; then
			logger -t "[monitomcid]" "LCT total wait times: $lct_wait_count reached, restarting ..."
			restart_lct_port
		fi
	fi
}

# ---------------------------------------------------------------------------
# Main loop — runs each health check sequentially, then sleeps.
# ---------------------------------------------------------------------------
monitomcid() {
	while true; do
		check_lct_status
		check_onu_status
		check_cop_error
		sleep "$MAIN_LOOP_INTERVAL"
	done
}

monitomcid
