#!/bin/sh
# omci_sync_time.sh — Set Linux system clock from hardware ToD
# Called by omcid sync_time_action_handle (binary patch)
#
# The Falcon SoC has a hardware ToD clock (SBS2.TOD registers) that may
# be populated by the GTC layer when the OLT sends PLOAM Time of Day.
# We read it via "onu gpe_tod_get" and set the Linux clock if valid.
#
# The hardware counter (sec_tai) counts seconds since 1970-01-01 in TAI
# (no leap seconds). For UTC conversion we subtract the current leap
# second count. This is approximate but acceptable for a GPON stick.

# UCI config for leap second offset (default: 37, correct since 2017-01-01)
LEAP_SECONDS=$(uci -q get 8311.config.tai_utc_offset)
LEAP_SECONDS=${LEAP_SECONDS:-37}

tod=$(onu gpe_tod_get 2>/dev/null)
[ -z "$tod" ] && exit 1

sec_tai=$(echo "$tod" | sed -n 's/.*sec_tai=\([0-9]*\).*/\1/p')

# Validate: must be after 2000-01-01 (946684800)
if [ -n "$sec_tai" ] && [ "$sec_tai" -gt 946684800 ]; then
	utc_sec=$((sec_tai - LEAP_SECONDS))
	date -u -s "@${utc_sec}" >/dev/null 2>&1
	logger -t "[clock]" "System clock set from GPON ToD (sec_tai=${sec_tai})"
else
	# Hardware ToD not populated — try PLOAM reload registers
	tod_sync=$(onu gpetsg 2>/dev/null)
	tod_sec=$(echo "$tod_sync" | sed -n 's/.*tod_seconds=\([0-9]*\).*/\1/p')

	if [ -n "$tod_sec" ] && [ "$tod_sec" -gt 946684800 ]; then
		utc_sec=$((tod_sec - LEAP_SECONDS))
		date -u -s "@${utc_sec}" >/dev/null 2>&1
		logger -t "[clock]" "System clock set from PLOAM ToD (tod_seconds=${tod_sec})"
	fi
fi
