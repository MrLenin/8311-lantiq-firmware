#!/bin/sh /etc/rc.common
# Copyright (C) 2009 OpenWrt.org
# Copyright (C) 2010 lantiq.com
#
# onu.sh -- ONU Hardware Initialization (init priority 61)
#
# First-stage init script that brings up the GPON ONU hardware layer.
# Execution order:  PLOAM -> GTC -> GPHY -> GPE -> shared buffers -> watchdog
#
# Dependencies:
#   /opt/lantiq/bin/onu          - Lantiq ONU CLI tool (all hardware commands)
#   /opt/lantiq/bin/sfp_i2c      - SFP I2C EEPROM reader (serial number)
#   /lib/falcon.sh               - Board-specific helpers (falcon_olt_type_get, etc.)
#   /etc/config/gpon             - UCI config sections: gtc, ploam, ethernet, gpe
#   /opt/lantiq/bin/config_onu.sh - Post-init ONU configuration
#
# Boot flow position: START=61, runs after base networking but before omcid (85).

START=61

# ---------------------------------------------------------------------------
# Shared buffer segment constants (GPE Traffic Management Unit)
# ---------------------------------------------------------------------------
IQM_GLOBAL_SEGMENTS_MAX=1024        # Input Queue Manager ceiling (both modes)
FTTDP_TMU_SEGMENTS=8800             # FTTdp: smaller shared buffer pool
DEFAULT_TMU_SEGMENTS=12288          # Standard GPON: default TMU global threshold

# ---------------------------------------------------------------------------
# Power-saving mode values for psmcs (GTC_powerSavingMode_t)
# ---------------------------------------------------------------------------
POWER_SAVING_OFF=0
# POWER_SAVING_DOZE=1
# POWER_SAVING_CYCLIC_SLEEP=2
# POWER_SAVING_WATCHFUL_SLEEP=4

# Dying gasp: sentinel values used when toggling hardware dying-gasp support
DYING_GASP_ENABLED=1
DYING_GASP_DISABLED=0

. "$IPKG_INSTROOT/lib/falcon.sh"

# log -- Emit a tagged daemon.err message to the console.
log() {
	logger -s -p daemon.err -t "[onu]" "$*" 2> /dev/console
}

# onu -- Wrapper around /opt/lantiq/bin/onu that checks the return status.
#   $* : arguments forwarded verbatim to the onu binary
# Logs an error if the command does not return "errorcode=0".
onu() {
	#echo "onu $*"
	result=$(/opt/lantiq/bin/onu "$*")
	#echo "result $result"
	status=${result%% *}
	if [ "$status" != "errorcode=0" ]; then
		log "onu $* failed: $result"
	fi
}

# ploam_config -- Resolve the GPON serial number and initialise PLOAM messaging.
#
# Serial number resolution order (first non-empty wins):
#   1. SFP I2C EEPROM (sfp_i2c -g), retried up to 5 times
#   2. U-Boot environment variable  (nSerial)
#   3. Synthesised from Lantiq OID prefix "SPTC" + last 4 octets of ethaddr
#
# After resolution, calls ploam_init then programmes the serial via gtcsns.
ploam_config() {
	local gpon_sn

	gpon_sn=""

	# Retry up to 5 times -- the SFP I2C bus may not be ready immediately
	for _ in $(seq 5);
	do
		gpon_sn=$(/opt/lantiq/bin/sfp_i2c -g 2>&- | cut -f 2 -d '=')

		if [ -n "$gpon_sn" ]; then
			break
		fi
	done

	if [ -z "$gpon_sn" ]; then
		# Fallback: try U-Boot env
		gpon_sn=$(fw_printenv nSerial 2>&- | cut -f 2 -d '=')

		if [ -z "$gpon_sn" ]; then
			# Last resort: synthesise from Lantiq OID + MAC address tail
			ethaddr=$(awk 'BEGIN{RS=" ";FS="="} $1 == "ethaddr" {print $2}' /proc/cmdline)
			gpon_sn=$(echo "$ethaddr" | awk 'BEGIN{FS=":"} {print "SPTC"$3""$4""$5""$6""}')
		fi
	fi

	# Initialise PLOAM state machine before setting the serial number
	onu ploam_init

	logger -t "[onu]" "Using ploam serial number: $gpon_sn"

	onu gtcsns "$gpon_sn"
}

# gtc_config -- Configure the GTC (GPON Transmission Convergence) layer.
#
# Reads DLOS, laser timing, power-saving, rogue-ONU, and dying-gasp
# parameters from UCI (gpon.gtc / gpon.ploam) and U-Boot env, then
# programmes them into the hardware via the onu CLI.
#
# Parameter types (from Lantiq SDK headers):
#   bDlosEnable            bool     - downstream LOS detection on/off
#   bDlosInversion         bool     - invert LOS signal polarity
#   nDlosWindowSize        uint8_t  - LOS detection window (in frames)
#   nDlosTriggerThreshold  uint32_t - LOS frame-count threshold
#   nLaserGap              uint8_t  - gap between laser bursts
#   nLaserOffset           uint8_t  - laser enable offset
#   nLaserEnEndExt         uint8_t  - laser enable end extension
#   nLaserEnStartExt       uint8_t  - laser enable start extension
#
# GTC_powerSavingMode_t ePower:
#   POWER_SAVING_OFF            = 0
#   POWER_SAVING_DOZE           = 1
#   POWER_SAVING_CYCLIC_SLEEP   = 2
#   POWER_SAVING_WATCHFUL_SLEEP = 4

gtc_config() {
	local bDlosEnable
	local bDlosInversion
	local nDlosWindowSize
	local nDlosTriggerThreshold
	local ePower
	local nLaserGap
	local nLaserOffset
	local nLaserEnEndExt
	local nLaserEnStartExt
	local nPassword
	local nT01
	local nT02

	local nDyingGaspEnable
	local nDyingGaspHyst
	local nDyingGaspMsg

	config_get bDlosEnable "gtc" bDlosEnable
	config_get bDlosInversion "gtc" bDlosInversion
	config_get nDlosWindowSize "gtc" nDlosWindowSize
	config_get nDlosTriggerThreshold "gtc" nDlosTriggerThreshold

	config_get ePower "gtc" ePower

	config_get nLaserGap "gtc" nLaserGap
	config_get nLaserOffset "gtc" nLaserOffset
	config_get nLaserEnEndExt "gtc" nLaserEnEndExt
	config_get nLaserEnStartExt "gtc" nLaserEnStartExt

	# PLOAM password: prefer U-Boot env, fall back to UCI
	nPassword=""
	nPassword=$(fw_printenv nPassword 2>&- | cut -f 2 -d '=')

	if [ -z "$nPassword" ]; then
		config_get nPassword "ploam" nPassword
	fi

	config_get nRogueMsgIdUpstreamReset "ploam" nRogueMsgIdUpstreamReset
	config_get nRogueMsgRepeatUpstreamReset "ploam" nRogueMsgRepeatUpstreamReset
	config_get nRogueMsgIdDeviceReset "ploam" nRogueMsgIdDeviceReset
	config_get nRogueMsgRepeatDeviceReset "ploam" nRogueMsgRepeatDeviceReset
	config_get nRogueEnable "ploam" nRogueEnable

	config_get nT01 "ploam" nT01
	config_get nT02 "ploam" nT02
	
	# Dying gasp: prefer U-Boot env; fall back to UCI only if the env
	# value is missing or invalid (anything other than 0 or 1).
	nDyingGaspEnable=""
	nDyingGaspEnable=$(fw_printenv nDyingGaspEnable 2>&- | cut -f2 -d=)

	if [ -z "$nDyingGaspEnable" ] || { [ "$nDyingGaspEnable" -ne "$DYING_GASP_ENABLED" ] && [ "$nDyingGaspEnable" -ne "$DYING_GASP_DISABLED" ]; }; then
	     config_get nDyingGaspEnable "gtc" nDyingGaspEnable
	fi
	
	config_get nDyingGaspHyst "gtc" nDyingGaspHyst
	config_get nDyingGaspMsg "gtc" nDyingGaspMsg

	# gtccs: GTC configuration set -- timers, rogue-ONU params, emergency stop, password
	onu gtccs 3600000 5 9 10 "$nRogueMsgIdUpstreamReset" "$nRogueMsgRepeatUpstreamReset" "$nRogueMsgIdDeviceReset" "$nRogueMsgRepeatDeviceReset" "$nRogueEnable" "$nT01" "$nT02" "$(falcon_ploam_emergency_stop_state_get)" "$nPassword"
	# gtci: GTC init -- DLOS detection + laser timing parameters
	onu gtci "$bDlosEnable" "$bDlosInversion" "$nDlosWindowSize" "$nDlosTriggerThreshold" "$nLaserGap" "$nLaserOffset" "$nLaserEnEndExt" "$nLaserEnStartExt"

	onu gtc_dying_gasp_cfg_set "$nDyingGaspEnable" "$nDyingGaspHyst" "$nDyingGaspMsg"

	# psmcs: power-saving mode config set -- only ePower is meaningful here;
	# remaining 9 zeros are reserved/unused timer fields
	onu psmcs "$ePower" 0 0 0 0 0 0 0 0 0
}

# nmea_config -- Set GPE Time-of-Day NMEA format and offset.
#   Reads from UCI section "nmea.message".
nmea_config() {
	local nmea_format
	local time_offset

	config_load nmea
	config_get nmea_format "message" nmea_format
	config_get time_offset "message" time_offset
	onu gpe_tod_nmea_cfg_set "$nmea_format" "$time_offset"
}

# start -- Main entry point (rc.common hook). Orchestrates full ONU hardware init.
#
# Sequence:
#   1. Load UCI gpon config (ethernet port enables, GPE PE count)
#   2. PLOAM init  -- resolve serial number, start PLOAM state machine
#   3. GTC config  -- laser, DLOS, power-saving, dying gasp, rogue-ONU
#   4. GPHY fw     -- download PHY firmware if present on flash
#   5. GPE init    -- load GPE firmware, enable UNI ports
#   6. NMEA ToD    -- configure time-of-day format
#   7. Shared bufs -- size TMU segment pool (FTTdp vs standard)
#   8. Watchdog    -- enable GTC watchdog if optic is calibrated
#   9. config_onu  -- run post-init configuration script
start() {
	local cfg="ethernet"
	local bUNI_PortEnable0
	local bUNI_PortEnable1
	local bUNI_PortEnable2
	local bUNI_PortEnable3
	local nPeNumber
	local fw="falcon_gpe_fw.bin"

	config_load gpon

	config_get bUNI_PortEnable0 "$cfg" bUNI_PortEnable0
	config_get bUNI_PortEnable1 "$cfg" bUNI_PortEnable1
	config_get bUNI_PortEnable2 "$cfg" bUNI_PortEnable2
	config_get bUNI_PortEnable3 "$cfg" bUNI_PortEnable3

	config_get nPeNumber "gpe" nPeNumber

	# --- Step 1-2: Initialise PLOAM and programme the GPON serial number ---
	ploam_config

	# --- Step 3: Configure the GTC hardware layer ---
	gtc_config

	# --- Step 4: Download GPHY firmware, if file is available ---
	[ -f /lib/firmware/phy11g.bin ] || [ -f /lib/firmware/a1x/phy11g.bin ] || [ -f /lib/firmware/a2x/phy11g.bin ] && onu langfd "phy11g.bin"

	# Log enabled hardware modules before GPE init for debugging
	cat /proc/driver/onu/sys

	# --- Step 5: Initialise GPE (GPON Processing Engine) ---
	# Use hgu-specific firmware if available; otherwise the default image.
	# gpei args: fw, ANI enables(3x1), UNI port enables (0-3, repeated for
	# ingress+egress), OMCI(1), CPU(1), reserved(0), PE count, padding(2x0),
	# OLT type.
	[ -f /lib/firmware/hgu/falcon_gpe_fw1.bin ] && fw="falcon_gpe_fw1.bin"
	onu gpei $fw 1 1 1 "$bUNI_PortEnable0" "$bUNI_PortEnable1" "$bUNI_PortEnable2" "$bUNI_PortEnable3" "$bUNI_PortEnable0" "$bUNI_PortEnable1" "$bUNI_PortEnable2" "$bUNI_PortEnable3" 1 1 0 "$nPeNumber" 0 0 "$(falcon_olt_type_get)"

	# --- Step 6: NMEA Time-of-Day configuration ---
	nmea_config

	# --- Step 7: Configure GPE shared buffer pool ---
	# gpe_shared_buffer_cfg_set params:
	#   iqm_global_segments_max, tmu_global_segments_{max,green,yellow,red}
	# FTTdp deployments use a smaller buffer (FTTDP_TMU_SEGMENTS) because the
	# shorter fibre distance allows tighter memory budgets.
	if [ -f "/etc/config/.fttdp" ]; then
		onu gpe_shared_buffer_cfg_set $IQM_GLOBAL_SEGMENTS_MAX $FTTDP_TMU_SEGMENTS $FTTDP_TMU_SEGMENTS $FTTDP_TMU_SEGMENTS $FTTDP_TMU_SEGMENTS
	else
		onu gpe_shared_buffer_cfg_set $IQM_GLOBAL_SEGMENTS_MAX $DEFAULT_TMU_SEGMENTS $DEFAULT_TMU_SEGMENTS $DEFAULT_TMU_SEGMENTS $DEFAULT_TMU_SEGMENTS
	fi

	# --- Step 8: Enable GTC watchdog only if the optic has been calibrated ---
	if [ "$(falcon_goi_calibrated_get)" -ge 1 ]; then
		onu gtc_watchdog_set 1
	fi

	# --- Step 9: Run post-init ONU configuration ---
	/opt/lantiq/bin/config_onu.sh ignore
}

# stop -- Disable the ONU line (takes the PON link down).
stop() {
	# onules 0: ONU Line Enable Set = disabled
	onu onules 0
}
