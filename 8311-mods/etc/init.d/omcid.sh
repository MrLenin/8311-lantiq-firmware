#!/bin/sh /etc/rc.common
# Copyright (C) 2011 OpenWrt.org
# Copyright (C) 2011 lantiq.com
#
# omcid.sh -- OMCI Daemon Init Script (init priority 85)
#
# Configures and launches the OMCI daemon (omcid) as a procd-managed service.
# Responsible for:
#   - Resolving the MIB file (env -> UCI -> auto-generation from templates)
#   - Generating a custom MIB when mib_customized=1 (vendor_id, hw_ver, etc.)
#   - Setting OMCC version, IOP mask, LCT interface, and log level
#   - Validating the omcid binary and restoring/modding it as needed
#
# Dependencies:
#   /opt/lantiq/bin/omcid          - OMCI daemon binary
#   /opt/lantiq/bin/config_onu.sh  - Binary restore/mod helper
#   /lib/falcon.sh                 - Board helpers
#   /etc/mibs/*.ini                - MIB template files (nameless, pptp, veip)
#   /etc/config/8311               - 8311 UCI config
#
# Boot flow position: START=85, runs after onu.sh (61) and pin_cfg.sh (63).

. "$IPKG_INSTROOT/lib/falcon.sh"

START=85

USE_PROCD=1

OMCID_BIN=/opt/lantiq/bin/omcid

# ---------------------------------------------------------------------------
# OMCC version default (G.988 baseline message set version 0xA0 = 160 decimal)
# ---------------------------------------------------------------------------
OMCC_VERSION_DEFAULT=160

# ---------------------------------------------------------------------------
# IOP (Interoperability) mask default -- no workarounds enabled
# ---------------------------------------------------------------------------
IOP_MASK_DEFAULT=0

# ---------------------------------------------------------------------------
# OMCI log level range: 1 (critical) through 7 (verbose debug)
# ---------------------------------------------------------------------------
OMCI_LOG_LEVEL_DEFAULT=3

# status_entry_create -- Initialise the OMCI status file with tracking sections.
#   $1 : path to the status file (e.g. /tmp/omci_status)
# Creates the file and populates UCI-style status sections for IP conflicts,
# DHCP timeouts, and DNS errors that omcid will update at runtime.
status_entry_create() {
	local path
	local base
	local dir

	path=$1
	base=$(basename "$path")
	dir=$(dirname "$path")

	touch "$path"

	uci -c "$dir" set "$base.ip_conflicts=status"
	uci -c "$dir" set "$base.dhcp_timeouts=status"
	uci -c "$dir" set "$base.dns_errors=status"
}

# wait_for_jffs -- Block until the JFFS2 overlay is mounted.
# Used during early boot to ensure writable storage is available before
# touching config files.  Currently disabled (see start_service).
wait_for_jffs() {
	while ! grep overlayfs:/overlay /proc/self/mounts >/dev/null
	do
		sleep 1
	done
}

# is_flash_boot -- Return true (0) if running from flash with an overlay FS.
is_flash_boot() {
	grep overlayfs /proc/self/mounts >/dev/null
}

# generate_custom_mib -- Build a custom MIB file from user-supplied identity fields.
#
# Reads vendor_id, hw_ver, equipment_id, and uni_type from UCI 8311.config,
# then assembles /etc/mibs/custom.ini by:
#   1. Copying the base "nameless" template (no identity baked in)
#   2. Appending ONT-G (ME 256) with vendor_id + hw_ver
#   3. Appending ONT2-G (ME 257) with equipment_id
#   4. Appending either VEIP or PPTP UNI managed entities based on uni_type
#
# Field length limits (from G.988 attribute definitions):
#   vendor_id    :  4 chars  (truncated via printf %.4s)
#   hw_ver       : 14 chars  (null-padded with \0 to 14)
#   equipment_id : 20 chars  (null-padded with \0 to 20)
#
# Returns 1 if any required UCI field is missing or the template is absent.
generate_custom_mib() {
	vendor_id=$(uci -q get 8311.config.vendor_id) || return 1
	hw_ver=$(uci -q get 8311.config.hw_ver) || return 1
	equipment_id=$(uci -q get 8311.config.equipment_id) || return 1
	uni_type=$(uci -q get 8311.config.uni_type | tr 'A-Z' 'a-z') || return 1

	# Truncate to G.988 maximum attribute lengths
	vendor_id=$(printf '%.4s' "${vendor_id}")
	hw_ver=$(printf '%.14s' "$(echo "$hw_ver" | sed 's/\\0//g')")
	equipment_id=$(printf '%.20s' "$(echo "$equipment_id" | sed 's/\\0//g')")

	# Right-pad with literal \0 sequences to fill the fixed-width fields
	hw_ver=$(printf %s "$hw_ver" "$(printf '%*s' $((14-${#hw_ver})) '' | sed 's/[[:space:]]/\\0/g')")
	equipment_id=$(printf %s "$equipment_id" "$(printf '%*s' $((20-${#equipment_id})) '' | sed 's/[[:space:]]/\\0/g')")

	mibsrc='/etc/mibs/nameless.ini'
	mibtgt='/etc/mibs/custom.ini'

	pptpsrc='/etc/mibs/pptp.ini'
	veipsrc='/etc/mibs/veip.ini'

	if [ ! -f "${mibsrc}" ]; then
		return 1
	fi

	if [ -f ${mibtgt} ]; then
		rm -f ${mibtgt}
	fi

	# Start from the identity-less base template
	cp ${mibsrc} ${mibtgt}

	{
		# ONT-G (ME 256, instance 0): identity + vendor info
		printf '\n# ONT-G\n256 0 %s %s 00000000 2 0 0 0 0 #0\n' "${vendor_id}" "${hw_ver}"
		# ONT2-G (ME 257, instance 0): equipment ID + capability flags
		printf '\n# ONT2-G\n257 0 %s 0xa0 0xcc 1 1 64 64 1 64 0 0x007f 0 24 48\n' "${equipment_id}"

		# Append UNI type: VEIP for virtualised Ethernet, PPTP otherwise
		if [ -n "$uni_type" ] && [ "$uni_type" = "veip" ]; then
			printf '\n%s\n' "$(cat ${veipsrc})"
		else #if [ -n "$uni_type" ] && [ "$uni_type" == "pptp" ]; then
			printf '\n%s\n' "$(cat ${pptpsrc})"
		fi
	} >>${mibtgt}
}

# start_service -- procd hook: resolve configuration and launch omcid.
#
# Configuration resolution phases:
#   1. MIB file     -- env > UCI > auto-generate (custom or stock by UNI type)
#   2. OMCI status  -- status file path for runtime counters
#   3. OMCC version -- protocol version (default 160 / 0xA0 baseline)
#   4. LCT iface    -- map network.lct.ifname to omcid -g flag
#   5. IOP mask     -- interop workaround bitmask (env > UCI > 0)
#   6. Binary check -- validate omcid, restore/mod if needed
#   7. Log level    -- 1-7 (default 3)
#   8. Launch       -- procd-managed respawn with resolved parameters
start_service() {
	local mib_file
	local omcc_version
	local omci_status
	local mib_file_env
	local mib_file_uci
	local omci_status_uci
	local omcc_version_uci
	local iop_mask_env
	local iop_mask_uci
	local omci_iop_mask
	local lct=""
	local mib_customized
	local uni_type
	local omcid_valid

	#is_flash_boot && wait_for_jffs

	# --- Phase 1: Resolve MIB file ---
	# Priority: U-Boot env mib_file > UCI mib_file (if not "auto.ini") > auto
	mib_file_env=$(fw_printenv mib_file 2>&- | cut -f 2 -d '=')
	mib_file_uci=$(uci -q get 8311.config.mib_file)
	mib_customized=$(uci -q get 8311.config.mib_customized)
	uni_type=$(uci -q get 8311.config.uni_type)

	if [ -f "/etc/mibs/$mib_file_env" ]; then
		# Env points to a real file on disk -- use it directly
		mib_file="/etc/mibs/$mib_file_env"
	elif [ -n "$mib_file_uci" ] && [ "$(echo "$mib_file_uci" | grep -c "auto.ini")" != "1" ]; then
		# UCI specifies a non-auto MIB file -- use it as-is
		mib_file="$mib_file_uci"
	else
		# Auto-select: generate custom MIB or pick a stock template by UNI type
		if [ "$mib_customized" = "1" ]; then
			generate_custom_mib
			ln -sf /etc/mibs/custom.ini /etc/mibs/auto.ini
		else
			if [ -n "$uni_type" ] && [ "$uni_type" = "veip" ]; then
				ln -sf /etc/mibs/data_1v_8q.ini /etc/mibs/auto.ini
			else #if [ -n "$uni_type" ] && [ "$uni_type" == "pptp" ]; then
				ln -sf /etc/mibs/data_1g_8q_us1280_ds512.ini /etc/mibs/auto.ini
			fi
		fi
		mib_file="/etc/mibs/auto.ini"
		uci set "8311.config.mib_file=$mib_file"
		uci commit 8311
	fi

	# --- Phase 2: OMCI status file ---
	omci_status_uci=$(uci -q get 8311.config.omci_status)

	if [ -n "$omci_status_uci" ]; then
		omci_status=$omci_status_uci
	else
		omci_status="/tmp/omci_status"
		uci set 8311.config.omci_status=$omci_status
		uci commit 8311.config.omci_status
	fi

	status_entry_create "$omci_status"

	# --- Phase 3: OMCC version ---
	# Default OMCC_VERSION_DEFAULT (160 = 0xA0 = G.988 baseline message set)
	omcc_version_uci=$(uci -q get 8311.config.omcc_version)

	if [ -n "$omcc_version_uci" ]; then
		omcc_version=$omcc_version_uci
	else
		omcc_version=$OMCC_VERSION_DEFAULT
	fi

	# --- Phase 4: LCT (Local Craft Terminal) interface mapping ---
	# Maps the UCI network.lct.ifname to an omcid -g<N> parameter.
	# lctN -> -g(N+1), except lct8 -> -g9 (reserved for management).
	case $(uci -q get network.lct.ifname) in
	lct0)
		lct=-g1
		;;
	lct1)
		lct=-g2
		;;
	lct2)
		lct=-g3
		;;
	lct3)
		lct=-g4
		;;
	lct8)
		lct=-g9
		;;
	esac

	# --- Phase 5: IOP (interoperability) mask ---
	# Priority: U-Boot env > UCI > default (IOP_MASK_DEFAULT=0, no workarounds)
	iop_mask_env=$(fw_printenv omci_iop_mask 2>&- | cut -f2 -d=)
	iop_mask_uci=$(uci -q get 8311.config.iop_mask)

	if [ -n "$iop_mask_env" ]; then
		omci_iop_mask=$iop_mask_env
	elif [ -n "$iop_mask_uci" ]; then
		omci_iop_mask=$iop_mask_uci
	else
		omci_iop_mask=$IOP_MASK_DEFAULT
	fi

	logger -t "[omcid]" "Use OMCI mib file: $mib_file"

	# --- Phase 6: Validate / restore / mod the omcid binary ---
	# Check that the binary is a valid OMCI daemon (help output contains "OMCI").
	# If invalid, or if the version doesn't match the expected stock version and
	# mod_omcid is unset, restore the original binary from backup.
	# If mod_omcid=1 explicitly, apply the modded binary instead.
	omcid_valid=$(${OMCID_BIN} -h | grep -c OMCI)
	omcid_version_default="6BA1896SPE2C05, internal_version =1620-00802-05-00-000D-01"
	omcid_version_current=$(${OMCID_BIN} -v | tail -n 1 | sed 's/\r//g' | cut -c 18-75)
	mod_omcid=$(uci -q get 8311.config.mod_omcid)

	if [ "$omcid_valid" = "0" ] || { [ -z "$mod_omcid" ] && [ "$omcid_version_default" != "$omcid_version_current" ]; }; then
		/opt/lantiq/bin/config_onu.sh restore
	elif [ "$mod_omcid" = "1" ]; then
		/opt/lantiq/bin/config_onu.sh mod
	fi

	# --- Phase 7: Log level ---
	# Valid range 1-7; anything else falls back to OMCI_LOG_LEVEL_DEFAULT (3).
	omci_log_level=$(uci -q get 8311.config.omci_log_level)

	if [ -z "$omci_log_level" ] || [ "$(echo "$omci_log_level" | grep -c '^[1-7]*$')" = "0" ]; then
		omci_log_level=$OMCI_LOG_LEVEL_DEFAULT
	fi

	omci_log_to_console=$(uci -q get 8311.config.omci_log_to_console)

	if [ -n "$omci_log_to_console" ]; then
		omci_log_path="/dev/console"
	else
		omci_log_path="/tmp/log/debug"
	fi

	# --- Phase 8: Launch omcid under procd with auto-respawn ---
	# omcid flags:
	#   -d  log level    -p  MIB file       -o  OMCC version
	#   -i  IOP mask     -g  LCT GEM port   -l  log output path
	procd_open_instance
	procd_set_param respawn
	procd_set_param command ${OMCID_BIN} -d "$omci_log_level" -p "$mib_file" -o "$omcc_version" -i "$omci_iop_mask" $lct -l $omci_log_path
	procd_set_param stdout 1
	procd_set_param stderr 1
	procd_close_instance
}

# stop_service -- Gracefully terminate the omcid process.
# Uses pgrep rather than procd tracking as a safety net in case procd
# lost track of the PID.
stop_service() {
	proc=$(pgrep omcid)
	if [ -n "$proc" ]; then
		kill "$proc"
	fi
}
