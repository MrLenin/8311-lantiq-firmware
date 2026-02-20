#!/bin/sh /etc/rc.common
# Copyright (C) 2011 OpenWrt.org
# Copyright (C) 2011 lantiq.com
#
# omcid.sh -- OMCI Daemon Init Script (init priority 85)
#
# Configures and launches the OMCI daemon (omcid) as a procd-managed service.
# Responsible for:
#   - Resolving the MIB file (env > UCI > auto-select by UNI type)
#   - Patching MIB identity fields, slot, and hardware version via sed
#   - Setting OMCC version, IOP mask, LCT interface, and log level
#   - Validating the omcid binary and restoring/modding it as needed
#
# Dependencies:
#   /opt/lantiq/bin/omcid          - OMCI daemon binary
#   /opt/lantiq/bin/config_onu.sh  - Binary restore/mod helper
#   /lib/falcon.sh                 - Board helpers
#   /etc/mibs/*.ini                - MIB template files
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

# Stock identity constants -- used to detect whether MIB patching is needed.
STOCK_VENDOR_ID="ALCL"
STOCK_EQUIPMENT_ID="BVL3A5HNAAG010SP"
STOCK_HW_VER="3FE56641AAAA01"

# start_service -- procd hook: resolve configuration and launch omcid.
#
# Configuration resolution phases:
#   0. Failsafe     -- optional startup delay for recovery access
#   1. MIB file     -- env > UCI > auto-select by UNI type
#   2. OMCI status  -- status file path for runtime counters
#   3. OMCC version -- protocol version (default 160 / 0xA0 baseline)
#   4. LCT iface    -- map network.lct.ifname to omcid -g flag
#   5. IOP mask     -- interop workaround bitmask (env > UCI > 0)
#   6. Binary check -- validate omcid, restore/mod if needed
#   7a. Log level   -- 1-7 (default 3)
#   7b. MIB patch   -- identity, pon_slot, cp_hw_ver_sync via sed
#   7c. Bank override -- override committed_image fwenv
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
	local uni_type
	local vendor_id
	local equipment_id
	local hw_ver
	local omcid_valid
	local failsafe_delay

	#is_flash_boot && wait_for_jffs

	# --- Phase 0: Failsafe delay ---
	# Delay omcid startup to give the user time to access the device
	# before it registers on the PON (useful for recovery from bad OMCI config).
	failsafe_delay=$(uci -q get 8311.config.failsafe_delay)
	if [ -n "$failsafe_delay" ] && [ "$failsafe_delay" -gt 0 ] 2>/dev/null; then
		logger -t "[omcid]" "Failsafe delay: waiting $failsafe_delay seconds before starting omcid ..."
		sleep "$failsafe_delay"
	fi

	# --- Phase 1: Resolve MIB file ---
	# Priority: U-Boot env mib_file > UCI mib_file (if not "auto.ini") > auto
	# Auto mode selects the stock template by UNI type (PPTP or VEIP) and
	# patches identity fields via sed in Phase 7b if they differ from stock.
	local need_identity_patch=0

	mib_file_env=$(fw_printenv mib_file 2>&- | cut -f 2 -d '=')
	mib_file_uci=$(uci -q get 8311.config.mib_file)
	uni_type=$(uci -q get 8311.config.uni_type)
	vendor_id=$(uci -q get 8311.config.vendor_id)
	equipment_id=$(uci -q get 8311.config.equipment_id)
	hw_ver=$(uci -q get 8311.config.hw_ver)

	if [ -f "/etc/mibs/$mib_file_env" ]; then
		# Env points to a real file on disk -- use it directly
		mib_file="/etc/mibs/$mib_file_env"
	elif [ -n "$mib_file_uci" ] && [ "$mib_file_uci" != "auto.ini" ]; then
		# UCI specifies a non-auto MIB file
		mib_file="/etc/mibs/$mib_file_uci"
	else
		# Auto-select stock template by UNI type
		if [ "$(echo "$uni_type" | tr 'A-Z' 'a-z')" = "veip" ]; then
			mib_file="/etc/mibs/data_1v_8q.ini"
		else
			mib_file="/etc/mibs/data_1g_8q_us1280_ds512.ini"
		fi
		need_identity_patch=1
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

	# --- Phase 7b: MIB file patching ---
	# All MIB modifications are applied here via sed on a working copy in
	# /tmp, preserving the original templates on disk.
	#
	# Patches applied (in order):
	#   1. Identity  -- vendor_id, hw_ver (ME 256), equipment_id (ME 257)
	#                   Auto mode only; skipped if identity matches stock.
	#   2. pon_slot  -- UNI slot number in ME 5, 6, 11, 264, 329
	#   3. cp_hw_ver_sync -- Circuit Pack version field in ME 6
	#
	# Each sed replaces only the target token(s) in the line, preserving
	# all template-specific fields (ANI slot types, queue metrics, etc.).
	local pon_slot
	local cp_hw_ver_sync
	local mib_patched=0

	pon_slot=$(uci -q get 8311.config.pon_slot)
	cp_hw_ver_sync=$(uci -q get 8311.config.cp_hw_ver_sync)

	# --- 7b.1: Identity patching (auto mode only) ---
	if [ "$need_identity_patch" = "1" ]; then
		if [ "$vendor_id" != "$STOCK_VENDOR_ID" ] || \
		   [ "$equipment_id" != "$STOCK_EQUIPMENT_ID" ] || \
		   [ "$hw_ver" != "$STOCK_HW_VER" ]; then

			cp "$mib_file" /tmp/omcid_mib.ini
			mib_file="/tmp/omcid_mib.ini"
			mib_patched=1

			# Truncate to G.988 maximum attribute lengths
			local vid eid hver pad_len
			vid=$(printf '%.4s' "$vendor_id")
			hver=$(printf '%.14s' "$(echo "$hw_ver" | sed 's/\\0//g')")
			eid=$(printf '%.20s' "$(echo "$equipment_id" | sed 's/\\0//g')")

			# Right-pad with \0 sequences to fill fixed-width fields
			pad_len=$((14 - ${#hver}))
			if [ "$pad_len" -gt 0 ]; then
				hver="${hver}$(printf '%*s' "$pad_len" '' | sed 's/ /\\0/g')"
			fi
			pad_len=$((20 - ${#eid}))
			if [ "$pad_len" -gt 0 ]; then
				eid="${eid}$(printf '%*s' "$pad_len" '' | sed 's/ /\\0/g')"
			fi

			logger -t "[omcid]" "Patching MIB identity: vendor=$vid hw_ver=$hver equip=$eid"

			# ME 256 (ONT-G): replace vendor_id (attr 1) and hw_ver (attr 2)
			sed -i "s/^\(256 0 \)[^ ]* [^ ]*/\1${vid} ${hver}/" "$mib_file"

			# ME 257 (ONT2-G): replace equipment_id (attr 1)
			sed -i "s/^\(257 0 \)[^ ]*/\1${eid}/" "$mib_file"
		fi
	fi

	# --- 7b.2: UNI slot patching (all modes) ---
	if [ -n "$pon_slot" ]; then
		local slot_hex
		slot_hex=$(printf '%02x' "$pon_slot")
		logger -t "[omcid]" "Patching MIB: pon_slot=$pon_slot (0x${slot_hex})"

		if [ "$mib_patched" = "0" ]; then
			cp "$mib_file" /tmp/omcid_mib.ini
			mib_file="/tmp/omcid_mib.ini"
			mib_patched=1
		fi

		# Change UNI slot in CardHolder(5), CircuitPack(6), PPTP(11),
		# UNI-G(264), VEIP(329). Matches instance IDs ending in 01 (port 1)
		# only, preserving ANI entries which end in 80.
		sed -i \
			-e "s/^\([?! ]*5 \)0x[0-9a-fA-F][0-9a-fA-F]01 /\10x${slot_hex}01 /" \
			-e "s/^\([?! ]*6 \)0x[0-9a-fA-F][0-9a-fA-F]01 /\10x${slot_hex}01 /" \
			-e "s/^\([?! ]*11 \)0x[0-9a-fA-F][0-9a-fA-F]01 /\10x${slot_hex}01 /" \
			-e "s/^\([?! ]*264 \)0x[0-9a-fA-F][0-9a-fA-F]01 /\10x${slot_hex}01 /" \
			-e "s/^\([?! ]*329 \)0x[0-9a-fA-F][0-9a-fA-F]01 /\10x${slot_hex}01 /" \
			"$mib_file"
	fi

	# --- 7b.3: Circuit Pack version sync (all modes) ---
	if [ "$cp_hw_ver_sync" = "1" ] && [ -n "$hw_ver" ]; then
		logger -t "[omcid]" "Patching MIB: syncing Circuit Pack version to hw_ver=$hw_ver"

		if [ "$mib_patched" = "0" ]; then
			cp "$mib_file" /tmp/omcid_mib.ini
			mib_file="/tmp/omcid_mib.ini"
			mib_patched=1
		fi

		# Pad hw_ver to 14 chars with \0 sequences (G.988 Version attribute width)
		local padded_ver
		padded_ver=$(printf '%.14s' "$(echo "$hw_ver" | sed 's/\\0//g')")
		local pad_len=$((14 - ${#padded_ver}))
		if [ "$pad_len" -gt 0 ]; then
			padded_ver="${padded_ver}$(printf '%*s' "$pad_len" '' | sed 's/ /\\0/g')"
		fi

		# Replace Version field (field 5 after class ID) in all ME 6 lines
		sed -r \
			"s#^(([!? ]*)?6(\s+(\"[^\"]*\"|[^\"][^ ]*)){4}\s+)(\"[^\"]*\"|[^\"][^ ]*)#\1${padded_ver}#g" \
			-i "$mib_file"
	fi

	# --- 7b.4: Update auto.ini symlink ---
	if [ "$need_identity_patch" = "1" ]; then
		ln -sf "$mib_file" /etc/mibs/auto.ini
	fi

	# --- Phase 7c: Override committed firmware bank ---
	# omcid reads committed_image via fw_printenv at startup (ME 7).
	# Set the fwenv before launch; bypasses the fw_setenv wrapper which
	# blocks committed_image writes from OLT-initiated firmware updates.
	local override_commit
	override_commit=$(uci -q get 8311.config.override_commit)

	if [ -n "$override_commit" ]; then
		local commit_val=""
		case "$override_commit" in
			A) commit_val=0 ;;
			B) commit_val=1 ;;
		esac
		if [ -n "$commit_val" ]; then
			logger -t "[omcid]" "Overriding committed bank to: $override_commit ($commit_val)"
			/opt/lantiq/bin/fw_setenv committed_image "$commit_val"
		fi
	fi

	# --- Phase 7d: Dual-VLAN DS fix config ---
	# Write /tmp/8311_dual_vlan.conf if enabled. omcid reads this file at
	# runtime during ME 171 ExtVLAN table programming to detect and resolve
	# DS many-to-one collisions (multiple customer VIDs → same transport VID).
	local dual_vlan
	local dual_vlan_mapper_list
	local vlan_mapper_map

	dual_vlan=$(uci -q get 8311.config.dual_vlan)
	rm -f /tmp/8311_dual_vlan.conf

	if [ "$dual_vlan" = "1" ]; then
		vlan_mapper_map=$(uci -q get 8311.config.vlan_mapper_map)
		dual_vlan_mapper_list=$(uci -q get 8311.config.dual_vlan_mapper_list)

		if [ -n "$vlan_mapper_map" ]; then
			# Explicit VID:mapper pairs — write one per line
			logger -t "[omcid]" "Dual-VLAN: explicit map: $vlan_mapper_map"
			echo "$vlan_mapper_map" | tr ',' '\n' | while read -r pair; do
				local vid mapper
				vid=${pair%%:*}
				mapper=${pair#*:}
				echo "${vid}:0x${mapper}"
			done > /tmp/8311_dual_vlan.conf
		elif [ -n "$dual_vlan_mapper_list" ]; then
			# Auto mode with mapper ME ID list
			logger -t "[omcid]" "Dual-VLAN: auto with mappers: $dual_vlan_mapper_list"
			echo "auto" > /tmp/8311_dual_vlan.conf
			echo "$dual_vlan_mapper_list" | tr ',' '\n' | while read -r id; do
				echo "0x${id}"
			done >> /tmp/8311_dual_vlan.conf
		else
			# No mapper info — can't activate without mapper ME IDs
			logger -t "[omcid]" "Dual-VLAN: enabled but no mapper IDs configured, feature inactive"
		fi
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
