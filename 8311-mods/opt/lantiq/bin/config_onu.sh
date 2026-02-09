#!/bin/sh
# config_onu.sh — ONU configuration and identity management
#
# Called by omcid.sh init script and by LuCI backend handlers to manage:
#   - GPON serial number, PLOAM/LOID credentials (via sfp_i2c EEPROM writes)
#   - Vendor ID, equipment ID, HW version (MIB customization for ISP spoofing)
#   - Network interface settings (LCT IP, gateway, MAC addresses)
#   - omcid binary patching (version string, 802.1x enforcement)
#   - RX LOS GPIO override, factory reset, console/ASC toggle
#
# Usage: config_onu.sh <command>
# Commands: load, set, init, setip, update, mod, restore_sw_ver, restore_8021x,
#           ignore, disable, rebootcause, rebootnum, reboot, switch, switchasc,
#           initasc, factoryreset
#
# Dependencies: sfp_i2c, fw_printenv/fw_setenv, uci, onu CLI

command=$1

# Stock Alcatel G-010S-P identity values (used for factory reset)
STOCK_EQUIPMENT_ID="BVL3A5HNAAG010SP"
STOCK_HW_VER="3FE56641AAAA01"
STOCK_VENDOR_ID="ALCL"
omcid_stock_csum="0da3eb0b76af1df5f4df414e3fc09dbb"  # MD5 of baked-in patched omcid binary

# Read current identity from firmware env and sync to UCI config.
# Called during initial setup to populate the web UI with current values.
load_config() {
	local gpon_sn
	local omci_loid
	local omci_password
	local ploam_password
	local vendor_id_from_sn

	gpon_sn=$(fw_printenv nSerial 2>&- | cut -f 2 -d '=')
	omci_loid=$(fw_printenv omci_loid 2>&- | cut -f 2 -d '=')
	omci_password=$(fw_printenv omci_lpwd 2>&- | cut -f 2 -d '=')
	ploam_password=$(fw_printenv nPassword 2>&- | cut -f 2 -d '=' | /usr/bin/xxd -r)
	vendor_id_from_sn=$(fw_printenv nSerial 2>&- | cut -f 2 -d '=' | cut -c -4)

	uci set 8311.config.gpon_sn="${gpon_sn}"
	uci commit 8311.config.gpon_sn
	uci set 8311.config.omci_loid="${omci_loid}"
	uci commit 8311.config.omci_loid
	uci set 8311.config.omci_lpwd="${omci_password}"
	uci commit 8311.config.omci_lpwd
	uci set 8311.config.ploam_password="${ploam_password}"
	uci commit 8311.config.ploam_password
	uci set 8311.config.vendor_id="${vendor_id_from_sn}"
	uci commit 8311.config.vendor_id
}

# Apply UCI identity config to firmware env and EEPROM. Compares current values
# against stored values and only writes on change. Handles two serial number
# formats: 8-char ASCII ("ALCL12345678") or 16-char hex-encoded vendor + serial.
# Also manages MIB customization (vendor/equipment/HW overrides for ISP spoofing).
set_config() {
	local gpon_sn
	local omci_loid
	local omci_password
	local ploam_password
	local mib_customized
	local mib_customized_old
	local vendor_id_from_sn
	local gpon_sn_vendor
	local gpon_sn_serial
	local vendor_id
	local equipment_id
	local hw_ver

	gpon_sn=$(uci -q get 8311.config.gpon_sn)
	omci_loid=$(uci -q get 8311.config.omci_loid)
	omci_password=$(uci -q get 8311.config.omci_lpwd)
	ploam_password=$(uci -q get 8311.config.ploam_password)
	mib_customized=$(uci -q get 8311.config.mib_customized)
	mib_customized_old=$(uci -q get 8311.config.mib_customized_old)
	vendor_id_from_sn=$(echo "$gpon_sn" | cut -c -4)
	vendor_id=$(uci -q get 8311.config.vendor_id)
	equipment_id=$(uci -q get 8311.config.equipment_id)
	hw_ver=$(uci -q get 8311.config.hw_ver)

	local gpon_sn_old
	local omci_loid_old
	local omci_password_old
	local ploam_password_old

	gpon_sn_old=$(fw_printenv nSerial 2>&- | cut -f 2 -d '=')
	omci_loid_old=$(fw_printenv omci_loid 2>&- | cut -f 2 -d '=')
	omci_password_old=$(fw_printenv omci_lpwd 2>&- | cut -f 2 -d '=')
	ploam_password_old=$(fw_printenv nPassword 2>&- | cut -f 2 -d '=' | /usr/bin/xxd -r)

	local gpon_sn_len

	gpon_sn_len=${#gpon_sn}

	# 16-char hex SN format: first 8 chars = hex-encoded 4-char vendor (e.g.
	# "414c434c" -> "ALCL"), last 8 chars = hex serial number
	if [ -n "$gpon_sn_len" ] && [ "$gpon_sn_len" = "16" ]; then
		gpon_sn_vendor=$(echo "$gpon_sn" | cut -c 1-8 | /usr/bin/xxd -r -ps)
		gpon_sn_serial=$(echo "$gpon_sn" | cut -c 9-16)
		gpon_sn=$gpon_sn_vendor$gpon_sn_serial
		vendor_id_from_sn=$gpon_sn_vendor
	fi

	local gpon_sn_upper
	local gpon_sn_old_upper

	gpon_sn_upper=$(echo "$gpon_sn" | tr 'a-z' 'A-Z')
	gpon_sn_old_upper=$(echo "$gpon_sn_old" | tr 'a-z' 'A-Z')

	if [ -n "$gpon_sn_upper" ] && [ "$gpon_sn_upper" != "$gpon_sn_old_upper" ]; then
		logger -t "[config_onu]" "Setting Vendor ID: $vendor_id_from_sn."
		/opt/lantiq/bin/sfp_i2c -i7 -s "${vendor_id_from_sn}"
		uci set 8311.config.vendor_id="${vendor_id_from_sn}"
		uci commit 8311.config.vendor_id
		logger -t "[config_onu]" "Setting GPON SN: $gpon_sn."
		/opt/lantiq/bin/sfp_i2c -i8 -s "${gpon_sn}"
	elif [ -z "$gpon_sn" ]; then
		logger -t "[config_onu]" "Clearing GPON SN."
		/opt/lantiq/bin/sfp_i2c -i8 -s ""
	fi

	if [ "$mib_customized" = "1" ]; then
		if [ -n "$vendor_id" ]; then
			logger -t "[config_onu]" "Setting Vendor ID: $vendor_id."
			/opt/lantiq/bin/sfp_i2c -i7 -s "${vendor_id}"
			uci set 8311.config.vendor_id="${vendor_id}"
			uci commit 8311.config.vendor_id
		fi

		if [ -n "$equipment_id" ]; then
			logger -t "[config_onu]" "Setting Equipment ID: $equipment_id."
			/opt/lantiq/bin/sfp_i2c -i6 -s "${equipment_id}"
			uci set 8311.config.equipment_id="${equipment_id}"
			uci commit 8311.config.equipment_id
		fi

		if [ -n "$hw_ver" ]; then
			logger -t "[config_onu]" "Setting ONT Version: $hw_ver."
			uci set 8311.config.hw_ver="${hw_ver}"
			uci commit 8311.config.hw_ver
		fi

		if [ -z "$mib_customized_old" ]; then
			uci set 8311.config.mib_customized_old="${mib_customized}"
			uci commit 8311.config.mib_customized_old
		fi
	elif [ "$mib_customized_old" = "1" ]; then
		logger -t "[config_onu]" "Resetting Vendor ID."
		uci set 8311.config.vendor_id="${STOCK_VENDOR_ID}"
		uci commit 8311.config.vendor_id
		logger -t "[config_onu]" "Resetting Equipment ID."
		uci set 8311.config.equipment_id="${STOCK_EQUIPMENT_ID}"
		uci commit 8311.config.equipment_id
		logger -t "[config_onu]" "Resetting ONT Version."
		uci set 8311.config.hw_ver="${STOCK_HW_VER}"
		uci commit 8311.config.hw_ver
		uci delete 8311.config.mib_customized_old
		uci commit 8311.config.mib_customized_old
	fi

	if [ -n "$omci_loid" ] && [ "$omci_loid" != "$omci_loid_old" ]; then
		logger -t "[config_onu]" "Setting LOID: $omci_loid."
		/opt/lantiq/bin/sfp_i2c -i9 -s "${omci_loid}"
	elif [ -z "$omci_loid" ]; then
		logger -t "[config_onu]" "Clearing LOID."
		/opt/lantiq/bin/sfp_i2c -i9 -s ""
	fi

	if [ -n "$omci_password" ] && [ "$omci_password" != "$omci_password_old" ]; then
		logger -t "[config_onu]" "Setting LOID Password: $omci_password."
		/opt/lantiq/bin/sfp_i2c -i10 -s "${omci_password}"
	elif [ -z "$omci_password" ]; then
		logger -t "[config_onu]" "Clearing LOID Password."
		/opt/lantiq/bin/sfp_i2c -i10 -s ""
	fi

	if [ -n "$ploam_password" ] && [ "$ploam_password" != "$ploam_password_old" ]; then
		logger -t "[config_onu]" "Setting Ploam Password: $ploam_password."
		/opt/lantiq/bin/sfp_i2c -i11 -s "${ploam_password}"
	elif [ -z "$ploam_password" ]; then
		logger -t "[config_onu]" "Clearing Ploam Password."
		/opt/lantiq/bin/sfp_i2c -i11 -s ""
	fi
}

# Apply all identity settings unconditionally (no change detection).
# Called once during omcid.sh init before omcid starts. Also handles
# MIB customization and clears the rebootdirect flag.
init_config() {
	local gpon_sn
	local omci_loid
	local omci_password
	local ploam_password
	local vendor_id_from_sn
	local gpon_sn_vendor
	local gpon_sn_serial
	local mib_customized
	local mib_customized_old
	local gpon_sn_len
	local vendor_id
	local equipment_id
	local hw_ver

	gpon_sn=$(uci -q get 8311.config.gpon_sn)
	omci_loid=$(uci -q get 8311.config.omci_loid)
	omci_password=$(uci -q get 8311.config.omci_lpwd)
	ploam_password=$(uci -q get 8311.config.ploam_password)
	vendor_id_from_sn=$(echo "$gpon_sn" | cut -c -4)
	mib_customized=$(uci -q get 8311.config.mib_customized)
	mib_customized_old=$(uci -q get 8311.config.mib_customized_old)
	gpon_sn_len=${#gpon_sn}
	vendor_id=$(uci -q get 8311.config.vendor_id)
	equipment_id=$(uci -q get 8311.config.equipment_id)
	hw_ver=$(uci -q get 8311.config.hw_ver)

	if [ -n "$gpon_sn_len" ] && [ "$gpon_sn_len" = "16" ]; then
		gpon_sn_vendor=$(echo "$gpon_sn" | cut -c 1-8 | /usr/bin/xxd -r -ps)
		gpon_sn_serial=$(echo "$gpon_sn" | cut -c 9-16)
		gpon_sn=$gpon_sn_vendor$gpon_sn_serial
	fi

	if [ "$mib_customized" = "1" ]; then
		if [ -n "$vendor_id" ]; then
			logger -t "[config_onu]" "Setting Vendor ID: $vendor_id."
			/opt/lantiq/bin/sfp_i2c -i7 -s "${vendor_id}"
			uci set 8311.config.vendor_id="${vendor_id}"
			uci commit 8311.config.vendor_id
		fi

		if [ -n "$equipment_id" ]; then
			logger -t "[config_onu]" "Setting Equipment ID: $equipment_id."
			/opt/lantiq/bin/sfp_i2c -i6 -s "${equipment_id}"
			uci set 8311.config.equipment_id="${equipment_id}"
			uci commit 8311.config.equipment_id
		fi

		if [ -n "$hw_ver" ]; then
			logger -t "[config_onu]" "Setting ONT Version: $hw_ver."
			uci set 8311.config.hw_ver="${hw_ver}"
			uci commit 8311.config.hw_ver
		fi

		if [ -z "$mib_customized_old" ]; then
			uci set 8311.config.mib_customized_old="${mib_customized}"
			uci commit 8311.config.mib_customized_old
		fi
	elif [ "$mib_customized_old" = "1" ]; then
		logger -t "[config_onu]" "Resetting Vendor ID."
		uci set 8311.config.vendor_id="${STOCK_VENDOR_ID}"
		uci commit 8311.config.vendor_id
		logger -t "[config_onu]" "Resetting Equipment ID."
		uci set 8311.config.equipment_id="${STOCK_EQUIPMENT_ID}"
		uci commit 8311.config.equipment_id
		logger -t "[config_onu]" "Resetting ONT Version."
		uci set 8311.config.hw_ver="${STOCK_HW_VER}"
		uci commit 8311.config.hw_ver
		uci delete 8311.config.mib_customized_old
		uci commit 8311.config.mib_customized_old
	fi

	if [ -n "$gpon_sn" ]; then
		logger -t "[config_onu]" "Setting GPON SN: $gpon_sn."
		/opt/lantiq/bin/sfp_i2c -i8 -s "${gpon_sn}"
	fi

	if [ -n "$omci_loid" ]; then
		logger -t "[config_onu]" "Setting LOID: $omci_loid."
		/opt/lantiq/bin/sfp_i2c -i9 -s "${omci_loid}"
	fi

	if [ -n "$omci_password" ]; then
		logger -t "[config_onu]" "Setting LOID Password: $omci_password."
		/opt/lantiq/bin/sfp_i2c -i10 -s "${omci_password}"
	fi

	if [ -n "$ploam_password" ]; then
		logger -t "[config_onu]" "Setting Ploam Password: $ploam_password."
		/opt/lantiq/bin/sfp_i2c -i11 -s "${ploam_password}"
	fi

	uci -q delete 8311.config.rebootdirect
	uci -q commit 8311.config
}

# Sync network settings (LCT IP/gateway/MAC, host MAC) between UCI and firmware env.
# LCT = Local Craft Terminal (management interface on the SFP stick).
set_ip() {
	local lct_addr
	local lct_gateway
	local lct_mac
	local lct_proto
	local host_mac

	local lct_addr_old
	local lct_gateway_old
	local host_mac_old

	local lct_mac_upper
	local host_mac_upper
	local host_mac_old_upper

	lct_addr=$(uci -q get network.lct.ipaddr)
	lct_gateway=$(uci -q get network.lct.gateway)
	lct_mac=$(uci -q get network.lct.macaddr)
	lct_proto=$(uci -q get network.lct.proto)
	host_mac=$(uci -q get network.host.macaddr)

	lct_addr_old=$(fw_printenv ipaddr 2>&- | cut -f 2 -d '=')
	lct_gateway_old=$(fw_printenv gatewayip 2>&- | cut -f 2 -d '=')
	host_mac_old=$(fw_printenv ethaddr 2>&- | cut -f 2 -d '=')

	lct_mac_upper=$(echo "$lct_mac" | tr 'a-z' 'A-Z')
	host_mac_upper=$(echo "$host_mac" | tr 'a-z' 'A-Z')
	host_mac_old_upper=$(echo "$host_mac_old" | tr 'a-z' 'A-Z')

	if [ "$lct_addr" != "$lct_addr_old" ]; then
		logger -t "[config_onu]" "Setting IP Address: $lct_addr."
		fw_setenv ipaddr "${lct_addr}"
		uci set network.lct.ipaddr="${lct_addr}"
		uci commit network.lct
	fi

	if [ "$lct_gateway" != "$lct_gateway_old" ]; then
		logger -t "[config_onu]" "Setting Gateway IP Address: $lct_gateway."
		fw_setenv gatewayip "${lct_gateway}"
		uci set network.lct.gateway="${lct_gateway}"
		uci commit network.lct
	fi

	if [ -n "$lct_mac" ]; then
		logger -t "[config_onu]" "Setting Lct MAC Address: $lct_mac_upper."
		uci set network.lct.macaddr="${lct_mac_upper}"
		uci commit network.lct
	fi

	if [ "$lct_proto" != "static" ]; then
		logger -t "[config_onu]" "Setting Lct Proto back to static ..."
		uci set network.lct.proto=static
		uci commit network.lct
	fi

	if [ "$host_mac_upper" != "$host_mac_old_upper" ]; then
		logger -t "[config_onu]" "Setting Host MAC Address: $host_mac_upper."
		fw_setenv ethaddr "${host_mac_upper}"
		uci set network.host.macaddr="${host_mac_upper}"
		uci commit network.host
	fi
}

# Patch the omcid binary in-place. Copies to /tmp, applies patches, copies back.
# Safety: only patches if MD5 matches either stock checksum or the last-patched
# checksum (stored in UCI). This prevents double-patching or patching unknown binaries.
mod_omcid() {
	local mod_omcid
	local omcid_csum
	local omcid_csum_current

	mod_omcid=$(uci -q get 8311.config.mod_omcid)
	omcid_csum=$(uci -q get 8311.config.omcid_csum)
	omcid_csum_current=$(md5sum /opt/lantiq/bin/omcid | cut -d' ' -f 1)

	logger -t "[config_onu]" "Patching OMCID ..."

	# Allow patching if: (a) stock binary (no prior patches), or
	# (b) previously-patched binary (checksum matches our last known state)
	if [ -n "$mod_omcid" ] &&
		{ { [ -z "$omcid_csum" ] && [ "$omcid_csum_current" = "$omcid_stock_csum" ]; } ||
		  { [ -n "$omcid_csum" ] && [ "$omcid_csum_current" = "$omcid_csum" ]; }; }; then

		local disable_8021x
		local omcid_version

		disable_8021x=$(uci -q get 8311.config.omcid_8021x)
		omcid_version=$(uci -q get 8311.config.omcid_version)

		cp /opt/lantiq/bin/omcid /tmp/omcid

		[ "$disable_8021x" = "1" ] && mod_omcid_8021x
		[ -n "$omcid_version" ] && mod_omcid_version "$omcid_version"

		cp /tmp/omcid /opt/lantiq/bin/omcid

		uci set 8311.config.omcid_csum="$(md5sum /opt/lantiq/bin/omcid | cut -d' ' -f 1)"
		uci commit 8311.config
	else
		logger -t "[config_onu]" "ERROR: OMCID checksum mismatch, patching aborted ..."
	fi
}

# Patch the omcid version string at a fixed binary offset.
# $1 = new version string (max 58 chars, zero-padded to 58 bytes)
# The version string is reported by omcid -v and visible to the OLT.
mod_omcid_version() {
	local omcid_version_cut
	local omcid_version_current

	local omcid_version_user="$1"

	omcid_version_cut=$(echo "$omcid_version_user" | cut -c 1-58)
	omcid_version_current=$(/opt/lantiq/bin/omcid -v | tail -n 1 | sed 's/\r//g' | cut -c 18-75)

	# Convert version string to hex, zero-pad to 116 hex chars (58 bytes)
	printf '%s' "$omcid_version_cut" | hexdump -e '60/1 "%02x" "\n"' |
		awk '{width=116; printf("%s",$1); for(i=0;i<width-length($1);++i) printf "%c", 0; print ""}' |
		cut -c 1-116 | xxd -r -p >/tmp/omcid_ver

	# Binary offset in omcid where the version string is stored
	local omcid_version_offset_2=316133

	if [ "$omcid_version_cut" != "$omcid_version_current" ]; then
		logger -t "[config_onu]" "Modding OMCID version: $omcid_version_cut."
		#dd if=/tmp/omcid_ver of=/tmp/omcid obs=1 seek=$omcid_version_offset_1 conv=notrunc
		dd if=/tmp/omcid_ver of=/tmp/omcid obs=1 seek=$omcid_version_offset_2 conv=notrunc 2>>/dev/null
	fi
}

# Patch omcid to disable 802.1x enforcement by zeroing one byte.
# Offset 275849 is a boolean flag in the omcid binary; 0x01=enforce, 0x00=disable.
mod_omcid_8021x() {
	local omcid_8021x_offset=275849

	logger -t "[config_onu]" "Disabling enforcement of 802.1x ..."
	printf '\x00' | dd of=/tmp/omcid conv=notrunc seek=$omcid_8021x_offset bs=1 count=1 2>/dev/null
}

# Restore 802.1x enforcement in omcid by writing 0x01 back to the patch offset.
restore_omcid_8021x() {
	local omcid_version
	local omcid_csum
	local omcid_csum_current

	local omcid_8021x_offset=275849

	omcid_version=$(uci -q get 8311.config.omcid_version)
	omcid_csum=$(uci -q get 8311.config.omcid_csum)
	omcid_csum_current=$(md5sum /opt/lantiq/bin/omcid | cut -d' ' -f 1)

	logger -t "[config_onu]" "Restoring OMCID 802.1x behaviour ..."

	if [ -n "$omcid_csum" ] && [ "$omcid_csum_current" = "$omcid_csum" ]; then
		logger -t "[config_onu]" "Re-enabling enforcement of 802.1x ..."

		cp /opt/lantiq/bin/omcid /tmp/omcid
		printf '\x01' | dd of=/tmp/omcid conv=notrunc seek=$omcid_8021x_offset bs=1 count=1 2>/dev/null
		cp /tmp/omcid /opt/lantiq/bin/omcid

		if [ -z "$omcid_version" ]; then 
			uci -q delete 8311.config.omcid_csum
			uci commit 8311.config
		else
			uci set 8311.config.omcid_csum="$(md5sum /opt/lantiq/bin/omcid | cut -d' ' -f 1)"
			uci commit 8311.config
		fi
	else
		logger -t "[config_onu]" "ERROR: OMCID checksum mismatch, unable to restore ..."
	fi
}

# Restore the stock omcid version string to the binary.
restore_omcid_version() {
	local disable_8021x
	local omcid_csum
	local omcid_csum_current

	disable_8021x=$(uci -q get 8311.config.omcid_8021x)
	omcid_csum=$(uci -q get 8311.config.omcid_csum)
	omcid_csum_current=$(md5sum /opt/lantiq/bin/omcid | cut -d' ' -f 1)

	logger -t "[config_onu]" "Restoring OMCID version."

	if [ -n "$omcid_csum" ] && [ "$omcid_csum_current" = "$omcid_csum" ]; then
		local omcid_version="6BA1896SPE2C05, internal_version =1620-00802-05-00-000D-01"

		printf '%s' "$omcid_version" | hexdump -e '60/1 "%02x" "\n"' |
			awk '{width=116; printf("%s",$1); for(i=0;i<width-length($1);++i) printf "%c", 0; print ""}' |
			cut -c 1-116 | xxd -r -p >/tmp/omcid_ver

		#local omcid_version_offset_1=307944
		local omcid_version_offset_2=316133

		logger -t "[config_onu]" "OMCID version: $omcid_version."

		cp /opt/lantiq/bin/omcid /tmp/omcid
		#dd if=/tmp/omcid_ver of=/tmp/omcid obs=1 seek=$omcid_version_offset_1 conv=notrunc
		dd if=/tmp/omcid_ver of=/tmp/omcid obs=1 seek=$omcid_version_offset_2 conv=notrunc 2>>/dev/null
		cp /tmp/omcid /opt/lantiq/bin/omcid

		if [ -z "$disable_8021x" ]; then 
			uci -q delete 8311.config.omcid_csum
			uci commit 8311.config
		else
			uci set 8311.config.omcid_csum="$(md5sum /opt/lantiq/bin/omcid | cut -d' ' -f 1)"
			uci commit 8311.config
		fi
	else
		logger -t "[config_onu]" "ERROR: OMCID checksum mismatch, unable to restore ..."
	fi
}

# Toggle RX LOS (Loss of Signal) GPIO pin status. When disabled (rx_los=1),
# forces the LOS pin low so the host device doesn't see a false LOS alarm.
# When re-enabled, unexports the GPIO and restores onu LOS pin config.
disable_rx_los_status() {
	local los_pin
	local LTQ_BIN
	local rx_los
	local rx_los_status_current1
	local rx_los_status_current2

	LTQ_BIN=/opt/lantiq/bin
	los_pin=$(uci -q get sfp_pins.@pin[2].pin)
	rx_los=$(uci -q get 8311.config.rx_los)
	# -1 = pin disabled in onu firmware
	rx_los_status_current1=$($LTQ_BIN/onu onu_los_pin_cfg_get | tee /dev/null | cut -f 3 -d '=')
	# Check if GPIO is currently driven low
	rx_los_status_current2=$(grep "gpio-$los_pin " /sys/kernel/debug/gpio | grep -c "lo")

	if [ "$rx_los" = "1" ] &&
		{ [ "$rx_los_status_current1" -ne -1 ] ||
		  [ "$rx_los_status_current2" -ne 1 ]; }; then

		logger -t "[config_onu]" "Disabling rx_los status ..."

		$LTQ_BIN/onu onu_los_pin_cfg_set -1 >/dev/null
		$LTQ_BIN/gpio_setup.sh "$los_pin" low >/dev/null

		rx_los_status_current2=$(grep "gpio-$los_pin " /sys/kernel/debug/gpio | grep -c "lo")

		if [ "$rx_los_status_current2" -ne 1 ]; then
			logger -t "[config_onu]" "Disable rx_los status failed, resync system config ..."
			uci -q delete 8311.config.rx_los
			uci commit 8311.config
		fi
	elif [ -z "$rx_los" ] &&
		{ [ "$rx_los_status_current1" -eq -1 ] ||
		  [ "$rx_los_status_current2" -eq 1 ]; }; then

		logger -t "[config_onu]" "Enabling rx_los status ..."

		echo "$los_pin" >/sys/class/gpio/unexport
		$LTQ_BIN/onu onu_los_pin_cfg_set "$los_pin" >/dev/null

		uci -q delete 8311.config.rx_los
		uci commit 8311.config
	fi
}

# Toggle whether the ONU ignores PLOAM RX message loss events.
ignore_rx_msg_lost() {
	local ignore_rx_msg_lost

	ignore_rx_msg_lost=$(uci -q get 8311.config.ignore_rx_msg_lost)

	if [ "$ignore_rx_msg_lost" = "1" ]; then
		logger -t "[config_onu]" "Ignoring rx loss message ..."
		/opt/lantiq/bin/onu onutms ignore_ploam_rx_loss_enable=1 >/dev/null
	else
		logger -t "[config_onu]" "Unignoring rx loss message ..."
		uci -q delete 8311.config.ignore_rx_msg_lost
		uci commit 8311.config
		/opt/lantiq/bin/onu onutms ignore_ploam_rx_loss_enable=0 >/dev/null
	fi
}

# Update GOI (GPON Optic Interface) calibration data in firmware env.
# Expects base64-encoded data with specific delimiters ("begin-base64 644 goi_config@...@====@").
update_goi() {
	local goi_value
	local goi_cur
	local result

	goi_value=$(uci -q get gpon.goi.goivalue)
	goi_cur=$(fw_printenv -n goi_config 2>&-)
	result=$(echo "$goi_value" | grep "begin-base64 644 goi_config@" | grep "@====@")

	if [ "$goi_cur" != "$goi_value" ] && [ "$result" != "" ]; then
		rm -f /etc/optic/.goi_recovered
		fw_setenv goi_config "${goi_value}"
	else
		logger -t "[config_onu]" "Error goi config value or config value no change, will not update!"
	fi
}

# Read and clear the reboot cause from firmware env. Saves to /tmp for LuCI.
rebootcause() {
	local rebootcause

	rebootcause=$(fw_printenv rebootcause 2>&- | cut -f 2 -d '=')
	echo "$rebootcause" >/tmp/rebootcause

	fw_setenv rebootcause 0
}

# Read reboot attempt counts from firmware env. Saves to /tmp for vlanexec.sh.
rebootnum() {
	local reboots_count
	local omcid_reboot_count

	reboots_count=$(fw_printenv reboottry 2>&- | cut -f 2 -d '=')
	omcid_reboot_count=$(fw_printenv omcidreboot 2>&- | cut -f 2 -d '=')

	if [ -z "$reboots_count" ]; then
		reboots_count=0
	fi

	if [ -z "$omcid_reboot_count" ]; then
		omcid_reboot_count=0
	fi

	echo "$reboots_count" >/tmp/reboots_count
	echo "$omcid_reboot_count" >/tmp/omcid_reboot_count
}

# Execute a delayed reboot if rebootdirect flag is set (via LuCI).
rebootdelay() {
	local rebootdirect
	local rebootwait

	rebootdirect=$(uci -q get 8311.config.rebootdirect)
	rebootwait=$(uci -q get 8311.config.rebootwait)

	if [ "$rebootdirect" = "1" ] && [ -n "$rebootwait" ]; then
		logger -t "[config_onu]" "Reboot enabled, waiting ..."
		reboot -f -d "$rebootwait" &
	fi
}

# Switch the committed boot image to the other firmware bank.
switchimage() {
	local imagenext

	imagenext=$(grep image /proc/mtd | cut -c 31)

	fw_setenv committed_image "$imagenext"
	fw_setenv "image${imagenext}_is_valid" 1
}

# Toggle the TTL serial console (ASC0). asc0=0 enables console, asc0=1 disables.
switchasc() {
	local console_en_env
	local console_en

	console_en_env=$(fw_printenv asc0 2>&- | cut -f 2 -d '=')
	console_en=$(uci -q get 8311.config.console_en)

	if [ "$console_en_env" != "0" ] && [ "$console_en" = "1" ]; then
		logger -t "[config_onu]" "Enabling TTL console, reboot required ..."
		fw_setenv asc0 0
	fi

	if [ "$console_en_env" = "0" ] && [ "$console_en" != "1" ]; then
		logger -t "[config_onu]" "Disabling TTL console, reboot required ..."
		fw_setenv asc0 1
	fi
}

# Sync UCI console_en state with the firmware env asc0 value on boot.
initasc() {
	local console_en_env
	local console_en

	console_en_env=$(fw_printenv asc0 2>&- | cut -f 2 -d '=')
	console_en=$(uci -q get 8311.config.console_en)

	if [ "$console_en_env" = "0" ] && [ "$console_en" != "1" ]; then
		logger -t "[config_onu]" "TTL console enabled, syncing system config ..."
		uci -q set 8311.config.console_en=1
		uci commit 8311.config.console_en
	fi

	if [ "$console_en_env" != "0" ] && [ "$console_en" = "1" ]; then
		logger -t "[config_onu]" "TTL console disabled, syncing system config ..."
		uci -q delete 8311.config.console_en
		uci commit 8311.config.console_en
	fi
}

# Clear all identity data from EEPROM and reset network settings to defaults.
# sfp_i2c indices: 6=equipment_id, 7=vendor_id, 8=serial, 9=LOID, 10=LOID pw, 11=PLOAM pw
factoryreset() {
	logger -t "[config_onu]" "Factory Resetting ..."
	/opt/lantiq/bin/sfp_i2c -i6 -s ""
	/opt/lantiq/bin/sfp_i2c -i7 -s ""
	/opt/lantiq/bin/sfp_i2c -i8 -s ""
	/opt/lantiq/bin/sfp_i2c -i9 -s ""
	/opt/lantiq/bin/sfp_i2c -i10 -s ""
	/opt/lantiq/bin/sfp_i2c -i11 -s ""
	fw_setenv ipaddr '192.168.1.10'
	fw_setenv netmask '255.255.255.0'
	fw_setenv gatewayip '192.168.2.0'
	fw_setenv ethaddr 'ac:9a:96:00:00:00'
}

# Command dispatch
case $command in
load)
	load_config
	;;
set)
	set_config
	;;
init)
	init_config
	;;
setip)
	set_ip
	;;
update)
	update_goi
	;;
mod)
	mod_omcid
	;;
restore_sw_ver)
	restore_omcid_version
	;;
restore_8021x)
	restore_omcid_8021x
	;;
ignore)
	ignore_rx_msg_lost
	;;
disable)
	disable_rx_los_status
	;;
rebootcause)
	rebootcause
	;;
rebootnum)
	rebootnum
	;;
reboot)
	rebootdelay
	;;
switch)
	switchimage
	;;
switchasc)
	switchasc
	;;
initasc)
	initasc
	;;
factoryreset)
	factoryreset
	;;
*)
	echo "Error Command $command"
	;;
esac
