#!/bin/sh /etc/rc.common
# Copyright (C) 2011 OpenWrt.org
# Copyright (C) 2011 lantiq.com
. "$IPKG_INSTROOT/lib/falcon.sh"

START=85

USE_PROCD=1

OMCID_BIN=/opt/lantiq/bin/omcid

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

wait_for_jffs() {
	while ! grep overlayfs:/overlay /proc/self/mounts >/dev/null
	do
		sleep 1
	done
}

is_flash_boot() {
	grep overlayfs /proc/self/mounts >/dev/null
}

generate_custom_mib() {
	vendor_id=$(uci -q get 8311.config.vendor_id) || return 1
	hw_ver=$(uci -q get 8311.config.hw_ver) || return 1
	equipment_id=$(uci -q get 8311.config.equipment_id) || return 1
	uni_type=$(uci -q get 8311.config.uni_type | tr 'A-Z' 'a-z') || return 1

	vendor_id=$(printf '%.4s' "${vendor_id}")
	hw_ver=$(printf '%.14s' "$(echo "$hw_ver" | sed 's/\\0//g')")
	equipment_id=$(printf '%.20s' "$(echo "$equipment_id" | sed 's/\\0//g')")

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

	cp ${mibsrc} ${mibtgt}
	
	{
		printf '\n# ONT-G\n256 0 %s %s 00000000 2 0 0 0 0 #0\n' "${vendor_id}" "${hw_ver}"
		printf '\n# ONT2-G\n257 0 %s 0xa0 0xcc 1 1 64 64 1 64 0 0x007f 0 24 48\n' "${equipment_id}"

		if [ -n "$uni_type" ] && [ "$uni_type" = "veip" ]; then
			printf '\n%s\n' "$(cat ${veipsrc})"
		else #if [ -n "$uni_type" ] && [ "$uni_type" == "pptp" ]; then
			printf '\n%s\n' "$(cat ${pptpsrc})"
		fi
	} >>${mibtgt}
}

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

	mib_file_env=$(fw_printenv mib_file 2>&- | cut -f 2 -d '=')
	mib_file_uci=$(uci -q get 8311.config.mib_file)
	mib_customized=$(uci -q get 8311.config.mib_customized)
	uni_type=$(uci -q get 8311.config.uni_type)

	if [ -f "/etc/mibs/$mib_file_env" ]; then
		mib_file="/etc/mibs/$mib_file_env"
	elif [ -n "$mib_file_uci" ] && [ "$(echo "$mib_file_uci" | grep -c "auto.ini")" != "1" ]; then
		mib_file="$mib_file_uci"
	else
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

	omci_status_uci=$(uci -q get 8311.config.omci_status)

	if [ -n "$omci_status_uci" ]; then
		omci_status=$omci_status_uci
	else
		omci_status="/tmp/omci_status"
		uci set 8311.config.omci_status=$omci_status
		uci commit 8311.config.omci_status
	fi

	status_entry_create "$omci_status"

	omcc_version_uci=$(uci -q get 8311.config.omcc_version)

	if [ -n "$omcc_version_uci" ]; then
		omcc_version=$omcc_version_uci
	else
		omcc_version=160
	fi

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

	iop_mask_env=$(fw_printenv omci_iop_mask 2>&- | cut -f2 -d=)
	iop_mask_uci=$(uci -q get 8311.config.iop_mask)

	if [ -n "$iop_mask_env" ]; then
		omci_iop_mask=$iop_mask_env
	elif [ -n "$iop_mask_uci" ]; then
		omci_iop_mask=$iop_mask_uci
	else
		omci_iop_mask=0
	fi

	logger -t "[omcid]" "Use OMCI mib file: $mib_file"

	omcid_valid=$(${OMCID_BIN} -h | grep -c OMCI)
	omcid_version_default="6BA1896SPE2C05, internal_version =1620-00802-05-00-000D-01"
	omcid_version_current=$(${OMCID_BIN} -v | tail -n 1 | sed 's/\r//g' | cut -c 18-75)
	mod_omcid=$(uci -q get 8311.config.mod_omcid)
	
	if [ "$omcid_valid" = "0" ] || { [ -z "$mod_omcid" ] && [ "$omcid_version_default" != "$omcid_version_current" ]; }; then
		/opt/lantiq/bin/config_onu.sh restore
	elif [ "$mod_omcid" = "1" ]; then
		/opt/lantiq/bin/config_onu.sh mod
	fi

	omci_log_level=$(uci -q get 8311.config.omci_log_level)

	if [ -z "$omci_log_level" ] || [ "$(echo "$omci_log_level" | grep -c '^[1-7]*$')" = "0" ]; then
		omci_log_level=3
	fi

	omci_log_to_console=$(uci -q get 8311.config.omci_log_to_console)

	if [ -n "$omci_log_to_console" ]; then
		omci_log_path="/dev/console"
	else
		omci_log_path="/tmp/log/debug"
	fi

	procd_open_instance
	procd_set_param respawn
	procd_set_param command ${OMCID_BIN} -d "$omci_log_level" -p "$mib_file" -o "$omcc_version" -i "$omci_iop_mask" $lct -l $omci_log_path
	procd_set_param stdout 1
	procd_set_param stderr 1
	procd_close_instance
}

stop_service() {
	proc=$(pgrep omcid)
	if [ -n "$proc" ]; then
		kill "$proc"
	fi
}
