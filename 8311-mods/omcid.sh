#!/bin/sh /etc/rc.common
# Copyright (C) 2011 OpenWrt.org
# Copyright (C) 2011 lantiq.com

. $IPKG_INSTROOT/lib/falcon.sh

START=85

USE_PROCD=1

OMCID_BIN=/opt/lantiq/bin/omcid

status_entry_create() {
	local path=$1
	local base=`basename $path`
	local dir=`dirname $path`

	touch $path

	uci -c $dir set $base.ip_conflicts=status
	uci -c $dir set $base.dhcp_timeouts=status
	uci -c $dir set $base.dns_errors=status
}

wait_for_jffs()
{
	while ! grep overlayfs:/overlay /proc/self/mounts >/dev/null
	do
		sleep 1
	done
}

is_flash_boot()
{
	grep overlayfs /proc/self/mounts >/dev/null
}

generate_custom_mib()
{
	vendor_id=`uci -q get gpon.onu.vendor_id` || return 1
	ont_version=`uci -q get gpon.onu.ont_version` || return 1
	equipment_id=`uci -q get gpon.onu.equipment_id` || return 1
	uni_type=`uci -q get gpon.onu.uni_type | tr [A-Z] [a-z]` || return 1

	ont_version=${ont_version//\\0}
	equipment_id=${equipment_id//\\0}

    ont_version=$(printf %s "$ont_version" $(yes "" | head -n $((14-${#ont_version}+1)) | sed ':a;N;$!ba;s/\n/\\0/g'))
	equipment_id=$(printf %s "$equipment_id" $(yes "" | head -n $((20-${#equipment_id}+1)) | sed ':a;N;$!ba;s/\n/\\0/g'))

	mibsrc='/etc/mibs/nameless.ini'
	mibtgt='/etc/mibs/custom.ini'

	pptpsrc='/etc/mibs/pptp.ini'
	veipsrc='/etc/mibs/veip.ini'

	if [ ! -f ${mibsrc} ]; then
		exit 1
	fi

	if [ -f ${mibtgt} ]; then
		rm -f ${mibtgt}
	fi

	cp ${mibsrc} ${mibtgt}
    echo -e "\n" >> ${mibtgt}
	echo "# ONT-G" >> ${mibtgt}
	echo "256 0 ${vendor_id} ${ont_version} 00000000 2 0 0 0 0 #0" >> ${mibtgt}
	echo -e "\n" >> ${mibtgt}
	echo "# ONT2-G" >> ${mibtgt}
	echo "257 0 ${equipment_id} 0xa0 0xcc 1 1 64 64 1 64 0 0x007f 0 24 48" >> ${mibtgt}

	if [ -n "$uni_type" ] && [ "$uni_type" == "veip" ]; then
		cat ${veipsrc} >> ${mibtgt}
	else #if [ -n "$uni_type" ] && [ "$uni_type" == "pptp" ]; then
		cat ${pptpsrc} >> ${mibtgt}
	fi

    echo -e "\n" >> ${mibtgt}
}

start_service() {
	local mib_file
	local omcc_version
	local omci_status
	local mibtmp1
	local mibtmp2
	local statustmp
	local omcctmp
	local ioptmp1
	local ioptmp2
	local omci_iop_mask
	local lct=""

	#is_flash_boot && wait_for_jffs

	mibtmp1=`fw_printenv mib_file 2>&- | cut -f 2 -d '='`
	mibtmp2=`uci -q get gpon.onu.mib_file`
	mc=`uci -q get gpon.onu.mib_customized`
	tp=`uci -q get gpon.onu.uni_type`
	if [ -f "/etc/mibs/$mibtmp1" ]; then
		mib_file="/etc/mibs/$mibtmp1"
	elif [ -n "$mibtmp2" ] && [ "`echo $mibtmp2 | grep -c "auto.ini"`" != "1" ]; then
		mib_file="$mibtmp2"
	else
        if [ "$mc" == "1" ]; then
		    generate_custom_mib
            ln -sf /etc/mibs/custom.ini /etc/mibs/auto.ini
        else
            if [ -n "$tp" ] && [ "$tp" == "veip" ]; then
                ln -sf /etc/mibs/data_1v_8q.ini /etc/mibs/auto.ini
            else #if [ -n "$tp" ] && [ "$tp" == "pptp" ]; then
                ln -sf /etc/mibs/data_1g_8q_us1280_ds512.ini /etc/mibs/auto.ini
            fi
        fi
		mib_file="/etc/mibs/auto.ini"
		uci set gpon.onu.mib_file=$mib_file
		uci commit gpon
	fi

	statustmp=`uci -q get gpon.onu.omci_status`
	if [ -n "$statustmp" ]; then
		omci_status=$statustmp
	else
		omci_status="/tmp/omci_status"
		uci set gpon.onu.omci_status=$omci_status
		uci commit gpon.onu.omci_status
	fi
	status_entry_create "$omci_status"

	omcctmp=`uci -q get gpon.onu.omcc_version`
	if [ -n "$omcctmp" ]; then
		omcc_version=$omcctmp
	else
		omcc_version=160
	fi

	case `uci -q get network.lct.ifname` in
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

	ioptmp1=`fw_printenv omci_iop_mask 2>&- | cut -f2 -d=`
	ioptmp2=`uci -q get gpon.onu.omci_iop_mask`
	if [ -n "$ioptmp1" ]; then
		omci_iop_mask=$ioptmp1
	elif [ -n "$ioptmp2" ]; then
		omci_iop_mask=$ioptmp2
	else
		omci_iop_mask=0
	fi

	logger -t "[omcid]" "Use OMCI mib file: $mib_file"

	omcidtest=`${OMCID_BIN} -h | grep -c OMCI`
	omcid_version_default="6BA1896SPE2C05, internal_version =1620-00802-05-00-000D-01"
	omcid_version_current=`${OMCID_BIN} -v | tail -n 1 | sed 's/\r//g' | cut -c 18-75`
	mod_omcid=`uci -q get gpon.onu.mod_omcid`
	if [ "$omcidtest" == "0" ] || [ -z "$mod_omcid" ] && [ "$omcid_version_default" != "$omcid_version_current" ]; then
		/opt/lantiq/bin/config_onu.sh restore
	elif [ "$mod_omcid" == "1" ]; then
		/opt/lantiq/bin/config_onu.sh mod
	fi

	omci_log_level=`uci -q get gpon.onu.omci_log_level`
	if [ -z "$omci_log_level" ] || [ "`echo $omci_log_level | grep -c '^[1-7]*$'`" == "0" ]; then
		omci_log_level=3
	fi

	omci_log_to_console=`uci -q get gpon.onu.omci_log_to_console`
	if [ -n "$omci_log_to_console" ]; then
		omci_log_path="/dev/console"
	else
		omci_log_path="/tmp/log/debug"
	fi

	procd_open_instance
	procd_set_param respawn
	procd_set_param command ${OMCID_BIN} -d $omci_log_level -p $mib_file -o $omcc_version -i $omci_iop_mask $lct -l $omci_log_path
	procd_set_param stdout 1
	procd_set_param stderr 1
	procd_close_instance
}

stop_service() {
	proc=`pgrep omcid`
	if [ -n "$proc" ]; then
		kill $proc
	fi
}
