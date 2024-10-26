#!/bin/sh

command=$1

equipid="BVL3A5HNAAG010SP"
hwver="3FE56641AAAA01"
vendid="ALCL"
omcid_stock_csum="b78fb6fa62fa967096af0e21c5a5879d"

load_config() {
	local nSerial
	local omci_loid
	local omci_password
	local ploam_password
	local vendorid

	nSerial=$(fw_printenv nSerial 2>&- | cut -f 2 -d '=')
	omci_loid=$(fw_printenv omci_loid 2>&- | cut -f 2 -d '=')
	omci_password=$(fw_printenv omci_lpwd 2>&- | cut -f 2 -d '=')
	ploam_password=$(fw_printenv nPassword 2>&- | cut -f 2 -d '=' | /usr/bin/xxd -r)
	vendorid=$(fw_printenv nSerial 2>&- | cut -f 2 -d '=' | cut -c -4)

	uci set gpon.onu.nSerial="${nSerial}"
	uci commit gpon.onu.nSerial
	uci set gpon.onu.omci_loid="${omci_loid}"
	uci commit gpon.onu.omci_loid
	uci set gpon.onu.omci_lpwd="${omci_password}"
	uci commit gpon.onu.omci_lpwd
	uci set gpon.onu.ploam_password="${ploam_password}"
	uci commit gpon.onu.ploam_password
	uci set gpon.onu.vendor_id="${vendorid}"
	uci commit gpon.onu.vendor_id
}

set_config() {
	local nSerial
	local omci_loid
	local omci_password
	local ploam_password
	local mib_customized
	local mib_customized_old
	local vendorid
	local vendor_id
	local equipment_id
	local ont_version

	nSerial=$(uci -q get gpon.onu.nSerial)
	omci_loid=$(uci -q get gpon.onu.omci_loid)
	omci_password=$(uci -q get gpon.onu.omci_lpwd)
	ploam_password=$(uci -q get gpon.onu.ploam_password)
	mib_customized=$(uci -q get gpon.onu.mib_customized)
	mib_customized_old=$(uci -q get gpon.onu.mib_customized_old)
	vendorid=$(uci -q get gpon.onu.nSerial | cut -c -4)
	vendor_id=$(uci -q get gpon.onu.vendor_id)
	equipment_id=$(uci -q get gpon.onu.equipment_id)
	ont_version=$(uci -q get gpon.onu.ont_version)

	local nSerial_old
	local omci_loid_old
	local omci_password_old
	local ploam_password_old

	nSerial_old=$(fw_printenv nSerial 2>&- | cut -f 2 -d '=')
	omci_loid_old=$(fw_printenv omci_loid 2>&- | cut -f 2 -d '=')
	omci_password_old=$(fw_printenv omci_lpwd 2>&- | cut -f 2 -d '=')
	ploam_password_old=$(fw_printenv nPassword 2>&- | cut -f 2 -d '=' | /usr/bin/xxd -r)

	local nSerial_len

	nSerial_len=${#nSerial}

	if [ -n "$nSerial_len" ] && [ "$nSerial_len" = "16" ]; then
		nSerial_a=$(echo "$nSerial" | cut -c 1-8 | /usr/bin/xxd -r -ps)
		nSerial_b=$(echo "$nSerial" | cut -c 9-16)
		nSerial=$nSerial_a$nSerial_b
		vendorid=$nSerial_a
	fi

	local nSerialtmp
	local nSerial_oldtmp

	nSerialtmp=$(echo "$nSerial" | tr 'a-z' 'A-Z')
	nSerial_oldtmp=$(echo "$nSerial_old" | tr 'a-z' 'A-Z')

	if [ -n "$nSerialtmp" ] && [ "$nSerial" != "$nSerial_oldtmp" ]; then
		logger -t "[config_onu]" "Setting Vendor ID: $vendorid."
		/opt/lantiq/bin/sfp_i2c -i7 -s "${vendorid}"
		uci set gpon.onu.vendor_id="${vendorid}"
		uci commit gpon.onu.vendor_id
		logger -t "[config_onu]" "Setting GPON SN: $nSerial."
		/opt/lantiq/bin/sfp_i2c -i8 -s "${nSerial}"
	elif [ -z "$nSerial" ]; then
		logger -t "[config_onu]" "Clearing GPON SN."
		/opt/lantiq/bin/sfp_i2c -i8 -s ""
	fi

	if [ "$mib_customized" = "1" ]; then
		if [ -n "$vendor_id" ]; then
			logger -t "[config_onu]" "Setting Vendor ID: $vendor_id."
			/opt/lantiq/bin/sfp_i2c -i7 -s "${vendor_id}"
			uci set gpon.onu.vendor_id="${vendor_id}"
			uci commit gpon.onu.vendor_id
		fi

		if [ -n "$equipment_id" ]; then
			logger -t "[config_onu]" "Setting Equipment ID: $equipment_id."
			/opt/lantiq/bin/sfp_i2c -i6 -s "${equipment_id}"
			uci set gpon.onu.equipment_id="${equipment_id}"
			uci commit gpon.onu.equipment_id
		fi

		if [ -n "$ont_version" ]; then
			logger -t "[config_onu]" "Setting ONT Version: $ont_version."
			uci set gpon.onu.ont_version="${ont_version}"
			uci commit gpon.onu.ont_version
		fi

		if [ -z "$mib_customized_old" ]; then
			uci set gpon.onu.mib_customized_old="${mib_customized}"
			uci commit gpon.onu.mib_customized_old
		fi
	elif [ "$mib_customized_old" = "1" ]; then
		logger -t "[config_onu]" "Resetting Vendor ID."
		uci set gpon.onu.vendor_id=${vendid}
		uci commit gpon.onu.vendor_id
		logger -t "[config_onu]" "Resetting Equipment ID."
		uci set gpon.onu.equipment_id=${equipid}
		uci commit gpon.onu.equipment_id
		logger -t "[config_onu]" "Resetting ONT Version."
		uci set gpon.onu.ont_version=${hwver}
		uci commit gpon.onu.ont_version
		uci delete gpon.onu.mib_customized_old
		uci commit gpon.onu.mib_customized_old
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

init_config() {
	local nSerial
	local omci_loid
	local omci_password
	local ploam_password
	local vendorid
	local mib_customized
	local mib_customized_old
	local vendorid
	local nSerial_len
	local vendor_id
	local equipment_id
	local ont_version

	nSerial=$(uci -q get gpon.onu.nSerial)
	omci_loid=$(uci -q get gpon.onu.omci_loid)
	omci_password=$(uci -q get gpon.onu.omci_lpwd)
	ploam_password=$(uci -q get gpon.onu.ploam_password)
	vendorid=$(uci -q get gpon.onu.nSerial | cut -c -4)
	mib_customized=$(uci -q get gpon.onu.mib_customized)
	mib_customized_old=$(uci -q get gpon.onu.mib_customized_old)
	vendorid=$(uci -q get gpon.onu.nSerial | cut -c -4)
	nSerial_len=${#nSerial}
	vendor_id=$(uci -q get gpon.onu.vendor_id)
	equipment_id=$(uci -q get gpon.onu.equipment_id)
	ont_version=$(uci -q get gpon.onu.ont_version)

	if [ -n "$nSerial_len" ] && [ "$nSerial_len" = "16" ]; then
		nSerial_a=$(echo "$nSerial" | cut -c 1-8 | /usr/bin/xxd -r -ps)
		nSerial_b=$(echo "$nSerial" | cut -c 9-16)
		nSerial=$nSerial_a$nSerial_b
	fi

	if [ "$mib_customized" = "1" ]; then
		if [ -n "$vendor_id" ]; then
			logger -t "[config_onu]" "Setting Vendor ID: $vendor_id."
			/opt/lantiq/bin/sfp_i2c -i7 -s "${vendor_id}"
			uci set gpon.onu.vendor_id="${vendor_id}"
			uci commit gpon.onu.vendor_id
		fi

		if [ -n "$equipment_id" ]; then
			logger -t "[config_onu]" "Setting Equipment ID: $equipment_id."
			/opt/lantiq/bin/sfp_i2c -i6 -s "${equipment_id}"
			uci set gpon.onu.equipment_id="${equipment_id}"
			uci commit gpon.onu.equipment_id
		fi

		if [ -n "$ont_version" ]; then
			logger -t "[config_onu]" "Setting ONT Version: $ont_version."
			uci set gpon.onu.ont_version="${ont_version}"
			uci commit gpon.onu.ont_version
		fi

		if [ -z "$mib_customized_old" ]; then
			uci set gpon.onu.mib_customized_old="${mib_customized}"
			uci commit gpon.onu.mib_customized_old
		fi
	elif [ "$mib_customized_old" = "1" ]; then
		logger -t "[config_onu]" "Resetting Vendor ID."
		uci set gpon.onu.vendor_id=${vendid}
		uci commit gpon.onu.vendor_id
		logger -t "[config_onu]" "Resetting Equipment ID."
		uci set gpon.onu.equipment_id=${equipid}
		uci commit gpon.onu.equipment_id
		logger -t "[config_onu]" "Resetting ONT Version."
		uci set gpon.onu.ont_version=${hwver}
		uci commit gpon.onu.ont_version
		uci delete gpon.onu.mib_customized_old
		uci commit gpon.onu.mib_customized_old
	fi

	if [ -n "$nSerial" ]; then
		logger -t "[config_onu]" "Setting GPON SN: $nSerial."
		/opt/lantiq/bin/sfp_i2c -i8 -s "${nSerial}"
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

	uci -q delete gpon.onu.rebootdirect
	uci -q commit gpon.onu
}

set_ip() {
	local lct_addr
	local lct_gateway
	local lct_mac
	local lct_proto
	local host_mac

	local lct_addr_old
	local lct_gateway_old
	local host_mac_old

	local lct_mac_cap
	local host_mac_cap
	local host_mac_old_cap

	lct_addr=$(uci -q get network.lct.ipaddr)
	lct_gateway=$(uci -q get network.lct.gateway)
	lct_mac=$(uci -q get network.lct.macaddr)
	lct_proto=$(uci -q get network.lct.proto)
	host_mac=$(uci -q get network.host.macaddr)

	lct_addr_old=$(fw_printenv ipaddr 2>&- | cut -f 2 -d '=')
	lct_gateway_old=$(fw_printenv gatewayip 2>&- | cut -f 2 -d '=')
	host_mac_old=$(fw_printenv ethaddr 2>&- | cut -f 2 -d '=')

	lct_mac_cap=$(echo "$lct_mac" | tr 'a-z' 'A-Z')
	host_mac_cap=$(echo "$host_mac" | tr 'a-z' 'A-Z')
	host_mac_old_cap=$(echo "$host_mac_old" | tr 'a-z' 'A-Z')

	if [ "$lct_addr" != "$lct_addr_old" ]; then
		logger -t "[config_onu]" "Setting IP Address: $lct_addr."
		fw_setenv ipaddr "${lct_addr}"
		uci set network.lct.ipaddr="${lct_addr}"
		uci commit network.lct
	fi

	if [ "$lct_gateway" != "$lct_gateway_old" ]; then
		logger -t "[config_onu]" "Setting Gateway IP Adress: $lct_gateway."
		fw_setenv gatewayip "${lct_gateway}"
		uci set network.lct.gateway="${lct_gateway}"
		uci commit network.lct
	fi

	if [ -n "$lct_mac" ]; then
		logger -t "[config_onu]" "Setting Lct MAC Address: $lct_mac_cap."
		uci set network.lct.macaddr="${lct_mac_cap}"
		uci commit network.lct
	fi

	if [ "$lct_proto" != "static" ]; then
		logger -t "[config_onu]" "Setting Lct Proto back to static ..."
		uci set network.lct.proto=static
		uci commit network.lct
	fi

	if [ "$host_mac_cap" != "$host_mac_old_cap" ]; then
		logger -t "[config_onu]" "Setting Host MAC Address: $host_mac_cap."
		fw_setenv ethaddr "${host_mac_cap}"
		uci set network.host.macaddr="${host_mac_cap}"
		uci commit network.host
	fi
}

mod_omcid() {
	local mod_omcid
	local omcid_csum
	local omcid_csum_current

	mod_omcid=$(uci -q get gpon.onu.mod_omcid)
	omcid_csum=$(uci -q get gpon.onu.omcid_csum)
	omcid_csum_current=$(md5sum /opt/lantiq/bin/omcid | cut -d' ' -f 1)

	logger -t "[config_onu]" "Patching OMCID ..."

	if [ -n "$mod_omcid" ] &&
		{ [ -z "$omcid_csum" ] && [ "$omcid_csum_current" = "$omcid_stock_csum" ]; } ||
		{ [ -n "$omcid_csum" ] && [ "$omcid_csum_current" = "$omcid_csum" ]; }; then

		local disable_8021x
		local omcid_version

		disable_8021x=$(uci -q get gpon.onu.omcid_8021x)
		omcid_version=$(uci -q get gpon.onu.omcid_version)

		cp /opt/lantiq/bin/omcid /tmp/omcid

		[ "$disable_8021x" = "1" ] && mod_omcid_8021x
		[ -n "$omcid_version" ] && mod_omcid_version "$omcid_version"

		cp /tmp/omcid /opt/lantiq/bin/omcid

		uci set gpon.onu.omcid_csum="$(md5sum /opt/lantiq/bin/omcid | cut -d' ' -f 1)"
		uci commit gpon.onu
	else
		logger -t "[config_onu]" "ERROR: OMCID checksum mismatch, patching aborted ..."
	fi
}

mod_omcid_version() {
	local omcid_version_cut
	local omcid_version_current

	local omcid_version_user="$1"

	omcid_version_cut=$(echo "$omcid_version_user" | cut -c 1-58)
	omcid_version_current=$(/opt/lantiq/bin/omcid -v | tail -n 1 | sed 's/\r//g' | cut -c 18-75)

	printf '%s' "$omcid_version_cut" | hexdump -e '60/1 "%02x" "\n"' |
		awk '{width=116; printf("%s",$1); for(i=0;i<width-length($1);++i) printf -e '"'\x00'"'; print ""}' |
		cut -c 1-116 | xxd -r -p >/tmp/omcid_ver

	#local omcid_version_offset_1=307944
	local omcid_version_offset_2=316133

	if [ "$omcid_version_cut" != "$omcid_version_current" ]; then
		logger -t "[config_onu]" "Modding OMCID version: $omcid_version_cut."
		#dd if=/tmp/omcid_ver of=/tmp/omcid obs=1 seek=$omcid_version_offset_1 conv=notrunc
		dd if=/tmp/omcid_ver of=/tmp/omcid obs=1 seek=$omcid_version_offset_2 conv=notrunc 2>>/dev/null
	fi
}

mod_omcid_8021x() {
	local omcid_8021x_offset=275849

	logger -t "[config_onu]" "Disabling enforcement of 802.1x ..."
	printf '\x00' | dd of=/tmp/omcid conv=notrunc seek=$omcid_8021x_offset bs=1 count=1 2>/dev/null
}

restore_omcid_8021x() {
	local omcid_version
	local omcid_csum
	local omcid_csum_current

	local omcid_8021x_offset=275849

	omcid_version=$(uci -q get gpon.onu.omcid_version)
	omcid_csum=$(uci -q get gpon.onu.omcid_csum)
	omcid_csum_current=$(md5sum /opt/lantiq/bin/omcid | cut -d' ' -f 1)

	logger -t "[config_onu]" "Restoring OMCID 802.1x behaviour ..."

	if [ -n "$omcid_csum" ] && [ "$omcid_csum_current" = "$omcid_csum" ]; then
		logger -t "[config_onu]" "Re-enabling enforcement of 802.1x ..."

		cp /opt/lantiq/bin/omcid /tmp/omcid
		printf '\x01' | dd of=/tmp/omcid conv=notrunc seek=$omcid_8021x_offset bs=1 count=1 2>/dev/null
		cp /tmp/omcid /opt/lantiq/bin/omcid

		if [ -z "$omcid_version" ]; then 
			uci -q delete gpon.onu.omcid_csum
			uci commit gpon.onu
		else
			uci set gpon.onu.omcid_csum="$(md5sum /opt/lantiq/bin/omcid | cut -d' ' -f 1)"
			uci commit gpon.onu
		fi
	else
		logger -t "[config_onu]" "ERROR: OMCID checksum mismatch, unable to restore ..."
	fi
}

restore_omcid_version() {
	local disable_8021x
	local omcid_csum
	local omcid_csum_current

	disable_8021x=$(uci -q get gpon.onu.omcid_8021x)
	omcid_csum=$(uci -q get gpon.onu.omcid_csum)
	omcid_csum_current=$(md5sum /opt/lantiq/bin/omcid | cut -d' ' -f 1)

	logger -t "[config_onu]" "Restoring OMCID version."

	if [ -n "$omcid_csum" ] && [ "$omcid_csum_current" = "$omcid_csum" ]; then
		local omcid_version="6BA1896SPE2C05, internal_version =1620-00802-05-00-000D-01"

		printf '%s' "$omcid_version" | hexdump -e '60/1 "%02x" "\n"' |
			awk '{width=116; printf("%s",$1); for(i=0;i<width-length($1);++i) printf -e '"'\x00'"'; print ""}' |
			cut -c 1-116 | xxd -r -p >/tmp/omcid_ver

		#local omcid_version_offset_1=307944
		local omcid_version_offset_2=316133

		logger -t "[config_onu]" "OMCID version: $omcid_version."

		cp /opt/lantiq/bin/omcid /tmp/omcid
		#dd if=/tmp/omcid_ver of=/tmp/omcid obs=1 seek=$omcid_version_offset_1 conv=notrunc
		dd if=/tmp/omcid_ver of=/tmp/omcid obs=1 seek=$omcid_version_offset_2 conv=notrunc 2>>/dev/null
		cp /tmp/omcid /opt/lantiq/bin/omcid

		if [ -z "$disable_8021x" ]; then 
			uci -q delete gpon.onu.omcid_csum
			uci commit gpon.onu
		else
			uci set gpon.onu.omcid_csum="$(md5sum /opt/lantiq/bin/omcid | cut -d' ' -f 1)"
			uci commit gpon.onu
		fi
	else
		logger -t "[config_onu]" "ERROR: OMCID checksum mismatch, unable to restore ..."
	fi
}

disable_rx_los_status() {
	local disable_rx_los_status
	local rx_los_status_current

	local mod_optic_offset=79607

	disable_rx_los_status=$(uci -q get gpon.onu.disable_rx_los_status)
	rx_los_status_current=$(dd if=/lib/modules/3.10.49/mod_optic.ko bs=1 count=1 skip=79687 conv=notrunc 2>>/dev/null | xxd -ps)

	if [ "$disable_rx_los_status" = "1" ] && [ "$rx_los_status_current" != "00" ]; then
		logger -t "[config_onu]" "Disabling rx_los status ..."
		printf '%b' '\x0' >/tmp/mod_optic
		cp /lib/modules/3.10.49/mod_optic.ko /tmp/mod_optic.ko
		dd if=/tmp/mod_optic of=/tmp/mod_optic.ko obs=1 seek=$mod_optic_offset conv=notrunc 2>>/dev/null
		cp /tmp/mod_optic.ko /lib/modules/3.10.49/mod_optic.ko

	elif [ -z "$disable_rx_los_status" ] && [ "$rx_los_status_current" = "00" ]; then
		logger -t "[config_onu]" "Enabling rx_los status ..."
		printf '%b' '\x1' >/tmp/mod_optic
		cp /lib/modules/3.10.49/mod_optic.ko /tmp/mod_optic.ko
		dd if=/tmp/mod_optic of=/tmp/mod_optic.ko obs=1 seek=$mod_optic_offset conv=notrunc 2>>/dev/null
		cp /tmp/mod_optic.ko /lib/modules/3.10.49/mod_optic.ko
		uci -q delete gpon.onu.disable_rx_los_status
		uci commit gpon.onu
	fi
}

ignore_rx_loss() {
	local ignore_rx_loss

	ignore_rx_loss=$(uci -q get gpon.onu.ignore_rx_loss)

	if [ "$ignore_rx_loss" = "1" ]; then
		logger -t "[config_onu]" "Ignoring rx loss message ..."
		/opt/lantiq/bin/onu onutms ignore_ploam_rx_loss_enable=1 >/dev/null
	else
		logger -t "[config_onu]" "Unignoring rx loss message ..."
		uci -q delete gpon.onu.ignore_rx_loss
		uci commit gpon.onu
		/opt/lantiq/bin/onu onutms ignore_ploam_rx_loss_enable=0 >/dev/null
	fi
}

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

rebootcause() {
	local rebootcause

	rebootcause=$(fw_printenv rebootcause 2>&- | cut -f 2 -d '=')
	echo "$rebootcause" >/tmp/rebootcause

	fw_setenv rebootcause 0
}

rebootnum() {
	local reboottrynum
	local omcidrebootnum

	reboottrynum=$(fw_printenv reboottry 2>&- | cut -c 11)
	omcidrebootnum=$(fw_printenv omcidreboot 2>&- | cut -c 13)

	if [ -z "$reboottrynum" ]; then
		reboottrynum=0
	fi

	if [ -z "$omcidrebootnum" ]; then
		omcidrebootnum=0
	fi

	echo "$reboottrynum" >/tmp/reboottrynum
	echo "$omcidrebootnum" >/tmp/omcidrebootnum
}

rebootdelay() {
	local rebootdirect
	local rebootwait

	rebootdirect=$(uci -q get gpon.onu.rebootdirect)
	rebootwait=$(uci -q get gpon.onu.rebootwait)

	if [ "$rebootdirect" = "1" ] && [ -n "$rebootwait" ]; then
		logger -t "[config_onu]" "Reboot enabled, waiting ..."
		reboot -f -d "$rebootwait" &
	fi
}

switchimage() {
	local imagenext

	imagenext=$(grep image /proc/mtd | cut -c 31)

	fw_setenv committed_image "$imagenext"
	fw_setenv "image${imagenext}_is_valid" 1
}

switchasc() {
	local ascenv
	local asc

	ascenv=$(fw_printenv asc0 2>&- | cut -f 2 -d '=')
	asc=$(uci -q get gpon.onu.asc)

	if [ "$ascenv" != "0" ] && [ "$asc" = "1" ]; then
		logger -t "[config_onu]" "Enabling TTL console, reboot required ..."
		fw_setenv asc0 0
	fi

	if [ "$ascenv" = "0" ] && [ "$asc" != "1" ]; then
		logger -t "[config_onu]" "Disabling TTL console, reboot required ..."
		fw_setenv asc0 1
	fi
}

initasc() {
	local ascenv
	local asc

	ascenv=$(fw_printenv asc0 2>&- | cut -f 2 -d '=')
	asc=$(uci -q get gpon.onu.asc)

	if [ "$ascenv" = "0" ] && [ "$asc" != "1" ]; then
		logger -t "[config_onu]" "TTL console enabled, syncing system config ..."
		uci -q set gpon.onu.asc=1
		uci commit gpon.onu.asc
	fi

	if [ "$ascenv" != "0" ] && [ "$asc" = "1" ]; then
		logger -t "[config_onu]" "TTL console disabled, syncing system config ..."
		uci -q delete gpon.onu.asc
		uci commit gpon.onu.asc
	fi
}

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
restore_version)
	restore_omcid_version
	;;
restore_8021x)
	restore_omcid_8021x
	;;
ignore)
	ignore_rx_loss
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
