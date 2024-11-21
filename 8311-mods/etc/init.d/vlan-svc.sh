#!/bin/sh /etc/rc.common
# Copyright (C) 2009 OpenWrt.org
# Copyright (C) 2011 lantiq.com
START=94
flag=1

USE_PROCD=1

start_service() {
	procd_open_instance
	procd_set_param respawn

	vlan_svc=$(/sbin/uci get 8311.config.vlan_svc)

	if [ "$vlan_svc" = "1" ]; then
		logger -t "[vlan_svc]" "VLAN Tagging Operation customisation engine enabled"
		procd_set_param command /opt/lantiq/bin/vlanexec.sh
	else
		logger -t "[vlan_svc]" "Normalized ITU standard"
	fi
    
	procd_set_param stdout 1
	procd_set_param stderr 1
	procd_close_instance
}
