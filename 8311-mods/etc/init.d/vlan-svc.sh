#!/bin/sh /etc/rc.common
# Copyright (C) 2009 OpenWrt.org
# Copyright (C) 2011 lantiq.com
#
# vlan-svc.sh -- VLAN Tagging Operation Service (init priority 94)
#
# Procd-managed service that optionally launches the custom VLAN tagging
# engine (vlanexec.sh).  When 8311.config.vlan_svc != 1, the ONU uses
# the normalised ITU-standard VLAN tagging and this service is a no-op.
#
# Dependencies:
#   /opt/lantiq/bin/vlanexec.sh  - VLAN tagging customisation daemon
#   /etc/config/8311             - UCI config (vlan_svc toggle)
#
# Boot flow position: START=94, runs after omcid (85).

START=94

USE_PROCD=1

# start_service -- Conditionally launch the VLAN tagging customisation engine.
# If 8311.config.vlan_svc is not set to "1", logs that ITU-standard tagging
# is in effect and exits without starting any process.
start_service() {
	vlan_svc=$(/sbin/uci -q get 8311.config.vlan_svc)

	if [ "$vlan_svc" != "1" ]; then
		logger -t "[vlan_svc]" "Normalized ITU standard"
		return
	fi

	logger -t "[vlan_svc]" "VLAN Tagging Operation customisation engine enabled"

	procd_open_instance
	procd_set_param respawn
	procd_set_param command /opt/lantiq/bin/vlanexec.sh
	procd_set_param stdout 1
	procd_set_param stderr 1
	procd_close_instance
}
