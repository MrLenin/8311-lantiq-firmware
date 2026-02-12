/*
 *  ONU ethernet driver
 *
 *  Copyright (C) 2010 Ralph Hempel <ralph.hempel@lantiq.com>
 *
 *  This program is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License version 2  as published
 *  by the Free Software Foundation.
 *
 */
#ifndef _INCLUDE_ONU_NETDEV_H_
#define _INCLUDE_ONU_NETDEV_H_

#define ONU_NETDEV_NAME         "onu_netdev"
#define ONU_NETDEV_DESC         "FALC(tm) ON Ethernet Driver"
#define ONU_NETDEV_VERSION      "0.7.0"

#undef CONFIG_ONU_NETDEV_DEBUG

#ifdef CONFIG_ONU_NETDEV_DEBUG
#define SW_DBG(f, a...)          printk(KERN_INFO "[%s] " f, ONU_NETDEV_NAME , ## a)
#else
#define SW_DBG(f, a...)          do {} while (0)
#endif
#define SW_ERR(f, a...)          printk(KERN_ERR "[%s] " f, ONU_NETDEV_NAME , ## a)
#define SW_INFO(f, a...)         printk(KERN_INFO "[%s] " f, ONU_NETDEV_NAME , ## a)

#define ONU_TX_TIMEOUT           HZ*400

#define ONU_NETDEV_NAME_WAN	"wan"
#define ONU_NETDEV_NAME_LAN	"lct"
#define ONU_NETDEV_NAME_EXC	"exc"

struct onu_netdev_if_priv {
	struct net_device *dev;
	unsigned int port_number;
	unsigned int lan_port_status_mask;
};

#endif				/* _INCLUDE_ONU_NETDEV_H_ */
