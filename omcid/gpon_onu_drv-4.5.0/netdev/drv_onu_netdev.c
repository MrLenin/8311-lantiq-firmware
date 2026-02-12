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

#if defined(LINUX) && !defined(ONU_SIMULATION)

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/ioport.h>
#include <linux/spinlock.h>
#include <linux/platform_device.h>
#include <linux/io.h>
#include <linux/irq.h>
#include <linux/version.h>

#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>

#include "drv_onu_netdev.h"
#include "drv_onu_debug.h"
#include "drv_onu_types.h"
#include "drv_onu_ll_ssb.h"
#include "drv_onu_lan_api_intern.h"
#include "drv_onu_resource.h"
#include "drv_onu_resource_gpe.h"

static struct platform_device *onu_netdev_device;
static struct net_device *onu_netdev_devs[ONU_NET_MAX_NETDEV_PORT];
static DEFINE_SPINLOCK(tx_lock);

STATIC int onu_netdev_if_open(struct net_device *dev);
STATIC int onu_netdev_if_stop(struct net_device *dev);
STATIC int onu_netdev_if_hard_start_xmit(struct sk_buff *skb,
					 struct net_device *dev);
STATIC void onu_netdev_if_set_multicast_list(struct net_device *dev);
STATIC int onu_netdev_if_do_ioctl(struct net_device *dev, struct ifreq *rq,
				  int cmd);
STATIC void onu_netdev_if_tx_timeout(struct net_device *dev);
STATIC int onu_netdev_if_set_mac_address(struct net_device *dev, void *p);

extern u32 onu_gpon_link_status_get(void);
extern u32 onu_mac_link_status_get(const u8 idx);

#  if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30))

static const struct net_device_ops onu_netdev_ops = {
	.ndo_open = onu_netdev_if_open,
	.ndo_stop = onu_netdev_if_stop,
	.ndo_start_xmit = onu_netdev_if_hard_start_xmit,
	.ndo_set_multicast_list = onu_netdev_if_set_multicast_list,
	.ndo_do_ioctl = onu_netdev_if_do_ioctl,
	.ndo_tx_timeout = onu_netdev_if_tx_timeout,
	.ndo_set_mac_address = onu_netdev_if_set_mac_address
};

/** \todo   dev->watchdog_timeo     = ONU_TX_TIMEOUT;*/

#endif

STATIC int onu_netdev_buf_alloc(const uint32_t len, struct net_buf *buf)
{
	struct sk_buff *skb;

	if (!len || !buf)
		return -1;

	skb = dev_alloc_skb(len);
	if (skb == NULL)
		return -1;

	buf->skb = (void*)skb;
	buf->data = (uint8_t*)skb->data;
	buf->len = len;

	return 0;
}

STATIC int onu_netdev_rx(struct net_device *dev, struct net_buf *buf)
{
	struct sk_buff *skb;

	if (!dev) {
		SW_ERR("no dev\n");
		return -1;
	}

	if (!netif_running(dev)) {
		SW_ERR("netif not running\n");
		return -1;
	}

	skb = (struct sk_buff *)buf->skb;

	if (skb == NULL) {
		dev->stats.rx_errors++;
		return -3;
	}

	if (buf->len == 0) {
		dev_kfree_skb(skb);
		dev->stats.rx_errors++;
		dev->stats.rx_length_errors++;
		if (0)		/** \todo add crc errors */
			dev->stats.rx_crc_errors++;
		return -5;
	}

	if (skb) {
		skb_put(skb, buf->len);
		skb->dev = dev;
		skb->protocol = eth_type_trans(skb, dev);
		skb->ip_summed = CHECKSUM_NONE;
		netif_rx(skb);
		dev->last_rx = jiffies;
		dev->stats.rx_packets++;
		dev->stats.rx_bytes += buf->len;
	}

	return 0;
}

STATIC int onu_netdev_irq(void *handle, struct net_buf *buf)
{
	int ret;

	ret = onu_netdev_rx(handle, buf);

	return ret;
}

STATIC int onu_netdev_lan_link_status(	void *handle, const uint8_t lan_port,
					const bool link_up)
{
	struct onu_netdev_if_priv *priv =
					netdev_priv((struct net_device*)handle);

	if (link_up)
		priv->lan_port_status_mask |= (1 << lan_port);
	else
		priv->lan_port_status_mask &= ~(1 << lan_port);

	if (priv->lan_port_status_mask &&
				!netif_carrier_ok((struct net_device*)handle)) {
		SW_DBG("lan%u up\n", lan_port);
		net_rx_enable(priv->port_number, true);
		netif_carrier_on((struct net_device*)handle);
	} else if (!priv->lan_port_status_mask &&
				netif_carrier_ok((struct net_device*)handle)){
		SW_DBG("lan%u down\n", lan_port);
		net_rx_enable(priv->port_number, false);
		netif_carrier_off((struct net_device*)handle);
	} else {
		return 0;
	}

	return 0;
}

STATIC int onu_netdev_wan_link_status(void *handle, const bool link_up)
{
	struct onu_netdev_if_priv *priv =
					netdev_priv((struct net_device*)handle);

	if (link_up && !netif_carrier_ok((struct net_device*)handle)) {
		SW_DBG("wan up\n");
		net_rx_enable(priv->port_number, true);
		netif_carrier_on((struct net_device*)handle);
	} else if (!link_up && netif_carrier_ok((struct net_device*)handle)){
		SW_DBG("wan down\n");
		net_rx_enable(priv->port_number, false);
		netif_carrier_off((struct net_device*)handle);
	} else {
		return 0;
	}

	return 0;
}

STATIC int onu_netdev_exc_link_status(void *handle, const bool link_up)
{
	struct onu_netdev_if_priv *priv =
					netdev_priv((struct net_device*)handle);

	if (link_up && !netif_carrier_ok((struct net_device*)handle)) {
		SW_DBG("exc up\n");
		net_rx_enable(priv->port_number, true);
		netif_carrier_on((struct net_device*)handle);
	} else if (!link_up && netif_carrier_ok((struct net_device*)handle)){
		SW_DBG("exc down\n");
		net_rx_enable(priv->port_number, false);
		netif_carrier_off((struct net_device*)handle);
	} else {
		return 0;
	}

	return 0;
}

STATIC int onu_netdev_if_open(struct net_device *dev)
{
	struct onu_netdev_if_priv *priv = netdev_priv(dev);
	struct net_cb cb_list = {
		NULL,
		{	onu_netdev_irq,
			onu_netdev_lan_link_status,
			onu_netdev_wan_link_status
		}
	};

	SW_DBG("open %p on %s\n", dev, dev->name);

	cb_list.net_dev = dev;

	switch (priv->port_number) {
	case ONU_NET_NETDEV_WAN_PORT:
		onu_netdev_wan_link_status(dev,
					   (bool)onu_gpon_link_status_get());

		cb_list.cb[NET_CB_LAN_STATUS] = NULL;
		break;
	case ONU_NET_NETDEV_LAN0_PORT:
	case ONU_NET_NETDEV_LAN1_PORT:
	case ONU_NET_NETDEV_LAN2_PORT:
	case ONU_NET_NETDEV_LAN3_PORT:
		onu_netdev_lan_link_status(
			dev, net_uni_get(priv->port_number),
			(bool)onu_mac_link_status_get(
					net_uni_get(priv->port_number)));
		cb_list.cb[NET_CB_WAN_STATUS] = NULL;
		break;
	case ONU_NET_NETDEV_EXC_PORT:
		onu_netdev_exc_link_status(dev, true);
		cb_list.cb[NET_CB_LAN_STATUS] = NULL;
		cb_list.cb[NET_CB_WAN_STATUS] = NULL;
		break;
	}

	if (net_cb_list_register((uint8_t)priv->port_number, &cb_list) < 0)
		return -1;

	netif_start_queue(dev);

	return 0;
}

STATIC int onu_netdev_if_stop(struct net_device *dev)
{
	struct onu_netdev_if_priv *priv = netdev_priv(dev);
	struct net_cb cb_list = {0};
	int uni;

	SW_DBG("stop on %s\n", dev->name);

	netif_stop_queue(dev);

	uni = net_uni_get(priv->port_number);
	if (uni < 0) {
		net_rx_enable((uint8_t)priv->port_number, false);
	} else {
		priv->lan_port_status_mask &= ~(1 << uni);
		if (!priv->lan_port_status_mask)
			net_rx_enable((uint8_t)priv->port_number, false);
	}

	netif_carrier_off(dev);
	net_cb_list_register((uint8_t)priv->port_number, &cb_list);

	return 0;
}

STATIC int onu_netdev_if_hard_start_xmit(struct sk_buff *skb,
					 struct net_device *dev)
{
	struct onu_netdev_if_priv *priv = netdev_priv(dev);
	int ret;

	spin_lock_irq(&tx_lock);

	SW_DBG("xmit on %s\n", dev->name);

	ret = net_pdu_write((uint8_t)priv->port_number, skb->len, skb->data);
	if (ret != 0) {
		SW_DBG("%s unable to transmit, packet dropped\n", dev->name);
		dev->stats.tx_dropped++;
	} else {
		dev->trans_start = jiffies;
		dev->stats.tx_packets++;
		dev->stats.tx_bytes += skb->len;
	}
	dev_kfree_skb(skb);
	spin_unlock_irq(&tx_lock);

	return 0;
}

STATIC void onu_netdev_if_tx_timeout(struct net_device *dev)
{
	SW_DBG("TX timeout on %s\n", dev->name);
}

STATIC void onu_netdev_if_set_multicast_list(struct net_device *dev)
{
	struct onu_netdev_if_priv *priv = netdev_priv(dev);

	(void)priv;

	SW_DBG("set multicast list on %s\n", dev->name);

	if (dev->flags & IFF_PROMISC) {
		/* enable unknown packets */
		SW_DBG("enable promisc mode on %s\n", dev->name);
	} else {
		/* disable unknown packets */
	}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35))
	if (dev->flags & IFF_PROMISC || dev->flags & IFF_ALLMULTI ||
	    dev->mc_count) {
		/* enable multicast packets */
	} else {
		/* disable multicast packets */
	}
#endif
}

STATIC int onu_netdev_if_set_mac_address(struct net_device *dev, void *p)
{
	struct onu_netdev_if_priv *priv = netdev_priv(dev);
	struct sockaddr *addr = p;

	SW_DBG("set mac address\n");

	memcpy(dev->dev_addr, addr->sa_data, dev->addr_len);

	switch (priv->port_number) {
	case ONU_NET_NETDEV_LAN0_PORT:
	case ONU_NET_NETDEV_LAN1_PORT:
	case ONU_NET_NETDEV_LAN2_PORT:
	case ONU_NET_NETDEV_LAN3_PORT:
		if (net_lan_mac_set(addr->sa_data) != 0)
			return -1;
		break;
	default:
		break;
	}

	return 0;
}

STATIC int onu_netdev_if_do_ioctl(struct net_device *dev, struct ifreq *rq,
				  int cmd)
{
	struct onu_netdev_if_priv *priv = netdev_priv(dev);

	(void)priv;

	SW_DBG("ioctl on %s\n", dev->name);

	switch (cmd) {
	default:
		return -EOPNOTSUPP;
	}
	return 0;
}

STATIC struct net_device *onu_netdev_if_alloc(void)
{
	struct net_device *dev;
	struct onu_netdev_if_priv *priv;

	SW_DBG("alloc\n");

	dev = alloc_etherdev(sizeof(*priv));
	if (!dev)
		return NULL;

	priv = netdev_priv(dev);
	priv->dev = dev;

#  if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30))
	/** \todo crosscheck irq
	*/
	/* dev->irq          = 42; */
	dev->open = onu_netdev_if_open;
	dev->hard_start_xmit = onu_netdev_if_hard_start_xmit;
	dev->stop = onu_netdev_if_stop;
	dev->set_multicast_list = onu_netdev_if_set_multicast_list;
	dev->do_ioctl = onu_netdev_if_do_ioctl;
	dev->tx_timeout = onu_netdev_if_tx_timeout;
	dev->watchdog_timeo = ONU_TX_TIMEOUT;
	dev->set_mac_address = onu_netdev_if_set_mac_address;
#  else
	dev->netdev_ops = &onu_netdev_ops;
#  endif

	return dev;
}

STATIC void onu_netdev_cleanup(void)
{
	int i;

	SW_DBG("cleanup\n");

	for (i = 0; i < ONU_NET_MAX_NETDEV_PORT; i++) {
		struct net_device *dev = onu_netdev_devs[i];
		if (dev) {
			unregister_netdev(dev);
			free_netdev(dev);
		}
		onu_netdev_devs[i] = NULL;
	}
}

STATIC int onu_netdev_probe(struct platform_device *pdev)
{
	int i, err;
	uint8_t max_lan_port;

	/* get available LAN ports number */
	max_lan_port = net_lan_max_port_get();

	for (i = 0; i < ONU_NET_MAX_NETDEV_PORT; i++) {
		struct net_device *dev;
		struct onu_netdev_if_priv *priv;

		/* skip unavailable LAN ports */
		if ((i == ONU_NET_NETDEV_LAN0_PORT && max_lan_port < 1) ||
		    (i == ONU_NET_NETDEV_LAN1_PORT && max_lan_port < 2) ||
		    (i == ONU_NET_NETDEV_LAN2_PORT && max_lan_port < 3) ||
		    (i == ONU_NET_NETDEV_LAN3_PORT && max_lan_port < 4))
			continue;

		dev = onu_netdev_if_alloc();
		if (!dev) {
			err = -ENOMEM;
			goto err;
		}

		onu_netdev_devs[i] = dev;
		priv = netdev_priv(dev);

		switch (i) {
		case ONU_NET_NETDEV_WAN_PORT:
			strcpy(dev->name, ONU_NETDEV_NAME_WAN);
			break;
		case ONU_NET_NETDEV_LAN0_PORT:
		case ONU_NET_NETDEV_LAN1_PORT:
		case ONU_NET_NETDEV_LAN2_PORT:
		case ONU_NET_NETDEV_LAN3_PORT:
			sprintf(dev->name, "%s%u", ONU_NETDEV_NAME_LAN,
						   net_uni_get(i));
			break;
		case ONU_NET_NETDEV_EXC_PORT:
			strcpy(dev->name, ONU_NETDEV_NAME_EXC);
			break;
		default:
			err = -1;
			goto err;
		}

		priv->port_number = i;
		priv->lan_port_status_mask = 0;

		err = register_netdev(dev);
		if (err) {
			SW_INFO("%s register failed, error=%d\n",
				dev->name, err);
			goto err;
		}
		netif_carrier_off(dev);
	}

	return 0;

err:
	onu_netdev_cleanup();

	SW_ERR("init failed\n");
	return err;
}

STATIC int onu_netdev_remove(struct platform_device *dev)
{
	SW_DBG("remove %s\n", dev->name);
	onu_netdev_cleanup();
	return 0;
}

static struct platform_driver onu_netdev_driver = {
	.probe = onu_netdev_probe,
	.remove = onu_netdev_remove,
	.driver = {
		   .name = ONU_NETDEV_NAME,
		   },
};

STATIC int __init onu_netdev_mod_init(void)
{
	int ret;
	struct net_dev dev  = { onu_netdev_buf_alloc };

	pr_info(ONU_NETDEV_DESC ", Version " ONU_NETDEV_VERSION
		" (c) Copyright 2011, Lantiq Deutschland GmbH\n");
	ret = platform_driver_register(&onu_netdev_driver);
	if (ret) {
		printk(KERN_ERR ONU_NETDEV_DESC
		       "Error registering platfom driver\n");
	}
	onu_netdev_device = platform_device_alloc("onu_netdev", -1);
	if (!onu_netdev_device) {
		printk(KERN_ERR ONU_NETDEV_DESC
		       "Error allocating platfom driver\n");
		ret = -ENOMEM;
		goto err_unregister_driver;
	}
	ret = platform_device_add(onu_netdev_device);
	if (ret) {
		printk(KERN_ERR ONU_NETDEV_DESC
		       "Error adding platfom driver\n");
		goto err_free_device;
	}

	ret =  net_dev_register(&dev);
	if (ret != 0) {
		printk(KERN_ERR ONU_NETDEV_DESC
		       "Error registering platfom driver\n");
		goto err_free_device;
	}

	return 0;

err_free_device:
	platform_device_put(onu_netdev_device);

err_unregister_driver:
	platform_driver_unregister(&onu_netdev_driver);

	return ret;
}

STATIC void __exit onu_netdev_mod_exit(void)
{
	SW_DBG("exit\n");

	platform_device_unregister(onu_netdev_device);
	platform_driver_unregister(&onu_netdev_driver);
}

module_init(onu_netdev_mod_init);
module_exit(onu_netdev_mod_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Ralph Hempel <ralph.hempel@lantiq.com>");
MODULE_DESCRIPTION(ONU_NETDEV_DESC);
MODULE_VERSION(ONU_NETDEV_VERSION);

#endif				/* defined(LINUX) && !defined(ONU_SIMULATION) */
