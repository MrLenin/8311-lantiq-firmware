/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "drv_onu_config.h"
#endif

#if defined(LINUX) && !defined(ONU_SIMULATION)

#include <linux/module.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/device.h>
#include <linux/sysdev.h>
#include <linux/netdevice.h>
#include <linux/timer.h>
#include <linux/ctype.h>
#include <linux/leds.h>
#include <linux/version.h>
#include <linux/if.h>
#include "drv_onu_notifier.h"

extern u32 onu_gpon_link_status_get(void);
extern u32 onu_gpon_packet_count_get(const u8 rx);
extern u32 onu_mac_link_status_get(const u8 idx);
extern u32 onu_mac_packet_count_get(const u8 idx, const u8 rx);

#define MAX_ONU_NOTIFIER_DEVICE		5

static struct onu_notifier_device onu_nfc_device[MAX_ONU_NOTIFIER_DEVICE] =
{
	{"mac0", MAC0_IDX},
	{"mac1", MAC1_IDX},
	{"mac2", MAC2_IDX},
	{"mac3", MAC3_IDX},
	{"gpon", GPON_IDX}
};

static struct onu_notifier_device_stats onu_nfc_stats[MAX_ONU_NOTIFIER_DEVICE];

struct onu_notifier_device *onu_get_by_name(const char *name)
{
	int i;

	if (name == NULL)
		return NULL;

	for (i=0;i<MAX_ONU_NOTIFIER_DEVICE;i++) {
		if (onu_nfc_device[i].name == NULL)
			continue;
		if (strcmp(name, onu_nfc_device[i].name) == 0) {
			return &onu_nfc_device[i];
		}
	}
	return NULL;
}

u32 onu_get_flags(struct onu_notifier_device *dev)
{
	switch (dev->idx) {
		case MAC0_IDX:
		case MAC1_IDX:
		case MAC2_IDX:
		case MAC3_IDX:
		return onu_mac_link_status_get(dev->idx) ? ONU_LOWER_UP : 0;

		case GPON_IDX:
		return onu_gpon_link_status_get() ? ONU_LOWER_UP : 0;
	}
	return 0;
}

u32 onu_carrier_ok(struct onu_notifier_device *dev)
{
	switch (dev->idx) {
	case MAC0_IDX:
	case MAC1_IDX:
	case MAC2_IDX:
	case MAC3_IDX:
		return onu_mac_link_status_get(dev->idx) ? ONU_LOWER_UP : 0;

	case GPON_IDX:
		return onu_gpon_link_status_get();
	}
	return 0;
}

struct onu_notifier_device_stats *onu_get_stats(struct onu_notifier_device *dev)
{
	switch (dev->idx) {
	case MAC1_IDX:
	case MAC0_IDX:
	case MAC2_IDX:
	case MAC3_IDX:
		onu_nfc_stats[dev->idx].rx_packets = onu_mac_packet_count_get(dev->idx, 1);
		onu_nfc_stats[dev->idx].tx_packets = onu_mac_packet_count_get(dev->idx, 0);
		return &onu_nfc_stats[dev->idx];

	case GPON_IDX:
		onu_nfc_stats[dev->idx].rx_packets = onu_gpon_packet_count_get(1);
		onu_nfc_stats[dev->idx].tx_packets = onu_gpon_packet_count_get(0);
		return &onu_nfc_stats[dev->idx];
	}
	return NULL;
}

EXPORT_SYMBOL(onu_get_flags);
EXPORT_SYMBOL(onu_carrier_ok);
EXPORT_SYMBOL(onu_get_stats);
EXPORT_SYMBOL(onu_get_by_name);

#endif /* #if defined(LINUX) && !defined(ONU_SIMULATION) */
