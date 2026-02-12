/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _drv_onu_notifier_h
#define _drv_onu_notifier_h

struct onu_notifier_device {
	char name[IFNAMSIZ];
	u8 idx;
};

struct onu_notifier_device_stats {
	u32 tx_packets;
	u32 rx_packets;
};

struct onu_notifier_device *onu_get_by_name(const char *name);
u32 onu_get_flags(struct onu_notifier_device *);
u32 onu_carrier_ok(struct onu_notifier_device *);
struct onu_notifier_device_stats *onu_get_stats(struct onu_notifier_device *);

#define ONU_LOWER_UP			0x01

#define ONU_DEV_UP			0x01
#define ONU_DEV_DOWN			0x02
#define ONU_DEV_CHANGE			0x04
#define ONU_DEV_REGISTER		0x08
#define ONU_DEV_UNREGISTER		0x10
#define ONU_NOTIFY_DONE			0x00

#define MAC0_IDX			0
#define MAC1_IDX			1
#define MAC2_IDX			2
#define MAC3_IDX			3
#define GPON_IDX			4

#endif
