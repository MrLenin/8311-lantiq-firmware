/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_onu_lan_api_intern.h
*/
#ifndef _drv_onu_drv_lan_api_intern_h
#define _drv_onu_drv_lan_api_intern_h

#include "drv_onu_std_defs.h"

EXTERN_C_BEGIN

#ifndef SWIG

/** \addtogroup ONU_MAPI_REFERENCE_INTERNAL
   @{
*/

/** \defgroup ONU_LAN_INTERNAL Ethernet Interface
   @{
*/

/** WAN Port Number*/
#define ONU_NET_NETDEV_WAN_PORT		0
/** LAN Port#0 Number*/
#define ONU_NET_NETDEV_LAN0_PORT	1
/** LAN Port#1 Number*/
#define ONU_NET_NETDEV_LAN1_PORT	2
/** LAN Port#2 Number*/
#define ONU_NET_NETDEV_LAN2_PORT	3
/** LAN Port#3 Number*/
#define ONU_NET_NETDEV_LAN3_PORT	4
/** WAN/LAN Exception Port Number*/
#define ONU_NET_NETDEV_EXC_PORT		5
/** Maximum netdev ports*/
#define ONU_NET_MAX_NETDEV_PORT		6

enum net_cb_type {
	NET_CB_NA = -1,
	/**
	Rx Callback*/
	NET_CB_RX = 0,
	/**
	LAN Link Status Callback*/
	NET_CB_LAN_STATUS = 1,
	/**
	WAN Link Status Callback*/
	NET_CB_WAN_STATUS = 2,
	/**
	Delimeter only*/
	NET_CB_MAX
};

#define ONU_NET_MAX_CB_NUM   NET_CB_MAX

struct net_cb {
	void *net_dev;
	void *cb[ONU_NET_MAX_CB_NUM];
};

struct net_buf {
	void *skb;
	uint8_t *data;
	uint32_t len;
};

typedef int (*onu_net_rx_cb_t) (void *handle, struct net_buf *buf);
typedef int (*onu_wan_status_cb_t) (void *handle, const bool link_up);
typedef int (*onu_lan_status_cb_t) (void *handle, const uint8_t lan_port,
				    const bool link_up);

typedef int (*onu_net_buf_alloc_t) (const uint32_t len, struct net_buf *buf);

struct net_dev {
	onu_net_buf_alloc_t onu_net_buf_alloc;
};

/**
   Register a callback list for the specified Netdev port number.

   \note The callback will be called in interrupt context.

   \param netdev_port   Netdev port number
   \param list       	Callback list.

   \return
   - -1 error
   - 0 success
*/
int net_cb_list_register(const uint8_t netdev_port, struct net_cb *list);

/** \todo add description
*/
int net_dev_register(struct net_dev *dev);

/** \todo add description
*/
int net_lan_mac_set(const uint8_t *mac);

/** \todo add description
*/
uint8_t net_lan_max_port_get(void);

/** \todo add description
*/
int net_egress_cpu_port_get(const uint8_t netdev_port);

/** \todo add description
*/
int net_port_get(const uint8_t uni);

/** \todo add description
*/
int net_uni_get(const uint8_t netdev_port);

/**
   Enable Rx interrupt for the specified Netdev port number.

   \param netdev_port   Netdev port number
   \param enable     	If true the RX interrupt will be enabled.

   \return
   - -1 error
   - 0 success
*/
int net_rx_enable(const uint8_t netdev_port, const bool enable);

/**
   Retrieve received Ethernet PDU information.

   \param cpu_egress_port	CPU egress port number
   \param info			PDU info

   \return
   - -1 error
   - 0 success
*/
int net_pdu_info_get(const uint8_t cpu_egress_port, struct onu_pdu_info *info);

/**
   Write an Ethernet frame to the specified Netdev port. This function use
   the packet engine.

   \param netdev_port   Netdev port number
   \param plen       	data length
   \param data       	Ethernet frame (not padded, no FCS)

   \return
   - -1 error
   - 0 success
*/
int net_pdu_write(const uint8_t netdev_port, const uint32_t plen,
		  const uint8_t *data);

/**
   Read an Ethernet frame. This function use the packet engine.

   \param info       PDU info
   \param data       Ethernet frame (not padded, no FCS)

   \return
   - -1 error
   - 0 success
*/
int net_pdu_read(const struct onu_pdu_info *info, uint8_t *data);

/*! @} */

/*! @} */

#endif /* SWIG */

EXTERN_C_END

#endif
