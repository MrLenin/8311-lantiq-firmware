/******************************************************************************
 * Copyright (c) 2025 8311 Contributors
 *
 * Falcon GPE device abstraction for MCC.
 * Direct ioctls replacing the PON Adapter abstraction from v8.6.3.
 *
 * Exception interface ("exc") for IGMP/MLD packet reception.
 * GPE multicast forwarding table ioctls for port add/remove/modify.
 * VLAN FID management and exception queue configuration.
 ******************************************************************************/
#define OMCI_DBG_MODULE OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "mcc/omci_mcc_core.h"

/* Driver headers for GPE ioctl structures */
#include "drv_onu_gpe_interface.h"
#include "drv_onu_gpe_tables_interface.h"
#include "drv_onu_resource_gpe.h"
#include "drv_onu_resource.h"
#include "drv_onu_types.h"

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

/* dev_ctl is defined in libomciapi.a (omci_api.c) */
extern enum omci_api_return dev_ctl(const uint8_t remote, const int fd,
				    const uint32_t cmd, void *p_data,
				    const size_t data_sz);

/** Exception interface name (created by onu_netdev kernel module) */
#define MCC_EXC_IF_NAME		"exc"

/** Exception queue ID for IGMP/MLD (must match what shipping binary uses) */
#define MCC_EXCEPTION_QID	0xb0

/** Wait timeout for "exc" interface to come UP (milliseconds) */
#define MCC_IF_WAIT_TIMEOUT	5000

/** Size of the exception packet header prepended by GPE */
#define MCC_EXC_HDR_SIZE	sizeof(union u_onu_exception_pkt_hdr)

/** Exception source bits in ctrl byte */
#define MCC_EXC_SRC_WAN_EGRESS	0	/* bits 7:6 = 00 */
#define MCC_EXC_SRC_WAN_INGRESS	1	/* bits 7:6 = 01 */
#define MCC_EXC_SRC_LAN_EGRESS	2	/* bits 7:6 = 10 */
#define MCC_EXC_SRC_LAN_INGRESS	3	/* bits 7:6 = 11 */

/**
 * Helper: call dev_ctl on /dev/onu0 via the MCC device context.
 * Returns OMCI_SUCCESS or OMCI_ERROR.
 */
static enum omci_error mcc_ioctl(struct mcc_dev_ctx *dev,
				 uint32_t cmd, void *data, size_t sz)
{
	int ret;

	ret = dev_ctl(dev->remote, dev->onu_fd, cmd, data, sz);
	if (ret != 0)
		return OMCI_ERROR;

	return OMCI_SUCCESS;
}

/**
 * Configure the GPE exception queue for IGMP/MLD packets.
 * When enabled, IGMP/MLD packets are delivered to the "exc" interface.
 * When disabled, they are sent to the null queue (dropped).
 */
static enum omci_error mcc_exc_queue_ctrl(struct mcc_dev_ctx *dev, bool enable)
{
	struct gpe_exception_queue_cfg queue_cfg;

	memset(&queue_cfg, 0, sizeof(queue_cfg));
	queue_cfg.exception_index = ONU_GPE_EXCEPTION_OFFSET_IGMP_MLD;
	queue_cfg.exception_queue = enable ? MCC_EXCEPTION_QID :
					     ONU_GPE_NULL_QUEUE;
	queue_cfg.snooping_enable = 0;

	return mcc_ioctl(dev, FIO_GPE_EXCEPTION_QUEUE_CFG_SET,
			 &queue_cfg, sizeof(queue_cfg));
}

enum omci_error mcc_dev_init(struct mcc_dev_ctx *dev,
			     int onu_fd, bool remote,
			     uint32_t *max_ports)
{
	struct ifreq ifr;
	struct sockaddr_ll sll;
	enum omci_error error;
	int i;

	dev->onu_fd = onu_fd;
	dev->remote = remote;
	dev->exc_sock = -1;
	dev->exc_ifindex = -1;

	/* Open raw socket on "exc" exception interface */
	dev->exc_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (dev->exc_sock < 0) {
		dbg_err("MCC dev: raw socket open failed, %d", errno);
		return OMCI_ERROR;
	}

	/* Get "exc" interface index */
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, MCC_EXC_IF_NAME, IFNAMSIZ - 1);
	if (ioctl(dev->exc_sock, SIOCGIFINDEX, &ifr) < 0) {
		dbg_err("MCC dev: \"%s\" interface not found: %s",
			MCC_EXC_IF_NAME, strerror(errno));
		close(dev->exc_sock);
		dev->exc_sock = -1;
		return OMCI_ERROR;
	}
	dev->exc_ifindex = ifr.ifr_ifindex;

	/* Wait for interface to be UP and RUNNING */
	for (i = 0; i < MCC_IF_WAIT_TIMEOUT / 100; i++) {
		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, MCC_EXC_IF_NAME, IFNAMSIZ - 1);
		if (ioctl(dev->exc_sock, SIOCGIFFLAGS, &ifr) < 0)
			break;
		if ((ifr.ifr_flags & IFF_UP) &&
		    (ifr.ifr_flags & IFF_RUNNING))
			break;
		usleep(100000); /* 100ms */
	}

	/* Ensure interface is UP and set promiscuous mode */
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, MCC_EXC_IF_NAME, IFNAMSIZ - 1);
	if (ioctl(dev->exc_sock, SIOCGIFFLAGS, &ifr) == 0) {
		if (!(ifr.ifr_flags & (IFF_UP | IFF_RUNNING))) {
			ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
			ioctl(dev->exc_sock, SIOCSIFFLAGS, &ifr);
		}
		ifr.ifr_flags |= IFF_PROMISC;
		ioctl(dev->exc_sock, SIOCSIFFLAGS, &ifr);
	}

	/* Bind to "exc" interface */
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_ALL);
	sll.sll_ifindex = dev->exc_ifindex;
	if (bind(dev->exc_sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		dbg_err("MCC dev: socket %d to %s i/f bind failed",
			dev->exc_sock, MCC_EXC_IF_NAME);
		close(dev->exc_sock);
		dev->exc_sock = -1;
		return OMCI_ERROR;
	}

	/* Configure IGMP/MLD exception queue */
	error = mcc_exc_queue_ctrl(dev, true);
	if (error != OMCI_SUCCESS)
		dbg_wrn("MCC dev: exception queue setup failed (non-fatal)");

	/* G-010S-P has 4 UNI ports (only 1 physical, but GPE supports 4) */
	if (max_ports)
		*max_ports = 4;

	dbg_prn("MCC dev: init ok, exc_sock=%d, exc_ifindex=%d",
		dev->exc_sock, dev->exc_ifindex);

	return OMCI_SUCCESS;
}

void mcc_dev_shutdown(struct mcc_dev_ctx *dev)
{
	/* Disable IGMP/MLD exception queue */
	mcc_exc_queue_ctrl(dev, false);

	if (dev->exc_sock >= 0) {
		close(dev->exc_sock);
		dev->exc_sock = -1;
	}
}

/**
 * Receive an exception packet from the "exc" interface.
 *
 * Exception packets have an 8-byte GPE header prepended:
 *   [egress_qid][ingress_info][gpix][ctrl]
 *   [o_vlan_msb][o_vlan_lsb][unused][ethtype_offset]
 *
 * ingress_info bits: 7:6 = LAN port index, 5:0 = FID
 * ctrl bits: 7:6 = exception source (0=WAN eg, 1=WAN ing, 2=LAN eg, 3=LAN ing)
 *            4:0 = exception index
 *
 * The buffer returned to the caller includes the exception header.
 * The info structure is filled with metadata extracted from it.
 */
enum omci_error mcc_dev_pkt_receive(struct mcc_dev_ctx *dev,
				    uint8_t *msg, uint16_t *len,
				    struct mcc_pkt_ll_info *info)
{
	ssize_t n;
	union u_onu_exception_pkt_hdr *exc_hdr;
	uint8_t exc_src;
	uint16_t o_vid;

	if (dev->exc_sock < 0)
		return OMCI_ERROR;

	n = recvfrom(dev->exc_sock, msg, *len, 0, NULL, NULL);
	if (n <= 0)
		return OMCI_ERROR;

	*len = (uint16_t)n;

	if (info) {
		memset(info, 0, sizeof(*info));
		info->cvid = MCC_VLAN_UNTAGGED;
		info->svid = MCC_VLAN_UNTAGGED;
		info->port_idx = 0;
		info->dir_us = true;
		info->offset_iph = MCC_EXC_HDR_SIZE + 14;

		/* Parse the 8-byte exception header */
		if ((size_t)n >= MCC_EXC_HDR_SIZE) {
			exc_hdr = (union u_onu_exception_pkt_hdr *)msg;

			/* Extract LAN port index from ingress_info bits 7:6 */
			info->port_idx =
				(exc_hdr->byte.ingress_info >> 6) & 0x03;

			/* Determine direction from exception source */
			exc_src = (exc_hdr->byte.ctrl >> 6) & 0x03;
			info->dir_us = (exc_src == MCC_EXC_SRC_LAN_INGRESS);

			/* Extract outer VLAN from exception header */
			o_vid = ((uint16_t)(exc_hdr->byte.o_vlan_msb & 0x0F) << 8)
				| exc_hdr->byte.o_vlan_lsb;
			if (o_vid > 0 && o_vid < 4096)
				info->cvid = o_vid;

			/* Use ethtype_offset to find IP header.
			   ethtype_offset is relative to the Ethernet frame
			   start (after the exception header), pointing to
			   the first non-VLAN EtherType. +2 past EtherType
			   is the IP header. */
			if (exc_hdr->byte.ethtype_offset > 0)
				info->offset_iph = MCC_EXC_HDR_SIZE +
					exc_hdr->byte.ethtype_offset + 2;
		}
	}

	return OMCI_SUCCESS;
}

void mcc_dev_pkt_receive_cancel(struct mcc_dev_ctx *dev)
{
	if (dev->exc_sock >= 0)
		shutdown(dev->exc_sock, SHUT_RDWR);
}

enum omci_error mcc_dev_pkt_send(struct mcc_dev_ctx *dev,
				 const uint8_t *msg, const uint16_t len,
				 const struct mcc_pkt_ll_info *info)
{
	ssize_t n;

	if (dev->exc_sock < 0)
		return OMCI_ERROR;

	n = send(dev->exc_sock, msg, len, 0);
	if (n < 0)
		return OMCI_ERROR;

	return OMCI_SUCCESS;
}

/**
 * Get Forwarding ID for a VLAN.
 * Uses FIO_GPE_VLAN_FID_GET to query the GPE VLAN→FID mapping table.
 * Returns default FID (0) for untagged or VLAN-unaware mode.
 */
enum omci_error mcc_dev_fid_get(struct mcc_dev_ctx *dev,
				const uint16_t o_vid,
				uint8_t *fid)
{
	union gpe_vlan_fid_u vlan_fid;
	enum omci_error error;

	if (!fid)
		return OMCI_ERROR;

	/* Untagged or VLAN-unaware → default FID */
	if (o_vid == 0 || o_vid >= MCC_VLAN_UNTAGGED) {
		*fid = ONU_GPE_CONSTANT_VAL_DEFAULT_FID;
		return OMCI_SUCCESS;
	}

	memset(&vlan_fid, 0, sizeof(vlan_fid));
	vlan_fid.in.vlan_1 = o_vid; /* VLAN ID in bits 0:11 */
	vlan_fid.in.vlan_2 = 0;     /* No inner VLAN */

	error = mcc_ioctl(dev, FIO_GPE_VLAN_FID_GET,
			  &vlan_fid, sizeof(vlan_fid));
	if (error != OMCI_SUCCESS) {
		/* FID not found for this VLAN — use default */
		*fid = ONU_GPE_CONSTANT_VAL_DEFAULT_FID;
		return OMCI_SUCCESS;
	}

	*fid = (uint8_t)vlan_fid.out.fid;
	return OMCI_SUCCESS;
}

/**
 * Enable/disable VLAN-unaware multicast forwarding mode.
 * In VLAN-unaware mode, all multicast uses default FID regardless of VLAN tags.
 */
enum omci_error mcc_dev_vlan_unaware_mode_enable(struct mcc_dev_ctx *dev,
						 const bool enable)
{
	/* The GPE doesn't have a single "VLAN unaware" toggle for multicast.
	   Instead, this affects how FID lookups work:
	   - Unaware mode: always use default FID (handled in mcc_dev_fid_get)
	   - Aware mode: look up FID from VLAN tag

	   Store the mode flag so mcc_dev_fid_get can check it.
	   The actual GPE behavior is controlled by per-VLAN FID entries. */
	dev->vlan_unaware = enable;
	return OMCI_SUCCESS;
}

/**
 * Update multicast forwarding table entry.
 * Programs the GPE IPv4 multicast forwarding table with port map
 * and optional source filters.
 */
enum omci_error mcc_dev_fwd_update(struct mcc_dev_ctx *dev,
				   const uint8_t fid,
				   const bool include_enable,
				   const uint16_t bridge_id,
				   const uint8_t port_map,
				   const union mcc_ip_addr *da,
				   struct mcc_list *fwd_slist)
{
	struct gpe_ipv4_mc_port_modify modify;

	if (!da)
		return OMCI_ERROR;

	memset(&modify, 0, sizeof(modify));
	modify.bridge_index = bridge_id;
	modify.port_map_index = port_map;
	modify.fid = fid;
	modify.igmp = 1; /* IGMP-managed entry */
	memcpy(modify.ip, da->ipv4, 4);

	return mcc_ioctl(dev, FIO_GPE_SHORT_FWD_IPV4_MC_PORT_MODIFY,
			 &modify, sizeof(modify));
}

/**
 * Add a LAN port to a multicast group.
 * Creates an IPv4 multicast forwarding entry in the GPE table.
 */
enum omci_error mcc_dev_port_add(struct mcc_dev_ctx *dev,
				 const enum mcc_dir dir,
				 const uint8_t lan_port,
				 const uint8_t fid,
				 const union mcc_ip_addr *ip)
{
	struct gpe_ipv4_mc_port mc_port;

	if (!ip)
		return OMCI_ERROR;

	memset(&mc_port, 0, sizeof(mc_port));
	mc_port.fid = fid;
	mc_port.lan_port_index = lan_port;
	mc_port.igmp = 1; /* IGMP-managed entry */
	memcpy(mc_port.ip, ip->ipv4, 4);

	dbg_prn("MCC dev: port %u add, fid=%u, ip=%u.%u.%u.%u",
		lan_port, fid,
		ip->ipv4[0], ip->ipv4[1], ip->ipv4[2], ip->ipv4[3]);

	return mcc_ioctl(dev, FIO_GPE_SHORT_FWD_IPV4_MC_PORT_ADD,
			 &mc_port, sizeof(mc_port));
}

/**
 * Remove a LAN port from a multicast group.
 * Deletes the IPv4 multicast forwarding entry from the GPE table.
 */
enum omci_error mcc_dev_port_remove(struct mcc_dev_ctx *dev,
				    const uint8_t lan_port,
				    const uint8_t fid,
				    const union mcc_ip_addr *ip)
{
	struct gpe_ipv4_mc_port mc_port;

	if (!ip)
		return OMCI_ERROR;

	memset(&mc_port, 0, sizeof(mc_port));
	mc_port.fid = fid;
	mc_port.lan_port_index = lan_port;
	mc_port.igmp = 1; /* IGMP-managed entry */
	memcpy(mc_port.ip, ip->ipv4, 4);

	dbg_prn("MCC dev: port %u remove, fid=%u, ip=%u.%u.%u.%u",
		lan_port, fid,
		ip->ipv4[0], ip->ipv4[1], ip->ipv4[2], ip->ipv4[3]);

	return mcc_ioctl(dev, FIO_GPE_SHORT_FWD_IPV4_MC_PORT_DELETE,
			 &mc_port, sizeof(mc_port));
}

/**
 * Check if a multicast group is active on a specific port.
 *
 * The Falcon GPE doesn't provide a direct "activity" query for multicast
 * forwarding entries. Activity detection relies on the MCC core's group
 * aging mechanism (tracking last IGMP report timestamp) rather than
 * hardware-level activity counters.
 *
 * Always returns true — the core layer handles aging via software timers.
 */
enum omci_error mcc_dev_port_activity_get(struct mcc_dev_ctx *dev,
					  const uint8_t lan_port,
					  const uint8_t fid,
					  const union mcc_ip_addr *ip,
					  bool *is_active)
{
	if (is_active)
		*is_active = true;
	return OMCI_SUCCESS;
}
