/******************************************************************************
 * Copyright (c) 2025 8311 Contributors
 *
 * Falcon GPE device abstraction for MCC.
 * Direct ioctls replacing the PON Adapter abstraction from v8.6.3.
 *
 * STUB: Minimal working implementation. Full GPE ioctls in Phase 7 Step 2.
 ******************************************************************************/
#define OMCI_DBG_MODULE OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "mcc/omci_mcc_core.h"

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

enum omci_error mcc_dev_init(struct mcc_dev_ctx *dev,
			     int onu_fd, bool remote,
			     uint32_t *max_ports)
{
	struct ifreq ifr;
	struct sockaddr_ll sll;

	dev->onu_fd = onu_fd;
	dev->remote = remote;
	dev->exc_sock = -1;
	dev->exc_ifindex = -1;

	/* Open raw socket on "exc" exception interface */
	dev->exc_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (dev->exc_sock < 0) {
		dbg_err("MCC dev: failed to open raw socket: %s",
			strerror(errno));
		return OMCI_ERROR;
	}

	/* Get "exc" interface index */
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, "exc", IFNAMSIZ - 1);
	if (ioctl(dev->exc_sock, SIOCGIFINDEX, &ifr) < 0) {
		dbg_err("MCC dev: \"exc\" interface not found: %s",
			strerror(errno));
		close(dev->exc_sock);
		dev->exc_sock = -1;
		return OMCI_ERROR;
	}
	dev->exc_ifindex = ifr.ifr_ifindex;

	/* Bind to "exc" interface */
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_ALL);
	sll.sll_ifindex = dev->exc_ifindex;
	if (bind(dev->exc_sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		dbg_err("MCC dev: bind to \"exc\" failed: %s",
			strerror(errno));
		close(dev->exc_sock);
		dev->exc_sock = -1;
		return OMCI_ERROR;
	}

	/* Set promiscuous mode */
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, "exc", IFNAMSIZ - 1);
	if (ioctl(dev->exc_sock, SIOCGIFFLAGS, &ifr) == 0) {
		ifr.ifr_flags |= IFF_PROMISC;
		ioctl(dev->exc_sock, SIOCSIFFLAGS, &ifr);
	}

	/* G-010S-P has 4 UNI ports (only 1 physical, but GPE supports 4) */
	if (max_ports)
		*max_ports = 4;

	dbg_prn("MCC dev: init ok, exc_sock=%d, exc_ifindex=%d",
		dev->exc_sock, dev->exc_ifindex);

	return OMCI_SUCCESS;
}

void mcc_dev_shutdown(struct mcc_dev_ctx *dev)
{
	if (dev->exc_sock >= 0) {
		close(dev->exc_sock);
		dev->exc_sock = -1;
	}
}

enum omci_error mcc_dev_pkt_receive(struct mcc_dev_ctx *dev,
				    uint8_t *msg, uint16_t *len,
				    struct mcc_pkt_ll_info *info)
{
	ssize_t n;

	if (dev->exc_sock < 0)
		return OMCI_ERROR;

	n = recv(dev->exc_sock, msg, *len, 0);
	if (n < 0) {
		if (errno == EINTR || errno == EAGAIN)
			return OMCI_ERROR;
		return OMCI_ERROR;
	}

	*len = (uint16_t)n;

	/* Extract VLAN info and port index from packet.
	   Full implementation in Phase 7 Step 2.
	   For now: parse Ethernet header for outer VLAN tag. */
	if (info) {
		memset(info, 0, sizeof(*info));
		info->cvid = MCC_VLAN_UNTAGGED;
		info->svid = MCC_VLAN_UNTAGGED;
		info->port_idx = 0;
		info->dir_us = true;
		info->offset_iph = 14; /* default: Ethernet header only */

		/* Check for 802.1Q tag */
		if (n >= 18) {
			uint16_t ethertype = (msg[12] << 8) | msg[13];
			if (ethertype == 0x8100 || ethertype == 0x88A8 ||
			    ethertype == 0x9100) {
				info->cvid = ((msg[14] & 0x0F) << 8) | msg[15];
				info->offset_iph = 18;
				/* Check for double tag */
				if (n >= 22) {
					uint16_t inner_et =
						(msg[16] << 8) | msg[17];
					if (inner_et == 0x8100) {
						info->svid = info->cvid;
						info->cvid =
							((msg[18] & 0x0F) << 8)
							| msg[19];
						info->offset_iph = 22;
					}
				}
			}
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

enum omci_error mcc_dev_fid_get(struct mcc_dev_ctx *dev,
				const uint16_t o_vid,
				uint8_t *fid)
{
	/* TODO: Phase 7 Step 2 — FIO_GPE_VLAN_FID_GET ioctl */
	if (fid)
		*fid = 0;
	return OMCI_SUCCESS;
}

enum omci_error mcc_dev_vlan_unaware_mode_enable(struct mcc_dev_ctx *dev,
						 const bool enable)
{
	/* TODO: Phase 7 Step 2 — FIO_GPE_CONSTANTS_SET ioctl */
	return OMCI_SUCCESS;
}

enum omci_error mcc_dev_fwd_update(struct mcc_dev_ctx *dev,
				   const uint8_t fid,
				   const bool include_enable,
				   const uint16_t bridge_id,
				   const uint8_t port_map,
				   const union mcc_ip_addr *da,
				   struct mcc_list *fwd_slist)
{
	/* TODO: Phase 7 Step 2 — FIO_GPE_SHORT_FWD_IPV4_MC_PORT_MODIFY */
	return OMCI_SUCCESS;
}

enum omci_error mcc_dev_port_add(struct mcc_dev_ctx *dev,
				 const enum mcc_dir dir,
				 const uint8_t lan_port,
				 const uint8_t fid,
				 const union mcc_ip_addr *ip)
{
	/* TODO: Phase 7 Step 2 — FIO_GPE_SHORT_FWD_IPV4_MC_PORT_ADD */
	return OMCI_SUCCESS;
}

enum omci_error mcc_dev_port_remove(struct mcc_dev_ctx *dev,
				    const uint8_t lan_port,
				    const uint8_t fid,
				    const union mcc_ip_addr *ip)
{
	/* TODO: Phase 7 Step 2 — FIO_GPE_SHORT_FWD_IPV4_MC_PORT_DELETE */
	return OMCI_SUCCESS;
}

enum omci_error mcc_dev_port_activity_get(struct mcc_dev_ctx *dev,
					  const uint8_t lan_port,
					  const uint8_t fid,
					  const union mcc_ip_addr *ip,
					  bool *is_active)
{
	/* TODO: Phase 7 Step 2 — activity detection via GPE table query */
	if (is_active)
		*is_active = true; /* Assume active until proven otherwise */
	return OMCI_SUCCESS;
}
