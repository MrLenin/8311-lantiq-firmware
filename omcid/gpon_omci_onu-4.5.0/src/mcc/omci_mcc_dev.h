/******************************************************************************
 * Copyright (c) 2025 8311 Contributors
 *
 * Falcon GPE device abstraction for MCC.
 * Replaces the PON Adapter (pa_omci_mcc_ops) abstraction from v8.6.3 with
 * direct Falcon GPE ioctls via dev_ctl() on the shared /dev/onu0 fd.
 ******************************************************************************/
#ifndef _omci_mcc_dev_h
#define _omci_mcc_dev_h

__BEGIN_DECLS

/** Multicast IP address — unified IPv4/IPv6 container.
    IPv4: stored in ipv4[0..3], ipv6 unused.
    IPv6: stored in ipv6[0..15], ipv4 unused.
    Replaces pa_mcc_ip_addr from PON Adapter. */
union mcc_ip_addr {
	/** IPv4 Address */
	uint8_t ipv4[4];
	/** IPv6 Address */
	uint8_t ipv6[16];
};

/** Direction definition (replaces pa_mcc_dir) */
enum mcc_dir {
	/** Downstream */
	MCC_DIR_DS = 0,
	/** Upstream */
	MCC_DIR_US = 1
};

/** Packet information from lower layer (replaces pa_mcc_pkt_info).
    Filled by mcc_dev_pkt_receive() from the Falcon exception interface. */
struct mcc_pkt_ll_info {
	/** Outer VLAN ID of the packet (prior to VLAN handling) */
	uint16_t cvid;
	/** Outer VLAN ID of the packet (after VLAN handling) */
	uint16_t svid;
	/** LAN port index, only for upstream packets */
	uint8_t port_idx;
	/** Flag for the direction of this packet */
	bool dir_us;
	/** Offset from buffer start to IP header */
	uint8_t offset_iph;
};

/** Multicast Source Filter Definition (replaces pa_mcc_src_filter) */
struct mcc_src_filter {
	/** LAN Port map */
	uint32_t port_map;
	/** Multicast Source IP address */
	union mcc_ip_addr sa;
};

/** Special value 4096 to mark untagged packets */
#define MCC_VLAN_UNTAGGED	4096

/** Special VID=4097 specifies VLAN unaware forwarding */
#define MCC_VLAN_UNAWARE_SVID	4097

struct mcc_ctx;
struct mcc_list;

/** Falcon GPE device context for MCC.
    Replaces pa_omci_mcc_ops + ll_ctx from PON Adapter. */
struct mcc_dev_ctx {
	/** /dev/onu0 file descriptor (shared from omci_api_ctx) */
	int onu_fd;
	/** Remote flag for dev_ctl() */
	bool remote;
	/** Raw socket on "exc" interface for IGMP/MLD packets */
	int exc_sock;
	/** "exc" interface index */
	int exc_ifindex;
	/** VLAN-unaware mode flag (use default FID for all multicast) */
	bool vlan_unaware;
};

/* Device layer functions — implemented in omci_mcc_dev.c */

enum omci_error mcc_dev_init(struct mcc_dev_ctx *dev,
			     int onu_fd, bool remote,
			     uint32_t *max_ports);

void mcc_dev_shutdown(struct mcc_dev_ctx *dev);

enum omci_error mcc_dev_pkt_receive(struct mcc_dev_ctx *dev,
				    uint8_t *msg, uint16_t *len,
				    struct mcc_pkt_ll_info *info);

void mcc_dev_pkt_receive_cancel(struct mcc_dev_ctx *dev);

enum omci_error mcc_dev_pkt_send(struct mcc_dev_ctx *dev,
				 const uint8_t *msg, const uint16_t len,
				 const struct mcc_pkt_ll_info *info);

enum omci_error mcc_dev_fid_get(struct mcc_dev_ctx *dev,
				const uint16_t o_vid,
				uint8_t *fid);

enum omci_error mcc_dev_vlan_unaware_mode_enable(struct mcc_dev_ctx *dev,
						 const bool enable);

enum omci_error mcc_dev_fwd_update(struct mcc_dev_ctx *dev,
				   const uint8_t fid,
				   const bool include_enable,
				   const uint16_t bridge_id,
				   const uint8_t port_map,
				   const union mcc_ip_addr *da,
				   struct mcc_list *fwd_slist);

enum omci_error mcc_dev_port_add(struct mcc_dev_ctx *dev,
				 const enum mcc_dir dir,
				 const uint8_t lan_port,
				 const uint8_t fid,
				 const union mcc_ip_addr *ip);

enum omci_error mcc_dev_port_remove(struct mcc_dev_ctx *dev,
				    const uint8_t lan_port,
				    const uint8_t fid,
				    const union mcc_ip_addr *ip);

enum omci_error mcc_dev_port_activity_get(struct mcc_dev_ctx *dev,
					  const uint8_t lan_port,
					  const uint8_t fid,
					  const union mcc_ip_addr *ip,
					  bool *is_active);

__END_DECLS

#endif
