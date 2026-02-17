/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_onu_types.h
   This is a common header file, that provides globally used structure
   definitions.
*/
#ifndef _drv_onu_types_h
#define _drv_onu_types_h

/** \addtogroup ONU_MAPI_REFERENCE
   @{
*/

/** enable / disable */
struct onu_enable {
	/** enable / disable */
	uint32_t enable;
};

/** Data direction
    Downstream: ANI to UNI
    Upstream: UNI to ANI
*/
enum gpe_direction {
	/** Upstream only */
	GPE_DIRECTION_UPSTREAM = 1,
	/** Downstream only */
	GPE_DIRECTION_DOWNSTREAM = 2,
	/** Upstream and downstream */
	GPE_DIRECTION_BIDIRECTIONAL = 3
};

/** Packet Data Unit (PDU) type
*/
enum gpe_pdu_type {
	/** Ethernet-encapsulated payload */
	GPE_PDU_TYPE_ETH = 0,
	/** GEM-encapsulated IP payload */
	GPE_PDU_TYPE_IP = 1,
	/** GEM-encapsulated MPLS */
	GPE_PDU_TYPE_MPLS = 2,
	/** GEM-encapsulated OMCI */
	GPE_PDU_TYPE_OMCI = 3,
	/** Command from SW to FW */
	GPE_PDU_TYPE_CMD = 4,
	/** Reserved code point */
	GPE_PDU_TYPE_RES5 = 5,
	/** Reserved code point */
	GPE_PDU_TYPE_RES6 = 6,
	/** Reserved code point */
	GPE_PDU_TYPE_RES7 = 7
};

/** Packet Data Unit (PDU) type
*/
enum gpe_command_type {
	/** Dummy command */
	GPE_SCE_CMD_DUMMY = 0,
	/** Aging process trigger */
	GPE_SCE_CMD_AGING = 0x0A
};

/** UNI port ID*/
struct uni_port_id {
	/** UNI port ID (LAN port ID), lower 2 bit are valid */
	uint32_t uni_port_id;
};

/** GEM port ID */
struct gem_port_id {
	/** GEM Port-ID, lower 12 bit are valid \ref ONU_GPE_MAX_GEM_PORT_ID */
	uint32_t val;
};

/** GEM port index */
struct gem_port_index {
	/** GEM Port index value \ref ONU_GPE_MAX_GPIX */
	uint32_t val;
};

/** Allocation ID */
struct alloc_id {
	/** 12-bit Allocation ID
	    The lower 12 bit (11:0) are used, the upper 4 bit (15:12) shall be
	    set to zero.*/
	uint32_t alloc_id;
};

/** T-CONT index */
struct tcont_index {
	/** T-CONT index, valid from 0 to the number of T-CONTs
	    (ONU_GPE_MAX_TCONT) minus 1. This is equal to the Managed Entity ID
	    of the related T-CONT Managed Entity.*/
	uint32_t tcont_idx;
};

/** PDU information */
struct onu_pdu_info {
	/** PDU type*/
	enum gpe_pdu_type pdu_type;
	/** PDU length in bytes */
	uint32_t len;
	/** PDU header length in bytes*/
	uint32_t hdr_len;
	/** PDU body length in bytes*/
	uint32_t bdy_len;
	/** PDU body offset in bytes within a segment*/
	uint32_t bdy_offset;
	/** PDU body offset in segments*/
	uint32_t seg_offset;
	/** Logical segment address - head */
	uint32_t hlsa;
	/** Logical segment address - tail */
	uint32_t tlsa;
	/** Number of segments */
	uint32_t segments;
};

/** Exception Packet Header */
union u_onu_exception_pkt_hdr {
	struct {
		/** Egress queue index.
		    This value holds the index value of the egress queue to
		    which the packet would have been sent, if no exception would
		    have happened.
		    The software can use this to insert it into this queue after
		    packet processing. This value shall be ignored, if the
		    packet is the result of an ingress exception.*/
		uint8_t	egress_qid;
		/** Ingress port and VLAN information.
		    This byte is composed of the ingress LAN port index (7:6)
		    and the FID (5:0), that has been derived from the incoming
		    VLAN tags. The data format is the same as used to configure
		    the ONU_GPE_LAN_EXCEPTION_TABLE. This value is only
		    available in upstream direction and shall be ignored, if the
		    packet results from an WAN ingress or LAN egress exception.
		    */
		uint8_t ingress_info;
		/** GEM Port Index.
		    This byte is the GEM port Index (gpix) of the incoming data
		    packet, if this results from a WAN ingress or LAN egress
		    exception. This byte is the GEM port Index (gpix) of the
		    outgoing data packet, if this results from a WAN egress
		    exception. This value shall be ignored, if the packet
		    results from a LAN ingress exception.*/
		uint8_t gpix;
		/** Exception Control.
		    - Bit (7:6): This indicates the exception source.
			0 = WAN egress
			1 = WAN ingress
			2 = LAN egress
			3 = LAN ingress
		    - Bit (4:0): Exception index as defined by
			       ONU_GPE_EXCEPTION_OFFSET_<...>. This identifies
			       the reason for the exception.
		    - Bit (5): Indicates, if the reserved bytes are used (1) or
			     shall be ignored (0).*/
		uint8_t ctrl;
		/** Received outer VLAN ID MSB (to be ignored by software
		    if untagged). */
		uint8_t o_vlan_msb;
		/** Received outer VLAN ID LSB (to be ignored by software
		    if untagged). */
		uint8_t o_vlan_lsb;
		/** Reserved.
		    These bytes are for future use and shall be ignored by the
		    software.*/
		/** Unused, to be ignored by software. */
		uint8_t unused;
		/** Ethertype offset in bytes
		    Pointer in the exception data set to first non-VLAN
		    Ethertype (typically IP-Ethertype, +2 will be the start of
		    the IP packet header). */
		uint8_t ethtype_offset;
	} byte;
	/** Exception header structure */
	struct {
		/** Egress QID*/
		uint32_t egress_qid : 8;
		/** LAN port index*/
		uint32_t lan_port_idx : 2;
		/** FID*/
		uint32_t fid : 6;
		/** GEM port index*/
		uint32_t gpix : 8;
		/** Exception side, 0 - WAN, 1 - LAN */
		uint32_t ex_side : 1;
		/** Exception direction, 0 - egress, 1 - ingress */
		uint32_t ex_dir : 1;
		/** Indicates, if the reserved bytes are used (1) or shall be
		    ignored (0)*/
		uint32_t ext_bytes : 1;
		/** Exception index*/
		uint32_t ex_idx : 5;
		/** Tagged frame indication.
		    0x1 - tagged
		    0x0 - untagged */
		uint32_t tagged : 1;
		/** Unused 1. */
		uint32_t unused1 : 3;
		/** Received outer VLAN ID MSB (to be ignored by software
		    if untagged). */
		uint32_t o_vlan_msb : 4;
		/** Received outer VLAN ID LSB (to be ignored by software
		    if untagged). */
		uint32_t o_vlan_lsb : 8;
		/** Unused 0. */
		uint32_t unused0 : 8;
		/** Ethertype offset in bytes
		    Pointer in the exception data set to first non-VLAN
		    Ethertype (typically IP-Ethertype, +2 will be the start of
		    the IP packet header). */
		uint32_t ethtype_offset : 8;
	} ext;
	struct {
		/** Main part of Raw header. */
		uint8_t m[4];
		/** Extended part of Raw header. */
		uint8_t e[4];
	} raw;
};

/** LAN port related performance counters. */
struct sce_lan_counter {
	/** Received broadcast frames/packets */
	uint64_t rx_bc_frames;
	/** Received multicast frames/packets */
	uint64_t rx_mc_frames;
	/** Received unicast frames/packets */
	uint64_t rx_uc_frames;
	/** Discarded non-PPPoE frames/packets */
	uint64_t rx_non_pppoe_frames;
};

/** LAN port related receive counters.
*/
struct ictrll_counter {
	/** Received layer-2 frames/packets */
	uint64_t rx_frames;
	/** Received layer-2 bytes */
	uint64_t rx_bytes;
	/** Received layer-2 undersized frames (dropped frames/packets) */
	uint64_t rx_undersized_frames;
	/** Received layer-2 oversized frames (dropped frames/packets) */
	uint64_t rx_oversized_frames;
	/** Received layer-2 frames/packets, size 64 byte */
	uint64_t rx64;
	/** Received layer-2 frames/packets, size 65-127 byte */
	uint64_t rx65;
	/** Received layer-2 frames/packets, size 128-255 byte */
	uint64_t rx128;
	/** Received layer-2 frames/packets, size 256-511 byte */
	uint64_t rx256;
	/** Received layer-2 frames/packets, size 512-1023 byte */
	uint64_t rx512;
	/** Received layer-2 frames/packets, size 1024-1518 byte */
	uint64_t rx1024;
	/** Received layer-2 frames/packets, size 1519-maximum size byte */
	uint64_t rx1519;
	/** Ingress buffer overflow events */
	uint64_t buffer_overflow;
	/** DMA error */
	uint64_t dma_write_error;
	/** MAC error */
	uint64_t mac_error;
};

/** LAN port related transmit counters.
*/
struct octrll_counter {
	/** Transmitted layer-2 frames/packets */
	uint64_t tx_frames;
	/** Transmitted layer-2 bytes */
	uint64_t tx_bytes;
	/** Transmitted layer-2 frames/packets, size 64 byte */
	uint64_t tx64;
	/** Transmitted layer-2 frames/packets, size 65-127 byte */
	uint64_t tx65;
	/** Transmitted layer-2 frames/packets, size 128-255 byte */
	uint64_t tx128;
	/** Transmitted layer-2 frames/packets, size 256-511 byte */
	uint64_t tx256;
	/** Transmitted layer-2 frames/packets, size 512-1023 byte */
	uint64_t tx512;
	/** Transmitted layer-2 frames/packets, size 1024-1518 byte */
	uint64_t tx1024;
	/** Transmitted layer-2 frames/packets, size 1519-maximum size byte */
	uint64_t tx1519;
};

/**
   Ethernet MAC related counters.

   \remark This is a list of the counters that are mentioned in
	ITU-T G.984.4 and not covered by ICTRLL/OCTRLL counters.
	Not all of these counters are supported by hardware,
	but all Managed Entity parameters can be equipped with data.
	Unsupported counters, however, deliver a constant value of 0.
*/
struct mac_counter {
	/** FCS error counter */
	uint64_t rx_fcs_err;
	/** Alignment error counter */
	uint64_t algn_err;
	/** Received fragment counter */
	uint64_t rx_frag;
	/** Receive buffer overflows counter */
	uint64_t rx_buff_overflow_events;
	/** Transmitted fragment counter */
	uint64_t tx_frag;
	/** Transmitted jabber (oversized) frame counter */
	uint64_t tx_jabber_frames;
	/** Transmit drop event counter */
	uint64_t tx_drop_events;
	/** Transmit buffer overflows counter */
	uint64_t tx_buff_overflow_events;
	/** Internal MAC transmit error counter */
	uint64_t tx_mac_err;
	/** Delay exceeded, dropped frames due to excessive pause time */
	uint64_t delay_exceeded;
	/** Excessive collision counter */
	uint64_t exc_col;
	/** Late collision counter */
	uint64_t late_col;
	/** Single collision frame counter */
	uint64_t sgl_col;
	/** Multiple collisions frame counter */
	uint64_t mul_col;
	/** Deferred transmission counter */
	uint64_t def_trans;
	/** Carrier sense error counter */
	uint64_t carrier_sense_err;
	/** SQE test message counter */
	uint64_t sqe_test;
};

/** UNI port-related counters. Used by \ref lan_counters.
   There are three hardware modules involved in performance counting. Each of
   these modules delivers a set of data in a separate data structure.
*/
struct lan_cnt_val {
	/** Receive/ingress direction (upstream) counters. */
	struct ictrll_counter rx;
	/** SCE LAN counters. */
	struct sce_lan_counter sce;
	/** Transmit/egress direction (downstream) counters. */
	struct octrll_counter tx;
	/** Transmit and receive Ethernet MAC counters. */
	struct mac_counter mac;
	/** Padding: v7.5.1 has 2 additional counters (368 bytes total, was 352). */
	uint64_t _v751_reserved[2];
};

/** Ethernet interface operation modes
*/
enum lan_mode_interface {
	/** Inactive */
	LAN_MODE_OFF = 0,
	/** 10/100/1000BASE-T mode (GPHY mode) */
	LAN_MODE_GPHY = 1,
	/** 10/100BASE-T mode (EPHY mode) */
	LAN_MODE_EPHY = 2,
	/** SGMII normal speed mode (1.250 Gbit/s) */
	LAN_MODE_SGMII_SLOW = 3,
	/** SGMII fast speed mode (3.125 Gbit/s) */
	LAN_MODE_SGMII_FAST = 4,
	/** RGMII MAC mode (DTE) */
	LAN_MODE_RGMII_MAC = 5,
	/** RMII MAC mode (DTE) */
	LAN_MODE_RMII_MAC = 6,
	/** RMII PHY mode (DCE) */
	LAN_MODE_RMII_PHY = 7,
	/** GMII MAC mode (DTE) */
	LAN_MODE_GMII_MAC = 8,
	/** GMII PHY mode (DCE) */
	LAN_MODE_GMII_PHY = 9,
	/** MII MAC mode (DTE) */
	LAN_MODE_MII_MAC = 10,
	/** MII PHY mode (DCE) */
	LAN_MODE_MII_PHY = 11,
	/** Turbo MII MAC mode (double speed MII MAC mode, DTE) */
	LAN_MODE_TMII_MAC = 12,
	/** Turbo MII PHY mode (double speed MII PHY mode, DCE) */
	LAN_MODE_TMII_PHY = 13,
	/** TBI MAC mode (DTE) */
	LAN_MODE_TBI_MAC = 14,
	/** TBI PHY mode (DCE) */
	LAN_MODE_TBI_PHY = 15
};

/** Ethernet PHY operating modes
*/
enum lan_phy_status {
	/** Inactive */
	LAN_PHY_STATUS_OFF = 0,
	/** 10/100/1000BASE-T link down */
	LAN_PHY_STATUS_DOWN = 1,
	/** 1000BASE-T link up */
	LAN_PHY_STATUS_10_UP = 2,
	/** 100BASE-T link up */
	LAN_PHY_STATUS_100_UP = 3,
	/** 10BASE-T link up */
	LAN_PHY_STATUS_1000_UP = 4,
	/** No PHY connected */
	LAN_PHY_STATUS_NONE = 5,
	/** Autonegotiation in progress */
	LAN_PHY_STATUS_UNKNOWN = 255
};

/** LAN interface speed modes
*/
enum lan_mode_speed {
	/** 10/100/1000BASE-T automatic speed negotiation */
	LAN_MODE_SPEED_AUTO = 0,
	/** 10 Mbit/s fixed speed selection */
	LAN_MODE_SPEED_10 = 1,
	/** 100 Mbit/s fixed speed selection */
	LAN_MODE_SPEED_100 = 2,
	/** 200 Mbit/s fixed speed selection */
	LAN_MODE_SPEED_200 = 3,
	/** 1000 Mbit/s fixed speed selection */
	LAN_MODE_SPEED_1000 = 4,
	/** 2500 Mbit/s fixed speed selection */
	LAN_MODE_SPEED_2500 = 5
};

/** Ethernet PHY duplex modes
*/
enum lan_mode_duplex {
	/** Automatic duplex mode negotiation */
	LAN_PHY_MODE_DUPLEX_AUTO = 0,
	/** Fixed full duplex mode selection */
	LAN_PHY_MODE_DUPLEX_FULL = 1,
	/** Fixed half duplex mode selection */
	LAN_PHY_MODE_DUPLEX_HALF = 2
};

/** Ethernet flow control modes
*/
enum lan_mode_flow_control {
	/** Automatic flow control negotiation by the connected PHY */
	LAN_FLOW_CONTROL_MODE_AUTO = 0,
	/** Flow control in receive direction only */
	LAN_FLOW_CONTROL_MODE_RX = 1,
	/** Flow control in transmit direction only */
	LAN_FLOW_CONTROL_MODE_TX = 2,
	/** Flow control in receive and transmit direction */
	LAN_FLOW_CONTROL_MODE_RXTX = 3,
	/** Flow control is disabled */
	LAN_FLOW_CONTROL_MODE_NONE = 4
};

/** LAN interface multiplex modes
*/
enum lan_interface_mux_mode {
	/** Undefined mode, needs to be configured via FIO_LAN_CFG_SET */
	LAN_MUX_UNDEFINED = 0,
	/** Up to 4 x internal FE PHY */
	LAN_MUX_FEPHY4 = 1,
	/** Up to 2 x RGMII/RMII, up to 2 x internal GPHY */
	LAN_MUX_GPHY2_RGMII2 = 2,
	/** 1 x RGMII/RMII, 1 x SGMII, up to 2 x internal GPHY */
	LAN_MUX_GPHY2_RGMII_SGMII = 3,
	/** 1 x GMII, 1 x SGMII, up to 2 x internal GPHY */
	LAN_MUX_GPHY2_GMII_SGMII = 4,
	/** Up to 2 x RGMII/RMII, 1 x SGMII, 1 x internal GPHY */
	LAN_MUX_GPHY_RGMII2_SGMII = 5,
	/** Up to 2 x RGMII/RMII, 1 x SGMII */
	LAN_MUX_RGMII2_SGMII = 6,
	/** Single RGMII only */
	LAN_MUX_RGMII1 = 7,
	/** 1 x MII, no other interfaces
	    \remarks This is used for the FPGA only */
	LAN_MUX_MII = 99
};

/** LAN physical layer link status.
*/
struct lan_link_status {
	/** Link status UP/DOWN*/
	uint32_t up;
	/** Link duplex mode*/
	enum lan_mode_duplex duplex;
	/** Link speed*/
	enum lan_mode_speed speed;

};

/** MDIO interface selection
*/
enum mdio_mode {
	/** Internal MDIO bus */
	MDIO_INTERNAL = 0,
	/** External MDIO bus */
	MDIO_EXTERNAL = 1
};

/** MDIO speed modes
*/
enum mdio_mode_speed {
   /** Undefined speed setting */
	MDIO_MODE_SPEED_UNDEFINED = -1,
	/** 2.44 Mbit/s */
	MDIO_MODE_SPEED_2M5 = 0,
	/** 4.88 Mbit/s */
	MDIO_MODE_SPEED_5M = 1,
	/** 9.77 Mbit/s */
	MDIO_MODE_SPEED_10M = 2,
	/** 19.53 Mbit/s */
	MDIO_MODE_SPEED_20M = 3
};

/** SGMII autonegotiation modes.
    v7.5.1 added modes 2 (SGMII clause 37) and 3 (SERDES).
*/
enum sgmii_autoneg_mode {
	/** SGMII MAC autonegotiation */
	SGMII_MAC_ANEG = 0,
	/** SGMII PHY autonegotiation */
	SGMII_PHY_ANEG = 1,
	/** SGMII clause 37 autonegotiation (eim_sgmii_autonegotiation_setup) */
	SGMII_CLAUSE37_ANEG = 2,
	/** SERDES autonegotiation (eim_serdes_autonegotiation_setup) */
	SGMII_SERDES_ANEG = 3
};

/** Bridge-related counter(s).
*/
struct gpe_cnt_bridge_val {
	/** Bridge learning entry discard count.*/
	uint64_t learning_discard;
};

/** Structure to retrieve Bridge Port Counters provided by the SCE firmware.
*/
struct gpe_cnt_bridge_port_val {
	/** Bridge port learning entry discard count.*/
	uint64_t learning_discard;
	/** Ingress Bridge port good count.*/
	uint64_t ibp_good;
	/** Ingress Bridge port discard count.*/
	uint64_t ibp_discard;
	/** Egress Bridge port good count.*/
	uint64_t ebp_good;
	/** Egress Bridge port discard count.*/
	uint64_t ebp_discard;
};

/** EIM-related counter.
*/
struct gpe_cnt_eim_val {
	uint64_t dummy;
};

/** ICTRLG-related counter(s) per GEM port
*/
struct gpe_cnt_ictrlg_gem_val {
	/** Received GEM frames/packets */
	uint64_t rx_frames;
	/** Received GEM payload bytes */
	uint64_t rx_bytes;
};

/** global ICTRLG-related counter(s).
*/
struct gpe_cnt_ictrlg_val {
	/** Oversized frames/packets.*/
	uint64_t rx_oversized_frames;
	/** DMA error */
	uint64_t dma_write_error;
	/** Dropped bad OMCI frames/packets.*/
	uint64_t omci_drop;
	/** Ethernet PDUs where the FCS check has failed.*/
	uint64_t fcserror;
	/** This counter is metering the number of reassembly errors.*/
	uint64_t reass_error;
	/** This counter is metering the number of Ethernet frames which are
	    smaller than 64 bytes.*/
	uint64_t undersize_error;
	/** Non-OMCI Packet Discard Counter.*/
	uint64_t pdc;
	/** This counter is metering the total number of received PDUs.*/
	uint64_t rx_gem_frames_total;
	/** All dropped frames/packets, due to FCS errors, reassembly errors,
	    undersize error, oversize error, or invalid GEM header; does not
	    include the dropped OMCI frames/packets.*/
	uint64_t drop;
};

/** OCTRLG-related counter(s) per GEM port.
*/
struct gpe_cnt_octrlg_gem_val {
	/** Transmitted GEM frames (not including GEM Idle frames).*/
	uint64_t tx_frames;
	/** Transmitted GEM payload bytes.*/
	uint64_t tx_bytes;
};

/** global OCTRLG-related counter(s).
*/
struct gpe_cnt_octrlg_val {
	/** Total number of transmitted GEM frames (not including GEM Idle frames).*/
	uint64_t tx_gem_frames_total;
	/** Total number of transmitted GEM payload bytes.*/
	uint64_t tx_gem_bytes_total;
	/** Total number of transmitted GEM Idle Frames Counter.*/
	uint64_t tx_gem_idle_frames_total;
	/** Total number of transmitted T-CONT Counter.*/
	uint64_t tx_tcont_total;
	/** Total Transmitted PDU Bytes Counter.
	    This counter is metering the transmitted PDU Bytes for all GEM Port
	    Indexes. Only GEM payload is counted. GEM Idles are not counted. */
	uint64_t tx_gem_pdu_bytes_total;
};

/** Structure to track GPE schedulers use.*/
struct gpe_scheduler_track {
	/** Usage indication.
	- true: is in use.
	- false: is not in use.*/
	uint32_t in_use;
	/** Scheduler ID.*/
	uint32_t id;
	/** Scheduler leaf mask.*/
	uint8_t leaf_mask;
	/** Scheduler policy.*/
	uint8_t policy;
	/** Scheduler level.*/
	uint8_t level;
};

/** Structure used to trigger the MAC table aging process.
*/
struct gpe_aging_trigger {
	/** Allocated LSA for the aging trigger command.*/
	uint16_t lsa;
	/** Trigger time interval, ms.*/
	uint32_t ttrig;
};

/** Firmware version information */
struct pe_fw_ver {
	/** Major version number.*/
	uint8_t major;
	/** Minor version number.*/
	uint8_t minor;
	/** Patch version.*/
	uint8_t patch;
	/** Internal version.*/
	uint8_t internal;
};

/** Firmware feature header entry */
struct pe_fw_fhdr_entry {
	/** Contains a unique byte value for the "extended table index". The
	    lower 6 bits of this value represent the "table index" as it is used
	    in host interface commands = local PE table index.*/
	uint8_t tbl_idx;
	/** 6 bit mask, where bits 0,..,5 are the allowed PE processor mask.
	    For example value 0x20 means only the PE5 processors can perform
	    read/write access to this local table.*/
	uint8_t pe_mask;
};


/** PE firmware file name maximum length.*/
#define ONU_PE_FIRMWARE_NAME_MAX	32

struct onu_fw {
	/** Firmware binary.*/
	uint8_t *bin;
	/** Firmware binary length [byte].*/
	uint32_t len;
	/** Firmware name.*/
	char fw_name[ONU_PE_FIRMWARE_NAME_MAX];
};

/** PE firmware information*/
struct pe_fw_info {
	/** Version information.*/
	struct pe_fw_ver ver;
	/** Firmware flags.*/
	uint32_t flags[2];
	/** Optional header.*/
	uint8_t *opt_hdr;
	/** Optional header length [bytes].*/
	uint32_t opt_hdr_len;
	/** Firmware name.*/
	char fw_name[ONU_PE_FIRMWARE_NAME_MAX];
};

/** GPHY firmware file name maximum length.*/
#define ONU_GPHY_FIRMWARE_NAME_MAX	32

/** GPHY firmware version maximum length.*/
#define ONU_GPHY_FIRMWARE_VERSION_MAX	32

/*! @} */

#endif
