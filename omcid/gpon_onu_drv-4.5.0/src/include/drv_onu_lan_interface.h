/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_onu_lan_interface.h
   This is the GPON LAN header file, used for the FALCON GPON modem driver.
*/
#ifndef _drv_onu_lan_h_
#define _drv_onu_lan_h_

#include "drv_onu_std_defs.h"
#include "drv_onu_types.h"

#ifndef __PACKED__
#  if defined (__GNUC__) || defined (__GNUG__)
     /* GNU C or C++ compiler */
#    define __PACKED__ __attribute__ ((packed))
#  else
     /* Byte alignment adjustment */
#    pragma pack(1)
#    if !defined (_PACKED_)
#      define __PACKED__	/* nothing */
#    endif
#  endif
#  define __PACKED_DEFINED__
#endif

EXTERN_C_BEGIN
/** \addtogroup ONU_MAPI_REFERENCE
   @{
*/
/** \defgroup ONU_LAN Ethernet Interface

    This chapter describes the software interface to access and configure the
    GPON Ethernet Interface Module (LAN).
   @{
*/

/* Constant Definitions - LAN
   ================================== */
/* Counter mask definitions.
   Each LAN counter is identified by a bit position in a 64-bit vector. */
/** Reset mask for the Received layer-2 frames/packets counter */
#define ONU_LAN_CNT_RST_MASK_RX_FRAMES			0x0000000000000001ULL
/** Reset mask for the Received layer-2 bytes counter */
#define ONU_LAN_CNT_RST_MASK_RX_BYTES			0x0000000000000002ULL
/** Reset mask for the Received undersized frames counter */
#define ONU_LAN_CNT_RST_MASK_RX_UNSZ_FRAMES		0x0000000000000004ULL
/** Reset mask for the Received oversized frames counter */
#define ONU_LAN_CNT_RST_MASK_RX_OVSZ_FRAMES		0x0000000000000008ULL
/** Reset mask for the Received frames/packets, size 64 byte counter */
#define ONU_LAN_CNT_RST_MASK_RX_64_FRAMES		0x0000000000000010ULL
/** Reset mask for the Received frames/packets, size 65-127 byte counter */
#define ONU_LAN_CNT_RST_MASK_RX_65_FRAMES		0x0000000000000020ULL
/** Reset mask for the Received frames/packets, size 128-255 byte counter */
#define ONU_LAN_CNT_RST_MASK_RX_128_FRAMES		0x0000000000000040ULL
/** Reset mask for the Received frames/packets, size 256-511 byte counter */
#define ONU_LAN_CNT_RST_MASK_RX_256_FRAMES		0x0000000000000080ULL
/** Reset mask for the Received frames/packets, size 512-1023 byte counter */
#define ONU_LAN_CNT_RST_MASK_RX_512_FRAMES		0x0000000000000100ULL
/** Reset mask for the Received frames/packets, size 1024-1518 byte counter */
#define ONU_LAN_CNT_RST_MASK_RX_1024_FRAMES		0x0000000000000200ULL
/** Reset mask for the Received frames/packets, size 1519 byte counter */
#define ONU_LAN_CNT_RST_MASK_RX_1519_FRAMES		0x0000000000000400ULL
/** Reset mask for the Ingress buffer overflow events counter */
#define ONU_LAN_CNT_RST_MASK_RX_BUFF_OVERFLOW		0x0000000000000800ULL
/** Reset mask for the DMA error counter */
#define ONU_LAN_CNT_RST_MASK_RX_DMA_WR_ERR		0x0000000000001000ULL
/** Reset mask for the MAC error counter */
#define ONU_LAN_CNT_RST_MASK_RX_MAC_ERR			0x0000000000002000ULL
/** Reset mask for the Received broadcast frames/packets counter */
#define ONU_LAN_CNT_RST_MASK_RX_BC_FRAMES		0x0000000000004000ULL
/** Reset mask for the Received multicast frames/packets counter */
#define ONU_LAN_CNT_RST_MASK_RX_MC_FRAMES		0x0000000000008000ULL
/** Reset mask for the Received unicast frames/packets counter */
#define ONU_LAN_CNT_RST_MASK_RX_UC_FRAMES		0x0000000000010000ULL
/** Reset mask for the Discarded non-PPPoE frames/packets counter */
#define ONU_LAN_CNT_RST_MASK_RX_NON_PPOE_FRAMES		0x0000000000020000ULL
/** Reset mask for the Transmitted frames/packets counter */
#define ONU_LAN_CNT_RST_MASK_TX_FRAMES			0x0000000000040000ULL
/** Reset mask for the Transmitted bytes counter */
#define ONU_LAN_CNT_RST_MASK_TX_BYTES			0x0000000000080000ULL
/** Reset mask for the Transmitted frames/packets, size 64 byte counter */
#define ONU_LAN_CNT_RST_MASK_TX_64_FRAMES		0x0000000000100000ULL
/** Reset mask for the Transmitted frames/packets, size 65-127 byte counter */
#define ONU_LAN_CNT_RST_MASK_TX_65_FRAMES		0x0000000000200000ULL
/** Reset mask for the Transmitted frames/packets, size 128-255 byte counter */
#define ONU_LAN_CNT_RST_MASK_TX_128_FRAMES		0x0000000000400000ULL
/** Reset mask for the Transmitted frames/packets, size 256-511 byte counter */
#define ONU_LAN_CNT_RST_MASK_TX_256_FRAMES		0x0000000000800000ULL
/** Reset mask for the Transmitted frames/packets, size 512-1024 byte counter */
#define ONU_LAN_CNT_RST_MASK_TX_512_FRAMES		0x0000000001000000ULL
/** Reset mask for the Transmitted frames/packets, size 1024-1518 byte counter */
#define ONU_LAN_CNT_RST_MASK_TX_1024_FRAMES		0x0000000002000000ULL
/** Reset mask for the Transmitted frames/packets, size 1519 byte counter */
#define ONU_LAN_CNT_RST_MASK_TX_1519_FRAMES		0x0000000004000000ULL
/** Reset mask for the FCS error counter */
#define ONU_LAN_CNT_RST_MASK_RX_FCS_ERR			0x0000000008000000ULL
/** Reset mask for the Alignment error counter */
#define ONU_LAN_CNT_RST_MASK_ALGN_ERR			0x0000000010000000ULL
/** Reset mask for the Received fragment counter */
#define ONU_LAN_CNT_RST_MASK_RX_FRAG			0x0000000020000000ULL
/** Reset mask for the Receive buffer overflows counter,
    \todo remove multiple definition*/
#define ONU_LAN_CNT_RST_MASK_RX_BUFF_OVERFLOW1		0x0000000040000000ULL
/** Reset mask for the Transmitted fragment counter */
#define ONU_LAN_CNT_RST_MASK_TX_FRAG			0x0000000080000000ULL
/** Reset mask for the Transmitted jabber (oversized) frame counter */
#define ONU_LAN_CNT_RST_MASK_TX_JABBER_FRAMES		0x0000000100000000ULL
/** Reset mask for the Transmit drop event counter */
#define ONU_LAN_CNT_RST_MASK_TX_DROP			0x0000000200000000ULL
/** Reset mask for the Transmit buffer overflows counter */
#define ONU_LAN_CNT_RST_MASK_TX_BUFF_OVERFLOW		0x0000000400000000ULL
/** Reset mask for the MAC transmit error counter */
#define ONU_LAN_CNT_RST_MASK_TX_MAC_ERR			0x0000000800000000ULL
/** Reset mask for the Delay exceeded counter */
#define ONU_LAN_CNT_RST_MASK_DLY_EXC			0x0000001000000000ULL
/** Reset mask for the Excessive collision counter */
#define ONU_LAN_CNT_RST_MASK_EXC_COL			0x0000002000000000ULL
/** Reset mask for the Late collision counter */
#define ONU_LAN_CNT_RST_MASK_LATE_COL			0x0000004000000000ULL
/** Reset mask for the Single collision counter */
#define ONU_LAN_CNT_RST_MASK_SGL_COL			0x0000008000000000ULL
/** Reset mask for the Multiple collision counter */
#define ONU_LAN_CNT_RST_MASK_MUL_COL			0x0000010000000000ULL
/** Reset mask for the Deferred transmission counter */
#define ONU_LAN_CNT_RST_MASK_TX_DEF			0x0000020000000000ULL
/** Reset mask for the Carrier sense error counter */
#define ONU_LAN_CNT_RST_MASK_CAR_SENSE_ERR		0x0000040000000000ULL
/** Reset mask for the SQE test message counter */
#define ONU_LAN_CNT_RST_MASK_SQE_TST			0x0000080000000000ULL
/** MDIO null address*/
#define ONU_LAN_MDIO_ADDR_NULL				(-1)

/* Structure Type Definitions - LAN
   =============================== */

/** Structure to specify GPHY firmware.
    Used by \ref FIO_LAN_GPHY_FIRMWARE_DOWNLOAD.
*/
struct lan_gphy_fw {
	/** Firmware binary name.*/
	char fw_name[128];
} __PACKED__;

/** LAN global hardware configuration data.
    Used by \ref FIO_LAN_CFG_SET and \ref FIO_LAN_CFG_GET.
*/
struct lan_cfg {
	/** LAN port operation mode, select one of the supported operating
	    modes.*/
	enum lan_interface_mux_mode mux_mode;
	/** Internal GPHY/EPHY MDIO device addresses.
	    Valid from 0 to 31 (must be different!).
	    This parameter defines the MDIO addresses that shall be used to
	    identify two internal GE PHYs or four internal FE PHYs.
	    \ref ONU_LAN_MDIO_ADDR_NULL specifies no PHY address. */
	int8_t mdio_dev_addr[4];
	/** MDIO data rate.*/
	enum mdio_mode_speed mdio_data_rate;
	/** MDIO preamble mode. This setting applies for all ports.*/
	uint32_t mdio_short_preamble_en;
	/** MDIO interface enable.*/
	uint32_t mdio_en;
} __PACKED__;

/** Structure to identify LAN port.*/
struct lan_port_index {
	/** Port Selection.
	    Valid from 0 to the ONU_GPE_MAX_ETH_UNI - 1.
	    0/1 are internal PHYs, 2/3 are external.*/
	uint32_t index;
};

/** LAN per-port hardware configuration data.
    Used by \ref FIO_LAN_PORT_CFG_SET and \ref lan_port_cfg_get_u.
*/
struct lan_port_cfg {
	/** Port Selection.
	    Valid from 0 to the ONU_GPE_MAX_ETH_UNI - 1.
	    0/1 are internal PHYs, 2/3 are external.*/
	uint32_t index;
	/** Port enable.*/
	uint32_t uni_port_en;
	/** Interface mode.
	    \note If selecting SGMII mode, the speed selection
	          (LAN_MODE_SGMII_SLOW/LAN_MODE_SGMII_FAST) must fit the GPE
		  initialiation (mode in gpe_init_data)."*/
	enum lan_mode_interface mode;
	/** PHY duplex selection.*/
	enum lan_mode_duplex duplex_mode;
	/** Flow control mode.*/
	enum lan_mode_flow_control flow_control_mode;
	/** Interface speed (if no PHY is connected).*/
	enum lan_mode_speed speed_mode;
	/** Transmit Clock Delay.
	    Configure the delay of TX_CLK_D versus TX_CLK in steps of 500ps.
	    The total configured delay is TD = TXDLY * 500ps.
	    Valid range: 0..7.
	    This setting is valid only in the \ref LAN_MODE_RGMII_MAC mode
	    selected.*/
	uint8_t tx_clk_dly;
	/** Receive Clock Delay.
	    Configure the delay of RX_CLK_D versus RX_CLK in steps of 500 ps.
	    The resulting delay is TD = RXDLY * 500 ps.
	    Valid range: 0..7.
	    This setting is valid only in the \ref LAN_MODE_RGMII_MAC mode
	    selected.*/
	uint8_t rx_clk_dly;
	/** Maximum Ethernet frames length, must be less
	    than ONU_GPE_MAX_ETHERNET_FRAME_LENGTH.
	    \note
	    Please take care to modify the related pdu_size_max_eth value within
	    \ref FIO_GPE_CFG_SET accordingly.
	*/
	uint16_t max_frame_size;
	/** LPI mode enable. */
	uint32_t lpi_enable;
	/** SGMII autonegotiation selection */
	enum sgmii_autoneg_mode autoneg_mode;
} __PACKED__;

/** Union to retrieve LAN port configuration data.
    Used by \ref FIO_LAN_PORT_CFG_GET
*/
union lan_port_cfg_get_u {
	/** Specified LAN port index.*/
	struct lan_port_index in;
	/** Retrieved LAN port configuration data.*/
	struct lan_port_cfg out;
} __PACKED__;

/** LAN counter control.
    Used by \ref FIO_LAN_COUNTER_RESET, \ref lan_counters
    and \ref lan_counter_get_u.
*/
struct lan_cnt_interval {
	/** UNI port ID (LAN port ID).
	    The valid range is from 0 to ONU_GPE_MAX_ETH_UNI - 1.*/
	uint32_t index;
	/** Reset Mask.
	    This defines which of the counters shall be reset after being read.
	    If a mask bit is set, the related counter is reset.
	    See ONU_LAN_CNT_RST_MASK_<counter> for the mask bit assignment.*/
	uint64_t reset_mask;
	/** Select if the counter read access shall deliver the most recent
	    counter value or the sum of the previous 15-minute time interval.
		- true: Read the latest (current) value.
		- false: Read the previous 15-minute interval value.*/
	uint32_t curr;
} __PACKED__;

/** UNI port-related counters.
    Used by \ref lan_counter_get_u.
    There are three hardware modules involved in performance counting.
    Each of these modules delivers a set of data in a separate data structure.
*/
struct lan_counters {
	/** Specified interval to retrieve LAN counters.*/
	struct lan_cnt_interval interval;
	/** LAN counters values.*/
	struct lan_cnt_val val;
} __PACKED__;

/** Union to retrieve LAN counters.
    Used by \ref FIO_LAN_COUNTER_GET.
*/
union lan_counter_get_u {
	/** Specified LAN counters interval.*/
	struct lan_cnt_interval in;
	/** Retrieved LAN counters.*/
	struct lan_counters out;
};

/** LAN-related thresholds.
    Used by \ref FIO_LAN_COUNTER_THRESHOLD_SET and
    \ref lan_counter_threshold_get_u.
*/
struct lan_cnt_threshold {
	/** Port Selection.
	    Valid from 0 to the ONU_GPE_MAX_ETH_UNI - 1.
	    0/1 are internal PHYs, 2/3 are external.*/
	uint32_t index;
	/** Threshold values.*/
	struct lan_cnt_val threshold;
} __PACKED__;

/** Union to retrieve LAN port thresholds.
    Used by \ref FIO_LAN_COUNTER_THRESHOLD_GET.
*/
union lan_counter_threshold_get_u {
	/** Specified LAN port index.*/
	struct lan_port_index in;
	/** Retrieved LAN port thresholds.*/
	struct lan_cnt_threshold out;
};

/** MDIO interface enable.
    Used by \ref FIO_MDIO_ENABLE.
*/
struct mdio_en {
	/** Enable MDIO for internal and/or external operation.*/
	enum mdio_mode mode;
} __PACKED__;

/** MDIO interface disable.
    Used by \ref FIO_MDIO_DISABLE.
*/
struct mdio_dis {
	/** Disable MDIO for internal and/or external operation.*/
	enum mdio_mode mode;
} __PACKED__;

/** LAN per-port hardware loop configuration data.
    Used by \ref FIO_LAN_LOOP_CFG_SET and \ref lan_loop_cfg_get_u and.
*/
struct lan_loop_cfg {
	/** Port Selection.
	    Valid from 0 to the ONU_GPE_MAX_ETH_UNI - 1.
	    0/1 are internal PHYs (FE/GE), 2/3 are internal PHYs (FE).*/
	uint32_t index;
	/** Ethernet MAC egress loop.*/
	uint32_t mac_egress_loop_en;
	/** xMII ingress loop.*/
	uint32_t mii_ingress_loop_en;
	/** SGMII ingress loop.*/
	uint32_t sgmii_ingress_loop_en;
	/** PHY ingress loop.*/
	uint32_t phy_ingress_loop_en;
	/** PHY egress loop.*/
	uint32_t phy_egress_loop_en;
} __PACKED__;

/** Union to retrieve per-port LAN loop configuration data.
    Used by \ref FIO_LAN_LOOP_CFG_GET.
*/
union lan_loop_cfg_get_u {
	/** Specified LAN port index.*/
	struct lan_port_index in;
	/** Retrieved LAN loop configuration data.*/
	struct lan_loop_cfg out;
} __PACKED__;

/** LAN per-port hardware status data.
    Used by \ref lan_port_status_get_u.
*/
struct lan_port_status {
	/** Port Selection.
	    Valid from 0 to the ONU_GPE_MAX_ETH_UNI - 1.*/
	uint32_t index;
	/** Interface mode.*/
	enum lan_mode_interface mode;
	/** Port enable status.*/
	uint32_t uni_port_en;
	/** PHY status.*/
	enum lan_phy_status link_status;
	/** PHY duplex selection.*/
	enum lan_mode_duplex phy_duplex;
} __PACKED__;

/** Union to retrieve LAN port status data.
    Used by \ref FIO_LAN_PORT_STATUS_GET.
*/
union lan_port_status_get_u {
	/** Specified LAN port index.*/
	struct lan_port_index in;
	/** Retrieved LAN status data.*/
	struct lan_port_status out;
} __PACKED__;

/** Wake-on-LAN configuration data.
    Used by \ref FIO_WOL_CFG_SET and \ref wol_cfg_get_u.
*/
struct wol_cfg {
	/** WoL port selection.
	    Only GPHY ports provide this function.*/
	uint32_t index;
	/** WoL target Ethernet address.*/
	uint8_t wol_addr[6];
	/** WoL password.*/
	uint8_t wol_password[6];
	/** WoL password enable.*/
	uint32_t wol_password_en;
	/** WoL interrupt enable.*/
	uint32_t wol_interrupt_en;
} __PACKED__;

/** Union to retrieve WOL configuration data.
    Used by \ref FIO_WOL_CFG_GET.
*/
union wol_cfg_get_u {
	/** Specified LAN port index.*/
	struct lan_port_index in;
	/** Retrieved WOL configuration data.*/
	struct wol_cfg out;
};

/** Wake-on-LAN status.
    Used by \ref wol_status_get_u.
*/
struct wol_status {
	/** Port Selection.
	    Valid from 0 to the ONU_GPE_MAX_ETH_UNI - 1.*/
	uint32_t index;
	/* WoL status per port.
	    Indicates, if a WoL frame has been received since the last status
	    check.
	    Individual indication per GPHY port.
	\todo check, comment added
	*/
	/** WoL status.*/
	uint32_t wol_sts;
} __PACKED__;

/** Union to retrieve WOL status data.
    Used by \ref FIO_WOL_STATUS_GET.
*/
union wol_status_get_u {
	/** Specified LAN port index.*/
	struct lan_port_index in;
	/** Retrieved WOL status data.*/
	struct wol_status out;
};

/** MDIO Register Access.
    Used by \ref mdio_data_read_u.
    Some PHY device registers have standard bit definitions as stated in
    IEEE 802.3. */
struct mdio {
	/** Device address on the MDIO interface.*/
	uint8_t addr_dev;
	/** Register address inside the device.*/
	uint8_t addr_reg;
} __PACKED__;

/** MDIO Register Access.
    Used by \ref mdio_data_read_u.
    Some PHY device registers have standard bit definitions as stated in
    IEEE 802.3. */
struct mdio_read {
	/** Exchange data word with the device (read / write).*/
	uint16_t data;
} __PACKED__;

/** Union to retrieve MDIO data.
    Used by \ref FIO_MDIO_DATA_READ.
*/
union mdio_data_read_u {
	/** Specifies MDIO access options.*/
	struct mdio in;
	/** Retrieved MDIO data.*/
	struct mdio_read out;
};

/** MDIO Register Access.
    Used by \ref FIO_MDIO_DATA_WRITE.
    The "data" value is directly written to the device register
    Some PHY device registers have standard bit definitions as stated in
    IEEE 802.3. */
struct mdio_write {
	/** Device address on the MDIO interface.*/
	uint8_t addr_dev;
	/** Register address inside the device.*/
	uint8_t addr_reg;
	/** Exchange data word with the device (read / write).*/
	uint16_t data;
} __PACKED__;


/** MMD Register Access.
    Used by \ref mmd_data_read_u.
    Some PHY device registers have standard bit definitions as stated in
    IEEE 802.3. */
struct mmd {
	/** Device address on the MDIO interface.*/
	uint8_t addr_dev;
	/** Device address on MMD interface.*/
	uint8_t mmd_sel;
	/** Register address inside the device.*/
	uint16_t mmd_addr;
} __PACKED__;

/** MMD Register Access.
    Used by \ref mmd_data_read_u.
    Some PHY device registers have standard bit definitions as stated in
    IEEE 802.3. */
struct mmd_read {
	/** Exchange data word with the device (read / write).*/
	uint16_t data;
} __PACKED__;

/** Union to retrieve MMD data.
    Used by \ref FIO_MDIO_DATA_READ.
*/
union mmd_data_read_u {
	/** Specifies MDIO access options.*/
	struct mmd in;
	/** Retrieved MDIO data.*/
	struct mmd_read out;
};

/** MDIO Register Access.
    Used by \ref FIO_MDIO_DATA_WRITE.
    The "data" value is directly written to the device register
    Some PHY device registers have standard bit definitions as stated in
    IEEE 802.3. */
struct mmd_write {
	/** Device address on the MDIO interface.*/
	uint8_t addr_dev;
	/** Device address on MMD interface.*/
	uint8_t mmd_sel;
	/** Register address inside the device.*/
	uint16_t mmd_addr;
	/** Exchange data word with the device (read / write).*/
	uint16_t data;
} __PACKED__;


/** LAN counter reset.
    Used by \ref FIO_LAN_COUNTER_RESET.*/
struct lan_cnt_reset {
	/** Port Selection.
	    Valid from 0 to the ONU_GPE_MAX_ETH_UNI - 1.*/
	uint32_t index;
} __PACKED__;

/** LAN port capability.
    Used by \ref FIO_LAN_PORT_CAPABILITY_CFG_SET. */
struct lan_port_capability_cfg {
	/** LAN port index, starting with 0. */
	uint32_t index;
	/** Supports full duplex mode. */
	bool full_duplex;
	/** Supports half-duplex mode. */
	bool half_duplex;
	/** Supports 10 Mbit/s data rate. */
	bool mbit_10;
	/** Supports 100 Mbit/s data rate. */
	bool mbit_100;
	/** Supports 1000 Mbit/s data rate. */
	bool mbit_1000;
	/** Supports pause frame reception ant transmission for backpressure. */
	bool sym_pause;
	/** Supports asymmetric pause frame handling for backpressure. */
	bool asym_pause;
	/** Supports Energy efficient Ethernet mode.
	    \remarks This argument is currently not supported and
	    should be set to 'false'. */
	bool eee;
} __PACKED__;

/** Union to retrieve per-port LAN port capability.
    Used by \ref FIO_LAN_PORT_CAPABILITY_CFG_GET. */
union lan_port_capability_cfg_get_u {
	/** Specified LAN port index.*/
	struct lan_port_index in;
	/** Retrieved LAN port capability.*/
	struct lan_port_capability_cfg out;
} __PACKED__;

/* IOCTL Command Declaration - LAN
   =============================== */

/** magic number */
#define LAN_MAGIC 7

/**
  Initialize the Ethernet interface hardware.

  \param No parameter is used, set to 0.

  \remarks The function returns an error code in case of error.
           The error code is described in \ref onu_errorcode.

  \return Return value as follows:
  - 0: if successful
  - An error code in case of error.

*/
#define FIO_LAN_INIT _IO(LAN_MAGIC, 0x00)

/**
  Configure the Ethernet interface hardware.
  \remarks This function must be called before the port-specific configuration
	  is done (see \ref FIO_LAN_PORT_CFG_SET).

  \param lan_cfg Pointer to \ref lan_cfg.

  \remarks The function returns an error code in case of error.
           The error code is described in \ref onu_errorcode.

  \return Return value as follows:
  - 0: if successful
  - An error code in case of error.

*/
#define FIO_LAN_CFG_SET _IOW(LAN_MAGIC, 0x01, struct lan_cfg)

/**
  Read the Ethernet interface hardware configuration.

  \param lan_cfg Pointer to \ref lan_cfg.

  \remarks The function returns an error code in case of error.
           The error code is described in \ref onu_errorcode.

  \return Return value as follows:
  - 0: if successful
  - An error code in case of error.

*/
#define FIO_LAN_CFG_GET _IOR(LAN_MAGIC, 0x02, struct lan_cfg)

/**
  Configure the Ethernet per-port interface hardware.
  \remark Before this function is called, the basic configuration must be set
	  through \ref FIO_LAN_CFG_SET.

  \param lan_port_cfg Pointer to \ref lan_port_cfg.

  \remarks The function returns an error code in case of error.
           The error code is described in \ref onu_errorcode.

  \return Return value as follows:
  - 0: if successful
  - An error code in case of error.

*/
#define FIO_LAN_PORT_CFG_SET _IOW(LAN_MAGIC, 0x03, struct lan_port_cfg)

/**
  Read the Ethernet interface per-port hardware configuration.

  \param lan_port_cfg Pointer to \ref lan_port_cfg_get_u.

  \remarks The function returns an error code in case of error.
           The error code is described in \ref onu_errorcode.

  \return Return value as follows:
  - 0: if successful
  - An error code in case of error.

*/
#define FIO_LAN_PORT_CFG_GET _IOWR(LAN_MAGIC, 0x04, union lan_port_cfg_get_u)

/**
  Enable a selected LAN port.
  \remarks Before this function is called, the basic configuration must be set
	   through \ref FIO_LAN_CFG_SET.

  \param lan_port_index Pointer to \ref lan_port_index.

  \remarks The function returns an error code in case of error.
           The error code is described in \ref onu_errorcode.

  \return Return value as follows:
  - 0: if successful
  - An error code in case of error.

*/
#define FIO_LAN_PORT_ENABLE _IOW(LAN_MAGIC, 0x05, struct lan_port_index)

/**
  Disable a selected LAN port.

  \param lan_port_index Pointer to \ref lan_port_index.

  \remarks The function returns an error code in case of error.
           The error code is described in \ref onu_errorcode.

  \return Return value as follows:
  - 0: if successful
  - An error code in case of error.

*/
#define FIO_LAN_PORT_DISABLE _IOW(LAN_MAGIC, 0x06, struct lan_port_index)

/**
  Configure diagnostic loops for the Ethernet interface per LAN port.

  \param lan_loop_cfg Pointer to \ref lan_loop_cfg.

  \remarks The function returns an error code in case of error.
           The error code is described in \ref onu_errorcode.

  \return Return value as follows:
  - 0: if successful
  - An error code in case of error.

*/
#define FIO_LAN_LOOP_CFG_SET _IOW(LAN_MAGIC, 0x07, struct lan_loop_cfg)

/**
  Read back the Ethernet loop setting.

  \param lan_loop_cfg Pointer to \ref lan_loop_cfg_get_u.

  \remarks The function returns an error code in case of error.
           The error code is described in \ref onu_errorcode.

  \return Return value as follows:
  - 0: if successful
  - An error code in case of error.

*/
#define FIO_LAN_LOOP_CFG_GET _IOWR(LAN_MAGIC, 0x08, union lan_loop_cfg_get_u)

/**
  Ethernet interface per-port hardware status readout.

  \param lan_port_status Pointer to \ref lan_port_status_get_u.

  \remarks The function returns an error code in case of error.
           The error code is described in \ref onu_errorcode.

  \return Return value as follows:
  - 0: if successful
  - GPE_STATUS_NOT_AVAILABLE: if the UNI Port index is unknown

*/
#define FIO_LAN_PORT_STATUS_GET \
			_IOWR(LAN_MAGIC, 0x09, union lan_port_status_get_u)

/**
   Read the LAN counters per UNI port ID.

   For the definition of the reset mask, see "ONU_LAN_CNT_RST_MASK_<counter>"
   in "drv_onu_lan_interface.h".

   \param lan_cnt Pointer to \ref lan_counter_get_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - GPE_STATUS_COUNTER_ERR: if one of the counters suffered from an overflow
			     event
   - GPE_STATUS_NO_SUPPORT: if the UNI port ID is invalid
*/
#define FIO_LAN_COUNTER_GET _IOWR(LAN_MAGIC, 0x0A, union lan_counter_get_u)

/**
   LAN-based counter reset. Calling this function clears all counters
   that are covered by \ref lan_cnt_val.

   \param lan_cnt_interval Pointer to \ref lan_cnt_interval.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - GPE_STATUS_NO_SUPPORT: if the UNI port ID is invalid
*/
#define FIO_LAN_COUNTER_RESET _IOW(LAN_MAGIC, 0x0B, struct lan_cnt_interval)

/**
   Write the LAN counter thresholds per UNI port ID.

   \param lan_cnt_threshold Pointer to \ref lan_cnt_threshold.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - GPE_STATUS_COUNTER_ERR: if one of the counters suffered from an overflow
			     event
   - GPE_STATUS_NO_SUPPORT: if the UNI port ID is invalid
*/
#define FIO_LAN_COUNTER_THRESHOLD_SET \
			_IOW(LAN_MAGIC, 0x0C, struct lan_cnt_threshold)

/**
   Read the LAN counter thresholds per UNI port ID.

   \param lan_cnt_threshold Pointer to \ref lan_counter_threshold_get_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - GPE_STATUS_COUNTER_ERR: if one of the counters suffered from an overflow
			     event
   - GPE_STATUS_NO_SUPPORT: if the UNI port ID is invalid
*/
#define FIO_LAN_COUNTER_THRESHOLD_GET \
		_IOWR(LAN_MAGIC, 0x0D, union lan_counter_threshold_get_u)

/**
   Read the LAN counter threshold crossing alarms per UNI port ID.

   \param lan_cnt_val Pointer to \ref lan_cnt_val.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - GPE_STATUS_NO_SUPPORT: if the UNI port ID is invalid
*/
#define FIO_LAN_TCA_GET _IOWR(LAN_MAGIC, 0x0E, struct lan_cnt_val)

/**
  Configure the Wake-on-LAN function.

  \param wol_cfg Pointer to \ref wol_cfg.

  \remarks The function returns an error code in case of error.
           The error code is described in \ref onu_errorcode.

  \return Return value as follows:
  - 0: if successful
  - GPE_STATUS_NOT_AVAILABLE: if the selected port is not a GPHY port

*/
#define FIO_WOL_CFG_SET _IOW(LAN_MAGIC, 0x0F, struct wol_cfg)

/**
  Read the Wake-on-LAN configuration.

  \param wol_cfg Pointer to \ref wol_cfg_get_u.

  \remarks The function returns an error code in case of error.
           The error code is described in \ref onu_errorcode.

  \return Return value as follows:
  - 0: if successful
   - GPE_STATUS_NOT_AVAILABLE: if the selected port is not a GPHY port

*/
#define FIO_WOL_CFG_GET _IOWR(LAN_MAGIC, 0x10, union wol_cfg_get_u)

/**
  Wake-on-LAN status readout.

  \param wol_status Pointer to \ref wol_status_get_u.

  \remarks The function returns an error code in case of error.
           The error code is described in \ref onu_errorcode.

  \return Return value as follows:
  - 0: if successful
  - GPE_STATUS_NOT_AVAILABLE: if the selected port is not a GPHY port

*/
#define FIO_WOL_STATUS_GET _IOWR(LAN_MAGIC, 0x11, union wol_status_get_u)

/**
   Read data from the MDIO interface. This function allows
   to read out various information of any attached device by register and
   device addressing.
   The "data" value (\ref mdio_data_read_u) contains the read device register.
   A write operation can be performed by using \ref FIO_MDIO_DATA_WRITE.

   \param mdio_read Pointer to \ref mdio_data_read_u.

   \remarks The function returns an error code in case an error occurred.
            The error code is described in \ref onu_errorcode.

   \remarks This function is intended for internal use and for debugging.

   \return Return value as follows:
   - 0: if successful
   - An error code in case an error occurred.
*/
#define FIO_MDIO_DATA_READ _IOWR(LAN_MAGIC, 0x12, union mdio_data_read_u)

/**
   Write data to the MDIO Interface. This function allows to configure
   any attached device by register and device addressing.
   This applies to external and internal Ethernet PHYs as well.
   The 'data' value (\ref mdio_write) is directly written to the
   device register.

   A read operation can be performed by using \ref FIO_MDIO_DATA_READ.

   \param mdio_write Pointer to \ref mdio_write.

   \remarks The function returns an error code in case an error occurred.
            The error code is described in \ref onu_errorcode.

   \remarks This function is intended for internal use and for debugging.

   \return Return value as follows:
   - 0: if successful
   - An error code in case an error occurred.
*/
#define FIO_MDIO_DATA_WRITE _IOW(LAN_MAGIC, 0x13, struct mdio_write)

/**
  Enable the MDIO interface.

  \param mdio_en Pointer to \ref mdio_en.

  \remarks The function returns an error code in case of error.
           The error code is described in \ref onu_errorcode.

  \return Return value as follows:
  - 0: if successful
  - An error code in case of error.

*/
#define FIO_MDIO_ENABLE _IOW(LAN_MAGIC, 0x14, struct mdio_en)

/**
  Disable a selected LAN port.

  \param mdio_dis Pointer to \ref mdio_dis.

  \remarks The function returns an error code in case of error.
           The error code is described in \ref onu_errorcode.

  \return Return value as follows:
  - 0: if successful
  - An error code in case of error.

*/
#define FIO_MDIO_DISABLE _IOW(LAN_MAGIC, 0x15, struct mdio_dis)

/**
  Download GPHY firmware binary.

  \param lan_gphy_fw Pointer to \ref lan_gphy_fw.

  \remarks Function for debugging only. Be aware to call it before
           the \ref FIO_GPE_INIT only!!!
           The function returns an error code in case of error.
           The error code is described in \ref onu_errorcode.

  \return Return value as follows:
  - 0: if successful
  - An error code in case of error.

*/
#define FIO_LAN_GPHY_FIRMWARE_DOWNLOAD _IOW(LAN_MAGIC, 0x16, struct lan_gphy_fw)

/**
   Read data from a "MDIO Manageable Device" via the MDIO interface.
   This function allows to read out various information of any attached device
   by indirect addressing.
   The "data" value (\ref mmd_data_read_u) contains the read device register.
   A write operation can be performed by using \ref FIO_MMD_DATA_WRITE.

   \param mmd_data_read Pointer to \ref mmd_data_read_u.

   \remarks The function returns an error code in case an error occurred.
            The error code is described in \ref onu_errorcode.

   \remarks This function is intended for internal use and for debugging.

   \return Return value as follows:
   - 0: if successful
   - An error code in case an error occurred.
*/
#define FIO_MMD_DATA_READ _IOWR(LAN_MAGIC, 0x17, union mmd_data_read_u)

/**
   Write data to the MDIO Interface of the switch device. This function allows
   to configure any attached device by register and device addressing.
   This applies to external and internal Ethernet PHYs as well.
   The 'data' value (\ref mmd_write) is directly written to the
   device register.
   A read operation can be performed by using \ref FIO_MMD_DATA_READ.

   \param mmd_write Pointer to \ref mmd_write.

   \remarks The function returns an error code in case an error occurred.
            The error code is described in \ref onu_errorcode.

   \remarks This function is intended for internal use and for debugging.

   \return Return value as follows:
   - 0: if successful
   - An error code in case an error occurred.
*/
#define FIO_MMD_DATA_WRITE _IOW(LAN_MAGIC, 0x18, struct mmd_write)

/**
  Configure auto negotiation capability for the Ethernet interface per LAN port.

  \param lan_port_capability_cfg Pointer to \ref lan_port_capability_cfg.

  \remarks The function returns an error code in case of error.
           The error code is described in \ref onu_errorcode.

  \return Return value as follows:
  - 0: if successful
  - An error code in case of error.

*/
#define FIO_LAN_PORT_CAPABILITY_CFG_SET \
	_IOW(LAN_MAGIC, 0x19, struct lan_port_capability_cfg)

/**
  Read back the Ethernet auto negotiation capability.

  \param lan_port_capability_cfg Pointer to \ref lan_port_capability_cfg_get_u.

  \remarks The function returns an error code in case of error.
           The error code is described in \ref onu_errorcode.

  \return Return value as follows:
  - 0: if successful
  - An error code in case of error.

*/
#define FIO_LAN_PORT_CAPABILITY_CFG_GET \
	_IOWR(LAN_MAGIC, 0x1a, union lan_port_capability_cfg_get_u)

/*! @} */

/*! @} */

EXTERN_C_END
#ifdef __PACKED_DEFINED__
#  if !defined (__GNUC__) && !defined (__GNUG__)
#    pragma pack()
#  endif
#  undef __PACKED_DEFINED__
#  undef __PACKED__
#endif
#endif				/* _drv_onu_lan_h_ */
