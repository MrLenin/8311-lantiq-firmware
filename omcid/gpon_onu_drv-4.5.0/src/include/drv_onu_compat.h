/**
 * drv_onu_compat.h — Compatibility header for shipping v7.5.1 kernel modules
 *
 * The v4.5.0 SDK headers define ioctl structs with sizes that don't match the
 * shipping kernel modules (v7.5.1). This header provides updated definitions
 * that produce the correct ioctl numbers for the shipping modules.
 *
 * Include this AFTER the standard v4.5.0 driver interface headers.
 *
 * See IOCTL_COMPAT.md for the full analysis.
 */
#ifndef _DRV_ONU_COMPAT_H
#define _DRV_ONU_COMPAT_H

#include <linux/ioctl.h>
#include "drv_onu_interface.h"

/*
 * ============================================================================
 *  New enum types (not in v4.5.0)
 * ============================================================================
 */

/** GMII multiplexer mode selection. Controls which PHY/interface the LAN port
    routes through on the Falcon SoC. */
enum lan_mode_gmux {
	LAN_MODE_GMUX_GPHY0_GMII = 0,
	LAN_MODE_GMUX_GPHY0_MII2 = 1,
	LAN_MODE_GMUX_GPHY1_GMII = 2,
	LAN_MODE_GMUX_GPHY1_MII2 = 3,
	LAN_MODE_GMUX_SGMII = 4,
	LAN_MODE_GMUX_XMII0 = 5,
	LAN_MODE_GMUX_XMII1 = 6,
};

/*
 * ============================================================================
 *  Redefined structs (sizes must match shipping kernel modules)
 * ============================================================================
 *
 * IMPORTANT: We #undef the FIO_* macros and redefine them with the new struct
 * sizes. The v4.5.0 API code accesses struct members by name, so the compiler
 * handles the new field offsets automatically.
 */

/*
 * --- lan_port_cfg: 36 → 52 bytes ---
 * Two fields INSERTED after uni_port_en, two APPENDED at end.
 * ALL field offsets after uni_port_en shifted by +8.
 */
#undef lan_port_cfg
struct lan_port_cfg {
	/** Port selection (0 to ONU_GPE_MAX_ETH_UNI - 1). */
	uint32_t index;
	/** Port enable. */
	uint32_t uni_port_en;
	/** MDIO device address for external PHY. Set -1 for internal. */
	int32_t mdio_dev_addr;
	/** GMII multiplexer routing. */
	enum lan_mode_gmux gmux_mode;
	/** Interface mode. */
	enum lan_mode_interface mode;
	/** PHY duplex selection. */
	enum lan_mode_duplex duplex_mode;
	/** Flow control mode. */
	enum lan_mode_flow_control flow_control_mode;
	/** Interface speed. */
	enum lan_mode_speed speed_mode;
	/** Transmit Clock Delay (0..7, in 500ps steps). */
	uint8_t tx_clk_dly;
	/** Receive Clock Delay (0..7, in 500ps steps). */
	uint8_t rx_clk_dly;
	/** Maximum Ethernet frame length. */
	uint16_t max_frame_size;
	/** LPI mode enable. */
	uint32_t lpi_enable;
	/** SGMII autonegotiation selection. */
	enum sgmii_autoneg_mode autoneg_mode;
	/** Invert TX clock signal. */
	uint32_t invtx;
	/** Invert RX clock signal. */
	uint32_t invrx;
} __PACKED__;

/* Verify size at compile time */
typedef char _check_lan_port_cfg_size
	[(sizeof(struct lan_port_cfg) == 52) ? 1 : -1];

#undef FIO_LAN_PORT_CFG_SET
#define FIO_LAN_PORT_CFG_SET _IOW(LAN_MAGIC, 0x03, struct lan_port_cfg)

/* GET uses a union; redefine it too */
#undef lan_port_cfg_get_u
union lan_port_cfg_get_u {
	struct lan_port_index in;
	struct lan_port_cfg out;
} __PACKED__;

#undef FIO_LAN_PORT_CFG_GET
#define FIO_LAN_PORT_CFG_GET _IOWR(LAN_MAGIC, 0x04, union lan_port_cfg_get_u)


/*
 * --- lan_loop_cfg: 24 → 32 bytes ---
 * Two fields APPENDED. Existing offsets preserved.
 */
#undef lan_loop_cfg
struct lan_loop_cfg {
	/** Port selection (0 to ONU_GPE_MAX_ETH_UNI - 1). */
	uint32_t index;
	/** Ethernet MAC egress loop enable. */
	uint32_t mac_egress_loop_en;
	/** xMII ingress loop enable. */
	uint32_t mii_ingress_loop_en;
	/** SGMII ingress loop enable. */
	uint32_t sgmii_ingress_loop_en;
	/** PHY ingress loop enable. */
	uint32_t phy_ingress_loop_en;
	/** PHY egress loop enable. */
	uint32_t phy_egress_loop_en;
	/** LAN port ingress loop enable (GPE-level). */
	uint32_t lan_port_ingress_loop_en;
	/** MAC address swap enable (for loopback testing). */
	uint32_t mac_swap_en;
} __PACKED__;

typedef char _check_lan_loop_cfg_size
	[(sizeof(struct lan_loop_cfg) == 32) ? 1 : -1];

#undef FIO_LAN_LOOP_CFG_SET
#define FIO_LAN_LOOP_CFG_SET _IOW(LAN_MAGIC, 0x07, struct lan_loop_cfg)

#undef lan_loop_cfg_get_u
union lan_loop_cfg_get_u {
	struct lan_port_index in;
	struct lan_loop_cfg out;
} __PACKED__;

#undef FIO_LAN_LOOP_CFG_GET
#define FIO_LAN_LOOP_CFG_GET _IOWR(LAN_MAGIC, 0x08, union lan_loop_cfg_get_u)


/*
 * --- lan_port_capability_cfg: 12 → 36 bytes ---
 * All bool fields widened to uint32_t. Same names, different types.
 */
#undef lan_port_capability_cfg
struct lan_port_capability_cfg {
	/** LAN port index, starting with 0. */
	uint32_t index;
	/** Supports full duplex mode. */
	uint32_t full_duplex;
	/** Supports half-duplex mode. */
	uint32_t half_duplex;
	/** Supports 10 Mbit/s data rate. */
	uint32_t mbit_10;
	/** Supports 100 Mbit/s data rate. */
	uint32_t mbit_100;
	/** Supports 1000 Mbit/s data rate. */
	uint32_t mbit_1000;
	/** Supports pause frame reception and transmission. */
	uint32_t sym_pause;
	/** Supports asymmetric pause frame handling. */
	uint32_t asym_pause;
	/** Supports Energy Efficient Ethernet mode. */
	uint32_t eee;
} __PACKED__;

typedef char _check_lan_port_capability_cfg_size
	[(sizeof(struct lan_port_capability_cfg) == 36) ? 1 : -1];

#undef FIO_LAN_PORT_CAPABILITY_CFG_SET
#define FIO_LAN_PORT_CAPABILITY_CFG_SET \
	_IOW(LAN_MAGIC, 0x19, struct lan_port_capability_cfg)

#undef lan_port_capability_cfg_get_u
union lan_port_capability_cfg_get_u {
	struct lan_port_index in;
	struct lan_port_capability_cfg out;
} __PACKED__;

#undef FIO_LAN_PORT_CAPABILITY_CFG_GET
#define FIO_LAN_PORT_CAPABILITY_CFG_GET \
	_IOWR(LAN_MAGIC, 0x1a, union lan_port_capability_cfg_get_u)


/*
 * --- gpe_parser_cfg: 20 → 28 bytes ---
 * Two hidden fields APPENDED (not exposed via CLI).
 */
#undef gpe_parser_cfg
struct gpe_parser_cfg {
	/** Four Ethertype values for VLAN tag identification. */
	uint32_t tpid[4];
	/** S-TAG indication Ethertype (deprecated). */
	uint32_t special_tag;
	/** Reserved (set to 0). */
	uint32_t _reserved[2];
} __PACKED__;

typedef char _check_gpe_parser_cfg_size
	[(sizeof(struct gpe_parser_cfg) == 28) ? 1 : -1];

#undef FIO_GPE_PARSER_CFG_SET
#define FIO_GPE_PARSER_CFG_SET _IOW(GPE_MAGIC, 0x22, struct gpe_parser_cfg)

/* GET direction changed from _IOR to _IOWR */
#undef FIO_GPE_PARSER_CFG_GET
#define FIO_GPE_PARSER_CFG_GET _IOWR(GPE_MAGIC, 0x23, struct gpe_parser_cfg)


/*
 * --- gpe_tod_sync: 16 → 24 bytes ---
 * Two fields APPENDED. SET direction changed from _IOW to _IOWR.
 */
#undef gpe_tod_sync
struct gpe_tod_sync {
	/** Multiframe counter value for time synchronization. */
	uint32_t multiframe_count;
	/** Time of Day higher part (in units of seconds). */
	uint32_t tod_seconds;
	/** Time of Day extended part (in units of seconds). */
	uint32_t tod_extended_seconds;
	/** Time of Day lower part (in units of nanoseconds). */
	uint32_t tod_nano_seconds;
	/** ToD offset in picoseconds for fine-grained adjustment. */
	int32_t tod_offset_pico_seconds;
	/** ToD quality indicator. */
	int32_t tod_quality;
} __PACKED__;

typedef char _check_gpe_tod_sync_size
	[(sizeof(struct gpe_tod_sync) == 24) ? 1 : -1];

/* Direction changed: _IOW → _IOWR */
#undef FIO_GPE_TOD_SYNC_SET
#define FIO_GPE_TOD_SYNC_SET _IOWR(GPE_MAGIC, 0x2C, struct gpe_tod_sync)

#undef FIO_GPE_TOD_SYNC_GET
#define FIO_GPE_TOD_SYNC_GET _IOR(GPE_MAGIC, 0x2E, struct gpe_tod_sync)


/*
 * --- gpe_tcont_cfg: 8 → 16 bytes ---
 * Two hidden fields APPENDED (not exposed via CLI for CREATE).
 * SET direction changed from _IOW to _IOWR.
 */
#undef gpe_tcont_cfg
struct gpe_tcont_cfg {
	/** Egress Port Number. */
	uint32_t epn;
	/** Policy. */
	uint32_t policy;
	/** Reserved (set to 0). */
	uint32_t _reserved[2];
} __PACKED__;

typedef char _check_gpe_tcont_cfg_size
	[(sizeof(struct gpe_tcont_cfg) == 16) ? 1 : -1];

#undef FIO_GPE_TCONT_CREATE
#define FIO_GPE_TCONT_CREATE _IOW(GPE_MAGIC, 0x1C, struct gpe_tcont_cfg)

/* SET direction changed: _IOW → _IOWR (struct gpe_tcont unchanged at 16 bytes) */
#undef FIO_GPE_TCONT_SET
#define FIO_GPE_TCONT_SET _IOWR(GPE_MAGIC, 0x1D, struct gpe_tcont)


/*
 * --- onu_version_string: 400 → 480 bytes ---
 * One char[80] field APPENDED.
 */
#undef onu_version_string
struct onu_version_string {
	char onu_version[80];
	char fw_version[80];
	char cop_version[80];
	char sce_interface_version[80];
	char chip_id[80];
	/** Device type string (e.g., "PSB98030"). */
	char device_type[80];
} __PACKED__;

typedef char _check_onu_version_string_size
	[(sizeof(struct onu_version_string) == 480) ? 1 : -1];

#undef FIO_ONU_VERSION_GET
#define FIO_ONU_VERSION_GET _IOR(ONU_MAGIC, 4, struct onu_version_string)


/*
 * ============================================================================
 *  New ONU ioctls (not in v4.5.0 SDK, available in shipping kernel)
 * ============================================================================
 */

/* 802.1x authentication — struct size TBD from kernel CLI */
/* #define FIO_LAN_PORT_802_1X_AUTH_CFG_SET ... */
/* #define FIO_LAN_PORT_802_1X_AUTH_CFG_GET ... */

/* LOS pin configuration — struct size TBD */
/* #define FIO_ONU_LOS_PIN_CFG_SET ... */
/* #define FIO_ONU_LOS_PIN_CFG_GET ... */


/*
 * ============================================================================
 *  Optic driver compat (mod_optic.ko v7.5.1 vs v4.5.0 headers)
 * ============================================================================
 *
 * The optic driver structs also changed between SDK versions.
 * Guard with the BOSA interface header's include guard so these only
 * take effect when the optic headers have already been included.
 */
#ifdef _drv_optic_bosa_interface_h_

/*
 * --- optic_bosa_tx_status: 9 → 24 bytes ---
 * tx_enable widened from bool (1 byte) to uint32_t (4 bytes).
 * 4-byte unknown field inserted after modulation_current.
 * 8 bytes of unknown fields appended after slope_efficiency.
 *
 * Layout verified by Ghidra decompilation of shipping omcid:
 *   FUN_004361c0 (tx_optical_level_get) accesses:
 *     buf+4=bias_current, buf+6=modulation_current,
 *     buf+12=laser_threshold, buf+14=slope_efficiency
 *   FUN_00436328 (laser_bias_current_get) accesses:
 *     buf+4=bias_current
 *   Ioctl constant: 0x4018CF0D = _IOR(207, 13, 24-byte struct)
 */
#undef optic_bosa_tx_status
struct optic_bosa_tx_status {
	/** Transmitter enable (widened from bool to uint32_t in v7.5.1). */
	uint32_t tx_enable;
	/** Actual transmit laser bias current,
	    [mA] << OPTIC_FLOAT2INTSHIFT_CURRENT. */
	uint16_t bias_current;
	/** Actual transmit laser modulation current,
	    [mA] << OPTIC_FLOAT2INTSHIFT_CURRENT. */
	uint16_t modulation_current;
	/** Unknown field added in v7.5.1 (4 bytes). */
	uint32_t _reserved1;
	/** Transmit laser threshold current (Ith),
	    [mA] << OPTIC_FLOAT2INTSHIFT_CURRENT. */
	uint16_t laser_threshold;
	/** Transmit laser Slope Efficiency,
	    [uW/mA] << OPTIC_FLOAT2INTSHIFT_SLOPEEFFICIENCY. */
	uint16_t slope_efficiency;
	/** Unknown fields added in v7.5.1 (8 bytes). */
	uint8_t _reserved2[8];
} __PACKED__;

typedef char _check_optic_bosa_tx_status_size
	[(sizeof(struct optic_bosa_tx_status) == 24) ? 1 : -1];

#undef FIO_BOSA_TX_STATUS_GET
#define FIO_BOSA_TX_STATUS_GET \
	_IOR(OPTIC_BOSA_MAGIC, 13, struct optic_bosa_tx_status)

#endif /* _drv_optic_bosa_interface_h_ */


/*
 * ============================================================================
 *  New optic driver ioctls (not in v4.5.0 SDK)
 * ============================================================================
 */
#ifdef _drv_optic_mm_interface_h_

/** Supply voltage measurement result.
    Ioctl added in v7.5.1 (OPTIC_MM_MAGIC ioctl #10).
    Returns voltage in [V] << OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE (= 14).
    Confirmed via Ghidra decompilation: 0x4004CB0A = _IOR(203, 10, 4). */
struct optic_supply_voltage {
	/** Supply voltage, [V] << OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE. */
	uint32_t voltage_val;
} __PACKED__;

typedef char _check_optic_supply_voltage_size
	[(sizeof(struct optic_supply_voltage) == 4) ? 1 : -1];

/** Read the supply voltage of the optical module.
    New in v7.5.1, not present in v4.5.0 (which has OPTIC_MM_MAX=9). */
#define FIO_MM_SUPPLY_VOLTAGE_GET \
	_IOR(OPTIC_MM_MAGIC, 10, struct optic_supply_voltage)

#endif /* _drv_optic_mm_interface_h_ */


#endif /* _DRV_ONU_COMPAT_H */
