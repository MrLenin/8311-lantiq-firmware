/******************************************************************************

                               Copyright (c) 2013
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/* attention, this file was automatically generated
   by update_sce.py at 31 Jan 2013 08:25:50 +000 */

/**
   \file
   This is the GPON GPE/SCE table definition file, used for the FALCON GPON Modem driver.
*/

#ifndef _drv_onu_gpe_tables_h_
#define _drv_onu_gpe_tables_h_

#if defined(WIN32)
#  define __BIG_ENDIAN              4321
#  define __LITTLE_ENDIAN           1234
#  define __BYTE_ORDER              __LITTLE_ENDIAN
#elif defined(LINUX)
#  ifdef __KERNEL__
#    include <asm/byteorder.h>
#    if defined(__BIG_ENDIAN)
#      define __BYTE_ORDER          __BIG_ENDIAN
#    elif defined(__LITTLE_ENDIAN)
#      define __BYTE_ORDER          __LITTLE_ENDIAN
#    else
#      error "Unknown byte order (linux kernel)!"
#    endif
#  else
#    include <endian.h>
#    if !defined(__BYTE_ORDER) || \
        !defined(__LITTLE_ENDIAN) || \
        !defined(__BIG_ENDIAN)
#      error "Unknown byte order (linux userspace)!"
#    endif
#  endif
#else
#  if defined(__BIG_ENDIAN)
#    undef __BIG_ENDIAN
#    undef __LITTLE_ENDIAN
#    define __BIG_ENDIAN            4321
#    define __LITTLE_ENDIAN         1234
#    define __BYTE_ORDER            __BIG_ENDIAN
#  elif defined(__LITTLE_ENDIAN)
#    undef __BIG_ENDIAN
#    undef __LITTLE_ENDIAN
#    define __BIG_ENDIAN            4321
#    define __LITTLE_ENDIAN         1234
#    define __BYTE_ORDER            __LITTLE_ENDIAN
#  else
#    error "Unknown byte order (unknown OS)!"
#  endif
#endif

#ifndef __PACKED__
#  if defined (__GNUC__) || defined (__GNUG__)
   /* GNU C or C++ compiler */
#    define __PACKED__ __attribute__ ((packed))
#  else
   /* Byte alignment adjustment */
#    pragma pack(1)
#    if !defined (_PACKED_)
#      define __PACKED__        /* nothing */
#    endif
#  endif
#  define __PACKED_DEFINED__
#endif

EXTERN_C_BEGIN

/** \addtogroup ONU_MAPI_REFERENCE
   @{
*/

/** \defgroup GPON_GPE_TABLES GPON Packet Engine Table Definitions

    This chapter describes the table definitions that are used by the GPE/SCE
    hardware module.
   @{
*/

/* ----------------------------------------------------------------------------
    Please note that this part of the code is endianess-aware.
    Switching to a little-endian operation system or to a different
    processor core or compiler needs adaptation of the bit definitions.

    The implementation has been chosen this way to make the table access
    more convenient and the software code better readable.

    Any change in the hardware or firmware table structure must be
    reflected in this part of the software code.
   ------------------------------------------------------------------------- */

#define GPON_SCE_INTERFACE_MAJOR 4
#define GPON_SCE_INTERFACE_MINOR 48
#define GPON_SCE_INTERFACE_STEP 0
#define GPON_SCE_INTERFACE_VERSION "4.48.0"

/** ONU_GPE_DS_GEM_PORT_TABLE structure definition.
   This table handles the GEM Port ID related handling instructions for downstream data traffic.
The index used to access this table is the GEM port index (gpix).
The table instance value shall be set to 1.
*/
struct gpe_ds_gem_port_table {
#if __BYTE_ORDER == __BIG_ENDIAN
	/** Unused data field, set to 0. */
	uint32_t unused4:1;
	/** MAC Bridge Port index, values 0 to ONU_GPE_BRIDGE_PORT_TABLE_SIZE - 1
	    are valid. If a fourth bridge port is added/removed, the
	    max_bridge_index value must be updated accordingly.
	*/
	uint32_t bridge_port_index3:7;
	/** Unused data field, set to 0. */
	uint32_t unused3:1;
	/** MAC Bridge Port index, values 0 to ONU_GPE_BRIDGE_PORT_TABLE_SIZE - 1
	    are valid. If a third bridge port is added/removed, the max_bridge_index
	    value must be updated accordingly.
	*/
	uint32_t bridge_port_index2:7;
	/** Unused data field, set to 0. */
	uint32_t unused2:1;
	/** MAC Bridge Port index, values 0 to ONU_GPE_BRIDGE_PORT_TABLE_SIZE - 1
	    are valid. If a second bridge port is added/removed, the
	    max_bridge_index value must be updated accordingly.
	*/
	uint32_t bridge_port_index1:7;
	/** Unused data field, set to 0. */
	uint32_t unused1:1;
	/** MAC Bridge Port index, values 0 to ONU_GPE_BRIDGE_PORT_TABLE_SIZE - 1
	    are valid. Alternatively, this field holds the QID to be used in case of
	    gem_loopback_enable = 1.
	    If only a single bridge port is connected to the GEM port, the
	    max_bridge_index value must be set to 0.
	*/
	uint32_t bridge_port_index0:7;
	/** Unused data field, set to 0. */
	uint32_t unused8:1;
	/** MAC Bridge Port index, values 0 to ONU_GPE_BRIDGE_PORT_TABLE_SIZE - 1
	    are valid. If an eighth bridge port is added/removed, the
	    max_bridge_index value must be updated accordingly.
	*/
	uint32_t bridge_port_index7:7;
	/** Unused data field, set to 0. */
	uint32_t unused7:1;
	/** MAC Bridge Port index, values 0 to ONU_GPE_BRIDGE_PORT_TABLE_SIZE - 1
	    are valid. If a seventh bridge port is added/removed, the
	    max_bridge_index value must be updated accordingly.
	*/
	uint32_t bridge_port_index6:7;
	/** Unused data field, set to 0. */
	uint32_t unused6:1;
	/** MAC Bridge Port index, values 0 to ONU_GPE_BRIDGE_PORT_TABLE_SIZE - 1
	    are valid. If a sixth bridge port is added/removed, the max_bridge_index
	    value must be updated accordingly.
	*/
	uint32_t bridge_port_index5:7;
	/** Unused data field, set to 0. */
	uint32_t unused5:1;
	/** MAC Bridge Port index, values 0 to ONU_GPE_BRIDGE_PORT_TABLE_SIZE - 1
	    are valid. If a fifth bridge port is added/removed, the max_bridge_index
	    value must be updated accordingly.
	*/
	uint32_t bridge_port_index4:7;
	/** Selects the decoding rule (1 of 8). Used as MSB of the DSCP Decoding
	    Table index, LSB is DSCP value.
	*/
	uint32_t dscp_table_pointer:3;
	/** Code points as defined by the ingress color marking attribute of the GEM
	    CTP Managed Entity. The selection controls the definition of the
	    internal priority.
	    Ingress color marking mode, values 0 and 2 to 7 are valid.
	    - 0: No marking (ignore ingress marking)
	    - 1: Reserved (do not use)
	    - 2: DEI
	    - 3: Use the PCP decoding as defined in lines 0 to 7 of the
	    ONU_GPE_PCP_DECODING_TABLE. For example, use this for the 8P0D mode.
	    - 4: Use the PCP decoding as defined in lines 8 to 15 of the
	    ONU_GPE_PCP_DECODING_TABLE. For example, use this for the 7P1D mode.
	    - 5: Use the PCP decoding as defined in lines 16 to 23 of the
	    ONU_GPE_PCP_DECODING_TABLE. For example, use this for the 6P2D mode.
	    - 6: Use the PCP decoding as defined in lines 24 to 31 of the
	    ONU_GPE_PCP_DECODING_TABLE. For example, use this for the 5P3D mode.
	    -7: DSCP
	*/
	uint32_t ingress_color_marking:3;
	/** Unused data field, set to 0. */
	uint32_t unused11:2;
	/** Profile for ANI (WAN) ingress exception processing.
	    This points to an entry of the ONU_GPE_EXCEPTION_TABLE.
	    Only the ingress_exception_flag_mask field of this entry is used.
	*/
	uint32_t exception_profile:3;
	/** Extended VLAN enable, enables the VLAN configuration defined by the
	    Extended VLAN Index (ext_vlan_index).
	*/
	uint32_t ext_vlan_enable:1;
	/** Extended VLAN Index, values 0 to ONU_GPE_EXTENDED_VLAN_TABLE_SIZE - 1
	    are valid, points to the ONU_GPE_EXTENDED_VLAN_TABLE.
	*/
	uint32_t ext_vlan_index:7;
	/** Unused data field, set to 0. */
	uint32_t unused10:1;
	/** Defines the usage of the inner VLAN field in the ingress extended VLAN
	    rule definition.
	    - 0: Inner VLAN ID
	    - 1: Reserved (do not use)
	    - 2: Ingress port number (ipn)
	    - 3: Received DSCP
	*/
	uint32_t ext_vlan_ingress_mode:2;
	/** downstream GEM meter enable.
	    - 0: Disabled.
	    - 1: Enabled.
	*/
	uint32_t ds_gem_meter_enable:1;
	/** Dual token bucket meter selection for downstream GEM frames, the upper 8
	    bit of this value are used to address one of up to 256 meter units, the
	    LSB must be set to 0.
	*/
	uint32_t ds_gem_meter_id:9;
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
	/** Unused data field, set to 0. */
	uint32_t unused15:1;
	/** GEM MAC swap enable. Swap MAC DA and MAC SA.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t gem_mac_swap_enable:1;
	/** GEM loopback enable. The QID for Loopback must be configured in
	    max_bridge_port_cfg0.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t gem_loopback_enable:1;
	/** Forwarding ID mask, enables the inner PCP for FID calculation.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t fid_mask_pcpi:1;
	/** Forwarding ID mask, enables the outer PCP for FID calculation.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t fid_mask_pcpo:1;
	/** Forwarding ID mask, enables the inner VID for FID calculation.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t fid_mask_vidi:1;
	/** Forwarding ID mask, enables the outer VID for FID calculation.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t fid_mask_vido:1;
	/** Enables PPPoE Termination on this GEM port.
	    - 0: No PPPoE Termination
	    - 1: PPPoE Termination
	*/
	uint32_t pppoe_enable:1;
	/** Enables NAPT on this GEM port (if NAPT is supported).
	    - 0: No NAPT
	    - 1: NAPT
	*/
	uint32_t napt_enable:1;
	/** queue selection mode for UNI egress queues.
	    - 0: selection based on outer PCP
	    - 1: selection based on priority queue pointer of downstream GEM port
	*/
	uint32_t queue_selection_mode:1;
	/** GEM Port Type. To be selected according to the GEM Interworking
	    Termination Point type defined by OMCI (GEM ITP or Multicast GEM ITP).
	    - 0: Unicast
	    - 1: Multicast
	*/
	uint32_t gem_port_type:1;
	/** LAN port (UNI port) index, values 0 to ONU_GPE_LAN_PORT_TABLE_SIZE - 1
	    are valid. This index points to the ONU_GPE_LAN_PORT_TABLE.
	*/
	uint32_t lan_port_index:3;
	/** Unused data field, set to 0. */
	uint32_t unused13:2;
	/** This is the maximum bridge index value to be used for replication of
	    downstream packets to multiple bridges (= num_bridges-1). Values 0 to
	    ONU_GPE_MAX_BRIDGES - 1 are valid.
	*/
	uint32_t max_bridge_index:3;
	/** Unused data field, set to 0. */
	uint32_t unused12:6;
	/** Priority queue pointer (UNI egress queue selection if
	    queue_selection_mode == 1).
	*/
	uint32_t egress_queue_offset:3;
	/** Interworking option, these values are valid.
	    - 1: Reserved
	    - 5: Mapping only without bridging (upstream p-Mapper)
	    - 6: Bridging (MAC bridge) or GEM broadcast
	    - Other values: Must not be used.
	*/
	uint32_t interworking_option:3;
#else
	/** MAC Bridge Port index, values 0 to ONU_GPE_BRIDGE_PORT_TABLE_SIZE - 1
	    are valid. Alternatively, this field holds the QID to be used in case of
	    gem_loopback_enable = 1.
	    If only a single bridge port is connected to the GEM port, the
	    max_bridge_index value must be set to 0.
	*/
	uint32_t bridge_port_index0:7;
	/** Unused data field, set to 0. */
	uint32_t unused1:1;
	/** MAC Bridge Port index, values 0 to ONU_GPE_BRIDGE_PORT_TABLE_SIZE - 1
	    are valid. If a second bridge port is added/removed, the
	    max_bridge_index value must be updated accordingly.
	*/
	uint32_t bridge_port_index1:7;
	/** Unused data field, set to 0. */
	uint32_t unused2:1;
	/** MAC Bridge Port index, values 0 to ONU_GPE_BRIDGE_PORT_TABLE_SIZE - 1
	    are valid. If a third bridge port is added/removed, the max_bridge_index
	    value must be updated accordingly.
	*/
	uint32_t bridge_port_index2:7;
	/** Unused data field, set to 0. */
	uint32_t unused3:1;
	/** MAC Bridge Port index, values 0 to ONU_GPE_BRIDGE_PORT_TABLE_SIZE - 1
	    are valid. If a fourth bridge port is added/removed, the
	    max_bridge_index value must be updated accordingly.
	*/
	uint32_t bridge_port_index3:7;
	/** Unused data field, set to 0. */
	uint32_t unused4:1;
	/** MAC Bridge Port index, values 0 to ONU_GPE_BRIDGE_PORT_TABLE_SIZE - 1
	    are valid. If a fifth bridge port is added/removed, the max_bridge_index
	    value must be updated accordingly.
	*/
	uint32_t bridge_port_index4:7;
	/** Unused data field, set to 0. */
	uint32_t unused5:1;
	/** MAC Bridge Port index, values 0 to ONU_GPE_BRIDGE_PORT_TABLE_SIZE - 1
	    are valid. If a sixth bridge port is added/removed, the max_bridge_index
	    value must be updated accordingly.
	*/
	uint32_t bridge_port_index5:7;
	/** Unused data field, set to 0. */
	uint32_t unused6:1;
	/** MAC Bridge Port index, values 0 to ONU_GPE_BRIDGE_PORT_TABLE_SIZE - 1
	    are valid. If a seventh bridge port is added/removed, the
	    max_bridge_index value must be updated accordingly.
	*/
	uint32_t bridge_port_index6:7;
	/** Unused data field, set to 0. */
	uint32_t unused7:1;
	/** MAC Bridge Port index, values 0 to ONU_GPE_BRIDGE_PORT_TABLE_SIZE - 1
	    are valid. If an eighth bridge port is added/removed, the
	    max_bridge_index value must be updated accordingly.
	*/
	uint32_t bridge_port_index7:7;
	/** Unused data field, set to 0. */
	uint32_t unused8:1;
	/** Dual token bucket meter selection for downstream GEM frames, the upper 8
	    bit of this value are used to address one of up to 256 meter units, the
	    LSB must be set to 0.
	*/
	uint32_t ds_gem_meter_id:9;
	/** downstream GEM meter enable.
	    - 0: Disabled.
	    - 1: Enabled.
	*/
	uint32_t ds_gem_meter_enable:1;
	/** Defines the usage of the inner VLAN field in the ingress extended VLAN
	    rule definition.
	    - 0: Inner VLAN ID
	    - 1: Reserved (do not use)
	    - 2: Ingress port number (ipn)
	    - 3: Received DSCP
	*/
	uint32_t ext_vlan_ingress_mode:2;
	/** Unused data field, set to 0. */
	uint32_t unused10:1;
	/** Extended VLAN Index, values 0 to ONU_GPE_EXTENDED_VLAN_TABLE_SIZE - 1
	    are valid, points to the ONU_GPE_EXTENDED_VLAN_TABLE.
	*/
	uint32_t ext_vlan_index:7;
	/** Extended VLAN enable, enables the VLAN configuration defined by the
	    Extended VLAN Index (ext_vlan_index).
	*/
	uint32_t ext_vlan_enable:1;
	/** Profile for ANI (WAN) ingress exception processing.
	    This points to an entry of the ONU_GPE_EXCEPTION_TABLE.
	    Only the ingress_exception_flag_mask field of this entry is used.
	*/
	uint32_t exception_profile:3;
	/** Unused data field, set to 0. */
	uint32_t unused11:2;
	/** Code points as defined by the ingress color marking attribute of the GEM
	    CTP Managed Entity. The selection controls the definition of the
	    internal priority.
	    Ingress color marking mode, values 0 and 2 to 7 are valid.
	    - 0: No marking (ignore ingress marking)
	    - 1: Reserved (do not use)
	    - 2: DEI
	    - 3: Use the PCP decoding as defined in lines 0 to 7 of the
	    ONU_GPE_PCP_DECODING_TABLE. For example, use this for the 8P0D mode.
	    - 4: Use the PCP decoding as defined in lines 8 to 15 of the
	    ONU_GPE_PCP_DECODING_TABLE. For example, use this for the 7P1D mode.
	    - 5: Use the PCP decoding as defined in lines 16 to 23 of the
	    ONU_GPE_PCP_DECODING_TABLE. For example, use this for the 6P2D mode.
	    - 6: Use the PCP decoding as defined in lines 24 to 31 of the
	    ONU_GPE_PCP_DECODING_TABLE. For example, use this for the 5P3D mode.
	    -7: DSCP
	*/
	uint32_t ingress_color_marking:3;
	/** Selects the decoding rule (1 of 8). Used as MSB of the DSCP Decoding
	    Table index, LSB is DSCP value.
	*/
	uint32_t dscp_table_pointer:3;
	/** Interworking option, these values are valid.
	    - 1: Reserved
	    - 5: Mapping only without bridging (upstream p-Mapper)
	    - 6: Bridging (MAC bridge) or GEM broadcast
	    - Other values: Must not be used.
	*/
	uint32_t interworking_option:3;
	/** Priority queue pointer (UNI egress queue selection if
	    queue_selection_mode == 1).
	*/
	uint32_t egress_queue_offset:3;
	/** Unused data field, set to 0. */
	uint32_t unused12:6;
	/** This is the maximum bridge index value to be used for replication of
	    downstream packets to multiple bridges (= num_bridges-1). Values 0 to
	    ONU_GPE_MAX_BRIDGES - 1 are valid.
	*/
	uint32_t max_bridge_index:3;
	/** Unused data field, set to 0. */
	uint32_t unused13:2;
	/** LAN port (UNI port) index, values 0 to ONU_GPE_LAN_PORT_TABLE_SIZE - 1
	    are valid. This index points to the ONU_GPE_LAN_PORT_TABLE.
	*/
	uint32_t lan_port_index:3;
	/** GEM Port Type. To be selected according to the GEM Interworking
	    Termination Point type defined by OMCI (GEM ITP or Multicast GEM ITP).
	    - 0: Unicast
	    - 1: Multicast
	*/
	uint32_t gem_port_type:1;
	/** queue selection mode for UNI egress queues.
	    - 0: selection based on outer PCP
	    - 1: selection based on priority queue pointer of downstream GEM port
	*/
	uint32_t queue_selection_mode:1;
	/** Enables NAPT on this GEM port (if NAPT is supported).
	    - 0: No NAPT
	    - 1: NAPT
	*/
	uint32_t napt_enable:1;
	/** Enables PPPoE Termination on this GEM port.
	    - 0: No PPPoE Termination
	    - 1: PPPoE Termination
	*/
	uint32_t pppoe_enable:1;
	/** Forwarding ID mask, enables the outer VID for FID calculation.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t fid_mask_vido:1;
	/** Forwarding ID mask, enables the inner VID for FID calculation.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t fid_mask_vidi:1;
	/** Forwarding ID mask, enables the outer PCP for FID calculation.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t fid_mask_pcpo:1;
	/** Forwarding ID mask, enables the inner PCP for FID calculation.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t fid_mask_pcpi:1;
	/** GEM loopback enable. The QID for Loopback must be configured in
	    max_bridge_port_cfg0.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t gem_loopback_enable:1;
	/** GEM MAC swap enable. Swap MAC DA and MAC SA.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t gem_mac_swap_enable:1;
	/** Unused data field, set to 0. */
	uint32_t unused15:1;
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
#endif
} __PACKED__;

/** ONU_GPE_US_GEM_PORT_TABLE structure definition.
   This table handles the GEM Port ID related handling instructions for upstream data traffic.
The index used to access this table is the GEM port index (gpix).
The table instance value shall be set to 1.
*/
struct gpe_us_gem_port_table {
#if __BYTE_ORDER == __BIG_ENDIAN
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
	/** Profile for ANI (WAN) egress exception processing.
	    This points to an entry of the ONU_GPE_EXCEPTION_TABLE.
	    Only the egress_exception_flag_mask field of this entry is used.
	*/
	uint32_t exception_profile:3;
	/** Selects the decoding rule (1 of 8) for Queue Marking. Used as MSBs of
	    the DSCP decoding table index (The 5 LSBs are the DSCP value).
	*/
	uint32_t dscp_table_pointer:3;
	/** Queue marking mode, values 0 to 7 are valid.
	    - 0: No marking
	    - 1: Internal marking by meter
	    - 2: DEI marking
	    - 3: PCP 8P0D marking
	    - 4: PCP 7P1D marking
	    - 5: PCP 6P2D marking
	    - 6: PCP 5P3D marking
	    - 7: DSCP marking
	*/
	uint32_t queue_marking_mode:3;
	/** Defines the usage of the inner VLAN field in the egress extended VLAN
	    rule definition.
	    - 0: Inner VLAN ID
	    - 1: Reserved (do not use)
	    - 2: Ingress port number (IPN)
	    - 3: Received DSCP
	*/
	uint32_t ext_vlan_egress_mode:2;
	/** Allow an egress extended VLAN operation to be based on the result of an
	    ingress extended VLAN operation.
	    - 0: VLAN operation is based on the original received data values
	    - 1: VLAN operation is based on the result of an ingress extended VLAN
	    operation
	*/
	uint32_t ext_vlan_incremental_enable:1;
	/** Egress color marking code, values 0 to 7 are valid.
	    - 0: No marking
	    - 1: Internal marking
	    - 2: DEI marking
	    - 3: PCP 8P0D marking
	    - 4: PCP 7P1D marking
	    - 5: PCP 6P2D marking
	    - 6: PCP 5P3D marking
	    - 7: DSCP marking
	*/
	uint32_t egress_color_marking:3;
	/** Extended VLAN enable, enables the VLAN configuration defined by the
	    Extended VLAN Index (ext_vlan_index).
	*/
	uint32_t ext_vlan_enable:1;
	/** Extended VLAN Index, values 0 to ONU_GPE_EXTENDED_VLAN_TABLE_SIZE - 1
	    are valid. This index points to the ONU_GPE_EXTENDED_VLAN_TABLE.
	*/
	uint32_t ext_vlan_index:7;
	/** Egress queue index, values 0 to GPON_MAX_QUEUE are valid. */
	uint32_t egress_queue_index:8;
#else
	/** Egress queue index, values 0 to GPON_MAX_QUEUE are valid. */
	uint32_t egress_queue_index:8;
	/** Extended VLAN Index, values 0 to ONU_GPE_EXTENDED_VLAN_TABLE_SIZE - 1
	    are valid. This index points to the ONU_GPE_EXTENDED_VLAN_TABLE.
	*/
	uint32_t ext_vlan_index:7;
	/** Extended VLAN enable, enables the VLAN configuration defined by the
	    Extended VLAN Index (ext_vlan_index).
	*/
	uint32_t ext_vlan_enable:1;
	/** Egress color marking code, values 0 to 7 are valid.
	    - 0: No marking
	    - 1: Internal marking
	    - 2: DEI marking
	    - 3: PCP 8P0D marking
	    - 4: PCP 7P1D marking
	    - 5: PCP 6P2D marking
	    - 6: PCP 5P3D marking
	    - 7: DSCP marking
	*/
	uint32_t egress_color_marking:3;
	/** Allow an egress extended VLAN operation to be based on the result of an
	    ingress extended VLAN operation.
	    - 0: VLAN operation is based on the original received data values
	    - 1: VLAN operation is based on the result of an ingress extended VLAN
	    operation
	*/
	uint32_t ext_vlan_incremental_enable:1;
	/** Defines the usage of the inner VLAN field in the egress extended VLAN
	    rule definition.
	    - 0: Inner VLAN ID
	    - 1: Reserved (do not use)
	    - 2: Ingress port number (IPN)
	    - 3: Received DSCP
	*/
	uint32_t ext_vlan_egress_mode:2;
	/** Queue marking mode, values 0 to 7 are valid.
	    - 0: No marking
	    - 1: Internal marking by meter
	    - 2: DEI marking
	    - 3: PCP 8P0D marking
	    - 4: PCP 7P1D marking
	    - 5: PCP 6P2D marking
	    - 6: PCP 5P3D marking
	    - 7: DSCP marking
	*/
	uint32_t queue_marking_mode:3;
	/** Selects the decoding rule (1 of 8) for Queue Marking. Used as MSBs of
	    the DSCP decoding table index (The 5 LSBs are the DSCP value).
	*/
	uint32_t dscp_table_pointer:3;
	/** Profile for ANI (WAN) egress exception processing.
	    This points to an entry of the ONU_GPE_EXCEPTION_TABLE.
	    Only the egress_exception_flag_mask field of this entry is used.
	*/
	uint32_t exception_profile:3;
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
#endif
} __PACKED__;

/** ONU_GPE_FID_ASSIGNMENT_TABLE structure definition.
   Defines the Forwarding IDs (FID) based on outer/inner VLAN.
*/
struct gpe_fwd_id_table {
#if __BYTE_ORDER == __BIG_ENDIAN
	/** Inner VLAN Priority, values 0 to 7 are valid. */
	uint32_t prio_inner:3;
	/** Unused data field, set to 0. */
	uint32_t unused2:1;
	/** Inner VLAN ID, values 0 to 4095 are valid. */
	uint32_t vid_inner:12;
	/** Outer VLAN Priority, values 0 to 7 are valid. */
	uint32_t prio_outer:3;
	/** Unused data field, set to 0. */
	uint32_t unused1:1;
	/** Outer VLAN ID, values 0 to 4095 are valid. */
	uint32_t vid_outer:12;
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
	/** End indication.
	    - 0: This is not the last entry.
	    - 1: This is the last entry.
	*/
	uint32_t end:1;
	/** Next entry pointer. Points to an entry of this table. */
	uint32_t next_entry:14;
	/** Unused data field, set to 0. */
	uint32_t unused3:7;
	/** Defines the behavior of this FID when forwarded in hybrid mode.
	    - 0: MAC & FID forwarding
	    - 1: FID cross connect
	*/
	uint32_t cross_connect:1;
	/** Forwarding ID (FID), values 0 to 63 are valid.
	    Attention: 8 bit are used for MDU applications, for SFU applications the
	    two MSB must be set to 0.
	*/
	uint32_t fid:8;
#else
	/** Outer VLAN ID, values 0 to 4095 are valid. */
	uint32_t vid_outer:12;
	/** Unused data field, set to 0. */
	uint32_t unused1:1;
	/** Outer VLAN Priority, values 0 to 7 are valid. */
	uint32_t prio_outer:3;
	/** Inner VLAN ID, values 0 to 4095 are valid. */
	uint32_t vid_inner:12;
	/** Unused data field, set to 0. */
	uint32_t unused2:1;
	/** Inner VLAN Priority, values 0 to 7 are valid. */
	uint32_t prio_inner:3;
	/** Forwarding ID (FID), values 0 to 63 are valid.
	    Attention: 8 bit are used for MDU applications, for SFU applications the
	    two MSB must be set to 0.
	*/
	uint32_t fid:8;
	/** Defines the behavior of this FID when forwarded in hybrid mode.
	    - 0: MAC & FID forwarding
	    - 1: FID cross connect
	*/
	uint32_t cross_connect:1;
	/** Unused data field, set to 0. */
	uint32_t unused3:7;
	/** Next entry pointer. Points to an entry of this table. */
	uint32_t next_entry:14;
	/** End indication.
	    - 0: This is not the last entry.
	    - 1: This is the last entry.
	*/
	uint32_t end:1;
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
#endif
} __PACKED__;

/** ONU_GPE_FID_HASH_TABLE structure definition.
   Defines the Forwarding IDs (FID) based on outer/inner VLAN.
*/
struct gpe_fwd_id_hash_table {
#if __BYTE_ORDER == __BIG_ENDIAN
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
	/** Unused data field, set to 0. */
	uint32_t unused2:1;
	/** Start pointer to the ONU_GPE_FID_ASSIGNMENT_TABLE. */
	uint32_t fwd_id_assignent_table_pointer:14;
	/** Unused data field, set to 0. */
	uint32_t unused1:16;
#else
	/** Unused data field, set to 0. */
	uint32_t unused1:16;
	/** Start pointer to the ONU_GPE_FID_ASSIGNMENT_TABLE. */
	uint32_t fwd_id_assignent_table_pointer:14;
	/** Unused data field, set to 0. */
	uint32_t unused2:1;
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
#endif
} __PACKED__;

/** ONU_GPE_BRIDGE_PORT_TABLE structure definition.
   This table holds bridge port related configurations.
The index used to access this table is the bridge_port_index.
The table instance value shall be set to 1 for reading and to 0x3F for write access.
*/
struct gpe_bridge_port_table {
#if __BYTE_ORDER == __BIG_ENDIAN
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
	/** Unused data field, set to 0. */
	uint32_t unused5:21;
	/** TP Type, indicates the type of instance connected to the egress bridge
	    port. Values 0 to 3 are valid. The MSB of this field serves as the ANI
	    indication (1 = ANI side, 0 = UNI side).
	    - 0: PPTP Ethernet UNI
	    - 1: Reserved (do not use)
	    - 2: 802.1p-Mapper
	    - 3: ITP
	*/
	uint32_t tp_type:2;
	/** Defines the index of the connected Termination Point instance, which can
	    be.
	    - LAN Port index
	    - P-Mapper index
	    - ITP ID (GEM port index, gpix)
	*/
	uint32_t tp_pointer:8;
	/** Unused data field, set to 0. */
	uint32_t unused4:3;
	/** Selects the decoding rule (1 of 8).
	    Used as MSB of the DSCP decoding table index.
	*/
	uint32_t dscp_table_pointer:3;
	/** Egress filter mask to implement the MAC bridge port preassign table.
	    Each bit position is related to a certain traffic type.
	    - 0: IPv4 broadcast
	    - 1: IPv4 multicast
	    - 2: IPv6 multicast
	    - 3: PPPoE broadcast
	    - 4: AppleTalk
	    - 5: IPX
	    - 6: ARP
	    - 7: RARP
	    - 8: NetBEUI
	    - 9: BPDU
	*/
	uint32_t egress_filter_mask:10;
	/** Egress dual token bucket meter selection, the upper 8 bit of this value
	    are used to address one of up to 256 meter units, the LSB must be set to
	    0.
	*/
	uint32_t meter_id_egress:9;
	/** Egress VLAN tagging filter, values 0 to
	    ONU_GPE_TAGGING_FILTER_TABLE_SIZE - 1 are valid. Points to an entry of
	    the ONU_GPE_TAGGING_FILTER_TABLE.
	*/
	uint32_t tagging_filter_egress:7;
	/** Ingress dual token bucket meter selection, the upper 8 bit of this value
	    are used to address one of up to 256 meter units, the LSB must be set to
	    0.
	*/
	uint32_t meter_id_ingress:9;
	/** Ingress VLAN tagging filter, values 0 to
	    ONU_GPE_TAGGING_FILTER_TABLE_SIZE - 1 are valid. Points to an entry of
	    the ONU_GPE_TAGGING_FILTER_TABLE.
	*/
	uint32_t tagging_filter_ingress:7;
	/** Start pointer into the ONU_GPE_MAC_FILTER_TABLE. */
	uint32_t da_filter_pointer:8;
	/** Start pointer into the ONU_GPE_MAC_FILTER_TABLE. */
	uint32_t sa_filter_pointer:8;
	/** Unused data field, set to 0. */
	uint32_t unused3:3;
	/** Egress queue marking mode, values 0 to 7 are valid.
	    - 0: No marking
	    - 1: Internal marking by meter
	    - 2: DEI marking
	    - 3: PCP 8P0D marking
	    - 4: PCP 7P1D marking
	    - 5: PCP 6P2D marking
	    - 6: PCP 5P3D marking
	    - 7: DSCP marking
	*/
	uint32_t egress_color_marking:3;
	/** Ingress color marking mode, values 0 and 2 to 7 are valid. */
	uint32_t ingress_color_marking:3;
	/** Ethernet MAC destination address filter mode configuration.
	    - 00: Allow all
	    - 01: Reserved
	    - 10: Deny for specific MAC DA
	    - 11: Allow only specific MAC DA
	*/
	uint32_t da_filter_mode:2;
	/** Ethernet MAC source address filter mode configuration.
	    - 00: Allow all
	    - 01: Reserved
	    - 10: Deny from specific MAC SA
	    - 11: Allow only specific MAC SA
	*/
	uint32_t sa_filter_mode:2;
	/** Port state, values 0 to 2 are supported.
	    - 0: Forwarding
	    - 1: Learning
	    - 2: Discarding
	    - 3: Reserved (do not be use)
	*/
	uint32_t port_state:2;
	/** Unused data field, set to 0. */
	uint32_t unused2:1;
	/** Bridge index, values 0 to ONU_GPE_MAX_BRIDGES - 1 are valid. */
	uint32_t bridge_index:3;
	/** Forwarding method.
	    - 0: Layer 2 - MAC address and VLAN (FID)
	    - 1: Layer 2 - MAC address only
	    - 2: Layer 2 - Hybrid mode (MAC&FID or FID cross connect, depending on
	    FID)
	    - 3: Layer 3 - IPv4, IPv6, or MPLS and VLAN (FID)
	    - 4: MDU - GEM port index (gpix)
	    - 5: VLAN Rule-based
	    - 6-15: Reserved for future releases
	*/
	uint32_t forwarding_method:4;
	/** Unknown Multicast (umc) Flooding Disable.
	    If this function is enabled, incoming packets with unknown MAC multicast
	    destination addresses are according to the programmed flood map of the
	    related bridge (flooding_bridge_port_enable).
	    If disabled, incoming packets are dropped, if the MAC multicast
	    destination address is unknown.
	    - 0: Flooding enabled
	    - 1: Flooding disabled
	*/
	uint32_t umc_flood_disable:1;
	/** Egress Meter enable.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t meter_egress_enable:1;
	/** Ingress Meter enable.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t meter_ingress_enable:1;
	/** Egress VLAN tagging filter enable.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t tagging_filter_egress_enable:1;
	/** Ingress VLAN tagging filter enable.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t tagging_filter_ingress_enable:1;
	/** Unknown Unicast (uuc) Flooding Disable.
	    If this function is enabled, incoming packets with unknown MAC unicast
	    destination addresses are flooded according to the programmed flood map
	    of the related bridge (flooding_bridge_port_enable).
	    If disabled, incoming packets are dropped, if the MAC unicast
	    destination address is unknown.
	    - 0: Flooding enabled
	    - 1: Flooding disabled
	*/
	uint32_t uuc_flood_disable:1;
	/** Local switching enable (switching between UNI ports).
	    This setting controls the switching between LAN-side ports that are
	    connected to the same bridge. Local switching is never been done between
	    LAN-side bridge ports that are connected to different bridges.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t local_switching_enable:1;
	/** Enables duplicate MAC address detection and relearning prevention for a
	    bridge port (port locking). It is copied to all dynamic forwarding table
	    entries resulting from this ingress bridge port.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t port_lock_enable:1;
	/** Learning Enable.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t learning_enable:1;
#else
	/** Learning Enable.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t learning_enable:1;
	/** Enables duplicate MAC address detection and relearning prevention for a
	    bridge port (port locking). It is copied to all dynamic forwarding table
	    entries resulting from this ingress bridge port.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t port_lock_enable:1;
	/** Local switching enable (switching between UNI ports).
	    This setting controls the switching between LAN-side ports that are
	    connected to the same bridge. Local switching is never been done between
	    LAN-side bridge ports that are connected to different bridges.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t local_switching_enable:1;
	/** Unknown Unicast (uuc) Flooding Disable.
	    If this function is enabled, incoming packets with unknown MAC unicast
	    destination addresses are flooded according to the programmed flood map
	    of the related bridge (flooding_bridge_port_enable).
	    If disabled, incoming packets are dropped, if the MAC unicast
	    destination address is unknown.
	    - 0: Flooding enabled
	    - 1: Flooding disabled
	*/
	uint32_t uuc_flood_disable:1;
	/** Ingress VLAN tagging filter enable.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t tagging_filter_ingress_enable:1;
	/** Egress VLAN tagging filter enable.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t tagging_filter_egress_enable:1;
	/** Ingress Meter enable.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t meter_ingress_enable:1;
	/** Egress Meter enable.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t meter_egress_enable:1;
	/** Unknown Multicast (umc) Flooding Disable.
	    If this function is enabled, incoming packets with unknown MAC multicast
	    destination addresses are according to the programmed flood map of the
	    related bridge (flooding_bridge_port_enable).
	    If disabled, incoming packets are dropped, if the MAC multicast
	    destination address is unknown.
	    - 0: Flooding enabled
	    - 1: Flooding disabled
	*/
	uint32_t umc_flood_disable:1;
	/** Forwarding method.
	    - 0: Layer 2 - MAC address and VLAN (FID)
	    - 1: Layer 2 - MAC address only
	    - 2: Layer 2 - Hybrid mode (MAC&FID or FID cross connect, depending on
	    FID)
	    - 3: Layer 3 - IPv4, IPv6, or MPLS and VLAN (FID)
	    - 4: MDU - GEM port index (gpix)
	    - 5: VLAN Rule-based
	    - 6-15: Reserved for future releases
	*/
	uint32_t forwarding_method:4;
	/** Bridge index, values 0 to ONU_GPE_MAX_BRIDGES - 1 are valid. */
	uint32_t bridge_index:3;
	/** Unused data field, set to 0. */
	uint32_t unused2:1;
	/** Port state, values 0 to 2 are supported.
	    - 0: Forwarding
	    - 1: Learning
	    - 2: Discarding
	    - 3: Reserved (do not be use)
	*/
	uint32_t port_state:2;
	/** Ethernet MAC source address filter mode configuration.
	    - 00: Allow all
	    - 01: Reserved
	    - 10: Deny from specific MAC SA
	    - 11: Allow only specific MAC SA
	*/
	uint32_t sa_filter_mode:2;
	/** Ethernet MAC destination address filter mode configuration.
	    - 00: Allow all
	    - 01: Reserved
	    - 10: Deny for specific MAC DA
	    - 11: Allow only specific MAC DA
	*/
	uint32_t da_filter_mode:2;
	/** Ingress color marking mode, values 0 and 2 to 7 are valid. */
	uint32_t ingress_color_marking:3;
	/** Egress queue marking mode, values 0 to 7 are valid.
	    - 0: No marking
	    - 1: Internal marking by meter
	    - 2: DEI marking
	    - 3: PCP 8P0D marking
	    - 4: PCP 7P1D marking
	    - 5: PCP 6P2D marking
	    - 6: PCP 5P3D marking
	    - 7: DSCP marking
	*/
	uint32_t egress_color_marking:3;
	/** Unused data field, set to 0. */
	uint32_t unused3:3;
	/** Start pointer into the ONU_GPE_MAC_FILTER_TABLE. */
	uint32_t sa_filter_pointer:8;
	/** Start pointer into the ONU_GPE_MAC_FILTER_TABLE. */
	uint32_t da_filter_pointer:8;
	/** Ingress VLAN tagging filter, values 0 to
	    ONU_GPE_TAGGING_FILTER_TABLE_SIZE - 1 are valid. Points to an entry of
	    the ONU_GPE_TAGGING_FILTER_TABLE.
	*/
	uint32_t tagging_filter_ingress:7;
	/** Ingress dual token bucket meter selection, the upper 8 bit of this value
	    are used to address one of up to 256 meter units, the LSB must be set to
	    0.
	*/
	uint32_t meter_id_ingress:9;
	/** Egress VLAN tagging filter, values 0 to
	    ONU_GPE_TAGGING_FILTER_TABLE_SIZE - 1 are valid. Points to an entry of
	    the ONU_GPE_TAGGING_FILTER_TABLE.
	*/
	uint32_t tagging_filter_egress:7;
	/** Egress dual token bucket meter selection, the upper 8 bit of this value
	    are used to address one of up to 256 meter units, the LSB must be set to
	    0.
	*/
	uint32_t meter_id_egress:9;
	/** Egress filter mask to implement the MAC bridge port preassign table.
	    Each bit position is related to a certain traffic type.
	    - 0: IPv4 broadcast
	    - 1: IPv4 multicast
	    - 2: IPv6 multicast
	    - 3: PPPoE broadcast
	    - 4: AppleTalk
	    - 5: IPX
	    - 6: ARP
	    - 7: RARP
	    - 8: NetBEUI
	    - 9: BPDU
	*/
	uint32_t egress_filter_mask:10;
	/** Selects the decoding rule (1 of 8).
	    Used as MSB of the DSCP decoding table index.
	*/
	uint32_t dscp_table_pointer:3;
	/** Unused data field, set to 0. */
	uint32_t unused4:3;
	/** Defines the index of the connected Termination Point instance, which can
	    be.
	    - LAN Port index
	    - P-Mapper index
	    - ITP ID (GEM port index, gpix)
	*/
	uint32_t tp_pointer:8;
	/** TP Type, indicates the type of instance connected to the egress bridge
	    port. Values 0 to 3 are valid. The MSB of this field serves as the ANI
	    indication (1 = ANI side, 0 = UNI side).
	    - 0: PPTP Ethernet UNI
	    - 1: Reserved (do not use)
	    - 2: 802.1p-Mapper
	    - 3: ITP
	*/
	uint32_t tp_type:2;
	/** Unused data field, set to 0. */
	uint32_t unused5:21;
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
#endif
} __PACKED__;

/** ONU_GPE_TAGGING_FILTER_TABLE structure definition.
   Defines the ingress VLAN handling.
The index values used to access this table are the tagging_filter_ingress and the tagging_filter_egress pointers that are provided in the ONU_GPE_BRIDGE_PORT_TABLE.
The table instance value shall be set to 1.
*/
struct gpe_tagging_filter_table {
#if __BYTE_ORDER == __BIG_ENDIAN
	/** Unused data field, set to 0. */
	uint32_t unused1:11;
	/** Unused data field, set to 0. */
	uint32_t unused0:1;
	/** Pass on match enable.
	    - 0: Disabled, frames are passed only if no match is found. Matching
	    frames are dropped.
	    - 1: Enabled, only frames with matching table entries are passed.
	*/
	uint32_t pass_on_match_enable:1;
	/** Enable dropping of all tagged frames.
	    - 0: Disabled, tagged frames are passed according to the table lookup
	    result.
	    - 1: Enabled, all tagged frames are dropped, no table lookup is done.
	*/
	uint32_t tagged_drop_enable:1;
	/** Enable passing of all tagged frames.
	    - 0: Disabled, tagged frames are compared to table entries.
	    - 1: Enabled, all tagged frames are passed without table lookup.
	*/
	uint32_t tagged_pass_enable:1;
	/** This bit controls the handling of untagged frames.
	    The setting does not affect the handling of tagged frames.
	    - 0: Disabled, all untagged frames are passed.
	    - 1: Enabled, all untagged frames are dropped.
	*/
	uint32_t untagged_drop_enable:1;
	/** TCI mask, any 16-bit value is valid, useful values are.
	    - 0xFFFF: use all bits
	    - 0xEFFF: use VID and PCP (ignore DEI)
	    - 0x0FFF: use VID only (ignore PCP and DEI)
	    - 0xE000: use PCP only (ignore VID and DEI)
	*/
	uint32_t tci_mask:16;
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
	/** Unused data field, set to 0. */
	uint32_t unused3:1;
	/** VLAN table index, values 0 to ONU_GPE_VLAN_TABLE_SIZE - 1 are valid.
	    Points to an entry of the ONU_GPE_VLAN_TABLE.
	*/
	uint32_t vlan_table_index:14;
	/** Unused data field, set to 0. */
	uint32_t unused2:16;
#else
	/** TCI mask, any 16-bit value is valid, useful values are.
	    - 0xFFFF: use all bits
	    - 0xEFFF: use VID and PCP (ignore DEI)
	    - 0x0FFF: use VID only (ignore PCP and DEI)
	    - 0xE000: use PCP only (ignore VID and DEI)
	*/
	uint32_t tci_mask:16;
	/** This bit controls the handling of untagged frames.
	    The setting does not affect the handling of tagged frames.
	    - 0: Disabled, all untagged frames are passed.
	    - 1: Enabled, all untagged frames are dropped.
	*/
	uint32_t untagged_drop_enable:1;
	/** Enable passing of all tagged frames.
	    - 0: Disabled, tagged frames are compared to table entries.
	    - 1: Enabled, all tagged frames are passed without table lookup.
	*/
	uint32_t tagged_pass_enable:1;
	/** Enable dropping of all tagged frames.
	    - 0: Disabled, tagged frames are passed according to the table lookup
	    result.
	    - 1: Enabled, all tagged frames are dropped, no table lookup is done.
	*/
	uint32_t tagged_drop_enable:1;
	/** Pass on match enable.
	    - 0: Disabled, frames are passed only if no match is found. Matching
	    frames are dropped.
	    - 1: Enabled, only frames with matching table entries are passed.
	*/
	uint32_t pass_on_match_enable:1;
	/** Unused data field, set to 0. */
	uint32_t unused0:1;
	/** Unused data field, set to 0. */
	uint32_t unused1:11;
	/** Unused data field, set to 0. */
	uint32_t unused2:16;
	/** VLAN table index, values 0 to ONU_GPE_VLAN_TABLE_SIZE - 1 are valid.
	    Points to an entry of the ONU_GPE_VLAN_TABLE.
	*/
	uint32_t vlan_table_index:14;
	/** Unused data field, set to 0. */
	uint32_t unused3:1;
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
#endif
} __PACKED__;

/** ONU_GPE_VLAN_TABLE structure definition.
   This table holds VLAN definitions.
The index used to access this table is arbitrary, controlled by the VLAN add function.
The table instance value shall be set to 1.
*/
struct gpe_vlan_table {
#if __BYTE_ORDER == __BIG_ENDIAN
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
	/** End indication.
	    - 0: This is not the last entry.
	    - 1: This is the last entry.
	*/
	uint32_t end:1;
	/** Unused data field, set to 0. */
	uint32_t unused:14;
	/** VLAN tag.
	    Note: Values must be masked with TCI_Mask before entering.
	    - Bit 11 to 0: VLAN ID (VID)
	    - Bit 12: DEI
	    - Bit 15 to 13: PCP
	*/
	uint32_t tci:16;
#else
	/** VLAN tag.
	    Note: Values must be masked with TCI_Mask before entering.
	    - Bit 11 to 0: VLAN ID (VID)
	    - Bit 12: DEI
	    - Bit 15 to 13: PCP
	*/
	uint32_t tci:16;
	/** Unused data field, set to 0. */
	uint32_t unused:14;
	/** End indication.
	    - 0: This is not the last entry.
	    - 1: This is the last entry.
	*/
	uint32_t end:1;
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
#endif
} __PACKED__;

/** ONU_GPE_EXTENDED_VLAN_TABLE structure definition.
   This table contains the basic part of the Extended VLAN configuration.
The index used to access this table is the Extended VLAN rule set number.
The table instance value shall be set to 1.
*/
struct gpe_extended_vlan_table {
#if __BYTE_ORDER == __BIG_ENDIAN
	/** Output (egress) TPID value, any 16-bit value is valid. */
	uint32_t output_tpid:16;
	/** Input (ingress) TPID value, any 16-bit value is valid. */
	uint32_t input_tpid:16;
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
	/** Unused data field, set to 0. */
	uint32_t unused2:1;
	/** Rule table pointer, values 0 to ONU_GPE_VLAN_RULE_TABLE_SIZE - 1 are
	    valid. Selects an entry of the ONU_GPE_VLAN_RULE_TABLE.
	*/
	uint32_t vlan_rule_table_pointer:14;
	/** Unused data field, set to 0. */
	uint32_t unused1:13;
	/** DSCP decode table pointer, values 0 to ONU_GPE_DSCP_DECODING_TABLE_SIZE
	    - 1 are valid. Selects an entry of the ONU_GPE_DSCP_DECODING_TABLE.
	*/
	uint32_t dscp_table_pointer:3;
#else
	/** Input (ingress) TPID value, any 16-bit value is valid. */
	uint32_t input_tpid:16;
	/** Output (egress) TPID value, any 16-bit value is valid. */
	uint32_t output_tpid:16;
	/** DSCP decode table pointer, values 0 to ONU_GPE_DSCP_DECODING_TABLE_SIZE
	    - 1 are valid. Selects an entry of the ONU_GPE_DSCP_DECODING_TABLE.
	*/
	uint32_t dscp_table_pointer:3;
	/** Unused data field, set to 0. */
	uint32_t unused1:13;
	/** Rule table pointer, values 0 to ONU_GPE_VLAN_RULE_TABLE_SIZE - 1 are
	    valid. Selects an entry of the ONU_GPE_VLAN_RULE_TABLE.
	*/
	uint32_t vlan_rule_table_pointer:14;
	/** Unused data field, set to 0. */
	uint32_t unused2:1;
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
#endif
} __PACKED__;

/** ONU_GPE_VLAN_RULE_TABLE structure definition.
   This table contains the filtering part of the Extended VLAN rules.
The index used to access this table is the vlan_rule_index.
The table instance value shall be set to 1.
*/
struct gpe_vlan_rule_table {
#if __BYTE_ORDER == __BIG_ENDIAN
	/** Unused data field, set to 0. */
	uint32_t unused2:3;
	/** Outer DE filter value (0 or 1). */
	uint32_t outer_de_filter:1;
	/** Enable outer DE filtering.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t outer_de_enable:1;
	/** Unused data field, set to 0. */
	uint32_t outer_reg_tpid_enable:1;
	/** Enable outer input TPID filtering.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t outer_input_tpid_enable:1;
	/** Outer VID value, values 0 to 4095 are valid. */
	uint32_t outer_vid_filter:12;
	/** Enable outer VID filtering.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t outer_vid_enable:1;
	/** Outer VLAN priority (PCP), values 0 to 7 are valid. */
	uint32_t outer_priority_filter:3;
	/** Enable outer VLAN priority filtering.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t outer_priority_enable:1;
	/** Unused data field, set to 0. */
	uint32_t unused1:5;
	/** Select if the rule shall apply to double-tagged frames.
	    Note: Setting of zero_enable, one_enable, two_enable at the same time is
	    allowed.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t two_enable:1;
	/** Select if the rule shall apply to single-tagged frames.
	    Note: Setting of zero_enable, one_enable, two_enable at the same time is
	    allowed.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t one_enable:1;
	/** Select if the rule shall apply to untagged frames.
	    Note: Setting of zero_enable, one_enable, two_enable at the same time is
	    allowed.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t zero_enable:1;
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
	/** End indication for table handling.
	    - 0: This is not the last entry of the rule set.
	    - 1: This is the last entry of the rule set.
	*/
	uint32_t end:1;
	/** Select if this shall be a default rule.
	    - 0: Disabled (this is not a default rule)
	    - 1: Enabled (this is a default rule)
	*/
	uint32_t def:1;
	/** Unused data field, set to 0. */
	uint32_t unused3:1;
	/** Enable spare filter 2. Reserved for future use, set to 0. */
	uint32_t spare_filter2_enable:1;
	/** Enable spare filter 1. Reserved for future use, set to 0. */
	uint32_t spare_filter1_enable:1;
	/** Enable Ethertype filter 5. The rule applies, if the packet's Ethertype
	    matches the specified Ethertype value.
	    Default initialization: none (reserved).
	    Reserved for future use, set to 0.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t ethertype_filter5_enable:1;
	/** Enable Ethertype filter 4. The rule applies, if the packet's Ethertype
	    matches the specified Ethertype value.
	    Default initialization: 0x86DD (IPv6).
	    Attention: If more than one of the Ethertype filters is enabled, there
	    will never be a rule match.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t ethertype_filter4_enable:1;
	/** Enable Ethertype filter 3. The rule applies, if the packet's Ethertype
	    matches the specified Ethertype value.
	    Default initialization: 0x0806 (ARP).
	    Attention: If more than one of the Ethertype filters is enabled, there
	    will never be a rule match.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t ethertype_filter3_enable:1;
	/** Enable Ethertype filter 2. The rule applies, if the packet's Ethertype
	    matches one of the specified Ethertype values.
	    Default initialization: 0x8863 and 0x8864 (PPPoE).
	    Attention: If more than one of the Ethertype filters is enabled, there
	    will never be a rule match.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t ethertype_filter2_enable:1;
	/** Enable Ethertype filter 1. The rule applies, if the packet's Ethertype
	    matches the specified Ethertype value.
	    Default initialization: 0x0800 (IPv4).
	    Attention: If more than one of the Ethertype filters is enabled, there
	    will never be a rule match.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t ethertype_filter1_enable:1;
	/** Inner DE filter value (0 or 1). */
	uint32_t inner_de_filter:1;
	/** Enable inner DE filtering.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t inner_de_enable:1;
	/** Unused data field, set to 0. */
	uint32_t inner_reg_tpid_enable:1;
	/** Enable inner input TPID filtering.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t inner_input_tpid_enable:1;
	/** Inner VID value, values 0 to 4095 are valid. */
	uint32_t inner_vid_filter:12;
	/** Enable inner VID filtering.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t inner_vid_enable:1;
	/** Inner VLAN priority (PCP), values 0 to 7 are valid. */
	uint32_t inner_priority_filter:3;
	/** Enable inner VLAN priority filtering.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t inner_priority_enable:1;
#else
	/** Select if the rule shall apply to untagged frames.
	    Note: Setting of zero_enable, one_enable, two_enable at the same time is
	    allowed.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t zero_enable:1;
	/** Select if the rule shall apply to single-tagged frames.
	    Note: Setting of zero_enable, one_enable, two_enable at the same time is
	    allowed.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t one_enable:1;
	/** Select if the rule shall apply to double-tagged frames.
	    Note: Setting of zero_enable, one_enable, two_enable at the same time is
	    allowed.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t two_enable:1;
	/** Unused data field, set to 0. */
	uint32_t unused1:5;
	/** Enable outer VLAN priority filtering.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t outer_priority_enable:1;
	/** Outer VLAN priority (PCP), values 0 to 7 are valid. */
	uint32_t outer_priority_filter:3;
	/** Enable outer VID filtering.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t outer_vid_enable:1;
	/** Outer VID value, values 0 to 4095 are valid. */
	uint32_t outer_vid_filter:12;
	/** Enable outer input TPID filtering.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t outer_input_tpid_enable:1;
	/** Unused data field, set to 0. */
	uint32_t outer_reg_tpid_enable:1;
	/** Enable outer DE filtering.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t outer_de_enable:1;
	/** Outer DE filter value (0 or 1). */
	uint32_t outer_de_filter:1;
	/** Unused data field, set to 0. */
	uint32_t unused2:3;
	/** Enable inner VLAN priority filtering.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t inner_priority_enable:1;
	/** Inner VLAN priority (PCP), values 0 to 7 are valid. */
	uint32_t inner_priority_filter:3;
	/** Enable inner VID filtering.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t inner_vid_enable:1;
	/** Inner VID value, values 0 to 4095 are valid. */
	uint32_t inner_vid_filter:12;
	/** Enable inner input TPID filtering.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t inner_input_tpid_enable:1;
	/** Unused data field, set to 0. */
	uint32_t inner_reg_tpid_enable:1;
	/** Enable inner DE filtering.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t inner_de_enable:1;
	/** Inner DE filter value (0 or 1). */
	uint32_t inner_de_filter:1;
	/** Enable Ethertype filter 1. The rule applies, if the packet's Ethertype
	    matches the specified Ethertype value.
	    Default initialization: 0x0800 (IPv4).
	    Attention: If more than one of the Ethertype filters is enabled, there
	    will never be a rule match.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t ethertype_filter1_enable:1;
	/** Enable Ethertype filter 2. The rule applies, if the packet's Ethertype
	    matches one of the specified Ethertype values.
	    Default initialization: 0x8863 and 0x8864 (PPPoE).
	    Attention: If more than one of the Ethertype filters is enabled, there
	    will never be a rule match.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t ethertype_filter2_enable:1;
	/** Enable Ethertype filter 3. The rule applies, if the packet's Ethertype
	    matches the specified Ethertype value.
	    Default initialization: 0x0806 (ARP).
	    Attention: If more than one of the Ethertype filters is enabled, there
	    will never be a rule match.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t ethertype_filter3_enable:1;
	/** Enable Ethertype filter 4. The rule applies, if the packet's Ethertype
	    matches the specified Ethertype value.
	    Default initialization: 0x86DD (IPv6).
	    Attention: If more than one of the Ethertype filters is enabled, there
	    will never be a rule match.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t ethertype_filter4_enable:1;
	/** Enable Ethertype filter 5. The rule applies, if the packet's Ethertype
	    matches the specified Ethertype value.
	    Default initialization: none (reserved).
	    Reserved for future use, set to 0.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t ethertype_filter5_enable:1;
	/** Enable spare filter 1. Reserved for future use, set to 0. */
	uint32_t spare_filter1_enable:1;
	/** Enable spare filter 2. Reserved for future use, set to 0. */
	uint32_t spare_filter2_enable:1;
	/** Unused data field, set to 0. */
	uint32_t unused3:1;
	/** Select if this shall be a default rule.
	    - 0: Disabled (this is not a default rule)
	    - 1: Enabled (this is a default rule)
	*/
	uint32_t def:1;
	/** End indication for table handling.
	    - 0: This is not the last entry of the rule set.
	    - 1: This is the last entry of the rule set.
	*/
	uint32_t end:1;
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
#endif
} __PACKED__;

/** ONU_GPE_VLAN_TREATMENT_TABLE structure definition.
   This table contains the treatment part of the Extended VLAN rules.
The index used to access this table is the vlan_rule_index.
The table instance value shall be set to 1. "taga" refers to the outer VLAN tag (if tagged), "tagb" to the inner (if double-tagged).
Note: Treatments that imply the reception of two VLAN tags must not be called for rules that have (zero_enable == 1) or (one_enable == 1). Otherwise the treatment would result in unpredictable results.
*/
struct gpe_vlan_treatment_table {
#if __BYTE_ORDER == __BIG_ENDIAN
	/** Unused data field, set to 0. */
	uint32_t unused1:12;
	/** Inner TPID and DE treatment.
	    - 0: Keep the received inner TPID and DE value.
	    - 1: Use the received outer TPID and DE as the new inner TPID and DE
	    value.
	    - 2: Use the output_tpid as new inner TPID and keep the inner DE value.
	    - 3: Use the output_tpid as new inner TPID and use the received outer DE
	    value.
	    - 4: Set the inner TPID to 0x8100 and DE to 0.
	    - 6: Use the output_tpid as new inner TPID value, set inner DE to 0.
	    - 7: Use the output_tpid as new inner TPID value, set inner DE to 1.
	    - others: Not valid, do not use.
	*/
	uint32_t tagb_tpid_treatment:3;
	/** Inner VLAN ID treatment.
	    - 0 to 4094: Use this as the new inner VLAN ID.
	    - 4096: Use the received inner as the new inner VLAN ID.
	    - 4097: Use the received outer VLAN ID as the new inner VLAN ID.
	    - others: Reserved (do not use).
	*/
	uint32_t tagb_vid_treatment:13;
	/** Inner VLAN tag treatment.
	    - 0 to 7: Send the inner VLAN tag with PCP = 0 to 7.
	    - 8: Send the inner VLAN tag with the received inner PCP value (no
	    change).
	    - 9: Send the inner VLAN tag with the received outer PCP value (PCP
	    translation).
	    - 10: Send the inner VLAN tag with the PCP derived from the received
	    DSCP value (DSCP translation).
	    - 11 to 15: Do not send an inner VLAN tag.
	*/
	uint32_t tagb_treatment:4;
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
	/** Unused data field, set to 0. */
	uint32_t unused3:4;
	/** Remove the former inner VLAN (if present).
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t inner_not_generate:1;
	/** Remove the former outer VLAN (if present).
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t outer_not_generate:1;
	/** Discard the packet.
	    - 0: Disabled (do not discard).
	    - 1: Enabled (discard the packet).
	*/
	uint32_t discard_enable:1;
	/** Unused data field, set to 0. */
	uint32_t unused2:4;
	/** Outer TPID and DE treatment.
	    - 0: Use the received inner TPID and DE value as new outer TPID and DE.
	    - 1: Keep the received outer TPID and DE values.
	    - 2: Use the output_tpid as new outer TPID and copy the inner DE value.
	    - 3: Use the output_tpid as new outer TPID and keep the received outer
	    DE value.
	    - 4: Set the outer TPID to 0x8100 and DE to 0.
	    - 6: Use the output_tpid as new outer TPID value, set outer DE to 0.
	    - 7: Use the output_tpid as new outer TPID value, set outer DE to 1.
	    - others: Not valid (do not use).
	*/
	uint32_t taga_tpid_treatment:3;
	/** Inner VLAN ID treatment.
	    - 0 to 4094: Use this as the new outer VLAN ID.
	    - 4096: Use the received inner VLAN ID as the new outer VLAN ID (VLAN ID
	    translation).
	    - 4097: Use the received outer VLAN ID as the new outer VLAN ID.
	    - others: Reserved (do not use).
	*/
	uint32_t taga_vid_treatment:13;
	/** Outer VLAN tag Treatment.
	    - 0 to 7: Send the outer VLAN tag with PCP = 0 to 7.
	    - 8: Send the outer VLAN tag with the received inner PCP value (PCP
	    translation).
	    - 9: Send the outer VLAN tag with the received outer PCP value (no
	    change).
	    - 10: Send the outer VLAN tag with the PCP derived from the received
	    DSCP value (DSCP translation).
	    - 11 to 15: Do not send an outer VLAN tag.
	*/
	uint32_t taga_treatment:4;
#else
	/** Inner VLAN tag treatment.
	    - 0 to 7: Send the inner VLAN tag with PCP = 0 to 7.
	    - 8: Send the inner VLAN tag with the received inner PCP value (no
	    change).
	    - 9: Send the inner VLAN tag with the received outer PCP value (PCP
	    translation).
	    - 10: Send the inner VLAN tag with the PCP derived from the received
	    DSCP value (DSCP translation).
	    - 11 to 15: Do not send an inner VLAN tag.
	*/
	uint32_t tagb_treatment:4;
	/** Inner VLAN ID treatment.
	    - 0 to 4094: Use this as the new inner VLAN ID.
	    - 4096: Use the received inner as the new inner VLAN ID.
	    - 4097: Use the received outer VLAN ID as the new inner VLAN ID.
	    - others: Reserved (do not use).
	*/
	uint32_t tagb_vid_treatment:13;
	/** Inner TPID and DE treatment.
	    - 0: Keep the received inner TPID and DE value.
	    - 1: Use the received outer TPID and DE as the new inner TPID and DE
	    value.
	    - 2: Use the output_tpid as new inner TPID and keep the inner DE value.
	    - 3: Use the output_tpid as new inner TPID and use the received outer DE
	    value.
	    - 4: Set the inner TPID to 0x8100 and DE to 0.
	    - 6: Use the output_tpid as new inner TPID value, set inner DE to 0.
	    - 7: Use the output_tpid as new inner TPID value, set inner DE to 1.
	    - others: Not valid, do not use.
	*/
	uint32_t tagb_tpid_treatment:3;
	/** Unused data field, set to 0. */
	uint32_t unused1:12;
	/** Outer VLAN tag Treatment.
	    - 0 to 7: Send the outer VLAN tag with PCP = 0 to 7.
	    - 8: Send the outer VLAN tag with the received inner PCP value (PCP
	    translation).
	    - 9: Send the outer VLAN tag with the received outer PCP value (no
	    change).
	    - 10: Send the outer VLAN tag with the PCP derived from the received
	    DSCP value (DSCP translation).
	    - 11 to 15: Do not send an outer VLAN tag.
	*/
	uint32_t taga_treatment:4;
	/** Inner VLAN ID treatment.
	    - 0 to 4094: Use this as the new outer VLAN ID.
	    - 4096: Use the received inner VLAN ID as the new outer VLAN ID (VLAN ID
	    translation).
	    - 4097: Use the received outer VLAN ID as the new outer VLAN ID.
	    - others: Reserved (do not use).
	*/
	uint32_t taga_vid_treatment:13;
	/** Outer TPID and DE treatment.
	    - 0: Use the received inner TPID and DE value as new outer TPID and DE.
	    - 1: Keep the received outer TPID and DE values.
	    - 2: Use the output_tpid as new outer TPID and copy the inner DE value.
	    - 3: Use the output_tpid as new outer TPID and keep the received outer
	    DE value.
	    - 4: Set the outer TPID to 0x8100 and DE to 0.
	    - 6: Use the output_tpid as new outer TPID value, set outer DE to 0.
	    - 7: Use the output_tpid as new outer TPID value, set outer DE to 1.
	    - others: Not valid (do not use).
	*/
	uint32_t taga_tpid_treatment:3;
	/** Unused data field, set to 0. */
	uint32_t unused2:4;
	/** Discard the packet.
	    - 0: Disabled (do not discard).
	    - 1: Enabled (discard the packet).
	*/
	uint32_t discard_enable:1;
	/** Remove the former outer VLAN (if present).
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t outer_not_generate:1;
	/** Remove the former inner VLAN (if present).
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t inner_not_generate:1;
	/** Unused data field, set to 0. */
	uint32_t unused3:4;
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
#endif
} __PACKED__;

/** ONU_GPE_PMAPPER_TABLE structure definition.
   This table holds the 802.1p mapper configuration.
The index used to access this table is the pmapper_index.
The table instance value shall be set to.
- 0x01: for reading
- 0x3F: for write access.
*/
struct gpe_pmapper_table {
#if __BYTE_ORDER == __BIG_ENDIAN
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
	/** Unmarked frame option, selects what to do if the received packet is
	    untagged.
	    - 0: Use DSCP-to-PCP mapping
	    - 1: Use the default PCP value
	*/
	uint32_t unmarked_frame_option:1;
	/** 802.1p-mapper multicast meter enable.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t meter_pmapper_mcen:1;
	/** 802.1p-mapper broadcast meter enable.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t meter_pmapper_bcen:1;
	/** Unused data field, set to 0. */
	uint32_t unused3:4;
	/** 802.1p-mapper egress dual token bucket meter selection for multicast
	    traffic, the upper 8 bit of this value are used to address one of up to
	    256 meter units, the LSB must be set to 0.
	*/
	uint32_t meter_id_pmapper_mc:9;
	/** 802.1p-mapper egress dual token bucket meter selection for broadcast
	    traffic, the upper 8 bit of this value are used to address one of up to
	    256 meter units, the LSB must be set to 0.
	*/
	uint32_t meter_id_pmapper_bc:9;
	/** Default PCP priority code point (0 to 7). */
	uint32_t default_pcp:3;
	/** DSCP-to-PCP mapping table pointer, values 0 to
	    ONU_GPE_DSCP_DECODING_TABLE_SIZE - 1 are valid. Selects one of eight
	    mapping subsets (each subset has 64 3-bit entries).
	*/
	uint32_t dscp_table_pointer:3;
	/** GEM port index for PCP == 7, values 0 to ONU_GPE_US_GEM_PORT_TABLE_SIZE
	    - 1 are valid (gpix).
	*/
	uint32_t itp_id7:8;
	/** GEM port index for PCP == 6, values 0 to ONU_GPE_US_GEM_PORT_TABLE_SIZE
	    - 1 are valid (gpix).
	*/
	uint32_t itp_id6:8;
	/** GEM port index for PCP == 5, values 0 to ONU_GPE_US_GEM_PORT_TABLE_SIZE
	    - 1 are valid (gpix).
	*/
	uint32_t itp_id5:8;
	/** GEM port index for PCP == 4, values 0 to ONU_GPE_US_GEM_PORT_TABLE_SIZE
	    - 1 are valid (gpix).
	*/
	uint32_t itp_id4:8;
	/** GEM port index for PCP == 3, values 0 to ONU_GPE_US_GEM_PORT_TABLE_SIZE
	    - 1 are valid (gpix).
	*/
	uint32_t itp_id3:8;
	/** GEM port index for PCP == 2, values 0 to ONU_GPE_US_GEM_PORT_TABLE_SIZE
	    - 1 are valid (gpix).
	*/
	uint32_t itp_id2:8;
	/** GEM port index for PCP == 1, values 0 to ONU_GPE_US_GEM_PORT_TABLE_SIZE
	    - 1 are valid (gpix).
	*/
	uint32_t itp_id1:8;
	/** GEM port index for PCP == 0, values 0 to ONU_GPE_US_GEM_PORT_TABLE_SIZE
	    - 1 are valid (gpix).
	*/
	uint32_t itp_id0:8;
#else
	/** GEM port index for PCP == 0, values 0 to ONU_GPE_US_GEM_PORT_TABLE_SIZE
	    - 1 are valid (gpix).
	*/
	uint32_t itp_id0:8;
	/** GEM port index for PCP == 1, values 0 to ONU_GPE_US_GEM_PORT_TABLE_SIZE
	    - 1 are valid (gpix).
	*/
	uint32_t itp_id1:8;
	/** GEM port index for PCP == 2, values 0 to ONU_GPE_US_GEM_PORT_TABLE_SIZE
	    - 1 are valid (gpix).
	*/
	uint32_t itp_id2:8;
	/** GEM port index for PCP == 3, values 0 to ONU_GPE_US_GEM_PORT_TABLE_SIZE
	    - 1 are valid (gpix).
	*/
	uint32_t itp_id3:8;
	/** GEM port index for PCP == 4, values 0 to ONU_GPE_US_GEM_PORT_TABLE_SIZE
	    - 1 are valid (gpix).
	*/
	uint32_t itp_id4:8;
	/** GEM port index for PCP == 5, values 0 to ONU_GPE_US_GEM_PORT_TABLE_SIZE
	    - 1 are valid (gpix).
	*/
	uint32_t itp_id5:8;
	/** GEM port index for PCP == 6, values 0 to ONU_GPE_US_GEM_PORT_TABLE_SIZE
	    - 1 are valid (gpix).
	*/
	uint32_t itp_id6:8;
	/** GEM port index for PCP == 7, values 0 to ONU_GPE_US_GEM_PORT_TABLE_SIZE
	    - 1 are valid (gpix).
	*/
	uint32_t itp_id7:8;
	/** DSCP-to-PCP mapping table pointer, values 0 to
	    ONU_GPE_DSCP_DECODING_TABLE_SIZE - 1 are valid. Selects one of eight
	    mapping subsets (each subset has 64 3-bit entries).
	*/
	uint32_t dscp_table_pointer:3;
	/** Default PCP priority code point (0 to 7). */
	uint32_t default_pcp:3;
	/** 802.1p-mapper egress dual token bucket meter selection for broadcast
	    traffic, the upper 8 bit of this value are used to address one of up to
	    256 meter units, the LSB must be set to 0.
	*/
	uint32_t meter_id_pmapper_bc:9;
	/** 802.1p-mapper egress dual token bucket meter selection for multicast
	    traffic, the upper 8 bit of this value are used to address one of up to
	    256 meter units, the LSB must be set to 0.
	*/
	uint32_t meter_id_pmapper_mc:9;
	/** Unused data field, set to 0. */
	uint32_t unused3:4;
	/** 802.1p-mapper broadcast meter enable.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t meter_pmapper_bcen:1;
	/** 802.1p-mapper multicast meter enable.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t meter_pmapper_mcen:1;
	/** Unmarked frame option, selects what to do if the received packet is
	    untagged.
	    - 0: Use DSCP-to-PCP mapping
	    - 1: Use the default PCP value
	*/
	uint32_t unmarked_frame_option:1;
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
#endif
} __PACKED__;

/** ONU_GPE_SHORT_FWD_HASH_TABLE structure definition.
   This is the hash table related to the ONU_GPE_SHORT_FWD_TABLE_MAC(_MC).
No table access by the application software is needed.
*/
struct gpe_short_fwd_hash_table {
#if __BYTE_ORDER == __BIG_ENDIAN
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
	/** Unused data field, set to 0. */
	uint32_t unused2:1;
	/** Start pointer to the ONU_GPE_SHORT_FWD_TABLE_xxx. */
	uint32_t fwd_table_pointer:14;
	/** Unused data field, set to 0. */
	uint32_t unused1:16;
#else
	/** Unused data field, set to 0. */
	uint32_t unused1:16;
	/** Start pointer to the ONU_GPE_SHORT_FWD_TABLE_xxx. */
	uint32_t fwd_table_pointer:14;
	/** Unused data field, set to 0. */
	uint32_t unused2:1;
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
#endif
} __PACKED__;

/** ONU_GPE_SHORT_FWD_TABLE_MAC structure definition.
   Layer-2 unicast forwarding table, separate entries are provided for upstream and downstream data traffic.
The table instance value shall be set to 1.
*/
struct gpe_short_fwd_table_mac {
#if __BYTE_ORDER == __BIG_ENDIAN
	/** Lower part of the layer-2 MAC address, any value is valid. */
	uint32_t mac_address_low:32;
	/** Key type, defines the kind of key to be used for table access.
	    - 0: Layer 2 Ethernet & VLAN (unicast MAC DA & FID). Uses the default
	    FID for untagged packet forwarding.
	    - 1: Layer 2 Ethernet only (unicast MAC DA).
	    - 2: Layer 2 Hybrid Ethernet and VLAN forwarding.
	    - 4: IPv4 (only used for ONU_GPE_SHORT_FWD_TABLE_IPV4).
	    - 6: IPv6 (only used for ONU_GPE_LONG_FWD_TABLE_IPV6).
	    - 8: GEM port index based forwarding (gpix).
	    - 9: Rule-based forwarding
	    - others: Reserved (do not use).
	*/
	uint32_t key_code:4;
	/** Unused data field, set to 0. */
	uint32_t unused1:1;
	/** Bridge index, values 0 to ONU_GPE_MAX_BRIDGES - 1 are valid. Points to
	    an entry of the ONU_GPE_BRIDGE_TABLE.
	*/
	uint32_t bridge_index:3;
	/** Forwarding ID, values 0 to ONU_GPE_FWD_ID_TABLE_SIZE - 1 are valid.
	    Points to an entry of the ONU_GPE_FWD_ID_TABLE.
	*/
	uint32_t fid:8;
	/** Higher part of the layer-2 MAC address, values from 0x0000 to 0x00FF are
	    valid.
	*/
	uint32_t mac_address_high:16;
	/** Learning time stamp, values from 0 to 255 are valid. */
	uint32_t learning_time_stamp:8;
	/** Unused data field, set to 0. */
	uint32_t unused3:3;
	/** Dummy field for Encapsulation Index of UC IP tables. */
	uint32_t dummy_encapsulation_index:9;
	/** Unused data field, set to 0. */
	uint32_t unused2:1;
	/** Dynamic or static entry mode.
	    - 0: Static
	    - 1: Dynamic
	*/
	uint32_t dynamic_enable:1;
	/** Indicates whether this entry is subject to limitation.
	    - 0: No limitation
	    - 1: Limitation
	*/
	uint32_t limitation:1;
	/** Forwarding activity.
	    - 0: Entry not used for forwarding since last check
	    - 1: Entry used for forwarding since last check
	    This bit is reset by SW after activity check and is set by microcode
	    during forwarding of a frame.
	*/
	uint32_t activity:1;
	/** Set always to zero. Indicates that bits 70:64 identify an egress bridge
	    port.
	*/
	uint32_t zero_port_map_indicator:1;
	/** Egress bridge port ID, values 0 to ONU_GPE_BRIDGE_PORT_TABLE_SIZE - 1
	    are valid. Points to an entry of the ONU_GPE_BRIDGE_PORT_TABLE.
	*/
	uint32_t bridge_port_index:7;
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
	/** End indication, marks if is the last entry of a sequence of entries that
	    are identified by the same hash value.
	    - 0: This is not the last entry.
	    - 1: This is the last entry.
	*/
	uint32_t end:1;
	/** Next entry pointer, values 0 to ONU_GPE_FWD_ID_TABLE_SIZE - 1 are valid.
	    This value points to the next entry that is identified by the same hash
	    value (next bucket).
	*/
	uint32_t next_entry:14;
	/** Unused data field, set to 0. */
	uint32_t unused4:16;
#else
	/** Lower part of the layer-2 MAC address, any value is valid. */
	uint32_t mac_address_low:32;
	/** Higher part of the layer-2 MAC address, values from 0x0000 to 0x00FF are
	    valid.
	*/
	uint32_t mac_address_high:16;
	/** Forwarding ID, values 0 to ONU_GPE_FWD_ID_TABLE_SIZE - 1 are valid.
	    Points to an entry of the ONU_GPE_FWD_ID_TABLE.
	*/
	uint32_t fid:8;
	/** Bridge index, values 0 to ONU_GPE_MAX_BRIDGES - 1 are valid. Points to
	    an entry of the ONU_GPE_BRIDGE_TABLE.
	*/
	uint32_t bridge_index:3;
	/** Unused data field, set to 0. */
	uint32_t unused1:1;
	/** Key type, defines the kind of key to be used for table access.
	    - 0: Layer 2 Ethernet & VLAN (unicast MAC DA & FID). Uses the default
	    FID for untagged packet forwarding.
	    - 1: Layer 2 Ethernet only (unicast MAC DA).
	    - 2: Layer 2 Hybrid Ethernet and VLAN forwarding.
	    - 4: IPv4 (only used for ONU_GPE_SHORT_FWD_TABLE_IPV4).
	    - 6: IPv6 (only used for ONU_GPE_LONG_FWD_TABLE_IPV6).
	    - 8: GEM port index based forwarding (gpix).
	    - 9: Rule-based forwarding
	    - others: Reserved (do not use).
	*/
	uint32_t key_code:4;
	/** Egress bridge port ID, values 0 to ONU_GPE_BRIDGE_PORT_TABLE_SIZE - 1
	    are valid. Points to an entry of the ONU_GPE_BRIDGE_PORT_TABLE.
	*/
	uint32_t bridge_port_index:7;
	/** Set always to zero. Indicates that bits 70:64 identify an egress bridge
	    port.
	*/
	uint32_t zero_port_map_indicator:1;
	/** Forwarding activity.
	    - 0: Entry not used for forwarding since last check
	    - 1: Entry used for forwarding since last check
	    This bit is reset by SW after activity check and is set by microcode
	    during forwarding of a frame.
	*/
	uint32_t activity:1;
	/** Indicates whether this entry is subject to limitation.
	    - 0: No limitation
	    - 1: Limitation
	*/
	uint32_t limitation:1;
	/** Dynamic or static entry mode.
	    - 0: Static
	    - 1: Dynamic
	*/
	uint32_t dynamic_enable:1;
	/** Unused data field, set to 0. */
	uint32_t unused2:1;
	/** Dummy field for Encapsulation Index of UC IP tables. */
	uint32_t dummy_encapsulation_index:9;
	/** Unused data field, set to 0. */
	uint32_t unused3:3;
	/** Learning time stamp, values from 0 to 255 are valid. */
	uint32_t learning_time_stamp:8;
	/** Unused data field, set to 0. */
	uint32_t unused4:16;
	/** Next entry pointer, values 0 to ONU_GPE_FWD_ID_TABLE_SIZE - 1 are valid.
	    This value points to the next entry that is identified by the same hash
	    value (next bucket).
	*/
	uint32_t next_entry:14;
	/** End indication, marks if is the last entry of a sequence of entries that
	    are identified by the same hash value.
	    - 0: This is not the last entry.
	    - 1: This is the last entry.
	*/
	uint32_t end:1;
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
#endif
} __PACKED__;

/** ONU_GPE_SHORT_FWD_TABLE_MAC_MC structure definition.
   Layer-2 multicast forwarding table.
The table instance value shall be set to 1.
*/
struct gpe_short_fwd_table_mac_mc {
#if __BYTE_ORDER == __BIG_ENDIAN
	/** Lower part of the layer-2 MAC address, any value is valid. */
	uint32_t mac_address_low:32;
	/** Key type, defines the kind of key to be used for table access.
	    For code point definition, see the description of the
	    ONU_GPE_SHORT_FWD_TABLE_MAC.
	*/
	uint32_t key_code:4;
	/** Unused data field, set to 0. */
	uint32_t unused1:1;
	/** Bridge index, values 0 to ONU_GPE_MAX_BRIDGES - 1 are valid. Points to
	    an entry of the ONU_GPE_BRIDGE_TABLE.
	*/
	uint32_t bridge_index:3;
	/** Forwarding ID, values 0 to ONU_GPE_FWD_ID_TABLE_SIZE - 1 are valid. */
	uint32_t fid:8;
	/** Higher part of the layer-2 MAC address, values from 0x0000 to 0x00FF are
	    valid.
	*/
	uint32_t mac_address_high:16;
	/** Dummy field for the learning time stamp, set to 0. */
	uint32_t dummy_learning_time_stamp:8;
	/** Unused data field, set to 0. */
	uint32_t unused2:2;
	/** Multicast entry source indication flag.
	    - 0: The entry has been created by OMCI and shall not be deleted by
	    IGMP.
	    - 1: The entry has been created by IGMP and may be deleted by IGMP.
	*/
	uint32_t igmp:1;
	/** Downstream source filter pointer, values 0 to
	    ONU_GPE_DS_MC_IPV4_SOURCE_FILTER_TABLE_SIZE - 1 are valid
	*/
	uint32_t source_filter_pointer:9;
	/** IGMPv3/MLDv2 Multicast Source Filtering (MSF) enable.
	    - 0: IGMPv2/MLDv1 (no source filtering)
	    - 1: IGMPv3/MLDv2 (source filtering is enabled)
	*/
	uint32_t msf_enable:1;
	/** Dynamic or static entry mode.
	    - 0: Static
	    - 1: Dynamic
	    Multicast entries shall always be static.
	*/
	uint32_t dynamic_enable:1;
	/** Always set to zero. Indicates that this entry is not subject to
	    limitation.
	*/
	uint32_t zero_limitation:1;
	/** Forwarding activity.
	    - 0: Entry not used for forwarding since last check
	    - 1: Entry used for forwarding since last check
	    This bit is reset by SW after activity check and is set by microcode
	    during forwarding of a frame.
	*/
	uint32_t activity:1;
	/** Set to one always. Indicates that bits 96:111 contain a port map. */
	uint32_t one_port_map_indicator:1;
	/** Include Enable Port Map for IP Multicast Source Filtering mode.
	    - 0: Exclude a matching frame from multicasting on this port.
	    - 1: Include a matching frame on this port.
	    The bit position is related to egress_bridge_port_index0 to
	    egress_bridge_port_index3 in ONU_GPE_BRIDGE_TABLE (see example below).
	    Bits 4/5/6 are unused.
	    - Bit 0: UNI port 0.
	    - Bit 1: UNI Port 1.
	    - Bit 2: UNI port 2.
	    - Bit 3: UNI port 3.
	*/
	uint32_t include_enable:7;
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
	/** End indication, marks if is the last entry of a sequence of entries that
	    are identified by the same hash value.
	    - 0: This is not the last entry.
	    - 1: This is the last entry.
	*/
	uint32_t end:1;
	/** Next entry pointer, values 0 to ONU_GPE_IPV4_MC_GROUP_TABLE_SIZE - 1 are
	    valid. This value points to the next entry that is identified by the
	    same hash value (next bucket).
	*/
	uint32_t next_entry:14;
	/** Multicast port map.
	    - 0: Do not forward to this bridge port.
	    - 1: Send a copy to this bridge port.
	    The bit positions are related to the configuration of
	    egress_bridge_port_index0 to egress_bridge_port_index15 in the
	    ONU_GPE_BRIDGE_TABLE.
	*/
	uint32_t port_map:16;
#else
	/** Lower part of the layer-2 MAC address, any value is valid. */
	uint32_t mac_address_low:32;
	/** Higher part of the layer-2 MAC address, values from 0x0000 to 0x00FF are
	    valid.
	*/
	uint32_t mac_address_high:16;
	/** Forwarding ID, values 0 to ONU_GPE_FWD_ID_TABLE_SIZE - 1 are valid. */
	uint32_t fid:8;
	/** Bridge index, values 0 to ONU_GPE_MAX_BRIDGES - 1 are valid. Points to
	    an entry of the ONU_GPE_BRIDGE_TABLE.
	*/
	uint32_t bridge_index:3;
	/** Unused data field, set to 0. */
	uint32_t unused1:1;
	/** Key type, defines the kind of key to be used for table access.
	    For code point definition, see the description of the
	    ONU_GPE_SHORT_FWD_TABLE_MAC.
	*/
	uint32_t key_code:4;
	/** Include Enable Port Map for IP Multicast Source Filtering mode.
	    - 0: Exclude a matching frame from multicasting on this port.
	    - 1: Include a matching frame on this port.
	    The bit position is related to egress_bridge_port_index0 to
	    egress_bridge_port_index3 in ONU_GPE_BRIDGE_TABLE (see example below).
	    Bits 4/5/6 are unused.
	    - Bit 0: UNI port 0.
	    - Bit 1: UNI Port 1.
	    - Bit 2: UNI port 2.
	    - Bit 3: UNI port 3.
	*/
	uint32_t include_enable:7;
	/** Set to one always. Indicates that bits 96:111 contain a port map. */
	uint32_t one_port_map_indicator:1;
	/** Forwarding activity.
	    - 0: Entry not used for forwarding since last check
	    - 1: Entry used for forwarding since last check
	    This bit is reset by SW after activity check and is set by microcode
	    during forwarding of a frame.
	*/
	uint32_t activity:1;
	/** Always set to zero. Indicates that this entry is not subject to
	    limitation.
	*/
	uint32_t zero_limitation:1;
	/** Dynamic or static entry mode.
	    - 0: Static
	    - 1: Dynamic
	    Multicast entries shall always be static.
	*/
	uint32_t dynamic_enable:1;
	/** IGMPv3/MLDv2 Multicast Source Filtering (MSF) enable.
	    - 0: IGMPv2/MLDv1 (no source filtering)
	    - 1: IGMPv3/MLDv2 (source filtering is enabled)
	*/
	uint32_t msf_enable:1;
	/** Downstream source filter pointer, values 0 to
	    ONU_GPE_DS_MC_IPV4_SOURCE_FILTER_TABLE_SIZE - 1 are valid
	*/
	uint32_t source_filter_pointer:9;
	/** Multicast entry source indication flag.
	    - 0: The entry has been created by OMCI and shall not be deleted by
	    IGMP.
	    - 1: The entry has been created by IGMP and may be deleted by IGMP.
	*/
	uint32_t igmp:1;
	/** Unused data field, set to 0. */
	uint32_t unused2:2;
	/** Dummy field for the learning time stamp, set to 0. */
	uint32_t dummy_learning_time_stamp:8;
	/** Multicast port map.
	    - 0: Do not forward to this bridge port.
	    - 1: Send a copy to this bridge port.
	    The bit positions are related to the configuration of
	    egress_bridge_port_index0 to egress_bridge_port_index15 in the
	    ONU_GPE_BRIDGE_TABLE.
	*/
	uint32_t port_map:16;
	/** Next entry pointer, values 0 to ONU_GPE_IPV4_MC_GROUP_TABLE_SIZE - 1 are
	    valid. This value points to the next entry that is identified by the
	    same hash value (next bucket).
	*/
	uint32_t next_entry:14;
	/** End indication, marks if is the last entry of a sequence of entries that
	    are identified by the same hash value.
	    - 0: This is not the last entry.
	    - 1: This is the last entry.
	*/
	uint32_t end:1;
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
#endif
} __PACKED__;

/** ONU_GPE_SHORT_FWD_TABLE_IPV4 structure definition.
   Layer-3 unicast forwarding table, separate entries are provided for upstream and downstream data traffic.
The table instance value shall be set to 1.
*/
struct gpe_short_fwd_table_ipv4 {
#if __BYTE_ORDER == __BIG_ENDIAN
	/** Unicast IPv4 address, all values are valid. */
	uint32_t ip_address:32;
	/** Key type, defines the kind of key to be used for table access.
	    For code point definition, see the description of the
	    ONU_GPE_SHORT_FWD_TABLE_MAC.
	*/
	uint32_t key_code:4;
	/** Unused data field, set to 0. */
	uint32_t unused2:1;
	/** Bridge index, values 0 to ONU_GPE_MAX_BRIDGES - 1 are valid. Points to
	    an entry of the ONU_GPE_BRIDGE_TABLE.
	*/
	uint32_t bridge_index:3;
	/** Forwarding ID, values 0 to ONU_GPE_FWD_ID_TABLE_SIZE - 1 are valid. Can
	    also be used as GEM Port Index (GPIX), depending on the key type.
	*/
	uint32_t fid:8;
	/** Unused data field, set to 0. */
	uint32_t unused1:16;
	/** Dummy field for learning timestamp of unicast MAC address entries. */
	uint32_t dummy_learning_time_stamp:8;
	/** Unused data field, set to 0. */
	uint32_t unused4:3;
	/** Used for direct IPv4 or MPLS over GEM handling. Points to an entry of
	    the NAPT table, which defines the layer-2 header to be applied. This
	    entry is ignored, if NAPT is not supported.
	*/
	uint32_t encapsulation_index:9;
	/** Unused data field, set to 0. */
	uint32_t unused3:1;
	/** Dynamic or static entry mode, always set to 0 (IPv4 unicast table
	    entries shall always be static).
	*/
	uint32_t zero_dynamic_enable:1;
	/** Always set to zero. Indicates that this entry is not subject to
	    limitation.
	*/
	uint32_t zero_limitation:1;
	/** Forwarding activity.
	    This bit is reset by SW after activity check and is set by microcode
	    during forwarding of a frame.
	    - 0: Entry not used for forwarding since last check.
	    - 1: Entry used for forwarding since last check.
	*/
	uint32_t activity:1;
	/** Set to zero always. Indicates that bits 70:64 identify an egress bridge
	    port.
	*/
	uint32_t zero_port_map_indicator:1;
	/** Egress bridge port index, values 0 to ONU_GPE_BRIDGE_PORT_TABLE_SIZE - 1
	    are valid. Points to an entry of the ONU_GPE_BRIDGE_PORT_TABLE.
	*/
	uint32_t bridge_port_index:7;
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
	/** End indication, marks if is the last entry of a sequence of entries that
	    are identified by the same hash value.
	    - 0: This is not the last entry.
	    - 1: This is the last entry.
	*/
	uint32_t end:1;
	/** Next entry pointer, values 0 to ONU_GPE_FWD_ID_TABLE_SIZE - 1 are valid.
	    This value points to the next entry that is identified by the same hash
	    value (next bucket).
	*/
	uint32_t next_entry:14;
	/** Unused data field, set to 0. */
	uint32_t unused5:16;
#else
	/** Unicast IPv4 address, all values are valid. */
	uint32_t ip_address:32;
	/** Unused data field, set to 0. */
	uint32_t unused1:16;
	/** Forwarding ID, values 0 to ONU_GPE_FWD_ID_TABLE_SIZE - 1 are valid. Can
	    also be used as GEM Port Index (GPIX), depending on the key type.
	*/
	uint32_t fid:8;
	/** Bridge index, values 0 to ONU_GPE_MAX_BRIDGES - 1 are valid. Points to
	    an entry of the ONU_GPE_BRIDGE_TABLE.
	*/
	uint32_t bridge_index:3;
	/** Unused data field, set to 0. */
	uint32_t unused2:1;
	/** Key type, defines the kind of key to be used for table access.
	    For code point definition, see the description of the
	    ONU_GPE_SHORT_FWD_TABLE_MAC.
	*/
	uint32_t key_code:4;
	/** Egress bridge port index, values 0 to ONU_GPE_BRIDGE_PORT_TABLE_SIZE - 1
	    are valid. Points to an entry of the ONU_GPE_BRIDGE_PORT_TABLE.
	*/
	uint32_t bridge_port_index:7;
	/** Set to zero always. Indicates that bits 70:64 identify an egress bridge
	    port.
	*/
	uint32_t zero_port_map_indicator:1;
	/** Forwarding activity.
	    This bit is reset by SW after activity check and is set by microcode
	    during forwarding of a frame.
	    - 0: Entry not used for forwarding since last check.
	    - 1: Entry used for forwarding since last check.
	*/
	uint32_t activity:1;
	/** Always set to zero. Indicates that this entry is not subject to
	    limitation.
	*/
	uint32_t zero_limitation:1;
	/** Dynamic or static entry mode, always set to 0 (IPv4 unicast table
	    entries shall always be static).
	*/
	uint32_t zero_dynamic_enable:1;
	/** Unused data field, set to 0. */
	uint32_t unused3:1;
	/** Used for direct IPv4 or MPLS over GEM handling. Points to an entry of
	    the NAPT table, which defines the layer-2 header to be applied. This
	    entry is ignored, if NAPT is not supported.
	*/
	uint32_t encapsulation_index:9;
	/** Unused data field, set to 0. */
	uint32_t unused4:3;
	/** Dummy field for learning timestamp of unicast MAC address entries. */
	uint32_t dummy_learning_time_stamp:8;
	/** Unused data field, set to 0. */
	uint32_t unused5:16;
	/** Next entry pointer, values 0 to ONU_GPE_FWD_ID_TABLE_SIZE - 1 are valid.
	    This value points to the next entry that is identified by the same hash
	    value (next bucket).
	*/
	uint32_t next_entry:14;
	/** End indication, marks if is the last entry of a sequence of entries that
	    are identified by the same hash value.
	    - 0: This is not the last entry.
	    - 1: This is the last entry.
	*/
	uint32_t end:1;
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
#endif
} __PACKED__;

/** ONU_GPE_SHORT_FWD_TABLE_IPV4_MC structure definition.
   Layer-3 multicast forwarding table.
The table instance value shall be set to 1.
*/
struct gpe_short_fwd_table_ipv4_mc {
#if __BYTE_ORDER == __BIG_ENDIAN
	/** Multicast IPv4 address, all values are valid. */
	uint32_t ip_address:32;
	/** Key type, defines the kind of key to be used for table access.
	    For code point definition, see the description of the
	    ONU_GPE_SHORT_FWD_TABLE_MAC.
	*/
	uint32_t key_code:4;
	/** Unused data field, set to 0. */
	uint32_t unused2:1;
	/** Bridge index, values 0 to ONU_GPE_MAX_BRIDGES - 1 are valid. Points to
	    an entry of the ONU_GPE_BRIDGE_TABLE.
	*/
	uint32_t bridge_index:3;
	/** Forwarding ID, values 0 to ONU_GPE_FWD_ID_TABLE_SIZE - 1 are valid. Can
	    also be used as GEM Port Index (GPIX), depending on the key type.
	*/
	uint32_t fid:8;
	/** Unused data field, set to 0. */
	uint32_t unused1:16;
	/** Dummy field for learning timestamp of unicast MAC address entries. */
	uint32_t dummy_learning_time_stamp:8;
	/** Unused data field, set to 0. */
	uint32_t unused3:2;
	/** Multicast entry source indication flag.
	    - 0: The entry has been created by OMCI and shall not be deleted by
	    IGMP.
	    - 1: The entry has been created by IGMP and may be deleted by IGMP.
	*/
	uint32_t igmp:1;
	/** IP Multicast Source Filtering pointer, values
	    0 to ONU_GPE_DS_MC_IPV4_SOURCE_FILTER_TABLE_SIZE - 1 or
	    0 to ONU_GPE_DS_MC_IPV6_SOURCE_FILTER_TABLE_SIZE - 1
	    are valid (depends on whether IPv4 or IPv6 is received).
	*/
	uint32_t source_filter_pointer:9;
	/** IGMPv3 source filtering enable.
	    - 0: IGMPv2 (no source filtering).
	    - 1: IGMPv3 (source filtering is enabled).
	*/
	uint32_t msf_enable:1;
	/** Dynamic or static entry mode:
	    Always set to
	    - 0: Static
	    IPv4 multicast table entries shall always be static.
	*/
	uint32_t zero_dynamic_enable:1;
	/** Always set to zero. Indicates that this entry is not subject to
	    limitation.
	*/
	uint32_t zero_limitation:1;
	/** Forwarding activity.
	    - 0: Entry not used for forwarding since last check
	    - 1: Entry used for forwarding since last check
	    This bit is reset by SW after activity check and is set by microcode
	    during forwarding of a frame.
	*/
	uint32_t activity:1;
	/** Set to one always. Indicates that bits 111:96 contain a port map. */
	uint32_t one_port_map_indicator:1;
	/** Include Enable Port Map for IP Multicast Source Filtering mode.
	    The bit position is related to egress_bridge_port_index0 to
	    egress_bridge_port_index3 in ONU_GPE_BRIDGE_TABLE (see example below).
	    Bits 4/5/6 are unused.
	    - 0: Exclude a matching frame from multicasting on this port.
	    - 1: Include a matching frame on this port.
	    - Bit 0: UNI port 0.
	    - Bit 1: UNI Port 1.
	    - Bit 2: UNI port 2.
	    - Bit 3: UNI port 3.
	*/
	uint32_t include_enable:7;
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
	/** End indication, marks if is the last entry of a sequence of entries that
	    are identified by the same hash value.
	    - 0: This is not the last entry.
	    - 1: This is the last entry.
	*/
	uint32_t end:1;
	/** Next entry pointer, values 0 to ONU_GPE_IPV4_MC_GROUP_TABLE_SIZE - 1 are
	    valid. This value points to the next entry that is identified by the
	    same hash value (next bucket).
	*/
	uint32_t next_entry:14;
	/** Multicast port map.
	    The bit positions are related to the configuration of
	    egress_bridge_port_index0 to egress_bridge_port_index15 in the
	    ONU_GPE_BRIDGE_TABLE.
	    - 0: Do not forward to this bridge port.
	    - 1: Send a copy to this bridge port.
	*/
	uint32_t port_map:16;
#else
	/** Multicast IPv4 address, all values are valid. */
	uint32_t ip_address:32;
	/** Unused data field, set to 0. */
	uint32_t unused1:16;
	/** Forwarding ID, values 0 to ONU_GPE_FWD_ID_TABLE_SIZE - 1 are valid. Can
	    also be used as GEM Port Index (GPIX), depending on the key type.
	*/
	uint32_t fid:8;
	/** Bridge index, values 0 to ONU_GPE_MAX_BRIDGES - 1 are valid. Points to
	    an entry of the ONU_GPE_BRIDGE_TABLE.
	*/
	uint32_t bridge_index:3;
	/** Unused data field, set to 0. */
	uint32_t unused2:1;
	/** Key type, defines the kind of key to be used for table access.
	    For code point definition, see the description of the
	    ONU_GPE_SHORT_FWD_TABLE_MAC.
	*/
	uint32_t key_code:4;
	/** Include Enable Port Map for IP Multicast Source Filtering mode.
	    The bit position is related to egress_bridge_port_index0 to
	    egress_bridge_port_index3 in ONU_GPE_BRIDGE_TABLE (see example below).
	    Bits 4/5/6 are unused.
	    - 0: Exclude a matching frame from multicasting on this port.
	    - 1: Include a matching frame on this port.
	    - Bit 0: UNI port 0.
	    - Bit 1: UNI Port 1.
	    - Bit 2: UNI port 2.
	    - Bit 3: UNI port 3.
	*/
	uint32_t include_enable:7;
	/** Set to one always. Indicates that bits 111:96 contain a port map. */
	uint32_t one_port_map_indicator:1;
	/** Forwarding activity.
	    - 0: Entry not used for forwarding since last check
	    - 1: Entry used for forwarding since last check
	    This bit is reset by SW after activity check and is set by microcode
	    during forwarding of a frame.
	*/
	uint32_t activity:1;
	/** Always set to zero. Indicates that this entry is not subject to
	    limitation.
	*/
	uint32_t zero_limitation:1;
	/** Dynamic or static entry mode:
	    Always set to
	    - 0: Static
	    IPv4 multicast table entries shall always be static.
	*/
	uint32_t zero_dynamic_enable:1;
	/** IGMPv3 source filtering enable.
	    - 0: IGMPv2 (no source filtering).
	    - 1: IGMPv3 (source filtering is enabled).
	*/
	uint32_t msf_enable:1;
	/** IP Multicast Source Filtering pointer, values
	    0 to ONU_GPE_DS_MC_IPV4_SOURCE_FILTER_TABLE_SIZE - 1 or
	    0 to ONU_GPE_DS_MC_IPV6_SOURCE_FILTER_TABLE_SIZE - 1
	    are valid (depends on whether IPv4 or IPv6 is received).
	*/
	uint32_t source_filter_pointer:9;
	/** Multicast entry source indication flag.
	    - 0: The entry has been created by OMCI and shall not be deleted by
	    IGMP.
	    - 1: The entry has been created by IGMP and may be deleted by IGMP.
	*/
	uint32_t igmp:1;
	/** Unused data field, set to 0. */
	uint32_t unused3:2;
	/** Dummy field for learning timestamp of unicast MAC address entries. */
	uint32_t dummy_learning_time_stamp:8;
	/** Multicast port map.
	    The bit positions are related to the configuration of
	    egress_bridge_port_index0 to egress_bridge_port_index15 in the
	    ONU_GPE_BRIDGE_TABLE.
	    - 0: Do not forward to this bridge port.
	    - 1: Send a copy to this bridge port.
	*/
	uint32_t port_map:16;
	/** Next entry pointer, values 0 to ONU_GPE_IPV4_MC_GROUP_TABLE_SIZE - 1 are
	    valid. This value points to the next entry that is identified by the
	    same hash value (next bucket).
	*/
	uint32_t next_entry:14;
	/** End indication, marks if is the last entry of a sequence of entries that
	    are identified by the same hash value.
	    - 0: This is not the last entry.
	    - 1: This is the last entry.
	*/
	uint32_t end:1;
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
#endif
} __PACKED__;

/** ONU_GPE_LONG_FWD_HASH_TABLE structure definition.
   This is the hash table related to the ONU_GPE_LONG_FWD_TABLE_IPV6(_MC).
No table access by the application software is needed.
*/
struct gpe_long_fwd_hash_table {
#if __BYTE_ORDER == __BIG_ENDIAN
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
	/** Unused data field, set to 0. */
	uint32_t unused2:1;
	/** Start pointer to the ONU_GPE_LONG_FWD_TABLE_xxx. */
	uint32_t fwd_table_pointer:14;
	/** Unused data field, set to 0. */
	uint32_t unused1:16;
#else
	/** Unused data field, set to 0. */
	uint32_t unused1:16;
	/** Start pointer to the ONU_GPE_LONG_FWD_TABLE_xxx. */
	uint32_t fwd_table_pointer:14;
	/** Unused data field, set to 0. */
	uint32_t unused2:1;
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
#endif
} __PACKED__;

/** ONU_GPE_LONG_FWD_TABLE_IPV6 structure definition.
   Layer-3 unicast forwarding table, separate entries are provided for upstream and downstream data traffic.
The table instance value shall be set to 1.
*/
struct gpe_long_fwd_table_ipv6 {
#if __BYTE_ORDER == __BIG_ENDIAN
	/** IPv6 address part 1, low word, any value is valid. */
	uint32_t ip_address0:32;
	/** IPv6 address part 2, any value is valid. */
	uint32_t ip_address1:32;
	/** IPv6 address part 3, any value is valid. */
	uint32_t ip_address2:32;
	/** IPv6 address part 4, high word, any value is valid. */
	uint32_t ip_address3:32;
	/** Key type, defines the kind of key to be used for table access.
	    For code point definition, see the description of the
	    ONU_GPE_SHORT_FWD_TABLE_MAC.
	*/
	uint32_t key_code:4;
	/** Unused data field, set to 0. */
	uint32_t unused1:1;
	/** Bridge index, values 0 to ONU_GPE_MAX_BRIDGES - 1 are valid. */
	uint32_t bridge_index:3;
	/** Forwarding ID, values 0 to ONU_GPE_FWD_ID_TABLE_SIZE - 1 are valid. */
	uint32_t fid:8;
	/** Unused key field, set to 0. */
	uint32_t zero0:16;
	/** Unused data field, set to 0. */
	uint32_t unused2:32;
	/** Dummy field for learning timestamp of unicast MAC address entries. */
	uint32_t dummy_learning_time_stamp:8;
	/** Unused data field, set to 0. */
	uint32_t unused4:3;
	/** Used for direct IPv6 over GEM handling. Points to an entry of the NAPT
	    table, which defines the layer-2 header to be applied.
	*/
	uint32_t encapsulation_index:9;
	/** Unused data field, set to 0. */
	uint32_t unused3:1;
	/** Dummy field for Dynamic or static entry mode. IPv6 unicast table entries
	    shall always be static. Always set to 0 (static).
	*/
	uint32_t zero_dynamic_enable:1;
	/** Always set to zero. Indicates that this entry is not subject to
	    limitation.
	*/
	uint32_t zero_limitation:1;
	/** Multicast group activity. Not used in this table. Set to 0. */
	uint32_t dummy_mc_group_active:1;
	/** Set to zero always. Indicates that bits 198:192 identify an egress
	    bridge port.
	*/
	uint32_t zero_port_map_indicator:1;
	/** Egress bridge port ID, values 0 to ONU_GPE_BRIDGE_PORT_TABLE_SIZE - 1
	    are valid. Points to an entry of the ONU_GPE_BRIDGE_PORT_TABLE.
	*/
	uint32_t bridge_port_index:7;
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
	/** End indication, marks if is the last entry of a sequence of entries that
	    are identified by the same hash value.
	    - 0: This is not the last entry.
	    - 1: This is the last entry.
	*/
	uint32_t end:1;
	/** Next entry pointer, values 0 to ONU_GPE_L3_FORWARDING_TABLE_SIZE - 1 are
	    valid. This value points to the next entry that is identified by the
	    same hash value (next bucket).
	*/
	uint32_t next_entry:14;
	/** Unused data field, set to 0. */
	uint32_t unused5:16;
#else
	/** IPv6 address part 1, low word, any value is valid. */
	uint32_t ip_address0:32;
	/** IPv6 address part 2, any value is valid. */
	uint32_t ip_address1:32;
	/** IPv6 address part 3, any value is valid. */
	uint32_t ip_address2:32;
	/** IPv6 address part 4, high word, any value is valid. */
	uint32_t ip_address3:32;
	/** Unused key field, set to 0. */
	uint32_t zero0:16;
	/** Forwarding ID, values 0 to ONU_GPE_FWD_ID_TABLE_SIZE - 1 are valid. */
	uint32_t fid:8;
	/** Bridge index, values 0 to ONU_GPE_MAX_BRIDGES - 1 are valid. */
	uint32_t bridge_index:3;
	/** Unused data field, set to 0. */
	uint32_t unused1:1;
	/** Key type, defines the kind of key to be used for table access.
	    For code point definition, see the description of the
	    ONU_GPE_SHORT_FWD_TABLE_MAC.
	*/
	uint32_t key_code:4;
	/** Unused data field, set to 0. */
	uint32_t unused2:32;
	/** Egress bridge port ID, values 0 to ONU_GPE_BRIDGE_PORT_TABLE_SIZE - 1
	    are valid. Points to an entry of the ONU_GPE_BRIDGE_PORT_TABLE.
	*/
	uint32_t bridge_port_index:7;
	/** Set to zero always. Indicates that bits 198:192 identify an egress
	    bridge port.
	*/
	uint32_t zero_port_map_indicator:1;
	/** Multicast group activity. Not used in this table. Set to 0. */
	uint32_t dummy_mc_group_active:1;
	/** Always set to zero. Indicates that this entry is not subject to
	    limitation.
	*/
	uint32_t zero_limitation:1;
	/** Dummy field for Dynamic or static entry mode. IPv6 unicast table entries
	    shall always be static. Always set to 0 (static).
	*/
	uint32_t zero_dynamic_enable:1;
	/** Unused data field, set to 0. */
	uint32_t unused3:1;
	/** Used for direct IPv6 over GEM handling. Points to an entry of the NAPT
	    table, which defines the layer-2 header to be applied.
	*/
	uint32_t encapsulation_index:9;
	/** Unused data field, set to 0. */
	uint32_t unused4:3;
	/** Dummy field for learning timestamp of unicast MAC address entries. */
	uint32_t dummy_learning_time_stamp:8;
	/** Unused data field, set to 0. */
	uint32_t unused5:16;
	/** Next entry pointer, values 0 to ONU_GPE_L3_FORWARDING_TABLE_SIZE - 1 are
	    valid. This value points to the next entry that is identified by the
	    same hash value (next bucket).
	*/
	uint32_t next_entry:14;
	/** End indication, marks if is the last entry of a sequence of entries that
	    are identified by the same hash value.
	    - 0: This is not the last entry.
	    - 1: This is the last entry.
	*/
	uint32_t end:1;
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
#endif
} __PACKED__;

/** ONU_GPE_LONG_FWD_TABLE_IPV6_MC structure definition.
   Layer-3 multicast forwarding table.
The table instance value shall be set to 1.
*/
struct gpe_long_fwd_table_ipv6_mc {
#if __BYTE_ORDER == __BIG_ENDIAN
	/** Multicast IPv6 address, LSB, all values are valid. */
	uint32_t ip_address0:32;
	/** Multicast IPv6 address, all values are valid. */
	uint32_t ip_address1:32;
	/** Multicast IPv6 address, all values are valid. */
	uint32_t ip_address2:32;
	/** Multicast IPv6 address, MSB, all values are valid. */
	uint32_t ip_address3:32;
	/** Key type, defines the kind of key to be used for table access.
	    For code point definition, see the description of the
	    ONU_GPE_SHORT_FWD_TABLE_MAC.
	*/
	uint32_t key_code:4;
	/** Unused data field, set to 0. */
	uint32_t unused1:1;
	/** Bridge Index, values 0 to ONU_GPE_MAX_BRIDGES - 1 are valid. Points to
	    the bridge that this multicast group is allocated to.
	*/
	uint32_t bridge_index:3;
	/** Forwarding ID, values 0 to ONU_GPE_FWD_ID_TABLE_SIZE - 1 are valid. */
	uint32_t fid:8;
	/** Unused key field, set to 0. */
	uint32_t zero0:16;
	/** Unused data field, set to 0. */
	uint32_t unused2:32;
	/** Dummy field for learning timestamp of unicast MAC address entries. */
	uint32_t dummy_learning_time_stamp:8;
	/** Unused data field, set to 0. */
	uint32_t unused4:2;
	/** Multicast entry source indication flag.
	    - 0: The entry has been created by OMCI and shall not be deleted by
	    IGMP.
	    - 1: The entry has been created by IGMP and may be deleted by IGMP.
	*/
	uint32_t igmp:1;
	/** Downstream source filter pointer, values 0 to
	    ONU_GPE_DS_MC_IPV6_SOURCE_FILTER_TABLE_SIZE - 1 are valid.
	*/
	uint32_t source_filter_pointer:9;
	/** MLDv2 source filtering enable.
	    - 0: MLDv1 (no source filtering).
	    - 1: MLDv2 (source filtering enabled).
	*/
	uint32_t msf_enable:1;
	/** Dummy field for dynamic or static entry mode:
	    Always set to 0: Static
	    IPv6 multicast table entries shall always be static.
	*/
	uint32_t zero_dynamic_enable:1;
	/** Always set to zero. Indicates that this entry is not subject to
	    limitation.
	*/
	uint32_t zero_limitation:1;
	/** Multicast group activity.
	    - 0: Multicast group is not active, no mc frame received since last
	    check
	    - 1: Multicast group is active, mc frame was received
	    This bit is set when a multicast frame is received and reset by SW after
	    activity check.
	*/
	uint32_t mc_group_active:1;
	/** Set to one always. Indicates that bits 239:224 contain a port map. */
	uint32_t one_port_map_indicator:1;
	/** Include Enable Port Map for IP Multicast Source Filtering mode.
	    The bit position is related to egress_bridge_port_index0 to
	    egress_bridge_port_index3 in ONU_GPE_BRIDGE_TABLE (see example below).
	    Bits 4/5/6 are unused.
	    - 0: Exclude a matching frame from multicasting on this port.
	    - 1: Include a matching frame on this port.
	    - Bit 0: UNI port 0.
	    - Bit 1: UNI Port 1.
	    - Bit 2: UNI port 2.
	    - Bit 3: UNI port 3.
	*/
	uint32_t include_enable:7;
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
	/** End indication, marks if is the last entry of a sequence of entries that
	    are identified by the same hash value.
	    - 0: This is not the last entry.
	    - 1: This is the last entry.
	*/
	uint32_t end:1;
	/** Next entry pointer, values 0 to ONU_GPE_IPV4_MC_GROUP_TABLE_SIZE - 1 are
	    valid. This value points to the next entry that is identified by the
	    same hash value (next bucket).
	*/
	uint32_t next_entry:14;
	/** Multicast port map.
	    - 0: Do not forward to this bridge port.
	    - 1: Send a copy to this bridge port.
	    The bit positions are related to the configuration of
	    egress_bridge_port_index0 to egress_bridge_port_index15 in the
	    ONU_GPE_BRIDGE_TABLE.
	*/
	uint32_t port_map:16;
#else
	/** Multicast IPv6 address, LSB, all values are valid. */
	uint32_t ip_address0:32;
	/** Multicast IPv6 address, all values are valid. */
	uint32_t ip_address1:32;
	/** Multicast IPv6 address, all values are valid. */
	uint32_t ip_address2:32;
	/** Multicast IPv6 address, MSB, all values are valid. */
	uint32_t ip_address3:32;
	/** Unused key field, set to 0. */
	uint32_t zero0:16;
	/** Forwarding ID, values 0 to ONU_GPE_FWD_ID_TABLE_SIZE - 1 are valid. */
	uint32_t fid:8;
	/** Bridge Index, values 0 to ONU_GPE_MAX_BRIDGES - 1 are valid. Points to
	    the bridge that this multicast group is allocated to.
	*/
	uint32_t bridge_index:3;
	/** Unused data field, set to 0. */
	uint32_t unused1:1;
	/** Key type, defines the kind of key to be used for table access.
	    For code point definition, see the description of the
	    ONU_GPE_SHORT_FWD_TABLE_MAC.
	*/
	uint32_t key_code:4;
	/** Unused data field, set to 0. */
	uint32_t unused2:32;
	/** Include Enable Port Map for IP Multicast Source Filtering mode.
	    The bit position is related to egress_bridge_port_index0 to
	    egress_bridge_port_index3 in ONU_GPE_BRIDGE_TABLE (see example below).
	    Bits 4/5/6 are unused.
	    - 0: Exclude a matching frame from multicasting on this port.
	    - 1: Include a matching frame on this port.
	    - Bit 0: UNI port 0.
	    - Bit 1: UNI Port 1.
	    - Bit 2: UNI port 2.
	    - Bit 3: UNI port 3.
	*/
	uint32_t include_enable:7;
	/** Set to one always. Indicates that bits 239:224 contain a port map. */
	uint32_t one_port_map_indicator:1;
	/** Multicast group activity.
	    - 0: Multicast group is not active, no mc frame received since last
	    check
	    - 1: Multicast group is active, mc frame was received
	    This bit is set when a multicast frame is received and reset by SW after
	    activity check.
	*/
	uint32_t mc_group_active:1;
	/** Always set to zero. Indicates that this entry is not subject to
	    limitation.
	*/
	uint32_t zero_limitation:1;
	/** Dummy field for dynamic or static entry mode:
	    Always set to 0: Static
	    IPv6 multicast table entries shall always be static.
	*/
	uint32_t zero_dynamic_enable:1;
	/** MLDv2 source filtering enable.
	    - 0: MLDv1 (no source filtering).
	    - 1: MLDv2 (source filtering enabled).
	*/
	uint32_t msf_enable:1;
	/** Downstream source filter pointer, values 0 to
	    ONU_GPE_DS_MC_IPV6_SOURCE_FILTER_TABLE_SIZE - 1 are valid.
	*/
	uint32_t source_filter_pointer:9;
	/** Multicast entry source indication flag.
	    - 0: The entry has been created by OMCI and shall not be deleted by
	    IGMP.
	    - 1: The entry has been created by IGMP and may be deleted by IGMP.
	*/
	uint32_t igmp:1;
	/** Unused data field, set to 0. */
	uint32_t unused4:2;
	/** Dummy field for learning timestamp of unicast MAC address entries. */
	uint32_t dummy_learning_time_stamp:8;
	/** Multicast port map.
	    - 0: Do not forward to this bridge port.
	    - 1: Send a copy to this bridge port.
	    The bit positions are related to the configuration of
	    egress_bridge_port_index0 to egress_bridge_port_index15 in the
	    ONU_GPE_BRIDGE_TABLE.
	*/
	uint32_t port_map:16;
	/** Next entry pointer, values 0 to ONU_GPE_IPV4_MC_GROUP_TABLE_SIZE - 1 are
	    valid. This value points to the next entry that is identified by the
	    same hash value (next bucket).
	*/
	uint32_t next_entry:14;
	/** End indication, marks if is the last entry of a sequence of entries that
	    are identified by the same hash value.
	    - 0: This is not the last entry.
	    - 1: This is the last entry.
	*/
	uint32_t end:1;
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
#endif
} __PACKED__;

/** ONU_GPE_DS_MC_IPV4_SOURCE_FILTER_TABLE structure definition.
   This table holds IPv4 MC source filter entries (IGMPv3).
The table instance value shall be set to 1.
*/
struct gpe_ds_mc_ipv4_source_filter_table {
#if __BYTE_ORDER == __BIG_ENDIAN
	/** IPv4 address */
	uint32_t ip_address:32;
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
	/** End indication, marks if is the last entry of a sequence of entries that
	    sequentially searched.
	    - 0: This is not the last entry.
	    - 1: This is the last entry.
	*/
	uint32_t end:1;
	/** Unused data field, set to 0. */
	uint32_t unused:26;
	/** Filter port map. The bit positions are related to the configuration of
	    egress_bridge_port_index0 to egress_bridge_port_index3 in the
	    ONU_GPE_BRIDGE_TABLE.
	    - Bit 0: Bridge port selected by egress_bridge_port_index0, this is UNI
	    port 0.
	    - Bit 1: Bridge port selected by egress_bridge_port_index1, this is UNI
	    port 1.
	    - Bit 2: Bridge port selected by egress_bridge_port_index2, this is UNI
	    port 2.
	    - Bit 3: Bridge port selected by egress_bridge_port_index3, this is UNI
	    port 3.
	*/
	uint32_t port_map:4;
#else
	/** IPv4 address */
	uint32_t ip_address:32;
	/** Filter port map. The bit positions are related to the configuration of
	    egress_bridge_port_index0 to egress_bridge_port_index3 in the
	    ONU_GPE_BRIDGE_TABLE.
	    - Bit 0: Bridge port selected by egress_bridge_port_index0, this is UNI
	    port 0.
	    - Bit 1: Bridge port selected by egress_bridge_port_index1, this is UNI
	    port 1.
	    - Bit 2: Bridge port selected by egress_bridge_port_index2, this is UNI
	    port 2.
	    - Bit 3: Bridge port selected by egress_bridge_port_index3, this is UNI
	    port 3.
	*/
	uint32_t port_map:4;
	/** Unused data field, set to 0. */
	uint32_t unused:26;
	/** End indication, marks if is the last entry of a sequence of entries that
	    sequentially searched.
	    - 0: This is not the last entry.
	    - 1: This is the last entry.
	*/
	uint32_t end:1;
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
#endif
} __PACKED__;

/** ONU_GPE_DS_MC_IPV6_SOURCE_FILTER_TABLE structure definition.
   This table holds IPv6 MC source filter entries (MLDv2).
The table instance value shall be set to 1.
*/
struct gpe_ds_mc_ipv6_source_filter_table {
#if __BYTE_ORDER == __BIG_ENDIAN
	/** IPv6 address, LSB, all values are valid. */
	uint32_t ip_address0:32;
	/** IPv6 address, all values are valid. */
	uint32_t ip_address1:32;
	/** IPv6 address, all values are valid. */
	uint32_t ip_address2:32;
	/** IPv6 address, MSB, all values are valid. */
	uint32_t ip_address3:32;
	/** Unused data field, set to 0. */
	uint32_t unused1:28;
	/** Filter port map. The bit positions are related to the configuration of
	    egress_bridge_port_index0 to egress_bridge_port_index3 in the
	    ONU_GPE_BRIDGE_TABLE.
	    - Bit 0: Bridge port selected by egress_bridge_port_index0, this is UNI
	    port 0.
	    - Bit 1: Bridge port selected by egress_bridge_port_index1, this is UNI
	    port 1.
	    - Bit 2: Bridge port selected by egress_bridge_port_index2, this is UNI
	    port 2.
	    - Bit 3: Bridge port selected by egress_bridge_port_index3, this is UNI
	    port 3.
	*/
	uint32_t port_map:4;
	/** Unused data field, set to 0. */
	uint32_t unused2:32;
	/** Unused data field, set to 0. */
	uint32_t unused3:32;
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
	/** End indication, marks if is the last entry of a sequence of entries that
	    sequentially searched.
	    - 0: This is not the last entry.
	    - 1: This is the last entry.
	*/
	uint32_t end:1;
	/** Unused data field, set to 0. */
	uint32_t unused4:30;
#else
	/** IPv6 address, LSB, all values are valid. */
	uint32_t ip_address0:32;
	/** IPv6 address, all values are valid. */
	uint32_t ip_address1:32;
	/** IPv6 address, all values are valid. */
	uint32_t ip_address2:32;
	/** IPv6 address, MSB, all values are valid. */
	uint32_t ip_address3:32;
	/** Filter port map. The bit positions are related to the configuration of
	    egress_bridge_port_index0 to egress_bridge_port_index3 in the
	    ONU_GPE_BRIDGE_TABLE.
	    - Bit 0: Bridge port selected by egress_bridge_port_index0, this is UNI
	    port 0.
	    - Bit 1: Bridge port selected by egress_bridge_port_index1, this is UNI
	    port 1.
	    - Bit 2: Bridge port selected by egress_bridge_port_index2, this is UNI
	    port 2.
	    - Bit 3: Bridge port selected by egress_bridge_port_index3, this is UNI
	    port 3.
	*/
	uint32_t port_map:4;
	/** Unused data field, set to 0. */
	uint32_t unused1:28;
	/** Unused data field, set to 0. */
	uint32_t unused2:32;
	/** Unused data field, set to 0. */
	uint32_t unused3:32;
	/** Unused data field, set to 0. */
	uint32_t unused4:30;
	/** End indication, marks if is the last entry of a sequence of entries that
	    sequentially searched.
	    - 0: This is not the last entry.
	    - 1: This is the last entry.
	*/
	uint32_t end:1;
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
#endif
} __PACKED__;

/** ONU_GPE_LEARNING_LIMITATION_TABLE structure definition.
   This table holds the MAC address learning limits per bridge port.
The index used to access this table is the bridge_port_index.
The table instance value shall be set to 1.
*/
struct gpe_learning_limitation_table {
#if __BYTE_ORDER == __BIG_ENDIAN
	/** Per-port learning limit, values 0 to ONU_GPE_FORWARDING_TABLE_SIZE - 1
	    are valid.
	*/
	uint32_t learning_limit:16;
	/** Association Count, values 0 to ONU_GPE_FORWARDING_TABLE_SIZE - 1 are
	    valid.
	*/
	uint32_t association_count:16;
#else
	/** Association Count, values 0 to ONU_GPE_FORWARDING_TABLE_SIZE - 1 are
	    valid.
	*/
	uint32_t association_count:16;
	/** Per-port learning limit, values 0 to ONU_GPE_FORWARDING_TABLE_SIZE - 1
	    are valid.
	*/
	uint32_t learning_limit:16;
#endif
} __PACKED__;

/** ONU_GPE_LAN_PORT_TABLE structure definition.
   UNI-port specific configuration: 4 Ethernet UNI ports and 4 Virtual Ethernet Interface ports.
The index used to access this table is the lan_port_index.
The table instance value shall be set to.
- 0x01: for reading
- 0x3F: for write acces
*/
struct gpe_lan_port_table {
#if __BYTE_ORDER == __BIG_ENDIAN
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
	/** This threshold value defines the maximum ingress data rate that is
	    accepted by the LAN-port-based ingress policer. See the UMPR document
	    for rate configuration.
	*/
	uint32_t policer_threshold:21;
	/** Exception ingress meter enable.
	    - 0: Disabled.
	    - 1: Enabled.
	*/
	uint32_t uni_except_meter_enable:1;
	/** Dual token bucket meter selection for exception traffic to the software,
	    the upper 8 bit of this value are used to address one of up to 256 meter
	    units, the LSB must be set to 0.
	*/
	uint32_t uni_except_meter_id:9;
	/** Unused, set to 0. */
	uint32_t unused3:3;
	/** IGMP ingress meter enable.
	    - 0: Disabled.
	    - 1: Enabled.
	*/
	uint32_t igmp_except_meter_enable:1;
	/** Dual token bucket meter selection for IGMP control traffic from Ingress
	    UNI or Egress UNI to the software, the upper 8 bit of this value are
	    used to address one of up to 256 meter units, the LSB must be set to 0.
	*/
	uint32_t igmp_except_meter_id:9;
	/** Exception profile selection for LAN-side ingress and egress exception
	    processing.
	*/
	uint32_t exception_profile:3;
	/** Selects the entry point of the ACL table to start the filtering. */
	uint32_t acl_filter_index:8;
	/** Selects if the ACL filter function shall be applied.
	    - 0: Disabled.
	    - 1: Enabled.
	*/
	uint32_t acl_filter_enable:1;
	/** Access Control List Filter operation mode.
	    - 0: Blacklist (filter works in blacklist mode, drop if at least one
	    matching rule is found).
	    - 1: Whitelist (filter works in whitelist mode, pass only if matching
	    rule is found).
	*/
	uint32_t acl_filter_mode:1;
	/** Selects the decoding rule (1 of 8) for Queue Marking. Used as MSBs of
	    the DSCP decoding table index (the 5 LSBs are the DSCP value).
	*/
	uint32_t dscp_table_pointer:3;
	/** Queue marking mode, values 0 to 7 are valid.
	    - 0: No marking.
	    - 1: Internal marking by meter.
	    - 2: DEI marking.
	    - 3: PCP 8P0D marking.
	    - 4: PCP 7P1D marking.
	    - 5: PCP 6P2D marking.
	    - 6: PCP 5P3D marking.
	    - 7: DSCP marking.
	*/
	uint32_t queue_marking_mode:3;
	/** Ingress Extended VLAN processing enable for multicast packets and
	    IGMP/MLD control packets. Extended VLAN handling is enabled, if the
	    condition ((ext_vlan_ingress ==1)||(ext_vlan_mc_enable_ingress==1)) is
	    met.
	    If the condition ((ext_vlan_ingress
	    ==1)&&(ext_vlan_mc_enable_ingress==0)) is met, a dummy rule must be
	    configured for multicast/IGMP packets in the VLAN rule/treatment tables.
	    
	    - 0: Disabled (extended VLAN processing is not applied to multicast and
	    IGMP/MLD packets).
	    - 1: Enabled (extended VLAN processing is applied to all packets).
	*/
	uint32_t ext_vlan_mc_enable_ingress:1;
	/** LAN MAC swap enable. Swap MAC DA and MAC SA.
	    - 0: Disabled.
	    - 1: Enabled.
	*/
	uint32_t lan_mac_swap_enable:1;
	/** Loopback enable.
	    - 0: Disabled.
	    - 1: Enabled.
	*/
	uint32_t lan_loopback_enable:1;
	/** Ethertype Filter Enable.
	    - 0: Disabled (no filtering is performed).
	    - 1: Enabled (blacklist or whitelist filtering is performed).
	*/
	uint32_t ethertype_filter_enable:1;
	/** Ethertype Filter operation mode:
	    - 0: Blacklist (block if it matches).
	    - 1: Whitelist (pass if it matches).
	*/
	uint32_t ethertype_filter_mode:1;
	/** Ethertype Filter Pointer. This is the start pointer into the Ethertype
	    Filter Table
	*/
	uint32_t ethertype_filter_pointer:6;
	/** Allow an egress extended VLAN operation to be based on the result of an
	    ingress extended VLAN operation.
	    - 0: VLAN operation is based on the original received data values.
	    - 1: VLAN operation is based on the result of an ingress extended VLAN
	    operation.
	*/
	uint32_t ext_vlan_incremental_enable:1;
	/** Defines the usage of the inner VLAN field in the ingress extended VLAN
	    rule definition.
	    - 0: Inner VLAN ID.
	    - 1: Reserved (do not use).
	    - 2: Ingress port number (ipn).
	    - 3: Received DSCP.
	*/
	uint32_t ext_vlan_ingress_mode:2;
	/** Defines the usage of the inner VLAN field in the egress extended VLAN
	    rule definition.
	    - 0: Inner VLAN ID.
	    - 1: GEM port index (gpix).
	    - 2: Ingress port number (ipn).
	    - 3: Received DSCP.
	*/
	uint32_t ext_vlan_egress_mode:2;
	/** Extended VLAN enable, enables the VLAN configuration defined by the
	    Extended VLAN Index.
	*/
	uint32_t ext_vlan_enable_egress:1;
	/** Extended VLAN Index, values 0 to ONU_GPE_EXTENDED_VLAN_TABLE_SIZE - 1
	    are valid. Points to the ONU_GPE_EXTENDED_VLAN_TABLE.
	*/
	uint32_t ext_vlan_index_egress:7;
	/** Extended VLAN enable, enables the VLAN configuration defined by the
	    Extended VLAN Index.
	*/
	uint32_t ext_vlan_enable_ingress:1;
	/** Extended VLAN Index, values 0 to ONU_GPE_EXTENDED_VLAN_TABLE_SIZE - 1
	    are valid; points to the ONU_GPE_EXTENDED_VLAN_TABLE.
	*/
	uint32_t ext_vlan_index_ingress:7;
	/** Forwarding ID mask to enable inner PCP for FID calculation.
	    - 0: Disabled.
	    - 1: Enabled.
	*/
	uint32_t fid_mask_pcpi:1;
	/** Forwarding ID mask to enable outer PCP for FID calculation.
	    - 0: Disabled.
	    - 1: Enabled.
	*/
	uint32_t fid_mask_pcpo:1;
	/** Forwarding ID mask to enable inner VID for FID calculation.
	    - 0: Disabled.
	    - 1: Enabled.
	*/
	uint32_t fid_mask_vidi:1;
	/** Forwarding ID mask to enable the outer VID for FID calculation.
	    - 0: Disabled.
	    - 1: Enabled.
	*/
	uint32_t fid_mask_vido:1;
	/** Egress ExtVLAN_Enable for MC and IGMP/MLD. */
	uint32_t ext_vlan_mc_enable_egress:1;
	/** PPPoE filtering enable.
	    - 0: Disabled (all packets are accepted).
	    - 1: Enabled (only PPPoE packets are accepted).
	*/
	uint32_t pppoe_filter_enable:1;
	/** CFM meter enable.
	    - 0: Disabled.
	    - 1: Enabled.
	*/
	uint32_t cfm_meter_enable:1;
	/** Dual token bucket meter selection for CFM frames, the upper 8 bit of
	    this value are used to address one of up to 256 meter units, the LSB
	    must be set to 0.
	*/
	uint32_t cfm_meter_id:9;
	/** Base queue index of the LAN port's group of egress queues, values 0 to
	    GPON_MAX_EGRESS_QUEUES - 7 are valid.
	*/
	uint32_t base_queue_index:8;
	/** Interworking Option.
	    - 0: Bridging, interworking_index is a bridge port index.
	    - 1: P-Mapper, interworking_index is a P-Mapper index.
	*/
	uint32_t interworking_option:1;
	/** Bridge port index (0 to ONU_GPE_BRIDGE_PORT_TABLE_SIZE - 1) or P-Mapper
	    index (0 to ONU_GPE_PMAPPER_TABLE_SIZE - 1). Points to an entry of the
	    ONU_GPE_BRIDGE_PORT_TABLE or of the ONU_GPE_PMAPPER_TABLE.
	*/
	uint32_t interworking_index:7;
#else
	/** Bridge port index (0 to ONU_GPE_BRIDGE_PORT_TABLE_SIZE - 1) or P-Mapper
	    index (0 to ONU_GPE_PMAPPER_TABLE_SIZE - 1). Points to an entry of the
	    ONU_GPE_BRIDGE_PORT_TABLE or of the ONU_GPE_PMAPPER_TABLE.
	*/
	uint32_t interworking_index:7;
	/** Interworking Option.
	    - 0: Bridging, interworking_index is a bridge port index.
	    - 1: P-Mapper, interworking_index is a P-Mapper index.
	*/
	uint32_t interworking_option:1;
	/** Base queue index of the LAN port's group of egress queues, values 0 to
	    GPON_MAX_EGRESS_QUEUES - 7 are valid.
	*/
	uint32_t base_queue_index:8;
	/** Dual token bucket meter selection for CFM frames, the upper 8 bit of
	    this value are used to address one of up to 256 meter units, the LSB
	    must be set to 0.
	*/
	uint32_t cfm_meter_id:9;
	/** CFM meter enable.
	    - 0: Disabled.
	    - 1: Enabled.
	*/
	uint32_t cfm_meter_enable:1;
	/** PPPoE filtering enable.
	    - 0: Disabled (all packets are accepted).
	    - 1: Enabled (only PPPoE packets are accepted).
	*/
	uint32_t pppoe_filter_enable:1;
	/** Egress ExtVLAN_Enable for MC and IGMP/MLD. */
	uint32_t ext_vlan_mc_enable_egress:1;
	/** Forwarding ID mask to enable the outer VID for FID calculation.
	    - 0: Disabled.
	    - 1: Enabled.
	*/
	uint32_t fid_mask_vido:1;
	/** Forwarding ID mask to enable inner VID for FID calculation.
	    - 0: Disabled.
	    - 1: Enabled.
	*/
	uint32_t fid_mask_vidi:1;
	/** Forwarding ID mask to enable outer PCP for FID calculation.
	    - 0: Disabled.
	    - 1: Enabled.
	*/
	uint32_t fid_mask_pcpo:1;
	/** Forwarding ID mask to enable inner PCP for FID calculation.
	    - 0: Disabled.
	    - 1: Enabled.
	*/
	uint32_t fid_mask_pcpi:1;
	/** Extended VLAN Index, values 0 to ONU_GPE_EXTENDED_VLAN_TABLE_SIZE - 1
	    are valid; points to the ONU_GPE_EXTENDED_VLAN_TABLE.
	*/
	uint32_t ext_vlan_index_ingress:7;
	/** Extended VLAN enable, enables the VLAN configuration defined by the
	    Extended VLAN Index.
	*/
	uint32_t ext_vlan_enable_ingress:1;
	/** Extended VLAN Index, values 0 to ONU_GPE_EXTENDED_VLAN_TABLE_SIZE - 1
	    are valid. Points to the ONU_GPE_EXTENDED_VLAN_TABLE.
	*/
	uint32_t ext_vlan_index_egress:7;
	/** Extended VLAN enable, enables the VLAN configuration defined by the
	    Extended VLAN Index.
	*/
	uint32_t ext_vlan_enable_egress:1;
	/** Defines the usage of the inner VLAN field in the egress extended VLAN
	    rule definition.
	    - 0: Inner VLAN ID.
	    - 1: GEM port index (gpix).
	    - 2: Ingress port number (ipn).
	    - 3: Received DSCP.
	*/
	uint32_t ext_vlan_egress_mode:2;
	/** Defines the usage of the inner VLAN field in the ingress extended VLAN
	    rule definition.
	    - 0: Inner VLAN ID.
	    - 1: Reserved (do not use).
	    - 2: Ingress port number (ipn).
	    - 3: Received DSCP.
	*/
	uint32_t ext_vlan_ingress_mode:2;
	/** Allow an egress extended VLAN operation to be based on the result of an
	    ingress extended VLAN operation.
	    - 0: VLAN operation is based on the original received data values.
	    - 1: VLAN operation is based on the result of an ingress extended VLAN
	    operation.
	*/
	uint32_t ext_vlan_incremental_enable:1;
	/** Ethertype Filter Pointer. This is the start pointer into the Ethertype
	    Filter Table
	*/
	uint32_t ethertype_filter_pointer:6;
	/** Ethertype Filter operation mode:
	    - 0: Blacklist (block if it matches).
	    - 1: Whitelist (pass if it matches).
	*/
	uint32_t ethertype_filter_mode:1;
	/** Ethertype Filter Enable.
	    - 0: Disabled (no filtering is performed).
	    - 1: Enabled (blacklist or whitelist filtering is performed).
	*/
	uint32_t ethertype_filter_enable:1;
	/** Loopback enable.
	    - 0: Disabled.
	    - 1: Enabled.
	*/
	uint32_t lan_loopback_enable:1;
	/** LAN MAC swap enable. Swap MAC DA and MAC SA.
	    - 0: Disabled.
	    - 1: Enabled.
	*/
	uint32_t lan_mac_swap_enable:1;
	/** Ingress Extended VLAN processing enable for multicast packets and
	    IGMP/MLD control packets. Extended VLAN handling is enabled, if the
	    condition ((ext_vlan_ingress ==1)||(ext_vlan_mc_enable_ingress==1)) is
	    met.
	    If the condition ((ext_vlan_ingress
	    ==1)&&(ext_vlan_mc_enable_ingress==0)) is met, a dummy rule must be
	    configured for multicast/IGMP packets in the VLAN rule/treatment tables.
	    
	    - 0: Disabled (extended VLAN processing is not applied to multicast and
	    IGMP/MLD packets).
	    - 1: Enabled (extended VLAN processing is applied to all packets).
	*/
	uint32_t ext_vlan_mc_enable_ingress:1;
	/** Queue marking mode, values 0 to 7 are valid.
	    - 0: No marking.
	    - 1: Internal marking by meter.
	    - 2: DEI marking.
	    - 3: PCP 8P0D marking.
	    - 4: PCP 7P1D marking.
	    - 5: PCP 6P2D marking.
	    - 6: PCP 5P3D marking.
	    - 7: DSCP marking.
	*/
	uint32_t queue_marking_mode:3;
	/** Selects the decoding rule (1 of 8) for Queue Marking. Used as MSBs of
	    the DSCP decoding table index (the 5 LSBs are the DSCP value).
	*/
	uint32_t dscp_table_pointer:3;
	/** Access Control List Filter operation mode.
	    - 0: Blacklist (filter works in blacklist mode, drop if at least one
	    matching rule is found).
	    - 1: Whitelist (filter works in whitelist mode, pass only if matching
	    rule is found).
	*/
	uint32_t acl_filter_mode:1;
	/** Selects if the ACL filter function shall be applied.
	    - 0: Disabled.
	    - 1: Enabled.
	*/
	uint32_t acl_filter_enable:1;
	/** Selects the entry point of the ACL table to start the filtering. */
	uint32_t acl_filter_index:8;
	/** Exception profile selection for LAN-side ingress and egress exception
	    processing.
	*/
	uint32_t exception_profile:3;
	/** Dual token bucket meter selection for IGMP control traffic from Ingress
	    UNI or Egress UNI to the software, the upper 8 bit of this value are
	    used to address one of up to 256 meter units, the LSB must be set to 0.
	*/
	uint32_t igmp_except_meter_id:9;
	/** IGMP ingress meter enable.
	    - 0: Disabled.
	    - 1: Enabled.
	*/
	uint32_t igmp_except_meter_enable:1;
	/** Unused, set to 0. */
	uint32_t unused3:3;
	/** Dual token bucket meter selection for exception traffic to the software,
	    the upper 8 bit of this value are used to address one of up to 256 meter
	    units, the LSB must be set to 0.
	*/
	uint32_t uni_except_meter_id:9;
	/** Exception ingress meter enable.
	    - 0: Disabled.
	    - 1: Enabled.
	*/
	uint32_t uni_except_meter_enable:1;
	/** This threshold value defines the maximum ingress data rate that is
	    accepted by the LAN-port-based ingress policer. See the UMPR document
	    for rate configuration.
	*/
	uint32_t policer_threshold:21;
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
#endif
} __PACKED__;

/** ONU_GPE_PCP_DECODING_TABLE structure definition.
   This table is used to configure the PCP decoding.
The index to this table is composed of two parts.
- Bit 4-3: Controlled by the PCP decoding mode (mode 3 = 0b00 to mode 6 = 0b11.
- Bit 2-0: Controlled by the received PCP code point.
The table instance value shall be set to.
- 0x01: for reading
- 0x3F: for write access
*/
struct gpe_pcp_decoding_table {
#if __BYTE_ORDER == __BIG_ENDIAN
	/** Unused data field, set to 0. */
	uint8_t unused:2;
	/** This data field is not used, set to 0. */
	uint8_t color:2;
	/** Drop eligible indicator, values 0 to 1 are valid. */
	uint8_t de:1;
	/** Priority code point, values 0 to 7 are valid. */
	uint8_t priority:3;
#else
	/** Priority code point, values 0 to 7 are valid. */
	uint8_t priority:3;
	/** Drop eligible indicator, values 0 to 1 are valid. */
	uint8_t de:1;
	/** This data field is not used, set to 0. */
	uint8_t color:2;
	/** Unused data field, set to 0. */
	uint8_t unused:2;
#endif
} __PACKED__;

/** ONU_GPE_DSCP_DECODING_TABLE structure definition.
   This table is used to configure the DSCP decoding.
The index to this table is composed of two parts.
- Bit 8-6: Controlled by the dscp_table_pointer (selects one of eight sub-tables).
- Bit 5-0: Controlled by the received DSCP/TOS field of the IP header.
The table instance value shall be set to.
- 0x01: for reading
- 0x3F: for write access.
*/
struct gpe_dscp_decoding_table {
#if __BYTE_ORDER == __BIG_ENDIAN
	/** Unused data field, set to 0. */
	uint8_t unused:2;
	/** Color coding, values 0 to 3 are valid.
	    - 0: Unassigned.
	    - 1: Green.
	    - 2: Yellow.
	    - 3: Red.
	*/
	uint8_t color:2;
	/** This data field is not used, set to 0. */
	uint8_t de:1;
	/** PCP, values 0 to 7 are valid. */
	uint8_t pcp:3;
#else
	/** PCP, values 0 to 7 are valid. */
	uint8_t pcp:3;
	/** This data field is not used, set to 0. */
	uint8_t de:1;
	/** Color coding, values 0 to 3 are valid.
	    - 0: Unassigned.
	    - 1: Green.
	    - 2: Yellow.
	    - 3: Red.
	*/
	uint8_t color:2;
	/** Unused data field, set to 0. */
	uint8_t unused:2;
#endif
} __PACKED__;

/** ONU_GPE_PCP_ENCODING_TABLE structure definition.
   This table is used to configure the PCP encoding.
The index to this table is composed of three parts.
- Bit 5-4: These bits are controlled by the egress_color_marking mode (subtract 3 from the mode's code point).
- Bit 3: This bit is controlled by the DE bit.
- Bit 2-0: These are controlled by the priority.
The table instance value shall be set to.
- 0x01: for reading
- 0x3F: for write access.
*/
struct gpe_pcp_encoding_table {
#if __BYTE_ORDER == __BIG_ENDIAN
	/** Unused data field, set to 0. */
	uint8_t unused:5;
	/** Priority (PCP), values 0 to 7 are valid. */
	uint8_t pcp:3;
#else
	/** Priority (PCP), values 0 to 7 are valid. */
	uint8_t pcp:3;
	/** Unused data field, set to 0. */
	uint8_t unused:5;
#endif
} __PACKED__;

/** ONU_GPE_DSCP_ENCODING_TABLE structure definition.
   This table is used to configure the DSCP encoding.
The index to this table is composed of two parts.
- Bit 4-3: These bits are controlled by the egress_color_marking mode (subtract 3 from the mode's code point).
- Bit 2-0 These bits are controlled by the priority.
The table instance value shall be set to.
- 0x01: for reading
- 0x3F: for write access.
*/
struct gpe_dscp_encoding_table {
#if __BYTE_ORDER == __BIG_ENDIAN
	/** Unused data field, set to 0. */
	uint8_t unused:2;
	/** DSCP, values 0 to 63 are valid. */
	uint8_t dscp:6;
#else
	/** DSCP, values 0 to 63 are valid. */
	uint8_t dscp:6;
	/** Unused data field, set to 0. */
	uint8_t unused:2;
#endif
} __PACKED__;

/** ONU_GPE_EXCEPTION_TABLE structure definition.
   This table is used to configure the exception handling.
This table is addressed by an exception_profile index.
The table instance value shall be set to 1.
*/
struct gpe_exception_table {
#if __BYTE_ORDER == __BIG_ENDIAN
	/** Egress exception flag mask, each bit is associated with a dedicated
	    traffic type (see drv_onu_resources_gpe.h) and an entry of the
	    ONU_GPE_REDIRECTION_TABLE.
	*/
	uint32_t egress_exception_flag_mask:32;
	/** Ingress exception flag mask, each bit is associated with a dedicated
	    traffic type (see drv_onu_resources_gpe.h) and an entry of the
	    ONU_GPE_REDIRECTION_TABLE.
	*/
	uint32_t ingress_exception_flag_mask:32;
#else
	/** Ingress exception flag mask, each bit is associated with a dedicated
	    traffic type (see drv_onu_resources_gpe.h) and an entry of the
	    ONU_GPE_REDIRECTION_TABLE.
	*/
	uint32_t ingress_exception_flag_mask:32;
	/** Egress exception flag mask, each bit is associated with a dedicated
	    traffic type (see drv_onu_resources_gpe.h) and an entry of the
	    ONU_GPE_REDIRECTION_TABLE.
	*/
	uint32_t egress_exception_flag_mask:32;
#endif
} __PACKED__;

/** ONU_GPE_REDIRECTION_TABLE structure definition.
   Traffic redirection by exception.
The table instance value shall be set to.
- 0x01: for reading
- 0x3F: for write access.
*/
struct gpe_redirection_table {
#if __BYTE_ORDER == __BIG_ENDIAN
	/** Unused data field, set to 0. */
	uint32_t unused2:16;
	/** Unused data field, set to 0. */
	uint32_t unused1:7;
	/** Snooping Enable. If set, the frame is handled as configured for the
	    detected exception and in addition is copied and handled according to
	    the configured data flow. If not set, the frame is only handled as
	    exception frame.
	    - 0: Disabled.
	    - 1: Enabled.
	*/
	uint32_t snooping_enable:1;
	/** Egress queue ID (QID) for exception redirection. Value == 255 causes
	    packet discard (discard queue).
	*/
	uint32_t redirection_queue_index:8;
#else
	/** Egress queue ID (QID) for exception redirection. Value == 255 causes
	    packet discard (discard queue).
	*/
	uint32_t redirection_queue_index:8;
	/** Snooping Enable. If set, the frame is handled as configured for the
	    detected exception and in addition is copied and handled according to
	    the configured data flow. If not set, the frame is only handled as
	    exception frame.
	    - 0: Disabled.
	    - 1: Enabled.
	*/
	uint32_t snooping_enable:1;
	/** Unused data field, set to 0. */
	uint32_t unused1:7;
	/** Unused data field, set to 0. */
	uint32_t unused2:16;
#endif
} __PACKED__;

/** ONU_GPE_MAC_FILTER_TABLE structure definition.
   MAC table for SA/DA filtering.
The table instance value shall be set to 1.
*/
struct gpe_mac_filter_table {
#if __BYTE_ORDER == __BIG_ENDIAN
	/** MAC address (32 LSBs) */
	uint32_t mac_address_low:32;
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
	/** End indication, marks if is the last entry of a sequence of entries that
	    are identified by the same hash value.
	    - 0: This is not the last entry.
	    - 1: This is the last entry.
	*/
	uint32_t end:1;
	/** Unused data field, set to 0. */
	uint32_t unused:11;
	/** Key code.
	    - 0: Source Filter lookup
	    - 1: Destination Filter lookup
	    - 2: No filter entry (used for MAC Index Expansion)
	    - others: Reserved
	*/
	uint32_t key_code:3;
	/** MAC address (16 MSBs) */
	uint32_t mac_address_high:16;
#else
	/** MAC address (32 LSBs) */
	uint32_t mac_address_low:32;
	/** MAC address (16 MSBs) */
	uint32_t mac_address_high:16;
	/** Key code.
	    - 0: Source Filter lookup
	    - 1: Destination Filter lookup
	    - 2: No filter entry (used for MAC Index Expansion)
	    - others: Reserved
	*/
	uint32_t key_code:3;
	/** Unused data field, set to 0. */
	uint32_t unused:11;
	/** End indication, marks if is the last entry of a sequence of entries that
	    are identified by the same hash value.
	    - 0: This is not the last entry.
	    - 1: This is the last entry.
	*/
	uint32_t end:1;
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
#endif
} __PACKED__;

/** ONU_GPE_ACL_FILTER_TABLE structure definition.
   Ingress packet filter, processed after exception handling.
The table instance value shall be set to.
- 0x01: for reading
- 0x3F: for write access.
*/
struct gpe_acl_filter_table {
#if __BYTE_ORDER == __BIG_ENDIAN
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
	/** End indication, marks if is the last entry of a sequence of entries that
	    are identified by the same hash value.
	    - 0: This is not the last entry.
	    - 1: This is the last entry.
	*/
	uint32_t end:1;
	/** Unused data field, set to 0. */
	uint32_t unused1:7;
	/** Ingress port enable for LAN 3, selects if this filter shall be applied.
	    - 0: Disabled (this ACL entry is ignored for this port).
	    - 1: Enabled (this ACL entry is used for this port).
	*/
	uint32_t ingress_port_lan3:1;
	/** Ingress port enable for LAN 2, selects if this filter shall be applied.
	    - 0: Disabled (this ACL entry is ignored for this port).
	    - 1: Enabled (this ACL entry is used for this port).
	*/
	uint32_t ingress_port_lan2:1;
	/** Ingress port enable for LAN 1, selects if this filter shall be applied.
	    - 0: Disabled (this ACL entry is ignored for this port).
	    - 1: Enabled (this ACL entry is used for this port).
	*/
	uint32_t ingress_port_lan1:1;
	/** Ingress port enable for LAN 0, selects if this filter shall be applied.
	    - 0: Disabled (this ACL entry is ignored for this port).
	    - 1: Enabled (this ACL entry is used for this port).
	*/
	uint32_t ingress_port_lan0:1;
	/** Enable UDP port for comparison.
	    - 0: Ignore UDP port.
	    - 1: Compare UDP port.
	*/
	uint32_t layer4_udp_enable:1;
	/** Enable TCP port for comparison.
	    - 0: Ignore TCP port.
	    - 1: Compare TCP port.
	*/
	uint32_t layer4_tcp_enable:1;
	/** Select TCP/UDP address for comparison.
	    - 0: Compare TCP/UDP destination port
	    - 1: Compare TCP/UDP source port
	*/
	uint32_t layer4_port_compare:1;
	/** Select IP address for comparison.
	    - 0: Compare IP destination address.
	    - 1: Compare IP source address.
	*/
	uint32_t layer3_ip_address_compare:1;
	/** Select layer-3 field for comparison.
	    - 0: Compare IP Protocol.
	    - 1: Compare IP address (source or destination: see
	    layer3_ip_address_compare).
	*/
	uint32_t layer3_compare:1;
	/** Select MAC address for comparison.
	    - 0: Compare MAC destination address.
	    - 1: Compare MAC source address.
	*/
	uint32_t layer2_mac_address_compare:1;
	/** Select layer-2 field for comparison.
	    - 0: Compare Ethertype.
	    - 1: Compare MAC address (source or destination: see
	    layer2_mac_address_compare).
	*/
	uint32_t layer2_compare:1;
	/** Disable layer-4 fields for comparison.
	    - 0: Enabled (use the layer-4 fields of parameter1 for comparison;
	    TCP/UDP address).
	    - 1: Disabled (do not use the layer-4 fields of parameter1 for
	    comparison; TCP/UDP address).
	*/
	uint32_t layer4_disable:1;
	/** Disable layer-3 fields for comparison.
	    - 0: Enabled (use the layer-3 fields of parameter1 for comparison; IPv4
	    address, IP Protocol).
	    - 1: Disabled (do not use the layer-3 fields of parameter1 for
	    comparison; IPv4 address, IP Protocol).
	*/
	uint32_t layer3_disable:1;
	/** Disable the FID field for comparison.
	    - 0: Enabled (use the FID for comparison, field fid).
	    - 1: Disabled (do not use the FID for comparison, field fid).
	*/
	uint32_t fid_disable:1;
	/** Disable layer-2 fields for comparison.
	    - 0: Enabled (use the layer-2 fields of parameter2 for comparison; MAC
	    address, Ethertype).
	    - 1: Disabled (do not use the layer-2 fields of parameter2 for
	    comparison; MAC address, Ethertype).
	*/
	uint32_t layer2_disable:1;
	/** Forwarding ID, selects one of the configured forwarding IDs. The FID 
	    represents a VLAN or combination of two VLANs and is assigned in the FID
	    assignment (see ONU_GPE_FID_ASSIGNMENT_TABLE).
	*/
	uint32_t fid:8;
	/** Parameter Mask 1, each bit of parameter10 can be excluded from
	    comparison (masked) in IPv4 source and destination address mode. Bit 0
	    controls parameter10(0), and so on. The mask does not apply if
	    parameter10 is used as IPv4 protocol type.
	    - 0: Ignore (do not use the selected bit position for comparison).
	    - 1: Use (use the selected bit position for comparison).
	*/
	uint32_t parameter_mask1:32;
	/** Bit 31:0 of the second parameter.
	    On API level either parameter200 or parameter201 can be selected.
	    This parameter can be disabled by layer4_disable.
	    This parameter can be of different types, selected by
	    layer4_port_compare, layer4_tcp_compare, and layer4_udp_compare.
	    - TCP source port or
	    - TCP destination port or
	    - UDP source port or
	    - UDP destination port or
	    - TCP/UDP source port or
	    - TCP/UDP destination port
	*/
	uint32_t parameter201:16;
	/** Bit 47:32 of the second parameter.
	    Set to 0 in case of Ethertype in parameter200 or in case parameter201 is
	    selected.
	*/
	uint32_t parameter21:16;
	/** Bit 31:0 of the second parameter.
	    On API level either parameter200 or parameter201 can be selected.
	    This parameter can be disabled by layer2_disable.
	    This parameter can be of different types, selected by layer2_compare.
	    - MAC source address.
	    - MAC destination address.
	    - Ethertype (bits 15:0 of second parameter, set bits 31:16 to 0)
	*/
	uint32_t parameter200:32;
	/** Bit 127:96 of the first parameter (reserved for IPv6). */
	uint32_t parameter13:32;
	/** Bit 95:64 of the first parameter (reserved for IPv6). */
	uint32_t parameter12:32;
	/** Bit 63:32 of the first parameter (reserved for IPv6). */
	uint32_t parameter11:32;
	/** Bit 31:0 of the first parameter.
	    This parameter can be disabled by layer3_disable.
	    This parameter can be of different types, selected by layer3_compare.
	    - IPv4 source address.
	    - IPv4 destination address.
	    - IP Protocol: bits 7:0, set bits 31:8 to 0.
	*/
	uint32_t parameter10:32;
#else
	/** Bit 31:0 of the first parameter.
	    This parameter can be disabled by layer3_disable.
	    This parameter can be of different types, selected by layer3_compare.
	    - IPv4 source address.
	    - IPv4 destination address.
	    - IP Protocol: bits 7:0, set bits 31:8 to 0.
	*/
	uint32_t parameter10:32;
	/** Bit 63:32 of the first parameter (reserved for IPv6). */
	uint32_t parameter11:32;
	/** Bit 95:64 of the first parameter (reserved for IPv6). */
	uint32_t parameter12:32;
	/** Bit 127:96 of the first parameter (reserved for IPv6). */
	uint32_t parameter13:32;
	/** Bit 31:0 of the second parameter.
	    On API level either parameter200 or parameter201 can be selected.
	    This parameter can be disabled by layer2_disable.
	    This parameter can be of different types, selected by layer2_compare.
	    - MAC source address.
	    - MAC destination address.
	    - Ethertype (bits 15:0 of second parameter, set bits 31:16 to 0)
	*/
	uint32_t parameter200:32;
	/** Bit 47:32 of the second parameter.
	    Set to 0 in case of Ethertype in parameter200 or in case parameter201 is
	    selected.
	*/
	uint32_t parameter21:16;
	/** Bit 31:0 of the second parameter.
	    On API level either parameter200 or parameter201 can be selected.
	    This parameter can be disabled by layer4_disable.
	    This parameter can be of different types, selected by
	    layer4_port_compare, layer4_tcp_compare, and layer4_udp_compare.
	    - TCP source port or
	    - TCP destination port or
	    - UDP source port or
	    - UDP destination port or
	    - TCP/UDP source port or
	    - TCP/UDP destination port
	*/
	uint32_t parameter201:16;
	/** Parameter Mask 1, each bit of parameter10 can be excluded from
	    comparison (masked) in IPv4 source and destination address mode. Bit 0
	    controls parameter10(0), and so on. The mask does not apply if
	    parameter10 is used as IPv4 protocol type.
	    - 0: Ignore (do not use the selected bit position for comparison).
	    - 1: Use (use the selected bit position for comparison).
	*/
	uint32_t parameter_mask1:32;
	/** Forwarding ID, selects one of the configured forwarding IDs. The FID 
	    represents a VLAN or combination of two VLANs and is assigned in the FID
	    assignment (see ONU_GPE_FID_ASSIGNMENT_TABLE).
	*/
	uint32_t fid:8;
	/** Disable layer-2 fields for comparison.
	    - 0: Enabled (use the layer-2 fields of parameter2 for comparison; MAC
	    address, Ethertype).
	    - 1: Disabled (do not use the layer-2 fields of parameter2 for
	    comparison; MAC address, Ethertype).
	*/
	uint32_t layer2_disable:1;
	/** Disable the FID field for comparison.
	    - 0: Enabled (use the FID for comparison, field fid).
	    - 1: Disabled (do not use the FID for comparison, field fid).
	*/
	uint32_t fid_disable:1;
	/** Disable layer-3 fields for comparison.
	    - 0: Enabled (use the layer-3 fields of parameter1 for comparison; IPv4
	    address, IP Protocol).
	    - 1: Disabled (do not use the layer-3 fields of parameter1 for
	    comparison; IPv4 address, IP Protocol).
	*/
	uint32_t layer3_disable:1;
	/** Disable layer-4 fields for comparison.
	    - 0: Enabled (use the layer-4 fields of parameter1 for comparison;
	    TCP/UDP address).
	    - 1: Disabled (do not use the layer-4 fields of parameter1 for
	    comparison; TCP/UDP address).
	*/
	uint32_t layer4_disable:1;
	/** Select layer-2 field for comparison.
	    - 0: Compare Ethertype.
	    - 1: Compare MAC address (source or destination: see
	    layer2_mac_address_compare).
	*/
	uint32_t layer2_compare:1;
	/** Select MAC address for comparison.
	    - 0: Compare MAC destination address.
	    - 1: Compare MAC source address.
	*/
	uint32_t layer2_mac_address_compare:1;
	/** Select layer-3 field for comparison.
	    - 0: Compare IP Protocol.
	    - 1: Compare IP address (source or destination: see
	    layer3_ip_address_compare).
	*/
	uint32_t layer3_compare:1;
	/** Select IP address for comparison.
	    - 0: Compare IP destination address.
	    - 1: Compare IP source address.
	*/
	uint32_t layer3_ip_address_compare:1;
	/** Select TCP/UDP address for comparison.
	    - 0: Compare TCP/UDP destination port
	    - 1: Compare TCP/UDP source port
	*/
	uint32_t layer4_port_compare:1;
	/** Enable TCP port for comparison.
	    - 0: Ignore TCP port.
	    - 1: Compare TCP port.
	*/
	uint32_t layer4_tcp_enable:1;
	/** Enable UDP port for comparison.
	    - 0: Ignore UDP port.
	    - 1: Compare UDP port.
	*/
	uint32_t layer4_udp_enable:1;
	/** Ingress port enable for LAN 0, selects if this filter shall be applied.
	    - 0: Disabled (this ACL entry is ignored for this port).
	    - 1: Enabled (this ACL entry is used for this port).
	*/
	uint32_t ingress_port_lan0:1;
	/** Ingress port enable for LAN 1, selects if this filter shall be applied.
	    - 0: Disabled (this ACL entry is ignored for this port).
	    - 1: Enabled (this ACL entry is used for this port).
	*/
	uint32_t ingress_port_lan1:1;
	/** Ingress port enable for LAN 2, selects if this filter shall be applied.
	    - 0: Disabled (this ACL entry is ignored for this port).
	    - 1: Enabled (this ACL entry is used for this port).
	*/
	uint32_t ingress_port_lan2:1;
	/** Ingress port enable for LAN 3, selects if this filter shall be applied.
	    - 0: Disabled (this ACL entry is ignored for this port).
	    - 1: Enabled (this ACL entry is used for this port).
	*/
	uint32_t ingress_port_lan3:1;
	/** Unused data field, set to 0. */
	uint32_t unused1:7;
	/** End indication, marks if is the last entry of a sequence of entries that
	    are identified by the same hash value.
	    - 0: This is not the last entry.
	    - 1: This is the last entry.
	*/
	uint32_t end:1;
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
#endif
} __PACKED__;

/** ONU_GPE_ACL_FILTER_TABLE_2 structure definition.
   Ingress packet filter, processed after exception handling.
The table instance value shall be set to.
- 0x01: for reading
- 0x3F: for write access.
*/
struct gpe_acl_filter_table2 {
#if __BYTE_ORDER == __BIG_ENDIAN
	/** Bit 31:0 of the first parameter.
	    This parameter can be disabled by layer3_disable.
	    This parameter can be of different types, selected by layer3_compare.
	    - IPv4 source address.
	    - IPv4 destination address.
	    - IP Protocol: bits 7:0, set bits 31:8 to 0.
	*/
	uint32_t parameter10:32;
	/** Bit 63:32 of the first parameter (reserved for IPv6). */
	uint32_t parameter11:32;
	/** Bit 95:64 of the first parameter (reserved for IPv6). */
	uint32_t parameter12:32;
	/** Bit 127:96 of the first parameter (reserved for IPv6). */
	uint32_t parameter13:32;
	/** Bit 31:0 of the second parameter.
	    On API level either parameter200 or parameter201 can be selected.
	    This parameter can be disabled by layer2_disable.
	    This parameter can be of different types, selected by layer2_compare.
	    - MAC source address.
	    - MAC destination address.
	    - Ethertype (bits 15:0 of second parameter, set bits 31:16 to 0)
	*/
	uint32_t parameter200:32;
	/** Bit 31:0 of the second parameter.
	    On API level either parameter200 or parameter201 can be selected.
	    This parameter can be disabled by layer4_disable.
	    This parameter can be of different types, selected by
	    layer4_port_compare, layer4_tcp_compare, and layer4_udp_compare.
	    - TCP source port or
	    - TCP destination port or
	    - UDP source port or
	    - UDP destination port or
	    - TCP/UDP source port or
	    - TCP/UDP destination port
	*/
	uint32_t parameter201:16;
	/** Bit 47:32 of the second parameter.
	    Set to 0 in case of Ethertype in parameter200 or in case parameter201 is
	    selected.
	*/
	uint32_t parameter21:16;
	/** Parameter Mask 1, each bit of parameter 1 can be excluded from
	    comparison (masked) in IPv4 mode. Bit 0 controls parameter1(0), and so
	    on.
	    - 0: Ignore (do not use the selected bit position for comparison).
	    - 1: Use (use the selected bit position for comparison).
	*/
	uint32_t parameter_mask1:32;
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
	/** End indication, marks if is the last entry of a sequence of entries that
	    are identified by the same hash value.
	    - 0: This is not the last entry.
	    - 1: This is the last entry.
	*/
	uint32_t end:1;
	/** Unused data field, set to 0. */
	uint32_t unused1:7;
	/** Ingress port enable for LAN 3, selects if this filter shall be applied.
	    - 0: Disabled (this ACL entry is ignored for this port).
	    - 1: Enabled (this ACL entry is used for this port).
	*/
	uint32_t ingress_port_lan3:1;
	/** Ingress port enable for LAN 2, selects if this filter shall be applied.
	    - 0: Disabled (this ACL entry is ignored for this port).
	    - 1: Enabled (this ACL entry is used for this port).
	*/
	uint32_t ingress_port_lan2:1;
	/** Ingress port enable for LAN 1, selects if this filter shall be applied.
	    - 0: Disabled (this ACL entry is ignored for this port).
	    - 1: Enabled (this ACL entry is used for this port).
	*/
	uint32_t ingress_port_lan1:1;
	/** Ingress port enable for LAN 0, selects if this filter shall be applied.
	    - 0: Disabled (this ACL entry is ignored for this port).
	    - 1: Enabled (this ACL entry is used for this port).
	*/
	uint32_t ingress_port_lan0:1;
	/** Enable UDP port for comparison.
	    - 0: Ignore UDP port.
	    - 1: Compare UDP port.
	*/
	uint32_t layer4_udp_enable:1;
	/** Enable TCP port for comparison.
	    - 0: Ignore TCP port.
	    - 1: Compare TCP port.
	*/
	uint32_t layer4_tcp_enable:1;
	/** Select TCP/UDP address for comparison.
	    - 0: Compare TCP/UDP destination port
	    - 1: Compare TCP/UDP source port
	*/
	uint32_t layer4_port_compare:1;
	/** Select IP address for comparison.
	    - 0: Compare IP destination address.
	    - 1: Compare IP source address.
	*/
	uint32_t layer3_ip_address_compare:1;
	/** Select layer-3 field for comparison.
	    - 0: Compare IP Protocol.
	    - 1: Compare IP address (source or destination: see
	    layer3_ip_address_compare).
	*/
	uint32_t layer3_compare:1;
	/** Select MAC address for comparison.
	    - 0: Compare MAC destination address.
	    - 1: Compare MAC source address.
	*/
	uint32_t layer2_mac_address_compare:1;
	/** Select layer-2 field for comparison.
	    - 0: Compare Ethertype.
	    - 1: Compare MAC address (source or destination: see
	    layer2_mac_address_compare).
	*/
	uint32_t layer2_compare:1;
	/** Disable layer-4 fields for comparison.
	    - 0: Enabled (use the layer-4 fields of parameter1 for comparison;
	    TCP/UDP address).
	    - 1: Disabled (do not use the layer-4 fields of parameter1 for
	    comparison; TCP/UDP address).
	*/
	uint32_t layer4_disable:1;
	/** Disable layer-3 fields for comparison.
	    - 0: Enabled (use the layer-3 fields of parameter1 for comparison; IPv4
	    address, IP Protocol).
	    - 1: Disabled (do not use the layer-3 fields of parameter1 for
	    comparison; IPv4 address, IP Protocol).
	*/
	uint32_t layer3_disable:1;
	/** Disable the FID field for comparison.
	    - 0: Enabled (use the FID for comparison, field fid).
	    - 1: Disabled (do not use the FID for comparison, field fid).
	*/
	uint32_t fid_disable:1;
	/** Disable layer-2 fields for comparison.
	    - 0: Enabled (use the layer-2 fields of parameter2 for comparison; MAC
	    address, Ethertype).
	    - 1: Disabled (do not use the layer-2 fields of parameter2 for
	    comparison; MAC address, Ethertype).
	*/
	uint32_t layer2_disable:1;
	/** Forwarding ID, selects one of the configured forwarding IDs. The FID 
	    represents a VLAN or combination of two VLANs and is assigned in the FID
	    assignment (see ONU_GPE_FID_ASSIGNMENT_TABLE).
	*/
	uint32_t fid:8;
#else
	/** Bit 31:0 of the first parameter.
	    This parameter can be disabled by layer3_disable.
	    This parameter can be of different types, selected by layer3_compare.
	    - IPv4 source address.
	    - IPv4 destination address.
	    - IP Protocol: bits 7:0, set bits 31:8 to 0.
	*/
	uint32_t parameter10:32;
	/** Bit 63:32 of the first parameter (reserved for IPv6). */
	uint32_t parameter11:32;
	/** Bit 95:64 of the first parameter (reserved for IPv6). */
	uint32_t parameter12:32;
	/** Bit 127:96 of the first parameter (reserved for IPv6). */
	uint32_t parameter13:32;
	/** Bit 31:0 of the second parameter.
	    On API level either parameter200 or parameter201 can be selected.
	    This parameter can be disabled by layer2_disable.
	    This parameter can be of different types, selected by layer2_compare.
	    - MAC source address.
	    - MAC destination address.
	    - Ethertype (bits 15:0 of second parameter, set bits 31:16 to 0)
	*/
	uint32_t parameter200:32;
	/** Bit 47:32 of the second parameter.
	    Set to 0 in case of Ethertype in parameter200 or in case parameter201 is
	    selected.
	*/
	uint32_t parameter21:16;
	/** Bit 31:0 of the second parameter.
	    On API level either parameter200 or parameter201 can be selected.
	    This parameter can be disabled by layer4_disable.
	    This parameter can be of different types, selected by
	    layer4_port_compare, layer4_tcp_compare, and layer4_udp_compare.
	    - TCP source port or
	    - TCP destination port or
	    - UDP source port or
	    - UDP destination port or
	    - TCP/UDP source port or
	    - TCP/UDP destination port
	*/
	uint32_t parameter201:16;
	/** Parameter Mask 1, each bit of parameter 1 can be excluded from
	    comparison (masked) in IPv4 mode. Bit 0 controls parameter1(0), and so
	    on.
	    - 0: Ignore (do not use the selected bit position for comparison).
	    - 1: Use (use the selected bit position for comparison).
	*/
	uint32_t parameter_mask1:32;
	/** Forwarding ID, selects one of the configured forwarding IDs. The FID 
	    represents a VLAN or combination of two VLANs and is assigned in the FID
	    assignment (see ONU_GPE_FID_ASSIGNMENT_TABLE).
	*/
	uint32_t fid:8;
	/** Disable layer-2 fields for comparison.
	    - 0: Enabled (use the layer-2 fields of parameter2 for comparison; MAC
	    address, Ethertype).
	    - 1: Disabled (do not use the layer-2 fields of parameter2 for
	    comparison; MAC address, Ethertype).
	*/
	uint32_t layer2_disable:1;
	/** Disable the FID field for comparison.
	    - 0: Enabled (use the FID for comparison, field fid).
	    - 1: Disabled (do not use the FID for comparison, field fid).
	*/
	uint32_t fid_disable:1;
	/** Disable layer-3 fields for comparison.
	    - 0: Enabled (use the layer-3 fields of parameter1 for comparison; IPv4
	    address, IP Protocol).
	    - 1: Disabled (do not use the layer-3 fields of parameter1 for
	    comparison; IPv4 address, IP Protocol).
	*/
	uint32_t layer3_disable:1;
	/** Disable layer-4 fields for comparison.
	    - 0: Enabled (use the layer-4 fields of parameter1 for comparison;
	    TCP/UDP address).
	    - 1: Disabled (do not use the layer-4 fields of parameter1 for
	    comparison; TCP/UDP address).
	*/
	uint32_t layer4_disable:1;
	/** Select layer-2 field for comparison.
	    - 0: Compare Ethertype.
	    - 1: Compare MAC address (source or destination: see
	    layer2_mac_address_compare).
	*/
	uint32_t layer2_compare:1;
	/** Select MAC address for comparison.
	    - 0: Compare MAC destination address.
	    - 1: Compare MAC source address.
	*/
	uint32_t layer2_mac_address_compare:1;
	/** Select layer-3 field for comparison.
	    - 0: Compare IP Protocol.
	    - 1: Compare IP address (source or destination: see
	    layer3_ip_address_compare).
	*/
	uint32_t layer3_compare:1;
	/** Select IP address for comparison.
	    - 0: Compare IP destination address.
	    - 1: Compare IP source address.
	*/
	uint32_t layer3_ip_address_compare:1;
	/** Select TCP/UDP address for comparison.
	    - 0: Compare TCP/UDP destination port
	    - 1: Compare TCP/UDP source port
	*/
	uint32_t layer4_port_compare:1;
	/** Enable TCP port for comparison.
	    - 0: Ignore TCP port.
	    - 1: Compare TCP port.
	*/
	uint32_t layer4_tcp_enable:1;
	/** Enable UDP port for comparison.
	    - 0: Ignore UDP port.
	    - 1: Compare UDP port.
	*/
	uint32_t layer4_udp_enable:1;
	/** Ingress port enable for LAN 0, selects if this filter shall be applied.
	    - 0: Disabled (this ACL entry is ignored for this port).
	    - 1: Enabled (this ACL entry is used for this port).
	*/
	uint32_t ingress_port_lan0:1;
	/** Ingress port enable for LAN 1, selects if this filter shall be applied.
	    - 0: Disabled (this ACL entry is ignored for this port).
	    - 1: Enabled (this ACL entry is used for this port).
	*/
	uint32_t ingress_port_lan1:1;
	/** Ingress port enable for LAN 2, selects if this filter shall be applied.
	    - 0: Disabled (this ACL entry is ignored for this port).
	    - 1: Enabled (this ACL entry is used for this port).
	*/
	uint32_t ingress_port_lan2:1;
	/** Ingress port enable for LAN 3, selects if this filter shall be applied.
	    - 0: Disabled (this ACL entry is ignored for this port).
	    - 1: Enabled (this ACL entry is used for this port).
	*/
	uint32_t ingress_port_lan3:1;
	/** Unused data field, set to 0. */
	uint32_t unused1:7;
	/** End indication, marks if is the last entry of a sequence of entries that
	    are identified by the same hash value.
	    - 0: This is not the last entry.
	    - 1: This is the last entry.
	*/
	uint32_t end:1;
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
#endif
} __PACKED__;

/** ONU_GPE_BRIDGE_TABLE structure definition.
   Bridge Configuration.
The table instance value shall be set to 0x01 for reading and to 0x3F for write access.
*/
struct gpe_bridge_table {
#if __BYTE_ORDER == __BIG_ENDIAN
	/** Unused data field, set to 0. */
	uint32_t unused27:32;
	/** Unused data field, set to 0. */
	uint32_t unused26:32;
	/** Unused data field, set to 0. */
	uint32_t unused25:1;
	/** Bridge Port Index for Bit 15 of the flooding and multicast port map. */
	uint32_t egress_bridge_port_index15:7;
	/** Unused data field, set to 0. */
	uint32_t unused24:1;
	/** Bridge Port Index for Bit 14 of the flooding and multicast port map. */
	uint32_t egress_bridge_port_index14:7;
	/** Unused data field, set to 0. */
	uint32_t unused23:1;
	/** Bridge Port Index for Bit 13 of the flooding and multicast port map. */
	uint32_t egress_bridge_port_index13:7;
	/** Unused data field, set to 0. */
	uint32_t unused22:1;
	/** Bridge Port Index for Bit 12 of the flooding and multicast port map. */
	uint32_t egress_bridge_port_index12:7;
	/** Unused data field, set to 0. */
	uint32_t unused21:1;
	/** Bridge Port Index for Bit 11 of the flooding and multicast port map. */
	uint32_t egress_bridge_port_index11:7;
	/** Unused data field, set to 0. */
	uint32_t unused20:1;
	/** Bridge Port Index for Bit 10 of the flooding and multicast port map. */
	uint32_t egress_bridge_port_index10:7;
	/** Unused data field, set to 0. */
	uint32_t unused19:1;
	/** Bridge Port Index for Bit 9 of the flooding and multicast port map. */
	uint32_t egress_bridge_port_index9:7;
	/** Unused data field, set to 0. */
	uint32_t unused18:1;
	/** Bridge Port Index for Bit 8 of the flooding and multicast port map. */
	uint32_t egress_bridge_port_index8:7;
	/** Unused data field, set to 0. */
	uint32_t unused17:1;
	/** Bridge Port Index for Bit 7 of the flooding and multicast port map. */
	uint32_t egress_bridge_port_index7:7;
	/** Unused data field, set to 0. */
	uint32_t unused16:1;
	/** Bridge Port Index for Bit 6 of the flooding and multicast port map. */
	uint32_t egress_bridge_port_index6:7;
	/** Unused data field, set to 0. */
	uint32_t unused15:1;
	/** Bridge Port Index for Bit 5 of the flooding and multicast port map. */
	uint32_t egress_bridge_port_index5:7;
	/** Unused data field, set to 0. */
	uint32_t unused14:1;
	/** Bridge Port Index for Bit 4 of the flooding and multicast port map. */
	uint32_t egress_bridge_port_index4:7;
	/** Unused data field, set to 0. */
	uint32_t unused13:1;
	/** Bridge Port Index for Bit 3 of the flooding and multicast port map.
	    This is always connected with UNI port 3.
	*/
	uint32_t egress_bridge_port_index3:7;
	/** Unused data field, set to 0. */
	uint32_t unused12:1;
	/** Bridge Port Index for Bit 2 of the flooding and multicast port map.
	    This is always connected with UNI port 2.
	*/
	uint32_t egress_bridge_port_index2:7;
	/** Unused data field, set to 0. */
	uint32_t unused11:1;
	/** Bridge Port Index for Bit 1 of the flooding and multicast port map.
	    This is always connected with UNI port 1.
	*/
	uint32_t egress_bridge_port_index1:7;
	/** Unused data field, set to 0. */
	uint32_t unused10:1;
	/** Bridge Port Index for Bit 0 of the flooding and multicast port map.
	    This is always connected with UNI port 0.
	*/
	uint32_t egress_bridge_port_index0:7;
	/** Flooding Bridge Port Enable bit map [15:0].
	    Bit x controls the egress bridge port index x.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t flooding_bridge_port_enable:16;
	/** Broadcast meter enable.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t bc_meter_enable:1;
	/** Unused data field, set to 0. */
	uint32_t unused3:6;
	/** Ingress dual token bucket meter selection for broadcast traffic, the
	    upper 8 bit of this value are used to address one of up to 256 meter
	    units, the LSB must be set to 0.
	*/
	uint32_t bc_meter_id:9;
	/** Multicast meter enable.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t mc_meter_enable:1;
	/** Unused data field, set to 0. */
	uint32_t unused2:6;
	/** Ingress dual token bucket meter selection for multicast traffic, the
	    upper 8 bit of this value are used to address one of up to 256 meter
	    units, the LSB must be set to 0.
	*/
	uint32_t mc_meter_id:9;
	/** Unknown unicast meter enable.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t uuc_meter_enable:1;
	/** Unused data field, set to 0. */
	uint32_t unused1:6;
	/** Ingress dual token bucket meter selection for unknown unicast traffic,
	    the upper 8 bit of this value are used to address one of up to 256 meter
	    units, the LSB must be set to 0.
	*/
	uint32_t uuc_meter_id:9;
#else
	/** Ingress dual token bucket meter selection for unknown unicast traffic,
	    the upper 8 bit of this value are used to address one of up to 256 meter
	    units, the LSB must be set to 0.
	*/
	uint32_t uuc_meter_id:9;
	/** Unused data field, set to 0. */
	uint32_t unused1:6;
	/** Unknown unicast meter enable.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t uuc_meter_enable:1;
	/** Ingress dual token bucket meter selection for multicast traffic, the
	    upper 8 bit of this value are used to address one of up to 256 meter
	    units, the LSB must be set to 0.
	*/
	uint32_t mc_meter_id:9;
	/** Unused data field, set to 0. */
	uint32_t unused2:6;
	/** Multicast meter enable.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t mc_meter_enable:1;
	/** Ingress dual token bucket meter selection for broadcast traffic, the
	    upper 8 bit of this value are used to address one of up to 256 meter
	    units, the LSB must be set to 0.
	*/
	uint32_t bc_meter_id:9;
	/** Unused data field, set to 0. */
	uint32_t unused3:6;
	/** Broadcast meter enable.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t bc_meter_enable:1;
	/** Flooding Bridge Port Enable bit map [15:0].
	    Bit x controls the egress bridge port index x.
	    - 0: Disabled
	    - 1: Enabled
	*/
	uint32_t flooding_bridge_port_enable:16;
	/** Bridge Port Index for Bit 0 of the flooding and multicast port map.
	    This is always connected with UNI port 0.
	*/
	uint32_t egress_bridge_port_index0:7;
	/** Unused data field, set to 0. */
	uint32_t unused10:1;
	/** Bridge Port Index for Bit 1 of the flooding and multicast port map.
	    This is always connected with UNI port 1.
	*/
	uint32_t egress_bridge_port_index1:7;
	/** Unused data field, set to 0. */
	uint32_t unused11:1;
	/** Bridge Port Index for Bit 2 of the flooding and multicast port map.
	    This is always connected with UNI port 2.
	*/
	uint32_t egress_bridge_port_index2:7;
	/** Unused data field, set to 0. */
	uint32_t unused12:1;
	/** Bridge Port Index for Bit 3 of the flooding and multicast port map.
	    This is always connected with UNI port 3.
	*/
	uint32_t egress_bridge_port_index3:7;
	/** Unused data field, set to 0. */
	uint32_t unused13:1;
	/** Bridge Port Index for Bit 4 of the flooding and multicast port map. */
	uint32_t egress_bridge_port_index4:7;
	/** Unused data field, set to 0. */
	uint32_t unused14:1;
	/** Bridge Port Index for Bit 5 of the flooding and multicast port map. */
	uint32_t egress_bridge_port_index5:7;
	/** Unused data field, set to 0. */
	uint32_t unused15:1;
	/** Bridge Port Index for Bit 6 of the flooding and multicast port map. */
	uint32_t egress_bridge_port_index6:7;
	/** Unused data field, set to 0. */
	uint32_t unused16:1;
	/** Bridge Port Index for Bit 7 of the flooding and multicast port map. */
	uint32_t egress_bridge_port_index7:7;
	/** Unused data field, set to 0. */
	uint32_t unused17:1;
	/** Bridge Port Index for Bit 8 of the flooding and multicast port map. */
	uint32_t egress_bridge_port_index8:7;
	/** Unused data field, set to 0. */
	uint32_t unused18:1;
	/** Bridge Port Index for Bit 9 of the flooding and multicast port map. */
	uint32_t egress_bridge_port_index9:7;
	/** Unused data field, set to 0. */
	uint32_t unused19:1;
	/** Bridge Port Index for Bit 10 of the flooding and multicast port map. */
	uint32_t egress_bridge_port_index10:7;
	/** Unused data field, set to 0. */
	uint32_t unused20:1;
	/** Bridge Port Index for Bit 11 of the flooding and multicast port map. */
	uint32_t egress_bridge_port_index11:7;
	/** Unused data field, set to 0. */
	uint32_t unused21:1;
	/** Bridge Port Index for Bit 12 of the flooding and multicast port map. */
	uint32_t egress_bridge_port_index12:7;
	/** Unused data field, set to 0. */
	uint32_t unused22:1;
	/** Bridge Port Index for Bit 13 of the flooding and multicast port map. */
	uint32_t egress_bridge_port_index13:7;
	/** Unused data field, set to 0. */
	uint32_t unused23:1;
	/** Bridge Port Index for Bit 14 of the flooding and multicast port map. */
	uint32_t egress_bridge_port_index14:7;
	/** Unused data field, set to 0. */
	uint32_t unused24:1;
	/** Bridge Port Index for Bit 15 of the flooding and multicast port map. */
	uint32_t egress_bridge_port_index15:7;
	/** Unused data field, set to 0. */
	uint32_t unused25:1;
	/** Unused data field, set to 0. */
	uint32_t unused26:32;
	/** Unused data field, set to 0. */
	uint32_t unused27:32;
#endif
} __PACKED__;

/** ONU_GPE_ETHERTYPE_EXCEPTION_TABLE structure definition.
   This table defines the Ethertypes which shall be considered as Exceptions.
*/
struct gpe_ethertype_exception_table {
#if __BYTE_ORDER == __BIG_ENDIAN
	/** Matching one of these Ethertypes causes a SpecTag Exception */
	uint16_t spec_ethertype:16;
#else
	/** Matching one of these Ethertypes causes a SpecTag Exception */
	uint16_t spec_ethertype:16;
#endif
} __PACKED__;

/** ONU_GPE_ETHERTYPE_FILTER_TABLE structure definition.
   Ethertypes for blacklist or whitelist filtering.
The table instance value shall be set to 1.
*/
struct gpe_ethertype_table {
#if __BYTE_ORDER == __BIG_ENDIAN
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
	/** End indication, marks if is the last entry to be used in a linear
	    search.
	    - 0: This is not the last entry.
	    - 1: This is the last entry.
	*/
	uint32_t end:1;
	/** Unused data field, set to 0. */
	uint32_t unused:14;
	/** Ethertype value. */
	uint32_t ethertype:16;
#else
	/** Ethertype value. */
	uint32_t ethertype:16;
	/** Unused data field, set to 0. */
	uint32_t unused:14;
	/** End indication, marks if is the last entry to be used in a linear
	    search.
	    - 0: This is not the last entry.
	    - 1: This is the last entry.
	*/
	uint32_t end:1;
	/** Entry validity.
	    - 0: This table entry is void.
	    - 1: This table entry is valid.
	*/
	uint32_t valid:1;
#endif
} __PACKED__;

/** ONU_GPE_ENQUEUE_TABLE structure definition.
   Vector of Enqueue Enable Bits.
The table instance value shall be set to 0x01 for reading and to 0x3F for write access.
*/
struct gpe_enqueue_table {
#if __BYTE_ORDER == __BIG_ENDIAN
	/** Enqueue Enable Bits.
	    Bit N refers to QID = 32*INDEX + N
	    - 0: Enqueueing disabled.
	    - 1: Enqueueing enabled.
	*/
	uint32_t enable:32;
#else
	/** Enqueue Enable Bits.
	    Bit N refers to QID = 32*INDEX + N
	    - 0: Enqueueing disabled.
	    - 1: Enqueueing enabled.
	*/
	uint32_t enable:32;
#endif
} __PACKED__;

/** ONU_GPE_COUNTER_TABLE structure definition.
   Performance counters.
The table instance value shall be set to 1.
*/
struct gpe_counter_table {
#if __BYTE_ORDER == __BIG_ENDIAN
	/** Counter value. */
	uint32_t counter_value:32;
#else
	/** Counter value. */
	uint32_t counter_value:32;
#endif
} __PACKED__;

/** ONU_GPE_STATUS_TABLE structure definition.
   SCE firmware output.
The table instance value shall be set to.
- 0x01: for reading
- 0x3F: for write access.
*/
struct gpe_status_table {
#if __BYTE_ORDER == __BIG_ENDIAN
	/** See the definition of entry_data in the UM PR document. */
	uint32_t entry_data:32;
#else
	/** See the definition of entry_data in the UM PR document. */
	uint32_t entry_data:32;
#endif
} __PACKED__;

/** ONU_GPE_CONSTANTS_TABLE structure definition.
   Definition of global SCE firmware constants.
The table instance value shall be set toThe table instance value shall be set to.
- 0x01: for reading
- 0x3F: for write access.
*/
struct gpe_constants_table {
#if __BYTE_ORDER == __BIG_ENDIAN
	/** See the definition of entry_data in the UM PR document. */
	uint32_t entry_data:32;
#else
	/** See the definition of entry_data in the UM PR document. */
	uint32_t entry_data:32;
#endif
} __PACKED__;

/** Hardware coprocessor message container. */
struct gpe_cop_message {
	/** Coprocessor message contents. */
	uint32_t data[8];
} __PACKED__;

/** Structure to specify all Extended VLAN translation bits
 */
struct gpe_extended_translation_in {
	/** VLAN priority code point */
	uint32_t riPCP:3;
	/** Drop Eligible Indicator */
	uint32_t riDEI:1;
	/** VLAN identifier */
	uint32_t riVID:12;
	/** unused field */
	uint32_t Spare2:8;
	/** Is single tagged information */
	uint32_t SingleTagged:1;
	/** Is multiple tagged information */
	uint32_t MultipleTagged:1;
	/** unused field */
	uint32_t Spare1:6;
	/** VLAN priority code point */
	uint32_t roPCP:3;
	/** drop eligible indicator */
	uint32_t roDEI:1;
	/** VLAN identifier */
	uint32_t roVID:12;
	/** VLAN tag protocol identifier */
	uint32_t riTPID:16;
	/** Ethertype field */
	uint32_t rETY:16;
	/** VLAN tag protocol identifier */
	uint32_t roTPID:16;
} __PACKED__;

/** Structure to specify all Extended VLAN translation result bits
 */
struct gpe_extended_translation_out {
	/** VLAN priority code point */
	uint32_t taPCP:3;
	/** Drop Eligible Indicator */
	uint32_t taDEI:1;
	/** VLAN identifier */
	uint32_t taVID:12;
	/** Unused field */
	uint32_t unused1:5;
	/** DSCP translation table pointer */
	uint32_t DSCP_TablePointer:3;
	/** Unused field */
	uint32_t unused2:1;
	/** DSCP code point */
	uint32_t tbdscptopcp:1;
	/** DSCP code point */
	uint32_t tadscptopcp:1;
	/** Discard flag */
	uint32_t discard:1;
	/** VLAN tag flag */
	uint32_t titag:1;
	/** VLAN tag flag */
	uint32_t totag:1;
	/** VLAN tag flag */
	uint32_t tbtag:1;
	/** VLAN tag flag */
	uint32_t tatag:1;
	/** VLAN priority code point */
	uint32_t tbPCP:3;
	/** Drop Eligible Indicator */
	uint32_t tbDEI:1;
	/** VLAN identifier */
	uint32_t tbVID:12;
	/** VLAN tag protocol identifier */
	uint32_t taTPID:16;
	/** Unused field */
	uint32_t unused3:16;
	/** VLAN tag protocol identifier */
	uint32_t tbTPID:16;
	/** Unused field */
	uint32_t unused4:32;
} __PACKED__;

/** Structure to specify all Tagging filter bits (input)
*/
struct gpe_tagg_filter_in {
	/** Tagging filter. */
	uint32_t tagged:1;
	/** Reserved. */
	uint32_t res:15;
	/** Tag control information. */
	uint32_t tci:16;
} __PACKED__;

/** Structure to specify all Tagging filter bits (output)
*/
struct gpe_tagg_filter_out {
	/** Tagging filter. */
	uint32_t data;
} __PACKED__;

/** Table entry data */
union gpe_table_data {
	/** ONU_GPE_DS_GEM_PORT_TABLE structure definition.
	 This table handles the GEM Port ID related handling instructions for
	 downstream data traffic.
	 The index used to access this table is the GEM port index (gpix).
	 The table instance value shall be set to 1.
	 */
	struct gpe_ds_gem_port_table ds_gem_port;
	/** ONU_GPE_US_GEM_PORT_TABLE structure definition.
	 This table handles the GEM Port ID related handling instructions for
	 upstream data traffic.
	 The index used to access this table is the GEM port index (gpix).
	 The table instance value shall be set to 1.
	 */
	struct gpe_us_gem_port_table us_gem_port;
	/** ONU_GPE_FID_ASSIGNMENT_TABLE structure definition.
	 Defines the Forwarding IDs (FID) based on outer/inner VLAN.
	 */
	struct gpe_fwd_id_table fwd_id;
	/** ONU_GPE_FID_HASH_TABLE structure definition.
	 Defines the Forwarding IDs (FID) based on outer/inner VLAN.
	 */
	struct gpe_fwd_id_hash_table fwd_id_hash;
	/** ONU_GPE_BRIDGE_PORT_TABLE structure definition.
	 This table holds bridge port related configurations.
	 The index used to access this table is the bridge_port_index.
	 The table instance value shall be set to 1 for reading and to 0x3F for
	 write access.
	 */
	struct gpe_bridge_port_table bridge_port;
	/** ONU_GPE_TAGGING_FILTER_TABLE structure definition.
	 Defines the ingress VLAN handling.
	 The index values used to access this table are the
	 tagging_filter_ingress and the tagging_filter_egress pointers that are
	 provided in the ONU_GPE_BRIDGE_PORT_TABLE.
	 The table instance value shall be set to 1.
	 */
	struct gpe_tagging_filter_table tagging_filter;
	/** ONU_GPE_VLAN_TABLE structure definition.
	 This table holds VLAN definitions.
	 The index used to access this table is arbitrary, controlled by the VLAN
	 add function.
	 The table instance value shall be set to 1.
	 */
	struct gpe_vlan_table vlan;
	/** ONU_GPE_EXTENDED_VLAN_TABLE structure definition.
	 This table contains the basic part of the Extended VLAN configuration.
	 The index used to access this table is the Extended VLAN rule set
	 number.
	 The table instance value shall be set to 1.
	 */
	struct gpe_extended_vlan_table extended_vlan;
	/** ONU_GPE_VLAN_RULE_TABLE structure definition.
	 This table contains the filtering part of the Extended VLAN rules.
	 The index used to access this table is the vlan_rule_index.
	 The table instance value shall be set to 1.
	 */
	struct gpe_vlan_rule_table vlan_rule;
	/** ONU_GPE_VLAN_TREATMENT_TABLE structure definition.
	 This table contains the treatment part of the Extended VLAN rules.
	 The index used to access this table is the vlan_rule_index.
	 The table instance value shall be set to 1. "taga" refers to the outer
	 VLAN tag (if tagged), "tagb" to the inner (if double-tagged).
	 Note: Treatments that imply the reception of two VLAN tags must not be
	 called for rules that have (zero_enable == 1) or (one_enable == 1).
	 Otherwise the treatment would result in unpredictable results.
	 */
	struct gpe_vlan_treatment_table vlan_treatment;
	/** ONU_GPE_PMAPPER_TABLE structure definition.
	 This table holds the 802.1p mapper configuration.
	 The index used to access this table is the pmapper_index.
	 The table instance value shall be set to.
	 - 0x01: for reading
	 - 0x3F: for write access.
	 */
	struct gpe_pmapper_table pmapper;
	/** ONU_GPE_SHORT_FWD_HASH_TABLE structure definition.
	 This is the hash table related to the ONU_GPE_SHORT_FWD_TABLE_MAC(_MC).
	 No table access by the application software is needed.
	 */
	struct gpe_short_fwd_hash_table short_fwd_hash;
	/** ONU_GPE_SHORT_FWD_TABLE_MAC structure definition.
	 Layer-2 unicast forwarding table, separate entries are provided for
	 upstream and downstream data traffic.
	 The table instance value shall be set to 1.
	 */
	struct gpe_short_fwd_table_mac short_fwd_table_mac;
	/** ONU_GPE_SHORT_FWD_TABLE_MAC_MC structure definition.
	 Layer-2 multicast forwarding table.
	 The table instance value shall be set to 1.
	 */
	struct gpe_short_fwd_table_mac_mc short_fwd_table_mac_mc;
	/** ONU_GPE_SHORT_FWD_TABLE_IPV4 structure definition.
	 Layer-3 unicast forwarding table, separate entries are provided for
	 upstream and downstream data traffic.
	 The table instance value shall be set to 1.
	 */
	struct gpe_short_fwd_table_ipv4 short_fwd_table_ipv4;
	/** ONU_GPE_SHORT_FWD_TABLE_IPV4_MC structure definition.
	 Layer-3 multicast forwarding table.
	 The table instance value shall be set to 1.
	 */
	struct gpe_short_fwd_table_ipv4_mc short_fwd_table_ipv4_mc;
	/** ONU_GPE_LONG_FWD_HASH_TABLE structure definition.
	 This is the hash table related to the ONU_GPE_LONG_FWD_TABLE_IPV6(_MC).
	 No table access by the application software is needed.
	 */
	struct gpe_long_fwd_hash_table long_fwd_hash;
	/** ONU_GPE_LONG_FWD_TABLE_IPV6 structure definition.
	 Layer-3 unicast forwarding table, separate entries are provided for
	 upstream and downstream data traffic.
	 The table instance value shall be set to 1.
	 */
	struct gpe_long_fwd_table_ipv6 long_fwd_table_ipv6;
	/** ONU_GPE_LONG_FWD_TABLE_IPV6_MC structure definition.
	 Layer-3 multicast forwarding table.
	 The table instance value shall be set to 1.
	 */
	struct gpe_long_fwd_table_ipv6_mc long_fwd_table_ipv6_mc;
	/** ONU_GPE_DS_MC_IPV4_SOURCE_FILTER_TABLE structure definition.
	 This table holds IPv4 MC source filter entries (IGMPv3).
	 The table instance value shall be set to 1.
	 */
	struct gpe_ds_mc_ipv4_source_filter_table ds_mc_ipv4_source_filter;
	/** ONU_GPE_DS_MC_IPV6_SOURCE_FILTER_TABLE structure definition.
	 This table holds IPv6 MC source filter entries (MLDv2).
	 The table instance value shall be set to 1.
	 */
	struct gpe_ds_mc_ipv6_source_filter_table ds_mc_ipv6_source_filter;
	/** ONU_GPE_LEARNING_LIMITATION_TABLE structure definition.
	 This table holds the MAC address learning limits per bridge port.
	 The index used to access this table is the bridge_port_index.
	 The table instance value shall be set to 1.
	 */
	struct gpe_learning_limitation_table learning_limitation;
	/** ONU_GPE_LAN_PORT_TABLE structure definition.
	 UNI-port specific configuration: 4 Ethernet UNI ports and 4 Virtual
	 Ethernet Interface ports.
	 The index used to access this table is the lan_port_index.
	 The table instance value shall be set to.
	 - 0x01: for reading
	 - 0x3F: for write acces
	 */
	struct gpe_lan_port_table lan_port;
	/** ONU_GPE_PCP_DECODING_TABLE structure definition.
	 This table is used to configure the PCP decoding.
	 The index to this table is composed of two parts.
	 - Bit 4-3: Controlled by the PCP decoding mode (mode 3 = 0b00 to mode 6
	 = 0b11.
	 - Bit 2-0: Controlled by the received PCP code point.
	 The table instance value shall be set to.
	 - 0x01: for reading
	 - 0x3F: for write access
	 */
	struct gpe_pcp_decoding_table pcp_decoding;
	/** ONU_GPE_DSCP_DECODING_TABLE structure definition.
	 This table is used to configure the DSCP decoding.
	 The index to this table is composed of two parts.
	 - Bit 8-6: Controlled by the dscp_table_pointer (selects one of eight
	 sub-tables).
	 - Bit 5-0: Controlled by the received DSCP/TOS field of the IP header.
	 The table instance value shall be set to.
	 - 0x01: for reading
	 - 0x3F: for write access.
	 */
	struct gpe_dscp_decoding_table dscp_decoding;
	/** ONU_GPE_PCP_ENCODING_TABLE structure definition.
	 This table is used to configure the PCP encoding.
	 The index to this table is composed of three parts.
	 - Bit 5-4: These bits are controlled by the egress_color_marking mode
	 (subtract 3 from the mode's code point).
	 - Bit 3: This bit is controlled by the DE bit.
	 - Bit 2-0: These are controlled by the priority.
	 The table instance value shall be set to.
	 - 0x01: for reading
	 - 0x3F: for write access.
	 */
	struct gpe_pcp_encoding_table pcp_encoding;
	/** ONU_GPE_DSCP_ENCODING_TABLE structure definition.
	 This table is used to configure the DSCP encoding.
	 The index to this table is composed of two parts.
	 - Bit 4-3: These bits are controlled by the egress_color_marking mode
	 (subtract 3 from the mode's code point).
	 - Bit 2-0 These bits are controlled by the priority.
	 The table instance value shall be set to.
	 - 0x01: for reading
	 - 0x3F: for write access.
	 */
	struct gpe_dscp_encoding_table dscp_encoding;
	/** ONU_GPE_EXCEPTION_TABLE structure definition.
	 This table is used to configure the exception handling.
	 This table is addressed by an exception_profile index.
	 The table instance value shall be set to 1.
	 */
	struct gpe_exception_table exception;
	/** ONU_GPE_REDIRECTION_TABLE structure definition.
	 Traffic redirection by exception.
	 The table instance value shall be set to.
	 - 0x01: for reading
	 - 0x3F: for write access.
	 */
	struct gpe_redirection_table redirection;
	/** ONU_GPE_MAC_FILTER_TABLE structure definition.
	 MAC table for SA/DA filtering.
	 The table instance value shall be set to 1.
	 */
	struct gpe_mac_filter_table mac_filter;
	/** ONU_GPE_ACL_FILTER_TABLE structure definition.
	 Ingress packet filter, processed after exception handling.
	 The table instance value shall be set to.
	 - 0x01: for reading
	 - 0x3F: for write access.
	 */
	struct gpe_acl_filter_table acl_filter;
	/** ONU_GPE_ACL_FILTER_TABLE_2 structure definition.
	 Ingress packet filter, processed after exception handling.
	 The table instance value shall be set to.
	 - 0x01: for reading
	 - 0x3F: for write access.
	 */
	struct gpe_acl_filter_table2 acl_filter_table2;
	/** ONU_GPE_BRIDGE_TABLE structure definition.
	 Bridge Configuration.
	 The table instance value shall be set to 0x01 for reading and to 0x3F
	 for write access.
	 */
	struct gpe_bridge_table bridge;
	/** ONU_GPE_ETHERTYPE_EXCEPTION_TABLE structure definition.
	 This table defines the Ethertypes which shall be considered as
	 Exceptions.
	 */
	struct gpe_ethertype_exception_table ethertype_exception;
	/** ONU_GPE_ETHERTYPE_FILTER_TABLE structure definition.
	 Ethertypes for blacklist or whitelist filtering.
	 The table instance value shall be set to 1.
	 */
	struct gpe_ethertype_table ethertype;
	/** ONU_GPE_ENQUEUE_TABLE structure definition.
	 Vector of Enqueue Enable Bits.
	 The table instance value shall be set to 0x01 for reading and to 0x3F
	 for write access.
	 */
	struct gpe_enqueue_table enqueue;
	/** ONU_GPE_COUNTER_TABLE structure definition.
	 Performance counters.
	 The table instance value shall be set to 1.
	 */
	struct gpe_counter_table counter;
	/** ONU_GPE_STATUS_TABLE structure definition.
	 SCE firmware output.
	 The table instance value shall be set to.
	 - 0x01: for reading
	 - 0x3F: for write access.
	 */
	struct gpe_status_table status;
	/** ONU_GPE_CONSTANTS_TABLE structure definition.
	 Definition of global SCE firmware constants.
	 The table instance value shall be set toThe table instance value shall
	 be set to.
	 - 0x01: for reading
	 - 0x3F: for write access.
	 */
	struct gpe_constants_table constants;
	/** Hardware coprocessor message container. */
	struct gpe_cop_message message;
	/** ExtVLAN execute response */
	struct gpe_extended_translation_in extended_vlan_in;
	/** ExtVLAN execute response */
	struct gpe_extended_translation_out extended_vlan_out;
	/** Tagging filter execute response */
	struct gpe_tagg_filter_in tagg_filter_in;
	/** Tagging filter execute response */
	struct gpe_tagg_filter_out tagg_filter_out;
} __PACKED__;

/** Structure to specify GPE table access.
*/
struct gpe_table {
	/** Table ID
	    Please refer to ONU_GPE_<table_name>_TABLE_ID as defined in
	    drv_onu_resource_gpe.h */
	uint32_t id;
	/** Table instance selection
	    This parameter provides a bit map for firmware-based tables only 
	    and ignored for hardware-based tables.
	    It is used to access one or more hardware instances of the same logical
	    table. Up to six parallel tables are supported, addressed by bit 
	    positions 0 to 5. Multiple bits may be set for write accesses, a value 
	    of 0x3F causes all six tables to be written with the same value. 
	    If one or more of the six processing elements have not been activated,
	    the related bits are ignored. */
	uint32_t instance;
	/** Table index */
	uint32_t index;
	/** Table data */
	union gpe_table_data data;
} __PACKED__;

/** Generic GPE table access structure. Used by \ref FIO_GPE_TABLE_ENTRY_SET
   and \ref FIO_GPE_TABLE_ENTRY_GET.
*/
struct gpe_table_entry {
	/** Table ID
	    Please refer to ONU_GPE_<table_name>_TABLE_ID as defined in
	    drv_onu_resource_gpe.h */
	uint32_t id;
	/** Table instance selection
	    This parameter provides a bit map for firmware-based tables only 
	    and ignored for hardware-based tables.
	    It is used to access one or more hardware instances of the same logical
	    table. Up to six parallel tables are supported, addressed by bit 
	    positions 0 to 5. Multiple bits may be set for write accesses, a value 
	    of 0x3F causes all six tables to be written with the same value. 
	    If one or more of the six processing elements have not been activated,
	    the related bits are ignored. */
	uint32_t instance;
	/** Table index */
	uint32_t index;
	/** Table data */
	union gpe_table_data data;
	/** Hash data in case of using hashed tables */
	union gpe_table_data hashdata;
	/** Table result */
	uint32_t result;
} __PACKED__;

EXTERN_C_END

/*! @} */

/*! @} */

#ifdef __PACKED_DEFINED__
#  if !defined (__GNUC__) && !defined (__GNUG__)
#    pragma pack()
#  endif
#  undef __PACKED_DEFINED__
#  undef __PACKED__
#endif

#endif
