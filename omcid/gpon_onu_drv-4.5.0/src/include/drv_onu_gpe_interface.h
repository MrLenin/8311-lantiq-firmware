/******************************************************************************

                               Copyright (c) 2012
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_onu_gpe_interface.h
   This is the GPON Packet Engine (GPE) header file, used for PSB980x0 FALC ON-bsed GPON ONUs.

   The variable types (8, 16, or 32 bit) reflect the values ranges
   that are defined by the hardware table sizes etc. If hardware
   resources are increased, the variable type definition might need
   to be changed. Check drv_onu_resource.h for changes.
*/
#ifndef _drv_onu_gpe_h_
#define _drv_onu_gpe_h_

#include "drv_onu_std_defs.h"
#include "drv_onu_types.h"
#include "drv_onu_gpe_tables.h"
#include "drv_onu_resource.h"
#include "drv_onu_resource_gpe.h"

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
/** \defgroup ONU_GPE GPON Packet Engine

    This chapter describes the software interface to access and configure the
    GPON Packet Engine (GPE).
   @{
*/
    /*
    The access to the following GPE sub-modules is
    covered by this software functions:
    - ICTRLG: Input Control for data received from the GPON link
             (downstream direction); the related register block is named ICTRLG.
    - ICTRLL: Input Control for date received on one of the LAN interfaces in
             (upstream direction); the related register blocks are named ICTRL1
             to ICTRL4.
    - OCTRLG: Output Control for data to be sent on the GPON link in
             (upstream direction); the related register block is named OCTRLG.
    - OCTRLL: Output Control for data to be sent on one of the LAN interfaces
             (downstream direction); the related register blocks are named
             OCTRL0 to OCTRL3
    - FSQM:  Free Segment Queue Manager
    - IQM:   Ingress Queue Manager
    - TBM:   Token Bucket Meter for traffic flow metering in upstream and
             downstream direction
    - TMU:   Traffic Management Unit for queueing and scheduling of data traffic
             in upstream and downstream direction, composed of
             - PBM: Packet Buffer Manager and
             - PSM: Packet Scheduler Manager
    - SCE:   Shared Classification Engine for data parsing and classification;
             the related register block is named PCTRL.
             */

/* Constant Definitions - GPE
   ================================== */
/** Reset mask for the Received GEM frames/packets counter*/
#define ONU_GPE_GEM_CNT_RST_MASK_RX_FRAMES			(1 << 0)
/** Reset mask for the Received GEM payload bytes counter*/
#define ONU_GPE_GEM_CNT_RST_MASK_RX_BYTES			(1 << 1)
/** Reset mask for the Transmitted GEM frames counter*/
#define ONU_GPE_GEM_CNT_RST_MASK_TX_FRAMES			(1 << 2)
/** Reset mask for the Transmitted GEM payload bytes counter*/
#define ONU_GPE_GEM_CNT_RST_MASK_TX_BYTES			(1 << 3)

/** Reset mask for the Bridge learning entry discard counter*/
#define ONU_GPE_BRIDGE_CNT_RST_MASK_LEARN_DISCARD	(1 << 0)

/** Minimum configurable value for Committed Information Rate, bytes/s*/
#define ONU_GPE_TBS_CIR_MIN	2500UL
/** Maximum configurable value for Committed Information Rate, bytes/s*/
#define ONU_GPE_TBS_CIR_MAX	125000000UL
/** Factory default value for Committed Information Rate, bytes/s*/
#define ONU_GPE_TBS_CIR_DEF	ONU_GPE_TBS_CIR_MAX

/** Minimum configurable value for Peak Information Rate, bytes/s*/
#define ONU_GPE_TBS_PIR_MIN	2500UL
/** Maximum configurable value for Peak Information Rate, bytes/s*/
#define ONU_GPE_TBS_PIR_MAX	125000000UL
/** Factory default value for Peak Information Rate, bytes/s*/
#define ONU_GPE_TBS_PIR_DEF	ONU_GPE_TBS_PIR_MAX

/** Maximum configurable value for TBS committed maximum burst size*/
#define ONU_GPE_TBS_CBS_MAX	16777215UL
/** Factory default value for TBS committed maximum burst size*/
#define ONU_GPE_TBS_CBS_DEF	16000000UL

/** Maximum configurable value for TBS peak maximum burst size*/
#define ONU_GPE_TBS_PBS_MAX	16777215UL
/** Factory default value for TBS peak maximum burst size*/
#define ONU_GPE_TBS_PBS_DEF	16000000UL

/** Minimum configurable value for Committed Information Rate, bytes/s*/
#define ONU_GPE_METER_CIR_MIN	3
/** Maximum configurable value for Committed Information Rate, bytes/s*/
#define ONU_GPE_METER_CIR_MAX	125000000UL
/** Factory default value for Committed Information Rate, bytes/s*/
#define ONU_GPE_METER_CIR_DEF	ONU_GPE_METER_CIR_MAX

/** Minimum configurable value for Peak Information Rate, bytes/s*/
#define ONU_GPE_METER_PIR_MIN	3
/** Maximum configurable value for Peak Information Rate, bytes/s*/
#define ONU_GPE_METER_PIR_MAX	125000000UL
/** Factory default value for Peak Information Rate, bytes/s*/
#define ONU_GPE_METER_PIR_DEF	ONU_GPE_METER_PIR_MAX

/** Maximum configurable value for Meter committed maximum burst size*/
#define ONU_GPE_METER_CBS_MAX	1048575UL
/** Factory default value for TBS committed maximum burst size*/
#define ONU_GPE_METER_CBS_DEF	ONU_GPE_METER_CBS_MAX

/** Maximum configurable value for Meter peak maximum burst size*/
#define ONU_GPE_METER_PBS_MAX	1048575UL
/** Factory default value for TBS peak maximum burst size*/
#define ONU_GPE_METER_PBS_DEF	ONU_GPE_METER_PBS_MAX

/** \todo add definition for QOSL */
#define ONU_GPE_QOSL		8000UL

/* Enumeration Type Definitions - GPE (GPON Packet Engine)
   =======================================================
*/
/** Port state.
    Port states are defined in IEEE 802.1 as well as in IETF RFC 1493.
    For this reason, different names can be used for physically and logically
    equivalent port states.
*/
enum gpe_port_state {
	/** Forwarding state: frames are forwarded, MAC addresses are learned.*/
	GPE_PORT_STATE_FORWARDING = 0,
	/** Learning state: frames are dropped, MAC addresses are learned.*/
	GPE_PORT_STATE_LEARNING = 1,
	/** Discarding state: frames are dropped, no MAC address is learned.*/
	GPE_PORT_STATE_DISCARDING = 2,
	/** Listening state (same code point as above, alternative naming).*/
	GPE_PORT_STATE_LISTENING = 2,
	/** Blocking state (same code point as above, alternative naming).*/
	GPE_PORT_STATE_BLOCKING = 2,
	/** Broken state (same code point as above, alternative naming).*/
	GPE_PORT_STATE_BROKEN = 2,
	/** Disabled state (same code point as above, alternative naming).*/
	GPE_PORT_STATE_DISABLED = 2
};

/** Ingress frame coloring mode.
    Used by \ref gpe_equeue_cfg.
*/
enum gpe_coloring_mode {
	/** No coloring, all incoming frames are "green".*/
	GPE_COLORING_MODE_NONE = 0,
	/** Internal coloring, based on Traffic Descriptor Managed Entity.*/
	GPE_COLORING_MODE_INTERNAL = 1,
	/** DEI-based coloring.*/
	GPE_COLORING_MODE_DEI = 2,
	/** PCP 8B0D-based coloring.*/
	GPE_COLORING_MODE_PCP8B0D = 3,
	/** PCP 7B1D-based coloring.*/
	GPE_COLORING_MODE_PCP7B1D = 4,
	/** PCP 6B2D-based coloring.*/
	GPE_COLORING_MODE_PCP6B2D = 5,
	/** PCP 5B3D-based coloring.*/
	GPE_COLORING_MODE_PCP5B3D = 6,
	/** DSCP-based coloring.*/
	GPE_COLORING_MODE_DSCP = 7
};

/** Scheduling policy.
    Used by \ref gpe_scheduler_cfg.
*/
enum gpe_policy {
	/** No policy specified, use default.*/
	GPE_POLICY_NULL = 0,
	/** Head of Line policy.*/
	GPE_POLICY_HOL = 1,
	/** Weighted Round Robin policy.*/
	GPE_POLICY_WRR = 2
};

/** Metering Mode selection.
    Used by \ref gpe_meter_cfg.
*/
enum gpe_metering_mode {
	/** No policy specified, use default.*/
	GPE_METER_NONE = 0,
	/** RFC 4115 algorithm.*/
	GPE_METER_RFC4115 = 1,
	/** RFC 2698 algorithm.*/
	GPE_METER_RFC2698 = 2
};

/** Metering position selection.
    Used by \ref gpe_meter_cfg.
*/
enum gpe_metering_position {
	/** GEM port.*/
	GPE_METER_GEM_PORT = 0,
	/** MAC bridge port.*/
	GPE_METER_BRIDGE_PORT = 1
};

/** TMU counter type selection.
    Used by \ref gpe_cnt_tmu_val.
*/
enum gpe_tmu_cnt_type {
	/** Egress queue related counter.*/
	GPE_TMU_COUNTER_EGRESS_QUEUE = 0,
	/** Ingress queue related counter.*/
	GPE_TMU_COUNTER_INGRESS_QUEUE = 1,
	/** T-CONT related counter.*/
	GPE_TMU_COUNTER_TCONT = 2,
	/** UNI port related counter.*/
	GPE_TMU_COUNTER_UNI = 3,
	/** Virtual UNI port related counter.*/
	GPE_TMU_COUNTER_VUNI = 4
};

/** SCE counter type selection.
    Used by \ref gpe_cnt_sce_val.
*/
enum gpe_sce_cnt_type {
	/** Good Unicast PDUs.*/
	GPE_SCE_UNICAST = 0,
	/** Good Broadcast PDUs.*/
	GPE_SCE_BROADCAST = 1,
	/** Good Multicast PDUs.*/
	GPE_SCE_MULTICAST = 2,
	/** Discarded PDUs.*/
	GPE_SCE_DISCARDED = 3,
	/** Learning not successful.*/
	GPE_SCE_LEARNING_FAIL = 4,
	/** PDUs passed through by Ingress Bridge Port.*/
	GPE_SCE_ACCEPTED_INGRESS = 5,
	/** PDUs passed through by Egress Bridge Port.*/
	GPE_SCE_ACCEPTED_EGRESS = 6,
	/** PDUs discarded by Ingress Bridge Port.*/
	GPE_SCE_DISCARDED_INGRESS = 7,
	/** PDUs discarded by Egress Bridge Port.*/
	GPE_SCE_DISCARDED_EGRESS = 8,
	/** PDUs discarded by UNI ingress PPPoE filter.*/
	GPE_SCE_DISCARDED_PPPOE = 9,
	/** PDUs discarded by exception policer.*/
	GPE_SCE_EXCEPTION_POLICER = 10,
	/** PDUs lost due policing */
	GPE_SCE_EXCEPTION_LOST = 11,
	/** Counters based on UNI port number 0-3 */
	GPE_SCE_BROADCAST_EGRESS = 12,
	/** Counters based on UNI port number 0-3 */
	GPE_SCE_MULTICAST_EGRESS = 13
};

/* Structure Type Definitions - GPE
   ================================
*/

/** Packet Engine hardware modules selection.
    Used by \ref FIO_GPE_LOW_LEVEL_MODULES_ENABLE and \ref gpe_init_data.
*/
struct gpe_ll_mod_sel {
	/** Select the FSQM module.*/
	uint32_t fsqm;
	/** Select the IQM module.*/
	uint32_t iqm;
	/** Select the TMU module.*/
	uint32_t tmu;
	/** select the ICTRLL module.*/
	uint32_t ictrll[4];
	/** Select the OCTRLL module.*/
	uint32_t octrll[4];
	/** Select the ICTRLG module.*/
	uint32_t ictrlg;
	/** Select the OCTRLG module.*/
	uint32_t octrlg;
} __PACKED__;

/** SGMI interface arbiter mode.
    Used by \ref gpe_init_data.
*/
enum gpe_arb_mode {
	/** Not available. */
	ARB_MODE_NA = -1,
	/** SGMII normal (default) mode.*/
	ARB_MODE_DEFAULT = 0,
	/** SGMII mode 2.5 GBit/s.*/
	ARB_MODE_GIG2_5 = 1
};

/** Packet Engine hardware initialization.
    Used by \ref FIO_GPE_INIT.
*/
struct gpe_init_data {
	/** Firmware binary name.*/
	char fw_name[ONU_PE_FIRMWARE_NAME_MAX];
	/** Low level modules selection by an application scenario.*/
	struct gpe_ll_mod_sel ll_mod_sel;
	/** GPE arbiter mode selection (for SGMII running at default or 2.5
	    Gbit/s).*/
	enum gpe_arb_mode arb_mode;
	/** Number of active Processing Elements
	    (1 to \ref ONU_GPE_NUMBER_OF_PE_MAX).*/
	uint32_t num_pe;
} __PACKED__;

/** Basic config mode
    Used by \ref gpe_basic_cfg.
*/
enum gpe_basic_cfg_mode {
	/** Simple downstream mode.*/
	GPE_BASIC_DS = 0,
	/** Simple upstream mode.*/
	GPE_BASIC_US = 1,
	/** Simple PON loop.*/
	GPE_BASIC_PONLOOP = 2,
	/** Simple LAN loop.*/
	GPE_BASIC_LANLOOP = 3
};

/** Packet Engine hardware configuration.
    Currently unused.
*/
struct gpe_basic_cfg {
	/** GEM Port ID, valid from 0 to ONU_GPE_MAX_GEM_PORT_ID - 1.*/
	uint32_t gem_port_id;
	/** UNI port ID (LAN port ID), lower 2 bit are valid.*/
	uint32_t uni_port_id;
	/** Regular egress port number (EPN), valid numbers are:
	    GTC ports (u/s): ONU_GPE_MIN_ANI_TMU_EGRESS_PORT
				     to ONU_GPE_MAX_ANI_TMU_EGRESS_PORT
	    LAN ports (d/s): ONU_GPE_UNI0_EGRESS_PORT_NUMBER
				     to ONU_GPE_UNI3_EGRESS_PORT_NUMBER
	    HOST ports (u/s or d/s): ONU_GPE_CPU0_EGRESS_PORT_NUMBER
				     to ONU_GPE_CPU3_EGRESS_PORT_NUMBER*/
	uint32_t egress_port_number;
	/** Preempting egress port used for T-CONTs.*/
	uint32_t pre_egress_port_number;
	/** T-CONT index, valid from 0 to the number of available T-CONTs - 1.*/
	uint32_t tcont_idx;
	/** Allocation ID (valid from 0 to ONU_GPE_MAX_ALLOCATION_ID).*/
	uint32_t alloc_id;
	/** Defines the configuration for basic mode setup.*/
	enum gpe_basic_cfg_mode gpe_basic_cfg_mode;
} __PACKED__;

/** Packet Engine hardware configuration.
    Used by \ref FIO_GPE_CFG_SET and \ref FIO_GPE_CFG_GET.
*/
struct gpe_cfg {
	/** GEM block size, used to calculate block-related values.
	    Given in number of bytes, the default is 48.*/
	uint32_t gem_blk_len;
	/** Maximum GEM payload size in upstream direction.*/
	uint32_t gem_payload_size_max;
	/** Maximum Ethernet frames length, must be less
	    than ONU_GPE_MAX_ETHERNET_FRAME_LENGTH.
	    \note
	    Please take care to modify the related max_frame_size value within
	    \ref FIO_LAN_PORT_CFG_SET accordingly.
	*/
	uint32_t pdu_size_max_eth;
	/** Maximum OMCI frames length, must be less
	    than 1984.*/
	uint32_t pdu_size_max_omci;
	/** Maximum IP frames length, must be less
	    than ONU_GPE_MAX_IP_FRAME_LENGTH.*/
	uint32_t pdu_size_max_ip;
	/** Maximum MPLS frames length, must be less
	    than ONU_GPE_MAX_MPLS_FRAME_LENGTH.*/
	uint32_t pdu_size_max_mpls;
	/** DBRu debug mode enable bit.*/
	uint32_t dbru_dbg_mode;
	/** MAC bridge aging time [s]*/
	uint32_t aging_time;
} __PACKED__;

/** GPON Packet Engine hardware status.
    Used by \ref FIO_GPE_STATUS_GET.
*/
struct gpe_status {
	/** DBRu mode */
	uint32_t dbru_mode;
	/** Shared buffer size (number of segments) */
	uint32_t ssb_size;
        /** Number of activated Processing Element (PE). */
        uint32_t num_pe;
} __PACKED__;

/** GEM Port configuration.
    If the same Port ID is already configured, this entry is superseded.
    Used by \ref FIO_GPE_GEM_PORT_ADD, \ref FIO_GPE_GEM_PORT_SET,
    \ref FIO_GPE_GEM_PORT_GET, and \ref gpe_gem_port_get_u.
*/
struct gpe_gem_port {
	/** GEM Port ID, valid from 0 to ONU_GPE_MAX_GEM_PORT_ID - 1.*/
	uint32_t gem_port_id;
	/** GEM port index, valid from 0 to ONU_GPE_MAX_GEM_PORT - 1.*/
	uint32_t gem_port_index;
	/** OMCI indication, true if the GEM port carries OMCI data.*/
	uint32_t gem_port_is_omci;
	/** Multicast indication, true if the GEM port carries GEM multicast
	    downstream data.*/
	uint32_t gem_port_is_mc;
	/** Data direction.*/
	enum gpe_direction data_direction;
	/** Indicates if the entry is valid.*/
	uint32_t gem_port_enable;
	/** Encryption indication, true = encrypted, false = plain.*/
	uint32_t encryption_enable;
} __PACKED__;

/** Union to retrieve GEM port configuration data.
    Used by \ref FIO_GPE_GEM_PORT_GET.
*/
union gpe_gem_port_get_u {
	/** Specified GEM port ID.*/
	struct gem_port_id in;
	/** Retrieved GEM port configuration data.*/
	struct gpe_gem_port out;
} __PACKED__;

/** The GPE arbiter can be configured to operate in several modes.
*/
struct gpe_arbiter{
	/** GEM Port ID. Valid from 0 to ONU_GPE_MAX_GEM_PORT_ID - 1.*/
	enum gpe_arb_mode arb_mode;
	/** Port ID register array for arbiter configuration */
	uint32_t data_25g[16];
} __PACKED__;


/** Ingress queue configuration.
    Used by \ref gpe_iqueue_cfg_get_u and \ref gpe_iqueue_status_get_u.
*/
struct gpe_iqueue {
	/** Ingress Queue Index (0 to 8).*/
	uint32_t index;
} __PACKED__;

/** Ingress queue configuration.
    Used by \ref FIO_GPE_INGRESS_QUEUE_CFG_SET and \ref gpe_iqueue_cfg_get_u.
*/
struct gpe_iqueue_cfg {
	/** Ingress Queue Index (0 to 8).*/
	uint32_t index;
	/** Ingress Queue Enable.*/
	uint32_t qe;
	/** Ingress Queue Discard Threshold.*/
	uint32_t qdth;
	/** Ingress Queue Reservation Threshold.*/
	uint32_t qrth;
	/** Ingress Queue Block.*/
	uint32_t qb;
	/** Ingress Queue Backpressure Threshold High.*/
	uint32_t qbth;
	/** Ingress Queue Backpressure Threshold Low.*/
	uint32_t qbtl;
	/** Ingress Queue Thread Mask.*/
	uint32_t tmask;
} __PACKED__;

/** Union to retrieve Ingress Queue configuration data.
    Used by \ref FIO_GPE_INGRESS_QUEUE_CFG_GET.
*/
union gpe_iqueue_cfg_get_u {
	/** Specified Ingress Queue Index.*/
	struct gpe_iqueue in;
	/** Retrieved Ingress Queue configuration data.*/
	struct gpe_iqueue_cfg out;
} __PACKED__;

/** Ingress queue status variables.
    Used by \ref gpe_iqueue_status_get_u.
*/
struct gpe_iqueue_status {
	/** Ingress Queue Index (0 to 8).*/
	uint32_t index;
	/** Queue fill status.*/
	uint32_t qf;
	/** Backpressure enable status.*/
	uint32_t bp;
	/** Queue Occupancy Counter, in number of buffer segments.*/
	uint32_t qocc;
	/** Queue Occupancy Counter, in number of packets (PDUs).*/
	uint32_t pocc;
	/** Queue Discard Counter.*/
	uint32_t qdc;
	/** Ticket Counter.*/
	uint32_t tick;
} __PACKED__;

/** Union to retrieve status variables of an ingress queue
    Used by \ref FIO_GPE_INGRESS_QUEUE_STATUS_GET.
*/
union gpe_iqueue_status_get_u {
	/** Specified Ingress Queue index.*/
	struct gpe_iqueue in;
	/** Retrieved Ingress Queue status variables.*/
	struct gpe_iqueue_status out;
} __PACKED__;

/** Egress queue configuration.
    Used by \ref FIO_GPE_EGRESS_QUEUE_CREATE and
    \ref gpe_equeue_get_u.
*/
struct gpe_equeue_create {
	/** Egress Queue Index (0 to ONU_GPE_MAX_QUEUE - 1).*/
	uint32_t index;
	/** Queue Egress port number (EPN), valid numbers are:
	    GTC ports (u/s): ONU_GPE_MIN_ANI_TMU_EGRESS_PORT
				     to ONU_GPE_MAX_ANI_TMU_EGRESS_PORT
	    LAN ports (d/s): ONU_GPE_UNI0_EGRESS_PORT_NUMBER
				     to ONU_GPE_UNI3_EGRESS_PORT_NUMBER
	    HOST ports (u/s or d/s): ONU_GPE_CPU0_EGRESS_PORT_NUMBER
				     to ONU_GPE_CPU3_EGRESS_PORT_NUMBER */
	uint32_t egress_port_number;
	/** Queue scheduler block input number (SBIN),
	    this defines the scheduler to be used as well as the input
	    selection of this scheduler,
	    valid from 0 to ONU_GPE_MAX_SCHEDULER * 8 - 1.*/
	uint32_t scheduler_input;
} __PACKED__;

/** Structure to specify Egress queue.
    Used by \ref FIO_GPE_EGRESS_QUEUE_DELETE,
    \ref FIO_GPE_EGRESS_QUEUE_PATH_GET, \ref gpe_equeue_cfg_get_u,
    \ref gpe_equeue_status_get_u, and \ref gpe_equeue_get_u.
*/
struct gpe_equeue {
	/** Egress Queue Index (0 to ONU_GPE_MAX_QUEUE - 1).*/
	uint32_t index;
} __PACKED__;

/** Union to retrieve structural attributes of an egress queue.
    Used by \ref FIO_GPE_EGRESS_QUEUE_GET.
*/
union gpe_equeue_get_u {
	/** Specified Egress Queue Index.*/
	struct gpe_equeue in;
	/** Retrieved Egress Queue configuration.*/
	struct gpe_equeue_create out;
} __PACKED__;

/** This structure specifies Egress queue configuration options.
    Used by \ref FIO_GPE_EGRESS_QUEUE_CFG_SET and \ref gpe_equeue_cfg_get_u.
*/
struct gpe_equeue_cfg {
	/** Egress Queue Index (0 to ONU_GPE_MAX_QUEUE - 1).*/
	uint32_t index;
	/** Queue enable.*/
	uint32_t enable;
	/** Scheduler input enable.*/
	uint32_t sbin_enable;
	/** Queue weight.*/
	uint32_t weight;
	/** Queue WRED enable.*/
	uint32_t wred_enable;
	/** Queue averaging coefficient (w_q), valid from 0 to 15,
	    a typical default value is 9.
	    This attribute determines the averaging coefficient, w_q, as
	    described in Floyd and Jacobson. The averaging coefficient, w_q, is
	    equal to 2^(-Queue_drop_w_q).
	    For example, when queue drop_w_q has the value 9, the averaging
	    coefficient, w_q, is 1/512 = 0.0019. */
	uint32_t avg_weight;
	/** Queue size (largest threshold), 
	given in number of eight 64-byte buffer segments (512 byte). */
	uint32_t size;
	/** Queue reservation threshold, enabled by setting value > 0 
	given in number of eight 64-byte buffer segments (512 byte). */
	uint32_t reservation_threshold;
	/** Queue tail drop threshold for red packets 
	given in number of eight 64-byte buffer segments (512 byte). */
	uint32_t drop_threshold_red;
	/** Maximum drop threshold for "green" data frames 
	given in number of eight 64-byte buffer segments (512 byte). */
	uint32_t drop_threshold_green_max;
	/** Minimum drop threshold for "green" data frames 
	given in number of eight 64-byte buffer segments (512 byte). */
	uint32_t drop_threshold_green_min;
	/** Maximum drop threshold for "yellow" data frames 
	given in number of eight 64-byte buffer segments (512 byte). */
	uint32_t drop_threshold_yellow_max;
	/** Minimum drop threshold for "yellow" data frames 
	given in number of eight 64-byte buffer segments (512 byte). */
	uint32_t drop_threshold_yellow_min;
	/** Maximum drop probability for "green" data frames, 
	defined by a 12-bit value which represents a fraction of the 
	probability range between 0 and 1. */
	uint32_t drop_probability_green;
	/** Maximum drop probability for "yellow" data frames, 
	defined by a 12-bit value which represents a fraction of the 
	probability range between 0 and 1. */
	uint32_t drop_probability_yellow;
	/** Coloring mode. This value is ignored by gpe_egress_queue_cfg_set.*/
	enum gpe_coloring_mode coloring_mode;
} __PACKED__;

/** Union to retrieve Egress Queue configuration data.
    Used by \ref FIO_GPE_EGRESS_QUEUE_CFG_GET.
*/
union gpe_equeue_cfg_get_u {
	/** Specified Egress Queue.*/
	struct gpe_equeue in;
	/** Retrieved Egress Queue configuration data.*/
	struct gpe_equeue_cfg out;
};

/** Egress queue status.
    Used by \ref gpe_equeue_status_get_u.
*/
struct gpe_equeue_status {
	/** Egress Queue Index (queue identifier, from 0 to the number of
	    supported egress queues minus 1).*/
	uint32_t index;
	/** Queue configuration option (read-only, fixed value = 1).*/
	uint32_t config_opt;
	/** Maximum queue filling level, in number of bytes.*/
	uint32_t fill_max;
	/** Actual queue filling level, in number of bytes.*/
	uint32_t fill;
	/** Average queue filling level, in number of bytes.*/
	uint32_t fill_avg;
	/** Actual number of frames (packets) in the queue.*/
	uint32_t frames;
	/** Actual queue weight */
	uint32_t iwgt;
} __PACKED__;

/** Union to retrieve Egress Queue status data.
    Used by \ref FIO_GPE_EGRESS_QUEUE_STATUS_GET.
*/
union gpe_equeue_status_get_u {
	/** Specified Egress Queue.*/
	struct gpe_equeue in;
	/** Retrieved Egress Queue status data.*/
	struct gpe_equeue_status out;
};

/** Egress queue counter configuration.
    Used by \ref FIO_GPE_EGRESS_QUEUE_COUNTER_CFG_SET and
    \ref FIO_GPE_EGRESS_QUEUE_COUNTER_CFG_GET.
*/
struct gpe_equeue_cnt_cfg {
	/** Egress Queue Index (queue identifier, from 0 to the number of
	    supported egress queues minus 1).*/
	uint32_t index;
	/** Discard counter automatic reset interval in units of 1 ms.*/
	uint32_t egress_priority_queue_counter_reset_interval;
} __PACKED__;

/** Egress queue status and drop counter.
*/
struct gpe_cnt_equeue_val {
	/** Egress Queue Index (queue identifier, from 0 to the number of
	    supported egress queues minus 1).*/
	uint32_t index;
	/** Actual queue filling level, in number of bytes.*/
	uint32_t fill;
	/** Average queue filling level, in number of bytes.*/
	uint32_t fill_avg;
	/** Actual number of frames in the queue.*/
	uint32_t frames;
	/** Number of discarded frames with color code = 0b00.*/
	uint32_t egress_priority_queue_dropped_frames_unassigned;
	/** Number of discarded frames with color code = 0b01.*/
	uint32_t egress_priority_queue_dropped_frames_green;
	/** Number of discarded frames with color code = 0b10.*/
	uint32_t egress_priority_queue_dropped_frames_yellow;
	/** Number of discarded frames with color code = 0b11.*/
	uint32_t egress_priority_queue_dropped_frames_red;
} __PACKED__;

/** GPE hardware per egress queue related counter reset.
*/
struct gpe_cnt_equeue_reset {
	/** Queue index.
	    Select within the valid range from 0 to 255 to clear an individual
	    counter set, select 0xFFFF to clear all counter sets in one
	    operation.*/
	uint32_t egress_queue_index;

} __PACKED__;

/** Scheduler information - per level.
    Used by \ref gpe_equeue_path_get_u.
*/
struct gpe_equeue_path_level {
	uint32_t sbid;
	uint32_t leaf;
	uint32_t sie;
	uint32_t sit;
	uint32_t iwgt;
	uint32_t qsid;
	uint32_t soe;
	uint32_t lvl;
} __PACKED__;

/** Egress queue path.
    Used by \ref gpe_equeue_path_get_u.
*/
struct gpe_equeue_path {
	uint32_t lvl;
	uint32_t sbid;
	uint32_t qe;
	uint32_t epn;
	uint32_t omid;
	uint32_t epe;
	struct gpe_equeue_path_level info[9];
} __PACKED__;

/** Union to retrieve Egress Queue path data.
    Used by \ref FIO_GPE_EGRESS_QUEUE_PATH_GET.
*/
union gpe_equeue_path_get_u {
	/** Specified Egress Queue.*/
	struct gpe_equeue in;
	/** Retrieved Egress Queue status data.*/
	struct gpe_equeue_path out;
};

/** Create an GPON T-CONT.
    Used by \ref FIO_GPE_TCONT_CREATE.
*/
struct gpe_tcont_cfg {
	/** Egress Port Number */
	uint32_t epn;
	/** Policy */
	uint32_t policy;
	/** Reserved (set to 0). Added in v7.5.1. */
	uint32_t _reserved[2];
} __PACKED__;

/** Add an entry to the GPON T-CONT table.
    Used by \ref FIO_GPE_TCONT_SET and \ref gpe_tcont_get_u.
*/
struct gpe_tcont {
	/** T-CONT index. Valid from 0 to the number of
	    T-CONTs (ONU_GPE_MAX_TCONT) minus 1. This is equal to the Managed
	    Entity ID of the related T-CONT Managed Entity.*/
	uint32_t tcont_idx;
	/** Allocation ID (valid from 0 to ONU_GPE_MAX_ALLOCATION_ID).*/
	uint32_t alloc_id;
	/** Regular egress port number.*/
	uint32_t reg_egress_port;
	/** Preempting egress port number.*/
	uint32_t pre_egress_port;
} __PACKED__;

/** Union to retrieve Allocation ID of a T-CONT in the T-CONT table.
    Used by \ref FIO_GPE_TCONT_GET.
*/
union gpe_tcont_get_u {
	/** Specified T-CONT index.*/
	struct tcont_index in;
	/** Retrieved entry of T-CONT table.*/
	struct gpe_tcont out;
} __PACKED__;

/** Add an entry to the GPON scheduler table.
    Used by \ref FIO_GPE_SCHEDULER_CREATE and \ref gpe_scheduler_get_u.
*/
struct gpe_sched_create {
	/** Scheduler index, valid from 0 to ONU_GPE_MAX_SCHEDULER - 1.*/
	uint32_t index;
	/** Defines if the scheduler output is connected to a T-CONT identified
	    by port_idx via a regular or a preempting egress port
	    (use_tcont == true) or if the options of use_regular apply
	    (use_tcont == false).*/
	uint32_t use_tcont;
	/** Level within the scheduling hierarchy. This number is equal to the
	    longest path counted in number of schedulers seen from this
	    scheduler down the hierarchy.
	    Valid from 0 to \ref ONU_GPE_MAX_SCHEDULER_LEVEL*/
	uint32_t level;
	/** Scheduler ID (OMCI Managed Entity ID of a Traffic Scheduler
	    Managed Entity).*/
	uint32_t scheduler_id;
	/** Output port index (T-CONT or UNI, usage depends on use_tcont).*/
	uint32_t port_idx;
	/** Output scheduler index.*/
	uint32_t connected_scheduler_index;
	/** If use_tcont == true, this parameter selects if the scheduler is
	    attached to the regular or the preempting egress port. If
	    use_tcont == false, this parameter selects if the scheduler is
	    attached to the egress port identified by port_idx
	    (use_regular == true) or to the input of another scheduler
	    identified by connected_scheduler_index (use_regular == false).*/
	uint32_t use_regular;
	/** Scheduling policy of this scheduler.*/
	enum gpe_policy scheduler_policy;
	/** Priority/Weight into the connected scheduler.*/
	uint32_t priority_weight;
} __PACKED__;

/** Traffic Scheduler index.
    Used by \ref gpe_scheduler_cfg, \ref gpe_scheduler_cfg_get_u and
    \ref gpe_scheduler_status_get_u.
*/
struct gpe_scheduler_idx {
	/** Scheduler index, valid from 0 to the number of schedulers minus 1.
	*/
	uint32_t index;
} __PACKED__;

/** Union to retrieve structural attributes of a Traffic Scheduler.
    Used by \ref FIO_GPE_SCHEDULER_GET.
*/
union gpe_scheduler_get_u {
	/** Specifies Traffic Scheduler.*/
	struct gpe_scheduler_idx in;
	/** Received Traffic Scheduler structural attributes.*/
	struct gpe_sched_create out;
} __PACKED__;

/** Traffic Scheduler configuration data.
    Used by \ref FIO_GPE_SCHEDULER_CFG_SET and \ref gpe_scheduler_cfg_get_u.
*/
struct gpe_scheduler_cfg {
	/** Scheduler index, valid from 0 to the number of schedulers minus 1.
	*/
	uint32_t index;
	/** Output enable.*/
	uint32_t output_enable;
	/** Weight into connected scheduler.*/
	uint32_t weight;
} __PACKED__;

/** Union to retrieve traffic scheduler configuration data.
    Used by \ref FIO_GPE_SCHEDULER_CFG_GET.
*/
union gpe_scheduler_cfg_get_u {
	/** Specified Scheduler index.*/
	struct gpe_scheduler_idx in;
	/** Retrieved Traffic Scheduler configuration data.*/
	struct gpe_scheduler_cfg out;
} __PACKED__;

/** Traffic Scheduler status values.
    Used by \ref gpe_scheduler_status_get_u.
*/
struct gpe_scheduler_status {
	/** Scheduler index, valid from 0 to the number of schedulers minus 1.
	*/
	uint32_t index;
	/** The scheduler output is filled, if true.*/
	uint32_t sof;
	/** Winner leaf to be selected next to transmit from this scheduler.*/
	uint32_t wl;
	/** Winner egress queue to be selected next to transmit from this
	    scheduler.*/
	uint32_t wqid;
} __PACKED__;

/** Union to retrieve Traffic Scheduler status.
    Used by \ref FIO_GPE_SCHEDULER_STATUS_GET.
*/
union gpe_scheduler_status_get_u {
	/** Specified Scheduler index.*/
	struct gpe_scheduler_idx in;
	/** Received Traffic Scheduler status.*/
	struct gpe_scheduler_status out;
} __PACKED__;


/** TMU flat path configuration parameters.
    Used by \ref FIO_GPE_FLAT_EGRESS_PATH_CREATE.
*/
struct gpe_flat_egress_path {
	/** Number of egress ports to create.*/
	uint32_t num_ports;
	/** Egress Port number to start with.*/
	uint32_t base_epn;
	/** Scheduler number to start with.*/
	uint32_t base_sbid;
	/** Egress Queue number to start with.*/
	uint32_t base_qid;
	/** Number of Egress Queues per Scheduler.*/
	uint32_t qid_per_sb;
} __PACKED__;


/** Traffic descriptor (meter).
    Used by \ref gpe_meter_cfg_get_u.
*/
struct gpe_meter{
	/** Meter index.
	    Allowed range is from 0 to (\ref ONU_GPE_MAX_TBM / 2) - 1 */
	uint32_t index;
} __PACKED__;

/** Traffic descriptor (meter) configuration.
    Used by \ref FIO_GPE_METER_CFG_SET and \ref gpe_meter_cfg_get_u.
*/
struct gpe_meter_cfg {
	/** Meter index.
	    Allowed range is from 0 to (\ref ONU_GPE_MAX_TBM / 2) - 1*/
	uint32_t index;
	/** Committed Information Rate (CIR), in byte/s.
		The configurable range is:
		- Minimum: \ref ONU_GPE_METER_CIR_MIN byte/s (64 kbit/s).
		- Maximum: \ref ONU_GPE_METER_CIR_MAX byte/s (1 Gbit/s).
	    Values less than \ref ONU_GPE_METER_CIR_MIN
	    will be treated as \ref ONU_GPE_METER_CIR_MIN.*/
	uint32_t cir;
	/** Peak Information Rate (PIR), in byte/s.
		The configurable range is:
		- Minimum: \ref ONU_GPE_METER_PIR_MIN byte/s (64 kbit/s).
		- Maximum: \ref ONU_GPE_METER_PIR_MAX byte/s (1 Gbit/s).
	    Special value 0 will select factory default value
	    \ref ONU_GPE_METER_PIR_DEF. */
	uint32_t pir;
	/** Committed Block Size (CBS), in byte.
		The maximum configurable number is
		\ref ONU_GPE_METER_CBS_MAX. */
	uint32_t cbs;
	/** Peak Block Size (PBS), in byte.
		The maximum configurable number is ONU_GPE_METER_PBS_MAX.
		Special value 0 will select factory default value
	        \ref ONU_GPE_METER_PBS_DEF.*/
	uint32_t pbs;
	/** Color awareness selection.
	    - true: color-aware operation.
	    - false: color-unaware operation. */
	uint32_t color_aware;
	/** Metering mode selection. Selectable modes are:
		- GPE_METER_NONE: No meter mode given, this will use RFC 2698 policy.
		- GPE_METER_RFC2698: Use RFC 2698 policy.
		- GPE_METER_RFC4115: Use RFC 4115 policy.
		\remark 
		The driver stores this setting in the GPE hardware.
		The hardware accepts either GPE_METER_RFC4115 or GPE_METER_RFC2698 
		as a valid mode.
		If a "set" operation is performed with mode = GPE_METER_NONE,
		the "get" operation will return mode = GPE_METER_RFC2698. */
	enum gpe_metering_mode mode;
} __PACKED__;

/** Union to retrieve meter configuration of a selected
    Token Bucket Meter (TBM).
    Used by \ref FIO_GPE_METER_CFG_GET.
*/
union gpe_meter_cfg_get_u {
	/** Specified Meter index.*/
	struct gpe_meter in;
	/** Retrieved Traffic descriptor (meter) configuration.*/
	struct gpe_meter_cfg out;
} __PACKED__;


/** Traffic descriptor (meter) status.
    Used by \ref FIO_GPE_METER_STATUS_GET and \ref gpe_meter_status_get_u.
*/
struct gpe_meter_status {
	/** Meter index.*/
	uint32_t index;
	/** Token Bucket Counter (value in number of bytes).*/
	uint32_t tbc;
	/** Last Time Stamp (time stamp of the last meter request).*/
	uint32_t lts;
	/** Epoc Time Stamp (indicates the crawler epoc when LTS was last updated).*/
	uint32_t ets;
	/** Valid Time Stamp (indicates if LTS is valid).*/
	uint32_t vts;

} __PACKED__;

/** Union to retrieve Token Bucket Meter status.
    Used by \ref FIO_GPE_METER_STATUS_GET.
*/
union gpe_meter_status_get_u {
	/** Specified Token Bucket Meter index.*/
	struct gpe_meter  in;
	/** Retrieved Token Bucket Shaper status.*/
	struct gpe_meter_status out;
} __PACKED__;


/** Structure to specify Bridge Index.
    Used by \ref gpe_bridge_counter_threshold_get_u.
*/
struct gpe_bridge {
	/** Bridge selection (from 0 to number of bridges - 1).*/
	uint32_t bridge_index;
} __PACKED__;

/** Bridge-related counter(s) control.
    Used by \ref FIO_GPE_BRIDGE_COUNTER_RESET,
    \ref gpe_bridge_counter_get_u and \ref gpe_bridge_counter.
*/
struct gpe_bridge_cnt_interval {
	/** Bridge selection (from 0 to number of bridges - 1).*/
	uint32_t bridge_index;
	/** Reset Mask. This defines which of the counters shall be reset
	    after being read. If a mask bit is set, the related counter is
	    reset. See ONU_GPE_BRIDGE_CNT_RST_MASK_<counter> for the mask
	    bit assignment.*/
	uint32_t reset_mask;
	/** Select if the counter read access shall deliver the most recent
	    counter value or the sum of the previous 15-minute time interval.
	    - true: Read the latest (current) value.
	    - false: Read the previous 15-minute interval value.*/
	uint32_t curr;
} __PACKED__;

/** Structure to specify Bridge-related counter(s).
    Used by \ref gpe_bridge_counter_get_u.
*/
struct gpe_bridge_counter {
	/** Counter(s) control.*/
	struct gpe_bridge_cnt_interval cnt_ctrl;
	/** Counter(s) values.*/
	struct gpe_cnt_bridge_val cnt_val;
} __PACKED__;

/** Union to retrieve bridge-based performance counters.
    Used by \ref FIO_GPE_BRIDGE_COUNTER_GET.
*/
union gpe_bridge_counter_get_u {
	/** Specified bridge-related counter control.*/
	struct gpe_bridge_cnt_interval in;
	/** Retrieved bridge-based performance counters.*/
	struct gpe_bridge_counter out;
} __PACKED__;

/** Bridge-related threshold(s) for Threshold Crossing Alarms (TCA).
    Used by \ref FIO_GPE_BRIDGE_COUNTER_THRESHOLD_SET and
    \ref gpe_bridge_counter_threshold_get_u.
*/
struct gpe_cnt_bridge_threshold {
	/** Bridge selection (from 0 to number of bridges - 1).*/
	uint32_t bridge_index;
	/** Threshold values.*/
	struct gpe_cnt_bridge_val threshold;
} __PACKED__;

/** Union to retrieve bridge-based counter thresholds.
    Used by \ref FIO_GPE_BRIDGE_COUNTER_THRESHOLD_GET and
    \ref FIO_GPE_BRIDGE_TCA_GET.
*/
union gpe_bridge_counter_threshold_get_u {
	/** Specified bridge index.*/
	struct gpe_bridge in;
	/** Retrieved bridge-related threshold(s).*/
	struct gpe_cnt_bridge_threshold out;
} __PACKED__;


/** Bridge port index structure.
*/
struct gpe_bridge_port_index {
	/** Bridge port index */
	uint32_t index;
};

/** Bridge port related counter(s) control.
    Used by \ref FIO_GPE_BRIDGE_PORT_COUNTER_RESET,
    \ref gpe_bridge_port_counter_get_u and \ref gpe_bridge_port_counter.
*/
struct gpe_bridge_port_cnt_interval {
	/** Bridge port selection (from 0 to number of bridges ports - 1).*/
	uint32_t index;
	/** Reset Mask. This defines which of the counters shall be reset
	    after being read. If a mask bit is set, the related counter is
	    reset. See ONU_GPE_BRIDGE_CNT_RST_MASK_<counter> for the mask
	    bit assignment.*/
	uint32_t reset_mask;
	/** Select if the counter read access shall deliver the most recent
	    counter value or the sum of the previous 15-minute time interval.
	    - true: Read the latest (current) value.
	    - false: Read the previous 15-minute interval value.*/
	uint32_t curr;
} __PACKED__;

/** Structure to specify bridge port related counter(s).
    Used by \ref gpe_bridge_port_counter_get_u.
*/
struct gpe_bridge_port_counter {
	/** Counter(s) control.*/
	struct gpe_bridge_port_cnt_interval ctrl;
	/** Counter(s) values.*/
	struct gpe_cnt_bridge_port_val val;
} __PACKED__;

/** Union to retrieve bridge port based performance counters.
    Used by \ref FIO_GPE_BRIDGE_PORT_COUNTER_GET.
*/
union gpe_bridge_port_counter_get_u {
	/** Specified bridge port related counter control.*/
	struct gpe_bridge_port_cnt_interval in;
	/** Retrieved bridge port based performance counters.*/
	struct gpe_bridge_port_counter out;
} __PACKED__;

/** Bridge port related threshold(s) for Threshold Crossing Alarms (TCA).
    Used by \ref FIO_GPE_BRIDGE_PORT_COUNTER_THRESHOLD_SET and
    \ref gpe_bridge_port_counter_threshold_get_u.
*/
struct gpe_cnt_bridge_port_threshold {
	/** Bridge port selection (from 0 to number of bridges ports - 1).*/
	uint32_t index;
	/** Threshold values.*/
	struct gpe_cnt_bridge_port_val threshold;
} __PACKED__;

/** Union to retrieve bridge port based counter thresholds.
    Used by \ref FIO_GPE_BRIDGE_PORT_COUNTER_THRESHOLD_GET and
    \ref FIO_GPE_BRIDGE_PORT_TCA_GET.
*/
union gpe_bridge_port_counter_threshold_get_u {
	/** Specified bridge port index.*/
	struct gpe_bridge_port_index in;
	/** Retrieved bridge port related threshold(s).*/
	struct gpe_cnt_bridge_port_threshold out;
} __PACKED__;


/** Ingress queue (IQM) global configuration parameters.
    Used by \ref FIO_GPE_IQM_GLOBAL_CFG_SET and \ref FIO_GPE_IQM_GLOBAL_CFG_GET.
*/
struct gpe_iqm_global_cfg {
	/** Global buffer occupancy threshold, given in number of segments.*/
	uint32_t goth;
	/** Weighted Round Robin period, given in number of slots
	    (up to 36).*/
	uint32_t  wrrper;
	/** Weighted Round Robin ingress queue assignment per slot.
	    For each of the up to 36 slots an ingress queue number is held in
	    this array.*/
	uint32_t  wrrq[36];
} __PACKED__;

/** IQM global status variables.
*/
struct gpe_iqm_global_status {
	/** Global buffer occupancy count, units of buffer segments.*/
	uint32_t gocc;
	/** Global discard counter. Counts PDUs with that have been discarded
	    because a global threshold was exceeded.*/
	uint32_t gpdc;
	/** Each bit (31:0) set in this variable indicates by its position if
	    the corresponding pointer segment address is free.*/
	uint32_t sfree0;
	/** Each bit (15:0) set in this variable indicates by its position if
	    the corresponding pointer segment address is free.*/
	uint32_t sfree1;
} __PACKED__;


/** Traffic Management Unit (TMU) global configuration parameters.
*/
struct gpe_tmu_global_cfg {
	/** True enables the sequential mode of the Relog Pipeline.*/
	uint32_t rps;
	/** True disables the Token Bucket Accumulation Crawler.*/
	uint32_t dta;
	/** This specifies the Maximum TBID that can be used for shaping,
	    initially set to 255.*/
	uint32_t maxtb;
	/** Pseudo random number generated by a linear feedback shift register,
	    read-only.*/
	uint32_t lfsr;
	/** This is the WRED crawler period. It indicates the time interval to
	    elapse between QAVG calculations on consecutive queues. It is
	    specified with a granularity of 1024 clocks. A value of 0 means that
	    the crawler is disabled.*/
	uint32_t cp;
	/** Enqueue Request Delay. Determines an additional internal delay in
	    number of clock cycles between acceptance of an Enqueue Request by
	    the TMU and the time the TMU is ready to receive the next
	    Enqueue Request.*/
	uint32_t erd;
	/** Token Accumulation Period. This parameter holds the token
	    accumulation crawler period in number of clock cycles between
	    triggers to calculate at subsequent TBIDs.*/
	uint32_t  tacp;
} __PACKED__;

/** Traffic Management Unit (TMU) global status variables.
*/
struct gpe_tmu_global_status {
	/** Free Pointer Counter. This parameter holds the number of free PDU
	    pointers in the IPPT.*/
	uint32_t fpcr;
	/** Global buffer occupancy count, units of buffer segments.*/
	uint32_t gocc;
	/** Global discard counter, per color. Counts PDUs with that have been
	    discarded because a global threshold was exceeded.*/
	uint32_t gpdc[4];
	/** Egress queue fill status for queues 0 to 255.
	    - 0: empty.
	    - 1: filled.*/
	uint32_t qfill[8];
	/** Egress port fill status for ports 0 to 71.
		- 0: empty.
		- 1: filled.*/
	uint32_t epf[3];
} __PACKED__;

/** TMU counters selection.
    Used by \ref gpe_tmu_counter_get_u.
*/
struct gpe_cnt_tmu_sel {
	/** TMU counter type select.
	    - Dropped packets per egress queue
	    - Dropped packets per ingress queue
	    - Dropped packets per T-CONT
	    - Dropped packets per LAN port (UNI)
	    - Dropped packets per virtual UNI port*/
	enum gpe_tmu_cnt_type cnt_type;
	/** Counter index.
	    The meaning of the index depends on the selected counter type and is
	    either the
	    - Egress queue index
	    - T-CONT index
	    - Ingress queue index
	    - LAN port index or
	    - Virtual UNI index*/
	uint32_t index;
} __PACKED__;

/** TMU-related counters.
    Used by \ref FIO_GPE_TMU_COUNTER_RESET and \ref gpe_tmu_counter_get_u.
*/
struct gpe_cnt_tmu_val {
	/** TMU counter type select.
	    - Dropped packets per egress queue
	    - Dropped packets per ingress queue
	    - Dropped packets per T-CONT
	    - Dropped packets per LAN port (UNI)
	    - Dropped packets per virtual UNI port*/
	enum gpe_tmu_cnt_type cnt_type;
	/** Counter index.
	   The meaning of the index depends on the selected counter type and is
	   either the
	    - Egress queue index
	    - T-CONT index
	    - Ingress queue index
	    - LAN port index or
	    - Virtual UNI index*/
	uint32_t index;
	/** Dropped frames per color.
	    \remark \ref GPE_TMU_COUNTER_INGRESS_QUEUE counter type is reported
	            via dropped_frames[0].*/
	uint32_t dropped_frames[ONU_GPE_QUEUE_MAX_COLOR];
} __PACKED__;

/** Union to retrieve TMU-based counters.
    Used by \ref FIO_GPE_TMU_COUNTER_GET.
*/
union gpe_tmu_counter_get_u {
	/** Specified TMU counter selection.*/
	struct gpe_cnt_tmu_sel in;
	/** Retrieved TMU-related counters.*/
	struct gpe_cnt_tmu_val out;
} __PACKED__;

/** TMU-related counter reset.
    Used by \ref FIO_GPE_TMU_COUNTER_RESET.
*/
struct gpe_cnt_tmu_reset {
	/** No parameter needed.*/
	uint32_t dummy;
} __PACKED__;

/** SCE counters selection.
    Used by \ref gpe_sce_cnt_get_u.
*/
struct gpe_cnt_sce_sel {
	/** SCE counter type select.*/
	enum gpe_sce_cnt_type cnt_type;
	/** Counter index.*/
	uint32_t index;
} __PACKED__;

/** SCE-related counters.
    Used by \ref gpe_sce_cnt_get_u.
*/
struct gpe_cnt_sce_val {
	/** SCE counter type select.*/
	enum gpe_sce_cnt_type cnt_type;
	/** Counter index.*/
	uint32_t index;
	/** Counter value.*/
	uint32_t counter;
} __PACKED__;

/**
   Union to retrieve SCE-based counters.
   Used by \ref FIO_GPE_SCE_COUNTER_GET.
*/
union gpe_sce_cnt_get_u {
	/** Specified SCE counter selection.*/
	struct gpe_cnt_sce_sel in;
	/** Retrieved SCE-related counters.*/
	struct gpe_cnt_sce_val out;
} __PACKED__;

/** TMU-related counter reset.
    Used by \ref FIO_GPE_SCE_COUNTER_RESET.
*/
struct gpe_cnt_sce_reset {
	/** No parameter needed.*/
	uint32_t dummy;
} __PACKED__;

/** Structure to retrieve Ingress Queue Counters provided by the SCE firmware.
*/
struct gpe_cnt_iqn_val {
	/** Ingress queue number.*/
	uint32_t iqn;
	/** Unicast counter.*/
	uint32_t uc;
	/** Multicast counter.*/
	uint32_t mc;
	/** Broadcast counter.*/
	uint32_t bc;
	/** IPN discard counter.*/
	uint32_t ipn_discard;
} __PACKED__;

/** Structure to retrieve UNI port dependent Counters provided by the SCE
    firmware.
*/
struct gpe_cnt_uni_val {
	/** UNI port index.*/
	uint32_t uni_index;
	/** PPPoE counter.*/
	uint32_t pppoe;
} __PACKED__;

/** Ingress packet parser.
    Used by \ref gpe_parser_cfg.
*/
struct gpe_parser {
	/** Parser ID, valid from 0 to 1
	    0: ANI-to-UNI (GPON d/s direction, connected to GTC)
	    1: UNI-to-ANI (GPON u/s direction, connected to LAN ports)
	    This setting also defines if OMCI is parsed.*/
	uint32_t parser_id;
} __PACKED__;

/** Ingress packet parser configuration.
    Used by \ref FIO_GPE_PARSER_CFG_SET.
*/
struct gpe_parser_cfg {
	/** Four Ethertype values that are used to identify a VLAN tag.*/
	uint32_t tpid[4];
	/** S-TAG indication Ethertype.
	    This Ethertype value is used to identify a "special tag".
            \attention This is a deprecated function and shall no longer
		       be used. A new function is provided to define multiple
		       special Ethertype values. These are configured in the
		       ONU_GPE_ETHERTYPE_EXCEPTION_TABLE. */
	uint32_t special_tag;
	/** Reserved (set to 0). Added in v7.5.1. */
	uint32_t _reserved[2];
} __PACKED__;

/** TPID (VLAN Ethertype) definition.
*/
struct gpe_tpid {
	/** Ethertype values that are used to identify a ingress VLAN tag.*/
	uint32_t input_tpid[4];
	/** Ethertype values that are used to identify a egress VLAN tag.*/
	uint32_t output_tpid[4];
} __PACKED__;

/** Token Bucket Shaper.
    Used by \ref FIO_GPE_TOKEN_BUCKET_SHAPER_CREATE,
    \ref FIO_GPE_TOKEN_BUCKET_SHAPER_DELETE and
    \ref gpe_token_bucket_shaper_get_u.
*/
struct gpe_token_bucket_shaper {
	/** Token Bucket Shaper index, must be less than ONU_GPE_MAX_SHAPER - 1.
	*/
	uint32_t index;
	/** Related Scheduler Block input number
	    (0  to  ONU_GPE_MAX_SCHEDULER * 8).*/
	uint32_t tbs_scheduler_block_input;
} __PACKED__;

/** Token Bucket Shaper index.
    Used by \ref gpe_token_bucket_shaper_cfg_get_u and
    \ref gpe_token_bucket_shaper_get_u.
*/
struct gpe_token_bucket_shaper_idx {
	/** Token Bucket Shaper index, must be less than ONU_GPE_MAX_SHAPER - 1.
	*/
	uint32_t index;
} __PACKED__;

/** Union to retrieve structural links of a Token Bucket Shapers.
    Used by \ref FIO_GPE_TOKEN_BUCKET_SHAPER_GET.
*/
union gpe_token_bucket_shaper_get_u {
	/** Specified Token Bucket Shaper index.*/
	struct gpe_token_bucket_shaper_idx in;
	/** Received Token Bucket Shaper structural links.*/
	struct gpe_token_bucket_shaper out;
} __PACKED__;

/** Token Bucket Shaper configuration.
    Used by \ref FIO_GPE_TOKEN_BUCKET_SHAPER_CFG_SET and
    \ref gpe_token_bucket_shaper_cfg_get_u.
*/
struct gpe_token_bucket_shaper_cfg {
	/** Token Bucket Shaper index.
	    Must be less than ONU_GPE_MAX_SHAPER - 1.*/
	uint32_t index;
	/** Token Bucket Shaper enable.*/
	uint32_t enable;
	/** Token Bucket Shaper operation mode (0  to  3).*/
	uint32_t mode;
	/** Committed data rate (bytes/s) - 32 bits required by OMCI.
	    Valid range from \ref ONU_GPE_TBS_CIR_MIN to
	    \ref ONU_GPE_TBS_CIR_MAX. Values less than \ref ONU_GPE_TBS_CIR_MIN
	    will be treated as \ref ONU_GPE_TBS_CIR_MIN. */
	uint32_t cir;
	/** Peak data rate (bytes/s) - 32 bits required by OMCI.
	    Valid range from \ref ONU_GPE_TBS_PIR_MIN to
	    \ref ONU_GPE_TBS_PIR_MAX.
	    Special value 0 will select factory default value
	    \ref ONU_GPE_TBS_PIR_DEF.*/
	uint32_t pir;
	/** Token Bucket Shaper committed maximum burst size
	    (0  to  \ref ONU_GPE_TBS_CBS_MAX - 1), given in number of bytes. */
	uint32_t cbs;
	/** Token Bucket Shaper peak maximum burst size
	    (0  to  \ref ONU_GPE_TBS_PBS_MAX - 1), 
	    given in number of bytes.
	    Special value 0 will select factory default value
	    \ref ONU_GPE_TBS_PBS_DEF.*/
	uint32_t pbs;
} __PACKED__;

/** Union to retrieve Token Bucket Shaper instance configuration.
    Used by \ref FIO_GPE_TOKEN_BUCKET_SHAPER_CFG_GET.
*/
union gpe_token_bucket_shaper_cfg_get_u{
	/** Specified Token Bucket Shaper index.*/
	struct gpe_token_bucket_shaper_idx in;
	/** Retrieved Token Bucket Shaper configuration.*/
	struct gpe_token_bucket_shaper_cfg out;
} __PACKED__;

/** Token Bucket Shaper configuration.
    Used by \ref gpe_token_bucket_shaper_status_get_u.
*/
struct gpe_token_bucket_shaper_status {
	/** Token Bucket Shaper index.
	    Must be less than GPON_MAX_SHAPER - 1.*/
	uint32_t index;
	/** PASS condition bucket 0.*/
	uint32_t pass0;
	/** PASS condition bucket 1.*/
	uint32_t pass1;
	/** Token Bucket Shaper SRC0.*/
	uint32_t src0;
	/** Token Bucket Shaper SRC1.*/
	uint32_t src1;
	/** Token Bucket Counter 0.*/
	uint32_t tbc0;
	/** Token Bucket Counter 1.*/
	uint32_t tbc1;
	/** Color of next PDU.*/
	uint32_t col;
	/** Length of next PDU.*/
	uint32_t qosl;
	/** Token Accumulation time stamp.*/
	uint32_t ts_tacc;
} __PACKED__;

/** Union to retrieve Token Bucket Shaper configuration.
    Used by \ref FIO_GPE_TOKEN_BUCKET_SHAPER_STATUS_GET.
*/
union gpe_token_bucket_shaper_status_get_u {
	/** Specified Token Bucket Shaper index.*/
	struct gpe_token_bucket_shaper_idx in;
	/** Retrieved Token Bucket Shaper configuration.*/
	struct gpe_token_bucket_shaper_status out;
} __PACKED__;

/** Global shared buffer configuration.
    Used by \ref FIO_GPE_SHARED_BUFFER_CFG_SET and
    \ref FIO_GPE_SHARED_BUFFER_CFG_GET.
*/
struct gpe_shared_buffer_cfg {
	/** Maximum number of segments usable by the ingress queueing
	    manager.*/
	uint32_t iqm_global_segments_max;
	/** Maximum total number of segments usable by the egress queueing
	    manager.*/
	uint32_t tmu_global_segments_max;
	/** Maximum number of segments usable by the egress queueing manager for
	    "green" packets.*/
	uint32_t tmu_global_segments_green;
	/** Maximum number of segments usable by the egress queueing manager for
	    "yellow" packets.*/
	uint32_t tmu_global_segments_yellow;
	/** Maximum number of segments usable by the egress queueing manager for
	    "red" packets.*/
	uint32_t tmu_global_segments_red;
} __PACKED__;

/** GEM port counter control.
    Used by \ref FIO_GPE_GEM_COUNTER_RESET, \ref gpe_gem_counter and
    \ref gpe_gem_counter_get_u.
*/
struct gpe_gem_cnt_interval {
	/** GEM Port index.*/
	uint32_t gem_port_index;
	/** Reset Mask.
	    This defines which of the counters shall be reset after
	    being read. If a mask bit is set, the related counter is reset.
	    See ONU_GPE_GEM_CNT_RST_MASK_<counter> for the mask bit assignment.
	    */
	uint32_t reset_mask;
	/** Select if the counter read access shall deliver the most recent
	    counter value or the sum of the previous 15-minute time interval.
	    - true: Read the latest (current) value.
	    - false: Read the previous 15-minute interval value.*/
	uint32_t curr;
} __PACKED__;

/** GEM port related counters.
    Used by \ref gpe_gem_counter and \ref gpe_cnt_gem_threshold.
*/
struct gpe_cnt_gem_val {
	/* GEM Port index.
	   0xFFFF selects the global counter that counts all GEM port IDs.*/
	/* \todo:  uint32_t gem_port_index; */
	/** Receive direction counters (downstream).*/
	struct gpe_cnt_ictrlg_gem_val rx;
	/** Transmit direction counters (upstream).*/
	struct gpe_cnt_octrlg_gem_val tx;
} __PACKED__;

/** GEM port ID related counters.
    Used by \ref gpe_gem_counter_get_u.
*/
struct gpe_gem_counter {
	/** GEM port counters control.*/
	struct gpe_gem_cnt_interval cnt_ctrl;
	/** GEM port related counters.*/
	struct gpe_cnt_gem_val cnt_val;
} __PACKED__;

/** Union to retrieve GEM port ID based counters.
    Used by \ref FIO_GPE_GEM_COUNTER_GET.
*/
union gpe_gem_counter_get_u {
	/** Specified GEM port counters control.*/
	struct gpe_gem_cnt_interval in;
	/** Retrieved GEM port related counters.*/
	struct gpe_gem_counter out;
} __PACKED__;

/** GEM port ID related counter threshold alarms.
    Used by \ref gpe_gem_tca_get_u.
*/
struct gpe_gem_tca_val {
	/** GEM port ID.*/
	struct gem_port_id index;
	/** GEM port related counter threshold alarms.*/
	struct gpe_cnt_gem_val cnt_val;
} __PACKED__;

/** Union to retrieve GEM port ID related counter threshold alarms.
    Used by \ref FIO_GPE_GEM_TCA_GET.
*/
union gpe_gem_tca_get_u {
	/** Specified GEM port ID.*/
	struct gem_port_id in;
	/** Retrieved GEM port related counter threshold alarms.*/
	struct gpe_gem_tca_val out;
} __PACKED__;

/** GEM port ID related thresholds.
    Used by
    \ref FIO_GPE_GEM_COUNTER_THRESHOLD_SET and
    \ref gpe_gem_counter_threshold_get_u.
*/
struct gpe_cnt_gem_threshold {
	/** GEM Port-ID, lower 12 bit are valid.*/
	uint32_t gem_port_index;
	/** Threshold values.*/
	struct gpe_cnt_gem_val threshold;
} __PACKED__;

/** Union to retrieve GEM counter threshold values.
    Used by \ref FIO_GPE_GEM_COUNTER_THRESHOLD_GET.
*/
union gpe_gem_counter_threshold_get_u {
	/** Specified GEM port ID.*/
	struct gem_port_id in;
	/** Retrieved GEM port related thresholds.*/
	struct gpe_cnt_gem_threshold out;
} __PACKED__;

/* Structure Type Definitions - Bridge Table Access
   ================================================
*/

/** OMCI message.
*/
struct gpe_omci_msg {
	/** OMCI message length up to 1980 bytes (CRC is not included).
	*/
	uint32_t length;
	/** OMCI message data.*/
	uint8_t message[ONU_GPE_MAX_OMCI_FRAME_LENGTH];
} __PACKED__;

/** Initialization parameters for the Time of Day serial interface.
    Used by \ref FIO_GPE_TOD_INIT.
*/
struct gpe_tod_init_data {
	/** 1PPS pulse width.
	    Selects the duration of the 1PPS pulse signal.
	    Given in multiples of 100 us. The maximum number of steps is 4095.*/
	uint32_t pps_pulse_width;
	/** Interrupt delay in multiples of 100 us.
	    Defines the time between the rising edge of the PPS pulse and the
	    delayed interrupt that serves the serial interface.
	    The maximum number of steps is 4095.*/
	uint32_t interrupt_delay;
} __PACKED__;

/** Set the Time of Day synchronously with the GTC sublayer.
    Used by \ref FIO_GPE_TOD_SYNC_SET.
*/
struct gpe_tod_sync {
	/** Multiframe counter value for time synchronization.*/
	uint32_t multiframe_count;
	/** Time of Day higher part, given in units of seconds.*/
	uint32_t tod_seconds;
	/** Time of Day extended part, given in units of seconds.*/
	uint32_t tod_extended_seconds;
	/** Time of Day lower part, given in units of nanoseconds.*/
	uint32_t tod_nano_seconds;
	/** ToD offset in picoseconds for fine-grained adjustment. Added in v7.5.1. */
	int32_t tod_offset_pico_seconds;
	/** ToD quality indicator. Added in v7.5.1. */
	int32_t tod_quality;
} __PACKED__;

/** Set or get the Time of Day asynchronously.
    Used by \ref FIO_GPE_TOD_GET.
*/
struct gpe_tod {
	/** Seconds [0-60] (including up to 1 leap second).*/
	uint32_t sec;
	/** Minutes [0-59].*/
	uint32_t min;
	/** Hours [0-23].*/
	uint32_t hour;
	/** Day [1-31].*/
	uint32_t mday;
	/** Month [0-11].*/
	uint32_t mon;
	/** Year [2010-2xxx].*/
	uint32_t year;
	/** Day of week [0-6].*/
	uint32_t wday;
	/** Days in year [0-365].*/
	uint32_t yday;
	/** Number of seconds, as defined by TAI.*/
	uint32_t sec_tai;
} __PACKED__;

/** Structure used to describe Egress port creation options.
    Used by \ref FIO_GPE_EGRESS_PORT_CREATE and \ref gpe_eport_get_u.
*/
struct gpe_eport_create {
	/** Port Index.
	    - UNI port (LAN port) index to be configured, valid from 0
	    to ONU_GPE_MAX_ETH_UNI - 1.
	    - T-CONT index to be connected, valid from 0
	    to ONU_GPE_MAX_TCONT - 1.*/
	uint32_t index;
	/** Selection if this function call is targeted at a UNI port
	    or a T-CONT, true: UNI, false: T-CONT.*/
	uint32_t is_uni;
	/** Regular Egress port to be connected.*/
	uint32_t regular_epn;
	/** Regular Scheduler block to be connected.*/
	uint32_t regular_sbid;
	/** Preempting Egress port to be connected.*/
	uint32_t preempting_epn;
	/** Preempting Scheduler block to be connected.*/
	uint32_t preempting_sbid;
} __PACKED__;

/** Structure to specify Egress port number.
    Used by \ref gpe_egress_port_cfg_get_u and
    \ref gpe_egress_port_status_get_u.
*/
struct gpe_epn {
	/** Port Index.
	    - UNI port (LAN port) index to be configured, valid from 0
	      to ONU_GPE_MAX_ETH_UNI - 1
	    - T-CONT index to be connected, valid from 0
	      to ONU_GPE_MAX_TCONT - 1
	    - ANI port*/
	uint32_t epn;
} __PACKED__;

/** Set the egress port configuration.
    Used by \ref FIO_GPE_EGRESS_PORT_CFG_SET and \ref gpe_egress_port_cfg_get_u.
*/
struct gpe_egress_port_cfg {
	/** Egress Port Number (0...71).*/
	uint32_t epn;
	/** Egress port enable.*/
	uint32_t enable;
	/** Maximum drop threshold, in multiples of 8 buffer segments.*/
	uint32_t egress_port_threshold_max;
	/** Green drop threshold, in multiples of 8 buffer segments.*/
	uint32_t egress_port_threshold_green;
	/** Yellow drop threshold, in multiples of 8 buffer segments.*/
	uint32_t egress_port_threshold_yellow;
	/** Red drop threshold, in multiples of 8 buffer segments.*/
	uint32_t egress_port_threshold_red;
} __PACKED__;

/** Union to retrieve Egress Port configuration data.
    Used by \ref FIO_GPE_EGRESS_PORT_CFG_GET.
*/
union gpe_egress_port_cfg_get_u {
	/** Egress Port Number.*/
	struct gpe_epn in;
	/** Retrieved Egress Port configuration data.*/
	struct gpe_egress_port_cfg out;
};

/** Get the egress port status.
    Used by \ref gpe_egress_port_status_get_u.
*/
struct gpe_egress_port_status {
	/** Egress Port Number (0...71).*/
	uint32_t  epn;
	/** Maximum port occupancy, in number of buffer segments.*/
	uint32_t egress_port_occupancy_max;
	/** Green occupancy, in number of buffer segments.*/
	uint32_t egress_port_occupancy_green;
	/** Yellow occupancy, in number of buffer segments.*/
	uint32_t egress_port_occupancy_yellow;
	/** Red occupancy, in number of buffer segments.*/
	uint32_t egress_port_occupancy_red;
} __PACKED__;

/** Union to retrieve Egress Port status.
    Used by \ref FIO_GPE_EGRESS_PORT_STATUS_GET.
*/
union gpe_egress_port_status_get_u {
	/** Specified Egress Port Number.*/
	struct gpe_epn in;
	/** Received Egress Port status.*/
	struct gpe_egress_port_status out;
} __PACKED__;

/** Structure to identify Egress port.
    Used by \ref FIO_GPE_EGRESS_PORT_CREATE, \ref FIO_GPE_EGRESS_PORT_DELETE.
*/
struct gpe_egress_port {
	/** Port Index.
	    - UNI port (LAN port) index to be configured, valid from 0
	    to ONU_GPE_MAX_ETH_UNI - 1
	    - T-CONT index to be connected, valid from 0
	    to ONU_GPE_MAX_TCONT - 1
	    - ANI port*/
	uint32_t index;
	/** Selection if this function call is targeted at a UNI port
	    or a T-CONT, true: UNI, false: T-CONT / ANI port.*/
	uint32_t is_uni;
} __PACKED__;

/** Union to retrieve structural parameters of a TMU egress port.
    Used by \ref FIO_GPE_EGRESS_PORT_GET.
*/
union gpe_eport_get_u {
	/** Specified egress port.*/
	struct gpe_epn in;
	/** Retrieved egress port configuration.*/
	struct gpe_eport_create out;
} __PACKED__;

/** Union to retrieve structural parameters of a TMU egress port.
    Used by \ref FIO_GPE_PORT_INDEX_GET.
*/
union gpe_port_index_get_u {
	/** Specified egress port.*/
	struct gpe_egress_port in;
	/** Retrieved egress port configuration.*/
	struct gpe_eport_create out;
} __PACKED__;

/** Structure to set or get the LAN port backpressure configuration.
    Used by \ref FIO_GPE_BACKPRESSURE_CFG_SET and
    \ref FIO_GPE_BACKPRESSURE_CFG_GET.
*/
struct gpe_backpressure_cfg {
	/** Back pressure thresholds related to the number of free buffer
	    segments.*/
	uint32_t free_segment_threshold[5];
	/** Back pressure higher thresholds related to the UNI ports.*/
	uint32_t lan_queue_backpressure_high[4];
	/** Back pressure lower thresholds related to the UNI ports.*/
	uint32_t lan_queue_backpressure_low[4];
} __PACKED__;

/* HW/FW supports up to 64 entries, only 32 are used.
    the remaining 32 entries are reserved for later enhancements.*/
/** Structure to set or get the Ethertype filter configuration.
    Used by \ref FIO_GPE_ETHERTYPE_FILTER_CFG_SET and
    \ref FIO_GPE_ETHERTYPE_FILTER_CFG_GET.
*/
struct gpe_ethertype_filter_cfg {
	/** Linked or associated LAN port index.*/
	uint32_t lanport_index;
	/** Ethertype filter pointer.*/
	uint32_t ethertype_filter_pointer;
	/** Ethertype code table.*/
	uint32_t ethertype[ONU_GPE_MAX_ETHFILT];
	/** Number of valid Ethertype entries.*/
	uint32_t num_valid_ethertypes;
	/** Ethertype filter mode.
	    - true: whitelist
	    - false: blacklist */
	uint32_t whitelist_mode;
} __PACKED__;

/** Structure to get the Ethertype filter configuration for a corresponding
	LAN port index
*/
struct gpe_ethertype_filter_index {
	/** Linked or associated LAN port index.*/
	uint32_t lanport_index;
};

/** GPON Packet Engine (GPE) hardware thread selector.
    Used by \ref FIO_GPE_SCE_RESTART_VM and \ref FIO_GPE_SCE_RUN.
*/
struct sce_thread_mask {
	/** Thread mask.*/
	uint32_t mask;
} __PACKED__;

/** SCE thread index.
*/
struct sce_thread {
	/** Thread ID (PE_INDEX*4 + VM_NUM).*/
	uint32_t tid;
};

/** Breakpoint for the specified hardware threads.
    Used by \ref FIO_GPE_SCE_BREAK_SET, \ref FIO_GPE_SCE_BREAK_GET, and
    \ref FIO_GPE_SCE_BREAK_REMOVE.
*/
struct sce_break_point {
	/** Thread ID (PE_INDEX*4 + VM_NUM).*/
	uint32_t tid;
	/** Program address.*/
	uint32_t addr;
} __PACKED__;

/** Breakpoint index.
*/
struct sce_break_index {
	/** Thread ID (PE_INDEX*4 + VM_NUM).*/
	uint32_t tid;
	/** Breakpoint index.*/
	uint32_t idx;
} __PACKED__;

/** Processing Element (PE) restart configuration.
*/
struct sce_restart_cfg {
	/** PE index (0xFF for all PEs).*/
	uint32_t pid;
} __PACKED__;

/** SCE Firmware download configuration.
    Used by \ref FIO_GPE_SCE_DOWNLOAD.
*/
struct sce_download_cfg {
	/** PE index (0xFF for all PEs).*/
	uint32_t pid;
	/** Firmware binary name.*/
	char fw_name[ONU_PE_FIRMWARE_NAME_MAX];
} __PACKED__;

/** COP Microcode download configuration.
    Used by \ref FIO_GPE_COP_DOWNLOAD.
*/
struct cop_download_cfg {
	/** COP index */
	uint32_t cop_id;
	/** Microcode binary name.*/
	char mc_name[32];
} __PACKED__;

/** Structure for write access to the ICTRLC interface.
*/
struct ictrlc_write {
	/** Queue ID.*/
	uint32_t qid;
	/** PDU type.*/
	uint32_t pdu_type;
	/** Packet length.*/
	uint32_t plen;
	/** Packet data.*/
	uint8_t *data;
}  __PACKED__;

/** PE index.
    Used by \ref FIO_GPE_SCE_VERSION_GET.
*/
struct sce_pe_index {
	/** PE index (0xFF for all PEs).*/
	uint32_t pid;
} __PACKED__;

/** SCE firmware version.
*/
struct sce_version {
	/** Processing Element (PE) index (0xFF for all PEs).*/
	uint32_t pid;
	/** 4 digits firmware number.*/
	uint8_t data[4];
} __PACKED__;

/** Union to retrieve the SCE firmware version identifier.
    Used by \ref FIO_GPE_SCE_VERSION_GET.
*/
union sce_version_get_u {
	/** Specified PE.*/
	struct sce_pe_index in;
	/** Retrieved SCE version data.*/
	struct sce_version  out;
} __PACKED__;

/** Break information, delivers the program address of the break event.
    Used by \ref FIO_GPE_SCE_BREAK and \ref FIO_GPE_SCE_SINGLE_STEP.
*/
struct sce_break_info {
	/** Program address.*/
	uint32_t addr;
} __PACKED__;

/** SCE debug status.
*/
struct sce_status {
	/** vm_status*/
	uint32_t tstat0;
	/** vm_err*/
	uint32_t terr;
	/** vm_enable*/
	uint32_t tctrl0;
	/** vm_debug*/
	uint32_t tdebug0;
	/** vm_break*/
	uint32_t bctrl0;
	/** vm_breakhit*/
	uint32_t bstat0;
	/** vm_breakdis*/
	uint32_t bdis0;
} __PACKED__;

/** SCE register.
    Used by \ref sce_register_get_u.
*/
struct sce_register {
	/** Thread ID.*/
	uint32_t tid;
	/** Register number.*/
	uint32_t reg;
} __PACKED__;

/** SCE register value.
    Used by \ref FIO_GPE_SCE_REGISTER_SET and
    \ref sce_register_get_u.
*/
struct sce_register_val {
	/** Thread ID.*/
	uint32_t tid;
	/** Register number.*/
	uint32_t reg;
	/** Register value.*/
	uint32_t val;
} __PACKED__;

/** Union to retrieve hardware thread register value.
    Used by \ref FIO_GPE_SCE_REGISTER_GET.
*/
union sce_register_get_u {
	/** Specified SCE register.*/
	struct sce_register in;
	/** Retrieved SCE register value.*/
	struct sce_register_val out;
} __PACKED__;

/** SCE memory.
    Used by \ref sce_memory_get_u
*/
struct sce_memory {
	/** Thread ID.*/
	uint32_t tid;
	/** Memory address.*/
	uint32_t addr;
} __PACKED__;

/** SCE memory value.
    Used by \ref FIO_GPE_SCE_MEMORY_SET and \ref sce_memory_get_u.
*/
struct sce_memory_val {
	/** Thread ID.*/
	uint32_t tid;
	/** Memory address.*/
	uint32_t addr;
	/** Memory address.*/
	uint32_t val;
} __PACKED__;

/** Union to retrieve hardware thread memory word.
    Used by \ref FIO_GPE_SCE_MEMORY_GET.
*/
union sce_memory_get_u {
	/** Specified SCE memory.*/
	struct sce_memory in;
	/** Retrieved SCE memory value.*/
	struct sce_memory_val out;
} __PACKED__;

/** Aging time definition for MAC learning.
    Used by \ref FIO_GPE_AGING_TIME_SET and \ref FIO_GPE_AGING_TIME_GET.
*/
struct sce_aging_time {
	/** Aging time, given in multiples of 1 s.*/
	uint32_t aging_time;
} __PACKED__;

/** Age of a dynamic MAC table entry.
    Used by \ref FIO_GPE_AGE_GET.
*/
struct sce_mac_entry_age {
	/** Ticks count of a MAC table entry */
	uint32_t ticks;
	/** Age of a MAC table entry, given in multiples of 1 s.*/
	uint32_t age;
} __PACKED__;

/** LAN-side exception configuration index.
*/
struct gpe_lan_exception_idx {
	/** LAN port index (0 to 3) */
	uint32_t lan_port_index;
} __PACKED__;

/** LAN-side exception configuration data.
    Used by \ref FIO_GPE_LAN_EXCEPTION_CFG_SET and
    \ref FIO_GPE_LAN_EXCEPTION_CFG_SET.
*/
struct gpe_lan_exception_cfg {
	/** LAN port index (0 to 3). */
	uint32_t lan_port_index;
	/** Exception profile (0 to 3).
        \remark It is recommended to use one profile per LAN port,
        with lan_port_index == exception_profile. */
	uint32_t exception_profile;
	/** Policer index to be used to limit the total amount of exception
	traffic to the software, not accounting for IGMP or MLD messages. */
	uint32_t uni_except_meter_id;
	/** Enable global policer. */
	uint32_t uni_except_meter_enable;
	/* v7.5.1: IGMP meter fields removed. Struct is 16 bytes (char[16]
	   in ioctl encoding). Stock decompilation (FUN_00433258) confirms
	   only 4 fields: lport, profile, meter_id, meter_enable. */
} __PACKED__;

/** LAN-side exception configuration data.
    Used by \ref FIO_GPE_LAN_EXCEPTION_CFG_SET and
    \ref FIO_GPE_LAN_EXCEPTION_CFG_SET.
*/
union gpe_lan_exception_cfg_u {
	/** Specified exception index */
	struct gpe_lan_exception_idx in;
	/** Received exception configuration data */
	struct gpe_lan_exception_cfg out;
} __PACKED__;

/** ANI-side exception configuration index.
*/
struct gpe_ani_exception_idx {
	/** GEM port index (0 to 255) */
	uint32_t gem_port_index;
} __PACKED__;

/** ANI-side exception configuration data.
    Used by \ref FIO_GPE_ANI_EXCEPTION_CFG_SET and
    \ref FIO_GPE_ANI_EXCEPTION_CFG_SET.
*/
struct gpe_ani_exception_cfg {
	/** GEM port index (0 to 255) */
	uint32_t gem_port_index;
	/** Downstream Exception profile. */
	uint32_t ds_exception_profile;
	/** Upstream Exception profile. */
	uint32_t us_exception_profile;
} __PACKED__;

/** ANI-side exception configuration data.
    Used by \ref FIO_GPE_ANI_EXCEPTION_CFG_SET and
    \ref FIO_GPE_ANI_EXCEPTION_CFG_SET.
*/
union gpe_ani_exception_cfg_u {
	/** Specified exception index */
	struct gpe_ani_exception_idx in;
	/** Received exception configuration data */
	struct gpe_ani_exception_cfg out;
} __PACKED__;

/** Exception queue configuration index.
    Used by \ref FIO_GPE_EXCEPTION_QUEUE_CFG_SET.
*/
struct gpe_exception_queue_idx {
	/** Exception index (0 to 31) */
	uint32_t exception_index;
} __PACKED__;

/** Exception queue configuration data.
    Used by \ref FIO_GPE_EXCEPTION_QUEUE_CFG_SET.
*/
struct gpe_exception_queue_cfg {
	/** Exception index (0 to 31) */
	uint32_t exception_index;
	/** A target queue number is configured for each of the exceptions. If an
	exception is disabled or the exception action shall be "drop", the target
	queue setting is ignored and shall be set to ONU_GPE_NULL_QUEUE.*/
	uint32_t exception_queue;
	/** Snooping Enable. If true, the frame is handled as configured for the
	    detected exception and in addition is copied and handled according to
	    the configured data flow. If false, the frame is only handled as
	    exception frame. */
	uint32_t snooping_enable;
	/** Reserved padding for v7.5.1 kernel ABI compatibility. */
	uint32_t _v751_reserved[2];
} __PACKED__;

/** Exception queue configuration data.
    Used by \ref FIO_GPE_EXCEPTION_QUEUE_CFG_GET.
*/
union gpe_exception_queue_cfg_u {
	/** Specified exception queue index */
	struct gpe_exception_queue_idx in;
	/** Received exception queue configuration data */
	struct gpe_exception_queue_cfg out;
} __PACKED__;

/** Exception profile configuration data.
    There are 32 exception types that can be flexibly enabled.
    The exception type index values are defined as
    "ONU_GPE_EXCEPTION_OFFSET_<type>" in "drv_onu_resource_gpe.h".
    Used by \ref FIO_GPE_EXCEPTION_PROFILE_CFG_SET and
    \ref FIO_GPE_EXCEPTION_PROFILE_CFG_GET.
*/
struct gpe_exception_profile_cfg {
	/** Exception profile index (0 to 7). */
	uint32_t exception_profile;
	/** 32-bit mask to enable ingress exceptions for the selected profile.
	   - 0: Ingress exception is disabled for the selected exception type.
	   - 1: Ingress exception is enabled for the selected exception type. */
	uint32_t ingress_exception_mask;
	/** 32-bit mask to enable egress exceptions for the selected profile.
	   - 0: Egress exception is disabled for the selected exception type.
	   - 1: Egress exception is enabled for the selected exception type. */
	uint32_t egress_exception_mask;
} __PACKED__;

/** Exception profile configuration index.
    Used by \ref FIO_GPE_EXCEPTION_PROFILE_CFG_GET.
*/
struct gpe_exception_profile_idx {
	/** Exception profile (0 to7) */
	uint32_t exception_profile;
} __PACKED__;

/** Exception profile configuration data.
    Used by \ref FIO_GPE_EXCEPTION_PROFILE_CFG_GET.
*/
union gpe_exception_profile_cfg_u {
	/** Specified exception profile index */
	struct gpe_exception_profile_idx in;
	/** Received exception queue configuration data */
	struct gpe_exception_profile_cfg out;
} __PACKED__;



/** Structure to define TR181 counters retrieving.
    Used by \ref FIO_GPE_TR181_COUNTER_GET.
*/
struct gpe_tr181_counters_cfg {
	/** Number of egress queue specified in the Upstream list. */
	uint32_t us_egress_queue_num;
	/** List specifies the affected egress queues numbers which are used
	    in the Upstream path. */
	uint32_t us_egress_queue_list[ONU_GPE_MAX_QUEUE];
	/** Number of egress queue specified in the Downstream list. */
	uint32_t ds_egress_queue_num;
	/** List specifies the affected egress queues numbers which are used
	    in the Downstream path. */
	uint32_t ds_egress_queue_list[ONU_GPE_MAX_QUEUE];
} __PACKED__;

/** Structure to define TR181 counters.
    Used by \ref FIO_GPE_TR181_COUNTER_GET.
*/
struct gpe_tr181_counters {
	/** The total number of bytes transmitted out of the interface,
	    including framing characters. */
	uint64_t bytes_sent;
	/** The total number of bytes received on the interface, including
	    framing characters. */
	uint64_t bytes_received;
	/** The total number of packets transmitted out of the interface. */
	uint64_t packets_sent;
	/** The total number of packets received on the interface. */
	uint64_t packets_received;
	/** The total number of outbound packets that could not be transmitted
	    because of errors. */
	uint32_t errors_sent;
	/** The total number of inbound packets that contained errors preventing
	    them from being delivered to a higher-layer protocol. */
	uint32_t errors_received;
	/** The total number of outbound packets which were chosen to be
	    discarded even though no errors had been detected to prevent their
	    being transmitted: One possible reason for discarding such a packet
	    could be to free up buffer space. */
	uint32_t discard_packets_sent;
	/** The total number of inbound packets which were chosen to be
	    discarded even though no errors had been detected to prevent their
	    being delivered. One possible reason for discarding such a packet
	    could be to free up buffer space. */
	uint32_t discard_packets_received;
} __PACKED__;

/** TR181 counters related data.
    Used by \ref FIO_GPE_TR181_COUNTER_GET.
*/
union gpe_tr181_counters_get_u {
	/** TR181 counters retrieving configuration. */
	struct gpe_tr181_counters_cfg in;
	/** Retrieved TR181 counters related to the optical interface. */
	struct gpe_tr181_counters out;
} __PACKED__;

/** GPE capability structure.
    Used by \ref FIO_GPE_CAPABILITY_GET.
*/
struct gpe_capability {
	/** Maximum number of Meters */
	uint32_t max_meter;
	/** Maximum number of GPIX */
	uint32_t max_gpix;
	/** Maximum number of Ethernet UNIs */
	uint32_t max_eth_uni;
	/** Maximum number of POTS UNIs */
	uint32_t max_pots_uni;
	/** Maximum number of Bridge ports */
	uint32_t max_bridge_port;
	/** Chip revision */
	uint32_t hw_version;
	/** Reserved padding for v7.5.1 kernel ABI compatibility. */
	uint32_t _v751_reserved;
};

/* IOCTL Command Declaration - GPE
   ===============================
*/

/** Magic number */
#define GPE_MAGIC 4

/** Magic number for GPE Table subsystem (v7.5.1) */
#define GPE_TABLE_MAGIC 5

/**
   Initialize the GPON Packet Engine (GPE) hardware.
   This function provides the initialization of all sub-modules that are part of
   the GPE. It also loads the SCE firmware into the local Packet Engine (PE)
   code memories, initializes the local data memories and initializes the
   hardware accelerators (coprocessor modules, COP).

   \param gpe_init_data Pointer to \ref gpe_init_data.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - An error code in case of error.
*/
#define FIO_GPE_INIT _IOW(GPE_MAGIC, 0x00, struct gpe_init_data)

/**
   Define the basic GPON Packet Engine configuration.
   This function provides the implementation-specific configuration of the GPE
   module itself.

   Additional configuration functions are provided for some of the GPE
   sub-modules to reduce this function's complexity:
   - \ref FIO_GPE_SCHEDULER_CFG_SET
   - \ref FIO_GPE_METER_CFG_SET
   - \ref FIO_GPE_EGRESS_QUEUE_COUNTER_CFG_SET
   - \ref FIO_GPE_PARSER_CFG_SET
   - \ref FIO_GPE_TOKEN_BUCKET_SHAPER_CFG_SET
   - \ref FIO_GPE_EGRESS_PORT_CFG_SET
   - \ref FIO_GPE_BACKPRESSURE_CFG_SET
   - \ref FIO_GPE_ETHERTYPE_FILTER_CFG_SET

   \param gpe_cfg Pointer to \ref gpe_cfg.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - An error code in case of error.
*/
#define FIO_GPE_CFG_SET _IOW(GPE_MAGIC, 0x01, struct gpe_cfg)

/**
   Read the basic GPON Packet Engine configuration back.

   \param gpe_cfg Pointer to \ref gpe_cfg.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - An error code in case of error.

*/
#define FIO_GPE_CFG_GET _IOR(GPE_MAGIC, 0x02, struct gpe_cfg)

/**
   Retrieve GPON Packet Engine status information.

   \param gpe_status Pointer to \ref gpe_status.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - An error code in case of error.
*/
#define FIO_GPE_STATUS_GET _IOR(GPE_MAGIC, 0x03, struct gpe_status)

/**
   Add a GEM Port ID to the GPE configuration. If all GEM Port IDs are already
   used, an error code is responded. If the Port ID already exists, this entry
   is silently overwritten. If the Port ID is larger than the number given by
   ONU_GPE_MAX_GEM_PORT_ID - 1, another error code is returned.

   \param gpe_gem_port Pointer to \ref gpe_gem_port.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_VALUE_RANGE_ERR: if the GEM Port ID
				 is >= ONU_GPE_MAX_GEM_PORT_ID
   - GPE_STATUS_VALUE_RANGE_ERR: if the T-CONT index is >= ONU_GPE_MAX_TCONT
   - GPE_STATUS_NOT_AVAILABLE: if no GEM Port ID entry is free
*/
#define FIO_GPE_GEM_PORT_ADD \
			_IOWR(GPE_MAGIC, 0x04, struct gpe_gem_port)

/**
   Remove a GEM Port ID from the GPE configuration. If the given GEM Port ID is
   not present in the GPE configuration, an error code is responded. If the GEM
   Port ID is larger than ONU_GPE_MAX_GEM_PORT_ID - 1, another error code is
   returned.

   \param gem_port_id Pointer to \ref gem_port_id.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_VALUE_RANGE_ERR: if the GEM Port ID
				 is >= ONU_GPE_MAX_GEM_PORT_ID
   - GPE_STATUS_NOT_AVAILABLE: if the GEM Port ID is unknown
*/
#define FIO_GPE_GEM_PORT_DELETE _IOW(GPE_MAGIC, 0x05, struct gem_port_id)

/**
   Read back the GPE configuration for a given GEM Port ID. If the Port ID is
   not present in the GPE configuration, an error code is responded. If the GEM
   Port ID is larger than ONU_GPE_MAX_GEM_PORT_ID - 1, another error code is
   returned.

   \param gpe_gem_port_get_u Pointer to \ref gpe_gem_port_get_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_VALUE_RANGE_ERR: if the GEM Port ID
				 is >= ONU_GPE_MAX_GEM_PORT_ID
   - GPE_STATUS_NOT_AVAILABLE: if the GEM Port ID is unknown
*/
#define FIO_GPE_GEM_PORT_GET _IOWR(GPE_MAGIC, 0x06, union gpe_gem_port_get_u)

/**
   This function must be called to activate a formerly unused egress queue and
   assign it to a scheduler input and to an egress port.

   This function is the last step in the process of building a data path through
   the TMU. It is assumed that a scheduler hierarchy has been created
   from the scheduler input up an egress port beforehand.
   The egress port number provided MUST identify the egress port assigned to the
   toplevel scheduler in the hierarchy above the scheduler input.

   Functional description.
   - Establishment of a bidirectional link between an egress queue and a
      scheduler block input.
   - Enabling of the scheduler block input for PDU transmission.
   - Enabling of the egress queue for PDU acceptance.

   \param gpe_equeue_create Pointer to \ref gpe_equeue_create.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.
            The function must not be used after activation of the TMU

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_EGRESS_QUEUE_CREATE \
			_IOW(GPE_MAGIC, 0x07, struct gpe_equeue_create)

/**
   This function may be called to disable a formerly created egress queue.
   The queue will no longer be served. Data that is held in the queue during
   time of deactivation will be lost.

   \param gpe_equeue Pointer to \ref gpe_equeue.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_EGRESS_QUEUE_DELETE _IOW(GPE_MAGIC, 0x08, struct gpe_equeue)

/**
   Update the configuration for a egress queue within the GPE.

   \param gpe_equeue_cfg Pointer to \ref gpe_equeue_cfg.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_VALUE_RANGE_ERR: if weight > 15
   - GPE_STATUS_NOT_AVAILABLE: if index > ONU_GPE_MAX_QUEUE - 1
*/
#define FIO_GPE_EGRESS_QUEUE_CFG_SET \
			_IOW(GPE_MAGIC, 0x09, struct gpe_equeue_cfg)

/**
   Read the configuration of an egress queue within the GPE.

   \param gpe_equeue_cfg Pointer to \ref gpe_equeue_cfg_get_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_EGRESS_QUEUE_CFG_GET \
			_IOWR(GPE_MAGIC, 0x0A, union gpe_equeue_cfg_get_u)

/**
   Read the status of an egress queue within the GPE.

   \param gpe_equeue_status Pointer to \ref gpe_equeue_status_get_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_EGRESS_QUEUE_STATUS_GET \
			_IOWR(GPE_MAGIC, 0x0B, union gpe_equeue_status_get_u)

/**
   Update the configuration for an ingress queue within the GPE.

   \param gpe_iqueue_cfg Pointer to \ref gpe_iqueue_cfg.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_INGRESS_QUEUE_CFG_SET \
			_IOW(GPE_MAGIC, 0x0C, struct gpe_iqueue_cfg)

/**
   Read the configuration of an ingress queue within the GPE.

   \param gpe_iqueue_cfg Pointer to \ref gpe_iqueue_cfg_get_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_INGRESS_QUEUE_CFG_GET \
			_IOWR(GPE_MAGIC, 0x0D, union gpe_iqueue_cfg_get_u)

/**
   Set the configuration for a traffic scheduler within the GPE.

   \param gpe_scheduler_cfg Pointer to \ref gpe_scheduler_cfg.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_NOT_AVAILABLE: if (scheduler index > 143)
   - GPE_STATUS_INVALID_CTL: if ((T-CONT index > 0)&&(scheduler index > 0))
*/
#define FIO_GPE_SCHEDULER_CFG_SET \
			_IOW(GPE_MAGIC, 0x0E, struct gpe_scheduler_cfg)

/**
   Read the configuration of a traffic scheduler within the GPE.

   \param gpe_scheduler_cfg Pointer to \ref gpe_scheduler_cfg_get_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_SCHEDULER_CFG_GET \
			_IOWR(GPE_MAGIC, 0x0F, union gpe_scheduler_cfg_get_u)

/**
   Create meter by searching a free Token Bucket Meter (TBM) block.

   \param gpe_meter Pointer to \ref gpe_meter.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_METER_CREATE _IOR(GPE_MAGIC, 0x10, struct gpe_meter)

/**
   Delete the specified meter.

   \param gpe_meter_cfg Pointer to \ref gpe_meter_cfg.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_METER_DELETE _IOW(GPE_MAGIC, 0x11, struct gpe_meter)

/**
   Set the meter parameters of a selected Token Bucket Meter (TBM).

   \param gpe_meter_cfg Pointer to \ref gpe_meter_cfg.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_NO_SUPPORT: if the meter index is > 511

*/
#define FIO_GPE_METER_CFG_SET _IOW(GPE_MAGIC, 0x12, struct gpe_meter_cfg)

/**
   Read the meter configuration of a selected Token Bucket Meter (TBM).

   \param gpe_meter_cfg Pointer to \ref gpe_meter_cfg_get_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_NO_SUPPORT: if the meter index is > 511
*/
#define FIO_GPE_METER_CFG_GET \
			_IOWR(GPE_MAGIC, 0x13, union gpe_meter_cfg_get_u)

/**
   Read the meter status of a selected Token Bucket Meter (TBM).

   \param gpe_meter_status Pointer to \ref gpe_meter_status_get_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_METER_STATUS_GET \
			_IOWR(GPE_MAGIC, 0x14, union gpe_meter_status_get_u)

/**
   Read the bridge-based performance counters.

   \param gpe_bridge_counter Pointer to \ref gpe_bridge_counter_get_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_COUNTER_ERR: if one of the counters suffered from an overflow
                                 event
   - GPE_STATUS_NO_SUPPORT: if the bridge index is invalid
*/
#define FIO_GPE_BRIDGE_COUNTER_GET \
			_IOWR(GPE_MAGIC, 0x16, union gpe_bridge_counter_get_u)

/**
   Write the bridge-based counter thresholds.

   \param gpe_cnt_bridge_threshold Pointer to \ref gpe_cnt_bridge_threshold.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_COUNTER_ERR: if one of the counters suffered from an overflow
			     event
   - GPE_STATUS_NO_SUPPORT: if the GEM port ID is invalid
*/
#define FIO_GPE_BRIDGE_COUNTER_THRESHOLD_SET \
			_IOW(GPE_MAGIC, 0x17, struct gpe_cnt_bridge_threshold)

/**
   Read the bridge-based counter thresholds.

   \param gpe_bridge_counter_threshold Pointer to
	  \ref gpe_bridge_counter_threshold_get_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_COUNTER_ERR: if one of the counters suffered from an overflow
			     event
   - GPE_STATUS_NO_SUPPORT: if the GEM port ID is invalid
*/
#define FIO_GPE_BRIDGE_COUNTER_THRESHOLD_GET \
			_IOWR(GPE_MAGIC, 0x18, \
				union gpe_bridge_counter_threshold_get_u)

/**
   Read the bridge-based counter threshold alarms.

   \param gpe_bridge_counter_threshold Pointer to
          \ref gpe_bridge_counter_threshold_get_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_NO_SUPPORT: if the GEM port ID is invalid
*/
#define FIO_GPE_BRIDGE_TCA_GET \
			_IOWR(GPE_MAGIC, 0x19, \
				union gpe_bridge_counter_threshold_get_u)

/**
   Bridge-based counter reset. Calling this function clears all counters
   that are covered by \ref gpe_cnt_bridge_val.

   \param gpe_bridge_cnt_interval Pointer to \ref gpe_bridge_cnt_interval.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_NO_SUPPORT: if the bridge index is invalid
*/
#define FIO_GPE_BRIDGE_COUNTER_RESET \
			_IOW(GPE_MAGIC, 0x1A, struct gpe_bridge_cnt_interval)

/**
   Set the egress queue counter parameters of a selected egress queue.

   \param gpe_equeue_cnt_cfg Pointer to \ref gpe_equeue_cnt_cfg.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_NO_SUPPORT: if the queue index is > ONU_GPE_MAX_QUEUE_PSB9801x
*/
/* Not in v7.5.1 kernel */
/* #define FIO_GPE_EGRESS_QUEUE_COUNTER_CFG_SET \
			_IOW(GPE_MAGIC, 0x1A, struct gpe_equeue_cnt_cfg) */

/**
   Read the egress queue counter parameters of a selected egress queue.

   \param gpe_equeue_cnt_cfg Pointer to \ref gpe_equeue_cnt_cfg.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_NO_SUPPORT: if the queue index is > ONU_GPE_MAX_QUEUE_PSB9801x
*/
/* Not in v7.5.1 kernel */
/* #define FIO_GPE_EGRESS_QUEUE_COUNTER_CFG_GET \
			_IOR(GPE_MAGIC, 0x1B, struct gpe_equeue_cnt_cfg) */

/**
   Create the T-CONT ressource. Implicitly a scheduler will be created.

   \param gpe_tcont_cfg Pointer to \ref gpe_tcont_cfg.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_NO_SUPPORT: if the index is out of range
   - GPE_STATUS_VALUE_RANGE_ERR: if the Allocation ID is out of range
   - GPE_STATUS_NOT_AVAILABLE: if the T-CONT index is out of range
*/
#define FIO_GPE_TCONT_CREATE _IOW(GPE_MAGIC, 0x1B, char[8])

/**
   Set an Allocation ID in the T-CONT table. Existing Allocation IDs are
   silently overwritten.

   \param gpe_tcont Pointer to \ref gpe_tcont.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_NO_SUPPORT: if the index is out of range
   - GPE_STATUS_VALUE_RANGE_ERR: if the Allocation ID is out of range
   - GPE_STATUS_NOT_AVAILABLE: if the T-CONT index is out of range
*/
#define FIO_GPE_TCONT_SET _IOW(GPE_MAGIC, 0x1C, struct gpe_tcont)

/**
   Get the Allocation ID of a T-CONT in the T-CONT table.

   \param gpe_tcont Pointer to \ref gpe_tcont_get_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_NOT_AVAILABLE: if the given T-CONT index is out of range
*/
#define FIO_GPE_TCONT_GET _IOWR(GPE_MAGIC, 0x1D, union gpe_tcont_get_u)

/**
   Remove an entry from the T-CONT table. If the given T-CONT ID is not
   present in the T-CONT table, an error code is responded.

   \param tcont_index Pointer to \ref tcont_index.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_VALUE_RANGE_ERR: if the given T-CONT index is out of range
   - GPE_STATUS_NOT_AVAILABLE: if the given T-CONT index is not active
*/
#define FIO_GPE_TCONT_DELETE _IOW(GPE_MAGIC, 0x1E, struct tcont_index)

/**
   Activate a formerly unused scheduler
   for transmission and either assign it to an egress port (ANI / UNI) or to
   another scheduler block input.

   This function is a mandatory first step in the process of creating a data
   path through the TMU.
   Optionally, the function is called as part of the stepwise creation of a
   scheduler hierarchy.

   If all schedulers are used, an error code is responded (resource not
   available).
   If the scheduler ID already exists in the table, nothing is done but an
   error code is returned.

   The function performs the following.
	- Establishment of a bidirectional link between
	either a scheduler output and an egress port in case it is a toplevel scheduler
	(v == 0) or
	a scheduler output and another scheduler input in case it is
	not a toplevel scheduler (v == 1).
	- Enabling of the scheduler output for transmission.

   \param gpe_sched_create Pointer to \ref gpe_sched_create.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_NOT_AVAILABLE: if no table entry is free
   - GPE_STATUS_CONFIG_MISMATCH: if the entry is already occupied
*/
#define FIO_GPE_SCHEDULER_CREATE \
			_IOW(GPE_MAGIC, 0x1F, struct gpe_sched_create)

/**
   Remove an entry from the scheduler table. If the given scheduler ID is not
   present in the scheduler table, an error code is responded.

   \param gpe_scheduler_idx Pointer to \ref gpe_scheduler_idx.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_NOT_AVAILABLE: if the scheduler ID is unknown
*/
#define FIO_GPE_SCHEDULER_DELETE \
			_IOW(GPE_MAGIC, 0x20, struct gpe_scheduler_idx)

/**
   Set the ingress packet parser parameters.
   The parsing process that is applied to each incoming data packet is
   configured through this function.

   \param gpe_parser_cfg Pointer to \ref gpe_parser_cfg.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_PARSER_CFG_SET _IOW(GPE_TABLE_MAGIC, 0x4B, char[20])

/**
   Read the ingress packet parser configuration.

   \param gpe_parser_cfg Pointer to \ref gpe_parser_cfg.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_PARSER_CFG_GET \
			_IOR(GPE_TABLE_MAGIC, 0x4C, char[20])

/**
   Read the TMU-based counters. Available counter values are:
   - Discarded packets per egress queue
   - Discarded packets per ingress queue
   - Discarded packets per T-CONT
   - Discarded packets per LAN port
   - Discarded packets per virtual UNI

   A write access using \ref gpe_cnt_tmu_sel selects the counter type and
   counter index to be accessed by the subsequent read access.
   \ref gpe_cnt_tmu_val delivers the desired counter value.

   \param gpe_cnt_tmu Pointer to \ref gpe_tmu_counter_get_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_COUNTER_ERR: if one of the counters suffered from an overflow
                                 event
*/
#define FIO_GPE_TMU_COUNTER_GET \
			_IOWR(GPE_MAGIC, 0x21, union gpe_tmu_counter_get_u)

/**
   TMU-based counter reset. Calling this function clears all counters
   that are covered by \ref gpe_cnt_tmu_val.

   \param gpe_cnt_tmu_reset Pointer to \ref gpe_cnt_tmu_reset.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
/* Not in v7.5.1 kernel */
/* #define FIO_GPE_TMU_COUNTER_RESET \
				_IOW(GPE_MAGIC, 0x25, struct gpe_cnt_tmu_reset) */

/**
   Read the SCE-based counters.

   \param gpe_sce_cnt Pointer to \ref gpe_sce_cnt_get_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_COUNTER_ERR: if one of the counters suffered from an overflow
			     event
   - GPE_STATUS_NO_SUPPORT: if the UNI port ID is invalid
*/
/* Not in v7.5.1 kernel — dead ioctl, will return ENOTTY at runtime */
#define FIO_GPE_SCE_COUNTER_GET _IOWR(0xFF, 0x01, union gpe_sce_cnt_get_u)

/**
   SCE-based counter reset. Calling this function clears all counters
   that are covered by \ref gpe_cnt_sce_val.

   \param gpe_cnt_sce_reset Pointer to \ref gpe_cnt_sce_reset.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_NO_SUPPORT: if the UNI port ID is invalid
*/
/* Not in v7.5.1 kernel */
/* #define FIO_GPE_SCE_COUNTER_RESET \
			_IOW(GPE_MAGIC, 0x27, struct gpe_cnt_sce_reset) */

/**
   Configure a Token Bucket Shaper instance.

   \param gpe_token_bucket_shaper_cfg Pointer to
	  \ref gpe_token_bucket_shaper_cfg.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_NO_SUPPORT: if the Token Bucket Shaper Index is invalid
   - GPE_STATUS_VALUE_RANGE_ERR: if one of the parameter values is invalid
*/
#define FIO_GPE_TOKEN_BUCKET_SHAPER_CFG_SET \
		_IOW(GPE_MAGIC, 0x22, struct gpe_token_bucket_shaper_cfg)

/**
   Read the configuration of a Token Bucket Shaper instance.

   \param gpe_token_bucket_shaper_cfg Pointer to
	  \ref gpe_token_bucket_shaper_cfg_get_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_NO_SUPPORT: if the Token Bucket Shaper Index is invalid
*/
#define FIO_GPE_TOKEN_BUCKET_SHAPER_CFG_GET \
		_IOWR(GPE_MAGIC, 0x23, union gpe_token_bucket_shaper_cfg_get_u)

/**
   Send an OMCI message to the OLT.

   \param gpe_omci_msgx Pointer to \ref gpe_omci_msg.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - ONU_STATUS_ERR: if the message could not be send
   - GTC_STATUS_VALUE_RANGE_ERR: if the OMCI size does not match
*/
#define FIO_GPE_OMCI_SEND _IOW(GPE_MAGIC, 0x24, struct gpe_omci_msg)

/**
   Initialize the Time of Day serial interface data format.

   \param gpe_tod_init_data Pointer to \ref gpe_tod_init_data.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GTC_STATUS_VALUE_RANGE_ERR: if on of the parameter values is invalid
*/
#define FIO_GPE_TOD_INIT _IOW(GPE_MAGIC, 0x25, struct gpe_tod_init_data)

/**
   Set the Time of Day synchronously with the GTC sublayer.

   \param gpe_tod_sync Pointer to \ref gpe_tod_sync.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_TOD_SYNC_SET _IOW(GPE_MAGIC, 0x26, char[20])

/**
   Read the Time of Day. The returned format is UTC.

   \param gpe_tod Pointer to \ref gpe_tod.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_TOD_GET _IOR(GPE_MAGIC, 0x27, struct gpe_tod)

/**
   Read the parameters of the latest \ref FIO_GPE_TOD_SYNC_SET call back.

   \param gpe_tod_sync Pointer to \ref gpe_tod_sync.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_TOD_SYNC_GET _IOR(GPE_MAGIC, 0x28, char[20])

/**
   Configure an egress port and a priority queue instance for a UNI (LAN) port.

   \param gpe_egress_port_cfg Pointer to \ref gpe_egress_port_cfg.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_EGRESS_PORT_CFG_SET \
			_IOW(GPE_MAGIC, 0x2B, struct gpe_egress_port_cfg)

/**
   Read the egress port configuration of a UNI (LAN) port instance.

   \param gpe_egress_port Pointer to \ref gpe_egress_port_cfg_get_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_EGRESS_PORT_CFG_GET \
		_IOWR(GPE_MAGIC, 0x2C, union gpe_egress_port_cfg_get_u)

/**
   Configure the UNI (LAN) port flow control (backpressure).

   \param gpe_backpressure_cfg Pointer to \ref gpe_backpressure_cfg.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_BACKPRESSURE_CFG_SET \
			_IOW(GPE_MAGIC, 0x2D, struct gpe_backpressure_cfg)

/**
   Read the configuration of the UNI (LAN) port flow control (backpressure).

   \param gpe_backpressure_cfg Pointer to \ref gpe_backpressure_cfg.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_BACKPRESSURE_CFG_GET \
			_IOR(GPE_MAGIC, 0x2E, struct gpe_backpressure_cfg)

/**
   Read the GEM port ID based counters.

   To read the counters related to a dedicated GEM port, two accesses are
   required. The first is a write access that selects the target GEM port, the
   reset mask, and the scope of the counter access (current value or sum of the
   last 15-min interval).
   The write access uses the structure \ref gpe_gem_cnt_interval to set the
   target values. The second access is a read access, using the
   \ref gpe_cnt_gem_val structure. This delivers a data set that covers all
   counters that are related to the selected GEM port.

   For the definition of the reset mask,
   see "ONU_GPE_GEM_CNT_RST_MASK_<counter>" in "drv_onu_gpe_interface.h".

   \param gpe_gem_counter Pointer to \ref gpe_gem_counter_get_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_NO_SUPPORT: if the GEM Port ID is not assigned
   - GPE_STATUS_COUNTER_ERR: if one of the counters suffered from an overflow
                                 event
*/
#define FIO_GPE_GEM_COUNTER_GET \
			_IOWR(GPE_MAGIC, 0x2F, union gpe_gem_counter_get_u)

/**
   Write the GEM counter thresholds per GEM port ID.

   \param gpe_cnt_gem_threshold Pointer to \ref gpe_cnt_gem_threshold.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_COUNTER_ERR: if one of the counters suffered from an overflow
			     event
   - GPE_STATUS_NO_SUPPORT: if the GEM port ID is invalid
*/
#define FIO_GPE_GEM_COUNTER_THRESHOLD_SET \
			_IOW(GPE_MAGIC, 0x30, struct gpe_cnt_gem_threshold)

/**
   Read the GEM counter threshold values per GEM port ID.

   \param gpe_gem_cnt_threshold Pointer to
		\ref gpe_gem_counter_threshold_get_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_COUNTER_ERR: if one of the counters suffered from an overflow
			     event
   - GPE_STATUS_NO_SUPPORT: if the GEM port ID is invalid
*/
#define FIO_GPE_GEM_COUNTER_THRESHOLD_GET \
			_IOWR(GPE_MAGIC, 0x31, \
				union gpe_gem_counter_threshold_get_u)

/**
   Read the GEM counter threshold alarms per GEM port id.

   \param gpe_gem_tca Pointer to \ref gpe_gem_tca_get_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_NO_SUPPORT: if the GEM port ID is invalid
*/
#define FIO_GPE_GEM_TCA_GET _IOWR(GPE_MAGIC, 0x32, union gpe_gem_tca_get_u)

/**
   GEM port ID based counter reset. Calling this function clears all counters
   that are covered by \ref gpe_cnt_gem_val (per selected GEM Port ID).

   \param gpe_gem_cnt_interval Pointer to \ref gpe_gem_cnt_interval.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_NO_SUPPORT: if the GEM Port index is within the invalid
                                     range of 128 to 254
*/
#define FIO_GPE_GEM_COUNTER_RESET \
			_IOW(GPE_MAGIC, 0x33, struct gpe_gem_cnt_interval)

/* The following functions are used to handle SCE FW debugging */

/**
   Set the Packet Engine (PE) hardware thread specific breakpoint.

   \param sce_break_point Pointer to \ref sce_break_point.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_SCE_BREAK_SET _IOW(GPE_MAGIC, 0x36, struct sce_break_point)

/**
   Read breakpoint information for a specific index

   \param sce_break_point Pointer to \ref sce_break_point.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_SCE_BREAK_GET _IOWR(GPE_MAGIC, 0x37, struct sce_break_point)

/**
   Remove the hardware thread specific breakpoint.
   The breakpoint remains valid until no more hardware thread is selected.

   \param sce_break_point Pointer to \ref sce_break_point.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_SCE_BREAK_REMOVE _IOW(GPE_MAGIC, 0x38, struct sce_break_point)

/**
   Break the specified hardware thread.

   \param sce_break_info Pointer to \ref sce_break_info.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_SCE_BREAK _IOWR(GPE_MAGIC, 0x39, struct sce_break_info)

/**
   Perform a single step of the specified hardware threads.

   \param sce_break_info Pointer to \ref sce_break_info.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_SCE_SINGLE_STEP _IOWR(GPE_MAGIC, 0x3A, struct sce_break_info)

/**
   Run the specified hardware thread.

   \param sce_thread Pointer to \ref sce_thread.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_SCE_RUN _IOW(GPE_MAGIC, 0x3B, struct sce_thread)

/**
   Download the SCE firmware.

   \param sce_download_cfg Pointer to \ref sce_download_cfg.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_SCE_DOWNLOAD _IOW(GPE_MAGIC, 0x3C, struct sce_download_cfg)

/**
   Restart the specified hardware thread(s). This is intended for debugging
   only.

   \param sce_restart_cfg Pointer to \ref sce_restart_cfg.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_SCE_RESTART_VM _IOW(GPE_MAGIC, 0x3D, struct sce_restart_cfg)

/**
   Run the specified hardware thread(s).

   \param sce_thread_mask Pointer to \ref sce_thread_mask.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_SCE_RUN_MASK _IOW(GPE_MAGIC, 0x3E, struct sce_thread_mask)

/**
   Break the specified hardware thread(s).

   \param sce_thread_mask Pointer to \ref sce_thread_mask.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_SCE_BREAK_MASK _IOWR(GPE_MAGIC, 0x3F, struct sce_thread_mask)

/**
   Get SCE debug status.

   \param sce_status Pointer to \ref sce_status.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_SCE_STATUS_GET _IOR(GPE_MAGIC, 0x40, struct sce_status)

/**
   Set the hardware thread register.

   \param sce_register_val Pointer to \ref sce_register_val.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_SCE_REGISTER_SET _IOW(GPE_MAGIC, 0x41, struct sce_register_val)

/**
   Read the hardware thread register.

   \param sce_register Pointer to \ref sce_register_get_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - ONU_STATUS_ERR: in the case of error
*/
#define FIO_GPE_SCE_REGISTER_GET \
			_IOWR(GPE_MAGIC, 0x42, union sce_register_get_u)

/**
   Set the hardware thread memory word.

   \param sce_memory_val Pointer to \ref sce_memory_val.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_SCE_MEMORY_SET _IOW(GPE_MAGIC, 0x43, struct sce_memory_val)

/**
   Read the hardware thread memory word.

   \param sce_memory Pointer to \ref sce_memory_get_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - ONU_STATUS_ERR: in the case of error
*/
#define FIO_GPE_SCE_MEMORY_GET _IOWR(GPE_MAGIC, 0x44, union sce_memory_get_u)

/**
   Read the SCE firmware version.

   \param sce_version_get_u Pointer to \ref sce_version_get_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_SCE_VERSION_GET _IOWR(GPE_TABLE_MAGIC, 0x4F, union sce_version_get_u)

/**
   Enable/disable low level modules FSM.

   \param gpe_ll_mod_sel Pointer to \ref gpe_ll_mod_sel.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - An error code in case of error.
*/
#define FIO_GPE_LOW_LEVEL_MODULES_ENABLE \
				_IOW(GPE_MAGIC, 0x45, struct gpe_ll_mod_sel)

/**
   Set the configuration of the Ethertype whitelist/blacklist filter.

   \param gpe_ethertype_filter_cfg Pointer to \ref gpe_ethertype_filter_cfg.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful

*/
#define FIO_GPE_ETHERTYPE_FILTER_CFG_SET \
         _IOW(GPE_TABLE_MAGIC, 0x4D, struct gpe_ethertype_filter_cfg)

/**
   Read the configuration of the Ethertype whitelist/blacklist filter.

   \param gpe_ethertype_filter_cfg Pointer to \ref gpe_ethertype_filter_cfg.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_NO_SUPPORT: if the meter index is > 511
*/
#define FIO_GPE_ETHERTYPE_FILTER_CFG_GET \
			_IOWR(GPE_TABLE_MAGIC, 0x4E, struct gpe_ethertype_filter_cfg)

/**
   Create a token bucket shaper and assign it to a scheduler input.

   \param gpe_token_bucket_shaper Pointer to \ref gpe_token_bucket_shaper.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_TOKEN_BUCKET_SHAPER_CREATE \
			_IOW(GPE_MAGIC, 0x46, struct gpe_token_bucket_shaper)

/**
   Delete a previously created token bucket shaper.

   \param gpe_token_bucket_shaper Pointer to \ref gpe_token_bucket_shaper.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_TOKEN_BUCKET_SHAPER_DELETE \
			_IOW(GPE_MAGIC, 0x47, struct gpe_token_bucket_shaper)

/**
   Read back the structural links of a token bucket shapers.

   \param gpe_token_bucket_shaper Pointer to
				\ref gpe_token_bucket_shaper_get_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_TOKEN_BUCKET_SHAPER_GET \
				_IOWR(GPE_MAGIC, 0x48, \
					union gpe_token_bucket_shaper_get_u)

/**
   Read back the status variables of a token bucket shaper.

   \param gpe_token_bucket_shaper Pointer to
				\ref gpe_token_bucket_shaper_status_get_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_TOKEN_BUCKET_SHAPER_STATUS_GET \
			_IOWR(GPE_MAGIC, 0x49, \
				union gpe_token_bucket_shaper_status_get_u)

/**
   Read back the structural attributes of an egress queue.

   \param gpe_equeue Pointer to \ref gpe_equeue_get_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_NOT_AVAILABLE: if no table entry is free
   - GPE_STATUS_CONFIG_MISMATCH: if the entry is already occupied
*/
#define FIO_GPE_EGRESS_QUEUE_GET \
			_IOWR(GPE_MAGIC, 0x4A, union gpe_equeue_get_u)

/**
   Read back the structural attributes of a scheduler

   \param gpe_scheduler_idx Pointer to \ref gpe_scheduler_get_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_NOT_AVAILABLE: if no table entry is free
   - GPE_STATUS_CONFIG_MISMATCH: if the entry is already occupied
*/
#define FIO_GPE_SCHEDULER_GET \
			_IOWR(GPE_MAGIC, 0x4B, union gpe_scheduler_get_u)

/**
   Read back the status variables of a scheduler

   \param gpe_scheduler_status Pointer to \ref gpe_scheduler_status_get_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_NOT_AVAILABLE: if no table entry is free
   - GPE_STATUS_CONFIG_MISMATCH: if the entry is already occupied
*/
#define FIO_GPE_SCHEDULER_STATUS_GET \
			_IOWR(GPE_MAGIC, 0x4C, \
				union gpe_scheduler_status_get_u)

/**
   Create a TMU egress port.

   \param gpe_eport_create Pointer to \ref gpe_eport_create.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_NOT_AVAILABLE: if no table entry is free
   - GPE_STATUS_CONFIG_MISMATCH: if the entry is already occupied
*/
#define FIO_GPE_EGRESS_PORT_CREATE \
			_IOW(GPE_MAGIC, 0x4D, struct gpe_eport_create)

/**
   Read back the structural parameters of a TMU egress port

   \param gpe_eport Pointer to \ref gpe_eport_get_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_NOT_AVAILABLE: if no table entry is free
   - GPE_STATUS_CONFIG_MISMATCH: if the entry is already occupied
*/
#define FIO_GPE_EGRESS_PORT_GET \
			_IOWR(GPE_MAGIC, 0x4E, union gpe_eport_get_u)

/**
   Read back the structural parameters of a TMU egress port

   \param gpe_egress_port Pointer to \ref gpe_egress_port.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_NOT_AVAILABLE: if no table entry is free
   - GPE_STATUS_CONFIG_MISMATCH: if the entry is already occupied
*/
#define FIO_GPE_EGRESS_PORT_DELETE \
			_IOW(GPE_MAGIC, 0x4F, struct gpe_egress_port)


/**
   Read back the status variables of an egress port

   \param gpe_egress_port_status Pointer to \ref gpe_egress_port_status_get_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_NOT_AVAILABLE: if no table entry is free
   - GPE_STATUS_CONFIG_MISMATCH: if the entry is already occupied
*/
#define FIO_GPE_EGRESS_PORT_STATUS_GET \
			_IOWR(GPE_MAGIC, 0x50, \
					union gpe_egress_port_status_get_u)

/**
   Create several consecutive egress ports with assigned schedulers and queues.

   The first port to be created is provided as base_epn.
   The first scheduler to be created is provided as base_sbid.
   The first egress queue to be created is provided as base_qid.
   The number of queues per scheduler is provided as qid_per_sb.

   There is a 1:1 relationship between egress ports and schedulers.
   There is a qid_per_sb: 1 relationship between queues and schedulers.

   \param gpe_flat_egress_path Pointer to \ref gpe_flat_egress_path.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_NOT_AVAILABLE: if no table entry is free
   - GPE_STATUS_CONFIG_MISMATCH: if the entry is already occupied
*/
#define FIO_GPE_FLAT_EGRESS_PATH_CREATE \
			_IOW(GPE_MAGIC, 0x51, struct gpe_flat_egress_path)


/**
   This function reads back the shared data buffer configuration.

   \param gpe_shared_buffer_cfg Pointer to \ref gpe_shared_buffer_cfg.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_SHARED_BUFFER_CFG_GET \
			_IOR(GPE_MAGIC, 0x52, struct gpe_shared_buffer_cfg)

/**
   This function configures the shared data buffer.

   \param gpe_shared_buffer_cfg Pointer to \ref gpe_shared_buffer_cfg.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_SHARED_BUFFER_CFG_SET \
			_IOW(GPE_MAGIC, 0x53, struct gpe_shared_buffer_cfg)

/**
   This function checks the consistency of the free segment list of the
   shared buffer.

   \param len Known length of the free list.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_FSQM_CHECK \
			_IOW(GPE_MAGIC, 0x54, uint32_t)

/**
   This function is used to print out structural attributes
   along the path from a queue up to the egress port.

   \param gpe_equeue Pointer to \ref gpe_equeue.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_EGRESS_QUEUE_PATH_GET \
			_IOWR(GPE_MAGIC, 0x55, union gpe_equeue_path_get_u)

/**
   This function is used to configure global IQM parameters.

   \param gpe_iqm_global_cfg Pointer to \ref gpe_iqm_global_cfg.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_IQM_GLOBAL_CFG_SET \
			_IOW(GPE_MAGIC, 0x56, struct gpe_iqm_global_cfg)

/**
   This function is used to read back global IQM parameters.

   \param gpe_iqm_global_cfg Pointer to \ref gpe_iqm_global_cfg.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_IQM_GLOBAL_CFG_GET \
			_IOR(GPE_MAGIC, 0x57, struct gpe_iqm_global_cfg)

/**
   This function is used to read back global IQM status variables.

   \param gpe_iqm_global_status Pointer to \ref gpe_iqm_global_status.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_IQM_GLOBAL_STATUS_GET \
			_IOR(GPE_MAGIC, 0x58, struct gpe_iqm_global_status)

/**
   This function is used to read back global TMU parameters.

   \param gpe_tmu_global_cfg Pointer to \ref gpe_tmu_global_cfg.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_TMU_GLOBAL_CFG_GET \
			_IOR(GPE_MAGIC, 0x59, struct gpe_tmu_global_cfg)


/**
   This function is used to read back global TMU status variables.

   \param gpe_tmu_global_status Pointer to \ref gpe_tmu_global_status.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_TMU_GLOBAL_STATUS_GET \
			_IOR(GPE_MAGIC, 0x5A, struct gpe_tmu_global_status)

/**
   Read the status variables of an ingress queue within the GPE.

   \param gpe_iqueue_status Pointer to \ref gpe_iqueue_status_get_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_INGRESS_QUEUE_STATUS_GET \
			_IOWR(GPE_MAGIC, 0x5B, union gpe_iqueue_status_get_u)

/**
   Set the GPE configuration for a given GEM Port Index and GEM Port ID.
   If the GEM Port ID is larger than ONU_GPE_MAX_GEM_PORT_ID - 1, an error code
   is returned.

   \param gpe_gem_port Pointer to \ref gpe_gem_port.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_VALUE_RANGE_ERR: if the GEM Port ID
				 is >= ONU_GPE_MAX_GEM_PORT_ID
   - GPE_STATUS_NOT_AVAILABLE: if the GEM Port ID is unknown
*/
#define FIO_GPE_GEM_PORT_SET _IOW(GPE_MAGIC, 0x5C, struct gpe_gem_port)

/**
   Download the COP microcode.

   \param cop_download_cfg Pointer to \ref cop_download_cfg.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_COP_DOWNLOAD _IOW(GPE_MAGIC, 0x5D, struct cop_download_cfg)

/**
   Write a command to the ICTRLC interface.

   \param ictrlc_write Pointer to \ref ictrlc_write.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_ICTRLC_WRITE _IOW(GPE_MAGIC, 0x5E, struct ictrlc_write)

/**
   This function is used to configure the exception handling on the LAN side of
   the device. Individual exceptions can be defined per LAN port and FID (VLAN).

   \param gpe_lan_exception_cfg Pointer to \ref gpe_lan_exception_cfg.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_LAN_EXCEPTION_CFG_SET \
			_IOW(GPE_TABLE_MAGIC, 0x47, char[16])

/**
   This function is used to read back the exception configuration related to
   the LAN side of the device.

   \param gpe_lan_exception_cfg Pointer to \ref gpe_lan_exception_cfg_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_LAN_EXCEPTION_CFG_GET \
			_IOWR(GPE_TABLE_MAGIC, 0x48, char[16])

/**
   This function is used to configure the exception handling on the ANI side of
   the device. Individual exceptions can be defined per GEM port ID.

   \param gpe_ani_exception_cfg Pointer to \ref gpe_ani_exception_cfg.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_ANI_EXCEPTION_CFG_SET \
			_IOW(GPE_TABLE_MAGIC, 0x45, struct gpe_ani_exception_cfg)

/**
   This function is used to read back the exception configuration.

   \param gpe_ani_exception_cfg Pointer to \ref gpe_ani_exception_cfg_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_ANI_EXCEPTION_CFG_GET \
			_IOWR(GPE_TABLE_MAGIC, 0x46, union gpe_ani_exception_cfg_u)

/**
   This function is used to configure the target queues for the exception
   handling. The configuration is shared by LAN and ANI exceptions.
   For each exception type, a dedicated egress queue can be assigned. Multiple
   exception types can as well share the same egress queue.

   \param gpe_exception_queue_cfg Pointer to \ref gpe_exception_queue_cfg.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_EXCEPTION_QUEUE_CFG_SET \
			_IOW(GPE_TABLE_MAGIC, 0x43, struct gpe_exception_queue_cfg)

/**
   This function is used to read back the exception queue configuration.

   \param gpe_exception_queue_cfg Pointer to \ref gpe_exception_queue_cfg_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_EXCEPTION_QUEUE_CFG_GET \
			_IOWR(GPE_TABLE_MAGIC, 0x44, union gpe_exception_queue_cfg_u)

/**
   This function is used to get a TR-181 set of counters related to the optical
   interface.

   \param gpe_tr181_counters_get Pointer to \ref gpe_tr181_counters_get_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_TR181_COUNTER_GET \
			_IOWR(GPE_MAGIC, 0x5F, union gpe_tr181_counters_get_u)

/**
   Read back the structural parameters of a TMU egress port

   \param gpe_eport Pointer to \ref gpe_port_index_get_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_NOT_AVAILABLE: if no table entry is free
   - GPE_STATUS_CONFIG_MISMATCH: if the entry is already occupied
*/
#define FIO_GPE_PORT_INDEX_GET \
			_IOWR(GPE_MAGIC, 0x60, union gpe_port_index_get_u)

/**
   Get GPE capability (maximum number of resources available)

   \param gpe_capability Pointer to \ref gpe_capability

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_CAPABILITY_GET \
			_IOR(GPE_MAGIC, 0x61, struct gpe_capability)

/**
   This function is used to configure the profiles for the exception
   handling. The configuration is shared by LAN and ANI exceptions.
   For each exception profile, exception types can be enabled independently
   for ingress and egress direction.

   \param gpe_exception_profile_cfg Pointer to \ref gpe_exception_profile_cfg.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_EXCEPTION_PROFILE_CFG_SET \
			_IOW(GPE_TABLE_MAGIC, 0x49, struct gpe_exception_profile_cfg)

/**
   This function is used to read back the exception profile configuration.

   \param gpe_exception_profile_cfg Pointer to \ref gpe_exception_profile_cfg.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_EXCEPTION_PROFILE_CFG_GET \
		       _IOWR(GPE_TABLE_MAGIC, 0x4A, union gpe_exception_profile_cfg_u)

/**
   This function is used to enable the specified egress port.

   \param gpe_epn Pointer to \ref gpe_epn.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_EGRESS_PORT_ENABLE \
			_IOW(GPE_MAGIC, 0x62, struct gpe_epn)

/**
   This function is used to disable the specified egress port.

   \param gpe_epn Pointer to \ref gpe_epn.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_EGRESS_PORT_DISABLE \
			_IOW(GPE_MAGIC, 0x63, struct gpe_epn)

/**
   Initialize the GPON Packet Engine (GPE) hardware.
   This function provides the initialization of all sub-modules that are part of
   the GPE. It also loads the SCE firmware into the local Packet Engine (PE)
   code memories and initializes the hardware accelerators
   (coprocessor modules, COP).
   This function doesn't run PEs after initialization and also doesn't
   initialize tables for debug purposes.

   \param gpe_init_data Pointer to \ref gpe_init_data.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - An error code in case of error.
*/
#define FIO_GPE_DEBUG_INIT _IOW(GPE_MAGIC, 0x64, struct gpe_init_data)

/**
   Read the bridge port based performance counters.

   \param gpe_bridge_port_counter Pointer to \ref gpe_bridge_port_counter_get_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_COUNTER_ERR: if one of the counters suffered from an overflow
                                 event
   - GPE_STATUS_NO_SUPPORT: if the bridge port index is invalid
*/
/* Not in v7.5.1 kernel — dead ioctl, will return ENOTTY at runtime */
#define FIO_GPE_BRIDGE_PORT_COUNTER_GET \
			_IOWR(0xFF, 0x02, union gpe_bridge_port_counter_get_u)

/**
   Write the bridge port based counter thresholds.

   \param gpe_cnt_bridge_port_threshold Pointer to \ref gpe_cnt_bridge_port_threshold.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_COUNTER_ERR: if one of the counters suffered from an overflow
			     event
   - GPE_STATUS_NO_SUPPORT: if the bridge port index is invalid
*/
/* Not in v7.5.1 kernel */
/* #define FIO_GPE_BRIDGE_PORT_COUNTER_THRESHOLD_SET \
			_IOW(GPE_MAGIC, 0x73, struct gpe_cnt_bridge_port_threshold) */

/**
   Read the bridge port based counter thresholds.

   \param gpe_bridge_port_counter_threshold Pointer to
	  \ref gpe_bridge_port_counter_threshold_get_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_COUNTER_ERR: if one of the counters suffered from an overflow
			     event
   - GPE_STATUS_NO_SUPPORT: if the bridge port index is invalid
*/
/* Not in v7.5.1 kernel */
/* #define FIO_GPE_BRIDGE_PORT_COUNTER_THRESHOLD_GET \
			_IOWR(GPE_MAGIC, 0x74, \
				union gpe_bridge_port_counter_threshold_get_u) */

/**
   Read the bridge port based counter threshold alarms.

   \param gpe_bridge_port_counter_threshold Pointer to
          \ref gpe_bridge_port_counter_threshold_get_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_NO_SUPPORT: if the bridge port index is invalid
*/
/* Not in v7.5.1 kernel */
/* #define FIO_GPE_BRIDGE_PORT_TCA_GET \
			_IOWR(GPE_MAGIC, 0x75, \
				union gpe_bridge_port_counter_threshold_get_u) */

/**
   Bridge port based counter reset. Calling this function clears all counters
   that are covered by \ref gpe_bridge_port_cnt_interval.

   \param gpe_bridge_port_cnt_interval Pointer to \ref gpe_bridge_port_cnt_interval.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_NO_SUPPORT: if the bridge port index is invalid
*/
/* Not in v7.5.1 kernel */
/* #define FIO_GPE_BRIDGE_PORT_COUNTER_RESET \
			_IOW(GPE_MAGIC, 0x76, struct gpe_bridge_port_cnt_interval) */

/*! @} */

/* v7.5.1 PSM (Power Save Mode) ioctls — replaced bridge port counter ioctls 0x73-0x7F.
   Stock omci_api_init calls psm_fsm_event_mask_set(0xFFFFFFFF) during event handler init.
   Confirmed via mod_onu.ko CLI table: "Long Form: psm_fsm_event_mask_set" (psmfems). */

/** Set PSM FSM event mask. Stock calls with 0xFFFFFFFF (all events enabled).
    v7.5.1 kernel cmd 0x78, _IOW(GPE_MAGIC, 0x78, uint32_t). */
#define FIO_GPE_PSM_FSM_EVENT_MASK_SET _IOW(GPE_MAGIC, 0x78, uint32_t)

/** Get PSM FSM event mask.
    v7.5.1 kernel cmd 0x79, _IOWR(GPE_MAGIC, 0x79, uint32_t). */
#define FIO_GPE_PSM_FSM_EVENT_MASK_GET _IOWR(GPE_MAGIC, 0x79, uint32_t)

/*! @} */

EXTERN_C_END
#ifdef __PACKED_DEFINED__
#  if !defined (__GNUC__) && !defined (__GNUG__)
#    pragma pack()
#  endif
#  undef __PACKED_DEFINED__
#  undef __PACKED__
#endif
#endif				/* _drv_onu_gpe_h_ */
