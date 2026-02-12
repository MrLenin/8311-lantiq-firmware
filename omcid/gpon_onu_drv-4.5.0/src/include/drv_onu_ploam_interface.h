/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_onu_ploam_interface.h
   This header file holds the definitions used to handle PLOAM messages.
*/
#ifndef _drv_onu_ploam_interface_h
#define _drv_onu_ploam_interface_h

#include "drv_onu_std_defs.h"

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
/** \defgroup ONU_PLOAM Physical Layer Messaging Channel (PLOAM)

   The Physical Layer OAM (PLOAM) channel supports the PON TC layer management
   functions, including ONU activation, OMCC establishment, encryption
   configuration, key management, and alarm signalling. It is transported in
   the 13-byte PLOAM message field within the overhead section of the
   downstream GTC frame and Default Alloc-ID allocation of the upstream GTC
   burst.

   \see ITU-T Rec. G.984.3 (03/2008) - Prepublished version
   @{
*/
/** Size of PLOAM message (without CRC field!) */
#define PLOAM_MESSAGE_LEN                 12
/** \defgroup PLOAM_DN Downstream Messages
   The downstream messages are handled by the driver.

   It is possible to register for the \ref ONU_EVENT_PLOAM_DS event. In this case
   a user application can sniff the downstream messages using the event
   interface (\ref ONU_EVENT_API).

   The processing time of all downstream messages is within 750 us, which is
   the time required by the ONU to process the downstream message and prepare
   any corresponding upstream actions.
   @{
*/
/** Size of serial number field */
#define PLOAM_FIELD_SN_LEN                8
/** Size of password field */
#define PLOAM_FIELD_PASSWORD_LEN          10
/**
   To instruct the ONU which pre-assigned delay and the
   number of preamble bytes to use in the upstream direction.
   In addition, ONU optical power is defined. */
#define PLOAM_DN_UPSTREAM_OVERHEAD        0x01
#define PLOAM_DN_SERIAL_NUM_MASK          0x02
/**
   To link a free ONU-ID number with the serial number also
   provided in this message. */
#define PLOAM_DN_ASSIGN_ONU_ID            0x03
/**
   To indicate the value (expressed in number of upstream bits) that the
   specified ONU must fill in into its equalization delay register.
   Dedicated field indicates if this EqD is for the main or protection path. */
#define PLOAM_DN_RANGING_TIME             0x04
/**
   To instruct an ONU with this ONU-ID to stop sending upstream traffic and
   reset itself. It can also be a broadcast message. */
#define PLOAM_DN_DEACTIVE_ONU_ID          0x05
/**
   To disable/enable an ONU with this serial number. */
#define PLOAM_DN_DISABLE_SERIAL_NUM       0x06
#define PLOAM_DN_CONFIGURE_VP_VC          0x07
/**
   To indicate to ONUs which channels are encrypted or not. */
#define PLOAM_DN_ENCRYPTED_PORTID         0x08
/**
   To request the password from an ONU in order to verify it. The OLT has a
   local table of passwords of the connected ONUs. */
#define PLOAM_DN_REQUEST_PASSWORD         0x09
/**
   To instruct an ONU that the specified Allocation ID is assigned to it.*/
#define PLOAM_DN_ASSIGN_ALLOC_ID          0x0a
/**
   No message available when a PLOAM field is transmitted. */
#define PLOAM_DN_NO_MESSAGE               0x0b
/**
   The OLT forces all the ONUs which are in POPUP state and not in LOS/LOF
   state to go from POPUP state to Ranging state (O4) or commanding specific
   ONU to go directly to Operation state (O5). */
#define PLOAM_DN_POPUP                    0x0c
/**
   The OLT triggers the ONU to generate a new encryption key,
   and send it  upstream. */
#define PLOAM_DN_REQUEST_KEY              0x0d
/**
   This message links the internally processed OMCI channel at the ONU with a
   12-bit Port-ID. The Port-ID is appended to the GEM overhead and used as an
   addressing mechanism to route OMCI over GEM channel. */
#define PLOAM_DN_CONFIGURE_PORT_ID        0x0e
/**
   To indicate to the ONUs that the OLT is unable to send both GEM frames and
   OMCC frames. */
#define PLOAM_DN_PHY_EQUIPMENT_ERR        0x0f
/**
   The OLT triggers the ONU to either increase or decrease its transmitted
   power level. */
#define PLOAM_DN_CHANGE_POWER_LEVEL       0x10
/**
   To check the ONU-OLT connectivity in a survivable PON configuration, and to
   perform APS. */
#define PLOAM_DN_PST                      0x11
/**
   It defines the accumulation interval per ONU expressed in the number of
   downstream frames for the ONU counting the number of downstream bit errors.
*/
#define PLOAM_DN_BER_INTERVAL             0x12
/**
   The OLT indicates to the ONU when to begin using the new encryption key. */
#define PLOAM_DN_KEY_SWITCHING_TIME       0x13
/**
   To instruct the ONU the number of type 3 preamble bytes to use in the
   upstream direction.
*/
#define PLOAM_DN_EXTENDED_BURST_LEN       0x14
/**
   PON-ID message
*/
#define PLOAM_DN_PON_ID                   0x15
/*! @} */
/** \defgroup PLOAM_UP Upstream Messages
   The driver will create all upstream PLOAM messages.

   It is possible to register for the \ref ONU_EVENT_PLOAM_US event. In this case
   a user application can sniff the downstream messages using the event
   interface (\ref ONU_EVENT_API).

   @{
*/
/**
   It contains the serial number of an ONU. */
#define PLOAM_UP_SERIAL_NUMBER_ONU        0x01
/**
   To verify an ONU based on its password. */
#define PLOAM_UP_PASSWORD                 0x02
/**
   To inform the OLT that the ONU will power-off in a normal operation. This
   is to prevent the OLT from issuing unnecessary alarm reports. */
#define PLOAM_UP_DYING_GASP               0x03
/**
   Rate decoupling for PLOAM channel, power control opportunity for ONU. */
#define PLOAM_UP_NO_MESSAGE               0x04
/**
   It sends a fragment of the new
encryption key to the OLT. */
#define PLOAM_UP_ENCRYPTION_KEY           0x05
/**
   To indicate to the OLT that the ONU is unable to send both GEM frames
   and OMCC frames in the direction from GEM layer to TC layer. */
#define PLOAM_UP_PHY_EQUIPMENT_ERR        0x06
/**
   To check  the ONU-OLT connectivity in a survivable PON configuration, and to
   perform APS. */
#define PLOAM_UP_PST                      0x07
/**
   Contains the number of BIP detected errors counted during the BER interval.
 */
#define PLOAM_UP_REI                      0x08
/**
   This is used by the ONU to indicate the reception of downstream messages.
   */
#define PLOAM_UP_ACKNOWLEDGE              0x09
/*! @} */
/** \addtogroup PLOAM_DN
   @{
*/
/**
   Status of pre-Equalization mechanism:
   - 0: No pre-equalization delay,
   - 1: Use pre-equalization delay given below */
#define PLOAM_STATUS_PRE_EQAL_MASK              0x20
/**
   Status of SN_Mask mechanism:
   - 0: SN_Mask disabled
   - 1: SN_Mask enable

   \note As the SN_Mask message has been deprecated,
         the m bit shall be set to 0.
*/
#define PLOAM_STATUS_SN_MASK                    0x10
/**
   Max number of extra SN-transmissions sent in response to a single
   SN-request. For example, ss = 10b means an ONU will send 3
   SN-transmissions when responding to a SN-request.

   \note As multiple SN transmission method has been effectively deprecated,
         ss bits shall be set to 00.
*/
#define PLOAM_MAX_NUM_SN_RSP_MASK              0x0c
/**
ONU transmit power level mode - mask */
#define PLOAM_POWER_LEVEL_MODE_MASK            0x03
/** ONU transmit power level mode - normal */
#define PLOAM_POWER_LEVEL_MODE_NORMAL          0x00
/** ONU transmit power level mode - normal - 3dB */
#define PLOAM_POWER_LEVEL_MODE_NORMAL_3DB      0x01
/** ONU transmit power level mode - normal - 6dB */
#define PLOAM_POWER_LEVEL_MODE_NORMAL_6DB      0x02
/** ONU transmit power level mode - reserved */
#define PLOAM_POWER_LEVEL_MODE_NORMAL_RES      0x03
/** Upstream_Overhead message.
   \see 9.2.3.1 */
struct ploam_dn_upstream_overhead {
	/**
	Must be 0xFF broadcast */
	uint8_t onu_id;
	/**
	Must be 0x01 "Upstream_Overhead" */
	uint8_t msg_id;
	/**
	Number of guard bits */
	uint8_t num_guard_bits;
	/**
	Number of type 1 preamble bits */
	uint8_t num_t1_preamble_bits;
	/**
	Number of type 2 preamble bits */
	uint8_t num_t2_preamble_bits;
	/**
	Pattern of type 3 preamble bits */
	uint8_t t3_preamble_pattern;
	/**data to be programmed in delimiter byte 1 */
	uint8_t delimiter_byte1;
	/**
	Data to be programmed in delimiter byte 2 */
	uint8_t delimiter_byte2;
	/**
	Data to be programmed in delimiter byte 3 */
	uint8_t delimiter_byte3;
	/** Various Flags defined in
	- \ref PLOAM_STATUS_PRE_EQAL_MASK
	- \ref PLOAM_STATUS_SN_MASK
	- \ref PLOAM_STATUS_SN_MASK
	- \ref PLOAM_MAX_NUM_SN_RSP_MASK
	- \ref PLOAM_POWER_LEVEL_MODE_MASK */
	uint8_t flags;
	/**
	Pre-assigned equalization delay */
	uint8_t eql_delay[2];
};

/** Serial_Number_Mask message.
   \see 9.2.3.2
   \note The Serial_Number_Mask message has been deprecated */
struct ploam_dn_ser_num_mask {
	/**
	Must be 0xFF broadcast */
	uint8_t onu_id;
	/**
	Must be 0x02 "Serial_Number_Mask" */
	uint8_t msg_id;
	/**
	Number of valid bits, count started from LSB of byte 4 counting up
	to the MSB of byte 11 */
	uint8_t num_valid_bits;
	/**
	Serial number byte 1 ~ 8 */
	uint8_t serial_number[PLOAM_FIELD_SN_LEN];
	/**
	Reserved.*/
	uint8_t unspecified;
};

/** Assign_ONU-ID message.
   \see 9.2.3.3
   \note This message is used to assign an ONU-ID to a physical ONU.
   Later, Alloc-IDs are assigned to each T-CONT of the specific ONU
   according to its ONU-ID. */
struct ploam_dn_assign_onu_id {
	/**
	Must be 0xFF broadcast */
	uint8_t onu_id;
	/**
	Must be 0x03 "Assign_ONU-ID" */
	uint8_t msg_id;
	/**
	ONU-ID */
	uint8_t assign_onu_id;
	/**
	Serial number byte 1 ~ 8 */
	uint8_t serial_number[PLOAM_FIELD_SN_LEN];
	/**
	Reserved.*/
	uint8_t unspecified;
};

/** Ranging_Time message.
   \note The unit of the equalization delay parameter is bits.
   \note Both the main path EqD and the protection path EqD can be
         assigned to the ONU using this message.
   \see 9.2.3.4 */
struct ploam_dn_rng_time {
	/**
	Directed message to one ONU */
	uint8_t onu_id;
	/**
	Must be 0x04 "Ranging_Time" */
	uint8_t msg_id;
	/**
	Path specifier
	- 0 main path
	- 1 protection path */
	uint8_t eqd_path;
	/**
	Delay value */
	uint8_t delay[4];
	/**
	Reserved.*/
	uint8_t unspecified[5];
};

/** Deactivate_ONU-ID message.
   \see 9.2.3.5 */
struct ploam_dn_deact_onu_id {
	/**
	Directed message to one ONU or all ONUs */
	uint8_t onu_id;
	/**
	Must be 0x05 "Deactivate_ONU-ID" */
	uint8_t msg_id;
	/**
	Reserved.*/
	uint8_t unspecified[10];
};

/** The ONU with this serial number is denied upstream access. */
#define PLOAM_DSN_DISABLE_ONE            0xFF
/** All ONUs which were denied upstream access can participate
    in ranging process. The content of bytes 4-11 are irrelevant. */
#define PLOAM_DSN_ENABLE_ALL             0x0F
/** All ONUs are denied in upstream access.
    IOP: customer specific proposal and implementation,
    not yet part of the standard.
*/
#define PLOAM_DSN_DISABLE_ALL            0xF0
/** The ONU with this serial number can participate in the ranging process. */
#define PLOAM_DSN_ENABLE_ONE             0x00

/** Disable_Serial_ Number message
   \see 9.2.3.6 */
struct ploam_dn_dis_ser_num {
	/**
	Must be 0xFF broadcast */
	uint8_t onu_id;
	/**
	Must be 0x06 "Disable_Serial_Number" */
	uint8_t msg_id;
	/**
	Disable/Enable
	\ref PLOAM_DSN_DISABLE_ONE,
	\ref PLOAM_DSN_ENABLE_ALL,
	\ref PLOAM_DSN_ENABLE_ONE */
	uint8_t ctrl;
	/**
	Serial number byte 1 ~ 8 */
	uint8_t serial_number[PLOAM_FIELD_SN_LEN];
	/**
	Reserved.*/
	uint8_t unspecified;
};

/** Configure_VP/VC message
   \see 9.2.3.7
   \note The Configure_VP/VC message has been deprecated. */
struct ploam_dn_cfg_vp_vc {
	/**
	Directed message to one ONU */
	uint8_t onu_id;
	/**
	Must be 0x07 "Configure_VP/VC" */
	uint8_t msg_id;
	/**
	Enable/Disable
	- 1: activates this VP/VC;
	- 0: deactivates this VP/VC */
	uint8_t ctrl;
	/**
	ATM header byte1(MSB) ~ byte4(LSB) */
	uint8_t header[4];
	/**
	All the bits of MASK that are set to 1 define the corresponding bits
	in HEADER that must be used for termination or generation of cells
	at the ATM layer */
	uint8_t mask[4];
	/**
	Reserved.*/
	uint8_t unspecified;
};

/** Encrypted_VPI/Port-ID control field - disable encryption */
#define PLOAM_ENC_CTRL_DISABLE   0x00
/** Encrypted_VPI/Port-ID control field - enable encryption */
#define PLOAM_ENC_CTRL_ENABLE    0x01

/** Encrypted Port-ID message
   \see 9.2.3.8
   \note This message is not required to complete ranging, or to make
         any connection active. It can be issued at any time in the life
         of a connection. Changing the encryption mode of an active
         connection will likely cause temporary service interruption. */

struct ploam_dn_encr_port_id {
	/**
	Directed message to one ONU */
	uint8_t onu_id;
	/**
	Must be 0x08 "Encrypted_Port-ID" */
	uint8_t msg_id;
	/**
	Control/Type field
	\ref PLOAM_ENC_CTRL_DISABLE,
	\ref PLOAM_ENC_CTRL_ENABLE ) */
	uint8_t ctrl;
	/**
	[0] abcdefgh = Port-ID[11-4]
	[1] ijkl0000 = Port-ID[3-0] */
	uint8_t port_id[2];
	/**
	Reserved.*/
	uint8_t unspecified[7];
};

/** \note PLOAM_DN_Encrypted_PortId_t didn't match 984.3 rec! Was: */
/* typedef struct {
   uint8_t onu_id;
   uint8_t msg_id;
   uint8_t ctrl;
   uint8_t port_id[2];
   uint8_t vpi[2];
   uint8_t unspecified;
} PLOAM_DN_Encrypted_PortID_t;
*/

/** Request Password message.
   \see 9.2.3.9 */
struct ploam_dn_req_pwd {
	/**
	Directed message to one ONU */
	uint8_t onu_id;
	/**
	Must be 0x09 "Request_Password" */
	uint8_t msg_id;
	/**
	Reserved.*/
	uint8_t unspecified[10];
};

/** Assign Alloc-ID.
   \see 9.2.3.10 */
struct ploam_dn_assign_alloc_id {
	/**
	Directed message to one ONU.*/
	uint8_t onu_id;
	/**
	Must be 0x0a "Assign_Alloc-ID".*/
	uint8_t msg_id;
	/**
	Alloc-ID.*/
	uint8_t alloc_id[2];
	/**
	Indicates for what payload type this Alloc-ID will be used:
	  - 0: ATM payload;
	  - 1: GEN payload;
	  - 2: DBA payload;
	  - 3-255: Reserved.*/
	uint8_t type;
	/**
	Reserved.*/
	uint8_t unspecified[7];
};

/** No Message.
   \see 9.2.3.11 */
struct ploam_dn_no_msg {
	/**
	Must be 0xFF broadcast */
	uint8_t onu_id;
	/**
	Must be 0x0b "no message" */
	uint8_t msg_id;
	/**
	Reserved.*/
	uint8_t unspecified[10];
};

/** POPUP message.
   \see 9.2.3.12
   \note All ONUs in POPUP-state that receive a Broadcast POPUP message return
         to Ranging-state.  An ONU that receives a specific POPUP Message (with
         its ONU-ID) moves directly to Operation-state while keeping its
         equalization delay, ONU-ID and Alloc-IDs */
struct ploam_dn_popup {
	/**
	Directed message to one ONU or all ONUs */
	uint8_t onu_id;
	/**
	Must be 0x0c "POPUP" */
	uint8_t msg_id;
	/**
	Reserved.*/
	uint8_t unspecified[10];
};

/** Request Key message.
   \see 9.2.3.13 */
struct ploam_dn_request_key {
	/**
	Directed message to one ONU */
	uint8_t onu_id;
	/**
	Must be 0x0d "Request_Key" */
	uint8_t msg_id;
	/**
	Reserved.*/
	uint8_t unspecified[10];
};

/** Configure Port-ID message control - mask */
#define PLOAM_CFG_PORT_ID_CTRL_MASK      0x01
/** Configure Port-ID message control - disable Port-ID */
#define PLOAM_CFG_PORT_ID_CTRL_DISABLE   0x00
/** Configure Port-ID message control - enable Port-ID */
#define PLOAM_CFG_PORT_ID_CTRL_ENABLE    0x01

/** Configure Port-ID message.
   \see 9.2.3.14
   \note A maximum of one OMCI connection can ever be configured to any ONU.
   If the OLT attempts to configure a second OMCI connection, the ONU should
   implicitly assume that the first connection is deactivated. */
struct ploam_dn_cfg_port_id {
	/**
	Directed message to one ONU */
	uint8_t onu_id;
	/**
	Must be 0x0e "Configure Port-ID" */
	uint8_t msg_id;
	/**
	Disable/Enable
	- bit0 - 1: activates this Port-ID
	- bit0 - 0: deactivates this Port-ID */
	uint8_t ctrl;
	/**
	Port-ID */
	uint8_t port_id[2];
	/**
	Reserved.*/
	uint8_t unspecified[7];
};

/** Physical Equipment Error message.
   \see 9.2.3.15 */
struct ploam_dn_phy_equipment_err {
	/**
	Must be 0xFF broadcast */
	uint8_t onu_id;
	/**
	Must be 0x0f "Physical_equipment_error" */
	uint8_t msg_id;
	/**
	Reserved.*/
	uint8_t unspecified[10];
};

/** Change Power Level message control - mask */
#define PLOAM_CPL_MASK        0x03
/** Change Power Level message control - Increase ONU TX power */
#define PLOAM_CPL_INCREASE    0x02
/** Change Power Level message control - Decrease ONU TX power */
#define PLOAM_CPL_DECREASE    0x01

/** Change Power Level message.
   \see 9.2.3.16 */
struct ploam_dn_change_pwr_lvl {
	/**
	Directed message to one ONU or all ONUs */
	uint8_t onu_id;
	/**
	Must be 0x10 "Change Power Level" */
	uint8_t msg_id;
	/**
	Control Field \ref PLOAM_CPL_MASK, \ref PLOAM_CPL_INCREASE,
		      \ref PLOAM_CPL_DECREASE) */
	uint8_t ctrl;
	/**
	Reserved.*/
	uint8_t unspecified[9];
};

/** PST message.
   \see 9.2.3.17 */
struct ploam_dn_pst {
	/**
	Directed message to one ONU or all ONUs */
	uint8_t onu_id;
	/**
	Must be 0x11 "PST" */
	uint8_t msg_id;
	/**
	0 or 1 */
	uint8_t line_num;
	/**
	K1 byte as specified in ITU-T Rec. G.841 */
	uint8_t k1_byte;
	/**
	K2 byte as specified in ITU-T Rec. G.841 */
	uint8_t k2_byte;
	/**
	Reserved.*/
	uint8_t unspecified[7];
};

/** BER Interval message.
   \see 9.2.3.18 */
struct ploam_dn_ber_interval {
	/**
	Directed message to one ONU or all ONUs */
	uint8_t onu_id;
	/**
	Must be 0x12 "BER Interval" */
	uint8_t msg_id;
	/**
	MSB - LSB, in units of downstream frames */
	uint8_t interval[4];
	/**
	Reserved.*/
	uint8_t unspecified[6];
};

/** Key Switching Time message.
   \see 9.2.3.19 */
struct ploam_dn_key_switching_time {
	/**
	Directed message to one ONU or all ONUs */
	uint8_t onu_id;
	/**
	Must be 0x13 "Key_Switching_Time" */
	uint8_t msg_id;
	/**
	MSB - LSB, 30bits of the superframe counter of the first frame to use
	the new key */
	uint8_t frame_counter[4];
	/**
	Reserved.*/
	uint8_t unspecified[6];
};

/** Extended Burst Length message.
   \see 9.2.3.20
   \note The use of Extended_Burst_Length message by OLT is optional. The
   support of this message by ONU is mandatory.
   \note Like it is the case with the Upstream_Overhead message, the
   parameters of the Extended_Burst_Length message, having been received and
   processed by the ONU once during its activation, continue to mandate the
   ONU's behaviour throughput the activity cycle, i.e., until the ONU is
   deactivated by the OLT or moves itself into the Standby state (O2).
   Type 1, 2, and 3 preambles are defined in the message definition and
   notes of the Upstream_Overhead message (see Section 9.2.3.1). When the
   Extended_Burst_Length message is not used by the OLT, the length of the
   Type 3 preamble is determined by subtracting the lengths of the Guard
   bits, Types 1 & 2 preambles, and Delimiter from the recommended burst
   mode overhead time specified in G.984.2 Appendix I. If the
   Extended_Burst_Length message is used, the values specified in
   Octets 3 and 4 of this message supersede the length of the Type 3
   preamble implied by the "Upstream_Overhead" message. The maximum length
   of the entire burst mode overhead is 128 bytes. Note that the length of
   the Type 3 preamble is an integer number of bytes. It is the responsibility
   of the OLT to ensure that the total length of the burst mode overhead
   (Guard bits + Type 1 + Type 2 + Type 3 + Delimiter) is also an integer
   number of bytes. */
struct ploam_dn_extended_burst_length {
	/**
	Must be 0xFF broadcast */
	uint8_t onu_id;
	/**
	Must be 0x14 "Extended Burst Length" */
	uint8_t msg_id;
	/**
	Number of Type 3 preamble bytes to be used while the ONU remains in the
	"pre-ranged" states: Serial_Number State (O3) and Ranging State (O4).
	Each byte of the Type 3 preamble contains the pattern specified in
	Octet 6 of the "Upstream_Overhead" message. */
	uint8_t num_t3_pb_preranged;
	/**
	Number of Type 3 preamble bytes to be used after the ONU enters the
	Operation State (O5). Each byte of the Type 3 preamble contains the
	pattern specified in Octet 6 of the "Upstream_Overhead" message. */
	uint8_t num_t3_pb_ranged;
	/**
	Reserved for future study. */
	uint8_t unspecified[8];
};

/** Structure contains information received through the latest PON ID PLOAMd
    message.
*/
struct ploam_dn_pon_id {
	/**
	Must be 0xFF broadcast */
	uint8_t onu_id;
	/**
	Must be 0x15 "PON-ID" */
	uint8_t msg_id;
	/** reach extender, ODN class */
	uint8_t type;
	/** PON identifier string */
	uint8_t id[7];
	/** OLT transmit optical power. */
	uint16_t olt_tx_power;
};

/** PLOAM message. */
struct ploam_msg {
	/**
	ONU-ID */
	uint8_t onu_id;
	/**
	Message ID */
	uint8_t msg_id;
	/**
	Payload data */
	uint8_t content[10];
};

/** Union to access all downstream message types */
union ploam_dn_msg {
	/** PLOAM downstream message */
	struct ploam_msg message;
	/** PLOAM downstream message: Upstream overhead */
	struct ploam_dn_upstream_overhead up_overhead;
	/** PLOAM downstream message: Serial number mask */
	struct ploam_dn_ser_num_mask sn;
	/** PLOAM downstream message: Assign ONU ID */
	struct ploam_dn_assign_onu_id assign_onu_id;
	/** PLOAM downstream message: Ranging time */
	struct ploam_dn_rng_time ranging_time;
	/** PLOAM downstream message: Deactivate ONU ID */
	struct ploam_dn_deact_onu_id deactivate_onu;
	/** PLOAM downstream message: Serial number disable */
	struct ploam_dn_dis_ser_num disable_sn;
	/** PLOAM downstream message: Configure VP/VC */
	struct ploam_dn_cfg_vp_vc config_vp_vc;
	/** PLOAM downstream message: Encrypted port ID */
	struct ploam_dn_encr_port_id enc_portid;
	/** PLOAM downstream message: Request password */
	struct ploam_dn_req_pwd req_password;
	/** PLOAM downstream message: Assign allocation ID */
	struct ploam_dn_assign_alloc_id assign_alloc_id;
	/** PLOAM downstream message: No message */
	struct ploam_dn_no_msg no;
	/** PLOAM downstream message: Popup */
	struct ploam_dn_popup popup;
	/** PLOAM downstream message: Request key */
	struct ploam_dn_request_key req_key;
	/** PLOAM downstream message: Configure GEM port ID */
	struct ploam_dn_cfg_port_id config_port_id;
	/** PLOAM downstream message: Physical equipment error */
	struct ploam_dn_phy_equipment_err pee;
	/** PLOAM downstream message: Change transmit power level */
	struct ploam_dn_change_pwr_lvl chg_pow_lvl;
	/** PLOAM downstream message: PST */
	struct ploam_dn_pst pst;
	/** PLOAM downstream message: BER interval */
	struct ploam_dn_ber_interval ber_int;
	/** PLOAM downstream message: Key switching time */
	struct ploam_dn_key_switching_time key_switch_time;
	/** PLOAM downstream message: Extended burst length */
	struct ploam_dn_extended_burst_length extended_burst_len;
	/** PLOAM downstream message: PON-ID */
	struct ploam_dn_pon_id pon_id;
	/** PLOAM downstream message data */
	uint32_t data[3];
};

/*! @} */

/** \addtogroup PLOAM_UP
   @{
*/

/** Serial Number ONU message.
   \see 9.2.4.1
   \note The code set for the Vendor_ID is specified in ANSI T1.220.
         The 4 characters are mapped in the 4-byte field by taking each
         ASCII/ANSI character code and concatenating them.
         Example: Vendor_ID = ABCD -> VID1 = 0x41, VID2 = 0x42,
         VID3 = 0x43, VID4 = 0x44.
   \note Be mindful that the coding of the power level modes in the
         Serial_Number_ONU message, where 2 is highest and 0 is lowest,
         is opposite to that in the Upstream_Overhead message. */
struct ploam_up_ser_num_onu {
	/**
	Must be 0xFF, no ONU-ID was assigned yet.*/
	uint8_t onu_id;
	/**
	Must be 0x01 "Serial_Number_ONU".*/
	uint8_t msg_id;
	/**
	Vendor_ID, byte 1 to byte 4.*/
	uint8_t vendor_id[4];
	/**
	Vendor-specific serial number, byte 1 to byte 4. */
	uint8_t vendor_sn[4];
	/**
	The Random delay (MSB/LSB) (In 32 byte units) used by the ONU when
	sending this message. The LSB bits should be coded as follows, - bit
	0x08, this bit shall not be evaluated by the OLT - bit 0x04,
	GEM transport is supported by this ONU - bits 0x03, ONU TX Power Level
	Mode used by the ONU
	- 00: Low Power
	- 01: Medium Power
	- 10: High Power
	- 11: Reserved */
	uint8_t random_delay[2];
};

/** Password message.
   \see 9.2.4.2 */
struct ploam_up_password {
	/**
	Indicates the ONU sourcing this message.*/
	uint8_t onu_id;
	/**
	Must be 0x02 "Password".*/
	uint8_t msg_id;
	/**
	Password byte 1 to password byte 10.*/
	uint8_t data[PLOAM_FIELD_PASSWORD_LEN];
};

/** Dying Gasp message.
   \see 9.2.4.3 */
struct ploam_up_dying_gasp {
	/**
	Indicates the ONU sourcing this message.*/
	uint8_t onu_id;
	/**
	Must be 0x03 "Dying_Gasp".*/
	uint8_t msg_id;
	/**
	Reserved.*/
	uint8_t unspecified[10];
};

/** No message.
   \see 9.2.4.4
   \note Data ONU places here can be used as a fixed known pattern for
         the measurement and control of its transmitter. ONU must form
         the data so that when it is scrambled, the desired pattern results.
         In addition, care should be taken not to produce more than 72
         consecutive identical digits, or the OLT receiver may go into LOS.*/
struct ploam_up_no_msg {
	/**
	Indicates the ONU sourcing this message.*/
	uint8_t onu_id;
	/**
	Must be 0x04 "no message".*/
	uint8_t msg_id;
	/**
	Reserved.*/
	uint8_t unspecified[10];
};

/**  Encryption Key message.
   \see 9.2.4.5
   \note The first fragment of the key (bytes 0-7) will have Frag_Index = 0,
         the second (bytes 8-15) will have Frag_Index = 1, and so on, for
         as many fragments are required to carry the key.  Currently, only
         two fragments are required for AES-128. */
struct ploam_up_encr_key {
	/**
	Indicates the ONU sourcing this message.*/
	uint8_t onu_id;
	/**
	Must be 0x05 "Encryption_Key".*/
	uint8_t msg_id;
	/**
	Indicating which ONU key this mess carries.*/
	uint8_t key_index;
	/**
	Indicating which part of the key this message carries.*/
	uint8_t frag_index;
	/**
	Byte 0 to byte 7 of fragment (Frag_Index) of Key (Key_Index).*/
	uint8_t key[8];
};

/** Physical Equipment Error message.
   \see 9.2.4.6 */
struct ploam_up_phy_equipment_err {
	/**
	Indicates the ONU sourcing this message.*/
	uint8_t onu_id;
	/**
	Must be 0x06 "Physical_equipment_error".*/
	uint8_t msg_id;
	/**
	Reserved.*/
	uint8_t unspecified[10];
};

/** PST message.
   \see 9.2.4.7 */
struct ploam_up_pst {
	/**
	Indicates the ONU sourcing this message.*/
	uint8_t onu_id;
	/**
	Must be 0x07 "PST".*/
	uint8_t msg_id;
	/**
	0 or 1 */
	uint8_t line_num;
	/**
	K1 byte as specified in ITU-T G.841.*/
	uint8_t k1_byte;
	/**
	K2 byte as specified in ITU-T G.841.*/
	uint8_t k2_byte;
	/**
	Reserved.*/
	uint8_t unspecified[7];
};

/** REI message.
   \see 9.2.4.8 */
struct ploam_up_rei {
	/**
	Indicates the ONU sourcing this message */
	uint8_t onu_id;
	/**
	Must be 0x08 "REI" */
	uint8_t msg_id;
	/**
	MSB - LSB REI counter */
	uint8_t err_count[4];
	/**
	bit3 ~ 0: Sequence number - Each time an REI message is sent,
	the seq_num is incremented by 1.*/
	uint8_t seq_num;
	/**
	Reserved.*/
	uint8_t unspecified[5];
};

/** Acknowledge message.
   \see 9.2.4. */
struct ploam_up_ack {
	/**
	Indicates the ONU sourcing this message.*/
	uint8_t onu_id;
	/**
	Must be 0x09 "Acknowledge".*/
	uint8_t msg_id;
	/**
	Message identification of downstream message.*/
	uint8_t dm_id;
	/**
	byte 1 ~ 9 of downstream message.*/
	uint8_t dm_byte[9];
};

/** Union to access all upstream message types */
union ploam_up_msg {
   /** Arbitrary PLOAM message. */
	struct ploam_msg message;
	/** PLOAM "Serial number" message definition. */
	struct ploam_up_ser_num_onu sn;
	/** PLOAM "Password" message definition. */
	struct ploam_up_password password;
	/** PLOAM "Dying Gasp" message definition. */
	struct ploam_up_dying_gasp dying_gasp;
	/** PLOAM "No Message" message definition. */
	struct ploam_up_no_msg no;
	/** Downstream encryption key. */
	struct ploam_up_encr_key encrypt_key;
	/** PLOAM "Physical Equipment Error" message definition. */
	struct ploam_up_phy_equipment_err pee;
	/** PLOAM "PON Section Trace" message definition. */
	struct ploam_up_pst pst;
	/** PLOAM "Remote error Indication" message definition. */
	struct ploam_up_rei rei;
	/** PLOAM "Acknowledge" message definition. */
	struct ploam_up_ack ack;
	/** PLOAM data. */
	uint32_t data[3];
};

/*! @} */

/** \addtogroup ONU_PLOAM_FSM_INTERFACE PLOAM Final State Machine Interface

   The final state machine is triggered by downstream PLOAM messages
   and system events. It performs the state transitions O0 - O7.
   @{
*/

/**
   PLOAM States
   \see 10.2.2 ONU State Specification
*/
enum ploam_state {
	/** Power Up.
	*/
	PLOAM_STATE_O0 = 0,
	/** Initial state.
	    The ONU powers up in this state. LOS/LOF is asserted. Once
	    downstream traffic is received, LOS and LOF are cleared, the ONU
	    moves to the Standby state (O2). */
	PLOAM_STATE_O1 = 1,
	/** Standby state.
	    Downstream traffic is received by the ONU. The ONU waits for global
	    network parameters.  Once the Upstream_Overhead message is
	    received, the ONU configures these parameters (e.g., delimiter
	    value, power level mode, and pre-assigned delay) and moves to the
	    Serial Number state (O3). */
	PLOAM_STATE_O2 = 2,
	/** Serial Number state.
	    By responding to the Serial Number requests sent out by the OLT,
	    the ONU makes itself known to the OLT and allows the OLT to
	    discover the ONU's Serial Number.  Once the ONU has responded to a
	    Serial Number request, it waits for the unique ONU-ID assignment
	    from the OLT. The ONU-ID is assigned using the Assign_ONU-ID
	    message.  Once assigned, the ONU moves to the Ranging state (O4).
	    The OLT may, at its discretion, use the Extended_Burst_Length
	    message to communicate the extended overhead parameters to all the
	    ONUs on the PON.
	    If the ONU in State O3 receives the Extended_Burst_Length message
	    prior to receiving any Serial Number requests, it configures the
	    Type 3 Preamble lengths according to the received values. */
	PLOAM_STATE_O3 = 3,
	/** Ranging state.
	    The upstream transmission from the different ONUs must be
	    synchronized with the upstream GTC frame boundaries. In order make
	    the ONUs appear to be at an equal distance from the OLT, an
	    Equalization Delay per ONU is required.
	    This Equalization Delay is measured during this ranging state. Once
	    the ONU receives the Ranging_Time message, it moves to the
	    Operation state (O5). */
	PLOAM_STATE_O4 = 4,
	/** Operation state.
	    Once in this state the ONU can send upstream data and PLOAM
	    messages as directed by the OLT. Additional connections can be
	    established with the ONU as required while in this state. Once the
	    network is ranged, and all the ONUs are working with their correct
	    Equalization Delay, all upstream bursts will be synchronized
	    together between all the ONUs. The upstream transmissions will
	    arrive separately, each one in its correct location within the
	    upstream GTC frame. */
	PLOAM_STATE_O5 = 5,
	/** POPUP state.
	    The ONU enters this state from the Operation state (O5) following
	    the detection of LOS or LOF alarms. When entering the POPUP state
	    (O6), the ONU immediately stops upstream transmission. As a result,
	    the OLT will detect an LOS alarm for that ONU.  In the case of a
	    break in the fibre ODN, there will be multiple ONUs that enter
	    POPUP State. Based on the network survivability scheme, one of the
	    following options will be implemented:
	    If protection switching has been implemented, OLT can switch all
	    the ONUs to the protection fibres. In this case all the ONUs have
	    to be re-ranged.
	    To accomplish this goal, the OLT sends a Broadcast POPUP message to
	    the ONUs instructing them to move to the Ranging state (O4).
	    If there is no protection switching, or in case the ONU has
	    internal protection capabilities, the OLT can send a Directed POPUP
	    message to the ONU instructing it to move to the Operation state
	    (O5). Once the ONU is in the Operation state (O5), the OLT can test
	    the ONU before returning it to full service. In particular, an
	    encryption key switch event may have been scheduled while in the
	    POPUP (O6) state. To ensure graceful recovery in such a situation,
	    the OLT should restart the key exchange and switch-over procedure
	    with the ONU.
	    If the ONU does not recover from the of LOS or LOF alarms, it will
	    not receive the POPUP message (Broadcast or Directed) and will move
	    to the Initial state (O1), following time-out (TO2). */
	PLOAM_STATE_O6 = 6,
	/** Emergency Stop state.
	    An ONU that receives a Disable_Serial_Number message with the
	    "Disable" option moves to the Emergency Stop state (O7) and shuts
	    its laser off.
	    During Emergency Stop, the ONU is prohibited from sending data in
	    the upstream direction. If the ONU fails to move to Emergency Stop
	    state, that is, after the Disable_Serial_Number message has been
	    sent three times, the OLT continues to receive the ONU
	    transmissions in the provided upstream bandwidth allocations, a
	    DFi alarm is asserted in the OLT.  When the deactivated ONU's
	    malfunction is fixed, the OLT may activate the ONU in order to
	    bring it back to working condition. The activation is achieved by
	    sending a Disable_Serial_Number message with the "Enable" option
	    to the ONU. As a result, the ONU returns to Standby state (O2).
	    All parameters (including Serial Number and ONU-ID) are
	    reexamined. */
	PLOAM_STATE_O7 = 7
};

/*! @} */

/** PLOAM access */
struct ploam_message {
	/** PLOAM data.*/
	uint8_t data[12];
} __PACKED__;

/** Retrieve the PLOAM FSM state.*/
struct ploam_state_data_get {
	/** Current FSM state.*/
	enum ploam_state curr_state;
	/** Previous FSM state.*/
	enum ploam_state previous_state;
	/** Elapsed time (milliseconds).*/
	uint32_t elapsed_msec;
} __PACKED__;

/** Modify the PLOAM FSM state.*/
struct ploam_state_data_set {
	/** New FSM state.*/
	enum ploam_state state;
} __PACKED__;

/** magic number
*/
#define PLOAM_MAGIC 6

/**
   Write downstream PLOAM message, for OLT simulation.

   \remarks Not Implemented

   \param ploam_message Pointer to \ref ploam_message.

*/
#define FIO_PLOAM_DS_INSERT   _IOW(PLOAM_MAGIC,  0, struct ploam_message)

/**
   Read downstream PLOAM message, for OLT monitoring.

   \remarks Not Implemented

   \param ploam_message Pointer to \ref ploam_message.

*/
#define FIO_PLOAM_DS_EXTRACT   _IOR(PLOAM_MAGIC,  1, struct ploam_message)

/**
   Write upstream PLOAM message, for ONU simulation.

   \remarks Not Implemented

   \param ploam_message Pointer to \ref ploam_message.

*/
#define FIO_PLOAM_US_INSERT   _IOW(PLOAM_MAGIC,  2, struct ploam_message)

/**
   Read upstream PLOAM message, for ONU monitoring.

   \remarks Not Implemented

   \param ploam_message Pointer to \ref ploam_message.

*/
#define FIO_PLOAM_US_EXTRACT   _IOR(PLOAM_MAGIC,  3, struct ploam_message)

/**
   Retrieve the state of the PLOAM state machine.

   \param ploam_state_data_get Pointer to \ref ploam_state_data_get.

*/
#define FIO_PLOAM_STATE_GET   _IOR(PLOAM_MAGIC,  4, struct ploam_state_data_get)

/**
   Force the PLOAM state machine to the specified state.

   \param ploam_state_data_set Pointer to \ref ploam_state_data_set.

*/
#define FIO_PLOAM_STATE_SET   _IOW(PLOAM_MAGIC,  5, struct ploam_state_data_set)

/**
   Initialize the PLOAM state machine handling.

*/
#define FIO_PLOAM_INIT _IO(PLOAM_MAGIC,  6)

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
#endif
