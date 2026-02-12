/******************************************************************************

                              Copyright (c) 2012
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_enhanced_security_control.h

   Enhanced Security Control ME (class 332).
   Backported from gpon_omci_onu-8.6.3 to v4.5.0 framework.

   Stub implementation: table management and state machine are functional,
   but no hardware crypto driver is available on the Falcon SoC, so
   authentication cannot complete. ONU auth status remains "indeterminate" (0).
*/
#ifndef _omci_enhanced_security_control_h
#define _omci_enhanced_security_control_h

#include "omci_interface_types.h"

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_ENHANCED_SECURITY_CONTROL Enhanced Security Control ME

   G.988 Section 9.13.11 — Enhanced Security Control (class 332).
   Symmetric-key-based three-step OLT/ONU authentication.

   @{
*/

/** Storage for OLT crypto capabilities */
struct olt_crypto_caps {
	/** Cryptographic capabilities bitmap (16 bytes) */
	uint8_t data[16];
};

/** OLT random challenge table entry */
struct olt_random_chl_table_entry {
	/** The table row number, starting at 1 */
	uint8_t row_number;
	/** Contents of the entry (16 bytes) */
	uint8_t content[16];
};

/** ONU random challenge table entry */
struct onu_random_chl_table_entry {
	/** ONU random challenge value (16 bytes) */
	uint8_t content[16];
};

/** ONU authentication result table entry */
struct onu_auth_result_table_entry {
	/** ONU authentication result data (16 bytes) */
	uint8_t content[16];
};

/** OLT authentication result table entry */
struct olt_auth_result_table_entry {
	/** The table row number, starting at 1 */
	uint8_t row_number;
	/** OLT authentication result data (16 bytes) */
	uint8_t content[16];
};

#define BC_ROW_SET 0     /* 00 - Set the specified row. */
#define BC_ROW_CLEAR 1   /* 01 - Clear the specified row. */
#define BC_TABLE_CLEAR 2 /* 10 - Clear the entire table. */
#define BC_RESERVED 3    /* 11 - Reserved. */

/** Broadcast key table entry */
struct broadcast_key_table_entry {
	/** Row control (1 byte) */
	uint8_t row_control;
	/** Row identifier (1 byte) */
	uint8_t row_identifier;
	/** Key fragment (16 bytes) */
	uint8_t key_fragment[16];
} __PACKED__;

/** Enhanced Security Control ME attributes */
struct omci_me_enh_sec_ctrl {
	/** 1. OLT cryptographic capabilities (W, 16 bytes) */
	struct olt_crypto_caps olt_crypto_caps;
	/** 2. OLT random challenge table (R/W, 17*N bytes) */
	struct olt_random_chl_table_entry olt_random_chl_table;
	/** 3. OLT challenge status (R/W, 1 byte) */
	uint8_t olt_chl_status;
	/** 4. ONU selected crypto capabilities (R, 1 byte) */
	uint8_t onu_selected_crypto_caps;
	/** 5. ONU random challenge table (R, 16*P bytes) */
	struct onu_random_chl_table_entry onu_random_chl_table;
	/** 6. ONU authentication result table (R, 16*Q bytes) */
	struct onu_auth_result_table_entry onu_auth_result_table;
	/** 7. OLT authentication result table (W, 17*R bytes) */
	struct olt_auth_result_table_entry olt_auth_result_table;
	/** 8. OLT result status (R/W, 1 byte) */
	uint8_t olt_result_status;
	/** 9. ONU authentication status (R, 1 byte)
	    0=Indeterminate, 3=Success, 4=Failure */
	uint8_t onu_auth_status;
	/** 10. Master session key name (R, 16 bytes) */
	uint8_t master_session_key_name[16];
	/** 11. Broadcast key table (R/W, optional, 18*N bytes) */
	struct broadcast_key_table_entry broadcast_key_table;
	/** 12. Effective key length (R, optional, 2 bytes) */
	uint16_t effective_key_length;
} __PACKED__;

/** Attribute numbers */
enum omci_attr_num_enhanced_security_control {
	omci_me_enh_sec_ctrl_olt_crypto_caps = 1,
	omci_me_enh_sec_ctrl_olt_random_chl_table = 2,
	omci_me_enh_sec_ctrl_olt_chl_status = 3,
	omci_me_enh_sec_ctrl_onu_selected_crypto_caps = 4,
	omci_me_enh_sec_ctrl_onu_random_chl_table = 5,
	omci_me_enh_sec_ctrl_onu_auth_result_table = 6,
	omci_me_enh_sec_ctrl_olt_auth_result_table = 7,
	omci_me_enh_sec_ctrl_olt_result_status = 8,
	omci_me_enh_sec_ctrl_onu_auth_status = 9,
	omci_me_enh_sec_ctrl_master_session_key_name = 10,
	omci_me_enh_sec_ctrl_broadcast_key_table = 11,
	omci_me_enh_sec_ctrl_effective_key_length = 12,
};

/** @} */

/** @} */

__END_DECLS

#endif
