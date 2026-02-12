/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_network_dial_plan_table_h
#define _omci_network_dial_plan_table_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_NETWORK_DIAL_PLAN_TABLE Network Dial Plan Table Managed Entity

    The network dial plan table ME is optional for ONUs providing VoIP service.
    This ME is used to provision dial plans from the OLT.

    Instances of this managed entity are created and deleted by the OLT.
    If a non-OMCI interface is used to manage SIP for VoIP, this ME is
    unnecessary.

    @{
*/

/** Maximum number of dial plans that can be stored in the dial plan table.*/
#define OMCI_NETWORK_DIAL_PLAN_TABLE_MAX_SIZE	100

/** Network Dial Plan Table Entry.
    See \ref omci_me_network_dial_plan_table::dial_plan_table */
struct omci_dial_plan_table {
	/** Dial plan id

	    The row number, a unique identifier of a dial plan within 
	    the dial plan table */
	uint8_t dial_plan_id;
	/** Action 

	    Remove (0) or add (1) this plan (set action). When a dial plan is
	    being removed, the dial plan token field is not used. */
	uint8_t action;
	/** Dial plan token

	     The definition of the dial plan itself. Unused trailing bytes
	     may be padded with nulls or ASCII spaces. */
	uint8_t dial_plan_token[28];
};

/** This structure holds the attributes of the Network Dial Plan Rable Managed
    Entity. */
struct omci_me_network_dial_plan_table {
	/** Dial plan number

	    This attribute indicates the current number of dial plans in the
	    dial plan table.

	    This attribute is readable only by the OLT.
	*/
	uint16_t dial_plan_number;

	/** Dial plan table max size

	    This attribute defines the maximum number of dial plans that can be
	    stored in the dial plan table.

	    This attribute is application dependent and read-only by the OLT.
	*/
	uint16_t dial_plan_tbl_max_size;


	/** Critical dial timeout

	    This attribute defines the critical dial timeout for digit map
	    processing, in milliseconds. The recommended default value
	    is 4000 ms.

	    This attribute is readable and writable by the OLT.
	*/
	uint16_t critical_dial_timeout;

	/** Partial dial timeout

	    This attribute defines the partial dial timeout for digit map
	    processing, in milliseconds. The recommended default value
	    is 16000 ms.

	    This attribute is readable and writable by the OLT.
	*/
	uint16_t partial_dial_timeout;

	/** Dial plan format

	    This attribute define the dial plan format standard that is
	    supported in the ONU for VoIP. Valid values include 
		0 Not defined 
		1 H.248 format with specific plan (table entries define the dialling plan)
		2 NCS format [b-PKT-SP-EC-MGCP] 
		3 Vendor specific format 

	    This attribute is readable and writable by the OLT.
	*/
	uint8_t dial_plan_format;

	/** Dial plan table

	    The table is the digit map that describes the dial plans used by the
	    VoIP service, along with fields to manage the table.

	    This attribute is readable and writable by the OLT.
	*/
	struct omci_dial_plan_table dial_plan_table;

} __PACKED__;

/** This enumerator holds the attribute numbers of the Network Dial Plan Table
    Managed Entity. */
enum {
	omci_me_network_dial_plan_table_dial_plan_number = 1,
	omci_me_network_dial_plan_table_dial_plan_tbl_max_size = 2,
	omci_me_network_dial_plan_table_critical_dial_timeout = 3,
	omci_me_network_dial_plan_table_partial_dial_timeout = 4,
	omci_me_network_dial_plan_table_dial_plan_format = 5,
	omci_me_network_dial_plan_table_dial_plan_table = 6
};

/** @} */

/** @} */

__END_DECLS

#endif
