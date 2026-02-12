/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_managed_entity_h
#define _omci_managed_entity_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_MANAGED_ENTITY 'Managed Entity' Managed Entity

    The "Managed Entity" Managed Entity describes the details of each Managed
    Entity that is supported by the ONU. This Managed Entity is not included in
    MIB upload. One or more "Managed Entity" Managed Entities are related to
    the "OMCI" object Managed Entity.

    @{
*/

/** This structure holds the attributes of the "Managed Entity" Managed Entity.
*/
struct omci_me_managed_entity {
	/** Name

	    This attribute contains a 25 byte ASCII coded mnemonic tag for the
	    Managed Entity type. Strings shorter than 25 bytes are padded with
	    null characters.

	    This string is read-only by the OLT.
	*/
	uint8_t name[25];

	/** Attributes table

	    This table contains pointers to the attribute Managed Entities that
            describe each of this Managed Entity's attributes.
	    Note: The Managed Entity ID attribute is not included in the list,
	    since the type of this attribute is fixed.

	    This table is read-only by the OLT.
	*/
	uint16_t attr_table;

	/** Access

	    This attribute represents who creates this Managed Entity.
	    The following code points are defined:
	    - 1: Created by the ONU autonomously
	    - 2: Created by the OLT on request
	    - 3: Created by the ONU autonomously or by the OLT on request

	    This value is read-only by the OLT.
	*/
	uint8_t access;

	/** Alarms table

	    This attribute lists the alarm codes that are supported.

	    This table is read-only by the OLT.
	*/
	uint8_t alarm_table;

	/** AVCs table

	    This attribute lists the AVCs that are supported.

	    This table is read-only by the OLT.
	*/
	uint8_t avc_table;

	/** Actions

	    This attribute lists the action codes supported on this object,
	    formatted as a bit map. The action codes are the message types from
	    table 11-1/G.984.4.
	    The least significant bit represents action 0, and so on.

	    This value is read-only by the OLT.
	*/
	uint32_t actions;

	/** Instances table

	    This attribute is a list of pointers to all instances of this ME.

	    This table is read-only by the OLT.
	*/
	uint16_t inst_table;

	/** Support

	    This attribute represents support capability of this Managed Entity
            ONU's implementation. This attribute does not declare if the OMCI
	    OMCI implementation complies with the recommendations, but if it
	    complies with the OMCI declaration itself. The following code
	    points are defined:
	    - 1: Supported (supported as defined in this object)
	    - 2: Unsupported (OMCI returns error code if accessed)
	    - 3: Partially supported (some aspects of ME supported)
	    - 4: Ignored (OMCI supported, but underlying function is not)

	    This value is read-only by the OLT.
	*/
	uint8_t support;

} __PACKED__;

/** This enumerator holds the attribute numbers of the ME Managed Entity.
*/
enum {
	omci_me_managed_entity_name = 1,
	omci_me_managed_entity_attr_table = 2,
	omci_me_managed_entity_access = 3,
	omci_me_managed_entity_alarm_table = 4,
	omci_me_managed_entity_avc_table = 5,
	omci_me_managed_entity_actions = 6,
	omci_me_managed_entity_inst_table = 7,
	omci_me_managed_entity_support = 8
};

/** @} */

/** @} */

__END_DECLS

#endif
