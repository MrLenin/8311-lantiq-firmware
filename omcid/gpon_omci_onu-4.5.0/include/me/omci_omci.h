/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_omci_h
#define _omci_omci_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_OMCI OMCI Managed Entity

    This Managed Entity describes the ONT's general level of support for OMCI
    Managed Entities and messages. This Managed Entity is not included in MIB
    upload. One instance exists in the ONT. The "Managed Entity" entities are
    related to the "OMCI" Managed Entity.

    @{
*/

/* The table sizes are application dependent. For debugging define the size
   here, for the final revision read the sizes from an external non-volatile
   memory. The tables themselves are also retrieved from am external memory.

   According to ITU-T G.984.4 status of May 2009, there are no more than 312
   Managed Entities defined (see Table 11-2/G.984.4 - Managed entity
   identifiers).

   According to ITU-T G.984.4 status of May 2009, there are no more than 25
   messages defined (see Table 11-1/G.984.4 - OMCI message types).
*/

/** Size of struct omci_me_omci::my_type_table */
#define OMCI_ME_TABLE_SIZE                 OMCI_ME_CLASS_NUM

/*
#define OMCI_ME_TABLE_SIZE 312
*/

/** Size of struct omci_me_omci::msg_type_table */
#define OMCI_MT_TABLE_SIZE                 22


/** This structure holds the attributes of the "OMCI" Managed Entity.
*/
struct omci_me_omci {
	/** Managed Entity Type Table

	    This attribute lists the Managed Entity classes that are supported
	    by the ONU. Each entry contains the Managed Entity class value of a
	    supported Managed Entity.
	    This table is read-only by the OLT. The table size depends on the
	    number of supported Managed Entities which in turn depends on the
	    target application.
	*/
	uint16_t my_type_table;

	/** Message Type Table

	    This attribute is a list of message types that are supported by the
	    ONU.
	    Each entry contains the message type of a supported OMCI message.
	    This table is read-only by the OLT. The table size depends on the
	    number of supported messages which in turn depends on the target
	    application.
	*/
	uint8_t msg_type_table;

} __PACKED__;

/** This enumerator holds the attribute numbers of the OMCI Managed Entity.
*/
enum {
	omci_me_omci_me_type_table = 1,
	omci_me_omci_msg_type_table = 2
};

/*! @} */

/*! @} */

__END_DECLS

#endif
