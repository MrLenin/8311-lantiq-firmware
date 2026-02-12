/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_tcont_h
#define _omci_tcont_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_TCONT T-CONT Managed Entity

    An instance of the Traffic Container Managed Entity T-CONT represents a
    logical connection group associated with a PLOAM layer AllocId.

    The ONT autonomously creates instances of this ME. The OLT can discover
    the number of T-CONT instances via the ANI-G Managed Entity. When the ONT's
    MIB is reset or created for the first time, all supported T-CONTs are
    created.

    The maximum number of T-CONTS that are physically available is read from
    a non-volatile memory.

    @{
*/

/** Invalid Alloc-ID value */
#define OMCI_ALLOC_ID_INVALID 0x00ff

/** This structure holds the attributes of the T-CONT Managed Entity.
*/
struct omci_me_tcont {
	/** Allocation ID

	    This attribute links the T-CONT with the AllocId assigned by the
	    OLT in the assignAllocID PLOAM message. Legal values range from
	    0x000 to 0x0FFF.
	    Upon instantiation, this attribute has default value
	    0x00FF (unassigned).

	    This attribute is readable and writable by the OLT.
	*/
	uint16_t alloc_id;

	/** Mode Indicator

	    This attribute holds a fixed value of 0x01. It is read-only by the
	    OLT.
	*/
	uint8_t mode_indicator;

	/** Upstream Scheduler Policy

	    This attribute indicates the T-CONT's traffic scheduling policy.
	    Valid values are:
	    - 0x00: NULL
	    - 0x01: Head-of-Line queueing (HOL)
	    - 0x02: Weighted Round Robin queueing (WRR)

	    The attribute setting depends on the application implementation.

	    The value of this attribute is read from a non-volatile memory.

	    This attribute is read-only by the OLT.
	*/
	uint8_t policy;

} __PACKED__;

/** This enumerator holds the attribute numbers of the T-CONT Managed Entity.
*/
enum {
	omci_me_tcont_alloc_id = 1,
	omci_me_tcont_mode_indication = 2,
	omci_me_tcont_policy = 3
};

/** Get T-CONT ID */
#define OMCI_TCONT_ID_GET(ME_ID) \
   ((uint8_t)((ME_ID) & 0x00ff))

/** Get T-CONT Slot ID */
#define OMCI_TCON_SLOTID_GET(ME_ID) \
   ((uint8_t)(((ME_ID) & 0xff00)) >> 8)

/** @} */

/** @} */

__END_DECLS

#endif
