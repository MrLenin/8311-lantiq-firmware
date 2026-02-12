/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_traffic_scheduler_h
#define _omci_traffic_scheduler_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_TRAFFIC_SCHEDULER Traffic Scheduler Managed Entity

    An instance of this Managed Entity represents a logical object that can
    control upstream GEM packets. A traffic scheduler can accommodate GEM
    packets after a priority queue or other traffic scheduler and transfer
    them toward the next traffic scheduler or T-CONT. Because T-CONTs and
    traffic schedulers are created autonomously by the ONT, the ONT vendor
    predetermines the most complex traffic handling model it is prepared to
    support. The OLT may use less than the ONU's full capabilities, but
    cannot ask for more (it can ask, but the answer will be "no").

    After the ONU creates instances of T-CONT ME, it then autonomously creates
    instances of the Traffic Scheduler Managed Entity.

    The Traffic Scheduler Managed Entity may be related to a T-CONT or
    other traffic schedulers through pointer attributes.

    @{
*/

/** This structure holds the attributes of the Traffic Scheduler
    Managed Entity.
*/
struct omci_me_traffic_scheduler {
	/** T-CONT Pointer

	    This attribute points to the T-CONT Managed Entity instance
	    associated with this traffic scheduler. This pointer is used when
	    this traffic scheduler is connected to the T-CONT directly. It is
	    null (0x0000) otherwise.

	    This parameter is application dependent.

	    This attribute is read-only by the OLT.
	*/
	uint16_t tcont_ptr;

	/** Traffic Scheduler Pointer

	    This attribute points to another Traffic Scheduler Managed Entity
	    instance that may serve this traffic scheduler. This pointer is
	    used when this traffic scheduler is connected to another traffic
	    scheduler, it is null (0x0000) otherwise.

	    This parameter is application dependent.

	    This attribute is read-only by the OLT.
	*/
	uint16_t traffic_scheduler_ptr;

	/** Traffic Scheduler Policy

	    This attribute represents scheduling policy. Valid values include:
	    - 0x00 Null
	    - 0x01 Head of Line (HOL)
	    - 0x02 Weighted Round Robin (WRR)

	    This parameter is application dependent.

	    This attribute is read-only by the OLT.
	*/
	uint8_t policy;

	/** Priority or Weight

	    This attribute represents priority for HOL scheduling or the weight
	    for WRR scheduling. This value is used by the T-CONT or traffic
	    scheduler indicated by the T-CONT pointer attribute or traffic
	    scheduler pointer attribute. If the indicated pointer has
	    policy = HOL, this value is interpreted as a priority (0 is the
	    highest priority, 255 the lowest).  If the indicated pointer has
	    policy = WRR, this value is interpreted as a weight. Upon Managed
	    Entity instantiation, the ONT sets this attribute to 0x00.

	    This parameter is application dependent.

	    This attribute is readable and writable by the OLT.
	*/
	uint8_t priority_weight;

} __PACKED__;

#define OMCI_TS_POLICY_NULL		0
#define OMCI_TS_POLICY_HOL		1
#define OMCI_TS_POLICY_WRR		2

/** This enumerator holds the attribute numbers of the Traffic Scheduler
    Managed Entity.
*/
enum {
	omci_me_traffic_scheduler_tcont_pointer = 1,
	omci_me_traffic_scheduler_traffic_scheduler_ptr = 2,
	omci_me_traffic_scheduler_policy = 3,
	omci_me_traffic_scheduler_priority_weight = 4
};

/** Get Traffic scheduler Slot ID from the Managed Entity ID */
#define OMCI_TS_SLOTID_GET(ME_ID) \
   ((uint8_t)(((ME_ID) & 0xff00) >> 8))

/** Get Traffic scheduler ID from the Managed Entity ID */
#define OMCI_TS_ID_GET(ME_ID) \
   ((uint8_t)((ME_ID) & 0x00ff))

/** @} */

/** @} */

__END_DECLS

#endif
