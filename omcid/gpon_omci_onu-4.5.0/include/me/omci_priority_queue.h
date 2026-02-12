/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_priority_queue_h
#define _omci_priority_queue_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_PRIORITY_QUEUE Priority Queue Managed Entity

    The Priority Queue Managed Entity specifies the priority queue used by a
    GEM port network Connection Termination Point. In the upstream direction,
    a Priority Queue Managed Entity is related to a T-CONT Managed Entity.

    If N priority queues reside in the ONT and its circuit packs, the ONT
    creates N instances of the priority Priority Queue Managed Entity
    following the creation of the circuit pack or T-CONT Managed Entities.
    After the ONT creates T-CONT Managed Entities, it autonomously creates
    instances of the Priority Queue Managed Entity.

    One or more instances of this Managed Entity are associated with the ONU-G
    Managed Entity to model the upstream priority queues if the traffic
    management option attribute in the ONU-G ME is 0.

    One or more instances of this Managed Entity are associated with a Circuit
    Pack Managed Entity serving UNI functions as downstream priority queues.
    For an ONT that has one or more fixed user interfaces, one or more instances
    are associated with the ONU-G Managed Entity for the downstream priority
    queues.

    @{
*/

/** The default value of the Discard Block Counter reset interval is 1 minute
    given in multiples of one millisecond. */
#define OMCI_DEFAULT_DISCARD_BLOCK_COUNTER_INTERVAL   60000

/** The default value of the Allocated Queue Size is 0. */
#define OMCI_DEFAULT_ALLOCATED_QUEUE_SIZE             0x0000

/** This is the default value of the threshold for discarded blocks. */
#define OMCI_DEFAULT_THR_FOR_DISCARDED_BLOCKS         0xFFFF

/** This is the default value of the traffic scheduler pointer. */
#define OMCI_DEFAULT_TRAFFIC_SCHEDULER_POINTER        0x0000

/** This is the default value of the weight. */
#define OMCI_DEFAULT_WEIGHT                           0x01

/** This is the default value of the back pressure time. */
#define OMCI_DEFAULT_BACK_PRESSURE_TIME               0x00000000

/** This is the default value of the back pressure occur threshold. */
#define OMCI_DEFAULT_BACK_PRESSURE_OCCUR_THR          0xFFFF

/** This is the default value of the back pressure clear threshold. */
#define OMCI_DEFAULT_BACK_PRESSURE_CLEAR_THR          0xFFFF

/** This structure holds the attributes of the Priority Queue
    Managed Entity.
*/
struct omci_me_priority_queue {
	/** Queue Configuration Option

	    This attribute identifies the buffer partitioning policy. The value
	    0x01 means that several queues share one buffer size of maximum
	    queue size, while the value 0x00 means that each queue has an
	    individual buffer of maximum queue size.

	    The default value of this attribute is read from a non-volatile
	    memory.
	    This attribute is read-only by the OLT.

	    The hardware uses a "traffic profile" to limit the size of a queue.
	    Register TPT3 holds the maximum size, which is called "Queue Tail
	    Drop Threshold". The selected traffic profile must then be assigned
	    to the queue by using register QMT5.TPID.

	    This attribute is read-only by the OLT.
	*/
	uint8_t config_option;

	/** Maximum Queue Size

	    This attribute specifies the maximum size of the queue.

	    Units are GEM block lengths, which are defined by the ANI-G Managed
	    Entity (see \ref omci_me_ani_g::gem_block_len).

	    If the \ref config_option is set to 0x01, the
	    \ref max_size value of the most recently received Priority
	    Queue OMCI message is used as the global queue limitation threshold.

	    The default value of this attribute is read from a non-volatile
	    memory.

	    This attribute is read-only by the OLT.
	*/
	uint16_t max_size;

	/** Allocated Queue Size

	    This attribute identifies the allocated size of this queue. Units
	    are GEM block lengths, as defined by the ANI-G Managed Entity.

	    This value may be selected to be less or equal to
	    \ref max_size, but not larger. If a larger value is given,
	    \ref max_size is used instead and a warning is indicated.

	    The default value of this attribute is defined by
	    \ref OMCI_DEFAULT_ALLOCATED_QUEUE_SIZE.

	    This attribute is readable and writable by the OLT.

	    \remarks The hardware uses a "traffic profile" to limit the queue
	    size.  Register TPT3 holds the maximum size, which is called "Queue
	    Tail Drop Threshold".  The selected traffic profile must then be
	    assigned to the queue by using register QMT5.TPID. The number of
	    traffic profiles and queues is limited and must be handled by a
	    resource manager.
	*/
	uint16_t allocated_size;

	/** Discard Block Counter Reset Interval

	    This attribute represents the interval in milliseconds at which the
	    Discard Block Counter resets itself.

	    The default value of this attribute is defined by
	    \ref OMCI_DEFAULT_DISCARD_BLOCK_COUNTER_INTERVAL.

	    This attribute is readable and writable by the OLT.
	*/
	uint16_t discard_block_counter_reset_interval;

	/** Threshold Value for Discarded Blocks

	    This attribute defined the threshold for the number of GEM block
	    lengths discarded on this queue due to buffer overflow.

	    The default value of this attribute is defined by
	    \ref OMCI_DEFAULT_THR_FOR_DISCARDED_BLOCKS.

	    This attribute is readable and writable by the OLT.
	*/
	uint16_t discard_block_thr;

	/** Related Port

	    This attribute represents the slot, port/T-CONT and priority
	    information associated with the instance of Priority Queue Manage
	    Entity.

	    In the upstream direction, the first two bytes are the ME ID of the
	    associated T-CONT.

	    In the downstream direction, the first byte is the slot number and
	    the second byte is the port number of the queue's destination port.

	    The last two bytes represent the priority of this queue. The range
	    of priority is 0x0000 to 0x0FFF. The value 0x0000 indicates the
	    highest priority and 0x0FFF indicates the lowest priority.

	    The default value of this attribute is read from a non-volatile
	    memory.

	    This attribute is read-only by the OLT.

	    \remarks The traffic port number is selected by setting register
	    QMT0.EPN.
	*/
	uint32_t related_port;

	/** Traffic Scheduler Pointer

	    This attribute points to the Traffic Scheduler Managed Entity
	    instance that is associated with this priority queue.

	    This pointer is used when this priority queue is connected with a
	    traffic scheduler.

	    The default value is defined by
	    \ref OMCI_DEFAULT_TRAFFIC_SCHEDULER_POINTER.

	    This attribute is readable and writable by the OLT.

	    \remarks The traffic scheduler is selected by setting register
	    QMT5.SBIN.
	*/
	uint16_t traffic_scheduler_ptr;

	/** Weight

	    This attribute represents the weight for Weighted Round Robin
	    scheduling.

	    This attribute represents weight for WRR. In the upstream direction
	    this weight is used by the traffic scheduler or T-CONT (whose
	    policy is WRR) indicated by the traffic scheduler pointer attribute
	    or related port attribute.

	    Upon Managed Entity instantiation, the ONT sets this attribute to
	    the value 0x01.

	    This attribute is readable and writable by the OLT.

	    \remarks The hardware uses a "traffic profile" to define the queue's
	    weight. Register TPT3 holds the weight. The selected traffic profile
	    must then be assigned to the queue by using register QMT5.TPID.
	*/
	uint8_t weight;

	/** Back Pressure Operation

	    This attribute enables or disables back pressure operation.

	    The coding is
	    - 0x00 enabled
	    - 0x01 disabled

	    The default value defined by ITU-T G.984.4 is 0x00.

	    Back pressure operation per queue is not provided by the hardware,
	    so the default is set to 0x01.

	    If the OLT tries to enable back pressure, this is refused due
	    to the lack of hardware support.

	    This attribute is readable and writable by the OLT.
	*/
	uint16_t back_pressure_oper;

	/** Back Pressure Time

	    This attribute indicates the time for which the customer terminal
	    temporarily suspends sending data.

	    This attribute presents the duration in microseconds.
	    The values range is from 0x0000 0000 to 0xFFFF FFFF.

	    Upon ME instantiation, the ONT sets this attribute to 0x0000 0000
	    (\ref OMCI_DEFAULT_BACK_PRESSURE_TIME).

	    This attribute is readable and writable by the OLT.

	    \remarks Back pressure is only provided if based on the total buffer
	    filling level, not per queue (see \ref back_pressure_oper).
	*/
	uint32_t back_pressure_time;

	/** Back Pressure Occur Threshold

	    This attribute identifies the threshold size of this queue to start
	    sending the back pressure signal. The value is given in units of GEM
	    block length.

	    The default value upon Managed Entity instantiation is given by
	    \ref OMCI_DEFAULT_BACK_PRESSURE_OCCUR_THR

	    This attribute is readable and writable by the OLT.

	    \remarks Back pressure is only provided if based on the total buffer
	    filling level, not per queue (see \ref back_pressure_oper).
	*/
	uint16_t back_pressure_occur_thr;

	/** Back Pressure Clear Threshold

	    This attribute identifies the threshold size of this queue to end
	    sending the back pressure signal. The value is given in units of GEM
	    block length.

	    The default value upon Managed Entity instantiation is given by
	    \ref OMCI_DEFAULT_BACK_PRESSURE_CLEAR_THR

	    This attribute is readable and writable by the OLT.

	    \remarks Back pressure is only provided if based on the total buffer
	    filling level, not per queue (see \ref back_pressure_oper).
	*/
	uint16_t back_pressure_clear_thr;

#ifdef INCLUDE_G984_4_AMENDMENT_2
	/** Packet Drop Thresholds

	    This attribute is a composite of four 2-byte values, a minimum and a
	    maximum threshold, measured in GEM block lengths, for green and
	    yellow packets. The first value is the minimum threshold, the queue
	    occupancy, below which all green packets are admitted to the queue.
	    The second value is the maximum threshold, the queue occupancy, at
	    or above which all green packets are discarded. The third value is
	    the minimum threshold, the queue occupancy, below which all yellow
	    packets are admitted to the queue. The fourth value is the maximum
	    threshold, the queue occupancy, at or above which all yellow packets
	    are discarded.
	    The default is that all thresholds take the value of the maximum
	    queue size.

	    This attribute is readable and writable by the OLT.
	*/
	uint16_t packet_drop_thr_green_min;
	uint16_t packet_drop_thr_green_max;
	uint16_t packet_drop_thr_yellow_min;
	uint16_t packet_drop_thr_yellow_max;

	/** Packet Drop Probability

	    This attribute is a composite of two 1-byte values, the probability
	    of dropping a green or yellow packet when the queue occupancy lies
	    just below the max threshold. The first value is the green packet
	    max_p, and the second value is the yellow packet max_p. The
	    probability, max_p, is determined by adding one to the unsigned
	    value (0..255) of this attribute and dividing the result by 256.
	    The default for each value is 255.

	    This attribute is readable and writable by the OLT.
	*/
	uint8_t packet_drop_probability_green;
	uint8_t packet_drop_probability_yellow;

	/** Queue Drop Averaging Coefficients

	    This attribute determines the averaging coefficient, w_q, as
	    described in: Floyd, S, and Jacobson, V, Random early detection
	    gateways for congestion avoidance. IEEE/ACM Transactions on
	    Networking, V.1 N.4, August 1993, p. 397-413.

	    The averaging coefficient, w_q, is equal to 2-Queue_drop_w_q.
	    For example, when queue_drop_w_q has the value of 9, the averaging
	    coefficient, w_q, is 0.0019. The default value is 9.

	    This attribute is readable and writable by the OLT.
	*/
	uint8_t drop_avg_coef;

	/** Drop Precedence Color Marking Mode

	    This attribute specifies how the drop precedence is marked on the
	    ingress packets to the priority queue. The default value is 0x00.

	    Allowed settings are:
	    - 0x00 No marking, all packets are treated as "green"
	    - 0x01 Internal marking (from Traffic Descriptor ME)
	    - 0x02 DEI (IEEE 802.1ad)
	    - 0x03 PCP 8P0D (IEEE 802.1ad)
	    - 0x04 PCP 7P1D (IEEE 802.1ad)
	    - 0x05 PCP 6P2D (IEEE 802.1ad)
	    - 0x06 PCP 5P3D (IEEE 802.1ad)
	    - 0x07 DSCP AF class (IETF RFC 2597)
	*/
	uint8_t drop_precedence_color_marking;
#endif

} __PACKED__;

/** This enumerator holds the attribute numbers of the Priority Queue
    Managed Entity.
*/
enum {
	omci_me_priority_queue_config_option = 1,
	omci_me_priority_queue_max_size = 2,
	omci_me_priority_queue_allocated_size = 3,
	omci_me_priority_queue_discard_block_counter_reset_interval = 4,
	omci_me_priority_queue_discard_block_thr = 5,
	omci_me_priority_queue_related_port = 6,
	omci_me_priority_queue_traffic_scheduler_ptr = 7,
	omci_me_priority_queue_weight = 8,
	omci_me_priority_queue_back_pressure_oper = 9,
	omci_me_priority_queue_back_pressure_time = 10,
	omci_me_priority_queue_back_pressure_occur_thr = 11,
	omci_me_priority_queue_back_pressure_clear_thr = 12,
	omci_me_priority_queue_packet_drop_thr = 13,
	omci_me_priority_queue_packet_drop_probability = 14,
	omci_me_priority_queue_drop_avg_coef = 15,
	omci_me_priority_queue_drop_precedence_color_marking = 16
};

/** Get Priority Queue ID */
#define OMCI_PQG_ID_GET(ME_ID) \
   ((uint16_t)((ME_ID) & 0x7fff))

/** Get Priority Queue direction */
#define OMCI_PQG_DIRECTION_GET(ME_ID) \
   ((uint16_t)(((ME_ID) & 0x8000)) >> 15)

/** @} */

/** @} */

__END_DECLS

#endif
