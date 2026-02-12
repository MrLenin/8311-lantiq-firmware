/******************************************************************************

                              Copyright (c) 2010
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_priority_queue
#define _omci_api_me_priority_queue

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** Maximum Number of priority queues*/
#define OMCI_API_PRIORITY_QUEUE_MAX	255

/** \defgroup OMCI_API_ME_PRIORITY_QUEUE Priority Queue

   This Managed Entity specifies the priority queue used by a GEM port network
   CTP. In the upstream direction, a priority queue-G ME is also related to a
   T-CONT ME. By default, this relationship is fixed by the ONU hardware
   architecture, but some ONUs may also permit the relationship to be
   configured through OMCI, as indicated by the QoS configuration flexibility
   attribute of the ONU2-G Managed Entity.

   In the downstream direction, priority queues are associated with UNIs.
   Again, the association is fixed by default, but some ONUs may permit the
   association to be configured through OMCI. The OLT can find all the queues
   by reading the priority queue-G Managed Entity instances. If the OLT tries
   to retrieve a non-existent priority queue, the ONU denies the get action
   with an error indication.

   Upstream priority queues can be added to the ONU. Moreover, priority queues
   can exist in the ONU core and circuit packs serving both UNI and ANI
   functions.

   In the upstream direction, the weight attribute permits configuring an
   optional traffic scheduler. Several attributes support back pressure
   operation, whereby a back pressure signal is sent backward and causes the
   attached terminal to temporarily suspend sending data.

   The yellow packet drop thresholds are used to specify the packet drop
   probability for a packet that has been marked yellow (drop eligible) by a
   traffic descriptor or by external equipment such as a residential gateway.
   If the current queue occupancy is less than the min threshold, the yellow
   packet drop probability is zero. If the current queue occupancy is greater
   than or equal to the max threshold, the yellow packet drop probability is
   one. Otherwise, the yellow drop probability increases linearly between 0 and
   max_p as the current queue occupancy increases from the min to the max
   threshold.

   Drop precedence color marking indicates the method by which a packet is
   marked as drop eligible (yellow). For DEI and PCP marking, a drop eligible
   indicator is equivalent to yellow color, otherwise the color is green.
   For DSCP AF marking, the lowest drop precedence is equivalent to green,
   otherwise the color is yellow.

   @{
*/

/** Set Drop Precedence Color Marking for a given LAN port and direction

   \param direction                           Direction, upstream or downstream
   \param lan_port                            LAN port index
   \param color_marking                       Related port

*/
enum omci_api_return
omci_api_priority_queue_drop_precedence_color_marking_set(
				const enum omci_api_queue_direction direction,
				const uint8_t lan_port,
				const uint8_t color_marking);

/** Get Drop Precedence Color Marking for a given LAN port and direction

   \param direction                           Direction, upstream or downstream
   \param lan_port                            LAN port index
   \param color_marking                       Related port

*/
enum omci_api_return
omci_api_priority_queue_drop_precedence_color_marking_get(
				const enum omci_api_queue_direction direction,
				const uint8_t lan_port,
				uint8_t *color_marking);

/** Enable Managed Entity identifier mapping to driver index and initialize
    corresponding driver structures

   \param ctx                                OMCI API context pointer
   \param me_id Managed                      Entity identifier
   \param related_port                       Related port
   \param traffic_scheduler_g_ptr            Traffic scheduler pointer
   \param alloc_queue_size                   Allocated queue size
   \param discard_block_cnt_reset_interval   Discard-block counter reset
                                             interval
   \param threshold_value_for_discarded_blocks  Threshold value for discarded
                                             blocks due to buffer overflow
   \param weight                             Weight
   \param back_pressure_operation            Back pressure operation
   \param back_pressure_time                 Back pressure time
   \param back_pressure_occur_threshold      Back pressure occur queue
                                             threshold
   \param back_pressure_clear_threshold      Back pressure clear queue
                                             threshold
   \param packet_drop_queue_threshold_green_min  Packet drop queue thresholds
                                             first value
   \param packet_drop_queue_threshold_green_max  Packet drop queue thresholds
                                             second value
   \param packet_drop_queue_threshold_yellow_min Packet drop queue thresholds
                                             third value
   \param packet_drop_queue_threshold_yellow_max Packet drop queue thresholds
                                             fourth value
   \param packet_drop_probability_green      The probability of dropping a
                                             green packet
   \param packet_drop_probability_yellow     The probability of dropping a
                                             yellow packet
   \param queue_drop_averaging_coefficient   Queue_drop_w_q
   \param drop_precedence_color_marking      Drop precedence color marking

*/
enum omci_api_return
omci_api_priority_queue_create(struct omci_api_ctx *ctx,
			       const uint16_t me_id,
			       const uint32_t related_port,
			       const uint16_t traffic_scheduler_g_ptr,
			       const uint16_t alloc_queue_size,
			       const uint16_t discard_block_cnt_reset_interval,
			       const uint16_t
			       threshold_value_for_discarded_blocks,
			       const uint8_t weight,
			       const uint16_t back_pressure_operation,
			       const uint32_t back_pressure_time,
			       const uint16_t back_pressure_occur_threshold,
			       const uint16_t back_pressure_clear_threshold,
			       const uint16_t
			       packet_drop_queue_threshold_green_min,
			       const uint16_t
			       packet_drop_queue_threshold_green_max,
			       const uint16_t
			       packet_drop_queue_threshold_yellow_min,
			       const uint16_t
			       packet_drop_queue_threshold_yellow_max,
			       const uint8_t packet_drop_probability_green,
			       const uint8_t packet_drop_probability_yellow,
			       const uint8_t queue_drop_averaging_coefficient,
			       const uint8_t drop_precedence_color_marking);

/** Disable Managed Entity identifier mapping to driver index and clear
   corresponding driver structures

   \param ctx   OMCI API context pointer
   \param me_id Managed Entity identifier
*/
enum omci_api_return
omci_api_priority_queue_destroy(struct omci_api_ctx *ctx,
				uint16_t me_id);

/** Update Priority Queue resources

   \param ctx                                OMCI API context pointer
   \param me_id                              Managed Entity identifier
   \param alloc_queue_size                   Allocated queue size
   \param discard_block_cnt_reset_interval   Discard-block counter reset
                                             interval
   \param threshold_value_for_discarded_blocks  Threshold value for discarded
                                             blocks due to buffer overflow
   \param weight                             Weight
   \param back_pressure_operation            Back pressure operation
   \param back_pressure_time                 Back pressure time
   \param back_pressure_occur_threshold      Back pressure occur queue
                                             threshold
   \param back_pressure_clear_threshold      Back pressure clear queue
                                             threshold
   \param packet_drop_queue_threshold_green_min  Packet drop queue thresholds
                                             first value
   \param packet_drop_queue_threshold_green_max  Packet drop queue thresholds
                                             second value
   \param packet_drop_queue_threshold_yellow_min Packet drop queue thresholds
                                             third value
   \param packet_drop_queue_threshold_yellow_max Packet drop queue thresholds
                                             fourth value
   \param packet_drop_probability_green      The probability of dropping a
                                             green packet
   \param packet_drop_probability_yellow     The probability of dropping a
                                             yellow packet
   \param queue_drop_averaging_coefficient   Queue_drop_w_q
   \param drop_precedence_color_marking      Drop precedence color marking
*/
enum omci_api_return
omci_api_priority_queue_update(struct omci_api_ctx *ctx,
			       const uint16_t me_id,
			       const uint16_t alloc_queue_size,
			       const uint16_t discard_block_cnt_reset_interval,
			       const uint16_t
			       threshold_value_for_discarded_blocks,
			       const uint8_t weight,
			       const uint16_t back_pressure_operation,
			       const uint32_t back_pressure_time,
			       const uint16_t back_pressure_occur_threshold,
			       const uint16_t back_pressure_clear_threshold,
			       const uint16_t
			       packet_drop_queue_threshold_green_min,
			       const uint16_t
			       packet_drop_queue_threshold_green_max,
			       const uint16_t
			       packet_drop_queue_threshold_yellow_min,
			       const uint16_t
			       packet_drop_queue_threshold_yellow_max,
			       const uint8_t packet_drop_probability_green,
			       const uint8_t packet_drop_probability_yellow,
			       const uint8_t queue_drop_averaging_coefficient,
			       const uint8_t drop_precedence_color_marking);

/** @} */

/** @} */

__END_DECLS

#endif
