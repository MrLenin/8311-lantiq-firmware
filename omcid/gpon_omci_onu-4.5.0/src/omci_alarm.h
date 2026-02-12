/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_alarm_h
#define _omci_alarm_h

#include "omci_timeout.h"

/** \addtogroup OMCI_CORE

   @{
*/

/** \defgroup OMCI_ALARM Optical Network Unit - Alarm Handling

   @{
*/

/** This structure is used in a list containing alarms table copy */
struct alarm_copy_entry {
	/** Managed Entity class identifier */
	uint16_t class_id;

	/** Managed Entity instance identifier */
	uint16_t instance_id;

	/** Managed Entity alarm mask */
	uint8_t alarm_bitmap[OMCI_ALARM_BITMAP_SIZE];
};

/** This is an alarms copy context */
struct alarm_copy {
	/** Id of timeout which should clean list */
	unsigned long timeout_id;

	/** Copy of Managed Entities alarms */
	struct list list;
};

/** This is an ARC context */
struct me_arc_context {
	/** ARC disable timeout identifier */
	unsigned long timeout_id;

	/** ARC attribute number */
	unsigned int arc_attr;

	/** ARC_interval attribute number */
	unsigned int arc_interval_attr;
};

/** Initialize alarm copy

   \param[in] context OMCI context pointer
*/
enum omci_error alarm_copy_init(struct omci_context *context);

/** Shutdown alarm copy

   \param[in] context OMCI context pointer
*/
enum omci_error alarm_copy_shutdown(struct omci_context *context);

/** Check if alarm bitmap has no pending alarms

   \param[in] alarm_bitmap alarm bitmap

   \return true if alarm bitmap is empty or if alarm_bitmap == NULL
*/
bool is_alarm_bitmap_empty(const uint8_t alarm_bitmap[OMCI_ALARM_BITMAP_SIZE]);

/** Set alarm

   \param[in] alarm_bitmap Alarm bitmap
   \param[in] alarm        Alarm number [0 .. \ref OMCI_ALARMS_NUM - 1]
   \param[in] active       Alarm status:
                            - true - Turn on alarm
                            - false - Turn off alarm
*/
enum omci_error alarm_set(uint8_t alarm_bitmap[OMCI_ALARM_BITMAP_SIZE],
			  uint8_t alarm,
			  bool active);

/** Clear alarm bitmap

   \param[in] alarm_bitmap Alarm bitmap
*/
enum omci_error alarm_bitmap_clear(uint8_t alarm_bitmap
				   [OMCI_ALARM_BITMAP_SIZE]);

/** Get value of the alarm

   \param[in]  alarm_bitmap Alarm bitmap
   \param[in]  alarm        Alarm number [0 .. \ref OMCI_ALARMS_NUM - 1]
   \param[out] active       Returns alarm status:
                             - true - Alarm is on
                             - false - Alarm is off
*/
enum omci_error alarm_get(const uint8_t *alarm_bitmap,
			  uint8_t alarm,
			  bool *active);

struct me;

/** Allocate me->alarm_bitmap (used in Managed Entity instance initializing
    procedure)

   \param[in] me Managed Entity pointer
*/
enum omci_error alarm_bitmap_alloc(struct me *me);

/** Deallocate me->alarm_bitmap (used in Managed Entity instance terminating
    procedure)

   \param[in] me Managed Entity pointer
*/
enum omci_error alarm_bitmap_free(struct me *me);

/** Allocate me->arc_context (used in Managed Entity instance initializing
    procedure)

   \param[in] me Managed Entity pointer
*/
enum omci_error arc_context_alloc(struct me *me);

/** Deallocate me->arc_context (used in Managed Entity instance terminating
    procedure)

   \param[in] me Managed Entity pointer
*/
enum omci_error arc_context_free(struct me *me);

/** Set ARC interval

   \param[in] context   OMCI context pointer
   \param[in] me        Managed Entity pointer
   \param[in] data      Attribute data to set
   \param[in] data_size Data size
*/
enum omci_error arc_interval_set(struct omci_context *context,
				 struct me *me,
				 const uint8_t *data,
				 size_t data_size);

/** This is a timeout event handler.
   It called when ARC interval is expired.

   \param[in] context OMCI context pointer
   \param[in] timeout timeout entry
*/
enum omci_error arc_interval_exp_timeout_handler(struct omci_context *context,
						 struct timeout *timeout);

/** @} */

/** @} */

#endif
