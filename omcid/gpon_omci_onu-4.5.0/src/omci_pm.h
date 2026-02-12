/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_pm_h
#define _omci_pm_h

#include "ifxos_thread.h"

#include "omci_alarm.h"

/** \defgroup OMCI_PM Optical Network Unit - Performance Monitoring

  OMCI SW supports the following PM Managed Entities handling:

  1. External.

     me_counters_get handler is called upon the reception of Get/Get Current
     OMCI message with appropriate 'interval' value (OMCI_PM_INTERVAL_CURR or
     OMCI_PM_INTERVAL_HIST). Counters are copied to the ME data and then
     returned as is to the OLT.

     me_thr_set handler is called whenever thresholds are updated from the OLT.
     Thresholds are passed as is and should be forwarded to the threshold
     controlling application.

     To use this mode please provide appropriate me_counter_get and
     me_thr_set handlers. Managed Entity should also have OMCI_ME_PROP_PM
     property.

  2. Internal.

     me_counters_get handler is called every PM_POLLING_TIME milliseconds.
     Absolute counter values are copied to the ME data and checked for the
     thresholds.

     In this mode interval value is meaningless because only absolute counters
     are expected (but anyway, me_counter_get handler is called with the
     OMCI_PM_INTERVAL_ABS value in interval parameter each PM_POLLING_TIME ms).

     me_counters_get is also called with the OMCI_PM_INTERVAL_CURR and
     OMCI_PM_INTERVAL_HIST in order to able to manage external and internal
     counters in one Managed Entity (see note below) upon the reception of
     Get/Get Current OMCI message.

     You should install default_me_thr_set handler for the me_thr_set because
     thresholds management is now handled by the OMCI SW.

     To use this mode please provide appropriate me_counter_get handler and
     use default_me_thr_set for the me_thr_set handler. Managed Entity should
     also have OMCI_ME_PROP_PM and OMCI_ME_PROP_PM_INTERNAL properties.

  What if there is a situation where you need to support external and internal
  counters in _one_ ME? Then you have to use 'Internal' mode and then workaround
  external counters. When me_counters_get is called with the
  OMCI_PM_INTERVAL_CURR or OMCI_PM_INTERVAL_HIST you have to update external
  counters. For thresholds you just have to define handler in which external
  thresholds go to external application and then call default_me_thr_set for
  internally handled counters (for external counters set thresholds to 0).

  If you need to simulate absolute values you just need to add new difference
  to the current ME data because when the me_counters_get is called for the
  internally handled PM MEs, ME data points to the interval with absolute
  counter values.

  Another call to me_counters_get is made after each 15-min interval.
  The 'interval' variable has value OMCI_PM_INTERVAL_END and gives you
  a possibility to calculate counters that should be updated only at the
  end of the PM interval.
  This call is made only for internally (OMCI_ME_PROP_PM_INTERNAL) managed
  PM MEs.

   @{
*/

/** Define TCA entry

    Generate TCA NUMBER if attribute THR_CROSSING_ALERT crossed threshold
    THR_VALUE_ATTR in Threshold Data 1/2 Managed Entity.

    This define represents table entry in the 'Threshold crossing alert'
    table of G.984.4.
*/
#define TCA(NUMBER, THR_CROSSING_ALERT, THR_VALUE_ATTR) \
	{ (NUMBER), (THR_CROSSING_ALERT), (THR_VALUE_ATTR) }

/** TCA mapping structure */
struct me_tca {
	/** Number of the threshold to be sent */
	uint8_t thr_num;

	/** Number of the attribute for this threshold */
	uint8_t attr_num;

	/** Number of the attribute in the Threshold data 1/2 */
	uint8_t thr_attr_num;
};

/** Number of thresholds (refer to ITU-G.984.4) */
#define PM_THR_NUM                                          15

#ifdef INCLUDE_PM

struct me;

/** PM Managed Entity data header */
struct pm_me_data {
	/** Interval End Time

	    This attribute identifies the most recently finished 15-minute
	    interval. The sequence of 15-minute intervals is initiated by the
	    synchronize time action, issued by the OLT. The counter is
	    incremented every 15 minutes autonomously by the ONU and rolls over
	    from 255 to 0.

	    This attribute is read-only by the OLT.
	*/
	uint8_t interval_end_time;

	/** Threshold Data 1/2 ID

	    This attribute points to an instance of the threshold data 1 Managed
	    Entity that contains PM threshold values.
	    Since no threshold value attribute number exceeds 7, a threshold
	    data 2 Managed Entity is optional.

	    This attribute is readable and writable by the OLT.
	*/
	uint16_t thr_data_id;
} __PACKED__;

/** PM Managed Entity attributes */
enum {
	omci_me_pm_interval_end_time = 1,
	omci_me_pm_thr_data_id = 2,
	omci_me_pm_counter_1 = 3,
	omci_me_pm_counter_2 = 4,
	omci_me_pm_counter_3 = 5,
	omci_me_pm_counter_4 = 6,
	omci_me_pm_counter_5 = 7,
	omci_me_pm_counter_6 = 8,
	omci_me_pm_counter_7 = 9,
	omci_me_pm_counter_8 = 10,
	omci_me_pm_counter_9 = 11,
	omci_me_pm_counter_10 = 12,
	omci_me_pm_counter_11 = 13,
	omci_me_pm_counter_12 = 14,
	omci_me_pm_counter_13 = 15,
	omci_me_pm_counter_14 = 16,
	omci_me_pm_counter_max
};

/** PM context */
struct pm_context {
	/** Most recently finished 15-min interval */
	uint8_t interval_end_time;
	/** List of PM managed entities */
	struct list list;
	/** PM thread control */
	IFXOS_ThreadCtrl_t thread_ctrl;
};

/** PM Managed Entity context */
struct pm_me_context {
	/** Managed Entity data for history intervals */
	void *interval[OMCI_PM_INTERVAL_MAX];
	/** TCA bitmap */
	uint8_t tca_bitmap[OMCI_ALARM_BITMAP_SIZE];
	/** Threshold values */
	uint32_t thr[PM_THR_NUM];
};

/** PM list entry */
struct pm_list_entry {
	/** Managed Entity pointer */
	struct me *me;
};

/** PM Managed Entity counters get handler

    Retrieved counters data is stored in the Managed Entity data (me->data)

   \param[in] context  OMCI context pointer
   \param[in] me       Managed Entity pointer
   \param[in] interval 15-min interval:
                        - 0 for current data
                        - 1 for history data
*/
typedef enum omci_error (pm_counters_get_handler) (struct omci_context *context,
						   struct me *me,
						   enum omci_pm_interval interval);

/** PM Managed Entity thresholds set handler

   \param[in] context    OMCI context pointer
   \param[in] me         Managed Entity pointer
   \param[in] thr        Thresholds values
*/
typedef enum omci_error (pm_thr_set_handler) (struct omci_context *context,
					      struct me *me,
					      uint32_t thr[PM_THR_NUM]);

/** Default thresholds set handler used for internally managed PM MEs

   \param[in] context    OMCI context pointer
   \param[in] me         Managed Entity pointer
   \param[in] thr        Thresholds values
*/
enum omci_error default_me_thr_set(struct omci_context *context,
				   struct me *me,
				   uint32_t thr[PM_THR_NUM]);

/** Get value of Interval End Time

   \param[in]  context   OMCI context pointer
   \param[in]  me        Managed Entity pointer
   \param[out] data      Pointer to data which will be filled up within the
                         function
   \param[in]  data_size Data size
*/
enum omci_error pm_interval_end_time_get(struct omci_context *context,
					 struct me *me,
					 void *data,
					 size_t data_size);

/** Update PM Managed Entity counters (retrieve from driver)

   \param[in] context  OMCI context pointer
   \param[in] me       Managed Entity pointer
   \param[in] interval 15-min interval
*/
enum omci_error pm_me_counters_get(struct omci_context *context,
				   struct me *me,
				   enum omci_pm_interval interval);

/** Initialize PM module

   \param[in] context OMCI context pointer
*/
enum omci_error pm_init(struct omci_context *context);

/** Shutdown PM module

   \param[in] context OMCI context pointer
*/
enum omci_error pm_shutdown(struct omci_context *context);

/** This routine should be called in order to indicate that 15-min interval
   has been passed

   \param[in] context           OMCI context pointer
   \param[in] interval_end_time Finished interval number
*/
enum omci_error pm_interval_end(struct omci_context *context,
				uint8_t interval_end_time);

/** Allocate ME PM context

   \param[in] me       Managed Entity pointer
*/
enum omci_error pm_me_context_alloc(struct me *me);

/** Free ME PM context

   \param[in] me       Managed Entity pointer
*/
enum omci_error pm_me_context_free(struct me *me);

/** Add ME to the internal PM list

   \param[in] context  OMCI context pointer
   \param[in] me       Managed Entity pointer
*/
enum omci_error pm_me_add(struct omci_context *context,
			  struct me *me);

/** Remove ME from the internal PM list

   \param[in] context  OMCI context pointer
   \param[in] me       Managed Entity pointer
*/
enum omci_error pm_me_remove(struct omci_context *context,
			     struct me *me);

/** Select PM interval for ME

   \param[in] context  OMCI context pointer
   \param[in] me       Managed Entity pointer
   \param[in] interval PM interval
*/
void pm_me_interval_set(struct omci_context *context,
			struct me *me,
			enum omci_pm_interval interval);

/** Set the PM threshold data for ME

   \param[in] context  OMCI context pointer
   \param[in] me       Managed Entity pointer
*/
enum omci_error pm_me_thr_set(struct omci_context *context,
			     struct me *me);
#endif

/** @} */

#endif
