/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_timeout_h
#define _omci_timeout_h

#include "ifxos_lock.h"

/** \defgroup OMCI_TIMEOUT Optical Network Unit - Timeout Support
   @{
*/

struct timeout;

/** timeout handler */
typedef enum omci_error (timeout_handler) (struct omci_context *context,
					   struct timeout *timeout);

/** timeout descriptor structure */
struct timeout {
	/** timeout argument */
	unsigned long arg1;

	/** timeout argument */
	unsigned long arg2;

	/** timeout argument */
	unsigned long arg3;

	/** class id (if available), otherwise 0 */
	unsigned short class_id;

	/** instance id (if available), otherwise 0 */
	unsigned short instance_id;

	/** timeout handler */
	timeout_handler *handler;
};

/** timeout list entry */
struct timeout_list_entry {
	/** Time when the timeout becomes active (in milliseconds) */
	time_t timeout_time;

	/** Unique timeout ID */
	unsigned long timeout_id;

	/** timeout descriptor */
	struct timeout timeout;
};

/** Initialize timeout module

   \param[in] context OMCI context pointer
*/
enum omci_error timeout_init(struct omci_context *context);

/** Shutdown timeout module

   \param[in] context OMCI context pointer
*/
enum omci_error timeout_shutdown(struct omci_context *context);

/** Add timeout event

   \param[in]  context      OMCI context pointer
   \param[out] timeout_id   Returns generated timeout identifer
   \param[in]  timeout_time Timeout value (in milliseconds)
   \param[in]  handler      Timeout handler
   \param[in]  class_id     Timeout emitting Managed Entity class id
   \param[in]  instance_id  Timeout emitting Managed Entity instance id
   \param[in]  arg1         Timeout argument
   \param[in]  arg2         Timeout argument
   \param[in]  arg3         Timeout argument
*/
enum omci_error timeout_event_add(struct omci_context *context,
				  unsigned long *timeout_id,
				  time_t timeout_time,
				  timeout_handler *handler,
				  unsigned short class_id,
				  unsigned short instance_id,
				  unsigned long arg1,
				  unsigned long arg2,
				  unsigned long arg3);

/** Remove timeout event with given timeout identifier

   \param[in] context    OMCI context pointer
   \param[in] timeout_id timeout identifier
*/
enum omci_error timeout_event_remove(struct omci_context *context,
				     unsigned long timeout_id);

/** Start timeout thread

   \param[in] context OMCI context pointer
*/
enum omci_error timeout_thread_start(struct omci_context *context);

/** Stop timeout thread

   \param[in] context OMCI context pointer
*/
enum omci_error timeout_thread_stop(struct omci_context *context);

/** @} */

#endif
