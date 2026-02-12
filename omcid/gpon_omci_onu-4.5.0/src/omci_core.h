/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_core_h
#define _omci_core_h

#include "ifx_fifo.h"

#include "omci_os.h"
#include "omci_interface.h"
#include "omci_me.h"

/** \defgroup OMCI_CORE Optical Network Unit - Core

   @{
*/
/** Maximum number of concurrent table attributes copy (for different Managed
   Entities and attributes) */
#define OMCI_TABLE_COPY_NUM				5

/** Lock context */
void context_lock(struct omci_context *context);

/** Unlock context */
void context_unlock(struct omci_context *context);

/** Lock table attributes copies */
void table_copy_lock(struct omci_context *context);

/** Unlock table attributes copies */
void table_copy_unlock(struct omci_context *context);

/** Copy of the table attribute for the get next message purposes */
struct tbl_copy_entry {
	/** Class identifier of copy */
	uint16_t class_id;

	/** Instance identifier of copy */
	uint16_t instance_id;

	/** Attribute number of copy [1 .. \ref OMCI_ATTRIBUTES_NUM] */
	unsigned int attr;

	/** Attribute copy data */
	void *data;

	/** Attribute copy data size */
	size_t data_size;

	/** Should timeout handler free data?

	    By default is set to true.

	    Helpful when you need to use static (non-heap) memory in the
	    timeout handler. */
	bool free_data;

	/** timeout identifier of timeout event which should clear this data */
	unsigned long timeout_id;

	/** Is data is valid (becomes invalid after cleanup) */
	bool valid;
};

/** Copy of the table attributes */
struct tbl_copy {
	/** Managed Entities table attributes copies */
	struct tbl_copy_entry array[OMCI_TABLE_COPY_NUM];

	/** Table attribute copy lock */
	IFXOS_lock_t lock;
};

/** OMCI Messages FIFO */
struct msg_fifo {
	/** Received messages FIFO */
	IFX_VFIFO fifo;

	/** Received messages FIFO buffer */
	void *buf;
};

#include "omci_mib.h"

/** Holds response retransmit data */
struct retransmit {
	/** Retransmit data */
	struct {
		/** Valid/invalid entry indication */
		bool valid;
		/** Incoming message transaction id */
		uint16_t tci;
		/** Response sent */
		union omci_msg rsp;
	} data[2];
};

/** Maximum number of US priority Queues*/
#define OMCI_US_PRIORITY_QUEUE_MAX	64

struct map_gem2pqueue {
	/** Priority Queue ID*/
	uint16_t pqueue_id;
	/** GEM port ID*/
	uint16_t gem_port_id;
	/** Map indicator*/
	bool mapped;
};

/** message action context */
struct action_handler {
	/** message handling is executed */
	volatile bool run;
	/** message handling result is ready, response is updated */
	volatile bool ready;
	/** message input */
	union omci_msg msg;
	/** message handling response */
	union omci_msg rsp;
	/** message handling result */
	volatile enum omci_error handler_error;
};

/** Default OMCI message action timeout (shipping v7.5.1 uses 900) */
#define OMCI_DEFAUL_MAX_ACTION_TIMEOUT		900

/** OMCI context */
struct omci_context {
	/** ONU ID */
	uint16_t onu_id;

	/** Guessed or actual OLT */
	enum omci_olt olt;

	/** Startup time (in ms) */
	time_t startup_time;

	/** MIB */
	struct mib mib;

	/** MIB copy */
	struct mib_copy mib_copy;

	/** Alarms copy */
	struct alarm_copy alarm_copy;

	/** Table attributes copy */
	struct tbl_copy tbl_copy;

	/** Retransmit data */
	struct retransmit retransmit;

	/** timeout list */
	struct list timeout_list;

	/** Last used timeout identifier (this used for timeout identifier
	    generation) */
	unsigned long last_timeout_id;

	/** Core thread control structure */
	IFXOS_ThreadCtrl_t core_thread_ctrl;

	/** OMCI message event */
	IFXOS_event_t msg_event;

	/** Action thread control structure */
	IFXOS_ThreadCtrl_t action_thread_ctrl;

	/** Action event */
	IFXOS_event_t action_event;

	/** Action handled event — signaled when action thread completes
	    processing. Core thread waits on this instead of polling. */
	IFXOS_event_t action_handled_event;

	/** Timeout thread control structure */
	IFXOS_ThreadCtrl_t timeout_thread_ctrl;

	/** Received messages FIFO */
	struct msg_fifo msg_fifo;

	/** Received messages count */
	unsigned long omci_received;

	/** Sent messages count */
	unsigned long omci_sent;

	/** Enable(true)/disable(false) OMCI processing */
	bool omci_enabled;

	/** Indicates whether device can reboot or not. Used to protect some
	   critical actions (e.g. Software Download). 0 means that device can
	   safely reboot */
	unsigned int cant_reboot;

	/** MIB on reset handler */
	omci_mib_on_reset *mib_on_reset;
#ifdef INCLUDE_CLI_SUPPORT
	/** CLI command execute handler */
	omci_cli_on_exec *cli_on_exec;
#endif
	/** Context lock */
	IFXOS_lock_t lock;

	/** OMCI API context */
	struct omci_api_ctx *api;

#ifdef INCLUDE_PM
	/** PM context */
	struct pm_context pm;
#endif
	/** ONU-G Traffic Management Option Capability */
	uint8_t traffic_management_opt;
	/** US Priority Queue mapping */
	struct map_gem2pqueue map_gem2pqueue[OMCI_US_PRIORITY_QUEUE_MAX];

	/** Failsafe mode - always return \ref OMCI_MR_CMD_SUCCESS in the
	   OMCI response */
	bool failsafe;

	/** message handler action context */
	struct action_handler action;

	/** OMCI message action timeout after which BUSY response is sent */
	uint32_t action_timeout;

	/** IOP (Interoperability Option) mask */
	uint32_t iop_mask;

	/** OMCC version byte */
	uint8_t omcc_version;

	/** LCT port number (0xFF = not configured) */
	uint8_t lct_port;
};

/** Find timeouted entry in table attribute copy array and return its pointer

   \param[in]  context     OMCI context pointer
   \param[in]  class_id    Managed Entity class identifier
   \param[in]  instance_id Managed Entity instance identifier
   \param[in]  attr        Attribute number [1 .. \ref OMCI_ATTRIBUTES_NUM]
   \param[out] tbl_copy    Returns pointer to new attribute copy entry
*/
enum omci_error me_tbl_copy_empty_get(struct omci_context *context,
				      uint16_t class_id,
				      uint16_t instance_id,
				      unsigned int attr,
				      struct tbl_copy_entry **tbl_copy);

/** Find table attribute and return its pointer

   \param[in]  context     OMCI context pointer
   \param[in]  class_id    Managed Entity class identifier
   \param[in]  instance_id Managed Entity instance identifier
   \param[in]  attr        Attribute number [1 .. \ref OMCI_ATTRIBUTES_NUM]
   \param[out] tbl_copy    Returns pointer to the attribute copy entry
*/
enum omci_error me_tbl_copy_find(struct omci_context *context,
				 uint16_t class_id,
				 uint16_t instance_id,
				 unsigned int attr,
				 struct tbl_copy_entry **tbl_copy);

/** Handle OMCI Message

   \param[in]  context OMCI context pointer
   \param[in]  msg     OMCI Message pointer
   \param[out] rsp     Returns response to given OMCI Message
*/
enum omci_error msg_handle(struct omci_context *context,
			   const union omci_msg *msg,
			   union omci_msg *rsp);

/** Initialize received messages FIFO

   \param[in] context OMCI context pointer
*/
enum omci_error msg_fifo_init(struct omci_context *context);

/** Shutdown received messages FIFO

   \param[in] context OMCI context pointer
*/
enum omci_error msg_fifo_shutdown(struct omci_context *context);

/** Initialize table attributes copy

   \param[in] context OMCI context pointer
*/
enum omci_error tbl_copy_init(struct omci_context *context);

/** Shutdown table attributes copy

   \param[in] context OMCI context pointer
*/
enum omci_error tbl_copy_shutdown(struct omci_context *context);

/** Start core thread

   \param[in] context OMCI context pointer
*/
enum omci_error core_thread_start(struct omci_context *context);

/** Stop core thread

   \param[in] context OMCI context pointer
*/
enum omci_error core_thread_stop(struct omci_context *context);

/** Start message handler thread

   \param[in] context OMCI context pointer
*/
enum omci_error action_thread_start(struct omci_context *context);

/** Stop message handler thread

   \param[in] context OMCI context pointer
*/
enum omci_error action_thread_stop(struct omci_context *context);

/** create empty response to a given message

   \param[in]  msg Input message
   \param[out] rsp Returns blank response to given message
*/
enum omci_error rsp_create(const union omci_msg *msg, union omci_msg *rsp);

/** Send AVC message

   \param[in] context OMCI context pointer
   \param[in] me      Managed Entity pointer
   \param[in] attr    Changed attribute [1 .. \ref OMCI_ATTRIBUTES_NUM]
 */
enum omci_error avc_send(struct omci_context *context,
			 struct me *me,
			 unsigned int attr);

/** Send AVC message after a sertain period of time

   \param[in] context OMCI context pointer
   \param[in] me      Managed Entity pointer
   \param[in] attr    Changed attribute [1 .. \ref OMCI_ATTRIBUTES_NUM]
   \param[in] timeout Timeout time (in milliseconds)
 */
enum omci_error avc_send_delayed(struct omci_context *context,
				 struct me *me,
				 unsigned int attr,
				 unsigned int timeout);

/** Send alarm bitmap (mask) for given Managed Entity

   \param[in] context OMCI context pointer
   \param[in] me      Managed Entity pointer
*/
enum omci_error alarm_send(struct omci_context *context,
			   const struct me *me);

/** Send Threshold crossing alert for given Managed Entity and given Threshold
   bitmap

   \param[in] context    OMCI context pointer
   \param[in] me         Managed Entity pointer
   \param[in] tca_bitmap TCA bitmap
*/
enum omci_error tca_send(struct omci_context *context,
			 const struct me *me,
			 const uint8_t tca_bitmap[OMCI_ALARM_BITMAP_SIZE]);

#if defined(OMCI_SWAP)
/** Swap bytes in data regarding its size

   \param[in] data      Data pointer
   \param[in] data_size Data size
*/
enum omci_error data_swap(void *data, size_t data_size);
#endif

#if defined(OMCI_SWAP)
/** Swap attributes in data regarding given mask (attr_mask)

   \param[in] me_class  Managed Entity class pointer
   \param[in] data      Attributes data pointer
   \param[in] data_size Attributes data size
   \param[in] attr_mask Attribute mask
*/
enum omci_error attr_swap(const struct me_class *me_class,
			  void *data,
			  size_t data_size,
			  uint16_t attr_mask);
#endif

/** Flush retransmit buffer

   \param[in] context OMCI context pointer
*/
void retransmit_flush(struct omci_context *context);

void omci_handler_install(void);

/** @} */

#endif
