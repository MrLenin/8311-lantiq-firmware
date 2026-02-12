/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_interface_h
#define _omci_interface_h

#ifndef SWIG
#include <stdarg.h>
#endif

#if defined(WIN32)
#    define inline __inline
#endif

#ifndef SWIG
#include "ifxos_std_defs.h"
#include "ifxos_file_access.h"
#endif

#ifdef HAVE_CONFIG_H
#include "omci_config.h"
#endif

#include "omci_interface_types.h"
#include "omci_msg.h"

__BEGIN_DECLS

/** \defgroup OMCI_API Optical Network Unit - API

   @{
*/

#ifndef SWIG
/** Create required Managed Entities on MIB reset

   \param[in] context OMCI context pointer
*/
typedef enum omci_error (omci_mib_on_reset) (struct omci_context *context);
#endif

#ifndef SWIG
/** Execute CLI command

   \param[in] context OMCI context pointer
   \param[in] cmd     CLI command to execute
   \param[in] arg     CLI command arguments
   \param[in] out     Print command result to specified file handle
*/
typedef enum omci_error (omci_cli_on_exec) (struct omci_context *context,
					    char *cmd, char *arg,
				            IFXOS_File_t *out);
#endif

#ifndef SWIG
/** Point OMCI SW debug output to given file
 *
 * \param[in] file File pointer
 */
enum omci_error omci_dbg_file_set(IFXOS_File_t *file);
#endif

#ifndef SWIG
/** Initialize OMCI context

   \param[out] ref_context Reference to NULL pointer of type
                           struct omci_context.
                           The memory allocation and deletion will be done
                           by the library itself.
                           Returns OMCI context pointer

   \param[in] mib_on_reset MIB on reset handler
   \param[in] cli_on_exec  Routine which will be called upon CLI command execute
                           request from ONU remote debug ME
   \param[in] mib          Select default MIB
   \param[in] remote_ip    Remote ONU IP address
   \param[in] uni2lan      UNI to LAN mapping info
*/
enum omci_error omci_init(struct omci_context **ref_context,
			  omci_mib_on_reset * mib_on_reset,
			  omci_cli_on_exec *cli_on_exec,
			  enum omci_olt mib,
			  const char *remote_ip,
			  const char *uni2lan);
#endif

#ifndef SWIG
/** Shutdown OMCI context

   \param[in] context OMCI context pointer
*/
enum omci_error omci_shutdown(struct omci_context *context);
#endif

/** Maximum length of version strings in \ref omci_version */
#define OMCI_MAX_INFO_STRING_LEN                             80

/** Version information structure */
struct omci_version {
	/** OMCI stack version */
	char omci_version[OMCI_MAX_INFO_STRING_LEN];

	/** Lib IFXOS version */
	char ifxos_version[OMCI_MAX_INFO_STRING_LEN];

	/** GPON driver version */
	char onu_version[OMCI_MAX_INFO_STRING_LEN];

	/** Chip set firmware version */
	char firmware_version[OMCI_MAX_INFO_STRING_LEN];

	/** OMCI API version */
	char omci_api_version[OMCI_MAX_INFO_STRING_LEN];

};

/** Get all version related data

   \param[in]  context OMCI context pointer
   \param[out] version Pointer to the version data structure which will be
                       filled up within the function
*/
enum omci_error omci_version_info_get(struct omci_context *context,
				      struct omci_version *version);

#ifndef OMCI_DEBUG_DISABLE
/** Set module debug level

   \param[in] module Module index
   \param[in] level  Level to set
*/
enum omci_error omci_dbg_module_level_set(enum omci_dbg_module module,
					  enum omci_dbg level);
#endif

#ifndef OMCI_DEBUG_DISABLE
/** Get module debug level

   \param[in]  module Module index
   \param[out] level  Returns module debug level
*/
enum omci_error omci_dbg_module_level_get(enum omci_dbg_module module,
					  enum omci_dbg *level);
#endif

#ifndef OMCI_DEBUG_DISABLE
/** Set debug level for all modules

   \param[in] level Level to set
*/
enum omci_error omci_dbg_level_set(enum omci_dbg level);
#endif

#ifndef SWIG
/** Receive OMCI message (from OLT)

   \param[in] context OMCI context pointer
   \param[in] msg     OMCI message pointer
*/
enum omci_error omci_msg_recv(struct omci_context *context,
			      const union omci_msg *msg);
#endif

#ifndef SWIG
/** Send OMCI message (to OLT)

   \param[in] context OMCI context pointer
   \param[in] msg     OMCI message pointer
*/
enum omci_error omci_msg_send(struct omci_context *context,
			      const union omci_msg *msg);
#endif

/** Set Managed Entity alarm

   \param[in] context     OMCI context pointer
   \param[in] class_id    Managed Entity class identifier
   \param[in] instance_id Managed Entity instance identifier
   \param[in] alarm       Alarm number [0 .. \ref OMCI_ALARMS_NUM - 1]
   \param[in] active      Alarm status:
                           - true - Turn on alarm
                           - false - Turn off alarm
*/
enum omci_error omci_me_alarm_set(struct omci_context *context,
				  uint16_t class_id,
				  uint16_t instance_id,
				  unsigned int alarm, bool active);

/** Get Managed Entity alarm

   \param[in]  context     OMCI context pointer
   \param[in]  class_id    Managed Entity class identifier
   \param[in]  instance_id Managed Entity instance identifier
   \param[in]  alarm       Alarm number [0 .. \ref OMCI_ALARMS_NUM - 1]
   \param[out] active      Returns alarm status:
                            - true - Alarm is on
                            - false - Alarm is off
*/
enum omci_error omci_me_alarm_get(struct omci_context *context,
				  uint16_t class_id,
				  uint16_t instance_id,
				  unsigned int alarm,
				  bool *active);

/** Enable/disable OMCI processing

   \param[in] context OMCI context pointer
   \param[in] enable  OMCI status:
                       - true - Enable
                       - false - Disable
*/
enum omci_error omci_processing_enable(struct omci_context *context,
				       bool enable);

#ifndef SWIG
/** Create Managed Entity

   \param[in] context      OMCI context pointer
   \param[in] active       Use Managed Entity implementation
   \param[in] class_id     Managed Entity class identifier
   \param[in] instance_id  Managed Entity instance identifier
   \param[in] data         Managed Entity instance data
   \param[in] suppress_avc Suppress AVC for given attributes
*/
enum omci_error omci_me_create(struct omci_context *context,
			       const bool active,
			       const uint16_t class_id,
			       const uint16_t instance_id,
			       void *data,
			       const uint16_t suppress_avc);
#endif

/** Delete Managed Entity

   \param[in] context     OMCI context pointer
   \param[in] class_id    Managed Entity class identifier
   \param[in] instance_id Managed Entity instance identifier
*/
enum omci_error omci_me_delete(struct omci_context *context,
			       uint16_t class_id,
			       uint16_t instance_id);

#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
/** Get Managed Entity name

   \param[in]  context  OMCI context pointer
   \param[in]  class_id Managed Entity class identifier
   \param[out] name     Returns Managed Entity name
*/
enum omci_error omci_me_name_get(struct omci_context *context,
				 uint16_t class_id,
				 char name[26]);
#endif

#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
/** Get Managed Entity attribute name

   \param[in]  context   OMCI context pointer
   \param[in]  class_id  Managed Entity class identifier
   \param[in]  attr      Attribute number [1 .. \ref OMCI_ATTRIBUTES_NUM]
   \param[out] attr_name Returns attribute name
*/
enum omci_error omci_me_attr_name_get(struct omci_context *context,
				      uint16_t class_id,
				      unsigned int attr,
				      char attr_name[26]);
#endif

/** Get Managed Entity properties

   \param[in]  context  OMCI context pointer
   \param[in]  class_id Managed Entity class identifier
   \param[out] me_prop  Returns Managed Entity properties
*/
enum omci_error omci_me_prop_get(struct omci_context *context,
				 uint16_t class_id,
				 enum omci_me_prop *me_prop);

/** Get Managed Entity attribute size

   \param[in]  context   OMCI context pointer
   \param[in]  class_id  Managed Entity class identifier
   \param[in]  attr      Attribute number [1 .. \ref OMCI_ATTRIBUTES_NUM]
   \param[out] attr_size Returns attribute size

   \note For table attributes attr_size would be one entry size!
*/
enum omci_error omci_me_attr_size_get(struct omci_context *context,
				      uint16_t class_id,
				      unsigned int attr,
				      size_t *attr_size);

/** Get Managed Entity attribute properties

   \param[in]  context   OMCI context pointer
   \param[in]  class_id  Managed Entity class identifier
   \param[in]  attr      Attribute number [1 .. \ref OMCI_ATTRIBUTES_NUM]
   \param[out] attr_prop Returns attribute properties
*/
enum omci_error omci_me_attr_prop_get(struct omci_context *context,
				      uint16_t class_id,
				      unsigned int attr,
				      enum omci_attr_prop *attr_prop);

#ifndef SWIG
/** Get all Managed Entity attributes data

   \param[in]  context        OMCI context pointer
   \param[in]  class_id       Managed Entity class identifier
   \param[in]  instance_id    Managed Entity instance identifier
   \param[in]  interval       15-min interval; for PM Managed Entities only
   \param[out] attr_data      Pointer to allocated buffer which will be filled
                              up with the attribute data
   \param[in]  attr_data_size Attribute data buffer size in bytes

   \note It's not possible to get table attributes via this routine,
         please use \ref omci_me_tbl_data_get instead!
*/
enum omci_error omci_me_data_get(struct omci_context *context,
				 uint16_t class_id,
				 uint16_t instance_id,
				 enum omci_pm_interval interval,
				 void *attr_data,
				 size_t attr_data_size);

/** Get table attribute data

   \param[in]  context       OMCI context pointer
   \param[in]  class_id      Managed Entity class identifier
   \param[in]  instance_id   Managed Entity instance identifier
   \param[in]  attr          Table attribute position
   \param[out] tbl_data      Pointer to allocated buffer which will be filled
                             up with the attribute data
   \param[out] tbl_data_size Attribute data buffer size in bytes

   \note Pointer returned in tbl_data should be freed by user!
*/
enum omci_error omci_me_tbl_data_get(struct omci_context *context,
				     uint16_t class_id,
				     uint16_t instance_id,
				     unsigned int attr,
				     void **tbl_data,
				     size_t *tbl_data_size);
#endif

/** Get Managed Entity attribute format

   \param[in]  context   OMCI context pointer
   \param[in]  class_id  Managed Entity class identifier
   \param[in]  attr      Attribute number [1 .. \ref OMCI_ATTRIBUTES_NUM]
                         up with the attribute data
   \param[in]  attr_type Returns attribute format

   \note It's not possible to get table attributes via this routine!
*/
enum omci_error omci_me_attr_type_get(struct omci_context *context,
				      uint16_t class_id,
				      unsigned int attr,
				      enum omci_attr_type *attr_type);

/** Get Managed Entity attribute offset
 *
   \param[in]  context     OMCI context pointer
   \param[in]  class_id    Managed Entity class identifier
   \param[in]  attr        Attribute number [1 .. \ref OMCI_ATTRIBUTES_NUM]
                           up with the attribute data
   \param[in]  attr_offset Returns attribute offset
*/
enum omci_error omci_me_attr_offset_get(struct omci_context *context,
					uint16_t class_id,
					unsigned int attr,
					size_t *attr_offset);

#ifndef SWIG
/** Get Managed Entity alarm bitmap

   \param[in]  context      OMCI context pointer
   \param[in]  class_id     Managed Entity class identifier
   \param[in]  instance_id  Managed Entity instance identifier
   \param[out] alarm_bitmap Pointer to allocated alarm bitmap array which
                            will be filled up within the function
*/
enum omci_error omci_me_alarm_bitmap_get(struct omci_context *context,
					 uint16_t class_id,
					 uint16_t instance_id,
					 uint8_t alarm_bitmap
					 [OMCI_ALARM_BITMAP_SIZE]);
#endif

/** Get number of Managed Entities in the MIB

   \param[in]  context OMCI context pointer
   \param[out] count   Returns Managed Entity count
*/
enum omci_error omci_me_count_get(struct omci_context *context,
				  size_t *count);

/** Managed Entity instance structure */
struct omci_me {
	/** Entity class ID */
	uint16_t class_id;

	/** Entity instance ID */
	uint16_t instance_id;
};

#ifndef SWIG
/** Get array of Managed Entities in the MIB

   \param[in]  context    OMCI context pointer
   \param[out] array      Pointer to the buffer which will be filled with
                          Managed Entity list
   \param[in]  array_size Size of the buffer in bytes; Should be >= number
                          of Managed Entities in the MIB *
                          sizeof(\ref omci_me)
*/
enum omci_error omci_me_list_get(struct omci_context *context,
				 struct omci_me *array,
				 size_t array_size);
#endif

/** Inform OMCI stack that attribute has been changed autonomously

   \param[in]  context     OMCI context pointer
   \param[in]  class_id    Managed Entity class identifier
   \param[in]  instance_id Managed Entity instance identifier
   \param[in]  attr        Attribute number [1 .. \ref OMCI_ATTRIBUTES_NUM]
*/
enum omci_error omci_attr_change(struct omci_context *context,
				 uint16_t class_id,
				 uint16_t instance_id,
				 uint16_t attr);

/** Inform OMCI stack that 15-min interval has been ended

   \param[in] context           OMCI context pointer
   \param[in] interval_end_time Finished interval number
*/
enum omci_error omci_interval_end(struct omci_context *context,
				  uint8_t interval_end_time);

/** Get name/type of the connected OLT

   \param[in]  context  OMCI context pointer
   \param[out] pOlt     OLT name/type
*/
enum omci_error omci_olt_get(struct omci_context *context,
			     enum omci_olt *pOlt);

/** Reset MIB

   \param[in] context OMCI context pointer
*/
enum omci_error omci_mib_reset(struct omci_context *context);

/** Check if Managed Entity is supported

   \param[in] context  OMCI context pointer
   \param[in] class_id Managed Entity class identifier

   \return
       - \ref omci_error::OMCI_ERROR_ME_NOT_SUPPORTED in specified class ID
              is not supported
       - \ref omci_error::OMCI_SUCCESS on success
*/
enum omci_error omci_me_is_supported(struct omci_context *context,
				     uint16_t class_id);

/** Enable/disable failsafe mode

   \param[in] context OMCI context pointer
   \param[in] enable  Enable (true) or disable (false)
*/
enum omci_error omci_failsafe_enable(struct omci_context *context,
				     bool enable);

/** Change OMCI message action timeout after which BUSY response is sent

   \param[in] context        OMCI context pointer
   \param[in] action_timeout Action timeout
*/
enum omci_error omci_action_timeout_set(struct omci_context *context,
					uint32_t action_timeout);

/** Get OMCI message action timeout after which BUSY response is sent

   \param[in]  context        OMCI context pointer
   \param[out] action_timeout Action timeout
*/
enum omci_error omci_action_timeout_get(struct omci_context *context,
					uint32_t *action_timeout);

/** Get number of OMCI messages (to be handled) in the message queue

   \param[in]  context OMCI context pointer
   \param[out] num     Number of messages to be handled
*/
enum omci_error omci_msg_num_get(struct omci_context *context,
				 unsigned int *num);

#ifndef SWIG
/** Get OMCI API context pointer
   \param[in]  context OMCI context pointer
*/
void *omci_api_ctx_get(struct omci_context *context);
#endif

/** Send AVC message for the given attribute

   \param[in] context     OMCI context pointer
   \param[in] class_id    Managed Entity class identifier
   \param[in] instance_id Managed Entity instance identifier
   \param[in] attr        Attribute number [1 .. \ref OMCI_ATTRIBUTES_NUM]
*/
enum omci_error omci_attr_avc_send(struct omci_context *context,
				   uint16_t class_id,
				   uint16_t instance_id,
				   unsigned int attr);

#ifndef SWIG
/** vprintf wrapper (default stdout) */
void omci_vprintf(const char *fmt, va_list args);

/** printf wrapper (default stdout) */
void omci_printf(const char *fmt, ...);

/** printf wrapper (stderr) */
void omci_printfe(const char *fmt, ...);
#endif

/** @} */

__END_DECLS

#endif
