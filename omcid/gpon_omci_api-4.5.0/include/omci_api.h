/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_h
#define _omci_api_h

#ifdef __cplusplus
#  ifndef __BEGIN_DECLS
#     define __BEGIN_DECLS extern "C" {
#  endif
#  ifndef __END_DECLS
#     define __END_DECLS   }
#  endif
#else
#  ifndef __BEGIN_DECLS
#     define __BEGIN_DECLS
#  endif
#  ifndef __END_DECLS
#     define __END_DECLS
#  endif
#endif

__BEGIN_DECLS

/** \defgroup OMCI_API_ME OMCI Programming Interface

   This set of functions is used to implement the OMCI Managed Entities (ME)
   that are needed to operate the device in a GPON ONU application.
   Function names and attribute names are aligned with the definitions given
   by ITU-T G.984.4 and ITU-T G.988.
   @{
*/

/** OMCI API context */
struct omci_api_ctx;

/** Function return status */
enum omci_api_return {
	/** Device indicates no data available */
	OMCI_API_WRN_DEV_NO_DATA = 1,
	/** Function exited successfully */
	OMCI_API_SUCCESS = 0,
	/** Function exited with an error */
	OMCI_API_ERROR = -1,
	/** Item/element was not found */
	OMCI_API_NOT_FOUND = -2,
	/** Resource not available */
	OMCI_API_NOT_AVAIL = -3,
	/** Memory allocation error */
	OMCI_API_NO_MEMORY = -4
};

/** API debug module */
enum omci_api_dbg_module {
	/** Common API module*/
	OMCI_API_DBG_MODULE_API = 0,
	/** VoIP module*/
	OMCI_API_DBG_MODULE_VOIP = 1,
	/** MCC module*/
	OMCI_API_DBG_MODULE_MCC = 2
};

/** Structure to specify OMCI API initialization parameters*/
struct omci_api_init_data {
	bool dummy;
};

/** Maximum length of version strings in
   \ref omci_api_ver_inf */
#define OMCI_API_MAX_INFO_STRING_LEN                       80

/** Action type */
enum omci_api_action_type {
	OMCI_API_ACTION_CREATE,
	OMCI_API_ACTION_UPDATE,
	OMCI_API_ACTION_DESTROY
};

/** Priority Queue Direction
*/
enum omci_api_queue_direction {
	/** Upstream only */
	OMCI_API_QUEUE_DIRECTION_UPSTREAM = 1,
	/** Downstream only */
	OMCI_API_QUEUE_DIRECTION_DOWNSTREAM = 2
};

/** GEM Port Direction
*/
enum omci_api_gem_port_direction {
	/** Upstream only */
	OMCI_API_GEM_PORT_DIRECTION_UPSTREAM = 1,
	/** Downstream only */
	OMCI_API_GEM_PORT_DIRECTION_DOWNSTREAM = 2,
	/** Both */
	OMCI_API_GEM_PORT_DIRECTION_BOTH = 3
};

/** OMCI API event */
struct omci_api_event {
	enum {
		OMCI_API_EVENT_ALARM,
		OMCI_API_EVENT_OMCI,
		OMCI_API_EVENT_PLOAM_STATE,
		OMCI_API_EVENT_INTERVAL_END,
		OMCI_API_EVENT_ERROR,
		OMCI_API_EVENT_LINK_STATE,
		OMCI_API_EVENT_AC_POWER_ON,
		OMCI_API_EVENT_AC_POWER_OFF
	} type;

	union {
		struct {
			uint16_t class_id;
			uint16_t instance_id;
			uint8_t alarm;
			bool active;
		} alarm;

		struct {
			uint8_t msg[48];
		} omci;

		struct {
			int prev;
			int curr;
		} ploam_state;

		struct {
			uint8_t interval_end_time;
		} interval_end;

		struct {
			uint16_t class_id;
			uint16_t instance_id;
			enum omci_api_action_type action;
			enum omci_api_return ret;
		} error;

		struct {
			/** PPTP Ethernet UNI instance id */
			uint16_t instance_id;
			bool state;
			/** PPTP Ethernet UNI configuration indication */
			uint8_t config_ind;
		} link_state;
	};
};

struct bridge_port_data {
	uint16_t me_id;
	uint8_t tp_type;
	uint16_t tp_ptr;
};

#define BRIDGE_DATA_PORT 16

struct bridge_data {
	uint16_t me_id;
	struct bridge_port_data port[BRIDGE_DATA_PORT];
	uint16_t count;
};

struct pmapper_data {
	uint16_t me_id;
	uint16_t bridge_port_me_id[8];
	uint16_t bridge_me_id[8];
	uint16_t count;
};

/** OMCI API event handler */
typedef void (omci_api_event_handler_t)(void *caller,
					struct omci_api_event *event);

/** Count CRC-32 as defined in ITU-T I.363.5

   \param p_data data pointer
   \param data_sz Size of data in bytes

   \return CRC-32
*/
uint32_t omci_api_calc_checksum_crc32_i363(const void *p_data, size_t data_sz);

/** Create the device. To be called once.

   \param[in]     init       Init data
   \param[in]     handler    Event handler pointer
   \param[in]     caller_ctx Caller context pointer
   \param[in]     remote_ip  IP address of remote ONU
   \param[in]     uni2lan    UNI to LAN mapping info
   \param[in,out] p_ctx      OMCI API context pointer
*/
enum omci_api_return omci_api_init(struct omci_api_init_data *init,
				   omci_api_event_handler_t *handler,
				   void *caller_ctx,
				   const char *remote_ip,
				   const char *uni2lan,
				   struct omci_api_ctx **p_ctx );

/** Make the basic initialization (interrupt enable etc.). To be called once.

   \param[in] ctx OMCI API context pointer
*/
enum omci_api_return omci_api_start(struct omci_api_ctx *ctx);

/** Terminate device. To be called once.

   \param[in] ctx OMCI API context pointer
*/
enum omci_api_return omci_api_shutdown(struct omci_api_ctx *ctx);

/** Send OMCI message

   \param[in] ctx OMCI API context pointer
   \param[in] msg OMCI message data
   \param[in] len OMCI message length
*/
enum omci_api_return omci_api_msg_send(struct omci_api_ctx *ctx,
				       const uint8_t *msg, const uint16_t len);

/** Version information strings */
struct omci_api_ver_inf {
	/** Driver version */
	char driver_version[OMCI_API_MAX_INFO_STRING_LEN];

	/** OMCI API version */
	char omci_api_version[OMCI_API_MAX_INFO_STRING_LEN];
};

/** Get version of the OMCI API

   \param[in]  ctx OMCI API context pointer
   \param[out] ver Returns version string
*/
enum omci_api_return omci_api_ver_inf_get(struct omci_api_ctx *ctx,
					  struct omci_api_ver_inf *ver);

/** Reboot ONU

   \param[in] timeout_ms Reboot in timeout_ms (in ms)

   \note This function is non-blocking! For blocking reboot please use
         IFXOS_Reboot
*/
enum omci_api_return omci_api_reboot(time_t timeout_ms);

/** Reset all mappings (for MIB reset)

   \param[in] ctx OMCI API context pointer
*/
enum omci_api_return omci_api_mapper_reset(struct omci_api_ctx *ctx);

/** Dump all mapping information

   \param[in] ctx OMCI API context pointer
*/
enum omci_api_return omci_api_mapper_dump(struct omci_api_ctx *ctx);

/** Set debug level
    0 - message
    1 - print
    2 - warnings
    3 - errors
    4 - off

   \param[in] module debug module
   \param[in] level new error level
*/
void omci_api_debug_level_set(const enum omci_api_dbg_module module,
			      const uint8_t level);

/** Get debug level
    0 - message
    1 - print
    2 - warnings
    3 - errors
    4 - off

   \param[in] module debug module
   \param[out] level new error level
*/
void omci_api_debug_level_get(const enum omci_api_dbg_module module,
			      uint8_t *level);

/** Get LAN port index based on the MEID value.

   \param[in] ctx OMCI API context pointer
   \param[in] me_id ME instance ID
   \param[out] lan_port LAN port index
*/
enum omci_api_return omci_api_uni2lan(struct omci_api_ctx *ctx,
				      const uint16_t me_id,
				      uint8_t *lan_port);

/** @} */

__END_DECLS

#endif
