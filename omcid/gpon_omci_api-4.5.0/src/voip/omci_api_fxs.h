/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_fxs_h
#define _omci_api_fxs_h

#include "omci_api.h"
#include "vmmc_io.h"
#include "drv_tapi_io.h"
#include "drv_tapi_qos_io.h"
#include "drv_vmmc_errno.h"
/** \todo add to installation path to get TAPI_Status_t definition
*/
/*#include "drv_tapi_errno.h"*/

__BEGIN_DECLS

/** \addtogroup OMCI_API_VOIP_FXS

   @{
*/

/** Maximum number of supported FXS*/
#define OMCI_API_FXS_MAX		2

/** Voice device base name*/
#define OMCI_API_VOICE_DEV_BASE_NAME	"/dev/vmmc"
/** Voice firmware */
#define OMCI_API_VOICE_DEV_FW_NAME   	"/lib/firmware/falcon_voip_fw.bin"
/** Voice coefficients*/
#define OMCI_API_VOICE_DEV_BBD_NAME	"/lib/firmware/falcon_bbd.bin"

/** FXS select timeout*/
#define FXS_SELECT_TIMEOUT_MS		1000
/** Maximum number of digits in the dialed number */
#define FXS_DIAL_NUM_COUNT_MAX		7

#define FXS_DTMF_LEVEL_A_DEFAULT	(-110)
#define FXS_DTMF_LEVEL_B_DEFAULT	(-90)
#define FXS_DTMF_CADENCE0_DEFAULT	(100)

/** Jitter Buffer min time, ms*/
#define FXS_JB_MIN_TIME_DEFAULT	(10)
/** Jitter Buffer max time, ms*/
#define FXS_JB_MAX_TIME_DEFAULT	(180)

/** Minimum Hook Flash time, ms*/
#define FXS_HOOK_FLASH_MIN_TIME_DEFAULT	(40)
/** Maximum Hook Flash time, ms*/
#define FXS_HOOK_FLASH_MAX_TIME_DEFAULT	(200)


/** Enumeration to specify stream type.
*/
enum fxs_stream_type {
	/** stream not specified*/
	FXS_STREAM_UNKNOWN = -1,
	/** voice stream*/
	FXS_STREAM_VOICE = 0,
	/** T38 fax stream*/
	FXS_STREAM_T38_FAX = 1
};

/** Structure to identify last error code in the FXS device
*/
struct fxs_last_err {
	/** High level error. \todo use TAPI_Status_t here. */
	uint16_t high;
	/** Low level error*/
	VMMC_status_t low;
};

struct fxs_dial_num {
	/** Dialed ASCII digits*/
	char num[FXS_DIAL_NUM_COUNT_MAX];
	/** The last dialed character position*/
	uint8_t c;
};

/** Structure to identify connection information.
*/
struct fxs_conn_info {
	/** Source IP address in network byte order*/
	uint32_t src_addr;
	/** Source IP port*/
	uint16_t src_port;
	/** Destination IP address in network byte order*/
	uint32_t dst_addr;
	/** Destination IP port*/
	uint16_t dst_port;
};

/** Structure to identify stream information.
*/
struct fxs_stream_info {
	/** stream id*/
	uint8_t id;
	/** stream type*/
	enum fxs_stream_type type;
	/** connection info*/
	struct fxs_conn_info conn;
};

/**
*/
struct fxs_data {
	/** Control FD*/
	int ctrl_fd;
	/** Channel FD*/
	int ch_fd[OMCI_API_FXS_MAX];
	/** RTP stream socket FD */
	int stream_sock_fd[OMCI_API_FXS_MAX];
	/** RTP stream TOS value */
	uint8_t stream_rtp_tos[OMCI_API_FXS_MAX];
	/** Dialed number*/
	struct fxs_dial_num dial_num[OMCI_API_FXS_MAX];
	/** Last off-hook event time */
	IFX_time_t offhook_time[OMCI_API_FXS_MAX];
	/** Number of dialing events after last off-hook */
	unsigned int dialing_events[OMCI_API_FXS_MAX];
	/** Max off-hook .. on-hook duration */
	IFX_time_t max_offhook_duration[OMCI_API_FXS_MAX];
	/** Number of events without dialing events */
	unsigned int abandoned_calls[OMCI_API_FXS_MAX];
};

/** Initialize FXS.
*/
enum omci_api_return fxs_init(struct omci_api_ctx *ctx);

/** Deinitialize FXS.
*/
enum omci_api_return fxs_exit(struct omci_api_ctx *ctx);

/** Get FXS event
*/
enum omci_api_return fxs_event_get(const struct fxs_data *fxs,
				   IFX_TAPI_EVENT_t *tapi_event);

/** Enable/disable the line
*/
enum omci_api_return fxs_phone_enable(const struct fxs_data *fxs,
				      const uint16_t id,
				      const bool enable);

/** Stop playing any local tone
*/
enum omci_api_return fxs_local_tone_stop(const struct fxs_data *fxs,
					 const uint16_t id);

/** Play local dial tone
*/
enum omci_api_return fxs_local_dial_tone_play(const struct fxs_data *fxs,
					      const uint16_t id);

/** Play local busy tone
*/
enum omci_api_return fxs_local_busy_tone_play(const struct fxs_data *fxs,
					      const uint16_t id);

/** Play local ringback tone
*/
enum omci_api_return fxs_local_ringback_tone_play(const struct fxs_data *fxs,
						  const uint16_t id);

/** Control FXS ringing
*/
enum omci_api_return fxs_ring_ctrl(const struct fxs_data *fxs,
				   const uint16_t id,
				   const bool start);

/** Set FXS codec type.
*/
enum omci_api_return fxs_codec_set(const struct fxs_data *fxs,
				   const uint8_t src_id,
				   const enum voip_codec codec);

/** Function to create FXS voice stream.
*/
enum omci_api_return fxs_stream_start(struct fxs_data *fxs,
				      const struct fxs_stream_info *inf);

/** Function to delete FXS voice stream.
*/
enum omci_api_return fxs_stream_stop(struct fxs_data *fxs,
				     const uint8_t id);

enum omci_api_return fxs_hook_status_get(const struct fxs_data *fxs,
					 const uint8_t id,
					 bool *off_hook);

/** Function to configure Jitter Buffer setting

   \param[in] fxs_data              FXS specific data
   \param[in] id                    FXS id (port number)
   \param[in] jitter_target         JB target size, ms, 0 - adaptive
   \param[in] jitter_buffer_max     JB max size, ms
*/
enum omci_api_return fxs_jb_cfg_set(const struct fxs_data *fxs,
				    const uint8_t id,
				    const uint16_t jitter_target,
				    const uint16_t jitter_buffer_max);

/** Function to enable/disable phone Line Echo Canceller

   \param[in] fxs_data              FXS specific data
   \param[in] id                    FXS id (port number)
   \param[in] en                    LEC enable/disable
*/
enum omci_api_return fxs_phone_lec_enable(const struct fxs_data *fxs,
					  const uint8_t id,
					  const bool en);

/** Function to set DTMF configuration
*/
enum omci_api_return fxs_dtmf_cfg_set(const struct fxs_data *fxs,
				      const uint8_t id,
				      const uint16_t dtmf_digit_levels,
				      const uint16_t dtmf_digit_duration);

/** Function to set Hook flashing time
*/
enum omci_api_return fxs_hook_flash_cfg_set(const struct fxs_data *fxs,
					    const uint8_t id,
					    const uint16_t hook_flash_min_time,
					    const uint16_t hook_flash_max_time);

/** Function to retrieve RTP packet loss
*/
enum omci_api_return fxs_rtp_pkt_loss_get(const struct fxs_data *fxs,
					  const uint8_t id,
					  uint32_t *pkt_loss);

/** Function to retrieve Jitter Buffer statistics
*/
enum omci_api_return fxs_jb_stat_get(const struct fxs_data *fxs,
				     const uint8_t id,
				     uint32_t *rtp_errors,
				     uint32_t *max_jitter,
				     uint32_t *buffer_overflows);

/** Set FXS debug level */
void fxs_debug_level_set(uint8_t level);

/** @} */

__END_DECLS

#endif

