/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_voip_h
#define _omci_api_voip_h

__BEGIN_DECLS

/** \addtogroup OMCI_API_VOIP

   @{
*/

#define OMCI_API_RFC5237_PROTO_IPV6	(0)
#define OMCI_API_RFC5237_PROTO_TCP	(6)
#define OMCI_API_RFC5237_PROTO_UDP	(17)

#define OMCI_API_URI_MAX		376 /* 15 * 25 + 1 */
#define OMCI_API_USERNAME_MAX		51

/** Default RTP stream TOS value */
#define OMCI_API_STREAM_RTP_TOS_DEFAULT (0xB8)

/** SIP registration expiration time in seconds */
#define OMCI_API_SIP_REG_EXP_TIME_DEFAULT_SEC	(3600)

/** Codecs definition according to rfc2327.
*/
enum voip_codec {
	/** Not available*/
	CODEC_NA = -1,
	/** G.711 ALaw*/
	CODEC_G711A = 8,
	/** G729*/
	CODEC_G729 = 18
};

/** SIP agent.
*/
struct sip_agent {
	/** SIP transport layer port number*/
	uint16_t agent_port;
	/** IP address*/
	uint32_t agent_ip;
	/** SIP agent protocol (see RFC5237)*/
	uint16_t agent_proto;
	/** Specifies the SIP registration expiration time in seconds. If its
	value is 0, the SIP agent does not add an expiration time to the
	registration requests and does not perform re-registration. The default
	value is 3600 seconds.*/
	uint32_t reg_exp_time;
	/** Registrar URL*/
	char registrar[OMCI_API_URI_MAX];
	/** Proxy URL*/
	char proxy[OMCI_API_URI_MAX];
};

/** SIP agent counters.
*/
struct sip_agent_counters {
	/** Transactions */
	uint32_t transactions;
	/** Total Rx invite requests including retx*/
	uint32_t rx_total_invite_reqs;
	/** Rx invite requests excluding retx*/
	uint32_t rx_invite_reqs;
	/** Total Rx noninvite requests including retx*/
	uint32_t rx_total_noninvite_reqs;
	/** Total Rx noninvite requests including retx*/
	uint32_t rx_noninvite_reqs;
	/** Total Rx response including retx*/
	uint32_t rx_total_response;
	/** Rx response*/
	uint32_t rx_response;
	/** Rx invite response*/
	uint32_t rx_invite_response;
	/** Total Tx invite requests including retx*/
	uint32_t tx_total_invite_reqs;
	/** Tx invite requests*/
	uint32_t tx_invite_reqs;
	/** Total Tx noninvite requests including retx*/
	uint32_t tx_total_noninvite_reqs;
	/** Tx noninvite requests*/
	uint32_t tx_noninvite_reqs;
	/** Total Tx response including retx */
	uint32_t tx_total_response;
	/** Tx response */
	uint32_t tx_response;
	/** Count the number of times the SIP UA timed out during SIP call
	    initiations. */
	uint32_t sip_init_timout;
	/** Counts the number of times the SIP UA failed to reach/connect its
	    TCP/UDP peer during SIP call initiations. */
	uint32_t sip_init_failed_to_connect;
	/** Counts the number of times the SIP UA received a failure error code
	    during SIP call initiations.*/
	uint32_t sip_init_failure_received;
	/** Counts the number of times the SIP UA failed to validate its peer
	    during SIP call initiations. */
	uint32_t sip_init_validate_fail;
	/** This attribute counts the number of times the SIP UA failed to
	    authenticate itself during SIP call initiations.*/
	uint32_t sip_init_auth_fail;
};

/** SIP user.
*/
struct sip_user {
	/** Username*/
	char username[OMCI_API_USERNAME_MAX];
	/** Password*/
	char password[25];
	/** Password*/
	char realm[25];
	/** media layer port number*/
	uint16_t user_port;
	/** media layer IP address number*/
	uint32_t user_ip;
	/** media layer IP address number (dotted notation)*/
	char user_ip_s[46];
	/** media channel number*/
	uint8_t media_channel;
	/** used codec*/
	enum voip_codec media_codec;
};

/**
*/
struct voip_call_info {
	uint8_t user_id;
	char *dst_uri;
};

/** VoIP event information
*/
struct omci_api_voip_event {
	enum {
		OMCI_API_VOIP_EVENT_DUMMY,
	} type;

	union {
		struct {
			int dummy;
		} dummy;
	};
};

enum omci_api_return omci_api_voip_call_make(struct omci_api_ctx *ctx,
					     const struct voip_call_info *inf);

enum omci_api_return omci_api_voip_call_answer(struct omci_api_ctx *ctx,
					       const uint8_t user_id);

enum omci_api_return omci_api_voip_call_end(struct omci_api_ctx *ctx,
					    const uint8_t user_id);

enum omci_api_return omci_api_voip_agent_cfg_set(struct omci_api_ctx *ctx,
					         const struct sip_agent *agent);

enum omci_api_return omci_api_voip_agent_cfg_get(struct omci_api_ctx *ctx,
					         struct sip_agent *agent);

enum omci_api_return omci_api_voip_agent_update(struct omci_api_ctx *ctx);

enum omci_api_return omci_api_voip_agent_destroy(struct omci_api_ctx *ctx);

enum omci_api_return omci_api_voip_agent_cnt_get(struct omci_api_ctx *ctx,
						 struct sip_agent_counters *cnt);

enum omci_api_return omci_api_voip_user_cfg_set(struct omci_api_ctx *ctx,
						const uint8_t user_id,
						const struct sip_user *user);

enum omci_api_return omci_api_voip_user_cfg_get(struct omci_api_ctx *ctx,
						const uint8_t user_id,
						struct sip_user *user);

enum omci_api_return omci_api_voip_user_rtp_tos_set(struct omci_api_ctx *ctx,
						    const uint8_t user_id,
						    const uint8_t tos);

enum omci_api_return omci_api_voip_user_register(struct omci_api_ctx *ctx,
						 const uint8_t user_id);

/** VoIP callback definition */
typedef enum omci_api_return(omci_api_voip_cb_t)(void *caller,
						 struct omci_api_voip_event
						 event);

/** Register VoIP events callback */
enum omci_api_return omci_api_voip_cb_register(struct omci_api_ctx *ctx,
					       omci_api_voip_cb_t *callback);

void omci_api_voip_debug_level_set(uint8_t level);

uint8_t omci_api_voip_debug_level_get(void);

/** @} */

__END_DECLS

#endif

