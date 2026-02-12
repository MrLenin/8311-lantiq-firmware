/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_sip_h
#define _omci_api_sip_h

#include "omci_api.h"
#include "voip/omci_api_voip.h"
#include "omci_api_fxs.h"
#include <pjsip.h>
#include <pjsip_ua.h>
#include <pjsip_simple.h>
#include <pjlib-util.h>
#include <pjlib.h>

__BEGIN_DECLS

/** \addtogroup OMCI_API_VOIP_SIP

   @{
*/


#define OMCI_API_SIP_AGENTS_NUM		1

/** Maximum number of SIP users*/
#define OMCI_API_SIP_USERS_NUM		OMCI_API_FXS_MAX

/** Structure to identify SIP endpoint.
*/
struct sip_endpt {
	/** pjsip global pool factory*/
	pj_caching_pool pj_cp;
	/* pjsip memory pool*/
	pj_pool_t *pool;
	/** pjsip endpoint*/
	pjsip_endpoint *pj_sip_endpt;
	/** pjsip event thread*/
	pj_thread_t *sip_thread;
	/** flag to signal SIP thread quit*/
	bool sip_thread_quit;
};

/**
*/
struct sip_call {
	/** call index*/
	uint8_t idx;
	/** call invite session*/
	pjsip_inv_session *inv;
	/** Invite Request received indication*/
	bool invite_received;
	/** user*/
	struct sip_user *user;
};

/** SIP related context.
*/
struct sip_data {
	/** sip agent*/
	struct sip_agent agent[OMCI_API_SIP_AGENTS_NUM];
	/** sip agent counters*/
	struct sip_agent_counters cnt[OMCI_API_SIP_AGENTS_NUM];
	/* sip user*/
	struct sip_user user[OMCI_API_SIP_USERS_NUM];
	/** sip registration entries */
	pjsip_regc *regc[OMCI_API_SIP_USERS_NUM];
	/** sip endpoint entry*/
	struct sip_endpt pjsip;
	/** sip call*/
	struct sip_call call[OMCI_API_SIP_USERS_NUM];
};

/** Create SIP agent.
*/
enum omci_api_return sip_agent_create(struct sip_data *sip);

/** Destroy SIP agent.
*/
enum omci_api_return sip_agent_destroy(struct sip_data *sip);

/** Update SIP agent.
*/
enum omci_api_return sip_agent_update(struct sip_data *sip);

/** Convert media channel id to user id
*/
enum omci_api_return sip_media2user(struct sip_data *sip,
				    const uint8_t media_channel,
				    uint8_t *user_id);

/** Set SIP user configuration data.
*/
enum omci_api_return sip_user_cfg_set(struct sip_data *sip,
				      const uint8_t id,
				      const struct sip_user *user);

/** User account register.
*/
enum omci_api_return sip_user_register(struct sip_data *sip,
				       const uint8_t id);

/** Make SIP call.
*/
enum omci_api_return sip_call_make(struct sip_data *sip,
				   const uint8_t user_id,
				   const char *dst_uri);

/** End SIP call.
*/
enum omci_api_return sip_call_end(struct sip_data *sip, const uint8_t user_id);

/** Answer SIP call.
*/
enum omci_api_return sip_call_answer(struct sip_data *sip,
				     const uint8_t user_id);

/** SIP Init.
    Call before any SIP access.
*/
enum omci_api_return sip_init(struct sip_data *sip);

/** SIP exit.
*/
enum omci_api_return sip_exit(struct sip_data *sip);

/** Set SIP debug level */
void sip_debug_level_set(uint8_t level);

/** @} */

__END_DECLS

#endif

