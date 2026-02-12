/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#include "omci_api_common.h"
#include "omci_api_debug.h"

#ifdef INCLUDE_OMCI_API_VOIP

#include "voip/omci_api_voip.h"
#include "omci_api_voip_common.h"

struct voip_ctx *voip_ctx = NULL;

static uint8_t voip_dbg_level = 4;

static enum omci_api_return fxs_event_onhook(struct voip_ctx *ctx,
					     const uint16_t ch)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint8_t user_id;
	IFX_time_t time_diff;

	time_diff = IFXOS_ElapsedTimeMSecGet(0) - ctx->fxs.offhook_time[ch];
	if (ctx->fxs.max_offhook_duration[ch] < time_diff)
		ctx->fxs.max_offhook_duration[ch] = time_diff;

	if (ctx->fxs.dialing_events[ch] == 0)
		ctx->fxs.abandoned_calls[ch]++;

	ret = sip_media2user(&ctx->sip, ch, &user_id);
	if ( ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("user id get failed for media "
				   "channel %u!\n", ch)); return ret;
	}

	/* Hangup a call if any*/
	if (ctx->sip.call[user_id].inv) {
		ret = sip_call_end(&ctx->sip, user_id);
		if ( ret != OMCI_API_SUCCESS) {
			DBG(OMCI_API_ERR, ("call %u end failed!\n", user_id));
			return ret;
		}
	}

	ret = fxs_local_tone_stop(&ctx->fxs, ch);
	if ( ret != OMCI_API_SUCCESS)
		return ret;

	/* Switch line to STANDBY state*/
	ret = fxs_phone_enable(&ctx->fxs, ch, false);
	if ( ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("fxs %u standby failed!\n", ch));
		return ret;
	}

	return ret;
}

static enum omci_api_return fxs_event_offhook(struct voip_ctx *ctx,
					      const uint16_t ch)
{
	enum omci_api_return ret;
	uint8_t user_id;
	bool in_a_call = false;

	ctx->fxs.offhook_time[ch] = IFXOS_ElapsedTimeMSecGet(0);
	ctx->fxs.dialing_events[ch] = 0;

	/* Stop ringing*/
	ret = fxs_ring_ctrl(&ctx->fxs, ch, false);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	/* Enable the line*/
	ret = fxs_phone_enable(&ctx->fxs, ch, true);
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("fxs %u enable failed!\n", ch));
		return ret;
	}

	/* clear the previously dialed number*/
	memset(&ctx->fxs.dial_num[ch], 0x0, sizeof(ctx->fxs.dial_num[ch]));

	ret = sip_media2user(&ctx->sip, ch, &user_id);
	if ( ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("user id get failed for "
			"media channel %u!\n", ch));
		return ret;
	}

	/* Answer a call if any*/
	if (ctx->sip.call[user_id].inv && ctx->sip.call[user_id].invite_received) {
		if (ctx->sip.call[user_id].inv->state == PJSIP_INV_STATE_INCOMING ||
		    ctx->sip.call[user_id].inv->state == PJSIP_INV_STATE_EARLY) {
			ret = sip_call_answer(&ctx->sip, user_id);
			if (ret == OMCI_API_SUCCESS)
				in_a_call = true;
		}
	} else if (ctx->sip.call[user_id].inv) {
		in_a_call = true;
	}

	if (ret == OMCI_API_SUCCESS)
		if (!in_a_call)
			ret = fxs_local_dial_tone_play(&ctx->fxs, ch);

	return ret;
}

static enum omci_api_return fxs_event_dtmf_digit(struct voip_ctx *ctx,
						 const uint16_t ch,
						 char ascii_digit)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	char dialed_str[FXS_DIAL_NUM_COUNT_MAX + 1];
	char dst_uri[OMCI_API_URI_MAX + OMCI_API_USERNAME_MAX + 7];
	uint8_t user_id;

	ctx->fxs.dialing_events[ch]++;

	switch (ascii_digit) {
	case '#':
		/* get the dialed characters*/
		memcpy(dialed_str, ctx->fxs.dial_num[ch].num,
			ctx->fxs.dial_num[ch].c);
		dialed_str[ctx->fxs.dial_num[ch].c] = '\0';

		/* clear the dialed number*/
		memset(&ctx->fxs.dial_num[ch], 0x0,
			sizeof(ctx->fxs.dial_num[ch]));

		/* ...and try to make a call*/
		if (strlen(ctx->sip.agent[0].registrar))
			sprintf(dst_uri, "sip:%s@%s", dialed_str,
				ctx->sip.agent[0].registrar);
		else
			DBG(OMCI_API_ERR, ("call to %s failed, no registrar\n",
						dialed_str));

		ret = sip_media2user(&ctx->sip, ch, &user_id);
		if ( ret != OMCI_API_SUCCESS) {
			DBG(OMCI_API_ERR, ("user id get failed for "
				"media channel %u!\n", ch));
			return ret;
		}

		if (sip_call_make(&ctx->sip, user_id, dst_uri)
							!= OMCI_API_SUCCESS)
			DBG(OMCI_API_ERR, ("call to %s failed\n", dst_uri));

		break;
	default:
		/* store ASCII digit*/
		ctx->fxs.dial_num[ch].num[ctx->fxs.dial_num[ch].c] =
								ascii_digit;
		if (ctx->fxs.dial_num[ch].c >= FXS_DIAL_NUM_COUNT_MAX)
			DBG(OMCI_API_ERR, ("dial limit %u reached!\n",
						FXS_DIAL_NUM_COUNT_MAX));
		else
			ctx->fxs.dial_num[ch].c++;

		break;
	}

	return ret;
}

static enum omci_api_return fxs_event_handler(struct voip_ctx *ctx)
{
	enum omci_api_return status = OMCI_API_SUCCESS;
	int ret = 0;
	uint16_t ch;
	IFX_TAPI_EVENT_t tapi_event;

	status = fxs_event_get(&ctx->fxs, &tapi_event);
	if (status != OMCI_API_SUCCESS)
		return status;

	if (tapi_event.id != IFX_TAPI_EVENT_NONE) {
		ch = tapi_event.ch;
		if (ch >= OMCI_API_FXS_MAX) {
			DBG(OMCI_API_ERR, ("FXS(%d) event %u handle failed\n",
					  ch, tapi_event.id));
			return OMCI_API_ERROR;
		}

		switch (tapi_event.id) {
		case IFX_TAPI_EVENT_FXS_ONHOOK:
			status = fxs_event_onhook(ctx, ch);
			break;
		case IFX_TAPI_EVENT_FXS_OFFHOOK:
			status = fxs_event_offhook(ctx, ch);
			break;
		case IFX_TAPI_EVENT_DTMF_DIGIT:
			if (ctx->fxs.dial_num[ch].c == 0) {
				status = fxs_local_tone_stop(&ctx->fxs, ch);
				if (status != OMCI_API_SUCCESS)
					return status;
			}
			status = fxs_event_dtmf_digit(ctx, ch,
					(char)tapi_event.data.dtmf.ascii);
			break;
		default:
			DBG(OMCI_API_MSG, ("FXS(%d) unhandled event %u\n",
					  ch, tapi_event.id));
			break;
		}
	}

	return status;
}

static int32_t fxs_event_thread(struct IFXOS_ThreadParams_s *thr_params)
{
	enum omci_api_return ret;
	struct voip_ctx *ctx = (struct voip_ctx *)thr_params->nArg1;
	IFXOS_devFd_set_t rfds, trfds;
	IFX_uint32_t width = 0;
	struct timeval tv;
	IFX_uint32_t sretval;

#ifdef LINUX
	DBG(OMCI_API_MSG, ("FXS Thread - Started (tid %d)" CRLF, getpid()));
#endif

	IFXOS_DevFdZero(&rfds);

	IFXOS_DevFdSet(ctx->fxs.ctrl_fd, &rfds);
	width = ctx->fxs.ctrl_fd;

	ctx->run = true;

	while (ctx->run) {
		/* Update the local file descriptor by the copy in the
		   task parameter */
		memcpy((void *)&trfds, (void*)&rfds, sizeof(IFXOS_devFd_set_t));

		tv.tv_sec = FXS_SELECT_TIMEOUT_MS / 1000;
		tv.tv_usec = (FXS_SELECT_TIMEOUT_MS % 1000) * 1000;

		sretval = select(width + 1, &trfds, IFX_NULL, IFX_NULL, &tv); 

		/* error or timeout on select */
		if (sretval <= 0)
			continue;

		/* Check device control channel*/
		if (IFXOS_DevFdIsSet(ctx->fxs.ctrl_fd, &trfds)) {
			if (fxs_event_handler(ctx) != OMCI_API_SUCCESS) {
				DBG(OMCI_API_ERR,("FXS event handle failed\n"));
				return -1;
			}
		}
	}

	return 0;
}

enum omci_api_return voip_init(struct omci_api_ctx *ctx)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct voip_ctx *voip = &ctx->voip;

	memset(voip, 0x0, sizeof(struct voip_ctx));

	omci_api_voip_debug_level_set(voip_dbg_level);

	ret = fxs_init(ctx);
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("FXS init failed!\n"));
		goto err_fxs;
	}

	ret = sip_init(&voip->sip);
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("SIP init failed!\n"));
		goto err_sip;
	}

	if (IFXOS_ThreadInit(&voip->fxs_event_thread_ctrl, "fxsevt",
			     fxs_event_thread,
			     IFXOS_DEFAULT_STACK_SIZE,
			     IFXOS_THREAD_PRIO_LOWEST,
			     (unsigned long)voip,
			     0)) {
		DBG(OMCI_API_ERR, ("Can't start FXS event thread\n"));
		goto err_thread;
	}

	voip_ctx = voip;
	voip->init = true;

	return OMCI_API_SUCCESS;

err_thread:
	sip_exit(&voip->sip);
err_sip:
	fxs_exit(ctx);
err_fxs:

	return OMCI_API_ERROR;
}

enum omci_api_return voip_exit(struct omci_api_ctx *ctx)
{
	struct voip_ctx *voip = &ctx->voip;

	if (voip->init == false)
		return OMCI_API_SUCCESS;

	voip->run = false;

	if (IFXOS_THREAD_INIT_VALID(&voip->fxs_event_thread_ctrl))
		(void)IFXOS_ThreadDelete(&voip->fxs_event_thread_ctrl, 0);

	fxs_exit(ctx);
	sip_exit(&voip->sip);
	voip_ctx = NULL;
	voip->init = false;

	return OMCI_API_SUCCESS;
}

enum omci_api_return omci_api_voip_agent_cfg_set(struct omci_api_ctx *ctx,
					         const struct sip_agent *agent)
{
	/** \todo add sanity checks
	*/

	memcpy(&ctx->voip.sip.agent[0], agent, sizeof(struct sip_agent));

	return OMCI_API_SUCCESS;
}

enum omci_api_return omci_api_voip_agent_cfg_get(struct omci_api_ctx *ctx,
					         struct sip_agent *agent)
{
	memcpy(agent, &ctx->voip.sip.agent[0], sizeof(struct sip_agent));

	return OMCI_API_SUCCESS;
}

enum omci_api_return omci_api_voip_agent_update(struct omci_api_ctx *ctx)
{
	return sip_agent_update(&ctx->voip.sip);
}

enum omci_api_return omci_api_voip_agent_destroy(struct omci_api_ctx *ctx)
{
	if (sip_agent_destroy(&ctx->voip.sip) != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("SIP agent destroy failed!\n"));
		return OMCI_API_ERROR;
	}

	/* clean configuration*/
	memset(&ctx->voip.sip.agent[0], 0x0, sizeof(struct sip_agent));

	return OMCI_API_SUCCESS;
}

enum omci_api_return omci_api_voip_agent_cnt_get(struct omci_api_ctx *ctx,
						 struct sip_agent_counters *cnt)
{
	memcpy(cnt, &(ctx->voip.sip.cnt[0]), sizeof(*cnt));

	return OMCI_API_SUCCESS;
}

enum omci_api_return omci_api_voip_user_cfg_set(struct omci_api_ctx *ctx,
						const uint8_t user_id,
						const struct sip_user *user)
{
	if (user_id >= OMCI_API_SIP_USERS_NUM) {
		DBG(OMCI_API_ERR, ("Unsupported user_id=%u!\n", user_id));
		return OMCI_API_ERROR;
	}

	return sip_user_cfg_set(&ctx->voip.sip, user_id, user);
}

enum omci_api_return omci_api_voip_user_cfg_get(struct omci_api_ctx *ctx,
						const uint8_t user_id,
						struct sip_user *user)
{
	if (user_id >= OMCI_API_SIP_USERS_NUM) {
		DBG(OMCI_API_ERR, ("Unsupported user_id=%u!\n", user_id));
		return OMCI_API_ERROR;
	}

	memcpy(user, &ctx->voip.sip.user[user_id], sizeof(struct sip_user));

	return OMCI_API_SUCCESS;
}

enum omci_api_return omci_api_voip_user_rtp_tos_set(struct omci_api_ctx *ctx,
						    const uint8_t user_id,
						    const uint8_t tos)
{
	if (user_id >= OMCI_API_SIP_USERS_NUM) {
		DBG(OMCI_API_ERR, ("Unsupported user_id=%u!\n", user_id));
		return OMCI_API_ERROR;
	}
	
	ctx->voip.fxs.stream_rtp_tos[user_id] = tos;

	return OMCI_API_SUCCESS;
}

enum omci_api_return omci_api_voip_user_register(struct omci_api_ctx *ctx,
						 const uint8_t user_id)
{
	if (user_id >= OMCI_API_SIP_USERS_NUM) {
		DBG(OMCI_API_ERR, ("Unsupported user_id=%u!\n", user_id));
		return OMCI_API_ERROR;
	}

	return sip_user_register(&ctx->voip.sip, user_id);
}

enum omci_api_return omci_api_voip_call_make(struct omci_api_ctx *ctx,
					     const struct voip_call_info *inf)
{
	enum omci_api_return ret;
	uint8_t fxs_id;

	if (inf->user_id >= OMCI_API_SIP_USERS_NUM) {
		DBG(OMCI_API_ERR, ("Unsupported user_id=%u!\n", inf->user_id));
		return OMCI_API_ERROR;
	}

	fxs_id = ctx->voip.sip.user[inf->user_id].media_channel;
	/* Enable the line*/
	ret = fxs_phone_enable(&ctx->voip.fxs, fxs_id, true);
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("fxs %u enable failed!\n", fxs_id));
		return ret;
	}

	return sip_call_make(&ctx->voip.sip, inf->user_id, inf->dst_uri);
}

enum omci_api_return omci_api_voip_call_answer(struct omci_api_ctx *ctx,
					       const uint8_t user_id)
{
	enum omci_api_return ret = OMCI_API_ERROR;
	uint8_t fxs_id;

	if (user_id >= OMCI_API_SIP_USERS_NUM) {
		DBG(OMCI_API_ERR, ("Unsupported user_id=%u!\n", user_id));
		return OMCI_API_ERROR;
	}

	fxs_id = ctx->voip.sip.user[user_id].media_channel;
	/* Stop ringing*/
	if (fxs_ring_ctrl(&ctx->voip.fxs, fxs_id, false) != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;

	/* Answer a call if any*/
	if (ctx->voip.sip.call[user_id].inv &&
				ctx->voip.sip.call[user_id].invite_received) {
		if (ctx->voip.sip.call[user_id].inv->state ==
						     PJSIP_INV_STATE_INCOMING ||
		    ctx->voip.sip.call[user_id].inv->state ==
						     PJSIP_INV_STATE_EARLY)
			ret = sip_call_answer(&ctx->voip.sip, user_id);
	}

	return ret;
}

enum omci_api_return omci_api_voip_call_end(struct omci_api_ctx *ctx,
					    const uint8_t user_id)
{
	return sip_call_end(&ctx->voip.sip, user_id);
}

enum omci_api_return omci_api_voip_cb_register(struct omci_api_ctx *ctx,
					       omci_api_voip_cb_t *callback)
{
	if (!callback)
		return OMCI_API_ERROR;

	ctx->voip.callback = callback;
	return OMCI_API_SUCCESS;
}

void omci_api_voip_debug_level_set(uint8_t level)
{
	fxs_debug_level_set(level);
	sip_debug_level_set(level);
	voip_dbg_level = level;
}

uint8_t omci_api_voip_debug_level_get(void)
{
	return voip_dbg_level;
}

#endif /* #ifdef INCLUDE_OMCI_API_VOIP*/

