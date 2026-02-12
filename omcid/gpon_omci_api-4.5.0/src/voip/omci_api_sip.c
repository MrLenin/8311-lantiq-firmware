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

#include "omci_api_voip_common.h"

/* Change to pj_AF_INET6() for IPv6.
   PJ_HAS_IPV6 must be enabled and your system must support IPv6.  */
#define AF	pj_AF_INET()

/* Listening SIP port */
#define SIP_PORT    5060
/* RTP port */
#define RTP_PORT    4000

/* Maximum time to wait for PJSIP events [ms]*/
#define SIP_EVENTS_WAIT_TIMEOUT	500

#define SIP_CNT_INC(sip_ptr, x) sip_ptr->cnt[0].x++

static pj_bool_t mod_app_on_rx_req(pjsip_rx_data *rdata);

static pj_bool_t mod_trl_on_rx_req(pjsip_rx_data *rdata);
static pj_bool_t mod_trl_on_rx_res(pjsip_rx_data *rdata);
static pj_status_t mod_trl_on_tx_req(pjsip_tx_data *tdata);
static pj_status_t mod_trl_on_tx_res(pjsip_tx_data *tdata);

/* This is a PJSIP module to be registered by application to handle
 * incoming requests outside any dialogs/transactions. The main purpose
 * here is to handle incoming INVITE request message, where we will
 * create a dialog and INVITE session for it.
 */
static pjsip_module mod_app =
{
	NULL, NULL,			 /* prev, next.		*/
	{ "mod-app", 7 },		 /* Name.		*/
	-1,				 /* Id			*/
	PJSIP_MOD_PRIORITY_APPLICATION,	 /* Priority		*/
	NULL,			   	 /* load()		*/
	NULL,			    	 /* start()		*/
	NULL,			    	 /* stop()		*/
	NULL,			    	 /* unload()		*/
	&mod_app_on_rx_req,		 /* on_rx_request()	*/
	NULL,				 /* on_rx_response()	*/
	NULL,				 /* on_tx_request.	*/
	NULL,				 /* on_tx_response()	*/
	NULL,			    	 /* on_tsx_state()	*/
};

/* The transport layer module instance. */
static pjsip_module mod_trl = 
{
	NULL, NULL,				/* prev, next.		*/
	{ "mod-pm", 6 },			/* Name.		*/
	-1,					/* Id			*/
	PJSIP_MOD_PRIORITY_TRANSPORT_LAYER-1,	/* Priority	        */
	NULL,					/* load()		*/
	NULL,					/* start()		*/
	NULL,					/* stop()		*/
	NULL,					/* unload()		*/
	&mod_trl_on_rx_req,			/* on_rx_request()	*/
	&mod_trl_on_rx_res,			/* on_rx_response()	*/
	&mod_trl_on_tx_req,			/* on_tx_request.	*/
	&mod_trl_on_tx_res,			/* on_tx_response()	*/
	NULL,					/* on_tsx_state()	*/

};

static int pjsip_thread_register(void)
{
	pj_status_t status;
	pj_thread_desc desc;
	pj_thread_t *thread = 0;

	if (!pj_thread_is_registered()) {
		status = pj_thread_register("sip_call_thread", desc, &thread);
		if (status != PJ_SUCCESS) {
			DBG(OMCI_API_ERR, ("extenrnal pjsip calling "
					   "thread registration failed!\n"));
			return -1;
		} else {
			DBG(OMCI_API_MSG, ("extenrnal pjsip calling "
					   "thread registered\n"));
			return 0;
		}
	}

	return 0;
}

static uint8_t user_index_get(struct sip_data *sip, pjsip_rx_data *rdata)
{
	pj_str_t *s;
	char buf[OMCI_API_URI_MAX];
	pj_str_t str1, str2;
	uint8_t i;

	if (!rdata->msg_info.to->uri->vptr->
			p_print(PJSIP_URI_IN_FROMTO_HDR ,
				rdata->msg_info.to->uri,
				buf, (pj_size_t)sizeof(buf))) {
		DBG(OMCI_API_ERR, ("set default call index to 0!\n"));
		return 0;
	}

	for (i = 0; i < OMCI_API_SIP_USERS_NUM; i++) {
		str1 = pj_str(buf);
		str2 = pj_str((char *)sip->user[i].username);

		if (pj_strstr(&str1, &str2)) {
			DBG(OMCI_API_MSG, ("%s account mapped to "
					   "media chan %u\n",
					   sip->user[i].username,
					   sip->user[i].media_channel));
			return i;
		}
	}

	DBG(OMCI_API_ERR, ("set default call index to 0!\n"));
	return 0;
}

static void codec_pt2str(const enum voip_codec pt,
			 char *str1, const size_t str_cnt1,
			 char *str2, const size_t str_cnt2)
{
	switch (pt) {
	case CODEC_G729:
		strncpy(str2, "G729", str_cnt2);
		break;
	case CODEC_G711A:
		strncpy(str2, "PCMA", str_cnt2);
		break;
	default:
		strncpy(str2, "n/a", str_cnt2);
		return;
	}
	snprintf(str1, str_cnt1, "%d", pt);
}

/* Create SDP session for a call */
/** \todo add implementation here
*/
static int call_sdp_create(const struct sip_user *usr,
			   pj_pool_t *pool, pjmedia_sdp_session **p_sdp)
{
	pj_time_val tv;
	char ip_addr[32];
	pjmedia_sdp_session *sdp;
	pjmedia_sdp_media *m;
	pjmedia_sdp_attr *attr;

	/* Create and initialize basic SDP session */
	sdp = pj_pool_zalloc (pool, sizeof(pjmedia_sdp_session));

	pj_gettimeofday(&tv);
	sdp->origin.user	= pj_str((char*)usr->username);
	sdp->origin.version 	= sdp->origin.id = tv.sec + 2208988800UL;
	sdp->origin.net_type 	= pj_str("IN");
	sdp->origin.addr_type 	= pj_str("IP4");
	sdp->origin.addr 	= *pj_gethostname();
	sdp->name 		= pj_str("omci-sip");

	/* Since we only support one media stream at present, put the
	   SDP connection line in the session level.*/
	sdp->conn = pj_pool_zalloc (pool, sizeof(pjmedia_sdp_conn));
	sdp->conn->net_type	= pj_str("IN");
	sdp->conn->addr_type 	= pj_str("IP4");
	sdp->conn->addr		= pj_str((char*)usr->user_ip_s);

	/* SDP time and attributes. */
	sdp->time.start = 0;
	sdp->time.stop  = 0;
	sdp->attr_count = 0;

	/* Create media stream 0: */
	sdp->media_count = 1;
	m = pj_pool_zalloc (pool, sizeof(pjmedia_sdp_media));
	sdp->media[0] = m;

	/* Standard media info: */
	m->desc.media	   = pj_str("audio");
	m->desc.port 	   = usr->user_port;
	m->desc.port_count = 1;
	m->desc.transport  = pj_str("RTP/AVP");

	/* Add format and rtpmap for each codec. */
	m->desc.fmt_count = 1;
	m->attr_count = 0;
	{
		pjmedia_sdp_rtpmap rtpmap;
		pjmedia_sdp_attr *attr;
		char pt_str1[10];
		char pt_str2[10];

		codec_pt2str(usr->media_codec,
			     pt_str1, sizeof(pt_str1),
			     pt_str2, sizeof(pt_str2));

		/* add selected codec*/
		pj_strdup2(pool, &m->desc.fmt[0], pt_str1);
		rtpmap.pt = m->desc.fmt[0];
		rtpmap.clock_rate = 8000;
		rtpmap.enc_name = pj_str((char *)pt_str2);
		rtpmap.param.slen = 0;

		pjmedia_sdp_rtpmap_to_attr(pool, &rtpmap, &attr);
		m->attr[m->attr_count++] = attr;
	}

	/* Add sendrecv attribute. */
	attr = pj_pool_zalloc(pool, sizeof(pjmedia_sdp_attr));
	attr->name = pj_str("sendrecv");
	m->attr[m->attr_count++] = attr;

	*p_sdp = sdp;

	return 0;
}

/*
  Callback when INVITE session state has changed.
  This callback is registered when the invite session module is initialized.
  We mostly want to know when the invite session has been disconnected,
  so that we can quit the application.*/
static void call_on_state_changed(pjsip_inv_session *inv, pjsip_event *e)
{
	pj_status_t status;
	struct sip_call *call = inv->mod_data[mod_app.id];
	bool off_hook = false;

	PJ_UNUSED_ARG(e);

	if (!call)
		return;

	DBG(OMCI_API_MSG, ("call #%u state changed to %s\n",
				call->idx, pjsip_inv_state_name(inv->state)));

	if (inv->state == PJSIP_INV_STATE_INCOMING) {
		/* Start ringing*/
		fxs_ring_ctrl(FXS_CTX(voip_ctx), call->user->media_channel, true);
	} else if (inv->state == PJSIP_INV_STATE_CALLING) {
		(void)fxs_local_ringback_tone_play(FXS_CTX(voip_ctx),
						   call->user->media_channel);
	} else if (inv->state == PJSIP_INV_STATE_DISCONNECTED) {
		DBG(OMCI_API_MSG, ("call #%u DISCONNECTED [reason=%d (%s)]\n",
				  call->idx, inv->cause,
				  pjsip_get_status_text(inv->cause)->ptr));

		/* Stop ringing*/
		fxs_ring_ctrl(FXS_CTX(voip_ctx), call->user->media_channel, false);

		fxs_stream_stop(FXS_CTX(voip_ctx), call->user->media_channel);

		if (fxs_hook_status_get(FXS_CTX(voip_ctx),
					call->user->media_channel,
					&off_hook) == OMCI_API_SUCCESS) {
			if (off_hook && inv->cause != PJSIP_SC_BUSY_HERE)
				(void)fxs_local_busy_tone_play(
						FXS_CTX(voip_ctx),
						call->user->media_channel);
		}

		call->invite_received = false;
		call->inv = NULL;
		call->user = NULL;
		inv->mod_data[mod_app.id] = NULL;
	} else if (inv->state == PJSIP_INV_STATE_CONFIRMED) {
		DBG(OMCI_API_MSG, ("call #%u CONNECTED\n", call->idx));
		(void)fxs_local_tone_stop(FXS_CTX(voip_ctx),
					  call->user->media_channel);
	}
}


/* This callback is called when dialog has forked. */
static void call_on_forked(pjsip_inv_session *inv, pjsip_event *e)
{
	/* To be done... */
	PJ_UNUSED_ARG(inv);
	PJ_UNUSED_ARG(e);
}

/*
   Callback when SDP negotiation has completed.
   We are interested with this callback because we want to start media
   as soon as SDP negotiation is completed. */
static void call_on_media_update(pjsip_inv_session *inv, pj_status_t status)
{
	pj_status_t sts;
	struct sip_call *call = inv->mod_data[mod_app.id];
	const pjmedia_sdp_session *l_sdp, *r_sdp;
	pj_hostent he;
	struct fxs_stream_info fxs_stream_inf;

	if (status != PJ_SUCCESS) {
		DBG(OMCI_API_ERR, ("SDP negotiation has failed!\n"));
		/* Here we should disconnect call if we're not in the middle
		  of initializing an UAS dialog and if this is not a re-INVITE.
		*/
		return;
	}

	if (!call)
		return;

	/* capture media definitions from the SDP */
	sts = pjmedia_sdp_neg_get_active_local(inv->neg, &l_sdp);
	if (sts != PJ_SUCCESS) {
		DBG(OMCI_API_ERR, ("SDP negotiation local get failed, "
				   "call_idx=%u!\n", call->idx));
		return;
	}

	sts = pjmedia_sdp_neg_get_active_remote(inv->neg, &r_sdp);
	if (sts != PJ_SUCCESS) {
		DBG(OMCI_API_ERR, ("SDP negotiation remote get failed, "
				   "call_idx=%u!\n", call->idx));
		return;
	}

	if (!l_sdp->conn || !r_sdp->conn)
		return;

	if (!r_sdp->media_count) {
		DBG(OMCI_API_ERR, ("No remote media available, "
				   "call_idx=%u!\n", call->idx));
		return;
	}

	sts = pj_gethostbyname(&l_sdp->conn->addr, &he);
	if (sts != PJ_SUCCESS) {
		DBG(OMCI_API_ERR, ("can't resolve local %s, "
				   "call_idx=%u!\n",
				   l_sdp->conn->addr.ptr, call->idx));
		return;
	}

	fxs_stream_inf.conn.src_addr = *(uint32_t*)he.h_addr_list[0];
	fxs_stream_inf.conn.src_port = pj_htons(l_sdp->media[0]->desc.port);

	sts = pj_gethostbyname(&r_sdp->conn->addr, &he);
	if (sts != PJ_SUCCESS) {
		DBG(OMCI_API_ERR, ("can't resolve remote %s, "
				   "call_idx=%u!\n",
				   r_sdp->conn->addr.ptr, call->idx));
		return;
	}

	fxs_stream_inf.conn.dst_addr = *(uint32_t*)he.h_addr_list[0];
	fxs_stream_inf.conn.dst_port = pj_htons(r_sdp->media[0]->desc.port);

	if (fxs_codec_set(FXS_CTX(voip_ctx), call->user->media_channel,
			  call->user->media_codec) != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("media codec set failed, "
				   "call_idx=%u!\n", call->idx));
		return;
	}

	fxs_stream_inf.type = FXS_STREAM_VOICE;
	fxs_stream_inf.id   = call->user->media_channel;

	if (fxs_stream_start(FXS_CTX(voip_ctx), &fxs_stream_inf)
						  != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("media start start failed, "
				   "call_idx=%u!\n", call->idx));
		return;
	}

	DBG(OMCI_API_MSG, ("call #%u SDP negotiation completed, src 0x%X:%u, "
			   "dst 0x%X:%u\n", call->idx,
			   fxs_stream_inf.conn.src_addr,
			   fxs_stream_inf.conn.src_port,
			   fxs_stream_inf.conn.dst_addr,
			   fxs_stream_inf.conn.dst_port));
}

static pj_bool_t mod_app_on_rx_req(pjsip_rx_data *rdata)
{
	struct sip_data *sip = SIP_CTX(voip_ctx);
	struct sip_agent_counters *cnt;
	pj_status_t status;
	char temp[80];
	unsigned options = 0;
	pj_str_t local_uri;
	pjsip_dialog *dlg;
	pjmedia_sdp_session *sdp;
	pjsip_tx_data *tdata;
	uint8_t user_idx = 0;
	struct sip_call *call;
	bool off_hook = false;

	if (!sip)
		return PJ_FALSE;

	cnt = &sip->cnt[0];

	/* Ignore strandled ACKs (must not send respone */
	if (rdata->msg_info.msg->line.req.method.id == PJSIP_ACK_METHOD)
		return PJ_FALSE;

	/* Respond (statelessly) any non-INVITE requests with 500  */
	if (rdata->msg_info.msg->line.req.method.id != PJSIP_INVITE_METHOD) {
		pj_str_t reason = pj_str("Unsupported Operation");
		pjsip_endpt_respond_stateless( 	sip->pjsip.pj_sip_endpt, rdata,
						500, &reason, NULL, NULL);
		return PJ_TRUE;
	}

	user_idx = user_index_get(sip, rdata);

	call = &sip->call[user_idx];

	if (call->inv) {
		pj_str_t reason = pj_str("Another call is in progress");

		pjsip_endpt_respond_stateless( 	sip->pjsip.pj_sip_endpt, rdata,
						500, &reason, NULL, NULL);
		return PJ_TRUE;
	}

	/* save call index*/
	call->idx = user_idx;
	/* save user*/
	call->user = &sip->user[user_idx];

	/* verify that we can handle the request. */
	status = pjsip_inv_verify_request(rdata, &options, NULL, NULL,
					  sip->pjsip.pj_sip_endpt, NULL);
	if (status != PJ_SUCCESS) {
		pj_str_t reason = pj_str("can not handle this INVITE");

		pjsip_endpt_respond_stateless( sip->pjsip.pj_sip_endpt, rdata,
					       500, &reason, NULL, NULL);
		return PJ_TRUE;
	}

	/* generate Contact URI*/
	pj_ansi_sprintf(temp, "<sip:%s@%s>", sip->user[user_idx].username,
					     sip->user[user_idx].user_ip_s);
	local_uri = pj_str((char*)temp);

	/* create UAS dialog */
	status = pjsip_dlg_create_uas(	pjsip_ua_instance(), rdata,
					&local_uri, &dlg);

	if (status != PJ_SUCCESS) {
		pjsip_endpt_respond_stateless(sip->pjsip.pj_sip_endpt, rdata,
					      500, NULL, NULL, NULL);
		return PJ_TRUE;
	}

	/* create SDP (media capabilities)*/
	if (call_sdp_create(&sip->user[user_idx], dlg->pool, &sdp) != 0) {
		DBG(OMCI_API_ERR, ("SDP create failed, call idx=%u!\n",
				  user_idx));
		return PJ_TRUE;
	}

        /* Create invite session, and pass both the UAS dialog and the SDP
           capability to the session.*/
	status = pjsip_inv_create_uas(dlg, rdata, sdp, 0, &call->inv);
	if (status != PJ_SUCCESS) {
		pjsip_dlg_create_response(dlg, rdata, 500, NULL, &tdata);
		pjsip_dlg_send_response(dlg, pjsip_rdata_get_tsx(rdata), tdata);
		return PJ_TRUE;
	}

	call->invite_received = true;

	/* Attach call data to invite session */
	call->inv->mod_data[mod_app.id] = call;


	if (fxs_hook_status_get(FXS_CTX(voip_ctx), call->user->media_channel,
				&off_hook) != OMCI_API_SUCCESS) {
		pjsip_dlg_create_response(dlg, rdata, 500, NULL, &tdata);
		pjsip_dlg_send_response(dlg, pjsip_rdata_get_tsx(rdata), tdata);
		return PJ_TRUE;
	}

	if (off_hook) {
		/* Send BUSY_HERE*/
		pjsip_dlg_create_response(dlg, rdata, 486, NULL, &tdata);
		pjsip_dlg_send_response(dlg, pjsip_rdata_get_tsx(rdata), tdata);
		return PJ_TRUE;
	} else {
		status = pjsip_inv_initial_answer(call->inv, rdata,
						  100, NULL, NULL, &tdata);
		if (status != PJ_SUCCESS)
			return PJ_TRUE;

		/* Send the 100 response. */
		status = pjsip_inv_send_msg(call->inv, tdata);
		if (status != PJ_SUCCESS)
			return PJ_TRUE;

		/* Now create 180 response.*/
		status = pjsip_inv_answer(call->inv, 180, NULL,NULL, &tdata);
		if (status != PJ_SUCCESS)
			return PJ_TRUE;

		/* Send the 180 response.*/
		status = pjsip_inv_send_msg(call->inv, tdata);
		if (status != PJ_SUCCESS)
			return PJ_TRUE;
	}

	return PJ_TRUE;
}

static pj_bool_t mod_trl_on_rx_req(pjsip_rx_data *rdata)
{
	struct sip_data *sip = SIP_CTX(voip_ctx);

	if (!sip)
		return PJ_FALSE;

	if (rdata->msg_info.msg->line.req.method.id == PJSIP_INVITE_METHOD)
		SIP_CNT_INC(sip, rx_total_invite_reqs);
	else
		SIP_CNT_INC(sip, rx_noninvite_reqs);

	/* Always return false, otherwise messages will not get processed! */
	return PJ_FALSE;
}

static pj_bool_t mod_trl_on_rx_res(pjsip_rx_data *rdata)
{
	struct sip_data *sip = SIP_CTX(voip_ctx);
	pjsip_status_code code;
	if (!sip)
		return PJ_FALSE;

	code = (pjsip_status_code)rdata->msg_info.msg->line.status.code;

	SIP_CNT_INC(sip, rx_total_response);

	if (code == PJSIP_SC_REQUEST_TIMEOUT || code == PJSIP_SC_SERVER_TIMEOUT)
		SIP_CNT_INC(sip, sip_init_timout);

	if (code == PJSIP_SC_TRYING)
		SIP_CNT_INC(sip, rx_invite_response);

	if (code >= PJSIP_SC_BAD_REQUEST)
		SIP_CNT_INC(sip, sip_init_failure_received);

	if (code == PJSIP_SC_NOT_FOUND)
		SIP_CNT_INC(sip, sip_init_validate_fail);

	/* Always return false, otherwise messages will not get processed! */
	return PJ_FALSE;
}

static pj_status_t mod_trl_on_tx_req(pjsip_tx_data *tdata)
{
	struct sip_data *sip = SIP_CTX(voip_ctx);
	pj_atomic_value_t ref_cnt;

	if (!sip)
		return PJ_SUCCESS;

	ref_cnt = pj_atomic_get(tdata->ref_cnt);

	if (tdata->msg->line.req.method.id == PJSIP_INVITE_METHOD) {
		SIP_CNT_INC(sip, tx_total_invite_reqs);
		if (ref_cnt != 1)
			SIP_CNT_INC(sip, tx_invite_reqs);
	} else {
		SIP_CNT_INC(sip, tx_total_noninvite_reqs);
		if (ref_cnt != 1)
			SIP_CNT_INC(sip, tx_noninvite_reqs);
	}

	/* Always return success, otherwise message will not get sent! */
	return PJ_SUCCESS; 
}

static pj_status_t mod_trl_on_tx_res(pjsip_tx_data *tdata)
{
	struct sip_data *sip = SIP_CTX(voip_ctx);

	if (!sip)
		return PJ_SUCCESS;

	SIP_CNT_INC(sip, tx_total_response);

	if (pj_atomic_get(tdata->ref_cnt) != 1)
		SIP_CNT_INC(sip, tx_response);

	/* Always return success, otherwise message will not get sent! */
	return PJ_SUCCESS; 
}

/* Worker thread for SIP */
static int sip_worker_thread(void *arg)
{
	struct sip_endpt *sip = (struct sip_endpt *)arg;

	while (!sip->sip_thread_quit) {
		pj_time_val timeout = {0, SIP_EVENTS_WAIT_TIMEOUT};
		pjsip_endpt_handle_events(sip->pj_sip_endpt, &timeout);
	}

	return 0;
}

static void on_user_reg(struct pjsip_regc_cbparam *param)
{
	pjsip_regc_info info;
	pj_status_t status;
	struct sip_data *sip = SIP_CTX(voip_ctx);

	status = pjsip_regc_get_info(param->regc, &info);
	if (status != PJ_SUCCESS) {
		DBG(OMCI_API_ERR, ("sip regc info get failed!\n"));
		return;
	}

	if ((param->status != PJ_SUCCESS) ||
	    (param->code < 200 || param->code >= 300)) {
		DBG(OMCI_API_ERR, ("%s registration failed!\n",
							info.client_uri.ptr));
		if (sip)
			SIP_CNT_INC(sip, sip_init_auth_fail);
	} else {
		DBG(OMCI_API_MSG, ("%s registered\n", info.client_uri.ptr));
	}

	if (sip->agent[0].reg_exp_time == 0)
		pjsip_regc_destroy(param->regc);
}

static int sip_agent_default_cfg_get(struct sip_agent *agent)
{
	agent->agent_ip = 0;
	agent->agent_port = SIP_PORT;
	agent->agent_proto = OMCI_API_RFC5237_PROTO_UDP;

	agent->reg_exp_time = OMCI_API_SIP_REG_EXP_TIME_DEFAULT_SEC;

	return 0;
}

static int sip_user_default_cfg_get(const uint8_t id, struct sip_user *user)
{
	pj_sockaddr hostaddr;
	pj_in_addr addr;
	pj_str_t s_addr;

	strcpy(user->realm, "*");

	sprintf(user->username, "omci_sip%u", id);
	user->user_port = RTP_PORT + id*2;

	if (pj_gethostip(AF, &hostaddr) != PJ_SUCCESS)
		return -1;

	pj_sockaddr_print(&hostaddr, user->user_ip_s,
			  sizeof(user->user_ip_s), 2);
	s_addr = pj_str((char*)user->user_ip_s);
	addr = pj_inet_addr(&s_addr);

	user->user_ip = addr.s_addr;

	user->media_channel = id;
	user->media_codec = CODEC_G711A;

	return 0;
}
enum omci_api_return sip_media2user(struct sip_data *sip,
				    const uint8_t media_channel,
				    uint8_t *user_id)
{
	uint8_t i;

	for (i = 0; i < OMCI_API_SIP_USERS_NUM; i++) {
		if (sip->user[i].media_channel == media_channel) {
			*user_id = i;
			return OMCI_API_SUCCESS;
		}
	}

	*user_id = 0;

	return OMCI_API_ERROR;
}

enum omci_api_return sip_user_cfg_set(struct sip_data *sip,
				      const uint8_t id,
				      const struct sip_user *user)
{
	pj_in_addr in_addr;

	if (user->media_channel >= OMCI_API_FXS_MAX) {
		DBG(OMCI_API_ERR, ("media_channel=%u out of range %u\n",
					user->media_channel, OMCI_API_FXS_MAX));
		return OMCI_API_ERROR;
	}

	memcpy(&sip->user[id], user, sizeof(struct sip_user));

	in_addr.s_addr = pj_htonl(sip->user[id].user_ip);
	pj_ansi_strcpy(sip->user[id].user_ip_s, pj_inet_ntoa(in_addr));

	return OMCI_API_SUCCESS;
}

enum omci_api_return sip_agent_create(struct sip_data *sip)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct sip_endpt *pjsip = &sip->pjsip;
	struct sip_agent *agent = &sip->agent[0];
	pj_status_t status;
	char ip_addr[PJ_INET6_ADDRSTRLEN+2];
	pj_str_t cp;
	pj_in_addr in_addr;
	pj_sockaddr addr;
	pjsip_inv_callback inv_cb;

	if (pjsip->pj_sip_endpt) {
		DBG(OMCI_API_ERR, ("sip agent already exists!\n"));
		return OMCI_API_ERROR;
	}

	if (pjsip_thread_register() != 0)
		return OMCI_API_ERROR;

	/* Must create a pool factory before we can allocate any memory. */
	pj_caching_pool_init(&pjsip->pj_cp, &pj_pool_factory_default_policy, 0);

	/* create session pool for misc */
	pjsip->pool = pj_pool_create(&pjsip->pj_cp.factory, "omci_api_sip_pool",
				     1000, 1000, NULL);
	if (!pjsip->pool) {
		DBG(OMCI_API_ERR, ("sip pool create failed!\n"));
		ret = OMCI_API_ERROR;
		goto on_err;
	}

	/* create the endpoint */
	status = pjsip_endpt_create(&pjsip->pj_cp.factory, "omci_sip",
				    &pjsip->pj_sip_endpt);
	if (status != PJ_SUCCESS) {
		DBG(OMCI_API_ERR, ("sip endpoint create failed!\n"));
		ret = OMCI_API_ERROR;
		goto on_err;
	}

	if (agent->agent_ip == 0) {
		/* Add transport on 0.0.0.0:port*/
		pj_sockaddr_init(AF, &addr, NULL,
				 (pj_uint16_t)agent->agent_port);
	} else {
		in_addr.s_addr = pj_htonl(agent->agent_ip);
		pj_ansi_strcpy(ip_addr, pj_inet_ntoa(in_addr));
		cp = pj_str((char*)ip_addr);
		pj_sockaddr_init(AF, &addr, &cp,
				 (pj_uint16_t)agent->agent_port);
	}

	switch (agent->agent_proto) {
	case OMCI_API_RFC5237_PROTO_IPV6:
		DBG(OMCI_API_WRN, ("unsupported proto %hu specified, "
				   "using default TCP/UDP!\n",
				   agent->agent_proto));
	case OMCI_API_RFC5237_PROTO_TCP:
		status = pjsip_tcp_transport_start(pjsip->pj_sip_endpt,
						   &addr.ipv4, 1, NULL);
		if (status != PJ_SUCCESS) {
			DBG(OMCI_API_ERR, ("sip TCP transport start failed!\n"));
			ret = OMCI_API_ERROR;
			break;
		}
	case OMCI_API_RFC5237_PROTO_UDP:
		status = AF == pj_AF_INET()?
				pjsip_udp_transport_start(pjsip->pj_sip_endpt,
							  &addr.ipv4, NULL,
							  1, NULL) :
				pjsip_udp_transport_start6(pjsip->pj_sip_endpt,
							   &addr.ipv6, NULL,
							   1, NULL);
		if (status != PJ_SUCCESS) {
			DBG(OMCI_API_ERR, ("sip UDP transport start failed!\n"));
			ret = OMCI_API_ERROR;
		}
		break;

	default:
		DBG(OMCI_API_ERR, ("unknown agent proto %u specified!\n",
				   agent->agent_proto));
		ret = OMCI_API_ERROR;
		goto on_err;
	}

	if (status != PJ_SUCCESS) {
		DBG(OMCI_API_ERR, ("sip transport start failed!\n"));
		ret = OMCI_API_ERROR;
		goto on_err;
	}

	/* Init transaction layer.
           This will create/initialize transaction hash tables etc. */
	status = pjsip_tsx_layer_init_module(pjsip->pj_sip_endpt);
	if (status != PJ_SUCCESS) {
		DBG(OMCI_API_ERR, ("sip tsx layer init failed!\n"));
		ret = OMCI_API_ERROR;
		goto on_err;
	}

	/* Initialize UA layer module.
           This will create/initialize dialog hash tables etc. */
	status = pjsip_ua_init_module(pjsip->pj_sip_endpt, NULL );
	if (status != PJ_SUCCESS) {
		DBG(OMCI_API_ERR, ("sip ua layer init failed!\n"));
		ret = OMCI_API_ERROR;
		goto on_err;
	}


	/*
	* Init invite session module.
	* The invite session module initialization takes additional argument,
	* i.e. a structure containing callbacks to be called on specific
	* occurence of events.
	*
	* The on_state_changed and on_new_session callbacks are mandatory.
	* Application must supply the callback function.
	*
	* We use on_media_update() callback in this application to start
	* media transmission.
	*/

	/* Init the callback for INVITE session*/
	pj_bzero(&inv_cb, sizeof(inv_cb));
	inv_cb.on_state_changed = &call_on_state_changed;
	inv_cb.on_new_session 	= &call_on_forked;
	inv_cb.on_media_update 	= &call_on_media_update;

	/* Initialize invite session module:  */
	status = pjsip_inv_usage_init(pjsip->pj_sip_endpt, &inv_cb);
	if (status != PJ_SUCCESS) {
		DBG(OMCI_API_ERR, ("sip invite session init failed!\n"));
		ret = OMCI_API_ERROR;
		goto on_err;
	}

	/* Initialize 100rel support */
	status = pjsip_100rel_init_module(pjsip->pj_sip_endpt);
	if (status != PJ_SUCCESS) {
		DBG(OMCI_API_ERR, ("sip 100rel init failed!\n"));
		ret = OMCI_API_ERROR;
		goto on_err;
	}

	/* Register our SIP module to receive incoming requests.*/
	status = pjsip_endpt_register_module(pjsip->pj_sip_endpt, &mod_app);
	if (status != PJ_SUCCESS) {
		DBG(OMCI_API_ERR, ("sip module registration failed!\n"));
		ret = OMCI_API_ERROR;
		goto on_err;
	}

	/* Register our SIP Transport Layer module to handle counters.*/
	status = pjsip_endpt_register_module(pjsip->pj_sip_endpt, &mod_trl);
	if (status != PJ_SUCCESS) {
		DBG(OMCI_API_ERR, ("sip PM module registration failed!\n"));
		ret = OMCI_API_ERROR;
		goto on_err;
	}

	/* start worker thread*/
#if PJ_HAS_THREADS
	pjsip->sip_thread_quit = false;

	status = pj_thread_create(pjsip->pool, "omci_api_sip_thread",
				  &sip_worker_thread,
				  (void*)pjsip, 0, 0, &pjsip->sip_thread);
	if (status != PJ_SUCCESS) {
		DBG(OMCI_API_ERR, ("sip thread create failed!\n"));
		ret = OMCI_API_ERROR;
		goto on_err;
	}
#else
	#error "Please enable PJ_HAS_THREADS!!!"
#endif

	return ret;

on_err:
	if (pjsip->pj_sip_endpt) {
		pjsip_endpt_destroy(pjsip->pj_sip_endpt);
		pjsip->pj_sip_endpt = NULL;
	}

	if (pjsip->pool) {
		pj_pool_release(pjsip->pool);
		pjsip->pool = NULL;
	}

	pj_caching_pool_destroy(&pjsip->pj_cp);

	return ret;
}

enum omci_api_return sip_agent_destroy(struct sip_data *sip)
{
	struct sip_endpt *pjsip = &sip->pjsip;
	uint8_t i;

	if (!pjsip->pj_sip_endpt) {
		DBG(OMCI_API_WRN, ("sip agent doesn't exist!\n"));
		return OMCI_API_SUCCESS;
	}

	if (pjsip_thread_register() != 0)
		return OMCI_API_ERROR;

	for (i = 0; i < OMCI_API_SIP_USERS_NUM; i++) {
		if (sip->regc[i]) {
			pjsip_regc_destroy(sip->regc[i]);
			sip->regc[i] = NULL;
		}
	}

	pjsip->sip_thread_quit = true;
	if (pjsip->sip_thread) {
		pj_thread_join(pjsip->sip_thread);
		pj_thread_destroy(pjsip->sip_thread);
		pjsip->sip_thread = NULL;
	}

	if (pjsip->pj_sip_endpt) {
		pjsip_endpt_destroy(pjsip->pj_sip_endpt);
		pjsip->pj_sip_endpt = NULL;

	}

	if (pjsip->pool) {
		pj_pool_release(pjsip->pool);
		pjsip->pool = NULL;
	}

	pj_caching_pool_destroy(&pjsip->pj_cp);

	return OMCI_API_SUCCESS;
}

enum omci_api_return sip_agent_update(struct sip_data *sip)
{
	if (sip_agent_destroy(sip) != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("sip agent destroy failed!\n"));
		return OMCI_API_ERROR;
	}

	if (sip_agent_create(sip) != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("sip agent create failed!\n"));
		return OMCI_API_ERROR;
	}

	return OMCI_API_SUCCESS;
}

enum omci_api_return sip_user_register(struct sip_data *sip,
				       const uint8_t id)
{
	pj_status_t status;
	const struct sip_user *user = &sip->user[id];
	struct sip_agent *agent = &sip->agent[0];
	pjsip_tx_data *tdata;
	/* <sip:>*/
	char registrar_buf[OMCI_API_URI_MAX + 6];
	/* <sip:@>*/
	char username_buf[OMCI_API_URI_MAX + OMCI_API_USERNAME_MAX + 7];
	char contact_buf[OMCI_API_URI_MAX + OMCI_API_USERNAME_MAX + 7];
	pj_str_t registrar_uri;
	pj_str_t aor, contact;
	pjsip_cred_info cred;

	if (!sip->pjsip.pj_sip_endpt) {
		DBG(OMCI_API_ERR, ("sip session not available!\n"));
		return OMCI_API_ERROR;
	}

	if (pjsip_thread_register() != 0) {
		DBG(OMCI_API_ERR, ("sip thread registration error!\n"));
		return OMCI_API_ERROR;
	}

	if (sip->regc[id])
		pjsip_regc_destroy(sip->regc[id]);

	status = pjsip_regc_create(sip->pjsip.pj_sip_endpt, (void*)sip,
				   &on_user_reg, &(sip->regc[id]));
	if (status != PJ_SUCCESS) {
		DBG(OMCI_API_ERR, ("can't create regc session!\n"));
		return OMCI_API_ERROR;
	}

	/* make registrar*/
	pj_ansi_snprintf(registrar_buf, sizeof(registrar_buf), "<sip:%s>",
			 strlen(sip->agent[0].registrar) ?
				sip->agent[0].registrar : user->user_ip_s);
	registrar_uri = pj_str((char*)registrar_buf);

	/* make aor*/
	pj_ansi_snprintf(username_buf, sizeof(username_buf),
			 "<sip:%s@%s>", user->username,
					user->user_ip_s);
	aor = pj_str((char*)username_buf);

	/* make contact*/
	pj_ansi_snprintf(contact_buf, sizeof(contact_buf),
			 "<sip:%s@%s>", user->username,
					user->user_ip_s);
	contact = pj_str((char*)contact_buf);

	status = pjsip_regc_init(sip->regc[id], &registrar_uri, &aor, &aor, 1,
				 &contact,
				 !agent->reg_exp_time ?
					PJSIP_REGC_EXPIRATION_NOT_SPECIFIED :
					agent->reg_exp_time);
	if (status != PJ_SUCCESS) {
		DBG(OMCI_API_ERR, ("can't initialize regc session (%d)!\n",
				   status));
		pjsip_regc_destroy(sip->regc[id]);
		return OMCI_API_ERROR;
	}

	if (strlen(user->realm)) {
		pj_bzero(&cred, sizeof(cred));
		cred.realm = pj_str(user->realm);
		cred.scheme = pj_str("digest");
		cred.username = pj_str(user->username);
		cred.data_type = PJSIP_CRED_DATA_PLAIN_PASSWD;
		cred.data = pj_str(user->password);
	
		status = pjsip_regc_set_credentials(sip->regc[id], 1, &cred);
		if (status != PJ_SUCCESS) {
			pjsip_regc_destroy(sip->regc[id]);
			return OMCI_API_ERROR;
		}
	}

	/* Register */
	status = pjsip_regc_register(sip->regc[id], PJ_TRUE, &tdata);
	if (status != PJ_SUCCESS) {
		DBG(OMCI_API_ERR, ("sip register request create failed!\n"));
		pjsip_regc_destroy(sip->regc[id]);
		return OMCI_API_ERROR;
	}

	status = pjsip_regc_send(sip->regc[id], tdata);
	if (status != PJ_SUCCESS) {
		DBG(OMCI_API_ERR, ("sip register request send failed!\n"));
		pjsip_regc_destroy(sip->regc[id]);
		return OMCI_API_ERROR;
	}

	return OMCI_API_SUCCESS;
}

enum omci_api_return sip_call_make(struct sip_data *sip,
				   const uint8_t user_id,
				   const char *dst_uri)
{
	struct sip_call *call;
	char uri_buf[OMCI_API_URI_MAX + OMCI_API_USERNAME_MAX + 7]; /*<sip:@>*/
	char cnt_buf[OMCI_API_URI_MAX + OMCI_API_USERNAME_MAX + 7]; /*<sip:@>*/
	struct sip_user *sip_usr;
	pj_str_t local_uri, contact, remote_uri = pj_str((char*)dst_uri);
	pjsip_dialog *dlg;
	pjmedia_sdp_session *sdp;
	pjsip_tx_data *tdata;
	pjsip_cred_info	cred[1];
	pj_status_t status;

	if (user_id >= OMCI_API_SIP_USERS_NUM) {
		DBG(OMCI_API_ERR, ("Unsupported user id (%u)!\n", user_id));
		return OMCI_API_ERROR;
	}

	if (!sip->pjsip.pj_sip_endpt) {
		DBG(OMCI_API_ERR, ("SIP session not available!\n"));
		return OMCI_API_ERROR;
	}

	call = &sip->call[user_id];

	if (call->inv) {
		DBG(OMCI_API_ERR, ("No free call slot!\n"));
		return OMCI_API_ERROR;
	}

	if (pjsip_thread_register() != 0)
		return OMCI_API_ERROR;

	/* get sip user data*/
	sip_usr = &sip->user[user_id];

	pj_ansi_sprintf(uri_buf, "<sip:%s@%s>",
					sip_usr->username,
					strlen(sip->agent[0].registrar) ?
						sip->agent[0].registrar :
						sip_usr->user_ip_s);
	local_uri = pj_str((char*)uri_buf);

	pj_ansi_sprintf(cnt_buf, "<sip:%s@%s>", sip_usr->username,
						sip_usr->user_ip_s);
	contact = pj_str((char*)cnt_buf);

	/* create UAC dialog */
	status = pjsip_dlg_create_uac(	pjsip_ua_instance(),
					&local_uri,	 /* local URI*/
					&contact,	 /* local Contact */
					&remote_uri,     /* remote URI*/
					NULL,		 /* remote target*/
					&dlg);		 /* dialog*/
	if (status != PJ_SUCCESS) {
		DBG(OMCI_API_ERR, ("UAC dialog create failed\n"));
		return OMCI_API_ERROR;
	}

	if (strlen(sip_usr->realm)) {
		cred[0].realm	  = pj_str((char*)sip_usr->realm);
		cred[0].scheme    = pj_str("digest");
		cred[0].data_type = PJSIP_CRED_DATA_PLAIN_PASSWD;
		cred[0].username  = pj_str((char*)sip_usr->username);
		cred[0].data      = pj_str((char*)sip_usr->password);
	
		pjsip_auth_clt_set_credentials( &dlg->auth_sess, 1, cred);
	}

	/* Get the SDP body to be put in the outgoing INVITE, by asking
	   media endpoint to create one for us. The SDP will contain all
	   codecs that have been registered to it (in this case, only
	   PCMA and PCMU), plus telephony event.*/
	if (call_sdp_create(sip_usr, dlg->pool, &sdp) != 0) {
		DBG(OMCI_API_ERR, ("SDP create failed, user id=%u!\n",
				  user_id));
		return OMCI_API_ERROR;
	}

	/* Create the INVITE session, and pass the SDP returned earlier
	   as the session's initial capability.*/
	status = pjsip_inv_create_uac(dlg, sdp, 0, &call->inv);
	if (status != PJ_SUCCESS) {
		DBG(OMCI_API_ERR, ("INVITE UAC create failed, call idx=%u!\n",
				  user_id));
		/*pjsip_dlg_terminate(dlg);*/
		return OMCI_API_ERROR;
	}

	/* Attach call data to invite session */
	call->idx = user_id;
	call->user = sip_usr;
	call->inv->mod_data[mod_app.id] = call;

	/* If we want the initial INVITE to travel to specific SIP proxies,
	   then we should put the initial dialog's route set here. The final
	   route set will be updated once a dialog has been established.
	*/
	if (strlen(sip->agent[0].proxy)) {
		pjsip_route_hdr route_set;
		pjsip_route_hdr *route;
		const pj_str_t hname = { "Route", 5 };

		pj_ansi_sprintf(uri_buf, "sip:%s;lr", sip->agent[0].proxy);

		pj_list_init(&route_set);

		route = pjsip_parse_hdr( dlg->pool, &hname,
					 uri_buf, strlen(uri_buf),
					 NULL);
		if (route == NULL) {
			DBG(OMCI_API_ERR, ("INVITE route set failed, "
					   "user id=%u!\n", user_id));
			return OMCI_API_ERROR;
		}

		pj_list_push_back(&route_set, route);

		pjsip_dlg_set_route_set(dlg, &route_set);
	}


	/* Create initial INVITE request.
	   This INVITE request will contain a perfectly good request and
	   an SDP body as well.*/
	status = pjsip_inv_invite(call->inv, &tdata);
	if (status != PJ_SUCCESS) {
		DBG(OMCI_API_ERR, ("INVITE req create failed, user id=%u!\n",
				  user_id));
		return OMCI_API_ERROR;
	}

	/* Send initial INVITE request.
	   From now on, the invite session's state will be reported to us
	   via the invite session callbacks.*/
	status = pjsip_inv_send_msg(call->inv, tdata);
    	if (status != PJ_SUCCESS) {
		DBG(OMCI_API_ERR, ("INVITE req send failed, user id=%u!\n",
				  user_id));
		return OMCI_API_ERROR;
	}

	return OMCI_API_SUCCESS;
}

enum omci_api_return sip_call_end(struct sip_data *sip, const uint8_t user_id)
{
	struct sip_call *call;
	pjsip_tx_data *tdata;
	pj_status_t status;
	int code;

	if (user_id >= OMCI_API_SIP_USERS_NUM) {
		DBG(OMCI_API_ERR, ("Unsupported user id (%u)!\n", user_id));
		return OMCI_API_ERROR;
	}

	if (!sip->pjsip.pj_sip_endpt) {
		DBG(OMCI_API_ERR, ("SIP session not available!\n"));
		return OMCI_API_ERROR;
	}

	call = &sip->call[user_id];

	if (call->inv == NULL) {
		DBG(OMCI_API_MSG, ("call (%u) is inactive!\n", user_id));
		return OMCI_API_SUCCESS;
	}

	if (pjsip_thread_register() != 0)
		return OMCI_API_ERROR;

	if (call->inv->state == PJSIP_INV_STATE_CONFIRMED)
	    code = PJSIP_SC_OK;
	else if (call->inv->role == PJSIP_ROLE_UAS)
	    code = PJSIP_SC_DECLINE;
	else
	    code = PJSIP_SC_REQUEST_TERMINATED;

	status = pjsip_inv_end_session(call->inv, code, NULL, &tdata);

	if (status == PJ_SUCCESS && tdata != NULL)
		pjsip_inv_send_msg(call->inv, tdata);

	return status != PJ_SUCCESS ? OMCI_API_ERROR : OMCI_API_SUCCESS;
}

enum omci_api_return sip_call_answer(struct sip_data *sip,
				     const uint8_t user_id)
{
	struct sip_call *call;
	pjsip_tx_data *tdata;
	pj_status_t status;

	if (user_id >= OMCI_API_SIP_USERS_NUM) {
		DBG(OMCI_API_ERR, ("Unsupported user id (%u)!\n", user_id));
		return OMCI_API_ERROR;
	}

	if (!sip->pjsip.pj_sip_endpt) {
		DBG(OMCI_API_ERR, ("SIP session not available!\n"));
		return OMCI_API_ERROR;
	}

	call = &sip->call[user_id];

	if (pjsip_thread_register() != 0)
		return OMCI_API_ERROR;

	/* Now create 200 response.*/
	status = pjsip_inv_answer(call->inv, 200, NULL,NULL, &tdata);
	if (status != PJ_SUCCESS)
		return OMCI_API_ERROR;

	/* Send the 200 response.*/
	status = pjsip_inv_send_msg(call->inv, tdata);
	if (status != PJ_SUCCESS)
		return OMCI_API_ERROR;

	return OMCI_API_SUCCESS;
}

enum omci_api_return sip_init(struct sip_data *sip)
{
	pj_status_t status;
	uint8_t i;

	/* init pjlib */
	status = pj_init();
	if (status != PJ_SUCCESS)
		return OMCI_API_ERROR;

	/* init pjlib-util */
	status = pjlib_util_init();
	if (status != PJ_SUCCESS)
		return OMCI_API_ERROR;

	/* set default sip agent configuration*/
	if (sip_agent_default_cfg_get(&sip->agent[0]) != 0) {
		DBG(OMCI_API_ERR, ("sip agent default cfg get failed!\n"));
		return OMCI_API_ERROR;
	}

	/* set default sip user(s) configuration*/
	for (i = 0; i < OMCI_API_SIP_USERS_NUM; i++) {
		if (sip_user_default_cfg_get(i, &sip->user[i]) != 0) {
			DBG(OMCI_API_ERR, ("sip user %u default cfg get "
					   "failed!\n", i));
			return OMCI_API_ERROR;
		}
	}

	/* create sip agent*/
	if (sip_agent_create(sip) != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("SIP agent create failed!\n"));
		return OMCI_API_ERROR;
	}

	return OMCI_API_SUCCESS;
}

enum omci_api_return sip_exit(struct sip_data *sip)
{
	sip_agent_destroy(sip);

	return OMCI_API_SUCCESS;
}

void sip_debug_level_set(uint8_t level)
{
	switch (level) {
	/* OMCI_DBG_MSG */
	case 0:
		pj_log_set_level(6);
		break;

	/* OMCI_DBG_PRN */
	case 1:
		pj_log_set_level(3);
		break;

	/* OMCI_DBG_WRN */
	case 2:
		pj_log_set_level(2);
		break;

	/* OMCI_DBG_ERR */
	case 3:
		pj_log_set_level(1);
		break;

	/* OMCI_DBG_OFF */
	case 4:
		pj_log_set_level(0);
		break;
	}
}

#endif /* #ifdef INCLUDE_OMCI_API_VOIP */
