/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_voip_common_h
#define _omci_api_voip_common_h

#include "omci_api_common.h"

#ifdef INCLUDE_OMCI_API_VOIP

__BEGIN_DECLS

/** \addtogroup OMCI_API_VOIP

   @{
*/

extern struct voip_ctx *voip_ctx;

#define SIP_CTX(voip_ctx)		&((struct voip_ctx *)(voip_ctx))->sip
#define FXS_CTX(voip_ctx)		&((struct voip_ctx *)(voip_ctx))->fxs

#include "ifxos_time.h"
#include "ifxos_thread.h"
#include "ifxos_memory_alloc.h"

#include "omci_api_fxs.h"
#include "omci_api_sip.h"

/** Structure to specify VoIP context.
*/
struct voip_ctx {
	/** VoIP is initialized */
	bool init;
	/** Thread run flag*/
	bool run;
	/** FXS specific data*/
	struct fxs_data fxs;
	/** SIP specific data*/
	struct sip_data sip;
	/** Event thread control structure */
	IFXOS_ThreadCtrl_t fxs_event_thread_ctrl;
	/** VoIP callback */
	omci_api_voip_cb_t *callback;
};

enum omci_api_return voip_init(struct omci_api_ctx *ctx);

enum omci_api_return voip_exit(struct omci_api_ctx *ctx);

/** @} */

__END_DECLS

#endif

#endif
