/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include <stdarg.h> /* va_list */
#include <unistd.h>
#include <fcntl.h>
#include "ifxos_thread.h"
#include "ifx_crc.h"
#include "ifxos_time.h"
#include "ifxos_memory_alloc.h"
#include "ifxos_misc.h"
#include "omci_api_common.h"
#include "omci_api_debug.h"

#if defined(INCLUDE_REMOTE_ONU)
#include "dti_rpc.h"
#endif

#include <stdio.h>
#include "drv_onu_lan_interface.h"

#define GOI_NAME "optic"

#define DLOG(fmt, ...) do { \
	FILE *_f = fopen("/tmp/8311_api.log", "a"); \
	if (_f) { fprintf(_f, fmt "\n", ##__VA_ARGS__); fclose(_f); } \
} while (0)

/*#define LOCAL_ETH*/

/* Diagnostic: check SERDES link status via full config read (v7.5.1) */
static void _diag_serdes(struct omci_api_ctx *ctx, const char *label)
{
	union lan_port_cfg_get_u cfg;
	FILE *f;
	memset(&cfg, 0, sizeof(cfg));
	cfg.in.index = 0;
	if (dev_ctl(0, ctx->onu_fd, FIO_LAN_PORT_CFG_GET,
		    &cfg, sizeof(cfg)) == 0) {
		f = fopen("/tmp/8311_serdes.log", "a");
		if (f) {
			fprintf(f, "SERDES[%s]: enable=%u speed=%u duplex=%u\n",
				label, cfg.out.uni_port_en,
				cfg.out.speed_mode,
				cfg.out.duplex_mode);
			fclose(f);
		}
	}
}

/** \addtogroup OMCI_API_API

   @{
*/

/** Image store thread priority */
#define OMCI_API_REBOOT_THREAD_PRIO            IFXOS_THREAD_PRIO_LOWEST
/** Image store thread stack size */
#define OMCI_API_REBOOT_THREAD_STACKSIZE       IFXOS_DEFAULT_STACK_SIZE
/** ONU reboot thread control structure */
static IFXOS_ThreadCtrl_t onu_reboot_thread_control;

#ifndef OMCI_API_DEBUG_DISABLE
struct dbg_module_level dbg_api_module = {OMCI_API_WRN, "API"};

const char *dbg_api_levels[OMCI_API_OFF+1] = {
	"MSG",
	"PRN",
	"WRN",
	"ERR",
	"OFF",
};
#endif

static uint32_t gp_crc32_i363_table[256] = {
	0x00000000L, 0x04c11db7L, 0x09823b6eL, 0x0d4326d9L,
	0x130476dcL, 0x17c56b6bL, 0x1a864db2L, 0x1e475005L,
	0x2608edb8L, 0x22c9f00fL, 0x2f8ad6d6L, 0x2b4bcb61L,
	0x350c9b64L, 0x31cd86d3L, 0x3c8ea00aL, 0x384fbdbdL,
	0x4c11db70L, 0x48d0c6c7L, 0x4593e01eL, 0x4152fda9L,
	0x5f15adacL, 0x5bd4b01bL, 0x569796c2L, 0x52568b75L,
	0x6a1936c8L, 0x6ed82b7fL, 0x639b0da6L, 0x675a1011L,
	0x791d4014L, 0x7ddc5da3L, 0x709f7b7aL, 0x745e66cdL,
	0x9823b6e0L, 0x9ce2ab57L, 0x91a18d8eL, 0x95609039L,
	0x8b27c03cL, 0x8fe6dd8bL, 0x82a5fb52L, 0x8664e6e5L,
	0xbe2b5b58L, 0xbaea46efL, 0xb7a96036L, 0xb3687d81L,
	0xad2f2d84L, 0xa9ee3033L, 0xa4ad16eaL, 0xa06c0b5dL,
	0xd4326d90L, 0xd0f37027L, 0xddb056feL, 0xd9714b49L,
	0xc7361b4cL, 0xc3f706fbL, 0xceb42022L, 0xca753d95L,
	0xf23a8028L, 0xf6fb9d9fL, 0xfbb8bb46L, 0xff79a6f1L,
	0xe13ef6f4L, 0xe5ffeb43L, 0xe8bccd9aL, 0xec7dd02dL,
	0x34867077L, 0x30476dc0L, 0x3d044b19L, 0x39c556aeL,
	0x278206abL, 0x23431b1cL, 0x2e003dc5L, 0x2ac12072L,
	0x128e9dcfL, 0x164f8078L, 0x1b0ca6a1L, 0x1fcdbb16L,
	0x018aeb13L, 0x054bf6a4L, 0x0808d07dL, 0x0cc9cdcaL,
	0x7897ab07L, 0x7c56b6b0L, 0x71159069L, 0x75d48ddeL,
	0x6b93dddbL, 0x6f52c06cL, 0x6211e6b5L, 0x66d0fb02L,
	0x5e9f46bfL, 0x5a5e5b08L, 0x571d7dd1L, 0x53dc6066L,
	0x4d9b3063L, 0x495a2dd4L, 0x44190b0dL, 0x40d816baL,
	0xaca5c697L, 0xa864db20L, 0xa527fdf9L, 0xa1e6e04eL,
	0xbfa1b04bL, 0xbb60adfcL, 0xb6238b25L, 0xb2e29692L,
	0x8aad2b2fL, 0x8e6c3698L, 0x832f1041L, 0x87ee0df6L,
	0x99a95df3L, 0x9d684044L, 0x902b669dL, 0x94ea7b2aL,
	0xe0b41de7L, 0xe4750050L, 0xe9362689L, 0xedf73b3eL,
	0xf3b06b3bL, 0xf771768cL, 0xfa325055L, 0xfef34de2L,
	0xc6bcf05fL, 0xc27dede8L, 0xcf3ecb31L, 0xcbffd686L,
	0xd5b88683L, 0xd1799b34L, 0xdc3abdedL, 0xd8fba05aL,
	0x690ce0eeL, 0x6dcdfd59L, 0x608edb80L, 0x644fc637L,
	0x7a089632L, 0x7ec98b85L, 0x738aad5cL, 0x774bb0ebL,
	0x4f040d56L, 0x4bc510e1L, 0x46863638L, 0x42472b8fL,
	0x5c007b8aL, 0x58c1663dL, 0x558240e4L, 0x51435d53L,
	0x251d3b9eL, 0x21dc2629L, 0x2c9f00f0L, 0x285e1d47L,
	0x36194d42L, 0x32d850f5L, 0x3f9b762cL, 0x3b5a6b9bL,
	0x0315d626L, 0x07d4cb91L, 0x0a97ed48L, 0x0e56f0ffL,
	0x1011a0faL, 0x14d0bd4dL, 0x19939b94L, 0x1d528623L,
	0xf12f560eL, 0xf5ee4bb9L, 0xf8ad6d60L, 0xfc6c70d7L,
	0xe22b20d2L, 0xe6ea3d65L, 0xeba91bbcL, 0xef68060bL,
	0xd727bbb6L, 0xd3e6a601L, 0xdea580d8L, 0xda649d6fL,
	0xc423cd6aL, 0xc0e2d0ddL, 0xcda1f604L, 0xc960ebb3L,
	0xbd3e8d7eL, 0xb9ff90c9L, 0xb4bcb610L, 0xb07daba7L,
	0xae3afba2L, 0xaafbe615L, 0xa7b8c0ccL, 0xa379dd7bL,
	0x9b3660c6L, 0x9ff77d71L, 0x92b45ba8L, 0x9675461fL,
	0x8832161aL, 0x8cf30badL, 0x81b02d74L, 0x857130c3L,
	0x5d8a9099L, 0x594b8d2eL, 0x5408abf7L, 0x50c9b640L,
	0x4e8ee645L, 0x4a4ffbf2L, 0x470cdd2bL, 0x43cdc09cL,
	0x7b827d21L, 0x7f436096L, 0x7200464fL, 0x76c15bf8L,
	0x68860bfdL, 0x6c47164aL, 0x61043093L, 0x65c52d24L,
	0x119b4be9L, 0x155a565eL, 0x18197087L, 0x1cd86d30L,
	0x029f3d35L, 0x065e2082L, 0x0b1d065bL, 0x0fdc1becL,
	0x3793a651L, 0x3352bbe6L, 0x3e119d3fL, 0x3ad08088L,
	0x2497d08dL, 0x2056cd3aL, 0x2d15ebe3L, 0x29d4f654L,
	0xc5a92679L, 0xc1683bceL, 0xcc2b1d17L, 0xc8ea00a0L,
	0xd6ad50a5L, 0xd26c4d12L, 0xdf2f6bcbL, 0xdbee767cL,
	0xe3a1cbc1L, 0xe760d676L, 0xea23f0afL, 0xeee2ed18L,
	0xf0a5bd1dL, 0xf464a0aaL, 0xf9278673L, 0xfde69bc4L,
	0x89b8fd09L, 0x8d79e0beL, 0x803ac667L, 0x84fbdbd0L,
	0x9abc8bd5L, 0x9e7d9662L, 0x933eb0bbL, 0x97ffad0cL,
	0xafb010b1L, 0xab710d06L, 0xa6322bdfL, 0xa2f33668L,
	0xbcb4666dL, 0xb8757bdaL, 0xb5365d03L, 0xb1f740b4L
};

#if defined(INCLUDE_REMOTE_ONU)
IFXOS_lock_t remote_lock[DTI_MAX_CONNECTIONS];
#endif

/** Retrieve driver version

   \param[in]  ctx     OMCI API context pointer
   \param[out] drv_ver Returns driver version
*/
static enum omci_api_return
omci_api_drv_version_get(struct omci_api_ctx *ctx,
			 char drv_ver[OMCI_API_MAX_INFO_STRING_LEN])
{
	struct onu_version_string drv_version;
	int drv_err;

	memset(&drv_version, 0, sizeof(drv_version));
	drv_err = dev_ctl(ctx->remote, ctx->onu_fd, FIO_ONU_VERSION_GET,
			  &drv_version, sizeof(drv_version));
	if (drv_err)
		return OMCI_API_ERROR;

	if (strlen(drv_version.onu_version) >= OMCI_API_MAX_INFO_STRING_LEN)
		return OMCI_API_ERROR;
	else
		strcpy(drv_ver, drv_version.onu_version);

	return OMCI_API_SUCCESS;
}

uint32_t omci_api_calc_checksum_crc32_i363(const void *p_data, size_t data_sz)
{
	uint32_t crc;
	unsigned int i;

	crc = 0xffffffff;

	for (i = 0; i < data_sz; i++)
		crc =
		    (crc << 8) ^
		    gp_crc32_i363_table[((crc >> 24) ^ ((uint8_t *)p_data)[i]) &
				     0xff];

	return crc ^ 0xffffffff;
}

static enum omci_api_return capability_get(struct omci_api_ctx *ctx)
{
	struct gpe_capability capability;
	int err;

	memset(&capability, 0, sizeof(capability));
	err = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_CAPABILITY_GET,
		      &capability, sizeof(capability));
	if (err)
		return OMCI_API_ERROR;

	ctx->capability.max_meter = capability.max_meter;
	ctx->capability.max_gpix = capability.max_gpix;
	ctx->capability.max_eth_uni = capability.max_eth_uni;
	ctx->capability.max_pots_uni = capability.max_pots_uni;
	ctx->capability.max_bridge_port = capability.max_bridge_port;
	ctx->capability.hw_version = capability.hw_version;

	DLOG("capability: eth_uni=%u pots=%u meter=%u gpix=%u bridge=%u hw=0x%x",
	     capability.max_eth_uni, capability.max_pots_uni,
	     capability.max_meter, capability.max_gpix,
	     capability.max_bridge_port, capability.hw_version);

	return OMCI_API_SUCCESS;
}

static enum omci_api_return
uni2lan_map(struct omci_api_ctx *ctx, const char *uni2lan)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint8_t i, uni, lan;
	char buff[16];
	IFXOS_File_t *f;

	/* set no mapping */
	for (i = 0; i < ONU_GPE_MAX_UNI; i++)
		ctx->uni2lan[i] = -1;

	if (uni2lan) {
		DBG(OMCI_API_MSG, ("Reading UNI2LAN mapping from %s ...\n",
								      uni2lan));
		f = IFXOS_FOpen(uni2lan, "r");
		if (!f) {
			DBG(OMCI_API_ERR, ("%s open failed\n", uni2lan));
			return OMCI_API_ERROR;
		}

		while (IFXOS_FGets(buff, sizeof(buff), f)) {
			/* get mapping info */
			if (sscanf(buff, "%hhu %hhu", &uni, &lan) != 2)
				continue;

			if (lan >= ONU_GPE_MAX_UNI) {
				DBG(OMCI_API_ERR,
					("LAN port %u map failed\n", lan));
				ret = OMCI_API_ERROR;
				break;
			}

			ctx->uni2lan[lan] = (int)uni;
			
			DBG(OMCI_API_MSG, ("UNI2LAN: %u %u\n", uni, lan));
			
			/* check for duplicates */
			for (i = 0; i < ONU_GPE_MAX_UNI; i++) {
				if (i == lan)
					continue;
				if (ctx->uni2lan[i] == (int)uni) {
					DBG(OMCI_API_ERR,
						("UNI2LAN duplicate entry for %u<->%u\n",
								uni, i));
					ret = OMCI_API_ERROR;
					break;
				}
			}
		}

		IFXOS_FClose(f);
	}
	/* If no file provided, leave mapping as -1.
	   uni2lan_portmap_get() will populate it from the kernel
	   after the device is opened. */

	return ret;
}

/**
   v7.5.1: Retrieve the LAN port-to-UNI mapping from the kernel driver.

   The ioctl returns a 12-byte structure: 1 byte count + up to 11 byte
   mapping entries.  Each entry gives the UNI ID for that LAN port index.

   Must be called after ctx->onu_fd is valid.
*/
static enum omci_api_return
uni2lan_portmap_get(struct omci_api_ctx *ctx)
{
	uint8_t portmap[12];
	uint8_t i, count;
	enum omci_api_return ret;

	memset(portmap, 0, sizeof(portmap));
	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_ONU_LAN_PORTMAP_GET,
		      portmap, sizeof(portmap));
	if (ret == OMCI_API_SUCCESS) {
		count = portmap[0];
		DLOG("LAN portmap: count=%u", count);
		/*
		   Kernel returns: portmap[1+i] = physical_port for logical_port i.
		   Our v4.5.0 omci_api_uni2lan() searches uni2lan[] for a matching
		   UNI ME instance byte and returns the array INDEX as the port.
		   So we need: uni2lan[physical_port] = UNI_instance = logical + 1.
		*/
		for (i = 0; i < count && i < ONU_GPE_MAX_UNI; i++) {
			uint8_t physical_port = portmap[1 + i];
			if (physical_port < ONU_GPE_MAX_UNI) {
				ctx->uni2lan[physical_port] = (int)(i + 1);
				DLOG("  uni2lan[%u] = %d (logical %u)",
				     physical_port, i + 1, i);
			}
		}
	} else {
		DBG(OMCI_API_ERR, ("LAN portmap get failed, ret=%d\n", ret));
	}

	return ret;
}

enum omci_api_return omci_api_init(struct omci_api_init_data *init,
				   omci_api_event_handler_t *handler,
				   void *caller_ctx,
				   const char *remote_ip,
				   const char *uni2lan,
				   struct omci_api_ctx **p_ctx)
{
	static char dev_onu_name[] = "/dev/" ONU_NAME "0";
	static char dev_goi_name[] = "/dev/" GOI_NAME "0";
	struct omci_api_ctx *ctx;
	enum omci_api_return ret;
	int i;

	int _afd;

	if (!init || !handler || !p_ctx)
		return OMCI_API_ERROR;

	_afd = open("/tmp/omcid_init.log",
		    O_WRONLY | O_APPEND | O_CREAT, 0644);

#define ALOG(msg) do { \
	write(STDERR_FILENO, msg, sizeof(msg) - 1); \
	if (_afd >= 0) write(_afd, msg, sizeof(msg) - 1); \
} while (0)

	ALOG("[omcid] api: alloc\n");
	ctx = (struct omci_api_ctx *)IFXOS_MemAlloc(sizeof(*ctx));
	if (!ctx) {
		DBG(OMCI_API_ERR, ("No memory\n"));
		if (_afd >= 0) close(_afd);
		return OMCI_API_ERROR;
	}

	memset(ctx, 0, sizeof(*ctx));

	*p_ctx = ctx;

	/* Perform UNI to LAN port IDs mapping */
	ALOG("[omcid] api: uni2lan\n");
	ret = uni2lan_map(ctx, uni2lan);
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR,("Can't map UNI to LAN!\n"));
		goto cleanup;
	}

	/** \todo XXX FIXME */
	ctx->onu_id = 0x12;
	ctx->caller = caller_ctx;
	ctx->event.cb = handler;

#if defined(INCLUDE_REMOTE_ONU)
	if (remote_ip || remote_default_ip_get()) {
		DBG(OMCI_API_MSG, ("Initialize remote connection ...\n"));

		for (i = 0; i < DTI_MAX_CONNECTIONS; i++)
			IFXOS_LockInit(&remote_lock[i]);

		ret = remote_init(remote_ip ?
					remote_ip : remote_default_ip_get(),
				  DTI_MAX_CONNECTIONS);
		if (ret != OMCI_API_SUCCESS) {
			DBG(OMCI_API_ERR,
				("Can't initialize remote connection\n"));
			goto cleanup;
		}

		ctx->remote = true;
	}
#endif

#if defined(INCLUDE_DRIVER_SIMULATION)
	optic_init();
	onu_init();
#endif
	ctx->onu_fd = -1;
	ctx->goi_fd = -1;
	ctx->onu_fd_nfc = -1;
	ctx->goi_fd_nfc = -1;

	ALOG("[omcid] api: dev_open onu\n");
	ctx->onu_fd = dev_open(ctx->remote, dev_onu_name);
	ALOG("[omcid] api: dev_open goi\n");
	ctx->goi_fd = dev_open(ctx->remote, dev_goi_name);
	ALOG("[omcid] api: dev_open onu_nfc\n");
	ctx->onu_fd_nfc = dev_open(ctx->remote, dev_onu_name);
	ALOG("[omcid] api: dev_open goi_nfc\n");
	ctx->goi_fd_nfc = dev_open(ctx->remote, dev_goi_name);

	if (ctx->onu_fd < 0 || ctx->onu_fd_nfc < 0) {
		DBG(OMCI_API_ERR, ("Can't open %s %d %d\n", dev_onu_name,
							    ctx->onu_fd,
							    ctx->onu_fd_nfc));
		goto cleanup;
	}

	if (ctx->goi_fd < 0 || ctx->goi_fd_nfc < 0) {
		DBG(OMCI_API_ERR, ("Can't open %s\n", dev_goi_name));
		goto cleanup;
	}

	ALOG("[omcid] api: capability_get\n");
	if (capability_get(ctx) != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("Can't retrieve driver's capabilities\n"));
		goto cleanup;
	}

	/* v7.5.1: Get LAN portmap from kernel (replaces file-based default).
	   Only needed if uni2lan_map didn't populate from a file. */
	if (ctx->uni2lan[0] == -1) {
		ALOG("[omcid] api: uni2lan_portmap_get\n");
		if (uni2lan_portmap_get(ctx) != OMCI_API_SUCCESS) {
			DBG(OMCI_API_ERR,
			    ("Can't retrieve ONU LAN mapping\n"));
			goto cleanup;
		}
	}

	/* v7.5.1: Read GTC config to check PLOAM emergency stop state.
	   Stock does this before timer_init + event_handling_start. The
	   emergency_stop_state field indicates if ONU is in O7 state. */
	{
		struct gtc_cfg gtc_cfg;
		memset(&gtc_cfg, 0, sizeof(gtc_cfg));
		if (dev_ctl(ctx->remote, ctx->onu_fd, FIO_GTC_CFG_GET,
			    &gtc_cfg, sizeof(gtc_cfg)) == 0) {
			ctx->ploam_emergency_stop =
				(gtc_cfg.emergency_stop_state != 0);
			DLOG("api_create: GTC_CFG_GET ok emerg_stop=%u",
			     ctx->ploam_emergency_stop);
		} else {
			DLOG("api_create: GTC_CFG_GET failed (non-fatal)");
		}
	}

	ALOG("[omcid] api: timer_init\n");
	if (omci_api_timer_init(ctx) != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("Can't initialize timer handling\n"));
		goto cleanup;
	}

	ALOG("[omcid] api: event_start\n");
	if (event_handling_start(ctx) != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("Can't start event handling\n"));
		goto cleanup;
	}

	ALOG("[omcid] api: mapper_reset\n");
	if (omci_api_mapper_reset(ctx) != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("Can't reset mapper\n"));
		goto cleanup;
	}
#ifdef INCLUDE_OMCI_API_VOIP
	ALOG("[omcid] api: voip_init\n");
	if (voip_init(ctx) != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("VoIP init failed!\n"));
		goto cleanup;
	}
#endif

	/* Old API-level mcc_init() hangs on v7.5.1 kernel (opens exc
	   socket + blocking recvfrom).  Skipped — our INCLUDE_MCC module
	   in gpon_omci_onu handles multicast instead. */

	ALOG("[omcid] api: done\n");
	if (_afd >= 0) close(_afd);
	return OMCI_API_SUCCESS;

cleanup:
	ALOG("[omcid] api: CLEANUP\n");
	if (_afd >= 0) close(_afd);
	if (event_handling_stop(ctx) != OMCI_API_SUCCESS)
		DBG(OMCI_API_ERR, ("Event handling stop failed!\n"));

#ifdef INCLUDE_OMCI_API_VOIP
	if (voip_exit(ctx) != OMCI_API_SUCCESS)
		DBG(OMCI_API_ERR, ("VoIP exit failed!\n"));
#endif
	/* Old API-level mcc_exit() skipped — mcc_init() is not called.
	   Our INCLUDE_MCC module handles multicast instead. */

	IFXOS_MemFree(ctx);
	*p_ctx = NULL;

	return OMCI_API_ERROR;
}

union onu_reg_read_access {
  struct onu_reg_addr	in;
  struct onu_reg_val	out;
};


enum omci_api_return omci_api_start(struct omci_api_ctx *ctx)
{
	int ret;
	uint32_t i;
	struct onu_enable onu;
	struct gpe_ll_mod_sel sel;
	union  sce_version_get_u ver;
	struct gpe_exception_queue_cfg exc_queue_cfg;
	struct gpe_meter_cfg meter_cfg;
	struct gpe_sce_constants constants;
	uint32_t meter_idx;

	if (!ctx)
		return OMCI_API_ERROR;

	DLOG("api_start: begin, max_eth_uni=%u", ctx->capability.max_eth_uni);
	_diag_serdes(ctx, "api_start_begin");

	ver.in.pid = 0;
	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_SCE_VERSION_GET,
		      &ver, sizeof(ver));
	if (ret != 0) {
		DLOG("api_start: SCE_VERSION_GET failed ret=%d", ret);
		DBG(OMCI_API_ERR, ("Can't retrieve firmware version\n"));
		return -1;
	}
	DLOG("api_start: SCE version ok");

	memset(&onu, 0, sizeof(onu));
	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_ONU_LINE_ENABLE_GET,
		      &onu, sizeof(onu));
	DLOG("api_start: LINE_ENABLE_GET ret=%d enable=%u", ret, onu.enable);
	if (ret == 0 && onu.enable == 1)
		goto err; /* skip initialization */

	if (ctx->remote)
		goto line_en;

	/* Verified: stock v7.5.1 omcid never calls FIO_GPE_FLAT_EGRESS_PATH_CREATE.
	   v4.5.0 SDK had 4 calls here (VUNI0-3). Removed to match stock behavior. */

	sel.fsqm = 1;
	sel.ictrlg = 1;
	sel.ictrll[0] = 1;
	sel.ictrll[1] = 1;
	sel.ictrll[2] = 1;
	sel.ictrll[3] = 1;
	sel.iqm = 1;
	sel.octrlg = 1;
	sel.octrll[0] = 1;
	sel.octrll[1] = 1;
	sel.octrll[2] = 1;
	sel.octrll[3] = 1;
	sel.tmu = 1;
	ret = dev_ctl(ctx->remote, ctx->onu_fd,
		      FIO_GPE_LOW_LEVEL_MODULES_ENABLE, &sel, sizeof(sel));
	DLOG("api_start: LL_MODULES_ENABLE ret=%d", ret);
	if (ret != 0)
		goto err;

	/* Old API-level mcc_start() skipped — mcc_init() is not called.
	   Our INCLUDE_MCC module handles multicast instead. */

	_diag_serdes(ctx, "after_ll_modules_en");

line_en:
	onu.enable = 1;
	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_ONU_LINE_ENABLE_SET,
		      &onu, sizeof(onu));
	DLOG("api_start: LINE_ENABLE_SET ret=%d", ret);
	if (ret != 0)
		goto err;

	_diag_serdes(ctx, "after_line_enable");

	/* bypass LCT setup (takes place in the onu-firmware)*/
	if (ctx->remote) goto err;

	/* v7.5.1: MIB reset — clear kernel MIB mirror state before re-populating.
	   GPE_TABLE cmd 0x31 is a v7.5.1 addition (not in v4.5.0 headers). */
	ret = dev_ctl(ctx->remote, ctx->onu_fd,
		      _IO(GPE_TABLE_MAGIC, 0x31), NULL, 0);
	DLOG("api_start: MIB_RESET ret=%d", ret);
	/* Non-fatal: kernel may not support this cmd */

	/* v7.5.1: Exception queues route to VUNI2 (EPN 70, base qid 0xb0).
	   Stock uses 0xb0 for most types, 0xb4 for IPX (snoop), 0xb5 for ICMP (snoop).
	   v4.5.0 incorrectly used 0xa8 (VUNI1/CPU1) — lct0 netdev listens on VUNI2. */
	{
		static const struct {
			uint32_t index;
			uint32_t queue;
			uint32_t snoop;
		} exc_map[] = {
			{ ONU_GPE_EXCEPTION_OFFSET_IPX,       0xb4, 1 },
			{ ONU_GPE_EXCEPTION_OFFSET_BPDU,      0xb0, 0 },
			{ ONU_GPE_EXCEPTION_OFFSET_LOCAL_MAC,  0xb0, 0 },
			{ ONU_GPE_EXCEPTION_OFFSET_ETH,        0xb0, 0 },
			{ ONU_GPE_EXCEPTION_OFFSET_ICMP,       0xb5, 1 },
			{ ONU_GPE_EXCEPTION_OFFSET_SPECTAG,    0xb0, 0 },
		};
		for (i = 0; i < sizeof(exc_map)/sizeof(exc_map[0]); i++) {
			memset(&exc_queue_cfg, 0, sizeof(exc_queue_cfg));
			exc_queue_cfg.exception_index = exc_map[i].index;
			exc_queue_cfg.exception_queue = exc_map[i].queue;
			exc_queue_cfg.snooping_enable = exc_map[i].snoop;
			ret = dev_ctl(ctx->remote, ctx->onu_fd,
				      FIO_GPE_EXCEPTION_QUEUE_CFG_SET,
				      &exc_queue_cfg, sizeof(exc_queue_cfg));
			DLOG("api_start: exc_queue idx=%u->q=0x%x snoop=%u ret=%d",
			     exc_map[i].index, exc_map[i].queue,
			     exc_map[i].snoop, ret);
			if (ret != 0)
				goto err;
		}
	}

	/* v7.5.1: Reconfigure VUNI0 queues (0xa0-0xa7).
	   Stock zeros weight/wred/avg_weight, sets size and drop thresholds
	   to 0x80 (128 × 512B = 64KB per threshold). */
	{
		struct gpe_equeue_cfg qcfg;
		for (i = 0; i < 8; i++) {
			memset(&qcfg, 0, sizeof(qcfg));
			qcfg.index = 0xa0 + i;
			ret = dev_ctl(ctx->remote, ctx->onu_fd,
				      FIO_GPE_EGRESS_QUEUE_CFG_GET,
				      &qcfg, sizeof(qcfg));
			if (ret != 0) {
				DLOG("api_start: VUNI0 q=0x%x GET fail ret=%d",
				     0xa0 + i, ret);
				goto err;
			}
			qcfg.weight = 0;
			qcfg.wred_enable = 0;
			qcfg.avg_weight = 0;
			qcfg.size = 0x80;
			qcfg.drop_threshold_red = 0x80;
			qcfg.drop_threshold_green_max = 0x80;
			qcfg.drop_threshold_green_min = 0x80;
			qcfg.drop_threshold_yellow_max = 0x80;
			qcfg.drop_threshold_yellow_min = 0x80;
			ret = dev_ctl(ctx->remote, ctx->onu_fd,
				      FIO_GPE_EGRESS_QUEUE_CFG_SET,
				      &qcfg, sizeof(qcfg));
			if (ret != 0) {
				DLOG("api_start: VUNI0 q=0x%x SET fail ret=%d",
				     0xa0 + i, ret);
				goto err;
			}
		}
		DLOG("api_start: VUNI0 queues 0xa0-0xa7 reconfigured");
	}

	/* v7.5.1: Reconfigure VUNI0 egress port thresholds (EPN 0x44).
	   Stock sets all 4 drop thresholds to 0x80. */
	{
		struct gpe_egress_port_cfg pcfg;
		memset(&pcfg, 0, sizeof(pcfg));
		pcfg.epn = ONU_GPE_EPN_VUNI0;
		ret = dev_ctl(ctx->remote, ctx->onu_fd,
			      FIO_GPE_EGRESS_PORT_CFG_GET,
			      &pcfg, sizeof(pcfg));
		if (ret != 0) {
			DLOG("api_start: VUNI0 port cfg GET fail ret=%d", ret);
			goto err;
		}
		pcfg.egress_port_threshold_max = 0x80;
		pcfg.egress_port_threshold_green = 0x80;
		pcfg.egress_port_threshold_yellow = 0x80;
		pcfg.egress_port_threshold_red = 0x80;
		ret = dev_ctl(ctx->remote, ctx->onu_fd,
			      FIO_GPE_EGRESS_PORT_CFG_SET,
			      &pcfg, sizeof(pcfg));
		DLOG("api_start: VUNI0 port cfg SET ret=%d", ret);
		if (ret != 0)
			goto err;
	}

	/* v7.5.1: Reconfigure VUNI2 queues (0xb0-0xb7) — weight 0x3ff→0x200.
	   Stock only changes weight, preserves all other fields from GET. */
	{
		struct gpe_equeue_cfg qcfg;
		for (i = 0; i < 8; i++) {
			memset(&qcfg, 0, sizeof(qcfg));
			qcfg.index = 0xb0 + i;
			ret = dev_ctl(ctx->remote, ctx->onu_fd,
				      FIO_GPE_EGRESS_QUEUE_CFG_GET,
				      &qcfg, sizeof(qcfg));
			if (ret != 0) {
				DLOG("api_start: VUNI2 q=0x%x GET fail ret=%d",
				     0xb0 + i, ret);
				goto err;
			}
			qcfg.weight = 0x200;
			ret = dev_ctl(ctx->remote, ctx->onu_fd,
				      FIO_GPE_EGRESS_QUEUE_CFG_SET,
				      &qcfg, sizeof(qcfg));
			if (ret != 0) {
				DLOG("api_start: VUNI2 q=0x%x SET fail ret=%d",
				     0xb0 + i, ret);
				goto err;
			}
		}
		DLOG("api_start: VUNI2 queues 0xb0-0xb7 weight=0x200");
	}

	/* ANI exception meter — v7.5.1 idempotency guard (ctx+0x3b38 in stock).
	   Stock checks existence flag before creating; logs "ANI_exception_meter_exists"
	   and returns error 3 if already created. Prevents meter leak on re-entry. */
	if (ctx->ani_meter_exists) {
		DLOG("api_start: ANI exception meter already exists idx=%u",
		     ctx->ani_meter_idx);
	} else {
		memset(&meter_cfg, 0, sizeof(meter_cfg));
		meter_cfg.cir = ONU_GPE_QOSL * 1000;
		meter_cfg.pir = ONU_GPE_QOSL * 1000;
		meter_cfg.cbs = ONU_GPE_QOSL * 30;
		meter_cfg.pbs = ONU_GPE_QOSL * 30;
		meter_cfg.mode = GPE_METER_RFC2698;
		meter_cfg.color_aware = 0;

		ret = omci_api_meter_create(ctx, &meter_idx);
		if (ret != 0) {
			DLOG("api_start: ani_meter_create FAILED ret=%d", ret);
			goto err;
		}
		meter_cfg.index = meter_idx;
		ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_METER_CFG_SET,
			      &meter_cfg, sizeof(meter_cfg));
		DLOG("api_start: ani_meter idx=%u cfg ret=%d", meter_idx, ret);
		if (ret != 0)
			goto err;

		ctx->ani_meter_exists = true;
		ctx->ani_meter_idx = meter_idx;
	}

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_SCE_CONSTANTS_GET,
			  &constants, sizeof(constants));
	DLOG("api_start: SCE_CONSTANTS_GET ret=%d sz=%u",
	     ret, (unsigned)sizeof(constants));
	if (ret != 0)
		goto err;

	constants.ani_exception_meter_id = ctx->ani_meter_idx;
	constants.ani_exception_enable = 1;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_SCE_CONSTANTS_SET,
				  &constants, sizeof(constants));
	DLOG("api_start: SCE_CONSTANTS_SET ani_meter=%u ret=%d",
	     ctx->ani_meter_idx, ret);
	if (ret != 0)
		goto err;

	/* v7.5.1: IGMP_MLD exception queue configured after SCE constants */
	memset(&exc_queue_cfg, 0, sizeof(exc_queue_cfg));
	exc_queue_cfg.exception_index = ONU_GPE_EXCEPTION_OFFSET_IGMP_MLD;
	exc_queue_cfg.exception_queue = 0xb0;
	exc_queue_cfg.snooping_enable = 0;
	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_EXCEPTION_QUEUE_CFG_SET,
		      &exc_queue_cfg, sizeof(exc_queue_cfg));
	DLOG("api_start: exc_queue IGMP_MLD(idx=%u)->q=0xb0 ret=%d",
	     ONU_GPE_EXCEPTION_OFFSET_IGMP_MLD, ret);
	if (ret != 0)
		goto err;

	/* v7.5.1: Second SCE constants round — meter_l2_only + common_ip_handling.
	   Stock FUN_00446ba0 does GET/SET after IGMP_MLD exception queue setup.
	   meter_l2_only_enable=1 forces L2 metering; common_ip_handling_en=1
	   enables shared IP processing (set when no PPTP/VEIP mode active). */
	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_SCE_CONSTANTS_GET,
		      &constants, sizeof(constants));
	if (ret != 0) {
		DLOG("api_start: SCE_CONSTANTS_GET #2 fail ret=%d", ret);
		goto err;
	}
	constants.meter_l2_only_enable = 1;
	constants.common_ip_handling_en = 1;
	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_SCE_CONSTANTS_SET,
		      &constants, sizeof(constants));
	DLOG("api_start: SCE_CONSTANTS_SET #2 l2=%u ip=%u ret=%d",
	     constants.meter_l2_only_enable, constants.common_ip_handling_en, ret);
	if (ret != 0)
		goto err;

	DLOG("api_start: COMPLETE (all steps succeeded)");
	_diag_serdes(ctx, "after_sce_constants");
err:
	return ret;
}

enum omci_api_return omci_api_shutdown(struct omci_api_ctx *ctx)
{
	(void)omci_api_timer_shutdown(ctx);
	(void)mapper_shutdown(ctx);
	(void)event_handling_stop(ctx);

	(void)dev_close(ctx->remote, ctx->onu_fd);
	(void)dev_close(ctx->remote, ctx->goi_fd);
	(void)dev_close(ctx->remote, ctx->onu_fd_nfc);
	(void)dev_close(ctx->remote, ctx->goi_fd_nfc);
#if defined(INCLUDE_DRIVER_SIMULATION)
	onu_exit();
	optic_exit();
#endif

	IFXOS_MemFree(ctx);

	return OMCI_API_SUCCESS;
}

enum omci_api_return omci_api_msg_send(struct omci_api_ctx *ctx,
				       const uint8_t *msg, const uint16_t len)
{
	int ret;
	struct gpe_omci_msg m;

	if (msg[3] == 0x0a) {
		/* baseline OMCI message */
		if (len != 40)
			return OMCI_API_ERROR;
		memcpy(&m.message[0], msg, 40);
		/* add baseline trailer */
		m.message[40] = 0x00;
		m.message[41] = 0x00;
		m.message[42] = 0x00;
		m.message[43] = 0x28;
		m.length = 44;
	} else if (msg[3] == 0x0b) {
		/* extended OMCI message */
		if (len >= ONU_GPE_MAX_OMCI_FRAME_LENGTH)
			return OMCI_API_ERROR;
		memcpy(&m.message[0], msg, len);
		m.length = len;
	} else {
		return OMCI_API_ERROR;
	}

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_OMCI_SEND,
		      &m, m.length + 4);
	if (ret < 1)
		return (enum omci_api_return) ret;

	return OMCI_API_SUCCESS;
}

enum omci_api_return omci_api_ver_inf_get(struct omci_api_ctx *ctx,
					  struct omci_api_ver_inf *ver)
{
	enum omci_api_return ret;

	if (!ver)
		return OMCI_API_ERROR;

	strcpy(ver->omci_api_version, VERSION);

	ret = omci_api_drv_version_get(ctx, ver->driver_version);
	
	return ret;
}


/** ONU reboot thread

   \param[in] thr_params IFXOS_ThreadParams_t structure
*/
static int32_t omci_api_reboot_thread(struct IFXOS_ThreadParams_s *thr_params)
{
	unsigned int timeout_ms;

#ifdef LINUX
	DBG(OMCI_API_MSG, ("RebootThread (tid %d)" CRLF, (int)getpid()));
#endif

	timeout_ms = (unsigned int)thr_params->nArg1;

	IFXOS_MSecSleep(timeout_ms);

	IFXOS_Reboot();

	return 0;
}

enum omci_api_return omci_api_reboot(time_t timeout_ms)
{
	if (IFXOS_THREAD_INIT_VALID(&onu_reboot_thread_control))
		(void)IFXOS_ThreadDelete(&onu_reboot_thread_control, 0);

	if (IFXOS_ThreadInit((IFXOS_ThreadCtrl_t *) & onu_reboot_thread_control,
			     "reboot",
			     omci_api_reboot_thread,
			     OMCI_API_REBOOT_THREAD_PRIO,
			     OMCI_API_REBOOT_THREAD_STACKSIZE,
			     (unsigned long)timeout_ms, (unsigned long)0)) {
		DBG(OMCI_API_ERR, ("Can't reboot ONU\n"));

		return OMCI_API_ERROR;
	}

	return OMCI_API_SUCCESS;
}

int event_wait(struct omci_api_ctx *ctx, const int m,
	       const unsigned int timeout, uint8_t out[2])
{
	int ret = 0;
	device_fd_set_t in_fds, out_fds;
 
#if defined(INCLUDE_REMOTE_ONU)
	if (ctx->remote) {
		ret = remote_device_event_wait(ctx->onu_fd_nfc,
					       ctx->goi_fd_nfc,
					       timeout);
		out[0] = ret & 1 ? 1 : 0;
		out[1] = ret & 2 ? 1 : 0;
	} else {
#else
	{
#endif
		device_fd_zero(&in_fds);
		device_fd_set(ctx->onu_fd_nfc, &in_fds);
		device_fd_set(ctx->goi_fd_nfc, &in_fds);
		ret = device_select(m+1, &in_fds, &out_fds, timeout);
		out[0] = device_fd_is_set(ctx->onu_fd_nfc, &out_fds) ? 1 : 0;
		out[1] = device_fd_is_set(ctx->goi_fd_nfc, &out_fds) ? 1 : 0;
	}
	if (ret > 0)
		return 1;
	else
		return 0;
}

enum omci_api_return dev_ctl(const uint8_t remote, const int fd,
			     const uint32_t cmd, void *p_data,
			     const size_t data_sz)
{
	int ret;
	struct fio_exchange exchange;

	if (_IOC_DIR(cmd) == _IOC_READ)
		memset(p_data, 0, data_sz);

#if defined(INCLUDE_REMOTE_ONU)
	if (remote) {
		IFXOS_LockGet(&remote_lock[fd]);

		if (cmd == FIO_ONU_EVENT_FIFO)
			ret = remote_notification_read(fd, cmd, p_data,
						       data_sz);
		else
			ret = remote_dev_ctl(fd, cmd, p_data, data_sz);

		IFXOS_LockRelease(&remote_lock[fd]);

		return ret;
	} else {
#else
	{
#endif
		exchange.error = 0;
		exchange.length = data_sz;
		exchange.p_data = p_data;

		/* Ioctl trace: full trace if /tmp/8311_ioctl_trace exists */
		{
			static int _trace_fd = -2;
			static int _trace_all = -1;
			if (_trace_fd == -2) {
				_trace_fd = open("/tmp/8311_ioctl.log",
					O_WRONLY | O_APPEND | O_CREAT, 0644);
				_trace_all = (access("/tmp/8311_ioctl_trace",
					F_OK) == 0) ? 1 : 0;
			}
			if (_trace_fd >= 0 && _trace_all) {
				char _buf[80];
				int _n = snprintf(_buf, sizeof(_buf),
					"ioctl cmd=0x%08x sz=%u\n",
					cmd, (unsigned)data_sz);
				if (_n > 0)
					write(_trace_fd, _buf, _n);
			}
		}

		ret = device_ioctl(fd, cmd, (unsigned long)&exchange);

		/* Log ioctl failures (skip event polling ioctls — they fail
		   normally when no data is queued and would flood the log) */
		{
			int result = (ret < exchange.error) ? ret : exchange.error;
			if (result != 0
			    && cmd != FIO_ONU_EVENT_FIFO
			    && cmd != FIO_OPTIC_EVENT_FIFO) {
				static int _err_fd = -2;
				if (_err_fd == -2)
					_err_fd = open("/tmp/8311_ioctl.log",
						O_WRONLY | O_APPEND | O_CREAT, 0644);
				if (_err_fd >= 0) {
					char _buf[96];
					int _n = snprintf(_buf, sizeof(_buf),
						"ioctl cmd=0x%08x sz=%u -> FAIL ret=%d err=%d\n",
						cmd, (unsigned)data_sz,
						ret, exchange.error);
					if (_n > 0)
						write(_err_fd, _buf, _n);
				}
			}
		}

		if (cmd == FIO_ONU_EVENT_FIFO)
			if (exchange.error == 1)
				DBG(OMCI_API_ERR,
					("ERR: notification FIFO overflow\n"));
		return (ret < exchange.error) ? ret : exchange.error;
	}
}

enum omci_api_return dev_open(const uint8_t remote, const char *dev_name)
{
#if defined(INCLUDE_REMOTE_ONU)
	if (remote) {
		return remote_device_open(dev_name);
	} else {
#else
	{
#endif
		return device_open(dev_name);
	}
}

enum omci_api_return dev_close(const uint8_t remote, const int fd)
{
#if defined(INCLUDE_REMOTE_ONU)
	if (remote) {
		remote_device_close(fd);
	} else {
#else
	{
#endif
		device_close(fd);
	}
	return OMCI_API_SUCCESS;
}

void omci_api_debug_level_set(const enum omci_api_dbg_module module,
			      const uint8_t level)
{
#ifndef OMCI_API_DEBUG_DISABLE
	switch (module) {
	case OMCI_API_DBG_MODULE_API:
		dbg_api_module.level = level;
		break;
	case OMCI_API_DBG_MODULE_VOIP:
#ifdef INCLUDE_OMCI_API_VOIP
		omci_api_voip_debug_level_set(level);
#endif
		break;
	case OMCI_API_DBG_MODULE_MCC:
#ifdef INCLUDE_OMCI_API_MCC
		(void)omci_api_mcc_debug_level_set(level);
#endif
		break;
	default:
		break;
	}
#endif
}

void omci_api_debug_level_get(const enum omci_api_dbg_module module,
			      uint8_t *level)
{
	/** \todo fix me*/
	*level = 4;
#ifndef OMCI_API_DEBUG_DISABLE
	switch (module) {
	case OMCI_API_DBG_MODULE_API:
		*level = dbg_api_module.level;
		break;
	case OMCI_API_DBG_MODULE_VOIP:
#ifdef INCLUDE_OMCI_API_VOIP
		*level = omci_api_voip_debug_level_get();
#endif
		break;
	case OMCI_API_DBG_MODULE_MCC:
#ifdef INCLUDE_OMCI_API_MCC
		*level = omci_api_mcc_debug_level_get();
#endif
		break;
	default:
		break;
	}
#endif
}

#ifndef OMCI_API_DEBUG_DISABLE
void omci_api_printf(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vfprintf(stdout, fmt, args);
	va_end(args);
}
#endif

/** Fetch grouping from DSCP to P-bit mapping 24 byte attribute

   \param[in] dscp_prio_map DSCP to P-bit mapping attribute
   \param[in] group                 Grouping number (0 - 63)

   \return Grouping value
*/
static uint8_t map2pcp(const uint8_t *dscp_prio_map, const unsigned int group)
{
	unsigned int bit, start_bit, start_byte, bit1 = 0, bit2 = 0, bit3 = 0;

	if (!dscp_prio_map || group >= 64)
		return 0;

	bit = group * 3;
	start_byte = bit / 8;
	start_bit = bit % 8;

	if (start_byte >= 24)
		return 0;

	if (dscp_prio_map[start_byte] & (0x80 >> start_bit))
		bit1 = 4;

	bit = group * 3 + 1;
	start_byte = bit / 8;
	start_bit = bit % 8;

	if (start_byte >= 24)
		return 0;

	if (dscp_prio_map[start_byte] & (0x80 >> start_bit))
		bit2 = 2;

	bit = group * 3 + 2;
	start_byte = bit / 8;
	start_bit = bit % 8;

	if (start_byte >= 24)
		return 0;

	if (dscp_prio_map[start_byte] & (0x80 >> start_bit))
		bit3 = 1;

	return (uint8_t)(bit3 | bit2 | bit1);
}

uint8_t dscp_profile_create(struct omci_api_ctx *ctx,
			    const uint8_t *dscp_prio_map)
{
	uint8_t dscp_profile_index = 0;
	uint8_t idx = 0;
	unsigned int i;

	idx = 255;
	dscp_profile_index = 255;
	for (i=0;i<8;i++) {
		if (ctx->dscp_prio_map[i][0] == 0) {
			if (idx == 255) {
				/* found first free item */
				idx = i;
			}
		} else {
			if (memcmp(&dscp_prio_map[0], 
				&ctx->dscp_prio_map[i][1], 24) == 0) {
				/* found existing item */
				/* increase internal ref count */
				ctx->dscp_prio_map[i][0]++;
				dscp_profile_index = i;
				break;
			}
		}
	}
	if ((i == 8) && (idx != 255)) {
		/* entry doesn't exist yet */
		dscp_profile_index = idx;
		ctx->dscp_prio_map[idx][0] = 1;
		memcpy(&ctx->dscp_prio_map[idx][1],
			&dscp_prio_map[0], 24);
		for (i=0; i<64; i++)
			ctx->pcp[idx][i] = map2pcp(&dscp_prio_map[0], i);
	}

	return dscp_profile_index;
}

void dscp_profile_delete(struct omci_api_ctx *ctx, const uint8_t dscp_profile)
{
	if (dscp_profile < 8 && ctx->dscp_prio_map[dscp_profile][0])
		ctx->dscp_prio_map[dscp_profile][0]--;
}

enum omci_api_return lan_exception_setup(struct omci_api_ctx *ctx,
					 const uint8_t lan_idx,
					 const uint8_t profile_idx,
					 const uint32_t ingress_mask_set,
					 const uint32_t ingress_mask_clr,
					 const uint32_t egress_mask_set,
					 const uint32_t egress_mask_clr)
{
	enum omci_api_return ret;
	union gpe_lan_exception_cfg_u exc_cfg;
	union gpe_exception_profile_cfg_u exc_profile;

	/* get exception profile */
	exc_profile.in.exception_profile = profile_idx;
	ret = dev_ctl(ctx->remote, ctx->onu_fd,
		      FIO_GPE_EXCEPTION_PROFILE_CFG_GET, &exc_profile,
		      sizeof(exc_profile));
	if (ret != OMCI_API_SUCCESS) {
		DLOG("lan_exc_setup: PROFILE_GET[%u] FAILED ret=%d", profile_idx, ret);
		return ret;
	}

	DLOG("lan_exc_setup: prof[%u] GET ingress=0x%08x egress=0x%08x",
	     profile_idx, exc_profile.out.ingress_exception_mask,
	     exc_profile.out.egress_exception_mask);

	exc_profile.out.ingress_exception_mask |= ingress_mask_set;
	exc_profile.out.egress_exception_mask  |= egress_mask_set;
	exc_profile.out.ingress_exception_mask &= ~ingress_mask_clr;
	exc_profile.out.egress_exception_mask  &= ~egress_mask_clr;

	/* set exception profile*/
	ret = dev_ctl(ctx->remote, ctx->onu_fd,
		      FIO_GPE_EXCEPTION_PROFILE_CFG_SET, &exc_profile.out,
		      sizeof(exc_profile.out));
	if (ret != OMCI_API_SUCCESS) {
		DLOG("lan_exc_setup: PROFILE_SET[%u] FAILED ret=%d", profile_idx, ret);
		return ret;
	}

	DLOG("lan_exc_setup: prof[%u] SET ingress=0x%08x egress=0x%08x",
	     profile_idx, exc_profile.out.ingress_exception_mask,
	     exc_profile.out.egress_exception_mask);

	/* read LAN port exception config*/
	exc_cfg.in.lan_port_index = lan_idx;
	ret = dev_ctl(ctx->remote, ctx->onu_fd,
		      FIO_GPE_LAN_EXCEPTION_CFG_GET, &exc_cfg, sizeof(exc_cfg));
	if (ret != OMCI_API_SUCCESS) {
		DLOG("lan_exc_setup: LAN_EXC_GET[%u] FAILED ret=%d", lan_idx, ret);
		return ret;
	}

	DLOG("lan_exc_setup: lan[%u] GET profile=%u uni_m=%u",
	     lan_idx, exc_cfg.out.exception_profile,
	     exc_cfg.out.uni_except_meter_id);

	/* assign exception profile to LAN port */
	exc_cfg.in.lan_port_index = lan_idx;
	exc_cfg.out.exception_profile = profile_idx;

	/* write LAN port exception config*/
	ret = dev_ctl(ctx->remote, ctx->onu_fd,
		      FIO_GPE_LAN_EXCEPTION_CFG_SET, &exc_cfg, sizeof(exc_cfg));
	if (ret != OMCI_API_SUCCESS) {
		DLOG("lan_exc_setup: LAN_EXC_SET[%u] FAILED ret=%d sz=%u",
		     lan_idx, ret, (unsigned)sizeof(exc_cfg));
		return ret;
	}

	return ret;
}

enum omci_api_return lan_exception_meter_setup(struct omci_api_ctx *ctx,
					 const uint8_t lan_idx,
					 const uint32_t uni_except_meter_id,
					 const uint32_t uni_except_meter_enable)
{
	enum omci_api_return ret;
	union gpe_lan_exception_cfg_u exc_cfg;

	/* read LAN port exception config*/
	exc_cfg.in.lan_port_index = lan_idx;
	ret = dev_ctl(ctx->remote, ctx->onu_fd,
		      FIO_GPE_LAN_EXCEPTION_CFG_GET, &exc_cfg, sizeof(exc_cfg));
	if (ret != OMCI_API_SUCCESS) {
		DLOG("lan_exc_meter: GET[%u] FAILED ret=%d", lan_idx, ret);
		return ret;
	}

	/* assign meter to LAN port (v7.5.1: IGMP meter removed) */
	exc_cfg.in.lan_port_index = lan_idx;
	exc_cfg.out.uni_except_meter_id = uni_except_meter_id;
	exc_cfg.out.uni_except_meter_enable = uni_except_meter_enable;

	/* write LAN port exception config*/
	ret = dev_ctl(ctx->remote, ctx->onu_fd,
		      FIO_GPE_LAN_EXCEPTION_CFG_SET, &exc_cfg, sizeof(exc_cfg));
	if (ret != OMCI_API_SUCCESS) {
		DLOG("lan_exc_meter: SET[%u] FAILED ret=%d", lan_idx, ret);
		return ret;
	}

	DLOG("lan_exc_meter: lan[%u] uni_m=%u/%u ok",
	     lan_idx, uni_except_meter_id, uni_except_meter_enable);

	return ret;
}

enum omci_api_return ani_exception_setup(struct omci_api_ctx *ctx,
					 const uint8_t gem_idx,
					 enum omci_api_gem_port_direction dir,
					 const uint8_t profile_idx,
					 const uint32_t ingress_mask_set,
					 const uint32_t ingress_mask_clr,
					 const uint32_t egress_mask_set,
					 const uint32_t egress_mask_clr)
{
	enum omci_api_return ret;
	union gpe_ani_exception_cfg_u exc_cfg;
	union gpe_exception_profile_cfg_u exc_profile;

	if (dir != OMCI_API_GEM_PORT_DIRECTION_UPSTREAM &&
	    dir != OMCI_API_GEM_PORT_DIRECTION_DOWNSTREAM &&
	    dir != OMCI_API_GEM_PORT_DIRECTION_BOTH)
		return OMCI_API_ERROR;

	exc_profile.in.exception_profile = profile_idx;
	ret = dev_ctl(ctx->remote, ctx->onu_fd,
		      FIO_GPE_EXCEPTION_PROFILE_CFG_GET, &exc_profile,
		      sizeof(exc_profile));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	exc_profile.out.ingress_exception_mask |= ingress_mask_set;
	exc_profile.out.egress_exception_mask  |= egress_mask_set;
	exc_profile.out.ingress_exception_mask &= ~ingress_mask_clr;
	exc_profile.out.egress_exception_mask  &= ~egress_mask_clr;

	ret = dev_ctl(ctx->remote, ctx->onu_fd,
		      FIO_GPE_EXCEPTION_PROFILE_CFG_SET, &exc_profile.out,
		      sizeof(exc_profile.out));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	/* get ANI exception configuration for the specified GEM port index */
	exc_cfg.in.gem_port_index = gem_idx;
	ret = dev_ctl(ctx->remote, ctx->onu_fd,
		      FIO_GPE_ANI_EXCEPTION_CFG_GET, &exc_cfg, sizeof(exc_cfg));
	if (ret != OMCI_API_SUCCESS)
		return ret;


	/* assign exception profile to the specified GEM port */
	exc_cfg.out.gem_port_index = gem_idx;

	if (dir == OMCI_API_GEM_PORT_DIRECTION_UPSTREAM) {
		exc_cfg.out.us_exception_profile = profile_idx;
	} else if (dir == OMCI_API_GEM_PORT_DIRECTION_DOWNSTREAM) {
		exc_cfg.out.ds_exception_profile = profile_idx;
	} else {
		exc_cfg.out.us_exception_profile = profile_idx;
		exc_cfg.out.ds_exception_profile = profile_idx;
	}

	ret = dev_ctl(ctx->remote, ctx->onu_fd,
		      FIO_GPE_ANI_EXCEPTION_CFG_SET, &exc_cfg, sizeof(exc_cfg));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	return ret;
}

enum omci_api_return omci_api_uni2lan(struct omci_api_ctx *ctx,
				      const uint16_t me_id,
				      uint8_t *lan_port)
{
	uint8_t i;

	for (i = 0; i < ONU_GPE_MAX_UNI; i++) {
		if (ctx->uni2lan[i] == (int)(me_id & 0xff)) {
			*lan_port = i;
			return OMCI_API_SUCCESS;
		}
	}
	
	return OMCI_API_ERR;
}

int omci_api_onu_fd_get(struct omci_api_ctx *ctx)
{
	if (!ctx)
		return -1;
	return ctx->onu_fd;
}

bool omci_api_remote_get(struct omci_api_ctx *ctx)
{
	if (!ctx)
		return false;
	return ctx->remote;
}

/** @} */
