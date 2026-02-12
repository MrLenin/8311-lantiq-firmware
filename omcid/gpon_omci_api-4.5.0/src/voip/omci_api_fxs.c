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

#define tapi_io(fd, cmd, data) \
			device_ioctl((fd), (cmd), (IFX_ulong_t)(data))

#ifdef INCLUDE_OMCI_API_TAPI_DETAILED_ERR_PRINT
#include "drv_vmmc_strerrno.h"
#include "drv_tapi_strerrno.h"

static void dev_fxs_last_err_print(const struct fxs_data *fxs)
{
	IFX_TAPI_Error_t err;
	uint32_t i, j;

	memset(&err, 0, sizeof(err));
	tapi_io(fxs->ctrl_fd, IFX_TAPI_LASTERR, &err);
	if (err.nCode != -1 && err.nCode != 0) {
		DBG(OMCI_API_ERR, ("TAPI error 0x%X occured\n", err.nCode));

		for (i = 0; i < err.nCnt; ++i) {
			DBG(OMCI_API_ERR,
				("\t%s:%d HL Code 0x%04X, LL Code 0x%04X\n", 
				err.stack[i].sFile, err.stack[i].nLine,
				err.stack[i].nHlCode, err.stack[i].nLlCode));

			for (j = 0; j < TAPI_ERRNO_CNT; ++j) {
				if (TAPI_drvErrnos[j] == err.stack[i].nHlCode) {
					DBG(OMCI_API_ERR,
						("\t  HL Err: %s\n",
						TAPI_drvErrStrings[j]));
					break;
				}
			}

			for (j = 0; j < VMMC_ERRNO_CNT; ++j) {
				if (VMMC_drvErrnos[j] == err.stack[i].nLlCode) {
					DBG(OMCI_API_ERR,
						("\t  LL Err: %s\n",
						VMMC_drvErrStrings[j]));
					break;
				}
			}
		}
	}
}
#endif /* #ifdef INCLUDE_OMCI_API_TAPI_DETAILED_ERR_PRINT */

static void dev_fxs_last_err_get(const struct fxs_data *fxs,
				 struct fxs_last_err *last_err)
{
	IFX_TAPI_Error_t err;

	memset(&err, 0, sizeof(err));
	tapi_io(fxs->ctrl_fd, IFX_TAPI_LASTERR, &err);

	if (err.nCode != 0xFFFFFFFF && err.nCode != 0) {
		last_err->high = (err.nCode >> 16) & 0xFFFF;
		last_err->low = err.nCode & 0xFFFF;
	} else {
		last_err->high = 0;
		last_err->low = 0;
	}
}

static int dev_fxs_open(const uint8_t dev_num, const uint8_t ch_num)
{
	int fd;
	char name[64] = {0};

	sprintf(name, "%s%u%u", OMCI_API_VOICE_DEV_BASE_NAME, dev_num, ch_num); 
	fd = dev_open(false, name);
	if (fd < 0) {
		DBG(OMCI_API_ERR, ("%s device open failed!\n", name));
		return -1;
	}
	return fd;
}

static int dev_fxs_close(const int fd)
{
	return dev_close(false, fd);
}

static int dev_fxs_start(const int fd, const bool start)
{
	IFX_TAPI_DEV_START_CFG_t tapistart;

	memset(&tapistart, 0x0, sizeof(IFX_TAPI_DEV_START_CFG_t));
	tapistart.nMode = IFX_TAPI_INIT_MODE_VOICE_CODER;

	return tapi_io(fd, start ? IFX_TAPI_DEV_START :
				   IFX_TAPI_DEV_STOP, start ? &tapistart : 0);
}

static int fw_load(const char *path, uint8_t **pp_buf, uint32_t *buf_sz)
{
	int ret = 0;
	IFXOS_File_t *fd;
	IFXOS_stat_t firmware_stat;

	/* Open FW binary for reading*/
	fd = IFXOS_FOpen(path, "rb");
	if (fd == IFX_NULL) {
		DBG(OMCI_API_ERR, ("%s open failed!\n", path));
		return -1;
	}

	/* Get FW binary statistics*/
	if (IFXOS_Stat((IFX_char_t*)path, &firmware_stat) != IFX_SUCCESS) {
		DBG(OMCI_API_ERR, ("%s statistics get failed!\n", path));
		return -1;
	}

	*pp_buf = (uint8_t *)IFXOS_MemAlloc(firmware_stat.st_size);
	if (*pp_buf == IFX_NULL) {
		ret = -1;
		goto on_exit;
	}

	if (IFXOS_FRead(*pp_buf, 1, firmware_stat.st_size, fd) <= 0) {
		ret = -1;
		goto on_exit;
	}

	*buf_sz = firmware_stat.st_size; 

on_exit:
	IFXOS_FClose(fd);

	if (*pp_buf != IFX_NULL && ret != IFX_SUCCESS)
		IFXOS_MemFree(*pp_buf);

	return ret;
}

static void fw_release(uint8_t *buf)
{
	if (buf != IFX_NULL)
		IFXOS_MemFree(buf);
}

static int fw_download(const int fd, char *name)
{
	int ret = 0;
	uint8_t *fw = IFX_NULL;
	uint32_t size = 0;
	VMMC_IO_INIT vmmc_io_init;

	/* create binary buffer*/
	ret = fw_load(name, &fw, &size);
	if (ret != 0) {
		DBG(OMCI_API_ERR, ("binary %s load failed!\n", name));
		return -1;
	}

	/* download voice firmware*/
	memset(&vmmc_io_init, 0, sizeof(VMMC_IO_INIT));
	vmmc_io_init.pPRAMfw   = fw;
	vmmc_io_init.pram_size = size;

	ret = tapi_io(fd, FIO_FW_DOWNLOAD, &vmmc_io_init);

	/* release buffer*/
	fw_release(fw);

	return ret;
}

static void voice_fw_ver_print(int fd)
{
	VMMC_IO_VERSION ioCmd;

	if (tapi_io(fd, FIO_GET_VERS, &ioCmd) == 0)
	printf("voice FW %d.%d.%d loaded\n", ioCmd.nEdspVers,
					     ioCmd.nEdspIntern,
					     ioCmd.nEDSPHotFix);
}

static int bbd_download(const int fd, char *name)
{
	int ret = 0;
	uint8_t *fw = NULL;
	uint32_t size = 0;
	VMMC_DWLD_t vmmc_bbd;

	ret = fw_load(name, &fw, &size);
	if (ret != 0) {
		DBG(OMCI_API_ERR, ("binary %s load failed!\n", name));
		return -1;
	}

	/* Download BBD Firmware*/
	memset(&vmmc_bbd, 0, sizeof(VMMC_DWLD_t));
	vmmc_bbd.buf  = fw;
	vmmc_bbd.size = size;

	ret = tapi_io(fd, FIO_BBD_DOWNLOAD, &vmmc_bbd);

	if (ret != 0)
		DBG(OMCI_API_ERR, ("FIO_BBD_DOWNLOAD ioctl failed!\n"));

	/* release buffer*/
	fw_release(fw);

	return ret;
}

static int phone_connect(const int fd, const uint8_t dst_ch, const bool connect)
{
	IFX_TAPI_MAP_DATA_t datamap;

	/* Perform mapping*/
	memset(&datamap, 0x0, sizeof(IFX_TAPI_MAP_DATA_t));
	datamap.nDstCh  = dst_ch;
	datamap.nChType = IFX_TAPI_MAP_TYPE_PHONE;

	return tapi_io(	fd, connect ? IFX_TAPI_MAP_DATA_ADD :
				      IFX_TAPI_MAP_DATA_REMOVE,
			&datamap);
} 

static int stream_socket_create(const uint16_t src_port,
				const uint32_t src_addr,
				const uint16_t dst_port,
				const uint32_t dst_addr)
{
	int s;
	IFXOS_sockAddr_t l_addr, r_addr;

	/* create socket DGRAM */
	if (IFXOS_SocketCreate(IFXOS_SOC_TYPE_DGRAM, &s) != IFX_SUCCESS) {
		DBG(OMCI_API_ERR, ("FXS UDP socket create failed!\n"));
		return OMCI_API_ERROR;
	}

	memset(&l_addr, 0, sizeof(l_addr));
	l_addr.sin_family = AF_INET;
	l_addr.sin_port = htons(src_port);
	l_addr.sin_addr.s_addr = htonl(src_addr); 

	/* bind socket */
	if (IFXOS_SocketBind(s, &l_addr) != IFX_SUCCESS) {
		DBG(OMCI_API_ERR, ("FXS UDP socket bind failed!\n"));
		IFXOS_SocketClose(s);
		return OMCI_API_ERROR;
	}

#ifdef LINUX
	/* make the socket non blocking */
	fcntl(s, F_SETFL, O_NONBLOCK);
#endif

	memset(&r_addr, 0, sizeof(r_addr));
	r_addr.sin_family = AF_INET;
	r_addr.sin_port = htons(dst_port);
	r_addr.sin_addr.s_addr = htonl(dst_addr); 

	/* ...connect */
	if (IFXOS_SocketConnect(s, &r_addr, sizeof(r_addr)) != IFX_SUCCESS) {
		DBG(OMCI_API_ERR, ("FXS UDP socket connect failed!\n"));
		IFXOS_SocketClose(s);
		return OMCI_API_ERROR;
	}

	return s;
}

static int stream_socket_delete(const int s)
{
	if (s > 0)
		return IFXOS_SocketClose(s);
	else
		return 0;
}

static int stream_tos_set(const int s, const uint8_t tos)
{
#ifdef LINUX
	int val = (int)tos;

	if (setsockopt(s, SOL_IP, IP_TOS, (char*)&val, sizeof(val)) < 0)
		return -1;
	return 0;
#else
	return 0;
#endif
}

static int stream_ctrl(const int fd, const bool start)
{
	int ret = 0;

	ret = tapi_io(fd, start ? IFX_TAPI_ENC_START : IFX_TAPI_ENC_STOP, 0);
	if (ret != 0)
		return -1;

	ret = tapi_io(fd, start ? IFX_TAPI_DEC_START : IFX_TAPI_DEC_STOP, 0);

	if (ret != 0) 
		return -1;

	return ret;
}

static int stream_redirect_start(const int fd, const int socket)
{
	QOS_INIT_SESSION_ON_SOCKET qos_session;

	qos_session.fd = socket;

	return tapi_io(fd, FIO_QOS_ON_SOCKET_START, &qos_session);
}

static int stream_redirect_stop(int fd)
{
	return tapi_io(fd, FIO_QOS_STOP, 0);
}

static int stream_clean(int fd)
{
	return tapi_io(fd, FIO_QOS_CLEAN, 0);
}

enum omci_api_return fxs_init(struct omci_api_ctx *ctx)
{
	struct voip_ctx *voip = &ctx->voip;
	struct fxs_data *fxs = &voip->fxs;
	uint8_t i;

	/* open TAPI control device*/
	fxs->ctrl_fd = dev_fxs_open(1, 0);
	if (fxs->ctrl_fd < 0) {
		DBG(OMCI_API_ERR, ("FXS control dev open failed!\n"));
		return OMCI_API_ERROR;
	}

	/* download voice firmware*/
	if (fw_download(fxs->ctrl_fd, OMCI_API_VOICE_DEV_FW_NAME) != 0) {
		DBG(OMCI_API_ERR, ("FXS firmware download failed!\n"));
		return OMCI_API_ERROR;
	}

	/* start TAPI*/
	if (dev_fxs_start(fxs->ctrl_fd, true) != 0) {
		DBG(OMCI_API_ERR, ("FXS start failed!\n"));
		return OMCI_API_ERROR;
	}

	voice_fw_ver_print(fxs->ctrl_fd);

	/* download bbd firmware*/
	if (bbd_download(fxs->ctrl_fd, OMCI_API_VOICE_DEV_BBD_NAME) != 0) {
		DBG(OMCI_API_ERR, ("FXS bbd download failed!\n"));
		return OMCI_API_ERROR;
	}

	for (i = 0; i < OMCI_API_FXS_MAX; i++) {
		fxs->ch_fd[i] = dev_fxs_open(1, i + 1);
		if (fxs->ch_fd[i] < 0) {
			DBG(OMCI_API_ERR, ("FXS chan %u open failed!\n", i+1));
			return OMCI_API_ERROR;
		}

		if (phone_connect(fxs->ch_fd[i], i, true) != 0) {
			DBG(OMCI_API_ERR, ("phone %u connect failed!\n", i));
			return OMCI_API_ERROR;
		} 

		DBG(OMCI_API_MSG, ("phone %u connected\n", i));

		if (fxs_phone_enable(fxs, i, false) != OMCI_API_SUCCESS) {
			DBG(OMCI_API_ERR, ("phone %u standby failed!\n", i));
			return OMCI_API_ERROR;
		}

		/* set default codec*/
		if (fxs_codec_set(fxs, i, CODEC_G711A) != OMCI_API_SUCCESS) {
			DBG(OMCI_API_ERR, ("chann %u codec set failed!\n", i+1));
			return OMCI_API_ERROR;
		}

		fxs->stream_rtp_tos[i] = OMCI_API_STREAM_RTP_TOS_DEFAULT;
		fxs->stream_sock_fd[i] = -1;
	}

	return OMCI_API_SUCCESS;
}

enum omci_api_return fxs_exit(struct omci_api_ctx *ctx)
{
	struct voip_ctx *voip = &ctx->voip;
	struct fxs_data *fxs = &voip->fxs;
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint8_t i;

	/* stop FXS*/
	if (dev_fxs_start(fxs->ctrl_fd, false) != 0)
		DBG(OMCI_API_ERR, ("FXS stop failed!\n"));;

	/* close FXS control device*/
	if (dev_fxs_close(fxs->ctrl_fd) != 0) {
		DBG(OMCI_API_ERR, ("FXS control dev close failed!\n"));
		return OMCI_API_ERROR;
	}

	for (i = 0; i < OMCI_API_FXS_MAX; i++) {
		if (stream_clean(fxs->ch_fd[i]) != 0) {
			DBG(OMCI_API_ERR, ("FXS stream %u clean failed!\n", i));
			ret = OMCI_API_ERROR;
		}

		if (dev_fxs_close(fxs->ch_fd[i]) != 0) {
			DBG(OMCI_API_ERR, ("FXS chan %u close failed!\n", i));
			ret = OMCI_API_ERROR;
		}
	}

	return ret;
}

enum omci_api_return fxs_event_get(const struct fxs_data *fxs,
				   IFX_TAPI_EVENT_t *tapi_event)
{
	int ret = 0;

	memset(tapi_event, 0, sizeof(*tapi_event));

	tapi_event->ch = IFX_TAPI_EVENT_ALL_CHANNELS;

	/* Get event*/
	ret = tapi_io(fxs->ctrl_fd, IFX_TAPI_EVENT_GET, tapi_event);
	if (ret != 0) {
		DBG(OMCI_API_ERR, ("FXS event get failed!\n"));
		return OMCI_API_ERROR;
	}

	return OMCI_API_SUCCESS;
}

enum omci_api_return fxs_phone_enable(const struct fxs_data *fxs,
				      const uint16_t id,
				      const bool enable)
{
	int ret = 0;

	if (id >= OMCI_API_FXS_MAX) {
		DBG(OMCI_API_ERR, ("invalid FXS id=%u!\n", id));
		return OMCI_API_ERROR;
	}

	ret = tapi_io(fxs->ch_fd[id], IFX_TAPI_LINE_FEED_SET,
			enable ? IFX_TAPI_LINE_FEED_ACTIVE :
				 IFX_TAPI_LINE_FEED_STANDBY);
	if (ret != 0) {
		DBG(OMCI_API_ERR, ("FXS(%u) %s failed!\n",
					id, enable ? "enable" : "disable"));
		return OMCI_API_ERROR;
	}

	return OMCI_API_SUCCESS;
}

enum omci_api_return fxs_local_tone_stop(const struct fxs_data *fxs,
					 const uint16_t id)
{
	int ret = 0;

	ret = tapi_io(fxs->ch_fd[id], IFX_TAPI_TONE_LOCAL_PLAY, 0);
	if (ret != 0) {
		DBG(OMCI_API_ERR,
			("FXS(%u) tone stop failed, ret=%d!\n", id, ret));
		return OMCI_API_ERROR;
	}

	return OMCI_API_SUCCESS;
}

enum omci_api_return fxs_local_dial_tone_play(const struct fxs_data *fxs,
					      const uint16_t id)
{
	int ret = 0;

	(void)tapi_io(fxs->ch_fd[id], IFX_TAPI_TONE_LOCAL_PLAY, 0);

	ret = tapi_io(fxs->ch_fd[id], IFX_TAPI_TONE_DIALTONE_PLAY, 0);
	if (ret != 0) {
		DBG(OMCI_API_ERR,
			("FXS(%u) dial tone play failed, ret=%d!\n", id, ret));
		return OMCI_API_ERROR;
	}

	return OMCI_API_SUCCESS;
}

enum omci_api_return fxs_local_busy_tone_play(const struct fxs_data *fxs,
					      const uint16_t id)
{
	int ret = 0;

	(void)tapi_io(fxs->ch_fd[id], IFX_TAPI_TONE_LOCAL_PLAY, 0);

	ret = tapi_io(fxs->ch_fd[id], IFX_TAPI_TONE_BUSY_PLAY, 0);
	if (ret != 0) {
		DBG(OMCI_API_ERR,
			("FXS(%u) busy tone play failed, ret=%d!\n", id, ret));
		return OMCI_API_ERROR;
	}

	return OMCI_API_SUCCESS;
}

enum omci_api_return fxs_local_ringback_tone_play(const struct fxs_data *fxs,
						  const uint16_t id)
{
	int ret = 0;

	(void)tapi_io(fxs->ch_fd[id], IFX_TAPI_TONE_LOCAL_PLAY, 0);

	ret = tapi_io(fxs->ch_fd[id], IFX_TAPI_TONE_RINGBACK_PLAY, 0);
	if (ret != 0) {
		DBG(OMCI_API_ERR,
			("FXS(%u) ringback tone play failed, ret=%d!\n", id,
									ret));
		return OMCI_API_ERROR;
	}

	return OMCI_API_SUCCESS;
}

enum omci_api_return fxs_ring_ctrl(const struct fxs_data *fxs,
				   const uint16_t id,
				   const bool start)
{
	int ret = 0;

	if (id >= OMCI_API_FXS_MAX) {
		DBG(OMCI_API_ERR, ("invalid FXS id=%u!\n", id));
		return OMCI_API_ERROR;
	}

	ret = tapi_io(fxs->ch_fd[id],
		      start ? IFX_TAPI_RING_START : IFX_TAPI_RING_STOP, 0);
	if (ret != 0)
		return OMCI_API_ERROR;

	return OMCI_API_SUCCESS;
}

enum omci_api_return fxs_codec_set(const struct fxs_data *fxs,
				   const uint8_t src_id,
				   const enum voip_codec codec)
{
	int fd;
	IFX_TAPI_ENC_CFG_t enc;

	if (src_id >= OMCI_API_FXS_MAX) {
		DBG(OMCI_API_ERR, ("FXS chan %u not available!\n", src_id));
		return OMCI_API_ERROR;
	}

	switch (codec) {
	case CODEC_G711A:
		enc.nEncType = IFX_TAPI_COD_TYPE_ALAW;
		break;
	case CODEC_G729:
		enc.nEncType = IFX_TAPI_COD_TYPE_G729;
		break;
	default:
		return OMCI_API_ERROR;
	}

	fd = fxs->ch_fd[src_id];

	/** \todo crosscheck if we need to make this value configurable
	*/
	enc.nFrameLen = IFX_TAPI_COD_LENGTH_20;

	if (tapi_io(fd, IFX_TAPI_ENC_CFG_SET, &enc) !=0) {
		DBG(OMCI_API_ERR, ("FXS chan %u enc type %d set failed!\n",
					src_id, enc.nEncType));
		return OMCI_API_ERROR;
	}

	/* switch off VAD: GPONSW-302*/
	if (tapi_io(fd, IFX_TAPI_ENC_VAD_CFG_SET, IFX_TAPI_ENC_VAD_NOVAD) !=0) {
		DBG(OMCI_API_ERR, ("FXS chan %u vad off set failed!\n",
					src_id));
		return OMCI_API_ERROR;
	}

	/* This interface is currently not supported, because the codec is
	   determined by the payload type of the received packets. 
	if (tapi_io(fd, IFX_TAPI_DEC_TYPE_SET, enc.nEncType) !=0) {
		DBG(OMCI_API_ERR, ("FXS chan %u dec type %d set failed!\n",
					src_id, enc.nEncType));
		return OMCI_API_ERROR;
	}
	*/

	return OMCI_API_SUCCESS;
}

enum omci_api_return fxs_stream_start(struct fxs_data *fxs,
				      const struct fxs_stream_info *inf)
{
	if (inf->type == FXS_STREAM_VOICE) {
		/* create stream socket */
		fxs->stream_sock_fd[inf->id] =
			stream_socket_create(inf->conn.src_port,
					     inf->conn.src_addr,
					     inf->conn.dst_port,
					     inf->conn.dst_addr);
		if (fxs->stream_sock_fd[inf->id] <= 0) {
			DBG(OMCI_API_ERR,
				("fxs %u stream socket create failed!\n",
				inf->id));
			return OMCI_API_ERROR;
		}

		/* set TOS value */
		if (stream_tos_set(fxs->stream_sock_fd[inf->id],
				   fxs->stream_rtp_tos[inf->id]) != 0) {
			DBG(OMCI_API_ERR,
				("fxs %u stream TOS set failed!\n", inf->id));
			return OMCI_API_ERROR;
		}

		/* start kernel KPI2UDP redirect */
		if (stream_redirect_start(fxs->ch_fd[inf->id],
					  fxs->stream_sock_fd[inf->id]) != 0) {
			DBG(OMCI_API_ERR, ("fxs %u stream redirect failed!\n",
					   inf->id));
			return OMCI_API_ERROR;
		}

		/* start voice stream */
		if (stream_ctrl(fxs->ch_fd[inf->id], true) != 0) {
			DBG(OMCI_API_ERR, ("fxs %u stream start failed!\n",
					  inf->id));
			return OMCI_API_ERROR;
		}
	} else if (inf->type == FXS_STREAM_T38_FAX) {
		/* Handle T38 fax configuration here. Currently not supported*/
		/** \todo add T38 fax handling here
		*/
		return OMCI_API_ERROR;
	} else {
		DBG(OMCI_API_ERR, ("Unknown stream type!\n"));
		return OMCI_API_ERROR;
	}

	return OMCI_API_SUCCESS;
}

enum omci_api_return fxs_stream_stop(struct fxs_data *fxs,
				     const uint8_t id)
{
	if (stream_redirect_stop(fxs->ch_fd[id]) != 0) {
		DBG(OMCI_API_ERR, ("fxs %u stream stop redirect failed!\n",
				  id));
		return OMCI_API_ERROR;
	}

	if (stream_ctrl(fxs->ch_fd[id], false) != 0) {
		DBG(OMCI_API_ERR, ("fxs %u stream stop failed!\n", id));
		return OMCI_API_ERROR;
	}

	if (stream_socket_delete(fxs->stream_sock_fd[id]) != 0) {
		DBG(OMCI_API_ERR, ("fxs %u stream socket delete failed!\n",
					id));
		return OMCI_API_ERROR;
	}
	fxs->stream_sock_fd[id] = -1;

	return OMCI_API_SUCCESS;
}

enum omci_api_return fxs_hook_status_get(const struct fxs_data *fxs,
					 const uint8_t id,
					 bool *off_hook)
{
	int ret = 0;
	uint32_t hook_status;

	if (id >= OMCI_API_FXS_MAX || !off_hook)
		return OMCI_API_ERROR;

	ret = tapi_io(	fxs->ch_fd[id], IFX_TAPI_LINE_HOOK_STATUS_GET,
			&hook_status);
	if (ret != 0) {
		DBG(OMCI_API_ERR, ("FXS hook status get failed!\n"));
		return OMCI_API_ERROR;
	}

	*off_hook = hook_status ? true : false;
	
	return OMCI_API_SUCCESS;
}

enum omci_api_return fxs_jb_cfg_set(const struct fxs_data *fxs,
				    const uint8_t id,
				    const uint16_t jitter_target,
				    const uint16_t jitter_buffer_max)
{
	int ret = 0;
	IFX_TAPI_JB_CFG_t jb_cfg;

	if (id >= OMCI_API_FXS_MAX)
		return OMCI_API_ERROR;

	memset (&jb_cfg, 0, sizeof(jb_cfg));

	if (jitter_target == 0) {
		/* Adaptive JB */
		jb_cfg.nJbType = IFX_TAPI_JB_TYPE_ADAPTIVE;
		/* Initial JB size, in 125 µs steps: 10 ms */
		jb_cfg.nInitialSize = FXS_JB_MIN_TIME_DEFAULT * 8;
		/* Minimum JB size, in 125 µs steps: 10 ms */
		jb_cfg.nMinSize = FXS_JB_MIN_TIME_DEFAULT * 8;
		/* Maximum JB size, in 125 µs steps: 180 ms */
		jb_cfg.nMaxSize = FXS_JB_MAX_TIME_DEFAULT * 8;
	} else {
		jb_cfg.nJbType = IFX_TAPI_JB_TYPE_FIXED;
		jb_cfg.nInitialSize = jitter_target * 8;
		jb_cfg.nMinSize = jitter_target * 8;
		jb_cfg.nMaxSize = jitter_buffer_max * 8;
	}

	/* Optimization for voice */
	jb_cfg.nPckAdpt = IFX_TAPI_JB_PKT_ADAPT_VOICE;
	/* nScaling multiplied by the packet length determines the play-out delay */
	jb_cfg.nScaling = 0x16;

	ret = tapi_io(fxs->ch_fd[id], IFX_TAPI_JB_CFG_SET, &jb_cfg);
	if (ret != 0) {
		DBG(OMCI_API_ERR, ("FXS Jitter Buf cfg set failed!\n"));
		return OMCI_API_ERROR;
	}

	return OMCI_API_SUCCESS;
}

enum omci_api_return fxs_phone_lec_enable(const struct fxs_data *fxs,
					  const uint8_t id,
					  const bool en)
{
	int ret = 0;
	IFX_TAPI_WLEC_CFG_t wlec_cfg;

	if (id >= OMCI_API_FXS_MAX)
		return OMCI_API_ERROR;

	memset (&wlec_cfg, 0, sizeof(wlec_cfg));

	if (en) {
		wlec_cfg.nType = IFX_TAPI_WLEC_TYPE_NE;
		wlec_cfg.bNlp = IFX_TAPI_WLEC_NLP_ON;
	} else {
		wlec_cfg.nType = IFX_TAPI_WLEC_TYPE_OFF;
		wlec_cfg.bNlp = IFX_TAPI_WLEC_NLP_OFF;
	}

	ret = tapi_io(fxs->ch_fd[id], IFX_TAPI_WLEC_PHONE_CFG_SET, &wlec_cfg);
	if (ret != 0) {
		DBG(OMCI_API_ERR, ("FXS WLEC cfg set failed!\n"));
		return OMCI_API_ERROR;
	}

	return OMCI_API_SUCCESS;
}

enum omci_api_return fxs_dtmf_cfg_set(const struct fxs_data *fxs,
				      const uint8_t id,
				      const uint16_t dtmf_digit_levels,
				      const uint16_t dtmf_digit_duration)
{
	int ret = 0;
	IFX_TAPI_TONE_t tone;
	int32_t lev_a, lev_b;
	uint32_t dur, idx;

	if (id >= OMCI_API_FXS_MAX)
		return OMCI_API_ERROR;

	memset(&tone, 0, sizeof(tone));

	if (dtmf_digit_levels != 0x8000) {
		lev_a = ((int32_t)((int16_t)dtmf_digit_levels)) * 10; 
		lev_b = lev_a;
	} else {
		lev_a = FXS_DTMF_LEVEL_A_DEFAULT; 
		lev_b = FXS_DTMF_LEVEL_B_DEFAULT;
	}

	dur = dtmf_digit_duration ? dtmf_digit_duration :
				    FXS_DTMF_CADENCE0_DEFAULT;

	tone.simple.format = IFX_TAPI_TONE_TYPE_SIMPLE;
	tone.simple.levelA = lev_a;
	tone.simple.levelB = lev_b;
	tone.simple.cadence[0] = dur;
	tone.simple.cadence[1] = 0;
	tone.simple.loop = 1;

	for (idx = 1; idx <= 31; idx++ ) {
		if (idx > 12 && idx < 28)
			continue;

		tone.simple.index = idx;
		ret = tapi_io(fxs->ch_fd[id], IFX_TAPI_TONE_TABLE_CFG_SET,
			      &tone);
		if (ret != 0) {
			DBG(OMCI_API_ERR,
				("FXS tone table cfg set failed, idx=%u!\n",
				idx));
			return OMCI_API_ERROR;
		}
	}

	return OMCI_API_SUCCESS;
}

enum omci_api_return fxs_hook_flash_cfg_set(const struct fxs_data *fxs,
					    const uint8_t id,
					    const uint16_t hook_flash_min_time,
					    const uint16_t hook_flash_max_time)
{
	int ret = 0;
	IFX_TAPI_LINE_HOOK_VT_t hook;

	if (id >= OMCI_API_FXS_MAX)
		return OMCI_API_ERROR;

	memset (&hook, 0, sizeof(hook));
	hook.nType = IFX_TAPI_LINE_HOOK_VT_HOOKFLASH_TIME;
	if (hook_flash_min_time && hook_flash_max_time) {
		hook.nMinTime = hook_flash_min_time;
		hook.nMaxTime = hook_flash_max_time;
	} else {
		/* set default time*/
		hook.nMinTime = FXS_HOOK_FLASH_MIN_TIME_DEFAULT;
		hook.nMaxTime = FXS_HOOK_FLASH_MAX_TIME_DEFAULT;
	}

	ret = tapi_io(fxs->ch_fd[id], IFX_TAPI_LINE_HOOK_VT_SET, &hook);
	if (ret != 0) {
		DBG(OMCI_API_ERR, ("FXS Hook Flash cfg set failed!\n"));
		return OMCI_API_ERROR;
	}

	return OMCI_API_SUCCESS;
}

enum omci_api_return fxs_rtp_pkt_loss_get(const struct fxs_data *fxs,
					  const uint8_t id,
					  uint32_t *pkt_loss)
{
	int ret = 0;
	struct fxs_last_err last_err;
	IFX_TAPI_PKT_RTCP_STATISTICS_t stat;

	if (id >= OMCI_API_FXS_MAX)
		return OMCI_API_ERROR;

	memset (&stat, 0, sizeof(stat));

	ret = tapi_io(fxs->ch_fd[id], IFX_TAPI_PKT_RTCP_STATISTICS_GET, &stat);
	if (ret != 0) {
		dev_fxs_last_err_get(fxs, &last_err);
		if (last_err.low == VMMC_statusCodNotActiveOnRtcpRead) {
			DBG(OMCI_API_WRN,
				("no RTP packet loss info available, port=%u!\n",
				id));
			return OMCI_API_WRN_DEV_NO_DATA;
		} else {
			DBG(OMCI_API_ERR,
				("failed to retrieve RTP packet loss, port=%u!\n",
				id));
			return OMCI_API_ERROR;
		}
	}

	*pkt_loss =
		(uint32_t)((((uint32_t)(-1))/((uint8_t)(-1)))*stat.fraction);

	return OMCI_API_SUCCESS;
}

enum omci_api_return fxs_jb_stat_get(const struct fxs_data *fxs,
				     const uint8_t id,
				     uint32_t *rtp_errors,
				     uint32_t *max_jitter,
				     uint32_t *buffer_overflows)
{
	int ret = 0;
	struct fxs_last_err last_err;
	IFX_TAPI_JB_STATISTICS_t stat;

	if (id >= OMCI_API_FXS_MAX)
		return OMCI_API_ERROR;

	memset (&stat, 0, sizeof(stat));
	ret = tapi_io(fxs->ch_fd[id], IFX_TAPI_JB_STATISTICS_GET, &stat);
	if (ret != 0){
		dev_fxs_last_err_get(fxs, &last_err);
		if (last_err.low == VMMC_statusCodNotActiveOnRtcpRead) {
			DBG(OMCI_API_WRN,
				("no JB statistics available, port=%u!\n",
				id));
			return OMCI_API_WRN_DEV_NO_DATA;
		} else {
			DBG(OMCI_API_ERR,
				("failed to retrieve JB statistics, port=%u!\n",
				id));
			return OMCI_API_ERROR;
		}
	}

	*rtp_errors = (uint32_t)stat.nInvalid;
	*max_jitter = (uint32_t)stat.nMaxBufSize;
	*buffer_overflows = (uint32_t)stat.nEarly;

	return OMCI_API_SUCCESS;
}

void fxs_debug_level_set(uint8_t level)
{
	/** \todo add TAPI/VMMC debugging? */
}

#endif /* #ifdef INCLUDE_OMCI_API_VOIP*/

