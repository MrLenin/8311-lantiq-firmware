/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "ifxos_print_io.h"
#include "ifxos_time.h"
#include "ifxos_thread.h"
#include "ifxos_memory_alloc.h"
#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_sw_image.h"

#ifdef INCLUDE_SW_IMAGE_SUPPORT
#  include "me/omci_api_sw_image_falcon.h"
#endif

/** \addtogroup OMCI_API_ME_SW_IMAGE

   @{
*/

/** Image store thread priority */
#define OMCI_API_SWIMAGE_STORE_THREAD_PRIO           IFXOS_THREAD_PRIO_LOWEST
/** Image store thread stack size */
#define OMCI_API_SWIMAGE_STORE_THREAD_STACKSIZE      IFXOS_DEFAULT_STACK_SIZE

/** Image commit thread priority */
#define OMCI_API_SWIMAGE_COMMIT_THREAD_PRIO          IFXOS_THREAD_PRIO_LOWEST
/** Image commit thread stack size */
#define OMCI_API_SWIMAGE_COMMIT_THREAD_STACKSIZE     IFXOS_DEFAULT_STACK_SIZE

/** Image activate thread priority */
#define OMCI_API_SWIMAGE_ACTIVATE_THREAD_PRIO        IFXOS_THREAD_PRIO_LOWEST
/** Image activate thread stack size */
#define OMCI_API_SWIMAGE_ACTIVATE_THREAD_STACKSIZE   IFXOS_DEFAULT_STACK_SIZE

enum omci_api_return omci_api_sw_image_download_start(struct omci_api_ctx *ctx,
						      unsigned int sw_image_id)
{
	enum omci_api_return ret;

	if (sw_image_id > 1)
		return OMCI_API_ERROR;

#ifdef INCLUDE_SW_IMAGE_SUPPORT
	ret = omci_api_falcon_sw_image_download_start(sw_image_id);
#else
	ret = OMCI_API_SUCCESS;
#endif

	return ret;
}

/** Image store thread control structure */
static IFXOS_ThreadCtrl_t image_store_thread_control;

/** Image store thread

   \param[in] thr_params IFXOS_ThreadParams_t structure
*/
static int32_t omci_api_sw_image_image_store_thread(struct IFXOS_ThreadParams_s
						    *thr_params)
{
	struct omci_api_sw_image *sw_image;
	bool valid;
	enum omci_api_return ret;

#ifdef LINUX
	DBG(OMCI_API_MSG, ("ImageStoreThread (tid %d)" CRLF, getpid()));
#endif

	sw_image = (struct omci_api_sw_image *)thr_params->nArg1;

#ifdef INCLUDE_SW_IMAGE_SUPPORT
	ret = omci_api_falcon_sw_image_download_end(sw_image->id,
						    sw_image->p_filepath,
						    sw_image->p_version);
#else
	memset(sw_image->p_version, 0, OMCI_API_UIMAGE_NAME_LEN);
	ret = OMCI_API_SUCCESS;
#endif

	if (ret) {
		valid = false;
	} else {
#ifdef INCLUDE_SW_IMAGE_SUPPORT
		ret = omci_api_falcon_sw_image_store(sw_image);
#else
		IFXOS_SecSleep(1);	/* for tests */
		ret = OMCI_API_SUCCESS;
#endif

		valid = (ret) ? false : true;
	}

	sw_image->p_write_complete_cb(sw_image->ctx->caller,
				      sw_image->id,
				      sw_image->p_version,
				      valid);

	IFXOS_MemFree(sw_image);

	return 0;
}

enum omci_api_return
omci_api_sw_image_download_end(struct omci_api_ctx *ctx,
			       unsigned int sw_image_id,
			       const char *sw_image_filepath,
			       omci_api_sw_image_download_end_cb_t
			       *p_write_complete_cb)
{
	struct omci_api_sw_image *sw_image;
	struct stat st;

	if (sw_image_id > 1)
		return OMCI_API_ERROR;

	if (stat(sw_image_filepath, &st)) {
		DBG(OMCI_API_ERR, ("Can't stat file '%s'\n",
							sw_image_filepath));

		return OMCI_API_ERROR;
	}

	sw_image = (struct omci_api_sw_image *)
	    IFXOS_MemAlloc(sizeof(struct omci_api_sw_image));
	if (!sw_image) {
		DBG(OMCI_API_ERR, ("Can't allocate %u bytes\n",
			  sizeof(struct omci_api_sw_image)));

		return OMCI_API_ERROR;
	}

	sw_image->ctx = ctx;
	sw_image->id = sw_image_id;
	strcpy(sw_image->p_filepath, sw_image_filepath);
	sw_image->p_write_complete_cb = p_write_complete_cb;

	/* create "store image to the flash" thread */
	if (IFXOS_THREAD_INIT_VALID(&image_store_thread_control))
		(void)IFXOS_ThreadDelete(&image_store_thread_control, 0);

	if (IFXOS_ThreadInit((IFXOS_ThreadCtrl_t *) &image_store_thread_control,
			     "imgsave",
			     omci_api_sw_image_image_store_thread,
			     OMCI_API_SWIMAGE_STORE_THREAD_STACKSIZE,
			     OMCI_API_SWIMAGE_STORE_THREAD_PRIO,
			     (unsigned long)sw_image, (unsigned long)0)) {

		DBG(OMCI_API_ERR, ("Can't start image storing thread\n"));

		IFXOS_MemFree(sw_image);

		return OMCI_API_ERROR;
	}

	return OMCI_API_SUCCESS;
}

enum omci_api_return omci_api_sw_image_activate(struct omci_api_ctx *ctx,
						unsigned int sw_image_id,
						uint32_t reboot_timeout)
{
	if (sw_image_id > 1)
		return OMCI_API_ERROR;

	DBG(OMCI_API_ERR, ("Activate ONU SW image #%u\n", sw_image_id));

#ifdef INCLUDE_SW_IMAGE_SUPPORT
	(void)omci_api_falcon_sw_image_activate(ctx, sw_image_id);
	/* 8311 mod: Do not reboot on SW Image Activate.
	   Our fw_update_guard blocks the actual flash write, so rebooting
	   would just restart with the same image and trigger OLT retry loops.
	   The OLT can still reboot via the OMCI Reboot action if needed. */
#else
	/* don't reboot while simulating software */
#endif

	return OMCI_API_SUCCESS;
}

/** Image commit thread control structure */
static IFXOS_ThreadCtrl_t image_commit_thread_control;

struct image_commit_info {
	struct omci_api_ctx *ctx;
	uint16_t sw_image_id;
	omci_api_sw_image_commit_cb_t *commit_cb;
};

/** Image commit thread

   \param[in] thr_params IFXOS_ThreadParams_t structure
*/
static int32_t omci_api_sw_image_image_commit_thread(struct IFXOS_ThreadParams_s
						     *thr_params)
{
	struct image_commit_info *info = (struct image_commit_info *)
		thr_params->nArg1;

	enum omci_api_return ret;

#ifdef LINUX
	DBG(OMCI_API_MSG, ("ImageCommitThread (tid %d)" CRLF, getpid()));
#endif

#ifdef INCLUDE_SW_IMAGE_SUPPORT
	ret = omci_api_falcon_sw_image_commit(info->sw_image_id);
#else
	ret = OMCI_API_SUCCESS;
#endif

	info->commit_cb(info->ctx->caller, info->sw_image_id,
			 (ret == OMCI_API_SUCCESS) ? true : false);

	IFXOS_MemFree(info);

	return 0;
}

enum omci_api_return omci_api_sw_image_commit(struct omci_api_ctx *ctx,
					      unsigned int sw_image_id,
					      omci_api_sw_image_commit_cb_t
					      *commit_complete_cb)
{
	struct image_commit_info *info;

	if (sw_image_id > 1)
		return OMCI_API_ERROR;

	DBG(OMCI_API_ERR, ("Commit ONU SW image #%u\n", sw_image_id));

	/* create "commit image" thread */
	if (IFXOS_THREAD_INIT_VALID(&image_commit_thread_control))
		(void)IFXOS_ThreadDelete(&image_commit_thread_control, 0);

	info = IFXOS_MemAlloc(sizeof(struct image_commit_info));

	if (!info) {
		(void)IFXOS_ThreadDelete(&image_commit_thread_control, 0);
		return OMCI_API_ERROR;
	}

	info->ctx = ctx;
	info->sw_image_id = sw_image_id;
	info->commit_cb = commit_complete_cb;

	if (IFXOS_ThreadInit((IFXOS_ThreadCtrl_t *)&image_commit_thread_control,
			     "imgcmt",
			     omci_api_sw_image_image_commit_thread,
			     OMCI_API_SWIMAGE_COMMIT_THREAD_STACKSIZE,
			     OMCI_API_SWIMAGE_COMMIT_THREAD_PRIO,
			     (unsigned long)info,
			     0)) {
		DBG(OMCI_API_ERR, ("Can't start image committing thread\n"));

		return OMCI_API_ERROR;
	}

	return OMCI_API_SUCCESS;
}

enum omci_api_return omci_api_sw_image_is_active(struct omci_api_ctx *ctx,
						 unsigned int sw_image_id,
						 bool *is_active)
{
	enum omci_api_return ret;

	if (sw_image_id > 1)
		return OMCI_API_ERROR;

#ifdef INCLUDE_SW_IMAGE_SUPPORT
	ret = omci_api_falcon_sw_image_is_active(sw_image_id, is_active);
#else
	ret = OMCI_API_SUCCESS;
#endif

	return ret;
}

enum omci_api_return omci_api_sw_image_is_committed(struct omci_api_ctx *ctx,
						    unsigned int sw_image_id,
						    bool *is_committed)
{
	enum omci_api_return ret;

	if (sw_image_id > 1)
		return OMCI_API_ERROR;

#ifdef INCLUDE_SW_IMAGE_SUPPORT
	ret = omci_api_falcon_sw_image_is_committed(sw_image_id, is_committed);
#else
	if (sw_image_id == 0)
		*is_committed = true;
	else
		*is_committed = false;

	ret = OMCI_API_SUCCESS;
#endif

	return ret;
}

enum omci_api_return omci_api_sw_image_is_valid(struct omci_api_ctx *ctx,
						unsigned int sw_image_id,
						bool *is_valid)
{
	enum omci_api_return ret;

	if (sw_image_id > 1)
		return OMCI_API_ERROR;

#ifdef INCLUDE_SW_IMAGE_SUPPORT
	ret = omci_api_falcon_sw_image_is_valid(sw_image_id, is_valid);
#else
	*is_valid = true;

	ret = OMCI_API_SUCCESS;
#endif

	return ret;
}

enum omci_api_return
omci_api_sw_image_version_get(struct omci_api_ctx *ctx,
			      unsigned int sw_image_id,
			      char p_version[OMCI_API_SWIMAGE_VERSION_LEN])
{
	enum omci_api_return ret;
	bool is_valid;

	if (sw_image_id > 1)
		return OMCI_API_ERROR;

	if (omci_api_sw_image_is_valid(ctx, sw_image_id, &is_valid)) {
		memset(p_version, 0, 14);

		return OMCI_API_ERROR;
	}

	if (is_valid == false) {
		memset(p_version, 0, 14);

		return OMCI_API_SUCCESS;
	}
#ifdef INCLUDE_SW_IMAGE_SUPPORT
	ret = omci_api_falcon_sw_image_version_get(sw_image_id, p_version);
#else

	if (sw_image_id == 0)
		strcpy(p_version,
		       "\x52\x32\x2e\x30\x2e\x39\x2e\x32\x31\x00\x00\x00");
	else
		strcpy(p_version,
		       "\x52\x31\x2e\x35\x2e\x37\x2e\x33\x00\x00\x00\x00");

	ret = OMCI_API_SUCCESS;
#endif

	return OMCI_API_SUCCESS;
}

/** @} */
