/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_sw_image.c
*/
#include "ifxos_memory_alloc.h"
#include "ifxos_print_io.h"

#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_sw_image.h"

#if 0
#ifdef WIN32
#pragma warning( disable : 4996 )	/* unlink is deprecated */
#endif
#endif
#include "me/omci_api_sw_image.h"

#ifdef LINUX
#include <unistd.h>
#endif

/** \addtogroup OMCI_ME_SW_IMAGE
   @{
*/

/** THIS IS TEMPORARY SWITCH! We may want to disable software logic for tests
   because loading via NFS fails. That's why this switch is introduced.

   1 - Disable SW related login
   0 - Enable
*/

#define SW_DISABLE                           0

/** reboot timeout for activate image action (in milliseconds) */
#define SW_IMAGE_REBOOT_TIMEOUT               REBOOT_TIMEOUT

/** Retrieve software image slot */
#define SW_IMAGE_SLOT(PME) \
         (((PME)->instance_id & 0xff00) >> 8)

#ifdef LINUX
/** Software image 0 save path
   The expected behavior: /tmp is mounted as tmpfs and located in memory! */
#  define SW_IMAGE0_PATH                     "/tmp/image0.img"
/** Software image 1 save path
   The expected behavior: /tmp is mounted as tmpfs and located in memory! */
#  define SW_IMAGE1_PATH                     "/tmp/image1.img"
#else
/** Software image 0 save path
   The expected behavior: /tmp is mounted as tmpfs and located in memory! */
#  define SW_IMAGE0_PATH                     "image0.img"
/** Software image 1 save path
   The expected behavior: /tmp is mounted as tmpfs and located in memory! */
#  define SW_IMAGE1_PATH                     "image1.img"
#endif

/** Software Image status (used in End SW Download) */
enum sw_image_status {
	/** Default status (no downloading & no storing) */
	SW_IMAGE_STATUS_NONE,

	/** Downloading */
	SW_IMAGE_STATUS_DOWNLOADING,

	/** Writing to Flash */
	SW_IMAGE_STATUS_WRITING,

	/** Writing complete */
	SW_IMAGE_STATUS_WRITING_COMPLETE
};

/** Non-ITU data of the Software Image Managed Entity */
struct internal_data {
	/** Image data. This is a pointer to the software image data */
	uint8_t *data;

	/** Number of sections in segment */
	size_t window_size;

	/** Allocated data size */
	size_t image_size;

	/** Current window  */
	unsigned int curr_window;

	/** Total number of received sections (excluding current window) */
	size_t total_sect_received;

	/** Number of sections received for current window */
	size_t curr_sect_received;

	/** timeout identifier */
	unsigned long timeout_id;

	/** Image status */
	enum sw_image_status status;

	/** count missing sections */
	unsigned int section_missed;
};

/** CRC-32 table */
static uint32_t crc32_i363_table[256] = {
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

/** Count CRC-32 as defined in ITU-T I.363.5

   \param data Data pointer
   \param data_size Size of data in bytes

   \return CRC-32
*/
static inline uint32_t crc32_i363_calc(const uint8_t *data, size_t data_size)
{
	uint32_t crc;
	unsigned int i;

	crc = 0xffffffff;

	for (i = 0; i < data_size; i++)
		crc = (crc << 8) ^ crc32_i363_table[((crc >> 24) ^ data[i]) &
			0xff];

	return crc ^ 0xffffffff;
}

/** This timeout event handler is called when the software image data is out
   of date (no more download sections).

   \param[in] context OMCI context pointer
   \param[in] timeout timeout descriptor
*/
static enum omci_error data_clean_timeout_handle(struct omci_context *context,
						 struct timeout *timeout)
{
	struct me *me;
	struct internal_data *me_internal_data;

	dbg_in(__func__, "%p, %p", (void *)context, (void *)timeout);

	me = (struct me *) timeout->arg1;
	me_internal_data = (struct internal_data *) me->internal_data;

	mib_lock_read(context);
	me_lock(context, me);

	dbg_prn("Timeout - Clear SW image data");

	IFXOS_MemFree(me_internal_data->data);
	me_internal_data->data = NULL;
	me_internal_data->status = SW_IMAGE_STATUS_NONE;

	me_internal_data->timeout_id = 0;

	me_unlock(context, me);
	mib_unlock(context);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error start_dl_action_handle(struct omci_context *context,
					      struct me *me,
					      const union omci_msg *msg,
					      union omci_msg *rsp)
{
	struct omci_me_sw_image *me_data;
	struct internal_data *me_internal_data;
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, %p", (void *)context, (void *)me,
	       (void *)msg, (void *)rsp);

	me_data = (struct omci_me_sw_image *) me->data;
	me_internal_data = (struct internal_data *) me->internal_data;

	rsp->start_dl_rsp.result = OMCI_MR_CMD_ERROR;

	/* remove old timeout event */
	(void)timeout_event_remove(context, me_internal_data->timeout_id);

	/* check if there were failed or inactive download */
	if (me_internal_data->data != NULL) {
		IFXOS_MemFree(me_internal_data->data);
		me_internal_data->data = NULL;
	}

	if (me_data->is_committed == true || me_data->is_active == true) {
		me_dbg_err(me, "Try to download active or committed image");

		rsp->start_dl_rsp.result = OMCI_MR_PARAM_ERROR;

		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;
	}

	/* get image & window sizes */
	me_internal_data->image_size = ntoh32(msg->start_dl.image_size);
	me_internal_data->window_size = msg->start_dl.window_size /*+ 1*/;

	/* don't change window size */
	rsp->start_dl_rsp.window_size = msg->start_dl.window_size;

	me_internal_data->curr_window = 0;
	me_internal_data->curr_sect_received = 0;
	me_internal_data->total_sect_received = 0;
	me_internal_data->section_missed = 0;

	me_dbg_err(me, "Received Start SW Download; "
		   "Image size = %lu bytes, Window size = %lu",
		   me_internal_data->image_size,
		   me_internal_data->window_size);

	/* allocate memory for image */
	me_internal_data->data = IFXOS_MemAlloc(me_internal_data->image_size);
	if (me_internal_data->data == NULL) {
		memset(rsp->msg_rsp.contents, 0, sizeof(rsp->msg_rsp.contents));
		rsp->start_dl_rsp.result = OMCI_MR_DEVICE_BUSY;

		me_dbg_err(me, "Not enough memory for software image "
			   "(required %lu bytes)",
			   me_internal_data->image_size);

		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;
	}
#if 0
	memset(me_internal_data->data, 0, me_internal_data->image_size);
#endif

	me_dbg_msg(me, "Allocated %lu bytes at %p",
		   me_internal_data->image_size,
		   (void *)me_internal_data->data);

	switch (SW_IMAGE_SLOT(me)) {
	case 0:
#if ((SW_DISABLE == 0))
		error = (enum omci_error)
			omci_api_sw_image_download_start(context->api,
							 me->instance_id & 1);
#else
		error = OMCI_SUCCESS;
#endif

		break;

	default:
		error = OMCI_ERROR;
		break;
	}

	if (error) {
		me_dbg_err(me, "SW image start download sub-handler failed");

		IFXOS_MemFree(me_internal_data->data);
		me_internal_data->data = NULL;

		RETURN_IF_ERROR(error);
	}

	me_data->is_valid = false;
	memset(me_data->version, 0, 14);

	/* increment MIB sequence number */
	error = mib_seq_num_inc(context);

	if (error) {
		IFXOS_MemFree(me_internal_data->data);
		me_internal_data->data = NULL;

		RETURN_IF_ERROR(error);
	}

	/* set new timeout */
	error = timeout_event_add(context, &me_internal_data->timeout_id,
				  OMCI_SWIMAGE_DOWNLOAD_TIMEOUT,
				  data_clean_timeout_handle,
				  me->class->class_id,
				  me->instance_id,
				  (unsigned long)me, 0, 0);

	if (error != OMCI_SUCCESS) {
		IFXOS_MemFree(me_internal_data->data);
		me_internal_data->data = NULL;

		me_dbg_err(me, "Can't add timeout event!");

		dbg_out_ret(__func__, error);
		return error;
	}

	me_internal_data->status = SW_IMAGE_STATUS_DOWNLOADING;

	rsp->start_dl_rsp.result = OMCI_MR_CMD_SUCCESS;

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error dl_section_action_handle(struct omci_context *context,
						struct me *me,
						const union omci_msg *msg,
						union omci_msg *rsp)
{
	struct omci_me_sw_image *me_data;
	struct internal_data *me_internal_data;
	size_t sect_size;
	uint32_t offset;
#if 0
	enum omci_error error;
#endif

	dbg_in(__func__, "%p, %p, %p, %p", (void *)context, (void *)me,
	       (void *)msg, (void *)rsp);

	me_data = (struct omci_me_sw_image *) me->data;
	me_internal_data = (struct internal_data *) me->internal_data;

	rsp->dl_section_rsp.result = OMCI_MR_CMD_ERROR;

#if 0
	/* remove old timeout event */
	(void)timeout_event_remove(context, me_internal_data->timeout_id);
#endif

	/* fool proofing */
	if (me_data->is_committed == true || me_data->is_active == true) {
		me_dbg_err(me, "Try to download active or committed image");

		rsp->dl_section_rsp.sect_num = msg->dl_section.sect_num;
		rsp->dl_section_rsp.result = OMCI_MR_PARAM_ERROR;

		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;
	}

	/* check if there were failed or inactive download */
	if (me_internal_data->data == NULL) {
		me_dbg_err(me, "SW image timeout");
		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;
	}

	if (msg->dl_section.sect_num == 0) {
		me_dbg_msg(me, "Section start received (section #0), window #%u",
		   me_internal_data->curr_window);
		me_internal_data->section_missed = 0;
	}

	me_dbg_msg(me, "Received Download Section #%u, waiting for #%u (window #%u)",
		   msg->dl_section.sect_num,
		   me_internal_data->curr_sect_received,
		   me_internal_data->curr_window);

	rsp->dl_section_rsp.sect_num = msg->dl_section.sect_num;

	/* expected section was not received; exit */
	if (me_internal_data->curr_sect_received != msg->dl_section.sect_num) {
		if ((me_internal_data->curr_sect_received + 1) ==
						    msg->dl_section.sect_num) {
			me_dbg_err(me, "Missed download section #%u",
					  me_internal_data->curr_sect_received);
			me_internal_data->curr_sect_received++;
			me_internal_data->section_missed++;
		} else {
			me_dbg_msg(me, "Received incorrect download section #%u, "
				       "expected #%lu",
					  msg->dl_section.sect_num,
					  me_internal_data->curr_sect_received);

			/* wait for section #0 */
			me_internal_data->curr_sect_received = 0;

			dbg_out_ret(__func__, OMCI_SUCCESS);
			return OMCI_SUCCESS;
		}
	}

	/* copy data */
	offset = (me_internal_data->total_sect_received
		  + me_internal_data->curr_sect_received)
		* sizeof(msg->dl_section.data);

	if (offset + sizeof(msg->dl_section.data) >
	    me_internal_data->image_size) {
		if (me_internal_data->image_size < offset) {
			/* don't copy data; it's padding */
			offset = me_internal_data->image_size;
			sect_size = 1;
		} else {
			sect_size = me_internal_data->image_size - offset;
		}
	} else {
		sect_size = sizeof(msg->dl_section.data);
	}

	if (offset + sect_size <= me_internal_data->image_size)
		memcpy(me_internal_data->data + offset, msg->dl_section.data,
		       sect_size);

	/* increment internal section counter */
	me_internal_data->curr_sect_received++;

	if (omci_msg_type_ar_get(msg) == 1)
		me_dbg_msg(me,"Ack request received, window #%u",
		   me_internal_data->curr_window);

	/* if this is the last section or OLT proposed smaller window size */
	if (/*me_internal_data->curr_sect_received >=
	    me_internal_data->window_size ||*/ omci_msg_type_ar_get(msg) == 1) {
		me_dbg_msg(me,
			   "Received window #%u (%lu total sections received)",
			   me_internal_data->curr_window,
			   me_internal_data->total_sect_received);
		/** check for overflow? */
		if (me_internal_data->section_missed) {
			me_dbg_err(me,"Please repeat window #%u (%lu total "
				      "sections missed)",
					    me_internal_data->curr_window,
					    me_internal_data->section_missed);
		} else {
			me_internal_data->curr_window++;
			me_internal_data->total_sect_received +=
			    me_internal_data->curr_sect_received;
		}
		me_internal_data->curr_sect_received = 0;
	}

#if 0
	/* set new timeout */
	error = timeout_event_add(context, &me_internal_data->timeout_id,
				  OMCI_SWIMAGE_DOWNLOAD_TIMEOUT,
				  data_clean_timeout_handle,
				  me->class->class_id,
				  me->instance_id,
				  (unsigned long)me, 0, 0);

	if (error != OMCI_SUCCESS) {
		me_dbg_err(me, "Can't add timeout event!");
		IFXOS_MemFree(me_internal_data->data);
		me_internal_data->data = NULL;

		dbg_out_ret(__func__, error);
		return error;
	}
#endif

	if (me_internal_data->section_missed) {
		rsp->dl_section_rsp.result = OMCI_MR_CMD_ERROR;
	} else {
		rsp->dl_section_rsp.result = OMCI_MR_CMD_SUCCESS;
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

#if ((SW_DISABLE == 0))
/** This is a callback handler which indicates that ONU software image was
   successfully stored (or not) to the FLASH

   \param[in] caller      OMCI context
   \param[in] sw_image_id Software image id
   \param[in] version     Software image version
   \param[in] valid       Returns software valid status;
                           - true - Image was successfully stored (valid)
                           - false - Image was not stored (invalid)
*/
static void end_dl_cb(void *caller,
		      unsigned int sw_image_id,
		      char version[OMCI_API_SWIMAGE_VERSION_LEN],
		      bool valid)
{
	struct omci_context *context = (struct omci_context *)caller;
	struct me *me;
	struct omci_me_sw_image *me_data;
	struct internal_data *me_internal_data;
	enum omci_error error;

	dbg_in(__func__, "%u, %p, %u", sw_image_id, (void *)version,
	       (unsigned int)valid);

#if ((SW_DISABLE == 0))
	context_lock(context);
	context->cant_reboot--;
	context_unlock(context);
#endif

	mib_lock_read(context);

	unlink((sw_image_id & 1) ? SW_IMAGE1_PATH : SW_IMAGE0_PATH);

	error = mib_me_find(context, OMCI_ME_SW_IMAGE,
			    (uint16_t)sw_image_id, &me);

	if (error) {
		me_unlock(context, me);
		mib_unlock(context);

		dbg_out(__func__);
		return;
	}

	me_data = (struct omci_me_sw_image *) me->data;
	me_internal_data = (struct internal_data *) me->internal_data;

	me_lock(context, me);

	if (valid) {
		me_data->is_valid = true;
		memcpy(me_data->version, version, 14);
		me_internal_data->status =
		    SW_IMAGE_STATUS_WRITING_COMPLETE;
	} else {
		me_data->is_valid = false;
		memset(me_data->version, 0, 14);
	}

	me_unlock(context, me);
	mib_unlock(context);

	dbg_out(__func__);
}
#endif

static enum omci_error end_dl_action_handle(struct omci_context *context,
					    struct me *me,
					    const union omci_msg *msg,
					    union omci_msg *rsp)
{
	struct omci_me_sw_image *me_data;
	struct internal_data *me_internal_data;
	uint32_t crc;
	enum omci_error error;
	IFXOS_File_t *sw_image_file;
	unsigned int written_bytes;

	dbg_in(__func__, "%p, %p, %p, %p", (void *)context, (void *)me,
	       (void *)msg, (void *)rsp);

	me_data = (struct omci_me_sw_image *) me->data;
	me_internal_data = (struct internal_data *) me->internal_data;

	me_dbg_err(me, "Received End SW Download");

	rsp->dl_section_rsp.result = OMCI_MR_CMD_ERROR;

	switch (me_internal_data->status) {
	case SW_IMAGE_STATUS_WRITING:
		rsp->dl_section_rsp.result = OMCI_MR_DEVICE_BUSY;

		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;

	case SW_IMAGE_STATUS_WRITING_COMPLETE:
		rsp->dl_section_rsp.result = OMCI_MR_CMD_SUCCESS;
		me_internal_data->status = SW_IMAGE_STATUS_NONE;

		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;

	case SW_IMAGE_STATUS_NONE:
		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;

	default:
		break;
	}

	/* remove old timeout event */
	(void)timeout_event_remove(context, me_internal_data->timeout_id);

	if (me_data->is_committed == true || me_data->is_active == true) {
		me_dbg_err(me, "Try to download active or committed image");

		rsp->end_dl_rsp.result = OMCI_MR_PARAM_ERROR;

		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;
	}

	crc = crc32_i363_calc(me_internal_data->data,
			      me_internal_data->image_size);

	/* check CRC */
	if (crc != ntoh32(msg->end_dl.crc)) {
		me_dbg_err(me, "Received incorrect CRC; "
			   "Received = 0x%08x; "
			   "Calculated = 0x%08x",
			   ntoh32(msg->end_dl.crc), crc);

		/* free data */
		IFXOS_MemFree(me_internal_data->data);
		me_internal_data->data = NULL;
		me_internal_data->status = SW_IMAGE_STATUS_NONE;

		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;
	}

	/* check image size */
	if (me_internal_data->image_size != ntoh32(msg->end_dl.image_size)) {
		me_dbg_err(me, "Received incorrect image size");

		/* free data */
		IFXOS_MemFree(me_internal_data->data);
		me_internal_data->data = NULL;
		me_internal_data->status = SW_IMAGE_STATUS_NONE;

		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;
	}

	/* save image to the file (memory mapped file?!) */
	sw_image_file = IFXOS_FOpen((me->instance_id & 1)
				    ? SW_IMAGE1_PATH :
				    SW_IMAGE0_PATH,
				    IFXOS_OPEN_MODE_WRITE_BIN);

	if (!sw_image_file) {
		me_dbg_err(me, "Can't store image to file '%s' (open)",
			   (me->instance_id & 1)
			   ? SW_IMAGE1_PATH : SW_IMAGE0_PATH);

		/* free data */
		IFXOS_MemFree(me_internal_data->data);
		me_internal_data->data = NULL;
		me_internal_data->status = SW_IMAGE_STATUS_NONE;

		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;
	}

	written_bytes = IFXOS_FWrite(me_internal_data->data, 1,
				     me_internal_data->image_size,
				     sw_image_file);

	(void)IFXOS_FClose(sw_image_file);

	IFXOS_MemFree(me_internal_data->data);
	me_internal_data->data = NULL;

	if (written_bytes != me_internal_data->image_size) {
		me_dbg_err(me,
			   "Can't store image to file '%s' (not enough space); "
			   "image size = %lu, written bytes = %u",
			   (me->instance_id & 1) ?
			   SW_IMAGE1_PATH : SW_IMAGE0_PATH,
			   me_internal_data->image_size, written_bytes);

		me_internal_data->status = SW_IMAGE_STATUS_NONE;

		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;
	}

	me_dbg_err(me, "Stored image to file '%s'",
		   (me->instance_id & 1) ? SW_IMAGE1_PATH : SW_IMAGE0_PATH);

	/* call sub-handler */
	me_internal_data->status = SW_IMAGE_STATUS_WRITING;

#if ((SW_DISABLE == 0))
	context_lock(context);
	context->cant_reboot++;
	context_unlock(context);
#endif

	switch (SW_IMAGE_SLOT(me)) {
	case 0:
#if ((SW_DISABLE == 0))
		error = (enum omci_error)
			omci_api_sw_image_download_end(context->api,
						       me->instance_id & 1,
						       (me->instance_id & 1)
						       ? SW_IMAGE1_PATH
						       : SW_IMAGE0_PATH,
						       end_dl_cb);
#else
		error = OMCI_SUCCESS;
#endif
		break;

	default:
		error = OMCI_ERROR;

		break;
	}

	if (error) {
		me_internal_data->status = SW_IMAGE_STATUS_NONE;

#if ((SW_DISABLE == 0))
		context_lock(context);
		context->cant_reboot--;
		context_unlock(context);
#endif

		unlink((me->instance_id & 1) ? SW_IMAGE1_PATH : SW_IMAGE0_PATH);

		RETURN_IF_ERROR(error);
	}

	rsp->dl_section_rsp.result = OMCI_MR_DEVICE_BUSY;

	dbg_out_ret(__func__, error);
	return error;
}

static enum omci_error activate_image_action_handle(struct omci_context
						    *context,
						    struct me *me,
						    const union omci_msg *msg,
						    union omci_msg *rsp)
{
	struct internal_data *me_internal_data;
	struct omci_me_sw_image *me_data;
	struct me *me2;
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, %p", (void *)context, (void *)me,
	       (void *)msg, (void *)rsp);

	me_data = (struct omci_me_sw_image *) me->data;
	me_internal_data = (struct internal_data *) me->internal_data;
	rsp->activate_image_rsp.result = OMCI_MR_CMD_ERROR;

	switch (me_internal_data->status) {
	case SW_IMAGE_STATUS_NONE:
	case SW_IMAGE_STATUS_WRITING_COMPLETE:
		break;

	default:
		rsp->activate_image_rsp.result = OMCI_MR_DEVICE_BUSY;

		me_dbg_err(me, "Try to activate image "
			   "that was not downloaded/stored so far");

		dbg_out_ret(__func__, OMCI_ERROR_ACTION);
		return OMCI_ERROR_ACTION;
	}

	/* check if image is valid */
	if (me_data->is_valid == false) {
		rsp->activate_image_rsp.result = OMCI_MR_PARAM_ERROR;

		me_dbg_err(me, "Try to activate invalid image");

		dbg_out_ret(__func__, OMCI_ERROR_ACTION);
		return OMCI_ERROR_ACTION;
	}
#if ((SW_DISABLE == 0))
	/* we don't want to reboot on OLT requests anymore because AL should
	   reboot ONT itself */
	context_lock(context);
	context->cant_reboot++;
	context_unlock(context);
#endif

	switch (SW_IMAGE_SLOT(me)) {
	case 0:
#if ((SW_DISABLE == 0))
		error = (enum omci_error)
			omci_api_sw_image_activate(context->api,
						   me->instance_id & 1,
						   SW_IMAGE_REBOOT_TIMEOUT);
#else
		error = OMCI_SUCCESS;
#endif
		break;

	default:
		error = OMCI_ERROR;

		break;
	}

	if (error) {
		me_dbg_err(me, "SW image activate sub-handler failed");
		RETURN_IF_ERROR(error);
	}

	/* find second image and make it uncommitted */
	error = mib_me_find(context, OMCI_ME_SW_IMAGE,
			    me->instance_id ^ 1, &me2);

	RETURN_IF_ERROR(error);

	me_data->is_active = true;

	me_lock(context, me2);
	/* if we will not reboot don't get confused with two active images */
	((struct omci_me_sw_image *) me2->data)->is_active = false;
	me_unlock(context, me2);

	/* increment MIB sequence number */
	error = mib_seq_num_inc(context);
	RETURN_IF_ERROR(error);

	rsp->activate_image_rsp.result = OMCI_MR_CMD_SUCCESS;

	dbg_out_ret(__func__, error);
	return error;
}

#if ((SW_DISABLE == 0))
/** This is a callback handler which indicates that ONU software image was
   successfully committed (or not)

   \param[in] caller      OMCI ONU context pointer
   \param[in] sw_image_id Software image id
   \param[in] bCommitted  Returns software commit status;
                          - true - Image was successfully committed
                          - false - Image was not committed
*/
static void commit_cb(void *caller,
		      unsigned int sw_image_id, bool committed)
{
	struct omci_context *context = (struct omci_context *)caller;
	struct me *me;
	struct me *me2;
	struct omci_me_sw_image *me_data;
	enum omci_error error;

	dbg_in(__func__, "%u, %u", sw_image_id, (unsigned int)committed);

#if ((SW_DISABLE == 0))
	context_lock(context);
	context->cant_reboot--;
	context_unlock(context);
#endif

	if (!committed)
		dbg_err("Failed to commit image %d", sw_image_id);

	dbg_out(__func__);
}
#endif

static enum omci_error commit_image_action_handle(struct omci_context *context,
						  struct me *me,
						  const union omci_msg *msg,
						  union omci_msg *rsp)
{
	struct internal_data *me_internal_data;
	struct omci_me_sw_image *me_data;
	struct me *me2;
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, %p", (void *)context, (void *)me,
	       (void *)msg, (void *)rsp);

	me_data = (struct omci_me_sw_image *) me->data;
	me_internal_data = (struct internal_data *) me->internal_data;
	rsp->commit_image_rsp.result = OMCI_MR_CMD_ERROR;

	switch (me_internal_data->status) {
	case SW_IMAGE_STATUS_NONE:
	case SW_IMAGE_STATUS_WRITING_COMPLETE:
		break;

	default:
		rsp->activate_image_rsp.result = OMCI_MR_DEVICE_BUSY;

		me_dbg_err(me, "Try to commit image "
			   "that was not downloaded/stored so far");

		dbg_out_ret(__func__, OMCI_ERROR_ACTION);
		return OMCI_ERROR_ACTION;
	}

	/* check if image is valid */
	if (me_data->is_valid == false) {
		me_dbg_err(me, "Try to commit invalid image");

		rsp->commit_image_rsp.result = OMCI_MR_PARAM_ERROR;

		dbg_out_ret(__func__, OMCI_ERROR_ACTION);
		return OMCI_ERROR_ACTION;
	}
#if ((SW_DISABLE == 0))
	context_lock(context);
	context->cant_reboot++;
	context_unlock(context);
#endif

	switch (SW_IMAGE_SLOT(me)) {
	case 0:
#if ((SW_DISABLE == 0))
		error = (enum omci_error)
			omci_api_sw_image_commit(context->api,
						 me->instance_id & 1,
						 commit_cb);
#else
		error = OMCI_SUCCESS;
#endif
		break;

	default:
		error = OMCI_ERROR;

		break;
	}

	if (error) {
		me_dbg_err(me, "SW image commit sub-handler failed");

#if ((SW_DISABLE == 0))
		context_lock(context);
		context->cant_reboot--;
		context_unlock(context);
#endif

		RETURN_IF_ERROR(error);
	}

	/* mark current image as committed and another one as uncommitted */
	me_data->is_committed = true;

	error = mib_me_find(context, OMCI_ME_SW_IMAGE,
			    me->instance_id ^ 1, &me2);
	RETURN_IF_ERROR(error);

	me_lock(context, me2);
	((struct omci_me_sw_image *)me2->data)->is_committed = false;
	me_unlock(context, me2);

	/* increment MIB sequence number */
	error = mib_seq_num_inc(context);
	RETURN_IF_ERROR(error);

	rsp->commit_image_rsp.result = OMCI_MR_CMD_SUCCESS;

	dbg_out_ret(__func__, error);
	return error;
}

static enum omci_error me_init(struct omci_context *context,
			       struct me *me,
			       void *init_data,
			       uint16_t suppress_avc)
{
#if ((SW_DISABLE == 0))
	bool tmp_bool;
#endif

	struct omci_me_sw_image data;
	struct internal_data *me_internal_data;
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context,
	       (void *)me, (void *)init_data, suppress_avc);

	memset(&data, 0x00, sizeof(data));
	me->internal_data = IFXOS_MemAlloc(sizeof(struct internal_data));
	RETURN_IF_MALLOC_ERROR(me->internal_data);
	memset(me->internal_data, 0, sizeof(struct internal_data));

	me_internal_data = (struct internal_data *) me->internal_data;

	switch (SW_IMAGE_SLOT(me)) {
	case 0:
#if ((SW_DISABLE == 0))
		error = OMCI_SUCCESS;
		error |= (enum omci_error)
			omci_api_sw_image_version_get(context->api,
						      me->instance_id & 1,
						      data.version);

		error |= (enum omci_error)
			omci_api_sw_image_is_committed(context->api,
						       me->instance_id & 1,
						       &tmp_bool);

		data.is_committed = (tmp_bool) ? true : false;

		error |= (enum omci_error)
			omci_api_sw_image_is_active(context->api,
						    me->instance_id & 1,
						    &tmp_bool);

		data.is_active = (tmp_bool) ? true : false;

		error |= (enum omci_error)
			omci_api_sw_image_is_valid(context->api,
						   me->instance_id & 1,
						   &tmp_bool);

		data.is_valid = (tmp_bool) ? true : false;
#else
		if (me->instance_id & 1) {
			data.is_committed = false;
			data.is_active = false;
			data.is_valid = false;
			memset(data.version, 0, 14);
		} else {
			data.is_committed = true;
			data.is_active = true;
			data.is_valid = true;
			memcpy(data.version,
			       "\0\0\0\0\0\0\0\0\0\0\0\0\0\0 ", 14);
		}
		error = OMCI_SUCCESS;
#endif
		break;

	default:
		error = OMCI_ERROR;

		break;
	}

	if (error != OMCI_SUCCESS) {
		me_dbg_err(me, "SW image init sub-handler failed");

		RETURN_IF_ERROR(error);
	}

	error = me_data_write(context, me, &data, sizeof(data),
			      ~me->class->inv_attr_mask, suppress_avc);
	RETURN_IF_ERROR(error);

	me_internal_data->status = SW_IMAGE_STATUS_NONE;

	dbg_out_ret(__func__, error);
	return error;
}

static enum omci_error me_shutdown(struct omci_context *context,
				   struct me *me)
{
	dbg_in(__func__, "%p, %p", (void *)context, (void *)me);

	IFXOS_MemFree(me->internal_data);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** Managed Entity class */
struct me_class me_sw_image_class = {
	/* Class ID */
	OMCI_ME_SW_IMAGE,
	/* Attributes */
	{
		/* 1. Version */
		ATTR_STR("Version",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_sw_image,
				  version),
			 14,
			 OMCI_ATTR_PROP_RD,
			 NULL),
		/* 2. Is committed */
		ATTR_BOOL("Is committed",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_sw_image,
				   is_committed),
			  1,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 3. Is active */
		ATTR_BOOL("Is active",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_sw_image,
				   is_active),
			  1,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 4. Is valid */
		ATTR_BOOL("Is valid",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_sw_image,
				   is_valid),
			  1,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 5-16. Doesn't exist */
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF()
	},
	/* Actions */
	{
		NULL, NULL, NULL, NULL,
		/* Create */
		NULL,
		NULL,
		/* Delete */
		NULL,
		NULL,
		/* Set */
		NULL,
		/* Get */
		get_action_handle,
		NULL,
		/* Get all alarms */
		NULL,
		/* Get all alarms next */
		NULL,
		/* MIB upload */
		NULL,
		/* MIB upload next */
		NULL,
		/* MIB reset */
		NULL,
		/* Alarm */
		NULL,
		/* Attribute value change */
		NULL,
		/* Test */
		NULL,
		/* Start SW download */
		start_dl_action_handle,
		/* Download section */
		dl_section_action_handle,
		/* End SW download */
		end_dl_action_handle,
		/* Activate software */
		activate_image_action_handle,
		/* Commit software */
		commit_image_action_handle,
		/* Synchronize Time */
		NULL,
		/* Reboot */
		NULL,
		/* Get next */
		NULL,
		/* Test result */
		NULL,
		/* Get current data */
		NULL
	},
	/* Init Handler */
	me_init,
	/* Shutdown Handler */
	me_shutdown,
	/* Validate Handler */
	NULL,
	/* Update Handler */
	default_me_update,
	/* Table Attribute Copy Handler */
	NULL,
	/* Table Attribute Operations Handler */
	NULL,
#ifdef INCLUDE_PM
	/* Counters get Handler */
	NULL,
	/* Thresholds set Handler */
	NULL,
#endif
	/* TCA Table */
	NULL,
	/* Data Size */
	sizeof(struct omci_me_sw_image),
	/* Properties */
	OMCI_ME_PROP_NONE | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"Software image",
		/* Access */
		ME_CREATED_BY_ONT,
		/* Supported alarms */
		NULL,
		/* Supported alarms count */
		0,
		/* Support */
		ME_SUPPORTED
	},
#endif
	/* dynamically calculated */
	0, 0, 0, 0, 0, 0
};

/** @} */
