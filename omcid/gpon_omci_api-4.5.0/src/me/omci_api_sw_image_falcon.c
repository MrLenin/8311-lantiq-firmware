/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "ifxos_memory_alloc.h"
#include "ifxos_print_io.h"
#include "ifxos_thread.h"

#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_sw_image_falcon.h"

#ifdef INCLUDE_SW_IMAGE_SUPPORT

#define GOI_STORE_SCRIPT "/opt/lantiq/bin/goi_store_uboot.sh"

#  ifdef LINUX
#     include <sys/types.h>
#     include <sys/wait.h>
#     include <unistd.h>
#  endif

/** \addtogroup OMCI_API_ME_SW_IMAGE_FALCON

   @{
*/

/** Image invalidate thread priority */
#  define OMCI_API_SWIMAGE_INVALIDATE_THREAD_PRIO       IFXOS_THREAD_PRIO_LOWEST
/** Image invalidate thread stack size */
#  define OMCI_API_SWIMAGE_INVALIDATE_THREAD_STACKSIZE  IFXOS_DEFAULT_STACK_SIZE

/* "included" from the U-boot include/image.h */
#  define IH_CPU_MIPS                        5	/* MIPS */
#  define IH_MAGIC                           0x27051956	/* Image Magic Number */
#  define IH_NMLEN                           32	/* Image Name Length */

#  if (OMCI_API_UIMAGE_NAME_LEN <= IH_NMLEN)
#    error "OMCI_API_UIMAGE_NAME_LEN should be greater than IH_NMLEN"
#  endif

/* all data in network byte order (aka natural aka bigendian) */
struct image_header {
	uint32_t ih_magic;	/* Image Header Magic Number */
	uint32_t ih_hcrc;	/* Image Header CRC Checksum */
	uint32_t ih_time;	/* Image Creation Timestamp */
	uint32_t ih_size;	/* Image Data Size */
	uint32_t ih_load;	/* Data Load  Address */
	uint32_t ih_ep;		/* Entry Point Address */
	uint32_t ih_dcrc;	/* Image Data CRC Checksum */
	uint8_t ih_os;		/* Operating System */
	uint8_t ih_arch;	/* CPU architecture */
	uint8_t ih_type;	/* Image Type */
	uint8_t ih_comp;	/* Compression Type */
	uint8_t ih_name[IH_NMLEN];	/* Image Name */
};

/** Read U-boot environment variable

   \param[in]  variable  Variable name to read
   \param[out] value     Pointer to value data
   \param[in]  value_size Size of the value data (value) in bytes
*/
static enum omci_api_return
omci_api_falcon_uboot_env_get(char *variable,
			      char *value,
			      unsigned int value_size)
{
	FILE *fprintenv;
	char buff[0x40 - 1];
	char val_buff[0x40 - 1];
	char *ptr;

	/* generate U-boot query */
	if (IFXOS_SNPrintf(buff, sizeof(buff), "fw_printenv %s", variable) <=
	    0) {
		DBG(OMCI_API_ERR, ("IFXOS_SNPrintf(); errno %u\n", errno));

		return OMCI_API_ERROR;
	}

	/* execute fw_printenv ... */
	if ((fprintenv = popen(buff, "r")) == (FILE *) 0) {
		DBG(OMCI_API_ERR, ("" "popen(); errno %u\n", errno));

		return OMCI_API_ERROR;
	}

	/* read fw_printenv output */
	if (fread(buff, 1, sizeof(buff), fprintenv) == 0) {
		(void)pclose(fprintenv);
		return OMCI_API_ERROR;
	}

	(void)pclose(fprintenv);

	/* extract value */
	if (sscanf(buff, "%*[^=]=%[^\n]", val_buff) == 0) {
		DBG(OMCI_API_ERR, ("" "sscanf(); errno %u\n", errno));

		return OMCI_API_ERROR;
	}

	strncpy(value, val_buff, value_size);

	return OMCI_API_SUCCESS;
}

/** Write U-boot environment variable

   \param[in] variable Variable name to write
   \param[in] value    Value to write
*/
static enum omci_api_return omci_api_falcon_uboot_env_set(char *variable,
							  char *value)
{
	pid_t pid;
	int pstatus;

	pid = fork();

	if (pid == 0) {
		/* child */

		if (execlp
		    ("fw_setenv", "fw_setenv", variable, value, (char *)0)
		    == -1) {
			DBG(OMCI_API_ERR, ("execl(); errno %u\n", errno));

			return OMCI_API_ERROR;
		}
	} else if (pid < 0) {
		/* fork error */
		DBG(OMCI_API_ERR, ("" "fork(); errno %u\n", errno));

		return OMCI_API_ERROR;
	} else {
		/* parent */

		/* wait till environment variable is set */
		if (waitpid(pid, &pstatus, 0) == -1) {
			DBG(OMCI_API_ERR, ("waitpid(); errno %u\n", errno));

			return OMCI_API_ERROR;
		}

		/* check if we wrote successfully */
		if (WIFEXITED(pstatus) == 0) {
			DBG(OMCI_API_ERR, ("" "fw_setenv status error\n"));

			return OMCI_API_ERROR;
		}
	}

	return OMCI_API_SUCCESS;
}

/** Make image valid/invalid

   \param[in] sw_image_id SW Image Instance ID
   \param[in] is_valid   Make image valid (true) or invalid (false)
*/
static enum omci_api_return
omci_api_falcon_sw_image_valid_flag_set(unsigned int sw_image_id,
					bool is_valid)
{
	if (sw_image_id > 1)
		return OMCI_API_ERROR;

	DBG(OMCI_API_ERR, ("Make ONU SW image #%u %s\n",
		  sw_image_id, (is_valid == true) ? "valid" : "invalid"));

	return omci_api_falcon_uboot_env_set((sw_image_id == 0)
					   ? "image0_is_valid" :
					   "image1_is_valid",
					   (is_valid == true) ? "1" : "0");
}

/** Store image to the FLASH memory

   \param[in] sw_image_id SW Image Instance ID
   \param[in] filename  SW Image file name
*/
static enum omci_api_return
omci_api_falcon_sw_image_nvm_store(unsigned int sw_image_id,
				   char *filename)
{
	char part_name[0x10];
	unsigned int part_size = 0x0000;
	char mtd[0x10];
	IFXOS_File_t *f_proc_mtd;
	struct stat st;
	unsigned int size;
	pid_t pid;
	int pstatus;

	if (sw_image_id > 1)
		return OMCI_API_ERROR;

	f_proc_mtd = IFXOS_FOpen("/proc/mtd", IFXOS_OPEN_MODE_READ);
	if (f_proc_mtd == NULL) {
		DBG(OMCI_API_ERR, ("Can't determine which image is loaded "
			  "(can't open /proc/mtd)\n"));

		return OMCI_API_ERROR;
	}

	/* pass header */
	fscanf(f_proc_mtd, "%*s %*s %*s %*s\n");
	/* parse contents */

	while (fscanf(f_proc_mtd, "%[^:]: %x %*s \"%[^\"]\"\n", mtd, &part_size,
		      part_name) > 0) {

		if ((sw_image_id == 1 && strcmp("image1", part_name) == 0)
		    || (sw_image_id == 0 && strcmp("image0", part_name) == 0)) {
			if (stat(filename, &st)) {
				DBG(OMCI_API_ERR, ("Can't stat file '%s'\n",
					  filename));

				return OMCI_API_ERROR;
			}

			size = st.st_size;

			if (size > part_size) {
				DBG(OMCI_API_ERR,
				    ("ERROR(-1) ONU SW Image size (%u) is "
				    "greater than partition size (%u)\n", size,
				     part_size));

				return OMCI_API_ERROR;
			}

			DBG(OMCI_API_ERR, ("Saving GOI configuration..."));
			if (system(GOI_STORE_SCRIPT)) {
				DBG(OMCI_API_WRN,
				    ("Can't save GOI configuration!"));
			}

			DBG(OMCI_API_ERR, ("Storing ONU SW image #%u "
				  "to %s (/dev/%s)...\n", sw_image_id,
				  part_name, mtd));

			pid = fork();

			if (pid == 0) {
				/* child */
				if (execlp
				    ("mtd", "mtd", "-e", part_name, "-q",
				     "write", filename, part_name,
				     (char *)NULL) == -1) {
					DBG(OMCI_API_ERR,
					    ("ERROR(-1) execl(); errno %u\n",
					     errno));

					return OMCI_API_ERROR;
				}
			} else if (pid < 0) {
				/* fork error */
				DBG(OMCI_API_ERR, ("fork(); errno %u\n",
					  errno));

				return OMCI_API_ERROR;
			} else {
				/* parent */

				if (waitpid(pid, &pstatus, 0) == -1) {
					DBG(OMCI_API_ERR,
					    ("ERROR(-1) waitpid(); errno %u\n",
					     errno));

					return OMCI_API_ERROR;
				}

				if (WIFEXITED(pstatus) == 0) {
					DBG(OMCI_API_ERR, (""
						  "mtd status error\n"));

					return OMCI_API_ERROR;
				}
			}

			DBG(OMCI_API_ERR,
				("Stored ONU SW image (%u bytes)\n", size));

			return OMCI_API_SUCCESS;
		}
	}

	DBG(OMCI_API_ERR, ("Can't find ONU SW image partition\n"));

	return OMCI_API_ERROR;
}

/** Image invalidate thread control structure */
static IFXOS_ThreadCtrl_t image_invalidate_thread_control;

/** Image invalidate thread

   \param[in] thr_params IFXOS_ThreadParams_t structure
*/
static int32_t
omci_api_sw_image_image_invalidate_thread(struct IFXOS_ThreadParams_s
					  *thr_params)
{
	unsigned int sw_image_id;

#ifdef LINUX
	DBG(OMCI_API_MSG, ("ImageInvalidateThread (tid %d)" CRLF, getpid()));
#endif

	sw_image_id = (unsigned int)thr_params->nArg1;

	omci_api_falcon_sw_image_valid_flag_set(sw_image_id, false);

	return 0;
}

enum omci_api_return
omci_api_falcon_sw_image_download_start(unsigned int sw_image_id)
{

	if (IFXOS_THREAD_INIT_VALID(&image_invalidate_thread_control))
		(void)IFXOS_ThreadDelete(&image_invalidate_thread_control, 0);

	if (IFXOS_ThreadInit((IFXOS_ThreadCtrl_t *)
					&image_invalidate_thread_control,
			     "imginv",
			     omci_api_sw_image_image_invalidate_thread,
			     OMCI_API_SWIMAGE_INVALIDATE_THREAD_STACKSIZE,
			     OMCI_API_SWIMAGE_INVALIDATE_THREAD_PRIO,
			     (unsigned long)sw_image_id,
			     (unsigned long)0)) {
		DBG(OMCI_API_ERR, ("Can't start image invalidate thread\n"));

		return OMCI_API_ERROR;
	}

	return OMCI_API_SUCCESS;
}

enum omci_api_return
omci_api_falcon_sw_image_download_end(unsigned int sw_image_id,
				      const char *sw_image_filepath,
				      char sw_image_version[OMCI_API_UIMAGE_NAME_LEN])
{
	struct omci_api_sw_image *sw_image;

	IFXOS_File_t *f_img;
	struct image_header header;

	f_img = IFXOS_FOpen(sw_image_filepath, IFXOS_OPEN_MODE_READ);
	if (!f_img) {
		DBG(OMCI_API_ERR, ("Can't open image file '%s'\n",
			  sw_image_filepath));

		return OMCI_API_ERROR;
	}

	if (IFXOS_FRead(&header, sizeof(header), 1, f_img) != 1) {
		DBG(OMCI_API_ERR, (""
			  "Can't read image '%s' header\n", sw_image_filepath));

		return OMCI_API_ERROR;
	}

	(void)IFXOS_FClose(f_img);

	if (ntohl(header.ih_magic) != IH_MAGIC) {
		DBG(OMCI_API_ERR, ("Bad image magic number (0x%x)\n",
			  ntohl(header.ih_magic)));

		return OMCI_API_ERROR;
	}

	if (ntohl(header.ih_arch) != IH_CPU_MIPS) {
		DBG(OMCI_API_ERR, ("Bad image arch (0x%x)\n",
			  ntohl(header.ih_arch)));

		return OMCI_API_ERROR;

	}

	/** \todo chech image CRC (header.ih_dcrc) */

	memcpy(sw_image_version, header.ih_name, IH_NMLEN);
	sw_image_version[OMCI_API_UIMAGE_NAME_LEN - 1] = '\0';

	if (strlen(sw_image_filepath)
	    > sizeof(sw_image->p_filepath) / sizeof(sw_image->p_filepath[0])) {
		DBG(OMCI_API_ERR, (""
			  "Image file path '%s' is too long\n",
			  sw_image_filepath));

		return OMCI_API_ERROR;
	}

	return OMCI_API_SUCCESS;
}

enum omci_api_return
omci_api_falcon_sw_image_store(struct omci_api_sw_image *sw_image)
{
	enum omci_api_return ret;

	/* store image to flash */
	ret = omci_api_falcon_sw_image_nvm_store(sw_image->id,
						 sw_image->p_filepath);
	if (ret)
		return OMCI_API_ERROR;

	/* store image version to fwenv */
	if (omci_api_falcon_uboot_env_set((sw_image->id == 0) ? "image0_version"
					: "image1_version",
					sw_image->p_version)) {
		DBG(OMCI_API_ERR, (""
			  "Can't save image #%u version '%s' to the "
			  "u-boot environment\n", sw_image->id,
			  sw_image->p_version));
		return OMCI_API_ERROR;
	}

	/* make image valid */
	ret = omci_api_falcon_sw_image_valid_flag_set(sw_image->id, true);

	if (ret)
		return OMCI_API_ERROR;

	return OMCI_API_SUCCESS;
}

/* Magic number address. Used to validate activate image ID from the u-boot
   side. */
#define OMCI_API_UBOOT_RAM_ACT_IMAGE_MAGIC_ADDR	0xBF200038
#define OMCI_API_UBOOT_RAM_ACT_IMAGE_MAGIC_VAL	0xDEADBEEF
/* Activate image ID address. Used by the u-boot to load the activated image. */
#define OMCI_API_UBOOT_RAM_ACT_IMAGE_VAL_ADDR	0xBF20003C

enum omci_api_return omci_api_falcon_sw_image_activate(struct omci_api_ctx *ctx,
						       unsigned int sw_image_id)
{
	enum omci_api_return ret;
	struct onu_reg_addr_val reg;

	reg.form = 32;
	reg.address = OMCI_API_UBOOT_RAM_ACT_IMAGE_MAGIC_ADDR;
	reg.value = OMCI_API_UBOOT_RAM_ACT_IMAGE_MAGIC_VAL;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_ONU_REGISTER_SET,
		      &reg, sizeof(reg));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	reg.form = 32;
	reg.address = OMCI_API_UBOOT_RAM_ACT_IMAGE_VAL_ADDR;
	reg.value = sw_image_id;

	return dev_ctl(ctx->remote, ctx->onu_fd, FIO_ONU_REGISTER_SET,
		       &reg, sizeof(reg));
}

enum omci_api_return omci_api_falcon_sw_image_commit(unsigned int sw_image_id)
{
	return omci_api_falcon_uboot_env_set("committed_image",
					   (sw_image_id == 0) ? "0" : "1");
}

enum omci_api_return omci_api_falcon_sw_image_is_active(unsigned int sw_image_id,
							bool *is_active)
{
	char part_name[0x10];
	IFXOS_File_t *f_proc_mtd;

	f_proc_mtd = IFXOS_FOpen("/proc/mtd", IFXOS_OPEN_MODE_READ);
	if (f_proc_mtd == NULL) {
		DBG(OMCI_API_ERR, (""
			  "Can't determine  which image is loaded "
			  "(can't open /proc/mtd)\n"));

		return OMCI_API_ERROR;
	}

	/* pass header */
	fscanf(f_proc_mtd, "%*s %*s %*s %*s\n");
	/* parse contents */
	while (fscanf(f_proc_mtd, "%*[^:]: %*s %*s \"%[^\"]\"", part_name)>0) {
		if (strcmp("image0", part_name) == 0) {
			/* found partition image0; therefore we are image 1 */
			if (sw_image_id == 1)
				*is_active = true;
			else
				*is_active = false;

			IFXOS_FClose(f_proc_mtd);

			return OMCI_API_SUCCESS;
		}

		if (strcmp("image1", part_name) == 0) {
			/* found partition image1; therefore we are image 0 */
			if (sw_image_id == 0)
				*is_active = true;
			else
				*is_active = false;

			IFXOS_FClose(f_proc_mtd);

			return OMCI_API_SUCCESS;
		}
	}

	if (sw_image_id == 0)
		*is_active = true;
	else
		*is_active = false;

	DBG(OMCI_API_ERR, (""
		  "Can't determine which image is loaded, "
		  "dual image support not activated\n"));

	IFXOS_FClose(f_proc_mtd);

	return OMCI_API_SUCCESS;
}

enum omci_api_return
omci_api_falcon_sw_image_is_committed(unsigned int sw_image_id,
				      bool *is_committed)
{
	char variable[5];

	if (omci_api_falcon_uboot_env_get
	    ("committed_image", variable, sizeof(variable))) {
		*is_committed = false;
		return OMCI_API_SUCCESS;
	}

	if ((variable[0] == '1' && sw_image_id == 1)
	    || (variable[0] == '0' && sw_image_id == 0))
		*is_committed = true;
	else
		*is_committed = false;

	return OMCI_API_SUCCESS;
}

enum omci_api_return omci_api_falcon_sw_image_is_valid(unsigned int sw_image_id,
						       bool *is_valid)
{
	char variable[5];

	if (omci_api_falcon_uboot_env_get((sw_image_id == 0)
					? "image0_is_valid" : "image1_is_valid",
					variable, sizeof(variable))) {
		*is_valid = false;
		return OMCI_API_SUCCESS;
	}

	*is_valid = (variable[0] == '1') ? true : false;

	return OMCI_API_SUCCESS;
}

enum omci_api_return
omci_api_falcon_sw_image_version_get(unsigned int sw_image_id,
				     char p_version[OMCI_API_SWIMAGE_VERSION_LEN])
{
	if (omci_api_falcon_uboot_env_get((sw_image_id == 0) ? "image0_version"
					: "image1_version", p_version,
					OMCI_API_SWIMAGE_VERSION_LEN)) {
		/* we can't read version, return default one */
		strncpy(p_version, OMCI_API_SWIMAGE_DEF_VERSION,
			OMCI_API_SWIMAGE_VERSION_LEN);
	}

	return OMCI_API_SUCCESS;
}

/** @} */

#endif
