/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_sw_image_h
#define _omci_api_me_sw_image_h

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_SW_IMAGE Software image

   This Managed Entity models an executable software image stored in the ONU.
   The ONU automatically creates two instances of this Managed Entity upon the
   creation of each Managed Entity that contains independently-manageable
   software, either the ONU itself or an individual circuit pack.

   The ME attributes are populated according to data within the ONU or the
   circuit pack.

   Some pluggable equipment types may contain no software. Others may contain
   software that is intrinsically bound to the ONU's own software image. No
   software image ME need exist for such equipment, though it may be
   convenient for the ONU to create them to support software version audit from
   the OLT. In this case, the dependent MEs would support only the get action.
   A slot may contain various types of equipment over its lifetime, and if software
   image MEs exist, the ONU must automatically create and delete them as the
   equipage changes. When controller packs are duplicated, each can be expected
   to contain two software image MEs, managed through reference to the
   individual controller packs themselves. When this occurs, the ONU should not
   have a global pair of software images MEs (instance 0), since an action
   (download, activate, commit) directed to instance 0 would be ambiguous.

   @{
*/

/** Image default version (if no version info is located in the u-boot) */
#define OMCI_API_SWIMAGE_DEF_VERSION               "00000000000000"

/** uImage name length */
#define OMCI_API_UIMAGE_NAME_LEN (32 + 1)

/** SW Image Version length as defined by G.984.10 */
#define OMCI_API_SWIMAGE_VERSION_LEN 14

/** Writing the downloaded image to non-volatile memory callback definition

   \param[in] caller      Caller context
   \param[in] sw_image_id SW Image Instance ID
   \param[in] p_version   SW Image version
   \param[in] valid       SW Image valid flag

   \note
   This callback is used by the backend to inform OMCI stack about the status
   of writing the downloaded image into non-volatile memory.
*/
typedef void (omci_api_sw_image_download_end_cb_t) (void *caller,
						    unsigned int sw_image_id,
						    char p_version[OMCI_API_SWIMAGE_VERSION_LEN],
						    bool valid);

/** Commit the downloaded image callback definition

   \param[in] caller      Caller context
   \param[in] sw_image_id SW Image Instance ID
   \param[in] bCommitted  SW Image commit status flag

   \note
   This callback is used by the backend to inform OMCI stack about the status
   of committing the downloaded image.
*/
typedef void (omci_api_sw_image_commit_cb_t) (void *caller,
					      unsigned int sw_image_id,
					      bool bCommitted);

/** Software image descriptor */
struct omci_api_sw_image {
	/** OMCI API context pointer */
	struct omci_api_ctx *ctx;

	/** Image id */
	unsigned int id;

	/** Image file path */
	char p_filepath[255];

	/** Image version */
	char p_version[OMCI_API_UIMAGE_NAME_LEN];

	/** Image write complete callback */
	omci_api_sw_image_download_end_cb_t *p_write_complete_cb;
};

/** This function is used by OMCI stack to inform the backend that
   download is started for software image

   \param[in] ctx         OMCI API context pointer
   \param[in] sw_image_id SW Image Instance ID
*/
enum omci_api_return omci_api_sw_image_download_start(struct omci_api_ctx *ctx,
						      unsigned int sw_image_id);

/** This function is used by OMCI stack to inform the backend that
   download is completed for software image

   \param[in] ctx                  OMCI API context pointer
   \param[in] sw_image_id          SW Image Instance ID
   \param[in] sw_image_filepath    SW Image file path
   \param[in] p_write_complete_cb  SW Image Write Complete Callback

   \note
   When this function is invoked the backend needs to validate the
   downloaded image using checksum or CRC embedded in the downloaded image,
   extract version information for the downloaded file and commit the
   downloaded software to non-volatile memory in the special thread and inform
   the OMCI stack about the status of writing the downloaded image
   into non-volatile memory via p_write_complete_cb callback.
*/
enum omci_api_return
omci_api_sw_image_download_end(struct omci_api_ctx *ctx,
			       unsigned int sw_image_id,
			       const char *sw_image_filepath,
			       omci_api_sw_image_download_end_cb_t
			       *p_write_complete_cb);

/** This function is used by OMCI to inform the backend that the downloaded
   and committed image needs to be activated and used after reboot

   \param[in] ctx             OMCI API context pointer
   \param[in] sw_image_id     SW Image Instance ID
   \param[in] reboot_timeout  Reboot Timeout

   \note
   When this function is invoked, the backend needs reboot with the
   requested software and activate the requested software.

   \remark
   For OMCI stack to send response to OLT before ONU is rebooted, the backend
   should record an indication that OMCI stack requested the activation of
   software and then return OMCI_API_SUCCESS if software activation can be
   executed, without actually initiating reboot and activation.
   After wait time for reboot is passed since omci_api_sw_image_activate is
   executed, the backend reboots and activates the requested software.
   The wait time is defined by reboot_timeout timeout.
*/
enum omci_api_return omci_api_sw_image_activate(struct omci_api_ctx *ctx,
						unsigned int sw_image_id,
						uint32_t reboot_timeout);

/** This function is used by OMCI to inform the backend about selected software
   image to be the default image to be loaded and executed by the boot code
   upon start-up

   \param[in] ctx                 OMCI API context pointer
   \param[in] sw_image_id         SW Image Instance ID
   \param[in] commit_complete_cb  SW Image Commit Complete Callback

   \note
   When this function is invoked the backend needs to set the commit flag on
   the downloaded software.
*/
enum omci_api_return
omci_api_sw_image_commit(struct omci_api_ctx *ctx,
			 unsigned int sw_image_id,
			 omci_api_sw_image_commit_cb_t *commit_complete_cb);

/** Check if given ONU SW image is active

   \param[in]  ctx         OMCI API context pointer
   \param[in]  sw_image_id Software image id (0 or 1)
   \param[out] is_active   Returns the following values:
                           - true image is active;
                           - false image is not active
*/
enum omci_api_return omci_api_sw_image_is_active(struct omci_api_ctx *ctx,
						 unsigned int sw_image_id,
						 bool *is_active);

/** Check if given ONU SW image is committed

   \param[in]  ctx          OMCI API context pointer
   \param[in]  sw_image_id  Software image id (0 or 1)
   \param[out] is_committed Returns the following values:
                            - true image is committed;
                            - false image is not committed
*/
enum omci_api_return omci_api_sw_image_is_committed(struct omci_api_ctx *ctx,
						    unsigned int sw_image_id,
						    bool *is_committed);

/** Check if ONU SW image is valid

   \param[in]  ctx         OMCI API context pointer
   \param[in]  sw_image_id Software image id (0 or 1)
   \param[out] is_valid    Returns the following values:
                           - true image is valid;
                           - false image is invalid
*/
enum omci_api_return omci_api_sw_image_is_valid(struct omci_api_ctx *ctx,
						unsigned int sw_image_id,
						bool *is_valid);

/** Retrieve ONU software image version

   \param[in]  ctx         OMCI API context pointer
   \param[in]  sw_image_id Software image id (0 or 1)
   \param[out] p_version   Returns ONU software image version
*/
enum omci_api_return
omci_api_sw_image_version_get(struct omci_api_ctx *ctx,
			      unsigned int sw_image_id,
			      char p_version[OMCI_API_SWIMAGE_VERSION_LEN]);

/** @} */

/** @} */

__END_DECLS

#endif
