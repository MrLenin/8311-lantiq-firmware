/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_sw_image_falcon_h
#define _omci_api_me_sw_image_falcon_h

#include "me/omci_api_sw_image.h"

#include "omci_api.h"

__BEGIN_DECLS

#ifdef INCLUDE_SW_IMAGE_SUPPORT

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_SW_IMAGE_FALCON Software image (FALC ON specific)

   This function is used to update the ONU's software image.
   @{
*/

/** This function is called when the download of software image has been
   started; it should make given image invalid

   \param[in] sw_image_id Software image instance
*/
enum omci_api_return omci_api_falcon_sw_image_download_start(unsigned int
								sw_image_id);

/** This function is called when the download of software image has been
   completed; it should check if the image is correct and return image
   version

   \param[in]  sw_image_id       Software image instance
   \param[in]  sw_image_filepath Downloaded software image file path
   \param[out] sw_image_version  Returns downloaded software image version
*/
enum omci_api_return
omci_api_falcon_sw_image_download_end(unsigned int sw_image_id,
				      const char *sw_image_filepath,
				      char
				      sw_image_version[OMCI_API_UIMAGE_NAME_LEN]);

/** This function should store given image (via filename) to the non-volatile
   memory, store image version and make image valid

   \param[in] sw_image Software image descriptor
*/
enum omci_api_return omci_api_falcon_sw_image_store(struct omci_api_sw_image
						    *sw_image);

/** This function should activate given software image

   \param[in]  ctx        OMCI API context pointer
   \param[in] sw_image_id Software image instance
*/
enum omci_api_return omci_api_falcon_sw_image_activate(struct omci_api_ctx *ctx,
						       unsigned int
						       sw_image_id);

/** This function should commit given software image

   \param[in] sw_image_id Software image instance
*/
enum omci_api_return omci_api_falcon_sw_image_commit(unsigned int sw_image_id);

/** This function indicates whether software image is active or not

   \param[in]  sw_image_id Software image instance
   \param[out] is_active  Returns the following values:
                          - true software image is active
                          - false software image is not active
*/
enum omci_api_return omci_api_falcon_sw_image_is_active(unsigned int
							sw_image_id,
							bool *is_active);

/** This function indicates whether software image is committed or not

   \param[in]  sw_image_id   Software image instance
   \param[out] is_committed Returns the following values:
                            - true software image is committed
                            - false software image is not committed
*/
enum omci_api_return omci_api_falcon_sw_image_is_committed(unsigned int
							   sw_image_id,
							   bool *is_committed);

/** This function indicates whether software image is valid or not

   \param[in]  sw_image_id Software image instance
   \param[out] is_valid   Returns the following values:
                          - true software image is valid
                          - false software image is not valid
*/
enum omci_api_return omci_api_falcon_sw_image_is_valid(unsigned int sw_image_id,
						       bool *is_valid);

/** This function returns software image version

   \param[in] sw_image_id Software image instance
   \param[in] p_version   Returns software image version
*/
enum omci_api_return
omci_api_falcon_sw_image_version_get(unsigned int sw_image_id,
				     char p_version[OMCI_API_SWIMAGE_VERSION_LEN]);

/** @} */

/** @} */

#endif

__END_DECLS

#endif
