/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_me_handlers_h
#define _omci_me_handlers_h

#include "omci_me.h"

/** \addtogroup OMCI_MIB

   @{
*/

/** \defgroup OMCI_ME_HANDLERS Optical Network Unit - Default Handlers

   @{
*/

/** Default "ONU Reboot" action handler

   \param[in]  context OMCI context pointer
   \param[in]  me      Managed Entity pointer
   \param[in]  msg     Received OMCI Message
   \param[out] rsp     Returns response to given OMCI Message

   \note This function passes table attributes
*/
enum omci_error reboot_acion_handle(struct omci_context *context,
				    struct me *me,
				    const union omci_msg *msg,
				    union omci_msg *rsp);

/** Default "Set" action handler

   \param[in]  context OMCI context pointer
   \param[in]  me      Managed Entity pointer
   \param[in]  msg     Received OMCI Message
   \param[out] rsp     Returns response to given OMCI Message

   \note This function passes table attributes
*/
enum omci_error set_action_handle(struct omci_context *context,
				  struct me *me,
				  const union omci_msg *msg,
				  union omci_msg *rsp);

/** Default "Get" action handler

   \param[in]  context OMCI context pointer
   \param[in]  me      Managed Entity pointer
   \param[in]  msg     Received OMCI Message
   \param[out] rsp     Returns response to given OMCI Message
*/
enum omci_error get_action_handle(struct omci_context *context,
				  struct me *me,
				  const union omci_msg *msg,
				  union omci_msg *rsp);

/** Default "Get Next" action handler

   \param[in]  context OMCI context pointer
   \param[in]  me      Managed Entity pointer
   \param[in]  msg     Received OMCI Message
   \param[out] rsp     Returns response to given OMCI Message
*/
enum omci_error get_next_action_handle(struct omci_context *context,
				       struct me *me,
				       const union omci_msg *msg,
				       union omci_msg *rsp);

#ifdef INCLUDE_PM
/** Default "Cet Current Data" action handler

   \param[in]  context OMCI context pointer
   \param[in]  me      Managed Entity pointer
   \param[in]  msg     Received OMCI Message
   \param[out] rsp     Returns response to given OMCI Message
*/
enum omci_error get_current_data_action_handle(struct omci_context *context,
					       struct me *me,
					       const union omci_msg *msg,
					       union omci_msg *rsp);
#endif

/** Default "Create" action handler

   \param[in]  context OMCI context pointer
   \param[in]  me      Managed Entity pointer
   \param[in]  msg     Received OMCI Message
   \param[out] rsp     Returns response to given OMCI Message
*/
enum omci_error create_action_handle(struct omci_context *context,
				     struct me *me,
				     const union omci_msg *msg,
				     union omci_msg *rsp);

/** Default "Delete" action handler

   \param[in]  context OMCI context pointer
   \param[in]  me      Managed Entity pointer
   \param[in]  msg     Received OMCI Message
   \param[out] rsp     Returns response to given OMCI Message
*/
enum omci_error delete_action_handle(struct omci_context *context,
				     struct me *me,
				     const union omci_msg *msg,
				     union omci_msg *rsp);

/** Default Managed Entity validate handler

   Only writable attributes are validated.

   \param[in]  context   OMCI context pointer
   \param[in]  me_class  Managed Entity class pointer
   \param[out] exec_mask Returns mask with invalid attributes (not-null if any)
   \param[in]  data      Data to validate

   \note
      - This handler doesn't check table or string attributes!
      - This handler doesn't check pointer attributes!
*/
enum omci_error default_me_validate(struct omci_context *context,
				    const struct me_class *me_class,
				    uint16_t *exec_mask,
				    const void *data);

/** Default Managed Entity update handler

   Just copies the updated values to the Managed Entity data

   \param[in] context   OMCI context pointer
   \param[in] me        Managed Entity pointer
   \param[in] data      Data to update
   \param[in] attr_mask Attributes to be set mask
*/
enum omci_error default_me_update(struct omci_context *context,
				  struct me *me,
				  void *data,
				  uint16_t attr_mask);

/** Default Managed Entity instance initialize handler

   \param[in] context      OMCI context pointer
   \param[in] me           Managed Entity pointer
   \param[in] init_data    Managed Entity initial data
   \param[in] suppress_avc Suppress AVC for given attributes
*/
enum omci_error default_me_init(struct omci_context *context,
				struct me *me,
				void *init_data,
				uint16_t suppress_avc);

/** Default Managed Entity instance shutdown handler

   \param[in] context OMCI context pointer
   \param[in] me      Managed Entity pointer
*/
enum omci_error default_me_shutdown(struct omci_context *context,
				    struct me *me);

/** @} */

/** @} */

#endif
