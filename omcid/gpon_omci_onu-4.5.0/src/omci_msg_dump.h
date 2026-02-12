/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_msg_dump_h
#define _omci_msg_dump_h

#ifndef OMCI_DEBUG_DISABLE

#include "omci_msg.h"

/** \addtogroup OMCI_CORE

   @{
*/

/** \defgroup OMCI_MSG_DUMP Optical Network Unit - OMCI Message Dump

   @{
*/

/** Dump OMCI message

   \param[in] context OMCI context pointer
   \param[in] prefix  Output message prefix (RX or TX)
   \param[in] msg     OMCI message
   \param[in] number  OMCI message counter
*/
void msg_dump(struct omci_context *context,
	      const char *prefix,
	      const union omci_msg *msg,
	      unsigned int number);

/** @} */

/** @} */

#endif

#endif
