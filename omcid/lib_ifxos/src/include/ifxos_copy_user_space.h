#ifndef _IFXOS_DRV_CPY_USER_SPACE_H
#define _IFXOS_DRV_CPY_USER_SPACE_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   This file contains definitions for data exchange between driver and 
   user (application) space.
*/

/** \defgroup IFXOS_IF_DRV_CPY_USER_SPACE Data Exchange (Driver and User Space)

   The requirement of this kind of functions have been come up with the Linux OS.
   Here there is a clear split between the user space (application) and the 
   Kernel space (driver). Data exchange is only possible via a corresponding 
   interface and the code for this exchange is located on driver side.
   This is an security issue to ensure that only privileged code will be executed
   within the Kernel space.

   Based on a Linux implementation this border will be also visible wihtin a 
   driver structure and makes sence to keep it also in other OS adaptations.

\note
   This functions are only used within the driver code.

\ingroup IFXOS_IF_MEMORY
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX OS adaptation - Global Includes
   ========================================================================= */
#include "ifx_types.h"

/* ============================================================================
   IFX OS adaptation - copy between user and driver space.
   ========================================================================= */
/** \addtogroup IFXOS_IF_DRV_CPY_USER_SPACE
@{ */

/**
   Copy a block FORM USER space (application) to driver space (kernel).

\param
   pTo         Points to the source (in user space).
\param
   pFrom       Points to the destination (in driver space).
\param
   size_byte   Block size to copy [byte].

\return
   IFX_NULL if an error occured, else pTo

\remark
   This function is required for the Linux adaptation where a clear split 
   between user code (application level) and driver code (kernel level, 
   privileged code) exists.
*/
IFX_void_t *IFXOS_CpyFromUser(
               IFX_void_t        *pTo, 
               const IFX_void_t  *pFrom, 
               IFX_uint32_t      size_byte);

/**
   Copy a block form driver space (kernel) TO USER space (application).

\param
   pTo         Points to the source (in driver space)
\param
   pFrom       Points to the destination (in user space)
\param
   size_byte   Block size to copy [byte]

\return
   IFX_NULL if an error occured, else pTo

\remark
   This function is required for the Linux adaptation where a clear split 
   between user code (application level) and driver code (kernel level, 
   privileged code) exists.
*/
IFX_void_t *IFXOS_CpyToUser(
               IFX_void_t        *pTo, 
               const IFX_void_t  *pFrom, 
               IFX_uint32_t      size_byte);

/** @} */

#ifdef __cplusplus
}
#endif

#endif      /* #ifndef _IFXOS_DRV_CPY_USER_SPACE_H */

