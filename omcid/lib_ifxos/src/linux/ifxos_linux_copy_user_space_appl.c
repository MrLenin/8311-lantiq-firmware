/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#if defined(LINUX) && !defined(__KERNEL__)


/** \file
   This file contains the IFXOS Layer implementation for LINUX User Space 
   Data exchange between driver and application.

\Remark
   The intention of this layer is to allow a application / driver simulation
   within the LINUX user space
   The simulation is base on the IFXOS DevIo implementation.

*/

#ifdef IFXOS_LOCAL_CHECK
#  undef  IFXOS_LOCAL_CHECK
#  define IFXOS_LOCAL_CHECK               1
#endif

/* ============================================================================
   IFX LINUX User Space adaptation - Global Includes 
   ========================================================================= */
#include <string.h>

#include "ifx_types.h"
#include "ifxos_rt_if_check.h"
#include "ifxos_copy_user_space.h"

/* ============================================================================
   IFX LINUX User Space adaptation - copy between user and driver space
   ========================================================================= */

/** \addtogroup IFXOS_DRV_CPY_USER_SPACE_LINUX_APPL
@{ */

/**
   Linux Appl - Copy a block FORM USER space (application) to driver space (kernel).

\par Implementation
   Copy data from user to driver space. This function is required for 
   compatibility agains the LINUX concept and als to increase the stability with
   the split between user and driver code.
   A simple memcpy is used.

\param
   pTo         Points to the source (in user space).
\param
   pFrom       Points to the destination (in driver space).
\param
   size_byte   Block size to copy [byte].

\return
   IFX_NULL if an error occured, else pTo

\remark
   This function is required for the LINUX adaptation where a clear split 
   between user code (application level) and driver code (kernel level, 
   privileged code) exists.
*/
IFX_void_t *IFXOS_CpyFromUser(
                     IFX_void_t        *pTo, 
                     const IFX_void_t  *pFrom, 
                     IFX_uint32_t      size_byte)
{
   IFXOS_RETURN_IF_POINTER_NULL(pTo, IFX_NULL);
   IFXOS_RETURN_IF_POINTER_NULL(pFrom, IFX_NULL);
   IFXOS_RETURN_IF_ARG_LE_ZERO(size_byte, IFX_NULL);

   return ((IFX_void_t *)memcpy((void *)pTo, (const void *)pFrom, size_byte));
}

/**
   Linux Appl - Copy a block form driver space (kernel) TO USER space (application).

\par Implementation
   Copy data from driver to user space. This function is required for 
   compatibility agains the LINUX concept and als to increase the stability with
   the split between user and driver code.
   A simple memcpy is used.

\param
   pTo         Points to the source (in driver space)
\param
   pFrom       Points to the destination (in user space)
\param
   size_byte   Block size to copy [byte]

\return
   IFX_NULL if an error occured, else pTo

\remark
   This function is required for the LINUX adaptation where a clear split 
   between user code (application level) and driver code (kernel level, 
   privileged code) exists.
*/
IFX_void_t *IFXOS_CpyToUser(
                     IFX_void_t        *pTo, 
                     const IFX_void_t  *pFrom, 
                     IFX_uint32_t      size_byte)
{
   IFXOS_RETURN_IF_POINTER_NULL(pTo, IFX_NULL);
   IFXOS_RETURN_IF_POINTER_NULL(pFrom, IFX_NULL);
   IFXOS_RETURN_IF_ARG_LE_ZERO(size_byte, IFX_NULL);

   return ((IFX_void_t *)memcpy((void *)pTo, (const void *)pFrom, size_byte));
}

/** @} */

#endif      /* #if defined(LINUX) && !defined(__KERNEL__) */
