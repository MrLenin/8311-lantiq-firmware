#ifndef _IFXOS_MEM_ALLOC_H
#define _IFXOS_MEM_ALLOC_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   This file contains definitions for the memory handling within the driver and 
   user (application) space.
*/

/** \defgroup IFXOS_IF_MEMORY Memory Handling 

   This Group contains the memory allocation and mapping definitions and  
   function. 

   Beneath the standard memory allocation and free functions this group also 
   introduce additional Linux specific functions for memory handling.
   This comes up with the clear split of user space (application) and kernel space 
   (driver, privileged code) within the Linux system. So this border is also visible 
   within the driver structure.
   Further the Linux system use a virtual memory management which is also 
   reflected within driver code.

   For compatibility and also for force a clear driver application structure
   the OS provides the corresponding functions for this features.
   So especially under Linux we have to differ between the user space (application)
   and kernel space (driver).

\ingroup IFXOS_INTERFACE
*/

/** \defgroup IFXOS_IF_MEM_ALLOC Memory Allocation.

   This functions provides a interface for allocate and free memory from the 
   underlaying OS.
   Here it can be necessary to get an continious block (HW related) or organized 
   and managed by the OS.

   Dependent of the underlaying OS the implementation differs also if we are in 
   user or driver space (see LINUX).

\ingroup IFXOS_IF_MEMORY
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX OS adaptation - Global Includes
   ========================================================================= */
#if ( !defined(IFXOS_FLAT_HIRACHY) || (IFXOS_FLAT_HIRACHY == 0) )
#  if defined(LINUX)
#     include "linux/ifxos_linux_memory_alloc.h"
#  elif defined(VXWORKS)
#     include "vxworks/ifxos_vxworks_memory_alloc.h"
#  elif defined(ECOS)
#     include "ecos/ifxos_ecos_memory_alloc.h"
#  elif defined(NUCLEUS_PLUS)
#     include "nucleus/ifxos_nucleus_memory_alloc.h"
#  elif defined(WIN32)
#     include "win32/ifxos_win32_memory_alloc.h"
#  elif defined(RTEMS)
#     include "rtems/ifxos_rtems_memory_alloc.h"
#  elif defined(SUN_OS)
#     include "sun_os/ifxos_sun_os_memory_alloc.h"
#  elif defined(GENERIC_OS)
#     include "generic_os/ifxos_generic_os_memory_alloc.h"
#  elif defined(XAPI)
#     include "xapi/ifxos_xapi_memory_alloc.h"
#  endif
#else
#  if defined(LINUX)
#     include "ifxos_linux_memory_alloc.h"
#  elif defined(VXWORKS)
#     include "ifxos_vxworks_memory_alloc.h"
#  elif defined(ECOS)
#     include "ifxos_ecos_memory_alloc.h"
#  elif defined(NUCLEUS_PLUS)
#     include "ifxos_nucleus_memory_alloc.h"
#  elif defined(WIN32)
#     include "ifxos_win32_memory_alloc.h"
#  elif defined(RTEMS)
#     include "ifxos_rtems_memory_alloc.h"
#  elif defined(SUN_OS)
#     include "ifxos_sun_os_memory_alloc.h"
#  elif defined(GENERIC_OS)
#     include "ifxos_generic_os_memory_alloc.h"
#  elif defined(XAPI)
#     include "ifxos_xapi_memory_alloc.h"
#  else
#     error "Memory Allocation Adaptation - Please define your OS"
#  endif
#endif

#include "ifx_types.h"

/* ============================================================================
   IFX OS adaptation - memory allocation
   ========================================================================= */

/** \addtogroup IFXOS_IF_MEM_ALLOC
@{ */

#if ( defined(IFXOS_HAVE_BLOCK_ALLOC) && (IFXOS_HAVE_BLOCK_ALLOC == 1) )

/** Wrap the free call - reset also the given pointer */
#define IFXOS_BLOCK_FREE(ptr)    if (ptr != IFX_NULL) {IFXOS_BlockFree((IFX_void_t*)ptr); ptr = IFX_NULL;}

/**
   Allocate a continious memory block of the given size [byte]

\param
   memSize_byte   Size of the requested memory block [byte]

\return
   IFX_NULL in case of error, else
   pointer to the allocated memory block.

*/
IFX_void_t *IFXOS_BlockAlloc(IFX_size_t memSize_byte);

/**
   Free the given memory block.

\param
   pMemBlock   Points to the memory block to free.

\return
   NONE
*/
IFX_void_t IFXOS_BlockFree(
               IFX_void_t *pMemBlock);

#endif      /* #if ( defined(IFXOS_HAVE_BLOCK_ALLOC) && (IFXOS_HAVE_BLOCK_ALLOC == 1) ) */


#if ( defined(IFXOS_HAVE_MEM_ALLOC) && (IFXOS_HAVE_MEM_ALLOC == 1) )
/**
   Allocate Memory Space from the OS

\param
   memSize_byte   Size of the requested memory block [byte]

\return
   IFX_NULL in case of error, else
   pointer to the allocated memory block.
*/
IFX_void_t *IFXOS_MemAlloc(
               IFX_size_t memSize_byte);

/**
   Free Memory Space

\param
   pMemBlock   Points to the memory block to free.

\return
   NONE
*/
IFX_void_t IFXOS_MemFree(
               IFX_void_t *pMemBlock);

#endif      /* #if ( defined(IFXOS_HAVE_MEM_ALLOC) && (IFXOS_HAVE_MEM_ALLOC == 1) ) */

/** @} */

#ifdef __cplusplus
}
#endif

#endif      /* #ifndef _IFXOS_MEM_ALLOC_H */

