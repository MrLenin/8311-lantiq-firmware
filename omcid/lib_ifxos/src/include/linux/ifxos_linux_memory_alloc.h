#ifndef _IFXOS_LINUX_MEM_ALLOC_H
#define _IFXOS_LINUX_MEM_ALLOC_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef LINUX

/** \file
   This file contains LINUX definitions for Memory handling.
*/

/** \defgroup IFXOS_MEMORY_LINUX Memory Handling (Linux)

   This Group contains the LINUX memory allocation and mapping definitions and  
   function. 

   Here we have to differ between:\n
   - memory handling on user space (application code).
   - memory handling on kernel space (driver code).

\par  Kernel Space
   There are several special memory handling functions which are only available
   in Kernel Space:
   - Allocation of an continious memory block.
   - Physical to virtual address mapping.
   - Data exchange between user and kernel space (copy from/to user).

\ingroup IFXOS_LAYER_LINUX
*/

/** \defgroup IFXOS_MEM_ALLOC_LINUX_APPL Memory Allocation (Linux User Space).

   This Group contains the LINUX Memory Allocation definitions.

\par Implementation - Memory allocation
   The standard memory allocation "malloc" and "free" is used.

\ingroup IFXOS_MEMORY_LINUX
*/

/** \defgroup IFXOS_MEM_ALLOC_LINUX_DRV Memory Allocation (Linux Kernel).

   This Group contains the LINUX Kernel Memory Allocation definitions.

   Within the kernel we differ between kmalloc and vmalloc.
   The important difference between vmalloc and kmalloc is that kmalloc 
   returns a continious memory space (important for HW interfaces).

\par Implementation - Standard memory allocation
   For standard memory allocation the virual memory alloc function is used
   see "vmalloc"

\par Implementation - Block memory allocation
   For block memory allocation the kernel memory alloc function is used
   see "kmalloc"

\ingroup IFXOS_MEMORY_LINUX
*/

/** \defgroup IFXOS_DRV_CPY_USER_SPACE_LINUX Data Exchange, Driver and User Space (Linux Kernel).

   This Group contains the LINUX Kernel definitions for data exchange between 
   driver and application.

\par Implementation
   For Data Exchange the corresponding LINUX Kernel functions are used.

   For data exchange the LINUX Kernel "copy_from_user" and "copy_to_user" functions
   are used.
   For detail, please have a look the to LINUX Implementation Doc.

\ingroup IFXOS_MEMORY_LINUX
*/

/** \defgroup IFXOS_DRV_CPY_USER_SPACE_LINUX_APPL Data Exchange, Driver and User Space.

   This Group contains the LINUX function definitions for data exchange between 
   driver and application.

\par Implementation
   For Data Exchange simple memcpy functions are used.

   The intention of this layer is to allow a application / driver simulation
   within the user space under LINUX.
   Therefore such a simulation is base on the IFXOS DevIo implementation.

\ingroup IFXOS_MEMORY_LINUX
*/

/** \defgroup IIFXOS_DRV_MEMORY_MAP_LINUX Physical to Virtual Address Mapping (Linux Kernel).

   This Group contains the LINUX Kernel definitions for Physical and 
   Virtual Address Mapping.

\par Implementation
   For Physical to Virtual Address Mapping the corresponding LINUX Kernel functions 
   are used.
   For detail, please have a look the to LINUX Implementation Doc.

\ingroup IFXOS_MEMORY_LINUX
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX LINUX adaptation - Includes
   ========================================================================= */
#include "ifx_types.h"

#ifdef __KERNEL__
#include <linux/slab.h>
#include <asm/io.h>
#else

#endif

/* ============================================================================
   IFX LINUX adaptation - supported features
   ========================================================================= */
#ifdef __KERNEL__

   /** IFX LINUX adaptation - Kernel support "mem block alloc" */
#  ifndef IFXOS_HAVE_BLOCK_ALLOC
#     define IFXOS_HAVE_BLOCK_ALLOC                   1
#  endif

   /** IFX LINUX adaptation - Kernel support "mem space alloc" */
#  ifndef IFXOS_HAVE_MEM_ALLOC
#     define IFXOS_HAVE_MEM_ALLOC                     1
#  endif

#else

   /** IFX LINUX adaptation - User support "mem block alloc" */
#  ifndef IFXOS_HAVE_BLOCK_ALLOC
#     define IFXOS_HAVE_BLOCK_ALLOC                   1
#  endif

   /** IFX LINUX adaptation - User support "mem space alloc" */
#  ifndef IFXOS_HAVE_MEM_ALLOC
#     define IFXOS_HAVE_MEM_ALLOC                     1
#  endif

#endif

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef LINUX */
#endif      /* #ifndef _IFXOS_LINUX_MEM_ALLOC_H */


