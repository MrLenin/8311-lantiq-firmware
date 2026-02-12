#ifndef _IFXOS_SUN_OS_MEM_ALLOC_H
#define _IFXOS_SUN_OS_MEM_ALLOC_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#if defined(SUN_OS)

/** \file
   This file contains Sun OS definitions for Memory handling.
*/

/** \defgroup IFXOS_MEMORY_SUN_OS Memory Handling (Sun OS)

   This Group contains the Sun OS memory allocation and mapping definitions and  
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

\ingroup IFXOS_LAYER_SUN_OS
*/

/** \defgroup IFXOS_MEM_ALLOC_SUN_OS_APPL Memory Allocation (Sun OS User Space).

   This Group contains the Sun OS Memory Allocation definitions.

\par Implementation - Memory allocation
   The standard memory allocation "malloc" and "free" is used.

\ingroup IFXOS_MEMORY_SUN_OS
*/

/** \defgroup IFXOS_MEM_ALLOC_SUN_OS_DRV Memory Allocation (Sun OS Kernel).

   This Group contains the Sun OS Kernel Memory Allocation definitions.

   Within the kernel we differ between kmalloc and vmalloc.
   The important difference between vmalloc and kmalloc is that kmalloc 
   returns a continious memory space (important for HW interfaces).

\par Implementation - Standard memory allocation
   For standard memory allocation the virual memory alloc function is used
   see "vmalloc"

\par Implementation - Block memory allocation
   For block memory allocation the kernel memory alloc function is used
   see "kmalloc"

\ingroup IFXOS_MEMORY_SUN_OS
*/

/** \defgroup IFXOS_DRV_CPY_USER_SPACE_SUN_OS Data Exchange, Driver and User Space (Sun OS Kernel).

   This Group contains the Sun OS Kernel definitions for data exchange between 
   driver and application.

\par Implementation
   For Data Exchange the corresponding Sun OS Kernel functions are used.

   For data exchange the Sun OS Kernel "copy_from_user" and "copy_to_user" functions
   are used.
   For detail, please have a look the to Sun OS Implementation Doc.

\ingroup IFXOS_MEMORY_SUN_OS
*/

/** \defgroup IFXOS_DRV_CPY_USER_SPACE_SUN_OS_APPL Data Exchange, Driver and User Space.

   This Group contains the Sun OS function definitions for data exchange between 
   driver and application.

\par Implementation
   For Data Exchange simple memcpy functions are used.

   The intention of this layer is to allow a application / driver simulation
   within the user space under Sun OS.
   Therefore such a simulation is base on the IFXOS DevIo implementation.

\ingroup IFXOS_MEMORY_SUN_OS
*/

/** \defgroup IIFXOS_DRV_MEMORY_MAP_SUN_OS Physical to Virtual Address Mapping (Sun OS Kernel).

   This Group contains the Sun OS Kernel definitions for Physical and 
   Virtual Address Mapping.

\par Implementation
   For Physical to Virtual Address Mapping the corresponding Sun OS Kernel functions 
   are used.
   For detail, please have a look the to Sun OS Implementation Doc.

\ingroup IFXOS_MEMORY_SUN_OS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX Sun OS adaptation - Includes
   ========================================================================= */
#include "ifx_types.h"

/* ============================================================================
   IFX Sun OS adaptation - supported features
   ========================================================================= */
#if defined(_KERNEL)

   /** IFX Sun OS adaptation - Kernel support "mem block alloc" */
#  ifndef IFXOS_HAVE_BLOCK_ALLOC
#     define IFXOS_HAVE_BLOCK_ALLOC                   0
#  endif

   /** IFX Sun OS adaptation - Kernel support "mem space alloc" */
#  ifndef IFXOS_HAVE_MEM_ALLOC
#     define IFXOS_HAVE_MEM_ALLOC                     0
#  endif

#else

   /** IFX Sun OS adaptation - User support "mem block alloc" */
#  ifndef IFXOS_HAVE_BLOCK_ALLOC
#     define IFXOS_HAVE_BLOCK_ALLOC                   0
#  endif

   /** IFX Sun OS adaptation - User support "mem space alloc" */
#  ifndef IFXOS_HAVE_MEM_ALLOC
#     define IFXOS_HAVE_MEM_ALLOC                     1
#  endif

#endif

#ifdef __cplusplus
}
#endif
#endif      /* #if defined(SUN_OS) */
#endif      /* #ifndef _IFXOS_SUN_OS_MEM_ALLOC_H */


