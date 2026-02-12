#ifndef _IFXOS_WIN32_MEM_ALLOC_H
#define _IFXOS_WIN32_MEM_ALLOC_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef WIN32

/** \file
   This file contains VxWorks definitions for Memory Allocation.
*/

/** \defgroup IFXOS_MEMORY_WIN32 Memory Handling (Win32)

   This Group contains the Win32 memory allocation and mapping definitions and  
   function. 

   Here we have to differ between:\n
   - memory handling on application space.
   - memory handling on driver space.

\par Driver Space
   There are several special memory handling functions which makes only sence
   in driver space.
   - Allocation of an continious memory block (HW interfaces).
   - Physical to virtual address mapping.
   - Data exchange between user and driver space (copy from/to user).

\note
   This split comes up with the LINUX OS. Under LINUX the user and Kernel space are 
   independant. 
   Further it makes sence to handle driver related fucntions seperatly.

\ingroup IFXOS_LAYER_WIN32
*/

/** \defgroup IFXOS_MEM_ALLOC_WIN32 Memory Allocation (Win32).

   This Group contains the VxWorks Memory Allocation definitions.

\par Implementation - Memory allocation
   Within Win32 there is no special handling for allocation a continious 
   memory block. So the standard malloc function is used for all adaptations.

\ingroup IFXOS_MEMORY_WIN32
*/

/** \defgroup IFXOS_CPY_USER_SPACE_WIN32_DRV Data Exchange, Driver and User Space (Win32).

   This Group contains the VxWorks definitions for data exchange between 
   driver and application.

\par Implementation
   Under VxWorks no special handling for Data Exchange between driver and user
   space is required. But such a border makes sence we provide the corresponding 
   IFXOS Layer functions for compatibility.

   For data exchange the standard memcpy function is used.

\ingroup IFXOS_MEMORY_WIN32
*/

/** \defgroup IFXOS_MEMORY_MAP_WIN32_DRV Physical to Virtual Address Mapping (Win32).

   This Group contains the VxWorks definitions for Physical to 
   Virtual Address Mapping.

\par Implementation
   Under Win32 no special handling for Physical to Virtual Address Mapping is 
   required (no Virtual Memory Management).
   To keep the compatibility wihtin the driver code we provide the corresponding 
   IFXOS Layer functions.
   For the mapping the phsyical address is simply assigned.

\ingroup IFXOS_MEMORY_WIN32
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX Win32 adaptation - Includes
   ========================================================================= */

/* ============================================================================
   IFX Win32 adaptation - supported features
   ========================================================================= */

/** IFX Win32 adaptation - support "mem alloc" */
#ifndef IFXOS_HAVE_BLOCK_ALLOC
#  define IFXOS_HAVE_BLOCK_ALLOC                   1
#endif

/** IFX Win32 adaptation - support "virtual mem alloc" */
#ifndef IFXOS_HAVE_MEM_ALLOC
#  define IFXOS_HAVE_MEM_ALLOC                     1
#endif

/* ============================================================================
   IFX Win32 adaptation - types
   ========================================================================= */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef WIN32 */
#endif      /* #ifndef _IFXOS_WIN32_MEM_ALLOC_H */

