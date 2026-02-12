#ifndef _IFXOS_VXWORKS_MEM_ALLOC_H
#define _IFXOS_VXWORKS_MEM_ALLOC_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef VXWORKS

/** \file
   This file contains VxWorks definitions for Memory handling.
*/

/** \defgroup IFXOS_MEMORY_VXWORKS Memory Handling (VxWorks)

   This Group contains the VxWorks memory allocation and mapping definitions and  
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

\ingroup IFXOS_LAYER_VXWORKS
*/

/** \defgroup IFXOS_MEM_ALLOC_VXWORKS Memory Allocation (VxWorks).

   This Group contains the VxWorks Memory Allocation definitions.

\par Implementation - Memory allocation
   Within VxWorks there is no special handling for allocation a continious 
   memory block. So the standard malloc function is used for all adaptations.

\ingroup IFXOS_MEMORY_VXWORKS
*/


/** \defgroup IFXOS_CPY_USER_SPACE_VXWORKS_DRV Data Exchange, Driver and User Space (VxWorks).

   This Group contains the VxWorks definitions for data exchange between 
   driver and application.

\par Implementation
   Under VxWorks no special handling for Data Exchange between driver and user
   space is required. But such a border makes sence we provide the corresponding 
   IFXOS Layer functions for compatibility.

   For data exchange the standard memcpy function is used.

\ingroup IFXOS_MEMORY_VXWORKS
*/

/** \defgroup IFXOS_MEMORY_MAP_VXWORKS_DRV Physical to Virtual Address Mapping (VxWorks).

   This Group contains the VxWorks definitions for Physical to 
   Virtual Address Mapping.

\par Implementation
   Under VxWorks no special handling for Physical to Virtual Address Mapping is 
   required (no Virtual Memory Management).
   To keep the compatibility wihtin the driver code we provide the corresponding 
   IFXOS Layer functions.
   For the mapping the phsyical address is simply assigned.

\ingroup IFXOS_MEMORY_VXWORKS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX VxWorks adaptation - Includes
   ========================================================================= */

/* ============================================================================
   IFX VxWorks adaptation - supported features
   ========================================================================= */

/** IFX VxWorks adaptation - support "mem alloc" */
#ifndef IFXOS_HAVE_BLOCK_ALLOC
#  define IFXOS_HAVE_BLOCK_ALLOC                   1
#endif

/** IFX VxWorks adaptation - support "virtual mem alloc" */
#ifndef IFXOS_HAVE_MEM_ALLOC
#  define IFXOS_HAVE_MEM_ALLOC                     1
#endif

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef VXWORKS */
#endif      /* #ifndef _IFXOS_VXWORKS_MEM_ALLOC_H */


