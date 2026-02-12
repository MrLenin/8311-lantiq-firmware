#ifndef _IFXOS_RTEMS_MEM_ALLOC_H
#define _IFXOS_RTEMS_MEM_ALLOC_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef RTEMS

/** \file
   This file contains Generic OS definitions for Memory handling.
*/

/** \defgroup IFXOS_MEMORY_RTEMS Memory Handling (Generic OS)

   This Group contains the Generic OS memory allocation and mapping definitions and
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

\ingroup IFXOS_LAYER_RTEMS
*/

/** \defgroup IFXOS_MEM_ALLOC_RTEMS Memory Allocation (Generic OS).

   This Group contains the Generic OS Memory Allocation definitions.

\par Implementation - Memory allocation
   Within Generic OS there is no special handling for allocation a continious
   memory block. So the standard malloc function is used for all adaptations.

\ingroup IFXOS_MEMORY_RTEMS
*/


/** \defgroup IFXOS_CPY_USER_SPACE_RTEMS_DRV Data Exchange, Driver and User Space (Generic OS).

   This Group contains the Generic OS definitions for data exchange between
   driver and application.

\par Implementation
   Under Generic OS no special handling for Data Exchange between driver and user
   space is required. But such a border makes sence we provide the corresponding
   IFXOS Layer functions for compatibility.

   For data exchange the standard memcpy function is used.

\ingroup IFXOS_MEMORY_RTEMS
*/

/** \defgroup IFXOS_MEMORY_MAP_RTEMS_DRV Physical to Virtual Address Mapping (Generic OS).

   This Group contains the Generic OS definitions for Physical to
   Virtual Address Mapping.

\par Implementation
   Under Generic OS no special handling for Physical to Virtual Address Mapping is
   required (no Virtual Memory Management).
   To keep the compatibility wihtin the driver code we provide the corresponding
   IFXOS Layer functions.
   For the mapping the phsyical address is simply assigned.

\ingroup IFXOS_MEMORY_RTEMS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   RTEMS adaptation - Includes
   ========================================================================= */

/* ============================================================================
   RTEMS adaptation - supported features
   ========================================================================= */

/** RTEMS adaptation - support "mem alloc" */
#define IFXOS_HAVE_BLOCK_ALLOC                   1
/** RTEMS adaptation - support "virtual mem alloc" */
#define IFXOS_HAVE_MEM_ALLOC                     1

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef RTEMS */
#endif      /* #ifndef _IFXOS_RTEMS_MEM_ALLOC_H */


