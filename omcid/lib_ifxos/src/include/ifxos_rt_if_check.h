#ifndef _IFXOS_ARGUMENT_CHECK_H
#define _IFXOS_ARGUMENT_CHECK_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   This file contains macros to check and verify the arguments 
   of the IFX OS functions.
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX OS adaptation - Includes
   ========================================================================= */
#include "ifx_types.h"

/* ============================================================================
   IFX OS adaptation - Check macros
   ========================================================================= */

#if defined(IFXOS_INTERFACE_CHECK) && (IFXOS_INTERFACE_CHECK == 1)
/**
   Check the given pointer - return given ret-val if NULL.
*/
#  define IFXOS_RETURN_IF_POINTER_NULL(p_argument, ret_value) \
         do { \
            if (p_argument == IFX_NULL) \
            { \
               return (ret_value); \
            } \
         } while (0)

/**
   Check the given pointer - return given ret-val if NOT NULL.
*/
#  define IFXOS_RETURN_IF_POINTER_NOT_NULL(p_argument, ret_value) \
         do { \
            if (p_argument != IFX_NULL) \
            { \
               return (ret_value); \
            } \
         } while (0)

/**
   Check the given pointer - return void if NULL.
*/
#  define IFXOS_RETURN_VOID_IF_POINTER_NULL(p_argument, ret_value) \
         do { \
            if (p_argument == IFX_NULL) \
            { \
               return ; \
            } \
         } while (0)


/**
   Check the given pointer - return void if NOT NULL.
*/
#  define IFXOS_RETURN_VOID_IF_POINTER_NOT_NULL(p_argument, ret_value) \
         do { \
            if (p_argument != IFX_NULL) \
            { \
               return ; \
            } \
         } while (0)

#else
#  define IFXOS_RETURN_IF_POINTER_NULL(p_argument, ret_value)
#  define IFXOS_RETURN_IF_POINTER_NOT_NULL(p_argument, ret_value)
#  define IFXOS_RETURN_VOID_IF_POINTER_NULL(p_argument, ret_value)
#  define IFXOS_RETURN_VOID_IF_POINTER_NOT_NULL(p_argument, ret_value)
#endif


#if defined(IFXOS_INTERFACE_CHECK) && (IFXOS_INTERFACE_CHECK == 1)
/**
   Check the given device file descriptor - return given ret-val if invalid.
*/
#  define IFXOS_RETURN_IF_DEVFD_INVALID(dev_fd, ret_value) \
         do { \
            if (dev_fd == -1) \
            { \
               return (ret_value); \
            } \
         } while (0)


/**
   Check the given device file descriptor - return void if invalid.
*/
#  define IFXOS_RETURN_VOID_IF_DEVFD_INVALID(dev_fd, ret_value) \
         do { \
            if (dev_fd == -1) \
            { \
               return; \
            } \
         } while (0)

#else
#  define IFXOS_RETURN_IF_DEVFD_INVALID(dev_fd, ret_value)
#  define IFXOS_RETURN_VOID_IF_DEVFD_INVALID(dev_fd, ret_value)
#endif

#if defined(IFXOS_INTERFACE_CHECK) && (IFXOS_INTERFACE_CHECK == 1)
 /**
   Check the given numeric argument - return given ret-val if <= 0.
*/
#  define IFXOS_RETURN_IF_ARG_LE_ZERO(n_arg, ret_value) \
         do { \
            if (n_arg <= 0) \
            { \
               return (ret_value); \
            } \
         } while (0)

 /**
   Check the given numeric argument - return void if < 0.
*/
#  define IFXOS_RETURN_VOID_IF_ARG_LE_ZERO(n_arg, ret_value) \
         do { \
            if (n_arg <= 0) \
            { \
               return; \
            } \
         } while (0)
#else
#  define IFXOS_RETURN_IF_ARG_LE_ZERO(n_arg, ret_value)
#  define IFXOS_RETURN_VOID_IF_ARG_LE_ZERO(n_arg, ret_value)
#endif

#if defined(IFXOS_INTERFACE_CHECK) && (IFXOS_INTERFACE_CHECK == 1)
/**
   Check the given numeric argument - return IFX_ERROR if <= 0.
*/
#  define IFXOS_RETURN_IF_OBJECT_IS_VALID(p_object, ret_value) \
         do { \
            if ((p_object)->bValid == IFX_TRUE) \
            { \
               return (ret_value); \
            } \
         } while (0)

/**
   Check the given numeric argument - return IFX_ERROR if < 0.
*/
#  define IFXOS_RETURN_IF_OBJECT_IS_INVALID(p_object, ret_value) \
         do { \
            if ((p_object)->bValid == IFX_FALSE) \
            { \
               return (ret_value); \
            } \
         } while (0)
#else
#  define IFXOS_RETURN_IF_OBJECT_IS_VALID(p_object, ret_value)
#  define IFXOS_RETURN_IF_OBJECT_IS_INVALID(p_object, ret_value)
#endif

#ifdef __cplusplus
}
#endif

#endif      /* #ifndef _IFXOS_ARGUMENT_CHECK_H */


