/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_std_defs_h
#define _omci_api_std_defs_h

#if !defined(__STDC_VERSION__) || (__STDC_VERSION__ < 199901L) \
   || defined(__cplusplus)

typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned uint32_t;
typedef unsigned long long int uint64_t;

#  if !defined(SWIG) && !defined(__cplusplus)
typedef unsigned char bool;

#     ifndef true
#        define true 1
#     endif
#     ifndef false
#        define false 0
#     endif
#  endif
#else
#     include <stdint.h>
#     include <stdbool.h>
#endif

#endif
