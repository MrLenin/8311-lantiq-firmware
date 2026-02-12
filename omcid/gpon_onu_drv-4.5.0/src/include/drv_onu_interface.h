/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_onu_interface.h
   This file holds the definitions needed for file I/O access.
*/
#ifndef _drv_onu_interface_h
#define _drv_onu_interface_h

#include "drv_onu_std_defs.h"

/** OMCI TCIX */
#define OMCI_TCIX 31

#ifndef _MKSTR_1
#define _MKSTR_1(x)    #x
#define _MKSTR(x)      _MKSTR_1(x)
#endif

/** \defgroup ONU_MAPI_REFERENCE ONU Driver Reference
    This chapter summarizes the function calls, separately for each of the
    hardware units that are involved.
   @{
*/

/** \defgroup ONU_COMMON Common Driver Interface

    This chapter describes the common driver interface.
   @{
*/

/** device name */
#define ONU_NAME               "onu"
#define DRV_IO_GPON_ONU        "/dev/onu"

/** driver version, major number */
#define ONU_VER_MAJOR            4
/** driver version, minor number */
#define ONU_VER_MINOR            4 
/** driver version, build number */
#define ONU_VER_STEP             0
/** driver version, package type */
#define ONU_VER_TYPE             0
/** driver version as string */
#define onu_ver_str        	_MKSTR(ONU_VER_MAJOR)"." \
				_MKSTR(ONU_VER_MINOR)"." \
				_MKSTR(ONU_VER_STEP)"." \
                                _MKSTR(ONU_VER_TYPE)

#define ONU_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))
#define ONU_VERSION_CODE  \
	((ONU_VER_MAJOR << 16) + (ONU_VER_MINOR << 8) + ONU_VER_STEP)

/** driver version, what string */
#define ONU_COPYRIGHT "(c) Copyright (c) 2011, Lantiq Deutschland GmbH"
#define ONU_WHAT_STR "@(#)FALC(tm) ON Base Driver, Version " onu_ver_str \
		     " "ONU_COPYRIGHT

#ifndef __PACKED__
#  if defined (__GNUC__) || defined (__GNUG__)
   /* GNU C or C++ compiler */
#    define __PACKED__ __attribute__ ((packed))
#  else
   /* Byte alignment adjustment */
#    pragma pack(1)
#    if !defined (_PACKED_)
#      define __PACKED__	/* nothing */
#    endif
#  endif
#  define __PACKED_DEFINED__
#endif

EXTERN_C_BEGIN
#ifdef SWIG
#undef _IO
#define _IO(a,b) ((a)<<8 | (b))
#undef _IOW
#define _IOW(a,b,c) ((a)<<8 | (b))
#undef _IOR
#define _IOR(a,b,c) ((a)<<8 | (b))
#undef _IOWR
#define _IOWR(a,b,c) ((a)<<8 | (b))
#endif
#ifndef SWIG
int onu_init(void);
void onu_exit(void);
#endif

/*! @} */

/*! @} */

EXTERN_C_END
#ifdef __PACKED_DEFINED__
#  if !defined (__GNUC__) && !defined (__GNUG__)
#    pragma pack()
#  endif
#  undef __PACKED_DEFINED__
#  undef __PACKED__
#endif
#endif
