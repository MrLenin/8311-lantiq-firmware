/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _drv_optic_devio_h
#define _drv_optic_devio_h

#include "drv_optic_std_defs.h"


EXTERN_C_BEGIN

#if defined(OPTIC_SIMULATION)

#if defined(_IO)
#  undef _IO
#endif

#if defined(_IOW)
#  undef _IOW
#endif

#if defined(_IOR)
#  undef _IOR
#endif

#if defined(_IOWR)
#  undef _IOWR
#endif

#if defined(_IOC_DIR)
# undef _IOC_DIR
#endif

#if defined(_IOC_DIRMASK)
# undef _IOC_DIRMASK
#endif

#if defined(_IOC_DIRSHIFT)
# undef _IOC_DIRSHIFT
#endif

#if defined(_IOC_READ)
# undef _IOC_READ
#endif

#if defined(_IOC_WRITE)
# undef _IOC_WRITE
#endif

#if defined(_IOC_SIZE)
# undef _IOC_SIZE
#endif

#if defined(_IOC_TYPE)
# undef _IOC_TYPE
#endif

#if defined(_IOC_NR)
# undef _IOC_NR
#endif

#define _IO             _IFXOS_IO
#define _IOW            _IFXOS_IOW
#define _IOR            _IFXOS_IOR
#define _IOWR           _IFXOS_IOWR
#define _IOC_DIR        _IFXOS_IOC_DIR
#define _IOC_DIRMASK    _IFXOS_IOC_DIRMASK
#define _IOC_DIRSHIFT   _IFXOS_IOC_DIRSHIFT
#define _IOC_READ       _IFXOS_IOC_READ
#define _IOC_WRITE      _IFXOS_IOC_WRITE
#define _IOC_SIZE       _IFXOS_IOC_SIZE
#define _IOC_TYPE       _IFXOS_IOC_TYPE
#define _IOC_NR         _IFXOS_IOC_NR

#define _IFXOS_IOC_NRBITS        8
#define _IFXOS_IOC_TYPEBITS      8
#define _IFXOS_IOC_SIZEBITS      13
#define _IFXOS_IOC_DIRBITS       3

#define _IFXOS_IOC_NRMASK        ((1 << _IFXOS_IOC_NRBITS)-1)
#define _IFXOS_IOC_TYPEMASK      ((1 << _IFXOS_IOC_TYPEBITS)-1)
#define _IFXOS_IOC_SIZEMASK      ((1 << _IFXOS_IOC_SIZEBITS)-1)
#define _IFXOS_IOC_DIRMASK       ((1 << _IFXOS_IOC_DIRBITS)-1)

#define _IFXOS_IOC_NRSHIFT       0
#define _IFXOS_IOC_TYPESHIFT     (_IFXOS_IOC_NRSHIFT+_IFXOS_IOC_NRBITS)
#define _IFXOS_IOC_SIZESHIFT     (_IFXOS_IOC_TYPESHIFT+_IFXOS_IOC_TYPEBITS)
#define _IFXOS_IOC_DIRSHIFT      (_IFXOS_IOC_SIZESHIFT+_IFXOS_IOC_SIZEBITS)

#define _IFXOS_IOC_NONE          1U
#define _IFXOS_IOC_READ          2U
#define _IFXOS_IOC_WRITE         4U

#define _IFXOS_IOC(dir,type,nr,size) \
                           (((dir)  << _IFXOS_IOC_DIRSHIFT) | \
                           ((type) << _IFXOS_IOC_TYPESHIFT) | \
                           ((nr)   << _IFXOS_IOC_NRSHIFT) | \
                           ((size) << _IFXOS_IOC_SIZESHIFT))

extern unsigned int __invalid_size_argument_for_IFXOS_IOC;

#define _IFXOS_IOC_TYPECHECK(t) \
                           ((sizeof(t) == sizeof(t[1]) && \
                           sizeof(t) < (1 << _IFXOS_IOC_SIZEBITS)) ? \
                           sizeof(t) : __invalid_size_argument_for_IFXOS_IOC)

#define _IFXOS_IO(type,nr)             _IFXOS_IOC(_IFXOS_IOC_NONE,(type),(nr),0)
#define _IFXOS_IOR(type,nr,size)       _IFXOS_IOC(_IFXOS_IOC_READ,(type),(nr),(_IFXOS_IOC_TYPECHECK(size)))
#define _IFXOS_IOW(type,nr,size)       _IFXOS_IOC(_IFXOS_IOC_WRITE,(type),(nr),(_IFXOS_IOC_TYPECHECK(size)))
#define _IFXOS_IOWR(type,nr,size)      _IFXOS_IOC(_IFXOS_IOC_READ|_IFXOS_IOC_WRITE,(type),(nr),(_IFXOS_IOC_TYPECHECK(size)))
#define _IFXOS_IOR_BAD(type,nr,size)   _IFXOS_IOC(_IFXOS_IOC_READ,(type),(nr),sizeof(size))
#define _IFXOS_IOW_BAD(type,nr,size)   _IFXOS_IOC(_IFXOS_IOC_WRITE,(type),(nr),sizeof(size))
#define _IFXOS_IOWR_BAD(type,nr,size)  _IFXOS_IOC(_IFXOS_IOC_READ|_IFXOS_IOC_WRITE,(type),(nr),sizeof(size))

#define _IFXOS_IOC_DIR(nr)             (((nr) >> _IFXOS_IOC_DIRSHIFT) & _IFXOS_IOC_DIRMASK)
#define _IFXOS_IOC_TYPE(nr)            (((nr) >> _IFXOS_IOC_TYPESHIFT) & _IFXOS_IOC_TYPEMASK)
#define _IFXOS_IOC_NR(nr)              (((nr) >> _IFXOS_IOC_NRSHIFT) & _IFXOS_IOC_NRMASK)
#define _IFXOS_IOC_SIZE(nr)            (((nr) >> _IFXOS_IOC_SIZESHIFT) & _IFXOS_IOC_SIZEMASK)


/** timer thread stack size */
#define OPTIC_TIMER_THREAD_STACK_SIZE   512
/** timer thread priority */
#define OPTIC_TIMER_THREAD_PRIO         16



#endif                          /* (WIN32) */

extern void *current;

EXTERN_C_END

#endif
