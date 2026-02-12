/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _drv_optic_base_h
#define _drv_optic_base_h

#include "drv_optic_std_defs.h"

EXTERN_C_BEGIN

long optic_open (void);
int optic_release (long dev);
void optic_irq_poll (void);

EXTERN_C_END

#endif
