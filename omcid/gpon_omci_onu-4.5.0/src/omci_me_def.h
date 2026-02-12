/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_me_def_h
#define _omci_me_def_h

#include "omci_me.h"

/** Supported Managed Entities classes */
extern struct me_class *me_def_class_array[];

/** Return number of elements in \ref me_def_class_array */
size_t omci_me_def_class_array_size(void);

#endif
