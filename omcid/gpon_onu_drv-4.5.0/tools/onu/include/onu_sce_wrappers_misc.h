/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef __sce_wrappers_misc_h
#define __sce_wrappers_misc_h

enum output_type {
	OUTPUT_XML,
	OUTPUT_JSON
};

int gpe_egress_queue_get(FILE *f, int onu_fd, enum output_type type, int index);

int wrapper_by_name_get(FILE *f, const char *wrapper_name, int onu_id, enum output_type type, int index);

#endif
