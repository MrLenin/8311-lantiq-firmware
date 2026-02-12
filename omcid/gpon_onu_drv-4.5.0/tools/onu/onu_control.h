#ifndef _onu_control_h_
#define _onu_control_h_

#include <getopt.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <linux/types.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>

#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L)
#  include <stdint.h>
#  include <stdbool.h>
#endif

#ifdef HAVE_CONFIG_H
#  include "onu_control_config.h"
#endif

#include "drv_onu_std_defs.h"
#include "drv_onu_interface.h"
#include "drv_onu_error.h"
#include "drv_onu_resource.h"
#include "drv_onu_common_interface.h"
#include "drv_onu_ploam_interface.h"
#include "drv_onu_lan_interface.h"
#include "drv_onu_gpe_interface.h"
#include "drv_onu_gpe_tables_interface.h"
#include "drv_onu_gtc_interface.h"
#include "drv_onu_event_interface.h"

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

/** OMCI message header */
struct omci_header {
	/** Transaction identifier */
	uint16_t tci;
	/** Message type */
	uint8_t type;
	/** Device identifier type */
	uint8_t dev_id;
	/** Entity class */
	uint16_t class_id;
	/** Entity instance */
	uint16_t instance_id;
} __PACKED__;

/** OMCI message struct
    \see ITU-T G.984.4 11.1.1 */
struct omci_msg {
	/** Message header */
	struct omci_header header;

	/** Message contents */
	uint8_t contents[32];
} __PACKED__;

/** OMCI message response struct */
struct omci_msg_rsp {
	/** Message header */
	struct omci_header header;

	/** Message response result */
	uint8_t result;
	/** Message response contents */
	uint8_t contents[31];
} __PACKED__;

#define ONU_DEVICE_PATH "/dev/onu0"

/** version string */
#define CTRL_WHAT_STR "@(#)GPON ONU control, version " onu_ver_str " " \
		      ONU_COPYRIGHT

#define MAX_PATH 256

int onu_cfg(int argc, char *argv[]);
int onu_open(const char *name);
int onu_close(const int fd);
int onu_iocmd(const int fd, const unsigned int cmd, void *data, const unsigned int size);

extern char buf[ONU_IO_BUF_SIZE];

#endif
