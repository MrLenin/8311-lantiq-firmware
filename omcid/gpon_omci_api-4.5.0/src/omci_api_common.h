/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_common_h
#define _omci_api_common_h

#include "ifx_types.h"

#ifndef WIN32
#include <sys/time.h>
#endif

#ifdef _lint
#  include <stddef.h>
#endif

#ifndef SWIG
#  include "ifxos_version.h"
#endif

#include "ifxos_common.h"
#ifndef IFXOS_BYTE_ORDER
#  error "Unknown byte order!"
#endif

#include "ifxos_thread.h"
#include "ifx_fifo.h"
#include "ifxos_lock.h"
#include "omci_api_config.h"

#ifdef INCLUDE_DRIVER_SIMULATION
/** When driver simulation enabled, don't do any swapping */
#define REMOTE_ENDIAN IFXOS_BYTE_ORDER
#else
/** Currently, we assume that target board is always big endian */
#define REMOTE_ENDIAN IFXOS_BIG_ENDIAN
#endif

#if (REMOTE_ENDIAN == IFXOS_BIG_ENDIAN) && \
				(IFXOS_BYTE_ORDER == IFXOS_LITTLE_ENDIAN)
#  define ONU_OMCI_SWAP
#endif

#if defined(ONU_OMCI_SWAP)

/** Network to host byte order for 16bit variable */
#  define ONU_OMCI_NTOH16(VAL) \
   ( (((uint16_t)(VAL) & 0xff00) >> 8) | \
     (((uint16_t)(VAL) & 0x00ff) << 8) )

/** Host to network byte order for 16bit variable */
#  define ONU_OMCI_HTON16(VAL) ONU_OMCI_NTOH16(VAL)

/** Network to host byte order for 32bit variable */
#  define ONU_OMCI_NTOH32(VAL) \
   ( (((uint32_t)(VAL) & 0xff000000) >> 24) | \
     (((uint32_t)(VAL) & 0x00ff0000) >> 8)  | \
     (((uint32_t)(VAL) & 0x0000ff00) << 8)  | \
     (((uint32_t)(VAL) & 0x000000ff) << 24) )

/** Host to network byte order for 32bit variable */
#  define ONU_OMCI_HTON32(VAL) ONU_OMCI_NTOH32(VAL)

#else

/** Network to host byte order for 16bit variable */
#  define ONU_OMCI_NTOH16(VAL) (VAL)

/** Host to network byte order for 16bit variable */
#  define ONU_OMCI_NTOH32(VAL) (VAL)

/** Network to host byte order for 32bit variable */
#  define ONU_OMCI_HTON16(VAL) (VAL)

/** Host to network byte order for 32bit variable */
#  define ONU_OMCI_HTON32(VAL) (VAL)

#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof((x)) / sizeof((x)[0]))
#endif

#ifndef MAX
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#endif 

/* check the IFXOS version */
#if !defined(IFXOS_HAVE_VERSION_CHECK) || !IFXOS_VERSION_CHECK_EG_THAN(1,5,10)
#  error Please update your IFX OS, require at least version 1.5.10!
#endif

#ifdef HAVE_CONFIG_H
#  include "omci_api_config.h"
#endif

#include "ifx_types.h"

#ifndef _lint
#  include "ifxos_std_defs.h"
#  include "drv_onu_std_defs.h"
#else
#  include <stddef.h>
#endif

#include "omci_api.h"
#include "omci_api_event.h"
#include "drv_onu_resource.h"
#include "drv_onu_resource_gpe.h"
#include "drv_onu_interface.h"
#include "drv_onu_common_interface.h"
#include "drv_onu_ploam_interface.h"
#include "drv_onu_lan_interface.h"
#include "drv_onu_ethertypes.h"
#include "drv_onu_gpe_interface.h"
#include "drv_onu_gpe_tables_interface.h"
#include "drv_onu_gtc_interface.h"
#include "drv_onu_gpe_tables.h"
#include "drv_onu_event_interface.h"
#include "drv_onu_error.h"

#include "drv_optic_interface.h"
#include "drv_optic_bosa_interface.h"
#include "drv_optic_mm_interface.h"
#include "drv_optic_event_interface.h"

/** Offset used to calculate SW_GPIX from the maximum number of GPIX */
#define SW_GPIX_OFFSET						1
/** Offset used to calculate OMCI_GPIX from the maximum number of GPIX */
#define OMCI_GPIX_OFFSET					2

#include "omci_api_mapper.h"
#include "omci_api_timer.h"

#include "ifxos_print.h"

#ifdef INCLUDE_OMCI_API_VOIP
#  include "ifxos_socket.h"
#    ifdef LINUX
#      include <sys/types.h>
#      include <sys/socket.h>
#      include <unistd.h>
#      include <fcntl.h>
#    endif
#endif

#if defined(INCLUDE_DRIVER_SIMULATION)
#  define ONU_SIMULATION
#  define IFXOS_USE_DEV_IO 1
#  include "ifxos_device_io.h"
#  include "drv_onu_devio.h"
#  define device_open DEVIO_open
#  define device_close DEVIO_close
#  define device_ioctl DEVIO_ioctl
#  define device_fd_set_t DEVIO_fd_set_t
#  define device_fd_zero DEVIO_fd_zero
#  define device_fd_set DEVIO_fd_set
#  define device_fd_is_set DEVIO_fd_isset
#  define device_select DEVIO_select
#else
#  include "ifxos_device_access.h"
#  define device_open IFXOS_DeviceOpen
#  define device_close IFXOS_DeviceClose
#  define device_ioctl IFXOS_DeviceControl
#  define device_fd_set_t IFXOS_devFd_set_t
#  define device_fd_zero IFXOS_DevFdZero
#  define device_fd_set IFXOS_DevFdSet
#  define device_fd_is_set IFXOS_DevFdIsSet
#  define device_select IFXOS_DeviceSelect
#  ifdef WIN32
      /* windows.h header will include winsock.h , _IOWR macro is missing */
#     define ONU_SIMULATION
#     include "drv_onu_devio.h"
#     undef ONU_SIMULATION
#  endif
#  ifdef ONU_OMCI_SWAP
      /* when swapping enabled, we need to use use the same DEVIO defines
       * as driver uses */
#     define ONU_SIMULATION
#     include "drv_onu_devio.h"
#     undef ONU_SIMULATION
#  endif
#endif

#include "me/omci_api_table_access.h"
#include "voip/omci_api_voip.h"
#include "voip/omci_api_voip_common.h"

#include "mcc/omci_api_mcc.h"
#include "mcc/omci_api_mcc_common.h"

/** \defgroup OMCI_API_COMMON OMCI API - Common Functionality

   @{
*/

#ifdef LINUX
/* from IFXOS, where it's under ifdefs */

/** LINUX Kernel Thread - priority - IDLE */
#  define IFXOS_THREAD_PRIO_IDLE                                       1
/** LINUX User Thread - priority - LOWEST */
#  define IFXOS_THREAD_PRIO_LOWEST                                     5
/** LINUX User Thread - priority - LOW */
#  define IFXOS_THREAD_PRIO_LOW                                        20
/** LINUX User Thread - priority - NORMAL */
#  define IFXOS_THREAD_PRIO_NORMAL                                     40
/** LINUX User Thread - priority - HIGH */
#  define IFXOS_THREAD_PRIO_HIGH                                       60
/** LINUX User Thread - priority - HIGHEST */
#  define IFXOS_THREAD_PRIO_HIGHEST                                    80
#endif

#ifndef offsetof
/** Receive structure member offset (POSIX 1-2001) */
#  define offsetof(STRUCT, MEMBER) \
   /*lint -save -e(413) -e(507) -e(831) */ \
   ((size_t) &((STRUCT *) 0)->MEMBER ) \
				/*lint -restore */
#endif

/** Convert counter value to 32-bit */
#define CNT_32(VAL) \
   (uint32_t)(((VAL) > 0xffffffff) ? (VAL) : 0xffffffff)

/** Get table entry size */
#define TABLE_ENTRY_SIZE(ENTRY) \
   (offsetof(struct gpe_table_entry, data) + sizeof(ENTRY))

#define OMCI_API_EVENT_FIFO_SIZE 5

struct omci_api_event_fifo_entry {
	uint16_t class_id;
	uint16_t instance_id;
	enum omci_api_action_type action;
	enum omci_api_return ret;
};

/** ONU driver capabilities */
struct omci_api_capability {
	/** Maximum number of Meters */
	uint32_t max_meter;
	/** Maximum number of GPIX */
	uint32_t max_gpix;
	/** Maximum number of Ethernet UNIs */
	uint32_t max_eth_uni;
	/** Maximum number of POTS UNIs */
	uint32_t max_pots_uni;
	/** Maximum number of Bridge ports */
	uint32_t max_bridge_port;
	/** Chip revision */
	uint32_t hw_version;
};

/** Structure to specify event handler context.
*/
struct event_ctx {
	/** event handler initialized */
	bool init;
	/** Thread run flag*/
	bool run;
	/** Control thread control structure */
	IFXOS_ThreadCtrl_t thread_ctrl;
	/** event callback */
	omci_api_event_handler_t *cb;
};

struct omci_api_ctx {
	void *caller;

	uint8_t onu_id;
	int onu_fd;
	int goi_fd;
	int onu_fd_nfc;
	int goi_fd_nfc;

	struct event_ctx event;
#ifdef INCLUDE_OMCI_API_VOIP
	struct voip_ctx voip;
#endif
#ifdef LINUX
	struct mcc_ctx mcc;
#endif
	/** Array of Mappers (for each ID type) */
	struct mapper *mapper[MAPPER_IDTYPE_MAX];
	/** prio mapping & ref count*/
	uint8_t dscp_prio_map[8][25];
	/** 64 * 3bit pcp values */
	uint8_t pcp[8][64];
	/** Traffic management option */
	uint8_t traff_mgmt_opt;
	/** ONU driver capabilities */
	struct omci_api_capability capability;
	/** if enabled use remote access */
	bool remote;
	/** Timers bookkeeping */
	struct omci_api_timer *timer[OMCI_API_TIMER_MAX];
	/** UNI to LAN IDs mapping */
	int uni2lan[ONU_GPE_MAX_UNI];
};

#ifdef INCLUDE_OMCI_API_DMALLOC
#	define DMALLOC
#	define DMALLOC_FUNC_CHECK

#	include <dmalloc.h>

#	define IFXOS_MemAlloc(SIZE) malloc((SIZE))
#	define IFXOS_MemFree(PTR) free((PTR))
#endif

/** Wait for device event (wakeup)

   \param[in]  ctx     OMCI API context pointer
   \param[in]  m       Max Device FDs
   \param[in]  timeout Wait timeout in ms
   \param[out] out     Event available indicator

   \return 0 - no data available
           1 - new data received
*/
int event_wait(struct omci_api_ctx *ctx, const int m,
	       const unsigned int timeout, uint8_t out[2]);

/** Execute ioctl

   \param[in]     remote   Remote or local access
   \param[in]     fd       Device FD
   \param[in]     cmd      Command
   \param[in,out] p_data   Command data
   \param[in]     data_sz  Command data size
*/
enum omci_api_return dev_ctl(const uint8_t remote, const int fd,
			     const uint32_t cmd, void *p_data,
			     const size_t data_sz);

/** Open device
*/
enum omci_api_return dev_open(const uint8_t remote, const char *dev_name);

/** Close device
*/
enum omci_api_return dev_close(const uint8_t remote, const int fd);

/** Create DSCP profile

   \param[in] ctx                         OMCI API context pointer
   \param[in] dscp_prio_map DSCP to P-bit mapping attribute

   \return DSCP profile index
*/
uint8_t dscp_profile_create(struct omci_api_ctx *ctx,
			    const uint8_t *dscp_prio_map);

/** Delete DSCP profile

   \param[in] ctx               OMCI API context pointer
   \param[in] dscp_profile 	DSCP profile index

*/
void dscp_profile_delete(struct omci_api_ctx *ctx, const uint8_t dscp_profile);

/** Setup exceptions at the LAN side

   \param[in] ctx               OMCI API context pointer
   \param[in] lan_idx 		LAN port index
   \param[in] profile_idx 	Exception profile index
   \param[in] ingress_mask_set 	Ingress exception mask to set
   \param[in] ingress_mask_clr 	Ingress exception mask to clear
   \param[in] egress_mask_set 	Ingress exception mask to set
   \param[in] egress_mask_clr 	Ingress exception mask to clear

*/
enum omci_api_return lan_exception_setup(struct omci_api_ctx *ctx,
					 const uint8_t lan_idx,
					 const uint8_t profile_idx,
					 const uint32_t ingress_mask_set,
					 const uint32_t ingress_mask_clr,
					 const uint32_t egress_mask_set,
					 const uint32_t egress_mask_clr);

/** Setup exception meter at the LAN side (v7.5.1: IGMP meter removed)

   \param[in] ctx               OMCI API context pointer
   \param[in] lan_idx		LAN port index
   \param[in] uni_except_meter_id 	UNI meter ID
   \param[in] uni_except_meter_enable 	UNI meter enable

*/
enum omci_api_return lan_exception_meter_setup(struct omci_api_ctx *ctx,
					 const uint8_t lan_idx,
					 const uint32_t uni_except_meter_id,
					 const uint32_t uni_except_meter_enable);

/** Setup exceptions at the ANI side

   \param[in] ctx               OMCI API context pointer
   \param[in] gem_idx 		GEM port index
   \param[in] dir 		GEM port direction
   \param[in] profile_idx 	Exception profile index
   \param[in] ingress_mask_set 	Ingress exception mask to set
   \param[in] ingress_mask_clr 	Ingress exception mask to clear
   \param[in] egress_mask_set 	Ingress exception mask to set
   \param[in] egress_mask_clr 	Ingress exception mask to clear

*/
enum omci_api_return ani_exception_setup(struct omci_api_ctx *ctx,
					 const uint8_t gem_idx,
					 enum omci_api_gem_port_direction dir,
					 const uint8_t profile_idx,
					 const uint32_t ingress_mask_set,
					 const uint32_t ingress_mask_clr,
					 const uint32_t egress_mask_set,
					 const uint32_t egress_mask_clr);

/** @} */

/** \defgroup OMCI_API_ME OMCI API - Managed Entities

   @{
*/

/** @} */

#endif
