/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_onu_event_interface.h
   This is the header file that defines the event interface.
*/
#ifndef _drv_onu_event_interface_h
#define _drv_onu_event_interface_h

#include "drv_onu_ploam_interface.h"
#include "drv_onu_gtc_interface.h"
#include "drv_onu_gpe_interface.h"

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
/** \addtogroup ONU_MAPI_REFERENCE
   @{
*/
/** \defgroup ONU_EVENT_API Event Interface

   This chapter describes the event interface of the driver. The event interface
   is used by the OMCI software to receive the downstream OMCI messages.
   In addition the information about PLOAM state changes and PLOAM messages
   could be recorded.

   @{
*/
/** magic number
*/
#define ONU_EVENT_MAGIC                            2
/* notification event ID's */
/** HW event received */
#define ONU_EVENT_HARDWARE                         0
/** PLOAM downstream message received */
#define ONU_EVENT_PLOAM_DS                         1
/** PLOAM upstream message received */
#define ONU_EVENT_PLOAM_US                         2
/** PLOAM final state machine - state change */
#define ONU_EVENT_STATE_CHANGE                     3
/** OMCI message received */
#define ONU_EVENT_OMCI_RECEIVE                     4
/** GTC Threshold Crossing Alarm */
#define ONU_EVENT_GTC_TCA                          5
/** GPE Threshold Crossing Alarm - GEM */
#define ONU_EVENT_GPE_TCA                          6
/** GPE Threshold Crossing Alarm - LAN */
#define ONU_EVENT_LAN_TCA                          7
/** Status change */
#define ONU_EVENT_GTC_STATUS_CHANGE                8
/** SCE FW breakpoint reached */
#define ONU_EVENT_SCE_BP_REACHED                   9
/** BWMAP trace was stopped */
#define ONU_EVENT_BWMAP_TRACE                      10
/** OMCI message sent */
#define ONU_EVENT_OMCI_SENT                        11
/** IOCTL trace */
#define ONU_EVENT_IOCTL_TRACE                      12
/** Link state change */
#define ONU_EVENT_LINK_STATE_CHANGE                13
/** 15 min interval end */
#define ONU_EVENT_15MIN_INTERVAL_END               14
/** Exception packet available */
#define ONU_EVENT_EXCEPTION_PACKET                 15
/** GPE Threshold Crossing Alarm - Bridge Counter */
#define ONU_EVENT_BRIDGE_TCA                       16
/** GPE Threshold Crossing Alarm - Bridge Port Counter */
#define ONU_EVENT_BRIDGE_PORT_TCA                  17

/** ioctl trace buffer size */
#define ONU_IOCTL_TRACE_MAX_SIZE_BYTE              1024

/** Defines a struct for notifications towards the user space.
    The event might be extended by additional data. It's ensured that
    always one event consist of at least sizeof(struct onu_fifo_header) bytes.
*/
struct onu_fifo_header {
	/** Event ID.*/
	uint32_t id;
	/** Length of additional data.*/
	uint32_t len;
} __PACKED__;

/** Link state. */
struct onu_link_state {
	/** Port number */
	uint32_t port;
	/** Old link state */
	uint32_t old;
	/** New (current) link state */
	uint32_t new;
} __PACKED__;

/** Optional event FIFO data.
*/
union onu_fifo_opt_data {
	/** 32-bit word.*/
	uint32_t val32;
	/** PLOAM state.*/
	struct ploam_state_data_get state;
	/** GTC status.*/
	struct gtc_status status;
	/** PLOAM message.*/
	struct ploam_msg ploam_message;
	/** OMCI message.*/
	struct gpe_omci_msg omci_message;
	/** SCE breakpoint.*/
	struct sce_break_point sce_break_point;
#ifdef INCLUDE_CLI_DUMP_SUPPORT
	char onu_ioctl_trace[ONU_IOCTL_TRACE_MAX_SIZE_BYTE];
#endif
	/** Link state. */
	struct onu_link_state link_state;
} __PACKED__;

/** Defines a struct to access an complete event depending on the event ID.
*/
struct onu_fifo_data {
	/** Event header.*/
	struct onu_fifo_header header;
	/** Optional data.*/
	union onu_fifo_opt_data data;
} __PACKED__;

/** Defines event notification mask.
*/
struct onu_event_mask {
	/** Bitwise mask, see the event notification ID's.*/
	uint32_t val;
} __PACKED__;

/** Hardware event.
*/
struct onu_event {
	/** Event mask, see PLOAM_GTC_FRAME_SYNC etc.*/
	uint32_t event;
} __PACKED__;

/**
   Event FIFO access.

   This ioctl reads one element from the ONU driver event FIFO. The
   system call is non blocking.

   \param onu_fifo_header Pointer to \ref onu_fifo_header.

   \remarks The function returns an error code in case an error occurred.
            The error code is described in \ref onu_errorcode.

   \remarks Each device descriptor has his own FIFO. If the application isn't
            reading the FIFO fast enough the events might get lost.

   \code
   FD_ZERO(&rfds);
   FD_SET(fd, &rfds);

   while(1) {
      tv.tv_sec = 5;
      tv.tv_usec = 0;
      ret = select(fd + 1, &rfds, NULL, NULL, &tv);
      if (ret == -1) {
         fprintf(stderr, "ERROR: select error.\n");
         break;
      }
      if (ret == 0) {
         // no data within timeout
         continue;
      }
      if(FD_ISSET(fd, &rfds) == 0) {
         // not for us
         continue;
      }
      ret = ioctl(fd, FIO_ONU_EVENT_FIFO, (long)&ex);
      if (ret != 0) {
         fprintf(stderr, "ERROR: can't read version from device.\n");
         break;
      }
      if(ex.error == 1) {
         fprintf(stderr, "WARN: fifo overflow.\n");
      }
      if (ex.error >= 0 && ex.length >= sizeof(struct onu_fifo_header)) {
         switch(FifoData.header.id) {
            case ONU_EVENT_PLOAM_DS:
            fprintf(stdout, "PLOAM_DS: onu id - %x / %s\n",
               FifoData.ploam_message.onu_id,
			onu_msg_id2_string(FifoData.ploam_message.msg_id));
            break;
         }
      }
   }
   \endcode

   \return Return value as follows:
   - 0 if successful
   - An error code in case an error occurred.
*/
#define FIO_ONU_EVENT_FIFO   _IOR(ONU_EVENT_MAGIC, 200, struct onu_fifo_header)

/**
   Configure event FIFO handling.

   This ioctl enables the event FIFO for the given device descriptor. The
   system call is non blocking.

   \param onu_event_mask Pointer to \ref onu_event_mask.
*/
#define FIO_ONU_EVENT_ENABLE_SET   \
			_IOW(ONU_EVENT_MAGIC, 201, struct onu_event_mask)

/**
   Read event FIFO settings.

   This ioctl reads the event FIFO settings for the given device descriptor.
   The system call is non blocking.

   \param onu_event_mask Pointer to \ref onu_event_mask.
*/
#define FIO_ONU_EVENT_ENABLE_GET   \
			_IOR(ONU_EVENT_MAGIC, 202, struct onu_event_mask)

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
