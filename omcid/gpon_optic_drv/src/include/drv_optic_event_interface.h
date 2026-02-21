/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_optic_event_interface.h
   Event interface used by the FALC(tm) ON Optic Driver.
*/
#ifndef _drv_optic_event_interface_h
#define _drv_optic_event_interface_h

#include "drv_optic_interface.h"

#ifndef __PACKED__
#  if defined (__GNUC__) || defined (__GNUG__)
   /* GNU C or C++ compiler */
#    define __PACKED__ __attribute__ ((packed))
#  else
   /* Byte alignment adjustment */
#    pragma pack(1)
#    if !defined (_PACKED_)
#      define __PACKED__        /* nothing */
#    endif
#  endif
#  define __PACKED_DEFINED__
#endif


EXTERN_C_BEGIN


/** \addtogroup MAPI_REFERENCE_EVENT Optical Interface Event Handler
   The optical interface software provides an event interface to signal status
   information to other software modules.
   @{
*/

/** \defgroup OPTIC_EVENT_API Optical Event Interface
   Interface to signal events between the optical interface software and other
   software components.
   @{
*/

/* Message types for the notification FIFO.*/
#define OPTIC_FIFO_EXIT                 0
#define OPTIC_FIFO_STATE_CHANGE         1
#define OPTIC_FIFO_TABLE_REQUEST        2
#define OPTIC_FIFO_BOSA_DUALLOOP        3
#define OPTIC_FIFO_ALARM                4
#define OPTIC_FIFO_TIMESTAMP            5
#define OPTIC_FIFO_BOSA_DUALLOOP_TRUE   6

/** Optical interface state definitions. */
enum optic_statetype {
	/** Boot in progress. */
	OPTIC_STATE_BOOT,
	/** Initialization in progress. */
	OPTIC_STATE_INIT,
	/** Configuration in progress. */
	OPTIC_STATE_CONFIG,
	/** Table initialization in progress. */
	OPTIC_STATE_TABLE_INIT,
	/** Table calculation in progress. */
	OPTIC_STATE_TABLE_CALC,
	/** No operation mode selected. */
	OPTIC_STATE_NOMODE,
	/** reset in progress. */
	OPTIC_STATE_RESET,
	/** Mode changing in progress. */
	OPTIC_STATE_MODECHANGE,
	/** Calibration in progress. */
	OPTIC_STATE_CALIBRATE,
	/** Running. */
	OPTIC_STATE_RUN,
	/** Measurement in progress. */
	OPTIC_STATE_MEASURE,
	/** RESTART because of PLL not correctly reset */
	OPTIC_STATE_PLL_ERROR,
};

/**
   Defines a structure for notifications towards the user space.
   The event might be extended by additional data. It's ensured that
   always one event consist of at least sizeof(OPTIC_fifoHeader_t) bytes.
*/
struct optic_fifo_header {
	/** Event ID
	The event ID should be one of the values listed below,
	- \ref OPTIC_FIFO_STATE_CHANGE
	- \ref OPTIC_FIFO_TABLE_REQUEST
	*/
	uint32_t id;
	/** Length of additional data */
	uint32_t len;
};

/** Event FIFO handling. */
union optic_fifo_payload {
	/** Optical interface state. */
	enum optic_statetype state;
	/** Table to request. */
	enum optic_tabletype table;
	/** Optical interface alarm. */
	enum optic_irq alarm;
	/** Time stamp. */
	uint32_t time;
};

/**
   Defines a structure to access a complete event depending on the event ID.
*/
struct optic_fifo_data {
	/** Event header. */
	struct optic_fifo_header header;
	/** Event data. */
	union optic_fifo_payload data;
	/** v7.5.1: alarm active flag (0 = inactive/cleared, nonzero = active).
	    Stock reads this directly for alarm set/clear instead of inferring
	    from the optic_irq enum value. */
	uint32_t alarm_active;
} __PACKED__;


/* Magic number: drv_optic_interface.h */

/**
   Event FIFO access.

   This ioctl reads one element from the optic driver event FIFO. The
   system call is non blocking.

   \param optic_fifo_data Pointer to \ref optic_fifo_data.

   \remarks The function returns an error code in case an error occurred.
            The error code is described in \ref optic_errorcode.

   \remarks Each device descriptor has his own FIFO. If the application isn't
            reading the FIFO fast enough the events might get lost.

   \example
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
      ret = ioctl(fd, FIO_OPTIC_EVENT_FIFO, (long)&ex);
      if (ret != 0) {
         fprintf(stderr, "ERROR: can't read version from device.\n");
         break;
      }
      if (ex.error == 0 && ex.length >= sizeof(OPTIC_fifoHeader_t)) {
         switch(FifoData.header.id) {
            case OPTIC_FIFO_PLOAM_DS:
            fprintf(stdout, "PLOAM_DS: onu id - %x / %s\n",
               FifoData.ploamMessage.onu_id, OPTIC_MsgId2String(FifoData.ploamMessage.msg_id));
            break;
         }
      }
   }

   \return Return value as follows:
   - 0 if successful
   - An error code in case an error occurred.
*/
#define FIO_OPTIC_EVENT_FIFO _IOR(OPTIC_EVENT_MAGIC, 0, struct optic_fifo_data)

/**
   Configure event FIFO handling.

   This ioctl enables the event FIFO for the given device descriptor.
   The system call is non-blocking.

   \param enum optic_activation Pointer to \ref optic_edable.
*/
#define FIO_OPTIC_EVENT_SET  _IOW(OPTIC_EVENT_MAGIC, 1, enum optic_activation)

/**
   Read event FIFO settings.

   This ioctl read the event FIFO settings for the given device descriptor.
   The system call is non blocking.

   \param enum optic_activation Pointer to \ref optic_edable.
*/
#define FIO_OPTIC_EVENT_GET  _IOR(OPTIC_EVENT_MAGIC, 2, enum optic_activation)

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
