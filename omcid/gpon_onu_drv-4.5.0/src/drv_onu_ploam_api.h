/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _drv_onu_ploam_api_h
#define _drv_onu_ploam_api_h

#include "drv_onu_types.h"

/* exclude some parts from SWIG generation */
#ifndef SWIG

/** \addtogroup ONU_MAPI_REFERENCE_INTERNAL
   @{
*/

/** \defgroup PLOAM_API_INTERNAL Physical Layer Messaging Channel (PLOAM)
   @{
*/

/**
   \todo
   - implement PLOAM allocation messages \see 5.5.3
   - Additional Alloc-IDs are assigned to the ONU explicitly by means of the
     Assign_Alloc-ID PLOAM message with Alloc-ID Type 1. Such an assignment
     can be explicitly reversed by means of Assign_Alloc-ID PLOAM message
     with Alloc-ID Type 255.
   - All Alloc-ID assignments, including the Default Alloc-ID assignment,
     shall be lost upon ONU deactivation.  - mapping between T-CONT and
     allocation ID's \see 5.5.4
   - The GEM Port-ID assignment to the OMCC logical connection is performed
     by means of Configure_Port-ID PLOAM message. \see 5.5.5
   - ONU registration,
      - configured serial number method
      - discovered serial number method
   - PSync, detected by Interrupt or Polling
*/

/** Threshold for Serial_Number_request events */
#define PLOAM_SN_REQUEST_THRESHOLD          10

/** PSync Synchronization */
#define PLOAM_GTC_FRAME_SYNC                0x0001
/** ONU received a ranging request */
#define PLOAM_RANGING_REQUEST               0x0002
/** Timer TO0 expires */
#define PLOAM_TO0_EXPIRED                   0x0004
/** Timer TO1 expires */
#define PLOAM_TO1_EXPIRED                   0x0008
/** Timer TO2 expires */
#define PLOAM_TO2_EXPIRED                   0x0010
/** LOS detected */
#define PLOAM_LOS                           0x0020
/** LOF detected */
#define PLOAM_LOF                           0x0040
/** ONU received PLOAMd message */
#define PLOAM_MSG_RECEIVED                  0x0080
/** The ONU received a Serial Number request
 (BW Allocation structure with Alloc-ID = 254 PLOAMu = "1") */
#define PLOAM_SN_REQUEST                    0x0100
/** ONU should send ack */
#define PLOAM_ACK_SEND                      0x0200
/** ONU should REI message */
#define PLOAM_BER_EXPIRED                   0x0400

/**
   ONU-ID value, assignable.
   Assigned by OLT at ONU activation. Used to identify the sender
   of an upstream burst or a PLOAMu and to address PLOAMd.
*/
#define PLOAM_ID_VALUE_ASSIGNABLE            0xFD

/**
 ONU-ID value, reserved.
 Reserved, should not be assigned, as it conflict with the Alloc-ID usage
*/
#define PLOAM_ID_VALUE_RESERVED             0xFE

/**
 ONU-ID value, broadcast.
 - broadcast address in downstream messages
 - unassigned in upstream messages
*/
#define ONU_ID_VALUE_BROADCAST            0xFF

/** FSM - error */
#define PLOAM_FSM_ERROR                     (-1)
/** FSM - error */
#define PLOAM_FSM_ERROR_EVENT_NOT_HANDLED   0x0100
/** FSM - state changed */
#define PLOAM_FSM_STATE_CHANGED             0x0001
/** FSM - PLOAM message received */
#define PLOAM_FSM_PLOAM_RECEIVED            0x0002

/*#define ONU_GET_MSG_ID(_msg_) (_msg_->msg_id)*/

/**
   Initialize the ONU context.

   \param onu_ctrl The control context pointer.

   \return
   - 0  Initialization successfully
   - -1    Error occurred during initialization
*/
int ploam_context_init(void *onu_ctrl);

/**
   Free the ONU context.

   \param onu_ctrl The control context pointer.

   \return
   - 0  Operation successfully
   - -1    Error occurred
*/
int ploam_context_free(void *onu_ctrl);

/**
   PLOAM Finite State Machine

   \param ploam_ctx   The PLOAM context pointer.

   \return
   - 0                        Success, but no state switch
   - PLOAM_FSM_ERROR            Error occurred.
   \return
   Following additional flags maybe set
   - PLOAM_FSM_STATE_CHANGED    State switch done successfully
   - PLOAM_FSM_ERROR_EVENT_NOT_HANDLED Is
*/
int ploam_fsm(struct ploam_context *ploam_ctx);

const char *ploam_msgid2string(uint8_t msg_id);

enum onu_errorcode ploam_ds_extract(struct onu_device *p_dev,
				    struct ploam_message *param);

enum onu_errorcode ploam_us_insert(struct onu_device *p_dev,
				   const struct ploam_message *param);

enum onu_errorcode ploam_us_extract(struct onu_device *p_dev,
				    struct ploam_message *param);

int onu_serial_number_send(struct ploam_context *ploam_ctx,
			   const uint8_t repeat);

void onu_ploam_log(const uint32_t id, void *data, const uint16_t size);

#endif				/* SWIG */

/**
   Simulate a downstream PLOAM message. The PLOAM message will be written to the
   register bank if the ONU ID is matching (or if it's a broadcast).
*/
enum onu_errorcode ploam_ds_insert(struct onu_device *p_dev,
				   const struct ploam_message *param);

enum onu_errorcode ploam_init(struct onu_device *p_dev);

enum onu_errorcode ploam_state_get(struct onu_device *p_dev,
				   struct ploam_state_data_get *param);

enum onu_errorcode ploam_state_set(struct onu_device *p_dev,
				   const struct ploam_state_data_set *param);


/*! @} */

/*! @} */

/*! @} */

/*! @} */

#endif
