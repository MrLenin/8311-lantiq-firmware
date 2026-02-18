/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_onu_loop_detection.h
   ME 65528: ONU Loop Detection — handler declarations.

   Stock v7.5.1 reference: ghidra/output/phase13_stock.c lines 15-620
*/
#ifndef _omci_onu_loop_detection_h
#define _omci_onu_loop_detection_h

#include "omci_interface.h"

__BEGIN_DECLS

/** \addtogroup OMCI_ME_ONU_LOOP_DETECTION
   @{
*/

/** Attribute indices for ONU Loop Detection ME (1-based) */
enum {
	omci_me_onu_loop_detection_operator_id = 1,
	omci_me_onu_loop_detection_loop_detect_mgmt = 2,
	omci_me_onu_loop_detection_loop_port_down = 3,
	omci_me_onu_loop_detection_loop_detect_freq = 4,
	omci_me_onu_loop_detection_loop_recovery_int = 5,
	omci_me_onu_loop_detection_port_vlan_table = 6
};

/* Forward declarations from omci framework */
struct omci_context;
struct me;
struct tbl_copy_entry;

/** ME init handler (replaces default_me_init for ME 65528) */
enum omci_error omci_onu_loop_detection_me_init(struct omci_context *context,
						struct me *me,
						void *init_data,
						uint16_t suppress_avc);

/** ME shutdown handler (replaces default_me_shutdown for ME 65528) */
enum omci_error omci_onu_loop_detection_me_shutdown(struct omci_context *context,
						    struct me *me);

/** ME update handler (replaces default_me_update for ME 65528) */
enum omci_error omci_onu_loop_detection_me_update(struct omci_context *context,
						  struct me *me,
						  void *data,
						  uint16_t attr_mask);

/** ME table copy handler (port_vlan_table for MIB upload) */
enum omci_error omci_onu_loop_detection_me_tbl_copy(struct omci_context *context,
						    struct me *me,
						    unsigned int attr,
						    struct tbl_copy_entry *tbl_copy);

/** Loop detection event action — called when kernel reports loop on a port.

   \param[in] context      OMCI context pointer
   \param[in] instance_id  Loop Detection ME instance (always 0)
   \param[in] uni_me_id    PPTP ETH UNI ME ID of port where loop detected
*/
enum omci_error omci_onu_loop_detect_action(struct omci_context *context,
					    uint16_t instance_id,
					    uint16_t uni_me_id);

/** @} */

__END_DECLS

#endif
