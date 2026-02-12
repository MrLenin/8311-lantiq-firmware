/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_msg_h
#define _omci_msg_h

#include "omci_types.h"

__BEGIN_DECLS

/** \defgroup OMCI_MSG Optical Network Unit - OMCI Message format

   @{
*/

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
struct omci_msg_msg {
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

/** Create message */
struct omci_msg_create {
	/** Message header */
	struct omci_header header;

	/** Attribute values of Set-by-create attributes (size depending on the
	   type of attribute) */
	uint8_t values[32];
} __PACKED__;

/** Create response */
struct omci_msg_create_rsp {
	/** Message header */
	struct omci_header header;

	/** Result, reason */
	uint8_t result;
	/** Attribute execution mask, used with \ref OMCI_MR_PARAM_ERROR
	   result */
	uint16_t attr_exec_mask;

	/** Padding */
	uint8_t padding[29];
} __PACKED__;

/** Delete message */
struct omci_msg_delete {
	/** Message header */
	struct omci_header header;

	/** Padding */
	uint8_t padding[32];
} __PACKED__;

/** Delete response */
struct omci_msg_delete_rsp {
	/** Message header */
	struct omci_header header;

	/** Result, reason */
	uint8_t result;

	/** Padding */
	uint8_t padding[31];
} __PACKED__;

/** Set message */
struct omci_msg_set {
	/** Message header */
	struct omci_header header;

	/** Attribute mask */
	uint16_t attr_mask;
	/** Attribute values to set (size depending on the type of attribute) */
	uint8_t values[30];
} __PACKED__;

/** Set response */
struct omci_msg_set_rsp {
	/** Message header */
	struct omci_header header;

	/** Result, reason */
	uint8_t result;
	/** Optional attribute mask, used with \ref OMCI_MR_ATTR_FAILED
	   result */
	uint16_t opt_attr_mask;
	/** Attribute execution mask, used with \ref OMCI_MR_ATTR_FAILED
	   result */
	uint16_t attr_exec_mask;

	/** Padding */
	uint8_t padding[25];
} __PACKED__;

/** Get message */
struct omci_msg_get {
	/** Message header */
	struct omci_header header;

	/** Attribute mask */
	uint16_t attr_mask;

	/** Padding */
	uint8_t padding[30];
} __PACKED__;

/** Get response */
struct omci_msg_get_rsp {
	/** Message header */
	struct omci_header header;

	/** Result, reason */
	uint8_t result;
	/** Attribute mask */
	uint16_t attr_mask;
	/** Attribute values of attributes included (size depending on the type
	   of attribute) */
	uint8_t values[25];
	/** Optional attribute mask, used with \ref OMCI_MR_ATTR_FAILED
	   result */
	uint16_t opt_attr_mask;
	/** Attribute execution mask, used with \ref OMCI_MR_ATTR_FAILED
	   result */
	uint16_t attr_exec_mask;
} __PACKED__;

/** Get table response */
struct omci_msg_get_tbl_rsp {
	/** Message header */
	struct omci_header header;

	/** Result, reason */
	uint8_t result;
	/** Attribute mask */
	uint16_t attr_mask;
	/** Table attribute size */
	uint32_t size;
	/** Attribute values of attributes included (size depending on the type
	   of attribute) */
	uint8_t padding[21];
	/** Optional attribute mask, used with \ref OMCI_MR_ATTR_FAILED
	   result */
	uint16_t opt_attr_mask;
	/** Attribute execution mask, used with \ref OMCI_MR_ATTR_FAILED
	   result */
	uint16_t attr_exec_mask;
} __PACKED__;

/** Get all alarms mode */
enum {
	/** All alarms */
	OMCI_GET_ALL_ALARMS_MODE_ALL = 0,

	/** Alarms that are not under ARC */
	OMCI_GET_ALL_ALARMS_MODE_NO_ARC = 1
};

/** Get all alarms message */
struct omci_msg_get_all_alarms {
	/** Message header */
	struct omci_header header;

	/** Alarm retrieval mode. Please refer to
	   \ref OMCI_GET_ALL_ALARMS_MODE_ALL
	   and \ref OMCI_GET_ALL_ALARMS_MODE_NO_ARC */
	uint8_t mode;

	/** Padding */
	uint8_t padding[31];
} __PACKED__;

/** Get all alarms response */
struct omci_msg_get_all_alarms_rsp {
	/** Message header */
	struct omci_header header;

	/** Number of subsequent commands */
	uint16_t seq_num;

	/** Padding */
	uint8_t padding[30];
} __PACKED__;

/** Get all alarms next message */
struct omci_msg_get_all_alarms_next {
	/** Message header */
	struct omci_header header;

	/** Command sequence number */
	uint16_t seq_num;

	/** Padding */
	uint8_t padding[30];
} __PACKED__;

/** Get all alarms next response */
struct omci_msg_get_all_alarms_next_rsp {
	/** Message header */
	struct omci_header header;

	/** Entity class on which the alarms are reported */
	uint16_t class_id;
	/** Entity instance on which the alarms are reported */
	uint16_t instance_id;
	/** Bitmap alarms */
	uint8_t alarm_bitmap[28];
} __PACKED__;

/** MIB upload message */
struct omci_msg_mib_upload {
	/** Message header */
	struct omci_header header;

	/** Padding */
	uint8_t padding[32];
} __PACKED__;

/** MIB upload response */
struct omci_msg_mib_upload_rsp {
	/** Message header */
	struct omci_header header;

	/** Number of subsequent commands */
	uint16_t seq_num;

	/** Padding */
	uint8_t padding[30];
} __PACKED__;

/** MIB upload next message */
struct omci_msg_mib_upload_next {
	/** Message header */
	struct omci_header header;

	/** Command sequence number */
	uint16_t seq_num;

	/** Padding */
	uint8_t padding[30];
} __PACKED__;

/** MIB upload next response */
struct omci_msg_mib_upload_next_rsp {
	/** Message header */
	struct omci_header header;

	/** Entity class of object */
	uint16_t class_id;
	/** Entity instance of object */
	uint16_t instance_id;
	/** Attribute mask */
	uint16_t attr_mask;
	/** Values of attributes (size depending on the type of the
	   attribute) */
	uint8_t values[26];
} __PACKED__;

/** MIB reset message */
struct omci_msg_mib_reset {
	/** Message header */
	struct omci_header header;

	/** Padding */
	uint8_t padding[32];
} __PACKED__;

/** MIB reset response */
struct omci_msg_mib_reset_rsp {
	/** Message header */
	struct omci_header header;

	/** Result, reason */
	uint8_t result;

	/** Padding */
	uint8_t padding[31];
} __PACKED__;

/** Alarm message */
struct omci_msg_alarm {
	/** Message header */
	struct omci_header header;

	/** Alarm bitmap */
	uint8_t alarm_bitmap[28];
	/** Padding */
	uint8_t padding[3];
	/** Alarm sequence number */
	uint8_t seq_num;
} __PACKED__;

/** AVC message */
struct omci_msg_avc {
	/** Message header */
	struct omci_header header;

	/** Attribute mask */
	uint16_t attr_mask;
	/** Attribute values of attributes changed (size depending on the type
	   of attribute) */
	uint8_t values[30];
} __PACKED__;

/** Test ONU-G message */
struct omci_msg_test_onu_g {
	/** Message header */
	struct omci_header header;

	/** Select test */
	uint8_t test;

	/** Padding */
	uint8_t padding[31];
} __PACKED__;

/** Test circuit pack message */
struct omci_msg_test_circuit_pack {
	/** Message header */
	struct omci_header header;

	/** Select test */
	uint8_t test;

	/** Padding */
	uint8_t padding[31];
} __PACKED__;

/** Test IP Host config message */
struct omci_msg_test_ip_host_config {
	/** Message header */
	struct omci_header header;

	/** Select test */
	uint8_t test;
	/** IP address of target */
	uint32_t ip_address;

	/** Padding */
	uint8_t padding[27];
} __PACKED__;

/** Test PPTP POTS UNI message */
struct omci_msg_test_pots_uni {
	/** Message header */
	struct omci_header header;

	/** Select test and test mode */
	uint8_t test;
	/** DBDT timer T1 (slow dial tone threshold), in units of 0.1 seconds */
	uint8_t dbdt_timer_t1;
	/** DBDT timer T2 (no dial tone threshold), in units of 0.1 seconds */
	uint8_t dbdt_timer_t2;
	/** DBDT timer T3 (slow break dial tone threshold), in units of 0.1
	   seconds  */
	uint8_t dbdt_timer_t3;
	/** DBDT timer T4 (no break dial tone threshold), in units of 0.1
	   seconds */
	uint8_t dbdt_timer_t4;
	/** DBDT control byte */
	uint8_t dbdt_control;
	/** Digit to be dialled, ASCII character in range "0"-"9", "*", "#" */
	uint8_t digit;
	/** Dial tone frequency 1, in units of Hz */
	uint16_t dial_tone_freq1;
	/** Dial tone frequency 2, in units of Hz */
	uint16_t dial_tone_freq2;
	/** Dial tone frequency 3, in units of Hz */
	uint16_t dial_tone_freq3;
	/** Dial tone power threshold, absolute value, 0.1 dB resolution */
	uint8_t dial_tone_power_thr;
	/** Idle channel power threshold, absolute value, 1 dB resolution */
	uint8_t idle_power_thr;
	/** DC hazardous voltage threshold, absolute value, volts */
	uint8_t dc_haz_volt_thr;
	/** AC hazardous voltage threshold, absolute value, volts RMS */
	uint8_t ac_haz_volt_thr;
	/** DC foreign voltage threshold, absolute value, volts */
	uint8_t dc_for_volt_thr;
	/** AC foreign voltage threshold, absolute value, volts RMS */
	uint8_t ac_for_volt_thr;
	/** Tip-ground and ring-ground resistance threshold */
	uint8_t tg_rt_res_thr;
	/** Tip-ring resistance threshold */
	uint8_t tr_res_thr;
	/** Ringer equivalence minimum threshold, in 0.01 REN units */
	uint16_t ringer_min_thr;
	/** Ringer equivalence maximum threshold, in 0.01 REN units */
	uint16_t ringer_max_thr;
	/** Pointer to a general purpose buffer ME, used to return
	   vendor-specific test results */
	uint16_t buffer_pointer;

	/** Padding */
	uint8_t padding[5];
} __PACKED__;

/** Test PPTP ISDN UNI message */
struct omci_msg_test_pptp_isdn_uni {
	/** Message header */
	struct omci_header header;

	/** Select test and test mode */
	uint8_t test;
	/** DBDT timer T1 (slow dial tone threshold), in units of 0.1 seconds */
	uint8_t dbdt_timer_t1;
	/** DBDT timer T2 (no dial tone threshold), in units of 0.1 seconds */
	uint8_t dbdt_timer_t2;
	/** DBDT timer T3 (slow break dial tone threshold), in units of 0.1
	   seconds  */
	uint8_t dbdt_timer_t3;
	/** DBDT timer T4 (no break dial tone threshold), in units of 0.1
	   seconds */
	uint8_t dbdt_timer_t4;
	/** DBDT control byte */
	uint8_t dbdt_control;
	/** Digit to be dialled, ASCII character in range "0"-"9", "*", "#" */
	uint8_t digit;
	/** Dial tone frequency 1, in units of Hz */
	uint16_t dial_tone_freq1;
	/** Dial tone frequency 2, in units of Hz */
	uint16_t dial_tone_freq2;
	/** Dial tone frequency 3, in units of Hz */
	uint16_t dial_tone_freq3;
	/** Dial tone power threshold, absolute value, 0.1 dB resolution */
	uint8_t dial_tone_power_thr;
	/** Idle channel power threshold, absolute value, 1 dB resolution */
	uint8_t idle_power_thr;
	/** DC hazardous voltage threshold, absolute value, volts */
	uint8_t dc_haz_volt_thr;
	/** AC hazardous voltage threshold, absolute value, volts RMS */
	uint8_t ac_haz_volt_thr;
	/** DC foreign voltage threshold, absolute value, volts */
	uint8_t dc_for_volt_thr;
	/** AC foreign voltage threshold, absolute value, volts RMS */
	uint8_t ac_for_volt_thr;
	/** Tip-ground and ring-ground resistance threshold */
	uint8_t tg_rt_res_thr;
	/** Tip-ring resistance threshold */
	uint8_t tr_res_thr;
	/** Ringer equivalence minimum threshold, in 0.01 REN units */
	uint16_t ringer_min_thr;
	/** Ringer equivalence maximum threshold, in 0.01 REN units */
	uint16_t ringer_max_thr;
	/** Pointer to a general purpose buffer ME, used to return
	   vendor-specific test results */
	uint16_t buffer_pointer;

	/** Padding */
	uint8_t padding[5];
} __PACKED__;

/** Test response */
struct omci_msg_test_rsp {
	/** Message header */
	struct omci_header header;

	/** Result, reason */
	uint8_t result;

	/** Padding */
	uint8_t padding[31];
} __PACKED__;

/** Start SW download message */
struct omci_msg_start_dl {
	/** Message header */
	struct omci_header header;

	/** Window size - 1 */
	uint8_t window_size;
	/** Image size in bytes */
	uint32_t image_size;
	/** Number of circuit packs to be updated in parallel (value 1..9) */
	uint8_t update_num;
	/** Software image ME ids for additional simultaneous downloads */
	uint16_t sw_img_inst[9];

	/** Padding */
	uint8_t padding[8];
} __PACKED__;

/** Start SW download response */
struct omci_msg_start_dl_rsp {
	/** Message header */
	struct omci_header header;

	/** Result, reason */
	uint8_t result;
	/** Window size - 1 */
	uint8_t window_size;
	/** Number of instances responding (value 0..9) */
	uint8_t update_num;

	/** Additional software image instance requests */
	struct {
		/** Additional software image instance */
		uint16_t sw_img_inst;

		/** Result, reason for additional software image instance */
		uint8_t result;
	} __PACKED__ req[9];

	uint8_t padding[2];
} __PACKED__;

/** Download section message */
struct omci_msg_dl_section {
	/** Message header */
	struct omci_header header;

	/** Download section number */
	uint8_t sect_num;
	/** Data */
	uint8_t data[31];
} __PACKED__;

/** Download section response */
struct omci_msg_dl_section_rsp {
	/** Message header */
	struct omci_header header;

	/** Result, reason */
	uint8_t result;
	/** Download section number */
	uint8_t sect_num;

	/** Padding */
	uint8_t padding[30];
} __PACKED__;

/** End SW download message */
struct omci_msg_end_dl {
	/** Message header */
	struct omci_header header;

	/** CRC-32 (ITU-T I.363.5) */
	uint32_t crc;
	/** Image size in bytes */
	uint32_t image_size;

	/** Number of parallel download instances sent in this message */
	uint8_t update_num;
	/** Software image ME ids for additional simultaneous downloads */
	uint16_t sw_img_inst[9];

	/** Padding */
	uint8_t padding[5];
} __PACKED__;

/** End SW download response */
struct omci_msg_end_dl_rsp {
	/** Message header */
	struct omci_header header;

	/** Result, reason */
	uint8_t result;
	/** Number of instances responding */
	uint8_t update_num;

	/** Additional software image instance requests */
	struct {
		/** Additional software image instance */
		uint16_t sw_img_inst;
		/** Result, reason for additional software image instance */
		uint8_t result;

	} __PACKED__ req[9];

	/** Padding */
	uint8_t padding[3];
} __PACKED__;

/** Activate image message */
struct omci_msg_activate_image {
	/** Message header */
	struct omci_header header;

	/** Padding */
	uint8_t padding[32];
} __PACKED__;

/** Activate image response */
struct omci_msg_activate_image_rsp {
	/** Message header */
	struct omci_header header;

	/** Result, reason */
	uint8_t result;

	/** Padding */
	uint8_t padding[31];
} __PACKED__;

/** Commit image message */
struct omci_msg_commit_image {
	/** Message header */
	struct omci_header header;

	/** Padding */
	uint8_t padding[32];
} __PACKED__;

/** Commit image response */
struct omci_msg_commit_image_rsp {
	/** Message header */
	struct omci_header header;

	/** Result, reason */
	uint8_t result;

	/** Padding */
	uint8_t padding[31];
} __PACKED__;

/** Synchronize time message (G.988 Table 11.2.2-1) */
struct omci_msg_sync_time {
	/** Message header */
	struct omci_header header;

	/** Year */
	uint16_t year;
	/** Month (1-12) */
	uint8_t month;
	/** Day of month (1-31) */
	uint8_t day;
	/** Hour (0-23) */
	uint8_t hour;
	/** Minute (0-59) */
	uint8_t minute;
	/** Second (0-59) */
	uint8_t second;

	/** Padding */
	uint8_t padding[25];
} __PACKED__;

/** Synchronize time response */
struct omci_msg_sync_time_rsp {
	/** Message header */
	struct omci_header header;

	/** Result, reason */
	uint8_t result;

	/** Padding */
	uint8_t padding[31];
} __PACKED__;

/** Reboot message */
struct omci_msg_reboot {
	/** Message header */
	struct omci_header header;

	/** Padding */
	uint8_t padding[32];
} __PACKED__;

/** Reboot response */
struct omci_msg_reboot_rsp {
	/** Message header */
	struct omci_header header;

	/** Result, reason */
	uint8_t result;

	/** Padding */
	uint8_t padding[31];
} __PACKED__;

/** Get next message */
struct omci_msg_get_next {
	/** Message header */
	struct omci_header header;

	/** Attribute mask */
	uint16_t attr_mask;
	/** Command sequence number */
	uint16_t seq_num;

	/** Padding */
	uint8_t padding[28];
} __PACKED__;

/** Get next response */
struct omci_msg_get_next_rsp {
	/** Message header */
	struct omci_header header;

	/** Result, reason */
	uint8_t result;
	/** Attribute mask */
	uint16_t attr_mask;
	/** Attribute value (size depending on the type of attribute) */
	uint8_t values[29];
} __PACKED__;

/** ONU-G self-test result */
struct omci_msg_str_onu_g {
	/** Message header */
	struct omci_header header;

	/** Unused */
	uint8_t unused;
	/** Self test result */
	uint8_t result;

	/** Padding */
	uint8_t padding[30];
} __PACKED__;

/** Circuit pack self-test result */
struct omci_msg_str_circuit_pack {
	/** Message header */
	struct omci_header header;

	/** Unused */
	uint8_t unused;
	/** Self test result */
	uint8_t result;

	/** Padding */
	uint8_t padding[30];
} __PACKED__;

/** ONU-G vendor-specific test result */
struct omci_msg_str_vendor_onu_g {
	/** Message header */
	struct omci_header header;

	/** Type 1 */
	uint8_t type1;
	/** Value 1 */
	uint16_t value1;
	/** Type 2 */
	uint8_t type2;
	/** Value 2 */
	uint16_t value2;
	/** Type 3 */
	uint8_t type3;
	/** Value 3 */
	uint16_t value3;
	/** Type 4 */
	uint8_t type4;
	/** Value 4 */
	uint16_t value4;
	/** Type 5 */
	uint8_t type5;
	/** Value 5 */
	uint16_t value5;
	/** Type 6 */
	uint8_t type6;
	/** Value 6 */
	uint16_t value6;
	/** Type 7 */
	uint8_t type7;
	/** Value 7 */
	uint16_t value7;
	/** Type 8 */
	uint8_t type8;
	/** Value 8 */
	uint16_t value8;
	/** Type 9 */
	uint8_t type9;
	/** Value 9 */
	uint16_t value9;
	/** Type 10 */
	uint8_t type10;
	/** Value 10 */
	uint16_t value10;

	/** Padding */
	uint8_t padding[2];
} __PACKED__;

/** Circuit pack vendor-specific test result */
struct omci_msg_str_vendor_circuit_pack {
	/** Message header */
	struct omci_header header;

	/** Type 1 */
	uint8_t type1;
	/** Value 1 */
	uint16_t value1;
	/** Type 2 */
	uint8_t type2;
	/** Value 2 */
	uint16_t value2;
	/** Type 3 */
	uint8_t type3;
	/** Value 3 */
	uint16_t value3;
	/** Type 4 */
	uint8_t type4;
	/** Value 4 */
	uint16_t value4;
	/** Type 5 */
	uint8_t type5;
	/** Value 5 */
	uint16_t value5;
	/** Type 6 */
	uint8_t type6;
	/** Value 6 */
	uint16_t value6;
	/** Type 7 */
	uint8_t type7;
	/** Value 7 */
	uint16_t value7;
	/** Type 8 */
	uint8_t type8;
	/** Value 8 */
	uint16_t value8;
	/** Type 9 */
	uint8_t type9;
	/** Value 9 */
	uint16_t value9;
	/** Type 10 */
	uint8_t type10;
	/** Value 10 */
	uint16_t value10;

	/** Padding */
	uint8_t padding[2];
} __PACKED__;

/** PPTP POTS UNI test result */
struct omci_msg_tr_pots_uni {
	/** Message header */
	struct omci_header header;

	/** MLT drop test result */
	uint8_t mlt_drop;
	/** Result of self test or vendor-specific test */
	uint8_t result;
	/** Dial tone make-break flags */
	uint8_t dt_meke_break;
	/** Dial tone power flags */
	uint8_t dt_power;
	/** Loop test DC voltage flags */
	uint8_t loop_dc_voltage;
	/** Loop test AC voltage flags */
	uint8_t loop_ac_voltage;
	/** Loop test resistance flags 1 */
	uint8_t loop_resistance1;
	/** Loop test resistance flags 2 */
	uint8_t loop_resistance2;
	/** Time to draw dial tone, in 0.1 second units */
	uint8_t dt_draw_time;
	/** Time to break dial tone, in 0.1 second units */
	uint8_t dt_break_time;
	/** Total dial tone power measurement, unsigned absolute value */
	uint8_t total_dt_power;
	/** Quiet channel power measurement, unsigned absolute value */
	uint8_t quiet_channel_power;
	/** Tip-ground DC voltage */
	uint16_t tg_dc_voltage;
	/** Ring-ground DC voltage */
	uint16_t rg_dc_voltage;
	/** Tip-ground AC voltage */
	uint8_t tg_ac_voltage;
	/** Ring-ground AC voltage */
	uint8_t rg_ac_voltage;
	/** Tip-ground DC resistance */
	uint16_t tg_dc_resistance;
	/** Ring-ground DC resistance */
	uint16_t rg_dc_resistance;
	/** Tip-ring DC resistance */
	uint16_t tr_dc_resistance;
	/** Ringer equivalence */
	uint8_t ringer_equiv;
	/** Pointer to a general purpose buffer ME. Valid only for
	   vendor-specific tests that require a GP buffer */
	uint16_t buffer_pointer;

	/** Padding */
	uint8_t padding[5];
} __PACKED__;

/** PPTP ISDN UNI test result */
struct omci_msg_tr_pptp_isdn_uni {
	/** Message header */
	struct omci_header header;

	/** MLT drop test result */
	uint8_t mlt_drop;
	/** Result of self test or vendor-specific test */
	uint8_t result;
	/** Dial tone make-break flags */
	uint8_t dt_meke_break;
	/** Dial tone power flags */
	uint8_t dt_power;
	/** Loop test DC voltage flags */
	uint8_t loop_dc_voltage;
	/** Loop test AC voltage flags */
	uint8_t loop_ac_voltage;
	/** Loop test resistance flags 1 */
	uint8_t loop_resistance1;
	/** Loop test resistance flags 2 */
	uint8_t loop_resistance2;
	/** Time to draw dial tone, in 0.1 second units */
	uint8_t dt_draw_time;
	/** Time to break dial tone, in 0.1 second units */
	uint8_t dt_break_time;
	/** Total dial tone power measurement, unsigned absolute value */
	uint8_t total_dt_power;
	/** Quiet channel power measurement, unsigned absolute value */
	uint8_t quiet_channel_power;
	/** Tip-ground DC voltage */
	uint16_t tg_dc_voltage;
	/** Ring-ground DC voltage */
	uint16_t rg_dc_voltage;
	/** Tip-ground AC voltage */
	uint8_t tg_ac_voltage;
	/** Ring-ground AC voltage */
	uint8_t rg_ac_voltage;
	/** Tip-ground DC resistance */
	uint16_t tg_dc_resistance;
	/** Ring-ground DC resistance */
	uint16_t rg_dc_resistance;
	/** Tip-ring DC resistance */
	uint16_t tr_dc_resistance;
	/** Ringer equivalence */
	uint8_t ringer_equiv;
	/** Pointer to a general purpose buffer ME. Valid only for
	   vendor-specific tests that require a GP buffer */
	uint16_t buffer_pointer;

	/** Padding */
	uint8_t padding[5];
} __PACKED__;

/** IP host config data test result */
struct omci_msg_tr_ip_host_config {
	/** Message header */
	struct omci_header header;

	/** Test result */
	uint8_t result;
	/** Test result contents */
	uint8_t contents[31];
} __PACKED__;

/** ANI-G test result */
struct omci_msg_tr_ani_g {
	/** Message header */
	struct omci_header header;

	/** Type = 1, Power feed voltage */
	uint8_t type1;
	/** V, 2s complement, 20 mV resolution */
	uint16_t value1;
	/** Type = 3, Received optical power */
	uint8_t type3;
	/** dBmW, 2s compliment, 0.002 dB resolution */
	uint16_t value3;
	/** Type = 5, Transmitted optical power */
	uint8_t type5;
	/** dBmW, 2s compliment, 0.002 dB resolution */
	uint16_t value5;
	/** Type = 9, Laser bias current */
	uint8_t type9;
	/** Unsigned integer, 2 mA resolution */
	uint16_t value9;
	/** Type = 12, Temperature, degrees */
	uint8_t type12;
	/** 2s compliment, 1/256 degree C resolution */
	uint16_t value12;

	/** Padding */
	uint8_t padding[17];
} __PACKED__;

/** Get current data message */
struct omci_msg_get_curr_data {
	/** Message header */
	struct omci_header header;

	/** Attribute mask */
	uint16_t attr_mask;

	/** Padding */
	uint8_t padding[30];
} __PACKED__;

/** Get current data response */
struct omci_msg_get_curr_data_rsp {
	/** Message header */
	struct omci_header header;

	/** Result, reason */
	uint8_t result;
	/** Attribute mask */
	uint16_t attr_mask;
	/** Attribute values of the attributes included (size depending on the
	   type of attribute) */
	uint8_t values[25];
	/** Optional attribute mask, used with \ref OMCI_MR_ATTR_FAILED result */
	uint16_t opt_attr_mask;
	/** Attribute execution mask, used with \ref OMCI_MR_ATTR_FAILED result */
	uint16_t attr_exec_mask;
} __PACKED__;

/** OMCI Message union */
union omci_msg {
	/** Plain message */
	struct omci_msg_msg msg;
	/** Plain response */
	struct omci_msg_rsp msg_rsp;
	/** Create message */
	struct omci_msg_create create;
	/** Create response */
	struct omci_msg_create_rsp create_rsp;
	/** Delete message */
	struct omci_msg_delete delete;
	/** Delete response */
	struct omci_msg_delete_rsp delete_rsp;
	/** Set message */
	struct omci_msg_set set;
	/** Set response */
	struct omci_msg_set_rsp set_rsp;
	/** Get message */
	struct omci_msg_get get;
	/** Get response */
	struct omci_msg_get_rsp get_rsp;
	/** Get table response */
	struct omci_msg_get_tbl_rsp get_tbl_rsp;
	/** Get all alarms message */
	struct omci_msg_get_all_alarms get_all_alarms;
	/** Get all alarms response */
	struct omci_msg_get_all_alarms_rsp get_all_alarms_rsp;
	/** Get all alarms next message */
	struct omci_msg_get_all_alarms_next get_all_alarms_next;
	/** Get all alarms next response */
	struct omci_msg_get_all_alarms_next_rsp get_all_alarms_next_rsp;
	/** MIB upload message */
	struct omci_msg_mib_upload mib_upload;
	/** MIB upload response */
	struct omci_msg_mib_upload_rsp mib_upload_rsp;
	/** MIB upload next message */
	struct omci_msg_mib_upload_next mib_upload_next;
	/** MIB upload next response */
	struct omci_msg_mib_upload_next_rsp mib_upload_next_rsp;
	/** MIB reset message */
	struct omci_msg_mib_reset mib_reset;
	/** MIB reset response */
	struct omci_msg_mib_reset_rsp mib_reset_rsp;
	/** Alarm message */
	struct omci_msg_alarm alarm;
	/** AVC message */
	struct omci_msg_avc avc;
	/** Test message (for ONU-G) */
	struct omci_msg_test_onu_g test_onu_g;
	/** Test message (for Circuit pack) */
	struct omci_msg_test_circuit_pack test_circuit_pack;
	/** Test message (for IP host config) */
	struct omci_msg_test_ip_host_config test_ip_host_config;
	/** Test message (for PORT UNI) */
	struct omci_msg_test_pots_uni test_pots_uni;
	/** Test message (for PPTP ISDN UNI) */
	struct omci_msg_test_pptp_isdn_uni test_pptp_isdn_uni;
	/** Test response */
	struct omci_msg_test_rsp test_rsp;
	/** Start software download message */
	struct omci_msg_start_dl start_dl;
	/** Start software download response */
	struct omci_msg_start_dl_rsp start_dl_rsp;
	/** Download section message */
	struct omci_msg_dl_section dl_section;
	/** Download section response */
	struct omci_msg_dl_section_rsp dl_section_rsp;
	/** End software download message */
	struct omci_msg_end_dl end_dl;
	/** End software download response */
	struct omci_msg_end_dl_rsp end_dl_rsp;
	/** Activate image message */
	struct omci_msg_activate_image activate_image;
	/** Activate image response */
	struct omci_msg_activate_image_rsp activate_image_rsp;
	/** Commit image message */
	struct omci_msg_commit_image commit_image;
	/** Commit image response */
	struct omci_msg_commit_image_rsp commit_image_rsp;
	/** Synchronize time message */
	struct omci_msg_sync_time sync_time;
	/** Synchronize time response */
	struct omci_msg_sync_time_rsp sync_time_rsp;
	/** Reboot message */
	struct omci_msg_reboot reboot;
	/** Reboot response */
	struct omci_msg_reboot_rsp reboot_rsp;
	/** Get next message */
	struct omci_msg_get_next get_next;
	/** Get next response */
	struct omci_msg_get_next_rsp get_next_rsp;
	/** Self-test result (for ONU-G) */
	struct omci_msg_str_onu_g onu_g;
	/** Self-test result (for Circuit pack) */
	struct omci_msg_str_circuit_pack circuit_pack;
	/** Vendor specific test result (for ONU-G) */
	struct omci_msg_str_vendor_onu_g vendor_on_u_g;
	/** Vendor specific test result (for Circuit pack) */
	struct omci_msg_str_vendor_circuit_pack vendor_circuit_pack;
	/** Test result (for POTS UNI) */
	struct omci_msg_tr_pots_uni tr_pots_uni;
	/** Test result (for PPTP ISDN UNI) */
	struct omci_msg_tr_pptp_isdn_uni tr_pptp_isdn_uni;
	/** Test result (for IP Host Config) */
	struct omci_msg_tr_ip_host_config tr_ip_host_config;
	/** Test result (for ANI-G) */
	struct omci_msg_tr_ani_g tr_ani_g;
	/** Get current data message */
	struct omci_msg_get_curr_data get_curr_data;
	/** Get current data response */
	struct omci_msg_get_curr_data_rsp get_curr_data_rsp;
} __PACKED__;

#ifndef SWIG
/** Get OMCI Message type Mt field */
static inline uint8_t omci_msg_type_mt_get(const union omci_msg *const msg)
{
	return msg->msg.header.type & ~0xe0;
}

/** Get OMCI Message type Ak field */
static inline uint8_t omci_msg_type_ak_get(const union omci_msg *msg)
{
	return (msg->msg.header.type & 0x20) >> 5;
}

/** Get OMCI Message type Ar field */
static inline uint8_t omci_msg_type_ar_get(const union omci_msg *msg)
{
	return (msg->msg.header.type & 0x40) >> 6;
}

/** Get OMCI Message type Db field */
static inline uint8_t omci_msg_type_db_get(const union omci_msg *msg)
{
	return (msg->msg.header.type & 0x80) >> 7;
}

/** Set OMCI Message type Mt field */
static inline void omci_msg_type_mt_set(union omci_msg *msg, uint8_t val)
{
	msg->msg.header.type = (msg->msg.header.type & 0xe0) | val;
}

/** Set OMCI Message type Ak field */
static inline void omci_msg_type_ak_set(union omci_msg *msg, uint8_t val)
{
	msg->msg.header.type = (msg->msg.header.type & ~0x20) | (val << 5);
}

/** Set OMCI Message type Ar field */
static inline void omci_msg_type_ar_set(union omci_msg *msg, uint8_t val)
{
	msg->msg.header.type = (msg->msg.header.type & ~0x40) | (val << 6);
}

/** Set OMCI Message type Db field */
static inline void omci_msg_type_db_set(union omci_msg *msg, uint8_t val)
{
	msg->msg.header.type = (msg->msg.header.type & ~0x80) | (val << 7);
}
#endif

/** @} */

__END_DECLS

#endif
