/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _drv_onu_api_h
#define _drv_onu_api_h

/** \defgroup ONU_MAPI_REFERENCE_INTERNAL Management API Reference - Internals
   @{
*/

/** \defgroup ONU_COMMON_INTERNAL Common Driver Interface

   This chapter describes the generic part of the internal driver interface.

   @{
*/

/* exclude some parts from SWIG generation */
#ifndef SWIG

#if defined(LINUX) && defined(__KERNEL__)
#include <linux/seq_file.h>
#endif

#ifdef HAVE_CONFIG_H
#include "drv_onu_config.h"
#endif

#include "ifx_fifo.h"
#include "ifxos_select.h"
#include "ifxos_debug.h"
#include "ifxos_mutex.h"
#include "ifxos_thread.h"
#if !defined(__KERNEL__) && !defined(ONU_LIBRARY)
#include "ifxos_print_io.h"
#endif
#endif /* #ifndef SWIG*/

#include "drv_onu_std_defs.h"
#ifdef ONU_SIMULATION
#  include "drv_onu_devio.h"
#endif
#include "drv_onu_error.h"
#include "drv_onu_debug.h"
#include "drv_onu_resource.h"
#include "drv_onu_types.h"
#include "drv_onu_ploam_interface.h"
#include "drv_onu_common_interface.h"	/* struct onu_dbg_level */
#include "drv_onu_gpe_interface.h"
#include "drv_onu_gtc_interface.h"
#include "drv_onu_lan_interface.h"
#include "drv_onu_lan_api_intern.h"
#include "drv_onu_interface.h"
#include "drv_onu_event_interface.h"
#ifdef INCLUDE_CLI_DUMP_SUPPORT
#  include "drv_onu_cli_dump.h"
#  include "drv_onu_cli_dump_misc.h"
#endif

#ifndef SWIG

EXTERN_C_BEGIN

/** Select one of the available device types that matches the target hardware:
   - PSB98010
   - PSB98020
   - PSB98030

   \remark Selection of a device type that does not match the target hardware
           will lead to system malfunction.
*/
#ifndef ONU_DEVICE_PSB980xx
#define ONU_DEVICE_PSB980xx ONU_DEVICE_PSB98010
#endif

/* The device-specific include file is selected here */
#if (ONU_DEVICE_PSB980xx == ONU_DEVICE_PSB98010)
#include "drv_onu_resource_device_psb98010.h"
#endif

#if (ONU_DEVICE_PSB980xx == ONU_DEVICE_PSB98020)
#include "drv_onu_resource_device_psb98020.h"
#endif

#if (ONU_DEVICE_PSB980xx == ONU_DEVICE_PSB98030)
#include "drv_onu_resource_device_psb98030.h"
#endif

#include "drv_onu_resource_gpe_tables.h"

/** OMCI GPIX */
#define OMCI_GPIX                          (ONU_GPE_MAX_GPIX - 1)

#ifndef ARRAY_SIZE
#   define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#ifndef MIN
#   define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif

#ifndef offsetof
#   define offsetof(STRUCT, MEMBER) ((size_t) &((STRUCT *) 0)->MEMBER )
#endif
/** maximum instances of this driver (GPON hardware) */
#ifndef MAX_ONU_INSTANCES
#  define MAX_ONU_INSTANCES            1
#endif
/** worker thread stack size */
#define ONU_WORKER_THREAD_STACK_SIZE   512
/* worker thread priority */
#define ONU_WORKER_THREAD_PRIO         64
/** max element size of the notification FIFO */
#define ONU_FIFO_ELEM_SIZE             64
#ifdef INCLUDE_CLI_DUMP_SUPPORT
/** size of the notification FIFO */
#  define ONU_FIFO_SIZE                  16*8*512
#else
/** size of the notification FIFO */
#  define ONU_FIFO_SIZE                  8*512
#endif

#define ONU_VER_FW_MIN_MAJOR  0
#define ONU_VER_FW_MIN_MINOR  3
#define ONU_VER_FW_MIN_PATCH  27
#define ONU_VER_FW_MIN_INTERN 1

#define ONU_FW_VERSION(p, pe_idx) (((p)->pe_fw[pe_idx].ver.major << 24) + \
  ((p)->pe_fw[pe_idx].ver.minor << 16) + ((p)->pe_fw[pe_idx].ver.patch << 8) + \
  ((p)->pe_fw[pe_idx].ver.internal))

#define ONU_FW_VERSION_MIN \
	((ONU_VER_FW_MIN_MAJOR << 24) + (ONU_VER_FW_MIN_MINOR << 16) + \
	(ONU_VER_FW_MIN_PATCH << 8) + ONU_VER_FW_MIN_INTERN)

/** FIFO management entity */
struct onu_fifo {
#ifdef __KERNEL__
	/**
	FIFO lock */
	spinlock_t lock;
#else
	/**
	FIFO lock */
	IFXOS_mutex_t lock;
#endif
	/**
	non-zero if FIFO should be used */
	uint32_t mask;
	/**
	FIFO overhead */
	IFX_VFIFO data;
	/**
	FIFO buffer by itself */
	uint8_t buf[ONU_FIFO_SIZE];
	/**
	number of lost elements */
	uint32_t lost;
	/**
	overflow condition detected */
	bool overflow;
	/**
	FIFO name */
	const char *name;
};

/**
   PLOAM Context
*/
struct ploam_context {
	/** current FSM state */
	enum ploam_state curr_state;
	/** previous FSM state */
	enum ploam_state previous_state;
	/** elapsed milliseconds */
	uint32_t elapsed_msec;
	/** elapsed seconds to/out of O5 */
	uint32_t o5_change_elapsed_sec;
	/** ONU Event to handle */
	uint32_t event;
	/** ONU-ID */
	uint8_t onu_id;
	/** Vendor ID / Vendor SN */
	uint8_t vendor_sn[8];
	/** GEM-Port-ID */
	uint8_t gem_port_id;
	/** Counter for Serial_Number_request events in the O3 State */
	uint8_t snrequest_count;
	/** Number of guard bits */
	uint16_t guard_bits;
	/** Number of type 1 preamble bits */
	uint16_t t1_bits;
	/** Number of type 2 preamble bits */
	uint16_t t2_bits;

	/** Number of Type 3 preamble bytes to be used while the ONU remains in
	    the "pre-ranged" states: Serial_Number State (O3) and Ranging State
	    (O4).  Each byte of the Type 3 preamble contains the pattern
	    specified in Octet 6 of the "Upstream_Overhead" message.

	    \see G.984.3 9.2.3.20 */
	uint16_t t3_pre_ranged_bits;
	/** Number of Type 3 preamble bytes to be used after the ONU enters the
	    Operation State (O5). Each byte of the Type 3 preamble contains the
	    pattern specified in Octet 6 of the "Upstream_Overhead" message.

	    \see G.943.3 9.2.3.20 */
	uint16_t t3_ranged_bits;
	/** Pattern to be used for Type 3 preamble bits */
	uint8_t t3_pattern;
	/** data to be programmed in delimiter */
	uint8_t delimiter[3];
	/** Pre-assigned Delay */
	uint16_t padelay;
	/** Random Delay */
	uint16_t rand_delay;
	/** Equalization Delay */
	uint32_t ranged_delay;
	/** Equalization Delay (fine range) */
	uint32_t fine_ranged_delay;
	/** OMCI connection Port-ID */
	uint16_t omci_port_id;
	/** downstream message */
	struct ploam_msg ds_msg;
	/** downstream message */
	struct ploam_msg ds_msg_previous;
	/** repeat count of downstream message */
	uint8_t ds_repeat_count;
	/** PLOAM password */
	uint8_t password[PLOAM_FIELD_PASSWORD_LEN];
	/** Signal Fail threshold */
	uint8_t sf_threshold;
	/** Signal Degrade threshold */
	uint8_t sd_threshold;
	/** downstream Physical Equipment Error detected */
	bool ds_pee;
	/** downstream Physical Equipment Error seconds */
	uint32_t ds_count_pee;
	/** REI sequence number */
	uint8_t rei_seq_num;
	/** downstream irq mask */
	uint32_t dsimask;
	/** upstream irq mask */
	uint32_t usimask;
	/** last BWMAP status */
	uint32_t bwmstat;
	/** bwmap status irq mask */
	uint32_t bwmmask;
	/** sstart_min value */
	uint16_t sstart_min;
	/** current start offset value */
	uint16_t offset_curr;
	/** start offset correction value */
	int16_t offset_corr;
	/** forced start offset value for state O5*/
	uint16_t offset_o5;
	/** TBD*/
	bool sn_mode;
	/** current power level */
	uint8_t powerlevel;
	/** last PON-ID information */
	struct ploam_dn_pon_id pon_id;
	/** TO1 value, given in multiples of 1 ms */
	uint32_t ploam_timeout_1;
	/** TO2 value, given in multiples of 1 ms */
	uint32_t ploam_timeout_2;
	/** set to 1 to force emergency stop state (O7) */
	uint32_t emergency_stop_state;
	/** points to the control structure */
	void *ctrl;
};

enum gpe_chip {
	GPE_CHIP_UNKNOWN = 0,
	GPE_CHIP_A11 = 0xA11,
	GPE_CHIP_A12 = 0xA12,
	GPE_CHIP_A21 = 0xA21
};

/** device related data */
struct onu_device {
#ifndef ONU_LIBRARY
	/** support for select() */
	IFXOS_drvSelectQueue_t select_queue;
#endif
	/** buffer for ioctl operation */
	uint8_t io_buf[ONU_IO_BUF_SIZE];
#ifdef INCLUDE_CLI_DUMP_SUPPORT
	/** buffer for ioctl trace dump*/
	char io_trace_buf[ONU_IOCTL_TRACE_MAX_SIZE_BYTE];
#endif
	/** notification FIFO */
	struct onu_fifo nfc_fifo;
	/** */
	bool nfc_need_wake_up;
	/** PLOAM related data */
	struct ploam_context *ploam_ctx;
	/** previous device */
	void *p_previous;
	/** next device */
	void *p_next;
	/** control structure */
	void *ctrl;
	/** helper pointer for CLI */
	char *help_out;
	/** helper variable for CLI */
	int32_t help_out_len;
	/** helper variable for CLI */
	int32_t help_max_len;
};

#ifdef __KERNEL__
typedef spinlock_t onu_lock_t;
typedef struct semaphore onu_sema_t;
#define onu_snprintf snprintf
#elif !defined(ONU_LIBRARY)
typedef IFXOS_mutex_t onu_lock_t;
typedef IFXOS_mutex_t onu_sema_t;
#define onu_snprintf IFXOS_SNPrintf
#else
typedef unsigned int onu_lock_t;
typedef unsigned int onu_sema_t;
#define onu_snprintf snprintf
#endif
#if defined(ONU_LIBRARY)
#define onu_spin_lock_init(id, p_name) (0)
#define onu_spin_lock_delete(id) (0)
#define onu_spin_lock_get(id, flags) (void)id; (void)flags;
#define onu_spin_lock_release(id, flags)
#else
int32_t onu_spin_lock_init(onu_lock_t *id, const char *p_name);
int32_t onu_spin_lock_delete(onu_lock_t *id);
int32_t onu_spin_lock_get(onu_lock_t *id, ulong_t *flags);
int32_t onu_spin_lock_release(onu_lock_t *id, ulong_t flags);
#endif

#define ONU_COUNTER_ACC          0
#define ONU_COUNTER_THRESHOLD    1
#define ONU_COUNTER_SHADOW       2

#define ONU_MAX_RX_CALLBACKS     4
#define ONU_MAX_STATUS_CALLBACKS 4

#define ONU_MAX_COP_SIZE         1024*8

#define ONU_GPE_DS_BUF_SIZE      2048
#define ONU_GPE_DS_CRC_SIZE      4
#define ONU_GPE_LINK_BUF_SIZE    36


/** firmware information */
struct onu_firmware {
	/** major version number */
	uint8_t major;
	/** minor version number */
	uint8_t minor;
	/** patch version */
	uint8_t patch;
	/** internal version */
	uint8_t internal;
	/** Firmware pointer. */
	uint32_t *data;
	/** Firmware length. */
	uint16_t len;
};

struct onu_control;

typedef enum onu_errorcode (*lan_port_en_fct_t) (struct onu_control *ctrl,
				  const uint8_t port_num, const bool enable);

typedef enum onu_errorcode (*lan_port_status_fct_t) (struct onu_control *ctrl,
				      const uint8_t port_num);

/** instance related data */
struct onu_control {
	/** GEM counter */
	struct gpe_cnt_gem_val gem_cnt[2][3][ONU_GPE_MAX_GPIX];
	/** LAN counter */
	struct lan_cnt_val lan_cnt[2][3][ONU_GPE_MAX_ETH_UNI];
	/** Bridge counter */
	struct gpe_cnt_bridge_val bridge_cnt[2][3][ONU_GPE_MAX_BRIDGES];
	/** GTC counter, threshold, shadow */
	struct gtc_cnt_value gtc_counter[2][3];
	/** garbage collection packet counter */
	uint32_t gc_count[ONU_GPE_MAX_EGRESS_PORT];
	/** Bridge port counter */
	struct gpe_cnt_bridge_port_val bridge_port_cnt[2][3][ONU_GPE_MAX_BRIDGE_PORT];
	/** successfully initialized the onu modules */
	bool init;
	/** successfully initialized GPE (\ref gpe_init) */
	bool gpe_init;
	/** Number of PEs*/
	uint8_t num_pe;
#ifndef ONU_LIBRARY
	/** run flag for the worker thread */
	bool run_worker;
	/** lock for device list handling */
	IFXOS_mutex_t list_lock;
	/** worker thread context */
	IFXOS_ThreadCtrl_t worker_ctx;
	/** device list */
	struct onu_device *p_dev_head;
#endif
	/** PLOAM context */
	struct ploam_context ploam_ctx;
	/** FIFO to inform applications about status changes & PLOAM messages */
	struct onu_fifo nfc_fifo;
	/** counters access lock*/
	onu_lock_t cnt_lock;
	/** MDIO access lock*/
	onu_lock_t mdio_lock;
	/** pointer to the current counter arrays */
	uint8_t current_counter;
	/** enable 15 min supervision */
	bool b15_min_supervision;
	/** enable external counters intervals supervision*/
	bool interval_supervision_ext;
	/** external counters interval trigger*/
	bool interval_trigger_ext;
	/** 15 min supervision second counter */
	uint32_t b15_min_second;
	/** Counters configuration*/
	struct onu_cnt_cfg cnt_cfg;
	/** GPE schedulers track*/
	struct gpe_scheduler_track gpe_sched_track[ONU_GPE_MAX_SCHEDULER];
	/** GPE queue weights */
	uint16_t gpe_equeue_weight[ONU_GPE_MAX_EGRESS_QUEUES];
	/** Track max VLANs per extended VLAN entry. */
	uint32_t vlan_max_track[ONU_GPE_EXTENDED_VLAN_TABLE_SIZE];
	struct gpe_aging_trigger gpe_aging_trigger;
	/** GTC Total BIP Error counter */
	uint64_t gtc_total_berr;
	/** No Message PLOAMu message */
	uint8_t no_msg[12];
	/** "Dying Gasp" PLOAMu message */
	uint8_t dying_gasp_msg[12];
	/** No Message scrambling enable */
	bool no_msg_is_scrambled;
	/** global flag to indicate whether the PLOAM state machine is working
	   autonomous */
	bool ploam_fsm_enable;
	/** NET callbacks*/
	struct net_cb net_cb_list[ONU_NET_MAX_NETDEV_PORT];
	/** NET device*/
	struct net_dev net_dev;
	/** LAN port enable/disable status */
	bool lan_port_en_status[ONU_GPE_MAX_ETH_UNI];
	/** GMII lan port CLKO pin status */
	uint8_t lan_gmii_clko_status;
	/** LAN port lock*/
	onu_lock_t lan_lock[ONU_GPE_MAX_ETH_UNI];
	lan_port_en_fct_t lan_port_en_fct[ONU_GPE_MAX_ETH_UNI];
	lan_port_status_fct_t lan_port_sts_fct[ONU_GPE_MAX_ETH_UNI];
	/** LAN MDIO addresses */
	int8_t mdio_dev_addr[4];
	/** LAN port operation mode, select one of multiple modes */
	enum lan_interface_mux_mode lan_mux_mode;
	/** LAN port configuration data */
	struct lan_port_cfg lan_port_cfg[ONU_GPE_MAX_ETH_UNI];
	/** LAN port loop configuration data */
	struct lan_loop_cfg lan_loop_cfg[ONU_GPE_MAX_ETH_UNI];
	/** LAN Port status*/
	struct lan_link_status lan_link_status[ONU_GPE_MAX_ETH_UNI];
	/** mark the link as forced up in case of a loop */
	bool lan_force_link[ONU_GPE_MAX_ETH_UNI];
	/** LAN port WOL configuration data*/
	struct wol_cfg lan_wol_cfg[ONU_GPE_MAX_ETH_UNI];
	/** LAN port PHY capability */
	struct lan_port_capability_cfg lan_port_capability_cfg[ONU_GPE_MAX_ETH_UNI];
	/** GPHY firmware RAM address*/
	uint32_t lan_gphy_fw_ram_addr;
	/** GPHY firmware version*/
	uint8_t lan_gphy_fw_version[ONU_GPHY_FIRMWARE_VERSION_MAX];
	/** SCE firmware */
	struct pe_fw_info pe_fw[ONU_GPE_NUMBER_OF_PE_MAX];
	/** Hardware coprocessor microcode */
	uint8_t cop_microcode_bin[ONU_MAX_COP_SIZE];
	/** length microcode */
	uint32_t cop_microcode_len;
	/** COP LIST type table information for NIL bits */
	uint32_t cop_list_info[4][16];
	/** counter of upstream OMCI messages */
	uint32_t omci_upstream;
	/** counter of downstream OMCI messages */
	uint32_t omci_downstream;
	/** counter of dropped downstream OMCI messages */
	uint32_t omci_downstream_dropped;
#ifndef ONU_LIBRARY
	/** ioctl trace enabled flag */
	bool ioctl_trace;
	/** max. duration of ioctrls */
	unsigned long ioctrl_duration;
	/** ioctrl cmd with longest duration */
	unsigned long ioctrl_cmd;
	/** Enabled interrupts mask access semaphore*/
	onu_sema_t irq_mask_sema;
	/** enabled ONU interrupts mask */
	uint32_t irq_enabled_mask;
#endif
#ifdef __KERNEL__
	/** Worker thread completion */
	struct completion worker_completion;
#endif
	uint8_t ds_buffer[ONU_GPE_DS_BUF_SIZE + ONU_GPE_DS_CRC_SIZE];
	uint32_t link_fifo_data[ONU_GPE_LINK_BUF_SIZE];
	uint32_t link_fifo_pos;
};

/** register field info */
struct onu_reg_info {
	/** register field name */
	const char *p_name;
	/** register field mask */
	const uint32_t mask;
};

typedef enum onu_errorcode (*onu_function0_t) (struct onu_device *p_dev);
typedef enum onu_errorcode (*onu_function1_t) (struct onu_device *p_dev,
					       void *);
typedef enum onu_errorcode (*onu_function2_t) (struct onu_device *p_dev,
					       const void *, void *);
#ifdef INCLUDE_CLI_DUMP_SUPPORT
typedef int 		(*onu_dump_function_t) (char *p_out,
						const void *p_data_in);
#endif

struct onu_entry {
	uint32_t id;
#ifdef INCLUDE_DEBUG_SUPPORT
	char const *name;
#endif
	uint32_t size_in;
	uint32_t size_out;
	onu_function0_t p_entry0;
	onu_function1_t p_entry1;
	onu_function2_t p_entry2;
#ifdef INCLUDE_CLI_DUMP_SUPPORT
	onu_dump_function_t p_entry_dump;
#endif
};

struct onu_tm {
	/*
	* the number of seconds after the minute, normally in the range
	* 0 to 59, but can be up to 60 to allow for leap seconds
	*/
	uint8_t tm_sec;
	/* the number of minutes after the hour, in the range 0 to 59*/
	uint8_t tm_min;
	/* the number of hours past midnight, in the range 0 to 23 */
	uint8_t tm_hour;
	/* the day of the month, in the range 1 to 31 */
	uint8_t tm_mday;
	/* the number of months since January, in the range 0 to 11 */
	uint8_t tm_mon;
	/* the number of years since 1900 */
	uint16_t tm_year;
	/* the number of days since Sunday, in the range 0 to 6 */
	uint8_t tm_wday;
	/* the number of days since January 1, in the range 0 to 365 */
	uint16_t tm_yday;
};

#ifdef INCLUDE_DEBUG_SUPPORT
#	ifndef INCLUDE_CLI_DUMP_SUPPORT
#		define TE0(id, f0) \
		{id, #id, 0, 0, (onu_function0_t) f0, NULL, NULL}
#		define TE1in(id, in_size, f1) \
		{id, #id, in_size, 0, NULL, (onu_function1_t) f1, NULL}
#		define TE1out(id, out_size, f1) \
		{id, #id, 0, out_size, NULL, (onu_function1_t) f1, NULL}
#		define TE2(id, in_size, out_size, f2) \
		{id, #id, in_size, out_size, NULL, NULL, (onu_function2_t) f2}
#	else
#		define TE0(id, f0) \
		{id, #id, 0, 0, (onu_function0_t) f0, NULL, NULL, \
		(onu_dump_function_t)dump_##f0}
#		define TE1in(id, in_size, f1) \
		{id, #id, in_size, 0, NULL, (onu_function1_t) f1, NULL, \
		(onu_dump_function_t)dump_##f1}
#		define TE1out(id, out_size, f1) \
		{id, #id, 0, out_size, NULL, (onu_function1_t) f1, NULL, \
		(onu_dump_function_t)dump_##f1}
#		define TE2(id, in_size, out_size, f2) \
		{id, #id, in_size, out_size, NULL, NULL, (onu_function2_t) f2, \
		(onu_dump_function_t)dump_##f2}
#	endif
#else
#	ifndef INCLUDE_CLI_DUMP_SUPPORT
#		define TE0(id, f0) \
		{id, 0, 0, (onu_function0_t) f0, NULL, NULL}
#		define TE1in(id, in_size, f1) \
		{id, in_size, 0, NULL, (onu_function1_t) f1, NULL}
#		define TE1out(id, out_size, f1) \
		{id, 0, out_size, NULL, (onu_function1_t) f1, NULL}
#		define TE2(id, in_size, out_size, f2) \
		{id, in_size, out_size, NULL, NULL, (onu_function2_t) f2}
#	else
#		define TE0(id, f0) \
		{id, 0, 0, (onu_function0_t) f0, NULL, NULL, \
		(onu_dump_function_t)dump_##f0}
#		define TE1in(id, in_size, f1) \
		{id, in_size, 0, NULL, (onu_function1_t) f1, NULL, \
		(onu_dump_function_t)dump_##f1}
#		define TE1out(id, out_size, f1) \
		{id, 0, out_size, NULL, (onu_function1_t) f1, NULL, \
		(onu_dump_function_t)dump_##f1}
#		define TE2(id, in_size, out_size, f2) \
		{id, in_size, out_size, NULL, NULL, (onu_function2_t) f2, \
		(onu_dump_function_t)dump_##f2}
#	endif
#endif

#if defined(ONU_LIBRARY)
#	define TE0_opt(id, f0) TE0(id, NULL)
#	define TE1in_opt(id, in_size, f1) TE1in(id, 0, NULL)
#	define TE1out_opt(id, out_size, f1) TE1out(id, 0, NULL)
#	define TE2_opt(id, in_size, out_size, f2) TE2(id,0,  NULL, 0, NULL)
#else
#	define TE0_opt(id, f0) TE0(id, f0)
#	define TE1in_opt(id, in_size, f1) TE1in(id, in_size, f1)
#	define TE1out_opt(id, out_size, f1) TE1out(id, out_size, f1)
#	define TE2_opt(id, in_size, out_size, f2) TE2(id, in_size, out_size, f2)
#endif

/** GTC DS interrupt enable/disable flag  */
#define IRQ_GTC_DS_FLAG			(1<<0)
/** GTC US interrupt enable/disable flag  */
#define IRQ_GTC_US_FlAG			(1<<1)
/** IQM interrupt enable/disable flag  */
#define IRQ_IQM_FLAG			(1<<2)
/** TMU interrupt enable/disable flag  */
#define IRQ_TMU_FLAG			(1<<3)
/** Breakpoint interrupt enable/disable flag  */
#define IRQ_CONFIG_BREAK_FLAG		(1<<4)
/** Time Of Day interrupt enable/disable flag  */
#define IRQ_TOD_FLAG			(1<<5)
/** Link interface interrupt enable/disable flag */
#define IRQ_LINK_FLAG			(1<<6)

/** common timer handler */
enum onu_errorcode onu_timer_exec(struct onu_control *ctrl, ulong_t timer_no);

/**
   Initializes the corresponding driver instance

   \param ctrl device control
   \param p_dev     private device data

   \return
   - ONU_STATUS_OK           Success
   - ONU_STATUS_ERR          in case of error
   - ONU_STATUS_ALLOC_ERR    in case of memory allocation error
*/
enum onu_errorcode onu_device_open(struct onu_control *ctrl,
				   struct onu_device *p_dev);

/** device close function */
enum onu_errorcode onu_device_close(struct onu_device *p_dev);

/** get random number within given range */
uint32_t onu_random_get(uint32_t const range_min, uint32_t const range_max);

/** enable/disable the ONU interrupts */
void onu_irq_enable(struct onu_control *ctrl, uint32_t mask);
/** enable additional ONU interrupts without disabling already enabled */
void onu_irq_add(struct onu_control *ctrl, uint32_t mask);
/** disable ONU interrupts specified only by mask */
void onu_irq_remove(struct onu_control *ctrl, uint32_t mask);

/** delay micro seconds */
void onu_udelay(uint32_t u_sec);

/** inform the user space about ONU PLOAM state change */
void onu_hot_plug_state(const uint32_t state, const uint32_t old_state);

/** load PE firmware from user space */
int onu_pe_fw_load(const char *name, struct onu_fw *pe_fw);

/** release loaded firmware resource*/
void onu_fw_release(struct onu_fw *pe_fw);

/** load PE firmware information */
int onu_pe_fw_info_load(const struct onu_fw *pe_fw, struct pe_fw_info *info);

/** release PE firmware information */
void onu_pe_fw_info_release(struct pe_fw_info *info);

/** load microcode from user space */
int onu_microcode_load(struct onu_control *ctrl, const char *name);

/** load GPHY firmware from user space*/
int onu_gphy_firmware_download(struct onu_control *ctrl, const char *name);
/** converts the calendar time to local broken-down time*/
void onu_time_to_tm(uint32_t totalsecs, int offset, struct onu_tm *result);
/** returns elapsed time in seconds, based on  jiffies, since startup or
    with respect to given ref time*/
unsigned long onu_elapsed_time_sec_get(unsigned long ref);

#ifdef INCLUDE_CLI_SUPPORT
/** strsep() abstraction*/
char *onu_strsep(char **stringp, const char *delim);
#endif

/** execute Command Line instruction */
enum onu_errorcode onu_cli(struct onu_device *p_dev, char *param);

/** initialization of overhead resources (lock) */
enum onu_errorcode onu_fifo_init(struct onu_fifo *fifo, const char *p_name);

/** delete / free of overhead resources (lock) */
enum onu_errorcode onu_fifo_delete(struct onu_fifo *fifo);

/** add data to FIFO */
enum onu_errorcode onu_fifo_write(struct onu_fifo *fifo, const uint32_t control,
				  const void *buf, const uint32_t len);

/** add data to FIFO */
enum onu_errorcode onu_fifo_write_value(struct onu_fifo *fifo,
					const uint32_t control,
					const uint32_t value);

/** read data from FIFO */
enum onu_errorcode onu_fifo_read(struct onu_fifo *fifo, void *buf,
				 uint32_t *len);

/** add device to internal list */
enum onu_errorcode onu_device_list_add(struct onu_control *ctrl,
				       struct onu_device *p_dev);

/** remove device from internal list */
enum onu_errorcode onu_device_list_delete(struct onu_control *ctrl,
					  struct onu_device *p_dev);

/**
   PLOAM final state machine handler

   \param ctrl - device control
   \param timer_no - timer number (see drv_onu_timer.h)

   \return ONU_STATUS_OK if command was successfully handled
   \return ONU_STATUS_ERR on error

*/
enum onu_errorcode onu_gtc_ds_handle(struct onu_control *ctrl,
				     uint32_t timer_no);

/**
   GTC interrupt handler

   \param ctrl - device control

   \return ONU_STATUS_OK if command was successfully handled
   \return ONU_STATUS_ERR on error

*/
enum onu_errorcode gtc_us_handle(struct onu_control *ctrl);

#ifndef ONU_LIBRARY
/** ONU worker thread */
int32_t onu_worker_thread(IFXOS_ThreadParams_t *param);
#endif

/**
   Reset device

   \param p_dev  private device data

   \return ONU_STATUS_OK    Success
   \return ONU_STATUS_ERR   in case of error
*/
enum onu_errorcode onu_reset(struct onu_device *p_dev);

#define GEM_COUNTER		0x00000001UL
#define LAN_COUNTER		0x00000002UL
#define BRIDGE_COUNTER		0x00000004UL
#define GTC_COUNTER		0x00000008UL
#define BRIDGE_PORT_COUNTER	0x00000010UL

enum onu_errorcode onu_interval_counter_update(struct onu_control *ctrl,
					       const uint16_t index,
					       const uint32_t sel,
					       const uint64_t rst_mask,
					       const bool curr,
					       void *data);

int onu_counter_value_update(uint64_t *const dest, const uint64_t threshold,
			     uint64_t *const tca, uint64_t *const shadow,
			     const uint64_t cnt);

/** control structures */
extern struct onu_control onu_control[MAX_ONU_INSTANCES];

/** what string */
extern const char onu_whatversion[];

/** chip version */
extern enum gpe_chip gpe_chip_version;

#if !defined(CONFIG_WITH_FALCON_A1X) && !defined(CONFIG_WITH_FALCON_A2X)
/* support for all version as default */
#define CONFIG_WITH_FALCON_A1X
#define CONFIG_WITH_FALCON_A2X
#endif

#if defined(CONFIG_WITH_FALCON_A1X) && defined(CONFIG_WITH_FALCON_A2X)
static inline bool is_falcon_chip_a11(void)
{
	return (gpe_chip_version == GPE_CHIP_A11);
}
static inline bool is_falcon_chip_a12(void)
{
	return (gpe_chip_version == GPE_CHIP_A12);
}
static inline bool is_falcon_chip_a1x(void)
{
	return (gpe_chip_version <= GPE_CHIP_A12);
}
static inline bool is_falcon_chip_a2x(void)
{
	return (gpe_chip_version >= GPE_CHIP_A21);
}
#else
#ifdef CONFIG_WITH_FALCON_A2X
static inline bool is_falcon_chip_a11(void) { return false; }
static inline bool is_falcon_chip_a12(void) { return false; }
static inline bool is_falcon_chip_a1x(void) { return false; }
static inline bool is_falcon_chip_a2x(void) { return true; }
#else
static inline bool is_falcon_chip_a11(void)
{
	return (gpe_chip_version == GPE_CHIP_A11);
}
static inline bool is_falcon_chip_a12(void)
{
	return (gpe_chip_version == GPE_CHIP_A12);
}
static inline bool is_falcon_chip_a1x(void) { return true; }
static inline bool is_falcon_chip_a2x(void) { return false; }
#endif
#endif

enum onu_errorcode onu_locked_memcpy(onu_lock_t *lock,
				     void *to, const void *from,
				     size_t sz_byte);

bool onu_is_initialized(void);
#endif				/* SWIG */

#ifdef INCLUDE_DEBUG_SUPPORT
enum onu_errorcode onu_debug_level_set(struct onu_device *p_dev,
				       const struct onu_dbg_level *param);

enum onu_errorcode onu_debug_level_get(struct onu_device *p_dev,
				       struct onu_dbg_level *param);
#endif

enum onu_errorcode onu_version_get(struct onu_device *p_dev,
				   struct onu_version_string *param);

/**
   Write to hardware register.

   \param p_dev    device structure
   \param param     register structure

   \return
   ONU_STATUS_OK    Success
   ONU_STATUS_ERR   in case of error
*/
enum onu_errorcode onu_register_set(struct onu_device *p_dev,
				    const struct onu_reg_addr_val *param);

/**
   Read hardware register.

   \param p_dev      device structure
   \param param_in  register structure
   \param param_out register structure

   \return
   ONU_STATUS_OK    Success
   ONU_STATUS_ERR   in case of error
*/
enum onu_errorcode onu_register_get(struct onu_device *p_dev,
				    const struct onu_reg_addr *param_in,
				    struct onu_reg_val *param_out);

/**
   Set test modes.

   \param p_dev      device structure
   \param param  test mode structure

   \return
   ONU_STATUS_OK    Success
   ONU_STATUS_ERR   in case of error
*/
enum onu_errorcode onu_test_mode_set(struct onu_device *p_dev,
				     const struct onu_test_mode *param);

/**
   Enable or disable the line.

   In case that the line will be disabled the PLOAM state
   will be forced to O0.

   \param p_dev      device structure
   \param param     enable/disable flag

   \return
   ONU_STATUS_OK    Success
   ONU_STATUS_ERR   in case of error
*/
enum onu_errorcode onu_line_enable_set(struct onu_device *p_dev,
				       const struct onu_enable *param);

enum onu_errorcode onu_line_enable_get(struct onu_device *p_dev,
				       struct onu_enable *param);

enum onu_errorcode onu_sync_time_set(struct onu_device *p_dev,
				     const struct onu_sync_time *param);
enum onu_errorcode onu_sync_time_get(struct onu_device *p_dev,
				     struct onu_sync_time *param);
/**
   Set various configuration options for internal counters handling.


   \param p_dev      device structure
   \param param      configuration options

   \return
   ONU_STATUS_OK    Success
   ONU_STATUS_ERR   in case of error
*/
enum onu_errorcode onu_counters_cfg_set(struct onu_device *p_dev,
					const struct onu_cnt_cfg *param);
/**
   Get various configuration options for internal counters handling.


   \param p_dev      device structure
   \param param      configuration options

   \return
   ONU_STATUS_OK    Success
   ONU_STATUS_ERR   in case of error
*/
enum onu_errorcode onu_counters_cfg_get(struct onu_device *p_dev,
					struct onu_cnt_cfg *param);
/**
   Reset PM counter.

   \param p_dev      device structure
   \param param      reset configuration structure

   \return
   ONU_STATUS_OK    Success
   ONU_STATUS_ERR   in case of error
*/
enum onu_errorcode onu_counters_reset(struct onu_device *p_dev,
					const struct onu_cnt_reset *param);

/* enable register dump */
extern int reg_dump_enable;

#ifndef SWIG
/** Initialize event queue */
void event_queue_init(struct onu_control *ctrl);

/** Wait for incoming events */
int event_queue_wait(struct onu_control *ctrl);

/** Wake up event queue */
void event_queue_wakeup(struct onu_control *ctrl);

/** Add event to the notification/event fifo */
enum onu_errorcode event_add(struct onu_control *ctrl,
			     const unsigned long event_id,
			     const void *data,
			     const size_t data_size);

uint32_t onu_round_div(const uint32_t x, const uint32_t y);
/** Returns bit reversed value of input */
uint32_t onu_bit_rev(uint32_t x);
uint32_t onu_gpon_link_status_get(void);
uint32_t onu_mac_link_status_get(const uint8_t idx);
uint32_t onu_gpon_packet_count_get(const uint8_t rx);
uint32_t onu_mac_packet_count_get(const uint8_t idx, const uint8_t rx);
enum gpe_chip onu_chip_get(void);

void onu_ploam_state_change(struct onu_control *ctrl,
				const enum ploam_state curr_state,
				const enum ploam_state previous_state,
				const uint32_t elapsed_msec);

#ifndef PRE_GPE_INIT_CMD
#define PRE_GPE_INIT_CMD(c) c
#endif
/** Subset of commands which are allowed to be executed prior to GPE init */
#define PRE_GPE_INIT_COMMANDS \
	PRE_GPE_INIT_CMD(ploam_init), \
	PRE_GPE_INIT_CMD(gtc_serial_number_set), \
	PRE_GPE_INIT_CMD(gtc_serial_number_get), \
	PRE_GPE_INIT_CMD(gtc_cfg_set), \
	PRE_GPE_INIT_CMD(gtc_cfg_get), \
	PRE_GPE_INIT_CMD(gtc_power_saving_mode_set), \
	PRE_GPE_INIT_CMD(gtc_power_saving_mode_get), \
	PRE_GPE_INIT_CMD(gtc_init), \
	PRE_GPE_INIT_CMD(lan_gphy_firmware_download), \
	PRE_GPE_INIT_CMD(onu_event_enable_set), \
	PRE_GPE_INIT_CMD(onu_event_enable_get), \
	PRE_GPE_INIT_CMD(gpe_init)
#endif

#if defined(LINUX) && defined(__KERNEL__) && defined(CONFIG_PROC_FS) && \
    defined(INCLUDE_PROCFS_SUPPORT)
#define INCLUDE_DUMP
#endif

#if defined(ONU_LIBRARY) && !defined(LINUX)

#define INCLUDE_DUMP

struct seq_file {
	unsigned int pos;
	char *buf;
	unsigned int max_size;
};

int seq_printf(struct seq_file *, const char *fmt, ...);

#endif

/*! @} */

/*! @} */

#ifndef SWIG
EXTERN_C_END
#endif
#endif
