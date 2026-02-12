/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _drv_onu_ll_sce_h
#define _drv_onu_ll_sce_h

/** \addtogroup ONU_LL_REFERENCE GPON Low-level Functions
   @{
*/

/** \addtogroup ONU_LL_SCE Shared Classification Engine Low-level Functions

   Low-level functions to access the functions of the Shared Classification
   Engine (SCE).
   @{
*/

#include "drv_onu_gpe_tables.h"

#define SCE_MAX_BREAKPOINTS	32

#define CMD_ERR			(1<<0)
#define CMD_RVAL		(1<<30)
#define CMD_NOTHING		(0x00)
#define CMD_SET_ADDR		(0x01)
#define CMD_MEM			(0x02)
#define CMD_R0H			(0x03)
#define CMD_R0L			(0x04)
#define CMD_R11H		(0x19)
#define CMD_R11L		(0x1A)
#define CMD_RFPH		(0x1B)
#define CMD_RFPL		(0x1C)
#define CMD_RGPH		(0x1D)
#define CMD_RGPL		(0x1E)
#define CMD_R15H		(0x1F)
#define CMD_RPC			(0x20)
#define CMD_IRQ_REASON		(0x21)
#define CMD_STOP		(0xFF)
#define CMD_REG_PREPARE		(0x3FF)

/* defines for MIPS-PE protocol */
#define CMD_W_OFFSET 		31
#define CMD_RVAL_OFFSET 	30
#define CMD_T_NUM_OFFSET 	25
#define CMD_LENGTH_OFFSET 	21
#define CMD_BYTE_OFFSET 	2
#define CMD_ERR_OFFSET 		0

/**
 Virtual Machine Management
*/

/** a virtual machine identifier
*/
enum vm {
	VM00 = (4*0+0),
	VM01 = (4*0+1),
	VM02 = (4*0+2),

	VM10 = (4*1+0),
	VM11 = (4*1+1),
	VM12 = (4*1+2),

	VM20 = (4*2+0),
	VM21 = (4*2+1),
	VM22 = (4*2+2),

	VM30 = (4*3+0),
	VM31 = (4*3+1),
	VM32 = (4*3+2),

	VM40 = (4*4+0),
	VM41 = (4*4+1),
	VM42 = (4*4+2),

	VM50 = (4*5+0),
	VM51 = (4*5+1),
	VM52 = (4*5+2)
};

/** PE operation status */
enum pe_errorcode {
	/** No error and no result */
	PE_STATUS_OK = 0,
	/** PE operation timeout error */
	PE_STATUS_TIMEOUT = 1,
	/** Generic or unknown error occurred */
	PE_STATUS_ERR = 2
};

/**
 Virtual Machine Management
*/

/** SCE Registers
FIXME: add prefix?
*/
enum sce_reg {
	REG_R0,
	REG_R1,
	REG_R2,
	REG_R3,
	REG_R4,
	REG_R5,
	REG_R6,
	REG_R7,
	REG_R8,
	REG_R9,
	REG_R10,
	REG_R11,
	REG_R12,
	REG_R13,
	REG_R14,
#define REG_FP  REG_R14
	REG_R15,
#define REG_ST  REG_R15
	REG_GP, /**<< 16, virtual register (identical to r15) */
	REG_T,  /**<< 17, virtual register */
	REG_PC, /**<< 18, virtual register */
	REG_L0, /**<< 19, virtual register */
	REG_L1, /**<< 20, virtual register */
	REG_L2, /**<< 21, virtual register */
	REG_L3, /**<< 22, virtual register */
	REG_L4, /**<< 23, virtual resister */
	REG_L5, /**<< 24, virtual register */
	REG_L6, /**<< 25, virtual register */
	REG_L7, /**<< 26, virtual register */
	REG_SP  /**<< 27, virtual register */
};

/** Processing Element Firmware Data.
*/
struct sce_fw_data {
	/** Processing Element selector */
	uint8_t pe_index;
	/** Firmware pointer. */
	uint32_t *data;
	/** Firmware length. */
	uint16_t len;
};

/** Processing Element firmware code and data pointer definition.
   Used by \ref sce_fw_init.
*/
struct sce_fw_init {
	/** Firmware code. */
	struct sce_fw_data code;
	/** Firmware data. */
	struct sce_fw_data data;
};

/** SCE configuration.
   Used by \ref sce_fw_cfg_set and \ref sce_fw_cfg_get.
*/
struct sce_fw_cfg {
	/** Processing Element enable. */
	bool thread_enable[ONU_GPE_NUMBER_OF_THREADS];
};


/** Data to be sent to or received from a PE.
   Used by \ref sce_pe_table_entry_read,
   and \ref sce_pe_table_init.
*/
struct sce_fw_pe_message {
	/** Processing Element selector */
	uint8_t pe_index;
	/** Table ID */
	uint8_t table_id;
	/** Table Idx */
	uint8_t table_idx;
	/** Table width in 32-bit units */
	uint8_t entry_width;
	/** Data */
	uint32_t message[16];
};

/**
   Initialize the SCE firmware
   Load the code and data memories of all Firmware processing Elements.
   The number of Processing Elements is given by \ref ONU_GPE_NUMBER_OF_PE_MAX.

   \param param Firmware initialization information.
   \param num_pe Number of PEs

   \return
   - 0  Initialization successful
   - -1 Error occurred during initialization
*/
int sce_fw_init(const struct sce_fw_init *param, const uint8_t num_pe);

/**
   Activates the PE, MRG and DISP modules.

   \param num_pe Number of PEs

   \return
   - 0  Initialization successful
   - -1 Error occurred during initialization
*/
int sce_init(const uint8_t num_pe);

/**
   Starts initialization sequence of merge module.

   \return
   - 0  Initialization successful
   - -1 Error occurred during initialization
*/
int sce_merge_init(void);


/**
   Set Activate / Deactivate switch for merge state machines.
*/
void sce_merge_enable(bool act);

/**
   Get Activate / Deactivate switch of merge state machines.
*/
bool sce_merge_is_enabled(void);

/**
   Set Activate / Deactivate switch for dispatcher state machines.
*/
void sce_dispatcher_enable(bool act);

/**
   Get Activate / Deactivate switch of dispatcher state machines.
*/
bool sce_dispatcher_is_enabled(void);


/**
   Read back the SCE firmware code memory from a selected Processing Element.

   \param param Firmware code memory.

   \return
   - 0  Initialization successful
   - -1 Error occurred during initialization
*/
int sce_fw_code_read(struct sce_fw_data *param);

/**
   Read back the SCE firmware data memory from a selected Processing Element.

   \param param Firmware data memory.

   \return
   - 0  Initialization successful
   - -1 Error occurred during initialization
*/
int sce_fw_data_read(struct sce_fw_data *param);

/**
   Configure the SCE firmware.

   \param param Firmware Configuration.

   \return
   - 0  Initialization successful
   - -1 Error occurred during initialization
*/
int sce_fw_cfg_set(const struct sce_fw_cfg *param);

/**
   Read back the SCE firmware configuration.

   \param param Firmware Configuration.

   \return
   - 0  Initialization successful
   - -1 Error occurred during initialization
*/
int sce_fw_cfg_get(struct sce_fw_cfg *param);

/**
   Read the status of a the SCE.

   \param tstat		Firmware tstat register.
   \param terr		Firmware terr register.
   \param tctrl		Firmware tctrl register.
   \param tdebug	Firmware tdebug register.
   \param bctrl		Firmware bctrl register.
   \param bstat		Firmware bstat register.
   \param bdis		Firmware bdis register.

   \return
   - 0  Initialization successful
   - -1 Error occurred during initialization
*/
int sce_fw_status_get(uint32_t *tstat, uint32_t *terr,
		      uint32_t *tctrl, uint32_t *tdebug,
		      uint32_t *bctrl, uint32_t *bstat,
		      uint32_t *bdis);

/**
   Send a message to one of the PEs.

   \param param PE message.
*/
enum pe_errorcode sce_fw_pe_message_send(const struct sce_fw_pe_message *param);

/**
   Receive a message from one of the PEs.

   \param param PE message.
*/
enum pe_errorcode sce_fw_pe_message_receive(struct sce_fw_pe_message *param);

/** Check whether PE table is supported

   \param pe_idx	PE index
   \param info		PE FW info structure pointer
   \param id		PE table id

   \return
   - true: Supported
   - false: Not supported
*/
bool is_pe_table_supported(const uint8_t pe_idx,
			   const struct pe_fw_info *info,
			   const uint32_t id);

#if defined(INCLUDE_SCE_DEBUG)
int sce_fw_breakpoint_set(const enum vm vm, const uint32_t addr);
int sce_fw_breakpoint_get(const enum vm vm, const uint32_t idx, uint32_t *addr);
int sce_fw_breakpoint_remove(const enum vm vm, const uint32_t addr);
int sce_fw_pe_reg_set(const enum vm vm, enum sce_reg reg, uint32_t val);
int sce_fw_pe_reg_get(const enum vm vm, enum sce_reg reg, uint32_t *val);
int sce_fw_pe_memset(const enum vm vm, const uint32_t addr, uint32_t val);
int sce_fw_pe_memget(const enum vm vm, const uint32_t addr, uint32_t *val);
int sce_fw_pe_break(const uint32_t vm_group);
int sce_fw_pe_break_check(uint32_t *vm_group);
int sce_fw_pe_restart(const enum vm vm);
int sce_fw_pe_single_step(const enum vm vm);
int sce_fw_pe_pc_set(const enum vm vm, const uint32_t pc);
int sce_fw_pe_pc_get(const enum vm vm, uint32_t *pc);
#endif /* defined(INCLUDE_SCE_DEBUG)*/
void sce_fw_pe_run(const uint32_t vm_group);

#if defined(INCLUDE_DUMP)

/**
   Dump the SCE register block.
*/
void sce_dump(struct seq_file *s);


/**
   Dump the MERGE register block.
*/
void merge_dump(struct seq_file *s);

#endif

/*! @} */

/*! @} */

#endif
