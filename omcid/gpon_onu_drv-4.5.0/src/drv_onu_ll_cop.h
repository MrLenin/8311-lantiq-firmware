/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _drv_onu_ll_cop_h
#define _drv_onu_ll_cop_h

struct onu_device;

/** \addtogroup ONU_LL_REFERENCE GPON Low-level Functions

   The following chapters describe the low-level functions that are used to
   access the GPON-related hardware modules of the device.
   @{
*/

/** \addtogroup ONU_LL_COP Hardware Coprocessor Low-level Functions

   Low-level functions to access the hardware coprocessors within the GPON
   Packet Engine (GPE) hardware module.
   @{
*/

#include "drv_onu_gpe_tables.h"

#define ONU_COP_BUGFIX
/* #define ONU_COP_USE_COP_LOADER_RAM_INIT */
/* #define ONU_COP_FLIP_DUMPS */

/* LINKC1 command request protocol definitions */
#define LINKC1_HEADER_SIZE 	1
#define LINKC1_INDEX_OFFSET 	0
#define LINKC1_INDEX_MSK	0x3FF
#define LINKC1_OFF_OFFSET 	10
#define LINKC1_OFF_MSK 		0x3
#define LINKC1_NIL_OFFSET 	11
#define LINKC1_NIL_MSK 		0x1
#define LINKC1_TABLE_OFFSET 	12
#define LINKC1_CMD_OFFSET 	16
#define LINKC1_TID_OFFSET 	20
#define LINKC1_COPID_OFFSET 	27
#define LINKC1_LEN_OFFSET 	0

/* LINKC1 command request/response timeout */
#define LINK_TIMEOUT 	1000

/* LINKC1 request protocol commands */
#define LINKC1_READ 	0x0
#define LINKC1_CLEAR 	0x1
#define LINKC1_WRITE 	0x2
#define LINKC1_COUNT 	0x3
#define LINKC1_SEARCHR 	0x1
#define LINKC1_SEARCH 	0x8
#define LINKC1_REMOVE 	0x9
#define LINKC1_ADD 	0xA
#define LINKC1_SEARCHW 	0xB
#define LINKC1_EXEC 	0xC

/* LINKC2 command response protocol definitions */
#define LINKC2_HEADER_SIZE 		2
#define LINKC2_ERR_OFFSET 		16
#define LINKC2_ERR_MASK 		0x70000
#define LINKC2_TIMESTAMP_OFFSET 	24
#define LINKC2_TIMESTAMP_MASK 		0xFF
#define LINKC2_RES_MASK 		0x80000

/* Local used thread IDs for LINK communication */
#define TID_CPU33 	0x7F
#define TID_CPU32 	0x7E
#define TID_CPU31 	0x7D

/* COP Table type definitions */
#define ONU_GPE_COP_ARRAY 	0
#define ONU_GPE_COP_VARRAY 	1
#define ONU_GPE_COP_LIST 	2
#define ONU_GPE_COP_LLIST 	3
#define ONU_GPE_COP_HASH 	4
#define ONU_GPE_COP_BITVECT 	6
#define ONU_GPE_COP_STRUCT 	7
#define ONU_GPE_COP_UNDEF 	15

/* API level commands */
#define ONU_GPE_COP_DC 		-1 /* don't care, used for PE */
#define ONU_GPE_COP_SET 	0
#define ONU_GPE_COP_ADD 	1
#define ONU_GPE_COP_DELETE 	2
#define ONU_GPE_COP_READ 	3
#define ONU_GPE_COP_WRITE 	4
#define ONU_GPE_COP_GET 	5
#define ONU_GPE_COP_SEARCH 	8
#define ONU_GPE_COP_TABLE0W 	0x14
#define ONU_GPE_COP_TABLE0R 	0x13
#define ONU_GPE_COP_EXEC 	0xC

/* Logical COP microcode label IDs, based on COP loader toolchain */
#define	IF_NONE	          	0
#define IF_FWD_AGE	      	1
#define IF_FWD_FORWARD    	2
#define IF_FWD_RELEARN    	3
#define IF_FWD_ADD        	4
#define IF_FWD_REMOVE     	5
#define IF_TAG_FILTER     	6
#define IF_IPV6_FORWARD   	7
#define IF_IPV4_SEARCH    	8
#define IF_VLAN_TRANSLATE 	9
#define IF_FID_LOOKUP    	10
#define IF_FID_SEARCH    	11
#define IF_UPGEM_SEARCHR 	12
#define IF_FID_GET_PREVIOUS 13
#define IF_FID_REMOVE 		14
#define IF_IPV6HASH_SEARCHR 15
#define IF_FIDHASH_SEARCHR 	16
#define IF_IPV4_SEARCHW 	17
#define IF_ETHFILT_SEARCHW	18
#define IF_LABEL_MAX 		19

/* LINKC1 request protocol commands for table type control fields */
#define ONU_GPE_COP_VALID_POS 	31
#define ONU_GPE_COP_VALID_MSK 	0x1
#define ONU_GPE_COP_END_POS 	30
#define ONU_GPE_COP_END_MSK 	0x1
#define ONU_GPE_COP_NEXT_POS 	16
#define ONU_GPE_COP_NEXT_MSK 	0x3FFF

/* LINKC1 request protocol commands for debugging messages */
#define ONU_GPE_COP_DBGPC_POS 	0
#define ONU_GPE_COP_DBGPC_MSK 	0x7F
#define ONU_GPE_COP_DBGNEXT_POS 8
#define ONU_GPE_COP_DBGNEXT_MSK 0x3FF
#define ONU_GPE_COP_DBGPREV_POS 18
#define ONU_GPE_COP_DBGPREV_MSK 0x3FF
#define ONU_GPE_COP_DBGERR_POS 	28
#define ONU_GPE_COP_DBGERR_MSK 	0x7
#define ONU_GPE_COP_DBGRES2_POS 31
#define ONU_GPE_COP_DBGRES2_MSK 0x1
#define ONU_GPE_COP_DBGOFF_POS 	10
#define ONU_GPE_COP_DBGOFF_MSK 	0x3
#define ONU_GPE_COP_COPID_POS 	LINKC1_COPID_OFFSET
#define ONU_GPE_COP_COPID_MSK 	0x1F
#define ONU_GPE_COP_TID_POS 	LINKC1_TID_OFFSET
#define ONU_GPE_COP_TID_MSK 	0x7F
#define ONU_GPE_COP_TABLE_POS 	LINKC1_TABLE_OFFSET
#define ONU_GPE_COP_TABLE_MSK 	0xF
#define ONU_GPE_COP_INDEX_POS 	LINKC1_INDEX_OFFSET
#define ONU_GPE_COP_INDEX_MSK 	LINKC1_INDEX_MSK
#define ONU_GPE_COP_NIL_POS 	LINKC1_NIL_OFFSET
#define ONU_GPE_COP_NIL_MSK 	0x1
#define ONU_GPE_COP_ERR_POS 	LINKC2_ERR_OFFSET
#define ONU_GPE_COP_ERR_MSK 	0x7
#define ONU_GPE_COP_RESULT_POS 	19
#define ONU_GPE_COP_RESULT_MSK 	0x1
#define ONU_GPE_COP_CMD_POS 	LINKC1_CMD_OFFSET
#define ONU_GPE_COP_CMD_MSK 	0xF

/* COP message protocol definitions */
#define ONU_GPE_COP_DATASIZE_MAX 	10
#define ONU_GPE_COP_CMDSIZE_MAX 	2

/* Maximum number of labels at one COP, based on COP loader toolchain */
#define ONU_GPE_COP_LABEL_MAX 		10
/* Maximum number of ALL labels togehter */
#define ONU_GPE_ALL_COP_LABEL_MAX 	25
/* Maximum string size for one COP label */
#define ONU_GPE_COP_LABEL_STR_SIZE_MAX  32

/* Shift factor handling for LIST Mgmt A21 */
#define ONU_GPE_LIST_NIL_SHIFTFACTOR 5
#define ONU_GPE_LIST_NIL_WORDSIZE (1 << ONU_GPE_LIST_NIL_SHIFTFACTOR)

/* Defines used for table entry age calculation */
#define ONU_GPE_COP_AGE_MAX 		56160
#define ONU_GPE_COP_PSCALE_FAC_SET 	298
#define ONU_GPE_COP_PSCALE_FAC_GET 	110
#define ONU_GPE_COP_PSCALE_DIV_SET 	256
#define ONU_GPE_COP_PSCALE_DIV_GET 	128

/* Local strings for dump routines */
#define LINK2 "[LNK2] "
#define COP "[COP ] "

extern uint32_t onu_gpe_cop_entrysize[4];
extern uint32_t onu_gpe_cop_keysize[8];

/** Hardware coprocessor label mapping.
 *  Used to map logical IDs to physical function address pointers.
 */
typedef struct {
	/** COP id of the microcode label */
	uint32_t cop_id;
	/** Physical function address pointer */
	uint32_t func_addr;
	/** Label name for debugging purposes */
	char label_name[32];
} labelmapping_t;

/** Hardware coprocessor operation status */
enum cop_errorcode {
	/** No error and no result */
	COP_STATUS_OK = 0,
	/** INDEX points beyond table size or was invalid,
	   e.g. after INDEX = AUX */
	COP_STATUS_INVALID_INDEX = 1,
	/** A sequential search has hit the end of table without having
	   found a match */
	COP_STATUS_END_OF_TABLE = 2,
	/** An ADD command to an LLIST failed because the free list was
	   empty (invalid AUX pointer) */
	COP_STATUS_OUT_OF_MEMORY = 3,
	/** An ADD command with OV=0 to a LIST or LLIST failed because there
	   is already an entry with the same key */
	COP_STATUS_ENTRY_EXISTS = 4,
	/** Controlled by External_0 */
	COP_STATUS_ERROR_DISCARD_FRAME = 5,
	/** Controlled by Microcode */
	COP_STATUS_SOFT_ERR_1 = 6,
	/** Controlled by Microcode */
	COP_STATUS_SOFT_ERR_2 = 7,
	/** A COP result was found */
	COP_STATUS_SUCCESS = 8,
	/* Any kind of generic error */
	COP_STATUS_ERR = 16,
	/* No response during a COP read command */
	COP_STATUS_TIMEOUT = 32,
	/* a receive flush error */
	COP_STATUS_ERR_FLUSH = 64,
	/* an initialization error */
	COP_INIT_ERR = 128
};

/** Hardware coprocessor communication protocol formats
*/
enum format {
	/** command: ADD, SEARCHW, etc */
	COP_FRM_FORMAT1 = 0,
	/** command: WRTIE */
	COP_FRM_FORMAT2 = 1
};

/** Data to be sent to or received from a hardware coprocessor.
*/
struct cop_message {
	/** Data length in 32-bit units */
	uint8_t request_length;
	/** Data length, in 32-bit units */
	uint8_t response_length;
	/** Data, maximum size of data is 8x32 (256bit data) + header */
	uint32_t data[ONU_GPE_COP_DATASIZE_MAX];
	/** Command fields */
	uint32_t command[ONU_GPE_COP_CMDSIZE_MAX];
	/** Command format */
	enum format format;
};

#ifdef INCLUDE_COP_DEBUG
/**
   Debug function which activates the trace mode at a hardware coprocessor.
   \param cop_id The coprocessor ID
   \param trace_enable 	The trace mode
*/
enum cop_errorcode cop_debug_set(const uint8_t cop_id,
				 const uint32_t trace_enable);
#endif

#ifdef INCLUDE_COP_DEBUG
/**
   Debug function which delivers the trace mode at a hardware coprocessor.
   \param cop_id The coprocessor ID

   \return The trace mode
*/
uint32_t cop_debug_get(const uint8_t cop_id);
#endif

#ifdef INCLUDE_COP_DEBUG
/**
   Debug function which send a single step during activated trace mode.
   \param cop_id 	The coprocessor ID
*/
void cop_debug_step(const uint32_t cop_id);
#endif

#ifdef INCLUDE_COP_DEBUG
/**
   Debug function which prints trace messages to console as long as trace mode
   is activated.
   \param stepcnt 	The amount of steps the server should perform on the
			traced function
   \param cop_mask 	Defines from which COP trace messages shall be printed
*/
void cop_debug_server(const uint32_t stepcnt, const uint32_t cop_mask);
#endif

#ifdef INCLUDE_COP_DEBUG
/**
   Debug function which receives a trace message.
   \param temp0 	First data word of trace message
   \param temp1 	Second data word of trace message
*/
enum cop_errorcode cop_debug_receive(uint32_t temp0, uint32_t temp1);
#endif

#ifdef INCLUDE_COP_DEBUG
/**
   Debug function which prints the disassembled microcode during hardware
   coprocessor table dumps.
   \param instr 	Instruction to be disassembled
   \param opcode 	Disassembled opcode string of instruction
   \param len 		Length of opcode string buffer
*/
void cop_debug_disassembly(uint16_t instr, char *opcode, uint32_t len);
#endif

/**
   Debug function to read out TABLE0 registers settings

   \param entry 	Table entry
 */
enum cop_errorcode cop_table0_read(struct gpe_table_entry *entry);

/**
   Initialize the hardware coprocessor microcode
   Load the code and data memories of all COP elements.
*/
enum cop_errorcode cop_init(struct onu_device *p_dev);

/**
   Initialize the hardware coprocessor tables
*/
enum cop_errorcode cop_table_init(uint32_t from_table_id, uint32_t to_table_id);

/**
   Initial preparation of hardware coprocessor CRAM.
*/
enum cop_errorcode cop_code_set(struct onu_device *p_dev);

/**
   Initial preparation of hardware coprocessor DRAM.
*/
enum cop_errorcode cop_cfg_set(void);

/**
   Handle send and receive message during COP communication.

   \param message	A hardware coprocessor message handle
*/
enum cop_errorcode cop_message(struct cop_message *message);

/**
   Send a message to a hardware coprocessor.

   \param message	A hardware coprocessor message handle
*/
enum cop_errorcode cop_message_send(const struct cop_message *message);

/**
   Receive a message from a hardware coprocessor.

   \param message	A hardware coprocessor message handle
*/
enum cop_errorcode cop_message_receive(struct cop_message *message);

/**
   Table access function which writes a specific hardware coprocessor
   table entry.

   \param table_data Table entry data
   \param cmd 			COP command (WRITE, SEARCHW, etc.)
*/
enum cop_errorcode cop_table_entry_write(struct gpe_table_entry *table_data,
					 uint32_t cmd);

/**
   Table access function which reads a specific table entry.

   \param table_data 	Table entry data
   \param cmd 			COP command (WRITE, SEARCHW, etc.)
*/
enum cop_errorcode cop_table_entry_read(struct gpe_table_entry *table_data,
					uint32_t cmd);

/**
   Table access function which adds a specific table entry.

   \param table_data 	Table entry data
   \param key_len 		Key length in amount of 32-bit words
*/
enum cop_errorcode cop_table_entry_add(struct gpe_table_entry *table_data,
				       const uint32_t key_len,
				       const bool nil);
/**
   Table access function which deletes a specific table entry.

   \param table_data 	Table entry data
   \param key_len 		Key length in amount of 32-bit words
*/
enum cop_errorcode cop_table_entry_delete(struct gpe_table_entry *table_data,
					  const uint32_t key_len);

/**
   Table access function which searches a specific table entry.

   \param table_data 	Table entry data
   \param key_len 		Key length in amount of 32-bit words
*/
enum cop_errorcode cop_table_entry_searchw(struct gpe_table_entry *table_data,
					  const uint32_t key_len);

/**
   Table access function which searches a specific table entry and
   deliver its content.

   \param table_data 	Table entry data
   \param key_len 		Key length in amount of 32-bit words
*/
enum cop_errorcode cop_table_entry_searchr(struct gpe_table_entry *table_data,
					  const uint32_t key_len);

/**
   Table access function which searches a specific table entry and
   deliver its index only.

   \param table_data 	Table entry data
   \param key_len 		Key length in amount of 32-bit words
*/
enum cop_errorcode cop_table_entry_search(struct gpe_table_entry *table_data,
					  const uint32_t key_len);

/**
   Table access function which execute microcode on a table.

   \param entry 	Table entry data
   \param key_len 	Key length in amount of 32-bit words
   \param instruction 	Microcode label for instruction
*/
enum cop_errorcode cop_table_entry_exec(struct gpe_table_entry *entry,
					const uint32_t key_len,
					const uint32_t instruction);

/** Get COP table size in bytes

   \param cop_id 	The coprocessor ID
   \param table_id 	The table ID

   \return 			Table entry size in amount of 32-bit words
*/
uint32_t cop_table_size_get(uint32_t cop_id, uint32_t table_id);

extern char mc_version_string[ONU_GPE_NUMBER_OF_COP][256];

/*! @} */

/*! @} */

#endif
