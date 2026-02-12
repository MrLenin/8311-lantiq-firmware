/******************************************************************************

                               Copyright (c) 2012
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef _drv_onu_reg_coplink_cop_h
#define _drv_onu_reg_coplink_cop_h

/** \addtogroup COP_REGISTER
   @{
*/
#define COPLINK_COP_TABLE10   (COPLINK_COP_BASE + 0x04)
#define COPLINK_COP_TABLE11   (COPLINK_COP_BASE + 0x05)
#define COPLINK_COP_TABLE12   (COPLINK_COP_BASE + 0x06)
#define COPLINK_COP_TABLE20   (COPLINK_COP_BASE + 0x08)
#define COPLINK_COP_TABLE21   (COPLINK_COP_BASE + 0x09)
#define COPLINK_COP_TABLE22   (COPLINK_COP_BASE + 0x0A)
#define COPLINK_COP_TABLE30   (COPLINK_COP_BASE + 0x0C)
#define COPLINK_COP_TABLE31   (COPLINK_COP_BASE + 0x0D)
#define COPLINK_COP_TABLE32   (COPLINK_COP_BASE + 0x0E)
#define COPLINK_COP_TABLE40   (COPLINK_COP_BASE + 0x10)
#define COPLINK_COP_TABLE41   (COPLINK_COP_BASE + 0x11)
#define COPLINK_COP_TABLE42   (COPLINK_COP_BASE + 0x12)
#define COPLINK_COP_TABLE50   (COPLINK_COP_BASE + 0x14)
#define COPLINK_COP_TABLE51   (COPLINK_COP_BASE + 0x15)
#define COPLINK_COP_TABLE52   (COPLINK_COP_BASE + 0x16)
#define COPLINK_COP_TABLE60   (COPLINK_COP_BASE + 0x18)
#define COPLINK_COP_TABLE61   (COPLINK_COP_BASE + 0x19)
#define COPLINK_COP_TABLE62   (COPLINK_COP_BASE + 0x1A)
#define COPLINK_COP_TABLE70   (COPLINK_COP_BASE + 0x1C)
#define COPLINK_COP_TABLE71   (COPLINK_COP_BASE + 0x1D)
#define COPLINK_COP_TABLE72   (COPLINK_COP_BASE + 0x1E)
#define COPLINK_COP_GLOBAL0   (COPLINK_COP_BASE + 0x100)
#define COPLINK_COP_GLOBAL1   (COPLINK_COP_BASE + 0x101)
#define COPLINK_COP_GLOBAL2   (COPLINK_COP_BASE + 0x102)
#define COPLINK_COP_GLOBAL3   (COPLINK_COP_BASE + 0x103)
#define COPLINK_COP_GLOBAL4   (COPLINK_COP_BASE + 0x104)
#define COPLINK_COP_GLOBAL5   (COPLINK_COP_BASE + 0x105)
#define COPLINK_COP_CRAM   (COPLINK_COP_BASE + 0x200)
#define COPLINK_COP_CUSTOM0   (COPLINK_COP_BASE + 0x300)
#define COPLINK_COP_CUSTOM1   (COPLINK_COP_BASE + 0x301)
#define COPLINK_COP_CUSTOM2   (COPLINK_COP_BASE + 0x302)
#define COPLINK_COP_CUSTOM3   (COPLINK_COP_BASE + 0x303)
#define COPLINK_COP_CUSTOM4   (COPLINK_COP_BASE + 0x304)
#define COPLINK_COP_CUSTOM5   (COPLINK_COP_BASE + 0x305)
#define COPLINK_COP_CUSTOM6   (COPLINK_COP_BASE + 0x306)
#define COPLINK_COP_CUSTOM7   (COPLINK_COP_BASE + 0x307)

/* Fields of "Table 1 config register 0" */
/** Table data mask
    Specifies the table data mask : each bit masks 16bit in one 256 entry */
#define COP_TABLE10_DATA_MASK_MASK 0xFFFF0000
/** field offset */
#define COP_TABLE10_DATA_MASK_OFFSET 16
/** Table key size
    Specifies the table key size : 0:0, 1:16, 2:32, 3:64, 4:96, 5:128, 6:144, 7:160 bits */
#define COP_TABLE10_KEY_SIZE_MASK 0x00000700
/** field offset */
#define COP_TABLE10_KEY_SIZE_OFFSET 8
/** Table entry size
    Specifies the table entry size : 0:32, 1:64, 2:128, 3:256 */
#define COP_TABLE10_ENTRY_SIZE_MASK 0x000000C0
/** field offset */
#define COP_TABLE10_ENTRY_SIZE_OFFSET 6
/** Table function
    Specifies the table function : 0: GENERIC, 1: CUSTOM (don't care for array and hash), 2: TERNARY */
#define COP_TABLE10_FUNCTION_MASK 0x00000038
/** field offset */
#define COP_TABLE10_FUNCTION_OFFSET 3
/** Table type
    Specifies the table type : 0:ARRAY, 1:VARRAY, 2:LIST, 3:LLIST, 4:HASH (, 5:TREE) */
#define COP_TABLE10_TYPE_MASK 0x00000007
/** field offset */
#define COP_TABLE10_TYPE_OFFSET 0

/* Fields of "Table 1 config register 1" */
/** Table size
    Specifies the table size in number of entries */
#define COP_TABLE11_SIZE_MASK 0xFFFF0000
/** field offset */
#define COP_TABLE11_SIZE_OFFSET 16
/** Table base address
    Specifies the table base address (granularity 32bit words) */
#define COP_TABLE11_BASE_MASK 0x0000FFFF
/** field offset */
#define COP_TABLE11_BASE_OFFSET 0

/* Fields of "Table 1 config register 2" */
/** Address Valid
    Defines whether aux address is valid or not. */
#define COP_TABLE12_AUX_V 0x80000000
/** Table entry counter
    Counts up if an entry created with CMD_ADD, counts down if an entry is removed with CMD_REMOVE */
#define COP_TABLE12_ENTRY_COUNTER_MASK 0x03FF0000
/** field offset */
#define COP_TABLE12_ENTRY_COUNTER_OFFSET 16
/** Table aux pointer
    LinkList only : Pointer to next element of free list */
#define COP_TABLE12_AUX_MASK 0x0000FFFF
/** field offset */
#define COP_TABLE12_AUX_OFFSET 0

/* Fields of "Table 2 config register 0" */
/** Table data mask
    Specifies the table data mask : each bit masks 16bit in one 256 entry */
#define COP_TABLE20_DATA_MASK_MASK 0xFFFF0000
/** field offset */
#define COP_TABLE20_DATA_MASK_OFFSET 16
/** Table key size
    Specifies the table key size : 0:0, 1:16, 2:32, 3:64, 4:96, 5:128, 6:144, 7:160 bits */
#define COP_TABLE20_KEY_SIZE_MASK 0x00000700
/** field offset */
#define COP_TABLE20_KEY_SIZE_OFFSET 8
/** Table entry size
    Specifies the table entry size : 0:32, 1:64, 2:128, 3:256 */
#define COP_TABLE20_ENTRY_SIZE_MASK 0x000000C0
/** field offset */
#define COP_TABLE20_ENTRY_SIZE_OFFSET 6
/** Table function
    Specifies the table function : 0: GENERIC, 1: CUSTOM (don't care for array and hash), 2: TERNARY */
#define COP_TABLE20_FUNCTION_MASK 0x00000038
/** field offset */
#define COP_TABLE20_FUNCTION_OFFSET 3
/** Table type
    Specifies the table type : 0:ARRAY, 1:VARRAY, 2:LIST, 3:LLIST, 4:HASH (, 5:TREE) */
#define COP_TABLE20_TYPE_MASK 0x00000007
/** field offset */
#define COP_TABLE20_TYPE_OFFSET 0

/* Fields of "Table 2 config register 1" */
/** Table size
    Specifies the table size in number of entries */
#define COP_TABLE21_SIZE_MASK 0xFFFF0000
/** field offset */
#define COP_TABLE21_SIZE_OFFSET 16
/** Table base address
    Specifies the table base address (granularity 32bit words) */
#define COP_TABLE21_BASE_MASK 0x0000FFFF
/** field offset */
#define COP_TABLE21_BASE_OFFSET 0

/* Fields of "Table 2 config register 2" */
/** Address Valid
    Defines whether aux address is valid or not. */
#define COP_TABLE22_AUX_V 0x80000000
/** Table entry counter
    Counts up if an entry created with CMD_ADD, counts down if an entry is removed with CMD_REMOVE */
#define COP_TABLE22_ENTRY_COUNTER_MASK 0x03FF0000
/** field offset */
#define COP_TABLE22_ENTRY_COUNTER_OFFSET 16
/** Table aux pointer
    LinkList only : Pointer to next element of free list */
#define COP_TABLE22_AUX_MASK 0x0000FFFF
/** field offset */
#define COP_TABLE22_AUX_OFFSET 0

/* Fields of "Table 3 config register 0" */
/** Table data mask
    Specifies the table data mask : each bit masks 16bit in one 256 entry */
#define COP_TABLE30_DATA_MASK_MASK 0xFFFF0000
/** field offset */
#define COP_TABLE30_DATA_MASK_OFFSET 16
/** Table key size
    Specifies the table key size : 0:0, 1:16, 2:32, 3:64, 4:96, 5:128, 6:144, 7:160 bits */
#define COP_TABLE30_KEY_SIZE_MASK 0x00000700
/** field offset */
#define COP_TABLE30_KEY_SIZE_OFFSET 8
/** Table entry size
    Specifies the table entry size : 0:32, 1:64, 2:128, 3:256 */
#define COP_TABLE30_ENTRY_SIZE_MASK 0x000000C0
/** field offset */
#define COP_TABLE30_ENTRY_SIZE_OFFSET 6
/** Table function
    Specifies the table function : 0: GENERIC, 1: CUSTOM (don't care for array and hash), 2: TERNARY */
#define COP_TABLE30_FUNCTION_MASK 0x00000038
/** field offset */
#define COP_TABLE30_FUNCTION_OFFSET 3
/** Table type
    Specifies the table type : 0:ARRAY, 1:VARRAY, 2:LIST, 3:LLIST, 4:HASH (, 5:TREE) */
#define COP_TABLE30_TYPE_MASK 0x00000007
/** field offset */
#define COP_TABLE30_TYPE_OFFSET 0

/* Fields of "Table 3 config register 1" */
/** Table size
    Specifies the table size in number of entries */
#define COP_TABLE31_SIZE_MASK 0xFFFF0000
/** field offset */
#define COP_TABLE31_SIZE_OFFSET 16
/** Table base address
    Specifies the table base address (granularity 32bit words) */
#define COP_TABLE31_BASE_MASK 0x0000FFFF
/** field offset */
#define COP_TABLE31_BASE_OFFSET 0

/* Fields of "Table 3 config register 2" */
/** Address Valid
    Defines whether aux address is valid or not. */
#define COP_TABLE32_AUX_V 0x80000000
/** Table entry counter
    Counts up if an entry created with CMD_ADD, counts down if an entry is removed with CMD_REMOVE */
#define COP_TABLE32_ENTRY_COUNTER_MASK 0x03FF0000
/** field offset */
#define COP_TABLE32_ENTRY_COUNTER_OFFSET 16
/** Table aux pointer
    LinkList only : Pointer to next element of free list */
#define COP_TABLE32_AUX_MASK 0x0000FFFF
/** field offset */
#define COP_TABLE32_AUX_OFFSET 0

/* Fields of "Table 4 config register 0" */
/** Table data mask
    Specifies the table data mask : each bit masks 16bit in one 256 entry */
#define COP_TABLE40_DATA_MASK_MASK 0xFFFF0000
/** field offset */
#define COP_TABLE40_DATA_MASK_OFFSET 16
/** Table key size
    Specifies the table key size : 0:0, 1:16, 2:32, 3:64, 4:96, 5:128, 6:144, 7:160 bits */
#define COP_TABLE40_KEY_SIZE_MASK 0x00000700
/** field offset */
#define COP_TABLE40_KEY_SIZE_OFFSET 8
/** Table entry size
    Specifies the table entry size : 0:32, 1:64, 2:128, 3:256 */
#define COP_TABLE40_ENTRY_SIZE_MASK 0x000000C0
/** field offset */
#define COP_TABLE40_ENTRY_SIZE_OFFSET 6
/** Table function
    Specifies the table function : 0: GENERIC, 1: CUSTOM (don't care for array and hash), 2: TERNARY */
#define COP_TABLE40_FUNCTION_MASK 0x00000038
/** field offset */
#define COP_TABLE40_FUNCTION_OFFSET 3
/** Table type
    Specifies the table type : 0:ARRAY, 1:VARRAY, 2:LIST, 3:LLIST, 4:HASH (, 5:TREE) */
#define COP_TABLE40_TYPE_MASK 0x00000007
/** field offset */
#define COP_TABLE40_TYPE_OFFSET 0

/* Fields of "Table 4 config register 1" */
/** Table size
    Specifies the table size in number of entries */
#define COP_TABLE41_SIZE_MASK 0xFFFF0000
/** field offset */
#define COP_TABLE41_SIZE_OFFSET 16
/** Table base address
    Specifies the table base address (granularity 32bit words) */
#define COP_TABLE41_BASE_MASK 0x0000FFFF
/** field offset */
#define COP_TABLE41_BASE_OFFSET 0

/* Fields of "Table 4 config register 2" */
/** Address Valid
    Defines whether aux address is valid or not. */
#define COP_TABLE42_AUX_V 0x80000000
/** Table entry counter
    Counts up if an entry created with CMD_ADD, counts down if an entry is removed with CMD_REMOVE */
#define COP_TABLE42_ENTRY_COUNTER_MASK 0x03FF0000
/** field offset */
#define COP_TABLE42_ENTRY_COUNTER_OFFSET 16
/** Table aux pointer
    LinkList only : Pointer to next element of free list */
#define COP_TABLE42_AUX_MASK 0x0000FFFF
/** field offset */
#define COP_TABLE42_AUX_OFFSET 0

/* Fields of "Table 5 config register 0" */
/** Table data mask
    Specifies the table data mask : each bit masks 16bit in one 256 entry */
#define COP_TABLE50_DATA_MASK_MASK 0xFFFF0000
/** field offset */
#define COP_TABLE50_DATA_MASK_OFFSET 16
/** Table key size
    Specifies the table key size : 0:0, 1:16, 2:32, 3:64, 4:96, 5:128, 6:144, 7:160 bits */
#define COP_TABLE50_KEY_SIZE_MASK 0x00000700
/** field offset */
#define COP_TABLE50_KEY_SIZE_OFFSET 8
/** Table entry size
    Specifies the table entry size : 0:32, 1:64, 2:128, 3:256 */
#define COP_TABLE50_ENTRY_SIZE_MASK 0x000000C0
/** field offset */
#define COP_TABLE50_ENTRY_SIZE_OFFSET 6
/** Table function
    Specifies the table function : 0: GENERIC, 1: CUSTOM (don't care for array and hash), 2: TERNARY */
#define COP_TABLE50_FUNCTION_MASK 0x00000038
/** field offset */
#define COP_TABLE50_FUNCTION_OFFSET 3
/** Table type
    Specifies the table type : 0:ARRAY, 1:VARRAY, 2:LIST, 3:LLIST, 4:HASH (, 5:TREE) */
#define COP_TABLE50_TYPE_MASK 0x00000007
/** field offset */
#define COP_TABLE50_TYPE_OFFSET 0

/* Fields of "Table 5 config register 1" */
/** Table size
    Specifies the table size in number of entries */
#define COP_TABLE51_SIZE_MASK 0xFFFF0000
/** field offset */
#define COP_TABLE51_SIZE_OFFSET 16
/** Table base address
    Specifies the table base address (granularity 32bit words) */
#define COP_TABLE51_BASE_MASK 0x0000FFFF
/** field offset */
#define COP_TABLE51_BASE_OFFSET 0

/* Fields of "Table 5 config register 2" */
/** Address Valid
    Defines whether aux address is valid or not. */
#define COP_TABLE52_AUX_V 0x80000000
/** Table entry counter
    Counts up if an entry created with CMD_ADD, counts down if an entry is removed with CMD_REMOVE */
#define COP_TABLE52_ENTRY_COUNTER_MASK 0x03FF0000
/** field offset */
#define COP_TABLE52_ENTRY_COUNTER_OFFSET 16
/** Table aux pointer
    LinkList only : Pointer to next element of free list */
#define COP_TABLE52_AUX_MASK 0x0000FFFF
/** field offset */
#define COP_TABLE52_AUX_OFFSET 0

/* Fields of "Table 6 config register 0" */
/** Table data mask
    Specifies the table data mask : each bit masks 16bit in one 256 entry */
#define COP_TABLE60_DATA_MASK_MASK 0xFFFF0000
/** field offset */
#define COP_TABLE60_DATA_MASK_OFFSET 16
/** Table key size
    Specifies the table key size : 0:0, 1:16, 2:32, 3:64, 4:96, 5:128, 6:144, 7:160 bits */
#define COP_TABLE60_KEY_SIZE_MASK 0x00000700
/** field offset */
#define COP_TABLE60_KEY_SIZE_OFFSET 8
/** Table entry size
    Specifies the table entry size : 0:32, 1:64, 2:128, 3:256 */
#define COP_TABLE60_ENTRY_SIZE_MASK 0x000000C0
/** field offset */
#define COP_TABLE60_ENTRY_SIZE_OFFSET 6
/** Table function
    Specifies the table function : 0: GENERIC, 1: CUSTOM (don't care for array and hash), 2: TERNARY */
#define COP_TABLE60_FUNCTION_MASK 0x00000038
/** field offset */
#define COP_TABLE60_FUNCTION_OFFSET 3
/** Table type
    Specifies the table type : 0:ARRAY, 1:VARRAY, 2:LIST, 3:LLIST, 4:HASH (, 5:TREE) */
#define COP_TABLE60_TYPE_MASK 0x00000007
/** field offset */
#define COP_TABLE60_TYPE_OFFSET 0

/* Fields of "Table 6 config register 1" */
/** Table size
    Specifies the table size in number of entries */
#define COP_TABLE61_SIZE_MASK 0xFFFF0000
/** field offset */
#define COP_TABLE61_SIZE_OFFSET 16
/** Table base address
    Specifies the table base address (granularity 32bit words) */
#define COP_TABLE61_BASE_MASK 0x0000FFFF
/** field offset */
#define COP_TABLE61_BASE_OFFSET 0

/* Fields of "Table 6 config register 2" */
/** Address Valid
    Defines whether aux address is valid or not. */
#define COP_TABLE62_AUX_V 0x80000000
/** Table entry counter
    Counts up if an entry created with CMD_ADD, counts down if an entry is removed with CMD_REMOVE */
#define COP_TABLE62_ENTRY_COUNTER_MASK 0x03FF0000
/** field offset */
#define COP_TABLE62_ENTRY_COUNTER_OFFSET 16
/** Table aux pointer
    LinkList only : Pointer to next element of free list */
#define COP_TABLE62_AUX_MASK 0x0000FFFF
/** field offset */
#define COP_TABLE62_AUX_OFFSET 0

/* Fields of "Table 7 config register 0" */
/** Table data mask
    Specifies the table data mask : each bit masks 16bit in one 256 entry */
#define COP_TABLE70_DATA_MASK_MASK 0xFFFF0000
/** field offset */
#define COP_TABLE70_DATA_MASK_OFFSET 16
/** Table key size
    Specifies the table key size : 0:0, 1:16, 2:32, 3:64, 4:96, 5:128, 6:144, 7:160 bits */
#define COP_TABLE70_KEY_SIZE_MASK 0x00000700
/** field offset */
#define COP_TABLE70_KEY_SIZE_OFFSET 8
/** Table entry size
    Specifies the table entry size : 0:32, 1:64, 2:128, 3:256 */
#define COP_TABLE70_ENTRY_SIZE_MASK 0x000000C0
/** field offset */
#define COP_TABLE70_ENTRY_SIZE_OFFSET 6
/** Table function
    Specifies the table function : 0: GENERIC, 1: CUSTOM (don't care for array and hash), 2: TERNARY */
#define COP_TABLE70_FUNCTION_MASK 0x00000038
/** field offset */
#define COP_TABLE70_FUNCTION_OFFSET 3
/** Table type
    Specifies the table type : 0:ARRAY, 1:VARRAY, 2:LIST, 3:LLIST, 4:HASH (, 5:TREE) */
#define COP_TABLE70_TYPE_MASK 0x00000007
/** field offset */
#define COP_TABLE70_TYPE_OFFSET 0

/* Fields of "Table 7 config register 1" */
/** Table size
    Specifies the table size in number of entries */
#define COP_TABLE71_SIZE_MASK 0xFFFF0000
/** field offset */
#define COP_TABLE71_SIZE_OFFSET 16
/** Table base address
    Specifies the table base address (granularity 32bit words) */
#define COP_TABLE71_BASE_MASK 0x0000FFFF
/** field offset */
#define COP_TABLE71_BASE_OFFSET 0

/* Fields of "Table 7 config register 2" */
/** Address Valid
    Defines whether aux address is valid or not. */
#define COP_TABLE72_AUX_V 0x80000000
/** Table entry counter
    Counts up if an entry created with CMD_ADD, counts down if an entry is removed with CMD_REMOVE */
#define COP_TABLE72_ENTRY_COUNTER_MASK 0x03FF0000
/** field offset */
#define COP_TABLE72_ENTRY_COUNTER_OFFSET 16
/** Table aux pointer
    LinkList only : Pointer to next element of free list */
#define COP_TABLE72_AUX_MASK 0x0000FFFF
/** field offset */
#define COP_TABLE72_AUX_OFFSET 0

/* Fields of "Global config register 0" */
/** Match function support
    Specifies what kind of match functions are supported by this cop */
#define COP_GLOBAL0_FUNCTION_MASK 0x00070000
/** field offset */
#define COP_GLOBAL0_FUNCTION_OFFSET 16
/** Ternary match */
#define COP_GLOBAL0_FUNCTION_Bit2 0x00010000
/** Custom match */
#define COP_GLOBAL0_FUNCTION_Bit1 0x00010000
/** Generic match */
#define COP_GLOBAL0_FUNCTION_Bit0 0x00010000
/** Types supported
    Specifies what kind of table type are supported by this cop */
#define COP_GLOBAL0_TYPE_MASK 0x0000FFFF
/** field offset */
#define COP_GLOBAL0_TYPE_OFFSET 0
/** HASH */
#define COP_GLOBAL0_TYPE_Bit4 0x00000001
/** LINKLIST */
#define COP_GLOBAL0_TYPE_Bit3 0x00000001
/** LIST */
#define COP_GLOBAL0_TYPE_Bit2 0x00000001
/** VARRAY */
#define COP_GLOBAL0_TYPE_Bit1 0x00000001
/** ARRAY */
#define COP_GLOBAL0_TYPE_Bit0 0x00000001

/* Fields of "Global config register 2" */
/** COP Version
    Specifies the cop version number */
#define COP_GLOBAL1_VERSION_MASK 0xF0000000
/** field offset */
#define COP_GLOBAL1_VERSION_OFFSET 28
/** COP tables
    Specifies the number of supported tables */
#define COP_GLOBAL1_TABLES_MASK 0x0F000000
/** field offset */
#define COP_GLOBAL1_TABLES_OFFSET 24
/** COP cram size
    Specifies the number of supported cram entries */
#define COP_GLOBAL1_CRAM_SIZE_MASK 0x00FF0000
/** field offset */
#define COP_GLOBAL1_CRAM_SIZE_OFFSET 16
/** COP dram size
    Specifies the size of the memory connected to this cop */
#define COP_GLOBAL1_DRAM_SIZE_MASK 0x0000FFFF
/** field offset */
#define COP_GLOBAL1_DRAM_SIZE_OFFSET 0

/* Fields of "Global config register 2" */
/** Destination TraceID
    Specifies the destination TraceID for the trace response */
#define COP_GLOBAL2_TRACE_ID_MASK 0x007F0000
/** field offset */
#define COP_GLOBAL2_TRACE_ID_OFFSET 16
/** Performance cntr enable. (A2X)
    This bit enables the performance cntr for each command.This bit not modified by hardware. Only for debugging ! */
#define COP_GLOBAL2_PERF 0x00000002
/** Disable */
#define COP_GLOBAL2_PERF_DIS 0x00000000
/** Enable */
#define COP_GLOBAL2_PERF_EN 0x00000002
/** Trace mode enable.
    This bit enables the trace mode while executing a command.This bit not modified by hardware. Only for debugging !Single commands generates two responses (normal and trace)Execute command generates one response after each executed micro code */
#define COP_GLOBAL2_TRACE 0x00000001
/** Disable */
#define COP_GLOBAL2_TRACE_DIS 0x00000000
/** Enable */
#define COP_GLOBAL2_TRACE_EN 0x00000001

/* Fields of "Global config register 3" */
/** Timestamp prescaler
    Specifies the prescaler for the timestamp counter */
#define COP_GLOBAL3_PRESCALE_MASK 0x0000FFFF
/** field offset */
#define COP_GLOBAL3_PRESCALE_OFFSET 0

/* Fields of "Global config register 4" (A2X) */
/** Performance counter
    If PERF = 1 (GLOBAL2), this register shows the last command process cycle count */
#define COP_GLOBAL4_PERFORMANCE_CNTR_MASK 0xFFFFFFFF
/** field offset */
#define COP_GLOBAL4_PERFORMANCE_CNTR_OFFSET 0

/* Fields of "Global 5 hidden feature register" (A2X) */
/** Hidden write enable code
    The hidden register can only written, if this mask has the value 0xF1 */
#define COP_GLOBAL5_WRITE_ENABLE_CODE_MASK 0xFF000000
/** field offset */
#define COP_GLOBAL5_WRITE_ENABLE_CODE_OFFSET 24
/** ADD on empty list (NIL = 0)
    ADD inserts also an element on an empty list (NIL = 0).This bit not modified by hardware. */
#define COP_GLOBAL5_ADD_FORCE_TOUCH 0x00000004
/** Disable */
#define COP_GLOBAL5_ADD_FORCE_TOUCH_DIS 0x00000000
/** Enable */
#define COP_GLOBAL5_ADD_FORCE_TOUCH_EN 0x00000004
/** SEARCHW with masked key field
    This bit enables the masking of the key field if the entry is written by a SEARCHW command.This bit not modified by hardware. */
#define COP_GLOBAL5_MASKED_SEARCHW 0x00000002
/** Disable */
#define COP_GLOBAL5_MASKED_SEARCHW_DIS 0x00000000
/** Enable */
#define COP_GLOBAL5_MASKED_SEARCHW_EN 0x00000002
/** SEARCHW with ADD protocol
    This bit enables the performance cntr for each command.This bit not modified by hardware. */
#define COP_GLOBAL5_NEW_SEARCHW 0x00000001
/** Disable */
#define COP_GLOBAL5_NEW_SEARCHW_DIS 0x00000000
/** Enable */
#define COP_GLOBAL5_NEW_SEARCHW_EN 0x00000001

/* Fields of "Code RAM" */
/** COMMAND to execute
    TBD see ip_parser.vsd */
#define COP_CRAM_COMMAND_MASK 0x0000FFFF
/** field offset */
#define COP_CRAM_COMMAND_OFFSET 0

/* Fields of "Custom blocks config register 0" */
/** FID value (A1X)
    This register provides the FID value for the custom match function */
#define COP_CUSTOM0_A1X_FID_MASK 0xFFFF0000
/** field offset */
#define COP_CUSTOM0_A1X_FID_OFFSET 16
/** TPID value (A2X)
    This register provides the TPID value for the custom match function */
#define COP_CUSTOM0_A2X_TPID_MASK 0xFFFF0000
/** field offset */
#define COP_CUSTOM0_A2X_TPID_OFFSET 16
/** X is true
    This bit set the X-condition always true */
#define COP_CUSTOM0_XTRUE 0x00000002
/** Disable */
#define COP_CUSTOM0_XTRUE_DIS 0x00000000
/** Enable */
#define COP_CUSTOM0_XTRUE_EN 0x00000002
/** Activate X
    This bit activates the default rule in the custom match function */
#define COP_CUSTOM0_DEFRULE 0x00000001
/** Disable */
#define COP_CUSTOM0_DEFRULE_DIS 0x00000000
/** Enable */
#define COP_CUSTOM0_DEFRULE_EN 0x00000001

/* Fields of "Custom blocks config register 1" */
/** Ethernet type
    This register provides the ethernet type register for the custom match function */
#define COP_CUSTOM1_ETY1_MASK 0x0000FFFF
/** field offset */
#define COP_CUSTOM1_ETY1_OFFSET 0

/* Fields of "Custom blocks config register 2" */
/** Ethernet type
    This register provides the ethernet type register for the custom match function */
#define COP_CUSTOM2_ETY2_MASK 0x0000FFFF
/** field offset */
#define COP_CUSTOM2_ETY2_OFFSET 0

/* Fields of "Custom blocks config register 3" */
/** Ethernet type
    This register provides the ethernet type register for the custom match function */
#define COP_CUSTOM3_ETY3_MASK 0x0000FFFF
/** field offset */
#define COP_CUSTOM3_ETY3_OFFSET 0

/* Fields of "Custom blocks config register 4" */
/** Ethernet type
    This register provides the ethernet type register for the custom match function */
#define COP_CUSTOM4_ETY4_MASK 0x0000FFFF
/** field offset */
#define COP_CUSTOM4_ETY4_OFFSET 0

/* Fields of "Custom blocks config register 5" */
/** Ethernet type mask
    This register provides the ethernet type mask register for the custom match function */
#define COP_CUSTOM5_ETY_MASK_MASK 0xFFFF0000
/** field offset */
#define COP_CUSTOM5_ETY_MASK_OFFSET 16
/** Ethernet type
    This register provides the ethernet type register for the custom match function */
#define COP_CUSTOM5_ETY5_MASK 0x0000FFFF
/** field offset */
#define COP_CUSTOM5_ETY5_OFFSET 0

/* Fields of "Custom blocks config register 6" */
/** Spare1 mask reg
    This register provides a future used register for the custom match function */
#define COP_CUSTOM6_SPARE1_MASK_MASK 0xFFFF0000
/** field offset */
#define COP_CUSTOM6_SPARE1_MASK_OFFSET 16
/** Spare1 reg
    This register provides a future used register for the custom match function */
#define COP_CUSTOM6_SPARE1_MASK 0x0000FFFF
/** field offset */
#define COP_CUSTOM6_SPARE1_OFFSET 0

/* Fields of "Custom blocks config register 7" */
/** Spare2 mask reg
    This register provides a future used register for the custom match function */
#define COP_CUSTOM7_SPARE2_MASK_MASK 0xFFFF0000
/** field offset */
#define COP_CUSTOM7_SPARE2_MASK_OFFSET 16
/** Spare2 reg
    This register provides a future used register for the custom match function */
#define COP_CUSTOM7_SPARE2_MASK 0x0000FFFF
/** field offset */
#define COP_CUSTOM7_SPARE2_OFFSET 0

/*! @} */ /* COP_REGISTER */

#endif /* _drv_onu_reg_coplink_cop_h */
