/******************************************************************************

			Copyright (c) 2011
			Lantiq Deutschland GmbH

For licensing information, see the file 'LICENSE' in the root folder of
this software module.

******************************************************************************/
#ifndef _TSE_H
#define _TSE_H

#ifdef ENV_SIM
#include "stdint.h"
#include "stdbool.h"
#endif

/*
* System Parameterization
*/
#ifndef TSE_NUM
#define TSE_NUM (6)
#endif

#ifndef TSE_CLK
#define TSE_CLK (625000000)
#endif

#ifndef TSE_PC_MASK
#define TSE_PC_MASK (0x7f)
#endif

#ifndef TSE_RESET
#define TSE_PROG_RESET (0x00)
#endif

/*
* Virtual Machine Management
*/
typedef enum tse_e {
	TSE0 = 0,
	#if TSE_NUM >= 2
	TSE1 = 1,
	#endif
	#if TSE_NUM >= 3
	TSE2 = 2,
	#endif
	#if TSE_NUM >= 4
	TSE3 = 3,
	#endif
	#if TSE_NUM >= 5
	TSE4 = 4,
	#endif
	#if TSE_NUM >= 6
	TSE5 = 5,
	#endif
	#if TSE_NUM >= 7
	TSE6 = 6,
	#endif
	#if TSE_NUM >= 8
	TSE7 = 7,
	#endif
}tse_t;

typedef enum { CUSTOM,TABLE,CODE,DATA, GLOBAL } destination_t;

typedef enum { USED, UNUSED, UNUSED_CONFIGED } table_used_t;

typedef enum { USE, RESTORE } config_t;

typedef enum { CMD_READ = 0, CMD_WRITE = 2 } cmd_t;

typedef union{
	struct {
	#ifdef ENV_SIM
		unsigned index:10;
		unsigned off:2;
		unsigned table:4;
		unsigned cmd:4;
		unsigned threadid:7;
		unsigned copid:5;
	#else
		unsigned copid:5;
		unsigned threadid:7;
		unsigned cmd:4;
		unsigned table:4;
		unsigned off:2;
		unsigned index:10;
	#endif
	};
	unsigned int all;
} header_t;


#define LINK2_THREAD_ID 0x7f

#define GLOBAL_REG 0x1
#define TABLE_REG 0x0
#define CODE_REG 0x2
#define COSTUM_REG 0x3

#define DATA_TABLE 7
#define DATA_TABLE_REG0_VALUE 0xFFFF0000
#define DATA_TABLE_REG0_ADDR  0x00000070
#define DATA_TABLE_REG1_VALUE 0x04000000	/* read from global */
#define DATA_TABLE_REG1_ADDR  0x00000074

#define GLOBAL_REG1_ADDR      0x00000004

#define ENDIAN

/* -----------------------------------------------------------------------------------------------
*
* System Interface
*
*
* -----------------------------------------------------------------------------------------------
*/
#ifndef TSE_ADDR_CODE
#define TSE_ADDR_CODE (0x0000)
#define TSE_ADDR_CODE_END 0x4000
#endif

#ifndef TSE_ADDR_DATA
#define TSE_ADDR_DATA (0x4000)
#define TSE_ADDR_DATA_END 0xC000
#endif

#ifndef TSE_ADDR_TABLE
#define TSE_ADDR_TABLE (0xC000)
#define TSE_ADDR_TABLE_END 0xE000
#endif

#ifndef TSE_ADDR_NAMES
#define TSE_ADDR_NAMES (0xE000)
#define TSE_ADDR_NAMES_END 0xF000
#endif

#ifndef TSE_ADDR_GLOBAL
#define TSE_ADDR_GLOBAL (0xF000)
#define TSE_ADDR_GLOBAL_END 0xF400
#endif

#ifndef TSE_ADDR_CUSTOM
#define TSE_ADDR_CUSTOM (0xF400)
#define TSE_ADDR_CUSTOM_END 0xF800
#endif

#ifndef TSE_ADDR_INTERFACE
#define TSE_ADDR_INTERFACE (0xF800)
#define TSE_ADDR_INTERFACE_END 0xFC00
#endif

#ifndef TSE_ADDR_COMMENT
#define TSE_ADDR_COMMENT (0xFC00)
#define TSE_ADDR_COMMENT_END 0x10000
#endif

typedef struct {
	uint16_t id;
	uint16_t addr;
	char*    name;
} tse_interface_t;

typedef struct{
	tse_t tse;
	char *image;
	uint16_t image_len;
	char* pbuffer;
	uint16_t BufLen;
	char* names_buffer;
	uint16_t NamesBufLen;
	tse_interface_t* tse_if;
	uint8_t data_init;
	uint16_t* cram_usage;
} tse_loader_t;

void tse_setthreadiD(uint8_t tid);
int32_t tse_load(tse_loader_t* loader);

uint16_t tse_progread   (tse_t tse, int32_t address);
void tse_progwrite  (tse_t tse, int32_t address, uint16_t data);

uint32_t tse_dataread32 (tse_t tse, int32_t address);
void tse_datawrite32(tse_t tse, int32_t address, uint32_t data);

void tse_dataread   (tse_t tse, int32_t address, uint8_t *data, int32_t len);
void tse_datawrite  (tse_t tse, int32_t address, uint8_t *data, int32_t len);

uint32_t tse_tableread  (tse_t tse, int32_t address);
void tse_tablewrite (tse_t tse, int32_t address, uint32_t data);

uint32_t tse_customread (tse_t tse, int32_t address);
void tse_customwrite(tse_t tse, int32_t address, uint32_t data);

uint32_t tse_link32(uint32_t header, uint32_t data);
uint32_t tse_createheader(tse_t tse, int32_t address, destination_t destination, cmd_t cmd);
void tse_configdatatable(tse_t tse, config_t config);

#endif
