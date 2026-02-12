/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/* #define ENV_SIM */

#ifdef ENV_SIM
#include "stdbool.h"
#include "stdint.h"
#include "stdlib.h"
#include "stdio.h"
#include "iso646.h"
#else
#include "drv_onu_api.h"
#include "drv_onu_ll_cop.h"
#endif

/* Interface */
#include "drv_onu_tse.h"

/* Plattform specific HW interface */
#ifdef SYSTEMC
# include "system.h"
#endif

static table_used_t data_table = UNUSED;
static uint32_t data_table_config[4];
static uint8_t ThreadId = LINK2_THREAD_ID;

int32_t tse_load(tse_loader_t* loader)
{
	int32_t c, len;
	uint32_t pc, addr;
	uint32_t names_buf_cnt, temp, buf_cnt, buf_len, names_buf_len;
	unsigned char 	sum;
	uint16_t Id, func_addr;
	char *image;
	tse_t tse;
	char *pbuffer;
	char *names_buffer;
	char *names_tmp;
	tse_interface_t	*tse_if;
	tse_interface_t *if_name;

	data_table = UNUSED;
	buf_cnt = 0;
	names_buf_cnt = 0;
	image = loader->image;
	tse = loader->tse;
	pbuffer = loader->pbuffer;
	names_buffer= loader->names_buffer;
	buf_len	= loader->BufLen;
	names_buf_len = loader->NamesBufLen;
	tse_if = loader->tse_if;
	if_name	= loader->tse_if;
	/* default PC value */
	pc = TSE_PROG_RESET;

	loader->cram_usage=0;

	while ((image - loader->image) < loader->image_len) {
		/* type */
		c   = *image++;
		/* length */
		sum  = *image;
		len  = ((uint8_t)*image++);

		/* body */
		if (c >= 1 && c <= 3) { /* data record */
			len   = len-c-2;
			addr = 0;
			do {
				sum += *image;
				addr = (addr<<8) | (uint8_t) *image++;
			} while (--c >= 0);

			if (addr < TSE_ADDR_CODE_END) {
				temp  = 0;
				while (--len >= 0) {
					sum += *image;
					temp = (temp<<8) | (uint8_t)*image++;
					if ((addr & 0x1) == 0x1) {
						tse_progwrite(tse, addr & ~0x1,
							      (uint16_t)temp);
						loader->cram_usage++;
						temp=0;
					}
					addr++;
				}
				sum += *image++;
				if (sum != 0xff)
					return -1;
			} else if ((addr>= TSE_ADDR_DATA) &&
						   (addr < TSE_ADDR_DATA_END)) {
				loader->data_init = 1;
				addr = addr-TSE_ADDR_DATA;
				tse_datawrite(tse, addr, (uint8_t *)image, len);
				addr += len;
				image = image+len+1; /* skip checksum */
			} else if ((addr>= TSE_ADDR_TABLE) &&
						  (addr < TSE_ADDR_TABLE_END)) {
				temp  = 0;
				while (--len >= 0) {
					sum += *image;
					temp = (temp<<8) | (uint8_t)*image++;

					if ((addr & 0x3) == 0x3) {
						tse_tablewrite(tse, addr & ~0x3,
							       temp);
						temp = 0;
					}
					addr++;
				}
				sum += *image++;
				if (sum != 0xff)
					return -1;
			} else if ((addr >= TSE_ADDR_CUSTOM) &&
						 (addr < TSE_ADDR_CUSTOM_END)) {
				temp = 0;
				while (--len >= 0) {
					sum += *image;
					temp = (temp<<8) | (uint8_t)*image++;

					if ((addr & 0x3) == 0x3) {
						tse_customwrite(tse,
								addr & ~0x3,
								temp);
						temp = 0;
					}
					addr++;
				}
				sum += *image++;
				if (sum != 0xff)
					return -1;
			} else if ((addr >= TSE_ADDR_GLOBAL) &&
						(addr < TSE_ADDR_GLOBAL_END)) {
				while (--len >= 0) {
					sum += *image;
					image++;
					addr++;
				}
				sum += *image++;
				if (sum != 0xff)
					return -1;
			} else if ((addr >= TSE_ADDR_INTERFACE) &&
					      (addr < TSE_ADDR_INTERFACE_END)) {
				while (len > 0) {
					sum += *image;
					Id = (*image++) << 8;
					sum += *image;
					Id = Id + (unsigned char)*image++;
					sum += *image;
					func_addr = *image++ << 8;
					sum += *image;
					func_addr = func_addr +
							(unsigned char)*image++;

					if (tse_if != NULL) {
						tse_if->addr = func_addr;
						tse_if->id = Id;
						tse_if ++;
					}
					len -= 4;
					addr+= 4;
				}
				sum += *image++;
				if (sum != 0xff) 
					return -1;
			} else if ((addr >= TSE_ADDR_COMMENT) &&
						(addr < TSE_ADDR_COMMENT_END)) {
				while (--len >= 0) {
					buf_cnt ++;
					if ((pbuffer != NULL) &&
					    (buf_cnt <= buf_len))
						*pbuffer++ = *image;
					sum += *image;
					image++;
					addr++;
				}

				sum += *image++;

				if (sum != 0xff)
					return -1;
			} else if((addr >= TSE_ADDR_NAMES) &&
						  (addr < TSE_ADDR_NAMES_END)) {
				while(--len >= 0) {
					if((names_buffer != NULL) &&
					   (names_buf_cnt <= names_buf_len)) {
						/* first function name will
						   start at beginning of char
						   buffer*/
						if (names_buf_cnt == 0) {
							names_tmp =
							   loader->names_buffer;
							if_name->name =
								      names_tmp;
							if_name++;
						} else {
							/* all following will
							   start at "\0" +1*/
							if (*image == '\0') {
								names_tmp =
								 names_buffer+1;
								if_name->name =
								      names_tmp;
								if_name++;
							}
						}

						*names_buffer++ = *image;
						names_buf_cnt++;
					}

					sum += *image;
					image++;
					addr++;
				}

				sum += *image++;
				if(sum != 0xff)
					return -1;
			}
		} else if (c >= 7 && c <= 9) { /* end record */
			pc = 0;
			do {
				pc = (pc << 8) | (uint8_t)*image++;
			} while (--len > 1);
			image++;
			break;
		} else if (c == 0 || c == 5) { /*header record or record count*/
			image += len;
		} else { /* invalid record */
			return -1;
		}
	}

	return (int32_t)pc;
}

void tse_progwrite(tse_t tse, int32_t address, uint16_t data)
{
	tse_link32(tse_createheader(tse,address,CODE,CMD_WRITE),data);
}

void tse_datawrite(tse_t tse, int32_t address, uint8_t *data, int len)
{
	int i;

#ifdef ENDIAN
	uint32_t dataw;
	uint32_t _data;
	header_t header;

	dataw = 0;

	tse_configdatatable(tse,USE);

	_data = (64<< 16) | (address >> 2); /* write size and base to hw */

	/*SIM_print("Base: %x Len: %d\n",Data&0xFFFF,len);*/

	/* table 7 reg 1 rewrite the base addr */
	header.all = tse_createheader(tse,((0x7 << 2) | 0x1) << 2,
				      TABLE, CMD_WRITE);

	_data = tse_link32(header.all, _data);

	address=0;
	for (i = 1;i <= len;i++) {
		dataw = (dataw<<8) | (uint8_t)*data++;
		if ((i%4) == 0) {
			tse_link32(tse_createheader(tse, address, DATA,
						    CMD_WRITE),
				   dataw);
			/*printf("DW 0x%08X --> 0x%08X\n",(address&0x3ff),dataw); */
			address = address + 1; /* +1 */
		}
	}
#else
	uint32_t *dataw;

	dataw = (uint32_t*)data;

	TSE_ConfigDataTable(tse,USE);

	for (i = 0; i < len; i = i + 4) {
		TSE_Link32(TSE_CreateHeader(tse,address+i,DATA,CMD_WRITE),*dataw);
		/*printf("DW 0x%08X --> 0x%08X\n",(address&0x3ff)+i,*dataw++);*/
	}
#endif

	tse_configdatatable(tse,RESTORE);

}

void tse_tablewrite(tse_t tse, int32_t address, uint32_t data)
{
	header_t header;

	header.all = tse_createheader(tse,address,TABLE,CMD_WRITE);
	tse_link32(header.all,data);

	header.index = header.index & 0x3f;

	if ((header.index >> 2) == 0x7) {
		data_table = USED;
		data_table_config[header.index & 0x3] = data;
	}
}

void tse_customwrite(tse_t tse, int32_t address, uint32_t data)
{
	tse_link32(tse_createheader(tse,address,CUSTOM,CMD_WRITE),data);
}

uint32_t tse_link32(uint32_t header, uint32_t data)
{
	uint32_t rdata;

#ifdef ENV_SIM
	uint32_t tse_data[2];
	tse_data[0]=header;
	tse_data[1]=data;

	/*printf("header %08lx data : %08lx\n",header,data);*/
	rdata = sim_tselink32(tse_data);

	/* check response bit in R0 */
#else

#ifdef SYSTEMC
	t_LINK_REGS	*pLink2	= (t_LINK_REGS*)LINK2(0);

	int ctrl,i;
	uint32_t tmp;

	response_t response;

	ctrl = 0;
	ctrl = ctrl | 
		(LINK_CTRL_BMX__MSK << LINK_CTRL_BMX) | 
		(LINK_CTRL_SOP__MSK << LINK_CTRL_SOP) | 
		(LINK_CTRL_EOP__MSK << LINK_CTRL_EOP);
	interface_write((unsigned int)(&pLink2->CTRL),ctrl);
	interface_write((unsigned int)(&pLink2->DATA0),data);
	interface_write((unsigned int)(&pLink2->DATA1),header);

	tmp = interface_read((unsigned int)(&pLink2->LEN));
	i = 10000; /* timeout */
	while ((tmp & (LINK_LEN_LENR__MSK<<LINK_LEN_LENR)) == 0) {
		tmp = interface_read((unsigned int)(&pLink2->LEN));
		i--;
		if (i == 0) {
			tmp = 0xffffffff;
			printf(">> CMD 0x%08X COP not response !  <<\n",header);
		}
	}

	rdata = interface_read((unsigned int)(&pLink2->DATA0));
	response.all = interface_read((unsigned int)(&pLink2->DATA1));

	if ((response.res != 1) || (response.error != 0))
		printf(">> CMD 0x%08X COP res = %d err = %d !  <<\n",
				header, response.res, response.error);
#else
	struct cop_message message;

	/* command */
	/*ONU_DEBUG_MSG("tse_link32 header: %08x", header);*/
	message.command[0] = header;
	message.request_length = LINKC1_HEADER_SIZE + 1;
	message.command[1] = 0;
	message.format = COP_FRM_FORMAT1;
	message.response_length = LINKC2_HEADER_SIZE;

	/* data */
	memcpy(&message.data[0], &data, 4);
	/*ONU_DEBUG_MSG("tse_link32");*/
	(void)cop_message(&message);

	rdata = message.data[0];
#endif

#endif

	return rdata;
}

uint32_t tse_createheader(tse_t tse, int32_t address,
			  destination_t destination, cmd_t cmd)
{
	header_t header;

	header.copid = tse;
	header.threadid = ThreadId;
	header.off = 0;

	header.table = 0;
	/* 10 bits of the address ( first data word) */
	header.index = address & 0x3FF;
	if (destination == CODE) {
		header.index = header.index>>1;
	} else if (destination == DATA) {
		header.index = header.index;
	} else {
		header.index = header.index>>2;
	}

	header.cmd = cmd;

	switch (destination) {
	case CUSTOM :
		header.index = header.index | (COSTUM_REG<<8);
		break;
	case TABLE :
		header.index = header.index | (TABLE_REG<<8);
		break;
	case CODE :
		header.index = header.index | (CODE_REG<<8);
		break;
	case GLOBAL :
		header.index = header.index | (GLOBAL_REG<<8);
		break;
	case DATA:
		header.table = DATA_TABLE;
		break;
	default:
#ifdef SYSTEMC
		printf("TSE: invalid destination for TSE loader = %i",
				destination);
#else
		ONU_DEBUG_ERR("TSE: invalid destination for TSE loader = %i",
				destination);
#endif
		break;
	}

	return header.all;
}

void tse_configdatatable(tse_t tse, config_t config)
{
	uint32_t global1;

	if (config == USE) {
		if ((data_table == UNUSED) || (data_table == USED)) {
			tse_link32(tse_createheader(tse, DATA_TABLE_REG0_ADDR,
						    TABLE,CMD_WRITE),
				   DATA_TABLE_REG0_VALUE);

			global1 = (tse_link32(tse_createheader(tse,
							GLOBAL_REG1_ADDR,
							GLOBAL,CMD_READ),
					      0)) & 0xffff;

			global1 = global1<<16;
			tse_link32(tse_createheader(tse, DATA_TABLE_REG1_ADDR,
						    TABLE,CMD_WRITE),
				   global1);

			if (data_table == UNUSED)
				data_table = UNUSED_CONFIGED;
		}
	} else { /* RESTORE */
		if (data_table == USED) {
			tse_link32(tse_createheader(tse, DATA_TABLE_REG0_ADDR,
						    TABLE,CMD_WRITE),
				   data_table_config[0]);

			tse_link32(tse_createheader(tse, DATA_TABLE_REG1_ADDR,
							 TABLE,CMD_WRITE),
				   data_table_config[1]);
		}
	}
}
