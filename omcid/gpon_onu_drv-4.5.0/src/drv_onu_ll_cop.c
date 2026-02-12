/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#include "drv_onu_api.h"
#include "drv_onu_register.h"
#include "drv_onu_gpe_interface.h"
#include "drv_onu_gpe_tables_interface.h"
#include "drv_onu_ll_sys.h"
#include "drv_onu_ll_cop.h"
#include "drv_onu_gpe_tables.h"
#include "drv_onu_tse_config.h"
#include "drv_onu_tse.h"
#include "drv_onu_ethertypes.h"
#include "drv_onu_gpe_tables_api.h"

/* =============================================================================
 * Global
 * ========================================================================== */
extern onu_lock_t cop_lock;

/* macro function used for message length alignment */
#define cop_round_up(x) (((x)+1) & ~1)

static const uint32_t port[3] = { 0, ONU_LINK0_SIZE/4, (2*ONU_LINK0_SIZE)/4};

#ifdef INCLUDE_COP_DEBUG
/* helper variable for COP code RAM during trace mode */
uint16_t code_ram[ONU_GPE_NUMBER_OF_COP][256];
#endif
/* COP timestamp value */
uint8_t timestamp_now = 0;
/* microcode version string container for dump functions */
char mc_version_string[ONU_GPE_NUMBER_OF_COP][256];
/* COP interface container for tool chain loader */
tse_interface_t tse_interface[ONU_GPE_COP_LABEL_MAX];
/* mapping structure for all COP microcode labels */
labelmapping_t labelmapping[ONU_GPE_ALL_COP_LABEL_MAX];

#ifdef INCLUDE_COP_DEBUG
/* synchronization flag during COP trace mode */
static uint32_t block_debug_read = 0;
/* control for COP debug mode */
uint32_t cop_debugmode[ONU_GPE_NUMBER_OF_COP];
/* strings for dump functions */
static const char *cop_str[32] = {
	"[TSE0] ",
	"[TSE1] ",
	"[TSE2] ",
	"[TSE3] ",
	"[TSE4] ",
	"[TSE5] ",
	"[?] ",
	"[?] ",

	"[?] ","[?] ","[?] ","[?] ","[?] ","[?] ","[?] ","[?] ",
	"[?] ","[?] ","[?] ","[?] ","[?] ","[?] ","[?] ","[?] ",
	"[?] ","[?] ","[?] ","[?] ","[?] ","[?] ","[TBM ] ","[LOOP] "
};
#endif

uint32_t onu_gpe_cop_entrysize[] = {
	32,
	64,
	128,
	256
};

uint32_t onu_gpe_cop_keysize[] = {
	0,
	16,
	32,
	64,
	96,
	128,
	144,
	160
};

uint32_t cop_table_size_get(uint32_t cop_id, uint32_t table_id)
{
	uint32_t global_id;

	global_id = cop_id*8 + table_id;

	/* This function is used to get the maximum message length, but
	 * HASH table sizes can not be derived directly from configuration
	 * structure, because table size is larger than configuration.
	 *
	 * A message for HASH tables need size of entry and key length!
	 * */
	if (cop_tbl_cfg[global_id].type == ONU_GPE_COP_HASH)
		return ((cop_tbl_cfg[global_id].entry_width +
				 cop_tbl_cfg[global_id].key_len) / 8) / 4;
	else
		return (cop_tbl_cfg[global_id].entry_width / 8) / 4;
}

static INLINE void reset_message_data(struct cop_message *message)
{
	uint16_t cnt;

	for (cnt = 0; cnt < ONU_GPE_COP_DATASIZE_MAX; cnt++)
		message->data[cnt] = 0;

	for (cnt = 0; cnt < ONU_GPE_COP_CMDSIZE_MAX; cnt++)
		message->command[cnt] = 0;

}
/** \addtogroup ONU_MAPI_REFERENCE_INTERNAL
   @{
*/

/** \addtogroup ONU_GPE_INTERNAL
   @{
*/

/* =============================================================================
 * Initialization and Configuration
 * ========================================================================== */
enum cop_errorcode cop_code_set(struct onu_device *p_dev)
{
	struct onu_control *ctrl = p_dev->ctrl;
	tse_loader_t loader;
	uint16_t cop_id;
	uint32_t label_idx;
	char names_buffer[ONU_GPE_COP_LABEL_MAX*ONU_GPE_COP_LABEL_STR_SIZE_MAX];

	/* handle structure of images for COP loader */
	const char* tse_images[ONU_GPE_NUMBER_OF_COPWMC] = {
			"tse0.bin",
			"tse1.bin",
			"tse2.bin",
			"tse3.bin",
			"tse4.bin",
			"tse5.bin"
	};

	/* initialize COP loader interface structure */
	for (label_idx = 0; label_idx < ONU_GPE_COP_LABEL_MAX; label_idx++) {
		tse_interface[label_idx].id = 0;
		tse_interface[label_idx].addr = 0;
		tse_interface[label_idx].name = names_buffer;
	}

	/* initialize mapping interface structure */
	for (label_idx = 0; label_idx < ONU_GPE_ALL_COP_LABEL_MAX; label_idx++) {
		labelmapping[label_idx].cop_id = 0;
		labelmapping[label_idx].func_addr = 0;
		labelmapping[label_idx].label_name[0] = '\0';
	}

	/* activate clock */
	sys_gpe_hw_activate_or_reboot(	SYS_GPE_ACT_COP7_SET |
					SYS_GPE_ACT_COP6_SET |
					SYS_GPE_ACT_COP5_SET |
					SYS_GPE_ACT_COP4_SET |
					SYS_GPE_ACT_COP3_SET |
					SYS_GPE_ACT_COP2_SET |
					SYS_GPE_ACT_COP1_SET |
					SYS_GPE_ACT_COP0_SET);

	for (cop_id = 0; cop_id < ONU_GPE_NUMBER_OF_COPWMC; cop_id++) {

		if (onu_microcode_load(ctrl, tse_images[cop_id]) != 0)
			return ONU_STATUS_FW_LOAD_ERR;

		/* initialize the COP loader structure */
		loader.tse = cop_id;
		loader.pbuffer = mc_version_string[cop_id];
		loader.NamesBufLen = sizeof(names_buffer);
		loader.names_buffer = &names_buffer[0];
		loader.BufLen = sizeof(names_buffer);
		loader.image = (char *)&ctrl->cop_microcode_bin[0];
		loader.image_len = ctrl->cop_microcode_len;
		loader.tse_if = &(tse_interface[0]);
		loader.data_init = 0;
		label_idx = 0;
		if (tse_load(&loader) > 0)
			return COP_INIT_ERR;

#ifdef ONU_COP_USE_COP_LOADER_RAM_INIT
		if (!loader.data_init)
			return COP_INIT_ERR;
#endif

		/* map the physical address of microcode function pointers to
		   logical IDs */
		while (tse_interface[label_idx].id != 0) {
			labelmapping[tse_interface[label_idx].id].cop_id = cop_id;
			labelmapping[tse_interface[label_idx].id].func_addr =
					     tse_interface[label_idx].addr >> 1;
			strcpy(
			   labelmapping[tse_interface[label_idx].id].label_name,
			   tse_interface[label_idx].name);

			label_idx++;
		}
	}

	return COP_STATUS_OK;
}

/** cop_cfg_set Hardware Programming Details
   Each of the hardware accelerators (coprocessors) is configured individually.
*/
enum cop_errorcode cop_cfg_set(void)
{
	enum cop_errorcode errorcode;
	enum onu_errorcode onuerrorcode;
	struct gpe_table_entry 	entry;
	struct gpe_ext_vlan_custom extvlancustom;
	uint16_t cop_id;

	entry.id = 0; /* Table 0 accesses the register table */
	for (cop_id = 0; cop_id < ONU_GPE_NUMBER_OF_COPWMC; cop_id++) {
#ifdef INCLUDE_COP_DEBUG
		cop_debugmode[cop_id] = 0;
#endif

		entry.index = (uintptr_t)COPLINK_COP_GLOBAL2;
		entry.instance = (uint8_t)cop_id;
		entry.data.message.data[0] = TID_CPU32 << 16;

		/* set the TRACE_ID for debugging mode */
		errorcode = cop_table_entry_write(&entry, ONU_GPE_COP_TABLE0W);

		if (errorcode != COP_STATUS_SUCCESS)
			return errorcode;

		if (is_falcon_chip_a2x()) {
			entry.index = (uintptr_t)COPLINK_COP_GLOBAL5;
			entry.instance = (uint8_t)cop_id;
			entry.data.message.data[0] = 0xf1000003;

			/* disable compatibility mode */
			errorcode = cop_table_entry_write(&entry, ONU_GPE_COP_TABLE0W);

			if (errorcode != COP_STATUS_SUCCESS)
				return errorcode;
		}
	}

	/*
	 * 2nd part
	 * DRAM initialization:
	 *
	 * ARRAY,VARRAY, HASHES: initialize everything to zero
	 * LIST: only valid bit to zero, and only end bit to 1 in every entry
	 * LLIST: everything to zero, but create linked list, last entry has
	 * end=1,
	 * 		  start of list into AUX field
	 */

#ifndef ONU_COP_USE_COP_LOADER_RAM_INIT
	errorcode = cop_table_init(0, COP_TABLE_CFG_SIZE);
	if (errorcode != COP_STATUS_SUCCESS)
		return errorcode;
#else
	for (index = 0;
		index < cop_tbl_cfg[ONU_GPE_LEARNING_LIMITATION_TABLE_ID].size;
		index++) {

		entry.id	= (ONU_GPE_LEARNING_LIMITATION_TABLE_ID % 8);
		entry.index	= index;
		entry.instance	= ONU_GPE_LEARNING_LIMITATION_TABLE_COP_ID;

		entry.data.message.data[0] = 0xFFFF0000;

		errorcode = cop_table_entry_write(&entry, LINKC1_WRITE);

		if (errorcode != COP_STATUS_SUCCESS)
			return errorcode;
	}
#endif

	/* Set ExtVLAN custom match parameters according to G988.4 */
	memset(&extvlancustom, 0, sizeof(extvlancustom));
	extvlancustom.defrule = 1;
	extvlancustom.tpid = ONU_ETHERTYPE_CVLAN;
	extvlancustom.ety1 = ONU_ETHERTYPE_IPV4;
	extvlancustom.ety2 = ONU_ETHERTYPE_PPPOE_DISC;
	extvlancustom.ety3 = ONU_ETHERTYPE_ARP;
	extvlancustom.ety4 = ONU_ETHERTYPE_IPV6;
	/* extvlancustom.ety5 = 0; */
	onuerrorcode = gpe_ext_vlan_custom_set(NULL, &extvlancustom);
	if (onuerrorcode != ONU_STATUS_OK)
		return COP_STATUS_ERR;

	return COP_STATUS_OK;
}

#ifdef INCLUDE_COP_DEBUG
enum cop_errorcode cop_debug_set(const uint8_t cop_id,
				 uint32_t const trace_enable)
{
	struct gpe_table_entry 	entry;
	enum cop_errorcode errorcode;
	enum onu_errorcode ret;
	uint32_t cnt, data, code_ram_size;
	uint16_t instr;

	/* do not set debug trace twice, HW gets messed up */
	if (trace_enable == true && cop_debugmode[cop_id] == true) {
		block_debug_read = 0;
		return COP_STATUS_OK;
	}

	/* if debugging trace mode is switched on, read out CRAM,
	 * during debug trace mode CRAM access is not possible any more
	 */
	if (trace_enable == true && cop_debugmode[cop_id] == false) {

		entry.instance 	= cop_id;
		entry.index 	= (uintptr_t)COPLINK_COP_GLOBAL1;
		/* do not analyze return value */
		ret		= cop_table0_read(&entry);
		data		= entry.data.message.data[0];

		code_ram_size	= (data>>16) & 0xff;

		/* Read COP code memory */
		for (cnt = 0; cnt < code_ram_size; cnt++) {
			entry.index  = (uintptr_t)COPLINK_COP_CRAM + cnt;
			/* do not analyze return value */
			ret	     = cop_table0_read(&entry);
			instr        = entry.data.message.data[0] & 0xffff;
			code_ram[cop_id][cnt] = instr;
		}
	}

	/* Declare global registers */
	entry.id	= 0;
	entry.instance 	= cop_id;
	entry.index	= (uintptr_t)COPLINK_COP_GLOBAL2;
	entry.data.message.data[0] = (TID_CPU32 << 16) | trace_enable;

	/* Activate the debug trace mode */
	block_debug_read = true;
	errorcode = cop_table_entry_write(&entry, ONU_GPE_COP_TABLE0W);
	cop_debugmode[cop_id] = trace_enable;

	if (errorcode != COP_STATUS_SUCCESS)
		return errorcode;

	cop_debug_step(cop_id);

	return COP_STATUS_OK;
}
#endif

#ifdef INCLUDE_COP_DEBUG
uint32_t cop_debug_get(const uint8_t cop_id)
{
	return cop_debugmode[cop_id];
}
#endif

#ifdef INCLUDE_COP_DEBUG
void cop_debug_step(const uint32_t cop_id)
{
	ONU_DEBUG_MSG("debug step !");
	pctrl_w32(cop_id, tsestep);
}
#endif

/* The cop_init function is used to initialize the COP hardware.
 * This function should never be called during runtime.
 *
 * It initializes the COP microcode, COP configuration and DRAM.
 */
enum cop_errorcode cop_init(struct onu_device *p_dev)
{
	enum cop_errorcode errorcode;
	struct onu_control *ctrl = p_dev->ctrl;

	errorcode = cop_code_set(p_dev);

	if (errorcode == COP_STATUS_OK)
		errorcode = cop_cfg_set();

	if (is_falcon_chip_a2x()) {
		/* GPONC-178 Mgmt for LIST type */
		/* The LIST Mgmt is required for:
		 * ONU_GPE_DS_MC_IPV4_SOURCE_FILTER_TABLE
		 * ONU_GPE_DS_MC_IPV6_SOURCE_FILTER_TABLE
		 * ONU_GPE_MAC_FILTER_TABLE
		 * ONU_GPE_ETHERTYPE_FILTER_TABLE
		 *
		 * \todo:
		 * The table is initialized with the maximum size (IPV4_SOURCE_FILTER),
		 * thus an memory overhead can be optimized, maybe also by using malloc...
		 */
		memset(&ctrl->cop_list_info, 0xFF, 4 * 16 * sizeof(uint32_t));
	}

	return errorcode;
}

enum cop_errorcode cop_table_init(uint32_t from_table_id, uint32_t to_table_id)
{
	enum cop_errorcode errorcode;
	struct gpe_table_entry 	entry;
	uint16_t table_id;
	uint32_t next, req_entry_size;
	uint16_t cop_id;
	uint32_t index;
#ifdef ONU_COP_DEBUG_LL
	uint16_t cnt;
#endif /* ONU_COP_DEBUG_LL */

	for (table_id = 0; table_id < COP_TABLE_CFG_SIZE-8; table_id++) {

		/* do not overwrite COP internal tables, software would try to
		   access them */
		if (cop_tbl_cfg[table_id].type != ONU_GPE_COP_UNDEF) {
			index = (table_id % 8) * 0x4;
			entry.index	= index + 1;
			entry.instance = table_id / 8;
			cop_table0_read(&entry);

			cop_tbl_cfg[table_id].size =
			 (entry.data.message.data[0] & COP_TABLE11_SIZE_MASK) >>
							COP_TABLE11_SIZE_OFFSET;
			cop_tbl_cfg[table_id].base =
			 (entry.data.message.data[0] & COP_TABLE11_BASE_MASK) >>
							COP_TABLE11_BASE_OFFSET;

			entry.index	= index;
			entry.instance = table_id / 8;
			cop_table0_read(&entry);

			cop_tbl_cfg[table_id].type =
			 (entry.data.message.data[0] & COP_TABLE10_TYPE_MASK) >>
							COP_TABLE10_TYPE_OFFSET;

			/* consider GPONC-122 */
			if (cop_tbl_cfg[table_id].type != ONU_GPE_COP_HASH ||
				is_falcon_chip_a2x()) {

				cop_tbl_cfg[table_id].entry_width =
					onu_gpe_cop_entrysize[
					   (entry.data.message.data[0] &
					      COP_TABLE10_ENTRY_SIZE_MASK) >>
					         COP_TABLE10_ENTRY_SIZE_OFFSET];

				cop_tbl_cfg[table_id].key_len =
					onu_gpe_cop_keysize[
					   (entry.data.message.data[0] &
					      COP_TABLE10_KEY_SIZE_MASK) >>
					         COP_TABLE10_KEY_SIZE_OFFSET];
			}
		}
	}
#ifdef ONU_COP_DEBUG_LL
	ONU_DEBUG_MSG("from_table_id: %i, to_table_id: %i",
			from_table_id,
			to_table_id);
#endif /* ONU_COP_DEBUG_LL */
	if (from_table_id > to_table_id ||
	    from_table_id >= COP_TABLE_CFG_SIZE ||
	    to_table_id > COP_TABLE_CFG_SIZE)
		return COP_INIT_ERR;

	if (from_table_id == to_table_id)
		to_table_id = from_table_id+1;

	for (table_id = from_table_id; table_id < to_table_id; table_id++) {
		if (cop_tbl_cfg[table_id].type == ONU_GPE_COP_UNDEF)
			continue;

		cop_id = table_id / 8;

		req_entry_size = cop_tbl_cfg[table_id].entry_width / 32 +
			((cop_tbl_cfg[table_id].entry_width % 32 == 0) ? 0 : 1);
#ifdef ONU_COP_DEBUG_LL
		ONU_DEBUG_MSG("reqsize: %i", req_entry_size);
#endif /* ONU_COP_DEBUG_LL */

		switch (cop_tbl_cfg[table_id].type) {
		case ONU_GPE_COP_HASH:
			memset(&(entry.hashdata.message.data[0]), 0, 4);
			break;
		case ONU_GPE_COP_ARRAY:
		case ONU_GPE_COP_VARRAY:
			memset(&(entry.data.message.data[0]), 0,
				req_entry_size == 1 ? 4 : req_entry_size * 4);

			if (table_id == ONU_GPE_LEARNING_LIMITATION_TABLE_ID)
				entry.data.message.data[0] = 0xFFFF0000;

			break;

		case ONU_GPE_COP_LIST:
			memset(	&(entry.data.message.data[0]), 0,
				req_entry_size * 4);
			if (is_falcon_chip_a1x()) /* GPONC-79 */
				entry.data.message.data[req_entry_size-1] = 1 << 30;
			else
				entry.data.message.data[req_entry_size-1] = 0;
			break;

		case ONU_GPE_COP_LLIST:
			/* handled below (requires extra work) */
			break;

		case ONU_GPE_COP_BITVECT:
			/* not handled; return error */
			return COP_STATUS_ERR;
		}

		for (index = 0; index < cop_tbl_cfg[table_id].size; index++) {

			if (cop_tbl_cfg[table_id].type == ONU_GPE_COP_LLIST) {

				memset(&entry.data, 0, req_entry_size * 4);

				next =
				   (index + 1) *
				      (cop_tbl_cfg[table_id].entry_width / 32) +
				         cop_tbl_cfg[table_id].base;

				if (index == cop_tbl_cfg[table_id].size - 1)
					entry.data.
					   message.data[req_entry_size-1] =
									1 << 30;
				else
					entry.data.
					   message.data[req_entry_size-1] =
								     next << 16;

#ifdef ONU_COP_DEBUG_LL
				ONU_DEBUG_MSG("LLIST\n");
				for (cnt = 0 ; cnt < req_entry_size; cnt++)
					ONU_DEBUG_MSG("%08x ",
						entry.data.message.data[cnt]);
				ONU_DEBUG_MSG("\n");
#endif /* ONU_COP_DEBUG_LL */
			}

			entry.id	= (table_id % 8);
			entry.index 	= index;
			entry.instance 	= (uint8_t)cop_id;
			errorcode 	= cop_table_entry_write(&entry,
								LINKC1_WRITE);

			if (errorcode != COP_STATUS_SUCCESS)
				return errorcode;
		}

		/* set AUX field and ENTRY_COUNTER new */
		entry.id = 0;
		entry.instance = GPE_TABLE_COP(table_id);
		entry.index = 4 * GPE_TABLE_ID(table_id) + 2;

		entry.data.message.data[0]  = COP_TABLE12_AUX_V;
		entry.data.message.data[0] |=
			   (cop_tbl_cfg[table_id].base & COP_TABLE12_AUX_MASK);

		errorcode = cop_table_entry_write(&entry, ONU_GPE_COP_TABLE0W);
		if (errorcode != COP_STATUS_SUCCESS)
			return errorcode;
	}

	return COP_STATUS_SUCCESS;
}

/* =============================================================================
 * Level 1 - Physical
 * ========================================================================== */
enum cop_errorcode cop_table0_read(struct gpe_table_entry *entry)
{
	enum cop_errorcode errorcode;
	uint32_t in = entry->id;

	entry->id = 0;

	errorcode = cop_table_entry_read(entry, ONU_GPE_COP_TABLE0R);

	entry->id = in;

	/* FIXME: why not returning errorcode?? */
	return COP_STATUS_OK;
}

/** The cop_message_send function is used to send data from
 *  software via the LINK2 interface to the COP hardware.
 */
enum cop_errorcode cop_message_send(const struct cop_message *message)
{
	uint32_t i, tmp, len;
#ifdef ONU_COP_DEBUG_LL
	uint32_t cop_id, cmd;
#endif
	/* wait for number of 64 bit words */
	i=0;
	do {
		tmp = link_r32_table(len, port[2]) & LINK_LEN_LENX_MASK;
		if (i >= LINK_TIMEOUT) {
			ONU_DEBUG_ERR(LINK2
				"tx FIFO access timeout, FIFO is full (%u), "
				"(cop_id=%u table_id=%u, index=%u)",
				tmp,
				(message->command[0] >> ONU_GPE_COP_COPID_POS) &
							 ONU_GPE_COP_COPID_MSK,
				(message->command[0] >> ONU_GPE_COP_TABLE_POS) &
							 ONU_GPE_COP_TABLE_MSK,
				(message->command[0] >> ONU_GPE_COP_INDEX_POS) &
							 ONU_GPE_COP_INDEX_MSK);
			return COP_STATUS_TIMEOUT;
		}
		i++;
	} while (tmp < message->request_length/2U);

#ifdef ONU_COP_DEBUG_LL
	cop_id = (message->command[0] >> ONU_GPE_COP_COPID_POS) &
							ONU_GPE_COP_COPID_MSK;
	cmd    = (message->command[0] >> ONU_GPE_COP_CMD_POS) &
							ONU_GPE_COP_CMD_MSK;
#endif

	if (message->request_length == 2) {
	    /* single word */
		link_w32_table(	LINK_CTRL_BMX | LINK_CTRL_SOP | LINK_CTRL_EOP,
				ctrl, port[2]);
		link_w32_table(message->data[0], data0, port[2]);
		link_w32_table(message->command[0], data1, port[2]);
#ifdef ONU_COP_DEBUG_LL
		ONU_DEBUG_MSG(LINK2 "send    %08x (cop_id=%d table_id=%d, "
			      "index=%d, nil=%u)",
				message->command[0],
				cop_id,
				(message->command[0] >> ONU_GPE_COP_TABLE_POS) &
							 ONU_GPE_COP_TABLE_MSK,
				(message->command[0] >> ONU_GPE_COP_INDEX_POS) &
							 ONU_GPE_COP_INDEX_MSK,
			    (message->command[0] >> ONU_GPE_COP_NIL_POS) &
							 ONU_GPE_COP_NIL_MSK);
		ONU_DEBUG_MSG(LINK2 "send    %08x ", message->data[0]);
#endif /* ONU_COP_DEBUG_LL */
	} else {

		/* 1st word */
		link_w32_table(LINK_CTRL_BMX | LINK_CTRL_SOP, ctrl, port[2]);
		if (message->format == COP_FRM_FORMAT1) { /* format1: ADD, SEARCHW, etc. */
			link_w32_table(message->data[0]   , data0, port[2]);
			link_w32_table(message->command[0], data1, port[2]);
#ifdef ONU_COP_DEBUG_LL
			ONU_DEBUG_MSG(LINK2
			   "send    %08x (cop_id=%d table_id=%d, index=%d, nil=%d)",
			      message->command[0], cop_id,
			      (message->command[0] >> ONU_GPE_COP_TABLE_POS) &
							 ONU_GPE_COP_TABLE_MSK,
			      (message->command[0] >> ONU_GPE_COP_INDEX_POS) &
							 ONU_GPE_COP_INDEX_MSK,
			      (message->command[0] >> ONU_GPE_COP_NIL_POS) &
							 ONU_GPE_COP_NIL_MSK);
			ONU_DEBUG_MSG(LINK2 "send    %08x ", message->data[0]);
#endif /* ONU_COP_DEBUG_LL */

			i=1;
		} else { /* format2: WRITE */
			link_w32_table(message->command[1], data0, port[2]);
			link_w32_table(message->command[0], data1, port[2]);
#ifdef ONU_COP_DEBUG_LL
			ONU_DEBUG_MSG(LINK2 "send    %08x ", message->command[0]);
			ONU_DEBUG_MSG(LINK2 "send    %08x ", message->command[1]);
#endif /* ONU_COP_DEBUG_LL */
			i=0;
		}

		/* intermediate words */
		link_w32_table(LINK_CTRL_BMX, ctrl, port[2]);
		for (len = 2; len < (uint32_t)(message->request_length-2);
								len+=2, i+=2) {
			link_w32_table(message->data[i+0], data0, port[2]);
			link_w32_table(message->data[i+1], data1, port[2]);
#ifdef ONU_COP_DEBUG_LL
			ONU_DEBUG_MSG(LINK2 "send    %08x ", message->data[i+0]);
			ONU_DEBUG_MSG(LINK2 "send    %08x ", message->data[i+1]);
#endif /* ONU_COP_DEBUG_LL */
		}

		/* last word */
		link_w32_table(LINK_CTRL_BMX | LINK_CTRL_EOP, ctrl, port[2]);
		link_w32_table(message->data[i+0], data0, port[2]);
		link_w32_table(message->data[i+1], data1, port[2]);

#ifdef ONU_COP_DEBUG_LL
		ONU_DEBUG_MSG(LINK2 "send    %08x ", message->data[i+0]);
		ONU_DEBUG_MSG(LINK2 "send    %08x ", message->data[i+1]);
#endif /* ONU_COP_DEBUG_LL */
	}

#ifdef ONU_COP_DEBUG_LL
	if (cop_debug_get(cop_id) &&
				((cmd & ONU_GPE_COP_EXEC) == ONU_GPE_COP_EXEC))
		cop_debug_step(1 << cop_id);
	/*else if (cop_debug_get(cop_id)) {
		block_debug_read = 0;
	}*/
#endif

	return COP_STATUS_OK;
}

/** The cop_message_receive function is used to receive data from
 *  the COP hardware via the LINK2 interface for the software.
 */
enum cop_errorcode cop_message_receive(struct cop_message *message)
{
	uint32_t i;
	uint32_t len, is_tracepacket = false;
	uint32_t temp0, temp1;

#ifdef INCLUDE_COP_DEBUG
	uint32_t cop_id, thread_id, table_id, index;
	enum cop_errorcode ret;
#endif

	if (message->response_length > ONU_GPE_COP_DATASIZE_MAX)
		return COP_STATUS_ERR;

	do {
		/* wait for number of 64 bit words */
		i=0;
		do {
			len = link_r32_table(len, port[2]);
			if (i >= LINK_TIMEOUT) {
				ONU_DEBUG_MSG(LINK2 "bail out in receive...");
				return COP_STATUS_TIMEOUT;
			}
			i++;

		} while (((len & LINK_LEN_LENR_MASK) >> LINK_LEN_LENR_OFFSET) <
						   message->response_length/2U);

		temp0 = link_r32_table(data0, port[2]);
		temp1 = link_r32_table(data1, port[2]);
#ifdef INCLUDE_COP_DEBUG
		cop_id = ((temp1 >> ONU_GPE_COP_COPID_POS) & ONU_GPE_COP_COPID_MSK);
		thread_id = ((temp1 >> ONU_GPE_COP_TID_POS) & ONU_GPE_COP_TID_MSK);
		table_id = ((temp1 >> ONU_GPE_COP_TABLE_POS) & ONU_GPE_COP_TABLE_MSK);
		index = ((temp1 >> ONU_GPE_COP_INDEX_POS) & ONU_GPE_COP_INDEX_MSK);

		/* check for tracing response */
		if (thread_id == TID_CPU32) {

			ret = cop_debug_receive(temp0, temp1);
			if (ret)
				return ret;

			cop_debug_step(1 << cop_id);

			is_tracepacket = true;

		} else {
			is_tracepacket = false;
		}
#endif

	} while (is_tracepacket);

	if (message->response_length == 2) {
		/* single word */
		message->data[0]    = temp0;
		message->command[0] = temp1;

#ifdef ONU_COP_DEBUG_LL
		ONU_DEBUG_MSG(LINK2
			"rec     %08x (cop_id=%d table_id=%d, "
			"index=%d, error=%d, result=%d, nil=%d)",
			   message->command[0], cop_id, table_id, index,
			   (message->command[0] >> ONU_GPE_COP_ERR_POS) &
							ONU_GPE_COP_ERR_MSK,
			   (message->command[0] >> ONU_GPE_COP_RESULT_POS) &
							ONU_GPE_COP_RESULT_MSK,
			   (message->command[0] >> ONU_GPE_COP_NIL_POS) &
							ONU_GPE_COP_NIL_MSK);
		ONU_DEBUG_MSG(LINK2 "rec     %08x ", message->data[0]);
#endif /* ONU_COP_DEBUG_LL */
	} else {
		/* first word */
		message->command[1] = temp0;
		message->command[0] = temp1;

#ifdef ONU_COP_DEBUG_LL
		ONU_DEBUG_MSG(LINK2
			"rec     %08x (cop_id=%d table_id=%d, "
			"index=%d, error=%d, result=%d, nil=%d)",
			   message->command[0], cop_id, table_id, index,
			   (message->command[0] >> ONU_GPE_COP_ERR_POS) &
							ONU_GPE_COP_ERR_MSK,
			   (message->command[0] >> ONU_GPE_COP_RESULT_POS) &
							ONU_GPE_COP_RESULT_MSK,
			   (message->command[0] >> ONU_GPE_COP_NIL_POS) &
			   	   	   	    ONU_GPE_COP_NIL_MSK);
		ONU_DEBUG_MSG(LINK2 "rec     %08x ", message->command[1]);
#endif /* ONU_COP_DEBUG_LL */

		/* other words */
		for (i=0; i < (uint32_t)(message->response_length-2); i+=2) {
			message->data[i+0] = link_r32_table(data0, port[2]);
			message->data[i+1] = link_r32_table(data1, port[2]);

#ifdef ONU_COP_DEBUG_LL
			ONU_DEBUG_MSG(LINK2 "rec     %08x ", message->data[i+0]);
			ONU_DEBUG_MSG(LINK2 "rec     %08x ", message->data[i+1]);
#endif /* ONU_COP_DEBUG_LL */
		}
	}

#ifdef INCLUDE_COP_DEBUG
	if (cop_debug_get(cop_id) == true) {

		/* we do not assume to get a debug message */
		if (block_debug_read ) {
			/* release the blocking mechanism for debugging */
			block_debug_read = false;
		} else {

			cop_debug_step(1 << cop_id);

			/* wait for last 5 debug words */
			ret = cop_debug_receive(temp0, temp1);
			if (ret)
				return ret;
		}
	}
#endif

	return COP_STATUS_OK;
}

#ifdef INCLUDE_COP_DEBUG
/** The cop_poll_debug_receive function is used to poll debug data from
 *  the COP hardware via the LINK2 interface for the software.
 */
void cop_debug_server(const uint32_t stepcnt, const uint32_t cop_mask)
{
	uint32_t i, len, msglen, thread_id, pc, cop_id, eop, loopcnt, table_id,
		 index, cnt, data[10];
	char opcode[256];


	for (cnt = 1; cnt <= stepcnt; cnt++) {
		/* wait for any packet */
		msglen=0;
		do {
			/* wait for data */
			loopcnt = 0;
			do {
				len = link_r32_table(len, port[2]);
				if (loopcnt >= LINK_TIMEOUT) {
					ONU_DEBUG_MSG(LINK2
						      "bail out in receive...");
					return;
				}
				loopcnt++;

			} while (((len & LINK_LEN_LENR_MASK)
						>> LINK_LEN_LENR_OFFSET) < 1);

			/* check for last data */
			eop = (link_r32_table(ctrl, port[2]) & LINK_CTRL_EOP) != 0;

			/* copy data */
			data[msglen+0] = link_r32_table(data0, port[2]);
			data[msglen+1] = link_r32_table(data1, port[2]);
			msglen+=2;
		} while (eop==0); /* more data */

		cop_id    = ((data[1] >> ONU_GPE_COP_COPID_POS) &
							ONU_GPE_COP_COPID_MSK);
		thread_id = ((data[1] >> ONU_GPE_COP_TID_POS) &
							ONU_GPE_COP_TID_MSK);

		if (thread_id == TID_CPU32) {

			pc = ((data[0] >> ONU_GPE_COP_DBGPC_POS) &
							ONU_GPE_COP_DBGPC_MSK);

			cop_debug_disassembly(code_ram[cop_id][pc], opcode,
					      sizeof(opcode));

			ONU_DEBUG_MSG(
					"%s COP:   %1d  TID:  0x%2x",
					cop_str[cop_id],
					cop_id,
					thread_id
					);

			ONU_DEBUG_MSG("%s PC:    %03x      %04x  %s", cop_str[cop_id], pc, code_ram[cop_id][pc & 0xFF], opcode);
			ONU_DEBUG_MSG(
					"%s TABLE: %3d  PREV: %3d   RES1: %1d   OFF:  %1d",
					cop_str[cop_id],
					((data[1] >> ONU_GPE_COP_TABLE_POS) & ONU_GPE_COP_TABLE_MSK),
					((data[0] >> ONU_GPE_COP_DBGPREV_POS) & ONU_GPE_COP_DBGPREV_MSK),
					((data[1] >> ONU_GPE_COP_RESULT_POS) & ONU_GPE_COP_RESULT_MSK),
					((data[1] >> ONU_GPE_COP_DBGOFF_POS) & ONU_GPE_COP_DBGOFF_MSK)
					);

			ONU_DEBUG_MSG(
					"%s INDEX: %3d  NEXT: %3d   RES2: %1d   ERR:  %1d",
					cop_str[cop_id],
					((data[1] >> ONU_GPE_COP_INDEX_POS) & ONU_GPE_COP_INDEX_MSK),
					((data[0] >> ONU_GPE_COP_DBGNEXT_POS) & ONU_GPE_COP_DBGNEXT_MSK),
					((data[0] >> ONU_GPE_COP_DBGRES2_POS) & ONU_GPE_COP_DBGRES2_MSK),
					((data[0] >> ONU_GPE_COP_DBGERR_POS) & ONU_GPE_COP_DBGERR_MSK)
			);

			ONU_DEBUG_MSG("%s DATA:  %08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x",
					cop_str[cop_id],
					data[9], data[8], data[7], data[6], data[5], data[4], data[3], data[2]);

			ONU_DEBUG_MSG("");

			cop_debug_step(1 << cop_id);
		} else if (thread_id == TID_CPU31) {
			/** ASCII print for PE should be placed here if required */
		} else {

			if ((cop_id > 0 && cop_id <= 5) && (cop_id & cop_mask)) {
				table_id = ((data[1] >> ONU_GPE_COP_TABLE_POS) &
						ONU_GPE_COP_TABLE_MSK);
				index = ((data[1] >> ONU_GPE_COP_INDEX_POS) &
						ONU_GPE_COP_INDEX_MSK);

				ONU_DEBUG_MSG(LINK2
					"rec     %08x (cop_id=%d table_id=%d, "
					"index=%d, error=%d, result=%d)",
					   data[1], cop_id, table_id, index,
					   (data[1] >> ONU_GPE_COP_ERR_POS) &
							    ONU_GPE_COP_ERR_MSK,
					   (data[1] >> ONU_GPE_COP_RESULT_POS) &
							ONU_GPE_COP_RESULT_MSK);
				ONU_DEBUG_MSG(LINK2 "rec     %08x ", data[0]);

				/* other words */
				for (i=2; i < msglen; i+=2) {
					ONU_DEBUG_MSG(LINK2 "rec     %08x ",
								     data[i+0]);
					ONU_DEBUG_MSG(LINK2 "rec     %08x ",
								     data[i+1]);
				}
			} else { /* TBM or other COP */
				for (i=0; i < msglen; i+=2) {
					ONU_DEBUG_MSG(LINK2 "rec     %08x ",
								     data[i+0]);
					ONU_DEBUG_MSG(LINK2 "rec     %08x ",
								     data[i+1]);
				}
			}
		}
	}
}
#endif

#ifdef INCLUDE_COP_DEBUG
/** The cop_debug_receive function is used to debug data from
 *  the COP hardware via the LINK2 interface for the software.
 */
enum cop_errorcode cop_debug_receive(uint32_t temp0, uint32_t temp1)
{
	uint32_t i, len, pc, temp[8], cop_id;
	char opcode[256];

	i = 0;
	/* tracing response is always 5 words, thus remaining 4 needs to be
	   received */
	do {
		len = link_r32_table(len, port[2]);
		if (i >= LINK_TIMEOUT) {
			ONU_DEBUG_MSG(LINK2 "bail out in debug receive...");
			return COP_STATUS_TIMEOUT;
		}
		i++;

	} while (((len & LINK_LEN_LENR_MASK) >> LINK_LEN_LENR_OFFSET) < 4);

	pc = ((temp0 >> ONU_GPE_COP_DBGPC_POS) & ONU_GPE_COP_DBGPC_MSK);
	cop_id = ((temp1 >> ONU_GPE_COP_COPID_POS) & ONU_GPE_COP_COPID_MSK);

	cop_debug_disassembly(code_ram[cop_id][pc], opcode, sizeof(opcode));

	ONU_DEBUG_MSG("%s PC:    %03x      %04x  %s", cop_str[cop_id], pc,
		code_ram[cop_id][pc & 0xFF], opcode);
	ONU_DEBUG_MSG(
		"%s TABLE: %3d  PREV: %3d   RES1: %1d   OFF:  %1d",
			cop_str[cop_id],
			((temp1 >> ONU_GPE_COP_TABLE_POS) &
							ONU_GPE_COP_TABLE_MSK),
			((temp0 >> ONU_GPE_COP_DBGPREV_POS) &
							ONU_GPE_COP_DBGPREV_MSK),
			((temp1 >> ONU_GPE_COP_RESULT_POS) &
							ONU_GPE_COP_RESULT_MSK),
			((temp1 >> ONU_GPE_COP_DBGOFF_POS) &
							ONU_GPE_COP_DBGOFF_MSK)
			);

	ONU_DEBUG_MSG(
		"%s INDEX: %3d  NEXT: %3d   RES2: %1d   ERR:  %1d",
			cop_str[cop_id],
			((temp1 >> ONU_GPE_COP_INDEX_POS) &
							ONU_GPE_COP_INDEX_MSK),
			((temp0 >> ONU_GPE_COP_DBGNEXT_POS) &
							ONU_GPE_COP_DBGNEXT_MSK),
			((temp0 >> ONU_GPE_COP_DBGRES2_POS) &
							ONU_GPE_COP_DBGRES2_MSK),
			((temp0 >> ONU_GPE_COP_DBGERR_POS) &
							ONU_GPE_COP_DBGERR_MSK)
			);

	for (i=0; i < 7; i+=2) {
		temp[i] = link_r32_table(data0, port[2]);
		temp[i+1] = link_r32_table(data1, port[2]);
	}

	ONU_DEBUG_MSG("%s DATA:  %08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x",
			cop_str[cop_id],
			temp[7], temp[6], temp[5], temp[4], temp[3], temp[2],
			temp[1], temp[0]);

	ONU_DEBUG_MSG("");

	return COP_STATUS_OK;
}
#endif

#ifdef INCLUDE_COP_DEBUG
void cop_debug_disassembly(uint16_t instr, char *opcode, uint32_t len)
{
	static const char *command_s[] = {
		"read", "clear", "write", "count",
		"searchr", "searchr", "searchr", "searchr",
		"search", "remove", "add", "searchw",
		"settab", "settab", "settab", "settab"
	};

	static const char *cc_s[] = {
		"[0]        ",
		"           ",
		"[!res1]    ",
		"[res1]     ",
		"[!err]     ",
		"[err]      ",
		"[!res1|err]",
		"[res1&err] ",
		"[eq8]      ",
		"[ne8]      ",
		"[lt16]     ",
		"[first]    ",
		"[last]     ",
		"[aged]     ",
		"[!res2]    ",
		"[res2]     "
	};

	static const char *not_s[] = {
		"!",
		""
	};

	static const char *reg_s[] = {
		"%index",
		"%data1"
	};

	static const char *bitop_s[] = {
		"mov", /* clr */
		"mov", /* set */
		"not",
		"mov",
		"and",
		"or",
		"xor",
		"xorn"
	};

	static const unsigned char off_s[] = {
		0,
		64,
		128,
		192
	};

	static const short len_s[] = {
		32,
		64,
		128,
		256
	};

	static const signed char cv_s[] = {
		 0,
		 0,
		 1,
		-1
	};

	static const char *mov_s[] = {
		"%index, %data1.16",
		"%index, %data1.48",
		"%index, %data1.112",
		"%index, %data1.239",
		"%index, %data1",
		"%index, %next",
		"%index, %prev_src",
		"%index, %aux",

		"%prev, %data1.16",
		"",
		"",
		"",
		"",
		"",
		"",
		"",

		"%data1.16, %index",
		"%data1.16, %index_ptr",
		"or", /* special case is covered */
		"%data1, %data2",
		"",
		"",
		"",
		"",

		"%data2.16, %index",
		"",
		"%data2, %data1",
		"shift", /* special case is covered */
		"",
		"",
		"",
		"",

		"%key_mask, %data1",
		"",
		"",
		"",
		"",
		"",
		"",
		"",

		"",
		"",
		"%key, %data1",
		"",
		"",
		"",
		"",
		"",

		"%res2, %res1"
		"",
		"",
		"",
		"",
		"",
		"",
		"",

		"",
		"",
		"",
		"",
		"",
		"",
		"",
		""
	};

	bool op = true;
	opcode[0] = '\0';

	if (instr == 0x0000) {
		sprintf(opcode, "\t\tnop");
	} else if ((instr & 0xFFF8)== 30720+(4<<3)) {
		sprintf(opcode, "\t\tnow");
	} else if ((instr & 0xFFF8)== 30720+(1<<3)) {
		sprintf(opcode, "\t\ttag");
	} else if ((instr & 0xFFF8)== 30720+(2<<3)) {
		sprintf(opcode, "\t\ttreat");
	} else if ((instr & 0xFFF8) == 0x7240) {
		sprintf(opcode, "\t\tor\t%%data1, %%data2");
	} else if ((instr & 0xFFE0) == 0x7360) {
		sprintf(opcode, "\t\tshift\t%%data2, %d",
			((instr>>3) & 0x3)*32+32);
	} else if ((instr>>13) == 0 && ((instr>>7) & 0xF) != 0) {
		sprintf(opcode, "%s\tgoto\t0x%x", cc_s[(instr >> 7) & 0xF],
			instr & 0x7F);
	} else if ((instr>>13) == 1) {
		sprintf(opcode, "[%sdata1.%d]\tgoto\t0x%x",
				not_s[(instr>>12) & 1],
				(instr>>7) & 0x1f, instr & 0x7F);
	} else if ((instr>>13) == 2) {
		sprintf(opcode, "\t\tmov\t%s, 0x%x", reg_s[(instr>>12) & 1],
			(instr>>3) & 0x1FF);
	} else if (((instr>>11) & 0x1F) == 0xC) {
		sprintf(opcode, "\t\tmov\t%%err, 0x%x", (instr>>3) & 0x7);
	} else if (((instr>>11) & 0x1F) == 0xD) {
		if (((instr>>8) & 0x7) <= 1)
			sprintf(opcode, "\t\t%s\t%%res1, %d",
			bitop_s[(instr>>8) & 0x7], (instr>>8) & 0x1);
		else if (((instr>>8) & 0x7) == 2)
			sprintf(opcode, "\t\t%s\t%%res1",
						bitop_s[(instr>>8) & 0x7]);
		else
			sprintf(opcode, "\t\t%s\t%%res1, %%data1.%d",
			bitop_s[(instr>>8) & 0x7], (instr>>3) & 0x1F);
	} else if (((instr>>11) & 0x1F) == 0xE) {
		sprintf(opcode, "\t\tmov\t%s", mov_s[(instr>>5) & 0x3F]);
	} else if (instr & 0x8000) {
		sprintf(opcode, "\t\t%s\t%d", command_s[(instr>>11) & 0xF],
			(instr>>3) & 0xf);
		switch(((instr>>11) & 0xf)) {
		case 0x1: /* BIT */
			opcode += strlen(opcode);
			sprintf(opcode, ", %d", 1<<((instr>>7) & 0xF));
			break;

		case 0x3: /* CV */
			opcode += strlen(opcode);
			sprintf(opcode, ", %d", cv_s[(instr>>7) & 0x3]);
			break;

		case 0x0:
		case 0x2:
		case 0x4:
		case 0xB: /* OFF, LEN */
			opcode += strlen(opcode);
			sprintf(opcode, ", %d, %d", off_s[(instr>>9) & 0x3],
				len_s[(instr>>7) & 0x3]);
			break;

		case 0xA: /* OV */
			opcode += strlen(opcode);
			sprintf(opcode, ", %d", ((instr>>9) & 0x1));
			break;
		
		case 0xC: /* set table */
		case 0x9: /* remove */
		case 0x8: /* search */
			break;

		default:
			opcode[0] = '\0';
			op = false;
			break;
		}
	}
	else {
		opcode[0] = '\0';
		op = false;
	}

	opcode += strlen(opcode);

	if ((((instr>>14) & 0x3) !=0) || (((instr>>14) & 0x3)==0 &&
		(instr>>7) & 0xF) == 0) {

		if ((instr & 0x7) != 0 && op==true) {
			sprintf(opcode, " || ");
			opcode += strlen(opcode);
		} else if (strlen(opcode) == 0) {
			sprintf(opcode, "\t\t");
			opcode += strlen(opcode);
		}

		switch (instr & 0x7) {
		case 1:
			sprintf(opcode, "return");
			break;
		case 4:
			sprintf(opcode, "return  32");
			break;
		case 5:
			sprintf(opcode, "return  64");
			break;
		case 6:
			sprintf(opcode, "return  128");
			break;
		case 7:
			sprintf(opcode, "return  256");
			break;
		default:
			/*sprintf(opcode, "");*/
			opcode[0] = '\0';
			break;
		}
	}
}
#endif

/** The cop_message function is used to handle the communication
 *  between software and COP hardware.
 *  A communication consists of command and response.
 *  A command is send to COP and its success is checked.
 *  The response is checked also, error codes are delivered
 *  to upper driver layers.
 */
enum cop_errorcode cop_message(struct cop_message *message)
{
	enum cop_errorcode errorcode;
	uint32_t header;
	unsigned long flags = 0;

	/* 1) send LINK C1 command request */

	/* check for unaligned send commands, only 64bits allowed */

	if (message->request_length & 0x1)
		return COP_STATUS_ERR;

	onu_spin_lock_get(&cop_lock, &flags);
	errorcode = cop_message_send(message);
	if (errorcode != COP_STATUS_OK) {
		ONU_DEBUG_ERR(LINK2 "send failed, return is %i", errorcode);
		goto COP_MESSAGE_ERROR;
	}

	/* 2) receive LINK C1 command response */

	/* check for unaligned receive commands, only 64bits allowed */
	if (message->response_length & 0x1) {
		errorcode = COP_STATUS_ERR;
		goto COP_MESSAGE_ERROR;
	}

	errorcode = cop_message_receive(message);
	if (errorcode != COP_STATUS_OK) {
		ONU_DEBUG_ERR(LINK2 "receive failed, return is %i", errorcode);
		goto COP_MESSAGE_ERROR;
	}

	header = message->command[0];

	/* get result and error bit field */
	errorcode = ((header & (LINKC2_RES_MASK | LINKC2_ERR_MASK)) >>
		     LINKC2_ERR_OFFSET);

	/* if there is an error, result bit is irrelevant,
	   just the error counts */
	if ((errorcode & 0x7) != 0)
		errorcode = errorcode & 0x7;

COP_MESSAGE_ERROR:
	onu_spin_lock_release(&cop_lock, flags);

	return errorcode;
}

/* ========================================================================
 * Level 2 - Data Link
 * ======================================================================== */

/* The cop_table_entry_write function is used to write any COP table entry.
 * Upper driver layers should handle the access to this function.
 * Direct use is only meant for debugging.
 */
enum cop_errorcode cop_table_entry_write(struct gpe_table_entry *entry,
					 uint32_t command)
{
	enum cop_errorcode errorcode;
	struct cop_message message;
	uint16_t wordsize;
	uint32_t *srcdatapnt;
	uint32_t tabletype;

	tabletype = cop_tbl_cfg[entry->instance*8 + entry->id].type;

	/* configuration */
	if (command == ONU_GPE_COP_TABLE0W) {
		wordsize = 1;
		command  = LINKC1_WRITE;
	} else {
		wordsize = cop_table_size_get(entry->instance, entry->id);
	}

	if (tabletype == ONU_GPE_COP_HASH)
		wordsize = 1;

	/* data */
	if (wordsize == 1) { /* optimization for 32 bit values */
		message.request_length = LINKC1_HEADER_SIZE + 1;
		message.command[1]     = 0;
		message.format         = COP_FRM_FORMAT1;
	} else {
		message.request_length = cop_round_up(LINKC1_HEADER_SIZE +
						  wordsize);
		/* no masking supported */
		message.command[1]     = 0xFFFFFFFF;
		message.format	       = COP_FRM_FORMAT2;
	}


	if (tabletype == ONU_GPE_COP_HASH)
		srcdatapnt = (uint32_t *)&(entry->hashdata);
	else
		srcdatapnt = (uint32_t *)&(entry->data);

	memcpy(&message.data[0], srcdatapnt, wordsize*4);

	/* command */
	command  = command         << LINKC1_CMD_OFFSET;
	command |= entry->index    << LINKC1_INDEX_OFFSET;
	/* offset field is don't care */
	command |= 0x0             << LINKC1_OFF_OFFSET;
	command |= entry->id       << LINKC1_TABLE_OFFSET;
	command |= TID_CPU33       << LINKC1_TID_OFFSET;
	command |= entry->instance << LINKC1_COPID_OFFSET;
	message.command[0] = command; /* high word */

	message.response_length = LINKC2_HEADER_SIZE;

	/* communication */
	errorcode = cop_message(&message);

	entry->index = (message.command[0] >> LINKC1_INDEX_OFFSET ) &
			LINKC1_INDEX_MSK;

	return errorcode;
}


/* The cop_table_entry_read function is used to read any COP table entry.
 * Upper driver layers should handle the access to this function.
 * Direct use is only meant for debugging.
 */
enum cop_errorcode cop_table_entry_read(struct gpe_table_entry *entry,
					uint32_t command)
{
	/* 0:32, 1:64, 2:128, 3:256 */
	static const char wordsize_to_len[] = { -1, 0, 1, 2,  2, 3, 3, 3,  3};
	enum cop_errorcode errorcode;
	struct cop_message message;
	uint16_t wordsize;

	/* configuration */
	if (command == ONU_GPE_COP_TABLE0R) {
		wordsize = 1;
		command  = LINKC1_READ;
	} else {
		wordsize = cop_table_size_get(entry->instance, entry->id);

		if (cop_tbl_cfg[entry->instance*8 + entry->id].type ==
							ONU_GPE_COP_HASH)
			wordsize = 1;
	}

	/* data */
	message.format = COP_FRM_FORMAT1;
	if (wordsize == 1) /* optimization for 32 bit values */
		message.response_length = LINKC2_HEADER_SIZE;
	else
		message.response_length = cop_round_up(LINKC2_HEADER_SIZE +
			wordsize);

	message.request_length = LINKC1_HEADER_SIZE + 1;

	/* command */
	command  = command 		<< LINKC1_CMD_OFFSET;
	command |= entry->index 	<< LINKC1_INDEX_OFFSET;
	/* offset field is don't care */
	command |= 0x0 			<< LINKC1_OFF_OFFSET;
	command |= entry->id 		<< LINKC1_TABLE_OFFSET;
	command |= TID_CPU33 		<< LINKC1_TID_OFFSET;
	command |= entry->instance	<< LINKC1_COPID_OFFSET;
	message.command[0] = command;
	message.data[0] = wordsize_to_len[wordsize] << LINKC1_LEN_OFFSET;

	/* communication */
	errorcode = cop_message(&message);

	/* data	*/
	memcpy(&(entry->data.message.data[0]), &message.data[0], wordsize*4);

	entry->index = (message.command[0] >> LINKC1_INDEX_OFFSET ) &
			LINKC1_INDEX_MSK;

	return errorcode;
}


/* The cop_table_entry_add function is used to add any COP table entry.
 * Upper driver layers should handle the access to this function.
 * Direct use is only meant for debugging.
 */
enum cop_errorcode cop_table_entry_add(	struct gpe_table_entry *entry,
					const uint32_t key_len,
					const bool nil)
{
	enum cop_errorcode errorcode;
	struct cop_message message;
	uint32_t command;
	uint32_t key_words, start, wordsize, tabletype, filling = 0;
	uint32_t *srcdatapnt;

	tabletype = cop_tbl_cfg[entry->instance*8 + entry->id].type;

#ifdef ONU_COP_DEBUG_LL
	ONU_DEBUG_MSG(COP "type: %i, entry: %i, key: %i, size: %i",
			tabletype,
			cop_tbl_cfg[entry->instance*8 + entry->id].entry_width,
			cop_tbl_cfg[entry->instance*8 + entry->id].key_len,
			cop_tbl_cfg[entry->instance*8 + entry->id].size);
#endif /* ONU_COP_DEBUG_LL */

	key_words = (key_len + 16) / 32; /* bits -> words */

	message.format = COP_FRM_FORMAT1;

	/* command */
	command  = LINKC1_ADD    	<< LINKC1_CMD_OFFSET;
	command |= entry->index 	<< LINKC1_INDEX_OFFSET;
	if (is_falcon_chip_a2x()) {
		/* GPONC-178, bugfix for errata no6 */
		command |= nil << LINKC1_NIL_OFFSET;
	}
	command |= 0x0 			<< LINKC1_OFF_OFFSET;
	command |= entry->id 		<< LINKC1_TABLE_OFFSET;
	command |= TID_CPU33 		<< LINKC1_TID_OFFSET;
	command |= entry->instance 	<< LINKC1_COPID_OFFSET;
	message.command[0] = command;

	/* key */
	memcpy(&message.data[0], &(entry->data.message.data[0]), key_words*4);

	/* optional masking of incomplete key words */
	if ( key_len == 16 || key_len == 144 ) {
		start = key_words;
		message.data[key_words-1] &= 0xffff;
	} else if (key_len == 0 || key_len == 32 || key_len == 64 ||
		   key_len == 128 || key_len == 160 ) {
		start = key_words+1;
		message.data[key_words] = 0;
	} else {
		start = key_words+1;
	}

	/* data */
	wordsize = cop_table_size_get(entry->instance, entry->id);
	wordsize = wordsize - key_words;

	if (tabletype == ONU_GPE_COP_HASH)
		wordsize = 1;

#ifdef ONU_COP_BUGFIX

	if ( wordsize == 0 &&
		 key_len == 32 &&
		 (tabletype == ONU_GPE_COP_LLIST ||
		  tabletype == ONU_GPE_COP_LIST) ) { /* bugfix for errata no2*/
		filling = 2;
		message.data[2] = 0;
		start = 1;
		key_words = 0;
		wordsize = 1;
		ONU_DEBUG_MSG(COP "using bugfix for errata no2");
	}

	if (is_falcon_chip_a1x()) {
		/* GPONC-76, bugfix for errata no5 */
		if ( wordsize == 1 && key_len == 0 ) { 
			filling = 2;
			message.data[2] = 0;
			ONU_DEBUG_MSG(COP "using bugfix for errata no5");
		}
	}

	if (cop_tbl_cfg[entry->instance*8 + entry->id].entry_width == 64 &&
	    key_len == 64 &&
	    tabletype == ONU_GPE_COP_LIST ) {
		ONU_DEBUG_ERR(COP "bugfix required");
		return COP_STATUS_ERR;
	}

#endif

	/* this case needs special treatment for 64bit alignment,
	   but it is NOT the same as the bugfix above,
	   therefore coded separately */
	if (wordsize == 0 && key_len == 16) {
		filling = 2;
		message.data[2] = 0;
		start = 1;
		key_words = 0;
		wordsize = 1;
	}

	message.request_length = cop_round_up(LINKC1_HEADER_SIZE + key_words +
					  wordsize + filling);
	message.response_length = LINKC2_HEADER_SIZE;


	if (tabletype == ONU_GPE_COP_HASH) {
		srcdatapnt = &(entry->hashdata.message.data[0]);

		if (key_len == 32 || is_falcon_chip_a2x())
			start = key_words;
	} else {
		srcdatapnt = &(entry->data.message.data[key_words]);
	}

	memcpy(	&message.data[start], srcdatapnt, wordsize*4);

	if (tabletype == ONU_GPE_COP_HASH &&
		is_falcon_chip_a1x())
		message.data[key_words+1] = 0;

	if (key_len == 16 || key_len == 144 )
		message.data[start] &= 0xffff0000;

	errorcode = cop_message(&message);

	entry->index = (message.command[0] >> LINKC1_INDEX_OFFSET ) &
			LINKC1_INDEX_MSK;

	if (is_falcon_chip_a2x()) {
		/* use result bit temporarily for layer above as NIL bit information */
		entry->result = (message.command[0] >> LINKC1_NIL_OFFSET ) &
					LINKC1_NIL_MSK;
	}

	return errorcode;
}


/* The cop_table_entry_delete function is used to delete any COP table entry.
 * Upper driver layers should handle the access to this function.
 * Direct use is only meant for debugging.
 */
enum cop_errorcode cop_table_entry_delete(struct gpe_table_entry *entry,
					  const uint32_t key_len)
{
	enum cop_errorcode errorcode;
	struct cop_message message;
	uint32_t command, key_words, entry_width, bugfilling = 0;

	entry_width = cop_tbl_cfg[entry->instance*8 + entry->id].entry_width;

#ifdef ONU_COP_DEBUG_LL
	ONU_DEBUG_MSG(COP "type: %i, entry: %i, key: %i, size: %i",
			cop_tbl_cfg[entry->instance*8 + entry->id].type,
			entry_width,
			cop_tbl_cfg[entry->instance*8 + entry->id].key_len,
			cop_tbl_cfg[entry->instance*8 + entry->id].size);
#endif /* ONU_COP_DEBUG_LL */

	key_words = (key_len+16) / 32; /* bits -> words */

	message.format = COP_FRM_FORMAT1;

	/* command */
	command  = LINKC1_REMOVE 	<< LINKC1_CMD_OFFSET;
	command |= entry->index 	<< LINKC1_INDEX_OFFSET;
	/* offset field is don't care */
	command |= 0x0 			<< LINKC1_OFF_OFFSET;
	command |= entry->id 		<< LINKC1_TABLE_OFFSET;
	command |= TID_CPU33 		<< LINKC1_TID_OFFSET;
	command |= entry->instance 	<< LINKC1_COPID_OFFSET;
	message.command[0] = command;

	/* key */
	memcpy(&message.data[0], &(entry->data.message.data[0]), key_words*4);

	/* optional masking of incomplete key words */
	if (key_len == 16 || key_len == 144)
		message.data[key_words-1] &= 0xffff;
	else if (key_len == 0 || key_len == 32 || key_len == 64 ||
		 key_len == 128 || key_len == 160)
		message.data[key_words] = 0;

#ifdef ONU_COP_BUGFIX
	if ( entry_width == 32 &&
		 key_len == 32 &&
		(cop_tbl_cfg[entry->instance*8 + entry->id].type ==
			ONU_GPE_COP_LLIST ||
		 cop_tbl_cfg[entry->instance*8 + entry->id].type ==
			ONU_GPE_COP_LIST) ) { /* bugfix for errata no2 */
		message.data[1] = message.data[0];
		message.data[2] = 0;
		bugfilling = 2;

		ONU_DEBUG_MSG(COP "using bugfix for errata no2");
	}

	if (cop_tbl_cfg[entry->instance*8 + entry->id].entry_width == 64 &&
	    key_len == 64 && cop_tbl_cfg[entry->instance*8 + entry->id].type
							== ONU_GPE_COP_LIST ) {
		ONU_DEBUG_ERR(COP "bugfix required");
		return COP_STATUS_ERR;
	}
#endif

	message.request_length  = cop_round_up(LINKC1_HEADER_SIZE + key_words +
					   bugfilling);
	message.response_length = LINKC2_HEADER_SIZE;

	errorcode = cop_message(&message);

	entry->index = (message.command[0] >> LINKC1_INDEX_OFFSET ) &
			LINKC1_INDEX_MSK;

	if (is_falcon_chip_a2x()) {
		/* use result bit temporarily for layer above as NIL bit information */
		entry->result = (message.command[0] >> LINKC1_NIL_OFFSET ) &
					LINKC1_NIL_MSK;
	}

	return errorcode;
}


/* The cop_table_entry_search function is used to search for a COP table entry.
 * Upper driver layers should handle the access to this function.
 * Direct use is only meant for debugging.
 */
enum cop_errorcode cop_table_entry_search(struct gpe_table_entry *entry,
					  const uint32_t key_len)
{
	enum cop_errorcode errorcode;
	struct cop_message message;
	uint32_t command, key_words, entry_width, bugfilling = 0;

	entry_width = cop_tbl_cfg[entry->instance*8 + entry->id].entry_width;

#ifdef ONU_COP_DEBUG_LL
	ONU_DEBUG_MSG(COP "type: %i, entry: %i, key: %i, size: %i",
			cop_tbl_cfg[entry->instance*8 + entry->id].type,
			entry_width,
			cop_tbl_cfg[entry->instance*8 + entry->id].key_len,
			cop_tbl_cfg[entry->instance*8 + entry->id].size);
#endif /* ONU_COP_DEBUG_LL */

	key_words = (key_len+16) / 32; /* bits -> words */

	message.format = COP_FRM_FORMAT1;

	/* command */
	command  = LINKC1_SEARCH 	<< LINKC1_CMD_OFFSET;
	command |= entry->index 	<< LINKC1_INDEX_OFFSET;
	/* offset field is don't care */
	command |= 0x0 			<< LINKC1_OFF_OFFSET;
	command |= entry->id 		<< LINKC1_TABLE_OFFSET;
	command |= TID_CPU33 		<< LINKC1_TID_OFFSET;
	command |= entry->instance 	<< LINKC1_COPID_OFFSET;
	message.command[0] = command;

	/* key */
	memcpy(&message.data[0], &(entry->data.message.data[0]), key_words*4);

	/* optional masking of incomplete key words */
	if (key_len == 16 || key_len == 144)
		message.data[key_words-1] &= 0xffff;
	else if (key_len == 0 || key_len == 32 || key_len == 64 ||
		 key_len == 128 || key_len == 160 )
		message.data[key_words] = 0;

#ifdef ONU_COP_BUGFIX
	if (entry_width == 32 &&
		key_len == 32 &&
		(cop_tbl_cfg[entry->instance*8 + entry->id].type ==
			ONU_GPE_COP_LLIST ||
		 cop_tbl_cfg[entry->instance*8 + entry->id].type ==
			ONU_GPE_COP_LIST) ) { /* bugfix for errata no2 */
		message.data[1] = message.data[0];
		message.data[2] = 0;
		bugfilling = 2;

		ONU_DEBUG_MSG(COP "using bugfix for errata no2");
	}

	if (cop_tbl_cfg[entry->instance*8 + entry->id].entry_width == 64 &&
	    key_len == 64 && cop_tbl_cfg[entry->instance*8 + entry->id].type
							== ONU_GPE_COP_LIST ) {
		ONU_DEBUG_ERR(COP "bugfix required");
		return COP_STATUS_ERR;
	}
#endif

	message.request_length  = cop_round_up(LINKC1_HEADER_SIZE + key_words +
					   bugfilling);
	message.response_length = LINKC2_HEADER_SIZE;

	errorcode = cop_message(&message);

	entry->index = (message.command[0] >> LINKC1_INDEX_OFFSET ) &
			LINKC1_INDEX_MSK;

	return errorcode;
}


/* The cop_table_entry_searchr function is used to search read
 * for a COP table entry.
 * Upper driver layers should handle the access to this function.
 * Direct use is only meant for debugging.
 */
enum cop_errorcode cop_table_entry_searchr(struct gpe_table_entry *entry,
					   const uint32_t key_len)
{
	/* 0:32, 1:64, 2:128, 3:256 */
	static const char wordsize_to_len[] = { -1, 0, 1, 2,  2, 3, 3, 3,  3};
	enum cop_errorcode errorcode;
	struct cop_message message;
	uint32_t command, wordsize, key_words, tabletype, bugfilling = 0;

	reset_message_data(&message);

	tabletype = cop_tbl_cfg[entry->instance*8 + entry->id].type;

#ifdef ONU_COP_DEBUG_LL
	ONU_DEBUG_MSG(COP "type: %i, entry: %i, key: %i, size: %i",
			tabletype,
			cop_tbl_cfg[entry->instance*8 + entry->id].entry_width,
			cop_tbl_cfg[entry->instance*8 + entry->id].key_len,
			cop_tbl_cfg[entry->instance*8 + entry->id].size);
#endif /* ONU_COP_DEBUG_LL */

	key_words = (key_len+16) / 32; /* bits -> words */
	wordsize = cop_table_size_get(entry->instance, entry->id);

	if (tabletype == ONU_GPE_COP_HASH)
		wordsize = key_words;

	message.format = COP_FRM_FORMAT1;

	/* command */
	command  = ((LINKC1_SEARCHR << 2 ) +
		    wordsize_to_len[wordsize]) << LINKC1_CMD_OFFSET;
	command |= entry->index 	<< LINKC1_INDEX_OFFSET;
	/* offset field is don't care */
	command |= 0x0 			<< LINKC1_OFF_OFFSET;
	command |= entry->id 		<< LINKC1_TABLE_OFFSET;
	command |= TID_CPU33 		<< LINKC1_TID_OFFSET;
	command |= entry->instance 	<< LINKC1_COPID_OFFSET;
	message.command[0] = command;

	/* key */
	memcpy(&message.data[0], &(entry->data.message.data[0]), key_words*4);

	/* optional masking of incomplete key words */
	if (key_len == 16 || key_len == 144)
		message.data[key_words-1] &= 0xffff;
	else if (key_len == 0 || key_len == 32 || key_len == 64 ||
		   key_len == 128 || key_len == 160 )
		message.data[key_words] = 0;

#ifdef ONU_COP_BUGFIX
	if (wordsize == 1 &&
		 key_len == 32 &&
		(tabletype == ONU_GPE_COP_LLIST ||
		 tabletype == ONU_GPE_COP_LIST) ) { /* bugfix for errata no2 */
		message.data[1] = message.data[0];
		message.data[2] = 0;
		bugfilling = 2;

		ONU_DEBUG_MSG(COP "using bugfix for errata no2");
	}

	if (cop_tbl_cfg[entry->instance*8 + entry->id].entry_width == 64 &&
	    key_len == 32 ) {

			ONU_DEBUG_ERR(COP "bugfix for errata no1 required "
				      "(microcode change)");
			return COP_STATUS_ERR;
	}
#endif

	message.request_length  = cop_round_up(LINKC1_HEADER_SIZE + key_words +
					   bugfilling);
	if (wordsize <= 1)
		message.response_length = LINKC2_HEADER_SIZE;
	else
		message.response_length = cop_round_up(LINKC2_HEADER_SIZE +
						   wordsize);

	errorcode = cop_message(&message);

	/* data	*/
	memcpy(&(entry->data.message.data[0]), &message.data[0], wordsize*4);

	if (message.response_length > LINKC2_HEADER_SIZE)
		timestamp_now = (message.command[1] >>
					LINKC2_TIMESTAMP_OFFSET) &
						LINKC2_TIMESTAMP_MASK;

	entry->index = (message.command[0] >> LINKC1_INDEX_OFFSET) &
						LINKC1_INDEX_MSK;

	return errorcode;
}


/* The cop_table_entry_searchw function is used to search write
 * for a COP table entry.
 * Upper driver layers should handle the access to this function.
 * Direct use is only meant for debugging.
 */
enum cop_errorcode cop_table_entry_searchw(struct gpe_table_entry *entry,
					   const uint32_t key_len)
{
	enum cop_errorcode errorcode;
	struct cop_message message;
	uint32_t command, key_words, start, wordsize, offset, entry_width,
		 key_align, filling = 0;

	reset_message_data(&message);

	entry_width = cop_tbl_cfg[entry->instance*8 + entry->id].entry_width;

#ifdef ONU_COP_DEBUG_LL
	ONU_DEBUG_MSG(COP "type: %i, entry: %i, key: %i, size: %i",
			cop_tbl_cfg[entry->instance*8 + entry->id].type,
			entry_width,
			cop_tbl_cfg[entry->instance*8 + entry->id].key_len,
			cop_tbl_cfg[entry->instance*8 + entry->id].size);
#endif /* ONU_COP_DEBUG_LL */

	key_words = (key_len+16) / 32; /* bits -> words */

	message.format = COP_FRM_FORMAT1;

	if ((entry_width == 256 && (key_len == 128 || key_len == 160)) ||
	    (entry_width == 32  && (key_len == 128 || key_len == 160)) )
		/* consider HASH cases as well */
		offset = 2;
	else
		offset = 0;

	/* command */
	command  = LINKC1_SEARCHW  	<< LINKC1_CMD_OFFSET;
	command |= entry->index 	<< LINKC1_INDEX_OFFSET;
	command |= offset 		<< LINKC1_OFF_OFFSET;
	command |= entry->id 		<< LINKC1_TABLE_OFFSET;
	command |= TID_CPU33 		<< LINKC1_TID_OFFSET;
	command |= entry->instance 	<< LINKC1_COPID_OFFSET;
	message.command[0] = command;

	/* key */
	memcpy(&message.data[0], &(entry->data.message.data[0]),
		key_words * 4);

	/* optional masking of incomplete key words */
	key_align = 0;
	if (key_len == 16 ) {
		start = key_words + 1;
		message.data[key_words-1] &= 0xffff;
		message.data[2] = 0;
		filling = 1;
	} else if (key_len == 0) {
		start = key_words + 1;
	} else if (key_len == 32) {
		start = key_words;
	} else if (key_len == 64 || key_len == 128) {
		start = key_words + 1;
		message.data[key_words] = 0;
	} else if (key_len == 160) {
		start = key_words + 1;
		message.data[key_words] = message.data[key_words-1];
		key_align = 1;
	} else {
		start = key_words + 1;
	}

	/* data */
	wordsize = cop_table_size_get(entry->instance, entry->id);

#ifdef ONU_COP_BUGFIX
	if (wordsize == 1 && key_len == 32) { /* bugfix for errata no2 */
		filling = 2;
		message.data[2] = 0;
		start = 1;
		key_words = 0;
		ONU_DEBUG_MSG(COP "using bugfix for errata no2");
	}

	if (is_falcon_chip_a1x()) {
		/* GPONC-76, bugfix for errata no5 */
		if (wordsize == 1 && key_len == 0) {
			filling = 2;
			message.data[2] = 0;
			start = 1;
			ONU_DEBUG_MSG(COP "using bugfix for errata no5");
		}
	}
#endif

	/* this case needs special treatment for 64bit alignment,
	   but it is NOT the same as the bugfix above,
	   therefore coded separately */
	if (wordsize == 1 && key_len == 16) {
		filling = 2;
		message.data[2] = 0;
		start = 1;
		key_words = 0;
	}

	/* this is true for all commands using an offset */
	message.request_length = cop_round_up(
					LINKC1_HEADER_SIZE +
					wordsize +
						((key_words + wordsize) > 8 ?
						      0 : key_words + filling));

	message.response_length = LINKC2_HEADER_SIZE;


	memcpy(	&message.data[start], &(entry->data.message.data[0+2 *
		offset + key_align]),
		(wordsize-2*offset-key_align)*4);

	errorcode = cop_message(&message);

	entry->index = (message.command[0] >> LINKC1_INDEX_OFFSET ) &
			LINKC1_INDEX_MSK;

	return errorcode;
}

enum cop_errorcode cop_table_entry_exec(struct gpe_table_entry *entry,
					const uint32_t key_len,
					const uint32_t instruction_id)
{
	enum cop_errorcode errorcode = COP_STATUS_SUCCESS;
	struct cop_message message;
	uint32_t command;
	uint32_t key_words, start, wordsize, tabletype, filling = 0;
	uint32_t * srcdatapnt;
	uint32_t instruction;

#ifdef ONU_COP_BUGFIX
	/* GPONSW-869*, workaround for deleted end bit from freelist bug in TSE Version 1 */
	uint32_t *pdata;
	struct gpe_table_entry cnt_entry;
	enum cop_errorcode ret;
	uint32_t Counter=0;

	pdata =&cnt_entry.data.message.data[0];
	if((is_falcon_chip_a1x())&&(instruction_id ==IF_FWD_ADD)){
		cnt_entry.id = 0x0;
		cnt_entry.instance 	= 1;
		cnt_entry.index = COPLINK_COP_TABLE22;
		ret = cop_table0_read(&cnt_entry);

		if(ret != COP_STATUS_OK){
			ONU_DEBUG_ERR("[TSE%1d] error: HW Counter get Failed !",entry->instance);
			return COP_STATUS_ERR;
		}
		Counter = (pdata[0] & COP_TABLE12_ENTRY_COUNTER_MASK)>>COP_TABLE12_ENTRY_COUNTER_OFFSET;

		if(Counter > (ONU_GPE_SHORT_FWD_TABLE_MAC_SIZE - ONU_GPE_SHORT_FWD_TABLE_SAFETY_MARGIN)){
			return COP_STATUS_OUT_OF_MEMORY;
		}
	}
#endif



	reset_message_data(&message);

	tabletype = cop_tbl_cfg[entry->instance*8 + entry->id].type;
	instruction = labelmapping[instruction_id].func_addr;

#ifdef ONU_COP_DEBUG_LL
	ONU_DEBUG_MSG(COP "type: %i, entry: %i, key: %i, size: %i, instruction %i",
			tabletype,
			cop_tbl_cfg[entry->instance*8 + entry->id].entry_width,
			cop_tbl_cfg[entry->instance*8 + entry->id].key_len,
			cop_tbl_cfg[entry->instance*8 + entry->id].size,
			instruction);
#endif /* ONU_COP_DEBUG_LL */

	key_words = (key_len+16) / 32; /* bits -> words */

	message.format = COP_FRM_FORMAT1;

	/* command */
	command  = LINKC1_EXEC    	<< LINKC1_CMD_OFFSET;
	command |= entry->index 	<< LINKC1_INDEX_OFFSET;
	command |= 0x0 				<< LINKC1_OFF_OFFSET;
	command |= instruction		<< LINKC1_TABLE_OFFSET;
	command |= TID_CPU33 		<< LINKC1_TID_OFFSET;
	command |= entry->instance 	<< LINKC1_COPID_OFFSET;
	message.command[0] = command;

	/* key */
	if(key_words)
		memcpy(&message.data[0], &(entry->data.message.data[0]), key_words*4);

	/* optional masking of incomplete key words */
	if (key_len == 16 || key_len == 144) {
		start = key_words;
		message.data[key_words-1] &= 0xffff;
	} else if (key_len == 0 || key_len == 32 || key_len == 64 ||
		   key_len == 128 || key_len == 160 ) {
		start = key_words+1;
		message.data[key_words] = 0;
	} else {
		start = key_words+1;
	}

	/* data */
	wordsize = cop_table_size_get(entry->instance, entry->id);
	wordsize = wordsize - key_words;

	if (tabletype == ONU_GPE_COP_HASH)
		wordsize = 1;

	/* Extended VLAN table handling */
	if (entry->instance == ONU_GPE_COP_EXT &&
	    entry->id == GPE_TABLE_ID(ONU_GPE_EXTENDED_VLAN_TABLE_ID))
		wordsize = 0;


#ifdef ONU_COP_BUGFIX

	if ( wordsize == 0 &&
		 key_len == 32 &&
		 (tabletype == ONU_GPE_COP_LLIST ||
		  tabletype == ONU_GPE_COP_LIST) ) { /* bugfix for errata no2*/
		filling = 2;
		message.data[2] = 0;
		start = 1;
		key_words = 0;
		wordsize = 1;
		ONU_DEBUG_MSG(COP "using bugfix for errata no2");
	}

	if (is_falcon_chip_a1x()) {
		/* GPONC-76, bugfix for errata no5 */
		if (wordsize == 1 && key_len == 0) {
			filling = 2;
			message.data[2] = 0;
			ONU_DEBUG_MSG(COP "using bugfix for errata no5");
		}
	}

#endif

	/* this case needs special treatment for 64bit alignment,
	   but it is NOT the same as the bugfix above,
	   therefore coded separately */
	if (wordsize == 0 && key_len == 16) {
		filling = 2;
		message.data[2] = 0;
		start = 1;
		key_words = 0;
		wordsize = 1;
	}

	message.request_length = cop_round_up(LINKC1_HEADER_SIZE + key_words +
					  wordsize + filling);

	/* get response length of microcode label */
	switch (instruction_id) {
		case IF_FWD_ADD: /* 32 bit */
		case IF_FWD_RELEARN:
		case IF_FWD_REMOVE:
		case IF_UPGEM_SEARCHR:
		case IF_FIDHASH_SEARCHR:
		case IF_IPV6HASH_SEARCHR:
		case IF_TAG_FILTER:
		case IF_IPV6_FORWARD:
		case IF_FWD_AGE:
			message.response_length = LINKC2_HEADER_SIZE;
			break;
		case IF_FWD_FORWARD: /* 64 bit */
		case IF_FID_LOOKUP:
		case IF_FID_GET_PREVIOUS:
		case IF_FID_REMOVE:
		case IF_IPV4_SEARCH:
			message.response_length = LINKC2_HEADER_SIZE + 2;
			break;
		case IF_VLAN_TRANSLATE: /* 128 bit */
			message.response_length = LINKC2_HEADER_SIZE + 4;
			break;
		default:
			ONU_DEBUG_ERR(COP "no response length for exec "
					  "instruction_id yet defined ");
			return COP_STATUS_ERR;
	}

	if (tabletype == ONU_GPE_COP_HASH)
		srcdatapnt = &(entry->hashdata.message.data[0]);
	else
		srcdatapnt = &(entry->data.message.data[key_words]);

	memcpy(	&message.data[start], srcdatapnt, wordsize*4);

	if (key_len == 16 || key_len == 144 )
		message.data[start] &= 0xffff0000;

#ifdef ONU_COP_BUGFIX
	if (instruction_id == IF_FID_REMOVE) {
		ONU_DEBUG_MSG(COP "using bugfix for errata no10");
		message.data[1] = entry->data.message.data[2];
	}
#endif

	errorcode = cop_message(&message);

	/* data	*/
	if (entry->instance == ONU_GPE_COP_EXT &&
	    entry->id == GPE_TABLE_ID(ONU_GPE_EXTENDED_VLAN_TABLE_ID))
		/* Extended VLAN table handling */
		wordsize = 4;

	if (instruction_id == IF_FID_GET_PREVIOUS ||
	    instruction_id == IF_FID_LOOKUP) {
		wordsize = 2;
	}

	memcpy(&(entry->data.message.data[0]), &message.data[0], wordsize * 4);

	entry->index = (message.command[0] >> LINKC1_INDEX_OFFSET ) &
			LINKC1_INDEX_MSK;

	return errorcode;
}


/*! @} */

/*! @} */
