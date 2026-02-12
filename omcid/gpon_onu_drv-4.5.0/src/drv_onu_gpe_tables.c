/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_onu_gpe.c
   This is the Packet Engine program file, used for Lantiq's FALCON GPON Modem
   driver.
*/

#if (defined (LINUX) && !defined(ONU_SIMULATION) && defined(__KERNEL__))
#  include <linux/kernel.h>
#  include <linux/uaccess.h>
#endif

#include "drv_onu_api.h"
#include "drv_onu_gpe_api.h"
#include "drv_onu_gpe_tables_api.h"
#include "drv_onu_resource_gpe.h"
#include "drv_onu_register.h"
#include "drv_onu_timer.h"
#include "drv_onu_ll_fsqm.h"
#include "drv_onu_ll_gpearb.h"
#include "drv_onu_ll_iqm.h"
#include "drv_onu_ll_ictrll.h"
#include "drv_onu_ll_ictrlg.h"
#include "drv_onu_ll_octrll.h"
#include "drv_onu_ll_octrlg.h"
#include "drv_onu_ll_ssb.h"
#include "drv_onu_gpe_interface.h"
#include "drv_onu_gpe_tables_interface.h"
#include "drv_onu_gtc_interface.h"
#include "drv_onu_ll_gtc.h"
#include "drv_onu_event_interface.h"
#include "drv_onu_ll_sce.h"
#include "drv_onu_ll_cop.h"
#include "drv_onu_ll_tmu.h"
#include "drv_onu_ll_sys.h"
#include "drv_onu_tse_config.h"
#include "drv_onu_tse.h"
#include "drv_onu_ethertypes.h"

#include "drv_onu_register.h"

extern onu_lock_t mailbox_lock;
extern tse_interface_t tse_interface[ONU_GPE_COP_LABEL_MAX];
extern labelmapping_t labelmapping[ONU_GPE_NUMBER_OF_COP*ONU_GPE_COP_LABEL_MAX];

extern uint8_t timestamp_now;
static uint16_t prescale = 0;
extern uint8_t raw_mode;

/** Maximum ID for HW table */
uint32_t gpe_hw_table_id_max[ONU_GPE_NUMBER_OF_COPWMC] = {
		0x0, /* no tables for ONU_GPE_COP_FID */
		ONU_GPE_LEARNING_LIMITATION_TABLE_ID,
		ONU_GPE_COUNTER_TABLE_ID,
		ONU_GPE_MAC_FILTER_TABLE_ID,
		ONU_GPE_DS_MC_IPV6_SOURCE_FILTER_TABLE_ID,
		ONU_GPE_VLAN_TREATMENT_TABLE_ID
};

#define ONU_COP_BUGFIX
#define ONU_COP_FLIP_DUMPS

#define UNUSED_PARAM_DEV (void)p_dev
#define UNUSED_PARAM (void)param

/** \addtogroup ONU_MAPI_REFERENCE_INTERNAL
   @{
*/

/** \addtogroup ONU_GPE_INTERNAL
   @{
*/

/** Convert hardware coprocessor status to error code

   \param[in] st    Hardware coprocessor status
   \param[in] entry Table entry which will contain COP status as a result
*/
static INLINE enum onu_errorcode
cop_to_onu_errorcode(enum cop_errorcode st,
		     struct gpe_table_entry *entry)
{
	entry->result = st;

	switch (st) {
		case COP_STATUS_INVALID_INDEX:
			return GPE_STATUS_COP_INVALID_INDEX;
		case COP_STATUS_END_OF_TABLE:
			return GPE_STATUS_COP_END_OF_TABLE;
		case COP_STATUS_OUT_OF_MEMORY:
			return GPE_STATUS_COP_OUT_OF_MEMORY;
		case COP_STATUS_ENTRY_EXISTS:
			return GPE_STATUS_COP_ENTRY_EXISTS;
		case COP_STATUS_ERROR_DISCARD_FRAME:
			return GPE_STATUS_COP_ERROR_DISCARD_FRAME;
		case COP_STATUS_SOFT_ERR_1:
			return GPE_STATUS_COP_SOFT_ERR_1;
		case COP_STATUS_SOFT_ERR_2:
			return GPE_STATUS_COP_SOFT_ERR_2;
		case COP_STATUS_ERR:
			return GPE_STATUS_COP_ERR;
		case COP_STATUS_TIMEOUT:
			return GPE_STATUS_COP_TIMEOUT;
		case COP_STATUS_ERR_FLUSH:
			return GPE_STATUS_COP_FLUSH;
		default:
			return ONU_STATUS_OK;
	}
}

/** Convert SCE status to error code

   \param[in] st SCE status
*/
static INLINE enum onu_errorcode sce_to_onu_errorcode(int st)
{
	switch (st) {
	case PE_STATUS_OK:
		return ONU_STATUS_OK;

		break;

	default:
		return (enum onu_errorcode) - (5000 + (int) st);

		break;
	}
}

static enum onu_errorcode sce_pe_table_init(struct onu_control *ctrl,
					    const uint32_t table_id)
{
	struct sce_fw_pe_message msg;
	uint32_t idx, pe_idx;
	uint32_t table_size;
	enum pe_errorcode ret;

	memset(msg.message, 0, sizeof(msg.message));

	if (pe_tbl_cfg[table_id].type == ONU_GPE_COP_UNDEF ||
	    pe_tbl_cfg[table_id].type == ONU_GPE_COP_STRUCT)
		return ONU_STATUS_OK;

	msg.table_id = table_id;
	msg.entry_width = pe_tbl_cfg[table_id].entry_width / 32;
	table_size = pe_tbl_cfg[table_id].size;

	if (msg.entry_width == 0)
		msg.entry_width = 1;

	switch (pe_tbl_cfg[table_id].type) {
	case ONU_GPE_COP_BITVECT:
	case ONU_GPE_COP_ARRAY:
	case ONU_GPE_COP_VARRAY:
		msg.message[0] = 0;
		break;

	case ONU_GPE_COP_LIST:
		msg.message[0] = (1 << 30);
		break;

	case ONU_GPE_COP_LLIST:
	case ONU_GPE_COP_HASH:
	case ONU_GPE_COP_UNDEF:
		/* not handled; return error */
		return GPE_STATUS_NO_SUPPORT;
	};

	for (idx = 0; idx < table_size; idx++) {
		msg.table_idx = idx;

		for (pe_idx = 0; pe_idx < ctrl->num_pe; pe_idx++) {
			if (!is_pe_table_supported(pe_idx,
					&(ctrl->pe_fw[pe_idx]), table_id))
				continue;

			msg.pe_index = pe_idx;
			ret = sce_fw_pe_message_send(&msg);
			if (ret != 0)
				return ONU_STATUS_FW_TABLES_INIT_ERR;
		}
	}

	return 0;
}

STATIC enum cop_errorcode cop_list_handle(struct gpe_table_entry *param,
		struct gpe_table_entry *entry,
		struct onu_control *ctrl,
		uint32_t cmd)
{
	uint32_t bitpos, wordpos, pos, nil;
	uint32_t *ptmp, *pTableTmp;
	enum cop_errorcode cop_ret;
	struct gpe_table_entry table;
	uint32_t list_ctrl;
	bool end_of_loop = false;
	bool end_of_list = false;

	/* get NIL bit position in the corresponding word */
	bitpos = param->index % ONU_GPE_LIST_NIL_WORDSIZE;
	/* get corresponding word for actual index */
	wordpos = param->index >> ONU_GPE_LIST_NIL_SHIFTFACTOR;

	switch(param->id) {
		case ONU_GPE_DS_MC_IPV4_SOURCE_FILTER_TABLE_ID:
			pos = 0;
			pTableTmp = &(table.data.message.data[
			              (ONU_GPE_DS_MC_IPV4_SOURCE_FILTER_TABLE_ENTRY_SIZE >> 5) - 1] );
			break;
		case ONU_GPE_DS_MC_IPV6_SOURCE_FILTER_TABLE_ID:
			pos = 1;
			pTableTmp = &(table.data.message.data[
			              (ONU_GPE_DS_MC_IPV6_SOURCE_FILTER_TABLE_ENTRY_SIZE >> 5) - 1] );
			break;
		case ONU_GPE_MAC_FILTER_TABLE_ID:
			pos = 2;
			pTableTmp = &(table.data.message.data[
			              (ONU_GPE_MAC_FILTER_TABLE_ENTRY_SIZE >> 5) - 1] );
			break;
		case ONU_GPE_ETHERTYPE_FILTER_TABLE_ID:
			pos = 3;
			pTableTmp = &(table.data.message.data[
			              (ONU_GPE_ETHERTYPE_FILTER_TABLE_ENTRY_SIZE >> 5) - 1] );
			break;
		default:
			ONU_DEBUG_ERR("COP LIST error "
				      "(table id %d, "
				      "instance %d, "
				      "cmd 0x%08x\n",
				      param->id,
				      param->instance,
				      cmd);

			return COP_STATUS_INVALID_INDEX;
			break;
	}
	ptmp = &(ctrl->cop_list_info[pos][wordpos]);

	/* get the corresponding NIL bit position */
	nil = (ctrl->cop_list_info[pos][wordpos] >> bitpos) & 0x1;

	if(cmd == ONU_GPE_COP_ADD) {
		/* sequence for protection of subsequent list */
		table.id = param->id;
		table.index = param->index;

		while(!end_of_loop &&
			table.index < cop_tbl_cfg[param->id].size) {
			cop_ret = gpe_table_entry_intresp(ctrl, &table, ONU_GPE_COP_READ);

#ifdef ONU_COP_DEBUG_LL
			ONU_DEBUG_MSG("index: %d, table: 0x%08x", table.index, *pTableTmp);
#endif
			/* get VALID and END ctrl bits from command response
			 * VALID = 31....1
			 * END = 30 ....0
			 * */
			if(cop_ret)
				return cop_ret;

			list_ctrl = ((*pTableTmp) >> 30) & 0x3;

			if(end_of_list) {
				end_of_loop = true;
				if(list_ctrl == 2 || list_ctrl == 3)
					return COP_STATUS_OUT_OF_MEMORY;
			}
#ifdef ONU_COP_DEBUG_LL
			ONU_DEBUG_MSG("valid: %d, end %d", (list_ctrl&0x2) >> 1, list_ctrl&0x1);
#endif
			switch(list_ctrl) {
				case 0:/*  not VALID, no END -> empty entry or empty list */
					end_of_loop = true;
					break;
				case 1: /* not VALID, END bit set -> ignore */
					table.index++;
					break;
				case 2: /* VALID, no END -> get next entry */
					table.index++;
					break;
				case 3: /* VALID, END -> end of list found */
					table.index++;
					end_of_list = true;
					break;
			}
		}

		cop_ret = cop_table_entry_add(entry,
				cop_tbl_cfg[param->id].key_len, nil);
	}
	else /* ONU_GPE_COP_DELETE */
		cop_ret = cop_table_entry_delete(entry,
				cop_tbl_cfg[param->id].key_len);

	if(cop_ret == COP_STATUS_SUCCESS) {
		/* abused result bit for NIL bit */
		nil = entry->result;
		entry->result = 0;

		/* update the NIL bit data structure */
		*ptmp &= ~(1 << bitpos);
		*ptmp |= (nil << bitpos);
	}

	return cop_ret;
}

/** Hardware Programming Details:

	All tables that are not microcode supported and operate on
	HASH maintained tables need to mimic hardware coprocessor microcode via
	software access.

	Required procedure for ADD:
	1.) first part of table holds the key (see excel)
	2.) key length can be delivered from global struct sce_table_cfg
	3.) read from hash table with key (use SEARCHR command with key)
	4.) If hash entry exists, extract start pointer from response
	5.) then perform add command with idx=startpointer (key, data),
		this will append the new entry to the end of list which starts
		at startpointer
	6.) If hash not exists, get a new element by reading AUX field from
		TABLE0 (config space shows the beginning of free list)
	7.) then idx=auxpointer and perform an add (on the table)
	8.) create hash entry for first element (hash did not exist until now),
		by issuing add command to hash table with key and data for hash
		table (data= has table entry)

	For more detailed information see microcode documentation !
*/
STATIC enum onu_errorcode general_add(struct onu_device *p_dev,
				      struct gpe_table_entry *in,
				      uint32_t hash_id,
				      uint32_t table_id)
{
	struct onu_control *ctrl = p_dev->ctrl;
	struct gpe_table_entry entry;
	uint16_t hash_found;
	uint32_t tbl_pointer, base_pointer, entry_width, tbl_index;
#ifdef ONU_COP_BUGFIX
	uint32_t instruction_id;
#endif
	enum onu_errorcode ret;
	enum cop_errorcode cop_ret;

	/* search if HASH exists already */
	entry.id = hash_id;
	entry.index = 0;
	memcpy( &(entry.data.message.data[0]), &(in->data.message.data[0]),
		sizeof(entry.data.message));

#ifdef ONU_COP_BUGFIX
	ONU_DEBUG_MSG("cop: using bugfix for GPONC-117 ");
	switch (hash_id) {
	case ONU_GPE_FID_HASH_TABLE_ID:
		instruction_id = IF_FIDHASH_SEARCHR;
		break;
	case ONU_GPE_LONG_FWD_HASH_TABLE_ID:
		instruction_id = IF_IPV6HASH_SEARCHR;
		break;
	default:
		ONU_DEBUG_ERR("cop: unknown hash id");
		return -1;
	}
	ret = gpe_table_entry_do(p_dev, &entry, instruction_id);
#else
	ret = TABLE_GET(ctrl, &entry);
#endif
	if (ret)
		return ret;

	if (entry.result == COP_STATUS_SUCCESS) {
		/* if HASH is found, extract start index */
		tbl_index = (entry.data.message.data[0] >> ONU_GPE_COP_NEXT_POS)
							& ONU_GPE_COP_NEXT_MSK;
		hash_found = 1;
	} else {
		/* HASH not found */
		/* read from address config space */
		entry.id = 0;
		entry.instance = GPE_TABLE_COP(table_id);

		switch(hash_id) {
		case ONU_GPE_LONG_FWD_HASH_TABLE_ID:
		case ONU_GPE_FID_HASH_TABLE_ID:
			entry.index = (uintptr_t)COPLINK_COP_TABLE22;
			break;
		default:
			ONU_DEBUG_ERR("cop: unknown hash id");
			return -1;
		}

		cop_ret = cop_table_entry_read(&entry, ONU_GPE_COP_TABLE0R);

		/* get AUX field from corresponding table and calculate
		   new index */
		if (cop_ret == COP_STATUS_SUCCESS) {
			tbl_pointer = entry.data.message.data[0] &
							   COP_TABLE12_AUX_MASK;
			base_pointer = cop_tbl_cfg[table_id].base;
			entry_width = cop_tbl_cfg[table_id].entry_width / 32;

			/* points to beginning of a new list */
			tbl_index = (tbl_pointer-base_pointer) / entry_width;
		} else {
			return cop_to_onu_errorcode(cop_ret, &entry);
		}

		hash_found = 0;
	}

	/* search for table entry */
	entry.id = table_id;
	entry.index = tbl_index;
	memcpy( &(entry.data.message.data[0]),
		&(in->data.message.data[0]),
		sizeof(entry.data.message));

#ifdef ONU_COP_BUGFIX
	if (cop_tbl_cfg[table_id].key_len == 32) {
		ONU_DEBUG_MSG("cop: using bugfix for errata no1");
		ret = gpe_table_entry_do(p_dev, &entry, IF_FID_LOOKUP);
	} else {
		ret = TABLE_GET(ctrl, &entry);
	}

#else
	ret = TABLE_GET(ctrl, &entry);
#endif

	if (ret && ret != GPE_STATUS_COP_ENTRY_NOT_FOUND)
		return ret;

	if (entry.result == COP_STATUS_SUCCESS) {
		/* table entry found, entry exists already */
		return ONU_STATUS_OK;
	} else {
		/* table entry not found */

		/* add FID ASSIGNMENT table entry */
		entry.id = table_id;
		entry.index = tbl_index;
		memcpy( &(entry.data.message.data[0]),
			&(in->data.message.data[0]),
			sizeof(entry.data.message));

		if(is_falcon_chip_a1x() || hash_found) {
			ret = gpe_table_entry_add(p_dev, &entry);
		}
		else { /* GPONC-178 */
			ret = gpe_table_entry_nil_add(p_dev, &entry, 1);
		}

		if (ret || entry.result != COP_STATUS_SUCCESS)
			return ret;

		if (!hash_found) {
			/* HASH was not found, also HASH needs to be created */

			/* add FID HASH entry */
			entry.id = hash_id;
			entry.index = 0;
			memcpy( &(entry.data.message.data[0]),
				&(in->data.message.data[0]),
				sizeof(entry.data.message));

			entry.hashdata.message.data[0] =
			   (ONU_GPE_COP_VALID_MSK << ONU_GPE_COP_VALID_POS) |
				((tbl_index & ONU_GPE_COP_NEXT_MSK) <<
							ONU_GPE_COP_NEXT_POS);
			ret = gpe_table_entry_add(p_dev, &entry);

			if (ret || entry.result != COP_STATUS_SUCCESS)
				return ret;
		}
	}

	return ONU_STATUS_OK;
}

/** Hardware Programming Details:

	All tables that are not microcode supported and operate on
	HASH maintained tables need to mimic hardware coprocessor microcode via
	software access.

    Required procedure for DELETE:
    1.) fetch bucket pointer (index) from hash table with key
    2.) check existence, otherwise exit
    3.) make search, if entry exists, store index
    4.) get next field (address)
    5.) delete entry
	6.) check end field at stored index

	For more detailed information see microcode documentation !
*/
STATIC enum onu_errorcode general_delete(struct onu_device *p_dev,
					 struct gpe_table_entry *in,
					 uint32_t hash_id,
					 uint32_t table_id)
{
	struct onu_control *ctrl = p_dev->ctrl;
	struct gpe_table_entry entry;
	enum onu_errorcode ret;
	uint32_t tbl_idx;
	uint32_t hash_idx;
	uint32_t delete_idx;
	uint32_t next_idx;
	uint32_t next_addr;
	uint32_t end;
	uint32_t pos;

	uint32_t prev_idx;
	uint32_t prev_next_idx;
	uint32_t prev_next_addr;
	uint32_t prev_corr_idx;
	uint32_t prev_corr_flag;
	uint32_t delete_fields;
	uint32_t instruction_id;

	/* 1.) fetch bucket pointer (index) from hash table with key */
	entry.id = hash_id;
	entry.index = 0;
	memcpy( &(entry.data.message.data[0]), &(in->data.message.data[0]),
		sizeof(entry.data.message));

#ifdef ONU_COP_BUGFIX
	ONU_DEBUG_MSG("cop: using bugfix for GPONC-117 ");
	switch (hash_id) {
		case ONU_GPE_FID_HASH_TABLE_ID:
			instruction_id = IF_FIDHASH_SEARCHR;
			break;
		case ONU_GPE_LONG_FWD_HASH_TABLE_ID:
			instruction_id = IF_IPV6HASH_SEARCHR;
			break;
		default:
			ONU_DEBUG_ERR("cop: unknown hash id");
			return -1;
	}
	ret = gpe_table_entry_do(p_dev, &entry, instruction_id);
#else
	ret = TABLE_GET(ctrl, &entry);
#endif
	if (ret)
		return ret;

	/* 2.) check existence, otherwise exit */
	if (entry.result != COP_STATUS_SUCCESS)
		return ONU_STATUS_ERR;

	hash_idx = entry.index;
	/* extract start index */
	tbl_idx = (entry.data.message.data[0] >> ONU_GPE_COP_NEXT_POS) &
							   ONU_GPE_COP_NEXT_MSK;

	/* 3.) search read the entry which shall be deleted */
	entry.id = table_id;
	entry.index = tbl_idx;
	memcpy( &(entry.data.message.data[0]), &(in->data.message.data[0]),
		sizeof(entry.data.message));

#ifdef ONU_COP_BUGFIX
	if (cop_tbl_cfg[table_id].key_len == 32) {
		ONU_DEBUG_MSG("cop: using bugfix for errata no1");
		ret = gpe_table_entry_do(p_dev, &entry, IF_FID_LOOKUP);
	} else {
		ret = TABLE_GET(ctrl, &entry);
	}

#else
	ret = TABLE_GET(ctrl, &entry);
#endif

	if (ret)
		return ret;

	/* check existence, otherwise exit */
	if (entry.result != COP_STATUS_SUCCESS)
		return ONU_STATUS_ERR;

	/* save delete index */
	delete_idx = entry.index;

	/* 4.) get next field (address) and end field */
	/* do low level read to obtain the next address field */
	entry.id = table_id;
	entry.index = delete_idx;

	ret = TABLE_READ(ctrl, &entry);
	/* entry must exist, therefore no check here */

	pos = (cop_tbl_cfg[table_id].entry_width / 32) - 1;
	next_addr = (entry.data.message.data[pos] >>
				ONU_GPE_COP_NEXT_POS) & ONU_GPE_COP_NEXT_MSK;
	end 	  = (entry.data.message.data[pos] >>
				ONU_GPE_COP_END_POS) & ONU_GPE_COP_END_MSK;

#ifdef ONU_COP_BUGFIX
	delete_fields = entry.data.message.data[pos];
#endif

	/* 5.) delete table entry */
	entry.id = table_id;
	entry.index = tbl_idx;
	memcpy( &(entry.data.message.data[0]), &(in->data.message.data[0]),
		sizeof(entry.data.message));

	if(is_falcon_chip_a1x()) { /* GPONC-81, GPONC-189 */
		if (hash_id == ONU_GPE_FID_HASH_TABLE_ID &&
			table_id == ONU_GPE_FID_ASSIGNMENT_TABLE_ID) {
			ONU_DEBUG_MSG("cop: using bugfix for errata no10");

			entry.index = tbl_idx;
			ret = gpe_table_entry_do(p_dev, &entry, IF_FID_GET_PREVIOUS);
			if (ret)
				return ret;

			prev_next_addr = (entry.data.message.data[pos] >>
					 ONU_GPE_COP_NEXT_POS) & ONU_GPE_COP_NEXT_MSK;
			prev_next_idx = (prev_next_addr - cop_tbl_cfg[table_id].base) /
					(cop_tbl_cfg[table_id].entry_width / 32);

			prev_corr_flag = 0;
			prev_idx = entry.index;
			prev_corr_idx = prev_idx;

			if (tbl_idx != delete_idx) {

				if ((prev_next_idx != delete_idx) &&
							(prev_idx != tbl_idx)) {
					prev_corr_flag = 1;
					prev_corr_idx = prev_idx + 1;
				}

				if ((prev_next_idx == delete_idx) &&
							(prev_idx == tbl_idx)) {
					prev_corr_flag = 1;
					prev_corr_idx = prev_idx;
				}

				if ((prev_next_idx != delete_idx) ||
							(prev_corr_flag == 1)) {
					prev_corr_flag = 1; /* if not set */

					entry.index = prev_corr_idx;
					ret = TABLE_READ(ctrl, &entry);
					if (ret)
						return ret;

					prev_next_addr =
						(entry.data.message.data[pos] >>
							ONU_GPE_COP_NEXT_POS) &
								   ONU_GPE_COP_NEXT_MSK;
					prev_next_idx =
					   (prev_next_addr -
						cop_tbl_cfg[table_id].base) /
						(cop_tbl_cfg[table_id].entry_width /
						   32);

					/* check again the correct previous */
					if (prev_next_idx != delete_idx) {
						/* we need manual fixing (search for previous */
						ONU_DEBUG_MSG("Manual prev search required");
						while (prev_next_idx != delete_idx) {
							entry.index = prev_next_idx;
							ret = TABLE_READ(ctrl, &entry);
							prev_next_addr = (entry.data.message.data[pos] >>
									ONU_GPE_COP_NEXT_POS) &
									ONU_GPE_COP_NEXT_MSK;
							prev_next_idx = (prev_next_addr -
									 cop_tbl_cfg[table_id].base) /
									(cop_tbl_cfg[table_id].entry_width / 32);
						}
						prev_corr_idx = entry.index;
					}
				}
			}

			if (prev_corr_flag == 0) {
				entry.id = table_id;
				entry.index = tbl_idx;
				memcpy(&(entry.data.message.data[0]),
					   &(in->data.message.data[0]),
					   sizeof(entry.data.message));
				ret = gpe_table_entry_delete(p_dev, &entry);
				if (ret)
					return ret;

				if (end && (tbl_idx != delete_idx)) {
					entry.index = prev_idx;
					ret = TABLE_READ(ctrl, &entry);
					if (ret)
						return ret;
					entry.data.message.data[pos] |=
								 (1 << ONU_GPE_COP_END_POS);
					ret = gpe_table_entry_write(p_dev, &entry);
				}

			} else {
				ONU_DEBUG_MSG("cop: using bugfix for errata no10 "
						  "special delete");
				entry.index = delete_idx;
				entry.data.message.data[0] = in->data.message.data[0];
				entry.data.message.data[1] = delete_fields;
				entry.data.message.data[2] =
					(prev_corr_idx & ONU_GPE_COP_NEXT_MSK) <<
								   ONU_GPE_COP_NEXT_POS;
				ret = gpe_table_entry_do(p_dev, &entry, IF_FID_REMOVE);
				if (ret)
					return ret;
			}
		} else { /* LONG FWD table */
			ret = gpe_table_entry_delete(p_dev, &entry);
			if (ret)
				return ret;
		}
	}
	else {
		ret = gpe_table_entry_delete(p_dev, &entry);
		if (ret)
			return ret;
	}

	/* check if delete succeeded */
	if (entry.result != COP_STATUS_SUCCESS)
		return ONU_STATUS_ERR;

	/* 6.) check end field at stored index */
	if (tbl_idx == delete_idx) { /* was the entry the first one ? */
		if (end) {
			/* was the entry the only one */
			/* delete also hash entry */
			entry.id = hash_id;
			entry.index = hash_idx;
			memcpy( &(entry.data.message.data[0]),
				&(in->data.message.data[0]),
				sizeof(entry.data.message));
			ret = gpe_table_entry_delete(p_dev, &entry);
			/* check if has delete succeeded */
			if (ret)
				return ret;
		} else {
			/* update start pointer */
			/* calculate index from address
			   formula is: next_idx =
					(next_addr - base_addr) / entry_width */
			next_idx =
			  (next_addr - cop_tbl_cfg[table_id].base) /
			  (cop_tbl_cfg[table_id].entry_width / 32);

			entry.id = hash_id;
			entry.index = hash_idx;

			entry.hashdata.message.data[0] =
			   (ONU_GPE_COP_VALID_MSK << ONU_GPE_COP_VALID_POS) |
				((next_idx & ONU_GPE_COP_NEXT_MSK) <<
							ONU_GPE_COP_NEXT_POS);
			ret = gpe_table_entry_set(p_dev, &entry);
			if (ret)
				return ret;

			/* check if search write succeeded */
			if (entry.result != COP_STATUS_SUCCESS)
				return ONU_STATUS_ERR;
		}
	}

	return ONU_STATUS_OK;
}

enum onu_errorcode sce_cnt_get(struct onu_control *ctrl,
			       struct gpe_table_entry *entry,
			       uint32_t idx)
{
	enum onu_errorcode ret;

	entry->id = ONU_GPE_COUNTER_TABLE_ID;
	entry->instance = 1;
	entry->index = idx;
	ret = TABLE_GET(ctrl, entry);
	if (ret)
		return ret;

	return ONU_STATUS_OK;
}

enum onu_errorcode sce_pe_table_entry_write(const struct pe_fw_info *fw_info,
					    const uint8_t num_pe,
					    const struct gpe_table_entry *entry)
{
	enum pe_errorcode ret;
	struct sce_fw_pe_message msg;
	uint8_t pe_idx;
	uint16_t tmp16;
	uint32_t size_in_bytes = pe_tbl_cfg[entry->id].entry_width / 8;
	uint32_t size = size_in_bytes / 4;
	int shift;
	bool wr = false;

	if (size == 0)
		size = 1;

	msg.table_id = entry->id;
	msg.entry_width = size;

	for (pe_idx = 0; pe_idx < num_pe; pe_idx++)
		if (is_pe_table_supported(pe_idx, &fw_info[pe_idx], entry->id))
			break;

	if (pe_idx >= num_pe)
		return ONU_STATUS_ERR;

	if (size_in_bytes == 1) {
		msg.table_idx = entry->index / 4;
		msg.pe_index = pe_idx;

		ret = sce_fw_pe_message_receive(&msg);
		if (ret != PE_STATUS_OK) {
			ONU_DEBUG_ERR("sce_fw_pe_message_receive error %d",ret);
			return sce_to_onu_errorcode(ret);
		}

		shift = (3 - entry->index % 4) * 8;

		msg.message[0] &= ~(0xFF << shift);
		msg.message[0] |= *(uint8_t *)&entry->data << shift;
	} else if (size_in_bytes == 2) {
		msg.table_idx = entry->index / 2;
		msg.pe_index = pe_idx;

		ret = sce_fw_pe_message_receive(&msg);
		if (ret != PE_STATUS_OK) {
			ONU_DEBUG_ERR("sce_fw_pe_message_receive error %d",ret);
			return sce_to_onu_errorcode(ret);
		}

		shift = (1 - entry->index % 2) * 16;
		memcpy(&tmp16, &entry->data, size_in_bytes);
		msg.message[0] &= ~(0xFFFF << shift);
		msg.message[0] |= tmp16 << shift;
	} else if (size_in_bytes < 4) {
		ONU_DEBUG_ERR("PE: WR unsupported table size "
			      "(%u bytes, id %u)!", size_in_bytes, entry->id);

		return ONU_STATUS_ERR;
	} else {
		msg.table_idx = entry->index;
		memcpy(msg.message, &entry->data, msg.entry_width * 4);
	}

	for (pe_idx = 0; pe_idx < num_pe; pe_idx++) {
		/* PE instance selected */
		if (entry->instance & (1 << pe_idx)) {
			if (!is_pe_table_supported(pe_idx, &fw_info[pe_idx],
						   entry->id))
				continue;

			msg.pe_index = pe_idx;

			ret = sce_fw_pe_message_send(&msg);
			if (ret != PE_STATUS_OK) {
				ONU_DEBUG_ERR("sce_fw_pe_message_send error %d",
									   ret);
				return sce_to_onu_errorcode(ret);
			}
			wr = true;
		}
	}

	return wr ? ONU_STATUS_OK : ONU_STATUS_ERR;
}

enum onu_errorcode sce_pe_table_entry_read(const struct pe_fw_info *fw_info,
					   const uint8_t num_pe,
					   struct gpe_table_entry *entry)
{
	enum pe_errorcode ret;
	struct sce_fw_pe_message msg;
	uint8_t pe_idx;
	uint16_t tmp16;
	uint32_t size_in_bytes = pe_tbl_cfg[entry->id].entry_width / 8;
	uint32_t size = size_in_bytes / 4;
	int shift;

	if (size == 0)
		size = 1;

	msg.table_id = entry->id;
	msg.entry_width = size;

	if (size_in_bytes == 1) {
		msg.table_idx = entry->index / 4;
	} else if (size_in_bytes == 2) {
		msg.table_idx = entry->index / 2;
	} else if (size_in_bytes < 4) {
		ONU_DEBUG_ERR("PE: RD unsupported table size "
			      "(%u bytes, id %u)!", size_in_bytes, entry->id);

		return ONU_STATUS_ERR;
	} else {
		msg.table_idx = entry->index;
	}

	for (pe_idx = 0; pe_idx < num_pe; pe_idx++) {
		if (entry->instance & (1 << pe_idx)) {

			if (!is_pe_table_supported(pe_idx, &fw_info[pe_idx],
						   entry->id))
				continue;

			msg.pe_index = pe_idx;

			ret = sce_fw_pe_message_receive(&msg);
			if (ret != PE_STATUS_OK)
				return sce_to_onu_errorcode(ret);

			if (size_in_bytes == 1) {

				shift = (3 - entry->index % 4) * 8;

				*(uint8_t *)&entry->data =
					(uint8_t)(msg.message[0] >> shift);
			} else if (size_in_bytes == 2) {
				shift = (1 - entry->index % 2) * 16;

				tmp16 = (msg.message[0] >> shift) & 0xFFFF;
				memcpy(&entry->data, &tmp16, size_in_bytes);
			} else {
				memcpy(&entry->data, msg.message,
				       msg.entry_width * 4);
			}

			/* return first selected PE data */
			return ONU_STATUS_OK;
		}
	}

	return ONU_STATUS_ERR;
}

/** The gpe_table_entry_set function is used to set an entry of a selected
    configuration table.
*/
/** Hardware Programming Details:

	Do NOT operate with this function on following tables:
	Use dedicated API functions therefore!

	ONU_GPE_SHORT_FWD_TABLE_MAC_ID
	ONU_GPE_SHORT_FWD_TABLE_IPV4_ID
	ONU_GPE_SHORT_FWD_TABLE_IPV4_MC_ID
	ONU_GPE_SHORT_FWD_HASH_TABLE_ID
	ONU_GPE_LEARNING_LIMITATION_TABLE_ID

	ONU_GPE_LONG_FWD_TABLE_IPV6_ID
	ONU_GPE_LONG_FWD_TABLE_IPV6_MC_ID
	ONU_GPE_LONG_FWD_TABLE_HASH_ID

	ONU_GPE_FID_ASSIGNMENT_TABLE_ID
	ONU_GPE_FID_HASH_TABLE_ID

	ONU_GPE_VLAN_TABLE_ID
	ONU_GPE_TAGGING_FILTER_TABLE_ID
	ONU_GPE_EXTENDED_VLAN_TABLE_ID
	ONU_GPE_VLAN_RULE_TABLE_ID
	ONU_GPE_VLAN_TREATMENT_TABLE_ID
*/
enum onu_errorcode gpe_table_entry_set(struct onu_device *p_dev,
				       struct gpe_table_entry *param)
{
	struct onu_control *ctrl = p_dev->ctrl;

	return gpe_table_entry_intcmd(ctrl, param, ONU_GPE_COP_SET);
}

/** The gpe_table_entry_add function is used to add an entry to a selected
    configuration table.
*/
/** Hardware Programming Details:

	See gpe_table_entry_set for details.
*/
enum onu_errorcode gpe_table_entry_add(struct onu_device *p_dev,
				       struct gpe_table_entry *param)
{
	struct onu_control *ctrl = p_dev->ctrl;

	return gpe_table_entry_intcmd(ctrl, param, ONU_GPE_COP_ADD);
}

enum onu_errorcode gpe_table_entry_nil_add(struct onu_device *p_dev,
				       struct gpe_table_entry *param,
				       const bool nil)
{
	struct gpe_table_entry entry;
	uint32_t cop_id, table_id;
	enum cop_errorcode cop_ret;

	cop_id = GPE_TABLE_COP(param->id);
	table_id = GPE_TABLE_ID(param->id);

	entry.id = table_id;
	entry.index = param->index;
	memcpy(&entry.data, &param->data, sizeof(entry.data));
	memcpy(&entry.hashdata, &param->hashdata, sizeof(entry.hashdata));

	ONU_DEBUG_MSG(	"FIO_GPE_TABLE_ENTRY_CMD id %d, cop_id %d, "
			"idx %d, cmd %d", param->id, cop_id,
					  param->index, ONU_GPE_COP_ADD);

	/* COP table */
	entry.instance = cop_id;

	if (cop_id >= ONU_GPE_NUMBER_OF_COPWMC) {
		ONU_DEBUG_ERR("Invalid table entry instance %u, "
				  "table_id %u", cop_id, table_id);
		return GPE_STATUS_VALUE_RANGE_ERR;
	}

	if (table_id > gpe_hw_table_id_max[cop_id]) {
		ONU_DEBUG_ERR("Invalid COP table entry ID %d",table_id);
		return GPE_STATUS_VALUE_RANGE_ERR;
	}

	cop_ret = cop_table_entry_add(&entry, cop_tbl_cfg[param->id].key_len, nil);

	return cop_to_onu_errorcode(cop_ret, param);
}

/** The gpe_table_delete function is used to delete an
	complete table.
*/
/** Hardware Programming Details:
*/
enum onu_errorcode gpe_table_reinit(struct onu_device *p_dev,
				    const struct gpe_reinit_table *reinit_table)
{
	struct onu_control *ctrl = p_dev->ctrl;
	uint32_t id;
	enum onu_errorcode ret = ONU_STATUS_OK;

	id = reinit_table->table_id;

	if (GPE_IS_PE_TABLE(id)) {
		ret = sce_pe_table_init(ctrl, id - GPE_TABLE_PE_MIN_ID);
	} else {
		if (cop_table_init(id, id) != COP_STATUS_SUCCESS)
			return ONU_STATUS_ERR;
	}

	return ret;
}


/** The gpe_table_entry_delete function is used to delete an
	entry from the selected configuration table.
*/
/** Hardware Programming Details:

	See gpe_table_entry_set for details.
*/
enum onu_errorcode gpe_table_entry_delete(struct onu_device *p_dev,
					  struct gpe_table_entry *param)
{
	struct onu_control *ctrl = p_dev->ctrl;

	return gpe_table_entry_intcmd(ctrl, param, ONU_GPE_COP_DELETE);
}

/** The gpe_table_entry_search function is used to search an
	entry from the selected configuration table.
*/
/** Hardware Programming Details:

	See gpe_table_entry_set for details.
*/
enum onu_errorcode gpe_table_entry_search(struct onu_device *p_dev,
					  struct gpe_table_entry *param)
{
	struct onu_control *ctrl = p_dev->ctrl;

	return gpe_table_entry_intcmd(ctrl, param, ONU_GPE_COP_SEARCH);
}

/** The gpe_table_entry_do function is used to perform a sequence of microcode.
*/
/** Hardware Programming Details:

	The gpe_table_entry_do function shall not be used as an API function.
	It is used internally only if dedicated microcode labels needs to be
	accessed from software driver.
*/
enum onu_errorcode gpe_table_entry_do(struct onu_device *p_dev,
				      struct gpe_table_entry *param,
				      uint32_t instruction_id)
{
	struct gpe_table_entry entry;
	uint32_t cop_id, table_id;
	enum cop_errorcode cop_ret;

	cop_id = GPE_TABLE_COP(param->id);
	table_id = GPE_TABLE_ID(param->id);

	entry.id = table_id;
	entry.instance = cop_id;
	entry.index = param->index;
	memcpy(&entry.data, &param->data, sizeof(entry.data));

	cop_ret = cop_table_entry_exec(&entry, cop_tbl_cfg[param->id].key_len,
				       instruction_id);

	param->index = entry.index;
	memcpy(&(param->data.message.data[0]), &(entry.data.message.data[0]),
		sizeof(entry.data.message.data));

	return cop_to_onu_errorcode(cop_ret, param);
}

/** The gpe_table_entry_write function is used to write an
	entry to a selected configuration table,
	It shall be used for debugging purposes only.
*/
/** Hardware Programming Details:

	The gpe_table_entry_write directly writes to the given table.
*/
enum onu_errorcode gpe_table_entry_write(struct onu_device *p_dev,
					 struct gpe_table_entry *param)
{
	struct onu_control *ctrl = p_dev->ctrl;

	return gpe_table_entry_intcmd(ctrl, param, ONU_GPE_COP_WRITE);
}

/** The gpe_table_entry_intcmd function is an internal function used by
    gpe_table_entry_set
    gpe_table_entry_add
    gpe_table_entry_delete
    gpe_table_entry_write
    and called with different commands dependent of function.
*/
/** Hardware Programming Details:

	The gpe_table_entry_intcmd is used for all set-like functions.
*/
enum onu_errorcode gpe_table_entry_intcmd(struct onu_control *ctrl,
					  struct gpe_table_entry *param,
					  uint32_t cmd)
{
	struct gpe_table_entry entry;
	uint32_t cop_id, table_id;
	enum onu_errorcode ret;
	enum cop_errorcode cop_ret = 0;
	unsigned long flags = 0;

	cop_id = GPE_TABLE_COP(param->id);
	table_id = GPE_TABLE_ID(param->id);

	entry.id = table_id;
	entry.index = param->index;
	memcpy(&entry.data, &param->data, sizeof(entry.data));
	memcpy(&entry.hashdata, &param->hashdata, sizeof(entry.hashdata));

	if (GPE_IS_PE_TABLE(param->id)) {
		ONU_DEBUG_MSG(	"FIO_GPE_TABLE_ENTRY_CMD id %d, table_id %d, "
				"idx %d, cmd %d", param->id, table_id,
						  param->index, cmd);

		/* PE table */
		entry.instance = param->instance;

		if (table_id > ONU_GPE_FW_TABLE_ID_MAX) {
			ONU_DEBUG_ERR("Invalid PE table entry ID %d", table_id);
			return GPE_STATUS_VALUE_RANGE_ERR;
		}

		if ((entry.instance & (~ONU_GPE_ALL_PE_MASK)) &&
		     entry.instance != 0xff) {
			ONU_DEBUG_ERR(	"Invalid table entry instance %d, "
					"table id %d", 	entry.instance,
							table_id);
			return GPE_STATUS_VALUE_RANGE_ERR;
		}

		onu_spin_lock_get(&mailbox_lock, &flags);
		ret = sce_pe_table_entry_write(ctrl->pe_fw, ctrl->num_pe,
					       &entry);
		onu_spin_lock_release(&mailbox_lock, flags);

		return ret;
	} else {
		ONU_DEBUG_MSG(	"FIO_GPE_TABLE_ENTRY_CMD id %d, cop_id %d, "
				"idx %d, cmd %d", param->id, cop_id,
						  param->index, cmd);

		/* COP table */
		entry.instance = cop_id;

		if (cop_id >= ONU_GPE_NUMBER_OF_COPWMC) {
			ONU_DEBUG_ERR("Invalid table entry instance %u, "
				      "table_id %u", cop_id, table_id);
			return GPE_STATUS_VALUE_RANGE_ERR;
		}

		if (table_id > gpe_hw_table_id_max[cop_id]) {
			ONU_DEBUG_ERR("Invalid COP table entry ID %d",table_id);
			return GPE_STATUS_VALUE_RANGE_ERR;
		}

		/* For documentation of this switch see excel sheet
		   "SCE table access functions.xls"
		*/
		switch (cmd) {
		case ONU_GPE_COP_SET:
			switch (cop_tbl_cfg[param->id].type) {
			case ONU_GPE_COP_ARRAY:
			case ONU_GPE_COP_VARRAY:
			case ONU_GPE_COP_HASH:
				cop_ret = cop_table_entry_write(
						&entry, LINKC1_WRITE);
				break;
			case ONU_GPE_COP_LIST:
			case ONU_GPE_COP_LLIST:
#ifdef ONU_COP_BUGFIX
				if (param->id ==
				    ONU_GPE_DS_MC_IPV4_SOURCE_FILTER_TABLE_ID ||
				    param->id ==
				    ONU_GPE_ETHERTYPE_FILTER_TABLE_ID ||
				    param->id ==
				    ONU_GPE_DS_MC_IPV6_SOURCE_FILTER_TABLE_ID) {

					ONU_DEBUG_MSG("cop: using bugfix for "
						      "GPONC-69/Errata 15 ");

					cop_ret =
					   cop_table_entry_search(&entry,
						cop_tbl_cfg[param->id].key_len);
					if (!cop_ret) {
						cop_ret =
							COP_STATUS_END_OF_TABLE;
						break;
					}
				}
#endif
				cop_ret = cop_table_entry_searchw(&entry,
						cop_tbl_cfg[param->id].key_len);
				break;

			default:
				ONU_DEBUG_ERR("COP type %u error "
					      "(table id %d, "
					      "instance %d, "
					      "cmd 0x%08x\n",
					      cop_tbl_cfg[param->id].type,
					      param->id,
					      param->instance,
					      cmd);

				return GPE_STATUS_COP_ERR;
			}
			break;
		case ONU_GPE_COP_ADD:
			if(is_falcon_chip_a1x() ||
			   cop_tbl_cfg[param->id].type != ONU_GPE_COP_LIST) {
				cop_ret = cop_table_entry_add(&entry,
						cop_tbl_cfg[param->id].key_len, 0);
			}
			else {
				/* GPONC-178 Mgmt for LIST type */
				cop_ret = cop_list_handle(param, &entry, ctrl, cmd);
			}
			break;
		case ONU_GPE_COP_DELETE:
			if(is_falcon_chip_a1x() ||
			   cop_tbl_cfg[param->id].type != ONU_GPE_COP_LIST) {

				/* workaround for GPONSYS-188 / GPONSW-895 */
				if (cop_tbl_cfg[param->id].type == ONU_GPE_COP_HASH) {
					cop_table_entry_search(&entry,
						    cop_tbl_cfg[param->id].key_len);
					/* we always have only 32 bit hash-data*/
					entry.hashdata.message.data[0] = 0x0;
					cop_table_entry_write(&entry, LINKC1_WRITE);
				} else {
					cop_ret = cop_table_entry_delete(&entry,
						    cop_tbl_cfg[param->id].key_len);

				}
			}
			else {
				/* GPONC-178 Mgmt for LIST type */
				cop_ret = cop_list_handle(param, &entry, ctrl, cmd);
			}
			break;
		case ONU_GPE_COP_SEARCH:
			cop_ret = cop_table_entry_search(&entry,
					cop_tbl_cfg[param->id].key_len);
			break;
		case ONU_GPE_COP_WRITE:
			cop_ret = cop_table_entry_write(&entry, LINKC1_WRITE);
			break;
		case ONU_GPE_COP_EXEC:
			cop_ret = cop_table_entry_write(&entry, LINKC1_EXEC);
			break;
		default:
			ONU_DEBUG_ERR("COP error (table id %d, instance %d, "
				      "cmd 0x%08x\n",	param->id,
							param->instance, cmd);

			return GPE_STATUS_COP_ERR;
		}

		return cop_to_onu_errorcode(cop_ret, param);
	}
}

/** The gpe_table_entry_read function is used to read back a selected table
    entry. It shall be used only for debugging purposes only.
*/
/** Hardware Programming Details:

	The gpe_table_entry_read directly reads from the given table.
*/
enum onu_errorcode gpe_table_entry_read(struct onu_device *p_dev,
					const struct gpe_table *in,
					struct gpe_table_entry *out)
{
	struct onu_control *ctrl = p_dev->ctrl;

	memcpy(out, in, sizeof(struct gpe_table));
	out->result = 0;

	return TABLE_READ(ctrl, out);
}

/** The gpe_table_entry_get function is used to get a selected table entry.
*/
/** Hardware Programming Details:

	See gpe_table_entry_set for details.
*/
enum onu_errorcode gpe_table_entry_get(struct onu_device *p_dev,
				       const struct gpe_table *in,
				       struct gpe_table_entry *out)
{
	struct onu_control *ctrl = p_dev->ctrl;

	memcpy(out, in, sizeof(struct gpe_table));
	out->result = 0;

	return TABLE_GET(ctrl, out);
}

/** The gpe_table_entry_intresp function is an internal function used by
    gpe_table_entry_get
    gpe_table_entry_read
    and called with different commands dependent of function.
*/
/** Hardware Programming Details:

	The gpe_table_entry_intresp is used for all get-like functions.
*/
enum onu_errorcode gpe_table_entry_intresp(struct onu_control *ctrl,
					   struct gpe_table_entry *param,
					   uint32_t cmd)
{
	uint32_t cop_id, table_id, key_len, orig_id, orig_instance;
	enum onu_errorcode ret;
	enum cop_errorcode cop_ret;
	unsigned long flags = 0;

	cop_id = GPE_TABLE_COP(param->id);
	table_id = GPE_TABLE_ID(param->id);

	orig_id = param->id;
	orig_instance = param->instance;

	if (GPE_IS_PE_TABLE(param->id)) {
		/* PE table */
		if (table_id > ONU_GPE_FW_TABLE_ID_MAX) {
			ONU_DEBUG_ERR("Invalid PE table entry ID %d", table_id);
			return GPE_STATUS_VALUE_RANGE_ERR;
		}

		if ((param->instance & (~ONU_GPE_ALL_PE_MASK)) &&
		     param->instance != 0xff) {
			ONU_DEBUG_ERR(	"Invalid table entry instance %d, "
					"table id %d", 	param->instance,
							table_id);
			return GPE_STATUS_VALUE_RANGE_ERR;
		}

		param->id = table_id;

		onu_spin_lock_get(&mailbox_lock, &flags);
		ret = sce_pe_table_entry_read(ctrl->pe_fw, ctrl->num_pe, param);
		onu_spin_lock_release(&mailbox_lock, flags);

		param->id = orig_id;
		if (ret != 0)
			ONU_DEBUG_ERR(	"sce error %d, table ID %d, index %u",
				ret, table_id, param->index);
		return ret;
	} else {
		if (cop_id >= ONU_GPE_NUMBER_OF_COPWMC) {
			ONU_DEBUG_ERR("Invalid table entry instance %u, "
				      "table_id=%u", cop_id, table_id);
			return GPE_STATUS_VALUE_RANGE_ERR;
		}

		/* COP table */
		if (table_id > gpe_hw_table_id_max[cop_id]) {
			ONU_DEBUG_ERR("Invalid COP table entry ID %d", cop_id);
			return GPE_STATUS_VALUE_RANGE_ERR;
		}

		/* For documentation of this switch see excel sheet
		   "SCE table access fucntions.xls"
		*/
		switch (cmd) {
		case ONU_GPE_COP_GET:
			switch (cop_tbl_cfg[param->id].type) {
			case ONU_GPE_COP_ARRAY:
			case ONU_GPE_COP_VARRAY:
				param->id = table_id;
				param->instance = cop_id;
				cop_ret = cop_table_entry_read(	param,
								LINKC1_READ);
				break;
			case ONU_GPE_COP_LIST:
			case ONU_GPE_COP_LLIST:
			case ONU_GPE_COP_HASH:
				key_len = cop_tbl_cfg[param->id].key_len;
				param->id = table_id;
				param->instance = cop_id;

#ifdef ONU_COP_BUGFIX
				if (orig_id ==
				    ONU_GPE_DS_MC_IPV4_SOURCE_FILTER_TABLE_ID) {
					ONU_DEBUG_MSG("cop: using bugfix for "
						      "errata no1");

					cop_ret = cop_table_entry_exec(param,
						       key_len, IF_IPV4_SEARCH);
				} else {
					cop_ret = cop_table_entry_searchr(param,
								       key_len);
				}
#else
				cop_ret = cop_table_entry_searchr(param,
								  key_len);
#endif

				if (cop_ret == COP_STATUS_OK) {
					param->id = orig_id;
					param->instance = orig_instance;
					param->result = 0;
					return GPE_STATUS_COP_ENTRY_NOT_FOUND;
				}

				break;

			default:
				ONU_DEBUG_ERR("COP type %u error (table id %d, "
					      "instance %d, cmd 0x%08x\n",
					      cop_tbl_cfg[param->id].type,
					      param->id, param->instance, cmd);

				return GPE_STATUS_COP_ERR;
			}
			break;
		case ONU_GPE_COP_READ:
			param->id = table_id;
			param->instance = cop_id;

			cop_ret = cop_table_entry_read(param, LINKC1_READ);
			break;
		default:
			ONU_DEBUG_ERR("COP error (table id %d, instance %d, "
				      "cmd 0x%08x\n", 	param->id,
							param->instance,
							cmd);

			return GPE_STATUS_COP_ERR;
		}

		param->id = orig_id;
		param->instance = orig_instance;

		return cop_to_onu_errorcode(cop_ret, param);
	}
}

/** The gpe_bridge_cnt_get function is used to read the bridge-based counters
    within the GPE hardware module. For each of the supported bridges, an
    individual set of counters is provided.
*/

/** Hardware Programming Details
    Input parameter:
    - bridge_index:     Selects one of the bridges.
    Output parameter:
    - learning_discard: Number of learning events that were not
                        successful, either due to learning limitation
                        or because the MAC table was full.

    The number of learning discard events is counted per bridge port. To deliver
    the bridge-related number, the counters of all bridge ports that are
    connected to the bridge must be accumulated.

    The relationship between bridge and bridge ports is held in the
    ONU_GPE_BRIDGE_PORT_TABLE. Scan all valid entries and check the
    given bridge_index against the table entries.

    For faster handling, the software should hold a reference list for each of
    the bridges that holds the associated bridge_port_index values. This table
    must be maintained each time the ONU_GPE_BRIDGE_PORT_TABLE is modified.
    This should be part of the generic table access routine.

    The firmware counters are wrapping around when the maximum counter value is
    reached.
*/
enum onu_errorcode gpe_bridge_cnt_get(struct onu_control *ctrl,
				      const uint32_t bridge_index,
				      struct gpe_cnt_bridge_val *counter)
{
	enum onu_errorcode ret;
	struct gpe_table_entry entry;
	struct gpe_bridge_port_index bridgeportindex;
	struct gpe_bridge_port bridgeport;
	uint16_t portidx;

	counter->learning_discard = 0;

	/* search through all bridge ports since currently no
	   faster handling available yet */
	for (portidx = 0; portidx < ONU_GPE_BRIDGE_PORT_TABLE_SIZE; portidx++) {
		bridgeportindex.index = portidx;

		ret = gpe_bridge_port_config_get(ctrl, &bridgeportindex,
						 &bridgeport);
		if (ret)
			return ret;
		/* scan all valid entries and check the
		   given bridge_index against the table entries. */
		if (bridgeport.gpe_bridge_port_tbl.valid &&
		    bridgeport.gpe_bridge_port_tbl.bridge_index ==
								bridge_index) {

			ret = sce_cnt_get(ctrl, &entry,
					  COP_COUNT_BASE_LIM + portidx);
			if (ret)
				return ret;

			/* the counters of all bridge ports that are
			   connected to the bridge must be accumulated */
			counter->learning_discard +=
				entry.data.counter.counter_value;
		}
	}

	return ONU_STATUS_OK;
}

/** The gpe_bridge_port_cnt_get function is used to read the SCE-based counters
    within the GPE hardware module based on bridge port id.
*/

/** Hardware Programming Details
    These are the counters that are provided by the SCE firmware
    and bridge port dependent:

	cnt_ibp_good			Ingress Bridge port good count
	cnt_ibp_discard 		Ingress Bridge port discard count
	learning_discard		Bridge port learning entry discard count
	cnt_ebp_good			Egress Bridge port good count
	cnt_ebp_discard			Egress Bridge port discard count
*/
enum onu_errorcode
gpe_bridge_port_cnt_get(struct onu_control *ctrl,
			const uint32_t index,
			struct gpe_cnt_bridge_port_val *out)
{
	enum onu_errorcode ret;
	struct gpe_table_entry entry;
	uint32_t idxmax,i;
	uint64_t *dst_addr;

	static const int off[]={
		offsetof(struct gpe_cnt_bridge_port_val,ibp_good),
		offsetof(struct gpe_cnt_bridge_port_val,ibp_discard),
		offsetof(struct gpe_cnt_bridge_port_val,learning_discard),
		offsetof(struct gpe_cnt_bridge_port_val,ebp_good),
		offsetof(struct gpe_cnt_bridge_port_val,ebp_discard)
	};

	static const uint32_t src_addr[]={
		COP_COUNT_BASE_IBP_GOOD,
		COP_COUNT_BASE_IBP_DISCARD,
		COP_COUNT_BASE_LIM,
		COP_COUNT_BASE_EBP_GOOD,
		COP_COUNT_BASE_EBP_DISCARD
	};

	memset(out, 0, sizeof(*out));

	if(index >= ONU_GPE_BRIDGE_PORT_TABLE_SIZE)
		return GPE_STATUS_VALUE_RANGE_ERR;

	idxmax = sizeof(src_addr) / sizeof(uint32_t);

	if(gpe_bridge_port_valid(ctrl, index) == false)
		return -1;

	/* read cnt_ibp_good */
	for (i = 0; i < idxmax; i++) {
		ret = sce_cnt_get(ctrl, &entry, src_addr[i] + index);
		if (ret)
			return -(i+3);

		dst_addr = (uint64_t*)((uint8_t*)out + off[i]);
		*dst_addr = (uint64_t)entry.data.counter.counter_value;
	}

	return ONU_STATUS_OK;
}

enum onu_errorcode sce_lan_cnt_get(struct onu_control *ctrl,
				   const uint8_t uni_idx,
				   struct sce_lan_counter *cnt)
{
	enum onu_errorcode ret;
	struct gpe_table_entry entry;

	if (uni_idx >= ONU_GPE_MAX_ETH_UNI)
		return ONU_STATUS_ERR;

	/* read cnt_uc */
	ret = sce_cnt_get(ctrl, &entry, COP_COUNT_BASE_UC + uni_idx);
	if (ret)
		return ret;
	cnt->rx_uc_frames = entry.data.counter.counter_value;

	/* read cnt_mc */
	ret = sce_cnt_get(ctrl, &entry, COP_COUNT_BASE_MC + uni_idx);
	if (ret)
		return ret;
	cnt->rx_mc_frames = entry.data.counter.counter_value;

	/* read cnt_bc */
	ret = sce_cnt_get(ctrl, &entry, COP_COUNT_BASE_BC + uni_idx);
	if (ret)
		return ret;
	cnt->rx_bc_frames = entry.data.counter.counter_value;

	/* read cnt_pppoe */
	ret = sce_cnt_get(ctrl, &entry,
			  COP_COUNT_BASE_PPPOE + uni_idx);
	if (ret)
		return ret;
	cnt->rx_non_pppoe_frames = entry.data.counter.counter_value;

	return ONU_STATUS_OK;
}

/** The gpe_bridge_port_cfg_set function is used to configure the
 *  bridge port table and the learning limitation table
*/
/** Hardware Programming Details
*/
enum onu_errorcode gpe_bridge_port_cfg_set(struct onu_device *p_dev,
					   const struct gpe_bridge_port *param)
{
	struct gpe_table_entry entry;
	enum onu_errorcode ret;

	/* first write limitation limits */
	entry.id = ONU_GPE_LEARNING_LIMITATION_TABLE_ID;
	entry.index = param->index;

	memcpy(&entry.data.learning_limitation,
	       &param->gpe_learning_limitation_tbl,
	       sizeof(entry.data.learning_limitation));

	ret = gpe_table_entry_set(p_dev, &entry);
	if (ret)
		return ret;

	/* second write bridge port itself */
	entry.id = ONU_GPE_BRIDGE_PORT_TABLE_ID;
	entry.index = param->index;

	memcpy(&entry.data.bridge_port,
	       &param->gpe_bridge_port_tbl,
	       sizeof(entry.data.bridge_port));

	ret = gpe_table_entry_set(p_dev, &entry);
	if (ret)
		return ret;

	return ONU_STATUS_OK;
}

enum onu_errorcode
gpe_bridge_port_config_get(struct onu_control *ctrl,
			   const struct gpe_bridge_port_index *in,
			   struct gpe_bridge_port *out)
{
	struct gpe_table_entry entry;
	enum onu_errorcode ret;

	out->index = in->index;

	entry.id = ONU_GPE_BRIDGE_PORT_TABLE_ID;
	entry.index = in->index;
	entry.instance = 1;

	ret = TABLE_GET(ctrl, &entry);
	if (ret)
		return ret;

	memcpy(&out->gpe_bridge_port_tbl,
	       &entry.data.bridge_port,
	       sizeof(entry.data.bridge_port));

	entry.id = ONU_GPE_LEARNING_LIMITATION_TABLE_ID;
	entry.index = in->index;
	entry.instance = 1;

	ret = TABLE_GET(ctrl, &entry);
	if (ret)
		return ret;

	memcpy(&out->gpe_learning_limitation_tbl,
	       &entry.data.learning_limitation,
	       sizeof(entry.data.learning_limitation));

	return ONU_STATUS_OK;
}

bool
gpe_bridge_port_valid(struct onu_control *ctrl,
			   const uint32_t index)
{
	struct gpe_table_entry entry;
	enum onu_errorcode ret;

	entry.id = ONU_GPE_BRIDGE_PORT_TABLE_ID;
	entry.index = index;
	entry.instance = 1;

	ret = TABLE_GET(ctrl, &entry);
	if (ret)
		return ret;

	return entry.data.bridge_port.valid;
}

/** The gpe_bridge_port_cfg_get function is used to read the
 *  bridge port table and the learning limitation table
*/
enum onu_errorcode
gpe_bridge_port_cfg_get(struct onu_device *p_dev,
			const struct gpe_bridge_port_index *in,
			struct gpe_bridge_port *out)
{
	return gpe_bridge_port_config_get(p_dev->ctrl, in, out);
}

/** The gpe_fid_add function is used to add an entry to the FID table.
*/
/** Hardware Programming Details:
    The FID table is not microcode supported.
   	See hardware coprocessor microcode documentation.
*/
enum onu_errorcode gpe_fid_add(	struct onu_device *p_dev,
				const struct gpe_table_entry *in)
{
	struct gpe_table_entry entry;

	memcpy(&(entry.data.message.data[0]), &(in->data.message.data[0]),
	       sizeof(entry.data.message));

	return general_add(p_dev, &entry,
			   ONU_GPE_FID_HASH_TABLE_ID,
			   ONU_GPE_FID_ASSIGNMENT_TABLE_ID);
}

/** The gpe_fid_delete function is used to delete an entry of the FID table.
*/
/** Hardware Programming Details:
	The FID table is not microcode supported.
	See hardware coprocessor microcode documentation.
*/
enum onu_errorcode gpe_fid_delete(struct onu_device *p_dev,
				  const struct gpe_table_entry *in)
{
	struct gpe_table_entry entry;

	memcpy(&(entry.data.message.data[0]), &(in->data.message.data[0]),
	       sizeof(entry.data.message));

	return general_delete(p_dev, &entry,
			      ONU_GPE_FID_HASH_TABLE_ID,
			      ONU_GPE_FID_ASSIGNMENT_TABLE_ID);
}

/** The gpe_fid_get function is used to get an entry of the FID table.
*/
/** Hardware Programming Details:
	The FID table is not microcode supported.
	See hardware coprocessor microcode documentation.
*/
enum onu_errorcode gpe_fid_get(struct onu_device *p_dev,
			       const struct gpe_table_entry *in,
			       struct gpe_table_entry *out)
{
	struct gpe_table_entry entry;
	uint32_t tbl_index;
#ifdef ONU_COP_BUGFIX
	uint32_t instruction_id;
#endif
	enum onu_errorcode ret;

	/* search if HASH exists */
	entry.id = ONU_GPE_FID_HASH_TABLE_ID;
	entry.index = 0;
	memcpy(&(entry.data.message.data[0]),
	       &(in->data.message.data[0]),
	       sizeof(entry.data.message));

#ifdef ONU_COP_BUGFIX
	ONU_DEBUG_MSG("cop: using bugfix for GPONC-117 ");
	instruction_id = IF_FIDHASH_SEARCHR;
	ret = gpe_table_entry_do(p_dev, &entry, instruction_id);
#else
	ret = TABLE_GET(ctrl, &entry);
#endif
	if (ret)
		return ret;

	if (entry.result == COP_STATUS_SUCCESS) {
		/* if HASH is found, extract start index */
		tbl_index = (entry.data.message.data[0] >> ONU_GPE_COP_NEXT_POS)
							& ONU_GPE_COP_NEXT_MSK;
	} else {
		return ONU_STATUS_ERR;
	}

	/* search for table entry */
	entry.id = ONU_GPE_FID_ASSIGNMENT_TABLE_ID;
	entry.index = tbl_index;
	memcpy(&(entry.data.message.data[0]), &(in->data.message.data[0]),
	       sizeof(entry.data.message));

#ifdef ONU_COP_BUGFIX
	ONU_DEBUG_MSG("cop: using bugfix for errata no1");
	ret = gpe_table_entry_do(p_dev, &entry, IF_FID_LOOKUP);
#else
	ret = TABLE_GET(ctrl, &entry);
#endif
	if (ret)
		return ret;

	if (entry.result == COP_STATUS_SUCCESS) {
		/* table entry found, entry exists  */
		memcpy(&(out->data.message.data[0]),
		       &(entry.data.message.data[0]),
		       sizeof(entry.data.fwd_id));

		return ONU_STATUS_OK;
	} 

	return GPE_STATUS_NOT_AVAILABLE;
}


/** The gpe_ext_vlan_set function is used to set an entry to the tables:
 	extended_vlan_tbl
	vlan_rule_tbl
	vlan_treatment_tbl
*/
/** Hardware Programming Details
*/
enum onu_errorcode gpe_ext_vlan_set(struct onu_device *p_dev,
				    const struct gpe_ext_vlan *param)
{
	struct onu_control *ctrl = (struct onu_control *)p_dev->ctrl;
	struct gpe_table_entry entry;
	enum onu_errorcode ret;
	uint16_t vlan, vlan_idx;

	if (param->index >= ONU_GPE_EXTENDED_VLAN_TABLE_SIZE)
		return GPE_STATUS_VALUE_RANGE_ERR;

	if (param->max_vlans > ONU_GPE_MAX_VLANS)
		return GPE_STATUS_VALUE_RANGE_ERR;

	if (param->num_valid_rules > param->max_vlans)
		return GPE_STATUS_VALUE_RANGE_ERR;

	/* 1.) table entry set with idx on extended vlan table */
	entry.id = ONU_GPE_EXTENDED_VLAN_TABLE_ID;
	entry.index = param->index;
	memcpy(&entry.data.extended_vlan, &param->extended_vlan_tbl,
	       sizeof(entry.data.extended_vlan));

	ret = gpe_table_entry_set(p_dev, &entry);
	if (ret || entry.result != COP_STATUS_SUCCESS)
		return ret;

	/* 2.) perform multiple table entry set on VLAN rule and treatment
		table starting with index vlan_table_index and increment */
	entry.index = param->extended_vlan_tbl.vlan_rule_table_pointer;
	for (vlan = 0; vlan < param->max_vlans; vlan++) {
		/* write VLAN rule table */
		entry.id = ONU_GPE_VLAN_RULE_TABLE_ID;

		if (vlan < param->num_valid_rules) {
			memcpy(&entry.data.vlan_rule,
			       &(param->vlan_rule_tbl[vlan]),
			       sizeof(entry.data.vlan_rule));

			entry.data.vlan_rule.valid = 1; /* always valid */
			entry.data.vlan_rule.end = 0;
		} else {
			memset(&entry.data.vlan_rule, 0,
			       sizeof(entry.data.vlan_rule));
		}

		if (vlan >= param->num_valid_rules - 1)
			entry.data.vlan_rule.end = 1;

#ifdef ONU_COP_BUGFIX
		ONU_DEBUG_MSG("cop: using workaround for custom match");
		entry.index = param->extended_vlan_tbl.vlan_rule_table_pointer +
			      vlan;
		ret = gpe_table_entry_write(p_dev, &entry);
#else
		ret = gpe_table_entry_add(p_dev, &entry);
#endif

		if (ret || entry.result != COP_STATUS_SUCCESS)
			return ret;

		/* write VLAN treatment table */
		entry.id = ONU_GPE_VLAN_TREATMENT_TABLE_ID;
		entry.index = param->extended_vlan_tbl.vlan_rule_table_pointer;

		if (vlan < param->num_valid_rules) {
			memcpy(&entry.data.vlan_treatment,
			       &(param->vlan_treatment_tbl[vlan]),
			       sizeof(entry.data.vlan_treatment));

			entry.data.vlan_treatment.valid = 1; /* always valid */
		} else {
			memset(&entry.data.vlan_treatment, 0,
			       sizeof(entry.data.vlan_treatment));
		}

#ifdef ONU_COP_BUGFIX
		ONU_DEBUG_MSG("cop: using workaround for custom match");
		entry.index = param->extended_vlan_tbl.vlan_rule_table_pointer +
			      vlan;
		ret = gpe_table_entry_write(p_dev, &entry);
#else
		ret = gpe_table_entry_add(p_dev, &entry);
#endif

		if (ret || entry.result != COP_STATUS_SUCCESS)
			return ret;
	}

	entry.id = ONU_GPE_VLAN_RULE_TABLE_ID;
	entry.index ++;
	vlan_idx = 2 - (entry.index & 0x1);
	if (vlan_idx < 2) {
		for (vlan = 0; vlan < vlan_idx; vlan++) {
			entry.data.vlan_rule.valid = 0; /* not valid */
			entry.data.vlan_rule.end = 0;
			ret = gpe_table_entry_intcmd(ctrl, &entry, ONU_GPE_COP_WRITE);
			entry.index++;

			if (ret || entry.result != COP_STATUS_SUCCESS)
				return ret;
		}
	}

	/* Store max VLANs track for the specified entry. */
	ctrl->vlan_max_track[param->index] = param->max_vlans;

	return ONU_STATUS_OK;
}

/** The gpe_ext_vlan_get function is used to get an entry from the tables:
 	extended_vlan_tbl
	vlan_rule_tbl
	vlan_treatment_tbl
*/
/** Hardware Programming Details
*/
enum onu_errorcode gpe_ext_vlan_get(struct onu_device *p_dev,
				    const struct gpe_ext_vlan_index *in,
				    struct gpe_ext_vlan *out)
{
	struct onu_control *ctrl = p_dev->ctrl;
	struct gpe_table_entry entry;
	enum onu_errorcode ret;
	uint16_t vlan;
	uint16_t valid_vlan;
	uint32_t end, valid, max_vlans;
	uint16_t vlan_rule_table_pointer;

	if (in->index >= ONU_GPE_EXTENDED_VLAN_TABLE_SIZE)
		return GPE_STATUS_VALUE_RANGE_ERR;

	max_vlans = ctrl->vlan_max_track[in->index];

	/* 1.) table entry get with idx on extended VLAN table */
	entry.id = ONU_GPE_EXTENDED_VLAN_TABLE_ID;
	entry.index = in->index;
	ret = TABLE_GET(ctrl, &entry);


	if (ret || entry.result != COP_STATUS_SUCCESS)
		return ret;

	memcpy( &out->extended_vlan_tbl, &entry.data.extended_vlan,
		sizeof(entry.data.extended_vlan));

	memset(out->vlan_rule_tbl, 0, sizeof(out->vlan_rule_tbl));
	memset(out->vlan_treatment_tbl, 0, sizeof(out->vlan_treatment_tbl));

	out->num_valid_rules = 0;

	if (entry.data.extended_vlan.valid == 0)
		return ONU_STATUS_OK;

	vlan_rule_table_pointer =
		entry.data.extended_vlan.vlan_rule_table_pointer;

	/* 2.) perform multiple table entry get on VLAN rule and treatment table
	       and check for valid bits, stop at end bit */
	valid_vlan = 0;
	for (vlan = 0; vlan < max_vlans; vlan++) {

		entry.id = ONU_GPE_VLAN_RULE_TABLE_ID;
		entry.index = vlan_rule_table_pointer + vlan;

#ifdef ONU_COP_BUGFIX
		ONU_DEBUG_MSG("cop: using workaround for custom match");
		ret = TABLE_READ(ctrl, &entry);
#else
		ret = TABLE_GET(ctrl, &entry);
#endif

		if (ret || entry.result != COP_STATUS_SUCCESS)
			return ret;

		end = entry.data.vlan_rule.end;
		valid = entry.data.vlan_rule.valid;

		/* vlan_rule and vlan_treatment is always in sync */
		if (valid) {

			valid_vlan++;

			memcpy(	&(out->vlan_rule_tbl[vlan]),
				&entry.data.vlan_rule,
				sizeof(entry.data.vlan_rule));

			entry.id = ONU_GPE_VLAN_TREATMENT_TABLE_ID;
			entry.index = vlan_rule_table_pointer + vlan;

#ifdef ONU_COP_BUGFIX
			ONU_DEBUG_MSG("cop: using workaround for custom match");
			ret = TABLE_READ(ctrl, &entry);
#else
			ret = TABLE_GET(ctrl, &entry);
#endif

			if (ret || entry.result != COP_STATUS_SUCCESS)
				return ret;

			memcpy(	&(out->vlan_treatment_tbl[vlan]),
				&entry.data.vlan_treatment,
				sizeof(entry.data.vlan_treatment));

			if (end)
				break;
		}
	}

	out->num_valid_rules = valid_vlan;
	out->max_vlans = max_vlans;

	return ONU_STATUS_OK;
}

/** The gpe_ext_vlan_do function is used to perform a microcode sequence
	on the table:
 	extended_vlan_tbl
	vlan_rule_tbl
	vlan_treatment_tbl
*/
/** Hardware Programming Details
*/
enum onu_errorcode gpe_ext_vlan_do(struct onu_device *p_dev,
				   const struct gpe_table_entry *in,
				   struct gpe_table_entry *out)
{
	struct gpe_table_entry entry;
	enum cop_errorcode cop_ret;
	uint32_t cop_id;

	cop_id = GPE_TABLE_COP(ONU_GPE_EXTENDED_VLAN_TABLE_ID),

	entry.id = GPE_TABLE_ID(ONU_GPE_EXTENDED_VLAN_TABLE_ID);
	entry.instance = cop_id;
	entry.index = in->index;
	memcpy(&(entry.data.message.data[0]),
	       &(in->data.message.data[0]),
	       sizeof(entry.data.extended_vlan_in));

	ONU_DEBUG_MSG("[TSE5] SingleTagged:   0x%1x",
			entry.data.extended_vlan_in.SingleTagged);
	ONU_DEBUG_MSG("[TSE5] MultipleTagged: 0x%1x",
			entry.data.extended_vlan_in.MultipleTagged);

	ONU_DEBUG_MSG("[TSE5] rETY:           0x%04x",
			entry.data.extended_vlan_in.rETY);
	ONU_DEBUG_MSG("[TSE5] riPCP:          0x%1x,    riDEI: 0x%1x, "
		      "riVID: 0x%03x, riTPID: 0x%04x",
			entry.data.extended_vlan_in.riPCP,
			entry.data.extended_vlan_in.riDEI,
			entry.data.extended_vlan_in.riVID,
			entry.data.extended_vlan_in.riTPID);
	ONU_DEBUG_MSG("[TSE5] roPCP:          0x%1x,    roDEI: 0x%1x, "
		      "roVID: 0x%03x, roTPID: 0x%04x",
			entry.data.extended_vlan_in.roPCP,
			entry.data.extended_vlan_in.roDEI,
			entry.data.extended_vlan_in.roVID,
			entry.data.extended_vlan_in.roTPID);

	cop_ret = cop_table_entry_exec(&entry, 96, IF_VLAN_TRANSLATE);

	memcpy(	&(out->data.message.data[0]),
			&(entry.data.message.data[0]),
			sizeof(entry.data.extended_vlan_out));

	out->index = entry.index;

	if (cop_ret != COP_STATUS_SUCCESS)
		return cop_to_onu_errorcode(cop_ret, &entry);

	ONU_DEBUG_MSG("[TSE5] DSCP_TablePtr:   0x%1x",
			entry.data.extended_vlan_out.DSCP_TablePointer);
	ONU_DEBUG_MSG("[TSE5] discard:         0x%1x",
			entry.data.extended_vlan_out.discard);

	ONU_DEBUG_MSG("[TSE5] tatag:           0x%1x,       tbtag: 0x%1x,    "
		      "totag: 0x%1x,     titag: 0x%1x",
			entry.data.extended_vlan_out.tatag,
			entry.data.extended_vlan_out.tbtag,
			entry.data.extended_vlan_out.totag,
			entry.data.extended_vlan_out.titag);

	ONU_DEBUG_MSG("[TSE5] tbdscptopcp:  0x%1x",
			entry.data.extended_vlan_out.tbdscptopcp);
	ONU_DEBUG_MSG("[TSE5] tadscptopcp:  0x%1x",
			entry.data.extended_vlan_out.tadscptopcp);

	ONU_DEBUG_MSG("[TSE5] taVID:        0x%03x, taDEI:  0x%1x, "
		      "taPCP: 0x%1x, taTPID: 0x%04x",
			entry.data.extended_vlan_out.taVID,
			entry.data.extended_vlan_out.taDEI,
			entry.data.extended_vlan_out.taPCP,
			entry.data.extended_vlan_out.taTPID);

	ONU_DEBUG_MSG("[TSE5] tbVID:        0x%03x, tbDEI:  0x%1x, "
		      "tbPCP: 0x%1x, tbTPID: 0x%04x",
			entry.data.extended_vlan_out.tbVID,
			entry.data.extended_vlan_out.tbDEI,
			entry.data.extended_vlan_out.tbPCP,
			entry.data.extended_vlan_out.tbTPID);

	return ONU_STATUS_OK;
}

/** The gpe_ext_vlan_cfg_set function is used to configure the custom match.
*/
/** Hardware Programming Details
*/
enum onu_errorcode gpe_ext_vlan_custom_set(struct onu_device *p_dev,
					   const struct gpe_ext_vlan_custom *in)
{
	struct gpe_table_entry entry;
	enum cop_errorcode ret;
	uint32_t reg_cnt, cop_id;
	uint32_t *temp;

	entry.id = 0;

	cop_id = GPE_TABLE_COP(ONU_GPE_EXTENDED_VLAN_TABLE_ID);
	temp = (uint32_t *)in;

	for (reg_cnt = 0; reg_cnt < 8; reg_cnt++) {

		entry.index = (uintptr_t)COPLINK_COP_CUSTOM0 + reg_cnt;
		entry.instance = cop_id;

		memcpy(	&(entry.data.message.data[0]), temp, 4);
		temp++;

		ret = cop_table_entry_write(&entry, ONU_GPE_COP_TABLE0W);

		if (ret != COP_STATUS_SUCCESS)
			return ONU_STATUS_ERR;
	}

	return ONU_STATUS_OK;
}


/** The gpe_ext_vlan_cfg_get function is used to get the
    configuration for the custom match.
*/
/** Hardware Programming Details
*/
enum onu_errorcode gpe_ext_vlan_custom_get(struct onu_device *p_dev,
					   struct gpe_ext_vlan_custom *out)
{
	struct gpe_table_entry entry;
	enum cop_errorcode ret;
	uint32_t reg_cnt, cop_id;
	uint32_t *temp;

	entry.id = 0;

	cop_id = GPE_TABLE_COP(ONU_GPE_EXTENDED_VLAN_TABLE_ID);
	temp = (uint32_t *)out;

	for (reg_cnt = 0; reg_cnt < 8; reg_cnt++) {

		entry.index = (uintptr_t)COPLINK_COP_CUSTOM0 + reg_cnt;
		entry.instance = cop_id;

		ret = cop_table_entry_read(&entry, ONU_GPE_COP_TABLE0R);

		if (ret != COP_STATUS_SUCCESS)
			return ONU_STATUS_ERR;

		memcpy(	temp, &(entry.data.message.data[0]), 4);
		temp++;
	}

	return ONU_STATUS_OK;
}

/** The gpe_short_fwd_add function is used to add
	an entry to the short forwarding table.

	Use this function to add an entry to any of these tables:
	ONU_GPE_SHORT_FWD_TABLE_MAC_ID
	ONU_GPE_SHORT_FWD_TABLE_MAC_MC_ID
	ONU_GPE_SHORT_FWD_TABLE_IPV4_ID
	ONU_GPE_SHORT_FWD_TABLE_IPV4_MC_ID
*/
/** Hardware Programming Details:
	The short forwarding tables are microcode supported.
*/
enum onu_errorcode gpe_short_fwd_add(struct onu_device *p_dev,
				     struct gpe_table_entry *in)
{
	struct gpe_table_entry entry;

	entry.id = ONU_GPE_SHORT_FWD_TABLE_MAC_ID;
	entry.index = 0;
	memcpy( &(entry.data.message.data[0]), &(in->data.message.data[0]),
		sizeof(entry.data.message));

	return gpe_table_entry_do(p_dev, &entry, IF_FWD_ADD);
}

/** The gpe_short_fwd_delete function is used to delete
	an entry from the short forwarding table.

	Use this function to delete an entry from any of these tables:
	ONU_GPE_SHORT_FWD_TABLE_MAC_ID
	ONU_GPE_SHORT_FWD_TABLE_MAC_MC_ID
	ONU_GPE_SHORT_FWD_TABLE_IPV4_ID
	ONU_GPE_SHORT_FWD_TABLE_IPV4_MC_ID
*/
/** Hardware Programming Details:
	The short forwarding tables are microcode supported.
*/
enum onu_errorcode gpe_short_fwd_delete(struct onu_device *p_dev,
					struct gpe_table_entry *in)
{
	struct gpe_table_entry entry;

	entry.id = ONU_GPE_SHORT_FWD_TABLE_MAC_ID;
	entry.index = 0;
	memcpy( &(entry.data.message.data[0]), &(in->data.message.data[0]),
		sizeof(entry.data.message));

	return gpe_table_entry_do(p_dev, &entry, IF_FWD_REMOVE);
}

/** The gpe_short_fwd_relearn function is used to relearn
	an entry to the short forwarding table.

	Use this function to relearn an entry to any of these tables:
	ONU_GPE_SHORT_FWD_TABLE_MAC_ID
	ONU_GPE_SHORT_FWD_TABLE_MAC_MC_ID
	ONU_GPE_SHORT_FWD_TABLE_IPV4_ID
	ONU_GPE_SHORT_FWD_TABLE_IPV4_MC_ID
*/
/** Hardware Programming Details:
	The short forwarding tables are microcode supported.
*/
enum onu_errorcode gpe_short_fwd_relearn(struct onu_device *p_dev,
					 struct gpe_table_entry *in)
{
	struct gpe_table_entry entry;

	entry.id = ONU_GPE_SHORT_FWD_TABLE_MAC_ID;
	entry.index = 0;
	memcpy( &(entry.data.message.data[0]), &(in->data.message.data[0]),
		sizeof(entry.data.message));

	return gpe_table_entry_do(p_dev, &entry, IF_FWD_RELEARN);
}


/** The gpe_short_fwd_forward function is used to forward
	an entry to the short forwarding table.

	Use this function to relearn an entry to any of these tables:
	ONU_GPE_SHORT_FWD_TABLE_MAC_ID
	ONU_GPE_SHORT_FWD_TABLE_MAC_MC_ID
	ONU_GPE_SHORT_FWD_TABLE_IPV4_ID
	ONU_GPE_SHORT_FWD_TABLE_IPV4_MC_ID
*/
/** Hardware Programming Details:
	The short forwarding tables are microcode supported.
*/
enum onu_errorcode gpe_short_fwd_forward(struct onu_device *p_dev,
					 struct gpe_table_entry *in)
{
	struct gpe_table_entry entry;

	entry.id = ONU_GPE_SHORT_FWD_TABLE_MAC_ID;
	entry.index = 0;
	memcpy( &(entry.data.message.data[0]), &(in->data.message.data[0]),
		sizeof(entry.data.message));

	return gpe_table_entry_do(p_dev, &entry, IF_FWD_FORWARD);
}

static bool is_mac_mc(const uint8_t mc_mac[6])
{
	if ((mc_mac[0] != 0x01 || mc_mac[1] != 0x00 ||
	     mc_mac[2] != 0x5E) ||
	    (mc_mac[0] == 0x01 && mc_mac[1] == 0x00 &&
	     mc_mac[2] == 0x5E && (mc_mac[3] & 0x80))) {
		ONU_DEBUG_ERR("%02X:%02X:%02X:%02X:%02X:%02X "
			      "is not a MC MAC address",
				  mc_mac[0], mc_mac[1], mc_mac[2],
				  mc_mac[3], mc_mac[4], mc_mac[5]);
		return false;
	} else {
		return true;
	}
}

static enum onu_errorcode gpe_short_fwd_mc_match(struct onu_device *p_dev,
						 const uint8_t lan_port_index,
						 struct gpe_mc_match *out)
{
	struct gpe_table table;
	struct gpe_table_entry entry;
	enum onu_errorcode ret;
	uint8_t pattern_match;

	/* Return an error, if the given lan_port_index is >3. */
	if (lan_port_index >= ONU_GPE_MAX_ETH_UNI) {
		ONU_DEBUG_ERR("LAN port index error, %u vs %u",
					lan_port_index, ONU_GPE_MAX_UNI);
		return GPE_STATUS_VALUE_RANGE_ERR;
	}

	table.id = ONU_GPE_LAN_PORT_TABLE_ID;
	table.instance = 1;
	table.index = lan_port_index;
	ret = gpe_table_entry_get(p_dev, &table, &entry);
	if (ret != ONU_STATUS_OK)
		return ret;

	/* With lan_port_index look up the interworking_index in the
	ONU_GPE_LAN_PORT_TABLE. This is the bridge_port_index to be used.
	Return an error if interworking_option != 0 in
	the ONU_GPE_LAN_PORT_TABLE for the selected lan_port_index. */
	if (entry.data.lan_port.interworking_option != 0) {
		ONU_DEBUG_ERR("bridging interworking option expected for "
			      "MC MAC forwarding");
		return GPE_STATUS_CONFIG_MISMATCH;
	}

	/* Return an error, if the LAN port is not defined (invalid entry). */
	if (entry.data.lan_port.valid == 0)
		return GPE_STATUS_NOT_AVAILABLE;

	/* With the bridge_port_index look up the bridge_index
	in the ONU_GPE_BRIDGE_PORT_TABLE. */
	table.id = ONU_GPE_BRIDGE_PORT_TABLE_ID;
	table.instance = 1;
	table.index = entry.data.lan_port.interworking_index;
	pattern_match = entry.data.lan_port.interworking_index;
	ret = gpe_table_entry_get(p_dev, &table, &entry);
	if (ret != ONU_STATUS_OK)
		return ret;

	/* Return an error, if the bridge port is not defined (invalid entry).*/
	if (entry.data.bridge_port.valid == 0)
		return GPE_STATUS_NOT_AVAILABLE;

	/* With the bridge_index look up the ONU_GPE_BRIDGE_TABLE to find
	   the port_map_index related to the bridge_port_index.
	   Return an error, if not found. */
	table.id = ONU_GPE_BRIDGE_TABLE_ID;
	table.instance = 1;
	table.index = entry.data.bridge_port.bridge_index;
	out->bridge_index = entry.data.bridge_port.bridge_index;
	ret = gpe_table_entry_get(p_dev, &table, &entry);
	if (ret != ONU_STATUS_OK)
		return ret;

	ret = GPE_STATUS_NOT_AVAILABLE;
	/* egress_bridge_port_index0..3 are fixed to UNI0..3*/
	switch (lan_port_index) {
	case 0:
		if (entry.data.bridge.egress_bridge_port_index0 ==
								pattern_match &&
		    entry.data.bridge.flooding_bridge_port_enable & 0x1)
			ret = ONU_STATUS_OK;
		break;
	case 1:
		if (entry.data.bridge.egress_bridge_port_index1 ==
								pattern_match &&
		    entry.data.bridge.flooding_bridge_port_enable & 0x2)
			ret = ONU_STATUS_OK;
		break;
	case  2:
		if (entry.data.bridge.egress_bridge_port_index2 ==
								pattern_match &&
		    entry.data.bridge.flooding_bridge_port_enable & 0x4)
			ret = ONU_STATUS_OK;
		break;
	case 3:
		if (entry.data.bridge.egress_bridge_port_index3 ==
								pattern_match &&
		    entry.data.bridge.flooding_bridge_port_enable & 0x8)
			ret = ONU_STATUS_OK;
		break;
	}

	if (ret == ONU_STATUS_OK)
		out->port_map_index = lan_port_index;

	return ret;
}

static enum onu_errorcode
gpe_short_fwd_mc_port_add_modify(struct onu_device *p_dev,
				 const uint32_t key_code,
				 const uint32_t bridge_index,
				 const uint32_t port_map_index,
				 const uint32_t fid,
				 const uint32_t igmp,
				 const bool is_mac,
				 const union gpe_mc_addr *mc_addr)
{
	enum onu_errorcode ret;
	uint32_t table_id;
	struct gpe_table table;
	struct gpe_table_entry entry, entry_search;

	memset(&entry, 0, sizeof(entry));
	memset(&entry_search, 0, sizeof(entry_search));

	if (is_mac) {
		table_id = ONU_GPE_SHORT_FWD_TABLE_MAC_ID;
		/** MAC multicast address of multicast group to be joined.
		    MAC=aa:bb:cc:dd:ee:ff corresponds to
		    mac[0]=aa,mac[1]=bb,mac[2]=cc,
		    mac[3]=dd,mac[4]=ee,mac[5]=ff */
		entry_search.data.short_fwd_table_mac_mc.mac_address_high =
			mc_addr->mc_mac[0] << 8 | mc_addr->mc_mac[1];
		entry_search.data.short_fwd_table_mac_mc.mac_address_low =
			mc_addr->mc_mac[2] << 24 | mc_addr->mc_mac[3] << 16 |
			mc_addr->mc_mac[4] << 8  | mc_addr->mc_mac[5];
	} else {
		table_id = ONU_GPE_SHORT_FWD_TABLE_IPV4_MC_ID;
		/** IPv4 multicast address of multicast group to be joined.
		    IP=aaa.bbb.ccc.ddd corresponds to
		    ip[0]=aaa,ip[1]=bbb,ip[2]=ccc,ip[3]=ddd*/
		entry_search.data.short_fwd_table_ipv4_mc.ip_address = 
			mc_addr->mc_ip[0] << 24 | mc_addr->mc_ip[1] << 16 |
			mc_addr->mc_ip[2] << 8  | mc_addr->mc_ip[3];
	}

	/* Read the ONU_GPE_SHORT_FWD_TABLE_MAC_MC for the given MAC address. */
	entry_search.id = table_id;
	entry_search.index = 0;
	/* prepare the key only, these fields are common for MAC and IP tables*/
	entry_search.data.short_fwd_table_mac_mc.key_code = key_code;
	entry_search.data.short_fwd_table_mac_mc.bridge_index = bridge_index;
	entry_search.data.short_fwd_table_mac_mc.fid = fid;

	memcpy(&entry, &entry_search, sizeof(entry));

	ret = gpe_table_entry_do(p_dev, &entry, IF_FWD_FORWARD);
	if (ret != ONU_STATUS_OK || entry.result == 0) {
		/* If the entry does not yet exist, create a new one for the
		   multicast address, set the port_map_index and
		   the igmp flag. */
		entry_search.data.short_fwd_table_mac_mc.port_map =
							  (1 << port_map_index);
		entry_search.data.short_fwd_table_mac_mc.igmp = igmp ? 1 : 0;
		entry_search.data.short_fwd_table_mac_mc.
						 one_port_map_indicator = 1;
		entry_search.data.short_fwd_table_mac_mc.include_enable = 1;

		gpe_short_fwd_add(p_dev, &entry_search);
	} else {
		table.id = table_id;
		table.index = entry.index;
		gpe_table_entry_read(p_dev, &table, &entry);
		/* If the entry exists, return an error if the igmp flag does
		   not match. Else add the port_map_index to the entry. */
		if (entry.data.short_fwd_table_mac_mc.igmp == 0) {
			if (is_mac) {
				ONU_DEBUG_ERR(
					"%02X:%02X:%02X:%02X:%02X:%02X "
					"MC MAC entry IGMP flag mismatch",
					   (entry.data.short_fwd_table_mac_mc.
						mac_address_high >> 8) & 0xFF,
					    entry.data.short_fwd_table_mac_mc.
						mac_address_high       & 0xFF,
					   (entry.data.short_fwd_table_mac_mc.
						mac_address_low >> 24) & 0xFF,
					   (entry.data.short_fwd_table_mac_mc.
						mac_address_low >> 16) & 0xFF,
					   (entry.data.short_fwd_table_mac_mc.
						mac_address_low >>  8) & 0xFF,
					    entry.data.short_fwd_table_mac_mc.
						mac_address_low        & 0xFF);
			} else {
				ONU_DEBUG_ERR(
					"%d.%d.%d.%d "
					"MC IPv4 entry IGMP flag mismatch",
					   (entry.data.short_fwd_table_ipv4_mc.
						ip_address >> 24) & 0xFF,
					   (entry.data.short_fwd_table_ipv4_mc.
						ip_address >> 16) & 0xFF,
					   (entry.data.short_fwd_table_ipv4_mc.
						ip_address >>  8) & 0xFF,
					    entry.data.short_fwd_table_ipv4_mc.
						ip_address        & 0xFF);
			}

			return GPE_STATUS_CONFIG_MISMATCH;
		} else {
			/*  read modify write */;
			entry.data.short_fwd_table_mac_mc.port_map |=
							  (1 << port_map_index);
			gpe_table_entry_write(p_dev, &entry);
		}
	}

	return ONU_STATUS_OK;
}

static enum onu_errorcode
gpe_short_fwd_mc_port_delete(struct onu_device *p_dev,
			     const uint8_t fid,
			     const uint8_t lan_port_index,
			     const uint8_t igmp,
			     const bool is_mac,
			     const union gpe_mc_addr *mc_addr)
{
	enum onu_errorcode ret;
	uint32_t table_id;
	struct gpe_table table;
	struct gpe_table_entry entry;
	struct gpe_mc_match mc_match;

	if (is_mac)
		if (!is_mac_mc(mc_addr->mc_mac))
			return GPE_STATUS_VALUE_RANGE_ERR;;

	ret = gpe_short_fwd_mc_match(p_dev, lan_port_index, &mc_match);
	if (ret)
		return ret;

	memset(&entry, 0, sizeof(entry));

	if (is_mac) {
		table_id = ONU_GPE_SHORT_FWD_TABLE_MAC_ID;
		/** MAC multicast address of multicast group to be joined.
		    MAC=aa:bb:cc:dd:ee:ff corresponds to
		    mac[0]=aa,mac[1]=bb,mac[2]=cc,
		    mac[3]=dd,mac[4]=ee,mac[5]=ff */
		entry.data.short_fwd_table_mac_mc.mac_address_high =
			mc_addr->mc_mac[0] << 8 | mc_addr->mc_mac[1];
		entry.data.short_fwd_table_mac_mc.mac_address_low =
			mc_addr->mc_mac[2] << 24 | mc_addr->mc_mac[3] << 16 |
			mc_addr->mc_mac[4] << 8  | mc_addr->mc_mac[5];
	} else {
		table_id = ONU_GPE_SHORT_FWD_TABLE_IPV4_MC_ID;
		/** IPv4 multicast address of multicast group to be joined.
		    IP=aaa.bbb.ccc.ddd corresponds to
		    ip[0]=aaa,ip[1]=bbb,ip[2]=ccc,ip[3]=ddd*/
		entry.data.short_fwd_table_ipv4_mc.ip_address = 
			mc_addr->mc_ip[0] << 24 | mc_addr->mc_ip[1] << 16 |
			mc_addr->mc_ip[2] << 8  | mc_addr->mc_ip[3];
	}

	/* Read the ONU_GPE_SHORT_FWD_TABLE_MAC_MC for the given MAC address. */
	entry.id = table_id;
	entry.index = 0;
	/* prepare the key only */
	/** \todo it will be better to have gpe tables related definitions
		  (gnerated automatically) for the key_code possible values */
	entry.data.short_fwd_table_mac_mc.key_code = is_mac ? 0 : 4;
	entry.data.short_fwd_table_mac_mc.bridge_index = mc_match.bridge_index;
	entry.data.short_fwd_table_mac_mc.fid = fid;

	ret = gpe_table_entry_do(p_dev, &entry, IF_FWD_FORWARD);
	if (ret != ONU_STATUS_OK || entry.result == 0) {
		/* Return an error, if the entry does not exist. */
		return GPE_STATUS_NOT_AVAILABLE;
	} else {
		table.id = table_id;
		table.index = entry.index;
		gpe_table_entry_read(p_dev, &table, &entry);
		/* Else remove the port_map_index from the entry */
		entry.data.short_fwd_table_mac_mc.port_map &=
						~(1 << mc_match.port_map_index);

		/* If the remaining port map would be empty, remove the complete
		   multicast entry.*/
		if (entry.data.short_fwd_table_mac_mc.port_map == 0)
			gpe_short_fwd_delete(p_dev, &entry);
		else
			gpe_table_entry_write(p_dev, &entry);
	}

	return ONU_STATUS_OK;
}

/** The gpe_short_fwd_mac_mc_port_add function is used to add
	an port map to an MC entry.
*/
/** Hardware Programming Details:
	The short forwarding tables are microcode supported.
*/
enum onu_errorcode
gpe_short_fwd_mac_mc_port_add(struct onu_device *p_dev,
			      const struct gpe_mac_mc_port *in)
{
	enum onu_errorcode ret;
	struct gpe_mc_match mc_match;
	union gpe_mc_addr mc_addr;

	if (!is_mac_mc(in->mc_mac))
		return GPE_STATUS_VALUE_RANGE_ERR;;

	ret = gpe_short_fwd_mc_match(p_dev, in->lan_port_index, &mc_match);
	if (ret)
		return ret;

	memcpy(mc_addr.mc_mac, in->mc_mac, sizeof(in->mc_mac));
	/** \todo it will be better to have gpe tables related definitions
		  (gnerated automatically) for the key_code possible values.
		  Here we use:
		  0: Layer 2 Ethernet & VLAN (unicast MAC DA & FID). Uses the
		     default FID for untagged packet forwarding*/
	ret = gpe_short_fwd_mc_port_add_modify(p_dev, 0,
					       mc_match.bridge_index,
					       mc_match.port_map_index,
					       in->fid,
					       in->igmp,
					       true,
					       &mc_addr);

	return ret;
}

/** The gpe_short_fwd_mac_mc_port_delete function is used to delete
	an port map from an existing MC entry.
*/
/** Hardware Programming Details:
	The short forwarding tables are microcode supported.
*/
enum onu_errorcode
gpe_short_fwd_mac_mc_port_delete(struct onu_device *p_dev,
				 const struct gpe_mac_mc_port *in)
{
	union gpe_mc_addr mc_addr;

	memcpy(mc_addr.mc_mac, in->mc_mac, sizeof(in->mc_mac));
	return gpe_short_fwd_mc_port_delete(p_dev,
					    in->fid,
					    in->lan_port_index,
					    in->igmp,
					    true,
					    &mc_addr);
}

enum onu_errorcode
gpe_short_fwd_mac_mc_port_modify(struct onu_device *p_dev,
				 const struct gpe_mac_mc_port_modify *in)
{
	enum onu_errorcode ret;
	union gpe_mc_addr mc_addr;

	memcpy(mc_addr.mc_mac, in->mc_mac, sizeof(in->mc_mac));
	/** \todo it will be better to have gpe tables related definitions
		  (gnerated automatically) for the key_code possible values.
		  Here we use:
		  0: Layer 2 Ethernet & VLAN (unicast MAC DA & FID). Uses the
		     default FID for untagged packet forwarding*/
	ret = gpe_short_fwd_mc_port_add_modify(p_dev, 0,
					       in->bridge_index,
					       in->port_map_index,
					       in->fid,
					       in->igmp,
					       true,
					       &mc_addr);

	return ONU_STATUS_OK;
}

/** The gpe_short_fwd_ipv4_mc_port_add function is used to add
	an port map to an MC entry.
*/
/** Hardware Programming Details:
	The short forwarding tables are microcode supported.
*/
enum onu_errorcode
gpe_short_fwd_ipv4_mc_port_add(struct onu_device *p_dev,
			       const struct gpe_ipv4_mc_port *in)
{
	enum onu_errorcode ret;
	struct gpe_mc_match mc_match;
	union gpe_mc_addr mc_addr;

	ret = gpe_short_fwd_mc_match(p_dev, in->lan_port_index, &mc_match);
	if (ret)
		return ret;

	memcpy(mc_addr.mc_ip, in->ip, sizeof(in->ip));
	/** \todo it will be better to have gpe tables related definitions
	  (gnerated automatically) for the key_code possible values.
	  Here we use:
	  4: IPv4 (only used for ONU_GPE_SHORT_FWD_TABLE_IPV4) */
	ret = gpe_short_fwd_mc_port_add_modify(p_dev, 4,
						mc_match.bridge_index,
						mc_match.port_map_index,
						in->fid,
						in->igmp,
						false,
						&mc_addr);

	return ret;
}

enum onu_errorcode
gpe_short_fwd_ipv4_mc_port_delete(struct onu_device *p_dev,
				  const struct gpe_ipv4_mc_port *in)
{
	union gpe_mc_addr mc_addr;

	memcpy(mc_addr.mc_ip, in->ip, sizeof(in->ip));
	return gpe_short_fwd_mc_port_delete(p_dev,
					    in->fid,
					    in->lan_port_index,
					    in->igmp,
					    false,
					    &mc_addr);
}

enum onu_errorcode
gpe_short_fwd_ipv4_mc_port_modify(struct onu_device *p_dev,
				  const struct gpe_ipv4_mc_port_modify *in)
{
	enum onu_errorcode ret;
	union gpe_mc_addr mc_addr;

	memcpy(mc_addr.mc_ip, in->ip, sizeof(in->ip));
	/** \todo it will be better to have gpe tables related definitions
	  (gnerated automatically) for the key_code possible values.
	  Here we use:
	  4: IPv4 (only used for ONU_GPE_SHORT_FWD_TABLE_IPV4) */
	ret = gpe_short_fwd_mc_port_add_modify(p_dev, 4,
						in->bridge_index,
						in->port_map_index,
						in->fid,
						in->igmp,
						false,
						&mc_addr);

	return ONU_STATUS_OK;
}

enum onu_errorcode gpe_aging_trigger_set(struct onu_control *ctrl)
{
	uint8_t cmd[SSB_CMD_AGING_SIZE] = {0};

	cmd[0] = (uint8_t)GPE_SCE_CMD_AGING;

	if (ssb_cmd_write(ctrl->gpe_aging_trigger.lsa, sizeof(cmd), cmd) != 0)
		return GPE_STATUS_ERR;

	return ONU_STATUS_OK;
}

enum onu_errorcode gpe_aging_time_set_debug(struct onu_device *p_dev,
					    const struct sce_aging_time *in)
{
	enum onu_errorcode ret = ONU_STATUS_OK;
	enum cop_errorcode cop_ret;
	struct gpe_table_entry entry;
	struct onu_control *ctrl = (struct onu_control *)p_dev->ctrl;

	entry.id = 0;
	entry.instance = ONU_GPE_COP_FWD;
	entry.index = (uintptr_t)COPLINK_COP_GLOBAL3;
	/* Prescale value calculation:
	 *
	 * Formula:
	 * time_tick = aging_time [s] / 128
	 * base_tick = 0.006711 s
	 * prescale_factor = time_tick / base_tick
	 *
	 * Implementation:
	 * time_tick = aging_time / 128
	 * prescale_factor = aging_time / 128 / 0.006711 = aging_time * 1.1641
	 *
	 * Nearest integer with shift:
	 * 1.1641 * 2^8 = 298,0...
	 * prescale_factor = aging_time * 298 >> 8
	 */

	/* check max range: 15,6 [h] * 3600 */
	if (in->aging_time > ONU_GPE_COP_AGE_MAX)
		return GPE_STATUS_VALUE_RANGE_ERR;

	ONU_DEBUG_MSG("age time: %u", in->aging_time);

	prescale = (uint16_t)onu_round_div(
				((uint32_t)in->aging_time) *
					ONU_GPE_COP_PSCALE_FAC_SET,
				ONU_GPE_COP_PSCALE_DIV_SET);

	entry.data.message.data[0] = prescale;

	cop_ret = cop_table_entry_write(&entry, ONU_GPE_COP_TABLE0W);
	if (cop_ret != COP_STATUS_SUCCESS)
		return GPE_STATUS_ERR;

#ifdef ONU_COP_BUGFIX
	if (is_falcon_chip_a12()) {
#endif

		if (ctrl->gpe_aging_trigger.lsa == ONU_GPE_LLT_NIL) {
			ctrl->gpe_aging_trigger.lsa = fsqm_segment_alloc();
			if (ctrl->gpe_aging_trigger.lsa == ONU_GPE_LLT_NIL) {
				ONU_DEBUG_ERR("ooops, can't get segment");
				return GPE_STATUS_ERR;
			}
		}

		ret = gpe_aging_trigger_set(ctrl);
		if (ret != ONU_STATUS_OK) {
			ONU_DEBUG_ERR("Aging Process Trigger failed!");
			return ret;
		}

		fsqm_segment_free(ctrl->gpe_aging_trigger.lsa,
				  ctrl->gpe_aging_trigger.lsa, 1, 0);
		ctrl->gpe_aging_trigger.lsa = ONU_GPE_LLT_NIL;

#ifdef ONU_COP_BUGFIX
	}
#endif

	return ONU_STATUS_OK;
}

enum onu_errorcode gpe_aging_time_set(struct onu_device *p_dev,
				      const struct sce_aging_time *in)
{
	enum onu_errorcode ret = ONU_STATUS_OK;
	enum cop_errorcode cop_ret;
	struct gpe_table_entry entry;
	struct onu_control *ctrl = (struct onu_control *)p_dev->ctrl;

	entry.id = 0;
	entry.instance = ONU_GPE_COP_FWD;
	entry.index = (uintptr_t)COPLINK_COP_GLOBAL3;
	/* Prescale value calculation:
	 *
	 * Formula:
	 * time_tick = aging_time [s] / 128
	 * base_tick = 0.006711 s
	 * prescale_factor = time_tick / base_tick
	 *
	 * Implementation:
	 * time_tick = aging_time / 128
	 * prescale_factor = aging_time / 128 / 0.006711 = aging_time * 1.1641
	 *
	 * Nearest integer with shift:
	 * 1.1641 * 2^8 = 298,0...
	 * prescale_factor = aging_time * 298 >> 8
	 */

	/* check max range: 15,6 [h] * 3600 */
	if (in->aging_time > ONU_GPE_COP_AGE_MAX)
		return GPE_STATUS_VALUE_RANGE_ERR;

	ONU_DEBUG_MSG("age time: %u", in->aging_time);

	prescale = (uint16_t)onu_round_div(
				((uint32_t)in->aging_time) *
					ONU_GPE_COP_PSCALE_FAC_SET,
				ONU_GPE_COP_PSCALE_DIV_SET);

	entry.data.message.data[0] = prescale;

	cop_ret = cop_table_entry_write(&entry, ONU_GPE_COP_TABLE0W);
	if (cop_ret != COP_STATUS_SUCCESS)
		return GPE_STATUS_ERR;

#ifdef ONU_COP_BUGFIX
	if (!is_falcon_chip_a11()) {
#endif
	onu_timer_stop(ONU_TIMER_AGING_TRIG);

	ctrl->gpe_aging_trigger.ttrig =
				(((uint32_t)in->aging_time) * 1000) >> 7;

	if (ctrl->gpe_aging_trigger.ttrig) {
		if (ctrl->gpe_aging_trigger.lsa == ONU_GPE_LLT_NIL) {
			ctrl->gpe_aging_trigger.lsa = fsqm_segment_alloc();
			if (ctrl->gpe_aging_trigger.lsa == ONU_GPE_LLT_NIL) {
				ONU_DEBUG_ERR("ooops, can't get segment");
				return GPE_STATUS_ERR;
			}
		}

		ret = gpe_aging_trigger_set(ctrl);
		if (ret != ONU_STATUS_OK) {
			ONU_DEBUG_ERR("Aging Process Trigger failed!");
			return ret;
		}

		onu_timer_start(ONU_TIMER_AGING_TRIG,
				ctrl->gpe_aging_trigger.ttrig);
	} else {
		fsqm_segment_free(ctrl->gpe_aging_trigger.lsa,
				  ctrl->gpe_aging_trigger.lsa, 1, 0);
		ctrl->gpe_aging_trigger.lsa = ONU_GPE_LLT_NIL;
	}

#ifdef ONU_COP_BUGFIX
	}
#endif

	return ONU_STATUS_OK;
}
enum onu_errorcode gpe_aging_time_get(	struct onu_device *p_dev,
					struct sce_aging_time *out)
{

	enum cop_errorcode cop_ret;
	struct gpe_table_entry entry;

	entry.id = 0;
	entry.instance = ONU_GPE_COP_FWD;
	entry.index = (uintptr_t)COPLINK_COP_GLOBAL3;
	/* Prescale value calculation:
	 *
	 * Formula:
	 * first part see set function
	 * => aging_time = time_tick * 128
	 * => aging_time = prescale_factor * base_tick * 128
	 * => aging_time = prescale_factor * 0.85888
	 *
	 * Nearest integer with shift:
	 * 0.859008 * 2^7 = 109,95 ~110
	 * => t_age [s] = prescale_factor * 110 >> 7
	 */
	cop_ret = cop_table_entry_read(&entry, ONU_GPE_COP_TABLE0R);

	if (cop_ret != COP_STATUS_SUCCESS)
		return ONU_STATUS_ERR;

	prescale = entry.data.message.data[0];

	out->aging_time = (uint16_t)onu_round_div(
					((uint32_t)prescale) *
						ONU_GPE_COP_PSCALE_FAC_GET,
					ONU_GPE_COP_PSCALE_DIV_GET);

	return ONU_STATUS_OK;
}
enum onu_errorcode gpe_age_get(	struct onu_device *p_dev,
				struct gpe_table_entry *in,
				struct sce_mac_entry_age *out)
{

	enum cop_errorcode cop_ret;
	uint32_t cop_id, table_id, key_len, orig_id, orig_instance;
	uint8_t t_learn;
	uint16_t t_now, time_tick;

	/* aging is supported for MAC unicast short forwarding only */
	if (in->id != ONU_GPE_SHORT_FWD_TABLE_MAC_ID)
		return ONU_STATUS_ERR;

	cop_id = GPE_TABLE_COP(in->id);
	table_id = GPE_TABLE_ID(in->id);
	orig_id = in->id;
	orig_instance = in->instance;

	in->id = table_id;
	in->instance = cop_id;
	key_len = cop_tbl_cfg[orig_id].key_len;

	cop_ret = cop_table_entry_searchr(in, key_len);

	in->id = orig_id;
	in->instance = orig_instance;

	out->ticks = 0;
	out->age = 0;

	if (cop_ret != COP_STATUS_SUCCESS)
		return ONU_STATUS_ERR;

	/* Age calculation:
	 *
	 * Formula:
	 * t_age = (t_now - t_learn) * time_tick
	 * time_tick = base_tick * prescale_factor
	 * base_tick = 0.006711 s
	 *
	 * t_age = (t_now - t_learn) * 0.006711 * prescale_factor

	 * Implementation:
	 * details see function above ...
	 * t_age = (t_now - t_learn) * prescale_factor * 110 >> 14
	 */
	t_learn = (in->data.message.data[2] >> LINKC2_TIMESTAMP_OFFSET) &
							  LINKC2_TIMESTAMP_MASK;

	t_now = timestamp_now < t_learn ? timestamp_now + 256 : timestamp_now;

	time_tick = (prescale * ONU_GPE_COP_PSCALE_FAC_GET) >> 14;
	ONU_DEBUG_MSG("prescale: %i, time_tick: %i, t_now: %i, t_learn: %i",
			prescale, time_tick, t_now, t_learn);

	out->ticks = (uint16_t)(t_now - t_learn);
	if (time_tick)
		out->age = 1 + (uint16_t)(t_now - t_learn) * time_tick;
	else
		out->age = 4095;

	return ONU_STATUS_OK;
}

enum onu_errorcode gpe_age(struct onu_device *p_dev,
			   struct gpe_table_entry *in)
{

	enum cop_errorcode cop_ret;
	uint32_t cop_id, table_id, orig_id, orig_instance;

	/* aging is supported for MAC unicast short forwarding only */
	if (in->id != ONU_GPE_SHORT_FWD_TABLE_MAC_ID)
		return ONU_STATUS_ERR;

	cop_id = GPE_TABLE_COP(in->id);
	table_id = GPE_TABLE_ID(in->id);
	orig_id = in->id;
	orig_instance = in->instance;

	in->id = table_id;
	in->instance = cop_id;

	cop_ret = cop_table_entry_exec(in, 0, IF_FWD_AGE);

	in->id = orig_id;
	in->instance = orig_instance;

	if (cop_ret != COP_STATUS_SUCCESS)
		return ONU_STATUS_ERR;

	return ONU_STATUS_OK;
}


/** The gpe_cop_debug_set function is used to set/reset
	the debug mode on one specific COP.
	This function is used for debugging only.
*/
enum onu_errorcode gpe_cop_debug_set(struct onu_device *p_dev,
				     const struct gpe_cop_tracing *in)
{
	UNUSED_PARAM_DEV;
	if (in->cop_idx >= ONU_GPE_NUMBER_OF_COP)
		return GPE_STATUS_VALUE_RANGE_ERR;

#ifdef INCLUDE_COP_DEBUG
	return cop_debug_set(in->cop_idx, in->trace_enable ? 1 : 0);
#else
	return ONU_STATUS_OK;
#endif
}

/** The gpe_cop_debug_server function is used to read executed microcode
	steps in single step mode during debugging.
	This function is used for debugging only.
*/
enum onu_errorcode gpe_cop_debug_server(struct onu_device *p_dev,
					const struct gpe_cop_debug *in)
{
	UNUSED_PARAM_DEV;
#ifdef INCLUDE_COP_DEBUG
	cop_debug_server(in->stepcnt, in->copmsk);
#endif

	return ONU_STATUS_OK;
}

/** The gpe_long_fwd_add function is used to add
	an entry to the long forwarding table.

	Use this function to add an entry to any of these tables:
	ONU_GPE_LONG_FWD_TABLE_IPV6_ID
	ONU_GPE_LONG_FWD_TABLE_IPV6_MC_ID
*/
/** Hardware Programming Details:
	The long forwarding tables are not microcode supported.
	See hardware coprocessor microcode documentation.
*/
enum onu_errorcode gpe_long_fwd_add(struct onu_device *p_dev,
				    const struct gpe_table_entry *in)
{
	struct gpe_table_entry entry;

	memcpy( &(entry.data.message.data[0]), &(in->data.message.data[0]),
		sizeof(entry.data.message));

	return general_add(p_dev, &entry,
			   ONU_GPE_LONG_FWD_HASH_TABLE_ID,
			   ONU_GPE_LONG_FWD_TABLE_IPV6_ID);
}

/** The gpe_long_fwd_add function is used to delete
	an entry from the long forwarding table.

	Use this function to delete an entry from any of these tables:
	ONU_GPE_LONG_FWD_TABLE_IPV6_ID
	ONU_GPE_LONG_FWD_TABLE_IPV6_MC_ID
*/
/** Hardware Programming Details:
	The long forwarding tables are not microcode supported.
	See hardware coprocessor microcode documentation.
*/
enum onu_errorcode gpe_long_fwd_delete(	struct onu_device *p_dev,
					const struct gpe_table_entry *in)
{
	struct gpe_table_entry entry;

	memcpy(&(entry.data.message.data[0]), &(in->data.message.data[0]),
	       sizeof(entry.data.message));

	return general_delete(p_dev, &entry,
			      ONU_GPE_LONG_FWD_HASH_TABLE_ID,
			      ONU_GPE_LONG_FWD_TABLE_IPV6_ID);
}

/** The gpe_long_fwd_forward function is used to forward
	an entry to the long forwarding table.

	Use this function to forward an entry to any of these tables:
	ONU_GPE_LONG_FWD_TABLE_IPV6_ID
	ONU_GPE_LONG_FWD_TABLE_IPV6_MC_ID
*/
/** Hardware Programming Details:
	The short forwarding tables are microcode supported.
*/
enum onu_errorcode gpe_long_fwd_forward(struct onu_device *p_dev,
					struct gpe_table_entry *in)
{
	struct gpe_table_entry entry;

	entry.id = ONU_GPE_LONG_FWD_TABLE_IPV6_ID;
	entry.index = 0;
	memcpy( &(entry.data.message.data[0]), &(in->data.message.data[0]),
		sizeof(entry.data.message));

	return gpe_table_entry_do(p_dev, &entry, IF_IPV6_FORWARD);
}

/** The gpe_tagging_filter_do function is used to perform a
	microcode sequence on the table tagging_filter_tbl and vlan_tbl
*/
/** Hardware Programming Details
*/
enum onu_errorcode gpe_tagging_filter_do(struct onu_device *p_dev,
					 const struct gpe_tagg_filter *in,
					 struct gpe_tagg_filter *out)
{
	struct gpe_table_entry entry;
	enum cop_errorcode cop_ret;
	uint32_t cop_id;

	cop_id = GPE_TABLE_COP(ONU_GPE_VLAN_TABLE_ID),

	entry.id = GPE_TABLE_ID(ONU_GPE_VLAN_TABLE_ID);
	entry.instance = cop_id;
	entry.index = in->index;
	memcpy(&entry.data, &in->in, sizeof(entry.data.tagg_filter_in));

	cop_ret = cop_table_entry_exec(&entry, 32, IF_TAG_FILTER);

	/* data field can be ignored.
	 * Result is coded in RES (0=abort, 1=pass) */
	out->out.data = ((uint32_t)cop_ret >> 3) & 0x1;

	if (cop_ret != COP_STATUS_SUCCESS && cop_ret != COP_STATUS_OK)
		return cop_to_onu_errorcode(cop_ret, &entry);

	return ONU_STATUS_OK;
}


/** The gpe_tagging_filter_get function is used to get
	an entry from the table tagging_filter_tbl and vlan_tbl
*/
/** Hardware Programming Details
	 1.) table entry get with idx on tagging filter table
	 2.) perform multiple table entry get on VLAN table and check
			for valid bits, stop at end bit
*/
enum onu_errorcode gpe_tagging_filter_get(struct onu_device *p_dev,
					  const struct gpe_tagging_index *in,
					  struct gpe_tagging *out)
{
	struct onu_control *ctrl = p_dev->ctrl;
	struct gpe_table_entry entry;
	enum onu_errorcode ret;
	uint16_t vlan;
	uint16_t valid_vlan;

	/* 1.) table entry get with idx on tagging filter table */
	entry.id = ONU_GPE_TAGGING_FILTER_TABLE_ID;
	entry.index = in->index;

	ret = TABLE_READ(ctrl, &entry); /* we need to low level read at
						  this point since we have
						  no key */

	if (ret || entry.result != COP_STATUS_SUCCESS)
		return ret;

	memcpy( &out->tagging_filter_tbl,
		&entry.data.tagging_filter,
		sizeof(entry.data.tagging_filter));

	/* 2.) perform multiple table entry get on VLAN table and check
			for valid bits, stop at end bit */
	valid_vlan = 0;
	for (vlan = 0; vlan < ONU_GPE_MAX_VLANS; vlan++) {

		/* needs to be set each time since id is overwritten */
		entry.id = ONU_GPE_VLAN_TABLE_ID;
		entry.index = entry.data.tagging_filter.vlan_table_index + vlan;

		ret = TABLE_READ(ctrl, &entry); /* we need to low level
							  read at this point
							  since we have
							  no key */

		if (ret || entry.result != COP_STATUS_SUCCESS)
			return ret;

		if (entry.data.vlan.valid) {
			memcpy(	&(out->vlan_tbl[valid_vlan]),
				&(entry.data.vlan),
				sizeof(entry.data.vlan));
			valid_vlan++;
		}

		if (entry.data.vlan.end)
			break;
	}

	out->num_valid_vlans = valid_vlan;

	return ONU_STATUS_OK;
}

/** The gpe_tagging_filter_set function is used to set
	an entry to the table tagging_filter_tbl and vlan_tbl
*/
/** Hardware Programming Details
    1.) table entry set with idx on tagging filter table
    2.) perform multiple table entry set on VLAN table starting with
		index vlan_table_index and increment

	Note: Overwrite VLAN entries, do not check for validity.
*/
enum onu_errorcode gpe_tagging_filter_set(struct onu_device *p_dev,
					  const struct gpe_tagging *param)
{
	struct onu_control *ctrl = p_dev->ctrl;
	struct gpe_table_entry entry;
	enum onu_errorcode ret;
	uint16_t vlan,vlan_idx;

	if (param->num_valid_vlans >= ONU_GPE_MAX_VLANS)
		return GPE_STATUS_VALUE_RANGE_ERR;

	/* 1.) table entry set with idx on tagging filter table */
	entry.id = ONU_GPE_TAGGING_FILTER_TABLE_ID;
	entry.index = param->index;
	memcpy( &entry.data.tagging_filter,
			&param->tagging_filter_tbl,
			sizeof(entry.data.tagging_filter));

	ret = gpe_table_entry_set(p_dev, &entry);
	if (ret)
		return ret;

	/* 2.) perform multiple table entry set on VLAN table starting with
		index vlan_table_index and increment */
	entry.id = ONU_GPE_VLAN_TABLE_ID;

	/* make the first entry invalid - if the table has to be deleted */
	if (param->num_valid_vlans == 0) {
		entry.index = entry.data.tagging_filter.vlan_table_index;
		entry.data.vlan.valid = 0;
		entry.data.vlan.end = 1;
#ifdef ONU_COP_BUGFIX
		ONU_DEBUG_MSG("cop: using workaround for GPONC-158");
		ret = gpe_table_entry_write(p_dev, &entry);
#else
		ret = gpe_table_entry_add(p_dev, &entry);
#endif
		if (ret || entry.result != COP_STATUS_SUCCESS)
			return ret;
	}

	for (vlan = 0; vlan < param->num_valid_vlans; vlan++) {

		entry.index = entry.data.tagging_filter.vlan_table_index + vlan;

		memcpy( &entry.data.vlan,
			&(param->vlan_tbl[vlan]),
			sizeof(entry.data.vlan));

		entry.data.vlan.valid = 1; /* always valid */
		entry.data.vlan.end = 0;
		/* last vlan has the end bit set */
		if (vlan == param->num_valid_vlans-1)
			entry.data.vlan.end = 1;

#ifdef ONU_COP_BUGFIX
		ONU_DEBUG_MSG("cop: using workaround for GPONC-158");
		ret = gpe_table_entry_write(p_dev, &entry);
#else
		ret = gpe_table_entry_add(p_dev, &entry);
#endif

		entry.index++;

		if (ret || entry.result != COP_STATUS_SUCCESS)
			return ret;
	}
	/*  GPONSW-1122 workaround for Bug in match pipeline not 
	    taking care of "end -bit" */
	vlan_idx = 4 - (entry.index & 0x3);

	/* check if we are on memory line border */
	if (vlan_idx < 4) {
		for (vlan = 0; vlan < vlan_idx; vlan++) {
			entry.data.vlan.valid = 0; /* not valid */
			entry.data.vlan.end = 0;
			ret = gpe_table_entry_intcmd(ctrl, 
				&entry, ONU_GPE_COP_WRITE);
			entry.index++;

			if (ret || entry.result != COP_STATUS_SUCCESS)
				return ret;
		}
	}

	return ONU_STATUS_OK;
}

enum onu_errorcode gpe_cop_table0_read(struct onu_device *p_dev,
				       struct gpe_table_entry *entry)
{
	return cop_table0_read(entry);
}

enum onu_errorcode gpe_sce_constant_set(struct onu_control *ctrl,
					const uint32_t idx,
					const uint32_t val)
{
	struct gpe_table_entry entry;

	entry.id = ONU_GPE_CONSTANTS_TABLE_ID;
	entry.instance = ONU_GPE_ALL_PE_MASK;
	entry.index = idx;
	entry.data.constants.entry_data = val;
	
	return gpe_table_entry_intcmd(ctrl, &entry, ONU_GPE_COP_SET);
}

enum onu_errorcode gpe_sce_constant_get(struct onu_control *ctrl,
					const uint32_t idx,
					uint32_t *val)
{
	enum onu_errorcode ret;
	struct gpe_table_entry entry;

	entry.id = ONU_GPE_CONSTANTS_TABLE_ID;
	entry.instance = ONU_GPE_ALL_PE_MASK;
	entry.index = idx;

	ret = gpe_table_entry_intresp(ctrl, &entry, ONU_GPE_COP_READ);
	if (ret == ONU_STATUS_OK)
		*val = entry.data.constants.entry_data;

	return ret;
}

/** Put all PEs in packet mode (sync = 0) */
enum onu_errorcode gpe_sce_process_mode_set(struct onu_control *ctrl,
					    enum sce_process_mode mode)
{
	enum onu_errorcode ret;

	ret = gpe_sce_constant_set (ctrl,
		ONU_GPE_CONST_PACKET_ENABLE,
		(mode == SCE_MODE_PACKET ? 1 : 0));
	if (ret != 0) {
		return ONU_STATUS_FW_PACKET_ERR;
	}

	return ONU_STATUS_OK;
}

static enum onu_errorcode gpe_sce_pcp_decoding_init(struct onu_control *ctrl)
{
	struct gpe_table_entry entry;
	enum pe_errorcode error;
	/* PCP decoding table according to IEEE802.1ad*/
	uint8_t priority[ONU_GPE_PCP_DECODING_TABLE_SIZE] = {
		0, 1, 2, 3, 4, 5, 6, 7,
		0, 1, 2, 3, 4, 4, 6, 7,
		0, 1, 2, 2, 4, 4, 6, 7,
		0, 0, 2, 2, 4, 4, 6, 7
	};
	uint8_t de[ONU_GPE_PCP_DECODING_TABLE_SIZE] = {
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 1, 0, 0, 0,
		0, 0, 1, 0, 1, 0, 0, 0,
		1, 0, 1, 0, 1, 0, 0, 0
	};
	uint8_t i;

	memset(&entry, 0, sizeof(entry));

	entry.instance = 255;
	entry.id = ONU_GPE_PCP_DECODING_TABLE_ID;

	for (i = 0; i < ONU_GPE_PCP_DECODING_TABLE_SIZE; i++) {
		entry.index = i;

		entry.data.pcp_decoding.priority = priority[i];
		entry.data.pcp_decoding.color = 0;
		entry.data.pcp_decoding.de = de[i];

		error = gpe_table_entry_intcmd(ctrl, &entry, ONU_GPE_COP_SET);
		if (error)
			return error;
	}

	return 0;
}

static enum onu_errorcode gpe_sce_pcp_encoding_init(struct onu_control *ctrl)
{
	struct gpe_table_entry entry;
	enum pe_errorcode error;
	uint32_t i;

	memset(&entry, 0, sizeof(entry));

	entry.instance = 255;
	entry.id = ONU_GPE_PCP_ENCODING_TABLE_ID;

	for (i = 0; i < ONU_GPE_PCP_ENCODING_TABLE_SIZE; i++) {
		entry.index = i;
		entry.data.pcp_encoding.pcp = i % 8;

		error = gpe_table_entry_intcmd(ctrl, &entry, ONU_GPE_COP_SET);
		if (error)
			return error;
	}

	return 0;
}


enum onu_errorcode gpe_sce_pe_init(struct onu_control *ctrl)
{
	uint32_t table_id;
	struct gpe_table_entry entry;
	enum onu_errorcode ret;

	for (table_id = 0; table_id < sce_table_cfg_size; table_id++) {
		ret = sce_pe_table_init(ctrl, table_id);
		if (ret != ONU_STATUS_OK)
			return ret;
	}

	/* special initalization for constants table */

	/** \todo make use of gpe_sce_constant_set or even
	gpe_sce_constants_set */
	entry.id = ONU_GPE_CONSTANTS_TABLE_ID;
	entry.instance = ONU_GPE_ALL_PE_MASK;

	entry.index = ONU_GPE_CONST_DEFAULT_FID;
	entry.data.constants.entry_data = ONU_GPE_CONSTANT_VAL_DEFAULT_FID;
	ret = gpe_table_entry_intcmd(ctrl, &entry, ONU_GPE_COP_SET);
	if (ret != 0)
		return ret;

	entry.index = ONU_GPE_CONST_VID;
	entry.data.constants.entry_data = ONU_GPE_CONSTANT_VAL_VID;
	ret = gpe_table_entry_intcmd(ctrl, &entry, ONU_GPE_COP_SET);
	if (ret != 0)
		return ret;

	entry.index = ONU_GPE_CONST_DEFAULT_DSCP;
	entry.data.constants.entry_data = ONU_GPE_CONSTANT_VAL_DEFAULT_DSCP;
	ret = gpe_table_entry_intcmd(ctrl, &entry, ONU_GPE_COP_SET);
	if (ret != 0)
		return ret;

	entry.index = ONU_GPE_CONST_UNUSED0;
	entry.data.constants.entry_data = ONU_GPE_CONSTANT_VAL_UNUSED0;
	ret = gpe_table_entry_intcmd(ctrl, &entry, ONU_GPE_COP_SET);
	if (ret != 0)
		return ret;

	entry.index = ONU_GPE_CONST_FWD_TABLESIZE;
	entry.data.constants.entry_data =
		cop_tbl_cfg[ONU_GPE_SHORT_FWD_TABLE_MAC_ID].size << 16;
	ret = gpe_table_entry_intcmd(ctrl, &entry, ONU_GPE_COP_SET);
	if (ret != 0)
		return ret;

	entry.index = ONU_GPE_CONST_TPID_CD;
	entry.data.constants.entry_data = (ONU_ETHERTYPE_CVLAN << 16) |
		ONU_ETHERTYPE_QINQ;
	ret = gpe_table_entry_intcmd(ctrl, &entry, ONU_GPE_COP_SET);
	if (ret != 0)
		return ret;

	entry.index = ONU_GPE_CONST_TPID_AB;
	entry.data.constants.entry_data = (ONU_ETHERTYPE_SVLAN << 16) |
		ONU_ETHERTYPE_CVLAN;
	ret = gpe_table_entry_intcmd(ctrl, &entry, ONU_GPE_COP_SET);
	if (ret != 0)
		return ret;

	entry.index = ONU_GPE_CONST_ADDED_LATENCY;
	entry.data.constants.entry_data = ONU_GPE_CONSTANT_VAL_ADDED_LATENCY;
	ret = gpe_table_entry_intcmd(ctrl, &entry, ONU_GPE_COP_SET);
	if (ret != 0)
		return ret;

	entry.index = ONU_GPE_CONST_UNUSED1;
	entry.data.constants.entry_data = ONU_GPE_CONSTANT_VAL_UNUSED1;
	ret = gpe_table_entry_intcmd(ctrl, &entry, ONU_GPE_COP_SET);
	if (ret != 0)
		return ret;

	entry.index = ONU_GPE_CONST_METER_L2_MODE;
	entry.data.constants.entry_data = ONU_GPE_CONSTANT_VAL_METER_L2_MODE;
	ret = gpe_table_entry_intcmd(ctrl, &entry, ONU_GPE_COP_SET);
	if (ret != 0)
		return ret;

	ret = gpe_sce_pcp_decoding_init(ctrl);
	if (ret != 0)
		return ret;

	ret = gpe_sce_pcp_encoding_init(ctrl);
	if (ret != 0)
		return ret;

	return 0;
}

enum onu_errorcode gpe_sce_constants_get(struct onu_device *p_dev,
					 struct gpe_sce_constants *param)
{
	enum onu_errorcode ret = ONU_STATUS_OK;
	struct onu_control *ctrl = p_dev->ctrl;
	uint32_t val[ONU_GPE_CONST_MAX], i;

	for (i = 0; i < ARRAY_SIZE(val); i++ ) {
		ret = gpe_sce_constant_get(ctrl, i, &val[i]);
		if (ret != ONU_STATUS_OK)
			return ret;
	}

	param->unused1 = val[ONU_GPE_CONST_UNUSED1];
	param->added_latency = val[ONU_GPE_CONST_ADDED_LATENCY];
	param->tpid_a = (uint16_t)(val[ONU_GPE_CONST_TPID_AB] & 0xFFFF);
	param->tpid_b = (uint16_t)((val[ONU_GPE_CONST_TPID_AB] >> 16) &
								   0xFFFF);
	param->tpid_c = (uint16_t)(val[ONU_GPE_CONST_TPID_CD] & 0xFFFF);
	param->tpid_d = (uint16_t)((val[ONU_GPE_CONST_TPID_CD] >> 16) &
								   0xFFFF);
	param->fwd_table_size = val[ONU_GPE_CONST_FWD_TABLESIZE];
	param->unused0 = val[ONU_GPE_CONST_UNUSED0];
	param->default_outer_vid = (uint16_t)(val[ONU_GPE_CONST_VID] &
								   0xFFFF);
	param->default_inner_vid = (uint16_t)((val[ONU_GPE_CONST_VID] >> 16)
								 & 0xFFFF);
	param->default_fid = val[ONU_GPE_CONST_DEFAULT_FID];
	param->default_dscp = val[ONU_GPE_CONST_DEFAULT_DSCP];
	param->packet_processing_enable =
			      val[ONU_GPE_CONST_PACKET_ENABLE];

	param->local_cpu_mac[0] =
		(val[ONU_GPE_CONST_LOCALMAC_ADRH] >> 24) & 0xFF;
	param->local_cpu_mac[1] =
		(val[ONU_GPE_CONST_LOCALMAC_ADRH] >> 16) & 0xFF;
	param->local_cpu_mac[2] =
		(val[ONU_GPE_CONST_LOCALMAC_ADRH] >> 8) & 0xFF;
	param->local_cpu_mac[3] =
		(val[ONU_GPE_CONST_LOCALMAC_ADRH]) & 0xFF;
	param->local_cpu_mac[4] =
		(val[ONU_GPE_CONST_LOCALMAC_ADRL] >> 24) & 0xFF;
	param->local_cpu_mac[5] =
		(val[ONU_GPE_CONST_LOCALMAC_ADRL] >> 16) & 0xFF;

	param->ani_exception_enable =
		(val[ONU_GPE_CONST_ANI_EXCEPTION_METER] >> 9) & 0x1;
	param->ani_exception_meter_id =
		(val[ONU_GPE_CONST_ANI_EXCEPTION_METER] >> 1) & 0xFF;

	param->ani_except_policer_threshold =
		val[ONU_GPE_ANI_EXCEPT_POLICER_THRESHOLD];
	param->uni_except_policer_threshold =
		val[ONU_GPE_UNI_EXCEPT_POLICER_THRESHOLD];
	param->igmp_except_policer_threshold =
		val[ONU_GPE_IGMP_EXCEPT_POLICER_THRESHOLD];

	param->unused = val[ONU_GPE_CONST_UNUSED];

	param->meter_l2_only_enable = val[ONU_GPE_CONST_METER_L2_MODE] & 0x1;

	return ret;
}

enum onu_errorcode gpe_sce_constants_set(struct onu_device *p_dev,
					 const struct gpe_sce_constants *param)
{
	enum onu_errorcode ret = ONU_STATUS_OK;
	struct onu_control *ctrl = p_dev->ctrl;
	uint32_t val[ONU_GPE_CONST_MAX], i;

	if (param->ani_exception_meter_id >= ONU_GPE_MAX_SHAPER)
		return GPE_STATUS_VALUE_RANGE_ERR;

	for (i = 0; i < ARRAY_SIZE(val); i++ ) {
		ret = gpe_sce_constant_get(ctrl, i, &val[i]);
		if (ret != ONU_STATUS_OK)
			return ret;
	}

	val[ONU_GPE_CONST_UNUSED1] = param->unused1;
	val[ONU_GPE_CONST_ADDED_LATENCY] = param->added_latency;
	val[ONU_GPE_CONST_TPID_AB] = (uint32_t)((param->tpid_b << 16) |
						    param->tpid_a);
	val[ONU_GPE_CONST_TPID_CD] = (uint32_t)((param->tpid_d << 16) |
						    param->tpid_c);
	val[ONU_GPE_CONST_FWD_TABLESIZE] = param->fwd_table_size;
	val[ONU_GPE_CONST_UNUSED1] = param->unused0;
	val[ONU_GPE_CONST_VID] = (uint32_t)((param->default_inner_vid << 16) |
						param->default_outer_vid);
	val[ONU_GPE_CONST_DEFAULT_FID] = param->default_fid;
	val[ONU_GPE_CONST_DEFAULT_DSCP] = param->default_dscp;

	val[ONU_GPE_CONST_LOCALMAC_ADRH] = (param->local_cpu_mac[0] << 24) |
					   (param->local_cpu_mac[1] << 16) |
					   (param->local_cpu_mac[2] << 8)  |
					    param->local_cpu_mac[3];
	val[ONU_GPE_CONST_LOCALMAC_ADRL] = (param->local_cpu_mac[4] << 24) |
					   (param->local_cpu_mac[5] << 16);

	val[ONU_GPE_CONST_ANI_EXCEPTION_METER] =
				param->ani_exception_enable ? (1 << 9) : 0;
	val[ONU_GPE_CONST_ANI_EXCEPTION_METER] |=
				param->ani_exception_meter_id & 0xFF;

	val[ONU_GPE_ANI_EXCEPT_POLICER_THRESHOLD] =
				param->ani_except_policer_threshold;
	val[ONU_GPE_UNI_EXCEPT_POLICER_THRESHOLD] =
				param->uni_except_policer_threshold;
	val[ONU_GPE_IGMP_EXCEPT_POLICER_THRESHOLD] =
				param->igmp_except_policer_threshold;
	val[ONU_GPE_CONST_METER_L2_MODE] = param->meter_l2_only_enable & 0x1;

	for (i = 0; i < ARRAY_SIZE(val); i++ ) {
		if (i != ONU_GPE_CONST_PACKET_ENABLE)
			ret = gpe_sce_constant_set(ctrl, i, val[i]);
		if (ret != ONU_STATUS_OK)
			return ret;
	}

	return ret;
}

enum onu_errorcode gpe_sce_constant_mac_set(struct onu_control *ctrl,
					    const uint8_t mac[6])
{
	enum onu_errorcode ret = ONU_STATUS_OK;
	uint32_t mach, macl;

	mach = 	(mac[0] << 24) | (mac[1] << 16) | (mac[2] << 8)  | mac[3];
	macl = 	(mac[4] << 24) | (mac[5] << 16);

	ret = gpe_sce_constant_set(ctrl, ONU_GPE_CONST_LOCALMAC_ADRH, mach);
	if (ret != ONU_STATUS_OK)
		return ret;

	ret = gpe_sce_constant_set(ctrl, ONU_GPE_CONST_LOCALMAC_ADRL, macl);
	if (ret != ONU_STATUS_OK)
		return ret;

	return ret;
}

enum onu_errorcode gpe_sce_mac_get(struct onu_device *p_dev,
				   struct gpe_sce_mac *param)
{
	enum onu_errorcode ret = ONU_STATUS_OK;
	struct onu_control *ctrl = p_dev->ctrl;
	uint32_t mach = 0, macl = 0;


	ret = gpe_sce_constant_get(ctrl, ONU_GPE_CONST_LOCALMAC_ADRH, &mach);
	if (ret != ONU_STATUS_OK)
		return ret;

	ret = gpe_sce_constant_get(ctrl, ONU_GPE_CONST_LOCALMAC_ADRL, &macl);
	if (ret != ONU_STATUS_OK)
		return ret;

	param->local_cpu_mac[0] = (mach >> 24) & 0xFF;
	param->local_cpu_mac[1] = (mach >> 16) & 0xFF;
	param->local_cpu_mac[2] = (mach >> 8) & 0xFF;
	param->local_cpu_mac[3] = (mach) & 0xFF;
	param->local_cpu_mac[4] = (macl >> 24) & 0xFF;
	param->local_cpu_mac[5] = (macl >> 16) & 0xFF;

	return ret;
}

enum onu_errorcode gpe_sce_mac_set(struct onu_device *p_dev,
				   const struct gpe_sce_mac *param)
{
	enum onu_errorcode ret = ONU_STATUS_OK;
	struct onu_control *ctrl = p_dev->ctrl;

	ret = gpe_sce_constant_mac_set(ctrl, param->local_cpu_mac);
	if (ret != ONU_STATUS_OK)
		return ret;

	return ret;
}

enum onu_errorcode gpe_vlan_fid_add(struct onu_device *p_dev,
				    const struct gpe_vlan_fid_in *in,
				    struct gpe_vlan_fid_out *out)
{
	enum onu_errorcode ret = ONU_STATUS_OK;
	struct onu_control *ctrl = p_dev->ctrl;
	struct gpe_table_entry entry_add, entry_out;
	uint16_t fid_cnt;
	uint8_t fid_table[64] = {0};
	int fid_free = -1;

	/* Outer VLAN should be always present*/
	if (in->vlan_1 == 0)
		return GPE_STATUS_VALUE_RANGE_ERR;

	memset(&entry_add, 0, sizeof(entry_add));

	entry_add.data.fwd_id.vid_outer = in->vlan_1 & 0xFFF;
	/** \todo outer DEI, definition is not available yet*/
	entry_add.data.fwd_id.unused1 = (in->vlan_1 >> 12) & 0x1;
	entry_add.data.fwd_id.prio_outer = (in->vlan_1 >> 13) & 0x7;

	entry_add.data.fwd_id.vid_inner = in->vlan_2 & 0xFFF;
	/** \todo inner DEI, definition is not available yet*/
	entry_add.data.fwd_id.unused2 = (in->vlan_2 >> 12) & 0x1;
	entry_add.data.fwd_id.prio_inner = (in->vlan_2 >> 13) & 0x7;

	ret = gpe_fid_get(p_dev, &entry_add, &entry_out);
	if (ret == ONU_STATUS_OK) {
		out->fid = entry_out.data.fwd_id.fid;
		return GPE_STATUS_EXISTS; /* resource exists*/
	}

	/* scan whole table for valid entries */
	for (fid_cnt=0; fid_cnt<ONU_GPE_FID_ASSIGNMENT_TABLE_SIZE; fid_cnt++) {
		entry_out.id = ONU_GPE_FID_ASSIGNMENT_TABLE_ID;
		entry_out.index = fid_cnt;
		ret = TABLE_READ(ctrl, &entry_out);
		if (ret)
			return ret;

		/* skip not valid entry*/
		if (!entry_out.data.fwd_id.valid)
			continue;
		/* Forwarding ID (FID), values 0 to 63 are valid.
		   Attention: 8 bit are used for MDU applications,
		   for SFU applications the two MSB must be set to 0. */
		/** \todo crosscheck if we need to handle MDU data
		*/
		if (entry_out.data.fwd_id.fid & 0xC0)
			continue;

		fid_table[entry_out.data.fwd_id.fid] = 1;
	}

	for (fid_cnt = 0; fid_cnt < ARRAY_SIZE(fid_table); fid_cnt++) {
		/* check if unused and not default*/
		if (fid_table[fid_cnt] == 0 &&
		    fid_cnt != ONU_GPE_CONSTANT_VAL_DEFAULT_FID) {
			fid_free = fid_cnt;
			break;
		}
	}

	if (fid_free == -1)
		/* no unused entry found*/
		return ONU_STATUS_ERR;

	/* add an entry */
	entry_add.data.fwd_id.fid = (uint8_t)fid_free;
	ret = gpe_fid_add(p_dev, &entry_add);
	if (ret)
		return ret;

	out->fid = (uint8_t)fid_free;

	return ONU_STATUS_OK;
}

enum onu_errorcode gpe_vlan_fid_get(struct onu_device *p_dev,
				    const struct gpe_vlan_fid_in *in,
				    struct gpe_vlan_fid_out *out)
{
	enum onu_errorcode ret = ONU_STATUS_OK;
	struct gpe_table_entry entry_in, entry_out;

	/* Outer VLAN should be always present*/
	if (in->vlan_1 == 0)
		return GPE_STATUS_VALUE_RANGE_ERR;

	memset(&entry_in, 0, sizeof(entry_in));
	memset(&entry_out, 0, sizeof(entry_out));

	entry_in.data.fwd_id.vid_outer = in->vlan_1 & 0xFFF;
	/** \todo outer DEI, definition is not available yet*/
	entry_in.data.fwd_id.unused1 = (in->vlan_1 >> 12) & 0x1;
	entry_in.data.fwd_id.prio_outer = (in->vlan_1 >> 13) & 0x7;

	entry_in.data.fwd_id.vid_inner = in->vlan_2 & 0xFFF;
	/** \todo inner DEI, definition is not available yet*/
	entry_in.data.fwd_id.unused2 = (in->vlan_2 >> 12) & 0x1;
	entry_in.data.fwd_id.prio_inner = (in->vlan_2 >> 13) & 0x7;

	ret = gpe_fid_get(p_dev, &entry_in, &entry_out);
	if (ret != ONU_STATUS_OK)
		return ret;

	out->fid = entry_out.data.fwd_id.fid;

	return ret;
}

enum onu_errorcode gpe_vlan_fid_delete(struct onu_device *p_dev,
				       const struct gpe_vlan_fid_in *in)
{
	struct gpe_table_entry entry;

	/* Outer VLAN should be always present*/
	if (in->vlan_1 == 0)
		return GPE_STATUS_VALUE_RANGE_ERR;

	entry.data.fwd_id.vid_outer = in->vlan_1 & 0xFFF;
	/** \todo outer DEI, definition is not available yet*/
	entry.data.fwd_id.unused1 = (in->vlan_1 >> 12) & 0x1;
	entry.data.fwd_id.prio_outer = (in->vlan_1 >> 13) & 0x7;

	entry.data.fwd_id.vid_inner = in->vlan_2 & 0xFFF;
	/** \todo inner DEI, definition is not available yet*/
	entry.data.fwd_id.unused2 = (in->vlan_2 >> 12) & 0x1;
	entry.data.fwd_id.prio_inner = (in->vlan_2 >> 13) & 0x7;

	return gpe_fid_delete(p_dev, &entry);
}

static struct {
	bool layer2_disable;
	bool layer3_disable;
	bool layer4_disable;
	bool layer2_compare;
	bool layer2_mac_address_compare;
	bool layer3_compare;
	bool layer3_ip_address_compare;
	bool layer4_port_compare;
	bool layer4_tcp_enable;
	bool layer4_udp_enable;
} acl_transformation[] = {
	/* GPE_ACL_PARAM1_NONE */

	/* + GPE_ACL_PARAM2_NONE */
	{ 1, 1, 1, 0, 0, 0, 0, 0, 0, 0 },
	/* + GPE_ACL_PARAM2_MAC_SA */
	{ 0, 1, 1, 1, 1, 0, 0, 0, 0, 0 },
	/* + GPE_ACL_PARAM2_MAC_DA */
	{ 0, 1, 1, 1, 0, 0, 0, 0, 0, 0 },
	/* + GPE_ACL_PARAM2_ETHERTYPE */
	{ 0, 1, 1, 0, 0, 0, 0, 0, 0, 0 },
	/* + GPE_ACL_PARAM2_TCP_SP */
	{ 1, 1, 0, 0, 0, 0, 0, 1, 1, 0 },
	/* + GPE_ACL_PARAM2_TCP_DP */
	{ 1, 1, 0, 0, 0, 0, 0, 0, 1, 0 },
	/* + GPE_ACL_PARAM2_UDP_SP */
	{ 1, 1, 0, 0, 0, 0, 0, 1, 0, 1 },
	/* + GPE_ACL_PARAM2_UDP_DP */
	{ 1, 1, 0, 0, 0, 0, 0, 0, 0, 1 },
	/* + GPE_ACL_PARAM2_TCP_UDP_SP */
	{ 1, 1, 0, 0, 0, 0, 0, 1, 1, 1 },
	/* + GPE_ACL_PARAM2_TCP_UDP_DP */
	{ 1, 1, 0, 0, 0, 0, 0, 0, 1, 1 },

	/* GPE_ACL_PARAM1_IPV4_SA */

	/* + GPE_ACL_PARAM2_NONE */
	{ 1, 0, 1, 0, 0, 1, 1, 0, 0, 0 },
	/* + GPE_ACL_PARAM2_MAC_SA */
	{ 0, 0, 1, 1, 1, 1, 1, 0, 0, 0 },
	/* + GPE_ACL_PARAM2_MAC_DA */
	{ 0, 0, 1, 1, 0, 1, 1, 0, 0, 0 },
	/* + GPE_ACL_PARAM2_ETHERTYPE */
	{ 0, 0, 1, 0, 0, 1, 1, 0, 0, 0 },
	/* + GPE_ACL_PARAM2_TCP_SP */
	{ 1, 0, 0, 0, 0, 1, 1, 1, 1, 0 },
	/* + GPE_ACL_PARAM2_TCP_DP */
	{ 1, 0, 0, 0, 0, 1, 1, 0, 1, 0 },
	/* + GPE_ACL_PARAM2_UDP_SP */
	{ 1, 0, 0, 0, 0, 1, 1, 1, 0, 1 },
	/* + GPE_ACL_PARAM2_UDP_DP */
	{ 1, 0, 0, 0, 0, 1, 1, 0, 0, 1 },
	/* + GPE_ACL_PARAM2_TCP_UDP_SP */
	{ 1, 0, 0, 0, 0, 1, 1, 1, 1, 1 },
	/* + GPE_ACL_PARAM2_TCP_UDP_DP */
	{ 1, 0, 0, 0, 0, 1, 1, 0, 1, 1 },

	/* GPE_ACL_PARAM1_IPV4_DA */

	/* + GPE_ACL_PARAM2_NONE */
	{ 1, 0, 1, 0, 0, 1, 0, 0, 0, 0 },
	/* + GPE_ACL_PARAM2_MAC_SA */
	{ 0, 0, 1, 1, 1, 1, 0, 0, 0, 0 },
	/* + GPE_ACL_PARAM2_MAC_DA */
	{ 0, 0, 1, 1, 0, 1, 0, 0, 0, 0 },
	/* + GPE_ACL_PARAM2_ETHERTYPE */
	{ 0, 0, 1, 0, 0, 1, 0, 0, 0, 0 },
	/* + GPE_ACL_PARAM2_TCP_SP */
	{ 1, 0, 0, 0, 0, 1, 0, 1, 1, 0 },
	/* + GPE_ACL_PARAM2_TCP_DP */
	{ 1, 0, 0, 0, 0, 1, 0, 0, 1, 0 },
	/* + GPE_ACL_PARAM2_UDP_SP */
	{ 1, 0, 0, 0, 0, 1, 0, 1, 0, 1 },
	/* + GPE_ACL_PARAM2_UDP_DP */
	{ 1, 0, 0, 0, 0, 1, 0, 0, 0, 1 },
	/* + GPE_ACL_PARAM2_TCP_UDP_SP */
	{ 1, 0, 0, 0, 0, 1, 0, 0, 1 ,1 },
	/* + GPE_ACL_PARAM2_TCP_UDP_DP */
	{ 1, 0, 0, 0, 0, 1, 0, 1, 1 ,1 },

	/* GPE_ACL_PARAM1_IPV4_PROT */

	/* + GPE_ACL_PARAM2_NONE */
	{ 1, 0, 1, 0, 0, 0, 0, 0, 0, 0 },
	/* + GPE_ACL_PARAM2_MAC_SA */
	{ 0, 0, 1, 1, 1, 0, 0, 0, 0, 0 },
	/* + GPE_ACL_PARAM2_MAC_DA */
	{ 0, 0, 1, 1, 0, 0, 0, 0, 0, 0 },
	/* + GPE_ACL_PARAM2_ETHERTYPE */
	{ 0, 0, 1, 0, 0, 0, 0, 0, 0, 0 },
	/* + GPE_ACL_PARAM2_TCP_SP */
	{ 1, 0, 0, 0, 0, 0, 0, 1, 1, 0 },
	/* + GPE_ACL_PARAM2_TCP_DP */
	{ 1, 0, 0, 0, 0, 0, 0, 0, 1, 0 },
	/* + GPE_ACL_PARAM2_UDP_SP */
	{ 1, 0, 0, 0, 0, 0, 0, 1, 0, 1 },
	/* + GPE_ACL_PARAM2_UDP_DP */
	{ 1, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
	/* + GPE_ACL_PARAM2_TCP_UDP_SP */
	{ 1, 0, 0, 0, 0, 0, 0, 1, 1, 1 },
	/* + GPE_ACL_PARAM2_TCP_UDP_DP */
	{ 1, 0, 0, 0, 0, 0, 0, 0, 1, 1 }

	/* no info in the UMPR for the following: */
	/* GPE_ACL_PARAM1_IPV6_SA */
	/* GPE_ACL_PARAM1_IPV6_DA */
};

enum onu_errorcode
gpe_acl_table_entry_set(struct onu_device *p_dev,
			const struct gpe_acl_table_entry *param)
{
	struct gpe_table_entry entry;
	uint32_t cfg;

	if (!is_falcon_chip_a1x())
		return ONU_STATUS_CHIP_NOT_SUPPORTED;

	if (param->acl_filter_index >= ONU_GPE_ACL_FILTER_TABLE_SIZE)
		return GPE_STATUS_VALUE_RANGE_ERR;

	entry.id = ONU_GPE_ACL_FILTER_TABLE_ID;
	entry.instance = 0xFF;
	entry.index = param->acl_filter_index;

	entry.data.acl_filter.valid = 1;
	entry.data.acl_filter.end = param->last_entry;
	entry.data.acl_filter.fid = param->fid;
	entry.data.acl_filter.fid_disable = param->fid_en == true ? 0 : 1;

	entry.data.acl_filter.ingress_port_lan0 =
		param->ingress_port_enable & 1;
	entry.data.acl_filter.ingress_port_lan1 =
		param->ingress_port_enable & 2 ? 1 : 0;
	entry.data.acl_filter.ingress_port_lan2 =
		param->ingress_port_enable & 4 ? 1 : 0;
	entry.data.acl_filter.ingress_port_lan3 =
		param->ingress_port_enable & 8 ? 1 : 0;

	cfg = param->param1_type * 10 + param->param2_type;

	if (cfg >= ARRAY_SIZE(acl_transformation))
		return GPE_STATUS_VALUE_RANGE_ERR;

	entry.data.acl_filter.layer2_disable =
		acl_transformation[cfg].layer2_disable;
	entry.data.acl_filter.layer3_disable =
		acl_transformation[cfg].layer3_disable;
	entry.data.acl_filter.layer4_disable =
		acl_transformation[cfg].layer4_disable;
	entry.data.acl_filter.layer2_compare =
		acl_transformation[cfg].layer2_compare;
	entry.data.acl_filter.layer2_mac_address_compare =
		acl_transformation[cfg].layer2_mac_address_compare;
	entry.data.acl_filter.layer3_compare =
		acl_transformation[cfg].layer3_compare;
	entry.data.acl_filter.layer3_ip_address_compare =
		acl_transformation[cfg].layer3_ip_address_compare;
	entry.data.acl_filter.layer4_port_compare =
		acl_transformation[cfg].layer4_port_compare;
	entry.data.acl_filter.layer4_tcp_enable =
		acl_transformation[cfg].layer4_tcp_enable;
	entry.data.acl_filter.layer4_udp_enable =
		acl_transformation[cfg].layer4_udp_enable;

	entry.data.acl_filter.parameter_mask1 = param->param1_mask;

	switch (param->param1_type) {
	case GPE_ACL_PARAM1_NONE:
		entry.data.acl_filter.parameter10 =
			entry.data.acl_filter.parameter11 =
			entry.data.acl_filter.parameter12 =
			entry.data.acl_filter.parameter13 = 0;
		break;
	case GPE_ACL_PARAM1_IPV4_DA:
	case GPE_ACL_PARAM1_IPV4_SA:
		entry.data.acl_filter.parameter10 =
			(param->param1[0] << 24) |
			(param->param1[1] << 16) |
			(param->param1[2] << 8) |
			param->param1[3];
		entry.data.acl_filter.parameter10 &= param->param1_mask;
		entry.data.acl_filter.parameter11 = 0;
		entry.data.acl_filter.parameter12 = 0;
		entry.data.acl_filter.parameter13 = 0;
		break;
	case GPE_ACL_PARAM1_IPV4_PROT:
		entry.data.acl_filter.parameter10 = param->param1[0];
		entry.data.acl_filter.parameter11 = 0;
		entry.data.acl_filter.parameter12 = 0;
		entry.data.acl_filter.parameter13 = 0;
		break;
	case GPE_ACL_PARAM1_IPV6_SA:
	case GPE_ACL_PARAM1_IPV6_DA:
		entry.data.acl_filter.parameter13 =
			(param->param1[0] << 24) |
			(param->param1[1] << 16) |
			(param->param1[2] << 8) |
			param->param1[3];
		entry.data.acl_filter.parameter12 =
			(param->param1[4] << 24) |
			(param->param1[5] << 16) |
			(param->param1[6] << 8) |
			param->param1[7];
		entry.data.acl_filter.parameter11 =
			(param->param1[8] << 24) |
			(param->param1[9] << 16) |
			(param->param1[10] << 8) |
			param->param1[11];
		entry.data.acl_filter.parameter10 =
			(param->param1[12] << 24) |
			(param->param1[13] << 16) |
			(param->param1[14] << 8) |
			param->param1[15];
		break;
	default:
		return GPE_STATUS_VALUE_RANGE_ERR;
	}

	switch (param->param2_type) {
	case GPE_ACL_PARAM2_NONE:
		entry.data.acl_filter.parameter200 =
			entry.data.acl_filter.parameter201 =
			entry.data.acl_filter.parameter21 = 0;
		break;
	case GPE_ACL_PARAM2_MAC_SA:
	case GPE_ACL_PARAM2_MAC_DA:
		entry.data.acl_filter.parameter21 =
			(param->param2[0] << 8) |
			param->param2[1];
		entry.data.acl_filter.parameter200 =
			(param->param2[2] << 24) |
			(param->param2[3] << 16) |
			(param->param2[4] << 8) |
			param->param2[5];
		entry.data.acl_filter.parameter201 = 0;
		break;
	case GPE_ACL_PARAM2_ETHERTYPE:
		entry.data.acl_filter.parameter200 =
			(param->param2[0] << 24) |
			(param->param2[1] << 16) |
			(param->param2[2] << 8) |
			param->param2[3];
		entry.data.acl_filter.parameter201 = 0;
		entry.data.acl_filter.parameter21 = 0;
		break;
	case GPE_ACL_PARAM2_TCP_SP:
	case GPE_ACL_PARAM2_TCP_DP:
	case GPE_ACL_PARAM2_UDP_SP:
	case GPE_ACL_PARAM2_UDP_DP:
	case GPE_ACL_PARAM2_TCP_UDP_SP:
	case GPE_ACL_PARAM2_TCP_UDP_DP:
		entry.data.acl_filter.parameter200 = 0;
		entry.data.acl_filter.parameter201 =
			(param->param2[0] << 8) |
			param->param2[1];

		entry.data.acl_filter.parameter21 = 0;
		break;
	default:
		return GPE_STATUS_VALUE_RANGE_ERR;
	}

	return gpe_table_entry_set(p_dev, &entry);
}

enum onu_errorcode
gpe_acl_table_entry_get(struct onu_device *p_dev,
			const struct gpe_acl_table_entry_idx *in,
			struct gpe_acl_table_entry *out)
{
	struct gpe_table table;
	struct gpe_table_entry entry;
	enum onu_errorcode ret;
	int cfg = -1;
	uint32_t i;

	if (!is_falcon_chip_a1x())
		return ONU_STATUS_CHIP_NOT_SUPPORTED;

	out->acl_filter_index = in->acl_filter_index;

	if (in->acl_filter_index >= ONU_GPE_ACL_FILTER_TABLE_SIZE)
		return GPE_STATUS_VALUE_RANGE_ERR;

	table.id = ONU_GPE_ACL_FILTER_TABLE_ID;
	table.instance = 1;
	table.index = in->acl_filter_index;

	ret = gpe_table_entry_get(p_dev, &table, &entry);
	if (ret != ONU_STATUS_OK)
		return ret;

	for (i = 0; i < ARRAY_SIZE(acl_transformation); i++) {
		if (entry.data.acl_filter.layer2_disable !=
		    acl_transformation[i].layer2_disable ||
		    entry.data.acl_filter.layer3_disable !=
		    acl_transformation[i].layer3_disable ||
		    entry.data.acl_filter.layer4_disable !=
		    acl_transformation[i].layer4_disable ||
		    entry.data.acl_filter.layer2_compare !=
		    acl_transformation[i].layer2_compare ||
		    entry.data.acl_filter.layer2_mac_address_compare !=
		    acl_transformation[i].layer2_mac_address_compare ||
		    entry.data.acl_filter.layer3_compare !=
		    acl_transformation[i].layer3_compare ||
		    entry.data.acl_filter.layer3_ip_address_compare !=
		    acl_transformation[i].layer3_ip_address_compare ||
		    entry.data.acl_filter.layer4_port_compare !=
		    acl_transformation[i].layer4_port_compare ||
		    entry.data.acl_filter.layer4_tcp_enable !=
		    acl_transformation[i].layer4_tcp_enable ||
		    entry.data.acl_filter.layer4_udp_enable !=
		    acl_transformation[i].layer4_udp_enable)
			continue;

		cfg = i;

		acl_transformation[cfg].layer2_disable =
			entry.data.acl_filter.layer2_disable;
		acl_transformation[cfg].layer3_disable =
			entry.data.acl_filter.layer3_disable;
		acl_transformation[cfg].layer4_disable =
			entry.data.acl_filter.layer4_disable;
		acl_transformation[cfg].layer2_compare =
			entry.data.acl_filter.layer2_compare;
		acl_transformation[cfg].layer2_mac_address_compare =
			entry.data.acl_filter.layer2_mac_address_compare;
		acl_transformation[cfg].layer3_compare =
			entry.data.acl_filter.layer3_compare;
		acl_transformation[cfg].layer3_ip_address_compare =
			entry.data.acl_filter.layer3_ip_address_compare;
		acl_transformation[cfg].layer4_port_compare =
			entry.data.acl_filter.layer4_port_compare;
		acl_transformation[cfg].layer4_tcp_enable =
			entry.data.acl_filter.layer4_tcp_enable;
		acl_transformation[cfg].layer4_udp_enable =
			entry.data.acl_filter.layer4_udp_enable;

		break;
	}

	if (cfg < 0)
		return ONU_STATUS_ERR;

	out->param1_type = cfg / 10;
	out->param2_type = cfg % 10;

	out->fid = entry.data.acl_filter.fid;
	out->fid_en = entry.data.acl_filter.fid_disable == 0;
	out->ingress_port_enable = entry.data.acl_filter.ingress_port_lan0
		| (entry.data.acl_filter.ingress_port_lan1 << 1)
		| (entry.data.acl_filter.ingress_port_lan2 << 2)
		| (entry.data.acl_filter.ingress_port_lan3 << 3);
	out->last_entry = entry.data.acl_filter.end;

	memset(out->param1, 0, sizeof(out->param1));

	switch (out->param1_type) {
	case GPE_ACL_PARAM1_NONE:
		break;
	case GPE_ACL_PARAM1_IPV4_DA:
	case GPE_ACL_PARAM1_IPV4_SA:
		out->param1[0] = get_val(entry.data.acl_filter.parameter10,
					 0xFF000000, 24);
		out->param1[1] = get_val(entry.data.acl_filter.parameter10,
					 0x00FF0000, 16);
		out->param1[2] = get_val(entry.data.acl_filter.parameter10,
					 0x0000FF00, 8);
		out->param1[3] = get_val(entry.data.acl_filter.parameter10,
					 0x000000FF, 0);
		break;
	case GPE_ACL_PARAM1_IPV4_PROT:
		out->param1[0] = entry.data.acl_filter.parameter10;
		break;
	case GPE_ACL_PARAM1_IPV6_SA:
	case GPE_ACL_PARAM1_IPV6_DA:
		out->param1[0] = get_val(entry.data.acl_filter.parameter13,
					 0xFF000000, 24);
		out->param1[1] = get_val(entry.data.acl_filter.parameter13,
					 0x00FF0000, 16);
		out->param1[2] = get_val(entry.data.acl_filter.parameter13,
					 0x0000FF00, 8);
		out->param1[3] = get_val(entry.data.acl_filter.parameter13,
					 0x000000FF, 0);

		out->param1[4] = get_val(entry.data.acl_filter.parameter12,
					 0xFF000000, 24);
		out->param1[5] = get_val(entry.data.acl_filter.parameter12,
					 0x00FF0000, 16);
		out->param1[6] = get_val(entry.data.acl_filter.parameter12,
					 0x0000FF00, 8);
		out->param1[7] = get_val(entry.data.acl_filter.parameter12,
					 0x000000FF, 0);

		out->param1[8] = get_val(entry.data.acl_filter.parameter11,
					 0xFF000000, 24);
		out->param1[9] = get_val(entry.data.acl_filter.parameter11,
					 0x00FF0000, 16);
		out->param1[10] = get_val(entry.data.acl_filter.parameter11,
					  0x0000FF00, 8);
		out->param1[11] = get_val(entry.data.acl_filter.parameter11,
					  0x000000FF, 0);

		out->param1[12] = get_val(entry.data.acl_filter.parameter10,
					  0xFF000000, 24);
		out->param1[13] = get_val(entry.data.acl_filter.parameter10,
					  0x00FF0000, 16);
		out->param1[14] = get_val(entry.data.acl_filter.parameter10,
					  0x0000FF00, 8);
		out->param1[15] = get_val(entry.data.acl_filter.parameter10,
					  0x000000FF, 0);

		break;
	}

	memset(out->param2, 0, sizeof(out->param2));

	switch (out->param2_type) {
	case GPE_ACL_PARAM2_NONE:
		break;
	case GPE_ACL_PARAM2_MAC_SA:
	case GPE_ACL_PARAM2_MAC_DA:
		out->param2[0] = get_val(entry.data.acl_filter.parameter21,
					 0x0000FF00, 8);
		out->param2[1] = get_val(entry.data.acl_filter.parameter21,
					 0x000000FF, 0);

		out->param2[2] = get_val(entry.data.acl_filter.parameter200,
					 0xFF000000, 24);
		out->param2[3] = get_val(entry.data.acl_filter.parameter200,
					 0x00FF0000, 16);
		out->param2[4] = get_val(entry.data.acl_filter.parameter200,
					 0x0000FF00, 8);
		out->param2[5] = get_val(entry.data.acl_filter.parameter200,
					 0x000000FF, 0);

		break;
	case GPE_ACL_PARAM2_ETHERTYPE:
		out->param2[0] = get_val(entry.data.acl_filter.parameter200,
					 0xFF000000, 24);
		out->param2[1] = get_val(entry.data.acl_filter.parameter200,
					 0x00FF0000, 16);
		out->param2[2] = get_val(entry.data.acl_filter.parameter200,
					 0x0000FF00, 8);
		out->param2[3] = get_val(entry.data.acl_filter.parameter200,
					 0x000000FF, 0);
		break;
	case GPE_ACL_PARAM2_TCP_SP:
	case GPE_ACL_PARAM2_TCP_DP:
	case GPE_ACL_PARAM2_UDP_SP:
	case GPE_ACL_PARAM2_UDP_DP:
	case GPE_ACL_PARAM2_TCP_UDP_SP:
	case GPE_ACL_PARAM2_TCP_UDP_DP:
		out->param2[0] = get_val(entry.data.acl_filter.parameter201,
					 0x0000FF00, 8);
		out->param2[1] = get_val(entry.data.acl_filter.parameter201,
					 0x000000FF, 0);
		break;
	}

	out->param1_mask = entry.data.acl_filter.parameter_mask1;

	return ONU_STATUS_OK;
}

enum onu_errorcode
gpe_acl_table_entry_delete(struct onu_device *p_dev,
			   const struct gpe_acl_table_entry_idx *param)
{
	struct gpe_table table;
	struct gpe_table_entry entry;
	enum onu_errorcode ret;
	int i;

	if (!is_falcon_chip_a1x())
		return ONU_STATUS_CHIP_NOT_SUPPORTED;

	table.id = ONU_GPE_ACL_FILTER_TABLE_ID;
	table.instance = 1;
	table.index = param->acl_filter_index;

	if (table.index >= ONU_GPE_ACL_FILTER_TABLE_SIZE)
		return GPE_STATUS_VALUE_RANGE_ERR;

	ret = gpe_table_entry_get(p_dev, &table, &entry);
	if (ret != ONU_STATUS_OK)
		return ret;

	entry.data.acl_filter.valid = 0;

	ret = gpe_table_entry_set(p_dev, &entry);
	if (ret != ONU_STATUS_OK)
		return ret;

	if (entry.data.acl_filter.end == 0)
		return ONU_STATUS_OK;

	/* remove entry with end == 1 */

	if (param->acl_filter_index == 0)
		return ONU_STATUS_OK;

	for (i = param->acl_filter_index - 1; i >= 0; i--) {
		table.id = ONU_GPE_ACL_FILTER_TABLE_ID;
		table.instance = 1;
		table.index = (uint8_t)i;

		ret = gpe_table_entry_get(p_dev, &table, &entry);
		if (ret != ONU_STATUS_OK)
			return ret;

		if (entry.data.acl_filter.valid == 0)
			continue;

		entry.data.acl_filter.end = 1;

		return gpe_table_entry_set(p_dev, &entry);
	}

	return ONU_STATUS_OK;
}

#if defined(INCLUDE_DUMP)

#ifdef LINUX
#include <asm/unaligned.h>
#endif

static const char *type[] = {
	"ARRAY",
	"VARRAY",
	"LIST",
	"LLIST",
	"HASH",
	"ILLEGAL",
	"ILLEGAL",
	"ILLEGAL"
};

static const char *coptype[] = {
	"FID",
	"FWD",
	"TAG",
	"TBL",
	"MSF",
	"EXT",
	"NONE",
	"NONE",
	"NONE"
};

void gpe_table_dump(struct seq_file *s)
{
	struct gpe_table_entry table0;
	uint16_t cnt;
	uint32_t data[8]; /* max entry width is 256 bit */
	enum onu_errorcode ret;
	uint16_t cop_id;
	uint32_t tableid;

	char *tabletype;
	uint32_t size;
	uint32_t entry_width;
	uint32_t key_size;
	uint32_t counter;
	uint32_t base;
	uint32_t data_mask;
	uint32_t aux_v;
	uint32_t aux;
	uint32_t func;

	seq_printf(s, "TSE: Table: Type: Size: Entry: Key: Counter: Base: "
		      "Data Mask: AUXv: AUX: Func: Name:\n");

	for (cop_id = 0; cop_id < 6; cop_id++) {
		seq_printf(s, "----------------------------------------------"
			      "----------------------------------------------"
			      "-------------\n");

		for (cnt = 1; cnt < 8; cnt++) {
			table0.id = 0;
			table0.instance = cop_id;

			for (tableid = 0; tableid <= 2; tableid++) {
				table0.index = 0x000 + (cnt*4) + tableid;
				ret		= cop_table0_read(&table0);
				if (ret) /* stop upon error while data read */
					break;
				data[tableid] 	= table0.data.message.data[0];
			}

			data_mask = (data[0] >> 16) & 0xFFFF;
			/* FIXME: why not used? */
			key_size = onu_gpe_cop_keysize[(data[0] >> 8) & 0x7];
			entry_width =
				onu_gpe_cop_entrysize[(data[0] >> 6) & 0x3];
			func = (data[0] >>  3) & 0x7;
			tabletype = (char *) type[(data[0] >>  0) & 0x7];

			size	= (data[1] >> 16) & 0xFFFF;
			/* FIXME: why not used? */
			base	= (data[1] >>  0) & 0xFFFF;

			aux_v	= (data[2] >> 31) & 0x1;
			counter	= (data[2] >> 16) & 0x3FF;
			aux 	= (data[2] >>  0) & 0xFFFF;

			if (size > 0) {
				seq_printf(s, "%4i %2i %6s "
					      "%6i "
					      "%6i "
					      "%6i "
					      "%6i  "
					      "0x%04x "
					      "0x%04x %6i 0x%04x %6i "
					      "%s\n",
					cop_id, cnt, tabletype,
					cop_tbl_cfg[cop_id*8 + cnt].size,
					cop_tbl_cfg[cop_id*8 + cnt].entry_width,
					cop_tbl_cfg[cop_id*8 + cnt].key_len,
					counter,
					cop_tbl_cfg[cop_id*8 + cnt].base,
					data_mask, aux_v, aux, func,
					cop_tbl_cfg[cop_id*8 + cnt].name);
			}
		}
	}

	if (ret)
		seq_printf(s,
			   "there was an error during table0 register read \n");
}

struct table_meta_info {
	uint32_t cop_id;
	uint32_t tableid;
	uint32_t tabletype;
	uint32_t entry_id;
	uint32_t entry_width;
	uint32_t func;
	uint32_t data_mask;
	uint32_t wordsize;
	uint32_t key_size;
	uint32_t counter;
	uint32_t base;
	uint32_t size;
	uint32_t aux;
	uint32_t aux_v;
};

STATIC void gpe_default_cop_table_entry(struct seq_file *s,
					const uint16_t cnt,
					struct table_meta_info *m,
					uint32_t *data)
{
	int16_t msg;
	uint32_t next;

#ifndef ONU_COP_FLIP_DUMPS
	switch (m->key_size) {
			case 16:
				seq_printf(s, "%04x", (data[0] >> 16) & 0xFFFF);
				seq_printf(s, "(%04x) ", data[0] & 0xFFFF);
			for (msg = 1; msg < m->wordsize; msg++)
					seq_printf(s, "%08x ", data[msg]);
				break;
			case 32:
				seq_printf(s, "(%08x) ", data[0]);
			for (msg = 1; msg < m->wordsize; msg++)
					seq_printf(s, "%08x ", data[msg]);
				break;
			case 64:
				seq_printf(s, "(%08x ", data[0]);
				seq_printf(s, "%08x) ", data[1]);
			for (msg = 2; msg < m->wordsize; msg++)
					seq_printf(s, "%08x ", data[msg]);
				break;
			case 96:
				for (msg = 0; msg < 2; msg++)
					seq_printf(s, "%08x ", data[msg]);
				break;
			case 128:
				seq_printf(s, "(%08x ", data[0]);
				seq_printf(s, "%08x ", data[1]);
				seq_printf(s, "%08x ", data[2]);
				seq_printf(s, "%08x) ", data[3]);
			for (msg = 4; msg < m->wordsize; msg++)
					seq_printf(s, "%08x ", data[msg]);
				break;
			case 144:
				seq_printf(s, "(%08x ", data[0]);
				seq_printf(s, "%08x ", data[1]);
				seq_printf(s, "%08x ", data[2]);
				seq_printf(s, "%08x) ", data[3]);
				seq_printf(s, "%04x", (data[4] >> 16) & 0xFFFF);
				seq_printf(s, "(%04x) ", data[4] & 0xFFFF);
			for (msg = 5; msg < m->wordsize; msg++)
					seq_printf(s, "%08x ", data[msg]);
				break;
			case 160:
				seq_printf(s, "(%08x ", data[0]);
				seq_printf(s, "%08x ", data[1]);
				seq_printf(s, "%08x ", data[2]);
				seq_printf(s, "%08x ", data[3]);
				seq_printf(s, "%08x) ", data[4]);
			for (msg = 5; msg < m->wordsize; msg++)
					seq_printf(s, "%08x ", data[msg]);
				break;

			default:
			for (msg = 0; msg < m->wordsize; msg++)
					seq_printf(s, "%08x ", data[msg]);
				break;
		}
#else
	switch (m->key_size) {
			case 16:
			for (msg = m->wordsize-1; msg > 0; msg--)
					seq_printf(s, "%08x ", data[msg]);
				seq_printf(s, "%04x", (data[0] >> 16) & 0xFFFF);
				seq_printf(s, "(%04x) ", data[0] & 0xFFFF);
				break;
			case 32:
			for (msg = m->wordsize-1; msg > 0; msg--)
					seq_printf(s, "%08x ", data[msg]);
				seq_printf(s, "(%08x) ", data[0]);
				break;
			case 64:
			for (msg = m->wordsize-1; msg > 1; msg--)
					seq_printf(s, "%08x ", data[msg]);
				seq_printf(s, "(%08x ", data[1]);
				seq_printf(s, "%08x) ", data[0]);
				break;
			case 96:
				for (msg = 1; msg >= 0; msg--)
					seq_printf(s, "%08x ", data[msg]);
				break;
			case 128:
			for (msg = m->wordsize-1; msg > 3; msg--)
					seq_printf(s, "%08x ", data[msg]);
				seq_printf(s, "(%08x ", data[3]);
				seq_printf(s, "%08x ", data[2]);
				seq_printf(s, "%08x ", data[1]);
				seq_printf(s, "%08x) ", data[0]);
				break;
			case 144:
			for (msg = m->wordsize-1; msg > 4; msg--)
					seq_printf(s, "%08x ", data[msg]);
				seq_printf(s, "(%04x) ", data[4] & 0xFFFF);
				seq_printf(s, "%04x", (data[4] >> 16) & 0xFFFF);
				seq_printf(s, "(%08x ", data[3]);
				seq_printf(s, "%08x ", data[2]);
				seq_printf(s, "%08x ", data[1]);
				seq_printf(s, "%08x) ", data[0]);
				break;
			case 160:
			for (msg = m->wordsize-1; msg > 4; msg--)
					seq_printf(s, "%08x ", data[msg]);
				seq_printf(s, "(%08x ", data[4]);
				seq_printf(s, "%08x ", data[3]);
				seq_printf(s, "%08x ", data[2]);
				seq_printf(s, "%08x ", data[1]);
				seq_printf(s, "%08x) ", data[0]);
				break;

			default:
			for (msg = m->wordsize-1; msg >= 0; msg--)
					seq_printf(s, "%08x ", data[msg]);
				break;
		}
	msg = m->wordsize;
#endif
	if (m->tabletype == ONU_GPE_COP_LLIST) {

		next = (data[msg-1] >> 16) & 0x3FFF;
		next = (next - m->base) / m->entry_width;

		if ((data[msg-1] & (1<<30)) == 0) {
			if (next >= m->size)
				seq_printf(s, "->[%i (ILLEGAL)] ", next);
			else
				seq_printf(s, "->[%i] ", next);
		}

		if ((m->base + cnt * m->entry_width) == m->aux)
			seq_printf(s, "<-AUX ");
	}

	if (m->entry_id == ONU_GPE_VLAN_RULE_TABLE_ID) {
		if (data[msg-1] & (1<<29))
			seq_printf(s, "DEF ");
	}

	if (m->tabletype == ONU_GPE_COP_VARRAY ||
	    m->tabletype == ONU_GPE_COP_LIST   ||
	    m->tabletype == ONU_GPE_COP_LLIST  ||
	    m->tabletype == ONU_GPE_COP_HASH ) {

		if (data[msg-1] & (1<<31))
			seq_printf(s, "V ");
	}

	if (m->tabletype == ONU_GPE_COP_LIST ||
	    m->tabletype == ONU_GPE_COP_LLIST) {

		if (data[msg-1] & (1<<30))
			seq_printf(s, "E ");
	}

	seq_printf(s, "\n");
}

STATIC void cprintf(struct seq_file *s, const char *fmt, const uint32_t val)
{
	if(val)
		seq_printf(s, fmt, val);
	else
		seq_printf(s, "; ");
}

STATIC void cprintfe(struct seq_file *s, const char *fmt,
		     const uint8_t p, const uint32_t val)
{
	if (val) {
		seq_printf(s, fmt, val);
	} else {
		switch(p) {
		case 4: seq_printf(s, ";    "); break;
		case 3: seq_printf(s, ";   "); break;
		case 2: seq_printf(s, ";  "); break;
		default: seq_printf(s, "; "); break;
		}
	}
}

STATIC void gpe_custom_ext_vlan_table_entry(struct seq_file *s,
					    const uint32_t no,
					    struct table_meta_info *meta,
					    uint32_t *data)
{
	struct gpe_extended_vlan_table entry;

	if (data == NULL) {
		seq_printf(s, "no;");
		seq_printf(s, "out tpid;");
		seq_printf(s, "in tpid;");
		seq_printf(s, "vlan rule pointer;");
		seq_printf(s, "dscp pointer\n");
		return;
	}

	memcpy(&entry, data, sizeof(entry));

	seq_printf(s, "%d", no);
	cprintf(s, ";0x%04x", entry.output_tpid);
	cprintf(s, ";0x%04x", entry.input_tpid);
	cprintfe(s, ";%4d", 4, entry.vlan_rule_table_pointer);
	cprintf(s, ";%d", entry.dscp_table_pointer);
	seq_printf(s, "\n");
}

STATIC void gpe_custom_ext_vlan_rule_table_entry(struct seq_file *s,
						 const uint32_t no,
						 struct table_meta_info *meta,
						 uint32_t *data)
{
	struct gpe_vlan_rule_table entry;

	if (data == NULL) {
		seq_printf(s, ";;;enable;;;ethertype filter;;;;;outer;;;;;;;"
					 "inner;;;;;;\n");
		seq_printf(s, "no;");
		seq_printf(s, "end;");
		seq_printf(s, "def;");
		seq_printf(s, "two;");
		seq_printf(s, "one;");
		seq_printf(s, "zero;");
		seq_printf(s, "5;");
		seq_printf(s, "4;");
		seq_printf(s, "3;");
		seq_printf(s, "2;");
		seq_printf(s, "1;");
		seq_printf(s, "de enable;");
		seq_printf(s, "de filter;");
		seq_printf(s, "input tpid enable;");
		seq_printf(s, "vid enable;");
		seq_printf(s, "vid filter;");
		seq_printf(s, "priority enable;");
		seq_printf(s, "priority filter;");
		seq_printf(s, "de enable;");
		seq_printf(s, "de filter;");
		seq_printf(s, "input tpid enable;");
		seq_printf(s, "vid enable;");
		seq_printf(s, "vid filter;");
		seq_printf(s, "priority enable;");
		seq_printf(s, "priority filter\n");
		return;
	}

	memcpy(&entry, data, sizeof(entry));

	if (entry.valid == 0)
		return;

	seq_printf(s, "%d", no);
	cprintf(s, ";%d", entry.end);
	cprintf(s, ";%d", entry.def);
	cprintf(s, ";%d", entry.two_enable);
	cprintf(s, ";%d", entry.one_enable);
	cprintf(s, ";%d", entry.zero_enable);
	cprintf(s, ";%d", entry.ethertype_filter5_enable);
	cprintf(s, ";%d", entry.ethertype_filter4_enable);
	cprintf(s, ";%d", entry.ethertype_filter3_enable);
	cprintf(s, ";%d", entry.ethertype_filter2_enable);
	cprintf(s, ";%d", entry.ethertype_filter1_enable);
	cprintf(s, ";%d", entry.outer_de_enable);
	cprintf(s, ";%d", entry.outer_de_filter);
	cprintf(s, ";%d", entry.outer_input_tpid_enable);
	cprintf(s, ";%d", entry.outer_vid_enable);
	cprintfe(s, ";%4d", 4, entry.outer_vid_filter);
	cprintf(s, ";%d", entry.outer_priority_enable);
	cprintf(s, ";%d", entry.outer_priority_filter);
	cprintf(s, ";%d", entry.inner_de_enable);
	cprintf(s, ";%d", entry.inner_de_filter);
	cprintf(s, ";%d", entry.inner_input_tpid_enable);
	cprintf(s, ";%d", entry.inner_vid_enable);
	cprintfe(s, ";%4d", 4, entry.inner_vid_filter);
	cprintf(s, ";%d", entry.inner_priority_enable);
	cprintf(s, ";%d", entry.inner_priority_filter);
	seq_printf(s, "\n");
}

STATIC void
gpe_custom_ext_vlan_treatment_table_entry(struct seq_file *s,
					  const uint32_t no,
					  struct table_meta_info *meta,
					  uint32_t *data)
{
	struct gpe_vlan_treatment_table entry;

	if (data == NULL) {
		seq_printf(s, ";;;;tagb;tagb;tagb;taga;taga;taga\n");
		seq_printf(s, "no;");
		seq_printf(s, "inner not generate;");
		seq_printf(s, "outer not generate;");
		seq_printf(s, "discard enable;");
		seq_printf(s, "tpid;");
		seq_printf(s, "vid;");
		seq_printf(s, "treatment;");
		seq_printf(s, "tpid;");
		seq_printf(s, "vid;");
		seq_printf(s, "treatment\n");
		return;
	}

	memcpy(&entry, data, sizeof(entry));

	if (entry.valid == 0)
		return;

	seq_printf(s, "%d", no);
	cprintf(s, ";%d", entry.inner_not_generate);
	cprintf(s, ";%d", entry.outer_not_generate);
	cprintf(s, ";%d", entry.discard_enable);
	cprintf(s, ";%d", entry.tagb_tpid_treatment);
	cprintfe(s, ";%4d", 4, entry.tagb_vid_treatment);
	cprintfe(s, ";%2d", 2, entry.tagb_treatment);
	cprintf(s, ";%d", entry.taga_tpid_treatment);
	cprintfe(s, ";%4d", 4, entry.taga_vid_treatment);
	cprintfe(s, ";%2d", 2, entry.taga_treatment);
	seq_printf(s, "\n");
}

STATIC void gpe_custom_ext_dsgem_table_entry(struct seq_file *s,
					     const uint32_t no,
					     struct table_meta_info *meta,
					     uint32_t *data)
{
	struct gpe_ds_gem_port_table entry;

	if (data == NULL) {
		seq_printf(s, "no;");
		seq_printf(s, "bridge port index0;1;2;3;4;5;6;7;");
		seq_printf(s, "dscp_table_pointer;");
		seq_printf(s, "ingress color marking;");
		seq_printf(s, "ext vlan enable;");
		seq_printf(s, "ext vlan index;");
		seq_printf(s, "ext vlan ingress mode;");
		seq_printf(s, "gem mac swap enable;");
		seq_printf(s, "gem loopback enable;");
		seq_printf(s, "fid mask pcpi;");
		seq_printf(s, "fid mask pcpo;");
		seq_printf(s, "fid mask vidi;");
		seq_printf(s, "fid mask vido;");
		seq_printf(s, "pppoe enable;");
		seq_printf(s, "napt enable;");
		seq_printf(s, "gem port type;");
		seq_printf(s, "lan port index;");
		seq_printf(s, "max bridge index;");
		seq_printf(s, "interworking option;");
		seq_printf(s, "queue selection mode;");
		seq_printf(s, "egress queue offset;");
		seq_printf(s, "exception_profile;");
		seq_printf(s, "ds_gem_meter_enable;");
		seq_printf(s, "ds_gem_meter_id\n");
		return;
	}

	memcpy(&entry, data, sizeof(entry));

	if (entry.valid == 0)
		return;

	seq_printf(s, "%d", no);
	cprintf(s, ";%d", entry.bridge_port_index0);
	cprintf(s, ";%d", entry.bridge_port_index1);
	cprintf(s, ";%d", entry.bridge_port_index2);
	cprintf(s, ";%d", entry.bridge_port_index3);
	cprintf(s, ";%d", entry.bridge_port_index4);
	cprintf(s, ";%d", entry.bridge_port_index5);
	cprintf(s, ";%d", entry.bridge_port_index6);
	cprintf(s, ";%d", entry.bridge_port_index7);
	cprintf(s, ";%d", entry.dscp_table_pointer);
	cprintf(s, ";%d", entry.ingress_color_marking);
	cprintf(s, ";%d", entry.ext_vlan_enable);
	cprintf(s, ";%d", entry.ext_vlan_index);
	cprintf(s, ";%d", entry.ext_vlan_ingress_mode);
	cprintf(s, ";%d", entry.gem_mac_swap_enable);
	cprintf(s, ";%d", entry.gem_loopback_enable);
	cprintf(s, ";%d", entry.fid_mask_pcpi);
	cprintf(s, ";%d", entry.fid_mask_pcpo);
	cprintf(s, ";%d", entry.fid_mask_vidi);
	cprintf(s, ";%d", entry.fid_mask_vido);
	cprintf(s, ";%d", entry.pppoe_enable);
	cprintf(s, ";%d", entry.napt_enable);
	cprintf(s, ";%d", entry.gem_port_type);
	cprintf(s, ";%d", entry.lan_port_index);
	cprintf(s, ";%d", entry.max_bridge_index);
	cprintf(s, ";%d", entry.interworking_option);
	cprintf(s, ";%d", entry.queue_selection_mode);
	cprintf(s, ";%d", entry.egress_queue_offset);
	cprintf(s, ";%d", entry.exception_profile);
	cprintf(s, ";%d", entry.ds_gem_meter_enable);
	cprintf(s, ";%d", entry.ds_gem_meter_id);
	seq_printf(s, "\n");
}

STATIC void gpe_custom_ext_usgem_table_entry(struct seq_file *s,
					     const uint32_t no,
					     struct table_meta_info *meta,
					     uint32_t *data)
{
	struct gpe_us_gem_port_table entry;

	if (data == NULL) {
		seq_printf(s, "no;");
		seq_printf(s, "dscp_table_pointer;");
		seq_printf(s, "queue marking mode;");
		seq_printf(s, "ext vlan egress mode;");
		seq_printf(s, "ext vlan incremental enable;");
		seq_printf(s, "egress color marking;");
		seq_printf(s, "ext vlan enable;");
		seq_printf(s, "ext vlan index;");
		seq_printf(s, "egress queue index;");
		seq_printf(s, "exception_profile\n");
		return;
	}

	memcpy(&entry, data, sizeof(entry));

	if (entry.valid == 0)
		return;

	seq_printf(s, "%d", no);
	cprintf(s, ";%d", entry.dscp_table_pointer);
	cprintf(s, ";%d", entry.queue_marking_mode);
	cprintf(s, ";%d", entry.ext_vlan_egress_mode);
	cprintf(s, ";%d", entry.ext_vlan_incremental_enable);
	cprintf(s, ";%d", entry.egress_color_marking);
	cprintf(s, ";%d", entry.ext_vlan_enable);
	cprintf(s, ";%d", entry.ext_vlan_index);
	cprintf(s, ";%d", entry.egress_queue_index);
	cprintf(s, ";%d", entry.exception_profile);
	seq_printf(s, "\n");
}

STATIC void gpe_custom_tagging_filter_table_entry(struct seq_file *s,
						  const uint32_t no,
						  struct table_meta_info *meta,
						  uint32_t *data)
{
	struct gpe_tagging_filter_table entry;

	if (data == NULL) {
		seq_printf(s, "no;");
		seq_printf(s, "pass_on_match_enable;");
		seq_printf(s, "tagged_drop_enable;");
		seq_printf(s, "tagged_pass_enable;");
		seq_printf(s, "untagged_drop_enable;");
		seq_printf(s, "tci_mask;");
		seq_printf(s, "vlan_table_index\n");
		return;
	}

	memcpy(&entry, data, sizeof(entry));

	if (entry.valid == 0)
		return;

	seq_printf(s, "%d", no);
	cprintf(s, ";%d", entry.pass_on_match_enable);
	cprintf(s, ";%d", entry.tagged_drop_enable);
	cprintf(s, ";%d", entry.tagged_pass_enable);
	cprintf(s, ";%d", entry.untagged_drop_enable);
	cprintf(s, ";0x%04x", entry.tci_mask);
	cprintf(s, ";0x%04x", entry.vlan_table_index);
	seq_printf(s, "\n");
}

STATIC void gpe_custom_shortfwdmac_table_entry(struct seq_file *s,
					       const uint32_t no,
					       struct table_meta_info *meta,
					       uint32_t *data)
{
	struct gpe_short_fwd_table_mac entry;

	if (data == NULL) {
		seq_printf(s, "no;");
		seq_printf(s, "mac_address;");
		seq_printf(s, "bridge_index;");
		seq_printf(s, "bridge_port_index;");
		seq_printf(s, "key_code;");
		seq_printf(s, "fid;");
		seq_printf(s, "learning_time_stamp;");
		seq_printf(s, "activity;");
		seq_printf(s, "dynamic_enable;");
		seq_printf(s, "limitation\n");
		return;
	}

	memcpy(&entry, data, sizeof(entry));

	if (entry.valid == 0)
		return;

	if (entry.zero_port_map_indicator == 1)
		return;

	seq_printf(s, "%d", no);
	if (!entry.mac_address_high && !entry.mac_address_low) {
		seq_printf(s, "; ");
	} else {
		seq_printf(s, ";0x%04x%08x",
			   entry.mac_address_high,
			   entry.mac_address_low);
	}
	cprintf(s, ";%d", entry.bridge_index);
	cprintf(s, ";%d", entry.bridge_port_index);
	cprintf(s, ";%d", entry.key_code);
	cprintf(s, ";%d", entry.fid);
	cprintf(s, ";%d", entry.learning_time_stamp);
	cprintf(s, ";%d", entry.activity);
	cprintf(s, ";%d", entry.dynamic_enable);
	cprintf(s, ";%d", entry.limitation);
	seq_printf(s, "\n");
}

STATIC void gpe_custom_shortfwdmacmc_table_entry(struct seq_file *s,
						 const uint32_t no,
						 struct table_meta_info *meta,
						 uint32_t *data)
{
	struct gpe_short_fwd_table_mac_mc entry;

	if (data == NULL) {
		seq_printf(s, "no;");
		seq_printf(s, "mac_address;");
		seq_printf(s, "bridge_index;");
		seq_printf(s, "port_map;");
		seq_printf(s, "include_enable;");
		seq_printf(s, "key_code;");
		seq_printf(s, "fid;");
		seq_printf(s, "dynamic_enable;");
		seq_printf(s, "msf_enable\n");
		return;
	}

	memcpy(&entry, data, sizeof(entry));

	if (entry.valid == 0)
		return;

	if (entry.one_port_map_indicator == 0)
		return;

	seq_printf(s, "%d", no);
	if (!entry.mac_address_high && !entry.mac_address_low) {
		seq_printf(s, "; ");
	} else {
		seq_printf(s, ";0x%04x%08x",
			   entry.mac_address_high,
			   entry.mac_address_low);
	}
	cprintf(s, ";%d", entry.bridge_index);
	cprintf(s, ";0x%x", entry.port_map);
	cprintf(s, ";0x%x", entry.include_enable);
	cprintf(s, ";%d", entry.key_code);
	cprintf(s, ";%d", entry.fid);
	cprintf(s, ";%d", entry.dynamic_enable);
	cprintf(s, ";%d", entry.msf_enable);
	seq_printf(s, "\n");
}

STATIC void gpe_custom_shortfwdipv4_table_entry(struct seq_file *s,
						 const uint32_t no,
						 struct table_meta_info *meta,
						 uint32_t *data)
{
	struct gpe_short_fwd_table_ipv4 entry;

	if (data == NULL) {
		seq_printf(s, "no;");
		seq_printf(s, "bridge_index;");
		seq_printf(s, "bridge_port_index;");
		seq_printf(s, "ip_address;");
		seq_printf(s, "fid;");
		seq_printf(s, "key_code;");
		seq_printf(s, "encapsulation_index;");
		seq_printf(s, "activity\n");
		return;
	}

	memcpy(&entry, data, sizeof(entry));

	if (entry.valid == 0)
		return;

	if (entry.zero_dynamic_enable == 1)
		return;

	if (entry.zero_port_map_indicator == 1)
		return;

	if (entry.zero_limitation == 1)
		return;

	seq_printf(s, "%d", no);
	cprintf(s, ";%d", entry.bridge_index);
	cprintf(s, ";%d", entry.bridge_port_index);
	cprintf(s, ";0x%08x", entry.ip_address);
	cprintf(s, ";%d", entry.fid);
	cprintf(s, ";%d", entry.key_code);
	cprintf(s, ";%d", entry.encapsulation_index);
	cprintf(s, ";%d", entry.activity);
	seq_printf(s, "\n");
}

STATIC void gpe_custom_shortfwdipv4mc_table_entry(struct seq_file *s,
						 const uint32_t no,
						 struct table_meta_info *meta,
						 uint32_t *data)
{
	struct gpe_short_fwd_table_ipv4_mc entry;

	if (data == NULL) {
		seq_printf(s, "no;");
		seq_printf(s, "bridge_index;");
		seq_printf(s, "ip_address;");
		seq_printf(s, "fid;");
		seq_printf(s, "key_code;");
		seq_printf(s, "port_map;");
		seq_printf(s, "include_enable;");
		seq_printf(s, "msf_enable;");
		seq_printf(s, "igmp;");
		seq_printf(s, "activity\n");
		return;
	}

	memcpy(&entry, data, sizeof(entry));

	if (entry.valid == 0)
		return;

	if (entry.zero_dynamic_enable == 1)
		return;

	if (entry.one_port_map_indicator == 0)
		return;

	if (entry.zero_limitation == 1)
		return;

	seq_printf(s, "%d", no);
	cprintf(s, ";%d", entry.bridge_index);
	cprintf(s, ";0x%08x", entry.ip_address);
	cprintf(s, ";%d", entry.fid);
	cprintf(s, ";%d", entry.key_code);
	cprintf(s, ";0x%02x", entry.port_map);
	cprintf(s, ";0x%02x", entry.include_enable);
	cprintf(s, ";%d", entry.msf_enable);
	cprintf(s, ";%d", entry.igmp);
	cprintf(s, ";%d", entry.activity);
	seq_printf(s, "\n");
}

STATIC void gpe_custom_fidass_table_entry(struct seq_file *s,
						 const uint32_t no,
						 struct table_meta_info *meta,
						 uint32_t *data)
{
	struct gpe_fwd_id_table entry;

	if (data == NULL) {
		seq_printf(s, "no;");
		seq_printf(s, "prio_inner;");
		seq_printf(s, "vid_inner;");
		seq_printf(s, "prio_outer;");
		seq_printf(s, "vid_outer;");
		seq_printf(s, "fid;");
		seq_printf(s, "cross_connect\n");
		return;
	}

	memcpy(&entry, data, sizeof(entry));

	if (entry.valid == 0)
		return;

	seq_printf(s, "%d", no);
	cprintf(s, ";%d", entry.prio_inner);
	cprintf(s, ";%d", entry.vid_inner);
	cprintf(s, ";%d", entry.prio_outer);
	cprintf(s, ";%d", entry.vid_outer);
	cprintf(s, ";%d", entry.fid);
	cprintf(s, ";%d", entry.cross_connect);
	seq_printf(s, "\n");
}

STATIC void gpe_cop_table_display(struct seq_file *s,
				  uint32_t entry_id,
				  void (*custom_dump)(struct seq_file *s,
						      const uint32_t no,
						      struct table_meta_info *m,
						      uint32_t *data))
{
	struct gpe_table_entry entry;
	struct table_meta_info m;
	uint16_t cnt;
	uint32_t data[8];
	enum onu_errorcode ret;
	uint32_t code_ram;
	uint32_t data_ram;
	uint32_t i;
	uint32_t instr;
	uint32_t debug = 0;
#ifdef INCLUDE_COP_DEBUG
	int8_t opcode[256];
#endif
	uint16_t tmp;
	struct onu_control *ctrl = &onu_control[0];

#ifdef INCLUDE_COP_DEBUG
	opcode[0] = 0;
#endif

	/* Global */
	entry.id = entry_id;
	m.cop_id    = GPE_TABLE_COP(entry.id);
	m.tableid  = GPE_TABLE_ID(entry.id);

#ifdef INCLUDE_COP_DEBUG
	/*    one trace might get lost, debugging PE and hardware coprocessor in
	    parallel is not possible */
	debug = cop_debug_get(m.cop_id);
	cop_debug_set(m.cop_id, 0);
#endif

	entry.instance 	= m.cop_id;

	/*
	 TABLEx0 - TABLEx2
	*/

	for (i = 0; i <= 2; i++) {
		entry.index = 0x000 + (m.tableid * 4) + i;
		ret 	    = cop_table0_read(&entry);
		data[i]	    = entry.data.message.data[0];
	}

	m.entry_id = entry_id;
	m.data_mask = (data[0] >> 16) & 0xFFFF;
	m.key_size = onu_gpe_cop_keysize[(data[0] >> 8) & 0x7];
	m.entry_width = onu_gpe_cop_entrysize[(data[0] >> 6) & 0x3];
	m.func = (data[0] >>  3) & 0x7;
	m.tabletype = (data[0] >>  0) & 0x7;

	m.size = (data[1] >> 16) & 0xFFFF;
	m.base = (data[1] >>  0) & 0xFFFF;

	m.aux_v = (data[2] >> 31) & 0x1;
	m.counter = (data[2] >> 16) & 0x3FF;
	m.aux = (data[2] >>  0) & 0xFFFF;

	/* Global*/
	seq_printf(s, "\nName:        %s\n", cop_tbl_cfg[entry.id].name);
	seq_printf(s, "ID:          %d\n", entry_id);

	/*
	 Table Data
	*/
	m.wordsize = cop_table_size_get(m.cop_id, m.tableid);
	if (m.tabletype == ONU_GPE_COP_HASH) {
		m.wordsize = 1;
		m.key_size = 0;
	}

	m.entry_width = m.entry_width / 32;

	/* print header */
	if (custom_dump && raw_mode == 0)
		custom_dump(s, -1, &m, NULL);

	entry.instance 	= 1; /* don't care */
	for (cnt = 0; cnt < m.size; cnt++) {
		if (custom_dump == NULL || raw_mode != 0)
			seq_printf(s, "[%04d]: ", cnt);

		entry.id = entry_id;
		entry.index = cnt;
		ret = TABLE_READ(ctrl, &entry);
		if (ret) /* stop upon error while data read */
			break;

		memcpy(&data, &entry.data, m.wordsize * 4);

		if (custom_dump && raw_mode == 0)
			custom_dump(s, cnt, &m, data);
		else
			gpe_default_cop_table_entry(s, cnt, &m, data);
	}

	if (custom_dump && raw_mode == 0)
		return;

	/* Table */
	seq_printf(s, "\nTable:       %i\n", m.tableid);

	seq_printf(s, " Type:       %s (%i)\n"
				  " Size:       %i\n"
				  " Entry size: %i\n"
				  " Key size:   %i\n"
				  " Counter:    %i\n"
				  " Base:       0x%04x\n\n",
				  type[m.tabletype],
				  m.tabletype,
				  m.size,
				  m.entry_width*32,
				  m.key_size,
				  m.counter,
				  m.base);

	seq_printf(s, " Data Mask:  0x%04x\n"
				  " AUX valid:  %i\n"
				  " AUX:        0x%04x\n\n"
				  " Func:       %i\n",
				  m.data_mask,
				  m.aux_v,
				  m.aux,
				  m.func
				  );

	/* Table.CUSTOM */
	if (m.func == 1) {
		entry.instance 	= m.cop_id;

		/* CUSTOM0-CUSTOM7 */
		for (i = 0; i <= 7; i++) {
			entry.index	= 0x300 + i;
			ret		= cop_table0_read(&entry);
			data[i]		= entry.data.message.data[0];
		}

		seq_printf(s,
					"  XTRUE:     %d\n"
					"  DEF RULE:  %d\n"
					"  TPID:      0x%04x\n",
					(data[0] >>  1) & 1,
					(data[0] >>  0) & 1,
					(data[0] >> 16) & 0xffff
					);

		seq_printf(s,
					"  ETY 1:     0x%04x\n"
					"  ETY 2:     0x%04x\n"
					"  ETY 3:     0x%04x\n"
					"  ETY 4:     0x%04x\n"
					"  ETY 5:     0x%04x (MASK=%04x)\n"
					"  SPARE 1:   0x%04x (MASK=%04x)\n"
					"  SPARE 2:   0x%04x (MASK=%04x)\n",
					data[1] & 0xffff,
					data[2] & 0xffff,
					data[3] & 0xffff,
					data[4] & 0xffff,
					data[5] & 0xffff, (data[5]>>16) & 0xffff,
					data[6] & 0xffff, (data[6]>>16) & 0xffff,
					data[7] & 0xffff, (data[7]>>16) & 0xffff
				);
	}

	/*
	 GLOBAL0-GLOBAL3
	*/
	entry.id = entry_id;
	entry.instance 	= m.cop_id;
	if (is_falcon_chip_a2x())
		tmp = 5;
	else
		tmp = 2;

	for (i = 0; i <= tmp; i++) {
		entry.index = 0x100+i;
		ret 	    = cop_table0_read(&entry);
		data[i]     = entry.data.message.data[0];
	}

	code_ram    = (data[1]>>16) & 0xff;
	data_ram    = (data[1]>> 0) & 0xffff;

	/* COP */
	seq_printf(s, "\nCOP:         %s (%i)\n", coptype[m.cop_id], m.cop_id);
	if (is_falcon_chip_a2x())
		seq_printf(s, " Comp:       0x%08x\n",data[5]);

	seq_printf(s, " Version:    %d\n"
				  " Tables:     %d\n"
				  " Code RAM:   %d\n"
				  " Data RAM:   %d\n",
				(data[1]>>28) & 0xf,
				(data[1]>>24) & 0xf,
				(data[1]>>16) & 0xff,
				((data[1]>> 0) & 0xffff)*4
			   );

	seq_printf(s, " Functions:  ");
	if (data[0] & (1<<16)) seq_printf(s, "Generic ");
	if (data[0] & (1<<17)) seq_printf(s, "Custom ");
	seq_printf(s, "\n");

	seq_printf(s, " Types:      ");
	if (data[0] & (1<<0) )  seq_printf(s, "ARRAY ");
	if (data[0] & (1<<0) )  seq_printf(s, "VARRAY ");
	if (data[0] & (1<<0) )  seq_printf(s, "LIST ");
	if (data[0] & (1<<0) )  seq_printf(s, "LLIST ");
	if (data[0] & (1<<0) )  seq_printf(s, "HASH ");
	seq_printf(s, "\n");

	seq_printf(s, " Trace:      %d\n"
				  " Trace ID:   0x%02x\n"
				  " Prescale:   0x%04x\n",
				/*(data[2]>> 0) & 0x1, */ debug,
				(data[2]>>16) & 0x7f,
				(data[3]>> 0) & 0xffff
			   );

	seq_printf(s, "\n");


	/*
	 Micro Code
	*/

	/* Microcode version information */
	for (i = 0; i < 256; i++) {
		seq_printf(s, "%c", mc_version_string[m.cop_id][i]);

		if (mc_version_string[m.cop_id][i] == '\0') {
			seq_printf(s, "\n");
			if (mc_version_string[m.cop_id][i+1] == '\0') {
				seq_printf(s, "\n");
				break;
			}
		}
	}

	/* Microcode label information */
	seq_printf(s, "Interface / Available function pointers:\n");
	for (i = 0; i < IF_LABEL_MAX; i++) {
		  if (labelmapping[i].cop_id == m.cop_id)
			seq_printf(s, " %s: 0x%02x\n",
						labelmapping[i].label_name,
						labelmapping[i].func_addr);
	}
	seq_printf(s, "\n");

	/* Microcode code */
	if (code_ram > 0) {
		seq_printf(s, " Code:\n");

		for (i = 0; i < code_ram; i++) {
			entry.index = 0x200 + i;
			ret 	= cop_table0_read(&entry);
			instr	= entry.data.message.data[0] & 0xffff;

#ifdef INCLUDE_COP_DEBUG
			cop_debug_disassembly(instr, opcode, sizeof(opcode));
			seq_printf(s, "  %02X:      %04X %s\n", i, instr, opcode);
#else
			seq_printf(s, "  %02X:      %04X\n", i, instr);
#endif

		}
		seq_printf(s, "\n");
	}

#ifdef INCLUDE_COP_DEBUG
	/* consider PE and COP might operate parallel, one trace might get lost,
	   debugging of PE and COP in parallel not possible */
	cop_debug_set((uint8_t)m.cop_id, debug);
#endif

	if (ret)
		seq_printf(s, "there was an error code: %d during "
			      "gpe_table_entry_read\n", ret);
}


void gpe_table_dsgem(struct seq_file *s)
{
	gpe_cop_table_display(s, ONU_GPE_DS_GEM_PORT_TABLE_ID,
			      gpe_custom_ext_dsgem_table_entry);
}

void gpe_table_usgem(struct seq_file *s)
{
	gpe_cop_table_display(s, ONU_GPE_US_GEM_PORT_TABLE_ID,
			      gpe_custom_ext_usgem_table_entry);
}

void gpe_table_fidhash(struct seq_file *s)
{
	gpe_cop_table_display(s, ONU_GPE_FID_HASH_TABLE_ID, NULL);
}

void gpe_table_fidass(struct seq_file *s)
{
	gpe_cop_table_display(s, ONU_GPE_FID_ASSIGNMENT_TABLE_ID,
			      gpe_custom_fidass_table_entry);
}

void gpe_table_tagg(struct seq_file *s)
{
	gpe_cop_table_display(s, ONU_GPE_TAGGING_FILTER_TABLE_ID,
			      gpe_custom_tagging_filter_table_entry);
}

void gpe_table_vlan(struct seq_file *s)
{
	gpe_cop_table_display(s,ONU_GPE_VLAN_TABLE_ID, NULL);
}

void gpe_table_extvlan(struct seq_file *s)
{
	gpe_cop_table_display(s,ONU_GPE_EXTENDED_VLAN_TABLE_ID,
			      gpe_custom_ext_vlan_table_entry);
}

void gpe_table_vlanrule(struct seq_file *s)
{
	gpe_cop_table_display(s, ONU_GPE_VLAN_RULE_TABLE_ID,
			      gpe_custom_ext_vlan_rule_table_entry);
}

void gpe_table_vlantreatment(struct seq_file *s)
{
	gpe_cop_table_display(s, ONU_GPE_VLAN_TREATMENT_TABLE_ID,
			      gpe_custom_ext_vlan_treatment_table_entry);
}

void gpe_table_shortfwdhash(struct seq_file *s)
{
	gpe_cop_table_display(s, ONU_GPE_SHORT_FWD_HASH_TABLE_ID, NULL);
}

void gpe_table_shortfwdmac(struct seq_file *s)
{
	gpe_cop_table_display(s, ONU_GPE_SHORT_FWD_TABLE_MAC_ID,
			      gpe_custom_shortfwdmac_table_entry);
}

void gpe_table_shortfwdmacmc(struct seq_file *s)
{
	gpe_cop_table_display(s, ONU_GPE_SHORT_FWD_TABLE_MAC_MC_ID,
			      gpe_custom_shortfwdmacmc_table_entry);
}

void gpe_table_shortfwdipv4(struct seq_file *s)
{
	gpe_cop_table_display(s, ONU_GPE_SHORT_FWD_TABLE_IPV4_ID,
			      gpe_custom_shortfwdipv4_table_entry);
}

void gpe_table_shortfwdipv4mc(struct seq_file *s)
{
	gpe_cop_table_display(s, ONU_GPE_SHORT_FWD_TABLE_IPV4_MC_ID,
			      gpe_custom_shortfwdipv4mc_table_entry);
}

void gpe_table_longfwdhash(struct seq_file *s)
{
	gpe_cop_table_display(s, ONU_GPE_LONG_FWD_HASH_TABLE_ID, NULL);
}

void gpe_table_longfwdipv6(struct seq_file *s)
{
	gpe_cop_table_display(s, ONU_GPE_LONG_FWD_TABLE_IPV6_ID, NULL);
}

void gpe_table_longfwdipv6mc(struct seq_file *s)
{
	gpe_cop_table_display(s, ONU_GPE_LONG_FWD_TABLE_IPV6_MC_ID, NULL);
}

void gpe_table_dsmcipv4(struct seq_file *s)
{
	gpe_cop_table_display(s, ONU_GPE_DS_MC_IPV4_SOURCE_FILTER_TABLE_ID,
			      NULL);
}

void gpe_table_dsmcipv6(struct seq_file *s)
{
	gpe_cop_table_display(s, ONU_GPE_DS_MC_IPV6_SOURCE_FILTER_TABLE_ID,
			      NULL);
}

void gpe_table_learnlim(struct seq_file *s)
{
	gpe_cop_table_display(s, ONU_GPE_LEARNING_LIMITATION_TABLE_ID, NULL);
}

void gpe_table_macfilter(struct seq_file *s)
{
	gpe_cop_table_display(s, ONU_GPE_MAC_FILTER_TABLE_ID, NULL);
}

void gpe_table_counter(struct seq_file *s)
{
	gpe_cop_table_display(s, ONU_GPE_COUNTER_TABLE_ID, NULL);
}

void gpe_table_ethertype_filter(struct seq_file *s)
{
	gpe_cop_table_display(s, ONU_GPE_ETHERTYPE_FILTER_TABLE_ID, NULL);
}

STATIC void gpe_custom_table_bridgeport(struct seq_file *s, 
					struct table_meta_info *m,
					struct gpe_table_entry *e)
{
	struct gpe_bridge_port_table entry;

	if (e == NULL) {
		seq_printf(s, "no;");
		seq_printf(s, "bridge_index;");
		seq_printf(s, "umc_flood_disable;");
		seq_printf(s, "uuc_flood_disable;");
		seq_printf(s, "local_switching_enable;");
		seq_printf(s, "port_lock_enable;");
		seq_printf(s, "learning_enable;");
		seq_printf(s, "tp_type;");
		seq_printf(s, "tp_pointer;");
		seq_printf(s, "dscp_table_pointer;");
		seq_printf(s, "egress_filter_mask;");
		seq_printf(s, "meter_id_egress;");
		seq_printf(s, "tagging_filter_egress;");
		seq_printf(s, "meter_id_ingress;");
		seq_printf(s, "tagging_filter_ingress;");
		seq_printf(s, "da_filter_pointer;");
		seq_printf(s, "sa_filter_pointer;");
		seq_printf(s, "egress_color_marking;");
		seq_printf(s, "ingress_color_marking;");
		seq_printf(s, "da_filter_mode;");
		seq_printf(s, "sa_filter_mode;");
		seq_printf(s, "port_state;");
		seq_printf(s, "forwarding_method;");
		seq_printf(s, "meter_egress_enable;");
		seq_printf(s, "meter_ingress_enable;");
		seq_printf(s, "tagging_filter_egress_enable;");
		seq_printf(s, "tagging_filter_ingress_enable\n");
		return;
	}

	memcpy(&entry, &e->data.bridge_port, sizeof(entry));

	if (entry.valid == 0)
		return;

	seq_printf(s, "%d", e->index);
	cprintf(s, ";%d", entry.bridge_index);
	cprintf(s, ";%d", entry.umc_flood_disable);
	cprintf(s, ";%d", entry.uuc_flood_disable);
	cprintf(s, ";%d", entry.local_switching_enable);
	cprintf(s, ";%d", entry.port_lock_enable);
	cprintf(s, ";%d", entry.learning_enable);
	cprintf(s, ";%d", entry.tp_type);
	cprintf(s, ";%d", entry.tp_pointer);
	cprintf(s, ";%d", entry.dscp_table_pointer);
	cprintf(s, ";%d", entry.egress_filter_mask);
	cprintf(s, ";%d", entry.meter_id_egress);
	cprintf(s, ";%d", entry.tagging_filter_egress);
	cprintf(s, ";%d", entry.meter_id_ingress);
	cprintf(s, ";%d", entry.tagging_filter_ingress);
	cprintf(s, ";%d", entry.da_filter_pointer);
	cprintf(s, ";%d", entry.sa_filter_pointer);
	cprintf(s, ";%d", entry.egress_color_marking);
	cprintf(s, ";%d", entry.ingress_color_marking);
	cprintf(s, ";%d", entry.da_filter_mode);
	cprintf(s, ";%d", entry.sa_filter_mode);
	cprintf(s, ";%d", entry.port_state);
	cprintf(s, ";%d", entry.forwarding_method);
	cprintf(s, ";%d", entry.meter_egress_enable);
	cprintf(s, ";%d", entry.meter_ingress_enable);
	cprintf(s, ";%d", entry.tagging_filter_egress_enable);
	cprintf(s, ";%d", entry.tagging_filter_ingress_enable);
	seq_printf(s, "\n");
}

STATIC void gpe_custom_table_lanport(struct seq_file *s, 
					struct table_meta_info *m,
					struct gpe_table_entry *e)
{
	struct gpe_lan_port_table entry;

	if (e == NULL) {
		seq_printf(s, "no;");
		seq_printf(s, "ext_vlan_incremental_enable;");
		seq_printf(s, "ext_vlan_ingress_mode;");
		seq_printf(s, "ext_vlan_egress_mode;");
		seq_printf(s, "ext_vlan_enable_egress;");
		seq_printf(s, "ext_vlan_index_egress;");
		seq_printf(s, "ext_vlan_enable_ingress;");
		seq_printf(s, "ext_vlan_index_ingress;");
		seq_printf(s, "ext_vlan_mc_enable_ingress;");
		seq_printf(s, "ext_vlan_mc_enable_egress;");
		seq_printf(s, "ethertype_filter_enable;");
		seq_printf(s, "ethertype_filter_mode;");
		seq_printf(s, "ethertype_filter_pointer;");
		seq_printf(s, "fid_mask_pcpi;");
		seq_printf(s, "fid_mask_pcpo;");
		seq_printf(s, "fid_mask_vidi;");
		seq_printf(s, "fid_mask_vido;");
		seq_printf(s, "dscp_table_pointer;");
		seq_printf(s, "queue_marking_mode;");
		seq_printf(s, "uni_except_meter_enable;");
		seq_printf(s, "uni_except_meter_id;");
		seq_printf(s, "igmp_except_meter_enable;");
		seq_printf(s, "igmp_except_meter_id;");
		seq_printf(s, "exception_profile;");
		seq_printf(s, "acl_filter_index;");
		seq_printf(s, "acl_filter_enable;");
		seq_printf(s, "acl_filter_mode;");
		seq_printf(s, "lan_mac_swap_enable;");
		seq_printf(s, "lan_loopback_enable;");
		seq_printf(s, "pppoe_filter_enable;");
		seq_printf(s, "cfm_meter_enable;");
		seq_printf(s, "cfm_meter_id;");
		seq_printf(s, "base_queue_index;");
		seq_printf(s, "interworking_option;");
		seq_printf(s, "interworking_index;");
		seq_printf(s, "policer_threshold\n");
		return;
	}

	memcpy(&entry, &e->data.lan_port, sizeof(entry));

	if (entry.valid == 0)
		return;

	seq_printf(s, "%d", e->index);
	cprintf(s, ";%d", entry.ext_vlan_incremental_enable);
	cprintf(s, ";%d", entry.ext_vlan_ingress_mode);
	cprintf(s, ";%d", entry.ext_vlan_egress_mode);
	cprintf(s, ";%d", entry.ext_vlan_enable_egress);
	cprintf(s, ";%d", entry.ext_vlan_index_egress);
	cprintf(s, ";%d", entry.ext_vlan_enable_ingress);
	cprintf(s, ";%d", entry.ext_vlan_index_ingress);
	cprintf(s, ";%d", entry.ext_vlan_mc_enable_ingress);
	cprintf(s, ";%d", entry.ext_vlan_mc_enable_egress);
	cprintf(s, ";%d", entry.ethertype_filter_enable);
	cprintf(s, ";%d", entry.ethertype_filter_mode);
	cprintf(s, ";%d", entry.ethertype_filter_pointer);
	cprintf(s, ";%d", entry.fid_mask_pcpi);
	cprintf(s, ";%d", entry.fid_mask_pcpo);
	cprintf(s, ";%d", entry.fid_mask_vidi);
	cprintf(s, ";%d", entry.fid_mask_vido);
	cprintf(s, ";%d", entry.dscp_table_pointer);
	cprintf(s, ";%d", entry.queue_marking_mode);
	cprintf(s, ";%d", entry.uni_except_meter_enable);
	cprintf(s, ";%d", entry.uni_except_meter_id);
	cprintf(s, ";%d", entry.igmp_except_meter_enable);
	cprintf(s, ";%d", entry.igmp_except_meter_id);
	cprintf(s, ";%d", entry.exception_profile);
	cprintf(s, ";%d", entry.acl_filter_index);
	cprintf(s, ";%d", entry.acl_filter_enable);
	cprintf(s, ";%d", entry.acl_filter_mode);
	cprintf(s, ";%d", entry.lan_mac_swap_enable);
	cprintf(s, ";%d", entry.lan_loopback_enable);
	cprintf(s, ";%d", entry.pppoe_filter_enable);
	cprintf(s, ";%d", entry.cfm_meter_enable);
	cprintf(s, ";%d", entry.cfm_meter_id);
	cprintf(s, ";%d", entry.base_queue_index);
	cprintf(s, ";%d", entry.interworking_option);
	cprintf(s, ";%d", entry.interworking_index);
	cprintf(s, ";%d", entry.policer_threshold);
	seq_printf(s, "\n");
}

STATIC void gpe_custom_table_bridge(struct seq_file *s, 
				    struct table_meta_info *m,
				    struct gpe_table_entry *e)
{
	struct gpe_bridge_table entry;

	if (e == NULL) {
		seq_printf(s, "no;");
		seq_printf(s, "flooding_bridge_port_enable;");
		seq_printf(s, "bp15;");
		seq_printf(s, "bp14;");
		seq_printf(s, "bp13;");
		seq_printf(s, "bp12;");
		seq_printf(s, "bp11;");
		seq_printf(s, "bp10;");
		seq_printf(s, "bp9;");
		seq_printf(s, "bp8;");
		seq_printf(s, "bp7;");
		seq_printf(s, "bp6;");
		seq_printf(s, "bp5;");
		seq_printf(s, "bp4;");
		seq_printf(s, "bp3;");
		seq_printf(s, "bp2;");
		seq_printf(s, "bp1;");
		seq_printf(s, "bp0;");
		seq_printf(s, "bc_meter_enable;");
		seq_printf(s, "bc_meter_id;");
		seq_printf(s, "mc_meter_enable;");
		seq_printf(s, "mc_meter_id;");
		seq_printf(s, "uuc_meter_enable;");
		seq_printf(s, "uuc_meter_id\n");
		return;
	}

	memcpy(&entry, &e->data.bridge, sizeof(entry));

	seq_printf(s, "%d", e->index);
	cprintf(s, ";%d", entry.flooding_bridge_port_enable);
	cprintf(s, ";%d", entry.egress_bridge_port_index15);
	cprintf(s, ";%d", entry.egress_bridge_port_index14);
	cprintf(s, ";%d", entry.egress_bridge_port_index13);
	cprintf(s, ";%d", entry.egress_bridge_port_index12);
	cprintf(s, ";%d", entry.egress_bridge_port_index11);
	cprintf(s, ";%d", entry.egress_bridge_port_index10);
	cprintf(s, ";%d", entry.egress_bridge_port_index9);
	cprintf(s, ";%d", entry.egress_bridge_port_index8);
	cprintf(s, ";%d", entry.egress_bridge_port_index7);
	cprintf(s, ";%d", entry.egress_bridge_port_index6);
	cprintf(s, ";%d", entry.egress_bridge_port_index5);
	cprintf(s, ";%d", entry.egress_bridge_port_index4);
	cprintf(s, ";%d", entry.egress_bridge_port_index3);
	cprintf(s, ";%d", entry.egress_bridge_port_index2);
	cprintf(s, ";%d", entry.egress_bridge_port_index1);
	cprintf(s, ";%d", entry.egress_bridge_port_index0);
	cprintf(s, ";%d", entry.bc_meter_enable);
	cprintf(s, ";%d", entry.bc_meter_id);
	cprintf(s, ";%d", entry.mc_meter_enable);
	cprintf(s, ";%d", entry.mc_meter_id);
	cprintf(s, ";%d", entry.uuc_meter_enable);
	cprintf(s, ";%d", entry.uuc_meter_id);
	seq_printf(s, "\n");
}

STATIC void gpe_pe_default_table_display(struct seq_file *s, 
					 struct table_meta_info *m,
					 struct gpe_table_entry *entry)
{
	uint32_t i;
	uint8_t *data;

	seq_printf(s, "[%04d]: ", entry->index);

	if (m->tabletype == ONU_GPE_COP_BITVECT) {
		data = (uint8_t *)&entry->data + entry->index / 8;

		seq_printf(s, "%u\n",
			   *data & (1 << (entry->index % 8))
			   ? 1 : 0);
		return;
	}

	for (i = 0; i < m->entry_width / 8; i++) {
		data = (uint8_t *)&entry->data + i;

		seq_printf(s, "%02x ", *data);

		if (i == 0) {
			if (m->tabletype == ONU_GPE_COP_VARRAY ||
				m->tabletype == ONU_GPE_COP_LIST   ||
				m->tabletype == ONU_GPE_COP_LLIST  ||
				m->tabletype == ONU_GPE_COP_HASH) {

				if (*data & (i << 7))
					seq_printf(s, "V ");
			}

			if (m->tabletype == ONU_GPE_COP_LIST ||
				m->tabletype == ONU_GPE_COP_LLIST) {

				if (*data & (i << 6))
					seq_printf(s, "E ");
			}
		}
	}

	seq_printf(s, "\n");
}

STATIC void
gpe_pe_table_display(struct seq_file *s, uint32_t entry_id,
		     void (*custom_dump)(struct seq_file *s,
					 struct table_meta_info *m,
					 struct gpe_table_entry *entry))
{
	struct table_meta_info m;
	uint32_t pe_idx;
	struct gpe_table_entry entry;
	enum onu_errorcode ret;
	struct onu_control *ctrl = &onu_control[0];

	m.tableid  = GPE_TABLE_ID(entry_id);
	m.tabletype = pe_tbl_cfg[m.tableid].type;
	m.size = pe_tbl_cfg[m.tableid].size;
	m.entry_width = pe_tbl_cfg[m.tableid].entry_width;
	m.base = pe_tbl_cfg[m.tableid].base;

	entry.id = entry_id;

	if(custom_dump && raw_mode == 0) {
		custom_dump(s, &m, NULL);
		entry.instance = 1 << 0;
		for (entry.index = 0; entry.index < m.size; entry.index++) {
			ret = TABLE_GET(ctrl, &entry);
			if (ret) {
				seq_printf(s, "[%04d]: error %d", entry.index,
					   ret);
				continue;
			}
			if (custom_dump && raw_mode == 0)
				custom_dump(s, &m, &entry);
			else
				gpe_pe_default_table_display(s, &m, &entry);

		}
	} else {
		seq_printf(s, "Name:        %s\n", pe_tbl_cfg[m.tableid].name);
		seq_printf(s, "ID:          %d\n\n", entry_id);
		seq_printf(s, "Table:       %i\n", m.tableid);
		seq_printf(s, " Type:       %s (%i)\n"
			   " Size:       %i\n"
			   " Entry size: %i\n"
			   " Base:       0x%04x\n",
			   type[m.tabletype], m.tabletype,
			   m.size,
			   m.entry_width,
			   m.base);
		for (pe_idx = 0; pe_idx < ctrl->num_pe; pe_idx++) {
			entry.instance = 1 << pe_idx;

			seq_printf(s, "\nPacket Engine #%u:\n", pe_idx);

			for (entry.index = 0; entry.index < m.size;
								entry.index++) {
				ret = TABLE_GET(ctrl, &entry);
				if (ret) {
					seq_printf(s, "[%04d]: error %d",
							entry.index, ret);
					continue;
				}

				if(custom_dump && raw_mode == 0)
					custom_dump(s, &m, &entry);
				else
					gpe_pe_default_table_display(s, &m,
								     &entry);
			}
		}
	}

}

void gpe_table_bridgeport(struct seq_file *s)
{
	gpe_pe_table_display(s, ONU_GPE_BRIDGE_PORT_TABLE_ID,
			     gpe_custom_table_bridgeport);
}

void gpe_table_pmapper(struct seq_file *s)
{
	gpe_pe_table_display(s, ONU_GPE_PMAPPER_TABLE_ID, NULL);
}

void gpe_table_lanport(struct seq_file *s)
{
	gpe_pe_table_display(s, ONU_GPE_LAN_PORT_TABLE_ID,
			     gpe_custom_table_lanport);
}

void gpe_table_enqueue(struct seq_file *s)
{
	gpe_pe_table_display(s, ONU_GPE_ENQUEUE_TABLE_ID, NULL);
}

void gpe_table_pcpdec(struct seq_file *s)
{
	gpe_pe_table_display(s, ONU_GPE_PCP_DECODING_TABLE_ID, NULL);
}

void gpe_table_dscpdec(struct seq_file *s)
{
	gpe_pe_table_display(s, ONU_GPE_DSCP_DECODING_TABLE_ID, NULL);
}

void gpe_table_pcpenc(struct seq_file *s)
{
	gpe_pe_table_display(s, ONU_GPE_PCP_ENCODING_TABLE_ID, NULL);
}

void gpe_table_dscpenc(struct seq_file *s)
{
	gpe_pe_table_display(s, ONU_GPE_DSCP_ENCODING_TABLE_ID, NULL);
}

void gpe_table_redir(struct seq_file *s)
{
	gpe_pe_table_display(s, ONU_GPE_REDIRECTION_TABLE_ID, NULL);
}

void gpe_table_aclfilt(struct seq_file *s)
{
	gpe_pe_table_display(s, ONU_GPE_ACL_FILTER_TABLE_ID, NULL);
}

void gpe_table_bridge(struct seq_file *s)
{
	gpe_pe_table_display(s, ONU_GPE_BRIDGE_TABLE_ID,
			     gpe_custom_table_bridge);
}

void gpe_table_const(struct seq_file *s)
{
	gpe_pe_table_display(s, ONU_GPE_CONSTANTS_TABLE_ID, NULL);
}

void gpe_table_status(struct seq_file *s)
{
	gpe_pe_table_display(s, ONU_GPE_STATUS_TABLE_ID, NULL);
}

void gpe_table_exp(struct seq_file *s)
{
	gpe_pe_table_display(s, ONU_GPE_EXCEPTION_TABLE_ID, NULL);
}
#endif

const struct onu_entry gpe_table_function_table[] = {
	TE1in(FIO_GPE_TABLE_ENTRY_SET,
		sizeof(struct gpe_table_entry),
		gpe_table_entry_set),
	TE2(FIO_GPE_TABLE_ENTRY_GET,
		sizeof(struct gpe_table),
		sizeof(struct gpe_table_entry),
		gpe_table_entry_get),
	TE1in(FIO_GPE_TABLE_ENTRY_ADD,
		sizeof(struct gpe_table_entry),
		gpe_table_entry_add),
	TE1in(FIO_GPE_TABLE_ENTRY_DELETE,
		sizeof(struct gpe_table_entry),
		gpe_table_entry_delete),
	TE2(FIO_GPE_TABLE_ENTRY_READ,
		sizeof(struct gpe_table),
		sizeof(struct gpe_table_entry),
		gpe_table_entry_read),
	TE1in(FIO_GPE_TABLE_ENTRY_WRITE,
		sizeof(struct gpe_table_entry),
		gpe_table_entry_write),

	TE2(FIO_GPE_BRIDGE_PORT_CFG_GET,
		sizeof(struct gpe_bridge_port_index),
		sizeof(struct gpe_bridge_port),
		gpe_bridge_port_cfg_get),
	TE1in(FIO_GPE_BRIDGE_PORT_CFG_SET,
		sizeof(struct gpe_bridge_port),
		gpe_bridge_port_cfg_set),

	TE2(FIO_GPE_EXT_VLAN_GET,
		sizeof(struct gpe_ext_vlan_index),
		sizeof(struct gpe_ext_vlan),
		gpe_ext_vlan_get),
	TE1in(FIO_GPE_EXT_VLAN_SET,
		sizeof(struct gpe_ext_vlan),
		gpe_ext_vlan_set),
	TE2(FIO_GPE_EXT_VLAN_DO,
		sizeof(struct gpe_ext_vlan_translate),
		sizeof(struct gpe_ext_vlan_translate),
		gpe_ext_vlan_do),

	TE1in(FIO_GPE_FID_ADD,
		sizeof(struct gpe_table_entry),
		gpe_fid_add),
	TE1in(FIO_GPE_FID_DELETE,
		sizeof(struct gpe_table_entry),
		gpe_fid_delete),

	TE1in(FIO_GPE_LONG_FWD_ADD,
		sizeof(struct gpe_table_entry),
		gpe_long_fwd_add),
	TE1in(FIO_GPE_LONG_FWD_DELETE,
		sizeof(struct gpe_table_entry),
		gpe_long_fwd_delete),

	TE2(FIO_GPE_TAGGING_FILTER_GET,
		sizeof(struct gpe_tagging_index),
		sizeof(struct gpe_tagging),
		gpe_tagging_filter_get),
	TE1in(FIO_GPE_TAGGING_FILTER_SET,
		sizeof(struct gpe_tagging),
		gpe_tagging_filter_set),

	TE1in_opt(FIO_GPE_COP_TABLE0_READ,
		sizeof(struct gpe_table_entry),
		gpe_cop_table0_read),

	TE1in(FIO_GPE_SHORT_FWD_ADD,
		sizeof(struct gpe_table_entry),
		gpe_short_fwd_add),

	TE1in(FIO_GPE_SHORT_FWD_DELETE,
		sizeof(struct gpe_table_entry),
		gpe_short_fwd_delete),

	TE1in_opt(FIO_GPE_COP_DEBUG_SET,
		sizeof(struct gpe_table_entry),
		gpe_cop_debug_set),

	TE1in(FIO_GPE_SHORT_FWD_RELEARN,
		sizeof(struct gpe_table_entry),
		gpe_short_fwd_relearn),

	TE1in(FIO_GPE_EXT_VLAN_CUSTOM_SET,
		sizeof(struct gpe_table_entry),
		gpe_ext_vlan_custom_set),

	TE1in_opt(FIO_GPE_COP_DEBUG_SERVER,
		sizeof(struct gpe_table_entry),
		gpe_cop_debug_server),

	TE1in(FIO_GPE_SHORT_FWD_FORWARD,
		sizeof(struct gpe_table_entry),
		gpe_short_fwd_forward),

	TE1in(FIO_GPE_TABLE_ENTRY_SEARCH,
		sizeof(struct gpe_table_entry),
		gpe_table_entry_search),

	TE2(FIO_GPE_TAGGING_FILTER_DO,
		sizeof(struct gpe_tagg_filter),
		sizeof(struct gpe_tagg_filter),
		gpe_tagging_filter_do),

	TE1in(FIO_GPE_TABLE_REINIT,
		sizeof(struct gpe_reinit_table),
		gpe_table_reinit),

	TE1in(FIO_GPE_LONG_FWD_FORWARD,
		sizeof(struct gpe_table_entry),
		gpe_long_fwd_forward),

	TE1out(FIO_GPE_EXT_VLAN_CUSTOM_GET,
		sizeof(struct gpe_ext_vlan_custom),
		gpe_ext_vlan_custom_get),

	TE1in(FIO_GPE_AGING_TIME_SET,
		sizeof(struct sce_aging_time),
		gpe_aging_time_set),

	TE2(FIO_GPE_AGING_TIME_GET,
		sizeof(struct sce_aging_time),
		sizeof(struct sce_aging_time),
		gpe_aging_time_get),

	TE2(FIO_GPE_AGE_GET,
		sizeof(struct gpe_table_entry),
		sizeof(struct sce_mac_entry_age),
		gpe_age_get),

	TE1in(FIO_GPE_AGE,
		sizeof(struct gpe_table_entry),
		gpe_age),

	TE1in(FIO_GPE_AGING_TIME_SET_DEBUG,
		sizeof(struct sce_aging_time),
		gpe_aging_time_set_debug),

	TE1in(FIO_GPE_ACL_TABLE_ENTRY_SET,
		sizeof(struct gpe_acl_table_entry),
		gpe_acl_table_entry_set),
	TE2(FIO_GPE_ACL_TABLE_ENTRY_GET,
		sizeof(struct gpe_acl_table_entry_idx),
		sizeof(struct gpe_acl_table_entry),
		gpe_acl_table_entry_get),
	TE1in(FIO_GPE_ACL_TABLE_ENTRY_DELETE,
		sizeof(struct gpe_acl_table_entry_idx),
		gpe_acl_table_entry_delete),
	TE2(FIO_GPE_SCE_CONSTANTS_GET,
		sizeof(struct gpe_sce_constants),
		sizeof(struct gpe_sce_constants),
		gpe_sce_constants_get),
	TE1in(FIO_GPE_SCE_CONSTANTS_SET,
		sizeof(struct gpe_sce_constants),
		gpe_sce_constants_set),

	TE1out(FIO_GPE_SCE_MAC_GET,
		sizeof(struct gpe_sce_mac),
		gpe_sce_mac_get),
	TE1in(FIO_GPE_SCE_MAC_SET,
		sizeof(struct gpe_sce_mac),
		gpe_sce_mac_set),

	TE1in(FIO_GPE_SHORT_FWD_MAC_MC_PORT_ADD,
		sizeof(struct gpe_mac_mc_port),
		gpe_short_fwd_mac_mc_port_add),

	TE1in(FIO_GPE_SHORT_FWD_MAC_MC_PORT_DELETE,
		sizeof(struct gpe_mac_mc_port),
		gpe_short_fwd_mac_mc_port_delete),

	TE1in(FIO_GPE_SHORT_FWD_MAC_MC_PORT_MODIFY,
		sizeof(struct gpe_mac_mc_port_modify),
		gpe_short_fwd_mac_mc_port_modify),

	TE2(FIO_GPE_VLAN_FID_ADD,
		sizeof(struct gpe_vlan_fid_in),
		sizeof(struct gpe_vlan_fid_out),
		gpe_vlan_fid_add),
	TE2(FIO_GPE_VLAN_FID_GET,
		sizeof(struct gpe_vlan_fid_in),
		sizeof(struct gpe_vlan_fid_out),
		gpe_vlan_fid_get),
	TE1in(FIO_GPE_VLAN_FID_DELETE,
		sizeof(struct gpe_vlan_fid_in),
		gpe_vlan_fid_delete),

	TE1in(FIO_GPE_SHORT_FWD_IPV4_MC_PORT_ADD,
		sizeof(struct gpe_ipv4_mc_port),
		gpe_short_fwd_ipv4_mc_port_add),

	TE1in(FIO_GPE_SHORT_FWD_IPV4_MC_PORT_DELETE,
		sizeof(struct gpe_ipv4_mc_port),
		gpe_short_fwd_ipv4_mc_port_delete),

	TE1in(FIO_GPE_SHORT_FWD_IPV4_MC_PORT_MODIFY,
		sizeof(struct gpe_ipv4_mc_port_modify),
		gpe_short_fwd_ipv4_mc_port_modify)
};

const unsigned int gpe_table_function_table_size =
					   ARRAY_SIZE(gpe_table_function_table);

/*! @} */

/*! @} */
