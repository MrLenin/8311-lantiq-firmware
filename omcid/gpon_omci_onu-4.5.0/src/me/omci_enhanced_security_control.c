/******************************************************************************

                              Copyright (c) 2012
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_enhanced_security_control.c

   Enhanced Security Control ME (class 332).
   Backported from gpon_omci_onu-8.6.3 to v4.5.0 framework.

   This is a stub/Tier-2 implementation: table management and state machine
   are functional, ONU random challenge generation works (via /dev/urandom),
   but no hardware crypto driver is available on the Falcon SoC.
   Authentication result computation cannot be performed, so ONU auth status
   remains "indeterminate" (0). OLTs that require completed enhanced security
   will see the ME exists but auth won't complete.
*/
#include "ifxos_memory_alloc.h"

#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_enhanced_security_control.h"

#ifdef LINUX
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

/** \addtogroup OMCI_ME_ENHANCED_SECURITY_CONTROL
   @{
*/

/* Size of data for one table entry fragment */
#define ENTRY_SIZE 16

/* Encryption algorithm identifiers (bit positions in crypto caps) */
#define ENC_AES_CMAC_128  0
#define ENC_HMAC_SHA_256  1
#define ENC_HMAC_SHA_512  2

/* Broadcast key definitions */
#define BC_KEY_DEF_FIRST  0x01
#define BC_KEY_DEF_SECOND 0x02

/* ---- Internal linked list entry types ---- */

struct olt_random_chl_list_entry {
	struct olt_random_chl_table_entry table_entry;
	struct olt_random_chl_list_entry *next;
	struct olt_random_chl_list_entry *prev;
};

struct onu_random_chl_list_entry {
	struct onu_random_chl_table_entry table_entry;
	struct onu_random_chl_list_entry *next;
	struct onu_random_chl_list_entry *prev;
};

struct onu_auth_result_list_entry {
	struct onu_auth_result_table_entry table_entry;
	struct onu_auth_result_list_entry *next;
	struct onu_auth_result_list_entry *prev;
};

struct olt_auth_result_list_entry {
	struct olt_auth_result_table_entry table_entry;
	struct olt_auth_result_list_entry *next;
	struct olt_auth_result_list_entry *prev;
};

struct broadcast_key_list_entry {
	struct broadcast_key_table_entry table_entry;
	struct broadcast_key_list_entry *next;
	struct broadcast_key_list_entry *prev;
};

/** Internal ME data */
struct internal_data {
	struct olt_random_chl_list_entry olt_random_chl_list_head;
	size_t olt_random_chl_entries_num;

	struct onu_random_chl_list_entry onu_random_chl_list_head;
	size_t onu_random_chl_entries_num;
	bool onu_random_chl_update_enabled;

	struct onu_auth_result_list_entry onu_auth_result_list_head;
	size_t onu_auth_result_entries_num;
	bool onu_auth_result_update_enabled;

	struct olt_auth_result_list_entry olt_auth_result_list_head;
	size_t olt_auth_result_entries_num;

	struct broadcast_key_list_entry broadcast_key_list_head;
	size_t broadcast_key_entries_num;
};

/* ---- List clear helpers ---- */

static enum omci_error
olt_random_chl_list_clear(struct internal_data *me_idata)
{
	struct olt_random_chl_list_entry *le, *nle;

	DLIST_FOR_EACH_SAFE(le, nle,
		&me_idata->olt_random_chl_list_head) {
		DLIST_REMOVE(le);
		IFXOS_MemFree(le);
		le = NULL;
	}
	me_idata->olt_random_chl_entries_num = 0;
	return OMCI_SUCCESS;
}

static enum omci_error
onu_random_chl_list_clear(struct internal_data *me_idata)
{
	struct onu_random_chl_list_entry *le, *nle;

	DLIST_FOR_EACH_SAFE(le, nle,
		&me_idata->onu_random_chl_list_head) {
		DLIST_REMOVE(le);
		IFXOS_MemFree(le);
		le = NULL;
	}
	me_idata->onu_random_chl_entries_num = 0;
	return OMCI_SUCCESS;
}

static enum omci_error
onu_auth_result_list_clear(struct internal_data *me_idata)
{
	struct onu_auth_result_list_entry *le, *nle;

	DLIST_FOR_EACH_SAFE(le, nle,
		&me_idata->onu_auth_result_list_head) {
		DLIST_REMOVE(le);
		IFXOS_MemFree(le);
		le = NULL;
	}
	me_idata->onu_auth_result_entries_num = 0;
	return OMCI_SUCCESS;
}

static enum omci_error
olt_auth_result_list_clear(struct internal_data *me_idata)
{
	struct olt_auth_result_list_entry *le, *nle;

	DLIST_FOR_EACH_SAFE(le, nle,
		&me_idata->olt_auth_result_list_head) {
		DLIST_REMOVE(le);
		IFXOS_MemFree(le);
		le = NULL;
	}
	me_idata->olt_auth_result_entries_num = 0;
	return OMCI_SUCCESS;
}

static enum omci_error
broadcast_key_list_clear(struct internal_data *me_idata)
{
	struct broadcast_key_list_entry *le, *nle;

	DLIST_FOR_EACH_SAFE(le, nle,
		&me_idata->broadcast_key_list_head) {
		DLIST_REMOVE(le);
		IFXOS_MemFree(le);
		le = NULL;
	}
	me_idata->broadcast_key_entries_num = 0;
	return OMCI_SUCCESS;
}

/* ---- Attribute update actions ---- */

/** Process OLT crypto capabilities (attr 1).
    Select best mutually-supported algorithm.
    STUB: always selects AES-CMAC-128 (mandatory per G.988). */
static enum omci_error
olt_crypto_caps_update_action(struct omci_context *context,
	struct me *me,
	struct omci_me_enh_sec_ctrl *upd_data)
{
	uint8_t olt_crypto_caps = upd_data->olt_crypto_caps.data[15];

	/* Side effect: OLT challenge status resets to false */
	upd_data->olt_chl_status = 0;

	if (!olt_crypto_caps)
		return OMCI_SUCCESS;

	/* Without a hardware crypto driver, we can only claim
	   AES-CMAC-128 support (mandatory, bit 0). Select the highest
	   algorithm the OLT offers that we "support" — which is only
	   AES-CMAC-128 in this stub. */
	if (olt_crypto_caps & (1 << ENC_AES_CMAC_128)) {
		upd_data->onu_selected_crypto_caps =
			(1 << ENC_AES_CMAC_128);
		upd_data->effective_key_length =
			128 << ENC_AES_CMAC_128;  /* 128 bits */
	} else {
		/* OLT doesn't offer AES-CMAC-128 — shouldn't happen
		   per G.988 (mandatory), but handle gracefully */
		me_dbg_wrn(me, "OLT does not offer AES-CMAC-128");
		upd_data->onu_selected_crypto_caps = 0;
		return OMCI_ERROR;
	}

	return OMCI_SUCCESS;
}

/** Generate ONU random challenge and populate table.
    STUB: generates random data but cannot send to crypto driver. */
static enum omci_error
onu_random_chl_generate(struct omci_context *context,
			struct me *me)
{
	struct internal_data *me_idata =
		(struct internal_data *)me->internal_data;
	struct omci_me_enh_sec_ctrl *data;
	size_t key_len;
	uint32_t i;
	uint8_t *onu_random_chl;
	enum omci_error error;
#ifdef LINUX
	int fd;
	ssize_t len = 0;
#endif

	data = (struct omci_me_enh_sec_ctrl *)me->data;

	/* Effective key length is stored in bits, calculate bytes */
	key_len = data->effective_key_length / 8;
	if (!key_len) {
		me_dbg_err(me, "Effective key length is 0");
		return OMCI_ERROR;
	}

	/* Allocate memory for concatenated ONU random challenge */
	onu_random_chl = IFXOS_MemAlloc(key_len);
	RETURN_IF_MALLOC_ERROR(onu_random_chl);
	memset(onu_random_chl, 0, key_len);

#ifdef LINUX
	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) {
		IFXOS_MemFree(onu_random_chl);
		me_dbg_err(me, "Open of /dev/urandom failed");
		return OMCI_ERROR;
	}

	len = read(fd, onu_random_chl, key_len);
	close(fd);

	if (len < 0 || (size_t)len != key_len) {
		IFXOS_MemFree(onu_random_chl);
		me_dbg_err(me, "Read of /dev/urandom failed");
		return OMCI_ERROR;
	}
#else
	/* Fallback: non-cryptographic RNG */
	srand((unsigned int)time(NULL));
	for (i = 0; i < key_len; i++)
		onu_random_chl[i] = rand();
#endif

	/* NOTE: In a full implementation, onu_random_chl would be sent
	   to a crypto driver here. We skip that (no driver available). */

	/* Clear old data in the list */
	onu_random_chl_list_clear(me_idata);

	/* Enable table update for this attribute */
	me_idata->onu_random_chl_update_enabled = true;

	/* Prepare ONU random challenge table for OLT */
	for (i = 0; i < key_len; i += ENTRY_SIZE) {
		error = me_attr_write(context, me,
				     omci_me_enh_sec_ctrl_onu_random_chl_table,
				     &onu_random_chl[i], ENTRY_SIZE, true);
		if (error != OMCI_SUCCESS) {
			IFXOS_MemFree(onu_random_chl);
			return error;
		}
	}

	me_idata->onu_random_chl_update_enabled = false;

	/* Inform OLT that ONU random challenge table is ready */
	error = omci_attr_avc_send(context, me->class->class_id,
				 me->instance_id,
				 omci_me_enh_sec_ctrl_onu_random_chl_table);

	IFXOS_MemFree(onu_random_chl);
	return error;
}

/** Process OLT challenge status becoming true (attr 3).
    Concatenates OLT challenge table, then generates ONU challenge. */
static enum omci_error
olt_chl_status_update_action(struct omci_context *context,
	struct me *me,
	uint8_t *entry)
{
	struct internal_data *me_idata =
		(struct internal_data *)me->internal_data;
	struct olt_random_chl_list_entry *le;
	uint8_t olt_chl_status = *entry;
	uint8_t *olt_random_chl;
	size_t olt_random_chl_len;
	uint32_t index = 0, index_checker = 1;
	enum omci_error error;

	if (!olt_chl_status)
		return OMCI_SUCCESS;

	olt_random_chl_len = me_idata->olt_random_chl_entries_num * ENTRY_SIZE;

	/* Check if all required messages were delivered (sequential rows) */
	DLIST_FOR_EACH(le, &me_idata->olt_random_chl_list_head) {
		if (le->table_entry.row_number != index_checker) {
			me_dbg_err(me, "OLT random challenge has wrong row numbers");
			return OMCI_ERROR;
		}
		++index_checker;
	}

	/* Allocate memory for concatenated OLT random challenge */
	olt_random_chl = IFXOS_MemAlloc(olt_random_chl_len);
	RETURN_IF_MALLOC_ERROR(olt_random_chl);

	/* Concatenate OLT random challenge */
	DLIST_FOR_EACH(le, &me_idata->olt_random_chl_list_head) {
		memcpy(&olt_random_chl[index], &le->table_entry.content,
			ENTRY_SIZE);
		index += ENTRY_SIZE;
	}

	/* NOTE: In a full implementation, olt_random_chl would be sent
	   to a crypto driver here. We skip that (no driver available). */

	/* Clear list and buffer */
	olt_random_chl_list_clear(me_idata);
	IFXOS_MemFree(olt_random_chl);

	/* Generate ONU random challenge table */
	error = onu_random_chl_generate(context, me);

	return error;
}

/** Process OLT result status becoming true (attr 8).
    Concatenates OLT auth result table for verification.
    STUB: accepts data but cannot verify — auth stays indeterminate. */
static enum omci_error
olt_result_status_update_action(struct omci_context *context,
	struct me *me,
	uint8_t *entry)
{
	struct internal_data *me_idata =
		(struct internal_data *)me->internal_data;
	struct omci_me_enh_sec_ctrl *data;
	struct olt_auth_result_list_entry *le;
	uint8_t olt_result_status = *entry;
	size_t olt_auth_result_len;
	uint32_t index_checker = 1;

	if (!olt_result_status)
		return OMCI_SUCCESS;

	data = (struct omci_me_enh_sec_ctrl *)me->data;

	olt_auth_result_len = me_idata->olt_auth_result_entries_num *
			      ENTRY_SIZE;

	/* Validate length matches selected key length */
	if ((data->effective_key_length / 8) != olt_auth_result_len) {
		me_dbg_err(me, "OLT auth result length mismatch");
		return OMCI_ERROR;
	}

	/* Check sequential row numbers */
	DLIST_FOR_EACH(le, &me_idata->olt_auth_result_list_head) {
		if (le->table_entry.row_number != index_checker) {
			me_dbg_err(me, "OLT auth result has wrong row numbers");
			return OMCI_ERROR;
		}
		++index_checker;
	}

	/* NOTE: In a full implementation, the concatenated OLT auth result
	   would be sent to a crypto driver for verification. Without a
	   driver, we cannot verify — auth status remains indeterminate. */
	me_dbg_wrn(me, "No crypto driver: cannot verify OLT auth result");

	olt_auth_result_list_clear(me_idata);

	return OMCI_SUCCESS;
}

/* ---- Table entry set helpers ---- */

static enum omci_error
olt_random_chl_tbl_entry_set(struct omci_context *context,
	struct me *me,
	struct omci_me_enh_sec_ctrl *upd_data)
{
	struct internal_data *me_idata;
	struct olt_random_chl_list_entry *le, *nle;
	struct olt_random_chl_table_entry *entry =
		&upd_data->olt_random_chl_table;

	me_idata = (struct internal_data *)me->internal_data;

	/* Side effect: OLT challenge status resets to false */
	upd_data->olt_chl_status = 0;

	if (!entry->row_number) {
		/* Clear list — set operation to row 0 */
		olt_random_chl_list_clear(me_idata);
		return OMCI_SUCCESS;
	}

	/* Check for existing entry to overwrite, or find insertion point */
	DLIST_FOR_EACH_SAFE(le, nle,
			&me_idata->olt_random_chl_list_head) {
		if (le->table_entry.row_number == entry->row_number) {
			memcpy(&le->table_entry, entry, sizeof(*entry));
			return OMCI_SUCCESS;
		}
		if (entry->row_number < le->table_entry.row_number) {
			le = le->prev;
			break;
		}
		if (nle->table_entry.row_number == 0 ||
			entry->row_number < nle->table_entry.row_number) {
			break;
		}
	}

	nle = IFXOS_MemAlloc(sizeof(*nle));
	RETURN_IF_MALLOC_ERROR(nle);

	memcpy(&nle->table_entry, entry, sizeof(*entry));

	DLIST_ADD(nle, le);
	++me_idata->olt_random_chl_entries_num;

	return OMCI_SUCCESS;
}

static enum omci_error
onu_random_chl_tbl_entry_set(struct omci_context *context,
	struct me *me,
	const struct onu_random_chl_table_entry *entry)
{
	struct internal_data *me_idata;
	struct onu_random_chl_list_entry *le;

	me_idata = (struct internal_data *)me->internal_data;

	if (!me_idata->onu_random_chl_update_enabled)
		return OMCI_SUCCESS;

	le = IFXOS_MemAlloc(sizeof(*le));
	RETURN_IF_MALLOC_ERROR(le);

	memcpy(&le->table_entry, entry, sizeof(*entry));

	DLIST_ADD_TAIL(le, &me_idata->onu_random_chl_list_head);
	++me_idata->onu_random_chl_entries_num;

	return OMCI_SUCCESS;
}

static enum omci_error
onu_auth_result_tbl_entry_set(struct omci_context *context,
	struct me *me,
	const struct onu_auth_result_table_entry *entry)
{
	struct internal_data *me_idata;
	struct onu_auth_result_list_entry *le;

	me_idata = (struct internal_data *)me->internal_data;

	if (!me_idata->onu_auth_result_update_enabled)
		return OMCI_SUCCESS;

	le = IFXOS_MemAlloc(sizeof(*le));
	RETURN_IF_MALLOC_ERROR(le);

	memcpy(&le->table_entry, entry, sizeof(*entry));

	DLIST_ADD_TAIL(le, &me_idata->onu_auth_result_list_head);
	++me_idata->onu_auth_result_entries_num;

	return OMCI_SUCCESS;
}

static enum omci_error
olt_auth_result_tbl_entry_set(struct omci_context *context,
	struct me *me,
	const struct olt_auth_result_table_entry *entry)
{
	enum omci_error error = OMCI_SUCCESS;
	struct internal_data *me_idata;
	struct olt_auth_result_list_entry *le, *nle;
	uint8_t olt_result_status = 0;

	me_idata = (struct internal_data *)me->internal_data;

	/* Side effect: first write to this table clears OLT result status */
	if (!me_idata->olt_auth_result_entries_num) {
		error = me_attr_write(context, me,
			omci_me_enh_sec_ctrl_olt_result_status,
			&olt_result_status, 1, false);
		if (error != OMCI_SUCCESS)
			return error;
	}

	if (!entry->row_number) {
		olt_auth_result_list_clear(me_idata);
		return OMCI_SUCCESS;
	}

	DLIST_FOR_EACH_SAFE(le, nle,
		&me_idata->olt_auth_result_list_head) {
		if (le->table_entry.row_number == entry->row_number) {
			memcpy(&le->table_entry, entry, sizeof(*entry));
			return OMCI_SUCCESS;
		}
		if (entry->row_number < le->table_entry.row_number) {
			le = le->prev;
			break;
		}
		if (nle->table_entry.row_number == 0 ||
			entry->row_number < nle->table_entry.row_number) {
			break;
		}
	}

	nle = IFXOS_MemAlloc(sizeof(*nle));
	RETURN_IF_MALLOC_ERROR(nle);

	memcpy(&nle->table_entry, entry, sizeof(*entry));

	DLIST_ADD(nle, le);
	++me_idata->olt_auth_result_entries_num;

	return OMCI_SUCCESS;
}

static enum omci_error
broadcast_key_tbl_entry_set(struct omci_context *context,
			    struct me *me,
			    const struct broadcast_key_table_entry *entry)
{
	struct omci_me_enh_sec_ctrl *data =
				(struct omci_me_enh_sec_ctrl *)me->data;
	struct internal_data *me_idata =
				(struct internal_data *)me->internal_data;
	struct broadcast_key_list_entry *le, *nle;
	struct broadcast_key_list_entry *new_le;

	/* ONU crypto capabilities not yet set */
	if (data->onu_selected_crypto_caps == 0)
		return OMCI_SUCCESS;

	if ((entry->row_control & 0x3) == BC_RESERVED) {
		me_dbg_wrn(me, "Broadcast key: reserved row_control");
		return OMCI_ERROR;
	}

	if ((entry->row_control & 0x3) == BC_TABLE_CLEAR) {
		broadcast_key_list_clear(me_idata);
		return OMCI_SUCCESS;
	}

	if ((entry->row_control & 0x3) == BC_ROW_CLEAR) {
		DLIST_FOR_EACH_SAFE(le, nle,
				    &me_idata->broadcast_key_list_head) {
			if (le->table_entry.row_identifier ==
				entry->row_identifier) {
				DLIST_REMOVE(le);
				IFXOS_MemFree(le);
				le = NULL;
				--me_idata->broadcast_key_entries_num;
				return OMCI_SUCCESS;
			}
		}
		return OMCI_ERROR;
	}

	if ((entry->row_control & 0x3) == BC_ROW_SET) {
		DLIST_FOR_EACH_SAFE(le, nle,
				    &me_idata->broadcast_key_list_head) {
			if (le->table_entry.row_identifier ==
				entry->row_identifier) {
				memcpy(&le->table_entry, entry, sizeof(*entry));
				return OMCI_SUCCESS;
			}
			if ((nle->table_entry.row_identifier & 0x0F) >
					(entry->row_identifier & 0x0F)) {
				break;
			}
		}

		new_le = IFXOS_MemAlloc(sizeof(*new_le));
		RETURN_IF_MALLOC_ERROR(new_le);

		memcpy(&new_le->table_entry, entry, sizeof(*entry));

		DLIST_ADD(new_le, le);
		++me_idata->broadcast_key_entries_num;

		/* NOTE: In a full implementation, when all fragments are
		   received, the key would be sent to a driver. We skip
		   that (no crypto driver available). */
	}

	return OMCI_SUCCESS;
}

/* ---- Table copy handlers (for Get/Get-Next) ---- */

static enum omci_error olt_random_chl_tbl_copy(struct omci_context *context,
	struct me *me,
	struct tbl_copy_entry *tbl_copy)
{
	uint32_t index = 0;
	struct internal_data *me_idata;
	struct olt_random_chl_list_entry *le;
	struct olt_random_chl_table_entry *tbl_entry;

	me_idata = (struct internal_data *)me->internal_data;

	tbl_copy->data_size = (uint16_t)
		(sizeof(struct olt_random_chl_table_entry)
			* me_idata->olt_random_chl_entries_num);

	if (!tbl_copy->data_size) {
		tbl_copy->data = NULL;
		return OMCI_SUCCESS;
	}

	tbl_copy->data = IFXOS_MemAlloc(tbl_copy->data_size);
	RETURN_IF_MALLOC_ERROR(tbl_copy->data);

	tbl_entry = (struct olt_random_chl_table_entry *)tbl_copy->data;

	DLIST_FOR_EACH(le, &me_idata->olt_random_chl_list_head) {
		memcpy(&tbl_entry[index], &le->table_entry,
			sizeof(*tbl_entry));
		index++;
	}

	return OMCI_SUCCESS;
}

static enum omci_error onu_random_chl_tbl_copy(struct omci_context *context,
	struct me *me,
	struct tbl_copy_entry *tbl_copy)
{
	uint32_t index = 0;
	struct internal_data *me_idata;
	struct onu_random_chl_list_entry *le;
	struct onu_random_chl_table_entry *tbl_entry;

	me_idata = (struct internal_data *)me->internal_data;

	tbl_copy->data_size = (uint16_t)
		(sizeof(struct onu_random_chl_table_entry)
			* me_idata->onu_random_chl_entries_num);

	if (!tbl_copy->data_size) {
		tbl_copy->data = NULL;
		return OMCI_SUCCESS;
	}

	tbl_copy->data = IFXOS_MemAlloc(tbl_copy->data_size);
	RETURN_IF_MALLOC_ERROR(tbl_copy->data);

	tbl_entry = (struct onu_random_chl_table_entry *)tbl_copy->data;

	DLIST_FOR_EACH(le, &me_idata->onu_random_chl_list_head) {
		memcpy(&tbl_entry[index], &le->table_entry,
			sizeof(*tbl_entry));
		index++;
	}

	return OMCI_SUCCESS;
}

static enum omci_error onu_auth_result_tbl_copy(struct omci_context *context,
	struct me *me,
	struct tbl_copy_entry *tbl_copy)
{
	uint32_t index = 0;
	struct internal_data *me_idata;
	struct onu_auth_result_list_entry *le;
	struct onu_auth_result_table_entry *tbl_entry;

	me_idata = (struct internal_data *)me->internal_data;

	tbl_copy->data_size = (uint16_t)
		(sizeof(struct onu_auth_result_table_entry)
			* me_idata->onu_auth_result_entries_num);

	if (!tbl_copy->data_size) {
		tbl_copy->data = NULL;
		return OMCI_SUCCESS;
	}

	tbl_copy->data = IFXOS_MemAlloc(tbl_copy->data_size);
	RETURN_IF_MALLOC_ERROR(tbl_copy->data);

	tbl_entry = (struct onu_auth_result_table_entry *)tbl_copy->data;

	DLIST_FOR_EACH(le, &me_idata->onu_auth_result_list_head) {
		memcpy(&tbl_entry[index], &le->table_entry,
			sizeof(*tbl_entry));
		index++;
	}

	return OMCI_SUCCESS;
}

static enum omci_error olt_auth_result_tbl_copy(struct omci_context *context,
	struct me *me,
	struct tbl_copy_entry *tbl_copy)
{
	uint32_t index = 0;
	struct internal_data *me_idata;
	struct olt_auth_result_list_entry *le;
	struct olt_auth_result_table_entry *tbl_entry;

	me_idata = (struct internal_data *)me->internal_data;

	tbl_copy->data_size = (uint16_t)
		(sizeof(struct olt_auth_result_table_entry)
			* me_idata->olt_auth_result_entries_num);

	if (!tbl_copy->data_size) {
		tbl_copy->data = NULL;
		return OMCI_SUCCESS;
	}

	tbl_copy->data = IFXOS_MemAlloc(tbl_copy->data_size);
	RETURN_IF_MALLOC_ERROR(tbl_copy->data);

	tbl_entry = (struct olt_auth_result_table_entry *)tbl_copy->data;

	DLIST_FOR_EACH(le, &me_idata->olt_auth_result_list_head) {
		memcpy(&tbl_entry[index], &le->table_entry,
			sizeof(*tbl_entry));
		index++;
	}

	return OMCI_SUCCESS;
}

static enum omci_error broadcast_key_tbl_copy(struct omci_context *context,
	struct me *me,
	struct tbl_copy_entry *tbl_copy)
{
	uint32_t index = 0;
	struct internal_data *me_idata;
	struct broadcast_key_list_entry *le;
	struct broadcast_key_table_entry *tbl_entry;

	me_idata = (struct internal_data *)me->internal_data;

	tbl_copy->data_size = (uint16_t)
		(sizeof(struct broadcast_key_table_entry)
			* me_idata->broadcast_key_entries_num);

	if (!tbl_copy->data_size) {
		tbl_copy->data = NULL;
		return OMCI_SUCCESS;
	}

	tbl_copy->data = IFXOS_MemAlloc(tbl_copy->data_size);
	RETURN_IF_MALLOC_ERROR(tbl_copy->data);

	tbl_entry = (struct broadcast_key_table_entry *)tbl_copy->data;

	DLIST_FOR_EACH(le, &me_idata->broadcast_key_list_head) {
		memcpy(&tbl_entry[index], &le->table_entry,
			sizeof(*tbl_entry));
		index++;
	}

	return OMCI_SUCCESS;
}

/* ---- ME handlers ---- */

static enum omci_error me_tbl_copy(struct omci_context *context,
	struct me *me,
	unsigned int attr,
	struct tbl_copy_entry *tbl_copy)
{
	switch (attr) {
	case omci_me_enh_sec_ctrl_olt_random_chl_table:
		return olt_random_chl_tbl_copy(context, me, tbl_copy);
	case omci_me_enh_sec_ctrl_onu_random_chl_table:
		return onu_random_chl_tbl_copy(context, me, tbl_copy);
	case omci_me_enh_sec_ctrl_onu_auth_result_table:
		return onu_auth_result_tbl_copy(context, me, tbl_copy);
	case omci_me_enh_sec_ctrl_olt_auth_result_table:
		return olt_auth_result_tbl_copy(context, me, tbl_copy);
	case omci_me_enh_sec_ctrl_broadcast_key_table:
		return broadcast_key_tbl_copy(context, me, tbl_copy);
	default:
		return OMCI_ERROR_INVALID_ME_ATTR;
	}
}

/** Attribute getter: MSK name (attr 10).
    STUB: returns zeros (no crypto driver to compute MSK). */
static enum omci_error msk_get(struct omci_context *context,
			       struct me *me,
			       void *data,
			       size_t data_size)
{
	assert(data_size == 16);

	/* Without a crypto driver, MSK is never computed.
	   Return all zeros per G.988 (invalidated key). */
	memset(data, 0, data_size);

	return OMCI_SUCCESS;
}

static enum omci_error me_update(struct omci_context *context,
				 struct me *me,
				 void *data,
				 uint16_t attr_mask)
{
	enum omci_error error;
	struct omci_me_enh_sec_ctrl *upd_data;

	upd_data = (struct omci_me_enh_sec_ctrl *)data;

	if (attr_mask &
		omci_attr2mask(omci_me_enh_sec_ctrl_olt_crypto_caps)) {
		error = olt_crypto_caps_update_action(context, me,
					upd_data);
		RETURN_IF_ERROR(error);
	}

	if (attr_mask &
		omci_attr2mask(omci_me_enh_sec_ctrl_olt_random_chl_table)) {
		error = olt_random_chl_tbl_entry_set(context, me,
					upd_data);
		RETURN_IF_ERROR(error);
	}

	if (attr_mask &
		omci_attr2mask(omci_me_enh_sec_ctrl_olt_chl_status)) {
		error = olt_chl_status_update_action(context, me,
					&upd_data->olt_chl_status);
		RETURN_IF_ERROR(error);
	}

	if (attr_mask &
		omci_attr2mask(omci_me_enh_sec_ctrl_onu_random_chl_table)) {
		error = onu_random_chl_tbl_entry_set(context, me,
					&upd_data->onu_random_chl_table);
		RETURN_IF_ERROR(error);
	}

	if (attr_mask &
		omci_attr2mask(omci_me_enh_sec_ctrl_onu_auth_result_table)) {
		error = onu_auth_result_tbl_entry_set(context, me,
					&upd_data->onu_auth_result_table);
		RETURN_IF_ERROR(error);
	}

	if (attr_mask &
		omci_attr2mask(omci_me_enh_sec_ctrl_olt_auth_result_table)) {
		error = olt_auth_result_tbl_entry_set(context, me,
					&upd_data->olt_auth_result_table);
		RETURN_IF_ERROR(error);
	}

	if (attr_mask &
		omci_attr2mask(omci_me_enh_sec_ctrl_olt_result_status)) {
		error = olt_result_status_update_action(context, me,
					&upd_data->olt_result_status);
		RETURN_IF_ERROR(error);
	}

	if (attr_mask &
		omci_attr2mask(omci_me_enh_sec_ctrl_broadcast_key_table)) {
		error = broadcast_key_tbl_entry_set(context, me,
					&upd_data->broadcast_key_table);
		RETURN_IF_ERROR(error);
	}

	return OMCI_SUCCESS;
}

static enum omci_error me_init(struct omci_context *context,
			       struct me *me,
			       void *init_data,
			       uint16_t suppress_avc)
{
	struct omci_me_enh_sec_ctrl data;
	struct internal_data *me_idata;
	enum omci_error error;

	me->internal_data = IFXOS_MemAlloc(sizeof(*me_idata));
	RETURN_IF_MALLOC_ERROR(me->internal_data);
	memset(me->internal_data, 0, sizeof(struct internal_data));

	me_idata = (struct internal_data *)me->internal_data;

	DLIST_HEAD_INIT(&me_idata->olt_random_chl_list_head);
	me_idata->olt_random_chl_entries_num = 0;

	DLIST_HEAD_INIT(&me_idata->onu_random_chl_list_head);
	me_idata->onu_random_chl_entries_num = 0;
	me_idata->onu_random_chl_update_enabled = false;

	DLIST_HEAD_INIT(&me_idata->onu_auth_result_list_head);
	me_idata->onu_auth_result_entries_num = 0;
	me_idata->onu_auth_result_update_enabled = false;

	DLIST_HEAD_INIT(&me_idata->olt_auth_result_list_head);
	me_idata->olt_auth_result_entries_num = 0;

	DLIST_HEAD_INIT(&me_idata->broadcast_key_list_head);
	me_idata->broadcast_key_entries_num = 0;

	if (init_data)
		memcpy(&data, init_data, sizeof(data));
	else
		memset(&data, 0x00, sizeof(data));

	error = me_data_write(context, me, &data, sizeof(data),
			      ~me->class->inv_attr_mask, suppress_avc);

	return error;
}

static enum omci_error me_shutdown(struct omci_context *context,
				   struct me *me)
{
	olt_random_chl_list_clear(me->internal_data);
	onu_random_chl_list_clear(me->internal_data);
	onu_auth_result_list_clear(me->internal_data);
	olt_auth_result_list_clear(me->internal_data);
	broadcast_key_list_clear(me->internal_data);

	IFXOS_MemFree(me->internal_data);

	return OMCI_SUCCESS;
}

/** Managed Entity class */
struct me_class me_enhanced_security_control_class = {
	/* Class ID */
	OMCI_ME_ENHANCED_SECURITY_CONTROL,
	/* Attributes */
	{
		/* 1. OLT crypto capabilities */
		ATTR_TBL("OLT crypto caps",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_enh_sec_ctrl,
				  olt_crypto_caps),
			 16,
			 OMCI_ATTR_PROP_WR,
			 NULL),
		/* 2. OLT random challenge table */
		ATTR_TBL("OLT rand chl tbl",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_enh_sec_ctrl,
				  olt_random_chl_table),
			 17,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			 NULL),
		/* 3. OLT challenge status */
		ATTR_BOOL("OLT chl status",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_enh_sec_ctrl,
				   olt_chl_status),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),
		/* 4. ONU selected crypto capabilities */
		ATTR_UINT("ONU selected crypto caps",
			  ATTR_SUPPORTED,
			  0x00,
			  0xFF,
			  offsetof(struct omci_me_enh_sec_ctrl,
				   onu_selected_crypto_caps),
			  1,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 5. ONU random challenge table */
		ATTR_TBL("ONU rand chl tbl",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_enh_sec_ctrl,
				  onu_random_chl_table),
			 16,
			 OMCI_ATTR_PROP_RD,
			 NULL),
		/* 6. ONU authentication result table */
		ATTR_TBL("ONU auth result tbl",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_enh_sec_ctrl,
				  onu_auth_result_table),
			 16,
			 OMCI_ATTR_PROP_RD,
			 NULL),
		/* 7. OLT authentication result table */
		ATTR_TBL("OLT auth result tbl",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_enh_sec_ctrl,
				  olt_auth_result_table),
			 17,
			 OMCI_ATTR_PROP_WR,
			 NULL),
		/* 8. OLT result status */
		ATTR_BOOL("OLT result status",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_enh_sec_ctrl,
				   olt_result_status),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),
		/* 9. ONU authentication status */
		ATTR_UINT("ONU auth status",
			  ATTR_SUPPORTED,
			  0x00,
			  0x05,
			  offsetof(struct omci_me_enh_sec_ctrl,
				   onu_auth_status),
			  1,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 10. Master session key name */
		ATTR_STR("Master session key name",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_enh_sec_ctrl,
			 master_session_key_name),
			 16,
			 OMCI_ATTR_PROP_RD,
			 msk_get),
		/* 11. Broadcast key table */
		ATTR_TBL("Broadcast key tbl",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_enh_sec_ctrl,
				  broadcast_key_table),
			 18,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_OPTIONAL,
			 NULL),
		/* 12. Effective key length */
		ATTR_UINT("Effective key length",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xFFFF,
			  offsetof(struct omci_me_enh_sec_ctrl,
				   effective_key_length),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_OPTIONAL,
			  NULL),
		/* 13-16. Not defined */
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF()
	},
	/* Actions */
	{
		NULL, NULL, NULL, NULL,
		/* Create */
		create_action_handle,
		NULL,
		/* Delete */
		delete_action_handle,
		NULL,
		/* Set */
		set_action_handle,
		/* Get */
		get_action_handle,
		NULL,
		/* Get all alarms */
		NULL,
		/* Get all alarms next */
		NULL,
		/* MIB upload */
		NULL,
		/* MIB upload next */
		NULL,
		/* MIB reset */
		NULL,
		/* Alarm */
		NULL,
		/* Attribute value change */
		NULL,
		/* Test */
		NULL,
		/* Start SW download */
		NULL,
		/* Download section */
		NULL,
		/* End SW download */
		NULL,
		/* Activate software */
		NULL,
		/* Commit software */
		NULL,
		/* Synchronize Time */
		NULL,
		/* Reboot */
		NULL,
		/* Get next */
		get_next_action_handle,
		/* Test result */
		NULL,
		/* Get current data */
		NULL
	},
	/* Init Handler */
	me_init,
	/* Shutdown Handler */
	me_shutdown,
	/* Validate Handler */
	default_me_validate,
	/* Update Handler */
	me_update,
	/* Table Attribute Copy Handler */
	me_tbl_copy,
#ifdef INCLUDE_PM
	/* Counters get Handler */
	NULL,
	/* Thresholds set Handler */
	NULL,
#endif
	/* TCA Table */
	NULL,
	/* Data Size */
	sizeof(struct omci_me_enh_sec_ctrl),
	/* Properties */
	OMCI_ME_PROP_NONE,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"Enhanced Security Control",
		/* Access */
		ME_CREATED_BY_ONT,
		/* Supported alarms */
		NULL,
		/* Supported alarms count */
		0,
		/* Support */
		ME_SUPPORTED
	},
#endif
	/* dynamically calculated */
	0, 0, 0, 0, 0, 0
};

/** @} */
