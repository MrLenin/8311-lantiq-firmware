/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "ifxos_memory_alloc.h"

#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_vlan_tagging_filter_data.h"
#include "me/omci_api_vlan_tagging_operation_config_data.h"

struct mapper_entry;

/** Mapper item initialization handler */
typedef void (*mapper_entry_handler)(struct omci_api_ctx *,
				     struct mapper_entry *);

/** Mapper item description entry */
struct mapper_entry {
	/** Item type */
	enum mapper_id_type type;
	/** Number of the same items */
	uint32_t num;
	/** ID minimum value */
	uint32_t min_id;
	/** ID maximum value */
	uint32_t max_id;
	/** Index minimum value */
	uint32_t min_idx;
	/** Index maximum value */
	uint32_t max_idx;
	/** Item type name */
	char name[64];
	/** Mapper entry init handler */
	mapper_entry_handler init;
};

#ifndef ONU_GPE_UNI3_EGRESS_PORT_NUMBER
#  define ONU_GPE_UNI3_EGRESS_PORT_NUMBER ONU_GPE_UNI0_EGRESS_PORT_NUMBER
#endif

void mapper_bridge_port_init(struct omci_api_ctx *ctx,
			     struct mapper_entry *entry)
{
	entry->max_idx = ctx->capability.max_bridge_port - 1;
}

/** Mapper items description */
struct mapper_entry m_entry[] = {
	{
		MAPPER_TCONT_MEID_TO_IDX,
		1,
		0,
		0xffffffff,
		0,
		ONU_GPE_MAX_TCONT - 1,
		"T-CONT -> IDX",
		NULL
	},
	{
		MAPPER_TRAFFSHEDG_MEID_TO_IDX,
		1,
		0,
		0xffff,
		0,
		ONU_GPE_MAX_SCHEDULER - 1,
		"Traffic Scheduler -> IDX",
		NULL
	},
	{
		MAPPER_DOT1PMAPPER_MEID_TO_IDX,
		1,
		0,
		0xffff,
		0,
		ONU_GPE_PMAPPER_TABLE_SIZE - 1,
		"802.1p Mapper Service Profile -> IDX",
		NULL
	},
	{
		MAPPER_DOT1PMAPPER_MEID_TO_DSCP_IDX,
		1,
		0,
		0xffff,
		0,
		ONU_GPE_PMAPPER_TABLE_SIZE - 1,
		"802.1p Mapper Service DSCP Profile -> IDX",
		NULL
	},
	{
		MAPPER_GEMPORTCTP_MEID_TO_PORTID,
		1,
		0,
		0xffff,
		0,
		0xffff,
		"GEM Port NW CTP -> Port ID",
		NULL
	},
	{
		MAPPER_GEMPORTCTP_MEID_TO_IDX,
		1,
		0,
		0xffff,
		0,
		0xffffffff,
		"GEM Port NW CTP -> GPID | GPIX",
		NULL
	},
	{
		MAPPER_GEMPORTCTP_MEID_TO_METER_IDX,
		1,
		0,
		0xffff,
		0,
		0xffff,
		"GEM Port NW CTP -> METER IDX",
		NULL
	},
	{
		MAPPER_MULCTCAST_GEMPORTITP_MEID_TO_CTP_MEID,
		1,
		0,
		0xffff,
		0,
		0xffff,
		"Multicast GEM Port NW ITP -> CTP",
		NULL
	},
	{
		MAPPER_PQUEUE_MEID_TO_IDX,
		1,
		0,
		0xffff,
		0,
		ONU_GPE_MAX_EGRESS_QUEUES - 1,
		"Priority Queue -> IDX",
		NULL
	},
	{
		MAPPER_PORT_TO_EPN,
		1,
		0,
		0xffff,
		ONU_GPE_UNI0_EGRESS_PORT_NUMBER,
		ONU_GPE_UNI3_EGRESS_PORT_NUMBER,
		"Port -> EPN",
		NULL
	},
	{
		MAPPER_MACBRIDGEPORT_MEID_TO_IDX,
		8,
		0,
		0xffffffff,
		0,
		0, /* initialized in \ref mapper_bridge_port_init */
		"MAC Bridge Port -> IDX",
		mapper_bridge_port_init
	},
	{
		MAPPER_MACBRIDGEPORT_MEID_TO_INGRESS_METER_IDX,
		1,
		0,
		0xffffffff,
		0,
		0xffffffff,
		"MAC Bridge Port -> Ingress Meter IDX",
		NULL
	},
	{
		MAPPER_MACBRIDGEPORT_MEID_TO_EGRESS_METER_IDX,
		1,
		0,
		0xffffffff,
		0,
		0xffffffff,
		"MAC Bridge Port -> Egress Meter IDX",
		NULL
	},
	{
		MAPPER_MACBRIDGE_MEID_TO_IDX,
		1,
		0,
		0xffff,
		0,
		ONU_GPE_MAX_BRIDGES - 1,
		"MAC Bridge -> IDX",
		NULL
	},
	{
		MAPPER_PPTPETHUNI_MEID_TO_IDX,
		1,
		0,
		0xffff,
		0,
		8,
		"PPTP Eth UNI -> IDX",
		NULL
	},
	{
		MAPPER_VLANTFD_MEID_TO_VLANGRP,
		1,
		0,
		0xffff,
		0,
		ONU_GPE_VLAN_TABLE_SIZE / OMCI_API_VLAN_GRP_SIZE,
		"VLAN TFD -> VLAN GRP",
		NULL
	},
	{
		MAPPER_VLANTOCD_MEID_TO_VLANRULEGRP_US,
		1,
		0,
		0xffff,
		0,
		ONU_GPE_VLAN_RULE_TABLE_SIZE / OMCI_API_VLAN_RULE_GRP_SIZE,
		"VLAN TOCD -> VLAN Rule GRP (US)",
		NULL
	},
	{
		MAPPER_VLANTOCD_MEID_TO_VLANRULEGRP_DS,
		1,
		0,
		0xffff,
		0,
		ONU_GPE_VLAN_RULE_TABLE_SIZE / OMCI_API_VLAN_RULE_GRP_SIZE,
		"VLAN TOCD -> VLAN Rule GRP (DS)",
		NULL
	},
	{
		MAPPER_MACBRIDGEPORTFPTD_MEID_TO_USEXCEPTIDX,
		1,
		0,
		0xffff,
		0,
		ONU_GPE_EXCEPTION_TABLE_ENTRY_SIZE - 1,
		"MAC BPFPT -> US Exception IDX",
		NULL
	},
	{
		MAPPER_MACBRIDGEPORTFPTD_MEID_TO_DSEXCEPTIDX,
		1,
		0,
		0xffff,
		0,
		ONU_GPE_EXCEPTION_TABLE_ENTRY_SIZE - 1,
		"MAC BPFPT -> DS Exception IDX",
		NULL
	},
	{
		MAPPER_TCONT_TO_EPN,
		1,
		0,
		0xffff,
		ONU_GPE_MIN_ANI_TMU_EGRESS_PORT,
		ONU_GPE_MAX_ANI_TMU_EGRESS_PORT,
		"T-CONT to EPN",
		NULL
	},
	{
		MAPPER_TRAFFDESCR_TO_IDX,
		1,
		0,
		0xffff,
		0,
		32,
		"Traffic Descriptor -> IDX",
		NULL
	},
	{
		MAPPER_TRAFFDESCR_TO_POLICERIDX,
		1,
		0,
		0xffff,
		0,
		32,
		"Traffic Descriptor -> Policer IDX",
		NULL
	},
	{
		MAPPER_EXTVLANCD_MEID_TO_EXTVLANIDX_US,
		1,
		0,
		0xffff,
		0,
		ONU_GPE_EXTENDED_VLAN_TABLE_SIZE,
		"EXTVLAN CD -> Ext VLAN Idx US",
		NULL
	},
	{
		MAPPER_EXTVLANCD_MEID_TO_EXTVLANIDX_DS,
		1,
		0,
		0xffff,
		0,
		ONU_GPE_EXTENDED_VLAN_TABLE_SIZE,
		"EXTVLAN CD -> Ext VLAN Idx DS",
		NULL
	},
	{
		MAPPER_EXTVLANCD_MEID_TO_MC_EXTVLANIDX_US,
		1,
		0,
		0xffff,
		0,
		ONU_GPE_EXTENDED_VLAN_TABLE_SIZE,
		"EXTVLAN CD -> MC Ext VLAN Idx US",
		NULL
	},
	{
		MAPPER_EXTVLANCD_MEID_TO_MC_EXTVLANIDX_DS,
		1,
		0,
		0xffff,
		0,
		ONU_GPE_EXTENDED_VLAN_TABLE_SIZE,
		"EXTVLAN CD -> MC Ext VLAN Idx DS",
		NULL
	},
	{
		MAPPER_EXTVLANCD_MEID_TO_LAN_IDX,
		1,
		0,
		0xffff,
		0,
		4,
		"EXTVLAN CD -> LAN port Idx",
		NULL
	},
	{
		MAPPER_GEMITP_MEID_TO_GPIX,
		1,
		0,
		0xffff,
		0,
		0xffff,
		"GEMITP -> GPIX",
		NULL
	},

	{
		MAPPER_MCOPPROFILE_MEID_TO_IDX,
		1,
		0,
		0xffff,
		0,
		0xffff,
		"MC Op Profile -> IDX",
		NULL
	},
	{
		MAPPER_MCSUBSCR_CFG_INFO_MEID_TO_IDX,
		1,
		0,
		0xffff,
		0,
		0xffff,
		"MC Subscr Cfg -> IDX",
		NULL
	},
	{
		MAPPER_MCSUBSCR_CFG_INFO_MEID_TO_LAN_IDX,
		1,
		0,
		0xffff,
		0,
		4,
		"MC Subscr Cfg -> LAN IDX",
		NULL
	},
	{
		MAPPER_MCSUBSCR_MONITOR_MEID_TO_IDX,
		1,
		0,
		0xffff,
		0,
		0xffff,
		"MC Subscr Mon -> IDX",
		NULL
	},
	{
		MAPPER_PQUEUE_MEID_TO_TBS_IDX,
		1,
		0,
		0xffff,
		0,
		ONU_GPE_MAX_SHAPER - 1,
		"US PQueue -> Token bucket shaper IDX",
		NULL
	},
	{
		MAPPER_VEIP_MEID_TO_IDX,
		1,
		0,
		0xffff,
		0,
		8,
		"VEIP -> IDX",
		NULL
	},
	{
		MAPPER_LCT_MEID_TO_LAN_IDX,
		1,
		0,
		0xffff,
		0,
		4,
		"LCT -> LAN IDX",
		NULL
	},
	{
		MAPPER_LCT_MEID_TO_METER_IDX,
		1,
		0,
		0xffff,
		0,
		0xffff,
		"LCT -> METER IDX",
		NULL
	},

#ifdef INCLUDE_OMCI_API_VOIP
	{
		MAPPER_SIP_AGT_TO_IDX,
		1,
		0x0000,
		0xffff,
		0,
		OMCI_API_SIP_AGENTS_NUM,
		"SIP Agent -> IDX",
		NULL
	},
	{
		MAPPER_SIP_USR_TO_IDX,
		1,
		0x0000,
		0xffff,
		0,
		OMCI_API_SIP_USERS_NUM,
		"SIP User -> IDX",
		NULL
	},
	{
		MAPPER_PPTPPOTSUNI_MEID_TO_IDX,
		1,
		0,
		0xffff,
		0,
		8,
		"PPTP POTS UNI -> IDX",
		NULL
	}
#endif
};

/** Return mapper for particular type */
static struct mapper *mapper_get(struct mapper *mapper[MAPPER_IDTYPE_MAX],
				 enum mapper_id_type id_type)
{
	if (mapper[id_type])
		return mapper[id_type];

	DBG(OMCI_API_ERR, ("Not initialized mapper for id type %d\n", id_type));
	return NULL;
}

/** Verify ID type

   \param[in] id_type ID Type

   \return
      - OMCI_API_SUCCESS ID Type is valid
      - OMCI_API_ERROR   ID type is invalid
*/
static enum omci_api_return id_type_verify(enum mapper_id_type id_type)
{
	if (/*(id_type >= MAPPER_IDTYPE_MIN) && */(id_type < MAPPER_IDTYPE_MAX))
		return OMCI_API_SUCCESS;

	DBG(OMCI_API_ERR, ("Invalid id type %d (> %d)\n", id_type,
		    MAPPER_IDTYPE_MAX));

	return OMCI_API_ERROR;
}

/** Verify key

   \note Verify key using range (minimal and maximal values)
      of key defined in appropriate Mapper

   \param[in] id_type  ID Type
   \param[in] key_type Key Type
   \param[in] key      Key

   \return
      - OMCI_API_SUCCESS Key is valid
      - OMCI_API_ERROR   Key is invalid (out of range)
*/
static enum omci_api_return key_verify(struct mapper *mapper[MAPPER_IDTYPE_MAX],
				       enum mapper_id_type id_type,
				       enum mapper_key_type key_type,
				       uint32_t key)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct mapper *m = NULL;

	ret = id_type_verify(id_type);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;

	m = mapper_get(mapper, id_type);
	if (!m)
		return OMCI_API_ERROR;

	if ((key >= m->min_key[key_type]) && (key <= m->max_key[key_type]))
		return OMCI_API_SUCCESS;

	DBG(OMCI_API_ERR, ("Key %d is out of range [%d .. %d] "
		    "(key type %d, id type %d)\n",
		    key,
		    m->min_key[key_type],
		    m->max_key[key_type],
		    key_type,
		    id_type));

	return OMCI_API_ERROR;
}

/** Create Mapping List Item

   \param[in]  key  Array of keys
   \param[out] item Pointer to pointer to created item

   \return
      - OMCI_API_SUCCESS Item was created successfully
      - OMCI_API_ERROR   Item creation failed
*/
static enum omci_api_return item_create(uint32_t key[KEY_TYPE_NUM],
					struct mapper_map_list **item)
{
	uint8_t i = 0;

	*item = (struct mapper_map_list *)
				IFXOS_MemAlloc(sizeof(struct mapper_map_list));
	if (!(*item)) {
		DBG(OMCI_API_ERR, ("Not enough memory for new mapper item\n"));
		return OMCI_API_ERROR;
	}

	for (i = 0; i < KEY_TYPE_NUM; i++) {
		(*item)->key[i] = key[i];
		(*item)->next[i] = NULL;
	}

	return OMCI_API_SUCCESS;
}

/** Delete Mapping List Item

   \param[in] item Pointer to Item to delete
*/
static void item_delete(struct mapper_map_list *item)
{
	IFXOS_MemFree((IFX_void_t *) item);
}

/** Add Item to Mapping list

   \param[in] id_type ID Type
   \param[in] pos     Array of position where to add Item
   \param[in] item    Pointer to Item to add

   \return
      - OMCI_API_SUCCESS Item was added successfully
      - OMCI_API_ERROR   Item addition failed
*/
static enum omci_api_return item_add(struct mapper *mapper[MAPPER_IDTYPE_MAX],
				     enum mapper_id_type id_type,
				     struct mapper_map_list *pos[KEY_TYPE_NUM],
				     struct mapper_map_list *item)
{
	struct mapper *m = NULL;
	uint8_t i = 0;

	m = mapper_get(mapper, id_type);
	if (!m) {
		DBG(OMCI_API_ERR, ("Can't map item of id type %d\n", id_type));
		return OMCI_API_ERROR;
	}

	for (i = 0; i < KEY_TYPE_NUM; i++) {
		if (pos[i] == NULL) {
			item->next[i] = m->list_head[i];
			m->list_head[i] = item;
		} else {
			item->next[i] = pos[i]->next[i];
			pos[i]->next[i] = item;
		}
	}

	return OMCI_API_SUCCESS;
}

/** Remove Item from Mapping List

   \note Just remove Item from the Mapping list,
      but NOT delete Item (for deletion use
      \ref item_delete)

   \param[in] id_type ID Type
   \param[in] pos     Array of Item positions

   \return
      - Pointer to the removed Item
      - NULL pointer if Item removing failed
*/
static struct mapper_map_list *item_remove(struct mapper
						*mapper[MAPPER_IDTYPE_MAX],
					   enum mapper_id_type id_type,
					   struct mapper_map_list
						*pos[KEY_TYPE_NUM])
{
	struct mapper *m = NULL;
	struct mapper_map_list *removed_item = NULL;
	uint8_t i = 0;

	m = mapper_get(mapper, id_type);
	if (!m)
		return removed_item;

	for (i = 0; i < KEY_TYPE_NUM; i++) {
		if (!(pos[i])) {
			removed_item = m->list_head[i];
			m->list_head[i] =
			    m->list_head[i]->next[i];
		} else {
			removed_item = pos[i]->next[i];
			pos[i]->next[i] = pos[i]->next[i]->next[i];
		}
	}

	if (!removed_item)
		DBG(OMCI_API_ERR, ("Item with id type %d removing failed\n",
								      id_type));

	return removed_item;
}

/** Retrieve Item for the given position

   \param[in] id_type  ID Type
   \param[in] key_type Key Type
   \param[in] pos      Item Position

   \return
      - Pointer to the Item
      - NULL if Item retrieving failed
*/
static struct mapper_map_list *item_get(struct mapper
						*mapper[MAPPER_IDTYPE_MAX],
					enum mapper_id_type id_type,
					enum mapper_key_type key_type,
					struct mapper_map_list *pos)
{
	struct mapper *m = NULL;
	struct mapper_map_list *item = NULL;

	m = mapper_get(mapper, id_type);
	if (!m)
		return item;

	if (!pos)
		item = m->list_head[key_type];
	else
		item = pos->next[key_type];

	return item;
}

/** Find Item in the Mapping List with the given Key number

   \param[in]  id_type  ID Type
   \param[in]  key_type Key Type
   \param[in]  key      Key
   \param[out] pos      Pointer to array of Item positions

   \return
      - OMCI_API_SUCCESS   Item was found successfully
      - OMCI_API_NOT_FOUND Item was not found
      - OMCI_API_ERROR     Item searching failed
*/
static enum omci_api_return item_find(struct mapper *mapper[MAPPER_IDTYPE_MAX],
				      enum mapper_id_type id_type,
				      enum mapper_key_type key_type,
				      uint32_t key,
				      struct mapper_map_list **pos)
{
	struct mapper *m = NULL;
	struct mapper_map_list *item = NULL;

	m = mapper_get(mapper, id_type);
	if (!m)
		return OMCI_API_ERROR;

	*pos = NULL;

	item = m->list_head[key_type];
	if ((!item))
		return OMCI_API_NOT_FOUND;

	if (key < item->key[key_type])
		return OMCI_API_NOT_FOUND;

	if (item->key[key_type] == key)
		return OMCI_API_SUCCESS;

	while (item->next[key_type]) {
		if (item->next[key_type]->key[key_type] == key) {
			*pos = item;
			return OMCI_API_SUCCESS;
		}
		if (key < item->next[key_type]->key[key_type]) {
			*pos = item;
			return OMCI_API_NOT_FOUND;
		}
		item = item->next[key_type];
	}

	*pos = item;

	return OMCI_API_NOT_FOUND;
}

/** Retrieve key from the given Item with respect to the key Type

   \param[in]  item     Item to retrieve key from
   \param[in]  key_type Key Type
   \param[out] key      Retrieved item

   \return
      - OMCI_API_SUCCESS Key was retrieved
      - OMCI_API_ERROR   Key retrieving failed
*/
static void key_get(struct mapper_map_list *item,
		    enum mapper_key_type key_type,
		    uint32_t *key)
{
	*key = item->key[key_type];
}

/** Find lowest NOT mapped key with respect to the
   key Type

   \param[in]  id_type  ID Type
   \param[in]  key_type Key Type
   \param[out] free_key Free key value
   \param[out] pos      Free position of Item with found Key

   \return
      - OMCI_API_SUCCESS   Free key was found successfully
      - OMCI_API_NOT_FOUND Free key was not found
      - OMCI_API_ERROR     Free key searching failed
*/
static enum omci_api_return free_key_find(struct mapper
						*mapper[MAPPER_IDTYPE_MAX],
					  enum mapper_id_type id_type,
					  enum mapper_key_type key_type,
					  uint32_t *free_key,
					  struct mapper_map_list **pos)
{
	struct mapper *m = NULL;
	struct mapper_map_list *item = NULL;

	m = mapper_get(mapper, id_type);
	if (!m)
		return OMCI_API_ERROR;

	*pos = NULL;

	item = m->list_head[key_type];
	if ((!item) || ((item->key[key_type] - m->min_key[key_type]) > 0)) {
		*free_key = m->min_key[key_type];
		return OMCI_API_SUCCESS;
	}

	while (item->next[key_type]) {
		if ((item->next[key_type]->key[key_type] -
		     item->key[key_type]) > 1) {
			*pos = item;
			*free_key = item->key[key_type] + 1;
			return OMCI_API_SUCCESS;
		}
		item = item->next[key_type];
	}

	if ((item->key[key_type]) == (m->max_key[key_type])) {
		DBG(OMCI_API_ERR,
			("No free key for id type %d and key type %d\n",
			    id_type, key_type));
		return OMCI_API_NOT_FOUND;
	}

	*pos = item;
	*free_key = item->key[key_type] + 1;

	return OMCI_API_SUCCESS;
}

/** Initialize mapping support for the given ID type

   \param[in] id_type ID Type
   \param[in] min_id  Minimal value of id
   \param[in] max_id  Maximal value of id
   \param[in] min_idx Minimal value of index
   \param[in] max_idx Maximal value of index
*/
static enum omci_api_return id_type_init(struct mapper
						*mapper[MAPPER_IDTYPE_MAX],
					 enum mapper_id_type id_type,
					 uint32_t min_id, uint32_t max_id,
					 uint32_t min_idx, uint32_t max_idx)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct mapper *m = NULL;

	DBG(OMCI_API_MSG, ("Init %3u map "
			   "id=[0x%08x,0x%08x] idx=[0x%08x,0x%08x]\n",
			   id_type, min_id, max_id, min_idx, max_idx));

	ret = id_type_verify(id_type);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;

	m = (struct mapper *) IFXOS_MemAlloc(sizeof(struct mapper));
	if (!m) {
		DBG(OMCI_API_ERR, ("Not enough memory for new id type %d\n",
								      id_type));
		return OMCI_API_ERROR;
	}

	m->min_key[KEY_TYPE_ID] = min_id;
	m->max_key[KEY_TYPE_ID] = max_id;
	m->list_head[KEY_TYPE_ID] = NULL;

	m->min_key[KEY_TYPE_INDEX] = min_idx;
	m->max_key[KEY_TYPE_INDEX] = max_idx;
	m->list_head[KEY_TYPE_INDEX] = NULL;

	mapper[id_type] = m;

	return OMCI_API_SUCCESS;
}

enum omci_api_return mapper_init(struct omci_api_ctx *ctx)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint32_t i, j;

	for (i = 0; i < sizeof(m_entry) / sizeof(m_entry[0]); i++) {
		for (j = 0; j < m_entry[i].num; j++) {
			if (m_entry[i].init)
				m_entry[i].init(ctx, &m_entry[i]);

			ret = id_type_init(ctx->mapper,
					   (enum mapper_id_type)
					   (m_entry[i].type + j),
					   m_entry[i].min_id,
					   m_entry[i].max_id,
					   m_entry[i].min_idx,
					   m_entry[i].max_idx);

			if (ret != OMCI_API_SUCCESS) {
				DBG(OMCI_API_ERR,
					("Can't initialize mapping for %s\n",
					    m_entry[i].name));
				return ret;
			}
		}
	}

#if 0				/* FOR FPGA OMCI IS ON TCONT #1 */
	ret = explicit_map(ctx,
			   MAPPER_TCONT_MEID_TO_IDX, 0xdeadbeef /* unique */ ,
			   OMCI_TCIX);
	if (ret != OMCI_API_SUCCESS)
		return ret;
#endif

	return OMCI_API_SUCCESS;
}

enum omci_api_return mapper_shutdown(struct omci_api_ctx *ctx)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	enum mapper_id_type id_type = MAPPER_IDTYPE_MIN;
	struct mapper_map_list *item_pos[KEY_TYPE_NUM] = { NULL };
	struct mapper_map_list *item = NULL;
	uint32_t key;

	for (id_type = MAPPER_IDTYPE_MIN; id_type < MAPPER_IDTYPE_MAX;
	     id_type++) {
		if (ctx->mapper[id_type]) {
			item = item_get(ctx->mapper, id_type,
					KEY_TYPE_ID, item_pos[KEY_TYPE_ID]);
			while (item) {
				key_get(item, KEY_TYPE_INDEX, &key);

				ret = item_find(ctx->mapper, id_type,
					       KEY_TYPE_INDEX, key,
					       &item_pos[KEY_TYPE_INDEX]);
				if (ret != OMCI_API_SUCCESS) {
					DBG(OMCI_API_ERR,
						("Index %d searching error "
						 "%d for id type %d\n",
						    key, ret, id_type));
					return OMCI_API_ERROR;
				}

				item = item_remove(ctx->mapper, id_type,
						   item_pos);
				if (!item)
					return OMCI_API_ERROR;

				item_delete(item);

				item = item_get(ctx->mapper, id_type,
						KEY_TYPE_ID,
						item_pos[KEY_TYPE_ID]);
			}
			IFXOS_MemFree((IFX_void_t *) ctx->mapper[id_type]);
		}
	}

	return OMCI_API_SUCCESS;
}

enum omci_api_return omci_api_mapper_reset(struct omci_api_ctx *ctx)
{
	return mapper_shutdown(ctx) | mapper_init(ctx);
}

enum omci_api_return explicit_map(struct omci_api_ctx *ctx,
				  enum mapper_id_type id_type,
				  uint32_t id,
				  uint32_t idx)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint32_t key[KEY_TYPE_NUM] = { 0 };
	struct mapper_map_list *item_pos[KEY_TYPE_NUM] = { NULL };
	struct mapper_map_list *item = NULL;
	uint8_t i = 0;

	DBG(OMCI_API_MSG, ("exlicit_map(%u, %u, %u)\n", id_type, id, idx));

	ret = id_type_verify(id_type);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;

	key[KEY_TYPE_ID] = id;
	key[KEY_TYPE_INDEX] = idx;

	for (i = 0; i < KEY_TYPE_NUM; i++) {
		ret = key_verify(ctx->mapper, id_type,
				 (enum mapper_key_type) i, key[i]);
		if (ret != OMCI_API_SUCCESS)
			return OMCI_API_ERROR;
	}

	for (i = 0; i < KEY_TYPE_NUM; i++) {
		ret = item_find(ctx->mapper, id_type,
			       (enum mapper_key_type) i, key[i], &item_pos[i]);
		if (ret == OMCI_API_SUCCESS) {
			DBG(OMCI_API_ERR,
				("Key %d with type %d is already mapped "
				 "for id type %d\n",
				    key[i], i, id_type));
			return OMCI_API_ERROR;
		}
	}

	ret = item_create(key, &item);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;

	ret = item_add(ctx->mapper, id_type, item_pos, item);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;

	return OMCI_API_SUCCESS;
}

enum omci_api_return id_map(struct omci_api_ctx *ctx,
			    enum mapper_id_type id_type,
			    uint32_t id,
			    uint32_t *idx)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct mapper_map_list *item_pos[KEY_TYPE_NUM] = { NULL };
	struct mapper_map_list *item = NULL;
	uint32_t key[KEY_TYPE_NUM] = { 0 };

	DBG(OMCI_API_MSG, ("id_map(%u, %u, %p)\n", id_type, id, idx));

	ret = key_verify(ctx->mapper, id_type, KEY_TYPE_ID, id);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;

	ret = item_find(ctx->mapper, id_type, KEY_TYPE_ID, id,
			&item_pos[KEY_TYPE_ID]);
	if (ret == OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("Id %d is already mapped for id type %d\n",
			    id, id_type));
		return OMCI_API_ERROR;
	}

	ret = free_key_find(ctx->mapper, id_type,
			  KEY_TYPE_INDEX, idx, &item_pos[KEY_TYPE_INDEX]);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;

	key[KEY_TYPE_ID] = id;
	key[KEY_TYPE_INDEX] = *idx;

	ret = item_create(key, &item);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;

	ret = item_add(ctx->mapper, id_type, item_pos, item);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;

	return OMCI_API_SUCCESS;
}

enum omci_api_return index_map(struct omci_api_ctx *ctx,
			       enum mapper_id_type id_type,
			       uint32_t *id,
			       uint32_t idx)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct mapper_map_list *item_pos[KEY_TYPE_NUM] = { NULL };
	struct mapper_map_list *item = NULL;
	uint32_t key[KEY_TYPE_NUM] = { 0 };

	DBG(OMCI_API_MSG, ("index_map(%u, %p, %u)\n", id_type, id, idx));

	ret = key_verify(ctx->mapper, id_type, KEY_TYPE_INDEX, idx);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;

	ret = item_find(ctx->mapper, id_type, KEY_TYPE_INDEX, idx,
			&item_pos[KEY_TYPE_INDEX]);
	if (ret == OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR,
			("Index %d is already mapped for id type %d\n",
					idx, id_type));
		return OMCI_API_ERROR;
	}

	ret = free_key_find(ctx->mapper, id_type, KEY_TYPE_ID, id,
			    &item_pos[KEY_TYPE_ID]);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;

	key[KEY_TYPE_ID] = *id;
	key[KEY_TYPE_INDEX] = idx;

	ret = item_create(key, &item);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;

	ret = item_add(ctx->mapper, id_type, item_pos, item);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;

	return OMCI_API_SUCCESS;
}

enum omci_api_return index_get(struct omci_api_ctx *ctx,
			       enum mapper_id_type id_type,
			       uint32_t id,
			       uint32_t *idx)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct mapper_map_list *item_pos = NULL;
	struct mapper_map_list *item = NULL;

	DBG(OMCI_API_MSG, ("index_get(%u, %u, %p)\n", id_type, id, idx));

	ret = id_type_verify(id_type);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;

	ret = key_verify(ctx->mapper, id_type, KEY_TYPE_ID, id);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;

	ret = item_find(ctx->mapper, id_type, KEY_TYPE_ID, id, &item_pos);
	if (ret == OMCI_API_NOT_FOUND) {
		DBG(OMCI_API_MSG,
			("Id %d is not found for id type %d (index_get)\n",
			    id, id_type));
		return OMCI_API_NOT_FOUND;
	} else if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("Id %d searching error %d for id type %d "
				   "(index_get)\n", id, ret, id_type));
		return OMCI_API_ERROR;
	}

	item = item_get(ctx->mapper, id_type, KEY_TYPE_ID, item_pos);
	if (!item) {
		DBG(OMCI_API_ERR, ("Id retrieving failed for id type %d "
				   "(index_get)\n", id_type));
		return OMCI_API_ERROR;
	}

	key_get(item, KEY_TYPE_INDEX, idx);

	return OMCI_API_SUCCESS;
}

enum omci_api_return id_get(struct omci_api_ctx *ctx,
			    enum mapper_id_type id_type,
			    uint32_t *id,
			    uint32_t idx)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct mapper_map_list *item_pos = NULL;
	struct mapper_map_list *item = NULL;

	DBG(OMCI_API_MSG, ("id_get(%u, %p, %u)\n", id_type, id, idx));

	ret = id_type_verify(id_type);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;

	ret = key_verify(ctx->mapper, id_type, KEY_TYPE_INDEX, idx);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;

	ret = item_find(ctx->mapper, id_type, KEY_TYPE_INDEX, idx, &item_pos);
	if (ret == OMCI_API_NOT_FOUND) {
		DBG(OMCI_API_MSG,
			("Index %d is not found for id type %d (id_get)\n",
			    idx, id_type));
		return OMCI_API_NOT_FOUND;
	} else if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("Index %d searching error %d for id type %d "
				   "(id_get)\n", idx, ret, id_type));
		return OMCI_API_ERROR;
	}

	item = item_get(ctx->mapper, id_type, KEY_TYPE_INDEX, item_pos);
	if (!item) {
		DBG(OMCI_API_ERR,
			("Index retrieving failed for id type %d (id_get)\n",
			    id_type));
		return OMCI_API_ERROR;
	}

	key_get(item, KEY_TYPE_ID, id);

	return OMCI_API_SUCCESS;
}

enum omci_api_return index_map_or_get(struct omci_api_ctx *ctx,
				      const uint16_t me_id,
				      const enum mapper_id_type id_type,
				      uint32_t *idx)
{
	enum omci_api_return ret = index_get(ctx, id_type, me_id, idx);

	if (ret == OMCI_API_NOT_FOUND)
		ret = id_map(ctx, id_type, me_id, idx);

	return ret;
}

enum omci_api_return index_array_get(struct omci_api_ctx *ctx,
				     enum mapper_id_type id_type,
				     uint32_t **idx,
				     uint32_t *size)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct mapper_map_list *item = NULL;
	uint32_t sz = 0;
	uint32_t i = 0;
	struct mapper *m;

	DBG(OMCI_API_MSG, ("index_array_get(%u, %p, %p)\n", id_type,
							    idx, size));

	ret = id_type_verify(id_type);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;

	m = mapper_get(ctx->mapper, id_type);
	if (!m)
		return OMCI_API_ERROR;

	item = m->list_head[KEY_TYPE_INDEX];
	if (!item) {
		*idx = NULL;
		*size = 0;
		return OMCI_API_SUCCESS;
	}

	while (item) {
		sz++;
		item = item->next[KEY_TYPE_INDEX];
	}

	*idx = (uint32_t *)IFXOS_MemAlloc(sz);
	if (!(*idx)) {
		DBG(OMCI_API_ERR,
			("Not enough memory for index array of id type %d\n",
			    id_type));
		return OMCI_API_ERROR;
	}

	item = m->list_head[KEY_TYPE_INDEX];
	while (item) {
		(*idx)[i++] = item->key[KEY_TYPE_INDEX];
		item = item->next[KEY_TYPE_INDEX];
	}
	*size = sz;

	return OMCI_API_SUCCESS;
}

enum omci_api_return id_array_get(struct omci_api_ctx *ctx,
				  enum mapper_id_type id_type,
				  uint32_t **id,
				  uint32_t *size)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct mapper_map_list *item = NULL;
	uint32_t sz = 0;
	uint32_t i = 0;
	struct mapper *m;

	DBG(OMCI_API_MSG, ("id_array_get(%u, %p, %p)\n", id_type, id, size));

	ret = id_type_verify(id_type);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;

	m = mapper_get(ctx->mapper, id_type);
	if (!m)
		return OMCI_API_ERROR;

	item = m->list_head[KEY_TYPE_ID];
	if (!item) {
		*id = NULL;
		*size = 0;
		return OMCI_API_SUCCESS;
	}

	while (item) {
		sz++;
		item = item->next[KEY_TYPE_ID];
	}

	*id = (uint32_t *)IFXOS_MemAlloc(sz);
	if (!(*id)) {
		DBG(OMCI_API_ERR,
			("Not enough memory for id array of id type %d\n",
			    id_type));
		return OMCI_API_ERROR;
	}

	item = m->list_head[KEY_TYPE_ID];
	while (item) {
		(*id)[i++] = item->key[KEY_TYPE_ID];
		item = item->next[KEY_TYPE_ID];
	}
	*size = sz;

	return OMCI_API_SUCCESS;
}

enum omci_api_return id_remove(struct omci_api_ctx *ctx,
			       enum mapper_id_type id_type,
			       uint32_t id)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct mapper_map_list *item_pos[KEY_TYPE_NUM] = { NULL };
	struct mapper_map_list *item = NULL;
	uint32_t idx = 0;

	DBG(OMCI_API_MSG, ("id_remove(%u, %u)\n", id_type, id));

	ret = id_type_verify(id_type);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;

	ret = key_verify(ctx->mapper, id_type, KEY_TYPE_ID, id);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;

	ret = item_find(ctx->mapper, id_type, KEY_TYPE_ID, id,
			&item_pos[KEY_TYPE_ID]);
	if (ret == OMCI_API_NOT_FOUND) {
		DBG(OMCI_API_ERR,
			("Id %d is not found for id type %d (id_remove)\n",
			    id, id_type));
		return OMCI_API_NOT_FOUND;
	} else if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("Id %d searching error %d for id type %d "
				   "(id_remove)\n", id, ret, id_type));
		return OMCI_API_ERROR;
	}

	item = item_get(ctx->mapper, id_type, KEY_TYPE_ID,
			item_pos[KEY_TYPE_ID]);
	if (!item) {
		DBG(OMCI_API_ERR,
			("Id retrieving failed for id type %d (id_remove)\n",
			    id_type));
		return OMCI_API_ERROR;
	}

	key_get(item, KEY_TYPE_INDEX, &idx);

	ret = item_find(ctx->mapper, id_type, KEY_TYPE_INDEX, idx,
			&item_pos[KEY_TYPE_INDEX]);
	if (ret == OMCI_API_NOT_FOUND) {
		DBG(OMCI_API_ERR, ("Index %d is not found for id type %d "
			    "(id_remove)\n", idx, id_type));
		return OMCI_API_NOT_FOUND;
	} else if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("Index %d searching error %d for id type %d "
				   "(id_remove)\n", idx, ret, id_type));
		return OMCI_API_ERROR;
	}

	item = item_remove(ctx->mapper, id_type, item_pos);
	if (!item)
		return OMCI_API_ERROR;

	item_delete(item);
	return OMCI_API_SUCCESS;
}

enum omci_api_return index_remove(struct omci_api_ctx *ctx,
				  enum mapper_id_type id_type,
				  uint32_t idx)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct mapper_map_list *item_pos[KEY_TYPE_NUM] = { NULL };
	struct mapper_map_list *item = NULL;
	uint32_t id = 0;

	DBG(OMCI_API_MSG, ("index_remove(%u, %u)\n", id_type, idx));

	ret = id_type_verify(id_type);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;

	ret = key_verify(ctx->mapper, id_type, KEY_TYPE_INDEX, idx);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;

	ret = item_find(ctx->mapper, id_type, KEY_TYPE_INDEX, idx,
			&item_pos[KEY_TYPE_INDEX]);
	if (ret == OMCI_API_NOT_FOUND) {
		DBG(OMCI_API_ERR, ("Index %d is not found for id type %d "
			    "(index_remove)\n", idx, id_type));
		return OMCI_API_NOT_FOUND;
	} else if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("Index %d searching error %d for id type %d "
			    "(index_remove)\n", idx, ret, id_type));
		return OMCI_API_ERROR;
	}

	item = item_get(ctx->mapper, id_type, KEY_TYPE_INDEX,
			item_pos[KEY_TYPE_INDEX]);
	if (!item) {
		DBG(OMCI_API_ERR, ("Index retrieving failed for id type %d "
			    "(index_remove)\n", id_type));
		return OMCI_API_ERROR;
	}

	key_get(item, KEY_TYPE_ID, &id);

	ret = item_find(ctx->mapper, id_type, KEY_TYPE_ID, id,
			&item_pos[KEY_TYPE_ID]);
	if (ret == OMCI_API_NOT_FOUND) {
		DBG(OMCI_API_ERR, ("Id %d is not found for id type %d "
			    "(index_remove)\n", id, id_type));
		return OMCI_API_NOT_FOUND;
	} else if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("Id %d searching error %d for id type %d "
			    "(index_remove)\n",
			    id, ret, id_type));
		return OMCI_API_ERROR;
	}

	item = item_remove(ctx->mapper, id_type, item_pos);
	if (!item)
		return OMCI_API_ERROR;

	item_delete(item);
	return OMCI_API_SUCCESS;
}

enum omci_api_return omci_api_mapper_dump(struct omci_api_ctx *ctx)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct mapper_map_list *item = NULL;
	enum mapper_id_type type;
	uint32_t id, index;
	uint32_t i;

	if (ctx == NULL)
		return OMCI_API_NOT_AVAIL;

	printf("+----------------------------------------------------+"
		"------------+------------\n");
	printf("| Type                                               |"
		  " Id         | Index\n");
	printf("+----------------------------------------------------+"
		"------------+------------\n");

	for (type = MAPPER_IDTYPE_MIN; type < MAPPER_IDTYPE_MAX; type++) {
		if (ctx->mapper[type] == NULL)
			continue;

		item = ctx->mapper[type]->list_head[KEY_TYPE_ID];

		while (item) {
			key_get(item, KEY_TYPE_ID, &id);
			key_get(item, KEY_TYPE_INDEX, &index);

			printf("| 0x%02x ", type);

			for (i = 0; i < sizeof(m_entry) / sizeof(m_entry[0]);
			     i++) {

				if (type >= m_entry[i].type
				    && type <= m_entry[i].type
				    + m_entry[i].num - 1) {
					printf("%-45s ", m_entry[i].name);
					break;
				}
			}
			printf("| 0x%08x | 0x%08x\n", id, index);

			item = item->next[KEY_TYPE_ID];
		}

		if (ctx->mapper[type]->list_head[KEY_TYPE_ID])
			printf
			    ("+-----------------------------------------------"
			     "-----+------------+------------\n");
	}

	return OMCI_API_SUCCESS;
}
