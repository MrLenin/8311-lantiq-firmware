/******************************************************************************
 * Stub ME implementations for v7.5.1 parity
 *
 * These MEs exist in the shipping binary but not in the v4.5.0 SDK source.
 * They are implemented as data-only stubs: Create/Delete/Get/Set operations
 * store and retrieve attribute data in the MIB, but no hardware ioctls are
 * issued. This is sufficient for OLT interoperability — the OLT sees the
 * MEs in the MIB upload and can provision them without error responses.
 ******************************************************************************/
#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_stub_mes.h"

/* ========================================================================
 * ME 299: Dot1ag Maintenance Domain
 * Created/deleted by OLT. 6 attributes. No hardware interaction.
 * ======================================================================== */
struct me_class me_dot1ag_md_class = {
	OMCI_ME_DOT1AG_MAINTENANCE_DOMAIN,
	{
		/* 1 */ ATTR_UINT("MD level", ATTR_SUPPORTED, 0, 7,
			offsetof(struct omci_dot1ag_md, md_level), 1,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC, NULL),
		/* 2 */ ATTR_UINT("MD name format", ATTR_SUPPORTED, 0, 0xFF,
			offsetof(struct omci_dot1ag_md, md_name_format), 1,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC, NULL),
		/* 3 */ ATTR_STR("MD name 1", ATTR_SUPPORTED,
			offsetof(struct omci_dot1ag_md, md_name_1), 25,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR, NULL),
		/* 4 */ ATTR_STR("MD name 2", ATTR_SUPPORTED,
			offsetof(struct omci_dot1ag_md, md_name_2), 25,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR, NULL),
		/* 5 */ ATTR_UINT("MHF creation", ATTR_SUPPORTED, 0, 0xFF,
			offsetof(struct omci_dot1ag_md, mhf_creation), 1,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC, NULL),
		/* 6 */ ATTR_UINT("Sender ID permission", ATTR_SUPPORTED, 0, 0xFF,
			offsetof(struct omci_dot1ag_md, snd_id_perm), 1,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC, NULL),
		ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF(),
		ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF(),
		ATTR_NOT_DEF(), ATTR_NOT_DEF()
	},
	{ NULL, NULL, NULL, NULL,
	  create_action_handle, NULL, delete_action_handle, NULL,
	  set_action_handle, get_action_handle, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL },
	default_me_init, default_me_shutdown, default_me_validate,
	NULL, NULL, NULL,
#ifdef INCLUDE_PM
	NULL, NULL,
#endif
	NULL, sizeof(struct omci_dot1ag_md), OMCI_ME_PROP_NONE,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{ "Dot1ag maintenance domain", ME_CREATED_BY_OLT, NULL, 0, ME_SUPPORTED },
#endif
	0, 0, 0, 0, 0, 0
};

/* ========================================================================
 * ME 300: Dot1ag Maintenance Association
 * Created/deleted by OLT. 8 attributes.
 * ======================================================================== */
struct me_class me_dot1ag_ma_class = {
	OMCI_ME_DOT1AG_MAINTENANCE_ASSOCIATION,
	{
		/* 1 */ ATTR_UINT("MD pointer", ATTR_SUPPORTED, 0, 0xFFFF,
			offsetof(struct omci_dot1ag_ma, md_ptr), 2,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC, NULL),
		/* 2 */ ATTR_UINT("Short MA name format", ATTR_SUPPORTED, 0, 0xFF,
			offsetof(struct omci_dot1ag_ma, ma_name_format), 1,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC, NULL),
		/* 3 */ ATTR_STR("MA name 1", ATTR_SUPPORTED,
			offsetof(struct omci_dot1ag_ma, ma_name_1), 25,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR, NULL),
		/* 4 */ ATTR_STR("MA name 2", ATTR_SUPPORTED,
			offsetof(struct omci_dot1ag_ma, ma_name_2), 25,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR, NULL),
		/* 5 */ ATTR_UINT("CCM interval", ATTR_SUPPORTED, 0, 0xFF,
			offsetof(struct omci_dot1ag_ma, ccm_interval), 1,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC, NULL),
		/* 6 */ ATTR_STR("Associated VLANs", ATTR_SUPPORTED,
			offsetof(struct omci_dot1ag_ma, vlans), 24,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR, NULL),
		/* 7 */ ATTR_UINT("MHF creation", ATTR_SUPPORTED, 0, 0xFF,
			offsetof(struct omci_dot1ag_ma, mhf_creation), 1,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC, NULL),
		/* 8 */ ATTR_UINT("Sender ID permission", ATTR_SUPPORTED, 0, 0xFF,
			offsetof(struct omci_dot1ag_ma, snd_id_perm), 1,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC, NULL),
		ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF(),
		ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF()
	},
	{ NULL, NULL, NULL, NULL,
	  create_action_handle, NULL, delete_action_handle, NULL,
	  set_action_handle, get_action_handle, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL },
	default_me_init, default_me_shutdown, default_me_validate,
	NULL, NULL, NULL,
#ifdef INCLUDE_PM
	NULL, NULL,
#endif
	NULL, sizeof(struct omci_dot1ag_ma), OMCI_ME_PROP_NONE,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{ "Dot1ag maintenance assoc", ME_CREATED_BY_OLT, NULL, 0, ME_SUPPORTED },
#endif
	0, 0, 0, 0, 0, 0
};

/* ========================================================================
 * ME 301: Dot1ag Default MD Level
 * Created by ONU. 5 attributes (attr 5 is table).
 * ======================================================================== */
struct me_class me_dot1ag_def_md_lvl_class = {
	OMCI_ME_DOT1AG_DEFAULT_MD_LEVEL,
	{
		/* 1 */ ATTR_UINT("Layer 2 type", ATTR_SUPPORTED, 0, 1,
			offsetof(struct omci_dot1ag_def_md_lvl, l2_type), 1,
			OMCI_ATTR_PROP_RD, NULL),
		/* 2 */ ATTR_UINT("Catchall level", ATTR_SUPPORTED, 0, 7,
			offsetof(struct omci_dot1ag_def_md_lvl, ch_lvl), 1,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR, NULL),
		/* 3 */ ATTR_UINT("Catchall MHF creation", ATTR_SUPPORTED, 0, 0xFF,
			offsetof(struct omci_dot1ag_def_md_lvl, ch_mhf_creation), 1,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR, NULL),
		/* 4 */ ATTR_UINT("Catchall sender ID perm", ATTR_SUPPORTED, 0, 0xFF,
			offsetof(struct omci_dot1ag_def_md_lvl, ch_snd_id_perm), 1,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR, NULL),
		/* 5 */ ATTR_STR("Default MD level table", ATTR_SUPPORTED,
			offsetof(struct omci_dot1ag_def_md_lvl, md_lvl_table), 29,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_TABLE, NULL),
		ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF(),
		ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF(),
		ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF()
	},
	{ NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL,
	  set_action_handle, get_action_handle, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, get_next_action_handle, NULL, NULL },
	default_me_init, default_me_shutdown, default_me_validate,
	NULL, NULL, NULL,
#ifdef INCLUDE_PM
	NULL, NULL,
#endif
	NULL, sizeof(struct omci_dot1ag_def_md_lvl), OMCI_ME_PROP_NONE,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{ "Dot1ag default MD level", ME_CREATED_BY_ONT, NULL, 0, ME_SUPPORTED },
#endif
	0, 0, 0, 0, 0, 0
};

/* ========================================================================
 * ME 302: Dot1ag MEP
 * Created/deleted by OLT. 14 attributes. Has alarms.
 * ======================================================================== */
static const uint8_t dot1ag_mep_alarms[] = {
	7 /* RDI CCM, MAC status, Remote CCM, Error CCM, Xcon CCM, Unexp period, AIS */
};

struct me_class me_dot1ag_mep_class = {
	OMCI_ME_DOT1AG_MEP,
	{
		/* 1 */ ATTR_UINT("Layer 2 entity ptr", ATTR_SUPPORTED, 0, 0xFFFF,
			offsetof(struct omci_dot1ag_mep, l2_ptr), 2,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC, NULL),
		/* 2 */ ATTR_UINT("Layer 2 type", ATTR_SUPPORTED, 0, 1,
			offsetof(struct omci_dot1ag_mep, l2_type), 1,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC, NULL),
		/* 3 */ ATTR_UINT("MA pointer", ATTR_SUPPORTED, 0, 0xFFFF,
			offsetof(struct omci_dot1ag_mep, ma_ptr), 2,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC, NULL),
		/* 4 */ ATTR_UINT("MEP ID", ATTR_SUPPORTED, 0, 0xFFFF,
			offsetof(struct omci_dot1ag_mep, mep_id), 2,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC, NULL),
		/* 5 */ ATTR_BF("MEP control", ATTR_SUPPORTED, 0xFF,
			offsetof(struct omci_dot1ag_mep, mep_ctrl), 1,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC, NULL),
		/* 6 */ ATTR_UINT("Primary VLAN", ATTR_SUPPORTED, 0, 0xFFFF,
			offsetof(struct omci_dot1ag_mep, pvlan), 2,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC, NULL),
		/* 7 */ ATTR_UINT("Admin state", ATTR_SUPPORTED, 0, 1,
			offsetof(struct omci_dot1ag_mep, admin_state), 1,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR, NULL),
		/* 8 */ ATTR_UINT("CCM LTM priority", ATTR_SUPPORTED, 0, 0xFF,
			offsetof(struct omci_dot1ag_mep, ccm_ltm_prio), 1,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC, NULL),
		/* 9 */ ATTR_STR("Egress identifier", ATTR_SUPPORTED,
			offsetof(struct omci_dot1ag_mep, egr_id), 8,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC, NULL),
		/* 10 */ ATTR_STR("Peer MEP IDs", ATTR_SUPPORTED,
			offsetof(struct omci_dot1ag_mep, peer_mep_id), 24,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR, NULL),
		/* 11 */ ATTR_BF("ETH AIS control", ATTR_SUPPORTED, 0xFF,
			offsetof(struct omci_dot1ag_mep, eth_ais_ctrl), 1,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC, NULL),
		/* 12 */ ATTR_UINT("Fault alarm threshold", ATTR_SUPPORTED, 0, 6,
			offsetof(struct omci_dot1ag_mep, fault_alarm_thr), 1,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC
			| OMCI_ATTR_PROP_OPTIONAL, NULL),
		/* 13 */ ATTR_UINT("Alarm decl soak time", ATTR_SUPPORTED, 0, 0xFFFF,
			offsetof(struct omci_dot1ag_mep, alarm_decl_soak), 2,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR, NULL),
		/* 14 */ ATTR_UINT("Alarm clear soak time", ATTR_SUPPORTED, 0, 0xFFFF,
			offsetof(struct omci_dot1ag_mep, alarm_clear_soak), 2,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR, NULL),
		ATTR_NOT_DEF(), ATTR_NOT_DEF()
	},
	{ NULL, NULL, NULL, NULL,
	  create_action_handle, NULL, delete_action_handle, NULL,
	  set_action_handle, get_action_handle, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL },
	default_me_init, default_me_shutdown, default_me_validate,
	NULL, NULL, NULL,
#ifdef INCLUDE_PM
	NULL, NULL,
#endif
	NULL, sizeof(struct omci_dot1ag_mep),
	OMCI_ME_PROP_HAS_ALARMS,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{ "Dot1ag MEP", ME_CREATED_BY_OLT, dot1ag_mep_alarms, 7, ME_SUPPORTED },
#endif
	0, 0, 0, 0, 0, 0
};

/* ========================================================================
 * ME 303: Dot1ag MEP Status
 * Created by ONU. Read-only. Not in MIB upload.
 * ======================================================================== */
struct me_class me_dot1ag_mep_status_class = {
	OMCI_ME_DOT1AG_MEP_STATUS,
	{
		/* 1 */ ATTR_STR("MEP MAC address", ATTR_SUPPORTED,
			offsetof(struct omci_dot1ag_mep_status, mep_mac), 6,
			OMCI_ATTR_PROP_RD, NULL),
		/* 2 */ ATTR_UINT("Fault notif gen state", ATTR_SUPPORTED, 0, 0xFF,
			offsetof(struct omci_dot1ag_mep_status, fault_state), 1,
			OMCI_ATTR_PROP_RD, NULL),
		/* 3 */ ATTR_UINT("Highest prio defect", ATTR_SUPPORTED, 0, 0xFF,
			offsetof(struct omci_dot1ag_mep_status, hp_defect), 1,
			OMCI_ATTR_PROP_RD, NULL),
		/* 4 */ ATTR_BF("Current defects", ATTR_SUPPORTED, 0xFF,
			offsetof(struct omci_dot1ag_mep_status, curr_defects), 1,
			OMCI_ATTR_PROP_RD, NULL),
		/* 5-6: table attributes — stub as not-supported */
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		/* 7 */ ATTR_UINT("OOS CCMs count", ATTR_SUPPORTED, 0, 0xFFFFFFFF,
			offsetof(struct omci_dot1ag_mep_status, ccm_oos_cnt), 4,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_OPTIONAL, NULL),
		/* 8 */ ATTR_UINT("CCMs TX count", ATTR_SUPPORTED, 0, 0xFFFFFFFF,
			offsetof(struct omci_dot1ag_mep_status, ccm_tx_cnt), 4,
			OMCI_ATTR_PROP_RD, NULL),
		/* 9 */ ATTR_UINT("Unexpected LTR count", ATTR_SUPPORTED, 0, 0xFFFFFFFF,
			offsetof(struct omci_dot1ag_mep_status, unexp_ltr_cnt), 4,
			OMCI_ATTR_PROP_RD, NULL),
		/* 10 */ ATTR_UINT("LBR TX count", ATTR_SUPPORTED, 0, 0xFFFFFFFF,
			offsetof(struct omci_dot1ag_mep_status, lbr_tx_cnt), 4,
			OMCI_ATTR_PROP_RD, NULL),
		/* 11 */ ATTR_UINT("Next LB txs ID", ATTR_SUPPORTED, 0, 0xFFFFFFFF,
			offsetof(struct omci_dot1ag_mep_status, next_lb_txs_id), 4,
			OMCI_ATTR_PROP_RD, NULL),
		/* 12 */ ATTR_UINT("Next LT txs ID", ATTR_SUPPORTED, 0, 0xFFFFFFFF,
			offsetof(struct omci_dot1ag_mep_status, next_lt_txs_id), 4,
			OMCI_ATTR_PROP_RD, NULL),
		ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF()
	},
	{ NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL,
	  NULL, get_action_handle, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL },
	default_me_init, default_me_shutdown, default_me_validate,
	NULL, NULL, NULL,
#ifdef INCLUDE_PM
	NULL, NULL,
#endif
	NULL, sizeof(struct omci_dot1ag_mep_status),
	OMCI_ME_PROP_NO_UPLOAD,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{ "Dot1ag MEP status", ME_CREATED_BY_ONT, NULL, 0, ME_SUPPORTED },
#endif
	0, 0, 0, 0, 0, 0
};

/* ========================================================================
 * ME 304: Dot1ag MEP CCM Database
 * Created by ONU. Read-only. Not in MIB upload.
 * ======================================================================== */
struct me_class me_dot1ag_mep_ccm_db_class = {
	OMCI_ME_DOT1AG_MEP_CCM_DATABASE,
	{
		/* 1-12: RMEP table attributes — stub as not-supported for now */
		ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF(),
		ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF(),
		ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF(),
		ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF()
	},
	{ NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL,
	  NULL, get_action_handle, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL },
	default_me_init, default_me_shutdown, default_me_validate,
	NULL, NULL, NULL,
#ifdef INCLUDE_PM
	NULL, NULL,
#endif
	NULL, sizeof(struct omci_dot1ag_mep_ccm_db),
	OMCI_ME_PROP_NO_UPLOAD,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{ "Dot1ag MEP CCM database", ME_CREATED_BY_ONT, NULL, 0, ME_SUPPORTED },
#endif
	0, 0, 0, 0, 0, 0
};

/* ========================================================================
 * ME 305: Dot1ag CFM Stack
 * Created by ONU. Read-only. Table attributes.
 * ======================================================================== */
struct me_class me_dot1ag_cfm_stack_class = {
	OMCI_ME_DOT1AG_CFM_STACK,
	{
		/* 1 */ ATTR_UINT("Layer 2 type", ATTR_SUPPORTED, 0, 1,
			offsetof(struct omci_dot1ag_cfm_stack, l2_type), 1,
			OMCI_ATTR_PROP_RD, NULL),
		/* 2-3: table attributes — stub as not-supported */
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF(),
		ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF(),
		ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF(),
		ATTR_NOT_DEF()
	},
	{ NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL,
	  NULL, get_action_handle, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL },
	default_me_init, default_me_shutdown, default_me_validate,
	NULL, NULL, NULL,
#ifdef INCLUDE_PM
	NULL, NULL,
#endif
	NULL, sizeof(struct omci_dot1ag_cfm_stack), OMCI_ME_PROP_NONE,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{ "Dot1ag CFM stack", ME_CREATED_BY_ONT, NULL, 0, ME_SUPPORTED },
#endif
	0, 0, 0, 0, 0, 0
};

/* ========================================================================
 * ME 306: Dot1ag Chassis-Management Info
 * Created by ONU. 10 attributes. Get/Set.
 * ======================================================================== */
struct me_class me_dot1ag_cmi_class = {
	OMCI_ME_DOT1AG_CHASSIS_MANAGEMENT_INFO,
	{
		/* 1 */ ATTR_UINT("Chassis ID length", ATTR_SUPPORTED, 0, 0xFF,
			offsetof(struct omci_dot1ag_cmi, cid_len), 1,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR, NULL),
		/* 2 */ ATTR_UINT("Chassis ID subtype", ATTR_SUPPORTED, 0, 0xFF,
			offsetof(struct omci_dot1ag_cmi, cid_subtype), 1,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR, NULL),
		/* 3 */ ATTR_STR("Chassis ID part 1", ATTR_SUPPORTED,
			offsetof(struct omci_dot1ag_cmi, cid_part1), 25,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR, NULL),
		/* 4 */ ATTR_STR("Chassis ID part 2", ATTR_SUPPORTED,
			offsetof(struct omci_dot1ag_cmi, cid_part2), 25,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR, NULL),
		/* 5 */ ATTR_UINT("Mgmt addr domain len", ATTR_SUPPORTED, 0, 0xFF,
			offsetof(struct omci_dot1ag_cmi, ma_domain_len), 1,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR, NULL),
		/* 6 */ ATTR_STR("Mgmt addr domain 1", ATTR_SUPPORTED,
			offsetof(struct omci_dot1ag_cmi, ma_domain1), 25,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR, NULL),
		/* 7 */ ATTR_STR("Mgmt addr domain 2", ATTR_SUPPORTED,
			offsetof(struct omci_dot1ag_cmi, ma_domain2), 25,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR, NULL),
		/* 8 */ ATTR_UINT("Mgmt address length", ATTR_SUPPORTED, 0, 0xFF,
			offsetof(struct omci_dot1ag_cmi, ma_len), 1,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR, NULL),
		/* 9 */ ATTR_STR("Mgmt address 1", ATTR_SUPPORTED,
			offsetof(struct omci_dot1ag_cmi, ma1), 25,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR, NULL),
		/* 10 */ ATTR_STR("Mgmt address 2", ATTR_SUPPORTED,
			offsetof(struct omci_dot1ag_cmi, ma2), 25,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR, NULL),
		ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF(),
		ATTR_NOT_DEF(), ATTR_NOT_DEF()
	},
	{ NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL,
	  set_action_handle, get_action_handle, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL },
	default_me_init, default_me_shutdown, default_me_validate,
	NULL, NULL, NULL,
#ifdef INCLUDE_PM
	NULL, NULL,
#endif
	NULL, sizeof(struct omci_dot1ag_cmi), OMCI_ME_PROP_NONE,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{ "Dot1ag chassis-mgmt info", ME_CREATED_BY_ONT, NULL, 0, ME_SUPPORTED },
#endif
	0, 0, 0, 0, 0, 0
};

/* ========================================================================
 * ME 334: Ethernet Frame Extended PMHD
 * Created/deleted by OLT. 16 attributes. PM stub (counters return 0).
 * ======================================================================== */
struct me_class me_eth_ext_pmhd_class = {
	OMCI_ME_ETHERNET_EXTENDED_PMHD,
	{
		/* 1 */ ATTR_UINT("Interval end time", ATTR_SUPPORTED, 0, 0xFF,
			offsetof(struct omci_eth_ext_pmhd, interval_end_time), 1,
			OMCI_ATTR_PROP_RD, NULL),
		/* 2 */ ATTR_STR("Control block", ATTR_SUPPORTED,
			offsetof(struct omci_eth_ext_pmhd, ctrl_block), 16,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC, NULL),
		/* 3 */ ATTR_UINT("Drop events", ATTR_SUPPORTED, 0, 0xFFFFFFFF,
			offsetof(struct omci_eth_ext_pmhd, drop_events), 4,
			OMCI_ATTR_PROP_RD, NULL),
		/* 4 */ ATTR_UINT("Octets", ATTR_SUPPORTED, 0, 0xFFFFFFFF,
			offsetof(struct omci_eth_ext_pmhd, octets), 4,
			OMCI_ATTR_PROP_RD, NULL),
		/* 5 */ ATTR_UINT("Frames", ATTR_SUPPORTED, 0, 0xFFFFFFFF,
			offsetof(struct omci_eth_ext_pmhd, frames), 4,
			OMCI_ATTR_PROP_RD, NULL),
		/* 6 */ ATTR_UINT("Broadcast frames", ATTR_SUPPORTED, 0, 0xFFFFFFFF,
			offsetof(struct omci_eth_ext_pmhd, bc_frames), 4,
			OMCI_ATTR_PROP_RD, NULL),
		/* 7 */ ATTR_UINT("Multicast frames", ATTR_SUPPORTED, 0, 0xFFFFFFFF,
			offsetof(struct omci_eth_ext_pmhd, mc_frames), 4,
			OMCI_ATTR_PROP_RD, NULL),
		/* 8 */ ATTR_UINT("CRC errored frames", ATTR_SUPPORTED, 0, 0xFFFFFFFF,
			offsetof(struct omci_eth_ext_pmhd, crc_err_frames), 4,
			OMCI_ATTR_PROP_RD, NULL),
		/* 9 */ ATTR_UINT("Undersize frames", ATTR_SUPPORTED, 0, 0xFFFFFFFF,
			offsetof(struct omci_eth_ext_pmhd, usize_frames), 4,
			OMCI_ATTR_PROP_RD, NULL),
		/* 10 */ ATTR_UINT("Oversize frames", ATTR_SUPPORTED, 0, 0xFFFFFFFF,
			offsetof(struct omci_eth_ext_pmhd, osize_frames), 4,
			OMCI_ATTR_PROP_RD, NULL),
		/* 11 */ ATTR_UINT("Frames 64 octets", ATTR_SUPPORTED, 0, 0xFFFFFFFF,
			offsetof(struct omci_eth_ext_pmhd, frames_64), 4,
			OMCI_ATTR_PROP_RD, NULL),
		/* 12 */ ATTR_UINT("Frames 65-127", ATTR_SUPPORTED, 0, 0xFFFFFFFF,
			offsetof(struct omci_eth_ext_pmhd, frames_65_127), 4,
			OMCI_ATTR_PROP_RD, NULL),
		/* 13 */ ATTR_UINT("Frames 128-255", ATTR_SUPPORTED, 0, 0xFFFFFFFF,
			offsetof(struct omci_eth_ext_pmhd, frames_128_255), 4,
			OMCI_ATTR_PROP_RD, NULL),
		/* 14 */ ATTR_UINT("Frames 256-511", ATTR_SUPPORTED, 0, 0xFFFFFFFF,
			offsetof(struct omci_eth_ext_pmhd, frames_256_511), 4,
			OMCI_ATTR_PROP_RD, NULL),
		/* 15 */ ATTR_UINT("Frames 512-1023", ATTR_SUPPORTED, 0, 0xFFFFFFFF,
			offsetof(struct omci_eth_ext_pmhd, frames_512_1023), 4,
			OMCI_ATTR_PROP_RD, NULL),
		/* 16 */ ATTR_UINT("Frames 1024-1518", ATTR_SUPPORTED, 0, 0xFFFFFFFF,
			offsetof(struct omci_eth_ext_pmhd, frames_1024_1518), 4,
			OMCI_ATTR_PROP_RD, NULL),
	},
	{ NULL, NULL, NULL, NULL,
	  create_action_handle, NULL, delete_action_handle, NULL,
	  set_action_handle, get_action_handle, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  get_action_handle /* get current data */ },
	default_me_init, default_me_shutdown, default_me_validate,
	NULL, NULL, NULL,
#ifdef INCLUDE_PM
	NULL, NULL,
#endif
	NULL, sizeof(struct omci_eth_ext_pmhd), OMCI_ME_PROP_NONE,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{ "Ethernet ext PMHD", ME_CREATED_BY_OLT, NULL, 0, ME_SUPPORTED },
#endif
	0, 0, 0, 0, 0, 0
};

/* ME 341 (GEM Port NW CTP PMHD) removed — now provided by PM subsystem
   via omci_gem_port_network_ctp_pmhd.c when INCLUDE_PM is enabled */

/* ========================================================================
 * ME 343: Energy Consumption PMHD
 * Created by ONU. 5 attributes.
 * ======================================================================== */
struct me_class me_energy_consumption_pmhd_class = {
	OMCI_ME_ENERGY_CONSUMPTION_PMHD,
	{
		/* 1 */ ATTR_UINT("Interval end time", ATTR_SUPPORTED, 0, 0xFF,
			offsetof(struct omci_energy_consumption_pmhd, interval_end_time), 1,
			OMCI_ATTR_PROP_RD, NULL),
		/* 2 */ ATTR_UINT("Threshold data 1/2 ID", ATTR_SUPPORTED, 0, 0xFFFF,
			offsetof(struct omci_energy_consumption_pmhd, threshold_data_id), 2,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR, NULL),
		/* 3 */ ATTR_UINT("Doze time", ATTR_SUPPORTED, 0, 0xFFFFFFFF,
			offsetof(struct omci_energy_consumption_pmhd, doze_time), 4,
			OMCI_ATTR_PROP_RD, NULL),
		/* 4 */ ATTR_UINT("Cyclic sleep time", ATTR_SUPPORTED, 0, 0xFFFFFFFF,
			offsetof(struct omci_energy_consumption_pmhd, cyclic_sleep_time), 4,
			OMCI_ATTR_PROP_RD, NULL),
		/* 5 */ ATTR_UINT("Energy consumed", ATTR_SUPPORTED, 0, 0xFFFFFFFF,
			offsetof(struct omci_energy_consumption_pmhd, energy_consumed), 4,
			OMCI_ATTR_PROP_RD, NULL),
		ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF(),
		ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF(),
		ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF()
	},
	{ NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL,
	  set_action_handle, get_action_handle, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  get_action_handle /* get current data */ },
	default_me_init, default_me_shutdown, default_me_validate,
	NULL, NULL, NULL,
#ifdef INCLUDE_PM
	NULL, NULL,
#endif
	NULL, sizeof(struct omci_energy_consumption_pmhd), OMCI_ME_PROP_NONE,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{ "Energy consumption PMHD", ME_CREATED_BY_ONT, NULL, 0, ME_SUPPORTED },
#endif
	0, 0, 0, 0, 0, 0
};

/* ========================================================================
 * ME 349: PoE Control
 * Created by ONU. 12 attributes. No hardware (SFP has no PoE).
 * ======================================================================== */
struct me_class me_poe_ctrl_class = {
	OMCI_ME_POE_CTRL,
	{
		/* 1 */ ATTR_UINT("PoE capabilities", ATTR_SUPPORTED, 0, 0xFFFF,
			offsetof(struct omci_poe_ctrl, poe_capabilities), 2,
			OMCI_ATTR_PROP_RD, NULL),
		/* 2 */ ATTR_UINT("Power pair pinout ctrl", ATTR_SUPPORTED, 0, 0xFF,
			offsetof(struct omci_poe_ctrl, power_pair_pinout_ctrl), 1,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR, NULL),
		/* 3 */ ATTR_UINT("Operational state", ATTR_SUPPORTED, 0, 1,
			offsetof(struct omci_poe_ctrl, op_state), 1,
			OMCI_ATTR_PROP_RD, NULL),
		/* 4 */ ATTR_UINT("Power detection status", ATTR_SUPPORTED, 0, 0xFF,
			offsetof(struct omci_poe_ctrl, power_detect_st), 1,
			OMCI_ATTR_PROP_RD, NULL),
		/* 5 */ ATTR_UINT("Power class status", ATTR_SUPPORTED, 0, 0xFF,
			offsetof(struct omci_poe_ctrl, power_class_st), 1,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_OPTIONAL, NULL),
		/* 6 */ ATTR_UINT("Power priority", ATTR_SUPPORTED, 0, 0xFF,
			offsetof(struct omci_poe_ctrl, power_prio), 1,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_OPTIONAL, NULL),
		/* 7 */ ATTR_UINT("Invalid signature cnt", ATTR_SUPPORTED, 0, 0xFFFF,
			offsetof(struct omci_poe_ctrl, invalid_sign_counter), 2,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_OPTIONAL, NULL),
		/* 8 */ ATTR_UINT("Power denied counter", ATTR_SUPPORTED, 0, 0xFFFF,
			offsetof(struct omci_poe_ctrl, power_denied_counter), 2,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_OPTIONAL, NULL),
		/* 9 */ ATTR_UINT("Overload counter", ATTR_SUPPORTED, 0, 0xFFFF,
			offsetof(struct omci_poe_ctrl, overload_counter), 2,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_OPTIONAL, NULL),
		/* 10 */ ATTR_UINT("Short counter", ATTR_SUPPORTED, 0, 0xFFFF,
			offsetof(struct omci_poe_ctrl, short_counter), 2,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_OPTIONAL, NULL),
		/* 11 */ ATTR_UINT("MPS absent counter", ATTR_SUPPORTED, 0, 0xFFFF,
			offsetof(struct omci_poe_ctrl, mps_absent_counter), 2,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_OPTIONAL, NULL),
		/* 12 */ ATTR_UINT("PSE class control", ATTR_SUPPORTED, 0, 0xFF,
			offsetof(struct omci_poe_ctrl, pse_class_ctrl), 1,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_OPTIONAL, NULL),
		ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF()
	},
	{ NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL,
	  set_action_handle, get_action_handle, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL },
	default_me_init, default_me_shutdown, default_me_validate,
	NULL, NULL, NULL,
#ifdef INCLUDE_PM
	NULL, NULL,
#endif
	NULL, sizeof(struct omci_poe_ctrl), OMCI_ME_PROP_NONE,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{ "PoE control", ME_CREATED_BY_ONT, NULL, 0, ME_SUPPORTED },
#endif
	0, 0, 0, 0, 0, 0
};

/* ========================================================================
 * ME 425: Ethernet Frame Extended PMHD 64-bit
 * Same as ME 334 but with 64-bit counters.
 * ======================================================================== */
struct me_class me_eth_ext_pmhd_64_class = {
	OMCI_ME_ETHERNET_EXTENDED_PMHD_64,
	{
		/* 1 */ ATTR_UINT("Interval end time", ATTR_SUPPORTED, 0, 0xFF,
			offsetof(struct omci_eth_ext_pmhd_64, interval_end_time), 1,
			OMCI_ATTR_PROP_RD, NULL),
		/* 2 */ ATTR_STR("Control block", ATTR_SUPPORTED,
			offsetof(struct omci_eth_ext_pmhd_64, ctrl_block), 16,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC, NULL),
		/* 3-16: 64-bit counters — use STR type for 8-byte fields */
		/* 3 */ ATTR_STR("Drop events", ATTR_SUPPORTED,
			offsetof(struct omci_eth_ext_pmhd_64, drop_events), 8,
			OMCI_ATTR_PROP_RD, NULL),
		/* 4 */ ATTR_STR("Octets", ATTR_SUPPORTED,
			offsetof(struct omci_eth_ext_pmhd_64, octets), 8,
			OMCI_ATTR_PROP_RD, NULL),
		/* 5 */ ATTR_STR("Frames", ATTR_SUPPORTED,
			offsetof(struct omci_eth_ext_pmhd_64, frames), 8,
			OMCI_ATTR_PROP_RD, NULL),
		/* 6 */ ATTR_STR("Broadcast frames", ATTR_SUPPORTED,
			offsetof(struct omci_eth_ext_pmhd_64, bc_frames), 8,
			OMCI_ATTR_PROP_RD, NULL),
		/* 7 */ ATTR_STR("Multicast frames", ATTR_SUPPORTED,
			offsetof(struct omci_eth_ext_pmhd_64, mc_frames), 8,
			OMCI_ATTR_PROP_RD, NULL),
		/* 8 */ ATTR_STR("CRC errored frames", ATTR_SUPPORTED,
			offsetof(struct omci_eth_ext_pmhd_64, crc_err_frames), 8,
			OMCI_ATTR_PROP_RD, NULL),
		/* 9 */ ATTR_STR("Undersize frames", ATTR_SUPPORTED,
			offsetof(struct omci_eth_ext_pmhd_64, usize_frames), 8,
			OMCI_ATTR_PROP_RD, NULL),
		/* 10 */ ATTR_STR("Oversize frames", ATTR_SUPPORTED,
			offsetof(struct omci_eth_ext_pmhd_64, osize_frames), 8,
			OMCI_ATTR_PROP_RD, NULL),
		/* 11 */ ATTR_STR("Frames 64 octets", ATTR_SUPPORTED,
			offsetof(struct omci_eth_ext_pmhd_64, frames_64), 8,
			OMCI_ATTR_PROP_RD, NULL),
		/* 12 */ ATTR_STR("Frames 65-127", ATTR_SUPPORTED,
			offsetof(struct omci_eth_ext_pmhd_64, frames_65_127), 8,
			OMCI_ATTR_PROP_RD, NULL),
		/* 13 */ ATTR_STR("Frames 128-255", ATTR_SUPPORTED,
			offsetof(struct omci_eth_ext_pmhd_64, frames_128_255), 8,
			OMCI_ATTR_PROP_RD, NULL),
		/* 14 */ ATTR_STR("Frames 256-511", ATTR_SUPPORTED,
			offsetof(struct omci_eth_ext_pmhd_64, frames_256_511), 8,
			OMCI_ATTR_PROP_RD, NULL),
		/* 15 */ ATTR_STR("Frames 512-1023", ATTR_SUPPORTED,
			offsetof(struct omci_eth_ext_pmhd_64, frames_512_1023), 8,
			OMCI_ATTR_PROP_RD, NULL),
		/* 16 */ ATTR_STR("Frames 1024-1518", ATTR_SUPPORTED,
			offsetof(struct omci_eth_ext_pmhd_64, frames_1024_1518), 8,
			OMCI_ATTR_PROP_RD, NULL),
	},
	{ NULL, NULL, NULL, NULL,
	  create_action_handle, NULL, delete_action_handle, NULL,
	  set_action_handle, get_action_handle, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  get_action_handle /* get current data */ },
	default_me_init, default_me_shutdown, default_me_validate,
	NULL, NULL, NULL,
#ifdef INCLUDE_PM
	NULL, NULL,
#endif
	NULL, sizeof(struct omci_eth_ext_pmhd_64), OMCI_ME_PROP_NONE,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{ "Ethernet ext PMHD 64b", ME_CREATED_BY_OLT, NULL, 0, ME_SUPPORTED },
#endif
	0, 0, 0, 0, 0, 0
};

/* ========================================================================
 * ME 65282: ZTE Extended Multicast Operations Profile
 * Created/deleted by OLT. 3 attributes.
 * ======================================================================== */
struct me_class me_zte_emop_class = {
	OMCI_ME_ZTE_EMOP,
	{
		/* 1 */ ATTR_UINT("Control mode", ATTR_SUPPORTED, 0, 0xFF,
			offsetof(struct omci_zte_emop, ctrl_mode), 1,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC, NULL),
		/* 2 */ ATTR_UINT("Num translations", ATTR_SUPPORTED, 0, 0xFF,
			offsetof(struct omci_zte_emop, num_translations), 1,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR, NULL),
		/* 3 */ ATTR_STR("VLAN xlat table", ATTR_SUPPORTED,
			offsetof(struct omci_zte_emop, vlan_xlat_table), 24,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR, NULL),
		ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF(),
		ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF(),
		ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF(),
		ATTR_NOT_DEF()
	},
	{ NULL, NULL, NULL, NULL,
	  create_action_handle, NULL, delete_action_handle, NULL,
	  set_action_handle, get_action_handle, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL },
	default_me_init, default_me_shutdown, default_me_validate,
	NULL, NULL, NULL,
#ifdef INCLUDE_PM
	NULL, NULL,
#endif
	NULL, sizeof(struct omci_zte_emop), OMCI_ME_PROP_NONE,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{ "ZTE ext multicast profile", ME_CREATED_BY_OLT, NULL, 0, ME_SUPPORTED },
#endif
	0, 0, 0, 0, 0, 0
};

/* ========================================================================
 * ME 65528: ONU Loop Detection
 * Created/deleted by OLT. 6 attributes. Has alarms.
 * ======================================================================== */
static const uint8_t onu_loop_detection_alarms[] = {
	4 /* loop detected on ports 0-3 */
};

struct me_class me_onu_loop_detection_class = {
	OMCI_ME_ONU_LOOP_DETECTION,
	{
		/* 1 */ ATTR_UINT("Operator ID", ATTR_SUPPORTED, 0, 0xFFFFFFFF,
			offsetof(struct omci_onu_loop_detection, operator_id), 4,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC, NULL),
		/* 2 */ ATTR_UINT("Loop detect mgmt", ATTR_SUPPORTED, 0, 0xFFFF,
			offsetof(struct omci_onu_loop_detection, loop_detect_mgmt), 2,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR, NULL),
		/* 3 */ ATTR_UINT("Loop port down", ATTR_SUPPORTED, 0, 0xFFFF,
			offsetof(struct omci_onu_loop_detection, loop_port_down), 2,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR, NULL),
		/* 4 */ ATTR_UINT("Loop detect msg freq", ATTR_SUPPORTED, 0, 0xFFFF,
			offsetof(struct omci_onu_loop_detection, loop_detect_freq), 2,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR, NULL),
		/* 5 */ ATTR_UINT("Loop recovery interval", ATTR_SUPPORTED, 0, 0xFFFF,
			offsetof(struct omci_onu_loop_detection, loop_recovery_int), 2,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR, NULL),
		/* 6 */ ATTR_STR("Port VLAN table", ATTR_SUPPORTED,
			offsetof(struct omci_onu_loop_detection, port_vlan_table), 28,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR, NULL),
		ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF(),
		ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF(),
		ATTR_NOT_DEF(), ATTR_NOT_DEF()
	},
	{ NULL, NULL, NULL, NULL,
	  create_action_handle, NULL, delete_action_handle, NULL,
	  set_action_handle, get_action_handle, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL },
	default_me_init, default_me_shutdown, default_me_validate,
	NULL, NULL, NULL,
#ifdef INCLUDE_PM
	NULL, NULL,
#endif
	NULL, sizeof(struct omci_onu_loop_detection),
	OMCI_ME_PROP_HAS_ALARMS,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{ "ONU loop detection", ME_CREATED_BY_OLT, onu_loop_detection_alarms, 4, ME_SUPPORTED },
#endif
	0, 0, 0, 0, 0, 0
};

/* ========================================================================
 * ME 65531: Extended Multicast Operations Profile
 * Created/deleted by OLT. 9 attributes.
 * ======================================================================== */
struct me_class me_ext_mop_class = {
	OMCI_ME_EXT_MOP,
	{
		/* 1 */ ATTR_UINT("IGMP version", ATTR_SUPPORTED, 0, 0xFF,
			offsetof(struct omci_ext_mop, igmp_version), 1,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC, NULL),
		/* 2 */ ATTR_UINT("IGMP function", ATTR_SUPPORTED, 0, 0xFF,
			offsetof(struct omci_ext_mop, igmp_function), 1,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC, NULL),
		/* 3 */ ATTR_UINT("Immediate leave", ATTR_SUPPORTED, 0, 0xFF,
			offsetof(struct omci_ext_mop, immediate_leave), 1,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC, NULL),
		/* 4 */ ATTR_UINT("US IGMP TCI", ATTR_SUPPORTED, 0, 0xFFFF,
			offsetof(struct omci_ext_mop, us_igmp_tci), 2,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR, NULL),
		/* 5 */ ATTR_UINT("US IGMP tag ctrl", ATTR_SUPPORTED, 0, 0xFF,
			offsetof(struct omci_ext_mop, us_igmp_tag_ctrl), 1,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR, NULL),
		/* 6 */ ATTR_UINT("US IGMP rate", ATTR_SUPPORTED, 0, 0xFFFFFFFF,
			offsetof(struct omci_ext_mop, us_igmp_rate), 4,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR, NULL),
		/* 7 */ ATTR_STR("Dynamic ACL table", ATTR_SUPPORTED,
			offsetof(struct omci_ext_mop, dynamic_acl_table), 24,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_TABLE, NULL),
		/* 8 */ ATTR_STR("Static ACL table", ATTR_SUPPORTED,
			offsetof(struct omci_ext_mop, static_acl_table), 24,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_TABLE, NULL),
		ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF(),
		ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF(), ATTR_NOT_DEF()
	},
	{ NULL, NULL, NULL, NULL,
	  create_action_handle, NULL, delete_action_handle, NULL,
	  set_action_handle, get_action_handle, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, get_next_action_handle, NULL, NULL, NULL },
	default_me_init, default_me_shutdown, default_me_validate,
	NULL, NULL, NULL,
#ifdef INCLUDE_PM
	NULL, NULL,
#endif
	NULL, sizeof(struct omci_ext_mop), OMCI_ME_PROP_NONE,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{ "Ext multicast oper profile", ME_CREATED_BY_OLT, NULL, 0, ME_SUPPORTED },
#endif
	0, 0, 0, 0, 0, 0
};
