/******************************************************************************
 * Stub ME definitions for v7.5.1 parity
 *
 * These MEs exist in the shipping binary but not in the v4.5.0 SDK source.
 * They are implemented as data-only stubs (no hardware interaction).
 ******************************************************************************/
#ifndef _omci_stub_mes_h
#define _omci_stub_mes_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/* ---- ME 299: Dot1ag Maintenance Domain ---- */
struct omci_dot1ag_md {
	uint8_t md_level;          /* 1B R/W/SBC */
	uint8_t md_name_format;    /* 1B R/W/SBC */
	uint8_t md_name_1[25];     /* 25B R/W */
	uint8_t md_name_2[25];     /* 25B R/W */
	uint8_t mhf_creation;      /* 1B R/W/SBC */
	uint8_t snd_id_perm;       /* 1B R/W/SBC */
} __PACKED__;

/* ---- ME 300: Dot1ag Maintenance Association ---- */
struct omci_dot1ag_ma {
	uint16_t md_ptr;            /* 2B R/W/SBC */
	uint8_t ma_name_format;     /* 1B R/W/SBC */
	uint8_t ma_name_1[25];      /* 25B R/W */
	uint8_t ma_name_2[25];      /* 25B R/W */
	uint8_t ccm_interval;       /* 1B R/W/SBC */
	uint16_t vlans[12];         /* 24B R/W */
	uint8_t mhf_creation;       /* 1B R/W/SBC */
	uint8_t snd_id_perm;        /* 1B R/W/SBC */
} __PACKED__;

/* ---- ME 301: Dot1ag Default MD Level ---- */
struct omci_dot1ag_def_md_lvl {
	uint8_t l2_type;            /* 1B R */
	uint8_t ch_lvl;             /* 1B R/W */
	uint8_t ch_mhf_creation;    /* 1B R/W */
	uint8_t ch_snd_id_perm;     /* 1B R/W */
	uint8_t md_lvl_table[29];   /* 29B R/W table */
} __PACKED__;

/* ---- ME 302: Dot1ag MEP ---- */
struct omci_dot1ag_mep {
	uint16_t l2_ptr;            /* 2B R/W/SBC */
	uint8_t l2_type;            /* 1B R/W/SBC */
	uint16_t ma_ptr;            /* 2B R/W/SBC */
	uint16_t mep_id;            /* 2B R/W/SBC */
	uint8_t mep_ctrl;           /* 1B R/W/SBC */
	uint16_t pvlan;             /* 2B R/W/SBC */
	uint8_t admin_state;        /* 1B R/W */
	uint8_t ccm_ltm_prio;       /* 1B R/W/SBC */
	uint8_t egr_id[8];          /* 8B R/W/SBC */
	uint16_t peer_mep_id[12];   /* 24B R/W */
	uint8_t eth_ais_ctrl;       /* 1B R/W/SBC */
	uint8_t fault_alarm_thr;    /* 1B R/W/SBC optional */
	uint16_t alarm_decl_soak;   /* 2B R/W */
	uint16_t alarm_clear_soak;  /* 2B R/W */
} __PACKED__;

/* ---- ME 303: Dot1ag MEP Status ---- */
struct omci_dot1ag_mep_status {
	uint8_t mep_mac[6];         /* 6B R */
	uint8_t fault_state;        /* 1B R */
	uint8_t hp_defect;          /* 1B R */
	uint8_t curr_defects;       /* 1B R */
	uint8_t err_ccm_table[1];   /* table R */
	uint8_t xcon_ccm_table[1];  /* table R */
	uint32_t ccm_oos_cnt;       /* 4B R optional */
	uint32_t ccm_tx_cnt;        /* 4B R */
	uint32_t unexp_ltr_cnt;     /* 4B R */
	uint32_t lbr_tx_cnt;        /* 4B R */
	uint32_t next_lb_txs_id;    /* 4B R */
	uint32_t next_lt_txs_id;    /* 4B R */
} __PACKED__;

/* ---- ME 304: Dot1ag MEP CCM Database ---- */
struct omci_dot1ag_mep_ccm_db {
	uint8_t rmep1[18];   /* table R */
	uint8_t rmep2[18];   /* table R */
	uint8_t rmep3[18];   /* table R */
	uint8_t rmep4[18];   /* table R */
	uint8_t rmep5[18];   /* table R */
	uint8_t rmep6[18];   /* table R */
	uint8_t rmep7[18];   /* table R */
	uint8_t rmep8[18];   /* table R */
	uint8_t rmep9[18];   /* table R */
	uint8_t rmep10[18];  /* table R */
	uint8_t rmep11[18];  /* table R */
	uint8_t rmep12[18];  /* table R */
} __PACKED__;

/* ---- ME 305: Dot1ag CFM Stack ---- */
struct omci_dot1ag_cfm_stack {
	uint8_t l2_type;             /* 1B R */
	uint8_t mp_status_table[18]; /* table R */
	uint8_t cfg_err_table[5];    /* table R */
} __PACKED__;

/* ---- ME 306: Dot1ag Chassis-Management Info ---- */
struct omci_dot1ag_cmi {
	uint8_t cid_len;            /* 1B R/W */
	uint8_t cid_subtype;        /* 1B R/W */
	uint8_t cid_part1[25];      /* 25B R/W */
	uint8_t cid_part2[25];      /* 25B R/W */
	uint8_t ma_domain_len;      /* 1B R/W */
	uint8_t ma_domain1[25];     /* 25B R/W */
	uint8_t ma_domain2[25];     /* 25B R/W */
	uint8_t ma_len;             /* 1B R/W */
	uint8_t ma1[25];            /* 25B R/W */
	uint8_t ma2[25];            /* 25B R/W */
} __PACKED__;

/* ---- ME 334: Ethernet Frame Extended PMHD ---- */
struct omci_eth_ext_pmhd {
	uint8_t interval_end_time;  /* 1B R */
	uint8_t ctrl_block[16];     /* 16B R/W/SBC */
	uint32_t drop_events;       /* 4B R */
	uint32_t octets;            /* 4B R */
	uint32_t frames;            /* 4B R */
	uint32_t bc_frames;         /* 4B R */
	uint32_t mc_frames;         /* 4B R */
	uint32_t crc_err_frames;    /* 4B R */
	uint32_t usize_frames;      /* 4B R */
	uint32_t osize_frames;      /* 4B R */
	uint32_t frames_64;         /* 4B R */
	uint32_t frames_65_127;     /* 4B R */
	uint32_t frames_128_255;    /* 4B R */
	uint32_t frames_256_511;    /* 4B R */
	uint32_t frames_512_1023;   /* 4B R */
	uint32_t frames_1024_1518;  /* 4B R */
} __PACKED__;

/* ME 341 (GEM Port NW CTP PMHD) removed — now provided by PM subsystem
   via omci_gem_port_network_ctp_pmhd.c when INCLUDE_PM is enabled */

/* ---- ME 343: Energy Consumption PMHD ---- */
struct omci_energy_consumption_pmhd {
	uint8_t interval_end_time;  /* 1B R */
	uint16_t threshold_data_id; /* 2B R/W */
	uint32_t doze_time;         /* 4B R */
	uint32_t cyclic_sleep_time; /* 4B R */
	uint32_t energy_consumed;   /* 4B R */
} __PACKED__;

/* ---- ME 349: PoE Control ---- */
struct omci_poe_ctrl {
	uint16_t poe_capabilities;       /* 2B R */
	uint8_t power_pair_pinout_ctrl;  /* 1B R/W */
	uint8_t op_state;                /* 1B R */
	uint8_t power_detect_st;         /* 1B R */
	uint8_t power_class_st;          /* 1B R optional */
	uint8_t power_prio;              /* 1B R/W optional */
	uint16_t invalid_sign_counter;   /* 2B R optional */
	uint16_t power_denied_counter;   /* 2B R optional */
	uint16_t overload_counter;       /* 2B R optional */
	uint16_t short_counter;          /* 2B R optional */
	uint16_t mps_absent_counter;     /* 2B R optional */
	uint8_t pse_class_ctrl;          /* 1B R/W optional */
} __PACKED__;

/* ---- ME 425: Ethernet Frame Extended PMHD 64-bit ---- */
struct omci_eth_ext_pmhd_64 {
	uint8_t interval_end_time;  /* 1B R */
	uint8_t ctrl_block[16];     /* 16B R/W/SBC */
	uint64_t drop_events;       /* 8B R */
	uint64_t octets;            /* 8B R */
	uint64_t frames;            /* 8B R */
	uint64_t bc_frames;         /* 8B R */
	uint64_t mc_frames;         /* 8B R */
	uint64_t crc_err_frames;    /* 8B R */
	uint64_t usize_frames;      /* 8B R */
	uint64_t osize_frames;      /* 8B R */
	uint64_t frames_64;         /* 8B R */
	uint64_t frames_65_127;     /* 8B R */
	uint64_t frames_128_255;    /* 8B R */
	uint64_t frames_256_511;    /* 8B R */
	uint64_t frames_512_1023;   /* 8B R */
	uint64_t frames_1024_1518;  /* 8B R */
} __PACKED__;

/* ---- ME 65282: ZTE Extended Multicast Operations Profile ---- */
struct omci_zte_emop {
	uint8_t ctrl_mode;            /* 1B R/W/SBC */
	uint8_t num_translations;     /* 1B R/W */
	uint8_t vlan_xlat_table[24];  /* 24B R/W */
} __PACKED__;

/* ---- ME 65528: ONU Loop Detection ---- */
struct omci_onu_loop_detection {
	uint32_t operator_id;       /* 4B R/W/SBC */
	uint16_t loop_detect_mgmt;  /* 2B R/W */
	uint16_t loop_port_down;    /* 2B R/W */
	uint16_t loop_detect_freq;  /* 2B R/W */
	uint16_t loop_recovery_int; /* 2B R/W */
	uint8_t port_vlan_table[28]; /* 28B R/W table */
} __PACKED__;

/* ---- ME 65531: Extended Multicast Operations Profile ---- */
struct omci_ext_mop {
	uint8_t igmp_version;       /* 1B R/W/SBC */
	uint8_t igmp_function;      /* 1B R/W/SBC */
	uint8_t immediate_leave;    /* 1B R/W/SBC */
	uint16_t us_igmp_tci;       /* 2B R/W */
	uint8_t us_igmp_tag_ctrl;   /* 1B R/W */
	uint32_t us_igmp_rate;      /* 4B R/W */
	uint8_t dynamic_acl_table[24]; /* 24B R/W table */
	uint8_t static_acl_table[24];  /* 24B R/W table */
} __PACKED__;

__END_DECLS

#endif
