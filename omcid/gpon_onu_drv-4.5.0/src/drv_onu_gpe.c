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
#include "drv_onu_resource.h"
#include "drv_onu_resource_gpe.h"
#include "drv_onu_register.h"
#include "drv_onu_ll_fsqm.h"
#include "drv_onu_ll_gpearb.h"
#include "drv_onu_ll_iqm.h"
#include "drv_onu_ll_ictrll.h"
#include "drv_onu_ll_ictrlg.h"
#include "drv_onu_ll_octrll.h"
#include "drv_onu_ll_octrlg.h"
#include "drv_onu_ll_ssb.h"
#include "drv_onu_gpe_interface.h"
#include "drv_onu_gtc_interface.h"
#include "drv_onu_ll_gtc.h"
#include "drv_onu_event_interface.h"
#include "drv_onu_ll_sce.h"
#include "drv_onu_ll_cop.h"
#include "drv_onu_ll_tmu.h"
#include "drv_onu_ll_sys.h"
#include "drv_onu_ll_tbm.h"
#include "drv_onu_ll_tod.h"
#include "drv_onu_tse.h"

#define UNUSED_PARAM_DEV (void)p_dev
#define UNUSED_PARAM (void)param

static struct fsq fsq_init_values;

/* COP interface container for tool chain loader */
extern tse_interface_t tse_interface[ONU_GPE_COP_LABEL_MAX];
/* mapping structure for all COP microcode labels */
extern labelmapping_t labelmapping[ONU_GPE_ALL_COP_LABEL_MAX];

extern enum gpe_arb_mode arbiter_mode;

extern onu_lock_t meter_lock;
extern onu_lock_t enqueue_lock;

int gem_port_remove(const uint16_t gem_port_id)
{
	uint16_t gpix;
	int error = 0;

	if (ictrlg_gpix_get(gem_port_id, &gpix) != 0)
		return 0;

	error |= gtc_port_id_encryption_set(gem_port_id, false);
	error |= gtc_port_id_enable(gem_port_id, false);
	error |= ictrlg_gem_port_delete(gem_port_id);
	error |= octrlg_gem_port_delete(gpix);

	return error;
}

/**
   Add a new GEM port table entry.
   \param gem_port_id        GEM port ID (0-4095)
   \param gem_port_is_omci   PDU type information
   \param gem_port_is_mc     Ingress Queue number information
                             (IQN: 5= Unicast, 6=Multicast, 7=OMCI)
   \param data_direction     Data direction of GEM port
 */
/** Hardware Programming Details
    Each GEM Port is identified by its 12-bit GEM Port ID. The hardware supports
    up to 256 GEM Ports at a time and identifies these by an 8-bit GEM Port
    Index (GPIX). The relationship between GEM Port ID and GEM Port Index must
    be unambiguous within the complete system, although the data is held in the
    software and at several locations in the hardware.

    \remark At no time a Port ID may be connected with more than one Port Index
            or the same index be used for different Port IDs in different parts
            of the hardware.

    - GPE/ICTRLG: The Ingress Controller of the SDMA provides a table that is
                  addressed by the 12-bit GEM Port ID and holds the 8-bit GEM
                  Port Index (together with a validity information bit).
                  This table must be updated each time a GEM Port ID is added.
                  It must be guaranteed that at no time more than 256 GEM Ports
                  are activated in this table. The GPT (GEM Port Table)
                  registers are used for configuration
    - GPE/OCTRLG: The Output Controller of the FDMA provides an inverse table
                  that is addressed by the GEM Port Index and which holds
                  the GEM Port IDs that are assigned to the GEM Ports.
                  The GPIXTABLE[n] registers are used for configuration.

    There are other configurations that are needed per GEM port which are not
    covered by the PLOAM or OMCI protocol and thus need application-specific
    implementation. These are:

    - GPE/IQM: For each active GEM port there must be an ingress queue assigned.
               This is configured in the ICTRLG register GPIX_CFG.IQN. There
               are three queues available for GEM data traffic:
               - Port ID is used for OMCI (gem_port_is_omci == true):
                  GPIX_CFG.IQN  = GPE_INGRESS_QUEUE_OMCI
                  GPIX_CFG.PDUT = GPE_PDU_TYPE_OMCI
               - Port ID is used for unicast data
                  ((bGEM_PortIsOMCI_ == false)&&(gem_port_is_mc == false):
                  GPIX_CFG.IQN  = ONU_GPE_INGRESS_QUEUE_GEM_UC
                  GPIX_CFG.PDUT = GPE_PDU_TYPE_ETH
               - Port ID is used for multicast data
                  ((gem_port_is_omci == false)&&(gem_port_is_mc == true):
                  GPIX_CFG.IQN  = ONU_GPE_INGRESS_QUEUE_GEM_MC
                  GPIX_CFG.PDUT = GPE_PDU_TYPE_ETH
*/
STATIC int gem_port_add(const uint16_t gem_port_id,
			const bool gem_port_is_omci,
			const bool gem_port_is_mc,
			const enum gpe_direction data_direction)
{
	int error;
	uint16_t gpix = ictrlg_gpix_free_get();

	if (gem_port_remove(gem_port_id) < 0)
		return -2;

	if (gpix >= ONU_GPE_MAX_GPIX)
		return -1;

	error = ictrlg_gem_port_set(gem_port_id, gem_port_is_omci,
				    gem_port_is_mc, gpix, data_direction);
	if (error == 0)
		error = octrlg_gem_port_set(gem_port_id, gpix, data_direction);

	return error;
}

int onu_cop_version_get(struct onu_control *ctrl,
			int cop_id,
			char *cop_name,
			int *major,
			int *minor)
{
	char tmp[256];
	char *tmp2;
	char version[6];
	uint16_t cnt;
	char *full_str;

	if (cop_id >= 6)
		return -1;

	full_str = &(mc_version_string[cop_id][0]);

	for (cnt = 0; cnt < 255; cnt++) {
		tmp[cnt] = full_str[cnt];
		if (full_str[cnt] != 0)
			continue;
		tmp[cnt] = '\n';
		if (full_str[cnt+1] == 0) {
			tmp[cnt] = 0;
			break;
		}
	}
	tmp[255] = 0;

	tmp2 = strstr(&tmp[0], "TITLE:");
	if (tmp2 == NULL)
		return -1;

	if (cop_name) {
		strncpy(cop_name, tmp2 + 7, 3);
		cop_name[3]='\0';
	}

	tmp2 = strstr(&tmp[0], "VERSION:");
	if (tmp2 == NULL)
		return -1;

	strncpy(version, tmp2 + 9, 5);
	version[4]='\0';

	return sscanf(version, "%d.%d", major, minor) != 2;
}

STATIC int onu_cop_version_print(struct onu_control *ctrl)
{
	char name[4];
	uint16_t cop_id;
	int major=0, minor=0;

	for (cop_id = 0; cop_id < 6; cop_id++) {
		if (onu_cop_version_get(ctrl, cop_id, name, &major, &minor)) {
			ONU_DEBUG_ERR("COP information get error");
			return -1;
		}

		ONU_DEBUG_MSG(" %s Microcode loaded V%d.%02d ",
			      name, major, minor);
	}

	return 0;
}

STATIC int gpe_scheduler_free_input_get(struct onu_control *ctrl,
					const uint16_t idx,
					uint8_t *leaf)
{
	int i;
	uint8_t leaf_mask;

	leaf_mask = ctrl->gpe_sched_track[idx].leaf_mask;
	/* get any free leaf out of 0..7*/
	for (i = 0; i < 8; i++) {
		if (!((leaf_mask >> i) & 0x1)) {
			leaf_mask |= (1 << i);
			break;
		}
	}
	if (i >= 8)
		return -1;

	ctrl->gpe_sched_track[idx].leaf_mask = leaf_mask;
	*leaf = i;

	return 0;
}

STATIC enum onu_errorcode gpe_redirection_table_init(struct onu_device *p_dev)
{
	enum onu_errorcode err;
	struct gpe_exception_queue_cfg cfg;
	uint8_t i;

	cfg.exception_queue = 0xFF;

	for (i = 0; i < ONU_GPE_REDIRECTION_TABLE_SIZE; i++) {
		cfg.exception_index = i;
		cfg.snooping_enable = false;

		err = gpe_exception_queue_cfg_set(p_dev, &cfg);
		if (err != ONU_STATUS_OK)
			return err;
	}

	return ONU_STATUS_OK;
}

STATIC enum onu_errorcode gpe_ds_gem_port_table_init(struct onu_device *p_dev)
{
	enum onu_errorcode ret = ONU_STATUS_OK;
	uint32_t i;
	struct gpe_table_entry entry;

	for (i = 0; i < ONU_GPE_DS_GEM_PORT_TABLE_SIZE; i++) {
		memset(&entry, 0x00, sizeof(entry));

		entry.id = ONU_GPE_DS_GEM_PORT_TABLE_ID;
		entry.instance = 0xFF;
		entry.index = i;
		entry.data.ds_gem_port.fid_mask_pcpi = ONU_GPE_FID_INNER_PCP_MASK;
		entry.data.ds_gem_port.fid_mask_pcpo = ONU_GPE_FID_OUTER_PCP_MASK;
		entry.data.ds_gem_port.fid_mask_vidi = ONU_GPE_FID_INNER_VID_MASK;
		entry.data.ds_gem_port.fid_mask_vido = ONU_GPE_FID_OUTER_VID_MASK;

		ret = gpe_table_entry_set(p_dev, &entry);
		if (ret != ONU_STATUS_OK)
			return ret;
	}

	return ret;
}

STATIC enum onu_errorcode gpe_lan_port_table_init(struct onu_device *p_dev)
{
	enum onu_errorcode ret = ONU_STATUS_OK;
	uint32_t i;
	struct gpe_table_entry entry;

	for (i = 0; i < ONU_GPE_LAN_PORT_TABLE_SIZE; i++) {
		memset(&entry, 0x00, sizeof(entry));

		entry.id = ONU_GPE_LAN_PORT_TABLE_ID;
		entry.instance = 0xFF;
		entry.index = i;
		entry.data.lan_port.fid_mask_pcpi = ONU_GPE_FID_INNER_PCP_MASK;
		entry.data.lan_port.fid_mask_pcpo = ONU_GPE_FID_OUTER_PCP_MASK;
		entry.data.lan_port.fid_mask_vidi = ONU_GPE_FID_INNER_VID_MASK;
		entry.data.lan_port.fid_mask_vido = ONU_GPE_FID_OUTER_VID_MASK;

		ret = gpe_table_entry_set(p_dev, &entry);
		if (ret != ONU_STATUS_OK)
			return ret;
	}

	return ret;
}

STATIC enum onu_errorcode gpe_enqueue_table_init(struct onu_device *p_dev)
{
	enum onu_errorcode ret = ONU_STATUS_OK;

	gpe_enqueue_modify(p_dev->ctrl, ONU_GPE_MAX_QUEUE, true);
	gpe_enqueue_modify(p_dev->ctrl, ONU_GPE_QUEUE_INDEX_OMCI_HI_US, true);

	return ret;
}

/** \addtogroup ONU_MAPI_REFERENCE_INTERNAL
   @{
*/

/** \addtogroup ONU_GPE_INTERNAL
   @{
*/

/** The gpe_init function is called upon GPON software startup to provide
    initial settings for the Packet Engine hardware module.
*/

/** Hardware Programming Details:
    The following hardware functions need to be initialized:
    - Table set-up
      Some of the configuration tables need to be cleared or pre-set.
      Table access is provided through ONU_GPE_TABLE_SET.

      SCE Tables
      ----------
      See the related chapter in the internal UMPR document.

    - TMU initializaiton

      IQM.IQT[n]0.QE = EN, [n] = 0 ... number of ingress queues - 1
      IQM.IQT[n]1.QB = EN, [n] = 0 ... number of ingress queues - 1

      For the LAN ports the scheduler block number is set to the same value as
      the egress port number
      for(nEgressPortIndex=64, nEgressPortIndex=<67, ++){
      EPMT.SBID = nEgressPortIndex;
      }

     Map the LAN queues to egress ports and schedulers (fixed setting):
     for(nQueueIndex=0, nQueueIndex=<7, ++){
      QSMT.SBIN = 64*8 + nQueueIndex;
      QEMT.EPN  = 64;
      QMTC.QID  = nQueueIndex;
     }
     for(nQueueIndex=8, nQueueIndex=<15, ++){
      QSMT.SBIN = 65*8 + nQueueIndex;
      QEMT.EPN  = 65;
      QMTC.QID  = nQueueIndex;
     }
     for(nQueueIndex=16, nQueueIndex=<23, ++){
      QSMT.SBIN = 66*8 + nQueueIndex;
      QEMT.EPN  = 66;
      QMTC.QID  = nQueueIndex;
     }
     for(nQueueIndex=24, nQueueIndex=<31, ++){
      QSMT.SBIN = 67*8 + nQueueIndex;
      QEMT.EPN  = 67;
      QMTC.QID  = nQueueIndex;
     }

   Map the LAN port scheduler inputs to LAN port queues:
     for(nQueueIndex=0, nQueueIndex=<7, ++){
      SBITR0.QSID = nQueueIndex;
      SBITC.SBIN  = 64*8 + nQueueIndex;
     }
     for(nQueueIndex=8, nQueueIndex=<15, ++){
      SBITR0.QSID = nQueueIndex;
      SBITC.SBIN  = 65*8 + nQueueIndex;
     }
     for(nQueueIndex=16, nQueueIndex=<23, ++){
      SBITR0.QSID = nQueueIndex;
      SBITC.SBIN  = 66*8 + nQueueIndex;
     }
     for(nQueueIndex=24, nQueueIndex=<31, ++){
      SBITR0.QSID = nQueueIndex;
      SBITC.SBIN  = 67*8 + nQueueIndex;
     }

   Map the scheduler outputs to egress ports:
     for(nEgressPortIndex=64, nEgressPortIndex<=67, ++){
      SBOTR0.OMID = nEgressPortIndex;
      SBOTR0.V    = 0;
      SBOTR0.LVL  = 0;
      SBOTR0.SOE  = 1;
      SBOTC.SBID  = nEgressPoretIndex;
     }

   -  Block ingress queue 7 for SW access
      IQM.IQT71.QB = blocked (0b1)
    - Clear the packet egress queues

    - Microengine firmware loading & configuration.
      Each of the microengines needs to be loaded with its firmware code.
      Each of the microengines needs to be loaded with its specific
      configuration.
      The configuration depends on the FW version!
      The Microcode engines are loaded with the output of the Assembler
      toolchain. The binaries hold information of code, configuration and
      optionally data initialization.
      Special configuration is required for some MC tables, like:
      ONU_GPE_COP_FWD: The aging time prescaler must be configured
                       according to the target aging time range
                       (8-bit counter wrap-around time).

    - Copy fuse information from FBS0.STATUS.FUSE1 to firmware configuration.

    - PCTRL configuration
      The PCTRL module is initialized by activating dispatcher, merger and
      processing elements (PE). FW can be loaded after successful activation.
      Tables resident on PE memory needs to be configured and initialized.
      Special configuration is required for some PE tables, like:
      Parser configuration (load the default values for VLAN
      Ethertypes (TPID))
      FIO_GPE_PARSER_CFG_SET

    - GPE hardware fixed pre-configuration
      Several parts of the GPE-related hardware must be pre-configured,
      which are:
      OCTRLL0.CFG.EPN     = 64
      OCTRLL1.CFG.EPN     = 65
        OCTRLL2.CFG.EPN     = 66
        OCTRLL3.CFG.EPN     = 67

    - GPE hardware activation
      Several parts of the GPE-related hardware must be actively switched on,
      which are:
        OCTRLG.CTRL.ACT     = EN after tables have been initialized
        OCTRLL0.CTRL.ACT    = EN if LAN port 0 is used, else = DIS
        OCTRLL0.CTRL.TOUTEN = EN if LAN port 0 timeout is used, else = DIS
        OCTRLL1.CTRL.ACT    = EN if LAN port 1 is used, else = DIS
        OCTRLL1.CTRL.TOUTEN = EN if LAN port 1 timeout is used, else = DIS
        OCTRLL2.CTRL.ACT    = EN if LAN port 2 is used, else = DIS
        OCTRLL2.CTRL.TOUTEN = EN if LAN port 2 timeout is used, else = DIS
        OCTRLL3.CTRL.ACT    = EN if LAN port 3 is used, else = DIS
        OCTRLL3.CTRL.TOUTEN = EN if LAN port 3 timeout is used, else = DIS
        TBM.CTRL.ACT        = EN
        TBM.CTRL.FRZ        = DIS
        TBM.CTRL.EPOC       = 0
        TBM.CTRL.CPERIOD    = 0
        IQM.CTRL.ACT        = SET
        FSQM.CTRL.ACT       = SET
        FSQM.CTRL.IOB_EN    = SET
        PCTRL.CTRL.ACT      = SET after the microengine firmware has been loaded
        SYS_GPE.ACT.PE0     = SET after the microengine firmware has been loaded
        SYS_GPE.ACT.PE1     = SET after the microengine firmware has been loaded
        SYS_GPE.ACT.PE2     = SET after the microengine firmware has been loaded
        SYS_GPE.ACT.PE3     = SET after the microengine firmware has been loaded
        SYS_GPE.ACT.PE4     = SET after the microengine firmware has been loaded
        SYS_GPE.ACT.PE5     = SET after the microengine firmware has been loaded
        SYS_GPE.ACT.PE6     = SET after the microengine firmware has been loaded
        SYS_GPE.ACT.PE7     = SET after the microengine firmware has been loaded
        SYS_GPE.ACT.GPON    = SET
        SYS_GPE.ACT.LAN0    = SET if LAN port 0 is used,
            else SYS_GPE.DEACT.LAN0 = CLR
        SYS_GPE.ACT.LAN1    = SET if LAN port 1 is used,
            else SYS_GPE.DEACT.LAN1 = CLR
        SYS_GPE.ACT.LAN2    = SET if LAN port 2 is used,
            else SYS_GPE.DEACT.LAN2 = CLR
        SYS_GPE.ACT.LAN3    = SET if LAN port 3 is used,
            else SYS_GPE.DEACT.LAN3 = CLR

        The Learning Limitation Table must be set to nLimit = 0x3FF for all
        bridge ports (unlimited learning).

   - GPE Arbiter, disabled after initialization
      GPEARB.CNTR.PERIOD = 0
      GPEARB.PID0        = 0
      ...
      GPEARB.PID63       = 0

   - Maximum Ethernet frame size
      ICTRLG.MAXSIZE0 = ONU_GPE_DEFAULT_MAX_ETHERNET_FRAME_LENGTH
      ICTRLL0.MAXSIZE0 = ONU_GPE_DEFAULT_MAX_ETHERNET_FRAME_LENGTH
      ICTRLL1.MAXSIZE0 = ONU_GPE_DEFAULT_MAX_ETHERNET_FRAME_LENGTH
      ICTRLL2.MAXSIZE0 = ONU_GPE_DEFAULT_MAX_ETHERNET_FRAME_LENGTH
      ICTRLL3.MAXSIZE0 = ONU_GPE_DEFAULT_MAX_ETHERNET_FRAME_LENGTH
      EIM_MACS_TOP_PDI.MAC_FLEN.LEN = ONU_GPE_DEFAULT_MAX_ETHERNET_FRAME_LENGTH
      EIM_MAC_PDI_0.MAC_CTRL_2.MLEN = JUMBO
      EIM_MAC_PDI_1.MAC_CTRL_2.MLEN = JUMBO
      EIM_MAC_PDI_2.MAC_CTRL_2.MLEN = JUMBO
      EIM_MAC_PDI_3.MAC_CTRL_2.MLEN = JUMBO

   - Maximum OMCI frame size
      ICTRLG.MAXSIZE3 = ONU_GPE_DEFAULT_MAX_OMCI_FRAME_LENGTH

   - Maximum IP frame size
      ICTRLG.MAXSIZE1 = ONU_GPE_DEFAULT_MAX_IP_FRAME_LENGTH

   - Maximum MPLS frame size
      ICTRLG.MAXSIZE2 = ONU_GPE_DEFAULT_MAX_MPLS_FRAME_LENGTH
*/
static enum onu_errorcode gpe_modules_init(struct onu_device *p_dev,
					   const bool debug,
					   const struct gpe_init_data *param)
{
	enum onu_errorcode err;
	struct onu_control *ctrl = p_dev->ctrl;
	uint16_t i;
	uint8_t num_pe = (uint8_t)param->num_pe;
	static const uint32_t pe_run_mask[ONU_GPE_NUMBER_OF_PE_MAX] = {
		0x7, 0x77, 0x777, 0x7777, 0x77777, 0x777777
	};

	if (num_pe > ONU_GPE_NUMBER_OF_PE_MAX || !num_pe)
		return GPE_STATUS_VALUE_RANGE_ERR;

	if (param->arb_mode < ARB_MODE_NA || param->arb_mode > ARB_MODE_GIG2_5)
		return GPE_STATUS_VALUE_RANGE_ERR;

	/* store the number of PEs in the context*/
	ctrl->num_pe = num_pe;

	/* initialize default queue weights */
	memset(ctrl->gpe_equeue_weight, 0xff, sizeof(ctrl->gpe_equeue_weight));

	gpearb_init(param->arb_mode);

	/* FSQM initialization */
	if (param->ll_mod_sel.fsqm) {
		fsq_init_values.head = ONU_GPE_LLT_MIN;
		fsq_init_values.tail = ONU_GPE_LLT_MAX;
		fsqm_init(&fsq_init_values);
	}

	if (param->ll_mod_sel.iqm)
		iqm_init();

	/* activate PEs, MRG and DISP module */
	sce_init(num_pe);

	/* activate hardware coprocessor, load code, load definitions,
	   initializes table contents */
	if (cop_init(p_dev) != 0)
		return ONU_STATUS_COP_INIT_ERR;
	else
		onu_cop_version_print(ctrl);

	tbm_init();

	/* Initialize dispatcher
	 * No special initialization is needed
	 */
	if (param->ll_mod_sel.tmu)
		tmu_init();

	/* Initialize OCTRLG and OCTRLL */
	if (param->ll_mod_sel.octrlg)
		if (octrlg_init() != 0)
			return ONU_STATUS_ERR;

	for (i = 0; i < ONU_GPE_MAX_ETH_UNI; i ++) {
		if (param->ll_mod_sel.octrll[i])
			octrll_init(i);
	}

	/* Initialize ICTRLG and ICTRLL */
	if (param->ll_mod_sel.ictrlg)
		ictrlg_init();

	for (i = 0; i < ONU_GPE_MAX_ETH_UNI; i ++) {
		if (param->ll_mod_sel.ictrll[i])
			ictrll_init(i);
	}

	/* Initialize merge */
	if (sce_merge_init() != 0)
		return ONU_STATUS_MRG_INIT_ERR;

	/* W O R K A R O U N D ! */
	/* reboot MERGER module */
	sys_gpe_merger_reboot();
	/* reboot TMU module */
	sys_gpe_tmu_reboot();
	sce_merge_init();
	tmu_init();
	/* end of WA */
	/* load PE firmware */
	err = gpe_sce_selected_download(p_dev, &param->fw_name[0], num_pe);
	if (err != ONU_STATUS_OK)
		return err;

	if (debug == false) {
		/*sce_process_mode_set (SCE_MODE_COMMAND);*/
		/* activating the firmware */
		sce_fw_pe_run(pe_run_mask[num_pe - 1]);

		/* initializes PE table contents */
		if (gpe_sce_pe_init(ctrl) != ONU_STATUS_OK) {
			ONU_DEBUG_ERR("FW can't init PE tables");
			return ONU_STATUS_FW_INIT_ERR;
		}

		/* initialize redirection table */
		err = gpe_redirection_table_init(p_dev);
		if (err != ONU_STATUS_OK)
			return err;

		/* initialize DS GEM port table*/
		err = gpe_ds_gem_port_table_init(p_dev);
		if (err != ONU_STATUS_OK)
			return err;

		/* initialize LAN port table*/
		err = gpe_lan_port_table_init(p_dev);
		if (err != ONU_STATUS_OK)
			return err;

		/* initialize enqueue table*/
		err = gpe_enqueue_table_init(p_dev);
		if (err != ONU_STATUS_OK)
			return err;
		}

	/* enable timer for aging feature, required in A12 only */
	pctrl_w32(0x1, tictrl);
	/* init SW trigger data for the Aging Process */
	ctrl->gpe_aging_trigger.lsa = ONU_GPE_LLT_NIL;
	ctrl->gpe_aging_trigger.ttrig = 0;

	ssb_init();

	((struct onu_control*)p_dev->ctrl)->gpe_init = true;

	return ONU_STATUS_OK;
}

enum onu_errorcode gpe_init(struct onu_device *p_dev,
			    const struct gpe_init_data *param)
{
	return gpe_modules_init(p_dev, false, param);
}

enum onu_errorcode gpe_debug_init(struct onu_device *p_dev,
				  const struct gpe_init_data *param)
{
	return gpe_modules_init(p_dev, true, param);
}

enum onu_errorcode
gpe_low_level_modules_enable(struct onu_device *p_dev,
			     const struct gpe_ll_mod_sel *param)
{
	enum onu_errorcode onu_errorcode = ONU_STATUS_OK;
	uint32_t i;

	UNUSED_PARAM_DEV;
	/* GPE arbiter is always enabled */
	/* activation sequence, do not change ! */
	if (param->fsqm && fsqm_is_enabled()) {
		ONU_DEBUG_ERR("FSQM enable failed, already enabled!");
		onu_errorcode = GPE_STATUS_VALUE_LL_MODULE_ENABLE_ERR;
	} else {
		fsqm_enable(param->fsqm);
	}

	if (param->iqm && iqm_is_enabled()) {
		ONU_DEBUG_ERR("IQM enable failed, already enabled!");
		onu_errorcode = GPE_STATUS_VALUE_LL_MODULE_ENABLE_ERR;
	} else {
		iqm_enable(param->iqm);
	}

	if (tbm_is_enabled()) {
		ONU_DEBUG_ERR("TBM enable failed, already enabled!");
		onu_errorcode = GPE_STATUS_VALUE_LL_MODULE_ENABLE_ERR;
	} else {
		tbm_enable(1);
	}

	if (param->tmu && tmu_is_enabled()) {
		ONU_DEBUG_ERR("TMU enable failed, already enabled!");
		onu_errorcode = GPE_STATUS_VALUE_LL_MODULE_ENABLE_ERR;
	} else {
		tmu_enable(param->tmu);
	}

	if (param->octrlg && octrlg_is_enabled()) {
		ONU_DEBUG_ERR("OCTRLG enable failed, already enabled!");
		onu_errorcode = GPE_STATUS_VALUE_LL_MODULE_ENABLE_ERR;
	} else {
		octrlg_enable(param->octrlg);
	}

	for (i = 0; i < ONU_GPE_MAX_ETH_UNI; i++) {
		if (param->octrll[i] && octrll_is_enabled(i)) {
			ONU_DEBUG_ERR("OCTRLL%d enable failed, already "
				      "enabled!", i);
			onu_errorcode = GPE_STATUS_VALUE_LL_MODULE_ENABLE_ERR;
		} else {
			octrll_enable(i, param->octrll[i]);
		}
	}

	if (param->ictrlg && ictrlg_is_enabled()) {
		ONU_DEBUG_ERR("ICTRLG enable failed, already enabled!");
		onu_errorcode = GPE_STATUS_VALUE_LL_MODULE_ENABLE_ERR;
	} else {
		ictrlg_enable(param->ictrlg);
	}

	for (i = 0; i < ONU_GPE_MAX_ETH_UNI; i++) {
		if (param->ictrll[i] && ictrll_is_enabled(i)) {
			ONU_DEBUG_ERR("ICTRLL%d enable failed, already "
				      "enabled!", i);
			onu_errorcode = GPE_STATUS_VALUE_LL_MODULE_ENABLE_ERR;
		} else {
			ictrll_enable(i, param->ictrll[i]);
		}
	}

	/* DISPATCHER is always mandatory  */
	if (sce_dispatcher_is_enabled()) {
		ONU_DEBUG_ERR("DISPATCHER enable failed, already enabled!");
		onu_errorcode = GPE_STATUS_VALUE_LL_MODULE_ENABLE_ERR;
	} else {
		sce_dispatcher_enable(true);
	}


	/* MERGER is always mandatory  */
	if (sce_merge_is_enabled()) {
		ONU_DEBUG_ERR("MERGER enable failed, already enabled!");
		onu_errorcode = GPE_STATUS_VALUE_LL_MODULE_ENABLE_ERR;
	} else {
		sce_merge_enable(true);
	}

	/* re-configure FSQM module */
	if (param->fsqm && fsqm_is_enabled() &&
	    !(fsq_init_values.init_status)) {
		fsqm_enable(0);
		fsq_init_values.head = ONU_GPE_LLT_MIN + 0x20;
		fsq_init_values.tail = ONU_GPE_LLT_MAX;
		fsqm_init(&fsq_init_values);
		fsq_init_values.init_status = 1;
	}
	if (param->fsqm && fsqm_is_enabled()) {
		ONU_DEBUG_ERR("ERR: FSQM enable failed, already enabled!");
		onu_errorcode = GPE_STATUS_VALUE_LL_MODULE_ENABLE_ERR;
	} else {
		fsqm_enable(param->fsqm);
	}

	((struct onu_control*)p_dev->ctrl)->init = true;

	return onu_errorcode;
}

/** The gpe_cfg_set function is used to provide basic configurations of the
    Packet Engine hardware module.
*/

/** Hardware Programming Details:
   - gem_blk_len:OCTRLG.CFG0.IBS
   - gem_payload_size_max: OCTRLG.CFG1.GEMPLSIZE
   - pdu_size_max_eth: ICTRLG.MAXSIZE0.SIZE
                       and ICTRLL0...3.MAXSIZE0.SIZE
   - pdu_size_max_omci: ICTRLG.MAXSIZE3.SIZE
   - pdu_size_max_ip: ICTRLG.MAXSIZE1.SIZE
   - pdu_size_max_mpls: ICTRLG.MAXSIZE2.SIZE

    dbru_mode:
    - GPE_DBRU_MODE_OFF: Enable DBRu debug mode and set data to a fixed value
      of 0 to ensure that if the OLT sends DBRu requests and the ONT shall be
      non-status-reporting, an all-zero value is reported.
      OCTRLG.DBRUDBG = 0000 0000
      OCTRLG.CFG1.DBRUDBG = 1 (EN)
   - GPE_DBRU_MODE_[others]: Disable DBRu debug mode
      OCTRLG.CFG1.DBRUDBG = 0 (DIS)
*/
enum onu_errorcode gpe_cfg_set(struct onu_device *p_dev,
			       const struct gpe_cfg *param)
{
	uint32_t pdu_sz_max[8] = {0};
	UNUSED_PARAM_DEV;

	/* gem_blk_len:OCTRLG.CFG0.IBS,
	   gem_payload_size_max: OCTRLG.CFG1.GEMPLSIZE */
	octrlg_config_set(param->gem_blk_len, param->gem_payload_size_max);

	/* pdu_size_max_eth: ICTRLG.MAXSIZE0.SIZE
                        and ICTRLL0...3.MAXSIZE0.SIZE

	   pdu_size_max_omci: ICTRLG.MAXSIZE3.SIZE
	   pdu_size_max_ip: ICTRLG.MAXSIZE1.SIZE
	   pdu_size_max_mpls: ICTRLG.MAXSIZE2.SIZE */
	pdu_sz_max[0] = param->pdu_size_max_eth;
	pdu_sz_max[1] = param->pdu_size_max_ip;
	pdu_sz_max[2] = param->pdu_size_max_mpls;
	pdu_sz_max[3] = param->pdu_size_max_omci;

	ictrlg_pdu_size_set(pdu_sz_max);

	/* GPE_DBRU_MODE_OFF: Enable DBRu debug mode and set data to a fixed
	   value of 0 to ensure that if the OLT sends DBRu requests and the ONT
	   shall be non-status-reporting, an all-zero value is reported.
	   OCTRLG.DBRUDBG = 0000 0000
	   OCTRLG.CFG1.DBRUDBG = 1 (EN)

	   GPE_DBRU_MODE_<others>: Disable DBRu debug mode
	   OCTRLG.CFG1.DBRUDBG = 0 (DIS) */
	octrlg_dbru_mode_dbg_set(param->dbru_dbg_mode);

	octrlg_dbru_debug_set(0, 0, 0);

	return ONU_STATUS_OK;
}

/** The gpe_cfg_get function is used to read back the basic configuration
    of the Packet Engine hardware module.
*/
/** Hardware Programming Details:
    For gpe_cfg_get hardware programming details see gpe_cfg_set.
*/
enum onu_errorcode gpe_cfg_get(struct onu_device *p_dev, struct gpe_cfg *param)
{
	uint32_t pdu_sz_max[8] = {0};

	UNUSED_PARAM_DEV;
	octrlg_config_get(&param->gem_blk_len, &param->gem_payload_size_max);

	ictrlg_pdu_size_get(pdu_sz_max);
	param->pdu_size_max_eth = pdu_sz_max[0];
	param->pdu_size_max_ip = pdu_sz_max[1];
	param->pdu_size_max_mpls = pdu_sz_max[2];
	param->pdu_size_max_omci = pdu_sz_max[3];

	octrlg_dbru_mode_dbg_get(&param->dbru_dbg_mode);

	/** \todo add handling for aging time
	*/
	param->aging_time = 0;

	return ONU_STATUS_OK;
}

/** The gpe_status_get function provides a summary of status information that
    is available for the Packet Engine hardware module.
*/
/** Hardware Programming Details:
    The status information is read from the following hardware registers:
     -
     \todo define GPE status registers/memories
*/
enum onu_errorcode gpe_status_get(struct onu_device *p_dev,
				  struct gpe_status *param)
{
	struct onu_control *ctrl = p_dev->ctrl;

	memset(param, 0, sizeof(struct gpe_status));

	octrlg_dbru_mode_get(&param->dbru_mode);

	param->num_pe = ctrl->num_pe;

	return ONU_STATUS_OK;
}

/** The gpe_arbiter_get function is used to get an the setting of
    the GPE arbiter
*/
/** Hardware Programming Details
*/
enum onu_errorcode gpe_arbiter_get(struct onu_device *p_dev,
				   struct gpe_arbiter *param)
{
	uint32_t i;

	if (sys_gpe_hw_is_activated(SYS_GPE_ACT_ARB_SET) == 0)
		return GPE_STATUS_NOT_AVAILABLE;

	for (i = 0; i < 16; i++)
		param->data_25g[i] = gpearb_r32(pid[i]);

	param->arb_mode = arbiter_mode;

	return ONU_STATUS_OK;
}

/** The gpe_arbiter_set function is used to set a configuration
    for the GPE arbiter
*/
/** Hardware Programming Details
*/
enum onu_errorcode gpe_arbiter_set(struct onu_device *p_dev,
				   const struct gpe_arbiter *param)
{
	UNUSED_PARAM_DEV;

	if (param->arb_mode < ARB_MODE_NA || param->arb_mode > ARB_MODE_GIG2_5)
		return GPE_STATUS_VALUE_RANGE_ERR;

	gpearb_init(param->arb_mode);

	return ONU_STATUS_OK;
}

/** The gpe_gem_port_add function is used to add a GEM port to the system.
*/
/** Hardware Programming Details
    Each GEM Port is identified by its 12-bit GEM Port ID. The hardware supports
    up to 256 GEM Ports at a time and identifies these by an 8-bit GEM Port
    Index (GPIX).
    The relationship between GEM Port ID and GEM Port Index must
    be unambiguous within the complete system, although the data is held in the
    software and at several locations in the hardware.

    \remark At no time a Port ID may be connected with more than one Port Index
            or the same index be used for different Port IDs in different parts
            of the hardware.

    - GPE/SCE:    The GEM Port Upstream Table is addressed by the 8-bit GEM Port
                  Index and holds up to 256 GEM Port ID validity
                  information bits and some other data). This table must be
                  updated each time a GEM Port ID is added.
                  The generic table access function is used to configure the
                  table.

    \note
    The gem_port_index is managed internally and can not be passed from OMCI
*/
enum onu_errorcode gpe_gem_port_add(struct onu_device *p_dev,
				    const struct gpe_gem_port *in,
				    struct gpe_gem_port *out)
{
	uint32_t valid = false;

	UNUSED_PARAM_DEV;

	if (in->gem_port_id >= ONU_GPE_MAX_GEM_PORT_ID)
		return GPE_STATUS_VALUE_RANGE_ERR;

	out->gem_port_id = in->gem_port_id;

	if (gem_port_add(in->gem_port_id,
			 in->gem_port_is_omci,
			 in->gem_port_is_mc,
			 in->data_direction) != 0)
		return GPE_STATUS_NOT_AVAILABLE;

	/* - re-use the encryption settings here
	   - it could be already be configured by PLOAM message
	   - don't overwrite from user space
	*/
	if (gtc_port_id_enable(in->gem_port_id, true) != 0)
		return GPE_STATUS_VALUE_RANGE_ERR;

	if (ictrlg_gem_port_get(out->gem_port_id,
				&out->gem_port_enable,
				&out->gem_port_is_omci,
				&out->gem_port_is_mc,
				&out->gem_port_index,
				&out->data_direction) != 0)
		return GPE_STATUS_NOT_AVAILABLE;

	if (gtc_port_id_get(out->gem_port_id,
			    &valid, &out->encryption_enable) != 0)
		return GPE_STATUS_VALUE_RANGE_ERR;


	return ONU_STATUS_OK;
}

/** The gpe_gem_port_set function is used,
    to set a GEM port at a specific GPIX entry.
*/
enum onu_errorcode gpe_gem_port_set(struct onu_device *p_dev,
				    const struct gpe_gem_port *in)
{
	UNUSED_PARAM_DEV;

	if (in->gem_port_id >= ONU_GPE_MAX_GEM_PORT_ID)
		return GPE_STATUS_VALUE_RANGE_ERR;

	if (ictrlg_gem_port_set(in->gem_port_id,
				in->gem_port_is_omci,
				in->gem_port_is_mc,
				in->gem_port_index,
				in->data_direction) != 0)
		return GPE_STATUS_NOT_AVAILABLE;

	if (octrlg_gem_port_set(in->gem_port_id,
				in->gem_port_index,
				in->data_direction) != 0)
		return GPE_STATUS_NOT_AVAILABLE;

	if (gtc_port_id_encryption_set(in->gem_port_id,
		in->encryption_enable) != 0)
		return GPE_STATUS_VALUE_RANGE_ERR;

	if (gtc_port_id_enable(in->gem_port_id, true) != 0)
		return GPE_STATUS_VALUE_RANGE_ERR;

	return ONU_STATUS_OK;
}

/** The gpe_gem_port_delete function is used to remove a GEM port.
*/
/** Hardware Programming Details
    This function performs the inverse action of gpe_gem_port_add.
    The required hardware actions are:

    - GPE/SCE: Mark the GEM Port Index invalid in the GEM Port Upstream
               Table.

    \note
    The gem_port_index is managed internally and can not be passed from OMCI
*/
enum onu_errorcode gpe_gem_port_delete(	struct onu_device *p_dev,
					const struct gem_port_id *param)
{
	UNUSED_PARAM_DEV;

	if (param->val >= ONU_GPE_MAX_GEM_PORT_ID)
		return GPE_STATUS_VALUE_RANGE_ERR;

	if (gem_port_remove(param->val) != 0)
		return GPE_STATUS_NOT_AVAILABLE;

	return ONU_STATUS_OK;
}

/** The gpe_gem_port_get function is used to report for a GEM port ID.
*/
/** Hardware Programming Details

    \note
    The gem_port_index is managed internally and can not be passed from OMCI
*/
enum onu_errorcode gpe_gem_port_get(struct onu_device *p_dev,
				    const struct gem_port_id *in,
				    struct gpe_gem_port *out)
{
	uint32_t valid = false;

	UNUSED_PARAM_DEV;

	if (in->val >= ONU_GPE_MAX_GEM_PORT_ID)
		return GPE_STATUS_VALUE_RANGE_ERR;

	out->gem_port_id = in->val;

	if (ictrlg_gem_port_get(in->val,
				&out->gem_port_enable,
				&out->gem_port_is_omci,
				&out->gem_port_is_mc,
				&out->gem_port_index,
				&out->data_direction) != 0) {
		out->encryption_enable = false;
		return GPE_STATUS_NOT_AVAILABLE;
	}
	if (gtc_port_id_get(in->val, &valid, &out->encryption_enable) != 0)
		return GPE_STATUS_VALUE_RANGE_ERR;

	return ONU_STATUS_OK;
}

enum onu_errorcode gpe_tcont_create(struct onu_device *p_dev,
				 const struct gpe_tcont_cfg *param)
{
	enum onu_errorcode ret;
	struct gpe_sched_create sched;
	struct gpe_scheduler_idx in;

	memset(&sched, 0x00, sizeof(sched));

	in.index = ONU_GPE_SCHEDULER_INDEX_TCONT + param->epn;
	ret = gpe_scheduler_get(p_dev, &in, &sched);
	if(ret != ONU_STATUS_OK)
		return ret;

	if(sched.use_tcont == false) {
		memset(&sched, 0x00, sizeof(sched));
		sched.index = ONU_GPE_SCHEDULER_INDEX_TCONT + param->epn;
		sched.scheduler_id = 0;
		sched.scheduler_policy = (enum gpe_policy) param->policy;
		sched.use_regular = 1;
		sched.priority_weight = 0;
		sched.level = 0;
		sched.port_idx = param->epn;
		sched.use_tcont = true;
		ret = gpe_scheduler_create(p_dev, &sched);
		if (ret == ONU_STATUS_OK) {
			struct gpe_epn egress_port;
			egress_port.epn = param->epn;
			ret = gpe_egress_port_enable(p_dev, &egress_port);
		}
	}

	return ret;
}

/** The gpe_tcont_set function is used to add Allocation ID information to
    the T-CONT table.
*/
enum onu_errorcode gpe_tcont_set(struct onu_device *p_dev,
				 const struct gpe_tcont *param)
{
	UNUSED_PARAM_DEV;

	if (param->alloc_id >= ONU_GPE_MAX_ALLOCATION_ID) {
		ONU_DEBUG_ERR("gpe_tcont_set - wrong alloc Id %d",
				param->alloc_id);
		return GPE_STATUS_VALUE_RANGE_ERR;
	}
	if (param->tcont_idx >= ONU_GPE_MAX_TCONT) {
		ONU_DEBUG_ERR("gpe_tcont_set - wrong TCIX %d",
				param->tcont_idx);
		return GPE_STATUS_VALUE_RANGE_ERR;
	}
	if (param->reg_egress_port != 127 &&
	   param->reg_egress_port > ONU_GPE_MAX_ANI_TMU_EGRESS_PORT) {
		ONU_DEBUG_ERR("gpe_tcont_set - wrong regular egress port %d",
				param->reg_egress_port);
		return GPE_STATUS_VALUE_RANGE_ERR;
	}
	if (param->pre_egress_port != 127 &&
	    param->pre_egress_port > ONU_GPE_MAX_ANI_TMU_EGRESS_PORT) {
		ONU_DEBUG_ERR("gpe_tcont_set - wrong preempting egress port %d",
				param->pre_egress_port);
		return GPE_STATUS_VALUE_RANGE_ERR;
	}

	octrlg_tcont_set(param->tcont_idx, param->alloc_id);
	octrlg_epn_set(param->tcont_idx, param->reg_egress_port,
		       param->pre_egress_port);
	gtc_tcont_set(param->tcont_idx, param->alloc_id);

	if (param->reg_egress_port != 127) {
		gpe_enqueue_enable(p_dev->ctrl, param->reg_egress_port, true);
	}

	return ONU_STATUS_OK;
}

/** The gpe_tcont_get function is used to evaluate the tcont
    parameters.
*/
enum onu_errorcode gpe_tcont_get(struct onu_device *p_dev,
				 const struct tcont_index *in,
				 struct gpe_tcont *out)
{
	uint32_t  repn, pepn;
	uint32_t  alloc_id;
	bool      used;
	UNUSED_PARAM_DEV;
	ONU_DEBUG_MSG("gpe_tcont_get tcont %d", in->tcont_idx);

	out->tcont_idx = in->tcont_idx;

	if (in->tcont_idx >= ONU_GPE_MAX_TCONT)
		return GPE_STATUS_VALUE_RANGE_ERR;
	if (gtc_tcont_get(in->tcont_idx, &alloc_id, &used) != 0)
		return GPE_STATUS_VALUE_RANGE_ERR;
	if (octrlg_epn_get(in->tcont_idx, &repn, &pepn) != 0)
		return GPE_STATUS_NOT_AVAILABLE;
	out->pre_egress_port = pepn;
	out->reg_egress_port = repn;
	out->alloc_id = used? alloc_id:0xFF;

	return ONU_STATUS_OK;
}

enum onu_errorcode gpe_tcont_shutdown(struct onu_device *p_dev,
										const uint32_t tcont_idx)
{
	uint32_t alloc_id;
	uint32_t  repn, pepn;
	bool used;

	gtc_tcont_get(tcont_idx, &alloc_id, &used);

	if (!used)
		return ONU_STATUS_OK;

	if (octrlg_epn_get(tcont_idx, &repn, &pepn) != 0)
		return GPE_STATUS_NOT_AVAILABLE;
	if (repn == 127)
		goto GPE_TCONT_SHUTDOWN;
	gpe_enqueue_enable(p_dev->ctrl, repn, false);

GPE_TCONT_SHUTDOWN:
	if (gtc_tcont_delete(tcont_idx) != 0)
		return GTC_STATUS_NOT_AVAILABLE;
	if (octrlg_epn_set(tcont_idx, 127, 127) != 0)
		return GTC_STATUS_NOT_AVAILABLE;
	if (octrlg_tcont_alloc_id_delete(alloc_id) != 0)
		return GPE_STATUS_NOT_AVAILABLE;

	return ONU_STATUS_OK;
}

/** The gpe_tcont_delete function is used to remove a T-CONT ID for a given
    T-CONT index from the T-CONT table.
*/
enum onu_errorcode gpe_tcont_delete(struct onu_device *p_dev,
				    const struct tcont_index *param)
{
	enum onu_errorcode ret = ONU_STATUS_OK;

	if (param->tcont_idx >= ONU_GPE_MAX_TCONT)
		return GPE_STATUS_VALUE_RANGE_ERR;


	if(param->tcont_idx == OMCI_TCIX) {
		if (octrlg_epn_set(param->tcont_idx, 127, ONU_GPE_OMCI_EGRESS_PORT) != 0)
			return GTC_STATUS_NOT_AVAILABLE;
	} else {
		ret = gpe_tcont_shutdown(p_dev, param->tcont_idx);
	}

	return ONU_STATUS_OK;
}

/** The gpe_egress_port_create function is used to connect a UNI port
    (LAN port) or a T-CONT with a TMU egress port.
*/
/** Hardware Programming Details

    Assume scheduler blocks for the egress ports to be created
    have been created beforehand.

    call ll driver functions:
    octrll_port_set
    octrlg_epn_set
    tmu_egress_port_link_set
*/
enum onu_errorcode gpe_egress_port_create(struct onu_device *p_dev,
					  const struct gpe_eport_create *param)
{
	enum onu_errorcode ret = ONU_STATUS_OK;
	UNUSED_PARAM_DEV;

	if (param->is_uni) {
		/** \todo add also the VUNI (CPU) ports 68...71,
			  which must be set in octrlc */
		if (octrll_port_set(param->index, param->regular_epn) == 0) {
			tmu_egress_port_link_set(param->regular_epn,
						 param->regular_sbid);
		} else {
			ret = ONU_STATUS_ERR;
		}
	} else {
		if (octrlg_epn_set(param->index, param->regular_epn,
				   param->preempting_epn) == 0) {
			tmu_egress_port_link_set(param->regular_epn,
						 param->regular_sbid);
			tmu_egress_port_link_set(param->preempting_epn,
						 param->preempting_sbid);
		} else {
			ret = ONU_STATUS_ERR;
		}
	}

	return ret;
}

/** The gpe_egress_port_get function is used to read back the structure
    of an egress port.
*/
enum onu_errorcode gpe_egress_port_get(struct onu_device *p_dev,
				       const struct gpe_epn *in,
				       struct gpe_eport_create *out)
{
	uint32_t epe, sbid;
	uint32_t in_epn = in->epn, epn, pepn;
	int ret;
	uint32_t i;
	UNUSED_PARAM_DEV;

	if (in_epn >= ONU_GPE_MAX_EGRESS_PORT)
		return GPE_STATUS_VALUE_RANGE_ERR;

	out->is_uni = false;
	out->index = 0xFF;
	out->regular_epn = 0xFF;
	out->preempting_epn = 0xFF;
	out->preempting_sbid = 0xFF;
	out->regular_sbid = 0xFF;

	/* check whether EPN belongs to LAN */
	for (i = 0; i < ONU_GPE_MAX_ETH_UNI; i++) {
		ret = octrll_port_get(i, &epn);
		if (ret)
			return ONU_STATUS_ERR;

		if (epn == in_epn) {
			out->is_uni = true;
			out->index = (uint8_t)i;
			out->regular_epn = epn;
			break;
		}
	}

	/* check whether EPN belongs to "virtual" LAN */
	if (out->is_uni == false) {
		if (in_epn == ONU_GPE_EPN_VUNI0 ||
		    in_epn == ONU_GPE_EPN_VUNI1 ||
		    in_epn == ONU_GPE_EPN_VUNI2 ||
		    in_epn == ONU_GPE_EPN_VUNI3) {
			out->is_uni = true;
			out->index = ONU_GPE_MAX_ETH_UNI
				+ in_epn - ONU_GPE_EPN_VUNI0;
			out->regular_epn = epn;
		}
	}

	/* check whether EPN belongs to ANI */
	if (out->is_uni == false) {
		for (i = 0; i < ONU_GPE_MAX_TCONT; i++) {
			ret = octrlg_epn_get((uint8_t)i, &epn, &pepn);
			if (ret)
				return ONU_STATUS_ERR;

			if (in_epn == epn || in_epn == pepn) {
				out->is_uni = false;
				out->index = (uint8_t)i;
				out->regular_epn = epn;
				out->preempting_epn = pepn;

				tmu_epmt_read(out->preempting_epn, &epe, &sbid);
				out->preempting_sbid = (uint8_t)sbid;

				break;
			}
		}
	}

	if (out->regular_epn != 0xFF) {
		tmu_epmt_read(out->regular_epn, &epe, &sbid);
		out->regular_sbid = (uint8_t)sbid;
	}

	return ONU_STATUS_OK;
}

/** The gpe_port_index_get function is used to read back the structure
    of an egress port.
*/
enum onu_errorcode gpe_port_index_get(struct onu_device *p_dev,
				      const struct gpe_egress_port *in,
				      struct gpe_eport_create *out)
{
	uint32_t epe, sbid;
	UNUSED_PARAM_DEV;

	if (in->is_uni) {
		if (octrll_port_get(in->index, &out->regular_epn) != 0)
			return ONU_STATUS_ERR;
	} else {
		if (octrlg_epn_get(in->index, &out->regular_epn,
				   &out->preempting_epn) != 0)
			return ONU_STATUS_ERR;
	}
	tmu_epmt_read(out->regular_epn, &epe, &sbid);
	out->regular_sbid = (uint8_t)sbid;

	if (!in->is_uni) {
		tmu_epmt_read(out->preempting_epn, &epe, &sbid);
		out->preempting_sbid = (uint8_t)sbid;
	}
	out->index = in->index;
	out->is_uni = in->is_uni;

	return ONU_STATUS_OK;
}

/** The gpe_egress_port_delete function is used to remove the link between a TMU
    egress port and the ANI / UNI egress port.
*/
enum onu_errorcode gpe_egress_port_delete(struct onu_device *p_dev,
					  const struct gpe_egress_port *param)
{
	UNUSED_PARAM_DEV;

	if (!param->is_uni && param->index >= ONU_GPE_MAX_TCONT_PORT)
		return GPE_STATUS_VALUE_RANGE_ERR;

	tmu_egress_port_link_set(param->index, 0x3F);

	return ONU_STATUS_NOT_IMPLEMENTED;
}


/** The gpe_egress_port_cfg_set function is used to configure an egress port.
*/
/** Hardware Programming Details

*/
enum onu_errorcode
gpe_egress_port_cfg_set(struct onu_device *p_dev,
			const struct gpe_egress_port_cfg *param)
{
	enum onu_errorcode ret = ONU_STATUS_OK;
	struct tmu_egress_port_thr epth;

	UNUSED_PARAM_DEV;

	tmu_egress_port_enable(param->epn, param->enable);

	epth.epth[0] = param->egress_port_threshold_max;
	epth.epth[1] = param->egress_port_threshold_green;
	epth.epth[2] = param->egress_port_threshold_yellow;
	epth.epth[3] = param->egress_port_threshold_red;
	tmu_egress_port_tail_drop_thr_set(param->epn, &epth);

	return ret;
}

/** The gpe_egress_port_cfg_get function is used to read back the configuration
    of an egress port.
*/
enum onu_errorcode gpe_egress_port_cfg_get(struct onu_device *p_dev,
					   const struct gpe_epn *in,
					   struct gpe_egress_port_cfg *out)
{
	struct tmu_egress_port_thr epth;
	bool ena;
	UNUSED_PARAM_DEV;

	tmu_egress_port_tail_drop_thr_get(in->epn, &epth);
	ena = tmu_is_egress_port_enabled(in->epn);

	out->enable			  = ena;
	out->egress_port_threshold_max	  = epth.epth[0];
	out->egress_port_threshold_green  = epth.epth[1];
	out->egress_port_threshold_yellow = epth.epth[2];
	out->egress_port_threshold_red	  = epth.epth[3];
	out->epn = in->epn;

	return ONU_STATUS_OK;
}

/** The gpe_egress_port_status_get function is used to read back the status
    of an egress port.
*/
enum onu_errorcode
gpe_egress_port_status_get(struct onu_device *p_dev,
			   const struct gpe_epn *in,
			   struct gpe_egress_port_status *param)
{
	struct tmu_egress_port_status epot;

	UNUSED_PARAM_DEV;

	tmu_egress_port_seg_occupancy_get(in->epn, epot.epoc);

	param->egress_port_occupancy_max    = epot.epoc[0];
	param->egress_port_occupancy_green  = epot.epoc[1];
	param->egress_port_occupancy_yellow = epot.epoc[2];
	param->egress_port_occupancy_red    = epot.epoc[3];

	param->epn = in->epn;

	return ONU_STATUS_OK;
}

/** The gpe_backpressure_cfg_set function is used to configure the
    backpressure (flow control) behavior of a LAN port.
*/
enum onu_errorcode
gpe_backpressure_cfg_set(struct onu_device *p_dev,
			 const struct gpe_backpressure_cfg *param)
{
	struct iqm_iqt_entry bkp;
	int iqn;
	UNUSED_PARAM_DEV;

	for (iqn = 0; iqn < 4; iqn++) {
		iqm_iqueue_cfg_get(iqn, &bkp);
		bkp.qbth = param->lan_queue_backpressure_high[iqn];
		bkp.qbtl = param->lan_queue_backpressure_low[iqn];
		iqm_iqueue_cfg_set(iqn, &bkp);
	}

	fsqm_free_segment_threshold_set(&param->free_segment_threshold[0]);

	return ONU_STATUS_OK;
}

/** The gpe_backpressure_cfg_get function is used to read back the
    backpressure (flow control) configuration of a LAN port.
*/
enum onu_errorcode gpe_backpressure_cfg_get(struct onu_device *p_dev,
					    struct gpe_backpressure_cfg *param)
{
	struct iqm_iqt_entry bkp;
	int iqn;

	UNUSED_PARAM_DEV;
	for (iqn = 0; iqn < 4; iqn++) {
		iqm_iqueue_cfg_get(iqn, &bkp);
		param->lan_queue_backpressure_high[iqn] = bkp.qbth;
		param->lan_queue_backpressure_low[iqn] = bkp.qbtl;
	}

	fsqm_free_segment_threshold_get(&param->free_segment_threshold[0]);

	return ONU_STATUS_OK;
}

/** The gpe_ingress_queue_cfg_get function is used to read back the
    configuration of an ingress queue.
*/
enum onu_errorcode gpe_ingress_queue_cfg_get(struct onu_device *p_dev,
					     const struct gpe_iqueue *in,
					     struct gpe_iqueue_cfg *out)
{
	struct iqm_iqt_entry iqm_cfg;
	UNUSED_PARAM_DEV;

	iqm_iqueue_cfg_get(in->index, &iqm_cfg);

	out->index = in->index;
	out->qe	   = iqm_cfg.qe;
	out->qb	   = iqm_cfg.qb;
	out->qdth  = (iqm_cfg.qdth)<<3;
	out->qrth  = (iqm_cfg.qrth)<<3;
	out->qbth  = (iqm_cfg.qbth)<<3;
	out->qbtl  = (iqm_cfg.qbtl)<<3;
	out->tmask = iqm_cfg.tmask;

	return ONU_STATUS_OK;
}

/** The gpe_ingress_queue_cfg_set function is used to set the
    configuration of an ingress queue.
*/
enum onu_errorcode gpe_ingress_queue_cfg_set(struct onu_device *p_dev,
					     const struct gpe_iqueue_cfg *param)
{
	struct iqm_iqt_entry iqm_cfg;
	UNUSED_PARAM_DEV;

	iqm_iqueue_cfg_get(param->index, &iqm_cfg);
	iqm_cfg.qe    = param->qe;
	iqm_cfg.qb    = param->qb;
	iqm_cfg.qdth  = (param->qdth)>>3;
	iqm_cfg.qrth  = (param->qrth)>>3;
	iqm_cfg.qbth  = (param->qbth)>>3;
	iqm_cfg.qbtl  = (param->qbtl)>>3;
	iqm_cfg.tmask = param->tmask;
	iqm_iqueue_cfg_set(param->index, &iqm_cfg);

	return ONU_STATUS_OK;
}

/** The gpe_ingress_queue_status_get function is used to read back the
    configuration of an ingress queue.
*/
enum onu_errorcode gpe_ingress_queue_status_get(struct onu_device *p_dev,
						const struct gpe_iqueue *in,
						struct gpe_iqueue_status *out)
{

	struct iqm_iqt_entry iq_stat;
	UNUSED_PARAM_DEV;

	iqm_iqueue_status_get(in->index, &iq_stat);

	out->index = in->index;

	out->qf    = iq_stat.qf;
	out->bp    = iq_stat.bp;
	out->pocc  = iq_stat.pocc;
	out->qocc  = iq_stat.qocc;
	out->qdc   = iq_stat.qdc;
	out->tick  = iq_stat.tick;

	return ONU_STATUS_OK;
}

/** The gpe_egress_queue_create function is used to assign the scheduler and
      egress port to an egress queue.
*/
enum onu_errorcode
gpe_egress_queue_create(struct onu_device *p_dev,
			const struct gpe_equeue_create *param)
{
	struct onu_control *ctrl = (struct onu_control *)p_dev->ctrl;
	uint16_t idx, scheduler_input;
	uint8_t leaf;
	int ret;

	ONU_DEBUG_MSG("gpe_egress_queue_create %d %d %d",
		      param->index,
		      param->scheduler_input,
		      param->egress_port_number);

	if (param->index >= EGRESS_QUEUE_ID_MAX ||
	    param->egress_port_number >= ONU_GPE_MAX_EGRESS_PORT ||
	    param->scheduler_input >= ONU_GPE_MAX_SCHEDULER * 8)
		return GPE_STATUS_VALUE_RANGE_ERR;

	/* not allowed if TMU is enabled */
	if (tmu_is_enabled())
		return ONU_STATUS_OK;

	scheduler_input = param->scheduler_input;
	idx = param->scheduler_input >> 3;
	if (idx >= ONU_GPE_MAX_SCHEDULER)
		return GPE_STATUS_VALUE_RANGE_ERR;
	if (ctrl->gpe_sched_track[idx].in_use == 0)
		return GPE_STATUS_NOT_AVAILABLE;

	if (ctrl->gpe_sched_track[idx].policy == GPE_POLICY_WRR) {
		scheduler_input &= ~7;
		ret = gpe_scheduler_free_input_get(ctrl, idx, &leaf);
		if (ret < 0)
			return GPE_STATUS_VALUE_RANGE_ERR;
		scheduler_input |= leaf;
	}

	tmu_egress_queue_create(param->index, scheduler_input,
				param->egress_port_number);

	return ONU_STATUS_OK;
}

/** The gpe_egress_queue_get function is used to read back structural attributes
    of a queue.
*/
enum onu_errorcode gpe_egress_queue_get(struct onu_device *p_dev,
					const struct gpe_equeue *in,
					struct gpe_equeue_create *out)
{
	uint32_t sbin, epn;

	UNUSED_PARAM_DEV;

	if (in->index >= EGRESS_QUEUE_ID_MAX)
		return GPE_STATUS_VALUE_RANGE_ERR;

	tmu_qsmt_read(in->index, &sbin);
	tmu_qemt_read(in->index, &epn);

	out->index = in->index;
	out->egress_port_number = epn;
	out->scheduler_input = sbin;

	return ONU_STATUS_OK;
}

enum onu_errorcode gpe_egress_queue_delete(struct onu_device *p_dev,
					   const struct gpe_equeue *param)
{
	UNUSED_PARAM_DEV;

	if (param->index >= EGRESS_QUEUE_ID_MAX)
		return GPE_STATUS_VALUE_RANGE_ERR;

	/* not allowed if TMU is enabled */
	if (tmu_is_enabled())
		return ONU_STATUS_OK;

	tmu_qemt_write(param->index, EPNNULL_EGRESS_PORT_ID);
	tmu_qsmt_write(param->index, NULL_SCHEDULER_INPUT_ID);

	return ONU_STATUS_OK;
}

static void gpe_scheduler_queues_weight_refresh(struct onu_control *ctrl,
						uint32_t scheduler_index)
{
	uint32_t i;
	uint32_t queue_scheduler_index;
	struct tmu_equeue_link equeue_link;
	uint32_t queues[ONU_GPE_MAX_EGRESS_QUEUES];
	uint32_t qid, queues_num = 0;
	uint32_t c = 255;
	uint32_t weight;

	for (i = 0; i < ONU_GPE_MAX_EGRESS_QUEUES; i++) {
		tmu_equeue_link_get(i, &equeue_link);
		queue_scheduler_index = (equeue_link.sbin & ~0x7) >> 3;

		if (queue_scheduler_index != scheduler_index)
			continue;

		if (ctrl->gpe_equeue_weight[i] == 0)
			continue;

		queues[queues_num++] = i;

		if (ctrl->gpe_equeue_weight[i] < c)
			c = ctrl->gpe_equeue_weight[i];
	}

	c *= 1023;

	for (i = 0; i < queues_num; i++) {
		qid = queues[i];

		weight = (c + ctrl->gpe_equeue_weight[qid] / 2) /
			ctrl->gpe_equeue_weight[qid];

		tmu_equeue_link_get(qid, &equeue_link);
		tmu_sched_blk_in_weight_set(equeue_link.sbin, weight);
	}
}

/** The gpe_egress_queue_cfg_set function is used to configure a priority queue.
*/
/** Hardware Programming Details

   Assumes /ref gpe_scheduler_create has been called beforehand.
   Assumes /ref gpe_egress_queue_create has been called beforehand.

   scheduler_input must not be changed by this command, unless equal to
   NULL_SCHEDULER_INPUT_ID
   egress_port_number must not be changed by this command, unless equal to
   EPNNULL_EGRESS_PORT_ID

   The egress queue parameters are configured through the TMU hardware module.

   The following hardware functions can be configured:
   - index                               -> TMU.QMTC.QID; QMTC.RWS = WR
   - enable                              -> TMU.QTHT0.QE
   - egress_port_number                  -> TMU.QEMT.EPN  (if undefined)
   - scheduler_input                     -> TMU.QSMT.SBIN (if undefined)
   - weight                              -> TMU.SBIT[scheduler_input].IWGT
   - avg_weight                          -> TMU.QOCT0.WQ
   - wred_enable                         -> TMU.QTHT0.DMOD
   - reservation_threshold               -> TMU.QOCT0.QRTH
   - size                                -> TMU.QTHT4.QTTH0
   - drop_threshold_red                  -> TMU.QTHT4.QTTH1
   - drop_threshold_green_max            -> TMU.QTHT2.MATH0
   - drop_threshold_green_min            -> TMU.QTHT1.MITH0
   - drop_threshold_yellow_max           -> TMU.QTHT2.MATH1
   - drop_threshold_yellow_min           -> TMU.QTHT1.MITH1
   - drop_probability_green              -> TMU.QTHT3.SLOPE1
   - drop_probability_yellow             -> TMU.QTHT3.SLOPE0
   - coloring_mode                       -> forward to SCE firmware
   - discard_block_cnt_reset_interval    -> manage in counter SW

   \remarks the thresholds in the driver are expressed in units of
            segments (64 bytes)

   ask scheduler attribute for policy (HOL or WRR)
   HOL:
   strict prio if all inputs on weight 0
   scheduler leaf indicates priority
   select leaf accordingly
   WRR: use weight directle for IWGT
*/
enum onu_errorcode gpe_egress_queue_cfg_set(struct onu_device *p_dev,
					    const struct gpe_equeue_cfg *param)
{
	struct onu_control *ctrl = (struct onu_control *)p_dev->ctrl;
	struct tmu_equeue_drop_params thx;
	struct tmu_equeue_link equeue_link;
	uint32_t scheduler_index;

	if (param->index >= EGRESS_QUEUE_ID_MAX ||
	    param->enable > 1 ||
	    param->sbin_enable >1 ||
	    param->weight > 1023 ||
	    param->wred_enable > 1 ||
	    param->avg_weight > 15 ||
	    param->size > 2304 << 3 ||
	    param->reservation_threshold > 0xFFF ||
	    param->drop_threshold_red > 2304 << 3 ||
	    param->drop_threshold_green_max > 2304 << 3 ||
	    param->drop_threshold_green_min > 2304 << 3 ||
	    param->drop_threshold_yellow_max > 2304 << 3 ||
	    param->drop_threshold_yellow_min > 2304 << 3 ||
	    param->drop_probability_green > 100 ||
	    param->drop_probability_yellow > 100)
		return GPE_STATUS_VALUE_RANGE_ERR;

	tmu_equeue_drop_params_get(param->index, &thx);

	thx.mith0 = param->drop_threshold_green_min;
	thx.math0 = param->drop_threshold_green_max;
	thx.mith1 = param->drop_threshold_yellow_min;
	thx.math1 = param->drop_threshold_yellow_max;
	thx.maxp0 = param->drop_probability_green;
	thx.maxp1 = param->drop_probability_yellow;
	thx.dmod  = param->wred_enable;
	thx.qe    = param->enable;
	thx.wq    = param->avg_weight;
	thx.qrth  = param->reservation_threshold;
	thx.qtth0 = param->size;
	thx.qtth1 = param->drop_threshold_red;

	tmu_equeue_drop_params_set(param->index, &thx);
	tmu_equeue_link_get(param->index, &equeue_link);

	tmu_sched_blk_in_enable(equeue_link.sbin, param->sbin_enable);
	if (ctrl->gpe_equeue_weight[param->index] != param->weight) {
		ctrl->gpe_equeue_weight[param->index] = param->weight;

		scheduler_index = (equeue_link.sbin & ~0x7) >> 3;

		if (param->weight == 0)
			tmu_sched_blk_in_weight_set(equeue_link.sbin, 0);
		else
			gpe_scheduler_queues_weight_refresh(ctrl,
							    scheduler_index);
	}

	return ONU_STATUS_OK;
}

/** The gpe_egress_queue_cfg_get function is used to read back the basic
    configuration of an egress queue in the Packet Engine hardware module.
*/
enum onu_errorcode gpe_egress_queue_cfg_get(struct onu_device *p_dev,
					    const struct gpe_equeue *in,
					    struct gpe_equeue_cfg *out)
{
	struct onu_control *ctrl = (struct onu_control *)p_dev->ctrl;
	struct tmu_equeue_drop_params thx;
	struct tmu_equeue_link equeue_link;
	struct tmu_sched_blk_in_link sblink;

	if (in->index >= EGRESS_QUEUE_ID_MAX)
		return GPE_STATUS_VALUE_RANGE_ERR;

	tmu_equeue_drop_params_get(in->index, &thx);
	tmu_equeue_link_get(in->index, &equeue_link);
	tmu_sched_blk_in_link_get(equeue_link.sbin, &sblink);

	out->enable = thx.qe;
	out->sbin_enable = sblink.sie;
	out->weight = ctrl->gpe_equeue_weight[in->index];
	out->avg_weight = thx.wq;
	out->wred_enable = thx.dmod;
	out->reservation_threshold = thx.qrth;
	out->size = thx.qtth0;
	out->drop_threshold_red = thx.qtth1;
	out->drop_threshold_green_max = thx.math0;
	out->drop_threshold_green_min = thx.mith0;
	out->drop_threshold_yellow_max = thx.math1;
	out->drop_threshold_yellow_min = thx.mith1;
	out->drop_probability_green = thx.maxp0;
	out->drop_probability_yellow = thx.maxp1;

	out->index = in->index;

	/* This parameter is not handled by this function. */
	out->coloring_mode = 000000;

	return ONU_STATUS_OK;
}

/** The gpe_egress_queue_status_get function is used to read the current status
    of an egress queue in the Packet Engine hardware module.
*/
/** Hardware Programming Details
    The following hardware functions must be read:
    - index: selects the egress queue
                                 TMU, QMTC.QID = index
                                 TMU, QMTC.RWS = RD
                                 TMU, QMTC.RWC = RD
    - fill: number of segments, currently in the egress queue
           TMU, QMT1.QOCC
    - fill_avg: number of bytes, average value
          TMU, QMT2.QAVG
    - frames: number of frames, currently in the egress queue TMU, QMT1.POCC

   Queue configuration option: shared maximum queue size to be reported
*/
enum onu_errorcode gpe_egress_queue_status_get(struct onu_device *p_dev,
					       const struct gpe_equeue *in,
					       struct gpe_equeue_status *out)
{
	struct tmu_equeue_link equeue_link;
	struct tmu_sched_blk_in_link sblink;
	uint32_t wq, qrth, qocc, qavg;
	uint32_t qfm[3];

	UNUSED_PARAM_DEV;

	if (in->index > EGRESS_QUEUE_ID_MAX)
		return GPE_STATUS_VALUE_RANGE_ERR;

	tmu_qoct_read(in->index, &wq, &qrth, &qocc, &qavg);
	tmu_qfmt_read(in->index, &qfm[0]);

	out->index = in->index;

	out->config_opt = 1;

	out->fill = get_val(qocc, TMU_QOCT1_QOCC_MASK,
				  TMU_QOCT1_QOCC_OFFSET);

	out->fill_avg = get_val(qavg, TMU_QOCT2_QAVG_MASK,
				      TMU_QOCT2_QAVG_OFFSET);

	out->frames = get_val(qfm[0], TMU_QFMT0_POCC_MASK,
				      TMU_QFMT0_POCC_OFFSET);

	out->fill_max = out->fill;

	tmu_equeue_link_get(in->index, &equeue_link);
	tmu_sched_blk_in_link_get(equeue_link.sbin, &sblink);
	out->iwgt = sblink.iwgt;

	return ONU_STATUS_OK;
}

/** The gpe_egress_queue_path_get function is used to read back structural
    attributes along the path from a queue up to the egress port.
    \attention
    The value dumped only.
*/
enum onu_errorcode gpe_egress_queue_path_get(struct onu_device *p_dev,
					     const struct gpe_equeue *in,
					     struct gpe_equeue_path *out)
{
	struct tmu_equeue_link        qmt;
	struct tmu_sched_blk_in_link  sbit;
	struct tmu_sched_blk_out_link sbot;
	struct tmu_eport_link         epmt;
	uint8_t lvl;

	UNUSED_PARAM_DEV;

	tmu_equeue_link_get(in->index, &qmt);
	tmu_sched_blk_in_link_get(qmt.sbin, &sbit);
	tmu_sched_blk_out_link_get(qmt.sbin>>3, &sbot);
	lvl = 0;

	ONU_DEBUG_MSG("QID       %4u", in->index);
	ONU_DEBUG_MSG("QE        %4u", qmt.qe);
	ONU_DEBUG_MSG("EPN       %4u", qmt.epn);
	out->qe = qmt.qe;
	out->epn = qmt.epn;

	ONU_DEBUG_MSG("SBID[%3d] %4u", lvl, qmt.sbin >> 3);
	ONU_DEBUG_MSG("LEAF[%3d] %4u", lvl, qmt.sbin &  7);
	ONU_DEBUG_MSG("SIE [%3d] %4u", lvl, sbit.sie);
	ONU_DEBUG_MSG("SIT [%3d] %4u", lvl, sbit.sit);
	ONU_DEBUG_MSG("IWGT[%3d] %4u", lvl, sbit.iwgt);
	ONU_DEBUG_MSG("QSID[%3d] %4u", lvl, sbit.qsid);
	ONU_DEBUG_MSG("SOE [%3d] %4u", lvl, sbot.soe);
	ONU_DEBUG_MSG("LVL [%3d] %4u", lvl, sbot.lvl);
	ONU_DEBUG_MSG("==============");

	out->info[lvl].sbid = qmt.sbin >> 3;
	out->info[lvl].leaf = qmt.sbin &  7;
	out->info[lvl].sie = sbit.sie;
	out->info[lvl].sit = sbit.sit;
	out->info[lvl].iwgt = sbit.iwgt;
	out->info[lvl].qsid = sbit.qsid;
	out->info[lvl].soe = sbot.soe;
	out->info[lvl].lvl = sbot.lvl;

	while ((sbot.v==1) && (lvl<8)) {
		lvl++;
		ONU_DEBUG_MSG("SBID[%3d] %4u", lvl, sbot.omid >> 3);
		ONU_DEBUG_MSG("LEAF[%3d] %4u", lvl, sbot.omid &  7);
		out->info[lvl].sbid = sbot.omid >> 3;
		out->info[lvl].leaf = sbot.omid &  7;
		tmu_sched_blk_in_link_get(sbot.omid, &sbit);
		tmu_sched_blk_out_link_get(sbot.omid>>3, &sbot);
		out->info[lvl].sie = sbit.sie;
		out->info[lvl].sit = sbit.sit;
		out->info[lvl].iwgt = sbit.iwgt;
		out->info[lvl].qsid = sbit.qsid;
		out->info[lvl].soe = sbot.soe;
		out->info[lvl].lvl = sbot.lvl;
		ONU_DEBUG_MSG("SIE [%3d] %4u", lvl, sbit.sie);
		ONU_DEBUG_MSG("SIT [%3d] %4u", lvl, sbit.sit);
		ONU_DEBUG_MSG("IWGT[%3d] %4u", lvl, sbit.iwgt);
		ONU_DEBUG_MSG("QSID[%3d] %4u", lvl, sbit.qsid);
		ONU_DEBUG_MSG("SOE [%3d] %4u", lvl, sbot.soe);
		ONU_DEBUG_MSG("LVL [%3d] %4u", lvl, sbot.lvl);
		ONU_DEBUG_MSG("==============");
	}

	ONU_DEBUG_MSG("EPN       %4u", sbot.omid);
	tmu_egress_port_link_get(sbot.omid, &epmt);
	ONU_DEBUG_MSG("EPE       %4u", epmt.epe);
	ONU_DEBUG_MSG("SBID      %4u", epmt.sbid);

	out->lvl = lvl;
	out->omid = sbot.omid;
	out->epe = epmt.epe;
	out->sbid = epmt.sbid;

	return ONU_STATUS_OK;
}

/** The gpe_scheduler_cfg_set function is used to configure a scheduler's
    parameters and scheduling policy.
*/
/** Hardware Programming Details
    Scheduler blocks are located in the TMU hardware module.
    The following hardware functions must be configured:
    - index: selects the scheduler to be configured
                       TMU, SBITC.SBIN = index
                            SBITC.RWS  = RD
                            SBITC.RWC  = WR

      An error code is returned(GPE_STATUS_VALUE_RANGE_ERR), if
      index > ONU_GPE_MAX_SCHEDULER - 1

    - use_tcont: This flag decides, if the scheduler's output is directed to
                 another shceduler's input (false) or to a T-CONT (true).

      - Case 1 (scheduler): TMU, SBOTR0.V    = SB
                                 SBOTR0.OMID = connected_scheduler_index
                            TMU, SBOTC.SBID  = index
                                 SBOTC.RWS   = RD
                                 SBOTC.RWC   = WR

        For the selected next-stage scheduler, the input type and source
        scheduler index must be configured as well:

                            TMU, SBITC.SBIN  = connected_scheduler_index
                                 SBITC.RWS   = RD
                                 SBITC.RWC   = WR
                            TMU, SBITR0.SIT  = SBID
                                 SBITR0.QSID = index

        An error code is returned (GPE_STATUS_VALUE_RANGE_ERR), if
        connected_scheduler_index > ONU_GPE_MAX_SCHEDULER - 1

      - Case 2 (T-CONT):    TMU, SBOTR0.V = EPN

        If the same T-CONT has already been referenced by more than one other
        scheduler, an error code is responded (GPE_STATUS_NOT_AVAILABLE).

        We can not configure the tcont_idx directly here, first we need to
        find out
        (a) to which egress port (EPN) the T-CONT is assigned. Then (b) we
       figure out the queue that is connected to this EPN and configure the
       queue to the scheduler.

        (a1) FDMA, egress_port_number = OCTRLG.TCTABLE<n/2>.REPN[n] with
        n = tcont_idx contains the egress port number that is assigned to
        the first tcont_idx.

        (a2) FDMA, egress_port_number = OCTRLG.TCTABLE<n/2>.PEPN[n] with
        n = tcont_idx contains the egress port number that is assigned to
        the second tcont_idx.

        (b) The T-CONT has not been used by any other scheduler yet:
            SCE, TMU.QMT0.EPN1 contains the egress port number
       egress_port_number that is assigned to an egress queue
       (identified by its egress_queue_index).

        The configuration sequence is as follows:
        - Check the egress port for the given tcont_idx
        - Check which egress_queue_index is assigned to this egress port
        - Set this queue in TMU, SBOTR0.OMID = egress_queue_index

        An error code is returned, if either no egress port is assigned to the
        T-CONT or no queue is assigned to the egress port
       (GPE_STATUS_NOT_AVAILABLE).
        An error code is also returned, if tcont_idx >= ONU_GPE_MAX_TCONT

    - priority_weight

      The weight parameter is provided for the _connected_ scheduler or T-CONT

      - Case 1 (scheduler):
                            TMU, SBITC.SBIN  = connected_scheduler_index
                                 SBITC.RWS   = RD
                                 SBITC.RWC   = WR
                            TMU, SBITR0.IWGT = 1023 - priority_weight

      An error code is returned if priority_weight > 1023
      (GPE_STATUS_VALUE_RANGE_ERR).

      - Case 2 (T-CONT):

      This attribute is ignored.

    - scheduler_policy

    - As the last action, activate the scheduler output:
      TMU, SBOTR0.SBO = EN (note the register description!)
*/
enum onu_errorcode gpe_scheduler_cfg_set(struct onu_device *p_dev,
					 const struct gpe_scheduler_cfg *param)
{
	uint32_t sbot[2];
	struct tmu_sched_blk_out_link sb;
	struct tmu_sched_blk_in_weights weights;

	UNUSED_PARAM_DEV;

	if (param->index >= ONU_GPE_MAX_SCHEDULER)
		return GPE_STATUS_VALUE_RANGE_ERR;

	if (param->weight > 1023)
		return GPE_STATUS_VALUE_RANGE_ERR;

	tmu_sched_blk_out_enable(param->index, param->output_enable);

	tmu_sched_blk_out_link_get(param->index, &sb);

	/* set the WRR in the connected scheduler if applicable */
	tmu_sbot_read(param->index, &sbot[0]);
	if (sb.v == 1) {
		tmu_sched_blk_in_weights_get(sb.omid>>3, &weights);
		weights.iwgt[sb.omid&0x7] = param->weight;
		tmu_sched_blk_in_weights_set(sb.omid>>3, &weights);
	}

	return ONU_STATUS_OK;
}

/** The gpe_scheduler_cfg_get function is used to read back the scheduling
    policy of a scheduler in the Packet Engine hardware module.
*/
enum onu_errorcode gpe_scheduler_cfg_get(struct onu_device *p_dev,
					 const struct gpe_scheduler_idx *in,
					 struct gpe_scheduler_cfg *out)
{
	struct tmu_sched_blk_out_link sb;
	struct tmu_sched_blk_in_weights weights;

	UNUSED_PARAM_DEV;

	if (in->index >= ONU_GPE_MAX_SCHEDULER)
		return GPE_STATUS_VALUE_RANGE_ERR;

	out->output_enable = tmu_is_sched_blk_out_enabled(in->index);
	out->index = in->index;

	tmu_sched_blk_out_link_get(in->index, &sb);

	/* get the WRR in the connected scheduler if applicable */
	if (sb.v == 1) {
		tmu_sched_blk_in_weights_get(sb.omid>>3, &weights);
		out->weight = weights.iwgt[sb.omid&0x7];
	} else {
		out->weight = 0;
	}

	return ONU_STATUS_OK;
}

/** The gpe_scheduler_create function is used to create a scheduler ID in the
    scheduler table.
*/
/** Hardware Programming Details

    The following parameters must be configured:
    - scheduler_id            : Managed Entity ID of the scheduler
                                Return an error if this number is already in use
                                (GPE_STATUS_NOT_AVAILABLE).
    - index                   : Identifies one of the available schedulers.
                                Return an error, if no more scheduler is
            available (GPE_STATUS_NOT_AVAILABLE).
                                Else return the selected value.
                                The relationship between scheduler_id and
                                index is stored in a software variable.
    - use_tcont               : Defines if the scheduler output is connected to
                                a T-CONT identified by port_idx via
                                a regular or a preempting egress port
            (use_tcont==1) or if the options of use_regular
            apply (use_tcont==0).
    - use_regular             : If use_tcont==1, this parameter selects if the
                                scheduler is attached to the regular or the
            preempting egress port.
                                If use_tcont==0, this parameter selects
                                if the scheduler is attached to the egress port
            identified by port_idx (use_regular==1) or to
            the input of another scheduler identified by
            connected_scheduler_index (use_regular==0).
    - port_idx                : T-CONT index, if use_tcont==1, else
            UNI egress port, if use_regular==1, else ignore
    - connected_scheduler_index
                              : If both use_tcont==0 and use_regular==0
                 Scheduler index (range 0..127),
                                Return an error code
            (GPE_STATUS_VALUE_RANGE_ERR),
                                else continue with priority_weight
    - priority_weight         : Priority/Weight value is used to determine both
                                the leaf of the connected_scheduler_index and
                                the weight of that leaf, to be set in IWGT.
                                The scheduler_leaf  will then be treated as a
                                hidden resource from the pool of 8 inputs per
                                scheduler. SW shall keep track of already
                                assigned inputs, taking into consideration that
                                each input will receive a weight (0 in case of
                                strict priority) and the leaf number indicates
                                 the priority in case of strict priority.

    - scheduler_policy        : returns the scheduler's policy as
                                GPE_POLICY_NULL: if nothing is connected to the
                                scheduler's input
                                GPE_POLICY_HOL : if a single
                                queue or a single scheduler is connected to the
                                scheduler's input
                                GPE_POLICY_WRR : if more than one
            queue/scheduler are connected to the scheduler's
                                input
*/
enum onu_errorcode gpe_scheduler_create(struct onu_device *p_dev,
				        const struct gpe_sched_create *param)
{
	enum onu_errorcode ret = ONU_STATUS_OK;
	struct onu_control *ctrl = (struct onu_control *)p_dev->ctrl;
	uint32_t omid;
	uint8_t  v;
	uint8_t leaf=0;
	uint16_t weight;
	uint8_t idx = (uint8_t)param->connected_scheduler_index;

	omid   = param->port_idx;
	v      = 0;
	weight = 0;

	/* not allowed if TMU is enabled */
	if (tmu_is_enabled())
		return ONU_STATUS_OK;

	if (param->index >= ONU_GPE_MAX_SCHEDULER)
		return GPE_STATUS_VALUE_RANGE_ERR;

	if (param->level > ONU_GPE_MAX_SCHEDULER_LEVEL)
		return GPE_STATUS_VALUE_RANGE_ERR;

	if (ctrl->gpe_sched_track[param->index].in_use)
		return GPE_STATUS_NOT_AVAILABLE;

	if ((param->use_tcont == 0) && (param->use_regular == 0)) {
		/* hierarchical scheduling */
		if (idx >= ONU_GPE_MAX_SCHEDULER)
			return GPE_STATUS_VALUE_RANGE_ERR;
		if (ctrl->gpe_sched_track[idx].in_use == 0)
			return GPE_STATUS_NOT_AVAILABLE;

		/* check for the correct level configuration */
		if (ctrl->gpe_sched_track[idx].level >= param->level)
			return GPE_STATUS_VALUE_RANGE_ERR;
		if (ctrl->gpe_sched_track[idx].level != (param->level - 1))
			return GPE_STATUS_VALUE_RANGE_ERR;

		switch (ctrl->gpe_sched_track[idx].policy) {
		case GPE_POLICY_NULL:
			/* connected scheduler is a head */
			return GPE_STATUS_NOT_AVAILABLE;
		case GPE_POLICY_HOL:
			if (param->priority_weight > 7)
				return GPE_STATUS_VALUE_RANGE_ERR;
			leaf = (uint8_t)param->priority_weight;
			weight = 0;
			break;
		case GPE_POLICY_WRR:
			if (param->priority_weight > 1023)
				return GPE_STATUS_VALUE_RANGE_ERR;
			if (gpe_scheduler_free_input_get(ctrl,
					param->connected_scheduler_index,
					&leaf) < 0)
				return GPE_STATUS_NOT_AVAILABLE;
			weight = param->priority_weight;
			break;
		default:
			return GPE_STATUS_VALUE_RANGE_ERR;
		}
		omid = (uint32_t) (
			(param->connected_scheduler_index << 3) |
			(leaf & 0x7));
		v = 1;
	}

	tmu_sched_blk_create(param->index, param->level, omid, v, weight);

	/* mark scheduler as used*/
	ctrl->gpe_sched_track[param->index].in_use = true;
	/* set scheduler id*/
	ctrl->gpe_sched_track[param->index].id = param->scheduler_id;
	/* remember the policy */
	ctrl->gpe_sched_track[param->index].policy = param->scheduler_policy;
	/* remember scheduler level*/
	ctrl->gpe_sched_track[param->index].level = param->level;

	return ret;
}

/** The gpe_scheduler_delete function is used to remove a scheduler from the
    scheduler table.
*/
/** Hardware Programming Details
    The index is used to identify the scheduler resource that shall be
    deactivated.

    TMU, SBITR0.SIE  = DIS
    TMU, SBITR1.TB0  = DIS
         SBITR1.TB1  = DIS
    TMU, SBITC.RWS   = RD
         SBITC.RWC   = WR
         SBITC.SBIN  = index
    TMU, SBOTR0.SOE  = DIS
    TMU, SBOTC.RWS   = RD
         SBOTC.RWC   = WR
         SBOTC.SBIN  = index

    The relationship between scheduler index and scheduler ID is removed from
    the software variable.
*/
enum onu_errorcode gpe_scheduler_delete(struct onu_device *p_dev,
				        const struct gpe_scheduler_idx *param)
{
	struct onu_control *ctrl = (struct onu_control *)p_dev->ctrl;
	uint32_t sbot[2];
	uint32_t sbit[4];
	uint32_t omid, leaf, connected_scheduler_index;
	uint32_t sbin;

	UNUSED_PARAM_DEV;

	/* not allowed if TMU is enabled */
	if (tmu_is_enabled())
		return ONU_STATUS_OK;

	if (param->index >= ONU_GPE_MAX_SCHEDULER)
		return GPE_STATUS_VALUE_RANGE_ERR;

	if (!ctrl->gpe_sched_track[param->index].in_use)
		return GPE_STATUS_NOT_AVAILABLE;

	tmu_sbot_read(param->index, &sbot[0]);

	/* remove leaf from the connected scheduler leaf mask */
	if (sbot[0] & TMU_SBOTR0_V_SBIN) {
		omid = get_val(sbot[0], TMU_SBOTR0_OMID_MASK,
			       TMU_SBOTR0_OMID_OFFSET);

		leaf = omid & 7;
		connected_scheduler_index = omid >> 3;

		ctrl->gpe_sched_track[connected_scheduler_index].leaf_mask &=
			~leaf;
	}

	/* disable Scheduler Block Output */
	sbot[0] &= ~TMU_SBOTR0_SOE_EN;
	tmu_sbot_write(param->index, &sbot[0]);

	/* disable all Scheduler Block Inputs for this scheduler */
	for (leaf = 0; leaf < 8; leaf++) {
		sbin = (param->index << 3) + leaf;
		tmu_sbit_read(sbin, &sbit[0]);
		sbit[0] &= ~TMU_SBITR0_SIE_EN;
		tmu_sbit_write(sbin, &sbit[0]);
	}

	ctrl->gpe_sched_track[param->index].in_use = false;

	return ONU_STATUS_OK;
}

/** The gpe_scheduler_get function is used to read back structural attributes
    of a scheduler.
*/
enum onu_errorcode gpe_scheduler_get(struct onu_device *p_dev,
				     const struct gpe_scheduler_idx *in,
				     struct gpe_sched_create *out)
{
	uint32_t ret, i, index;
	uint32_t epn, pepn;
	struct tmu_sched_blk_out_link sb;
	struct tmu_sched_blk_in_weights weights;
	struct onu_control *ctrl = (struct onu_control *)p_dev->ctrl;

	UNUSED_PARAM_DEV;

	if (in->index >= ONU_GPE_MAX_SCHEDULER)
		return GPE_STATUS_VALUE_RANGE_ERR;

	index = in->index;
	out->index = index;
	tmu_sched_blk_out_link_get(index, &sb);
	out->level = sb.lvl;
	out->scheduler_id = ctrl->gpe_sched_track[index].id;
	out->scheduler_policy = ctrl->gpe_sched_track[index].policy;

	if (sb.v == 0) {
		out->connected_scheduler_index = 0xFF;
		out->priority_weight = 0;

		/* find tcont_id by epn */
		for (i = 0; i < ONU_GPE_MAX_TCONT; i++) {
			ret = octrlg_epn_get(i, &epn, &pepn);
			if (ret)
				continue;

			if (sb.omid == epn) {
				out->use_tcont = true;
				out->use_regular = true;
				out->port_idx = i;
				return ONU_STATUS_OK;
			}

			if (sb.omid == pepn) {
				out->use_tcont = true;
				out->use_regular = false;
				out->port_idx = i;
				return ONU_STATUS_OK;
			}
		}

		/* check 4 uni ports */
		for (i = 0; i < ONU_GPE_MAX_ETH_UNI; i++) {
			ret = octrll_port_get(i, &epn);
			if (ret)
				continue;

			if (epn == sb.omid) {
				out->use_tcont = false;
				out->use_regular = true;
				out->port_idx = i;
				return ONU_STATUS_OK;
			}
		}

		/* check 4 cpu ports */
		if (sb.omid == ONU_GPE_EPN_VUNI0 ||
		    sb.omid == ONU_GPE_EPN_VUNI1 ||
		    sb.omid == ONU_GPE_EPN_VUNI2 ||
		    sb.omid == ONU_GPE_EPN_VUNI3) {

			out->use_tcont = false;
			out->use_regular = true;
			out->port_idx = sb.omid - ONU_GPE_EPN_VUNI0 + 4;
		}
	} else {
		out->use_tcont = false;
		out->use_regular = false;
		out->port_idx = 0xFF;
		out->connected_scheduler_index = sb.omid >> 3;

		tmu_sched_blk_in_weights_get(sb.omid >> 3, &weights);
		out->priority_weight = weights.iwgt[sb.omid&0x7];
	}

	return ONU_STATUS_OK;
}

/** The gpe_scheduler_status_get function is used to read back status variables
    of a scheduler.
    (for debug)
*/
enum onu_errorcode gpe_scheduler_status_get(struct onu_device *p_dev,
					    const struct gpe_scheduler_idx *in,
					    struct gpe_scheduler_status *out)
{

	struct tmu_sched_blk_out_status stat;

	UNUSED_PARAM_DEV;

	tmu_sched_blk_out_status_get(in->index, &stat);

	out->index = in->index;
	out->sof   = stat.sof;
	out->wl    = stat.wl;
	out->wqid  = stat.wqid;

	return ONU_STATUS_OK;

}

static enum onu_errorcode meter_cfg_set(struct onu_device *p_dev,
					const bool enable,
					const struct gpe_meter_cfg *cfg)
{
	uint16_t index = (uint16_t)cfg->index;
	struct tbm_token_bucket_meter_params tbmt;
	uint32_t pir, cir, pbs;
	int16_t mod;

	UNUSED_PARAM_DEV;

	/* always set both meters, hardware does the logic if really both are
	   used in the end */
	/* set first bucket meter */
	if (index > ONU_GPE_MAX_TBM - 2)
		return GPE_STATUS_VALUE_RANGE_ERR;

	if (index & 1)
		return GPE_STATUS_VALUE_RANGE_ERR;

	/* The default value 0 accepts the ONU's factory default policy */
	pir = cfg->pir == 0 ? ONU_GPE_METER_PIR_DEF : cfg->pir;
	/* The default value 0 accepts the ONU's factory default policy */
	pbs = cfg->pbs == 0 ? ONU_GPE_METER_PBS_DEF : cfg->pbs;

	/* Treat values < ONU_GPE_METER_PIR_MIN as ONU_GPE_METER_PIR_MIN */
	pir = pir < ONU_GPE_METER_PIR_MIN ?
					ONU_GPE_METER_PIR_MIN : pir;
	/* Treat values < ONU_GPE_METER_CIR_MIN as ONU_GPE_METER_CIR_MIN */
	cir = cfg->cir < ONU_GPE_METER_CIR_MIN ?
					ONU_GPE_METER_CIR_MIN : cfg->cir;

	if(pir > ONU_GPE_METER_PIR_MAX)
		return GPE_STATUS_VALUE_RANGE_ERR;
	if(pbs > ONU_GPE_METER_PBS_MAX)
		return GPE_STATUS_VALUE_RANGE_ERR;
	if(cir > ONU_GPE_METER_CIR_MAX)
		return GPE_STATUS_VALUE_RANGE_ERR;
	if(cfg->cbs > ONU_GPE_METER_CBS_MAX)
		return GPE_STATUS_VALUE_RANGE_ERR;

	tbmt.tbe  = enable ? 1 : 0;
	tbmt.tbid = index;
	mod  = find_meter_mode(cfg);
	if (mod < 0)
		return GPE_STATUS_VALUE_RANGE_ERR;

	tbmt.mod = mod;

	tbmt.rate = cir;
	tbmt.mbs  = cfg->cbs;
	tbm_meter_cfg_set(&tbmt);

	tbmt.tbe  = enable ? 1 : 0;
	tbmt.tbid = index + 1;
	mod  = find_meter_mode(cfg);
	if (mod < 0)
		return GPE_STATUS_VALUE_RANGE_ERR;

	tbmt.mod = mod;

	tbmt.rate = pir;
	tbmt.mbs  = pbs;
	tbm_meter_cfg_set(&tbmt);

	return ONU_STATUS_OK;
}

static enum onu_errorcode meter_cfg_get(struct onu_device *p_dev,
					const uint16_t meter_idx,
					bool *enabled,
					struct gpe_meter_cfg *cfg)
{
	uint16_t index = (uint16_t)meter_idx;
	struct tbm_token_bucket_meter_params tbmt;

	UNUSED_PARAM_DEV;

	if (index > ONU_GPE_MAX_TBM - 2)
		return GPE_STATUS_VALUE_RANGE_ERR;

	if (index & 1)
		return GPE_STATUS_VALUE_RANGE_ERR;

	cfg->index = meter_idx;

	/* read first meter */
	tbmt.tbid = index;
	tbm_meter_cfg_get(&tbmt);

	*enabled = tbmt.tbe ? true : false;
	cfg->cir = tbmt.rate;
	cfg->cbs = tbmt.mbs;

	/* read second meter */
	tbmt.tbid = index + 1;
	tbm_meter_cfg_get(&tbmt);

	*enabled = tbmt.tbe ? true : false;
	cfg->pir = tbmt.rate;
	cfg->pbs = tbmt.mbs;

	/* both meters have the same color awareness */
	cfg->color_aware = (tbmt.mod == 1 || tbmt.mod == 3) ? true : false;

	/* both meters have the same mode */
	cfg->mode = (tbmt.mod == 0 || tbmt.mod == 1) ?
					GPE_METER_RFC4115 : GPE_METER_RFC2698;

	return ONU_STATUS_OK;
}

enum onu_errorcode gpe_meter_create(struct onu_device *p_dev,
				    struct gpe_meter *param)
{
	enum onu_errorcode ret;
	uint16_t i;
	bool enabled;
	struct gpe_meter_cfg cfg;
	unsigned long flags = 0;

	onu_spin_lock_get(&meter_lock, &flags);

	for (i = 0; i < ONU_GPE_MAX_TBM; i+=2) {
		ret = meter_cfg_get(p_dev, i, &enabled, &cfg);
		if (ret != ONU_STATUS_OK)
			break;

		if (enabled)
			continue;

		/* set default values */
		cfg.cir = ONU_GPE_METER_CIR_DEF;
		cfg.pir = ONU_GPE_METER_PIR_DEF;
		cfg.cbs = ONU_GPE_METER_CBS_DEF;
		cfg.pbs = ONU_GPE_METER_PBS_DEF;
		cfg.mode = GPE_METER_RFC4115;

		ret = meter_cfg_set(p_dev, true, &cfg);
		param->index = i;
		break;
	}

	if (enabled && ret == ONU_STATUS_OK)
		ret = GPE_STATUS_NOT_AVAILABLE;

	onu_spin_lock_release(&meter_lock, flags);

	return ret;
}

enum onu_errorcode gpe_meter_delete(struct onu_device *p_dev,
				    const struct gpe_meter *param)
{
	enum onu_errorcode ret;
	bool enabled = false;
	struct gpe_meter_cfg cfg;
	unsigned long flags = 0;

	onu_spin_lock_get(&meter_lock, &flags);

	ret = meter_cfg_get(p_dev, param->index, &enabled, &cfg);
	if (ret == ONU_STATUS_OK) {
		if (!enabled) {
			ret = GPE_STATUS_NOT_AVAILABLE;
		} else {
			cfg.index = param->index;
			ret = meter_cfg_set(p_dev, false, &cfg);
		}
	}

	onu_spin_lock_release(&meter_lock, flags);

	return ret;
}

/** The gpe_meter_cfg_set function is used to configure two selected Token
    Bucket Meters (TBM) for CIR/CBS and PIR/PBS, respectively. If only a single
    meter shall be configured, both indexes are set to the same value.
*/
/** Hardware Programming Details
    The following hardware functions must be configured:
    - token_bucket_index_cir: select a free Token Bucket Meter (TBM) with
                              0 =< nTokenBucketMeterCirIndex <
                                  ONU_GPE_METER_TABLE_SIZE - 1
                            TBM, TBMTC.TBID = nTokenBucketMeterCirIndex
                                 TBMTC.SEL  = SELCFG
                                 TBMTC.RW   = WR

    - token_bucket_cir:      TBM, TBMTR0.EN  = EN
                                 TBMTR0.MOD = ingress_coloring_mode
                                 TBMTR0.MRE = max(ceil(log2(bTokenBucketCir*
                  ONU_GPE_IQM_CLOCK_RATE))-12,0)
                                 TBMTR0.MRM = ceil(bTokenBucketCir*
               ONU_GPE_IQM_CLOCK_RATE/(2**TBMTR0.MRE))

    - token_bucket_index_pir: if (token_bucket_index_cir ==
                     token_bucket_index_pir),
                            ignore the second configuration (PIR/PBS), else
                            select a free Token Bucket Meter (TBM) with
                            0 =< nTokenBucketMeterIndex <
                   ONU_GPE_METER_TABLE_SIZE - 1
                            TBM, TBMTC.TBID = nTokenBucketMeterPirIndex
                                 TBMTC.SEL  = SELCFG
                                 TBMTC.RW   = WR
                            If available, use token_bucket_index_pir =
                       token_bucket_index_cir + 1

    - token_bucket_pir:      TBM, TBMTR0.EN  = EN
                                 TBMTR0.MOD = ingress_coloring_mode
                                 TBMTR0.MRE = max(ceil(log2(bTokenBucketPir*
                  ONU_GPE_IQM_CLOCK_RATE))-12,0)
                                 TBMTR0.MRM = ceil(bTokenBucketPir*
               ONU_GPE_IQM_CLOCK_RATE/(2**TBMTR0.MRE))

    - token_bucket_cbs:      TBM, TBMTC.TBID = nTokenBucketMeterCirIndex
                                 TBMTC.SEL  = SELCFG
                                 TBMTC.RW   = WR
                                 TBMTR2.MBS = token_bucket_cbs

    - token_bucket_pbs:      TBM, TBMTC.TBID = nTokenBucketMeterPirIndex
                                 TBMTC.SEL  = SELCFG
                                 TBMTC.RW   = WR
                                 TBMTR2.MBS = token_bucket_pbs

    - mode:        TBM, TBMTC.TBID = nTokenBucketMeterCirIndex
    - color_aware:               TBMTC.SEL  = SELCFG
                                 TBMTC.RW   = WR
                                 TBMTR0.MOD = set the selected mode (see below)

                                 TBMTC.TBID = nTokenBucketMeterPirIndex
                                 TBMTC.SEL  = SELCFG
                                 TBMTC.RW   = WR
                                 TBMTR0.MOD = set the selected mode (see below)

       (mode == GPE_METER_RFC4115) && (color_aware == false): MOD = 0
       (mode == GPE_METER_RFC4115) && (color_aware == true) : MOD = 1
       (mode == GPE_METER_RFC2698) && (color_aware == false): MOD = 2
       (mode == GPE_METER_RFC2698) && (color_aware == true) : MOD = 3

    - egress_coloring_mode:

      The handling of the egress coloring mode depends on the meter
      position in the system (as defined by the OMCI MIB).

      Case 1: The Meter (Traffic Descriptor) is connected to a GEM port
              (GEM Port Network CTP)

      meter_position == GPE_METER_GEM_PORT

      Configure the egress coloring mode in the GEM Port upstream table with
        nTableId = ONU_GPE_US_GEM_PORT_TABLE_ID
        egress_color_marking = (uint8_t)egress_coloring_mode

      Case 2: The Meter (Traffic Descriptor) is connected to a bridge port
              (MAC Bridge Port Configuration data)

      meter_position == GPE_METER_BRIDGE_PORT

      Configure the egress coloring mode in the Bridge Port table with
        nTableId = ONU_GPE_BRIDGE_PORT_TABLE_ID
        egress_color_marking = (uint8_t)egress_coloring_mode

    - ingress_coloring_mode:
      The handling of the ingress coloring mode depends on the meter
      position in the system (as defined by the OMCI MIB).

      Case 1: The Meter (Traffic Descriptor) is connected to a GEM port
              (GEM Port Network CTP)

      meter_position == GPE_METER_GEM_PORT

      Configure the egress coloring mode in the GEM Port downstream table with
        nTableId = ONU_GPE_US_GEM_PORT_TABLE_ID
        ingress_color_marking = (uint8_t)ingress_coloring_mode
      \remark This is currently not supported by the GEM port downstream table

      Case 2: The Meter (Traffic Descriptor) is connected to a bridge port
              (MAC Bridge Port Configuration data)

      meter_position == GPE_METER_BRIDGE_PORT

      Configure the egress coloring mode in the Bridge Port table with
        nTableId = ONU_GPE_BRIDGE_PORT_TABLE_ID
        ingress_color_marking = (uint8_t)ingress_coloring_mode
*/
enum onu_errorcode gpe_meter_cfg_set(struct onu_device *p_dev,
				     const struct gpe_meter_cfg *param)
{
	enum onu_errorcode ret;
	bool enabled = false;
	struct gpe_meter_cfg cfg;
	unsigned long flags = 0;

	onu_spin_lock_get(&meter_lock, &flags);

	ret = meter_cfg_get(p_dev, param->index, &enabled, &cfg);
	if (ret == ONU_STATUS_OK) {
		if (!enabled) {
			ret = GPE_STATUS_NOT_AVAILABLE;
		} else {
			ret = meter_cfg_set(p_dev, true, param);
		}
	}

	onu_spin_lock_release(&meter_lock, flags);

	return ret;
}

/** The gpe_meter_cfg_get function is used to read back the configuration of
    two selected Token Bucket Meters (TBM).
*/
/** Hardware Programming Details
    \remark gpe_meter_cfg_get hardware programming details:

    See \ref gpe_meter_cfg. If only a single meter needs to be read,
    use the same index for CIR/CBS and PIR/PBS.
    The identical parameters are reported for both.
*/
enum onu_errorcode gpe_meter_cfg_get(struct onu_device *p_dev,
				     const struct gpe_meter *in,
				     struct gpe_meter_cfg *out)
{
	enum onu_errorcode ret;
	bool enabled = false;
	unsigned long flags = 0;

	onu_spin_lock_get(&meter_lock, &flags);

	ret = meter_cfg_get(p_dev, in->index, &enabled, out);
	if (!enabled && ret == ONU_STATUS_OK)
		ret = GPE_STATUS_NOT_AVAILABLE;

	onu_spin_lock_release(&meter_lock, flags);

	return ret;
}

enum onu_errorcode gpe_meter_status_get(struct onu_device *p_dev,
					const struct gpe_meter *in,
					struct gpe_meter_status *out)
{
	/** \todo implementation to be completed*/
	struct tbm_tbmt_entry tbmt;

	if (in->index > ONU_GPE_MAX_TBM - 1)
		return GPE_STATUS_VALUE_RANGE_ERR;

	tbmt.tbid = in->index;
	tbm_meter_get(&tbmt);

	out->index = in->index;
	out->tbc = tbmt.tbc;
	out->lts = tbmt.lts;
	out->ets = tbmt.ets;
	out->vts = tbmt.vts;

	return ONU_STATUS_OK;
}


/** The gpe_parser_cfg_set function is used to configure the ingress packet
    parser module.
*/
/** Hardware Programming Details
    The following parameters can be configured:
    - Ethertype to detect VLAN tags
      Up to four different Ethertypes can be configured (4 x 2 byte)
      - default: 0x8100, 0x88a8, 0x9100, 0x8100
    - Ethertype to detect Lantiq-specific "Special Tags" (1 x 2 byte)
      - default: 0x809b

    The GPE initialization sets the parser's default values. This can be done by
    calling this function. No need to call this function from the application
    code if the default setting is sufficient for the application.
*/
enum onu_errorcode gpe_parser_cfg_set(struct onu_device *p_dev,
				      const struct gpe_parser_cfg *param)
{
	enum onu_errorcode ret;
	struct gpe_table_entry entry;

	memset(&entry, 0x00, sizeof(entry));

	entry.id = ONU_GPE_CONSTANTS_TABLE_ID;
	entry.instance = ONU_GPE_ALL_PE_MASK;

	entry.index = ONU_GPE_CONST_TPID_AB;
	entry.data.constants.entry_data = param->tpid[1] << 16 | param->tpid[0];
	ret = gpe_table_entry_set(p_dev, &entry);
	if (ret != ONU_STATUS_OK)
		return ret;

	entry.index = ONU_GPE_CONST_TPID_CD;
	entry.data.constants.entry_data = param->tpid[3] << 16 | param->tpid[2];
	ret = gpe_table_entry_set(p_dev, &entry);
	if (ret != ONU_STATUS_OK)
		return ret;


	entry.id = ONU_GPE_ETHERTYPE_EXCEPTION_TABLE_ID;
	entry.instance = ONU_GPE_ALL_PE_MASK;
	entry.index = 0;
	entry.data.ethertype_exception.spec_ethertype =	param->special_tag &
									0xFFFF;
	ret = gpe_table_entry_set(p_dev, &entry);
	if (ret != ONU_STATUS_OK)
		return ret;

	return ONU_STATUS_OK;
}

/** The gpe_parser_cfg_get function is used to read back the configuration of
    the ingress packet parser.
*/
/** Hardware Programming Details
    \remark gpe_parser_cfg_get hardware programming details:

    See \ref gpe_parser_cfg_set.
*/
enum onu_errorcode gpe_parser_cfg_get(struct onu_device *p_dev,
				      struct gpe_parser_cfg *out)
{
	enum onu_errorcode ret;
	struct gpe_table entry_in;
	struct gpe_table_entry entry_out;

	entry_in.id = ONU_GPE_CONSTANTS_TABLE_ID;
	entry_in.instance = ONU_GPE_ALL_PE_MASK;

	entry_in.index = ONU_GPE_CONST_TPID_AB;
	ret = gpe_table_entry_get(p_dev, &entry_in, &entry_out);
	if (ret != ONU_STATUS_OK)
		return ret;

	out->tpid[0] = entry_out.data.constants.entry_data & 0x0000FFFF;
	out->tpid[1] = (entry_out.data.constants.entry_data & 0xFFFF0000) >> 16;

	entry_in.index = ONU_GPE_CONST_TPID_CD;
	ret = gpe_table_entry_get(p_dev, &entry_in, &entry_out);
	if (ret != ONU_STATUS_OK)
		return ret;

	out->tpid[2] = entry_out.data.constants.entry_data & 0x0000FFFF;
	out->tpid[3] = (entry_out.data.constants.entry_data & 0xFFFF0000) >> 16;

	entry_in.id = ONU_GPE_ETHERTYPE_EXCEPTION_TABLE_ID;
	entry_in.instance = ONU_GPE_ALL_PE_MASK;
	entry_in.index = 0;
	ret = gpe_table_entry_get(p_dev, &entry_in, &entry_out);
	if (ret != ONU_STATUS_OK)
		return ret;

	out->special_tag = entry_out.data.ethertype_exception.spec_ethertype;

	return ONU_STATUS_OK;
}

/** The gpe_ethertype_filter_cfg_set function is used to set the
    Ethertype filter table and its corresponding LAN port table
*/
enum onu_errorcode
gpe_ethertype_filter_cfg_set(struct onu_device *p_dev,
			     const struct gpe_ethertype_filter_cfg *param)
{
	enum onu_errorcode ret;
	struct onu_control *ctrl = p_dev->ctrl;
	struct gpe_table_entry entry;
	uint16_t ethcnt;

	if (param->num_valid_ethertypes > ONU_GPE_MAX_ETHFILT ||
	    param->ethertype_filter_pointer > ONU_GPE_MAX_ETHFILT)
		return GPE_STATUS_VALUE_RANGE_ERR;

	/* 1.) table entry get with idx on LAN port table */
	entry.id = ONU_GPE_LAN_PORT_TABLE_ID;
	entry.index = param->lanport_index;
	entry.instance = ONU_GPE_ALL_PE_MASK;
	ret = TABLE_GET(ctrl, &entry);

	if (ret)
		return ret;

	entry.data.lan_port.ethertype_filter_pointer =
				       param->ethertype_filter_pointer;
	entry.data.lan_port.ethertype_filter_mode =
				       param->whitelist_mode;
	entry.data.lan_port.ethertype_filter_enable =
				       param->num_valid_ethertypes == 0 ? 0 : 1;

	/* 2.) table entry set with modified values at idx on LAN port table */
	entry.id = ONU_GPE_LAN_PORT_TABLE_ID;
	entry.index = param->lanport_index;
	entry.instance = ONU_GPE_ALL_PE_MASK;
	ret = gpe_table_entry_set(p_dev, &entry);
	if (ret)
		return ret;

	/* 3.) perform multiple table entry set on Ethertype filter table
	       starting with index ethertype_filter_pointer and increment */
	for (ethcnt = 0; ethcnt < param->num_valid_ethertypes; ethcnt++) {

		/* write Ethertype filter table */
		entry.id = ONU_GPE_ETHERTYPE_FILTER_TABLE_ID;
		entry.data.ethertype.ethertype = param->ethertype[ethcnt];
		entry.data.ethertype.unused = 0;
		entry.data.ethertype.valid = 1; /* always valid */
		entry.data.ethertype.end = 0;

		if (ethcnt == param->num_valid_ethertypes-1)
			entry.data.ethertype.end = 1;

		entry.index = param->ethertype_filter_pointer + ethcnt;
		ret = gpe_table_entry_write(p_dev, &entry);

		if (ret || entry.result != COP_STATUS_SUCCESS)
			return ret;
	}

	return ONU_STATUS_OK;
}

/** The gpe_ethertype_filter_cfg_get function is used to get all entries
 	from the Ethertype filter table for its corresponding LAN port index
*/
enum onu_errorcode
gpe_ethertype_filter_cfg_get(struct onu_device *p_dev,
			     const struct gpe_ethertype_filter_index *in,
			     struct gpe_ethertype_filter_cfg *out)
{
	struct onu_control *ctrl = p_dev->ctrl;
	struct gpe_table_entry entry;
	enum onu_errorcode ret;
	uint16_t ethcnt;
	uint16_t valid_eth;
	uint32_t end, valid;
	uint16_t ethertype_filter_pointer;

	/* 1.) table entry get with idx on LAN port table table */
	entry.id = ONU_GPE_LAN_PORT_TABLE_ID;
	entry.index = in->lanport_index;
	entry.instance = ONU_GPE_ALL_PE_MASK;
	ret = TABLE_GET(ctrl, &entry);

	if (ret)
		return ret;

	out->lanport_index = in->lanport_index;
	out->whitelist_mode = entry.data.lan_port.ethertype_filter_mode;
	out->ethertype_filter_pointer =
				entry.data.lan_port.ethertype_filter_pointer;

	ethertype_filter_pointer = entry.data.lan_port.ethertype_filter_pointer;

	/* 2.) perform multiple table entry get on Ethertype filter table
	       and check for valid bits, stop at end bit */
	valid_eth = 0;
	for (ethcnt = 0; ethcnt < ONU_GPE_MAX_ETHFILT; ethcnt++) {

		entry.id = ONU_GPE_ETHERTYPE_FILTER_TABLE_ID;
		entry.index = ethertype_filter_pointer + ethcnt;
		ret = TABLE_READ(ctrl, &entry);

		if (ret || entry.result != COP_STATUS_SUCCESS)
			return ret;

		end = entry.data.ethertype.end;
		valid = entry.data.ethertype.valid;

		if (valid) {
			valid_eth++;
			out->ethertype[ethcnt] = entry.data.ethertype.ethertype;
		}
		if (end)
			break;
	}

	out->num_valid_ethertypes = valid_eth;

	return ONU_STATUS_OK;
}

/** The gpe_token_bucket_shaper_create function is used to attach a Token
    Bucket Shaper (TBS) to a scheduler input and enable it.
*/
enum onu_errorcode
gpe_token_bucket_shaper_create(struct onu_device *p_dev,
			       const struct gpe_token_bucket_shaper *param)
{
	struct tmu_token_bucket_shaper_params tbs;
	UNUSED_PARAM_DEV;

	if (param->index >= ONU_GPE_MAX_SHAPER)
		return GPE_STATUS_VALUE_RANGE_ERR;
	if (param->tbs_scheduler_block_input >= SCHEDULER_BLOCK_INPUT_ID_MAX)
		return GPE_STATUS_VALUE_RANGE_ERR;

	/* not allowed if TMU is enabled */
	if (tmu_is_enabled())
		return ONU_STATUS_OK;

	tmu_token_bucket_shaper_create(param->index,
				       param->tbs_scheduler_block_input);

	tbs.tbe0 = 1;
	tbs.tbe1 = 1;
	tbs.mod  = 0;

	tbs.pir  = ONU_GPE_TBS_PIR_DEF;
	tbs.pbs  = ONU_GPE_TBS_PBS_DEF;
	tbs.cir  = ONU_GPE_TBS_CIR_DEF;
	tbs.cbs  = ONU_GPE_TBS_CBS_DEF;

	tmu_token_bucket_shaper_cfg_set(param->index, &tbs);

	return ONU_STATUS_OK;
}

/** The gpe_token_bucket_shaper_delete function is used to remove a Token
    Bucket Shaper (TBS) from a scheduler input and disable it.
*/
enum onu_errorcode
gpe_token_bucket_shaper_delete(struct onu_device *p_dev,
			       const struct gpe_token_bucket_shaper *param)
{
	UNUSED_PARAM_DEV;

	if (param->index >= ONU_GPE_MAX_SHAPER)
		return GPE_STATUS_VALUE_RANGE_ERR;
	if (param->tbs_scheduler_block_input >= SCHEDULER_BLOCK_INPUT_ID_MAX)
		return GPE_STATUS_VALUE_RANGE_ERR;

	/* not allowed if TMU is enabled */
	if (tmu_is_enabled())
		return ONU_STATUS_OK;

	tmu_token_bucket_shaper_delete(param->index,
				       param->tbs_scheduler_block_input);

	return ONU_STATUS_OK;
}

/** The gpe_token_bucket_shaper_get function is used to read back the assignment
    of a Token Bucket Shaper (TBS) to a scheduler input.
*/
enum onu_errorcode
gpe_token_bucket_shaper_get(struct onu_device *p_dev,
			    const struct gpe_token_bucket_shaper_idx *in,
			    struct gpe_token_bucket_shaper *out)
{
	uint32_t sbin;
	UNUSED_PARAM_DEV;

	if (in->index >= ONU_GPE_MAX_SHAPER)
		return GPE_STATUS_VALUE_RANGE_ERR;

	tmu_token_bucket_shaper_link_get(in->index, &sbin);

	out->tbs_scheduler_block_input = sbin;
	out->index = in->index;

	return ONU_STATUS_OK;
}


/** The gpe_token_bucket_shaper_cfg_set function is used to configure a Token
    Bucket Scheduler (TBS) for CIR/CBS or PIR/PBS, respectively. If only a
    single shaper shall be configured, both indexes are set to the same value.
*/
enum onu_errorcode
gpe_token_bucket_shaper_cfg_set(struct onu_device *p_dev,
				const struct gpe_token_bucket_shaper_cfg *param)
{
	struct tmu_token_bucket_shaper_params tbs;
	uint32_t pir, cir, pbs;

	UNUSED_PARAM_DEV;

	if (param->index >= ONU_GPE_MAX_SHAPER)
		return GPE_STATUS_VALUE_RANGE_ERR;

	/* The default value 0 accepts the ONU's factory default policy */
	pir = param->pir == 0 ? ONU_GPE_TBS_PIR_DEF : param->pir;
	/* The default value 0 accepts the ONU's factory default policy */
	pbs = param->pbs == 0 ? ONU_GPE_TBS_PBS_DEF : param->pbs;

	/* Treat values < ONU_GPE_TBS_PIR_MIN as ONU_GPE_TBS_PIR_MIN */
	pir = pir < ONU_GPE_TBS_PIR_MIN ? ONU_GPE_TBS_PIR_MIN : pir;
	/* Treat values < ONU_GPE_TBS_CIR_MIN as ONU_GPE_TBS_CIR_MIN */
	cir = param->cir < ONU_GPE_TBS_CIR_MIN ? ONU_GPE_TBS_CIR_MIN : param->cir;

	tbs.tbe0 = param->enable;
	tbs.tbe1 = param->enable;
	tbs.mod  = param->mode;
	tbs.pir  = pir;
	tbs.pbs  = pbs;
	tbs.cir  = cir;
	tbs.cbs  = param->cbs;

	tmu_token_bucket_shaper_cfg_set(param->index, &tbs);

	return ONU_STATUS_OK;
}

/** The gpe_token_bucket_shaper_cfg_get function is used to read back the
    configuration of a Token Bucket Shaper (TBS).
*/
enum onu_errorcode
gpe_token_bucket_shaper_cfg_get(struct onu_device *p_dev,
				const struct gpe_token_bucket_shaper_idx *in,
				struct gpe_token_bucket_shaper_cfg *out)
{
	struct tmu_token_bucket_shaper_params tbs;

	UNUSED_PARAM_DEV;

	tmu_token_bucket_shaper_cfg_get(in->index, &tbs);

	out->index  = in->index;
	out->enable = tbs.tbe0 & tbs.tbe1;
	out->mode   = tbs.mod;
	out->pir    = tbs.pir;
	out->pbs    = tbs.pbs;
	out->cir    = tbs.cir;
	out->cbs    = tbs.cbs;

	return ONU_STATUS_OK;
}

/** The gpe_token_bucket_shaper_status_get function is used to read back the
    status variables of a Token Bucket Shaper (TBS).
*/
enum onu_errorcode
gpe_token_bucket_shaper_status_get(struct onu_device *p_dev,
				   const struct gpe_token_bucket_shaper_idx *in,
				   struct gpe_token_bucket_shaper_status *out)
{
	UNUSED_PARAM_DEV;

	out->index = in->index;
	out->pass0 = false;
	out->pass1 = false;
	out->src0 = 0;
	out->src1 = 0;
	out->tbc0 = 0;
	out->tbc1 = 0;
	out->col = 0;
	out->qosl = 0;
	out->ts_tacc = 0;

	return ONU_STATUS_NOT_IMPLEMENTED;
}

/** The gpe_shared_buffer_cfg_set function is used to configure the
    gpe shared segment buffer global thresholds for ingress and egress
    queuing.
*/
enum onu_errorcode
gpe_shared_buffer_cfg_set(struct onu_device *p_dev,
			  const struct gpe_shared_buffer_cfg *param)
{
	uint32_t iqmgoth;
	struct tmu_global_thr tmugoth;
	UNUSED_PARAM_DEV;

	if (param->iqm_global_segments_max >= ONU_GPE_BUFFER_SEGMENTS)
		return GPE_STATUS_VALUE_RANGE_ERR;
	if (param->tmu_global_segments_max >= ONU_GPE_BUFFER_SEGMENTS)
		return GPE_STATUS_VALUE_RANGE_ERR;
	if (param->tmu_global_segments_green >= ONU_GPE_BUFFER_SEGMENTS)
		return GPE_STATUS_VALUE_RANGE_ERR;
	if (param->tmu_global_segments_yellow >= ONU_GPE_BUFFER_SEGMENTS)
		return GPE_STATUS_VALUE_RANGE_ERR;
	if (param->tmu_global_segments_red >= ONU_GPE_BUFFER_SEGMENTS)
		return GPE_STATUS_VALUE_RANGE_ERR;

	iqmgoth		= param->iqm_global_segments_max;
	tmugoth.goth[0] = param->tmu_global_segments_max;
	tmugoth.goth[1] = param->tmu_global_segments_green;
	tmugoth.goth[2] = param->tmu_global_segments_yellow;
	tmugoth.goth[3] = param->tmu_global_segments_red;

	iqm_global_tail_drop_thr_set(iqmgoth);
	tmu_global_tail_drop_thr_set(&tmugoth);

	return ONU_STATUS_OK;
}

/** The gpe_shared_buffer_cfg_set function is used to read back the
    gpe shared segment buffer global thresholds for ingress and egress
    queuing.
*/
enum onu_errorcode gpe_shared_buffer_cfg_get(struct onu_device *p_dev,
					     struct gpe_shared_buffer_cfg *out)
{
	uint32_t iqmgoth;
	struct tmu_global_thr tmugoth;
	UNUSED_PARAM_DEV;

	iqm_global_tail_drop_thr_get(&iqmgoth);
	tmu_global_tail_drop_thr_get(&tmugoth);

	out->iqm_global_segments_max	= iqmgoth;
	out->tmu_global_segments_max	= tmugoth.goth[0];
	out->tmu_global_segments_green	= tmugoth.goth[1];
	out->tmu_global_segments_yellow = tmugoth.goth[2];
	out->tmu_global_segments_red	= tmugoth.goth[3];

	return ONU_STATUS_OK;
}

/** The gpe_omci_send function is used to send an OMCI control message to
    the OLT.
*/
enum onu_errorcode gpe_omci_send(struct onu_device *p_dev,
				 const struct gpe_omci_msg *param)
{
	enum onu_errorcode ret;
	struct onu_control *ctrl = p_dev->ctrl;
	struct ploam_context *ploam_ctx = &ctrl->ploam_ctx;

	if (ploam_ctx->curr_state != PLOAM_STATE_O5) {
		ONU_DEBUG_MSG
		    ("Skip OMCI upstream message (state %d instead state O5)",
		     ploam_ctx->curr_state);
		return ONU_STATUS_OK;
	}

	if (!onu_is_initialized())
		return ONU_STATUS_ERR;

	event_add(ctrl, ONU_EVENT_OMCI_SENT, param, param->length);

	ctrl->omci_upstream++;

	ret = ssb_equeue_write(ONU_GPE_QUEUE_INDEX_OMCI_HI_US, OMCI_GPIX,
			       GPE_PDU_TYPE_OMCI, param->length,
			       &param->message[0]);
	if (ret == -1) {
		ONU_DEBUG_ERR("ingress alloc failed %d", ret);
		return ONU_STATUS_ALLOC_ERR;
	}
	if (ret != 0) {
		ONU_DEBUG_ERR("ingress write failed %d", ret);
		return ONU_STATUS_ERR;
	}

	return ONU_STATUS_OK;
}

/** Maximum PPS Pulse Width in multiples of 100us */
#define ONU_TOD_PPS_PW_STEP_MAX	  (TOD_CFG_PW_MASK >> TOD_CFG_PW_OFFSET)
/** Maximum PPS Interrupt Delay in multiples of 100us */
#define ONU_TOD_PPS_INT_DELAY_MAX (TOD_CFG_INTDEL_MASK >> TOD_CFG_INTDEL_OFFSET)
/** Maximum Superframe counter value*/
#define ONU_TOD_SFRAME_CNT_MAX	  (TOD_SFCC_SFCC_MASK >> TOD_SFCC_SFCC_OFFSET)


/** The gpe_tod_init function is used to initialize the ToD serial interface.
*/
/** Hardware Programming Details
   pps_pulse_width:  --> SBS2.TOD.CFG.PW
   interrupt_delay: --> SBS2.TOD.CFG.INTDEL
*/
enum onu_errorcode gpe_tod_init(struct onu_device *p_dev,
			        const struct gpe_tod_init_data *param)
{
	struct onu_control *ctrl = (struct onu_control *)p_dev->ctrl;

	if (param->interrupt_delay > ONU_TOD_PPS_INT_DELAY_MAX ||
	    param->pps_pulse_width > ONU_TOD_PPS_PW_STEP_MAX)
		return GPE_STATUS_VALUE_RANGE_ERR;

	/* init low level part*/
	tod_init(param->interrupt_delay, param->pps_pulse_width);

	/* add IRQ to list*/
	onu_irq_add(ctrl, IRQ_TOD_FLAG);

	/** \todo activate TOD domain
	sys_gpon_hw_activate_or_reboot(ACT_TOD);*/

	return ONU_STATUS_OK;
}

/** The gpe_tod_sync_set function is used to update the Time of Day hardware
    clock synchronously.
*/
/** Hardware Programming Details
   multiframe_count:    --> SBS2.TOD.SFCC.SFCC(29:0), bits 31:30 = 0b00
   tod_seconds:         --> SBS2.TOD.RLDS.SEC(30:0), bit 15 = 0b0
                        --> SBS2.TOD.RLDNS.RLDNSHI(13:0), bits 14:15 = 0b00
   tod_extended_seconds: --> ignored until year 2106
   tod_nano_seconds:     --> multiply by 100000/31104 , then
                            SBS2.TOD.RLDNS.RLDNSLO(14:0), bit 15 = 0b0

*/
enum onu_errorcode gpe_tod_sync_set(struct onu_device *p_dev,
				    const struct gpe_tod_sync *param)
{
	struct tod_reload rld;
	struct tod_corr corr;

	UNUSED_PARAM_DEV;

	if (param->multiframe_count > ONU_TOD_SFRAME_CNT_MAX)
		return GPE_STATUS_VALUE_RANGE_ERR;

	corr.gtc_ds_delay = gtc_psync_delay_get();

	/* Get reload values*/
	tod_reload_get(param->tod_seconds, param->tod_nano_seconds,
		       &corr, &rld);

	/* disable the Free Running mode */
	tod_frm_enable(false);

	/* set superframe counter*/
	tod_sfcc_set(param->multiframe_count);
	/* set seconds in the reload register*/
	tod_rlds_set(rld.sec);
	/* set nano seconds in the reload register*/
	tod_rldns_set(rld.nsec_high, rld.nsec_low);

	return ONU_STATUS_OK;
}

/** The gpe_tod_get function is used to read back the Time of Day from the
    hardware clock.
*/
/** Hardware Programming Details
    \todo define programming details
    Note: The hardware clock's time is related to TAI, which differs from UTC
          by the number of leap seconds.

   sec  =
   min  =
   hour =
   mday =
   mon  =
   year =
   wday =
   yday =

   sec_tai =
*/
enum onu_errorcode gpe_tod_get(struct onu_device *p_dev, struct gpe_tod *param)
{
	struct onu_tm tm_time;

	UNUSED_PARAM_DEV;

	param->sec_tai = tod_pps_get();

	onu_time_to_tm(param->sec_tai, 0, &tm_time);

	param->sec = tm_time.tm_sec;
	param->min = tm_time.tm_min;
	param->hour = tm_time.tm_hour;
	param->mday = tm_time.tm_mday;
	param->mon = tm_time.tm_mon;
	param->year = tm_time.tm_year + 1900;
	param->wday = tm_time.tm_wday;
	param->yday = tm_time.tm_yday;

	return ONU_STATUS_OK;
}

/** The gpe_tod_sync_get function is used to read back the parameters of the
    latest call to gpe_tod_sync_set.
*/
/** Hardware Programming Details
    multiframe_count    = SBS2.TOD.SFCC.SFCC(29:0)
   tod_seconds         = SBS2.TOD.RLDS.SEC(30:0)
   tod_extended_seconds = SBS2.TOD.RLDNS.RLDNSHI(13:0)
   tod_nano_seconds     = 31104/100000 * SBS2.TOD.RLDNS.RLDNSLO(14:0)
*/
enum onu_errorcode gpe_tod_sync_get(struct onu_device *p_dev,
				    struct gpe_tod_sync *param)
{
	UNUSED_PARAM_DEV;

	param->multiframe_count = tod_sfcc_get();
	param->tod_seconds	= tod_rlds_get();
	param->tod_nano_seconds = tod_rldns2nsec(tod_rldns_get());
	/* Ignore extended seconds till the year 2106 :-) */
	param->tod_extended_seconds = 0;

	return ONU_STATUS_OK;
}

/** Hardware Programming Details:
    General counter handling:
    All hardware counters roll over if they reach the maximum count value. When
    reading the counter registers, the current value is checked with the most
    recent value and the difference is added to the logical counter.

    If the difference is positive, the increment is
    nIncrement = nHW_Counter(gem_port_index) - nHW_CounterKeep(gem_port_index).

    If the difference is negative, the counter has wrapped around and the
    increment is
    nIncrement = nCounterSize - nHW_CounterKeep(gem_port_index) +
       nHW_Counter(gem_port_index).

    \remark All hardware counters must be read regularly within one wrap-around
            period to avoid incorrect results.

    - gem_port_id: Selects one of the 12-bit GEM Port IDs. The index of the
                  selected Port ID (gem_port_index) must be looked up in a
                  table that holds the reference between assigned Port IDs
                  and the physical index (read from OCTRLG.GPT, GEM Port Table).

    The following hardware information is read:
    - nCntRxGEM_Frames:       ICTRLG.RXPCNT(gem_port_index)
    - nCntRxGEM_Blocks:       ICTRLG.RXBCNTH(gem_port_index)*2^32 +
               ICTRLG.RXBCNTL(gem_port_index),
                              divide by the GEM block length (nGEM_BlockLength)
    - nCntDiscardOMCI_Frames: ICTRLG.BADOMCI

    The byte counters RXBCNT are 64 bit wide, the byte counters TXBCNT are
    40 bit wide, all other hardware counters are 32 bit wide.
    If counters are wider than 32 bit, the hardware provides two registers.
    The register that contains the lower part must be read first.
*/
enum onu_errorcode gpe_gem_cnt_update(struct onu_control *ctrl,
				      const uint16_t index,
				      const uint64_t reset_mask,
				      const bool curr,
				      void *p_data)
{
	struct gpe_cnt_octrlg_gem_val tx_gem_cnt;
	struct gpe_cnt_ictrlg_gem_val rx_gem_cnt;
	struct gpe_cnt_gem_val *gem_data = p_data;
	uint64_t *dest, *threshold, *tca, *shadow;
	uint64_t *src;
	uint8_t i, k, ret = 0;

	if (index >= ONU_GPE_MAX_GPIX)
		return GPE_STATUS_VALUE_RANGE_ERR;

	if (curr)
		k = ctrl->current_counter ? 1 : 0;
	else
		k = ctrl->current_counter ? 0 : 1;

	if (curr) {
		dest = (uint64_t *) &ctrl->
				gem_cnt[k][ONU_COUNTER_ACC][index].tx;
		threshold = (uint64_t *) &ctrl->
				gem_cnt[0][ONU_COUNTER_THRESHOLD][index].tx;
		tca = (uint64_t *) &ctrl->
				gem_cnt[1][ONU_COUNTER_THRESHOLD][index].tx;
		shadow = (uint64_t *) &ctrl->
				gem_cnt[k][ONU_COUNTER_SHADOW][index].tx;
		src = octrlg_gem_counter_get(index, &tx_gem_cnt) != 0 ?
				shadow : (uint64_t *) &tx_gem_cnt;
		for (i = 0; i < sizeof(tx_gem_cnt) / sizeof(uint64_t); i++) {
			ret |= onu_counter_value_update(&dest[i], threshold[i],
							&tca[i], &shadow[i],
							src[i]);
		}

		dest = (uint64_t *) &ctrl->
				gem_cnt[k][ONU_COUNTER_ACC][index].rx;
		threshold = (uint64_t *) & ctrl->
				gem_cnt[0][ONU_COUNTER_THRESHOLD][index].rx;
		tca = (uint64_t *) &ctrl->
				gem_cnt[1][ONU_COUNTER_THRESHOLD][index].rx;
		shadow = (uint64_t *) &ctrl->
				gem_cnt[k][ONU_COUNTER_SHADOW][index].rx;
		src = ictrlg_gem_counter_get(index, &rx_gem_cnt) != 0 ?
				shadow : (uint64_t *) &rx_gem_cnt;
		for (i = 0; i < sizeof(rx_gem_cnt) / sizeof(uint64_t); i++) {
			ret |= onu_counter_value_update(&dest[i], threshold[i],
							&tca[i], &shadow[i],
							src[i]);
		}
		if (ret)
			event_add(ctrl, ONU_EVENT_GPE_TCA,
				  &index, sizeof(index));
	}
	if (p_data) {
		memcpy(gem_data,
		       &ctrl->gem_cnt[k][ONU_COUNTER_ACC][index],
		       sizeof(struct gpe_cnt_gem_val));
	}
	if (curr) {
		dest = (uint64_t *) &ctrl->gem_cnt[k][ONU_COUNTER_ACC][index];
		tca = (uint64_t *) &ctrl->
				       gem_cnt[1][ONU_COUNTER_THRESHOLD][index];
		for (i = 0; i < sizeof(struct gpe_cnt_gem_val) /
				sizeof(uint64_t); i++) {
			if (reset_mask & (1 << i)) {
				dest[i] = 0;
				tca[i] = 0;
			}
		}
	}

	return ret ? ONU_STATUS_TCA : ONU_STATUS_OK;
}

enum onu_errorcode gpe_bridge_cnt_update(struct onu_control *ctrl,
					 const uint16_t index,
					 const uint64_t reset_mask,
					 const bool curr,
					 void *p_data)
{
	struct gpe_cnt_bridge_val bridge_cnt;

	struct gpe_cnt_bridge_val *bridge_data = p_data;
	uint64_t *dest, *threshold, *tca, *shadow;
	uint64_t *src;
	uint8_t i, k, ret = 0;

	if (curr)
		k = ctrl->current_counter ? 1 : 0;
	else
		k = ctrl->current_counter ? 0 : 1;

	if (curr) {
		dest = (uint64_t *) &ctrl->
			bridge_cnt[k][ONU_COUNTER_ACC][index].
			learning_discard;
		threshold = (uint64_t *) &ctrl->
			bridge_cnt[0][ONU_COUNTER_THRESHOLD][index].
			learning_discard;
		tca = (uint64_t *) &ctrl->
			bridge_cnt[1][ONU_COUNTER_THRESHOLD][index].
			learning_discard;
		shadow = (uint64_t *) &ctrl->
			bridge_cnt[k][ONU_COUNTER_SHADOW][index].
			learning_discard;
		src = gpe_bridge_cnt_get(ctrl, index, &bridge_cnt)
							!= ONU_STATUS_OK ?
		      shadow : (uint64_t *) &bridge_cnt;
		for (i = 0; i < sizeof(bridge_cnt) / sizeof(uint64_t); i++) {
			ret |= onu_counter_value_update(&dest[i], threshold[i],
							&tca[i], &shadow[i],
							src[i]);
		}

		if (ret)
			event_add(ctrl, ONU_EVENT_BRIDGE_TCA,
				  &index, sizeof(index));
	}
	if (p_data) {
		memcpy(&bridge_data->learning_discard,
		       &ctrl->bridge_cnt[k][ONU_COUNTER_ACC][index].
		       learning_discard,
		       sizeof(bridge_cnt));
	}
	if (curr) {
		dest = (uint64_t *) &ctrl->
				bridge_cnt[k][ONU_COUNTER_ACC][index].
				learning_discard;
		tca = (uint64_t *) &ctrl->
				bridge_cnt[1][ONU_COUNTER_THRESHOLD][index].
				learning_discard;
		for (i = 0; i < sizeof(bridge_cnt) / sizeof(uint64_t); i++) {
			if (reset_mask & (1 << i)) {
				dest[i] = 0;
				tca[i] = 0;
			}
		}
	}

	return ret ? ONU_STATUS_TCA : ONU_STATUS_OK;
}

enum onu_errorcode gpe_bridge_port_cnt_update(struct onu_control *ctrl,
					 const uint16_t index,
					 const uint64_t reset_mask,
					 const bool curr,
					 void *p_data)
{
	struct gpe_cnt_bridge_port_val bridge_port_cnt;
	struct gpe_cnt_bridge_port_val *bridge_port_data = p_data;
	uint64_t *dest, *threshold, *tca, *shadow;
	uint64_t *src;
	uint8_t i, k, ret = 0;

	if (curr)
		k = ctrl->current_counter ? 1 : 0;
	else
		k = ctrl->current_counter ? 0 : 1;

	if (curr) {
		dest = (uint64_t *) &ctrl->
			bridge_port_cnt[k][ONU_COUNTER_ACC][index].
			learning_discard;
		threshold = (uint64_t *) &ctrl->
			bridge_port_cnt[0][ONU_COUNTER_THRESHOLD][index].
			learning_discard;
		tca = (uint64_t *) &ctrl->
			bridge_port_cnt[1][ONU_COUNTER_THRESHOLD][index].
			learning_discard;
		shadow = (uint64_t *) &ctrl->
			bridge_port_cnt[k][ONU_COUNTER_SHADOW][index].
			learning_discard;
		src = gpe_bridge_port_cnt_get(ctrl, index, &bridge_port_cnt)
							!= ONU_STATUS_OK ?
		      shadow : (uint64_t *) &bridge_port_cnt;
		for (i = 0; i < sizeof(bridge_port_cnt) / sizeof(uint64_t); i++) {
			ret |= onu_counter_value_update(&dest[i], threshold[i],
							&tca[i], &shadow[i],
							src[i]);
		}

		if (ret)
			event_add(ctrl, ONU_EVENT_BRIDGE_PORT_TCA,
				  &index, sizeof(index));
	}
	if (p_data) {
		memcpy(bridge_port_data,
		       &ctrl->bridge_port_cnt[k][ONU_COUNTER_ACC][index],
		       sizeof(*bridge_port_data));
	}
	if (curr) {
		dest = (uint64_t *) &ctrl->
				bridge_port_cnt[k][ONU_COUNTER_ACC][index].
				learning_discard;
		tca = (uint64_t *) &ctrl->
				bridge_port_cnt[1][ONU_COUNTER_THRESHOLD][index].
				learning_discard;
		for (i = 0; i < sizeof(bridge_port_cnt) / sizeof(uint64_t); i++) {
			if (reset_mask & (1 << i)) {
				dest[i] = 0;
				tca[i] = 0;
			}
		}
	}

	return ret ? ONU_STATUS_TCA : ONU_STATUS_OK;
}

/** The gpe_iqm_global_cfg_set function is used to configure global IQM
    parameters
*/
enum onu_errorcode
gpe_iqm_global_cfg_set(struct onu_device *p_dev,
		       const struct gpe_iqm_global_cfg *param)
{
	int i;
	struct iqm_wrr_cfg wrr;

	UNUSED_PARAM_DEV;

	iqm_global_tail_drop_thr_set(param->goth);

	wrr.per = param->wrrper;

	for (i = 0; i < 36; i++)
		wrr.wrrq[i] = param->wrrq[i];

	iqm_wrr_sched_cfg_set(&wrr);

	return ONU_STATUS_OK;
}

/** The gpe_iqm_global_cfg_get function is used to read back global
    IQM parameters
*/
enum onu_errorcode gpe_iqm_global_cfg_get(struct onu_device *p_dev,
					  struct gpe_iqm_global_cfg *param)
{
	int i;
	uint32_t goth;
	struct iqm_wrr_cfg wrr;

	UNUSED_PARAM_DEV;

	iqm_global_tail_drop_thr_get(&goth);
	iqm_wrr_sched_cfg_get(&wrr);

	param->goth   = goth;
	param->wrrper = wrr.per;

	for (i = 0; i < 36; i++)
		param->wrrq[i] = wrr.wrrq[i];

	return ONU_STATUS_OK;
}

/** The gpe_iqm_global_cfg_get function is used to read back global
    IQM status variables
*/
enum onu_errorcode
gpe_iqm_global_status_get(struct onu_device *p_dev,
			  struct gpe_iqm_global_status *param)
{
	uint32_t gocc;
	uint32_t gpdc;
	uint32_t sfree0;
	uint32_t sfree1;

	UNUSED_PARAM_DEV;

	iqm_global_occupancy_get(&gocc);
	iqm_global_discard_counter_get(&gpdc);
	iqm_sfree_get(&sfree0, &sfree1);

	param->gocc   = (uint16_t) gocc;
	param->gpdc   = gpdc;
	param->sfree0 = sfree0;
	param->sfree1 = sfree1;

	return ONU_STATUS_OK;
}

/** The gpe_tmu_global_cfg_get function is used to read back global
    TMU parameters
*/
enum onu_errorcode gpe_tmu_global_cfg_get(struct onu_device *p_dev,
					  struct gpe_tmu_global_cfg *param)
{
	uint32_t maxtb;
	uint32_t lfsr;
	uint32_t cp;
	uint32_t erd;
	uint32_t tacp;

	UNUSED_PARAM_DEV;
	tmu_max_token_bucket_get(&maxtb);
	tmu_random_number_get(&lfsr);
	tmu_crawler_period_get(&cp);
	tmu_enqueue_delay_get(&erd);
	tmu_tacc_period_get(&tacp);

	param->rps   = tmu_is_relog_sequential();
	param->dta   = tmu_is_token_accumulation_disabled();
	param->maxtb = (uint8_t) maxtb;
	param->lfsr  = (uint16_t)lfsr;
	param->cp    = (uint8_t) cp;
	param->erd   = (uint16_t)erd;
	param->tacp  = (uint8_t) tacp;

	return ONU_STATUS_OK;
}

/** The gpe_tmu_global_cfg_get function is used to read back global TMU status
    variables
*/
enum onu_errorcode
gpe_tmu_global_status_get(struct onu_device *p_dev,
			  struct gpe_tmu_global_status *param)
{
	uint32_t fpcr;
	uint32_t gocc;
	uint32_t gpdc[4];
	uint32_t qfill[8];
	uint32_t epf[3];
	uint32_t i;

	UNUSED_PARAM_DEV;

	tmu_free_pointer_counter_get(&fpcr);
	tmu_global_occupancy_get(&gocc);
	tmu_global_discard_counters_get(&gpdc[0]);
	tmu_equeue_fill_status_get(&qfill[0]);
	tmu_egress_port_fill_status_get(&epf[0]);

	param->fpcr = (uint16_t)fpcr;
	param->gocc = (uint16_t)gocc;
	for (i = 0; i < 4; i++)
		param->gpdc[i] = gpdc[i];
	for (i = 0; i < 8; i++)
		param->qfill[i] = qfill[i];
	for (i = 0; i < 3; i++)
		param->epf[i] = epf[i];

	return ONU_STATUS_OK;
}

/** The gpe_tmu_counter_get function is used to read the TMU-based counters
    within the GPE hardware module. Several groups of counters are provided,
    which count discarded (dropped) frames:
    - per egress queue (up to ONU_GPE_MAX_QUEUE - 1)
    - per egress port (up to ONU_GPE_MAX_TCONT*2 + ONU_GPE_MAX_ETH_UNI + 3)
    - per ingress queue (up to ONU_GPE_MAX_INGRESS_QUEUES - 1)

    The hardware counter is selected by the counter type and the counter index.
    All counters wrap around on overflow. The difference between the current
    counter reading and the most recent counter reading is added to the software
    counter value, if no wrap-around has happened (current reading >= last
    reading). If the counter has wrapped around (current reading < last reading),
    the maximum counter value is added to the current reading before calculating
    the difference.

    An error code is returned, if the given index value is out of range for the
    selected counter type (GPE_STATUS_VALUE_RANGE_ERR).
*/
/** Hardware Programming Details
     tmu_counter_type == GPE_TMU_COUNTER_EGRESS_QUEUE
      index  - PBM, QMTC.QID: Write the index of the queue to be checked.
                                 - PBM, QMTC.RWS: Activate a read access.
      dropped_frames         - PBM, QMT3.QDC0...3

     tmu_counter_type == GPE_TMU_COUNTER_INGRESS_QUEUE
        dropped_frames  - IQM, IQT3[n].QDC ([n] is the
                  Ingress Queue Index
                  (0 to ONU_GPE_MAX_INGRESS_QUEUES - 1)

     tmu_counter_type == GPE_TMU_COUNTER_TCONT
      Find the egress port that is assigned to the T-CONT index by checking
      EPN = OCTRLG.TCTABLE[index].REPN

      index - PBM, EPMTC.EPN: Write the egress port number to be checked.
                                - PBM, EPMTC.RWS: Activate a read access.
      dropped_frames        - PBM, EPMTR3.EPDC0...3

     tmu_counter_type == GPE_TMU_COUNTER_UNI
      Find the egress port that is assigned to the UNI index by checking
      EPN = OCTRLL[index].CFG.EPN

      index - PBM, EPMTC.EPN: Write the egress port number to be checked.
                                - PBM, EPMTC.RWS: Activate a read access.
      dropped_frames        - PBM, EPMTR3.EPDC0...3

     tmu_counter_type == GPE_TMU_COUNTER_VUNI
      Find the egress port that is assigned to the virtual UNI index by checking
      EPN = [index] + 68

      index - PBM, EPMTC.EPN: Write the egress port number to be checked.
                                - PBM, EPMTC.RWS: Activate a read access.
      dropped_frames        - PBM, EPMTR3.EPDC0...3
*/
enum onu_errorcode gpe_tmu_counter_get(struct onu_device *p_dev,
				       const struct gpe_cnt_tmu_sel *in,
				       struct gpe_cnt_tmu_val *out)
{
	uint32_t epn, pepn;
	bool eport_cnt = true;

	UNUSED_PARAM_DEV;

	out->cnt_type = in->cnt_type;
	out->index = in->index;

	switch (in->cnt_type) {
	case GPE_TMU_COUNTER_EGRESS_QUEUE:
		if (in->index >= ONU_GPE_MAX_QUEUE)
			return GPE_STATUS_VALUE_RANGE_ERR;
		eport_cnt = false;
		tmu_equeue_discard_counters_get((uint32_t) in->index,
						out->dropped_frames);
		break;
	case GPE_TMU_COUNTER_INGRESS_QUEUE:
		if (in->index >= ONU_GPE_MAX_INGRESS_QUEUES)
			return GPE_STATUS_VALUE_RANGE_ERR;
		eport_cnt = false;
		out->dropped_frames[0] =
			iqm_iqueue_discard_counter_get((uint32_t) in->index);
		break;
	case GPE_TMU_COUNTER_TCONT:
		if (in->index >= ONU_GPE_MAX_TCONT)
			return GPE_STATUS_VALUE_RANGE_ERR;
		octrlg_epn_get(in->index, &epn, &pepn);
		break;
	case GPE_TMU_COUNTER_UNI:
		if (in->index >= ONU_GPE_MAX_ETH_UNI)
			return GPE_STATUS_VALUE_RANGE_ERR;
		octrll_port_get((const uint16_t)in->index, &epn);
		break;
	case GPE_TMU_COUNTER_VUNI:
		if (in->index >= ONU_GPE_MAX_VUNI)
			return GPE_STATUS_VALUE_RANGE_ERR;
		epn = ONU_GPE_EPN_VUNI0 - in->index;
		break;
	default:
		return GPE_STATUS_VALUE_RANGE_ERR;
	}

	if (eport_cnt)
		tmu_eport_discard_counters_get((const uint32_t)epn,
						out->dropped_frames);

	return ONU_STATUS_OK;
}

/** The gpe_tmu_counter_reset function is used to reset the TMU-based
    counters.
*/

/** Hardware Programming Details
    The counter software variables are set to 0 for all TMU-related counters.
    The contents of all counters is read and kept as the counting reference.
    See \ref gpe_tmu_counter_get for more hardware programming details.
*/
enum onu_errorcode gpe_tmu_counter_reset(struct onu_device *p_dev,
					 const struct gpe_cnt_tmu_reset *param)
{
	UNUSED_PARAM_DEV;
	UNUSED_PARAM;
	return GPE_STATUS_NO_SUPPORT;
}

/** The gpe_egress_queue_cnt_get function is used to read the egress queue-based
    counters within the GPE hardware module. For each of the supported
    egress queues, an individual set of counters is provided.
*/

/** Hardware Programming Details:
    - egress_queue_index: Select one of the egress queues
                         (from 0 up to ONU_GPE_MAX_QUEUE-1).
    - egress_priority_queue_dropped_frames_green: Dropped frames of color
                       "green"
    - egress_priority_queue_dropped_frames_yellow: Dropped frames of color
                       "yellow"
    - egress_priority_queue_dropped_frames_red: Dropped frames of color
                       "red"
    - fill: Current filling status (bytes)
    - frames: Current filling status (frames)
    - fill_avg: Average filling status (bytes)

    Use the generic function \ref gpe_tmu_counter_get to read the queue
    counters.
*/
enum onu_errorcode gpe_egress_queue_cnt_get(struct onu_device *p_dev,
					    struct gpe_cnt_equeue_val *param)
{
	UNUSED_PARAM_DEV;
	memset(param, 0, sizeof(struct gpe_cnt_equeue_val));

	return ONU_STATUS_NOT_IMPLEMENTED;
}

/** The gpe_egress_queue_cnt_reset function is used to reset the egress queue
    based counters. The counters are reset commonly for all queues.
*/
/** Hardware Programming Details
    The counter software variables are set to 0 for all egress queue-related
    counters. The related hardware counters are read, the values are kept as
    reference.

    Use the generic function \ref gpe_tmu_counter_reset to clear the hardware
    counters.
*/
enum onu_errorcode
gpe_egress_queue_cnt_reset(struct onu_device *p_dev,
			   const struct gpe_cnt_equeue_reset *param)
{
	UNUSED_PARAM_DEV;
	UNUSED_PARAM;
	return ONU_STATUS_NOT_IMPLEMENTED;
}

/** The gpe_gem_counter_get function is used to read the Port ID-based counters
    within the GPE hardware module. For each of the supported Port IDs, an
    individual set of counters is provided.
*/
enum onu_errorcode gpe_gem_counter_get(struct onu_device *p_dev,
				       const struct gpe_gem_cnt_interval *in,
				       struct gpe_gem_counter *out)
{
	struct onu_control *ctrl = (struct onu_control *)p_dev->ctrl;

	if (in->gem_port_index >= ONU_GPE_MAX_GPIX) {
		memset(out, 0x00, sizeof(*out));
		return GPE_STATUS_VALUE_RANGE_ERR;
	}

	out->cnt_ctrl.gem_port_index = in->gem_port_index;
	out->cnt_ctrl.reset_mask = in->reset_mask;
	out->cnt_ctrl.curr = in->curr;

	onu_interval_counter_update(ctrl, in->gem_port_index, GEM_COUNTER,
				    (uint64_t)in->reset_mask, in->curr,
				    &(out->cnt_val));

	return ONU_STATUS_OK;
}

/** The gpe_gem_counter_threshold_get function is used to read the GEM-based
    counter thresholds.
*/
enum onu_errorcode
gpe_gem_counter_threshold_get(struct onu_device *p_dev,
			      const struct gem_port_index *in,
			      struct gpe_cnt_gem_val *out)
{
	struct onu_control *ctrl = (struct onu_control *)p_dev->ctrl;

	if (in->val >= ONU_GPE_MAX_GPIX) {
		memset(out, 0x00, sizeof(*out));
		return GPE_STATUS_VALUE_RANGE_ERR;
	}

	memcpy(out,
	       &ctrl->gem_cnt[0][ONU_COUNTER_THRESHOLD][in->val],
	       sizeof(struct gpe_cnt_gem_val));

	return ONU_STATUS_OK;
}

/** The gpe_gem_counter_threshold_get function is used to read the GEM-based
    counter thresholds.
*/
enum onu_errorcode gpe_gem_tca_get(struct onu_device *p_dev,
				   const struct gem_port_index *in,
				   struct gpe_gem_tca_val *out)
{
	struct onu_control *ctrl = (struct onu_control *)p_dev->ctrl;

	if (in->val >= ONU_GPE_MAX_GPIX) {
		memset(out, 0x00, sizeof(*out));
		return GPE_STATUS_VALUE_RANGE_ERR;
	}

	out->index.val = in->val;

	onu_locked_memcpy(&ctrl->cnt_lock,
			  &out->cnt_val,
			  &ctrl->gem_cnt[1][ONU_COUNTER_THRESHOLD][in->val],
			  sizeof(struct gpe_cnt_gem_val));

	return ONU_STATUS_OK;
}

/** The gpe_gem_counter_threshold_set function is used to write the GEM-based
    counter thresholds.
*/
enum onu_errorcode
gpe_gem_counter_threshold_set(struct onu_device *p_dev,
			      const struct gpe_cnt_gem_threshold *in)
{
	struct onu_control *ctrl = (struct onu_control *)p_dev->ctrl;

	if (in->gem_port_index >= ONU_GPE_MAX_GPIX)
		return GPE_STATUS_VALUE_RANGE_ERR;

	onu_locked_memcpy(&ctrl->cnt_lock,
	     &ctrl->gem_cnt[0][ONU_COUNTER_THRESHOLD][in->gem_port_index],
	     &in->threshold,
	     sizeof(struct gpe_cnt_gem_val));

	return ONU_STATUS_OK;
}

/** The gpe_gem_counter_reset function is used to reset the Port ID-based
    counters. The counters are reset commonly for all Port IDs.
*/
/** Hardware Programming Details:
    The counter software variables are set to 0 for all GEM-related counters.
    All hardware counters are read and the current value is stored as the new
    reference (nHW_CounterKeep).
*/
enum onu_errorcode
gpe_gem_counter_reset(struct onu_device *p_dev,
		      const struct gpe_gem_cnt_interval *param)
{
	struct onu_control *ctrl = (struct onu_control *)p_dev->ctrl;

	if (param->gem_port_index >= ONU_GPE_MAX_GPIX)
		return GPE_STATUS_VALUE_RANGE_ERR;

	onu_interval_counter_update(ctrl, param->gem_port_index, GEM_COUNTER,
				    (uint64_t)param->reset_mask, param->curr,
				    NULL);

	return ONU_STATUS_OK;
}

/** CRC-32 table */
static uint32_t crc32_i363_table[256] = {
	0x00000000L, 0x04c11db7L, 0x09823b6eL, 0x0d4326d9L,
	0x130476dcL, 0x17c56b6bL, 0x1a864db2L, 0x1e475005L,
	0x2608edb8L, 0x22c9f00fL, 0x2f8ad6d6L, 0x2b4bcb61L,
	0x350c9b64L, 0x31cd86d3L, 0x3c8ea00aL, 0x384fbdbdL,
	0x4c11db70L, 0x48d0c6c7L, 0x4593e01eL, 0x4152fda9L,
	0x5f15adacL, 0x5bd4b01bL, 0x569796c2L, 0x52568b75L,
	0x6a1936c8L, 0x6ed82b7fL, 0x639b0da6L, 0x675a1011L,
	0x791d4014L, 0x7ddc5da3L, 0x709f7b7aL, 0x745e66cdL,
	0x9823b6e0L, 0x9ce2ab57L, 0x91a18d8eL, 0x95609039L,
	0x8b27c03cL, 0x8fe6dd8bL, 0x82a5fb52L, 0x8664e6e5L,
	0xbe2b5b58L, 0xbaea46efL, 0xb7a96036L, 0xb3687d81L,
	0xad2f2d84L, 0xa9ee3033L, 0xa4ad16eaL, 0xa06c0b5dL,
	0xd4326d90L, 0xd0f37027L, 0xddb056feL, 0xd9714b49L,
	0xc7361b4cL, 0xc3f706fbL, 0xceb42022L, 0xca753d95L,
	0xf23a8028L, 0xf6fb9d9fL, 0xfbb8bb46L, 0xff79a6f1L,
	0xe13ef6f4L, 0xe5ffeb43L, 0xe8bccd9aL, 0xec7dd02dL,
	0x34867077L, 0x30476dc0L, 0x3d044b19L, 0x39c556aeL,
	0x278206abL, 0x23431b1cL, 0x2e003dc5L, 0x2ac12072L,
	0x128e9dcfL, 0x164f8078L, 0x1b0ca6a1L, 0x1fcdbb16L,
	0x018aeb13L, 0x054bf6a4L, 0x0808d07dL, 0x0cc9cdcaL,
	0x7897ab07L, 0x7c56b6b0L, 0x71159069L, 0x75d48ddeL,
	0x6b93dddbL, 0x6f52c06cL, 0x6211e6b5L, 0x66d0fb02L,
	0x5e9f46bfL, 0x5a5e5b08L, 0x571d7dd1L, 0x53dc6066L,
	0x4d9b3063L, 0x495a2dd4L, 0x44190b0dL, 0x40d816baL,
	0xaca5c697L, 0xa864db20L, 0xa527fdf9L, 0xa1e6e04eL,
	0xbfa1b04bL, 0xbb60adfcL, 0xb6238b25L, 0xb2e29692L,
	0x8aad2b2fL, 0x8e6c3698L, 0x832f1041L, 0x87ee0df6L,
	0x99a95df3L, 0x9d684044L, 0x902b669dL, 0x94ea7b2aL,
	0xe0b41de7L, 0xe4750050L, 0xe9362689L, 0xedf73b3eL,
	0xf3b06b3bL, 0xf771768cL, 0xfa325055L, 0xfef34de2L,
	0xc6bcf05fL, 0xc27dede8L, 0xcf3ecb31L, 0xcbffd686L,
	0xd5b88683L, 0xd1799b34L, 0xdc3abdedL, 0xd8fba05aL,
	0x690ce0eeL, 0x6dcdfd59L, 0x608edb80L, 0x644fc637L,
	0x7a089632L, 0x7ec98b85L, 0x738aad5cL, 0x774bb0ebL,
	0x4f040d56L, 0x4bc510e1L, 0x46863638L, 0x42472b8fL,
	0x5c007b8aL, 0x58c1663dL, 0x558240e4L, 0x51435d53L,
	0x251d3b9eL, 0x21dc2629L, 0x2c9f00f0L, 0x285e1d47L,
	0x36194d42L, 0x32d850f5L, 0x3f9b762cL, 0x3b5a6b9bL,
	0x0315d626L, 0x07d4cb91L, 0x0a97ed48L, 0x0e56f0ffL,
	0x1011a0faL, 0x14d0bd4dL, 0x19939b94L, 0x1d528623L,
	0xf12f560eL, 0xf5ee4bb9L, 0xf8ad6d60L, 0xfc6c70d7L,
	0xe22b20d2L, 0xe6ea3d65L, 0xeba91bbcL, 0xef68060bL,
	0xd727bbb6L, 0xd3e6a601L, 0xdea580d8L, 0xda649d6fL,
	0xc423cd6aL, 0xc0e2d0ddL, 0xcda1f604L, 0xc960ebb3L,
	0xbd3e8d7eL, 0xb9ff90c9L, 0xb4bcb610L, 0xb07daba7L,
	0xae3afba2L, 0xaafbe615L, 0xa7b8c0ccL, 0xa379dd7bL,
	0x9b3660c6L, 0x9ff77d71L, 0x92b45ba8L, 0x9675461fL,
	0x8832161aL, 0x8cf30badL, 0x81b02d74L, 0x857130c3L,
	0x5d8a9099L, 0x594b8d2eL, 0x5408abf7L, 0x50c9b640L,
	0x4e8ee645L, 0x4a4ffbf2L, 0x470cdd2bL, 0x43cdc09cL,
	0x7b827d21L, 0x7f436096L, 0x7200464fL, 0x76c15bf8L,
	0x68860bfdL, 0x6c47164aL, 0x61043093L, 0x65c52d24L,
	0x119b4be9L, 0x155a565eL, 0x18197087L, 0x1cd86d30L,
	0x029f3d35L, 0x065e2082L, 0x0b1d065bL, 0x0fdc1becL,
	0x3793a651L, 0x3352bbe6L, 0x3e119d3fL, 0x3ad08088L,
	0x2497d08dL, 0x2056cd3aL, 0x2d15ebe3L, 0x29d4f654L,
	0xc5a92679L, 0xc1683bceL, 0xcc2b1d17L, 0xc8ea00a0L,
	0xd6ad50a5L, 0xd26c4d12L, 0xdf2f6bcbL, 0xdbee767cL,
	0xe3a1cbc1L, 0xe760d676L, 0xea23f0afL, 0xeee2ed18L,
	0xf0a5bd1dL, 0xf464a0aaL, 0xf9278673L, 0xfde69bc4L,
	0x89b8fd09L, 0x8d79e0beL, 0x803ac667L, 0x84fbdbd0L,
	0x9abc8bd5L, 0x9e7d9662L, 0x933eb0bbL, 0x97ffad0cL,
	0xafb010b1L, 0xab710d06L, 0xa6322bdfL, 0xa2f33668L,
	0xbcb4666dL, 0xb8757bdaL, 0xb5365d03L, 0xb1f740b4L
};

/** Count CRC-32 as defined in ITU-T I.363.5

   \param data Data pointer
   \param data_size Size of data in bytes

   \return CRC-32
*/
static inline uint32_t crc32_i363_calc(const uint8_t *data, size_t data_size)
{
	uint32_t crc;
	unsigned int i;

	crc = 0xffffffff;

	for (i = 0; i < data_size; i++)
		crc = (crc << 8) ^ crc32_i363_table[((crc >> 24) ^ data[i]) &
			0xff];

	return crc ^ 0xffffffff;
}

STATIC int omci_read(struct onu_control *ctrl, struct onu_pdu_info *info)
{
	int ret;
	uint32_t rx_crc;
	uint32_t crc;
	uint32_t off;

	if (info->len >= ONU_GPE_DS_BUF_SIZE) {
		ONU_DEBUG_ERR("packet length %d exceed buff length %d", info->len, ONU_GPE_DS_BUF_SIZE);
		return -1;
	}

	if(is_falcon_chip_a2x())
		off = 0;
	else
		off = 4;

	ret = ssb_ingress_data_read(info,
				    &ctrl->ds_buffer[off]);
	if (ret != 0) {
		ONU_DEBUG_ERR("ingress data failed %d", ret);
		return -1;
	}

	if(is_falcon_chip_a1x()) {
		memcpy(&rx_crc, &ctrl->ds_buffer[info->len], 4);

		crc = crc32_i363_calc(&ctrl->ds_buffer[4], info->len - 4);
		if (crc != rx_crc) {
			ONU_DEBUG_ERR("OMCI CRC error");
			ctrl->omci_downstream_dropped++;
			return ONU_STATUS_ERR;
		}
		memcpy(&ctrl->ds_buffer[0], &info->len, 4);
		event_add(ctrl, ONU_EVENT_OMCI_RECEIVE, &ctrl->ds_buffer[0],
			  info->len + 4);
	} else {
		memcpy(&ctrl->ds_buffer[0], &info->len, 4);
		event_add(ctrl, ONU_EVENT_OMCI_RECEIVE, &ctrl->ds_buffer[0],
			  info->len);
	}

	ctrl->omci_downstream++;

	return 0;
}

/**
   GPE OMCI interrupt handler

   \param ctrl - device control

   \return ONU_STATUS_OK if command was successfully handled
   \return ONU_STATUS_ERR on error

*/
int onu_gpe_omci_handle(struct onu_control *ctrl)
{
	int ret, i;
	struct onu_pdu_info info;

	ret = link_fifo_read(1, &ctrl->link_fifo_pos,
						   ONU_GPE_LINK_BUF_SIZE, &ctrl->link_fifo_data[0]);
	if (ret == 0) {
		link_info_read(&ctrl->link_fifo_data[0], &info);
		omci_read(ctrl, &info);
	} else if (ret < -1) {
		for(i=0;i<ONU_GPE_LINK_BUF_SIZE;i++) {
			ONU_DEBUG_ERR("[%0d] 0x%x", i, ctrl->link_fifo_data[i]);
		}
	}
	link_data_request(1);

	return ONU_STATUS_OK;
}

/**
   Handle TMU interrupt for the CPU egress ports

   \param ctrl device control
   \param irnicr Interrupt capture register value

   \return ONU_STATUS_OK if command was successfully handled
   \return ONU_STATUS_ERR on error

*/
int onu_gpe_egress_cpu_port_handle(struct onu_control *ctrl,
				   const uint32_t irnicr)
{
	int port;
	uint32_t mask, exc_hdr_len;
	int netdev_port;
	onu_net_rx_cb_t cb = NULL;
	void *netdev_handle;
	onu_net_buf_alloc_t net_buf_get = ctrl->net_dev.onu_net_buf_alloc;
	struct net_buf net_buf;
	struct onu_pdu_info info;
	union u_onu_exception_pkt_hdr *exc_hdr;

	mask = TMU_IRNCR_EPFC0;

	for (port = 0; port < ONU_GPE_MAX_EGRESS_CPU_PORT; port++) {
		if ((irnicr & mask) == 0) {
			mask <<= 1;
			continue;
		}

		mask <<= 1;
		/* get pdu info*/
		if (net_pdu_info_get((uint8_t)port, &info) < 0)
			continue;

		if (net_buf_get) {
			if (net_buf_get(info.len, &net_buf) != 0) {
				/* just read & discard the data */
				net_pdu_read(&info, NULL);
				continue;
			} else {
				net_pdu_read(&info, net_buf.data);
			}
		} else {
			/* just read & discard the data */
			net_pdu_read(&info, NULL);
			continue;
		}

		if (port == 0) {
			netdev_port = ONU_NET_NETDEV_WAN_PORT;
		} else if (port == 1) {
			exc_hdr = (union u_onu_exception_pkt_hdr *)net_buf.data;

			netdev_port = net_port_get(exc_hdr->ext.lan_port_idx);
			if (netdev_port < 0)
				continue;

			exc_hdr_len = exc_hdr->ext.ext_bytes ?
				sizeof(*exc_hdr) :
				sizeof(*exc_hdr) - sizeof(exc_hdr->raw.e);

			/* remove exception header*/
			memmove(net_buf.data, net_buf.data + exc_hdr_len,
				net_buf.len - exc_hdr_len);
		} else if (port == 2) {
			netdev_port = ONU_NET_NETDEV_EXC_PORT;
		} else {
			continue;
		}

		cb = ctrl->net_cb_list[netdev_port].cb[NET_CB_RX];
		netdev_handle = ctrl->net_cb_list[netdev_port].net_dev;

		if (cb)
			cb(netdev_handle, &net_buf);
	}

	return ONU_STATUS_OK;
}

#if defined(INCLUDE_SCE_DEBUG)
enum onu_errorcode sce_break_set(struct onu_device *p_dev,
				 const struct sce_break_point *param)
{
	enum vm vm = (enum vm)param->tid;

	UNUSED_PARAM_DEV;

	if (vm > VM52)
		return GPE_STATUS_VALUE_RANGE_ERR;

	return sce_fw_breakpoint_set(vm, param->addr);
}

/** For CLI usage only */
enum onu_errorcode sce_break_autocheck_enable(struct onu_device *p_dev,
					      const bool enable)
{
	struct onu_control *ctrl = p_dev->ctrl;

	if (enable)
		onu_irq_add(ctrl, IRQ_CONFIG_BREAK_FLAG);
	else
		onu_irq_remove(ctrl, IRQ_CONFIG_BREAK_FLAG);

	return ONU_STATUS_OK;
}

enum onu_errorcode sce_break_get(struct onu_device *p_dev,
				 const struct sce_break_index *in,
				 struct sce_break_point *out)
{
	enum vm vm = (enum vm)in->tid;

	UNUSED_PARAM_DEV;

	if (vm > VM52)
		return GPE_STATUS_VALUE_RANGE_ERR;

	out->tid = in->tid;
	return sce_fw_breakpoint_get(vm, in->idx, &out->addr);
}

enum onu_errorcode sce_break_remove(struct onu_device *p_dev,
				    const struct sce_break_point *param)
{
	enum vm vm = (enum vm)param->tid;

	UNUSED_PARAM_DEV;

	if (vm > VM52)
		return GPE_STATUS_VALUE_RANGE_ERR;

	return sce_fw_breakpoint_remove(param->tid, param->addr);
}

enum onu_errorcode sce_break(struct onu_device *p_dev,
			     const struct sce_thread *in,
			     struct sce_break_info *out)
{
	int ret;
	enum vm vm = (enum vm)in->tid;

	UNUSED_PARAM_DEV;

	if (vm > VM52)
		return GPE_STATUS_VALUE_RANGE_ERR;

	ret = sce_fw_pe_break(1 << vm);
	if (ret == 0)
		ret = sce_fw_pe_pc_get(vm, &out->addr);
	else
		out->addr = 0;

	return ret == 0 ? ONU_STATUS_OK : ONU_STATUS_ERR;
}

enum onu_errorcode sce_single_step(struct onu_device *p_dev,
				   const struct sce_thread *in,
				   struct sce_break_info *out)
{
	int ret;
	enum vm vm = (enum vm)in->tid;

	UNUSED_PARAM_DEV;

	if (vm > VM52)
		return GPE_STATUS_VALUE_RANGE_ERR;

	ret = sce_fw_pe_single_step(vm);
	if (ret == 0)
		ret = sce_fw_pe_pc_get(vm, &out->addr);
	else
		out->addr = 0;

	return ret == 0 ? ONU_STATUS_OK : ONU_STATUS_ERR;
}

enum onu_errorcode sce_run(struct onu_device *p_dev,
			   const struct sce_thread *param)
{
	enum vm vm = (enum vm)param->tid;

	UNUSED_PARAM_DEV;

	if (vm > VM52)
		return GPE_STATUS_VALUE_RANGE_ERR;

	sce_fw_pe_run (1 << vm);

	return ONU_STATUS_OK;
}

enum onu_errorcode sce_restart_vm(struct onu_device *p_dev,
				  const struct sce_restart_cfg *param)
{
	struct onu_control *ctrl = p_dev->ctrl;
	struct sce_download_cfg download_cfg;
	uint8_t pe_idx;

	if (param->pid >= ctrl->num_pe && param->pid != 0xFF)
		return GPE_STATUS_VALUE_RANGE_ERR;

	pe_idx = param->pid != 0xFF ? param->pid : 0;

	memcpy(download_cfg.fw_name, ctrl->pe_fw[pe_idx].fw_name,
		ONU_PE_FIRMWARE_NAME_MAX);
	download_cfg.pid = param->pid;

	return gpe_sce_download(p_dev, &download_cfg);
}

enum onu_errorcode sce_run_mask(struct onu_device *p_dev,
				const struct sce_thread_mask *param)
{
	UNUSED_PARAM_DEV;

	sce_fw_pe_run(param->mask);

	return ONU_STATUS_OK;
}

enum onu_errorcode sce_break_mask(struct onu_device *p_dev,
				  const struct sce_thread_mask *param)
{
	int ret;
	UNUSED_PARAM_DEV;

	ret = sce_fw_pe_break(param->mask);

	return ret == 0 ? ONU_STATUS_OK : ONU_STATUS_ERR;
}

enum onu_errorcode sce_status_get(struct onu_device *p_dev,
				  struct sce_status *param)
{
	int ret;

	UNUSED_PARAM_DEV;

	ret = sce_fw_status_get(&param->tstat0,
				&param->terr,
				&param->tctrl0,
				&param->tdebug0,
				&param->bctrl0,
				&param->bstat0,
				&param->bdis0);

	return ret == 0 ? ONU_STATUS_OK : ONU_STATUS_ERR;
}

enum onu_errorcode sce_reg_set(struct onu_device *p_dev,
			       const struct sce_register_val *param)
{
	int ret;

	UNUSED_PARAM_DEV;

	ret = sce_fw_pe_reg_set(param->tid, param->reg, param->val);

	return ret == 0 ? ONU_STATUS_OK : ONU_STATUS_ERR;
}

enum onu_errorcode sce_reg_get(struct onu_device *p_dev,
			       const struct sce_register *in,
			       struct sce_register_val *out)
{
	int ret;
	enum vm vm = (enum vm)in->tid;

	UNUSED_PARAM_DEV;

	if (vm > VM52)
		return GPE_STATUS_VALUE_RANGE_ERR;

	out->tid = in->tid;
	out->reg = in->reg;
	ret = sce_fw_pe_reg_get(vm, in->reg, &out->val);

	return ret == 0 ? ONU_STATUS_OK : ONU_STATUS_ERR;
}

enum onu_errorcode sce_mem_set(struct onu_device *p_dev,
			       const struct sce_memory_val *param)
{
	int ret;
	enum vm vm = (enum vm)param->tid;

	UNUSED_PARAM_DEV;

	if (vm > VM52)
		return GPE_STATUS_VALUE_RANGE_ERR;

	ret = sce_fw_pe_memset(vm, param->addr, param->val);

	return ret == 0 ? ONU_STATUS_OK : ONU_STATUS_ERR;
}

enum onu_errorcode sce_mem_get(struct onu_device *p_dev,
			       const struct sce_memory *in,
			       struct sce_memory_val *out)
{
	int ret;
	enum vm vm = (enum vm)in->tid;

	UNUSED_PARAM_DEV;

	if (vm > VM52)
		return GPE_STATUS_VALUE_RANGE_ERR;

	out->tid = in->tid;
	out->addr = in->addr;
	ret = sce_fw_pe_memget(vm, in->addr, &out->val);

	return ret == 0 ? ONU_STATUS_OK : ONU_STATUS_ERR;
}

enum onu_errorcode sce_break_check(struct onu_device *p_dev,
				   struct sce_thread_mask *out)
{
	int ret;

	UNUSED_PARAM_DEV;

	ret = sce_fw_pe_break_check(&out->mask);
	return ret == 0 ? ONU_STATUS_OK : ONU_STATUS_ERR;
}
#endif /* defined(INCLUDE_SCE_DEBUG)*/

enum onu_errorcode gpe_cop_download(struct onu_device *p_dev,
				    const struct cop_download_cfg *param)
{
	struct onu_control *ctrl = p_dev->ctrl;
	tse_loader_t loader;
	uint32_t label_idx;
	uint32_t cop_label_idx;
	char names_buf[ONU_GPE_COP_LABEL_MAX * ONU_GPE_COP_LABEL_STR_SIZE_MAX];

	/* reboot and activate */
	sys_gpe_hw_activate_or_reboot(SYS_GPE_ACTS_COP0 << param->cop_id);

	if (onu_microcode_load(ctrl, &param->mc_name[0]) != 0)
		return ONU_STATUS_FW_LOAD_ERR;

	loader.tse     = param->cop_id;
	loader.pbuffer = mc_version_string[param->cop_id];
	loader.NamesBufLen = sizeof(names_buf);
	loader.names_buffer = &names_buf[0];
	loader.BufLen = sizeof(names_buf);
	loader.image  = (char *)&ctrl->cop_microcode_bin[0];
	loader.image_len = ctrl->cop_microcode_len;
	loader.tse_if  = &(tse_interface[0]);
	loader.data_init = 0;
	if (tse_load(&loader) > 0)
		return COP_INIT_ERR;

	/* remap the physical address of microcode function pointers to
	   logical IDs, new labels will not be updated! */
	cop_label_idx = 0;
	label_idx = 0;
	while (tse_interface[cop_label_idx].id != 0 ||
		   label_idx == IF_LABEL_MAX) {

		if (strcmp(labelmapping[tse_interface[label_idx].id].label_name,
		           tse_interface[cop_label_idx].name) == 0) {
			labelmapping[tse_interface[label_idx].id].func_addr =
					tse_interface[cop_label_idx].addr >> 1;
			cop_label_idx++;
		}
		label_idx++;
	}

	return ONU_STATUS_OK;
}

enum onu_errorcode gpe_sce_version_get(struct onu_device *p_dev,
				       const struct sce_pe_index *in,
				       struct sce_version *out)
{
	struct gpe_table_entry entry;
	enum onu_errorcode ret;
	struct onu_control *ctrl = p_dev->ctrl;
	uint32_t i, tmp;

	entry.id = ONU_GPE_STATUS_TABLE_ID;
	entry.instance = ONU_GPE_ALL_PE_MASK;
	entry.index = ONU_GPE_STATUS_VERS;
	out->pid = in->pid;
	ret = gpe_table_entry_intresp(ctrl, &entry, ONU_GPE_COP_READ);
	if (ret != 0)
		return ret;

	tmp = entry.data.status.entry_data;
	for (i = 0; i < 4; i++)
		out->data[3-i] = (uint8_t)(tmp >> (8*i));

	return ONU_STATUS_OK;
}

enum onu_errorcode gpe_sce_download(struct onu_device *p_dev,
				    const struct sce_download_cfg *param)
{
	int ret = 0;
	struct onu_control *ctrl = p_dev->ctrl;
	struct sce_fw_init fw_init;
	struct onu_fw pe_fw;
	uint8_t idx, start, stop;

	if (!ctrl->num_pe)
		return GPE_STATUS_NOT_AVAILABLE;
	if (ctrl->num_pe > ONU_GPE_NUMBER_OF_PE_MAX)
		return GPE_STATUS_VALUE_RANGE_ERR;

	if (param->pid == 0xFF) {
		start = 0;
		stop = ctrl->num_pe - 1;
	} else {
		if (param->pid >= ctrl->num_pe)
			return GPE_STATUS_VALUE_RANGE_ERR;
		start = stop = param->pid;
	}

	memset(&pe_fw, 0, sizeof(pe_fw));

	ret = onu_pe_fw_load(&param->fw_name[0], &pe_fw);
	if (ret == -3) {
		ONU_DEBUG_ERR("PE fw %s request failed", &param->fw_name[0]);
		return ONU_STATUS_FW_REQUEST_ERR;
	} else if (ret != 0) {
		ONU_DEBUG_ERR("PE fw %s load failed", &param->fw_name[0]);
		return ONU_STATUS_FW_LOAD_ERR;
	}

	for (idx = start; idx <= stop; idx++) {
		onu_pe_fw_info_release(&ctrl->pe_fw[idx]);

		ret = onu_pe_fw_info_load(&pe_fw, &ctrl->pe_fw[idx]);
		if (ret != 0)
			break;
	}

	if (ret == 0) {
		idx -= 1;
		if (ONU_FW_VERSION(ctrl, 0) < ONU_FW_VERSION_MIN)
			ONU_DEBUG_ERR("ERR (ignored): Minimum required "
				      "PE-Firwmare is %d.%d.%d.%d",
						ONU_VER_FW_MIN_MAJOR,
						ONU_VER_FW_MIN_MINOR,
						ONU_VER_FW_MIN_PATCH,
						ONU_VER_FW_MIN_INTERN);

		fw_init.code.pe_index = param->pid;
		fw_init.code.data = (uint32_t *)(pe_fw.bin + PE_FW_HEADER_SIZE +
						 ctrl->pe_fw[idx].opt_hdr_len);

		fw_init.code.len = pe_fw.len - PE_FW_HEADER_SIZE -
						ctrl->pe_fw[idx].opt_hdr_len;
		fw_init.data.pe_index = param->pid;
		fw_init.data.data = NULL;
		fw_init.data.len = 0;

		ret = sce_fw_init(&fw_init, ctrl->num_pe);

		if (ret == 0)
			ONU_DEBUG_ERR("PE[%u] firmware loaded v%u.%u.%u.%u",
						param->pid,
						ctrl->pe_fw[idx].ver.major,
						ctrl->pe_fw[idx].ver.minor,
						ctrl->pe_fw[idx].ver.patch,
						ctrl->pe_fw[idx].ver.internal);
	}

	onu_fw_release(&pe_fw);

	return ret != 0 ? ONU_STATUS_FW_INIT_ERR : ONU_STATUS_OK;
}

enum onu_errorcode gpe_sce_selected_download(struct onu_device *p_dev,
					     const char *name,
					     const uint8_t num_pe)
{
	enum onu_errorcode err = ONU_STATUS_OK;
	int ret = 0;
	struct onu_control *ctrl = p_dev->ctrl;
	struct sce_download_cfg dwnld_cfg;
	struct sce_fw_init fw_init;
	struct onu_fw pe_fw;
	uint8_t idx;
	char *s, str1[ONU_PE_FIRMWARE_NAME_MAX], str2[ONU_PE_FIRMWARE_NAME_MAX];

	if (strlen(name) > ONU_PE_FIRMWARE_NAME_MAX - 1) {
		ONU_DEBUG_ERR("PE fw file name length error");
		return ONU_STATUS_ERR;
	}

	s = strstr(name, ".bin");
	if (!s) {
		ONU_DEBUG_ERR("Wrong PE fw file extension, expecting .bin");
		return ONU_STATUS_ERR;
	}
	strncpy(str1, name, strlen(name) + 1);
	s = strstr(str1, "1.bin");
	if (!s) {
		/* download the specified binary for all PEs*/
		dwnld_cfg.pid = 0xFF;
		strncpy(dwnld_cfg.fw_name, name, ONU_PE_FIRMWARE_NAME_MAX);

		return gpe_sce_download(p_dev, &dwnld_cfg);
	}
	*s = '\0';

	memset(&pe_fw, 0, sizeof(pe_fw));
	for (idx = 0; idx < num_pe; idx++) {
		onu_snprintf(str2, sizeof(str2), "%s%u.bin", str1, idx + 1);

		ret = onu_pe_fw_load(str2, &pe_fw);
		if (ret != 0) {
			err = ONU_STATUS_FW_REQUEST_ERR;
			break;
		}

		onu_pe_fw_info_release(&ctrl->pe_fw[idx]);
		ret = onu_pe_fw_info_load(&pe_fw, &ctrl->pe_fw[idx]);
		if (ret != 0) {
			err = ONU_STATUS_FW_REQUEST_ERR;
			break;
		}

		fw_init.code.pe_index = idx;
		fw_init.code.data = (uint32_t *)(pe_fw.bin + PE_FW_HEADER_SIZE +
						 ctrl->pe_fw[idx].opt_hdr_len);

		fw_init.code.len = pe_fw.len - PE_FW_HEADER_SIZE -
						ctrl->pe_fw[idx].opt_hdr_len;
		fw_init.data.pe_index = idx;
		fw_init.data.data = NULL;
		fw_init.data.len = 0;

		ret = sce_fw_init(&fw_init, num_pe);
		if (ret != 0) {
			err = ONU_STATUS_FW_INIT_ERR;
			break;
		}
	}

	onu_fw_release(&pe_fw);

	return err;
}

/** gpe_sce_counter_get function directly reports SCE firmware counters
*/
enum onu_errorcode gpe_sce_counter_get(struct onu_device *p_dev,
				       const struct gpe_cnt_sce_sel *in,
				       struct gpe_cnt_sce_val *out)
{
	enum onu_errorcode ret = GPE_STATUS_VALUE_RANGE_ERR;
	struct gpe_table_entry gpe_tbl_entry;
	struct sce_cnt_get_helper map[] = {
		{GPE_SCE_UNICAST,
			COP_COUNT_BASE_UC, ONU_GPE_MAX_INGRESS_QUEUES},
		{GPE_SCE_BROADCAST,
			COP_COUNT_BASE_BC, ONU_GPE_MAX_INGRESS_QUEUES},
		{GPE_SCE_MULTICAST,
			COP_COUNT_BASE_MC, ONU_GPE_MAX_INGRESS_QUEUES},
		{GPE_SCE_DISCARDED,
			COP_COUNT_BASE_IPN_DISCARD, ONU_GPE_MAX_INGRESS_QUEUES},
		{GPE_SCE_LEARNING_FAIL,
			COP_COUNT_BASE_LIM, ONU_GPE_MAX_BRIDGES},
		{GPE_SCE_DISCARDED_INGRESS,
			COP_COUNT_BASE_IBP_DISCARD, ONU_GPE_MAX_BRIDGES},
		{GPE_SCE_ACCEPTED_INGRESS,
			COP_COUNT_BASE_IBP_GOOD, ONU_GPE_MAX_BRIDGES},
		{GPE_SCE_ACCEPTED_EGRESS,
			COP_COUNT_BASE_EBP_GOOD, ONU_GPE_MAX_BRIDGES},
		{GPE_SCE_DISCARDED_EGRESS,
			COP_COUNT_BASE_EBP_DISCARD, ONU_GPE_MAX_BRIDGES},
		{GPE_SCE_DISCARDED_PPPOE,
			COP_COUNT_BASE_PPPOE, ONU_GPE_MAX_BRIDGES},
		{GPE_SCE_EXCEPTION_POLICER,
			COP_COUNT_BASE_ANI_EXCEPTION_POLICER, 3},
		{GPE_SCE_EXCEPTION_LOST,
			COP_COUNT_BASE_EXCEPTIONS_LOST, 1},
		{GPE_SCE_BROADCAST_EGRESS,
			COP_COUNT_BASE_BC_EGRESS, 4},
		{GPE_SCE_MULTICAST_EGRESS,
			COP_COUNT_BASE_MC_EGRESS, 4}
	};
	uint32_t idx;
	uint8_t i;

	out->cnt_type = in->cnt_type;
	out->index = in->index;
	for (i = 0; i < ARRAY_SIZE(map); i++) {
		if (map[i].type == in->cnt_type) {
			if (in->index >= map[i].offset_max)
				goto gpe_sce_counter_get_err;
			idx = (uint32_t)(map[i].cop_base + in->index);
			break;
		}
	}
	if (i >= ARRAY_SIZE(map))
		goto gpe_sce_counter_get_err;

	ret = sce_cnt_get(p_dev->ctrl, &gpe_tbl_entry, idx);
	if (ret != ONU_STATUS_OK)
		goto gpe_sce_counter_get_err;

	out->counter = gpe_tbl_entry.data.counter.counter_value;

	return ret;

gpe_sce_counter_get_err:
	out->counter = 0;

	return ret;
}

enum onu_errorcode gpe_sce_counter_reset(struct onu_device *p_dev,
					 const struct gpe_cnt_sce_reset *param)
{
	UNUSED_PARAM_DEV;
	UNUSED_PARAM;
	return GPE_STATUS_NO_SUPPORT;
}

enum onu_errorcode
gpe_flat_egress_path_create(struct onu_device *p_dev,
			    const struct gpe_flat_egress_path *param)
{
	UNUSED_PARAM_DEV;

	tmu_create_flat_egress_path(param->num_ports,
				    param->base_epn,
				    param->base_sbid,
				    param->base_qid,
				    param->qid_per_sb);

	gpe_enqueue_enable(p_dev->ctrl, param->base_epn, true);

	return ONU_STATUS_OK;
}

enum onu_errorcode
gpe_bridge_counter_get(struct onu_device *p_dev,
		       const struct gpe_bridge_cnt_interval *in,
		       struct gpe_bridge_counter *out)
{
	struct onu_control *ctrl = (struct onu_control *)p_dev->ctrl;

	if (in->bridge_index >= ONU_GPE_MAX_BRIDGES)
		return GPE_STATUS_VALUE_RANGE_ERR;

	memcpy(&(out->cnt_ctrl), in, sizeof(out->cnt_ctrl));

	onu_interval_counter_update(ctrl, in->bridge_index, BRIDGE_COUNTER,
				    (uint64_t)in->reset_mask, in->curr,
				    &(out->cnt_val));

	return ONU_STATUS_OK;
}

enum onu_errorcode
gpe_bridge_counter_threshold_set(struct onu_device *p_dev,
				 const struct gpe_cnt_bridge_threshold *param)
{
	struct onu_control *ctrl = (struct onu_control *)p_dev->ctrl;

	if (param->bridge_index >= ONU_GPE_MAX_BRIDGES)
		return GPE_STATUS_VALUE_RANGE_ERR;

	onu_locked_memcpy(&ctrl->cnt_lock,
	     &ctrl->bridge_cnt[0][ONU_COUNTER_THRESHOLD][param->bridge_index],
	     &param->threshold,
	     sizeof(struct gpe_cnt_bridge_val));

	return ONU_STATUS_OK;
}

enum onu_errorcode
gpe_bridge_counter_threshold_get(struct onu_device *p_dev,
				 const struct gpe_bridge *in,
				 struct gpe_cnt_bridge_threshold *out)
{
	struct onu_control *ctrl = (struct onu_control *)p_dev->ctrl;

	if (in->bridge_index >= ONU_GPE_MAX_BRIDGES)
		return GPE_STATUS_VALUE_RANGE_ERR;

	out->bridge_index = in->bridge_index;

	memcpy(&(out->threshold), &ctrl->
	       bridge_cnt[0][ONU_COUNTER_THRESHOLD][in->bridge_index],
	       sizeof(struct gpe_cnt_bridge_val));

	return ONU_STATUS_OK;
}

enum onu_errorcode gpe_bridge_tca_get(struct onu_device *p_dev,
				      const struct gpe_bridge *in,
				      struct gpe_cnt_bridge_threshold *out)
{
	struct onu_control *ctrl = (struct onu_control *)p_dev->ctrl;

	if (in->bridge_index >= ONU_GPE_MAX_BRIDGES)
		return GPE_STATUS_VALUE_RANGE_ERR;

	out->bridge_index = in->bridge_index;

	onu_locked_memcpy(&ctrl->cnt_lock,
	     &(out->threshold), &ctrl->
	     bridge_cnt[1][ONU_COUNTER_THRESHOLD][in->bridge_index],
	     sizeof(struct gpe_cnt_bridge_val));

	return ONU_STATUS_OK;
}

enum onu_errorcode
gpe_bridge_counter_reset(struct onu_device *p_dev,
			 const struct gpe_bridge_cnt_interval *param)
{
	struct onu_control *ctrl = (struct onu_control *)p_dev->ctrl;

	if (param->bridge_index >= ONU_GPE_MAX_BRIDGES)
		return GPE_STATUS_VALUE_RANGE_ERR;

	onu_interval_counter_update(ctrl, param->bridge_index, BRIDGE_COUNTER,
				    (uint64_t)param->reset_mask, true, NULL);

	return ONU_STATUS_OK;
}

enum onu_errorcode
gpe_bridge_port_counter_get(struct onu_device *p_dev,
		       const struct gpe_bridge_port_cnt_interval *in,
		       struct gpe_bridge_port_counter *out)
{
	struct onu_control *ctrl = (struct onu_control *)p_dev->ctrl;

	if(in->index >= ONU_GPE_MAX_BRIDGE_PORT)
		return GPE_STATUS_VALUE_RANGE_ERR;

	memmove(&(out->ctrl), in, sizeof(out->ctrl));

	if(gpe_bridge_port_valid(ctrl, in->index) == false) {
		memset(&(out->val), 0, sizeof(out->val));
		return ONU_STATUS_ERR;
	}

	onu_interval_counter_update(ctrl, in->index, BRIDGE_PORT_COUNTER,
				    (uint64_t)in->reset_mask, in->curr,
				    &(out->val));

	return ONU_STATUS_OK;
}

enum onu_errorcode
gpe_bridge_port_counter_threshold_set(struct onu_device *p_dev,
				 const struct gpe_cnt_bridge_port_threshold *param)
{
	struct onu_control *ctrl = (struct onu_control *)p_dev->ctrl;

	if(param->index >= ONU_GPE_MAX_BRIDGE_PORT)
		return GPE_STATUS_VALUE_RANGE_ERR;

	onu_locked_memcpy(&ctrl->cnt_lock,
	     &ctrl->bridge_port_cnt[0][ONU_COUNTER_THRESHOLD][param->index],
	     &param->threshold,
	     sizeof(struct gpe_cnt_bridge_port_val));

	return ONU_STATUS_OK;
}

enum onu_errorcode
gpe_bridge_port_counter_threshold_get(struct onu_device *p_dev,
				 const struct gpe_bridge_port_index *in,
				 struct gpe_cnt_bridge_port_threshold *out)
{
	struct onu_control *ctrl = (struct onu_control *)p_dev->ctrl;

	if(in->index >= ONU_GPE_MAX_BRIDGE_PORT)
		return GPE_STATUS_VALUE_RANGE_ERR;

	out->index = in->index;

	if(gpe_bridge_port_valid(ctrl, in->index) == false) {
		memset(&(out->threshold), 0, sizeof(out->threshold));
		return ONU_STATUS_ERR;
	}

	memcpy(&(out->threshold), &ctrl->
	       bridge_port_cnt[0][ONU_COUNTER_THRESHOLD][in->index],
	       sizeof(struct gpe_cnt_bridge_port_val));

	return ONU_STATUS_OK;
}

enum onu_errorcode gpe_bridge_port_tca_get(struct onu_device *p_dev,
				      const struct gpe_bridge_port_index *in,
				      struct gpe_cnt_bridge_port_threshold *out)
{
	struct onu_control *ctrl = (struct onu_control *)p_dev->ctrl;

	if(in->index >= ONU_GPE_MAX_BRIDGE_PORT)
		return GPE_STATUS_VALUE_RANGE_ERR;

	out->index = in->index;

	if(gpe_bridge_port_valid(ctrl, in->index) == false) {
		memset(&(out->threshold), 0, sizeof(out->threshold));
		return ONU_STATUS_ERR;
	}

	onu_locked_memcpy(&ctrl->cnt_lock,
	     &(out->threshold), &ctrl->
	     bridge_port_cnt[1][ONU_COUNTER_THRESHOLD][in->index],
	     sizeof(struct gpe_cnt_bridge_port_val));

	return ONU_STATUS_OK;
}

enum onu_errorcode
gpe_bridge_port_counter_reset(struct onu_device *p_dev,
			 const struct gpe_bridge_port_cnt_interval *param)
{
	struct onu_control *ctrl = (struct onu_control *)p_dev->ctrl;

	if(param->index >= ONU_GPE_MAX_BRIDGE_PORT)
		return GPE_STATUS_VALUE_RANGE_ERR;

	if(gpe_bridge_port_valid(ctrl, param->index) == false)
		return ONU_STATUS_ERR;

	onu_interval_counter_update(ctrl, param->index, BRIDGE_PORT_COUNTER,
				    (uint64_t)param->reset_mask, true, NULL);

	return ONU_STATUS_OK;
}

#if !defined(ONU_LIBRARY)
enum onu_errorcode gpe_fsqm_check(struct onu_device *p_dev, uint16_t len)
{
	UNUSED_PARAM_DEV;
	return fsqm_check(len);
}
#endif

enum onu_errorcode gpe_iqueue_write_debug(struct onu_device *p_dev,
					  const struct ictrlc_write *param)
{
	/* avoid early access on Ethernet start to ONU resources */
	if (!onu_is_initialized())
		return ONU_STATUS_OK;

	return (enum onu_errorcode)ssb_iqueue_write(param->qid, 0xFF,
						    param->pdu_type,
						    param->plen, param->data);
}

enum onu_errorcode
gpe_lan_exception_cfg_set(struct onu_device *p_dev,
			  const struct gpe_lan_exception_cfg *param)
{
	enum onu_errorcode ret;
	struct onu_control *ctrl = p_dev->ctrl;
	struct gpe_table_entry entry;

	if (param->lan_port_index >= ONU_GPE_MAX_ETH_UNI ||
	    param->exception_profile >= ONU_GPE_EXCEPTION_TABLE_SIZE)
		return GPE_STATUS_VALUE_RANGE_ERR;

	entry.id = ONU_GPE_LAN_PORT_TABLE_ID;
	entry.index = param->lan_port_index;
	entry.instance = ONU_GPE_ALL_PE_MASK;
	ret = TABLE_GET(ctrl, &entry);

	if (ret)
		return ret;

	entry.data.lan_port.exception_profile = param->exception_profile;
	entry.data.lan_port.uni_except_meter_id = param->uni_except_meter_id;
	entry.data.lan_port.uni_except_meter_enable =
						param->uni_except_meter_enable;
	entry.data.lan_port.igmp_except_meter_id = param->igmp_except_meter_id;
	entry.data.lan_port.igmp_except_meter_enable = param->igmp_except_meter_enable;

	entry.id = ONU_GPE_LAN_PORT_TABLE_ID;
	entry.index = param->lan_port_index;
	entry.instance = ONU_GPE_ALL_PE_MASK;
	ret = gpe_table_entry_set(p_dev, &entry);
	if (ret)
		return ret;

	return ret;
}

enum onu_errorcode
gpe_lan_exception_cfg_get(struct onu_device *p_dev,
			  const struct gpe_lan_exception_idx *in,
			  struct gpe_lan_exception_cfg *out)
{
	enum onu_errorcode ret;
	struct onu_control *ctrl = p_dev->ctrl;
	struct gpe_table_entry entry;

	if (in->lan_port_index >= ONU_GPE_MAX_ETH_UNI)
		return GPE_STATUS_VALUE_RANGE_ERR;

	out->lan_port_index = in->lan_port_index;

	entry.id = ONU_GPE_LAN_PORT_TABLE_ID;
	entry.index = in->lan_port_index;
	entry.instance = ONU_GPE_ALL_PE_MASK;
	ret = TABLE_GET(ctrl, &entry);

	if (ret)
		return ret;

	out->exception_profile = entry.data.lan_port.exception_profile;
	out->uni_except_meter_id = entry.data.lan_port.uni_except_meter_id;
	out->uni_except_meter_enable =
				entry.data.lan_port.uni_except_meter_enable;
	out->igmp_except_meter_id = entry.data.lan_port.igmp_except_meter_id;
	out->igmp_except_meter_enable = entry.data.lan_port.igmp_except_meter_enable;

	return ret;
}

enum onu_errorcode
gpe_ani_exception_cfg_set(struct onu_device *p_dev,
			  const struct gpe_ani_exception_cfg *param)
{
	enum onu_errorcode ret;
	struct onu_control *ctrl = p_dev->ctrl;
	struct gpe_table_entry entry;

	if (param->ds_exception_profile >= ONU_GPE_EXCEPTION_TABLE_SIZE ||
	    param->us_exception_profile >= ONU_GPE_EXCEPTION_TABLE_SIZE)
		return GPE_STATUS_VALUE_RANGE_ERR;

	/*
		set exception profile for DS GEM port
	*/
	entry.id = ONU_GPE_DS_GEM_PORT_TABLE_ID;
	entry.index = param->gem_port_index;
	entry.instance = 0;
	ret = TABLE_GET(ctrl, &entry);

	if (ret)
		return ret;

	entry.data.ds_gem_port.exception_profile = param->ds_exception_profile;

	entry.id = ONU_GPE_DS_GEM_PORT_TABLE_ID;
	entry.index = param->gem_port_index;
	entry.instance = 0;
	ret = gpe_table_entry_set(p_dev, &entry);
	if (ret)
		return ret;

	/*
		set exception profile for US GEM port
	*/
	entry.id = ONU_GPE_US_GEM_PORT_TABLE_ID;
	entry.index = param->gem_port_index;
	entry.instance = 0;
	ret = TABLE_GET(ctrl, &entry);

	if (ret)
		return ret;

	entry.data.us_gem_port.exception_profile = param->us_exception_profile;

	entry.id = ONU_GPE_US_GEM_PORT_TABLE_ID;
	entry.index = param->gem_port_index;
	entry.instance = 0;
	ret = gpe_table_entry_set(p_dev, &entry);
	if (ret)
		return ret;

	return ret;
}

enum onu_errorcode
gpe_ani_exception_cfg_get(struct onu_device *p_dev,
			  const struct gpe_ani_exception_idx *in,
			  struct gpe_ani_exception_cfg *out)
{
	enum onu_errorcode ret;
	struct onu_control *ctrl = p_dev->ctrl;
	struct gpe_table_entry entry;

	out->gem_port_index = in->gem_port_index;

	/*
		get DS GEM port exception profile
	*/
	entry.id = ONU_GPE_DS_GEM_PORT_TABLE_ID;
	entry.index = in->gem_port_index;
	entry.instance = 0;
	ret = TABLE_GET(ctrl, &entry);
	if (ret)
		return ret;

	out->ds_exception_profile = entry.data.ds_gem_port.exception_profile;


	/*
		get US GEM port exception profile
	*/
	entry.id = ONU_GPE_US_GEM_PORT_TABLE_ID;
	entry.index = in->gem_port_index;
	entry.instance = 0;
	ret = TABLE_GET(ctrl, &entry);
	if (ret)
		return ret;

	out->us_exception_profile = entry.data.us_gem_port.exception_profile;

	return ret;
}

enum onu_errorcode
gpe_exception_queue_cfg_set(struct onu_device *p_dev,
			    const struct gpe_exception_queue_cfg *param)
{
	struct gpe_table_entry entry;

	memset(&entry, 0x00, sizeof(entry));

	entry.id = ONU_GPE_REDIRECTION_TABLE_ID;
	entry.instance = 0xFF;
	entry.index = param->exception_index;

	entry.data.redirection.redirection_queue_index = param->exception_queue;
	entry.data.redirection.snooping_enable = param->snooping_enable ? 1 : 0;

	if (entry.index >= ONU_GPE_REDIRECTION_TABLE_SIZE)
		return GPE_STATUS_VALUE_RANGE_ERR;

	return gpe_table_entry_set(p_dev, &entry);
}

enum onu_errorcode
gpe_exception_queue_cfg_get(struct onu_device *p_dev,
			    const struct gpe_exception_queue_idx *in,
			    struct gpe_exception_queue_cfg *out)
{
	struct gpe_table table;
	struct gpe_table_entry entry;
	enum onu_errorcode ret;

	out->exception_index = in->exception_index;

	table.id = ONU_GPE_REDIRECTION_TABLE_ID;
	table.instance = 1;
	table.index = in->exception_index;

	if (table.index >= ONU_GPE_REDIRECTION_TABLE_SIZE)
		return GPE_STATUS_VALUE_RANGE_ERR;

	ret = gpe_table_entry_get(p_dev, &table, &entry);

	out->exception_queue = entry.data.redirection.redirection_queue_index;
	out->snooping_enable = entry.data.redirection.snooping_enable ?
								true : false;

	return ret;
}

#ifdef INCLUDE_CLI_SUPPORT
enum onu_errorcode gpe_lan_port_acl_set(struct onu_device *p_dev,
					const struct gpe_lan_port_acl *in)
{
	struct gpe_table table;
	struct gpe_table_entry entry;
	enum onu_errorcode ret;

	memset(&entry, 0x00, sizeof(entry));

	table.id = ONU_GPE_LAN_PORT_TABLE_ID;
	table.instance = 1;
	table.index = in->port_index;

	if (table.index >= ONU_GPE_LAN_PORT_TABLE_SIZE)
		return GPE_STATUS_VALUE_RANGE_ERR;

	ret = gpe_table_entry_get(p_dev, &table, &entry);
	if (ret != ONU_STATUS_OK)
		return ret;

	entry.data.lan_port.acl_filter_enable =
					in->acl_filter_enable == true;
	entry.data.lan_port.acl_filter_index =
					in->acl_filter_index;
	entry.data.lan_port.acl_filter_mode =
					in->acl_filter_mode_whitelist == true;

	return gpe_table_entry_set(p_dev, &entry);
}

enum onu_errorcode gpe_lan_port_acl_get(struct onu_device *p_dev,
					const struct gpe_lan_port_acl_index *in,
					struct gpe_lan_port_acl *out)
{
	struct gpe_table table;
	struct gpe_table_entry entry;
	enum onu_errorcode ret;

	table.id = ONU_GPE_LAN_PORT_TABLE_ID;
	table.instance = 1;
	table.index = in->port_index;

	if (table.index >= ONU_GPE_LAN_PORT_TABLE_SIZE)
		return GPE_STATUS_VALUE_RANGE_ERR;

	ret = gpe_table_entry_get(p_dev, &table, &entry);
	if (ret != ONU_STATUS_OK)
		return ret;

	out->acl_filter_enable = entry.data.lan_port.acl_filter_enable == 1;
	out->acl_filter_index = entry.data.lan_port.acl_filter_index;
	out->acl_filter_mode_whitelist =
		entry.data.lan_port.acl_filter_mode == 1;
	out->port_index = in->port_index;

	return ret;
}
#endif

enum onu_errorcode
gpe_tr181_counter_get(struct onu_device *p_dev,
		      const struct gpe_tr181_counters_cfg *in,
		      struct gpe_tr181_counters *out)
{
	struct gpe_cnt_octrlg_val octrlg_cnt;
	struct gpe_cnt_ictrlg_val ictrlg_cnt;
	struct ictrll_counter ictrll_cnt;
	uint32_t qdc[4];
	uint8_t i;

	if (in->us_egress_queue_num >= ARRAY_SIZE(in->us_egress_queue_list) ||
	    in->ds_egress_queue_num >= ARRAY_SIZE(in->ds_egress_queue_list))
		return GPE_STATUS_VALUE_RANGE_ERR;

	(void)octrlg_counter_get(&octrlg_cnt);
	(void)ictrlg_counter_get(&ictrlg_cnt);

	out->bytes_sent = octrlg_cnt.tx_gem_pdu_bytes_total +
			  octrlg_cnt.tx_gem_idle_frames_total *
				octrlg_idle_len_get() +
			  octrlg_cnt.tx_tcont_total *
				gtc_upstream_header_len_get();
	out->bytes_received = gtc_gem_rxbcnt_get() + gtc_gem_rxfcnt_get() * 5;
	out->packets_sent = octrlg_cnt.tx_gem_frames_total;
	out->packets_received = ictrlg_cnt.rx_gem_frames_total;
	out->errors_received = (uint32_t)(gtc_gem_fuerrcnt_get() +
				ictrlg_cnt.fcserror +
				ictrlg_cnt.undersize_error +
				ictrlg_cnt.omci_drop);

	out->errors_sent = 0;
	for (i = 0; i < ONU_GPE_MAX_ETH_UNI; i++) {
		out->errors_sent += ictrll_pdc_get(i);
		(void)ictrll_counter_get(i, &ictrll_cnt);
		out->errors_sent += (uint32_t)ictrll_cnt.rx_undersized_frames;
	}

	out->discard_packets_sent = 0;
	for (i = 0; i < in->us_egress_queue_num; i++) {
		tmu_equeue_discard_counters_get(
			(uint32_t)in->us_egress_queue_list[i], qdc);
		out->discard_packets_sent += qdc[0] + qdc[1] + qdc[2] + qdc[3];
	}
	for (i = 0; i < ONU_GPE_MAX_ETH_UNI; i++)
		out->discard_packets_sent += iqm_iqueue_discard_counter_get(i);

	out->discard_packets_received = 0;
	for (i = 0; i < in->ds_egress_queue_num; i++) {
		tmu_equeue_discard_counters_get(
			(uint32_t)in->ds_egress_queue_list[i], qdc);
		out->discard_packets_received += qdc[0] + qdc[1] + qdc[2] +
						 qdc[3];
	}
	out->discard_packets_received += iqm_iqueue_discard_counter_get(5) +
				         iqm_iqueue_discard_counter_get(6) +
					 iqm_iqueue_discard_counter_get(7);

	return ONU_STATUS_OK;
}

enum onu_errorcode gpe_device_capability_get(struct gpe_capability *cap)
{
	uint32_t format;
	uint32_t analog, fuse0, max_eth_uni;

	if (gpe_chip_version == GPE_CHIP_UNKNOWN)
		gpe_chip_version = onu_chip_get();
	if (gpe_chip_version == GPE_CHIP_UNKNOWN)
		return GPE_STATUS_NOT_AVAILABLE;

	cap->hw_version = gpe_chip_version;

	status_fuses_get(&analog, &fuse0);
	if (analog != 0) {
		format = ((analog & STATUS_ANALOG_FS_MASK) >>
			  STATUS_ANALOG_FS_OFFSET);

		if (format == 0) {
			/* old fuses format, assume FALC ON-V */

			cap->max_meter = 128;
			cap->max_gpix = 128;
			max_eth_uni = 4;
			cap->max_pots_uni = 2;
			cap->max_bridge_port = 64;
		} else {
			/* new format */

			format = ((fuse0 & STATUS_FUSE0_F0_MASK) >>
				  STATUS_FUSE0_F0_OFFSET);

			switch (format) {
			case 0:
				/* FALC ON-D */
				cap->max_meter = 64;
				cap->max_gpix = 128;
				max_eth_uni = 2;
				cap->max_pots_uni = 0;
				cap->max_bridge_port = 64;

				break;

			case 1:
				/* FALC ON-V */
				cap->max_meter = 128;
				cap->max_gpix = 128;
				max_eth_uni = 4;
				cap->max_pots_uni = 2;
				cap->max_bridge_port = 64;

				break;

			case 2:
				/* FALC ON-M */
				cap->max_meter = 256;
				cap->max_gpix = 256;
				max_eth_uni = 4;
				cap->max_pots_uni = 0;
				cap->max_bridge_port = 126;

				break;

			default:
				/* unknown device, assume FALC ON-D */
				cap->max_meter = 64;
				cap->max_gpix = 128;
				max_eth_uni = 2;
				cap->max_pots_uni = 0;
				cap->max_bridge_port = 64;

				break;
			}
		}
	} else {
		cap->max_meter = ONU_GPE_MAX_METER;
		cap->max_gpix = ONU_GPE_MAX_GPIX;
		max_eth_uni = ONU_GPE_MAX_ETH_UNI;
		cap->max_pots_uni = ONU_GPE_MAX_VOICE_UNI;
		cap->max_bridge_port = ONU_GPE_MAX_BRIDGE_PORT;
	}

	cap->max_eth_uni = MIN(max_eth_uni, ONU_GPE_MAX_ETH_UNI);

	return ONU_STATUS_OK;
}

enum onu_errorcode gpe_capability_get(struct onu_device *p_dev,
				      struct gpe_capability *param)
{
	UNUSED_PARAM_DEV;

	return gpe_device_capability_get(param);
}

enum onu_errorcode
gpe_exception_profile_cfg_set(struct onu_device *p_dev,
			      const struct gpe_exception_profile_cfg *param)
{
	struct gpe_table_entry entry;

	memset(&entry, 0x00, sizeof(entry));

	entry.id = ONU_GPE_EXCEPTION_TABLE_ID;
	entry.instance = 0xFF;
	entry.index = param->exception_profile;

	if (entry.index >= ONU_GPE_EXCEPTION_TABLE_SIZE)
		return GPE_STATUS_VALUE_RANGE_ERR;

	entry.data.exception.ingress_exception_flag_mask =
						param->ingress_exception_mask;
	entry.data.exception.egress_exception_flag_mask =
						param->egress_exception_mask;

	return gpe_table_entry_set(p_dev, &entry);
}

enum onu_errorcode
gpe_exception_profile_cfg_get(struct onu_device *p_dev,
			      const struct gpe_exception_profile_idx *in,
			      struct gpe_exception_profile_cfg *out)
{
	struct gpe_table table;
	struct gpe_table_entry entry;
	enum onu_errorcode ret;

	out->exception_profile = in->exception_profile;

	table.id = ONU_GPE_EXCEPTION_TABLE_ID;
	table.instance = 1;
	table.index = in->exception_profile;

	if (table.index >= ONU_GPE_EXCEPTION_TABLE_SIZE)
		return GPE_STATUS_VALUE_RANGE_ERR;

	ret = gpe_table_entry_get(p_dev, &table, &entry);

	out->ingress_exception_mask =
			entry.data.exception.ingress_exception_flag_mask;
	out->egress_exception_mask =
			entry.data.exception.egress_exception_flag_mask;

	return ret;
}

enum onu_errorcode gpe_egress_port_enable(struct onu_device *p_dev,
					  const struct gpe_epn *param)
{
	UNUSED_PARAM_DEV;

	tmu_egress_port_enable(param->epn, true);

	return ONU_STATUS_OK;
}

enum onu_errorcode gpe_egress_port_disable(struct onu_device *p_dev,
					   const struct gpe_epn *param)
{
	UNUSED_PARAM_DEV;

	tmu_egress_port_enable(param->epn, false);

	return ONU_STATUS_OK;
}

uint32_t gpe_enqueue_flush(struct onu_control *ctrl, const uint16_t epn)
{
	int ret;
	uint32_t cnt=0;
	struct onu_pdu_info info;

	if(epn == 127)
		return 0;

	while (1) {
		ret = ssb_egress_info_read(epn, &info);
		if (ret != 0 || info.hlsa == ONU_GPE_LLT_NIL)
			break;
		ssb_egress_data_read(&info, NULL);
		cnt++;
	}

	if(ctrl)
		ctrl->gc_count[epn] += cnt;

	return cnt;
}

void gpe_enqueue_modify(struct onu_control *ctrl, const uint16_t qid, const bool ena)
{
	unsigned long flags = 0;
	struct gpe_table_entry entry;
	uint32_t index = qid / 32;
	uint32_t mask = 1 << (qid % 32);

	if (index >= ONU_GPE_ENQUEUE_TABLE_SIZE)
		return;

	memset(&entry, 0x00, sizeof(entry));

	onu_spin_lock_get(&enqueue_lock, &flags);

	entry.id = ONU_GPE_ENQUEUE_TABLE_ID;
	entry.instance = ONU_GPE_ALL_PE_MASK;
	entry.index = index;
	if (TABLE_GET(ctrl, &entry) != 0) {
		onu_spin_lock_release(&enqueue_lock, flags);
		return;
	}

	if(ena)
		entry.data.enqueue.enable |= mask;
	else
		entry.data.enqueue.enable &= ~mask;

	entry.id = ONU_GPE_ENQUEUE_TABLE_ID;
	entry.index = index;
	entry.instance = ONU_GPE_ALL_PE_MASK;

	gpe_table_entry_intcmd(ctrl, &entry, ONU_GPE_COP_SET);

	onu_spin_lock_release(&enqueue_lock, flags);
}

void gpe_enqueue_find(struct onu_control *ctrl, const uint32_t sbid, const bool ena)
{
	int i,k=sbid<<3;
	struct tmu_sched_blk_in_link sbit;

	for(i=0;i<8;i++,k++) {
		tmu_sched_blk_in_link_get(k, &sbit);
		if(sbit.sie == 0)
			continue;
		if(sbit.sit == 1) {
			gpe_enqueue_find(ctrl, sbit.qsid, ena);
			continue;
		}
		gpe_enqueue_modify(ctrl, sbit.qsid, ena);
	}
}

void gpe_enqueue_enable(struct onu_control *ctrl, const uint32_t epn, const bool ena)
{
	struct tmu_eport_link epmt;

	tmu_egress_port_link_get(epn, &epmt);
	if (epmt.epe != 1)
		return;

	gpe_enqueue_find(ctrl, epmt.sbid, ena);

	if(ena == false)
		gpe_enqueue_flush(ctrl, epn);
}

const struct onu_entry gpe_function_table[] = {
	TE1in(FIO_GPE_INIT,
		sizeof(struct gpe_init_data),
		gpe_init),
	TE1in(FIO_GPE_CFG_SET,
		sizeof(struct gpe_cfg),
		gpe_cfg_set),
	TE1out(FIO_GPE_CFG_GET,
		sizeof(struct gpe_cfg),
		gpe_cfg_get),
	TE1out(FIO_GPE_STATUS_GET,
		sizeof(struct gpe_status),
		gpe_status_get),

	TE2(FIO_GPE_GEM_PORT_ADD,
		sizeof(struct gpe_gem_port),
		sizeof(struct gpe_gem_port),
		gpe_gem_port_add),
	TE1in(FIO_GPE_GEM_PORT_DELETE,
		sizeof(struct gem_port_id),
		gpe_gem_port_delete),
	TE2(FIO_GPE_GEM_PORT_GET,
		sizeof(struct gem_port_id),
		sizeof(struct gpe_gem_port),
		gpe_gem_port_get),

	TE1in(FIO_GPE_EGRESS_QUEUE_CREATE,
		sizeof(struct gpe_equeue_create),
		gpe_egress_queue_create),
	TE1in(FIO_GPE_EGRESS_QUEUE_DELETE,
		sizeof(struct gpe_equeue),
		gpe_egress_queue_delete),

	TE1in(FIO_GPE_EGRESS_QUEUE_CFG_SET,
		sizeof(struct gpe_equeue_cfg),
		gpe_egress_queue_cfg_set),
	TE2(FIO_GPE_EGRESS_QUEUE_CFG_GET,
		sizeof(struct gpe_equeue),
		sizeof(struct gpe_equeue_cfg),
		gpe_egress_queue_cfg_get),
	TE2(FIO_GPE_EGRESS_QUEUE_STATUS_GET,
		sizeof(struct gpe_equeue),
		sizeof(struct gpe_equeue_status),
		gpe_egress_queue_status_get),

	TE1in(FIO_GPE_INGRESS_QUEUE_CFG_SET,
		sizeof(struct gpe_iqueue_cfg),
		gpe_ingress_queue_cfg_set),
	TE2(FIO_GPE_INGRESS_QUEUE_CFG_GET,
		sizeof(struct gpe_iqueue),
		sizeof(struct gpe_iqueue_cfg),
		gpe_ingress_queue_cfg_get),

	TE1in(FIO_GPE_SCHEDULER_CFG_SET,
		sizeof(struct gpe_scheduler_cfg),
		gpe_scheduler_cfg_set),
	TE2(FIO_GPE_SCHEDULER_CFG_GET,
		sizeof(struct gpe_scheduler_idx),
		sizeof(struct gpe_scheduler_cfg),
		gpe_scheduler_cfg_get),

	TE1out(FIO_GPE_METER_CREATE,
		sizeof(struct gpe_meter),
		gpe_meter_create),
	TE1in(FIO_GPE_METER_DELETE,
		sizeof(struct gpe_meter),
		gpe_meter_delete),
	TE1in(FIO_GPE_METER_CFG_SET,
		sizeof(struct gpe_meter_cfg),
		gpe_meter_cfg_set),
	TE2(FIO_GPE_METER_CFG_GET,
		sizeof(struct gpe_meter),
		sizeof(struct gpe_meter_cfg),
		gpe_meter_cfg_get),
	TE2(FIO_GPE_METER_STATUS_GET,
		sizeof(struct gpe_meter),
		sizeof(struct gpe_meter_status),
		gpe_meter_status_get),

	TE2(FIO_GPE_BRIDGE_COUNTER_GET,
		sizeof(struct gpe_bridge_cnt_interval),
		sizeof(struct gpe_bridge_counter),
		gpe_bridge_counter_get),
	TE1in(FIO_GPE_BRIDGE_COUNTER_THRESHOLD_SET,
		sizeof(struct gpe_cnt_bridge_threshold),
		gpe_bridge_counter_threshold_set),
	TE2(FIO_GPE_BRIDGE_COUNTER_THRESHOLD_GET,
		sizeof(struct gpe_bridge),
		sizeof(struct gpe_cnt_bridge_threshold),
		gpe_bridge_counter_threshold_get),
	TE2(FIO_GPE_BRIDGE_TCA_GET,
		sizeof(struct gpe_bridge),
		sizeof(struct gpe_cnt_bridge_threshold),
		gpe_bridge_tca_get),
	TE1in(FIO_GPE_BRIDGE_COUNTER_RESET,
		sizeof(struct gpe_bridge_cnt_interval),
		gpe_bridge_counter_reset),

	TE1in(FIO_GPE_EGRESS_QUEUE_COUNTER_CFG_SET,
		sizeof(struct gpe_equeue_cnt_cfg),
		NULL),
	TE1out(FIO_GPE_EGRESS_QUEUE_COUNTER_CFG_GET,
		sizeof(struct gpe_equeue_cnt_cfg),
		NULL),

	TE1in(FIO_GPE_TCONT_CREATE,
		sizeof(struct gpe_tcont_cfg),
		gpe_tcont_create),
	TE1in(FIO_GPE_TCONT_SET,
		sizeof(struct gpe_tcont),
		gpe_tcont_set),
	TE2(FIO_GPE_TCONT_GET,
		sizeof(struct tcont_index),
		sizeof(struct gpe_tcont),
		gpe_tcont_get),
	TE1in(FIO_GPE_TCONT_DELETE,
		sizeof(struct tcont_index),
		gpe_tcont_delete),

	TE1in(FIO_GPE_SCHEDULER_CREATE,
		sizeof(struct gpe_sched_create),
		gpe_scheduler_create),
	TE1in(FIO_GPE_SCHEDULER_DELETE,
		sizeof(struct gpe_scheduler_idx),
		gpe_scheduler_delete),

	TE1in(FIO_GPE_PARSER_CFG_SET,
		sizeof(struct gpe_parser_cfg),
		gpe_parser_cfg_set),
	TE1out(FIO_GPE_PARSER_CFG_GET,
		sizeof(struct gpe_parser_cfg),
		gpe_parser_cfg_get),

	TE2(FIO_GPE_TMU_COUNTER_GET,
		sizeof(struct gpe_cnt_tmu_sel),
		sizeof(struct gpe_cnt_tmu_val),
		gpe_tmu_counter_get),
	TE1in(FIO_GPE_TMU_COUNTER_RESET,
		sizeof(struct gpe_cnt_tmu_reset),
		gpe_tmu_counter_reset),

	TE2(FIO_GPE_SCE_COUNTER_GET,
		sizeof(struct gpe_cnt_sce_sel),
		sizeof(struct gpe_cnt_sce_val),
		gpe_sce_counter_get),
	TE1in(FIO_GPE_SCE_COUNTER_RESET,
		sizeof(struct gpe_cnt_sce_reset),
		gpe_sce_counter_reset),

	TE1in(FIO_GPE_TOKEN_BUCKET_SHAPER_CFG_SET,
		sizeof(struct gpe_token_bucket_shaper_cfg),
		gpe_token_bucket_shaper_cfg_set),
	TE2(FIO_GPE_TOKEN_BUCKET_SHAPER_CFG_GET,
		sizeof(struct gpe_token_bucket_shaper_idx),
		sizeof(struct gpe_token_bucket_shaper_cfg),
		gpe_token_bucket_shaper_cfg_get),

	TE1in(FIO_GPE_OMCI_SEND,
		sizeof(struct gpe_omci_msg),
		gpe_omci_send),

	TE1in(FIO_GPE_TOD_INIT,
		sizeof(struct gpe_tod_init_data),
		gpe_tod_init),
	TE1in(FIO_GPE_TOD_SYNC_SET,
		sizeof(struct gpe_tod_sync),
		gpe_tod_sync_set),
	TE1out(FIO_GPE_TOD_GET,
		sizeof(struct gpe_tod),
		gpe_tod_get),
	TE1out(FIO_GPE_TOD_SYNC_GET,
		sizeof(struct gpe_tod_sync),
		gpe_tod_sync_get),

	TE1in(FIO_GPE_EGRESS_PORT_CFG_SET,
		sizeof(struct gpe_egress_port_cfg),
		gpe_egress_port_cfg_set),
	TE2(FIO_GPE_EGRESS_PORT_CFG_GET,
		sizeof(struct gpe_epn),
		sizeof(struct gpe_egress_port_cfg),
		gpe_egress_port_cfg_get),

	TE1in(FIO_GPE_BACKPRESSURE_CFG_SET,
		sizeof(struct gpe_backpressure_cfg),
		gpe_backpressure_cfg_set),
	TE1out(FIO_GPE_BACKPRESSURE_CFG_GET,
		sizeof(struct gpe_backpressure_cfg),
		gpe_backpressure_cfg_get),

	TE2(FIO_GPE_GEM_COUNTER_GET,
		sizeof(struct gpe_gem_cnt_interval),
		sizeof(struct gpe_gem_counter),
		gpe_gem_counter_get),
	TE1in(FIO_GPE_GEM_COUNTER_THRESHOLD_SET,
		sizeof(struct gpe_cnt_gem_threshold),
		gpe_gem_counter_threshold_set),
	TE2(FIO_GPE_GEM_COUNTER_THRESHOLD_GET,
		sizeof(struct gem_port_id),
		sizeof(struct gpe_cnt_gem_val),
		gpe_gem_counter_threshold_get),
	TE2(FIO_GPE_GEM_TCA_GET,
		sizeof(struct gem_port_id),
		sizeof(struct gpe_gem_tca_val),
		gpe_gem_tca_get),
	TE1in(FIO_GPE_GEM_COUNTER_RESET,
		sizeof(struct gpe_gem_cnt_interval),
		gpe_gem_counter_reset),
#if defined(INCLUDE_SCE_DEBUG)
	TE1in(FIO_GPE_SCE_BREAK_SET,
		sizeof(struct sce_break_point),
		sce_break_set),
	TE2(FIO_GPE_SCE_BREAK_GET,
		sizeof(struct sce_break_index),
		sizeof(struct sce_break_point),
		sce_break_get),
	TE1in(FIO_GPE_SCE_BREAK_REMOVE,
		sizeof(struct sce_break_point),
		sce_break_remove),
	TE2(FIO_GPE_SCE_BREAK,
		sizeof(struct sce_thread),
		sizeof(struct sce_break_info),
		sce_break),
	TE2(FIO_GPE_SCE_SINGLE_STEP,
		sizeof(struct sce_thread),
		sizeof(struct sce_break_info),
		sce_single_step),
	TE1in(FIO_GPE_SCE_RUN,
		sizeof(struct sce_thread),
		sce_run),
#else
	TE1in(FIO_GPE_SCE_BREAK_SET, 0, NULL),
	TE2(FIO_GPE_SCE_BREAK_GET, 0, 0, NULL),
	TE1in(FIO_GPE_SCE_BREAK_REMOVE, 0, NULL),
	TE2(FIO_GPE_SCE_BREAK, 0, 0, NULL),
	TE2(FIO_GPE_SCE_SINGLE_STEP, 0, 0, NULL),
	TE1in(FIO_GPE_SCE_RUN, 0, NULL),
#endif
	TE1in(FIO_GPE_SCE_DOWNLOAD,
		sizeof(struct sce_download_cfg),
		gpe_sce_download),
#if defined(INCLUDE_SCE_DEBUG)
	TE1in(FIO_GPE_SCE_RESTART_VM,
		sizeof(struct sce_restart_cfg),
		sce_restart_vm),
	TE1in(FIO_GPE_SCE_RUN_MASK,
		sizeof(struct sce_thread_mask),
		sce_run_mask),
	TE2(FIO_GPE_SCE_BREAK_MASK,
		sizeof(struct sce_thread_mask),
		sizeof(struct sce_break_info),
		sce_break_mask),
	TE1out(FIO_GPE_SCE_STATUS_GET,
		sizeof(struct sce_status),
		sce_status_get),
	TE1in(FIO_GPE_SCE_REGISTER_SET,
		sizeof(struct sce_register),
		sce_reg_set),
	TE2(FIO_GPE_SCE_REGISTER_GET,
		sizeof(struct sce_register),
		sizeof(struct sce_register_val),
		sce_reg_get),
	TE1in(FIO_GPE_SCE_MEMORY_SET,
		sizeof(struct sce_memory),
		sce_mem_set),
	TE2(FIO_GPE_SCE_MEMORY_GET,
		sizeof(struct sce_memory),
		sizeof(struct sce_memory_val),
		sce_mem_get),
#else
	TE1in(FIO_GPE_SCE_RESTART_VM, 0, NULL),
	TE1in(FIO_GPE_SCE_RUN_MASK, 0, NULL),
	TE2(FIO_GPE_SCE_BREAK_MASK, 0, 0, NULL),
	TE1out(FIO_GPE_SCE_STATUS_GET, 0, NULL),
	TE1in(FIO_GPE_SCE_REGISTER_SET, 0, NULL),
	TE2(FIO_GPE_SCE_REGISTER_GET, 0, 0, NULL),
	TE1in(FIO_GPE_SCE_MEMORY_SET, 0, NULL),
	TE2(FIO_GPE_SCE_MEMORY_GET, 0, 0, NULL),
#endif
	TE2(FIO_GPE_SCE_VERSION_GET,
		sizeof(struct sce_pe_index),
		sizeof(struct sce_version),
		gpe_sce_version_get),

	TE1in(FIO_GPE_LOW_LEVEL_MODULES_ENABLE,
		sizeof(struct gpe_ll_mod_sel),
		gpe_low_level_modules_enable),

	TE1in(FIO_GPE_ETHERTYPE_FILTER_CFG_SET,
		sizeof(struct gpe_ethertype_filter_cfg),
		gpe_ethertype_filter_cfg_set),
	TE2(FIO_GPE_ETHERTYPE_FILTER_CFG_GET,
		sizeof(struct gpe_ethertype_filter_index),
		sizeof(struct gpe_ethertype_filter_cfg),
		gpe_ethertype_filter_cfg_get),

	TE1in(FIO_GPE_TOKEN_BUCKET_SHAPER_CREATE,
		sizeof(struct gpe_token_bucket_shaper),
		gpe_token_bucket_shaper_create),
	TE1in(FIO_GPE_TOKEN_BUCKET_SHAPER_DELETE,
		sizeof(struct gpe_token_bucket_shaper),
		gpe_token_bucket_shaper_delete),
	TE2(FIO_GPE_TOKEN_BUCKET_SHAPER_GET,
		sizeof(struct gpe_token_bucket_shaper_idx),
		sizeof(struct gpe_token_bucket_shaper),
		gpe_token_bucket_shaper_get),
	TE2(FIO_GPE_TOKEN_BUCKET_SHAPER_STATUS_GET,
		sizeof(struct gpe_token_bucket_shaper_idx),
		sizeof(struct gpe_token_bucket_shaper_status),
		gpe_token_bucket_shaper_status_get),

	TE2(FIO_GPE_EGRESS_QUEUE_GET,
		sizeof(struct gpe_equeue),
		sizeof(struct gpe_equeue_create),
		gpe_egress_queue_get),

	TE2(FIO_GPE_SCHEDULER_GET,
		sizeof(struct gpe_scheduler_idx),
		sizeof(struct gpe_sched_create),
		gpe_scheduler_get),
	TE2(FIO_GPE_SCHEDULER_STATUS_GET,
		sizeof(struct gpe_scheduler_idx),
		sizeof(struct gpe_scheduler_status),
		gpe_scheduler_status_get),

	TE1in(FIO_GPE_EGRESS_PORT_CREATE,
		sizeof(struct gpe_eport_create),
		gpe_egress_port_create),
	TE2(FIO_GPE_EGRESS_PORT_GET,
		sizeof(struct gpe_epn),
		sizeof(struct gpe_eport_create),
		gpe_egress_port_get),
	TE1in(FIO_GPE_EGRESS_PORT_DELETE,
		sizeof(struct gpe_egress_port),
		gpe_egress_port_delete),
	TE2(FIO_GPE_EGRESS_PORT_STATUS_GET,
		sizeof(struct gpe_epn),
		sizeof(struct gpe_egress_port_status),
		gpe_egress_port_status_get),
	TE1in(FIO_GPE_FLAT_EGRESS_PATH_CREATE,
		sizeof(struct gpe_flat_egress_path),
		gpe_flat_egress_path_create),
	TE1out(FIO_GPE_SHARED_BUFFER_CFG_GET,
		sizeof(struct gpe_shared_buffer_cfg),
		gpe_shared_buffer_cfg_get),
	TE1in(FIO_GPE_SHARED_BUFFER_CFG_SET,
		sizeof(struct gpe_shared_buffer_cfg),
		gpe_shared_buffer_cfg_set),

	TE1in_opt(FIO_GPE_FSQM_CHECK,
		sizeof(uint16_t),
		gpe_fsqm_check),

	TE2(FIO_GPE_EGRESS_QUEUE_PATH_GET,
		sizeof(struct gpe_equeue),
		sizeof(struct gpe_equeue_path),
		gpe_egress_queue_path_get),
	TE1in(FIO_GPE_IQM_GLOBAL_CFG_SET,
		sizeof(struct gpe_iqm_global_cfg),
		gpe_iqm_global_cfg_set),
	TE1out(FIO_GPE_IQM_GLOBAL_CFG_GET,
		sizeof(struct gpe_iqm_global_cfg),
		gpe_iqm_global_cfg_get),
	TE1out(FIO_GPE_IQM_GLOBAL_STATUS_GET,
		sizeof(struct gpe_iqm_global_status),
		gpe_iqm_global_status_get),
	TE1out(FIO_GPE_TMU_GLOBAL_CFG_GET,
		sizeof(struct gpe_tmu_global_cfg),
		gpe_tmu_global_cfg_get),
	TE1out(FIO_GPE_TMU_GLOBAL_STATUS_GET,
		sizeof(struct gpe_tmu_global_status),
		gpe_tmu_global_status_get),
	TE2(FIO_GPE_INGRESS_QUEUE_STATUS_GET,
		sizeof(struct gpe_iqueue),
		sizeof(struct gpe_iqueue_status),
		gpe_ingress_queue_status_get),
	TE1in(FIO_GPE_GEM_PORT_SET,
		sizeof(struct gpe_gem_port),
		gpe_gem_port_set),

	TE1in_opt(FIO_GPE_COP_DOWNLOAD,
		sizeof(struct cop_download_cfg),
		gpe_cop_download),

	TE1in(FIO_GPE_ICTRLC_WRITE,
		sizeof(struct ictrlc_write),
		gpe_iqueue_write_debug),

	TE1in(FIO_GPE_LAN_EXCEPTION_CFG_SET,
		sizeof(struct gpe_lan_exception_cfg),
		gpe_lan_exception_cfg_set),
	TE2(FIO_GPE_LAN_EXCEPTION_CFG_GET,
		sizeof(struct gpe_lan_exception_idx),
		sizeof(struct gpe_lan_exception_cfg),
		gpe_lan_exception_cfg_get),
	TE1in(FIO_GPE_ANI_EXCEPTION_CFG_SET,
		sizeof(struct gpe_ani_exception_cfg),
		gpe_ani_exception_cfg_set),
	TE2(FIO_GPE_ANI_EXCEPTION_CFG_GET,
		sizeof(struct gpe_ani_exception_idx),
		sizeof(struct gpe_ani_exception_cfg),
		gpe_ani_exception_cfg_get),
	TE1in(FIO_GPE_EXCEPTION_QUEUE_CFG_SET,
		sizeof(struct gpe_exception_queue_cfg),
		gpe_exception_queue_cfg_set),
	TE2(FIO_GPE_EXCEPTION_QUEUE_CFG_GET,
		sizeof(struct gpe_exception_queue_idx),
		sizeof(struct gpe_exception_queue_cfg),
		gpe_exception_queue_cfg_get),
	TE2(FIO_GPE_TR181_COUNTER_GET,
		sizeof(struct gpe_tr181_counters_cfg),
		sizeof(struct gpe_tr181_counters),
		gpe_tr181_counter_get),
	TE2(FIO_GPE_PORT_INDEX_GET,
		sizeof(struct gpe_egress_port),
		sizeof(struct gpe_eport_create),
		gpe_port_index_get),
	TE1out(FIO_GPE_CAPABILITY_GET,
	       sizeof(struct gpe_capability),
	       gpe_capability_get),
	TE1in(FIO_GPE_EXCEPTION_PROFILE_CFG_SET,
		sizeof(struct gpe_exception_profile_cfg),
		gpe_exception_profile_cfg_set),
	TE2(FIO_GPE_EXCEPTION_PROFILE_CFG_GET,
		sizeof(struct gpe_exception_profile_idx),
		sizeof(struct gpe_exception_profile_cfg),
		gpe_exception_profile_cfg_get),

	TE1in(FIO_GPE_EGRESS_PORT_ENABLE,
		sizeof(struct gpe_epn),
		gpe_egress_port_enable),
	TE1in(FIO_GPE_EGRESS_PORT_DISABLE,
		sizeof(struct gpe_epn),
		gpe_egress_port_disable),

	TE1in(FIO_GPE_DEBUG_INIT,
		sizeof(struct gpe_init_data),
		gpe_debug_init),

	TE2(FIO_GPE_BRIDGE_PORT_COUNTER_GET,
		sizeof(struct gpe_bridge_port_cnt_interval),
		sizeof(struct gpe_bridge_port_counter),
		gpe_bridge_port_counter_get),
	TE1in(FIO_GPE_BRIDGE_PORT_COUNTER_THRESHOLD_SET,
		sizeof(struct gpe_cnt_bridge_port_threshold),
		gpe_bridge_port_counter_threshold_set),
	TE2(FIO_GPE_BRIDGE_PORT_COUNTER_THRESHOLD_GET,
		sizeof(struct gpe_bridge_port_index),
		sizeof(struct gpe_cnt_bridge_port_threshold),
		gpe_bridge_port_counter_threshold_get),
	TE2(FIO_GPE_BRIDGE_PORT_TCA_GET,
		sizeof(struct gpe_bridge_port_index),
		sizeof(struct gpe_cnt_bridge_port_threshold),
		gpe_bridge_port_tca_get),
	TE1in(FIO_GPE_BRIDGE_PORT_COUNTER_RESET,
		sizeof(struct gpe_bridge_port_cnt_interval),
		gpe_bridge_port_counter_reset),
};

const unsigned int gpe_function_table_size = ARRAY_SIZE(gpe_function_table);

/*! @} */

/*! @} */
