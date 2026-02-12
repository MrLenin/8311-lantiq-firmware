/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#include "ifxos_time.h"

#include "drv_onu_api.h"
#include "drv_onu_gpe_interface.h"
#include "drv_onu_gtc_interface.h"
#include "drv_onu_register.h"
#include "drv_onu_ll_sys.h"
#include "drv_onu_ll_sce.h"
#include "drv_onu_ll_cop.h"
#include "drv_onu_event_interface.h"
#include "drv_onu_tse_config.h"
#include "drv_onu_ethertypes.h"
#include "drv_onu_gpe_tables_api.h"

#define PE_TIMEOUT 1000

/** \addtogroup ONU_MAPI_REFERENCE_INTERNAL
   @{
*/

/** \addtogroup ONU_GPE_INTERNAL
   @{
*/

static const uint32_t sce_offset = ONU_PE0_SIZE/4;

#if defined(INCLUDE_SCE_DEBUG)
struct sce_break_point_info {
	uint32_t addr;
	uint32_t vm;
	bool valid;
};

static struct sce_break_point_info breakpoints[ONU_GPE_NUMBER_OF_PE_MAX]
							[SCE_MAX_BREAKPOINTS];
#endif /* INCLUDE_SCE_DEBUG */

enum operation {
	ON,
	OFF,
	SET,
	GET
};

enum runmode {
	RUN,
	STEP,
	STEPOVER
};

static const uint32_t group_empty    = 0;
static       uint32_t group_serviced = 0;
static       uint32_t group_break    = 0x777777;

extern onu_lock_t sce_lock;

#define PROG_DEBUG	0
#define HOST_DEBUG	0
#define STACK_LEVELS	8
#define PC_MASK 	0xFFF8

#define MACRO STATIC INLINE

STATIC uint32_t pe_reg_read(enum vm vm, enum sce_reg i);
STATIC void pe_reg_write(enum vm vm, enum sce_reg i, uint32_t data);

/*
 * VM
*/
MACRO bool vm_is_member(uint32_t group, enum vm vm)
{
	return (group & (1<<vm)) != 0;
}

MACRO uint32_t vm_make_member(uint32_t group, enum vm vm)
{
	return group | (1<<vm);
}

MACRO uint32_t join(uint32_t group1, uint32_t group2)
{
	return group1 | group2;
}

MACRO uint8_t vm_to_pe(enum vm vm)
{
	return (uint8_t) (vm>>2);
}

MACRO uint32_t vm_to_vm_group(enum vm vm)
{
	return (uint32_t) (1<<vm);
}

MACRO uint32_t pe_to_vm_group(uint8_t pe_idx)
{
	return (uint32_t) (0x7<<(pe_idx<<2));
}

MACRO bool pe_is_member(uint32_t group, uint8_t pe_idx)
{
	return (group & (pe_to_vm_group(pe_idx))) != 0;
}

/*
 * VM control Interface
 */

MACRO uint32_t vm_status(void)
{
	return (uint32_t) pctrl_r32(tstat0);
}

MACRO void vm_step(uint32_t group)
{
	pctrl_w32(group, tstep0);
}

MACRO uint32_t vm_breakhit(uint32_t group, enum operation op)
{
	switch (op) {
	case OFF:
		pctrl_w32(group, bstat0);
		return group;
	case GET:
		return (uint32_t) pctrl_r32(bstat0);
	default:
		return group_empty;
	}
}

MACRO uint32_t vm_breakdis(uint32_t group, enum operation op)
{
	switch (op) {
	case OFF:
		pctrl_w32(group, bdis0);
		return group;
	case GET:
		return (uint32_t) pctrl_r32(bdis0);
	default:
		return group_empty;
	}
}

MACRO void vm_thread_inten(enum operation op)
{
	uint32_t mask = 0x03FF87FF;
	uint32_t prev_mask = 0;
	switch (op) {
		case ON:
			prev_mask = pctrl_r32(ictrl0);
			pctrl_w32(prev_mask | mask, ictrl0);
			prev_mask = pctrl_r32(ictrl1);
			pctrl_w32(prev_mask | mask, ictrl1);
			prev_mask = pctrl_r32(ictrl2);
			pctrl_w32(prev_mask | mask, ictrl2);
			prev_mask = pctrl_r32(ictrl3);
			pctrl_w32(prev_mask | mask, ictrl3);
			break;
		case OFF:
			prev_mask = pctrl_r32(ictrl0);
			pctrl_w32(prev_mask & ~mask, ictrl0);
			prev_mask = pctrl_r32(ictrl1);
			pctrl_w32(prev_mask & ~mask, ictrl1);
			prev_mask = pctrl_r32(ictrl2);
			pctrl_w32(prev_mask & ~mask, ictrl2);
			prev_mask = pctrl_r32(ictrl3);
			pctrl_w32(prev_mask & ~mask, ictrl3);
			break;
		default:
			/* do nothing*/
			break;
	}
}

MACRO uint32_t vm_error(uint32_t group, enum operation op)
{
	switch (op) {
	case OFF:
		pctrl_w32(group, terr);
		return group;
	case GET:
		return (uint32_t) pctrl_r32(terr);
	default:
		return group_empty;
	}
}

MACRO uint32_t vm_enable(uint32_t group, enum operation op)
{
	uint32_t group_prev;

	if (op != SET)
		group_prev = (uint32_t) pctrl_r32(tctrl0);

	switch (op) {
	case ON:
		pctrl_w32(group_prev | group, tctrl0);
		return group_prev;
	case OFF:
		pctrl_w32(group_prev &~group, tctrl0);
		return group_prev;
	case SET:
		pctrl_w32(group, tctrl0);
		return group;
	case GET:
		return group_prev;
	default:
		return group_empty;
	}
}

MACRO uint32_t vm_debug(uint32_t group, enum operation op)
{
	uint32_t group_prev;

	if (op != SET)
		group_prev = (uint32_t) pctrl_r32(tdebug0);

	switch (op) {
	case ON:
		pctrl_w32(group_prev | group, tdebug0);
		return group_prev;
	case OFF:
		pctrl_w32(group_prev &~group, tdebug0);
		return group_prev;
	case SET:
		pctrl_w32(group, tdebug0);
		return group;
	case GET:
		return group_prev;
	default:
		return group_empty;
	}
}

MACRO uint32_t vm_break(uint32_t group, enum operation op)
{
	uint32_t group_prev;

	if (op != SET)
		group_prev = (uint32_t) pctrl_r32(bctrl0);

	switch (op) {
	case ON:
		pctrl_w32(group_prev | group, bctrl0);
		return group_prev;
	case OFF:
		pctrl_w32(group_prev &~group, bctrl0);
		return group_prev;
	case SET:
		pctrl_w32(group, bctrl0);
		return group;
	case GET:
		return group_prev;
	default:
		return group_empty;
	}
}

MACRO uint32_t pe_offset_get(const uint8_t idx)
{
	if (idx < ONU_GPE_NUMBER_OF_PE_MAX)
		return sce_offset * idx;
	else
		return 0;
}

MACRO void pe_prog_write(uint8_t pe_idx, int address, uint64_t data)
{
	if (pe_is_member(group_serviced, pe_idx)==false)
		return;

	address = address >> 2;

	pe_w32(pe_idx, data>>32, prog[address + 0]);
	pe_w32(pe_idx, (data & 0xffffffff), prog[address + 1]);
}

MACRO uint64_t pe_prog_read(uint8_t pe_idx, int address)
{
	uint64_t data;

	if (pe_is_member(group_serviced, pe_idx)==false)
		return 0xEEEEEEEEEEEEEEEEULL;

	address = address >> 2;

	data  = (uint32_t) pe_r32(pe_idx, prog[address + 0]);
	data  <<= 32;
	data |= (uint32_t) pe_r32(pe_idx, prog[address + 1]);
	return data;
}

MACRO void pe_host_write(enum vm vm, int i, uint32_t data)
{
	pe_w32(vm_to_pe(vm), data, host[i]);
}

MACRO uint32_t pe_host_read(enum vm vm, int i)
{
	return pe_r32(vm_to_pe(vm), host[i]);
}

MACRO uint32_t pe_stop(uint32_t vm_group)
{
	unsigned long flags = 0;

	onu_spin_lock_get(&sce_lock, &flags);

	vm_group = vm_group | vm_breakhit(0, GET);

	if (vm_group == 0) {
		onu_spin_lock_release(&sce_lock, flags);
		return vm_group;
	}

	group_serviced = group_serviced | vm_group;

	vm_enable(vm_group, OFF);
	vm_debug (vm_group, ON);

	onu_spin_lock_release(&sce_lock, flags);
	return vm_group;
}

MACRO void pe_exec_ops(enum vm vm, const uint64_t *ops, uint32_t num)
{
	uint32_t i = 0;
	uint8_t pe_idx = vm_to_pe(vm);
	while (i<num) {
		pe_prog_write(pe_idx, PROG_DEBUG, *(ops+i));
		vm_step(vm_to_vm_group(vm));
		i++;
	}
}

STATIC uint32_t pe_stack_read(enum vm vm, uint32_t *stack)
{
	static const uint64_t op_pop[] = {
		0x000000000001e000ULL,  /* return_: return */
	};

	int      i;
	int32_t  data;
	int32_t  sp=0;
	uint32_t st;

	st = pe_reg_read(vm, REG_ST);

	for (i=STACK_LEVELS-1; i>=0; i--) {
		pe_exec_ops(vm, op_pop, ARRAY_SIZE(op_pop));

		data = pe_reg_read(vm, REG_ST);
		if (data & (1<<23)) sp = i;

		if (stack != NULL) {
			stack[i] = (data-0x00000008) & PC_MASK;
		}
	}

	pe_reg_write(vm, REG_ST, st);

	return sp;
}

STATIC void pe_stack_write(enum vm vm, int32_t level, uint32_t data)
{
	static const uint64_t op_store[] = {
		/* load_st: ld.i %r10, [HOST_DATA0+HOST_DEBUG*4] */
		0x000001655a000000ULL | (HOST_DEBUG << 20),
		/* goto %r10 */
		0x000000000001c00aULL,
		/* call 0 */
		0x0000000000019000ULL,
		/* return */
		0x000000000001e000ULL
	};

	const uint64_t *op_pop = &op_store[4]; /* alias: optimized away */

	int      i;
	uint32_t st;
	uint32_t r10;

	level = (pe_stack_read(vm, NULL)+level-1) & (STACK_LEVELS-1);

	st  = pe_reg_read(vm, REG_ST);
	r10 = pe_reg_read(vm, REG_R10);

	for (i=STACK_LEVELS-1; i>=0; i--) {
		if (i == level) {
			pe_host_write(vm, HOST_DEBUG, data);
			pe_exec_ops(vm, op_store, ARRAY_SIZE(op_store));
		}

		pe_exec_ops(vm, op_pop, 1);
	}

	pe_reg_write(vm, REG_R10, r10);
	pe_reg_write(vm, REG_ST,  st);
}

STATIC void pe_reg_write(enum vm vm, enum sce_reg i, uint32_t data)
{
	static const uint64_t op_write_reg[] = {
		/* write_r0:  ld.i  %r0, [HOST_DATA0+HOST_DEBUG*4] */
		0x000001641a000000ULL | (HOST_DEBUG << 20),
		/* write_r1:  ld.i  %r1, [HOST_DATA0+HOST_DEBUG*4] */
		0x000001643a000000ULL | (HOST_DEBUG << 20),
		/* write_r2:  ld.i  %r2, [HOST_DATA0+HOST_DEBUG*4] */
		0x000001645a000000ULL | (HOST_DEBUG << 20),
		/* write_r3:  ld.i  %r3, [HOST_DATA0+HOST_DEBUG*4] */
		0x000001647a000000ULL | (HOST_DEBUG << 20),
		/* write_r4:  ld.i  %r4, [HOST_DATA0+HOST_DEBUG*4] */
		0x000001649a000000ULL | (HOST_DEBUG << 20),
		/* write_r5:  ld.i  %r5, [HOST_DATA0+HOST_DEBUG*4] */
		0x00000164ba000000ULL | (HOST_DEBUG << 20),
		/* write_r6:  ld.i  %r6, [HOST_DATA0+HOST_DEBUG*4] */
		0x00000164da000000ULL | (HOST_DEBUG << 20),
		/* write_r7:  ld.i  %r7, [HOST_DATA0+HOST_DEBUG*4] */
		0x00000164fa000000ULL | (HOST_DEBUG << 20),
		/* write_r8:  ld.i  %r8, [HOST_DATA0+HOST_DEBUG*4] */
		0x000001651a000000ULL | (HOST_DEBUG << 20),
		/* write_r9:  ld.i  %r9, [HOST_DATA0+HOST_DEBUG*4] */
		0x000001653a000000ULL | (HOST_DEBUG << 20),
		/* write_r10: ld.i  %r10,[HOST_DATA0+HOST_DEBUG*4] */
		0x000001655a000000ULL | (HOST_DEBUG << 20),
		/* write_r11: ld.i  %r11,[HOST_DATA0+HOST_DEBUG*4] */
		0x000001657a000000ULL | (HOST_DEBUG << 20),
		/* write_r12: ld.i  %r12,[HOST_DATA0+HOST_DEBUG*4] */
		0x000001659a000000ULL | (HOST_DEBUG << 20),
		/* write_r13: ld.i  %zero,[HOST_DATA0+HOST_DEBUG*4] */
		0x00000165ba000000ULL | (HOST_DEBUG << 20),
		/* write_fp:  ld.i  %fp,  [HOST_DATA0+HOST_DEBUG*4] */
		0x00000165da000000ULL | (HOST_DEBUG << 20)
	};
	static const uint64_t op_write_st[] = {
		/* write_t:   ld.i %r10, [HOST_DATA0+PE_HOST_DEBUG*4] */
		0x000001655a000000ULL | (HOST_DEBUG << 20),
		/* and  %r10, %r10, 1 */
		0xd0aa020000000000ULL,
		/* mov  %t, %r10 */
		0xd7da020000000000ULL,
		/* write_pc:  ld.i %r10, [HOST_DATA0+PE_HOST_DEBUG*4] */
		0x000001655a000000ULL | (HOST_DEBUG << 20),
		/* goto %r10 */
		0x000000000001c00aULL
	};

	static const uint64_t op_write_gp[] = {
		/* write_gp:  ld.i %r10,[HOST_DATA0+HOST_DEBUG*4] */
		0x000001655a000000ULL | (HOST_DEBUG << 20),
		/* mova %gp, %r10 */
		0x000000b1f4000000ULL
	};
	uint32_t r10;

	if (vm_is_member(group_serviced, vm)==false)
		return;

	switch (i) {
	case REG_SP:
		/* TODO: not implemented yet */
		return;
	case REG_L0:
	case REG_L1:
	case REG_L2:
	case REG_L3:
	case REG_L4:
	case REG_L5:
	case REG_L6:
	case REG_L7:
		pe_stack_write(vm, i-REG_L0, data);
		return;
	default:
		break;
	}

	pe_host_write(vm, HOST_DEBUG, data);

	switch (i) {
	case REG_SP:
	case REG_L0:
	case REG_L1:
	case REG_L2:
	case REG_L3:
	case REG_L4:
	case REG_L5:
	case REG_L6:
	case REG_L7:
		/* already handled above */
		break;
	case REG_T:
	case REG_PC:
	case REG_ST:
	case REG_GP:
		r10 = pe_reg_read(vm, REG_R10);
		switch (i) {
		case REG_T:
			pe_exec_ops(vm, &op_write_st[0], 3);
			break;
		case REG_PC:
			pe_exec_ops(vm, &op_write_st[3], 2);
			break;
		case REG_ST:
			pe_host_write(vm, HOST_DEBUG, data - 0x0008);
			pe_exec_ops(vm, op_write_st, ARRAY_SIZE(op_write_st));
			break;
		case REG_GP:
			pe_exec_ops(vm, op_write_gp, ARRAY_SIZE(op_write_gp));
			break;
		default:
			break;
		}
		pe_reg_write(vm, REG_R10, r10);
		break;
	default:
		/* i==REG_R0...REG_R14 */
		pe_prog_write(vm_to_pe(vm), PROG_DEBUG, op_write_reg[i]);
		vm_step(vm_to_vm_group(vm));
		break;
	}
}

STATIC uint32_t pe_reg_read(enum vm vm, enum sce_reg i)
{
	static const uint64_t op_read_reg[] = {
		/* read_r0:  st.i %r0,  [HOST_DATA0+HOST_DEBUG*4] */
		0x000001601a000000ULL | (HOST_DEBUG << 20),
		/* read_r1:  st.i %r1,  [HOST_DATA0+HOST_DEBUG*4] */
		0x000001603a000000ULL | (HOST_DEBUG << 20),
		/* read_r2:  st.i %r2,  [HOST_DATA0+HOST_DEBUG*4] */
		0x000001605a000000ULL | (HOST_DEBUG << 20),
		/* read_r3:  st.i %r3,  [HOST_DATA0+HOST_DEBUG*4] */
		0x000001607a000000ULL | (HOST_DEBUG << 20),
		/* read_r4:  st.i %r4,  [HOST_DATA0+HOST_DEBUG*4] */
		0x000001609a000000ULL | (HOST_DEBUG << 20),
		/* read_r5:  st.i %r5,  [HOST_DATA0+HOST_DEBUG*4] */
		0x00000160ba000000ULL | (HOST_DEBUG << 20),
		/* read_r6:  st.i %r6,  [HOST_DATA0+HOST_DEBUG*4] */
		0x00000160da000000ULL | (HOST_DEBUG << 20),
		/* read_r7:  st.i %r7,  [HOST_DATA0+HOST_DEBUG*4] */
		0x00000160fa000000ULL | (HOST_DEBUG << 20),
		/* read_r8:  st.i %r8,  [HOST_DATA0+HOST_DEBUG*4] */
		0x000001611a000000ULL | (HOST_DEBUG << 20),
		/* read_r9:  st.i %r9,  [HOST_DATA0+HOST_DEBUG*4] */
		0x000001613a000000ULL | (HOST_DEBUG << 20),
		/* read_r10: st.i %r10, [HOST_DATA0+HOST_DEBUG*4] */
		0x000001615a000000ULL | (HOST_DEBUG << 20),
		/* read_r11: st.i %r11, [HOST_DATA0+HOST_DEBUG*4] */
		0x000001617a000000ULL | (HOST_DEBUG << 20),
		/* read_r12: st.i %r12, [HOST_DATA0+HOST_DEBUG*4] */
		0x000001619a000000ULL | (HOST_DEBUG << 20),
		/* read_r13: st.i %zero,[HOST_DATA0+HOST_DEBUG*4] */
		0x00000161ba000000ULL | (HOST_DEBUG << 20),
		/* read_fp:  st.i %fp,  [HOST_DATA0+HOST_DEBUG*4] */
		0x00000161da000000ULL | (HOST_DEBUG << 20),
		/* read_st:  st.i %st,  [HOST_DATA0+HOST_DEBUG*4] */
		0x00000161fa000000ULL | (HOST_DEBUG << 20)
	};
	static const uint64_t op_read_gp[] = {
		/* read_gp:  mova %r10, %gp */
		0x000000b15e000000ULL,
		/* st.i %r10, [HOST_DATA0+HOST_DEBUG*4] */
		0x000001615a000000ULL | (HOST_DEBUG << 20)
	};
	uint32_t data;
	uint32_t r10;
	uint32_t stack[STACK_LEVELS];
	uint32_t sp;

	if (vm_is_member(group_serviced, vm)==false)
		return 0xEEEEEEEE;

	switch (i) {
	case REG_GP:
		r10 = pe_reg_read(vm, REG_R10);
		pe_exec_ops(vm, op_read_gp, ARRAY_SIZE(op_read_gp));
		data = pe_host_read(vm, HOST_DEBUG);
		pe_reg_write(vm, REG_R10, r10);
		break;
	case REG_T:
	case REG_PC:
		pe_prog_write(vm_to_pe(vm), PROG_DEBUG, op_read_reg[REG_ST]);
		vm_step(vm_to_vm_group(vm));
		data = pe_host_read(vm, HOST_DEBUG);
		if (i == REG_T)
			data &= 1;
		else
			data &= PC_MASK;
		break;
	case REG_SP:
	case REG_L0:
	case REG_L1:
	case REG_L2:
	case REG_L3:
	case REG_L4:
	case REG_L5:
	case REG_L6:
	case REG_L7:
		sp = pe_stack_read(vm, stack);

		if (i == REG_SP)
			data = (STACK_LEVELS - sp) & (STACK_LEVELS-1);
		else
			data = stack[(sp + i - REG_L0) & (STACK_LEVELS-1)];
		break;
	default:
		pe_prog_write(vm_to_pe(vm), PROG_DEBUG, op_read_reg[i]);
		vm_step(vm_to_vm_group(vm));
		data = pe_host_read(vm, HOST_DEBUG);

		if (i == REG_ST)
			data += 8;
		break;
	}

	return data;
}

/** sce_fw_init Hardware Programming Details
   Each of the ONU_GPE_NUMBER_OF_PE_MAX Processing Elements is loaded with its
   FW code into its code memory and with configuration data into its data
   memory. By pre-loading the data memory, the local tables are automatically
   initialized.
   Code and data are identical for all Processing Elements.
*/
int sce_fw_init(const struct sce_fw_init *param, const uint8_t num_pe)
{
	uint32_t i, len;
	uint32_t *data;
	uint8_t idx;
	uint8_t start, stop;

	if (param->code.pe_index == 0xFF) {
		start = 0;
		stop = num_pe - 1;
	} else {
		start = stop = param->code.pe_index;
	}

	data = param->code.data;
	len = param->code.len / 4;
	if (data == NULL || len == 0)
		return -1;

	/**
	\todo - stop all PEx, reset PC ? really necessary with reset above???*/
	for (idx = start; idx <= stop; idx++) {
		/* clear threads, should not be running */
		pe_stop(pe_to_vm_group(idx));
		vm_break(pe_to_vm_group(idx), OFF);
		vm_breakhit(pe_to_vm_group(idx), OFF);

		/* hardware reset of PE */
		sys_gpe_hw_activate_or_reboot(SYS_GPE_ACTS_PE0 << idx);

		/* clear HOST0 HOST1 */
		pe_w32(idx, 0, host[0]);
		/** \todo set RVAL ? */

		/* copy firmware */
		for (i = 0; i < len; i++)
			pe_w32(idx, data[i], prog[i]);

		/* enable hardware for breakpoints */
		vm_break(~group_empty, ON);
#if defined(INCLUDE_SCE_DEBUG)
		for (i = 0; i < SCE_MAX_BREAKPOINTS; i++) {
			breakpoints[idx][i].addr = 0;
			breakpoints[idx][i].valid = false;
		}
#endif
	}
	/* enable the CPU signal interrupt for all PEs */
	vm_thread_inten(ON);

	return 0;
}

int sce_init(const uint8_t num_pe)
{
	static const uint32_t act_mask[ONU_GPE_NUMBER_OF_PE_MAX] = {
					SYS_GPE_ACT_PE0_SET,

					SYS_GPE_ACT_PE0_SET
				      | SYS_GPE_ACT_PE1_SET,

					SYS_GPE_ACT_PE0_SET
				      | SYS_GPE_ACT_PE1_SET
				      | SYS_GPE_ACT_PE2_SET,
				      
					SYS_GPE_ACT_PE0_SET
				      | SYS_GPE_ACT_PE1_SET
				      | SYS_GPE_ACT_PE2_SET
				      | SYS_GPE_ACT_PE3_SET,

					SYS_GPE_ACT_PE0_SET
				      | SYS_GPE_ACT_PE1_SET
				      | SYS_GPE_ACT_PE2_SET
				      | SYS_GPE_ACT_PE3_SET
				      | SYS_GPE_ACT_PE4_SET,

					SYS_GPE_ACT_PE0_SET
				      | SYS_GPE_ACT_PE1_SET
				      | SYS_GPE_ACT_PE2_SET
				      | SYS_GPE_ACT_PE3_SET
				      | SYS_GPE_ACT_PE4_SET
				      | SYS_GPE_ACT_PE5_SET
	};

	if (num_pe > ONU_GPE_NUMBER_OF_PE_MAX || !num_pe)
		return -1;

	/* activate clock */
	sys_gpe_hw_activate_or_reboot(act_mask[num_pe - 1]
				      | SYS_GPE_ACT_MRG_SET
				      | SYS_GPE_ACT_DISP_SET);

	return 0;
}

int sce_merge_init(void)
{
	uint32_t cnt;

	cnt = 100;
	/* Start RAM initialization (CTRL.INIT_START)*/
	merge_w32_mask(0, MERGE_CTRL_INITSTART_EN, ctrl);

	/*  Wait for completion (CTRL.INIT_DONE)*/
	while (cnt-- && !(merge_r32(ctrl) & MERGE_CTRL_INITDONE))
		onu_udelay(10);

	if (cnt == 0)
		return -1;

	return 0;
}

void sce_merge_enable(bool act)
{
	merge_w32_mask(MERGE_CTRL_ACT_EN, act ? MERGE_CTRL_ACT_EN : 0, ctrl);
}

bool sce_merge_is_enabled(void)
{
	return (merge_r32(ctrl) & MERGE_CTRL_ACT_EN) ? true : false;
}

void sce_dispatcher_enable(bool act)
{
	disp_w32_mask(DISP_CTRL_ACT_EN, act ? DISP_CTRL_ACT_EN : 0, ctrl);
}

bool sce_dispatcher_is_enabled(void)
{
	return (disp_r32(ctrl) & DISP_CTRL_ACT_EN) ? true : false;
}

/** sce_fw_code_read Hardware Programming Details
   The code memory of a single Processing Element is read back.

      \todo fw code read hw details
*/
int sce_fw_code_read(struct sce_fw_data *param)
{
	uint32_t i, len = param->len / 4;
	uint32_t *data = param->data;

	if (pe_is_member(group_serviced, param->pe_index) == false)
		return -1;

	for (i = 0; i < len; i++)
		data[i] = pe_r32(param->pe_index, prog[i]);

	return 0;
}

int sce_io_fw_pe_write16(const uint8_t pe_index, const uint16_t cmd,
			 const uint16_t pdata)
{
	uint32_t data = (uint32_t)pdata | ((uint32_t)pe_index << 27);
	(void)cmd;

	while (pe_r32(pe_index, host[0]) & CMD_RVAL) {
	}

	pe_w32(pe_index, data, host[0]);

	while ((pe_r32(pe_index, host[0]) & CMD_RVAL) == 0) {
	}

	data = pe_r32(pe_index, host[0]);

	pe_w32(pe_index, 0, host[0]);

	return data & CMD_ERR ? -1 : 0;
}

int sce_io_fw_pe_read16(const uint8_t pe_index, const uint16_t cmd,
			uint16_t *pdata)
{
	uint32_t data = (uint32_t)pe_index << 27;
	(void)cmd;

	while (pe_r32(pe_index, host[0]) & CMD_RVAL) {
	}

	pe_w32(pe_index, data, host[0]);

	while ((pe_r32(pe_index, host[0]) & CMD_RVAL) == 0) {
	}

	data = pe_r32(pe_index, host[0]);

	*pdata = data & 0xFFFF;

	pe_w32(pe_index, 0, host[0]);

	return data & CMD_ERR ? -1 : 0;
}

int sce_io_fw_pe_write32(const uint8_t pe_index, const uint16_t cmd_high,
			 const uint16_t cmd_low, uint32_t data)
{
	if (sce_io_fw_pe_write16(pe_index, cmd_high, data >> 16) == 0 &&
	    sce_io_fw_pe_write16(pe_index, cmd_low, data & 0xFFFF) == 0)
		return 0;

	return -1;
}

int sce_io_fw_pe_read32(const uint8_t pe_index, const uint16_t cmd_high,
			const uint16_t cmd_low, uint32_t *data)
{
	uint16_t low, high;
	if (sce_io_fw_pe_read16(pe_index, cmd_high, &high) == 0 &&
	    sce_io_fw_pe_read16(pe_index, cmd_low, &low) == 0) {
		*data = ((uint32_t)high << 16) | low;
		return 0;
	}
	return -1;
}

void modify_code(const uint8_t pe_index, const uint16_t pc, const bool enable)
{
	uint32_t instr;

	if (enable) {
		/* set breakpoint bit in program memory */
		instr = pe_r32(pe_index, prog[pc]);
		pe_w32(pe_index, instr | (1 << 17), prog[0]);
	} else {
		/* clear breakpoint bit in program memory */
		instr = pe_r32(pe_index, prog[pc]);
		pe_w32(pe_index, instr & ~(1 << 17), prog[0]);
	}
}

STATIC void sce_fw_pe_runmode(uint32_t vm_group, enum runmode mode)
{
	uint32_t debug_group;
	unsigned long flags = 0;

	onu_spin_lock_get(&sce_lock, &flags);

	if (vm_group == 0)
		vm_group = group_serviced;

	vm_group = vm_group & group_serviced;
	if (vm_group == 0) {
		onu_spin_lock_release(&sce_lock, flags);
		return;
	}

	debug_group = vm_debug(vm_group, OFF);
	vm_error(vm_group, OFF);
	vm_break(vm_group, OFF);
	vm_breakhit(vm_group, OFF);

	/* step ... (also over current breakpoint, if there) */
	vm_step(vm_group);

	/* ... then run */
	if (mode == RUN) {
		vm_break(group_break, SET);
		vm_enable(vm_group, ON);
		group_serviced = group_serviced & ~vm_group;
	} else {
		/* restore debug state */
		vm_debug(debug_group, SET);
	}

	onu_spin_lock_release(&sce_lock, flags);
}

#if defined(INCLUDE_SCE_DEBUG)
STATIC void pe_data_wr32(enum vm vm, uint32_t address, uint32_t data)
{
	static const uint64_t op_write_mem[] = {
		/* ld.i %r10, [HOST_DATA0+HOST_DEBUG*4] */
		0x000001655a000000ULL | (HOST_DEBUG << 20),
		/* ld.i %r11, [HOST_DATA0+HOST_DEBUG*4] */
		0x000001657a000000ULL | (HOST_DEBUG << 20),
		/* st.i %r11, [%r10] */
		0x0000016174000000ULL
	};
	uint32_t r10;
	uint32_t r11;

	if (vm_is_member(group_serviced, vm) == false)
		return;

	r10 = pe_reg_read(vm, REG_R10);
	r11 = pe_reg_read(vm, REG_R11);

	pe_host_write(vm, HOST_DEBUG, address);
	pe_exec_ops(vm, &op_write_mem[0], 1);

	pe_host_write(vm, HOST_DEBUG, data);
	pe_exec_ops(vm, &op_write_mem[1], 2);

	pe_reg_write(vm, REG_R11, r11);
	pe_reg_write(vm, REG_R10, r10);
}

STATIC uint32_t pe_data_rd32(enum vm vm, uint32_t address)
{
	static const uint64_t op_write_mem[] = {
		/* ld.i %r10, [HOST_DATA0+HOST_DEBUG*4] */
		0x000001655a000000ULL | (HOST_DEBUG << 20),
		/* ld.i %r10, [%r10] */
		0x0000016554000000ULL,
		/* st.i %r10, [HOST_DATA0+HOST_DEBUG*4] */
		0x000001615a000000ULL | (HOST_DEBUG << 20)
	};

	uint32_t r10;
	uint32_t data;

	if (vm_is_member(group_serviced, vm) == false)
		return 0;

	r10 = pe_reg_read(vm, REG_R10);

	pe_host_write(vm, HOST_DEBUG, address);
	pe_exec_ops(vm, op_write_mem, ARRAY_SIZE(op_write_mem));
	data = pe_host_read(vm, HOST_DEBUG);

	pe_reg_write(vm, REG_R10, r10);

	return data;
}

int sce_fw_breakpoint_set(const enum vm vm, const uint32_t addr)
{
	uint64_t data;
	int i;
	uint8_t pe_idx = vm_to_pe(vm);

	if (vm_is_member(group_serviced, vm) == false)
		return -1;

	for (i = 0; i < SCE_MAX_BREAKPOINTS; i++) {
		if (breakpoints[pe_idx][i].valid &&
		    breakpoints[pe_idx][i].addr != addr)
			continue;
		data = pe_prog_read(pe_idx, addr);
		pe_prog_write(pe_idx, addr, data | (1<<17));
		breakpoints[pe_idx][i].addr = addr;
		breakpoints[pe_idx][i].valid = true;
		return 0;
	}
	return -1;
}

int sce_fw_breakpoint_get(const enum vm vm, const uint32_t idx, uint32_t *addr)
{
	uint8_t pe_idx = vm_to_pe(vm);
	if (pe_idx >= ONU_GPE_NUMBER_OF_PE_MAX || idx >= SCE_MAX_BREAKPOINTS ||
	    breakpoints[pe_idx][idx].valid == false) {
		*addr = 0;
		return -1;
	}
	*addr = breakpoints[pe_idx][idx].addr;
	return 0;
}

int sce_fw_breakpoint_remove(const enum vm vm, const uint32_t addr)
{
	uint64_t data;
	int i;
	uint8_t pe_idx = vm_to_pe(vm);

	if (vm_is_member(group_serviced, vm) == false)
		return -1;

	for (i = 0; i < SCE_MAX_BREAKPOINTS; i++) {
		if (breakpoints[pe_idx][i].valid == false)
			continue;
		if (breakpoints[pe_idx][i].addr != addr)
			continue;
		data = pe_prog_read(pe_idx, addr);
		pe_prog_write(pe_idx, addr, data & ~(1<<17));
		breakpoints[pe_idx][i].addr = 0;
		breakpoints[pe_idx][i].valid = false;
		return 0;
	}
	return -1;
}

int sce_fw_pe_reg_set(const enum vm vm, enum sce_reg reg, uint32_t val)
{
	pe_reg_write(vm, reg, val);
	return 0;
}

int sce_fw_pe_reg_get(const enum vm vm, enum sce_reg reg, uint32_t *val)
{
	*val = pe_reg_read(vm, reg);
	return 0;
}

int sce_fw_pe_memset(const enum vm vm, const uint32_t addr, uint32_t val)
{
	pe_data_wr32(vm, addr, val);
	return 0;
}

int sce_fw_pe_memget(const enum vm vm, const uint32_t addr, uint32_t *val)
{
	*val = pe_data_rd32(vm, addr);
	return 0;
}

int sce_fw_pe_break(const uint32_t vm_group)
{
	vm_error(vm_group, OFF);
	vm_break(vm_group, OFF);
	vm_breakhit(vm_group, OFF);
	pe_stop(vm_group);
	return 0;
}

int sce_fw_pe_break_check(uint32_t *vm_group)
{
	/* with param 0 only the mask of reached breakpoints will be returned */
	*vm_group = pe_stop(0);

	/* clear bstat0 bits */
	if (*vm_group) {
		vm_break(*vm_group, OFF);
		vm_breakhit(*vm_group, OFF);
	}

	return 0;
}

int sce_fw_pe_restart(const enum vm vm)
{
	(void)vm;

	/** \todo */
	return -1;
}

int sce_fw_pe_single_step(const enum vm vm)
{
	sce_fw_pe_runmode(vm_to_vm_group(vm), STEP);
	return 0;
}

int sce_fw_pe_pc_set(const enum vm vm, const uint32_t pc)
{
	uint32_t pe_index, t = vm;
	uint32_t mask_all = 0x07;
	uint32_t mask_one = 0x01;
	(void)pc;

	for (pe_index = 0; pe_index < ONU_GPE_NUMBER_OF_PE_MAX; pe_index++) {
		if (t & 0x7) {
		}
		t = t >> 3;
		mask_all = mask_all << 4;
		mask_one = mask_one << 4;
	}

	return 0;
}

int sce_fw_pe_pc_get(const enum vm vm, uint32_t *pc)
{
	sce_fw_pe_reg_get(vm, REG_ST, pc);

	*pc = (*pc & 0xfff8) - 8;

	return 0;
}
#endif /* defined(INCLUDE_SCE_DEBUG)*/

void sce_fw_pe_run(const uint32_t vm_group)
{
	sce_fw_pe_runmode(vm_group, RUN);
}

/* SCE_IO_CfgSet Hardware Programming Details
   Each of the ONU_GPE_NUMBER_OF_THREADS PE threads is configured individually.

   DISP.TCTRL0: controls threads 0 to 31
   DISP.TCTRL1: controls threads 32 to ONU_GPE_NUMBER_OF_THREADS-1
*/
int sce_fw_cfg_set(const struct sce_fw_cfg *param)
{
	(void)param;
	return -1;
}

/** SCE_IO_CfgGet Hardware Programming Details
   Read back th econfiguration of a selected Processing Element.

      \todo fw cfg get hw details
*/
int sce_fw_cfg_get(struct sce_fw_cfg *param)
{
	(void)param;
	return -1;
}

/* SCE_IO_StatusGet Hardware Programming Details
   Read back the status of the SCE.

   DISP.TSTAT0: status of threads 0 to 31
   DISP.TSTAT1: status of threads 32 to ONU_GPE_NUMBER_OF_THREADS-1
   DISP.LFIFO0 to LFIFO11: status of Link FIFOs
*/
int sce_fw_status_get(uint32_t *tstat, uint32_t *terr,
		      uint32_t *tctrl, uint32_t *tdebug,
		      uint32_t *bctrl, uint32_t *bstat,
		      uint32_t *bdis)
{
	*tstat = vm_status();
	*terr = vm_error(0, GET);
	*tctrl = vm_enable(0, GET);
	*tdebug = vm_debug(0, GET);
	*bctrl = vm_break(0, GET);
	*bstat = vm_breakhit(0, GET);
	*bdis = vm_breakdis(0, GET);

	return 0;
}

bool is_pe_table_supported(const uint8_t pe_idx,
			   const struct pe_fw_info *info,
			   const uint32_t id)
{
	uint32_t num;
	struct pe_fw_fhdr_entry *hdr;

	if (!info->opt_hdr)
		return true;

	num = info->opt_hdr_len / sizeof(struct pe_fw_fhdr_entry);

	if (id > num)
		return false;

	hdr = (struct pe_fw_fhdr_entry *)info->opt_hdr;

	if (id != hdr[id].tbl_idx)
		return false;

	if (!hdr[id].pe_mask)
		return false;

	if (hdr[id].pe_mask & (1 << pe_idx))
		return true;
	else
		return false;
}

/** Sync mailbox and wait for MIPS<->PE command completion

   \return -1 on command error
*/
STATIC enum pe_errorcode pe_wait(uint32_t pe_idx)
{
	uint32_t cnt = 0, sig;
	
	/*
	 * signal PEs mailbox to wakeup
	 * pe_idx = 0: SIG signal S0 to THREAD_0_0_0 (0), ISIG0
	 * pe_idx = 1: SIG signal S16 to THREAD_1_0_0 (16), ISIG0
	 * pe_idx = 2: SIG signal S32 to THREAD_2_0_0 (32), ISIG1 + ISIG0
	 * ... 
	 */
	if (pe_idx & 1)
		sig = 0x00010000;
	else
		sig = 0x1;
	if (pe_idx < 2)
		/* first two only need sig0 */
		pctrl_w32 (sig, isig0);
	else if (pe_idx < 4)
		pctrl_w32 (sig, isig1);
	else
		pctrl_w32 (sig, isig2);
	/* upper 4 need additional ISIG0 to wake up */
	if (pe_idx > 1)
		pctrl_w32 (0, isig0);
	
	while ((pe_r32(pe_idx, host[1]) & CMD_RVAL) == 0) {
		if (cnt >= PE_TIMEOUT)
			return PE_STATUS_TIMEOUT;
		cnt++;
	}
	if (pe_r32(pe_idx, host[0]) & CMD_ERR)
		return PE_STATUS_ERR;
	else
		return PE_STATUS_OK;
}

/** sce_fw_pe_message_send Hardware Programming Details
   data is sent from the software to the firmware.
*/
enum pe_errorcode sce_fw_pe_message_send(const struct sce_fw_pe_message *param)
{
	enum pe_errorcode ret;
	uint32_t i, host, data_1_8_len;

	/* write data[1:8] */
	data_1_8_len = (param->entry_width > 8) ? 8 : param->entry_width;

	for (i = 0; i < data_1_8_len; i++) {
		pe_w32(param->pe_index, param->message[i], host[i + 2]);
	}

	host = 1 << CMD_W_OFFSET;
	host |= param->table_id << CMD_T_NUM_OFFSET;
	host |= (param->entry_width - 1) << CMD_LENGTH_OFFSET;
	host |= (param->table_idx * param->entry_width) << CMD_BYTE_OFFSET;
	pe_w32(param->pe_index, host, host[1]);
	
	ret = pe_wait(param->pe_index);

	return ret;
}

/** sce_fw_pe_message_receive Hardware Programming Details
   Data is received by the software from the firmware.
*/
enum pe_errorcode sce_fw_pe_message_receive(struct sce_fw_pe_message *param)
{
	enum pe_errorcode ret;
	uint32_t i, host, data_1_8_len;

	/* read data[1:8] */
	data_1_8_len = (param->entry_width > 8) ? 8 : param->entry_width;

	host = param->table_id << CMD_T_NUM_OFFSET;
	host |= (param->entry_width - 1) << CMD_LENGTH_OFFSET;
	host |= (param->table_idx * param->entry_width) << CMD_BYTE_OFFSET;
	pe_w32(param->pe_index, host, host[1]);

	ret = pe_wait(param->pe_index);
	if (ret != PE_STATUS_OK)
		return ret;

	for (i = 0; i < data_1_8_len; i++)
		param->message[i] = pe_r32(param->pe_index, host[i + 2]);

	return ret;
}

#if defined(INCLUDE_DUMP)

void sce_dump(struct seq_file *s)
{
	uint32_t i;

	if (sys_gpe_hw_is_activated(SYS_GPE_ACT_PE0_SET |
					SYS_GPE_ACT_PE1_SET |
					SYS_GPE_ACT_PE2_SET |
					SYS_GPE_ACT_PE3_SET |
					SYS_GPE_ACT_PE4_SET |
					SYS_GPE_ACT_PE5_SET |
					SYS_GPE_ACT_MRG_SET |
					SYS_GPE_ACT_DISP_SET) == 0) {
		seq_printf(s, "sce not activated\n");
		return;
	}
	for (i = 0; i < 6; i++)
		seq_printf(s, "sce%d\n", i);
}


void merge_dump(struct seq_file *s)
{
	if (sys_gpe_hw_is_activated(SYS_GPE_ACT_PE0_SET |
					SYS_GPE_ACT_PE1_SET |
					SYS_GPE_ACT_PE2_SET |
					SYS_GPE_ACT_PE3_SET |
					SYS_GPE_ACT_PE4_SET |
					SYS_GPE_ACT_PE5_SET |
					SYS_GPE_ACT_MRG_SET |
					SYS_GPE_ACT_DISP_SET) == 0) {
		seq_printf(s, "sce not activated\n");
		return;
	}

#define dump_reg(reg) \
	seq_printf(s, "%-14s = 0x%08x\n", # reg, merge_r32(reg))

	dump_reg(ctrl);
	dump_reg(tctrl0);
	dump_reg(tctrl1);
	dump_reg(tctrl2);
	dump_reg(nilcounter);
	dump_reg(discardcounter);
	dump_reg(irnicr);
	dump_reg(link_data0);
	dump_reg(link_data1);
	dump_reg(tmu_link_data0);
	dump_reg(tmu_link_data1);

#undef dump_reg
}

#endif

/*! @} */

/*! @} */
