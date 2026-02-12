/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef _drv_onu_fsqm_h
#define _drv_onu_fsqm_h

/** \addtogroup ONU_LL_REFERENCE GPON Low-level Functions
   @{
*/

/** \addtogroup ONU_LL_FSQM Free Segment Queue Manager Low-level Functions

   Low-level functions to access the Free Segment Queue Manager (FSQM).
   @{
*/

/**
   This structure is used to hold the priority control attributes.
*/
struct fsqm_prio {
	uint8_t pcpu;
	uint8_t pictrl;
	uint8_t ppctrl;
	uint8_t poctrl;
	uint8_t piqm;
	uint8_t rr;
};

struct fsq {
	uint16_t head;
	uint16_t tail;
	uint16_t init_status;
};

/**
   Set Activate / Deactivate switch for FSQM state machines.
*/
void fsqm_enable(bool act);

/**
   Get Activate / Deactivate switch of  FSQM state machines.
*/
bool fsqm_is_enabled(void);

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
/**
   Set Soft Reset switch for FSQM state machines.
*/
void fsqm_reset_set(bool res);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
/**
   Get Soft Reset switch of  FSQM state machines.
*/
void fsqm_reset_get(bool *res);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
/**
   Set Priority Control for FSQM arbiter.
*/
void fsqm_prio_set(struct fsqm_prio * prio);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
/**
   Get Priority Control for FSQM arbiter.
*/
void fsqm_prio_get(struct fsqm_prio * prio);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

/**
   Initialize the FSQM block.
*/
void fsqm_init(struct fsq *p_fsq);

void fsqm_free_segment_threshold_set(const uint32_t threshold[5]);

void fsqm_free_segment_threshold_get(uint32_t threshold[5]);

uint16_t fsqm_segment_alloc(void);

void fsqm_segment_free(const uint16_t tlsa,
		       const uint16_t hlsa, const uint16_t seg_len, const uint16_t hdr_seg_len);

uint16_t fsqm_llt_read(const uint16_t idx);

void fsqm_llt_write(const uint16_t idx, const uint32_t val);

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void fsqm_interrupt_enable_set(const uint32_t mask);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void fsqm_interrupt_enable_get(uint32_t *mask);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void fsqm_interrupt_control_set(const uint32_t ctrl);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void fsqm_interrupt_control_get(uint32_t *ctrl);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void fsqm_fsqm_interrupt_capture_set(const uint32_t capt);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void fsqm_fsqm_interrupt_capture_get(uint32_t *capt);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

bool fsqm_check(uint16_t len);

#if defined(INCLUDE_DUMP)

/**
   Dump the FSQM register block.
*/
void fsqm_dump(struct seq_file *s);
int fsqm_llt(struct seq_file *s, int pos);
int fsqm_rcnt(struct seq_file *s, int pos);

#endif

/*! @} */

/*! @} */

#endif
