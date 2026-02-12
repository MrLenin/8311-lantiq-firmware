/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef _drv_onu_iqm_h
#define _drv_onu_iqm_h

/** \addtogroup ONU_LL_REFERENCE GPON Low-level Functions
   @{
*/

/** \addtogroup ONU_LL_IQM Ingress Queue Manager Low-level Functions

   Low-level functions to access the Ingress Queue Manager (IQM).
   @{
*/

/**
   IQM configuration data structure.
*/
struct iqm_iqt_entry {
	uint16_t qe;
	uint16_t qdth;
	uint16_t qrth;
	uint16_t qb;
	uint16_t qbth;
	uint16_t qbtl;
	bool qf;
	bool bp;
	uint16_t pocc;
	uint16_t qocc;
	uint32_t qdc;
	uint8_t tick;
	uint32_t tmask; /* bit mask t0...t17, link0, link1 */
};

/**
   This structure is used to hold the configuration parameters of the
   WRR scheduler.
*/
struct iqm_wrr_cfg {
	/** This field defines the scheduler period for the IQM module and thus
	    the number of slots in the wrrq[] registers which are used. */
	uint8_t per;
	/** This array holds the QIDs to be selected for each WRR slot */
	uint8_t wrrq[36];
};

/**
   This structure is used to hold dequeue respond values.
*/
struct iqm_dequeue_res {
	/** timestamp */
	uint32_t ts;
	/** ticket */
	uint32_t tick;
	/** ingress port number */
	uint32_t ipn;
	/** PDU type */
	uint32_t pdut;
	/** Next LSA */
	uint32_t nlsa;
	/** PDU length */
	uint32_t plen;
	/** GEM Port Index */
	uint32_t gpix;
	/** Head LSA */
	uint32_t hlsa;
	/** Tail LSA */
	uint32_t tlsa;
};

/* ***************************************************************************/

/**
   Set Activate/Deactivate switch for IQM state machines.
*/
void iqm_enable(bool act);

/**
   Get Activate/Deactivate switch of  IQM state machines.
*/
bool iqm_is_enabled(void);

/**
   Initialize the IQM block.
*/
void iqm_init(void);

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
/**
   Set global SSB occupancy counters for IQM

      \param   gocc  The occupancy status of the SSB portion shared in the IQM
                     in units of segments.

      \remarks For debug only !
      \remarks Must not be used after activation of the state machine.

*/
void iqm_global_occupancy_set(uint32_t gocc);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

/**
   Get global SSB occupancy counters for IQM

      \param   gocc  the occupancy status of the SSB portion shared in the IQM
                     in units of segments

*/
void iqm_global_occupancy_get(uint32_t *gocc);

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
/**
   Set global discard counters

      \param   gpdc  discard counter

*/
void iqm_global_discard_counter_set(uint32_t gpdc);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

/**
   Set global discard counters

      \param   gpdc  discard counters

*/
void iqm_global_discard_counter_get(uint32_t *gpdc);

/**
   Set global Tail Drop Threshold for IQM

      \param   goth  global threshold provided in units of segments


*/
void iqm_global_tail_drop_thr_set(uint32_t goth);

/**
   Get global Tail Drop Threshold for IQM

      \param   goth  global threshold provided in units of segments


*/
void iqm_global_tail_drop_thr_get(uint32_t *goth);

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
/**
   Get timestamp value

      \param   ts    timestamp

      \remarks initialized and started by HW, read only by SW


*/
void iqm_timestamp_get(uint32_t *ts);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

/**
   Set WRR scheduler configuration registers

      \param   cfg \ref iqm_wrr_cfg

*/
void iqm_wrr_sched_cfg_set(struct iqm_wrr_cfg *cfg);

/**
   Get WRR scheduler configuration registers

      \param   cfg \ref iqm_wrr_cfg

*/
void iqm_wrr_sched_cfg_get(struct iqm_wrr_cfg *cfg);

/**
   Get free segment map

      \param   sfree0 has 32 valid bits
      \param   sfree1 has 16 valid bits

      \remarks initialized and started by HW, read only by SW
*/
void iqm_sfree_get(uint32_t * sfree0, uint32_t * sfree1);

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
/**
   Get Dequeue Response

      \param   resp    \ref iqm_dequeue_res

*/
void iqm_dequeue_respond_get(struct iqm_dequeue_res *resp);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
/**
   Enable / Disable specific IQM interrupts

      \param   mask   bitmap according to the fields below

   - 2   DR    Dequeue Ready
   - 3   CER   Command Error
   - 4   IF    IQM Full
   - 8   QF0   IQM Queue 0 filled
   - 9   QF0   IQM Queue 1 filled
   - 10  QF0   IQM Queue 2 filled
   - 11  QF0   IQM Queue 3 filled
   - 12  QF0   IQM Queue 4 filled
   - 13  QF0   IQM Queue 5 filled
   - 14  QF0   IQM Queue 6 filled
   - 15  QF0   IQM Queue 7 filled
   - 16  QF0   IQM Queue 8 filled

   - 20  BP0   IQM Queue 0 Back Pressure
   - 21  BP1   IQM Queue 1 Back Pressure
   - 22  BP2   IQM Queue 2 Back Pressure
   - 23  BP3   IQM Queue 3 Back Pressure
   - 24  BP4   IQM Queue 4 Back Pressure
   - 25  BP5   IQM Queue 5 Back Pressure
   - 26  BP6   IQM Queue 6 Back Pressure
   - 27  BP7   IQM Queue 7 Back Pressure
   - 28  BP8   IQM Queue 8 Back Pressure

*/
void iqm_interrupt_enable_set(const uint32_t mask);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
/**
   Get IQM interrupt mask

      \param   mask   bitmap according to the fields below

   - 2   DR    Dequeue Ready
   - 3   CER   Command Error
   - 4   IF    IQM Full
   - 8   QF0   IQM Queue 0 filled
   - 9   QF0   IQM Queue 1 filled
   - 10  QF0   IQM Queue 2 filled
   - 11  QF0   IQM Queue 3 filled
   - 12  QF0   IQM Queue 4 filled
   - 13  QF0   IQM Queue 5 filled
   - 14  QF0   IQM Queue 6 filled
   - 15  QF0   IQM Queue 7 filled
   - 16  QF0   IQM Queue 8 filled

   - 20  BP0   IQM Queue 0 Back Pressure
   - 21  BP1   IQM Queue 1 Back Pressure
   - 22  BP2   IQM Queue 2 Back Pressure
   - 23  BP3   IQM Queue 3 Back Pressure
   - 24  BP4   IQM Queue 4 Back Pressure
   - 25  BP5   IQM Queue 5 Back Pressure
   - 26  BP6   IQM Queue 6 Back Pressure
   - 27  BP7   IQM Queue 7 Back Pressure
   - 28  BP8   IQM Queue 8 Back Pressure

*/
void iqm_interrupt_enable_get(uint32_t *mask);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
/**
   Enable or disable specific IQM interrupts.

   \param ctrl bitmap according to the fields below

   - 2   DR    Dequeue Ready
   - 3   CER   Command Error
   - 4   IF    IQM Full
   - 8   QF0   IQM Queue 0 filled
   - 9   QF0   IQM Queue 1 filled
   - 10  QF0   IQM Queue 2 filled
   - 11  QF0   IQM Queue 3 filled
   - 12  QF0   IQM Queue 4 filled
   - 13  QF0   IQM Queue 5 filled
   - 14  QF0   IQM Queue 6 filled
   - 15  QF0   IQM Queue 7 filled
   - 16  QF0   IQM Queue 8 filled

   - 20  BP0   IQM Queue 0 Back Pressure
   - 21  BP1   IQM Queue 1 Back Pressure
   - 22  BP2   IQM Queue 2 Back Pressure
   - 23  BP3   IQM Queue 3 Back Pressure
   - 24  BP4   IQM Queue 4 Back Pressure
   - 25  BP5   IQM Queue 5 Back Pressure
   - 26  BP6   IQM Queue 6 Back Pressure
   - 27  BP7   IQM Queue 7 Back Pressure
   - 28  BP8   IQM Queue 8 Back Pressure

*/
void iqm_interrupt_control_set(const uint32_t ctrl);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
/**
   Get IQM interrupt mask

   \param ctrl bitmap according to the fields below

   - 2   DR    Dequeue Ready
   - 3   CER   Command Error
   - 4   IF    IQM Full
   - 8   QF0   IQM Queue 0 filled
   - 9   QF0   IQM Queue 1 filled
   - 10  QF0   IQM Queue 2 filled
   - 11  QF0   IQM Queue 3 filled
   - 12  QF0   IQM Queue 4 filled
   - 13  QF0   IQM Queue 5 filled
   - 14  QF0   IQM Queue 6 filled
   - 15  QF0   IQM Queue 7 filled
   - 16  QF0   IQM Queue 8 filled

   - 20  BP0   IQM Queue 0 Back Pressure
   - 21  BP1   IQM Queue 1 Back Pressure
   - 22  BP2   IQM Queue 2 Back Pressure
   - 23  BP3   IQM Queue 3 Back Pressure
   - 24  BP4   IQM Queue 4 Back Pressure
   - 25  BP5   IQM Queue 5 Back Pressure
   - 26  BP6   IQM Queue 6 Back Pressure
   - 27  BP7   IQM Queue 7 Back Pressure
   - 28  BP8   IQM Queue 8 Back Pressure

*/
void iqm_interrupt_control_get(uint32_t *ctrl);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
/**
   Enable or disable specific IQM interrupts.

   \param capt bitmap according to the fields below

   - 2   DR    Dequeue Ready
   - 3   CER   Command Error
   - 4   IF    IQM Full
   - 8   QF0   IQM Queue 0 filled
   - 9   QF0   IQM Queue 1 filled
   - 10  QF0   IQM Queue 2 filled
   - 11  QF0   IQM Queue 3 filled
   - 12  QF0   IQM Queue 4 filled
   - 13  QF0   IQM Queue 5 filled
   - 14  QF0   IQM Queue 6 filled
   - 15  QF0   IQM Queue 7 filled
   - 16  QF0   IQM Queue 8 filled

   - 20  BP0   IQM Queue 0 Back Pressure
   - 21  BP1   IQM Queue 1 Back Pressure
   - 22  BP2   IQM Queue 2 Back Pressure
   - 23  BP3   IQM Queue 3 Back Pressure
   - 24  BP4   IQM Queue 4 Back Pressure
   - 25  BP5   IQM Queue 5 Back Pressure
   - 26  BP6   IQM Queue 6 Back Pressure
   - 27  BP7   IQM Queue 7 Back Pressure
   - 28  BP8   IQM Queue 8 Back Pressure

*/
void iqm_interrupt_capture_set(const uint32_t capt);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
/**
   Get IQM interrupt mask

   \param capt bitmap according to the fields below

   - 2   DR    Dequeue Ready
   - 3   CER   Command Error
   - 4   IF    IQM Full
   - 8   QF0   IQM Queue 0 filled
   - 9   QF0   IQM Queue 1 filled
   - 10  QF0   IQM Queue 2 filled
   - 11  QF0   IQM Queue 3 filled
   - 12  QF0   IQM Queue 4 filled
   - 13  QF0   IQM Queue 5 filled
   - 14  QF0   IQM Queue 6 filled
   - 15  QF0   IQM Queue 7 filled
   - 16  QF0   IQM Queue 8 filled

   - 20  BP0   IQM Queue 0 Back Pressure
   - 21  BP1   IQM Queue 1 Back Pressure
   - 22  BP2   IQM Queue 2 Back Pressure
   - 23  BP3   IQM Queue 3 Back Pressure
   - 24  BP4   IQM Queue 4 Back Pressure
   - 25  BP5   IQM Queue 5 Back Pressure
   - 26  BP6   IQM Queue 6 Back Pressure
   - 27  BP7   IQM Queue 7 Back Pressure
   - 28  BP8   IQM Queue 8 Back Pressure

*/
void iqm_interrupt_capture_get(uint32_t *capt);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
/**
   Set Enable / Disable of an ingress queue.

   \param qid ingress queue identifier of ingress queue to be disabled
   \param ena enable = true, disable = false

*/
void iqm_iqueue_enable_set(const uint32_t qid, bool ena);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
/**
   Get Enable or disable of an ingress queue.

      \param qid ingress queue identifier of ingress queue to be disabled
      \param ena enable = true, disable = false

*/
void iqm_iqueue_enable_get(const uint32_t qid, bool *ena);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
/**
   Set blocking mode of an ingress queue.

      \param   qid   ingress queue identifier of ingress queue to be disabled
      \param   block block = 1, unblock = 0

*/
void iqm_iqueue_blk_set(const uint32_t qid, bool block);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
/**
   Get blocking mode of an ingress queue.

      \param   qid   ingress queue identifier of ingress queue to be disabled
      \param   block block = 1, unblock = 0

*/
void iqm_iqueue_blk_get(const uint32_t qid, bool *block);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

/**
   Set all configuration parameters of an ingress queue.

      \param   qid   ingress queue identifier
      \param   cfg   first 6 values of \ref iqm_iqt_entry

*/
void iqm_iqueue_cfg_set(const uint32_t qid, struct iqm_iqt_entry *cfg);

/**
   Get all configuration parameters of an ingress queue.

      \param   qid   ingress queue identifier
      \param   cfg   first 6 values of \ref iqm_iqt_entry

*/
void iqm_iqueue_cfg_get(const uint32_t qid, struct iqm_iqt_entry *cfg);

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
/**
   Set ingress queue discard counter

      \param   qid  ingress queue identifier of ingress queue to be read
      \param   qdc  the discard counter

      \remarks discards are counted in units of packets

*/
void iqm_iqueue_discard_counter_set(uint32_t qid, uint32_t qdc);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

/**
      Get ingress queue discard counter

      \param   qid  ingress queue identifier of ingress queue to be read

      \return   the discard counter

      \remarks discards are counted in units of packets

*/
uint32_t iqm_iqueue_discard_counter_get(uint32_t qid);

/**
   Get all status variables of an ingress queue.

      \param   qid   ingress queue identifier
      \param   cfg   last 7 values of \ref iqm_iqt_entry

      \remarks ingress queue status is initialized by HW and read only for SW

*/
void iqm_iqueue_status_get(const uint32_t qid, struct iqm_iqt_entry *cfg);

/**
   Returns ingress queue backpressure assertion status.

      \param   qid   ingress queue identifier
*/
bool iqm_is_backpressure_asserted(const uint8_t qid);

#if defined(INCLUDE_DUMP)

/**
   Dump the IQM register block.
*/
void iqm_dump(struct seq_file *s);

#endif

/*! @} */

/*! @} */

#endif
