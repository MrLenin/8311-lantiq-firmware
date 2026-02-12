/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef _drv_onu_ssb_h
#define _drv_onu_ssb_h

/** \addtogroup ONU_LL_REFERENCE GPON Low-level Functions
   @{
*/

/** \addtogroup ONU_LL_SSB Shared Segment Buffer Low-level Functions

   Low-level functions to control the Shared Segment Buffer (SSB).
   @{
*/

/** Aging command max size [bytes]*/
#define SSB_CMD_AGING_SIZE	48

#define SBB_SEG_GET(len_bytes)	\
	((len_bytes) ? ((len_bytes)-1)/ONU_GPE_BUFFER_SEGMENT_SIZE + 1 : 0)

typedef int (*ssb_write_t) (const uint32_t qid, const uint32_t gem_port_index,
			    const uint32_t pdu_type,
			    const uint32_t plen, const uint8_t *data);

/**
   Initialize the SSB block (ssb0).
*/
void ssb_init(void);

/**
   Write data to the SSB.

   \param max_len    Data length
   \param data       Data to write
   \param hlsa       Returned Head LSA
   \param tlsa       Returned Tail LSA
*/
int ssb_data_write(const uint32_t max_len, const uint8_t *data,
		   uint32_t *hlsa, uint32_t *tlsa);

/**
   Read the PDU information from the hardware Egress Queue.
   This information will be used to read the PDU data afterwards.

   The data read process is splitted into tow functions to allow the calling
   process to allocate the destination data memory.

   \param epn        Egress Port NUmber
   \param info       PDU information retrieved from queue
   for simple network access. Used for testing purposes
*/
int ssb_egress_info_read(const uint8_t epn, struct onu_pdu_info *info);

/**
   Convert the link data buffer

   \param data       Link data buffer
   \param info       PDU information retrieved from queue

*/
void link_info_read(const uint32_t *data, struct onu_pdu_info *info);

/**
   Execute a read request.

   \param idx        Link Interface Index

*/
void link_data_request(const uint8_t idx);

/**
   Read Link FIFO data.

   \param idx        Link Interface Index
   \param pos        Data buffer position
   \param max_size   Data buffer size (in 32 bit words)
   \param data       Data buffer

*/
int link_fifo_read(const uint8_t idx, uint32_t *pos, const uint32_t max_size, uint32_t *data);

/**
   Read the PDU data from the hardware.
   In case that the data pointer is zero the PDU will be freed.

   \param info       PDU information to be used
   \param data       PDU data retrieved from queue
*/
int ssb_ingress_data_read(const struct onu_pdu_info *info, uint8_t *data);

/**
   Read the PDU data from the hardware.
   In case that the data pointer is zero the PDU will be freed.

   \param info       PDU information to be used
   \param data       PDU data retrieved from queue
*/
int ssb_egress_data_read(const struct onu_pdu_info *info, uint8_t *data);

/** Write data to free segments

   \param qid            Queue ID
   \param gem_port_index GEM Port Index
   \param pdu_type       \ref GPE_PDU_TYPE_ETH for downstream or
		         \ref GPE_PDU_TYPE_OMCI for upstream direction
   \param plen            data length
   \param data           OMCI PDU or Ethernet frame (not padded, no fcs)

   \return
   - -2 inserting of segment failed
   - -1 out of memory, can not allocate free segment
   - 0 success
*/
int ssb_iqueue_write(const uint32_t qid, const uint32_t gem_port_index,
		     const uint32_t pdu_type,
		     const uint32_t plen, const uint8_t *data);

/** Write SCE command to the ingress queue \ref ONU_GPE_INGRESS_QUEUE_CPU_DS

   \param lsa        LSA
   \param len        command length
   \param cmd        command data

   \return
   - -2 inserting of segment failed
   - -1 out of memory, can not allocate free segment
   - 0 success
*/
int ssb_cmd_write(const uint16_t lsa, const uint32_t len, const uint8_t *cmd);

int ssb_equeue_write(const uint32_t qid, const uint32_t gem_port_index,
		     const uint32_t pdu_type,
		     const uint32_t plen, const uint8_t *data);

int ssb_equeue_read(const uint32_t qid, const uint32_t max_len,
		    uint8_t *data, uint32_t *len);

#if defined(INCLUDE_DUMP)

/**
   Dump the SSB memory.
*/
void ssb_dump(struct seq_file *s);

#endif

/*! @} */

/*! @} */

#endif
