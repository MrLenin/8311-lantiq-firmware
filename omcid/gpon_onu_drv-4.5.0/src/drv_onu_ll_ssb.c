/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "drv_onu_api.h"
#include "drv_onu_register.h"
#include "drv_onu_ll_ssb.h"
#include "drv_onu_ll_fsqm.h"
#include "drv_onu_ll_octrll.h"
#include "drv_onu_resource_gpe.h"	/* ONU_GPE_LLT_NIL */
#include "drv_onu_ll_sys.h"
#include "drv_onu_ll_iqm.h"

extern onu_lock_t ictrlc_lock;
extern onu_lock_t octrlc_lock;
extern onu_lock_t link_lock;

#define ONU_RAM_PACKET_BUFFER_OFFSET \
				(sbs0ctrl_r32(bar1) & SBS0CTRL_BAR1_BA1V_MASK)

#define MAX_LENGTH_CHECK 256

static const uint32_t link_port[3] = { 	0,
					ONU_LINK0_SIZE/4,
					(2*ONU_LINK0_SIZE)/4
};

static const uint32_t ictrlc_port[2] = {0, ONU_ICTRLC0_SIZE/4};

/* Fields of "Enqueue Request 0 Parameter Register 1" */
/** Tail LSA
    The logical SSB address of the second PDU segment */
#define NLSA_MASK 0x7FFF0000
/** field offset */
#define NLSA_OFFSET 16
/** PDU Type
    The PDU type is provided by SDMAx as a basic HW classification */
#define PDUT_MASK 0x00007000
/** field offset */
#define PDUT_OFFSET 12

/* Fields of "Enqueue Request 0 Parameter Register 2" */
/** GEM Port Index
    The GEM Port Index is mapped from the GEM Port Identifier in ICTRLG */
#define GPIX_MASK 0x00FF0000
/** field offset */
#define GPIX_OFFSET 16
/** PDU Length
    The PDU Length in Bytes */
#define PLEN_MASK 0x0000FFFF
/** field offset */
#define PLEN_OFFSET 0

/* Fields of "Enqueue Request 0 Parameter Register 3" */
/** Tail LSA
    The logical SSB address of the stored PDU tail */
#define TLSA_MASK 0x7FFF0000
/** field offset */
#define TLSA_OFFSET 16
/** Head LSA
    The logical SSB address of the stored PDU head */
#define HLSA_MASK 0x00007FFF
/** field offset */
#define HLSA_OFFSET 0

/* Fields of Deliver Request Parameter */
/** QOSL
    The logical SSB address of the stored PDU tail */
#define QOSL_MASK 0x7FFF0000
/** field offset */
#define QOSL_OFFSET 16
/** IPN
    Ingress Port Number */
#define IPN_MASK 0x00000F00
/** field offset */
#define IPN_OFFSET 8
/** COL
    Color code */
#define COL_MASK 0x03000000
/** field offset */
#define COL_OFFSET 24
/** CMD
    Command code to the TMU */
#define CMD_MASK 0x0C000000
/** field offset */
#define CMD_OFFSET 26
/** QID
    Defines the target egress queue */
#define QID_MASK 0x00FF0000
/** field offset */
#define QID_OFFSET 16

/* Fields of Schedule Request 0 Parameter Register 1*/
/** Egress Port Number
*/
#define SRQST_EPN_MASK 0x0000007F
/** field offset */
#define SRQST_EPN_OFFSET 0
/** Command Code
    Identifies the command to be performed.
	0x0 ER Enqueue Request (do nor use)
	0x1 SR Schedule Request (use this)
	0x2 BR Backlog Request (do not use)
	0x3 NOP reserved (do not use)
*/
/* Fields of Schedule Request 0 Parameter Register 2*/
#define SRQST_CMD_MASK 0x000C0000
/** field offset */
#define SRQST_CMD_OFFSET 18
/** Source Identifier
    Identifies the OCTRLC as the source of the command.
	53 OCTRLC send the request command from the OCTRLC
*/
#define SRQST_SRC_MASK 0x03F00000
/** field offset */
#define SRQST_SRC_OFFSET 20
/** Destination Identifier
    Identifies the TMU as the destination.
	57 TMU send the request command to the TMU
*/
#define SRQST_DST_MASK 0xFC000000
/** field offset */
#define SRQST_DST_OFFSET 26

/* Fields of Schedule Respond 0 Parameter Register 1*/
/** Segment Count
    Given in number of SSB segments.
*/
#define SRSND_SEGL_MASK 0x000003FF
/** field offset */
#define SRSND_SEGL_OFFSET 0
/** PDU Type
    Defines the type of data packet:
	0x0 ETH Ethernet
	0x1 IP Internet Protocol
	0x2 MPLS MPLS
	0x3 OMCI OMCI
	0x4 RES4 Reserved
	0x5 RES5 Reserved
	0x6 RES6 Reserved
	0x7 CMD Command
*/
#define SRSND_PDUT_MASK 0x0000E000
/** field offset */
#define SRSND_PDUT_OFFSET 13

/* Fields of Schedule Respond 0 Parameter Register 2*/
/** Header Length
    Given in number of bytes.
*/
#define SRSND_HDRL_MASK 0x000000FF
/** field offset */
#define SRSND_HDRL_OFFSET 0
/** Offset Value
    Given in number of bytes.
*/
#define SRSND_OFFS_MASK 0x0000FF00
/** field offset */
#define SRSND_OFFS_OFFSET 8

/* Fields of Schedule Respond 0 Parameter Register 3*/
/** Head Logical Segment Address
    LSA of the first segment that is used to hold the packet data.
*/
#define SRSND_HLSA_MASK 0x00007FFF
/** field offset */
#define SRSND_HLSA_OFFSET 0
/** Tail Logical Segment Address
    LSA of the last segment that is used to hold the packet data.
*/
#define SRSND_TLSA_MASK 0x7FFF0000
/** field offset */
#define SRSND_TLSA_OFFSET 16
/* Fields of Schedule Respond 0 Parameter Register 4*/
/** Body Length
    Given in number of bytes.
*/
#define SRSND_BDYL_MASK 0x0000FFFF
/** field offset */
#define SRSND_BDYL_OFFSET 0

#define REQ_C		(1 << 29)
#define RVAL(val, name) (((val) << name##_OFFSET) & name##_MASK)

STATIC int ssb_octrlc_write(const uint32_t *data);

void ssb_init(void)
{
	link_w32_table(LINK_CTRL_RSR, ctrl, link_port[0]);
	link_w32_table(LINK_CTRL_RSR, ctrl, link_port[1]);
	link_w32_table(LINK_IRNEN_RXR, irnen, link_port[0]);
	link_w32_table(LINK_IRNEN_RXR, irnen, link_port[1]);
	octrlc_w32(OCTRLC_CTRL_RSR | OCTRLC_CTRL_RSX | OCTRLC_CTRL_BMX, ctrl);
}

int ssb_egress_info_read(const uint8_t epn, struct onu_pdu_info *info)
{
	int ret = 0;
	uint8_t cmd = 1, src = 53, dst = 57;
	uint32_t tmp[4] = {0}, cnt = 0, reg;
	unsigned long flags = 0;

	/* reset info values */
	info->len = 0;
	info->segments = 0;
	info->seg_offset = 0;
	info->hlsa = ONU_GPE_LLT_NIL;
	info->tlsa = ONU_GPE_LLT_NIL;

	tmp[0] |= RVAL(epn, SRQST_EPN);
	tmp[1] |= RVAL(cmd, SRQST_CMD);
	tmp[1] |= RVAL(src, SRQST_SRC);
	tmp[1] |= RVAL(dst, SRQST_DST);

	onu_spin_lock_get(&octrlc_lock, &flags);

	/* send SCHEDULE_REQUEST */
	ret = ssb_octrlc_write(tmp);
	if (ret != 0)
		goto SSB_EGRESS_INFO_READ_ERROR;

	/* wait SCHEDULE_RESPOND */
	reg = octrlc_r32(len);
	while (((reg & OCTRLC_LEN_PACR_MASK) == 0) && (cnt++ < 3000))
		reg = octrlc_r32(len);
	if (cnt >= 3000) {
		ret = -2;
		goto SSB_EGRESS_INFO_READ_ERROR;
	}
	/* check for SOP */
	if ((octrlc_r32(irnicr) & OCTRLC_IRNEN_SOP) == 0) {
		ONU_DEBUG_ERR("no SOP in equeue");
		ret = -3;
		goto SSB_EGRESS_INFO_READ_ERROR;
	}

	/* read SCHEDULE_RESPOND */
	cnt = 0;
	tmp[cnt++] = octrlc_r32(data0);
	tmp[cnt++] = octrlc_r32(data1);
	/* check for EOP */
	if ((octrlc_r32(irnicr) & OCTRLC_IRNEN_EOP) == 0) {
		ONU_DEBUG_ERR("no EOP in equeue");
		ret = -3;
		goto SSB_EGRESS_INFO_READ_ERROR;
	}
	tmp[cnt++] = octrlc_r32(data0);
	tmp[cnt++] = octrlc_r32(data1);

	onu_spin_lock_release(&octrlc_lock, flags);

	/* fill pdu info*/
	info->pdu_type	 = (enum gpe_pdu_type)
			   ((tmp[0] & SRSND_PDUT_MASK) >> SRSND_PDUT_OFFSET);
	info->segments	 =  (tmp[0] & SRSND_SEGL_MASK) >> SRSND_SEGL_OFFSET;
	info->hdr_len	 =  (tmp[1] & SRSND_HDRL_MASK) >> SRSND_HDRL_OFFSET;
	info->bdy_offset =  (tmp[1] & SRSND_OFFS_MASK) >> SRSND_OFFS_OFFSET;
	info->hlsa 	 =  (tmp[2] & SRSND_HLSA_MASK) >> SRSND_HLSA_OFFSET;
	info->tlsa	 =  (tmp[2] & SRSND_TLSA_MASK) >> SRSND_TLSA_OFFSET;
	info->bdy_len	 =  (tmp[3] & SRSND_BDYL_MASK) >> SRSND_BDYL_OFFSET;
	info->len	 =  info->hdr_len + info->bdy_len;
	info->seg_offset =  info->hdr_len ? SBB_SEG_GET(info->hdr_len) : 1;

	if (info->bdy_len && info->segments == 0) {
		info->segments = info->seg_offset +
				 SBB_SEG_GET(info->bdy_len + info->bdy_offset);
	}

	return ret;

SSB_EGRESS_INFO_READ_ERROR:
	onu_spin_lock_release(&octrlc_lock, flags);
	return ret;
}

STATIC int link_length_read(const uint8_t idx)
{
	uint32_t reg;
	reg = link_r32_table(len, link_port[idx]);
	return (reg & LINK_LEN_LENR_MASK) >> LINK_LEN_LENR_OFFSET;
}

STATIC void link_data_read(const uint8_t idx, uint32_t *data)
{
	data[0] = link_r32_table(data0, link_port[idx]);
	data[1] = link_r32_table(data1, link_port[idx]);
}

STATIC int link_sop(const uint8_t idx)
{
	return link_r32_table(ctrl, link_port[idx]) & LINK_CTRL_SOP;
}

STATIC int link_eop(const uint8_t idx)
{
	return link_r32_table(ctrl, link_port[idx]) & LINK_CTRL_EOP;
}

void link_data_request(const uint8_t idx)
{
	uint32_t reg;

	if (link_length_read(idx))
		return;

	reg = link_r32_table(ctrl, link_port[idx]);
	link_w32_table(reg | LINK_CTRL_REQ, ctrl, link_port[idx]);
}

int link_fifo_read(const uint8_t idx, uint32_t *pos, const uint32_t max_size, uint32_t *data)
{
	uint32_t i, len, off;
	int ret = -1;

	if(is_falcon_chip_a2x())
		off = 18;
	else
		off = 14;

	len = link_length_read(idx);
	if (len == 0)
		return ret;

	for (i=0;i<(len-1);i++) {
		if (link_sop(idx) || *pos >= max_size)
			*pos = 0;
		if (link_eop(idx))
			break;
		link_data_read(idx, &data[*pos]);
		*pos += 2;
	}

	if (link_sop(idx) || *pos >= max_size)
		*pos = 0;

	if (link_eop(idx)) {
		/* to support extended baseline
		   change (off + 2) to the range of (off + 2) till 36 */
		if (*pos == off) {
			ret = 0;
		} else if (*pos > off && *pos < 36) {
			/* extended baseline */
			ONU_DEBUG_ERR("extended baseline not supported yet (%d)\n", *pos);
			ret = -2;
		} else {
			ONU_DEBUG_ERR("EOP at wrong position %d\n", *pos);
			ret = -3;
		}
	}

	link_data_read(idx, &data[*pos]);
	*pos += 2;

	return ret;
}

void link_info_read(const uint32_t *data, struct onu_pdu_info *info)
{
	memset(info, 0x00, sizeof(struct onu_pdu_info));
	info->len = (data[3] & IQM_DRP2_PLEN_MASK) >> IQM_DRP2_PLEN_OFFSET;
	info->segments = SBB_SEG_GET(info->len);
	info->hlsa = (data[2] & IQM_DRP3_HLSA_MASK) >> IQM_DRP3_HLSA_OFFSET;
	info->tlsa = (data[2] & IQM_DRP3_TLSA_MASK) >> IQM_DRP3_TLSA_OFFSET;
}

int ssb_ingress_data_read(const struct onu_pdu_info *info, uint8_t *data)
{
	int ret = 0;
	uint32_t lsa, len = info->len, to_copy, i;
	uint8_t *ptr;
	unsigned long psa;

	if (data == NULL || info->segments == 0 || info->tlsa == ONU_GPE_LLT_NIL
	    || info->hlsa == ONU_GPE_LLT_NIL || info->len == 0) {
		ret = -1;
		goto err;
	}

	ptr = data;
	lsa = info->hlsa;
	do {
		if (len > ONU_GPE_BUFFER_SEGMENT_SIZE)
			to_copy = ONU_GPE_BUFFER_SEGMENT_SIZE;
		else
			to_copy = len;

		psa =
		    ONU_SBS0RAM_BASE + ONU_RAM_PACKET_BUFFER_OFFSET +
		    (lsa * ONU_GPE_BUFFER_SEGMENT_SIZE);

		/* use uint8_t for ptr to allow unaligned buffers */
		for (i = 0; i < to_copy;) {
			uint32_t val;
			val = reg_r32((void *)psa);
			*ptr++ = (val >> 24) & 0xFF;
			*ptr++ = (val >> 16) & 0xFF;
			*ptr++ = (val >> 8) & 0xFF;
			*ptr++ = val & 0xFF;
			psa += 4;
			i += 4;
		}

		len -= to_copy;
		if (len)
			lsa = fsqm_llt_read(lsa);
	} while (len);

	if (lsa != info->tlsa)
		ONU_DEBUG_ERR("tlsa & lsa not equal");

err:
	fsqm_segment_free(info->tlsa, info->hlsa, info->segments, info->seg_offset);

	return ret;
}

STATIC int ssb_data_read(const uint32_t max_len, uint8_t *data,
			 const uint32_t hlsa, const uint32_t byte_offset,
			 const uint32_t seg_offset)
{
	uint32_t lsa, len = max_len, to_copy, i;
	uint8_t *ptr;
	unsigned long psa;
	uint32_t val = 0;

	ptr = data;
	lsa = hlsa;

	/* skip offset segments*/
	for (i = 0; i < seg_offset; i++)
		lsa = fsqm_llt_read(lsa);

	to_copy = (len > ONU_GPE_BUFFER_SEGMENT_SIZE) ||
		  (ONU_GPE_BUFFER_SEGMENT_SIZE - byte_offset) < len ?
			ONU_GPE_BUFFER_SEGMENT_SIZE - byte_offset : len;
	psa = ONU_SBS0RAM_BASE + ONU_RAM_PACKET_BUFFER_OFFSET +
	      (lsa * ONU_GPE_BUFFER_SEGMENT_SIZE) + byte_offset;

	while (len) {
		if ((psa & 3) == 0) {
			/* source (psa) is aligned */
			for (i = 0; i < to_copy; i++) {
				if (i % 4 == 0) {
					val = reg_r32((void *)psa);
					psa += 4;
				}
				*ptr++ = (val >> ((3-(i%4))*8)) & 0xFF;
			}
		} else {
			for (i = 0; i < to_copy; i++) {
				*ptr++ = *(uint8_t *)psa;
				psa += 1;
			}
		}

		len -= to_copy;

		to_copy = len > ONU_GPE_BUFFER_SEGMENT_SIZE ?
				ONU_GPE_BUFFER_SEGMENT_SIZE : len;
		if (len)
			lsa = fsqm_llt_read(lsa);

		psa = ONU_SBS0RAM_BASE + ONU_RAM_PACKET_BUFFER_OFFSET +
		      (lsa * ONU_GPE_BUFFER_SEGMENT_SIZE);
	}

	return 0;
}

int ssb_egress_data_read(const struct onu_pdu_info *info, uint8_t *data)
{
	int ret = 0;

	if(info->tlsa == ONU_GPE_LLT_NIL || info->hlsa == ONU_GPE_LLT_NIL)
		return -1;

	if (data == NULL || info->segments == 0 ||
	    info->len == 0 || info->pdu_type != GPE_PDU_TYPE_ETH ||
	    info->hdr_len + info->bdy_offset + info->bdy_len >
	    info->segments * ONU_GPE_BUFFER_SEGMENT_SIZE ||
	    info->bdy_offset > ONU_GPE_BUFFER_SEGMENT_SIZE ||
	    info->seg_offset > info->segments) {
		ret = -1;
		goto err;
	}

	/* read Ethernet packet header*/
	ssb_data_read(info->hdr_len, data, info->hlsa, 0, 0);

	/* read Ethernet packet body*/
	ssb_data_read(info->bdy_len, &data[info->hdr_len], info->hlsa,
		      info->bdy_offset, info->seg_offset);

err:
	fsqm_segment_free(info->tlsa, info->hlsa, info->segments, info->seg_offset);

	return ret;
}

STATIC int ssb_segm_write(const uint16_t lsa, const uint32_t len,
			  const uint8_t *data)
{
	uint32_t i;
	const uint8_t *ptr;
	unsigned long psa;

	if (len > ONU_GPE_BUFFER_SEGMENT_SIZE || lsa == ONU_GPE_LLT_NIL || !data)
		return -1;

	psa = ONU_SBS0RAM_BASE + ONU_RAM_PACKET_BUFFER_OFFSET +
		    (uint32_t)(lsa * ONU_GPE_BUFFER_SEGMENT_SIZE);

	ptr = data;

	if (((ulong_t) ptr & (sizeof(ulong_t) - 1)) == 0) {
		/* source (ptr) is aligned */
		for (i = 0; i < len;) {
			reg_w32(*((uint32_t *)ptr), (void *)psa);
			ptr += 4;
			psa += 4;
			i += 4;
		}
	} else {
		for (i = 0; i < len;) {
			uint32_t val;
			val =
			    ((ptr[0]) << 24) + ((ptr[1]) << 16) +
			    ((ptr[2]) << 8) + (ptr[3]);
			reg_w32(val, (void *)psa);
			ptr += 4;
			psa += 4;
			i += 4;
		}
	}

	return 0;
}

int ssb_data_write(const uint32_t max_len, const uint8_t *data,
		   uint32_t *hlsa, uint32_t *tlsa)
{
	int ret = 0;
	uint32_t i, to_copy, len, segments;
	const uint8_t *ptr;

	ptr = data;
	len = max_len;
	segments = SBB_SEG_GET(max_len);

	*hlsa = *tlsa = fsqm_segment_alloc();
	if (*tlsa == ONU_GPE_LLT_NIL) {
		ONU_DEBUG_ERR("ooops, can't get enough segments");
		return -1;
	}

	do {
		to_copy = (len > ONU_GPE_BUFFER_SEGMENT_SIZE) ?
				ONU_GPE_BUFFER_SEGMENT_SIZE : len;

		ssb_segm_write((uint16_t)*tlsa, to_copy, ptr);
		ptr += to_copy;
		len -= to_copy;

		if (len) {
			i = *tlsa;
			*tlsa = fsqm_segment_alloc();
			if (*tlsa == ONU_GPE_LLT_NIL) {
				ONU_DEBUG_ERR
				    ("ooops, can't get enough segments");
				fsqm_segment_free(*hlsa, i, segments, 0);
				return -1;
			}
			fsqm_llt_write(i, *tlsa);
		} else {
			fsqm_llt_write(*tlsa, ONU_GPE_LLT_NIL);
		}

	} while (len);

	return ret;
}

int ssb_link_write(const uint32_t idx, const uint32_t len, const uint32_t *data)
{
	int ret = 0;
	uint32_t tmp, i, cnt;
	unsigned long flags = 0;

	onu_spin_lock_get(&link_lock, &flags);

	for (i = 0; i < len;) {
		cnt = 0;
		do {
			tmp = link_r32_table(len, link_port[idx]) &
							LINK_LEN_LENX_MASK;
			cnt++;
		} while (tmp == 0 && cnt < 1000);
		if (cnt == 1000) {
			ONU_DEBUG_ERR("[link%d] no free TX link element", idx);
			ret = -1;
			break;
		}
		if (i == 0) {
			tmp = link_r32_table(ctrl, link_port[idx]);
			link_w32_table(tmp | LINK_CTRL_SOP, ctrl,
				       link_port[idx]);
		}
		if (i == len - 2) {
			tmp = link_r32_table(ctrl, link_port[idx]);
			link_w32_table(tmp | LINK_CTRL_EOP, ctrl,
				       link_port[idx]);
		}
		link_w32_table(data[i++], data0, link_port[idx]);
		link_w32_table(data[i++], data1, link_port[idx]);
	}

	onu_spin_lock_release(&link_lock, flags);

	return ret;
}

STATIC int ssb_ictrlc_write(const uint8_t idx, const uint32_t len,
			    const uint32_t *data)
{
	int ret = 0;
	uint32_t tmp, i, cnt;
	unsigned long flags = 0;

	if (idx > 1 || len < 2 || len % 2)
		return -1;

	onu_spin_lock_get(&ictrlc_lock, &flags);

	for (i = 0; i < len;) {
		cnt = 0;
		do {
			tmp = ictrlc_r32_table(len, ictrlc_port[idx]) &
							ICTRLC_LEN_LENX_MASK;
			cnt++;
		} while (tmp == 0 && cnt < 1000);

		if (cnt == 1000) {
			ONU_DEBUG_ERR(	"[ictrlc%d] no free TX link element",
					idx);
			ret = -1;
			break;
		}
		if (i == 0)
			ictrlc_w32_table_mask(	0, ICTRLC_CTRL_SOP, ctrl,
						ictrlc_port[idx]);
		if (i == len - 2)
			ictrlc_w32_table_mask(	0, ICTRLC_CTRL_EOP, ctrl,
						ictrlc_port[idx]);

		ictrlc_w32_table(data[i++], data0, ictrlc_port[idx]);
		ictrlc_w32_table(data[i++], data1, ictrlc_port[idx]);
	}

	onu_spin_lock_release(&ictrlc_lock, flags);

	return ret;
}

STATIC int ssb_octrlc_write(const uint32_t *data)
{
	uint32_t tmp, cnt;

	octrlc_w32(OCTRLC_CTRL_RSR | OCTRLC_CTRL_RSX | OCTRLC_CTRL_BMX, ctrl);

	cnt = 0;
	do {
		tmp = octrlc_r32(len) & OCTRLC_LEN_LENX_MASK;
		cnt++;
	} while (tmp == 0 && cnt < 1000);
	if (cnt == 1000) {
		ONU_DEBUG_ERR("[octrlc] no free TX link element");
		return -1;
	}
	octrlc_w32_mask(0, OCTRLC_CTRL_SOP | OCTRLC_CTRL_EOP, ctrl);
	octrlc_w32(data[0], data0);
	octrlc_w32(data[1], data1);
	octrlc_w32(0, ctrl);

	return 0;
}

/*  OMCI data is sent by writing the data into a segment of the shared buffer
    (SSB). The buffer segment address is then handed over to the Egress Queue
    Manager (TMU).
    The egress queue number is defined by
    n = ONU_GPE_EGRESS_QUEUE_OMCI if only a single queue is used or by
    n = ONU_GPE_EGRESS_QUEUE_OMCI_LOW and n = ONU_GPE_EGRESS_QUEUE_OMCI_HIGH
    if separate queues are used for high and low priority OMCI messages.

    Hardware Programming Details
    - Get a free segment of the SSB from the FSQM
      Logical Segment Address = FSQM.OMQ.LSA
    - Write the OMCI data to the SSB segment
    - Send an enqueue command to the TMU
*/
/*
	QOSL = 48D
(OMCI payload length, including CRC field)
PDUT = 1 (OMCI)
IPN = 7 (ingress port number is dont care)
TICK = 0 (no ticketing is performed on the OMCI traffic)
R = 0 (no re-sequencing)
U = 0 (no calendar update)
C = 1 (send command to TMU)
CMD = 1 (unicast)
COL = 1 (green)
PLEN = 44D (OMCI data length in SSB for short OMCI, not including the CRC;
in case of longer OMCI messages according to the actual length)
TLSA = logical segment number of the last OMCI data segment in the SSB
HLSA = logical segment number of the first OMCI data segment in the SSB
(for short OMCI messages TLSA and HLSA are equal)
This message is then sent to the Link 1 Interface according
	*/
int ssb_equeue_write(const uint32_t qid, const uint32_t gem_port_index,
		     const uint32_t pdu_type,
		     const uint32_t plen, const uint8_t *data)
{
	int ret = 0;
	uint32_t hlsa, tlsa;
	uint32_t tmp[4] = {0,0,0,0};
	const uint32_t qosl = plen + 4;
	const uint32_t ipn = 7;
	const uint32_t col = 1;
	const uint32_t cmd = 1;
	const uint32_t gpix = (uint32_t)gem_port_index;

	ret = ssb_data_write(plen, data, &hlsa, &tlsa);

	if (ret != 0)
		return ret;

	ONU_DEBUG_MSG("ssb_equeue_write: hlsa %x tlsa %x", hlsa, tlsa);

	tmp[0] |= RVAL(ipn, IPN);
	tmp[0] |= RVAL(pdu_type, PDUT);
	tmp[0] |= RVAL(qosl, QOSL);
	tmp[1] |= RVAL(qid, QID);
	tmp[2] |= RVAL(hlsa, HLSA);
	tmp[2] |= RVAL(tlsa, TLSA);
	tmp[3] |= RVAL(plen, PLEN);
	tmp[3] |= RVAL(gpix, GPIX);
	tmp[3] |= RVAL(col, COL);
	tmp[3] |= RVAL(cmd, CMD);
	tmp[3] |= REQ_C;

	return ssb_link_write(0, 4, tmp);
}

/**
    QID
        - Ingress queue of CPU for data in upstream direction (to the OLT)
	  ONU_GPE_INGRESS_QUEUE_CPU_US (4)
        - Ingress queue of CPU for data in downstream direction (to the LAN
          ports) ONU_GPE_INGRESS_QUEUE_CPU_DS (8)

*/
int ssb_iqueue_write(const uint32_t qid, const uint32_t gem_port_index,
		     const uint32_t pdu_type,
		     const uint32_t plen, const uint8_t *data)
{
	int ret = 0;
	uint8_t ictrlc_idx;
	uint32_t hlsa, tlsa;
	uint32_t gpix = gem_port_index;
	uint32_t tmp[4] = {0};

	if (pdu_type != GPE_PDU_TYPE_ETH)
		return -1;

	if (qid == ONU_GPE_INGRESS_QUEUE_CPU_US) {
		ictrlc_idx = 0;
	} else if (qid == ONU_GPE_INGRESS_QUEUE_CPU_DS) {
		ictrlc_idx = 1;
	} else {
		return -1;
	}

	if (iqm_is_backpressure_asserted(qid)) {
		ONU_DEBUG_ERR(	"ssb_iqueue_write: can't write ingress queue "
				"BP asserted");
		return -1;
	}

	ret = ssb_data_write(plen, data, &hlsa, &tlsa);
	if (ret != 0)
		return ret;

	ONU_DEBUG_MSG("ssb_iqueue_write: hlsa %x tlsa %x", hlsa, tlsa);

	tmp[0] |= RVAL(pdu_type, PDUT);
	/* Set Head and Tail, NLSA field set to 0 by default*/
	tmp[2] |= RVAL(hlsa, HLSA);
	tmp[2] |= RVAL(tlsa, TLSA);
	tmp[3] |= RVAL(plen, PLEN);
	tmp[3] |= RVAL(gpix, GPIX);

	/* Send ENQUEUE_REQUEST message*/
	ret = ssb_ictrlc_write(ictrlc_idx, 4, tmp);
	if (ret != 0) {
		fsqm_segment_free((uint16_t)tlsa, (uint16_t)hlsa,
				  SBB_SEG_GET(plen), 0);
		return ret;
	}

	return 0;
}

int ssb_cmd_write(const uint16_t lsa, const uint32_t len, const uint8_t *cmd)
{
	int ret = 0;
	uint32_t tmp[4] = {0};

	if (len > ONU_GPE_BUFFER_SEGMENT_SIZE || lsa == ONU_GPE_LLT_NIL || !cmd)
		return -1;

	if (iqm_is_backpressure_asserted(ONU_GPE_INGRESS_QUEUE_CPU_DS)) {
		ONU_DEBUG_ERR(	"ssb_iqueue_write: can't write ingress queue "
				"BP asserted");
		return -1;
	}

	ret = ssb_segm_write(lsa, len, cmd);
	if (ret != 0)
		return ret;

	tmp[0] |= RVAL(GPE_PDU_TYPE_CMD, PDUT);
	tmp[2] |= RVAL((uint32_t)lsa, HLSA);
	tmp[2] |= RVAL((uint32_t)lsa, TLSA);
	tmp[3] |= RVAL(len, PLEN);
	tmp[3] |= RVAL(0xFF, GPIX);

	/* Send ENQUEUE_REQUEST message*/
	ret = ssb_ictrlc_write(1, 4, tmp);
	if (ret != 0)
		return ret;

	return ret;
}

/** The OMCI messages can be received either directly from the OMCI ingress
    queue (before SCE processing) or from one or two egress queues (one per
    OMCI priority, after SCE processing).

    The first revision of this function supports only default-size OMCI messages
    (48 byte).
    \todo larger OMCI message support shall be added later if needed

    Note: The raw data format is different in ingress and egress queues.

    Hardware Programming Details - Read from Egress Queue
    - Send a "schedule request" command to the TMU, with the given egress
      port number, either
      - ONU_GPE_EGRESS_QUEUE_OMCI or
      - ONU_GPE_EGRESS_QUEUE_OMCI_LOW or
      - ONU_GPE_EGRESS_QUEUE_OMCI_HIGH
      The "request identifier" is set to "CPU", the coprocessor identifier is
      set to "TMU", the command code is "schedule request".
    - Read the corresponding "schedule response"
      The response request delivers
      - SEGL: number of 64-byte data segments; shall be 2 for 48-byte OMCI
        (1 header segment and one tail segment), else return an error code.
      - HLSA: Logical segment address of the header segment; this is a pointer
        to a segment within the SSB (Shared Segment Buffer).
      - TLSA: Logical segment address of the tail segment
      - HDRL: Header length; we need to distinguish if HDRL =< 64 (then we have
        a single header segment) or if HDRL > 64 (then we have multiple header
        segments.
      - OFFS: Offset; this defines the number of bytes that must be skipped in
        the segment that follows the (last) header segment. We need a case check
        here, if OFFS > 64 we have more than one segment to skip.
      - PDUT: PDU type, must be OMCI, else return an error code

      Other return values are of no interest here and shall be ignored.
    - Read the data segments from the SSB.
    - Free the data segments by writing to
      FSQM.IMQ.TLSA = TLSA
      FSQM.IMQ.HLSA = HLSA
      t.b.d.        = SEGL
    - Reassemble the data segments and return the message in nOMCI_Message[]
      according to the description in chapter
      "OMCI Data Reception  Default Size" of the UMPR.
*/
#if 0
int ssb_equeue_read(const uint8_t qid, const uint32_t max_len, uint8_t *data,
		    uint32_t *ret_len)
{
	int ret = -1;
	(void)qid;

	memset(data, 0, max_len);
	*ret_len = 0;

	return ret;
}
#endif

#if defined(INCLUDE_DUMP)

extern int g_p;

void ssb_dump(struct seq_file *s)
{
	uint32_t i, k, psa;

	/*g_p = 1; */
	seq_printf(s, "link\n");
	seq_printf(s, "ctrl:  ");
	for (i = 0; i < 3; i++) {
		seq_printf(s, "%08x ", link_r32_table(ctrl, link_port[i]));
	}
	seq_printf(s, "\nirnen:   ");
	for (i = 0; i < 3; i++) {
		seq_printf(s, "%08x ", link_r32_table(irnen, link_port[i]));
	}
	seq_printf(s, "\nirnicr:  ");
	for (i = 0; i < 3; i++) {
		seq_printf(s, "%08x ", link_r32_table(irnicr, link_port[i]));
	}
	seq_printf(s, "\nirncr:   ");
	for (i = 0; i < 3; i++) {
		seq_printf(s, "%08x ", link_r32_table(irncr, link_port[i]));
	}
	seq_printf(s, "\nlen:     ");
	for (i = 0; i < 3; i++) {
		seq_printf(s, "%08x ", link_r32_table(len, link_port[i]));
	}
	seq_printf(s, "\nlsa table\n");
	for (i = 0; i < 128; i++) {
		psa =
		    ONU_SBS0RAM_BASE + ONU_RAM_PACKET_BUFFER_OFFSET +
		    (i * ONU_GPE_BUFFER_SEGMENT_SIZE);
		seq_printf(s, "%08x:  ", psa);
		for (k = 0; k < 16 && i < 128; k++, i++) {
			psa =
			    ONU_SBS0RAM_BASE + ONU_RAM_PACKET_BUFFER_OFFSET +
			    (i * ONU_GPE_BUFFER_SEGMENT_SIZE);
			seq_printf(s, "%08x ", reg_r32((void *)psa));
		}
		seq_printf(s, "\n");
	}
}

#endif
