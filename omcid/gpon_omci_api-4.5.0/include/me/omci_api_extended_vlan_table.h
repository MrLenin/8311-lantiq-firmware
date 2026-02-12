/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_extended_table_data
#define _omci_api_me_extended_table_data

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_EXTENDED_VLAN_TABLE Extended VLAN Tagging Operation Table

   This managed entity organizes data associated with VLAN tagging. Regardless
   of its point of attachment, the specified tagging operations refer to the
   upstream direction.

   Instances of this managed entity are created and deleted by the OLT.

   @{
*/

struct omci_rule {
	uint16_t major;
	uint16_t minor;
	char *description;
	struct vlan_filter f;
};

struct omci_rules
{
	struct omci_rule up;
	struct omci_rule down;
};

struct sce_tags {
	int zero_enable;
	int one_enable;
	int two_enable;
};

struct sce_rule {
	int priority_enable;
	int priority_filter;
	int vid_enable;
	int vid_filter;
	int input_tpid_enable;
	int de_enable;
	int de_filter;
};

struct sce_ethertype {
	int filter1_enable;
	int filter2_enable;
	int filter3_enable;
	int filter4_enable;
	int filter5_enable;
};

struct sce_treatment {
	int taga;
	int taga_vid;
	int taga_tpid;
	int tagb;
	int tagb_vid;
	int tagb_tpid;
	int discard_enable;
	int outer_not_generate;
	int inner_not_generate;
};

struct sce_action
{
	uint16_t major;
	uint16_t minor;
	char *description;
	struct sce_tags tags;
	struct sce_rule outer;
	struct sce_rule inner;
	struct sce_ethertype ethertype;
	int def;
	struct sce_treatment treatment;
};

struct sce_rules
{
	struct sce_action up;
	struct sce_action down;
};

int omci_api_find_ext_vlan_rule(struct vlan_filter *filter, const bool dump);

enum omci_api_return omci_api_rule_us_map(struct omci_api_ctx *ctx,
					  const uint16_t omci_idx,
					  const struct vlan_filter *f,
				          struct gpe_vlan_rule_table *r,
				          struct gpe_vlan_treatment_table *t);

enum omci_api_return omci_api_rule_ds_map(struct omci_api_ctx *ctx,
					  const uint16_t omci_idx,
					  const struct vlan_filter *f,
					  struct gpe_vlan_rule_table *r,
					  struct gpe_vlan_treatment_table *t);

/** @} */

/** @} */

__END_DECLS

#endif
