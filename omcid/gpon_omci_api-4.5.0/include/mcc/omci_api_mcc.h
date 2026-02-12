/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_mcc_h
#define _omci_api_mcc_h

#include "me/omci_api_vlan_tagging_filter_data.h"
#include "me/omci_api_multicast_operations_profile.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_MCC Multicast Control

   @{
*/

/** Maximum supported subscribers.
    \todo fix this value to reflect the max number of UNIs. */
#define OMCI_API_MCC_MAX_SUBSCRIBERS	4

/** Maximum supported profiles (max 1 profile per subscriber). */
#define OMCI_API_MCC_MAX_PROFILES	OMCI_API_MCC_MAX_SUBSCRIBERS

/** Specifies NULL subscriber */
#define MCC_SUBSCR_NULL				0xFF
/** Specifies NULL profile */
#define MCC_PROFILE_NULL			0xFF
/** Maximum number of entried in the lost groups list*/
#define OMCI_API_MAX_LGL_ENTRIES		50
/** Maximum number of entried in the active groups list*/
#define OMCI_API_MAX_AGL_ENTRIES		50

/** Multicast Control event information
*/
struct omci_api_mcc_event {
	enum {
		OMCI_API_MCC_EVENT_DUMMY,
	} type;

	union {
		struct {
			int dummy;
		} dummy;
	};
};

/** Structure to specify MCC profile.
*/
struct omci_api_mcc_profile {
	/** Entry validity flag. */
	bool valid;
	/** This field specifies the version of IGMP to be supported.
		- 1: IGMP version 1 (deprecated)
		- 2: IGMP version 2
		- 3: IGMP version 3
	*/
	uint8_t igmp_ver;
	/** This field enables an IGMP function.
	   - 0: Transparent IGMP snooping only.
	   - 1: Snooping with proxy reporting (SPR).
	   - 2: IGMP proxy.
	   The function must be consistent with the capabilities specified
	   by the other IGMP configuration attributes. */
	uint8_t igmp_func;
	/** This attribute controls the immediate leave function.
	   - false: Disables immediate leave.
	   - true: Enables immediate leave. */
	bool imm_leave;
	/** Under control of the upstream IGMP tag control field, the
	    upstream IGMP TCI attribute defines a VLAN ID and p-bits to add to
	    upstream IGMP messages. */
	uint16_t us_igmp_tci;
	/** This attribute controls the upstream IGMP TCI attribute.
		- 0: Pass upstream IGMP traffic transparently, neither adding,
		     stripping nor modifying tags that may be present.
		- 1: Add a VLAN tag (including P bits) to upstream IGMP traffic.
		     The VLAN is specified by the upstream IGMP TCI attribute.
		- 2: Replace the entire TCI (VLAN ID plus P bits) on upstream
		     IGMP traffic. The new tag is specified by the upstream IGMP
		     TCI attribute.
		- 3: Replace only the VLAN ID on upstream IGMP traffic,
		     retaining the original CFI and P bits. The new VLAN ID is
		     specified by the VLAN ID field of the upstream IGMP TCI
		     attribute. */
	uint8_t us_igmp_tag_ctrl;
	/** TCI (VLAN ID and P bits) to be applied on the downstream IGMP/MLD
	    and multicast streams in case the replace or add option is selected.  
	*/
	uint16_t ds_igmp_mc_tci;
	/** This attribute controls the downstream tagging of both the IGMP/MLD
	    and multicast frames. 
		- 0: Pass downstream IGMP/MLD and multicast traffic
		     transparently, neither stripping nor modifying tags that
		     may be present. 
		- 1: Strip the outer VLAN tag (including P bits) from downstream
		     IGMP/MLD and multicast traffic. 
		- 2: Add a tag onto downstream IGMP/MLD and multicast traffic.
		- 3: Replace the tag on downstream IGMP/MLD and multicast
		     traffic.
		- 4: Replace only the VLAN ID on downstream IGMP/MLD and
		     multicast traffic, retaining the original DEI and P bits.
		- 5: Add a tag onto downstream IGMP/MLD and multicast traffic.
		     The new tag is specified by the VID (UNI) field of the
		     multicast service package table row of the multicast
		     subscriber config info ME that is associated with this
		     profile. If the VID (UNI) field is unspecified (0xFFFF) or
		     specifies untagged traffic. 
		- 6: Replace the tag on downstream IGMP/MLD and multicast
		     traffic. The new tag is specified by the VID (UNI) field of
		     the multicast service package table row of the multicast
		     subscriber config info ME that is associated with this
		     profile. If the VID (UNI) field specifies untagged traffic,
		     the outer VLAN tag (including P bits) is stripped from
		     downstream IGMP/MLD and multicast traffic.
		- 7: Replace only the VID on downstream IGMP/MLD and multicast
		     traffic, retaining the original DEI and P bits. The new
		     VLAN ID is specified by the VID (UNI) field of the
		     multicast service package table row of the multicast
		     subscriber config info ME that is associated with this
		     profile. If the VID (UNI) field specifies untagged traffic,
		     the outer VLAN tag (including P bits) is stripped from
		     downstream IGMP/MLD and multicast traffic.
	*/
	uint8_t ds_igmp_mc_tag_ctrl;
	/** This attribute limits the maximum rate of upstream IGMP traffic.
	    Traffic in excess of this limit is silently discarded. The attribute
	    value is specified in messages/second. The recommended default value
	    0 imposes no rate limit on this traffic. */
	uint32_t us_igmp_rate;
	/** Dynamic access control list*/
	struct omci_api_multicast_operations_profile_acl dynamic_acl;
};

/** Structure to specify the MCC subscriber configuration.
*/
struct omci_api_mcc_subscr_cfg {
	/** Entry validity flag. */
	bool valid;
	/** Subscriber LAN port index. */
	uint8_t lan_idx;
	/** Index to specify the linked MCC profile, 0xFF specifies
	    no profile. */
	uint8_t profile_idx;
	/** This field specifies the maximum number of dynamic multicast groups
	    that may be replicated to the client port at any one time. The
	    recommended default value 0 specifies that no administrative limit
	    is to be imposed. */
	uint16_t max_simultaneous_groups;
	/** This field specifies the maximum imputed dynamic bandwidth,
	    in bytes per second, that may be delivered to the client port at any
	    one time. The recommended default value 0 specifies that no
	    administrative limit is to be imposed. */
	uint32_t max_mc_bw;
	/** The recommended default value of this field is false,
	    and specifies that attempts to exceed the max multicast bandwidth be
	    counted but honoured. The value true specifies that such attempts be
	    counted and denied. The imputed bandwidth value is taken from the
	    dynamic access control list table, both for a new join request and
	    for pre-existing groups. */
	bool bw_enforcement;
};

/** Structure to specify the MCC subscriber status
*/
struct omci_api_mcc_subscr_status {
	/** Best effort estimate of the actual bandwidth currently being
	    delivered to subscriber port over all dynamic multicast groups. */
	uint32_t curr_mc_bw;
	/** Counter for the number of times subscriber sent a join message that
	    was accepted. */
	uint32_t join_msg_cnt;
	/** Counter for the number of join messages that did, or would have,
	    exceeded the max multicast bandwidth, whether accepted or denied. */
	uint32_t bw_exc_cnt;
};

struct omci_api_mcc_lost_group {
	/** Group address */
	uint32_t addr;
	/** VLAN ID*/
	uint16_t vlan_id;
};

struct omci_api_mcc_lost_groups_list {
	/** Lost group head */
	struct omci_api_mcc_lost_group entry[OMCI_API_MAX_LGL_ENTRIES];
	/** Number of lost groups in the list*/
	uint32_t count;
};

struct omci_api_mcc_active_group {
	/** VLAN ID */
	uint16_t vlan_id;
	/** Source IP address, 0.0.0.0 if not used */
	uint32_t source_ip;
	/** Multicast destination IP address */
	uint32_t mc_dest_ip;
	/** Best efforts actual bandwidth estimate, bytes per second  */
	uint32_t best_eff_act_bw_est;
	/** Client (set-top box) IP address, that is, the IP address of the
	    device currently joined*/
	uint32_t client_ip;
	/** Time since the most recent join of this client to the IP channel,
	    in seconds */
	uint32_t time_since_join;
};

struct omci_api_mcc_active_groups_list {
	/** Active group head */
	struct omci_api_mcc_active_group entry[OMCI_API_MAX_AGL_ENTRIES];
	/** Number of active groups in the list*/
	uint32_t count;
};

/** Multicast Control callback definition */
typedef enum omci_api_return(omci_api_mcc_cb_t)(void *caller,
						struct omci_api_mcc_event
						event);

/** Register Multicast Control events callback. */
enum omci_api_return omci_api_mcc_cb_register(struct omci_api_ctx *ctx,
					      omci_api_mcc_cb_t *callback);

/** Get lost groups list.

	\param ctx   OMCI API context.
	\param s_idx Subscriber index.
	\param list  Active groups list.
	
	\note Function uses dynamic memory allocation.

	\return OMCI_API_SUCCESS on success, error otherwise.
*/
enum omci_api_return
omci_api_mcc_active_groups_list_get(struct omci_api_ctx *ctx,
				    const uint8_t s_idx,
				    struct omci_api_mcc_active_groups_list
				    *list);

/** Get lost groups list.

	\param ctx OMCI API context.
	\param idx Profile index.
	\param list Lost groups list.
	
	\note Functions used dynamic memory allocation.

	\return OMCI_API_SUCCESS on success, error otherwise.
*/
enum omci_api_return
omci_api_mcc_lost_groups_list_get(struct omci_api_ctx *ctx,
				  const uint8_t idx,
				  struct omci_api_mcc_lost_groups_list *list);

/** Get multicast profile data.

	\param ctx OMCI API context.
	\param idx Profile index.
	\param profile Profile data.

	\return OMCI_API_SUCCESS on success, error otherwise.
*/
enum omci_api_return
omci_api_mcc_profile_get(struct omci_api_ctx *ctx,
			 const uint8_t idx,
			 struct omci_api_mcc_profile *profile);

/** Update multicast profile data.

	\param ctx OMCI API context.
	\param idx Profile index.
	\param profile Profile data.

	\return OMCI_API_SUCCESS on success, error otherwise.
*/
enum omci_api_return
omci_api_mcc_profile_update(struct omci_api_ctx *ctx,
			    const uint8_t idx,
			    const struct omci_api_mcc_profile *profile);

/** Update profile dynamic access control list.

	\param ctx OMCI API context.
	\param idx Profile index.
	\param acl dynamic access control list.

	\return OMCI_API_SUCCESS on success, error otherwise.
*/
enum omci_api_return
omci_api_mcc_profile_dacl_update(struct omci_api_ctx *ctx,
				 const uint8_t idx,
				 const struct omci_api_multicast_operations_profile_acl *acl);

/** Get multicast subscriber data.

	\param ctx OMCI API context.
	\param idx Subscriber index.
	\param subscr Subscriber data.

	\return OMCI_API_SUCCESS on success, error otherwise.
*/
enum omci_api_return
omci_api_mcc_subscr_get(struct omci_api_ctx *ctx,
		        const uint8_t idx,
		        struct omci_api_mcc_subscr_cfg *subscr);

/** Update multicast subscriber data.

	\param ctx OMCI API context.
	\param idx Subscriber index.
	\param subscr Subscriber data.

	\return OMCI_API_SUCCESS on success, error otherwise.
*/
enum omci_api_return
omci_api_mcc_subscr_update(struct omci_api_ctx *ctx,
			   const uint8_t idx,
			   const struct omci_api_mcc_subscr_cfg *subscr);

/** Get multicast subscriber status.

	\param ctx OMCI API context.
	\param idx Subscriber index.
	\param status Subscriber status.

	\return OMCI_API_SUCCESS on success, error otherwise.
*/
enum omci_api_return
omci_api_mcc_subscr_status_get(struct omci_api_ctx *ctx,
			       const uint8_t idx,
			       struct omci_api_mcc_subscr_status *status);

/** Reset multicast subscriber status.

	\param ctx OMCI API context.
	\param idx Subscriber index.

	\return OMCI_API_SUCCESS on success, error otherwise.
*/
enum omci_api_return
omci_api_mcc_subscr_status_reset(struct omci_api_ctx *ctx, const uint8_t idx);

/** Set debug level.

	\param level Debug level

	\return OMCI_API_SUCCESS on success, error otherwise.
*/
enum omci_api_return omci_api_mcc_debug_level_set(uint8_t level);

/** Get debug level.

	\return Debug level.
*/
uint8_t omci_api_mcc_debug_level_get(void);

/** @} */

__END_DECLS

#endif
