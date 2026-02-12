/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_traffic_descriptor_h
#define _omci_traffic_descriptor_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_TRAFFIC_DESCRIPTOR Traffic Descriptor Managed Entity

    The Traffic Descriptor is used to assign traffic management parameters.
    A priority controlled ONU can point from a MAC bridge port configuration
    data Managed Entity to a Traffic Descriptor in order to implement
    traffic management (such as marking and policing). A rate controlled ONU
    can point to a Traffic Descriptor from either a MAC bridge port
    configuration data Managed Entity or a GEM port network CTP to implement
    traffic management (such as marking and shaping).
    Packets are determined to be green, yellow or red as a function of the
    ingress packet rate and the settings in this Managed Entity. The color
    indicates drop precedence (eligibility), subsequently used by the
    priority queue-G Managed Entity to drop packets conditionally during
    congestion conditions. The packet color is also used by the mode 1 DBA
    status reporting function described in G.984.3. Red packets are dropped
    immediately. Yellow packets are marked as drop eligible, and green packets
    are marked as not drop eligible, according to the egress color marking
    attribute. The algorithm used to determine the color marking is specified
    by the meter type attribute. If RFC 4115 (DSCP two-rate Three Color Marker)
    is used, then
    - CIR[4115] = CIR
    - EIR[4115] = PIR - CIR
    - CBS[4115] = CBS
    - EBS[4115] = PBS - CBS
    This ME is associated with a GEM port network CTP or a MAC bridge port
    configuration data Managed Entity.

    @{
*/

/** This structure holds the attributes of the Traffic Descriptor
    Managed Entity.
*/
struct omci_me_traffic_descriptor {
	/** Committed Information Rate (CIR)

	    This attribute specifies the Committed Information Rate, in byte/s.
	    The default is 0x00000000.

	    This attribute is readable and writable by the OLT.
	*/
	uint32_t cir;

	/** Peak Information Rate (PIR)

	    This attribute specifies the Peak Information Rate, in byte/s.
	    The default value of 0x00000000 accepts the ONU's factory policy.

	    This attribute is readable and writable by the OLT.
	*/
	uint32_t pir;

	/** Committed Burst Size (CBS)

	    This attribute specifies the Committed Burst Size, in bytes.
	    The default value is 0x00000000.

	    This attribute is readable and writable by the OLT.
	*/
	uint32_t cbs;

	/** Peak Burst Size (PBS)

	    This attribute specifies the Peak Burst Size, in bytes.
	    The default value of 0x00000000 accepts the ONT's factory policy.

	    This attribute is readable and writable by the OLT.
	*/
	uint32_t pbs;

	/** Coloring Mode

	    This attribute specifies whether the color marking algorithm
	    considers pre-existing marking on ingress packets (color-aware
	    operation) or ignores it (color-blind operation).
	    If color-aware, packets can only be demoted (from green to yellow
	    or red, or from yellow to red).
	    The coding is:
	    - 0x00 Color-blind
	    - 0x01 Color-aware

	    The default value is 0x00.

	    This attribute is readable and writable by the OLT.
	*/
	uint8_t color_mode;

	/** Ingress Color Marking

	    This attribute is meaningful in color-aware mode only. It specifies
	    how the pre-existing drop precedence is marked on ingress packets.
	    For DEI and PCP marking, a drop eligible indicator is equivalent to
	    yellow color, otherwise the color is green. For DSCP AF (Assured
	    Forwarding)marking, the lowest drop precedence is equivalent to
	    green, otherwise the color is yellow.
	    The coding is:
	    - 0x00 No marking (ignore ingress marking)
	    - 0x01 reserved
	    - 0x02 DEI (IEEE 802.1ad)
	    - 0x03 PCP 8P0D (IEEE 802.1ad)
	    - 0x04 PCP 7P1D (IEEE 802.1ad)
	    - 0x05 PCP 6P2D (IEEE 802.1ad)
	    - 0x06 PCP 5P3D (IEEE 802.1ad)
	    - 0x07 DSCP AF class (IETF RFC 2597)

	    The default value is 0x00.

	    This attribute is readable and writable by the OLT.
	*/
	uint8_t ingress_color_marking;

	/** Egress Color Marking

	    This attribute specifies how the drop precedence is to be marked by
	    the ONU on egress packets. If set to internal marking only, the
	    externally visible packet contents are not modified, but the packet
	    is identified in a vendor specific local way that indicates its
	    color to the priority queue-G Managed Entity. It is possible for
	    the egress marking to differ from the ingress marking. For example,
	    ingress PCP marking could be translated to DEI egress marking.
	    The coding is:
	    - 0x00 No marking (ignore ingress marking)
	    - 0x01 Internal marking only
	    - 0x02 DEI (IEEE 802.1ad)
	    - 0x03 PCP 8P0D (IEEE 802.1ad)
	    - 0x04 PCP 7P1D (IEEE 802.1ad)
	    - 0x05 PCP 6P2D (IEEE 802.1ad)
	    - 0x06 PCP 5P3D (IEEE 802.1ad)
	    - 0x07 DSCP AF class (IETF RFC 2597)

	    The default value is 0x00.

	    This attribute is readable and writable by the OLT.
	*/
	uint8_t egress_color_marking;

	/** Meter Type

	    This attribute specifies the algorithm used to determine the color
	    of the packet.
	    The coding is:
	    - 0x00 Not specified
	    - 0x01 According to IETF RFC 4115 (DSCP two-rate three color
	    marking)
	    - 0x02 According to IETF RFC 2698 (two-rate three color marking)

	    The default value is 0x00.

	    This attribute is readable and writable by the OLT.
	*/
	uint8_t meter_type;

} __PACKED__;

/** This enumerator holds the attribute numbers of the Traffic Descriptor
    Managed Entity.
*/
enum {
	omci_me_traffic_descriptor_cir = 1,
	omci_me_traffic_descriptor_pir = 2,
	omci_me_traffic_descriptor_cbs = 3,
	omci_me_traffic_descriptor_pbs = 4,
	omci_me_traffic_descriptor_color_mode = 5,
	omci_me_traffic_descriptor_ingress_color_marking = 6,
	omci_me_traffic_descriptor_egress_color_marking = 7,
	omci_me_traffic_descriptor_meter_type = 8
};

/** @} */

/** @} */

__END_DECLS

#endif
