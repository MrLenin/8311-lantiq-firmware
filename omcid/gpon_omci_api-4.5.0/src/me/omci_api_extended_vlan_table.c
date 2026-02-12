/******************************************************************************

                              Copyright (c) 2012
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_extended_vlan_config_data.h"
#include "me/omci_api_extended_vlan_table.h"

#define X 0 /* don't care value */
#define NA -1
/* range checks, 0 - 4095 */
#define VIDc -2
#define VIDs -3
#define VIDx -4
#define VIDy -5
/* range checks, 0 - 7 */
#define Pc -6
#define Px -7
#define Py -8
#define E -9
#define PxOr8 -10
#define PyOr8 -11
#define default_inner_VID -12
#define default_outer_VID -13
#define m_4_6_7 -14
#define m_0_2_4_6_7 -15
#define m_0_7 -16
#define DEF -18
#define Ps -19
#define S -20
#define m_0_4 -21
#define m_1_4 -22

#define tip -30
#define tiv -31
#define tit -32
#define tot -33
#define top -34
#define fip -35
#define fiv -36
#define fop -37
#define tov -38
#define fov -39

struct omci_rules omci_rules[] =
{
	/* Untagged ingress frames */
	{{0,1,"Do nothing (default flow)",
		{15,4096,0,15,4096,0,0,0,15,NA,NA,15,NA,NA},
	},
	{0,1,"If untagged, do nothing",
		{15,4096,0,15,4096,0,0,0,15,NA,0,15,NA,0},
	}},
	{{0,2,"Do nothing (non-default flow)",
		{15,4096,0,15,4096,0,m_1_4,0,15,NA,NA,15,NA,NA},
	},
	{0,2,"If untagged, do nothing",
		{15,4096,0,15,4096,0,m_1_4,0,15,NA,0,15,NA,0},
	}},
	{{0,3,"Drop all (default flow)",
		{15,4096,0,15,4096,0,0,3,15,4096,0,15,4096,0},
	},
	{0,3,"There is no reverse rule for dropping",
		{NA,NA,NA,NA,NA,NA,NA,NA,NA,NA,NA,NA,NA,NA},
	}},
	{{0,4,"Drop all (non-default flow)",
		{15,4096,0,15,4096,0,m_1_4,3,15,4096,0,15,4096,0},
	},
	{0,4,"There is no reverse rule for dropping",
		{NA,NA,NA,NA,NA,NA,NA,NA,NA,NA,NA,NA,NA,NA},
	}},
	{{0,5,"Insert one full tag X with fixed prio (default flow)",
		{15,4096,0,15,4096,0,0,0,15,NA,NA,m_0_7,VIDx,m_4_6_7},
	},
	{0,5,"If single-tagged with X, remove outer tag X",
		{8,4096,0,PxOr8,VIDx,0,0,1,15,NA,0,15,NA,0},
	}},
	{{0,6,"Insert one full tag X with prio from DSCP (default flow)",
		{15,4096,0,15,4096,0,0,0,15,NA,NA,10,VIDx,m_4_6_7},
	},
	{0,6,"If single-tagged with X, remove outer tag X",
		{8,4096,0,PxOr8,VIDx,0,0,1,15,NA,0,15,NA,0},
	}},
	{{0,7,"Insert one full tag X with fixed prio for given Ethertype",
		{15,4096,0,15,4096,0,m_1_4,0,15,NA,NA,m_0_7,VIDx,m_4_6_7},
	},
	{0,7,"If single-tagged with X, remove outer tag X",
		{8,4096,0,PxOr8,VIDx,0,m_1_4,1,15,NA,0,15,NA,0},
	}},
	{{0,8,"Insert two full tags (outer=Y, inner=X) (default flow)",
		{15,4096,0,15,4096,0,0,0,m_0_7,VIDy,m_4_6_7,m_0_7,VIDx,m_4_6_7},
	},
	{0,8,"If double-tagged with Y-X, remove two outer tags (outer=Y, inner=X)",
		{PyOr8,VIDy,0,PxOr8,VIDx,0,0,2,15,NA,0,15,NA,0},
	}},
	{{0,9,"Insert two full tags (outer=Y, inner=X)",
		{15,4096,0,15,4096,0,m_1_4,0,m_0_7,VIDy,m_4_6_7,m_0_7,VIDx,m_4_6_7},
	},
	{0,9,"If double-tagged with Y-X, remove two outer tags (outer=Y, inner=X)",
		{PyOr8,VIDy,0,PxOr8,VIDx,0,m_1_4,2,15,NA,0,15,NA,0},
	}},
	/* Single-tagged ingress frames */
	{{1,1,"Do nothing (default flow)",
		{15,4096,0,14,4096,0,0,0,15,NA,NA,15,NA,NA},
	},
	{1,1,"If single-tagged, do nothing (default flow)",
		{15,4096,0,14,4096,0,0,0,15,NA,0,15,NA,0},
	}},
	{{1,2,"Do nothing (non-default flow)",
		{15,4096,0,14,4096,0,m_1_4,0,15,NA,NA,15,NA,NA},
	},
	{1,2,"If single-tagged, do nothing (non-default flow)",
		{15,4096,0,14,4096,0,m_1_4,0,15,NA,0,15,NA,0},
	}},
	{{1,3,"Drop all (default flow)",
		{15,4096,0,14,4096,0,0,3,15,4096,0,15,4096,0},
	},
	{1,3,"There is no reverse rule for dropping",
		{NA,NA,NA,NA,NA,NA,NA,NA,NA,NA,NA,NA,NA,NA},
	}},
	{{1,4,"Drop all (non-default flow)",
		{15,4096,0,14,4096,0,m_1_4,3,15,4096,0,15,4096,0},
	},
	{1,4,"There is no reverse rule for dropping",
		{NA,NA,NA,NA,NA,NA,NA,NA,NA,NA,NA,NA,NA,NA},
	}},
	{{1,5,"Insert one full tag X to all single-tagged",
		{15,4096,0,8,4096,0,m_0_4,0,15,NA,NA,m_0_7,VIDx,m_0_2_4_6_7},
	},
	{1,5,"If double-tagged, remove one tag X from all double-tagged",
		{PxOr8,4096,0,15,4096,0,m_0_4,1,15,NA,0,15,NA,0},
	}},
	{{1,6,"Drop all single-tagged with C-tag",
		{15,4096,0,8,4096,4,m_0_4,3,15,4096,0,15,4096,0},
	},
	{1,6,"There is no reverse rule for dropping",
		{NA,NA,NA,NA,NA,NA,NA,NA,NA,NA,NA,NA,NA,NA},
	}},
	{{1,7,"Drop all single-tagged with S-tag",
		{15,4096,0,8,4096,6,m_0_4,3,15,4096,0,15,4096,0},
	},
	{1,7,"There is no reverse rule for dropping",
		{NA,NA,NA,NA,NA,NA,NA,NA,NA,NA,NA,NA,NA,NA},
	}},
	{{1,8,"Drop all single-tagged with S-tag and VIDs",
		{15,4096,0,8,VIDs,6,m_0_4,3,15,4096,0,15,4096,0},
	},
	{1,8,"There is no reverse rule for dropping",
		{NA,NA,NA,NA,NA,NA,NA,NA,NA,NA,NA,NA,NA,NA},
	}},
	{{1,9,"Insert one full tag X if outer tag is C",
		{15,4096,0,8,VIDc,0,m_0_4,0,15,NA,NA,m_0_7,VIDx,m_0_2_4_6_7},
	},
	{1,9,"If double-tagged, remove one tag X if inner tag is C",
		{PxOr8,VIDx,0,8,VIDc,0,m_0_4,1,15,NA,0,15,NA,0},
	}},
	{{1,10,"Insert one tag X if outer tag is C, copy prio form C",
		{15,4096,0,8,VIDc,0,m_0_4,0,15,NA,NA,8,VIDx,m_0_2_4_6_7},
	},
	{1,10,"If double-tagged, remove one tag X if inner tag is C and copy prio from X to C",
		{8,VIDx,0,8,VIDc,0,m_0_4,2,15,NA,0,9,VIDc,0},
	}},
	{{1,11,"Insert one tag X if outer tag is C, derive prio from DSCP",
		{15,4096,0,8,VIDc,0,m_0_4,0,15,NA,NA,10,VIDx,m_0_2_4_6_7},
	},
	{1,11,"If double-tagged, remove one tag X if inner tag is C and copy prio from X to C",
		{8,VIDx,0,8,VIDc,0,m_0_4,2,15,NA,0,9,VIDc,0},
	}},
	{{1,12,"Modify tag to X if outer tag is C, derive prio from DSCP",
		{15,4096,0,8,VIDc,0,m_0_4,1,15,NA,NA,10,VIDx,m_0_2_4_6_7},
	},
	{1,12,"If single-tagged and outer tag is X, change to C and keep prio.",
		{8,4096,0,8,VIDx,0,m_0_4,1,15,NA,0,9,VIDc,0},
	}},
	{{1,13,"Insert two full tags Y-X to all single-tagged",
		{15,4096,0,8,VIDc,0,m_0_4,0,m_0_7,VIDy,m_0_2_4_6_7,m_0_7,VIDx,m_0_2_4_6_7},
	},
	{1,13,"If quad-tagged, remove two tags, if outer is Y and inner is X",
		{PyOr8,VIDy,0,PxOr8,VIDx,0,m_0_4,2,15,NA,0,15,NA,0},
	}},
	{{1,14,"Insert two full tags Y-X to all single-tagged if outer tag is C",
		{15,4096,0,8,VIDc,0,m_0_4,0,m_0_7,VIDy,m_0_2_4_6_7,m_0_7,VIDx,m_0_2_4_6_7},
	},
	{1,14,"If quad-tagged, remove two tags, if outer is Y and inner is X",
		{PyOr8,VIDy,0,PxOr8,VIDx,0,m_0_4,2,15,NA,0,15,NA,0},
	}},
	{{1,15,"Modify tag if tag is C (new VIDx, new prio Px)",
		{15,4096,0,8,VIDc,0,m_0_4,1,15,NA,NA,m_0_7,VIDx,m_0_2_4_6_7},
	},
	{1,15,"If single-tagged and tag is X, modify to C and copy prio",
		{15,4096,0,PxOr8,VIDx,0,m_0_4,1,15,NA,0,8,VIDc,0},
	}},
	{{1,16,"Modify tag if tag is C (new VIDx, keep prio Pc)",
		{15,4096,0,8,VIDc,4,m_0_4,1,15,NA,NA,8,VIDx,m_0_2_4_6_7},
	},
	{1,16,"If single-tagged and tag is X, modify to C and copy prio",
		{15,4096,0,PxOr8,VIDx,0,m_0_4,1,15,NA,0,8,VIDc,0},
	}},
	{{1,17,"Modify tag if tag is C with given prio (new VIDx, new prio Px)",
		{15,4096,0,Pc,VIDc,0,m_0_4,1,15,NA,NA,m_0_7,VIDx,m_0_2_4_6_7},
	},
	{1,17,"If single-tagged and tag is X, modify to C and set prio",
		{15,4096,0,PxOr8,VIDx,0,m_0_4,1,15,NA,0,Pc,VIDc,0},
	}},
	{{1,18,"Modify tag if tag is C with any prio (new VIDx, new Px, default rule)",
		{15,4096,0,14,VIDc,0,m_0_4,1,15,NA,NA,m_0_7,VIDx,m_0_2_4_6_7},
	},
	{1,18,"If single-tagged and tag is X, modify to C and copy prio",
		{15,4096,0,PxOr8,VIDx,0,m_0_4,1,15,NA,0,8,VIDc,0},
	}},
	{{1,19,"Modify tag if tag is anything with given prio (new VIDx, new prio Px)",
		{15,4096,0,Pc,4096,0,m_0_4,1,15,NA,NA,m_0_7,VIDx,m_0_2_4_6_7},
	},
	{1,19,"If single-tagged and tag is X, modify to 0 and set prio",
		{15,4096,0,PxOr8,VIDx,0,m_0_4,1,15,NA,0,Pc,0,0},
	}},
	{{1,20,"Modify a the existing tag (C->X) and add another one Y",
		{15,4096,0,8,VIDc,0,m_0_4,1,m_0_7,VIDy,NA,m_0_7,VIDx,m_0_2_4_6_7},
	},
	{1,20,"If double-tagged, remove the outer tag Y and change the inner from X to C.",
		{Py,VIDy,0,Px,VIDx,0,m_0_4,2,15,NA,0,0,VIDc,0},
	}},
	{{1,21,"Remove the tag, if tag is VIDc",
		{15,4096,0,8,VIDc,0,m_0_4,1,15,NA,NA,15,NA,NA},
	},
	{1,21,"If untagged, add a single tag C with prio 0",
		{15,4096,0,15,4096,0,m_0_4,0,15,NA,0,0,VIDc,0},
	}},
	{{1,22,"Remove the tag, if tag is VIDc and prio is Pc",
		{15,4096,0,Pc,VIDc,0,m_0_4,1,15,NA,NA,15,NA,NA},
	},
	{1,22,"If untagged, add a single tag C with prio Pc",
		{15,4096,0,15,4096,0,m_0_4,0,15,NA,0,Pc,VIDc,0},
	}},
	{{1,23,"Remove the tag, whatever it is",
		{15,4096,0,8,4096,0,m_0_4,1,15,NA,NA,15,NA,NA},
	},
	{1,23,"If untagged, add a zero tag (priority-tagged)",
		{15,4096,0,15,4096,0,m_0_4,0,15,NA,0,0,0,0},
	}},
	{{1,24,"Replace the tag, whatever it is, depending on Ethertype",
		{15,4096,0,8,4096,0,m_0_4,1,15,NA,NA,m_0_7,VIDx,m_0_2_4_6_7},
	},
	{1,24,"If tagged with VIDx/Px and Ethertype matches, replace with zero tag (priority-tagged)",
		{15,4096,0,Px,VIDx,0,m_0_4,1,15,NA,0,0,0,0},
	}},
	/* Double-tagged ingress frames */
	{{2,1,"Do nothing (default flow)",
		{14,4096,0,14,4096,0,0,0,15,NA,NA,15,NA,NA},
	},
	{2,1,"If double-tagged (or more), do nothing (default flow)",
		{14,4096,0,14,4096,0,0,0,15,NA,0,15,NA,0},
	}},
	{{2,2,"Do nothing (non-default flow)",
		{14,4096,0,14,4096,0,m_1_4,0,15,NA,NA,15,NA,NA},
	},
	{2,2,"If double-tagged (or more), do nothing (default flow)",
		{14,4096,0,14,4096,0,m_1_4,0,15,NA,0,15,NA,0},
	}},
	{{2,3,"Drop all (default flow)",
		{14,4096,0,14,4096,0,0,3,15,4096,0,15,4096,0},
	},
	{2,3,"There is no reverse rule for dropping",
		{NA,NA,NA,NA,NA,NA,NA,NA,NA,NA,NA,NA,NA,NA},
	}},
	{{2,4,"Drop all (non-default flow)",
		{14,4096,0,14,4096,0,m_1_4,3,15,4096,0,15,4096,0},
	},
	{2,4,"There is no reverse rule for dropping",
		{NA,NA,NA,NA,NA,NA,NA,NA,NA,NA,NA,NA,NA,NA},
	}},
	{{2,5,"Add another tag X to tags S (outer) and C (inner) with fixed prio",
		{8,VIDs,0,8,VIDc,0,m_0_4,0,15,NA,NA,m_0_7,VIDx,m_0_7},
	},
	{2,5,"If triple-tagged with VIDx/Vids/VIDc, remove the tag",
		{PxOr8,VIDx,0,8,VIDs,0,m_0_4,1,15,NA,0,15,NA,0},
	}},
	{{2,6,"Add another tag X to tags S (outer) and C (inner), copy prio from outer tag S",
		{8,VIDs,0,8,VIDc,0,m_0_4,0,15,NA,NA,9,VIDx,m_0_7},
	},
	{2,6,"If triple-tagged with VIDx/VIDs/VIDc, copy the prio from old outer to new outer tag, remove the outer tag",
		{8,VIDx,0,8,VIDs,0,m_0_4,2,9,VIDs,0,15,NA,0},
	}},
	{{2,7,"Add two tags Y (outer) and  X (inner) to tags S (outer) and C (inner) with fixed prios",
		{8,VIDs,0,8,VIDc,0,m_0_4,0,m_0_7,VIDy,m_0_7,m_0_7,VIDx,m_0_7},
	},
	{2,7,"If quad-tagged with Y-X-S-C, remove two tags.",
		{PyOr8,VIDy,0,PxOr8,VIDx,0,m_0_4,2,15,NA,0,15,NA,0},
	}},
	{{2,8,"Add two tags Y (outer) and  X (inner) to tags S (outer) and C (inner) with copied prios",
		{8,VIDs,0,8,VIDc,0,m_0_4,0,9,VIDy,m_0_7,8,VIDx,m_0_7},
	},
	{2,8,"If quad-tagged with Y-X-S-C, remove two tags.",
		{8,VIDy,0,8,VIDx,0,m_0_4,2,9,NA,0,8,NA,0},
	}},
	{{2,9,"Modify the outer tag to new VIDx and new prio",
		{8,VIDs,0,8,VIDc,0,m_0_4,1,15,NA,NA,m_0_7,VIDx,m_0_7},
	},
	{2,9,"If double-tagged with X-C, modify the outer tag to S.",
		{PxOr8,VIDx,0,8,VIDc,0,m_0_4,1,15,NA,0,9,VIDs,0},
	}},
	{{2,10,"Modify the outer tag if outer tag matches",
		{8,VIDs,5,14,4096,0,m_0_4,1,15,NA,NA,9,VIDx,m_0_7},
	},
	{2,10,"Modify the outer tag if outer tag matches",
		{8,VIDx,0,14,4096,0,m_0_4,1,15,NA,0,9,VIDs,0},
	}},
	{{2,11,"Modify the outer tag if outer tag and outer pbit matches",
		{Ps,VIDs,5,8,4096,0,m_0_4,1,15,NA,NA,Px,VIDx,m_0_7},
	},
	{2,11,"Modify the outer tag if outer tag and prio matches",
		{PxOr8,VIDx,0,14,4096,0,m_0_4,1,15,NA,0,Ps,VIDs,0},
	}},
	{{2,12,"Modify the outer tag to new VID and keep prio for inner tag VIDc and any inner prio",
		{8,VIDs,0,8,VIDc,0,m_0_4,1,15,NA,NA,9,VIDx,m_0_7},
	},
	{2,12,"If double-tagged with X-S with any Px and any Ps, modify the outer tag, keep outer prio.",
		{8,VIDx,0,8,VIDc,0,m_0_4,1,15,NA,0,9,VIDs,0},
	}},
	{{2,13,"Modify the outer tag to new VID and keep prio for any inner tag and inner prio",
		{8,VIDs,0,8,4096,0,m_0_4,1,15,NA,NA,9,VIDx,m_0_7},
	},
	{2,13,"If double-tagged with X-S with any Px and any Ps, modify the outer tag, keep outer prio.",
		{8,VIDx,0,8,VIDc,0,m_0_4,1,15,NA,0,9,VIDs,0},
	}},
	{{2,14,"Modify both tags to new fixed values and new prios",
		{8,VIDs,0,8,VIDc,0,m_0_4,2,m_0_7,VIDy,m_0_7,m_0_7,VIDx,m_0_7},
	},
	{2,14,"If double-tagged with Y-X, modify both tags to old values S-C, keep rpiorities.",
		{PyOr8,VIDy,0,PxOr8,VIDx,0,m_0_4,2,9,VIDs,0,8,VIDc,0},
	}},
	{{2,15,"Modify both tags to new fixed values and keep prios",
		{8,VIDs,0,8,VIDc,0,m_0_4,2,9,VIDy,m_0_7,8,VIDx,m_0_7},
	},
	{2,15,"If double-tagged with Y-X, modify both tags to old values S-C and copy prios.",
		{8,VIDy,0,8,VIDx,0,m_0_4,2,9,VIDs,0,8,VIDc,0},
	}},
	{{2,16,"Swap both tags",
		{8,VIDs,0,8,VIDc,0,m_0_4,2,8,4096,m_0_7,9,4097,m_0_7},
	},
	{2,16,"If double-tagged, swap both tags back.",
		{8,VIDc,0,8,VIDs,0,m_0_4,2,8,4096,0,9,4097,0},
	}},
	{{2,17,"Remove the outer tag, if tag is S-C.",
		{8,VIDs,0,8,VIDc,0,m_0_4,1,15,NA,NA,15,NA,NA},
	},
	{2,17,"If single-tagged with C, add a tag S.",
		{15,4096,0,8,VIDc,0,m_0_4,0,15,NA,0,0,VIDc,0},
	}},
	{{2,18,"Remove both tags, if tags are S and C.",
		{8,VIDs,0,8,VIDc,0,m_0_4,2,15,NA,NA,15,NA,NA},
	},
	{2,18,"If untagged, add two tags C and S.",
		{15,4096,0,15,4096,0,m_0_4,0,0,VIDs,0,0,VIDc,0},
	}},
	{{2,19,"Remove both tags.",
		{8,4096,0,8,4096,0,m_0_4,2,15,NA,NA,15,NA,NA},
	},
	{2,19,"If untagged, add two tags.",
		{15,4096,0,15,4096,0,m_0_4,0,0,default_inner_VID,0,0,default_outer_VID,0},
	}},
};
struct sce_rules sce_rules[] =
{
/* Untagged ingress frames on u/s ingress */
	{{0,1,"Do nothing (default flow)",
		{1,0,0},
		{0,X,0,X,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		1,
		{15,X,X,15,X,X,0,1,1},
	},
	{0,1,"If untagged, do nothing",
		{1,0,0},
		{X,X,X,X,X,X,X},
		{X,X,X,X,X,X,X},
		{0,0,0,0,0},
		1,
		{15,X,X,15,X,X,0,1,1},
	}},
	{{0,2,"Do nothing (non-default flow)",
		{1,0,0},
		{0,X,0,X,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		0,
		{15,X,X,15,X,X,0,1,1},
	},
	{0,2,"If untagged, do nothing",
		{1,0,0},
		{X,X,X,X,X,X,X},
		{X,X,X,X,X,X,X},
		{0,0,0,0,0},
		0,
		{15,X,X,15,X,X,0,1,1},
	}},
	{{0,3,"Drop all (default flow)",
		{1,0,0},
		{0,X,0,X,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		1,
		{X,X,X,X,X,X,1,1,1},
	},
	{0,3,"There is no reverse rule for dropping",
		{0,0,0},
		{0,0,0,0,0,0,0},
		{0,0,0,0,0,0,0},
		{0,0,0,0,0},
		0,
		{0,0,0,0,0,0,0,0,0},
	}},
	{{0,4,"Drop all (non-default flow)",
		{1,0,0},
		{0,X,0,X,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		0,
		{X,X,X,X,X,X,1,1,1},
	},
	{0,4,"There is no reverse rule for dropping",
		{0,0,0},
		{0,0,0,0,0,0,0},
		{0,0,0,0,0,0,0},
		{0,0,0,0,0},
		0,
		{0,0,0,0,0,0,0,0,0},
	}},
	{{0,5,"Insert one full tag X with fixed prio (default flow)",
		{1,0,0},
		{0,X,0,X,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		1,
		{tip,tiv,tit,15,X,X,0,1,1},
	},
	{0,5,"If single-tagged with X, remove outer tag X",
		{0,1,0},
		{0,X,0,X,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		1,
		{15,X,X,15,X,X,0,1,1},
	}},
	{{0,6,"Insert one full tag X with prio from DSCP (default flow)",
		{1,0,0},
		{0,X,0,X,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		1,
		{tip,tiv,tit,15,X,X,0,1,1},
	},
	{0,6,"If single-tagged with X, remove outer tag X",
		{0,1,0},
		{0,X,0,X,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		1,
		{15,X,X,15,X,X,0,1,1},
	}},
	{{0,7,"Insert one full tag X with fixed prio for given Ethertype",
		{1,0,0},
		{0,X,0,X,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		0,
		{tip,tiv,tit,15,X,X,0,1,1},
	},
	{0,7,"If single-tagged with X, remove outer tag X",
		{0,1,0},
		{0,X,0,X,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		0,
		{15,X,X,15,X,X,0,1,1},
	}},
	{{0,8,"Insert two full tags (outer=Y, inner=X) (default flow)",
		{1,0,0},
		{0,X,0,X,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		1,
		{top,tov,tot,tip,tiv,tit,0,1,1},
	},
	{0,8,"If double-tagged with Y-X, remove two outer tags (outer=Y, inner=X)",
		{0,0,1},
		{0,X,0,X,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		1,
		{15,X,X,15,X,X,0,1,1},
	}},
	{{0,9,"Insert two full tags (outer=Y, inner=X)",
		{1,0,0},
		{0,X,0,X,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		0,
		{top,tov,tot,tip,tiv,tit,0,1,1},
	},
	{0,9,"If double-tagged with Y-X, remove two outer tags (outer=Y, inner=X)",
		{0,0,1},
		{0,X,0,X,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		0,
		{15,X,X,15,X,X,0,1,1},
	}},
/* Single-tagged ingress frames on u/s ingress */
	{{1,1,"Do nothing (default flow)",
		{0,1,0},
		{0,X,0,X,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		1,
		{15,X,X,15,X,X,0,0,1},
	},
	{1,1,"If single-tagged, do nothing (default flow)",
		{0,1,0},
		{0,X,0,X,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		1,
		{15,X,X,15,X,X,0,0,1},
	}},
	{{1,2,"Do nothing (non-default flow)",
		{0,1,0},
		{0,X,0,X,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		0,
		{15,X,X,15,X,X,0,0,1},
	},
	{1,2,"If single-tagged, do nothing (non-default flow)",
		{0,1,0},
		{0,X,0,X,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		0,
		{15,X,X,15,X,X,0,0,1},
	}},
	{{1,3,"Drop all (default flow)",
		{0,1,0},
		{0,X,0,X,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		1,
		{15,X,X,15,X,X,1,0,0},
	},
	{1,3,"There is no reverse rule for dropping",
		{0,0,0},
		{0,0,0,0,0,0,0},
		{0,0,0,0,0,0,0},
		{0,0,0,0,0},
		0,
		{0,0,0,0,0,0,0,0,0},
	}},
	{{1,4,"Drop all (non-default flow)",
		{0,1,0},
		{0,X,0,X,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		0,
		{15,X,X,15,X,X,1,0,0},
	},
	{1,4,"There is no reverse rule for dropping",
		{0,0,0},
		{0,0,0,0,0,0,0},
		{0,0,0,0,0,0,0},
		{0,0,0,0,0},
		0,
		{0,0,0,0,0,0,0,0,0},
	}},
	{{1,5,"Insert one full tag X to all single-tagged",
		{0,1,0},
		{0,X,0,X,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		1,
		{tip,tiv,tit,15,X,X,0,0,1},
	},
	{1,5,"If double-tagged, remove one tag X from all double-tagged",
		{0,0,1},
		{1,tip,1,tiv,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		0,
		{15,X,X,15,X,X,0,1,0},
	}},
	{{1,6,"Drop all single-tagged with C-tag",
		{0,0,0},
		{0,0,0,0,1,0,0},
		{0,0,0,0,0,0,0},
		{0,0,0,0,0},
		0,
		{15,X,X,15,X,X,1,0,0},
	},
	{1,6,"There is no reverse rule for dropping",
		{0,0,0},
		{0,0,0,0,0,0,0},
		{0,0,0,0,0,0,0},
		{0,0,0,0,0},
		0,
		{0,0,0,0,0,0,0,0,0},
	}},
	{{1,7,"Drop all single-tagged with S-tag",
		{0,1,0},
		{0,X,0,X,1,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		0,
		{15,X,X,15,X,X,1,0,0},
	},
	{1,7,"There is no reverse rule for dropping",
		{0,0,0},
		{0,0,0,0,0,0,0},
		{0,0,0,0,0,0,0},
		{0,0,0,0,0},
		0,
		{0,0,0,0,0,0,0,0,0},
	}},
	{{1,8,"Drop all single-tagged with S-tag and VIDs",
		{0,0,0},
		{0,0,0,0,0,0,0},
		{0,0,0,0,0,0,0},
		{0,0,0,0,0},
		0,
		{15,X,X,15,X,X,1,0,0},
	},
	{1,8,"There is no reverse rule for dropping",
		{0,0,0},
		{0,0,0,0,0,0,0},
		{0,0,0,0,0,0,0},
		{0,0,0,0,0},
		0,
		{0,0,0,0,0,0,0,0,0},
	}},
	{{1,9,"Insert one full tag X if outer tag is C",
		{0,1,0},
		{0,X,1,fiv,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		0,
		{tip,tiv,tit,15,X,X,0,0,1},
	},
	{1,9,"If double-tagged, remove one tag X if inner tag is C",
		{0,0,1},
		{1,tip,1,tiv,0,0,X},
		{0,X,1,fiv,0,0,X},
		{0,0,0,0,0},
		0,
		{15,X,X,15,X,X,0,1,0},
	}},
	{{1,10,"Insert one tag X if outer tag is C, copy prio form C",
		{0,1,0},
		{0,X,1,fiv,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		0,
		{9,tiv,tit,15,X,X,0,0,1},
	},
	{1,10,"If double-tagged, remove one tag X if inner tag is C and copy prio from X to C",
		{0,0,1},
		{0,X,1,tiv,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		0,
		{15,X,X,15,X,X,0,1,0},
	}},
	{{1,11,"Insert one tag X if outer tag is C, derive prio from DSCP",
		{0,1,0},
		{0,X,1,fiv,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		0,
		{10,tiv,tit,15,X,X,0,0,1},
	},
	{1,11,"If double-tagged, remove one tag X if inner tag is C and copy prio from X to C",
		{0,0,1},
		{0,X,0,X,0,0,X},
		{0,X,1,tiv,0,0,X},
		{0,0,0,0,0},
		0,
		{15,X,X,15,X,X,0,1,0},
	}},
	{{1,12,"Modify tag to X if outer tag is C, derive prio from DSCP",
		{0,1,0},
		{0,X,1,fiv,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		0,
		{10,tiv,tit,15,X,X,0,1,1},
	},
	{1,12,"If single-tagged and outer tag is X, change to C and keep prio.",
		{0,1,0},
		{0,X,1,tiv,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		0,
		{9,fiv,X,15,X,X,0,1,1},
	}},
	{{1,13,"Insert two full tags Y-X to all single-tagged",
		{0,1,0},
		{0,X,0,X,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		0,
		{top,tov,tot,tip,tiv,tit,0,0,1},
	},
	{1,13,"If quad-tagged, remove two tags, if outer is Y and inner is X",
		{0,0,1},
		{0,X,1,tov,0,0,X},
		{0,X,1,tiv,0,0,X},
		{0,0,0,0,0},
		0,
		{15,X,X,15,X,X,0,1,1},
	}},
	{{1,14,"Insert two full tags Y-X to all single-tagged if outer tag is C",
		{0,1,0},
		{0,X,1,fiv,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		0,
		{top,tov,tot,tip,tiv,tit,0,0,1},
	},
	{1,14,"If quad-tagged, remove two tags, if outer is Y and inner is X",
		{0,0,1},
		{0,X,1,tov,0,0,X},
		{0,X,1,tiv,0,0,X},
		{0,0,0,0,0},
		0,
		{15,X,X,15,X,X,0,1,1},
	}},
	{{1,15,"Modify tag if tag is C (new VIDx, new prio Px)",
		{0,1,0},
		{0,X,1,fiv,1,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		0,
		{tip,tiv,tit,15,X,X,0,1,1},
	},
	{1,15,"If single-tagged and tag is X, modify to C and copy prio",
		{0,1,0},
		{1,tip,1,tiv,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		0,
		{fip,fiv,6,15,X,X,0,1,1},
	}},
	{{1,16,"Modify tag if tag is C (new VIDx, keep prio Pc)",
		{0,1,0},
		{0,X,1,fiv,1,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		0,
		{9,tiv,tit,15,X,X,0,1,1},
	},
	{1,16,"If single-tagged and tag is X, modify to C and copy prio",
		{0,1,0},
		{0,X,1,tiv,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		0,
		{9,fiv,6,15,X,X,0,1,1},
	}},
	{{1,17,"Modify tag if tag is C with given prio (new VIDx, new prio Px)",
		{0,1,0},
		{1,fip,1,fiv,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		0,
		{tip,tiv,tit,15,X,X,0,1,1},
	},
	{1,17,"If single-tagged and tag is X, modify to C and set prio",
		{0,1,0},
		{0,X,1,tiv,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		0,
		{9,fiv,6,15,X,X,0,1,1},
	}},
	{{1,18,"Modify tag if tag is C with any prio (new VIDx, new Px, default rule)",
		{0,1,0},
		{0,X,1,fiv,1,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		1,
		{tip,tiv,tit,15,X,X,0,1,1},
	},
	{1,18,"If single-tagged and tag is X, modify to C and copy prio",
		{0,1,0},
		{0,X,1,tiv,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		0,
		{9,fiv,6,15,X,X,0,1,1},
	}},
	{{1,19,"Modify tag if tag is anything with given prio (new VIDx, new prio Px)",
		{0,1,0},
		{1,fip,0,X,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		0,
		{tip,tiv,tit,15,X,X,0,1,1},
	},
	{1,19,"If single-tagged and tag is X, modify to 0 and set prio",
		{0,1,0},
		{0,X,1,tiv,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		0,
		{9,0,6,15,X,X,0,1,1},
	}},
	{{1,20,"Modify a the existing tag (C->X) and add another one Y",
		{0,1,0},
		{0,X,1,fiv,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		0,
		{top,tov,tot,tip,tiv,tit,0,1,1},
	},
	{1,20,"If double-tagged, remove the outer tag Y and change the inner from X to C.",
		{0,0,1},
		{0,X,1,tov,0,0,X},
		{0,X,1,tiv,0,0,X},
		{0,0,0,0,0},
		0,
		{9,fiv,6,15,X,X,0,1,1},
	}},
	{{1,21,"Remove the tag, if tag is VIDc",
		{0,1,0},
		{0,X,1,fiv,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		0,
		{15,X,X,15,X,X,0,1,1},
	},
	{1,21,"If untagged, add a single tag C with prio 0",
		{1,0,0},
		{X,X,X,X,X,X,X},
		{X,X,X,X,X,X,X},
		{0,0,0,0,0},
		0,
		{0,fiv,6,15,X,X,0,1,1},
	}},
	{{1,22,"Remove the tag, if tag is VIDc and prio is Pc",
		{0,1,0},
		{1,fip,1,fiv,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		0,
		{15,X,X,15,X,X,0,1,1},
	},
	{1,22,"If untagged, add a single tag C with prio Pc",
		{1,0,0},
		{X,X,X,X,X,X,X},
		{X,X,X,X,X,X,X},
		{0,0,0,0,0},
		0,
		{fip,fiv,6,15,X,X,0,1,1},
	}},
	{{1,23,"Remove the tag, whatever it is",
		{0,1,0},
		{0,X,0,X,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		1,
		{15,X,X,15,X,X,0,1,1},
	},
	{1,23,"If untagged, add a zero tag (priority-tagged)",
		{1,0,0},
		{X,X,X,X,X,X,X},
		{X,X,X,X,X,X,X},
		{0,0,0,0,0},
		0,
		{0,0,6,15,X,X,0,1,1},
	}},
	{{1,24,"Replace the tag, whatever it is, depending on Ethertype",
		{0,1,0},
		{0,X,0,X,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		0,
		{tip,tiv,tit,15,X,X,0,1,1},
	},
	{1,24,"If tagged with VIDx/Px and Ethertype matches, replace with zero tag (priority-tagged)",
		{0,1,0},
		{1,tip,1,tiv,X,X,X},
		{X,X,X,X,X,X,X},
		{0,0,0,0,0},
		0,
		{0,0,6,15,X,X,0,1,1},
	}},
/* Double-tagged ingress frames on u/s ingress */
	{{2,1,"Do nothing (default flow)",
		{0,0,1},
		{0,X,0,X,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		1,
		{15,X,X,15,X,X,0,0,0},
	},
	{2,1,"If double-tagged (or more), do nothing (default flow)",
		{0,0,1},
		{0,X,0,X,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		1,
		{15,X,X,15,X,X,0,0,0},
	}},
	{{2,2,"Do nothing (non-default flow)",
		{0,0,1},
		{0,X,0,X,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		0,
		{15,X,X,15,X,X,0,0,0},
	},
	{2,2,"If double-tagged (or more), do nothing (default flow)",
		{0,0,1},
		{0,X,0,X,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		0,
		{15,X,X,15,X,X,0,0,0},
	}},
	{{2,3,"Drop all (default flow)",
		{0,0,1},
		{0,X,0,X,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		1,
		{15,X,X,15,X,X,0,1,1},
	},
	{2,3,"There is no reverse rule for dropping",
		{0,0,0},
		{0,0,0,0,0,0,0},
		{0,0,0,0,0,0,0},
		{0,0,0,0,0},
		0,
		{0,0,0,0,0,0,0,0,0},
	}},
	{{2,4,"Drop all (non-default flow)",
		{0,0,1},
		{0,X,0,X,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		0,
		{15,X,X,15,X,X,0,1,1},
	},
	{2,4,"There is no reverse rule for dropping",
		{0,0,0},
		{0,0,0,0,0,0,0},
		{0,0,0,0,0,0,0},
		{0,0,0,0,0},
		0,
		{0,0,0,0,0,0,0,0,0},
	}},
	{{2,5,"Add another tag X to tags S (outer) and C (inner) with fixed prio",
		{0,0,1},
		{0,X,1,fov,0,0,X},
		{0,X,1,fiv,0,0,X},
		{0,0,0,0,0},
		0,
		{tip,tiv,tit,15,X,X,0,0,0},
	},
	{2,5,"If triple-tagged with VIDx/Vids/VIDc, remove the tag",
		{0,1,0},
		{1,tip,1,tiv,0,0,X},
		{0,X,1,fov,0,0,X},
		{0,0,0,0,0},
		0,
		{15,X,X,15,X,X,0,1,0},
	}},
	{{2,6,"Add another tag X to tags S (outer) and C (inner), copy prio from outer tag S",
		{0,0,1},
		{0,X,1,fov,0,0,X},
		{0,X,1,fiv,0,0,X},
		{0,0,0,0,0},
		0,
		{tip,tiv,tit,15,X,X,0,0,0},
	},
	{2,6,"If triple-tagged with VIDx/VIDs/VIDc, copy the prio from old outer to new outer tag, remove the outer tag",
		{0,1,0},
		{0,X,1,tiv,0,0,X},
		{0,X,1,fov,0,0,X},
		{0,0,0,0,0},
		0,
		{15,X,X,15,X,X,0,1,0},
	}},
	{{2,7,"Add two tags Y (outer) and  X (inner) to tags S (outer) and C (inner) with fixed prios",
		{0,0,1},
		{0,X,1,fov,0,0,X},
		{0,X,1,fiv,0,0,X},
		{0,0,0,0,0},
		0,
		{top,tov,tot,tip,tiv,tit,0,0,0},
	},
	{2,7,"If quad-tagged with Y-X-S-C, remove two tags.",
		{0,0,1},
		{1,top,1,tov,0,0,X},
		{1,tip,1,tiv,0,0,X},
		{0,0,0,0,0},
		0,
		{15,X,X,15,X,X,0,1,1},
	}},
	{{2,8,"Add two tags Y (outer) and  X (inner) to tags S (outer) and C (inner) with copied prios",
		{0,0,1},
		{0,X,1,fov,0,0,X},
		{0,X,1,fiv,0,0,X},
		{0,0,0,0,0},
		0,
		{top,tov,tot,tip,tiv,tit,0,0,0},
	},
	{2,8,"If quad-tagged with Y-X-S-C, remove two tags.",
		{0,0,1},
		{1,top,1,tov,0,0,X},
		{1,tip,1,tiv,0,0,X},
		{0,0,0,0,0},
		0,
		{15,X,X,15,X,X,0,1,1},
	}},
	{{2,9,"Modify the outer tag to new VIDx and new prio",
		{0,0,1},
		{0,X,1,fov,0,0,X},
		{0,X,1,fiv,0,0,X},
		{0,0,0,0,0},
		0,
		{top,tov,tot,15,X,X,0,1,0},
	},
	{2,9,"If double-tagged with X-C, modify the outer tag to S.",
		{0,0,1},
		{1,top,1,tov,0,0,X},
		{1,fip,1,fiv,0,0,X},
		{0,0,0,0,0},
		0,
		{9,fov,6,15,X,X,0,1,0},
	}},
	{{2,10,"Modify the outer tag if outer tag matches",
		{0,0,1},
		{0,X,1,fov,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		0,
		{tip,tov,tot,15,X,X,0,1,0},
	},
	{2,10,"Modify the outer tag if outer tag matches",
		{0,0,1},
		{1,top,1,tov,0,0,X},
		{1,fip,1,fiv,0,0,X},
		{0,0,0,0,0},
		0,
		{9,fov,6,15,X,X,0,1,0},
	}},
	{{2,11,"Modify the outer tag if outer tag and outer pbit matches",
		{0,0,1},
		{1,fop,1,fov,1,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		0,
		{tip,tiv,tit,15,X,X,0,1,0},
	},
	{2,11,"Modify the outer tag if outer tag and prio matches",
		{0,0,1},
		{1,tip,1,tiv,0,0,X},
		{1,fip,1,fiv,0,0,X},
		{0,0,0,0,0},
		0,
		{fop,fov,6,15,X,X,0,1,0},
	}},
	{{2,12,"Modify the outer tag to new VID and keep prio for inner tag VIDc and any inner prio",
		{0,0,1},
		{0,X,1,fov,0,0,X},
		{0,X,1,fiv,0,0,X},
		{0,0,0,0,0},
		0,
		{tip,tiv,tit,15,X,X,0,1,0},
	},
	{2,12,"If double-tagged with X-S with any Px and any Ps, modify the outer tag, keep outer prio.",
		{0,0,1},
		{1,top,1,tov,0,0,X},
		{0,X,1,fiv,0,0,X},
		{0,0,0,0,0},
		0,
		{9,fov,6,15,X,X,0,1,0},
	}},
	{{2,13,"Modify the outer tag to new VID and keep prio for any inner tag and inner prio",
		{0,0,1},
		{0,X,1,fov,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		0,
		{tip,tiv,tit,15,X,X,0,1,0},
	},
	{2,13,"If double-tagged with X-S with any Px and any Ps, modify the outer tag, keep outer prio.",
		{0,0,1},
		{0,X,1,tiv,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		0,
		{9,fov,6,15,X,X,0,1,0},
	}},
	{{2,14,"Modify both tags to new fixed values and new prios",
		{0,0,1},
		{0,X,1,fov,0,0,X},
		{0,X,1,fiv,0,0,X},
		{0,0,0,0,0},
		0,
		{top,tov,tot,tip,tiv,tit,0,1,1},
	},
	{2,14,"If double-tagged with Y-X, modify both tags to old values S-C, keep rpiorities.",
		{0,0,1},
		{1,top,1,tov,0,0,X},
		{1,tip,1,tiv,0,0,X},
		{0,0,0,0,0},
		0,
		{8,fov,6,9,fiv,6,0,1,1},
	}},
	{{2,15,"Modify both tags to new fixed values and keep prios",
		{0,0,1},
		{0,X,1,fov,0,0,X},
		{0,X,1,fiv,0,0,X},
		{0,0,0,0,0},
		0,
		{top,tov,tot,tip,tiv,tit,0,1,1},
	},
	{2,15,"If double-tagged with Y-X, modify both tags to old values S-C and copy prios.",
		{0,0,1},
		{1,top,1,tov,0,0,X},
		{1,tip,1,tiv,0,0,X},
		{0,0,0,0,0},
		0,
		{9,fov,6,8,fiv,6,0,1,1},
	}},
	{{2,16,"Swap both tags",
		{0,0,1},
		{0,X,1,fov,0,0,X},
		{0,X,1,fiv,0,0,X},
		{0,0,0,0,0},
		0,
		{8,fiv,tot,9,fov,tit,0,1,1},
	},
	{2,16,"If double-tagged, swap both tags back.",
		{0,0,1},
		{0,X,1,fiv,0,0,X},
		{0,X,1,fov,0,0,X},
		{0,0,0,0,0},
		0,
		{8,fov,6,9,fiv,6,0,1,1},
	}},
	{{2,17,"Remove the outer tag, if tag is S-C.",
		{0,0,1},
		{0,X,1,fov,0,0,X},
		{0,X,1,fiv,0,0,X},
		{0,0,0,0,0},
		0,
		{15,X,X,15,X,X,0,1,0},
	},
	{2,17,"If single-tagged with C, add a tag S.",
		{0,1,0},
		{0,X,1,fiv,0,0,X},
		{X,X,X,X,X,X,X},
		{0,0,0,0,0},
		0,
		{15,X,6,15,X,X,0,0,1},
	}},
	{{2,18,"Remove both tags, if tags are S and C.",
		{0,0,1},
		{0,X,1,fov,0,0,X},
		{0,X,1,fiv,0,0,X},
		{0,0,0,0,0},
		0,
		{15,X,X,15,X,X,0,1,1},
	},
	{2,18,"If untagged, add two tags C and S.",
		{1,0,0},
		{X,X,X,X,X,X,X},
		{X,X,X,X,X,X,X},
		{0,0,0,0,0},
		1,
		{0,DEF,6,15,DEF,6,0,1,1},
	}},
	{{2,19,"Remove both tags.",
		{0,0,1},
		{0,X,0,X,0,0,X},
		{0,X,0,X,0,0,X},
		{0,0,0,0,0},
		0,
		{15,X,X,15,X,X,0,1,1},
	},
	{2,19,"If untagged, add two tags.",
		{1,0,0},
		{X,X,X,X,X,X,X},
		{X,X,X,X,X,X,X},
		{0,0,0,0,0},
		1,
		{0,DEF,6,15,DEF,6,0,1,1},
	}},
};

int omci_api_find_ext_vlan_rule(struct vlan_filter *f, const bool dump)
{
	uint32_t i, k, m=0, best_match=0;
	struct omci_rules *ptr = &omci_rules[0];

	if (sizeof(sce_rules)/sizeof(sce_rules[0]) != sizeof(omci_rules)/sizeof(omci_rules[0])) {
		DBG(OMCI_API_ERR, ("table size missmatch: %d %d\n", 
			sizeof(sce_rules)/sizeof(sce_rules[0]), sizeof(omci_rules)/sizeof(omci_rules[0])));
	}

	for (i=0;i<sizeof(omci_rules)/sizeof(omci_rules[0]);i++, ptr++) {

		if (dump) {
			DBG(OMCI_API_ERR, ("match: test rule: %d.%d: %s (%d)\n",
								ptr->up.major, ptr->up.minor, ptr->up.description, i));

			DBG(OMCI_API_ERR, ("match: treatment_tags_to_remove %d %d\n",
								ptr->up.f.treatment_tags_to_remove, f->treatment_tags_to_remove));
		}

		if (ptr->up.f.treatment_tags_to_remove != f->treatment_tags_to_remove)
			continue;

		if (dump) {
			DBG(OMCI_API_ERR, ("match: filter_ethertype %d %d\n",
				ptr->up.f.filter_ethertype, f->filter_ethertype));
		}

		if (ptr->up.f.filter_ethertype == m_0_4) {
			if (f->filter_ethertype > 4 || f->filter_ethertype < 0)
				continue;
		} else if (ptr->up.f.filter_ethertype == m_1_4) {
			if (f->filter_ethertype > 4 || f->filter_ethertype < 1)
				continue;
		} else {
			if (ptr->up.f.filter_ethertype != f->filter_ethertype) {
				continue;
			}
		}

		if (dump) {
			DBG(OMCI_API_ERR, ("match: filter_outer_priority %d %d\n",
				ptr->up.f.filter_outer_priority, f->filter_outer_priority));
		}

		if (ptr->up.f.filter_outer_priority == Ps ||
		    ptr->up.f.filter_outer_priority== m_0_7) {
			if (f->filter_outer_priority > 7)
				continue;
		} else {
			if (ptr->up.f.filter_outer_priority != f->filter_outer_priority)
				continue;
		}

		if (dump) {
			DBG(OMCI_API_ERR, ("match: filter_inner_priority %d %d\n",
				ptr->up.f.filter_inner_priority, f->filter_inner_priority));
		}

		if (ptr->up.f.filter_inner_priority == Pc) {
			if (f->filter_inner_priority > 7)
				continue;
		} else {
			if (ptr->up.f.filter_inner_priority != f->filter_inner_priority)
				continue;
		}

		if (ptr->up.f.filter_outer_priority < 13) {
			if (dump) {
				DBG(OMCI_API_ERR, ("match: filter_outer_vid %d %d\n",
					ptr->up.f.filter_outer_vid, f->filter_outer_vid));
			}
			if (ptr->up.f.filter_outer_vid == VIDs) {
				if (f->filter_outer_vid > 4095)
					continue;
			} else {
				if (ptr->up.f.filter_outer_vid != f->filter_outer_vid)
					continue;
			}
		}

		if (ptr->up.f.filter_inner_priority < 13) {
			if (dump) {
				DBG(OMCI_API_ERR, ("match: filter_inner_vid %d %d\n",
					ptr->up.f.filter_inner_vid, f->filter_inner_vid));
			}
			if (ptr->up.f.filter_inner_vid == VIDc) {
				if (f->filter_inner_vid > 4095)
					continue;
			} else {
				if (ptr->up.f.filter_inner_vid != f->filter_inner_vid)
					continue;
			}
		}

		if (dump) {
			DBG(OMCI_API_ERR, ("match: treatment_outer_priority %d %d\n",
				ptr->up.f.treatment_outer_priority, f->treatment_outer_priority));
		}

		if (ptr->up.f.treatment_outer_priority == m_0_7) {
			if (f->treatment_outer_priority > 7)
				continue;
		} else {
			if (ptr->up.f.treatment_outer_priority != f->treatment_outer_priority)
				continue;
		}

		if (dump) {
			DBG(OMCI_API_ERR, ("match: treatment_inner_priority %d %d\n",
				ptr->up.f.treatment_inner_priority, f->treatment_inner_priority));
		}

		if (ptr->up.f.treatment_inner_priority == Px ||
		    ptr->up.f.treatment_inner_priority == m_0_7) {
			if (f->treatment_inner_priority > 7)
				continue;
		} else {
			if ((ptr->up.f.treatment_inner_priority == 8 && f->treatment_inner_priority == 9) ||
				(ptr->up.f.treatment_inner_priority == 9 && f->treatment_inner_priority == 8)) {
				/* allow 8 - 9 mismatch */
			} else {
				if (ptr->up.f.treatment_inner_priority != f->treatment_inner_priority)
					continue;
			}
		}

		if (dump) {
			DBG(OMCI_API_ERR, ("match: treatment_outer_priority %d treatment_outer_vid %d\n",
				ptr->up.f.treatment_outer_priority, f->treatment_outer_vid));
		}

		if (f->treatment_outer_priority != 15) {
			if (f->treatment_outer_vid > 4095)
				continue;
		}

		if (dump) {
			DBG(OMCI_API_ERR, ("match: treatment_inner_priority %d treatment_inner_vid %d\n",
				ptr->up.f.treatment_inner_priority, f->treatment_inner_vid));
		}

		if (f->treatment_inner_priority != 15) {
			if (f->treatment_inner_vid > 4095)
				continue;
		}

		DBG(OMCI_API_MSG, ("found rule: %d.%d: %s\n", ptr->up.major, ptr->up.minor, ptr->up.description));
		best_match = i;
		m++;
	}

	if (m == 0) {
		DBG(OMCI_API_ERR, ("no match\n"));
		return -1;
	}

	if (m > 1) {
		DBG(OMCI_API_ERR, ("multi match\n"));
		return -2;
	}

	return best_match;
}

static int map_sce_val(const struct vlan_filter *f, int val)
{
	switch(val) {
		case tip:
		return f->treatment_inner_priority;
		case tiv:
		return f->treatment_inner_vid;
		case tit:
		return f->treatment_inner_tpid_de;
		case top:
		return f->treatment_outer_priority;
		case tov:
		return f->treatment_outer_vid;
		case tot:
		return f->treatment_outer_tpid_de;
		case fip:
		return f->filter_inner_priority;
		case fiv:
		return f->filter_inner_vid;
		case fop:
		return f->filter_outer_priority;
		case fov:
		return f->filter_outer_vid;
		default:
		return val;
	}
}

enum omci_api_return omci_api_rule_us_map(struct omci_api_ctx *ctx,
					      const uint16_t omci_idx,
					      const struct vlan_filter *f,
					      struct gpe_vlan_rule_table *r,
					      struct gpe_vlan_treatment_table *t)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct sce_action *u = &sce_rules[omci_idx].up;

	memset(r, 0, sizeof(struct gpe_vlan_rule_table));
	memset(t, 0, sizeof(struct gpe_vlan_treatment_table));

	r->zero_enable = u->tags.zero_enable;
	r->one_enable = u->tags.one_enable;
	r->two_enable = u->tags.two_enable;
	r->def = u->def;

	if (r->zero_enable || r->one_enable || r->two_enable) {
		r->valid = 1;
		t->valid = 1;
	} else {
		return ret;
	}

	r->outer_vid_enable = u->outer.vid_enable;
	r->outer_vid_filter = map_sce_val(f, u->outer.vid_filter);
	r->outer_priority_enable = u->outer.priority_enable;
	r->outer_priority_filter = map_sce_val(f, u->outer.priority_filter);

	r->inner_vid_enable = u->inner.vid_enable;
	r->inner_vid_filter = map_sce_val(f, u->inner.vid_filter);
	r->inner_priority_enable = u->inner.priority_enable;
	r->inner_priority_filter = map_sce_val(f, u->inner.priority_filter);

	t->taga_treatment = map_sce_val(f, u->treatment.taga);
	t->taga_vid_treatment = map_sce_val(f, u->treatment.taga_vid);
	t->taga_tpid_treatment = map_sce_val(f, u->treatment.taga_tpid);

	t->tagb_treatment = map_sce_val(f, u->treatment.tagb);
	t->tagb_vid_treatment = map_sce_val(f, u->treatment.tagb_vid);
	t->tagb_tpid_treatment = map_sce_val(f, u->treatment.tagb_tpid);

	t->outer_not_generate = u->treatment.outer_not_generate;
	t->inner_not_generate = u->treatment.inner_not_generate;
	t->discard_enable = u->treatment.discard_enable;

	if (u->tags.one_enable) {
		switch(f->filter_inner_tpid_de) {
			case 0: /* do not filter on inner TPID and DE */
			case 1: /* invalid setting */
			case 2: /* invalid setting */
			case 3: /* invalid setting */
			break;
			case 7: /* filter on outer TPID == input TPID && DE == 1 */
			r->outer_de_filter = 1;
			case 6: /* filter on outer TPID == input TPID && DE == 0 */
			r->outer_de_enable = 1;
			case 4: /* */
			case 5: /* filter on outer TPID == input TPID only */
			r->outer_input_tpid_enable = 1;
			break;
		}
	}

	if (u->tags.two_enable) {
		switch(f->filter_inner_tpid_de) {
			case 0: /* do not filter on inner TPID and DE */
			case 1: /* invalid setting */
			case 2: /* invalid setting */
			case 3: /* invalid setting */
			break;
			case 7: /* filter on inner TPID == input TPID && DE == 1 */
			r->inner_de_filter = 1;
			case 6: /* filter on inner TPID == input TPID && DE == 0 */
			r->inner_de_enable = 1;
			case 4: /* filter on inner TPID = 0x8100 */
			case 5: /* filter on inner TPID == input TPID only */
			r->inner_input_tpid_enable = 1;
			break;
		}

		switch(f->filter_outer_tpid_de) {
			case 0: /* do not filter on inner TPID and DE */
			case 1: /* invalid setting */
			case 2: /* invalid setting */
			case 3: /* invalid setting */
			break;
			case 7: /* filter on outer TPID == input TPID && DE == 1 */
			r->outer_de_filter = 1;
			case 6: /* filter on outer TPID == input TPID && DE == 0 */
			r->outer_de_enable = 1;
			case 4: /* */
			case 5: /* filter on outer TPID == input TPID only */
			r->outer_input_tpid_enable = 1;
			break;
		}
	}

	if (f->filter_ethertype) {
		r->def = 0;
		ret = ext_vlan_custom_update(ctx, f->filter_ethertype);
		if (ret != OMCI_API_SUCCESS)
			return ret;
		if (f->filter_ethertype == 1)
			r->ethertype_filter1_enable = 1;
		else if (f->filter_ethertype == 2)
			r->ethertype_filter2_enable = 1;
		else if (f->filter_ethertype == 3)
			r->ethertype_filter3_enable = 1;
		else if (f->filter_ethertype == 4)
			r->ethertype_filter4_enable = 1;
		else if (f->filter_ethertype == 5)
			r->ethertype_filter5_enable = 1;
		else
			return OMCI_API_ERROR;
	}

	return ret;
}

enum omci_api_return omci_api_rule_ds_map(struct omci_api_ctx *ctx,
					      const uint16_t omci_idx,
					      const struct vlan_filter *f,
					      struct gpe_vlan_rule_table *r,
					      struct gpe_vlan_treatment_table *t)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct sce_action *d = &sce_rules[omci_idx].down;

	memset(r, 0, sizeof(struct gpe_vlan_rule_table));
	memset(t, 0, sizeof(struct gpe_vlan_treatment_table));

	r->zero_enable = d->tags.zero_enable;
	r->one_enable = d->tags.one_enable;
	r->two_enable = d->tags.two_enable;
	r->def = d->def;

	if (r->zero_enable || r->one_enable || r->two_enable) {
		r->valid = 1;
		t->valid = 1;
	} else {
		return ret;
	}

	r->outer_vid_enable = d->outer.vid_enable;
	r->outer_vid_filter = map_sce_val(f, d->outer.vid_filter);
	r->outer_priority_enable = d->outer.priority_enable;
	r->outer_priority_filter = map_sce_val(f, d->outer.priority_filter);

	r->inner_vid_enable = d->inner.vid_enable;
	r->inner_vid_filter = map_sce_val(f, d->inner.vid_filter);
	r->inner_priority_enable = d->inner.priority_enable;
	r->inner_priority_filter = map_sce_val(f, d->inner.priority_filter);

	t->taga_treatment = map_sce_val(f, d->treatment.taga);
	t->taga_vid_treatment = map_sce_val(f, d->treatment.taga_vid);
	t->taga_tpid_treatment = map_sce_val(f, d->treatment.taga_tpid);

	t->tagb_treatment = map_sce_val(f, d->treatment.tagb);
	t->tagb_vid_treatment = map_sce_val(f, d->treatment.tagb_vid);
	t->tagb_tpid_treatment = map_sce_val(f, d->treatment.tagb_tpid);

	t->outer_not_generate = d->treatment.outer_not_generate;
	t->inner_not_generate = d->treatment.inner_not_generate;
	t->discard_enable = d->treatment.discard_enable;

	if (d->tags.one_enable) {
		switch(f->filter_inner_tpid_de) {
			case 0: /* do not filter on inner TPID and DE */
			case 1: /* invalid setting */
			case 2: /* invalid setting */
			case 3: /* invalid setting */
			break;
			case 7: /* filter on outer TPID == input TPID && DE == 1 */
			r->outer_de_filter = 1;
			case 6: /* filter on outer TPID == input TPID && DE == 0 */
			r->outer_de_enable = 1;
			case 4: /* */
			case 5: /* filter on outer TPID == input TPID only */
			r->outer_input_tpid_enable = 1;
			break;
		}
	}

	if (d->tags.two_enable) {
		switch(f->filter_inner_tpid_de) {
			case 0: /* do not filter on inner TPID and DE */
			case 1: /* invalid setting */
			case 2: /* invalid setting */
			case 3: /* invalid setting */
			break;
			case 7: /* filter on inner TPID == input TPID && DE == 1 */
			r->inner_de_filter = 1;
			case 6: /* filter on inner TPID == input TPID && DE == 0 */
			r->inner_de_enable = 1;
			case 4: /* filter on inner TPID = 0x8100 */
			case 5: /* filter on inner TPID == input TPID only */
			/*r->inner_input_tpid_enable = 1;*/
			break;
		}

		switch(f->filter_outer_tpid_de) {
			case 0: /* do not filter on inner TPID and DE */
			case 1: /* invalid setting */
			case 2: /* invalid setting */
			case 3: /* invalid setting */
			break;
			case 7: /* filter on outer TPID == input TPID && DE == 1 */
			r->outer_de_filter = 1;
			case 6: /* filter on outer TPID == input TPID && DE == 0 */
			r->outer_de_enable = 1;
			case 4: /* */
			case 5: /* filter on outer TPID == input TPID only */
			r->outer_input_tpid_enable = 1;
			break;
		}
	}

	if (f->filter_ethertype) {
		r->def = 0;
		ret = ext_vlan_custom_update(ctx, f->filter_ethertype);
		if (ret != OMCI_API_SUCCESS)
			return ret;
		if (f->filter_ethertype == 1)
			r->ethertype_filter1_enable = 1;
		else if (f->filter_ethertype == 2)
			r->ethertype_filter2_enable = 1;
		else if (f->filter_ethertype == 3)
			r->ethertype_filter3_enable = 1;
		else if (f->filter_ethertype == 4)
			r->ethertype_filter4_enable = 1;
		else if (f->filter_ethertype == 5)
			r->ethertype_filter5_enable = 1;
		else
			return OMCI_API_ERROR;
	}

	return ret;
}

