/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_voice_service_profile_h
#define _omci_voice_service_profile_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_VOICE_SERVICE_PROFILE Voice Service Profile Managed Entity

    This managed entity organizes data that describes the voice service
    functions of the ONU.

    Instances of this managed entity are created and deleted by the OLT.
    An instance of this managed entity may be associated with zero or more
    instances of a VoIP voice CTP by way of a VoIP media profile. 

    @{
*/


/** Tone Pattern Table Entry.
    See \ref omci_me_voice_service_profile::tone_pattern_table */
struct omci_tone_pattern_table {
	/** Index

	    This component is simply an index into the table. It ranges
	    from 1..255. In a set operation, the value 0 in this field clears
	    the table. */
	uint8_t index;
	/** Tone on

	    This boolean component controls whether the tone is on (true) or
	    off. If the tone is off, the frequency and power fields are not
	    meaningful. */
	uint8_t tone_on;
	/** Frequency 1

	    This component specifies the frequency of one of the tone
	    components in Hz. */
	uint16_t frequency1;
	/** Power 1

	    This component specifies the power level of the corresponding
	    frequency component. It ranges from 0 (coded as 0) to -25.5
	    (coded as 255) dBm0 with 0.1 dB resolution. */
	uint8_t power1;
	/** Frequency 2

	    This component specifies the frequency of one of the tone
	    components in Hz. */
	uint16_t frequency2;
	/** Power 2

	    This component specifies the power level of the corresponding
	    frequency component. It ranges from 0 (coded as 0) to -25.5
	    (coded as 255) dBm0 with 0.1 dB resolution. */
	uint8_t power2;
	/** Frequency 3

	    This component specifies the frequency of one of the tone
	    components in Hz. */
	uint16_t frequency3;
	/** Power 2

	    This component specifies the power level of the corresponding
	    frequency component. It ranges from 0 (coded as 0) to -25.5
	    (coded as 255) dBm0 with 0.1 dB resolution. */
	uint8_t power3;
	/** Frequency 4

	    This component specifies the frequency of one of the tone
	    components in Hz. */
	uint16_t frequency4;
	/** Power 4

	    This component specifies the power level of the corresponding
	    frequency component. It ranges from 0 (coded as 0) to -25.5
	    (coded as 255) dBm0 with 0.1 dB resolution. */
	uint8_t power4;
	/** Modulation Frequency

	    This component specifies modulation frequency in Hz.*/
	uint16_t modulation_frequency;
	/** Modulation Power

	    This component specifies the power level of the corresponding
	    modulation frequency component. It ranges from 0 (coded as 0)
	    to -25.5 (coded as 255) dBm0 with 0.1 dB resolution.*/
	uint8_t modulation_power;
	/** Duration

	    This component specifies the duration of the phase, in milliseconds.
	    The value 0 specifies that the phase endures indefinitely, that is,
	    until terminated by other events such as call abandonment. */
	uint16_t duration;
	/** Next Entry

	    This component is a pointer to another entry in this same table,
	    which permits sequences of tones to be defined, possibly cyclically.
	    A reference to a non-existent table entry, or the value 0, indicates
	    that the sequence should be terminated. */
	uint8_t next_entry;
} __PACKED__;

/** Tone Event Table Entry.
    See \ref omci_me_voice_service_profile::tone_event_table */
struct omci_tone_event_table {
	/** Event

	    This component is an emumeration of the events for which a tone may
	    be defined. The event component also serves as the index for the
	    table. A set operation to event 0 causes the table to be cleared. 

		0 Not used for get operation; clears table under set operation 
		1 Busy 
		2 Confirmation 
		3 Dial 
		4 Message waiting
		5 Off hook warning (receiver off hook) 
		6 Ringback (audible ring) 
		7 Reorder 
		8 Stutter dial 
		9 Call waiting 1 
		10 Call waiting 2 
		11 Call waiting 3 
		12 Call waiting 4 
		13 Alerting signal 
		14 Special dial 
		15 Special info 
		16 Release 
		17 Congestion 
		18 User defined 1 
		19 User defined 2 
		20 User defined 3 
		21 User defined 4 
		22..32 Reserved 
		33 Intrusion 
		34 Dead tone 
		35..223 Reserved 
		224..255 Vendor specific codes, not to be standardized */
	uint8_t event;
	/** Tone pattern

	    This component specifies an entry point into the tone pattern table
	    attribute, to be invoked when the specified event occurs.
	    The value 0 indicates that no tone from the tone pattern table is
	    to be played. */
	uint8_t tone_pattern;
	/** Tone file

	    This component points to a large string managed entity that contains
	    the path and name of a file containing a codec sequence to be
	    played out. If no file is found after traversing these links, no
	    tone is played. The behaviour is unspecified if both tone pattern
	    and tone file are specified.  */
	uint16_t tone_file;
	/** Tone file repetitions

	    This component specifies the number of times the tone file is to be
	    repeated. The value 0 means that the file is to be repeated
	    indefinitely until terminated by some external event such as call
	    abandonment. */
	uint8_t tone_file_repetitions;
	/** Reserved */
	uint16_t reserved;
} __PACKED__;

/** Ringing Pattern Table Entry.
    See \ref omci_me_voice_service_profile::ringing_pattern_table */
struct omci_ringing_pattern_table {
	/** Index

	    This component is simply an index into the table. It ranges
	    from 1..255. In a set operation, the value 0 in this field clears
	    the table. */
	uint8_t index;
	/** Ringing on

	    This boolean component controls whether ringing is on (true) or off
	    during this interval. */
	uint8_t ringing_on;
	/** Duration

	    This component specifies the duration of the ringing phase,
	    in milliseconds. The value 0 specifies that the phase endures
	    indefinitely, that is, until terminated by other events such as call
	    abandonment. */
	uint16_t duration;
	/** Next entry

	    This component is a pointer to another entry in this same table,
	    which permits sequences of ringing bursts to be defined, possibly
	    cyclically. A reference to a non-existent table entry,
	    or the value 0, indicates that the sequence should be terminated. */
	uint8_t next_entry;
} __PACKED__;

/** Ringing Event Table Entry.
    See \ref omci_me_voice_service_profile::ringing_event_table */
struct omci_ringing_event_table {
	/** Event

	    This component is an emumeration of the events for which a ringing
	    sequence may be defined. The event component also serves as the
	    index for the table. A set operation with the value 0 in this field
	    causes the table to be cleared.

		0 Not used for get operation; clears table under set operation 
		1 Default 
		2 Splash 
		3..223 Reserved 
		224..255 Vendor specific codes, not to be standardized */
	uint8_t event;
	/** Ringing pattern

	    This component specifies an entry point into the ringing pattern
	    table attribute, to be invoked when the specified event occurs.
	    The value 0 indicates that no ringing sequence is defined in the
	    ringing pattern table. */
	uint8_t ringing_pattern;
	/** Ringing file

	    This component points to a large string managed entity that contains
	    the path and name of a file containing a ring tone to be played out.
	    If no file is found after traversing these links, no ringing is
	    played. The behaviour is unspecified if both ringing pattern and
	    ringing file fields are specified. 
	*/
	uint16_t ringing_file;
	/** Ringing file repetitions

	    This component specifies the number of times the ringing file is to
	    be repeated. The value 0 means that the file is to be repeated
	    indefinitely until terminated by some external event such as call
	    abandonment. */
	uint8_t ringing_file_repetitions;
	/** Ringing text

	    This component points to a large string managed entity that contains
	    a text string to be displayed on the CPE device in conjunction with
	    this event. A null pointer indicates that no text is to be
	    displayed. */
	uint16_t ringing_text;
} __PACKED__;

/** This structure holds the attributes of the Voice Service Profile Managed
    Entity. */
struct omci_me_voice_service_profile {
	/** Announcement type

	    This attribute specifies the treatment when a subscriber goes
	    off hook but does not attempt a call within the dial-tone timeout
	    interval. Valid values include: 
		0x01 Silence 
		0x02 Reorder tone 
		0x03 Fast busy 
		0x04 Voice announcement 
		0xFF Not specified; ONU is free to make its own choice. 
	    (R, W, Set-by-create) (mandatory) */
	uint8_t announcement_type;
	/** Jitter target

	    This attribute specifies the target value of the jitter buffer in
	    milliseconds. The system tries to maintain the jitter buffer at the
	    target value. The value 0 specifies dynamic jitter buffer sizing.
	    (R, W, Set-by-create) (optional) */
	uint16_t jitter_target;
	/** Jitter buffer max

	    This attribute specifies the maximum depth of the jitter buffer
	    associated with this service in milliseconds.
	    (R, W, Set-by-create) (optional) */
	uint16_t jitter_buffer_max;
	/** Echo cancel ind

	    The Boolean value true specifies that echo cancellation is on; false
	    specifies off.
	    (R, W, Set-by-create) (mandatory) */
	uint8_t echo_cancel_ind;
	/** PSTN protocol variant

	    This attribute controls which variant of POTS signalling is used on
	    the associated UNIs. Its value is equal to the [ITU-T E.164] country
	    code.
	    (R, W, Set-by-create) (optional) */
	uint16_t pstn_protocol_variant;
	/** DTMF digit levels

	    This attribute specifies the power level of DTMF digits that may be
	    generated by the ONU toward the subscriber set. It is a 2s
	    complement value referred to 1 mW at the 0 TLP (dBm0), with
	    resolution 1 dB. The default value 0x8000 selects the ONU's internal
	    policy.
	    (R, W, Set-by-create) (optional) */
	uint16_t dtmf_digit_levels;
	/** DTMF digit duration

	    This attribute specifies the duration of DTMF digits that may be
	    generated by the ONU toward the subscriber set. It is specified in
	    milliseconds. The default value 0 selects the ONU's internal policy.
	    (R, W, Set-by-create) (optional) */
	uint16_t dtmf_digit_duration;
	/** Hook flash minimum time

	    This attribute defines the minimum duration recognized by the ONU as
	    a switchhook flash. It is expressed in milliseconds; the default
	    value 0 selects the ONU's internal policy.
	    (R, W, Set-by-create) (optional) */
	uint16_t hook_flash_minimum_time;
	/** Hook flash maximum time

	    This attribute defines the maximum duration recognized by the ONU as
	    a switchhook flash. It is expressed in milliseconds; the default
	    value 0 selects the ONU's internal policy.
	    (R, W, Set-by-create) (optional) */
	uint16_t hook_flash_maximum_time;
	/** Tone pattern table

	    This attribute is a table, each of whose entries specifies a complex
	    tone (or silence) and a duration. By linking tones and silence
	    together, possibly cyclically, continuous, varying or interrupted
	    tone sequences, repetitive or not, may be defined. A tone sequence
	    is initiated by pointing to the first tone pattern table entry that
	    defines its parameters. */
	struct omci_tone_pattern_table tone_pattern_table;
	/** Tone event table

	    This attribute is a table, each of whose entries specifies an event
	    for which a tone is defined. If the tone can be synthesized by a
	    sequence of complex tones and silence, the event refers to an entry
	    in the tone pattern table. Otherwise, the event refers to a file
	    name that is expected to be recognized by the ONU environment.  */
	struct omci_tone_event_table tone_event_table;
	/** Ringing pattern table

	    This attribute is a table, each of whose entries specifies a ringing
	    pattern and a duration. By linking ringing and silence together,
	    possibly cyclically, continuous or interrupted ringing sequences,
	    repetitive or not, may be defined. A ringing sequence is initiated
	    by pointing to the first ringing pattern table entry that defines
	    its parameters. */
	struct omci_ringing_pattern_table ringing_pattern_table;
	/** Ringing event table

	    This attribute is a table, each of whose entries specifies an event
	    for which a ringing sequence is defined. If the ringing sequence can
	    be generated as a sequence of power ringing and silent intervals,
	    the event refers to an entry in the ringing pattern table.
	    Otherwise, the event refers to a file name that is expected to be
	    recognized by the ONU environment. */
	struct omci_ringing_event_table ringing_event_table;
} __PACKED__;

/** This enumerator holds the attribute numbers of the Network Dial Plan Table
    Managed Entity. */
enum {
	omci_me_voice_service_profile_announcement_type = 1,
	omci_me_voice_service_profile_jitter_target = 2,
	omci_me_voice_service_profile_jitter_buffer_max = 3,
	omci_me_voice_service_profile_echo_cancel_ind = 4,
	omci_me_voice_service_profile_pstn_protocol_variant = 5,
	omci_me_voice_service_profile_dtmf_digit_levels = 6,
	omci_me_voice_service_profile_dtmf_digit_duration = 7,
	omci_me_voice_service_profile_hook_flash_minimum_time = 8,
	omci_me_voice_service_profile_hook_flash_maximum_time = 9,
	omci_me_voice_service_profile_tone_pattern_table = 10,
	omci_me_voice_service_profile_tone_event_table = 11,
	omci_me_voice_service_profile_ringing_pattern_table = 12,
	omci_me_voice_service_profile_ringing_event_table = 13
};

/** @} */

/** @} */

__END_DECLS

#endif
