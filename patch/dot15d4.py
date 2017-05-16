## This file is for use with Scapy
## See http://www.secdev.org/projects/scapy for more information
## Copyright (C) Ryan Speers <ryan@rmspeers.com> 2011-2012
## 2012-03-10 Roger Meyer <roger.meyer@csus.edu>: Added frames
## This program is published under a GPLv2 license

"""
Wireless MAC according to IEEE 802.15.4 / Zigbee / ZigBee Light Link
"""

import re, struct

from scapy.packet import *
from scapy.fields import *


# ZigBee Cluster Library Identifiers, Table 2.2 ZCL
_zcl_cluster_identifier = {
    # Functional Domain: General
    0x0000: "basic",
    0x0001: "power_configuration",
    0x0002: "device_temperature_configuration",
    0x0003: "identify",
    0x0004: "groups",
    0x0005: "scenes",
    0x0006: "on_off",
    0x0007: "on_off_switch_configuration",
    0x0008: "level_control",
    0x0009: "alarms",
    0x000a: "time",
    0x000b: "rssi_location",
    0x000c: "analog_input",
    0x000d: "analog_output",
    0x000e: "analog_value",
    0x000f: "binary_input",
    0x0010: "binary_output",
    0x0011: "binary_value",
    0x0012: "multistate_input",
    0x0013: "multistate_output",
    0x0014: "multistate_value",
    0x0015: "commissioning",
    # 0x0016 - 0x00ff reserved
    # Functional Domain: Closures
    0x0100: "shade_configuration",
    # 0x0101 - 0x01ff reserved
    # Functional Domain: HVAC
    0x0200: "pump_configuration_and_control",
    0x0201: "thermostat",
    0x0202: "fan_control",
    0x0203: "dehumidification_control",
    0x0204: "thermostat_user_interface_configuration",
    # 0x0205 - 0x02ff reserved
    # Functional Domain: Lighting
    0x0300: "color_control",
    0x0301: "ballast_configuration",
    # Functional Domain: Measurement and sensing
    0x0400: "illuminance_measurement",
    0x0401: "illuminance_level_sensing",
    0x0402: "temperature_measurement",
    0x0403: "pressure_measurement",
    0x0404: "flow_measurement",
    0x0405: "relative_humidity_measurement",
    0x0406: "occupancy_sensing",
    # Functional Domain: Security and safethy
    0x0500: "ias_zone",
    0x0501: "ias_ace",
    0x0502: "ias_wd",
    # Functional Domain: Protocol Interfaces
    0x0600: "generic_tunnel",
    0x0601: "bacnet_protocol_tunnel",
    0x0602: "analog_input_regular",
    0x0603: "analog_input_extended",
    0x0604: "analog_output_regular",
    0x0605: "analog_output_extended",
    0x0606: "analog_value_regular",
    0x0607: "analog_value_extended",
    0x0608: "binary_input_regular",
    0x0609: "binary_input_extended",
    0x060a: "binary_output_regular",
    0x060b: "binary_output_extended",
    0x060c: "binary_value_regular",
    0x060d: "binary_value_extended",
    0x060e: "multistate_input_regular",
    0x060f: "multistate_input_extended",
    0x0610: "multistate_output_regular",
    0x0611: "multistate_output_extended",
    0x0612: "multistate_value_regular",
    0x0613: "multistate_value",
    # Smart Energy Profile Clusters
    0x0700: "price",
    0x0701: "demand_response_and_load_control",
    0x0702: "metering",
    0x0703: "messaging",
    0x0704: "smart_energy_tunneling",
    0x0705: "prepayment",
    # Functional Domain: General
    # Key Establishment
    0x0800: "key_establishment",
    0x1000: "ZLL_commissioning",
}

# ZigBee stack profiles
_zcl_profile_identifier = {
    0x0000: "ZigBee_Stack_Profile_1",
    0x0101: "IPM_Industrial_Plant_Monitoring",
    0x0104: "HA_Home_Automation",
    0x0105: "CBA_Commercial_Building_Automation",
    0x0107: "TA_Telecom_Applications",
    0x0108: "HC_Health_Care",
    0x0109: "SE_Smart_Energy_Profile",
    0xc05e: "ZLL_Light_Link",
}

# ZigBee Cluster Library, Table 2.8 ZCL Command Frames
_zcl_command_frames = {
    0x00: "read_attributes",
    0x01: "read_attributes_response",
    0x02: "write_attributes_response",
    0x03: "write_attributes_undivided",
    0x04: "write_attributes_response",
    0x05: "write_attributes_no_response",
    0x06: "configure_reporting",
    0x07: "configure_reporting_response",
    0x08: "read_reporting_configuration",
    0x09: "read_reporting_configuration_response",
    0x0a: "report_attributes",
    0x0b: "default_response",
    0x0c: "discover_attributes",
    0x0d: "discover_attributes_response",
    # 0x0e - 0xff Reserved
}

# ZigBee LightLink Command Frames
_zll_command_frames = {
    0x00: "scan_request",
    0x01: "scan_response",
    0x02: "device_information_request",
    0x03: "device_information_response",
    0x06: "identify_request",
    0x07: "reset_to_factory_new_request",
    0x10: "network_start_request",
    0x11: "network_start_response",
    0x12: "network_join_router_request",
    0x13: "network_join_router_response",
    0x14: "network_join_end_device_request",
    0x15: "network_join_end_device_response",
    0x16: "network_update_request",
    0x40: "endpoint_information",
    0x41: "get_group_identifiers_request",
    0x42: "get_endpoint_list_request",
}

# ZigBee Cluster Library, Table 2.16 Enumerated Status Values
_zcl_enumerated_status_values = {
    0x00: "SUCCESS",
    0x02: "FAILURE",
    # 0x02 - 0x7f Reserved
    0x80: "MALFORMED_COMMAND",
    0x81: "UNSUP_CLUSTER_COMMAND",
    0x82: "UNSUP_GENERAL_COMMAND",
    0x83: "UNSUP_MANUF_CLUSTER_COMMAND",
    0x84: "UNSUP_MANUF_GENERAL_COMMAND",
    0x85: "INVALID_FIELD",
    0x86: "UNSUPPORTED_ATTRIBUTE",
    0x87: "INVALID_VALUE",
    0x88: "READ_ONLY",
    0x89: "INSUFFICIENT_SPACE",
    0x8a: "DUPLICATE_EXISTS",
    0x8b: "NOT_FOUND",
    0x8c: "UNREPORTABLE_ATTRIBUTE",
    0x8d: "INVALID_DATA_TYPE",
    # 0x8e - 0xbf Reserved
    0xc0: "HARDWARE_FAILURE",
    0xc1: "SOFTWARE_FAILURE",
    0xc2: "CALIBRATION_ERROR",
    # 0xc3 - 0xff Reserved
}

# ZigBee Device Profile Status Values
# ZigBee Specification: Table 2.138 ZDP Enumerations Description
_zdp_enumerated_stauts_values = {
    0x00: "SUCCESS",
    # 0X01 - 0X7f Reserved
    0x80: "INV_REQUESTTYPE",
    0X81: "DEVICE_NOT_FOUND",
    0X82: "INVALID_EP",
    0X83: "NOT_ACTIVE",
    0X84: "NOT_SUPPORTED",
    0X85: "TIMEOUT",
    0X86: "NO_MATCH",
    # 0X87 Reserved
    0x88: "NO_ENTRY",
    0x89: "NO_DESCRIPTOR",
    0X8a: "INSUFFICIENT_SPACE",
    0x8b: "NOT_PERMITTED",
    0X8c: "TABLE_FULL",
    0x8d: "NOT_AUTHORIZED",
    0X8e: "DEVICE_BINDING_TABLE_FULL",
    # 0x8f - 0xff Reserved
}

# ZigBee Cluster Library, Table 2.15 Data Types
_zcl_attribute_data_types = {
    0x00: "no_data",
    # General data
    0x08: "8-bit_data",
    0x09: "16-bit_data",
    0x0a: "24-bit_data",
    0x0b: "32-bit_data",
    0x0c: "40-bit_data",
    0x0d: "48-bit_data",
    0x0e: "56-bit_data",
    0x0f: "64-bit_data",
    # Logical
    0x10: "boolean",
    # Bitmap
    0x18: "8-bit_bitmap",
    0x19: "16-bit_bitmap",
    0x1a: "24-bit_bitmap",
    0x1b: "32-bit_bitmap",
    0x1c: "40-bit_bitmap",
    0x1d: "48-bit_bitmap",
    0x1e: "56-bit_bitmap",
    0x1f: "64-bit_bitmap",
    # Unsigned integer
    0x20: "Unsigned_8-bit_integer",
    0x21: "Unsigned_16-bit_integer",
    0x22: "Unsigned_24-bit_integer",
    0x23: "Unsigned_32-bit_integer",
    0x24: "Unsigned_40-bit_integer",
    0x25: "Unsigned_48-bit_integer",
    0x26: "Unsigned_56-bit_integer",
    0x27: "Unsigned_64-bit_integer",
    # Signed integer
    0x28: "Signed_8-bit_integer",
    0x29: "Signed_16-bit_integer",
    0x2a: "Signed_24-bit_integer",
    0x2b: "Signed_32-bit_integer",
    0x2c: "Signed_40-bit_integer",
    0x2d: "Signed_48-bit_integer",
    0x2e: "Signed_56-bit_integer",
    0x2f: "Signed_64-bit_integer",
    # Enumeration
    0x30: "8-bit_enumeration",
    0x31: "16-bit_enumeration",
    # Floating point
    0x38: "semi_precision",
    0x39: "single_precision",
    0x3a: "double_precision",
    # String
    0x41: "octet-string",
    0x42: "character_string",
    0x43: "long_octet_string",
    0x44: "long_character_string",
    # Ordered sequence
    0x48: "array",
    0x4c: "structure",
    # Collection
    0x50: "set",
    0x51: "bag",
    # Time
    0xe0: "time_of_day",
    0xe1: "date",
    0xe2: "utc_time",
    # Identifier
    0xe8: "cluster_id",
    0xe9: "attribute_id",
    0xea: "bacnet_oid",
    # Miscellaneous
    0xf0: "ieee_address",
    0xf1: "128-bit_security_key",
    # Unknown
    0xff: "unknown",
}

### Fields ###

class dot15d4AddressField(Field):
    def __init__(self, name, default, length_of=None, fmt="<H", adjust=None):
        Field.__init__(self, name, default, fmt)
        self.length_of=length_of
        if adjust != None:  self.adjust=adjust
        else:               self.adjust=lambda pkt,x:self.lengthFromAddrMode(pkt, x)
    def i2repr(self, pkt, x):
        """Convert internal value to a nice representation"""
        if len(hex(self.i2m(pkt,x))) < 7: # short address
            return hex(self.i2m(pkt,x))
        else: # long address
            long_addr = struct.pack(">Q", self.i2m(pkt,x))
            return ":".join(["{0:>02x}".format(ord(byte)) for byte in long_addr])
    def addfield(self, pkt, s, val):
        """Add an internal value to a string"""
        if self.adjust(pkt, self.length_of) == 2:
            return s + struct.pack(self.fmt[0]+"H", val)
        elif self.adjust(pkt, self.length_of) == 8:
            return s + struct.pack(self.fmt[0]+"Q", val)
        else:
            return s
    def getfield(self, pkt, s):
        if self.adjust(pkt, self.length_of) == 2:
            return s[2:], self.m2i(pkt, struct.unpack(self.fmt[0]+"H", s[:2])[0])
        elif self.adjust(pkt, self.length_of) == 8:
            return s[8:], self.m2i(pkt, struct.unpack(self.fmt[0]+"Q", s[:8])[0])
        else:
            raise Exception('impossible case')
    def lengthFromAddrMode(self, pkt, x):
        pkttop = pkt
        while pkttop.underlayer != None: pkttop = pkttop.underlayer
        addrmode = pkttop.getfieldval(x)
        #print "Underlayer field value of", x, "is", addrmode
        if addrmode == 2: return 2
        elif addrmode == 3: return 8
        else: return 0


#class dot15d4Checksum(LEShortField,XShortField):
#    def i2repr(self, pkt, x):
#        return XShortField.i2repr(self, pkt, x)
#    def addfield(self, pkt, s, val):
#        return s
#    def getfield(self, pkt, s):
#        return s


### Layers ###

class Dot15d4(Packet):
    name = "802.15.4"
    fields_desc = [
        HiddenField(BitField("fcf_reserved_1", 0, 1), True), #fcf p1 b1
        BitEnumField("fcf_panidcompress", 0, 1, [False, True]),
        BitEnumField("fcf_ackreq", 0, 1, [False, True]),
        BitEnumField("fcf_pending", 0, 1, [False, True]),
        BitEnumField("fcf_security", 0, 1, [False, True]), #fcf p1 b2
        Emph(BitEnumField("fcf_frametype", 0, 3, {0:"Beacon", 1:"Data", 2:"Ack", 3:"Command"})),
        BitEnumField("fcf_srcaddrmode", 0, 2, {0:"None", 1:"Reserved", 2:"Short", 3:"Long"}),  #fcf p2 b1
        BitField("fcf_framever", 0, 2), # 00 compatibility with 2003 version; 01 compatible with 2006 version
        BitEnumField("fcf_destaddrmode", 2, 2, {0:"None", 1:"Reserved", 2:"Short", 3:"Long"}), #fcf p2 b2
        HiddenField(BitField("fcf_reserved_2", 0, 2), True),
        Emph(ByteField("seqnum", 1)) #sequence number
    ]

    def mysummary(self):
        return self.sprintf("802.15.4 %Dot15d4.fcf_frametype% ackreq(%Dot15d4.fcf_ackreq%) ( %Dot15d4.fcf_destaddrmode% -> %Dot15d4.fcf_srcaddrmode% ) Seq#%Dot15d4.seqnum%")

    def guess_payload_class(self, payload):
        if self.fcf_frametype == 0x00:      return Dot15d4Beacon
        elif self.fcf_frametype == 0x01:    return Dot15d4Data
        elif self.fcf_frametype == 0x02:    return Dot15d4Ack
        elif self.fcf_frametype == 0x03:    return Dot15d4Cmd
        else:                               return Packet.guess_payload_class(self, payload)

    def answers(self, other):
        if isinstance(other, Dot15d4):
            if self.fcf_frametype == 2: #ack
                if self.seqnum != other.seqnum: #check for seqnum matching
                    return 0
                elif other.fcf_ackreq == 1: #check that an ack was indeed requested
                    return 1
        return 0

    def post_build(self, p, pay):
        #This just forces destaddrmode to None for Ack frames.
        #TODO find a more elegant way to do this
        if self.fcf_frametype == 2 and self.fcf_destaddrmode != 0:
            self.fcf_destaddrmode = 0
            return str(self)
        else:
            return p + pay


class Dot15d4FCS(Dot15d4, Packet):
    '''
    This class is a drop-in replacement for the Dot15d4 class above, except
    it expects a FCS/checksum in the input, and produces one in the output.
    This provides the user flexibility, as many 802.15.4 interfaces will have an AUTO_CRC setting
    that will validate the FCS/CRC in firmware, and add it automatically when transmitting.
    '''
    def pre_dissect(self, s):
        """Called right before the current layer is dissected"""
        if (makeFCS(s[:-2]) != s[-2:]): #validate the FCS given
            warning("FCS on this packet is invalid or is not present in provided bytes.")
            return s                    #if not valid, pretend there was no FCS present
        return s[:-2]                   #otherwise just disect the non-FCS section of the pkt

    def post_build(self, p, pay):
        #This just forces destaddrmode to None for Ack frames.
        #TODO find a more elegant way to do this
        if self.fcf_frametype == 2 and self.fcf_destaddrmode != 0:
            self.fcf_destaddrmode = 0
            return str(self)
        else:
            return p + pay + makeFCS(p+pay) #construct the packet with the FCS at the end


class Dot15d4Ack(Packet):
    name = "802.15.4 Ack"
    fields_desc = [ ]


class Dot15d4AuxSecurityHeader(Packet):
    name = "802.15.4 Auxiliary Security Header"
    fields_desc = [
        HiddenField(BitField("sec_sc_reserved", 0, 3), True),
        # Key Identifier Mode
        # 0: Key is determined implicitly from the originator and receipient(s) of the frame
        # 1: Key is determined explicitly from the the 1-octet Key Index subfield of the Key Identifier field
        # 2: Key is determined explicitly from the 4-octet Key Source and the 1-octet Key Index
        # 3: Key is determined explicitly from the 8-octet Key Source and the 1-octet Key Index
        BitEnumField("sec_sc_keyidmode", 0, 2, {
            0:"Implicit", 1:"1oKeyIndex", 2:"4o-KeySource-1oKeyIndex", 3:"8o-KeySource-1oKeyIndex"}
        ),
        BitEnumField("sec_sc_seclevel", 0, 3, {0:"None", 1:"MIC-32", 2:"MIC-64", 3:"MIC-128",          \
                                               4:"ENC", 5:"ENC-MIC-32", 6:"ENC-MIC-64", 7:"ENC-MIC-128"}),
        XLEIntField("sec_framecounter", 0x00000000), # 4 octets
        # Key Identifier (variable length): identifies the key that is used for cryptographic protection
        # Key Source : length of sec_keyid_keysource varies btwn 0, 4, and 8 bytes depending on sec_sc_keyidmode
        # 4 octets when sec_sc_keyidmode == 2
        ConditionalField(XLEIntField("sec_keyid_keysource", 0x00000000),
            lambda pkt:pkt.getfieldval("sec_sc_keyidmode") == 2),
        # 8 octets when sec_sc_keyidmode == 3
        ConditionalField(LELongField("sec_keyid_keysource", 0x0000000000000000),
            lambda pkt:pkt.getfieldval("sec_sc_keyidmode") == 3),
        # Key Index (1 octet): allows unique identification of different keys with the same originator
        ConditionalField(XByteField("sec_keyid_keyindex", 0xFF),
            lambda pkt:pkt.getfieldval("sec_sc_keyidmode") != 0),
    ]

class Dot15d4Data(Packet):
    name = "802.15.4 Data"
    fields_desc = [
                    XLEShortField("dest_panid", 0xFFFF),
                    dot15d4AddressField("dest_addr", 0xFFFF, length_of="fcf_destaddrmode"),
                    ConditionalField(XLEShortField("src_panid", 0x0), \
                                        lambda pkt:util_srcpanid_present(pkt)),
                    ConditionalField(dot15d4AddressField("src_addr", None, length_of="fcf_srcaddrmode"), \
                                        lambda pkt:pkt.underlayer.getfieldval("fcf_srcaddrmode") != 0),
                    # Security field present if fcf_security == True
                    ConditionalField(PacketField("aux_sec_header", Dot15d4AuxSecurityHeader(), Dot15d4AuxSecurityHeader),
                                        lambda pkt:pkt.underlayer.getfieldval("fcf_security") == True),
                    ]
    def mysummary(self):
        return self.sprintf("802.15.4 Data ( %Dot15d4Data.src_panid%:%Dot15d4Data.src_addr% -> %Dot15d4Data.dest_panid%:%Dot15d4Data.dest_addr% )")

    def guess_payload_class(self, payload):
        if ord(payload[0]) & 0x01 and ord(payload[0]) & 0x02:  # Inter-PAN Frametype
            return ZigbeeNWKStub
        else:
            return Packet.guess_payload_class(self, payload)

class Dot15d4Beacon(Packet):
    name = "802.15.4 Beacon"
    fields_desc = [
                    XLEShortField("src_panid", 0x0),
                    dot15d4AddressField("src_addr", None, length_of="fcf_srcaddrmode"),
                    # Security field present if fcf_security == True
                    ConditionalField(PacketField("aux_sec_header", Dot15d4AuxSecurityHeader(), Dot15d4AuxSecurityHeader),
                        lambda pkt:pkt.underlayer.getfieldval("fcf_security") == True),

                    # Superframe spec field:
                    BitField("sf_sforder", 15, 4),      #not used by ZigBee
                    BitField("sf_beaconorder", 15, 4),  #not used by ZigBee
                    BitEnumField("sf_assocpermit", 0, 1, [False, True]),
                    BitEnumField("sf_pancoord", 0, 1, [False, True]),
                    BitField("sf_reserved", 0, 1),      #not used by ZigBee
                    BitEnumField("sf_battlifeextend", 0, 1, [False, True]), #not used by ZigBee
                    BitField("sf_finalcapslot", 15, 4), #not used by ZigBee

                    # GTS Fields
                    #  GTS Specification (1 byte)
                    BitEnumField("gts_spec_permit", 1, 1, [False, True]), #GTS spec bit 7, true=1 iff PAN cord is accepting GTS requests
                    BitField("gts_spec_reserved", 0, 4),  #GTS spec bits 3-6
                    BitField("gts_spec_desccount", 0, 3), #GTS spec bits 0-2
                    #  GTS Directions (0 or 1 byte)
                    ConditionalField(BitField("gts_dir_reserved", 0, 1), lambda pkt:pkt.getfieldval("gts_spec_desccount") != 0),
                    ConditionalField(BitField("gts_dir_mask", 0, 7), lambda pkt:pkt.getfieldval("gts_spec_desccount") != 0),
                    #  GTS List (variable size)
                    #TODO add a Packet/FieldListField tied to 3bytes per count in gts_spec_desccount

                    # Pending Address Fields:
                    #  Pending Address Specification (1 byte)
                    BitField("pa_num_short", 0, 3), #number of short addresses pending
                    BitField("pa_reserved_1", 0, 1),
                    BitField("pa_num_long", 0, 3), #number of long addresses pending
                    BitField("pa_reserved_2", 0, 1),
                    #  Address List (var length)
                    #TODO add a FieldListField of the pending short addresses, followed by the pending long addresses, with max 7 addresses
                    #TODO beacon payload
                    ]

    def mysummary(self):
        return self.sprintf("802.15.4 Beacon ( %Dot15d4Beacon.src_panid%:%Dot15d4Beacon.src_addr% ) assocPermit(%Dot15d4Beacon.sf_assocpermit%) panCoord(%Dot15d4Beacon.sf_pancoord%)")

class Dot15d4Cmd(Packet):
    name = "802.15.4 Command"
    fields_desc = [
                    XLEShortField("dest_panid", 0xFFFF),
                    # Users should correctly set the dest_addr field. By default is 0x0 for construction to work.
                    dot15d4AddressField("dest_addr", 0x0, length_of="fcf_destaddrmode"),
                    ConditionalField(XLEShortField("src_panid", 0x0), \
                                        lambda pkt:util_srcpanid_present(pkt)),
                    ConditionalField(dot15d4AddressField("src_addr", None, length_of="fcf_srcaddrmode"), \
                                        lambda pkt:pkt.underlayer.getfieldval("fcf_srcaddrmode") != 0),
                    # Security field present if fcf_security == True
                    ConditionalField(PacketField("aux_sec_header", Dot15d4AuxSecurityHeader(), Dot15d4AuxSecurityHeader),
                        lambda pkt:pkt.underlayer.getfieldval("fcf_security") == True),
                    ByteEnumField("cmd_id", 0, {
                        1:"AssocReq", # Association request
                        2:"AssocResp", # Association response
                        3:"DisassocNotify", # Disassociation notification
                        4:"DataReq", # Data request
                        5:"PANIDConflictNotify", # PAN ID conflict notification
                        6:"OrphanNotify", # Orphan notification
                        7:"BeaconReq", # Beacon request
                        8:"CoordRealign", # coordinator realignment
                        9:"GTSReq" # GTS request
                        # 0x0a - 0xff reserved
                    }),
                    #TODO command payload
                    ]

    def mysummary(self):
        return self.sprintf("802.15.4 Command %Dot15d4Cmd.cmd_id% ( %Dot15dCmd.src_panid%:%Dot15d4Cmd.src_addr% -> %Dot15d4Cmd.dest_panid%:%Dot15d4Cmd.dest_addr% )")

    # command frame payloads are complete: DataReq, PANIDConflictNotify, OrphanNotify, BeaconReq don't have any payload
    # Although BeaconReq can have an optional ZigBee Beacon payload (implemented in ZigBeeBeacon)
    def guess_payload_class(self, payload):
        if   self.cmd_id == 1: return Dot15d4CmdAssocReq
        elif self.cmd_id == 2: return Dot15d4CmdAssocResp
        elif self.cmd_id == 3: return Dot15d4CmdDisassociation
        elif self.cmd_id == 8: return Dot15d4CmdCoordRealign
        elif self.cmd_id == 9: return Dot15d4CmdGTSReq
        else:                  return Packet.guess_payload_class(self, payload)

class Dot15d4CmdCoordRealign(Packet):
    name = "802.15.4 Coordinator Realign Command"
    fields_desc = [
        # PAN Identifier (2 octets)
        XLEShortField("panid", 0xFFFF),
        # Coordinator Short Address (2 octets)
        XLEShortField("coord_address", 0x0000),
        # Logical Channel (1 octet): the logical channel that the coordinator intends to use for all future communications
        ByteField("channel", 0),
        # Short Address (2 octets)
        XLEShortField("dev_address", 0xFFFF),
        # Channel page (0/1 octet) TODO optional
        #ByteField("channel_page", 0),
    ]
    def mysummary(self):
        return self.sprintf("802.15.4 Coordinator Realign Payload ( PAN ID: %Dot15dCmdCoordRealign.pan_id% : channel %Dot15d4CmdCoordRealign.channel% )")


### ZigBee ###

class ZigbeePayloadField(StrField): # passes the remaining length of the current frame to do a relational offset such as all but the last 4 bytes.
    def __init__(self, name, default, codec=None, fld=None, length_from=None):
        StrField.__init__(self, name, default)
        self.length_from = length_from
    def getfield(self, pkt, s):
        l = self.length_from(pkt, s)
        if l <= 0:
            return s,""
        return s[l:], self.m2i(pkt,s[:l])

    def guess_payload_class(self, payload):
        if   self.cmd_id == 1: return Dot15d4CmdAssocReq
        elif self.cmd_id == 2: return Dot15d4CmdAssocResp
        elif self.cmd_id == 3: return Dot15d4CmdDisassociation
        elif self.cmd_id == 8: return Dot15d4CmdCoordRealign
        elif self.cmd_id == 9: return Dot15d4CmdGTSReq
        else:                  return Packet.guess_payload_class(self, payload)
class ZigbeeNWK(Packet):
    name = "Zigbee Network Layer"
    fields_desc = [
                    BitField("discover_route", 0, 2),
                    BitField("proto_version", 2, 4),
                    BitEnumField("frametype", 0, 2, {0:'data', 1:'command'}),
                    FlagsField("flags", 0, 8, ['multicast', 'security', 'source_route', 'extended_dst', 'extended_src', 'reserved1', 'reserved2', 'reserved3']),
                    XLEShortField("destination", 0),
                    XLEShortField("source", 0),
                    ByteField("radius", 0),
                    ByteField("seqnum", 1),

                    ConditionalField(ByteField("relay_count", 1), lambda pkt:pkt.flags & 0x04),
                    ConditionalField(ByteField("relay_index", 0), lambda pkt:pkt.flags & 0x04),
                    ConditionalField(FieldListField("relays", [ ], XLEShortField("", 0x0000), count_from = lambda pkt:pkt.relay_count), lambda pkt:pkt.flags & 0x04),

                    #ConditionalField(XLongField("ext_dst", 0), lambda pkt:pkt.flags & 8),
                    ConditionalField(dot15d4AddressField("ext_dst", 0, adjust=lambda pkt,x: 8), lambda pkt:pkt.flags & 8),
                    #ConditionalField(XLongField("ext_src", 0), lambda pkt:pkt.flags & 16),
                    ConditionalField(dot15d4AddressField("ext_src", 0, adjust=lambda pkt,x: 8), lambda pkt:pkt.flags & 16),
                ]

    def guess_payload_class(self, payload):
        if self.flags & 0x02:
            return ZigbeeSecurityHeader
        elif self.frametype == 0:
            return ZigbeeAppDataPayload
        elif self.frametype == 1:
            return ZigbeeNWKCommandPayload
        else:
            return Packet.guess_payload_class(self, payload)

class LinkStatusEntry(Packet):
    name = "ZigBee Link Status Entry"
    fields_desc = [
        # Neighbor network address (2 octets)
        XLEShortField("neighbor_network_address", 0x0000),
        # Link status (1 octet)
        BitField("reserved1", 0, 1),
        BitField("outgoing_cost", 0, 3),
        BitField("reserved2", 0, 1),
        BitField("incoming_cost", 0, 3),
    ]

class ZigbeeNWKCommandPayload(Packet):
    name = "Zigbee Network Layer Command Payload"
    fields_desc = [
        ByteEnumField("cmd_identifier", 1, {
            1:"route request",
            2:"route reply",
            3:"network status",
            4:"leave",
            5:"route record",
            6:"rejoin request",
            7:"rejoin response",
            8:"link status",
            9:"network report",
            10:"network update"
            # 0x0b - 0xff reserved
        }),

        ### Route Request Command ###
        # Command options (1 octet)
        ConditionalField(BitField("reserved", 0, 1), lambda pkt:pkt.cmd_identifier == 1),
        ConditionalField(BitField("multicast", 0, 1), lambda pkt:pkt.cmd_identifier == 1),
        ConditionalField(BitField("dest_addr_bit", 0, 1), lambda pkt:pkt.cmd_identifier == 1),
        ConditionalField(
            BitEnumField("many_to_one", 0, 2, {
                0:"not_m2one", 1:"m2one_support_rrt", 2:"m2one_no_support_rrt", 3:"reserved"}
            ), lambda pkt:pkt.cmd_identifier == 1),
        ConditionalField(BitField("reserved", 0, 3), lambda pkt:pkt.cmd_identifier == 1),
        # Route request identifier (1 octet)
        ConditionalField(ByteField("route_request_identifier", 0), lambda pkt:pkt.cmd_identifier == 1),
        # Destination address (2 octets)
        ConditionalField(XLEShortField("destination_address", 0x0000), lambda pkt:pkt.cmd_identifier == 1),
        # Path cost (1 octet)
        ConditionalField(ByteField("path_cost", 0), lambda pkt:pkt.cmd_identifier == 1),
        # Destination IEEE Address (0/8 octets), only present when dest_addr_bit has a value of 1
        ConditionalField(dot15d4AddressField("ext_dst", 0, adjust=lambda pkt,x: 8),
            lambda pkt:(pkt.cmd_identifier == 1 and pkt.dest_addr_bit == 1)),

        ### Route Reply Command ###
        # Command options (1 octet)
        ConditionalField(BitField("reserved", 0, 1), lambda pkt:pkt.cmd_identifier == 2),
        ConditionalField(BitField("multicast", 0, 1), lambda pkt:pkt.cmd_identifier == 2),
        ConditionalField(BitField("responder_addr_bit", 0, 1), lambda pkt:pkt.cmd_identifier == 2),
        ConditionalField(BitField("originator_addr_bit", 0, 1), lambda pkt:pkt.cmd_identifier == 2),
        ConditionalField(BitField("reserved", 0, 4), lambda pkt:pkt.cmd_identifier == 2),
        # Route request identifier (1 octet)
        ConditionalField(ByteField("route_request_identifier", 0), lambda pkt:pkt.cmd_identifier == 2),
        # Originator address (2 octets)
        ConditionalField(XLEShortField("originator_address", 0x0000), lambda pkt:pkt.cmd_identifier == 2),
        # Responder address (2 octets)
        ConditionalField(XLEShortField("responder_address", 0x0000), lambda pkt:pkt.cmd_identifier == 2),
        # Path cost (1 octet)
        ConditionalField(ByteField("path_cost", 0), lambda pkt:pkt.cmd_identifier == 2),
        # Originator IEEE address (0/8 octets)
        ConditionalField(dot15d4AddressField("originator_addr", 0, adjust=lambda pkt,x: 8),
            lambda pkt:(pkt.cmd_identifier == 2 and pkt.originator_addr_bit == 1)),
        # Responder IEEE address (0/8 octets)
        ConditionalField(dot15d4AddressField("responder_addr", 0, adjust=lambda pkt,x: 8),
            lambda pkt:(pkt.cmd_identifier == 2 and pkt.responder_addr_bit == 1)),

        ### Network Status Command ###
        # Status code (1 octet)
        ConditionalField(ByteEnumField("status_code", 0, {
            0x00: "No route available",
            0x01: "Tree link failure",
            0x02: "Non-tree link failure",
            0x03: "Low battery level",
            0x04: "No routing capacity",
            0x05: "No indirect capacity",
            0x06: "Indirect transaction expiry",
            0x07: "Target device unavailable",
            0x08: "Target address unallocated",
            0x09: "Parent link failure",
            0x0a: "Validate route",
            0x0b: "Source route failure",
            0x0c: "Many-to-one route failure",
            0x0d: "Address conflict",
            0x0e: "Verify addresses",
            0x0f: "PAN identifier update",
            0x10: "Network address update",
            0x11: "Bad frame counter",
            0x12: "Bad key sequence number",
            # 0x13 - 0xff Reserved
        }), lambda pkt:pkt.cmd_identifier == 3),
        # Destination address (2 octets)
        ConditionalField(XLEShortField("destination_address", 0x0000), lambda pkt:pkt.cmd_identifier == 3),

        ### Leave Command ###
        # Command options (1 octet)
        # Bit 7: Remove children
        ConditionalField(BitField("remove_children", 0, 1), lambda pkt:pkt.cmd_identifier == 4),
        # Bit 6: Request
        ConditionalField(BitField("request", 0, 1), lambda pkt:pkt.cmd_identifier == 4),
        # Bit 5: Rejoin
        ConditionalField(BitField("rejoin", 0, 1), lambda pkt:pkt.cmd_identifier == 4),
        # Bit 0 - 4: Reserved
        ConditionalField(BitField("reserved", 0, 5), lambda pkt:pkt.cmd_identifier == 4),

        ### Route Record Command ###
        # Relay count (1 octet)
        ConditionalField(ByteField("rr_relay_count", 0), lambda pkt:pkt.cmd_identifier == 5),
        # Relay list (variable in length)
        ConditionalField(
            FieldListField("rr_relay_list", [], XLEShortField("", 0x0000), count_from = lambda pkt:pkt.rr_relay_count),
            lambda pkt:pkt.cmd_identifier == 5),

        ### Rejoin Request Command ###
        # Capability Information (1 octet)
        ConditionalField(BitField("allocate_address", 0, 1), lambda pkt:pkt.cmd_identifier == 6), # Allocate Address
        ConditionalField(BitField("security_capability", 0, 1), lambda pkt:pkt.cmd_identifier == 6), # Security Capability
        ConditionalField(BitField("reserved2", 0, 1), lambda pkt:pkt.cmd_identifier == 6), # bit 5 is reserved
        ConditionalField(BitField("reserved1", 0, 1), lambda pkt:pkt.cmd_identifier == 6), # bit 4 is reserved
        ConditionalField(BitField("receiver_on_when_idle", 0, 1), lambda pkt:pkt.cmd_identifier == 6), # Receiver On When Idle
        ConditionalField(BitField("power_source", 0, 1), lambda pkt:pkt.cmd_identifier == 6), # Power Source
        ConditionalField(BitField("device_type", 0, 1), lambda pkt:pkt.cmd_identifier == 6), # Device Type
        ConditionalField(BitField("alternate_pan_coordinator", 0, 1), lambda pkt:pkt.cmd_identifier == 6), # Alternate PAN Coordinator

        ### Rejoin Response Command ###
        # Network address (2 octets)
        ConditionalField(XLEShortField("network_address", 0xFFFF), lambda pkt:pkt.cmd_identifier == 7),
        # Rejoin status (1 octet)
        ConditionalField(ByteField("rejoin_status", 0), lambda pkt:pkt.cmd_identifier == 7),

        ### Link Status Command ###
        # Command options (1 octet)
        ConditionalField(BitField("reserved", 0, 1), lambda pkt:pkt.cmd_identifier == 8), # Reserved
        ConditionalField(BitField("last_frame", 0, 1), lambda pkt:pkt.cmd_identifier == 8), # Last frame
        ConditionalField(BitField("first_frame", 0, 1), lambda pkt:pkt.cmd_identifier == 8), # First frame
        ConditionalField(BitField("entry_count", 0, 5), lambda pkt:pkt.cmd_identifier == 8), # Entry count
        # Link status list (variable size)
        ConditionalField(
            PacketListField("link_status_list", [], LinkStatusEntry, count_from = lambda pkt:pkt.entry_count),
            lambda pkt:pkt.cmd_identifier == 8),

        ### Network Report Command ###
        # Command options (1 octet)
        ConditionalField(
            BitEnumField("report_command_identifier", 0, 3, {0:"PAN identifier conflict"}), # 0x01 - 0x07 Reserved
            lambda pkt:pkt.cmd_identifier == 9),
        ConditionalField(BitField("report_information_count", 0, 5), lambda pkt:pkt.cmd_identifier == 9),
        # EPID: Extended PAN ID (8 octets)
        ConditionalField(dot15d4AddressField("epid", 0, adjust=lambda pkt,x: 8), lambda pkt:pkt.cmd_identifier == 9),
        # Report information (variable length)
        # Only present if we have a PAN Identifier Conflict Report
        ConditionalField(
            FieldListField("PAN_ID_conflict_report", [], XLEShortField("", 0x0000),
                count_from = lambda pkt:pkt.report_information_count),
            lambda pkt:(pkt.cmd_identifier == 9 and pkt.report_command_identifier == 0)
        ),

        ### Network Update Command ###
        # Command options (1 octet)
        ConditionalField(
            BitEnumField("update_command_identifier", 0, 3, {0:"PAN Identifier Update"}), # 0x01 - 0x07 Reserved
            lambda pkt:pkt.cmd_identifier == 10),
        ConditionalField(BitField("update_information_count", 0, 5), lambda pkt:pkt.cmd_identifier == 10),
        # EPID: Extended PAN ID (8 octets)
        ConditionalField(dot15d4AddressField("epid", 0, adjust=lambda pkt,x: 8), lambda pkt:pkt.cmd_identifier == 10),
        # Update Id (1 octet)
        ConditionalField(ByteField("update_id", 0), lambda pkt:pkt.cmd_identifier == 10),
        # Update Information (Variable)
        # Only present if we have a PAN Identifier Update
        # New PAN ID (2 octets)
        ConditionalField(XLEShortField("new_PAN_ID", 0x0000),
            lambda pkt:(pkt.cmd_identifier == 10 and pkt.update_command_identifier == 0)),

        #ZigbeePayloadField("data", "", length_from=lambda pkt, s:len(s)),
    ]

def util_mic_len(pkt):
    ''' Calculate the length of the attribute value field '''
    if ( pkt.nwk_seclevel == 0 ): # no encryption, no mic
        return 0
    elif ( pkt.nwk_seclevel == 1 ): # MIC-32
        return 4
    elif ( pkt.nwk_seclevel == 2 ): # MIC-64
        return 8
    elif ( pkt.nwk_seclevel == 3 ): # MIC-128
        return 16
    elif ( pkt.nwk_seclevel == 4 ): # ENC
        return 0
    elif ( pkt.nwk_seclevel == 5 ): # ENC-MIC-32
        return 4
    elif ( pkt.nwk_seclevel == 6 ): # ENC-MIC-64
        return 8
    elif ( pkt.nwk_seclevel == 7 ): # ENC-MIC-128
        return 16
    else:
        return 0

class ZigbeeSecurityHeader(Packet):
    name = "Zigbee Security Header"
    fields_desc = [
        # Security control (1 octet)
        HiddenField(FlagsField("reserved1", 0, 2, [ 'reserved1', 'reserved2' ]), True),
        BitField("extended_nonce", 1, 1), # set to 1 if the sender address field is present (source)
        # Key identifier
        BitEnumField("key_type", 1, 2, {
            0:'data_key',
            1:'network_key',
            2:'key_transport_key',
            3:'key_load_key'
        }),
        # Security level (3 bits)
        BitEnumField("nwk_seclevel", 0, 3, {
            0:"None",
            1:"MIC-32",
            2:"MIC-64",
            3:"MIC-128",
            4:"ENC",
            5:"ENC-MIC-32",
            6:"ENC-MIC-64",
            7:"ENC-MIC-128"
        }),
        # Frame counter (4 octets)
        XLEIntField("fc", 0), # provide frame freshness and prevent duplicate frames
        # Source address (0/8 octets)
        ConditionalField(dot15d4AddressField("source", 0, adjust=lambda pkt,x: 8), lambda pkt:pkt.extended_nonce),
        # Key sequence number (0/1 octet): only present when key identifier is 1 (network key)
        ConditionalField(ByteField("key_seqnum", 0), lambda pkt:pkt.getfieldval("key_type") == 1),
        # Payload
        # the length of the encrypted data is the payload length minus the MIC
        ZigbeePayloadField("data", "", length_from=lambda pkt, s:len(s)-util_mic_len(pkt) ),
        # Message Integrity Code (0/variable in size), length depends on nwk_seclevel
        StrLenField("mic", "", length_from=lambda pkt:util_mic_len(pkt) ),
    ]


class ZigbeeAppDataPayload(Packet):
    name = "Zigbee Application Layer Data Payload (General APS Frame Format)"
    fields_desc = [
        # Frame control (1 octet)
        FlagsField("frame_control", 2, 4, [ 'reserved1', 'security', 'ack_req', 'extended_hdr' ]),
        BitEnumField("delivery_mode", 0, 2, {0:'unicast', 1:'indirect', 2:'broadcast', 3:'group_addressing'}),
        BitEnumField("aps_frametype", 0, 2, {0:'data', 1:'command', 2:'ack'}),
        # Destination endpoint (0/1 octet)
        # ConditionalField(ByteField("dst_endpoint", 10), lambda pkt:(pkt.frame_control & 0x04 or pkt.aps_frametype == 2)), #  this is wrong?
        ConditionalField(ByteField("dst_endpoint", 10),
            lambda pkt:(pkt.delivery_mode in [0, 2])
        ),
        # Group address (0/2 octets)
        ConditionalField(XShortField("group_address", 0),
            lambda pkt:(pkt.delivery_mode == 3)
        ),
        # Cluster identifier (0/2 octets)
        ConditionalField(EnumField("cluster", 0, _zcl_cluster_identifier, fmt = "<H"), # unsigned short (little-endian)
            lambda pkt:(pkt.aps_frametype in [0, 2])
        ),
        # Profile identifier (0/2 octets)
        ConditionalField(EnumField("profile", 0, _zcl_profile_identifier, fmt = "<H"),
            lambda pkt:(pkt.aps_frametype in [0, 2])
        ),
        # Source endpoint (0/1 octets)
        ConditionalField(ByteField("src_endpoint", 10),
            lambda pkt:(pkt.aps_frametype in [0, 2])
        ),
        # APS counter (1 octet)
        ByteField("counter", 0),
        # TODO: optional extended header
        # variable length frame payload: 3 frame types: data, APS command, and acknowledgement
        #ConditionalField(ZigbeePayloadField("data", "", length_from=lambda pkt, s:len(s)), lambda pkt:pkt.aps_frametype == 0),
    ]

    def guess_payload_class(self, payload):
        if self.frame_control & 0x02: # we have a security header
            return ZigbeeSecurityHeader
        elif self.aps_frametype == 0:
            if self.profile == 0:  # ZDP
                if self.cluster == 0x0031:
                    return ZDPLqiRequest
                if self.cluster == 0x8031:
                    return ZDPLqiResponse
                if self.cluster == 0x0032:
                    return ZDPRoutingTableRequest
                if self.cluster == 0x8032:
                    return ZDPRoutingTableResponse
                if self.cluster == 0x0033:
                    return ZDPBindingTableRequest
                if self.cluster == 0x8033:
                    return ZDPBindingTableResponse
                if self.cluster == 0x0034:
                    return ZDPLeaveRequest
                if self.cluster == 0x8034:
                    return ZDPLeaveResponse

                return ZigbeeDeviceProfile
            elif self.cluster in _zcl_cluster_identifier:
                return ZigbeeClusterLibrary
            # TODO: might also be another frame
        elif self.aps_frametype == 1: # command
            return ZigbeeAppCommandPayload
        else:
            return Packet.guess_payload_class(self, payload)

class ZigbeeAppCommandPayload(Packet):
    name = "Zigbee Application Layer Command Payload"
    fields_desc = [
        ByteEnumField("cmd_identifier", 1, {
            1:"APS_CMD_SKKE_1",
            2:"APS_CMD_SKKE_2",
            3:"APS_CMD_SKKE_3",
            4:"APS_CMD_SKKE_4",
            5:"APS_CMD_TRANSPORT_KEY",
            6:"APS_CMD_UPDATE_DEVICE",
            7:"APS_CMD_REMOVE_DEVICE",
            8:"APS_CMD_REQUEST_KEY",
            9:"APS_CMD_SWITCH_KEY",
            10:"APS_CMD_EA_INIT_CHLNG",
            11:"APS_CMD_EA_RSP_CHLNG",
            12:"APS_CMD_EA_INIT_MAC_DATA",
            13:"APS_CMD_EA_RSP_MAC_DATA",
            14:"APS_CMD_TUNNEL"
        }),

        # Note: Only transport-key commands are implemented yet
        ConditionalField(ByteEnumField("transport_key_type", 0, {
            0: "Trust Center master key",
            1: "Standard network key",
            2: "Application master key",
            3: "Application link key",
            4: "Unique Trust-Center link key",
            5: "High-security network key",
            6: "unknown network key?",
        }), lambda pkt:pkt.cmd_identifier == 5),

        # Key descriptor:
        ConditionalField(XBitField("key", 0, 128),
            lambda pkt:pkt.cmd_identifier == 5),
        ConditionalField(ByteField("network_key_sqn", 0),
            lambda pkt:pkt.cmd_identifier == 5 and (pkt.transport_key_type in [1, 5, 6])),
        ConditionalField(dot15d4AddressField("key_dest_addr", 0, adjust=lambda pkt,x: 8),
            lambda pkt:pkt.cmd_identifier == 5 and (pkt.transport_key_type in [0, 1, 4, 5, 6])),
        ConditionalField(dot15d4AddressField("key_src_addr", 0, adjust=lambda pkt,x: 8),
            lambda pkt:pkt.cmd_identifier == 5 and (pkt.transport_key_type in [0, 1, 4, 5, 6])),
        ConditionalField(dot15d4AddressField("partner_addr", 0, adjust=lambda pkt,x: 8),
            lambda pkt:pkt.cmd_identifier == 5 and (pkt.transport_key_type in [2, 3])),
        ConditionalField(ByteField("initiator_flag", 0),
            lambda pkt:pkt.cmd_identifier == 5 and (pkt.transport_key_type in [2, 3])),

        # Fallback payload for unimplemented commands:
        ConditionalField(ZigbeePayloadField("data", "", length_from=lambda pkt, s:len(s)),
            lambda pkt:pkt.cmd_identifier != 5)

        # TODO: implement other transport-key commands
    ]

### Utility Functions ###
def util_srcpanid_present(pkt):
    '''A source PAN ID is included if and only if both src addr mode != 0 and PAN ID Compression in FCF == 0'''
    if (pkt.underlayer.getfieldval("fcf_srcaddrmode") != 0) and (pkt.underlayer.getfieldval("fcf_panidcompress") == 0): return True
    else: return False

# Do a CRC-CCITT Kermit 16bit on the data given
# Returns a CRC that is the FCS for the frame
#  Implemented using pseudocode from: June 1986, Kermit Protocol Manual
#  See also: http://regregex.bbcmicro.net/crc-catalogue.htm#crc.cat.kermit
def makeFCS(data):
    crc = 0
    for i in range(0, len(data)):
        c = ord(data[i])
        q = (crc ^ c) & 15              #Do low-order 4 bits
        crc = (crc // 16) ^ (q * 4225)
        q = (crc ^ (c // 16)) & 15      #And high 4 bits
        crc = (crc // 16) ^ (q * 4225)
    return struct.pack('<H', crc) #return as bytes in little endian order


class Dot15d4CmdAssocReq(Packet):
    name = "802.15.4 Association Request Payload"
    fields_desc = [
        BitField("allocate_address", 0, 1), # Allocate Address
        BitField("security_capability", 0, 1), # Security Capability
        BitField("reserved2", 0, 1), #  bit 5 is reserved
        BitField("reserved1", 0, 1), #  bit 4 is reserved
        BitField("receiver_on_when_idle", 0, 1), # Receiver On When Idle
        BitField("power_source", 0, 1), # Power Source
        BitField("device_type", 0, 1), # Device Type
        BitField("alternate_pan_coordinator", 0, 1), # Alternate PAN Coordinator
    ]
    def mysummary(self):
        return self.sprintf("802.15.4 Association Request Payload ( Alt PAN Coord: %Dot15d4CmdAssocReq.alternate_pan_coordinator% Device Type: %Dot15d4CmdAssocReq.device_type% )")

class Dot15d4CmdAssocResp(Packet):
    name = "802.15.4 Association Response Payload"
    fields_desc = [
        XLEShortField("short_address", 0xFFFF), # Address assigned to device from coordinator (0xFFFF == none)
        # Association Status
        # 0x00 == successful
        # 0x01 == PAN at capacity
        # 0x02 == PAN access denied
        # 0x03 - 0x7f == Reserved
        # 0x80 - 0xff == Reserved for MAC primitive enumeration values
        ByteEnumField("association_status", 0x00, {0:'successful', 1:'PAN_at_capacity', 2:'PAN_access_denied'}),
    ]
    def mysummary(self):
        return self.sprintf("802.15.4 Association Response Payload ( Association Status: %Dot15d4CmdAssocResp.association_status% Assigned Address: %Dot15d4CmdAssocResp.short_address% )")

class Dot15d4CmdDisassociation(Packet):
    name = "802.15.4 Disassociation Notification Payload"
    fields_desc = [
        # Disassociation Reason
        # 0x00 == Reserved
        # 0x01 == The coordinator wishes the device to leave the PAN
        # 0x02 == The device wishes to leave the PAN
        # 0x03 - 0x7f == Reserved
        # 0x80 - 0xff == Reserved for MAC primitive enumeration values
        ByteEnumField("disassociation_reason", 0x02, {1:'coord_wishes_device_to_leave', 2:'device_wishes_to_leave'}),
    ]
    def mysummary(self):
        return self.sprintf("802.15.4 Disassociation Notification Payload ( Disassociation Reason %Dot15d4CmdDisassociation.disassociation_reason% )")

class Dot15d4CmdGTSReq(Packet):
    name = "802.15.4 GTS request command"
    fields_desc = [
        # GTS Characteristics field (1 octet)
        # Reserved (bits 6-7)
        BitField("reserved", 0, 2),
        # Characteristics Type (bit 5)
        BitField("charact_type", 0, 1),
        # GTS Direction (bit 4)
        BitField("gts_dir", 0, 1),
        # GTS Length (bits 0-3)
        BitField("gts_len", 0, 4),
    ]
    def mysummary(self):
        return self.sprintf("802.15.4 GTS Request Command ( %Dot15d4CmdGTSReq.gts_len% : %Dot15d4CmdGTSReq.gts_dir% )")

# PAN ID conflict notification command frame is not necessary, only Dot15d4Cmd with cmd_id = 5 ("PANIDConflictNotify")
# Orphan notification command not necessary, only Dot15d4Cmd with cmd_id = 6 ("OrphanNotify")

class ZigBeeBeacon(Packet):
    name = "ZigBee Beacon Payload"
    fields_desc = [
        # Protocol ID (1 octet)
        ByteField("proto_id", 0),
        # nwkcProtocolVersion (4 bits)
        BitField("nwkc_protocol_version", 0, 4),
        # Stack profile (4 bits)
        BitField("stack_profile", 0, 4),
        # End device capacity (1 bit)
        BitField("end_device_capacity", 0, 1),
        # Device depth (4 bits)
        BitField("device_depth", 0, 4),
        # Router capacity (1 bit)
        BitField("router_capacity", 0, 1),
        # Reserved (2 bits)
        BitField("reserved", 0, 2),
        # Extended PAN ID (8 octets)
        dot15d4AddressField("pan_id_ext", 0, adjust=lambda pkt,x: 8),
        # Tx offset (3 bytes)
        # In ZigBee 2006 the Tx-Offset is optional, while in the 2007 and later versions, the Tx-Offset is a required value.
        BitField("tx_offset", 0, 24),
        # Update ID (1 octet)
        ByteField("update_id", 0),
    ]

# ZigBee Specification: Table 2.129
class ZDPRoutingTableListRecord(Packet):  # rename to RoutingDescriptor?
    name = "ZDP Routing Table List Record / Routing Descriptor"
    fields_desc = [
        # Destinatin Address (16 bits)
        dot15d4AddressField("route_dst_addr", 0, adjust=lambda pkt,x: 2),
        # Route Status (3 bits)
        BitEnumField("route_status", 0, 3, {
            0x0: "ACTIVE",
            0X1: "DISCOVERY_UNDERWAY",
            0X2: "DISCOVERY_FAILED",
            0X3: "INACTIVE",
            0X4: "VALIDATION_UNDERWAY",
            # 0x5 - 0x7 Reserved
        }),
        # Reserved (2 bits)
        BitField("reserved", 0 , 2),
        # Route record required (1 bit)
        BitField("route_record_required", 0, 1),
        # Many-to-one (1 bit)
        BitField("many_to_one", 0, 1),
        # Memory constrained (1 bit)
        BitField("memory_constrained", 0, 1),
        # Next-hop Address (16 bits)
        dot15d4AddressField("next_hop_addr", 0, adjust=lambda pkt,x: 2),
    ]

# ZigBee Specification: Table 2.131
class ZDPBindingTableListRecord(Packet):  # rename to BindingDescriptor?
    name = "ZDP Binding Table List Record / Binding Descriptor"
    fields_desc = [
        # Bind Source Address (8 octets)
        dot15d4AddressField("bind_src_addr", 0, adjust=lambda pkt,x: 8),
        # Bind Source Endpoint (1 octet)
        XByteField("bind_src_endpoint", 1),  # valid range: 0x01 - 0xfe
        # Bind Cluster id (2 octets)
        XLEShortField("bind_cluster", 0),
        # Destination Addr Mode (1 octet)
        #   0x00: reserved
        #   0x01: 16-bit group address for DstAddr and DstEndpoint not present
        #   0x02: reserved
        #   0x03: 64-bit extended address for DstAddr and DstEndp present
        #   0x04 - 0xff: reserved
        ByteField("bind_dst_addr_mode", 0x01),
        # Bind Destination Address (2/8 octets)
        dot15d4AddressField("bind_dst_addr", 0,
            adjust=lambda pkt,x:(8 if pkt.bind_dst_addr_mode == 0x03 else 2)),
        # Bind Destination Endpoint (0/1 octet)
        ConditionalField(
            XByteField("bind_dst_endpoint", 1),
            lambda pkt:(pkt.bind_dst_addr_mode == 0x03)),
    ]

# ZigBee Specification: Table 2.127
class ZDPNeighborTableListRecord(Packet):  # rename to NeighborDescriptor?
    name = "ZDP Neighbor Table List Record / Neighbor Descriptor"
    fields_desc = [
        # Neighbor extended PAN Id (8 octets)
        dot15d4AddressField("nb_ext_panid", 0, adjust=lambda pkt,x: 8),
        # Neighbor long Address (8 octets)
        dot15d4AddressField("nb_ext_addr", 0, adjust=lambda pkt,x: 8),
        # Neighbor short Address (2 octets)
        dot15d4AddressField("nb_addr", 0, adjust=lambda pkt,x: 2),
        # Reserved (1 bit)
        BitField("reserved_0", 0, 1),
        # Relationship (3 bits)
        BitEnumField("relationship", 0, 3, {
            0x0: "parent",
            0x1: "child",
            0x2: "sibling",
            0x3: "none",
            0x4: "previous_child",
        }),
        # Rx On When Idle (2 bits)
        BitEnumField("rx_on_when_idle", 1, 2, {
            0x0: "true",
            0x1: "false",
            0x2: "unknown",
        }),
        # Device Type (2 bits)
        BitEnumField("device_type", 0, 2, {
            0x0: "coordinator",
            0x1: "router",
            0x2: "end_device",
            0x3: "unknown",
        }),
        # Reserved (6 bits)
        BitField("reserved_1", 0, 6),
        # Permit Joining (2 bits)
        BitEnumField("permit_joining", 0, 2, {
            0x0: "true",
            0x1: "false",
            0x2: "unknown",
        }),
        # Depth (1 octet)
        ByteField("depth", 0),
        # LQI [Link Quality Indicator] (1 octet)
        ByteField("lqi", 0),
    ]

### ZDP Mgmt_Lqi_req Command (2.4.3.3.2) cluster 0x0031 ###
class ZDPLqiRequest(Packet):
    name = "Zigbee ZDP Mgmt_Lqi_req"
    fields_desc = [
        # sequence number (1 octet)
        ByteField("transaction_sequence", 0),
        # StartIndex (1 octet)
        ByteField("start_index", 0),
    ]
    def answers(self, other):
        if isinstance(other, ZDPLqiResponse):
            return (self.start_index == other.start_index \
                    and self.transaction_sequence == other.transaction_sequence)
        return 0

### ZDP Mgmt_Lqi_rsp Command (2.4.4.3.2) cluster 0x8031 ###
class ZDPLqiResponse(Packet):
    name = "Zigbee ZDP Mgmt_Lqi_rsp"
    fields_desc = [
        # sequence number (1 octet)
        ByteField("transaction_sequence", 0),
        # Status (1 octet)
        ByteEnumField("zdp_status", 0, _zdp_enumerated_stauts_values),
        # Neighbor Table Entries (1 octet)
        ByteField("neighbor_table_entries", 0, ),
        # StartIndex (1 octet)
        ByteField("start_index", 0),
        # Neighbor Table List Count (1 octet)
        FieldLenField("neighbor_table_list_count", None,
                count_of="neighbor_table_list", fmt="B"),
        # Neighbor Table List (22 octets * neighbor_table_list_count)
        PacketListField("neighbor_table_list", [], ZDPNeighborTableListRecord,
            count_from=lambda pkt:pkt.neighbor_table_list_count),
    ]


### ZDP Mgmt_Rtg_req Command (2.4.3.3.3) cluster 0x0032 ###
class ZDPRoutingTableRequest(Packet):
    name = "Zigbee ZDP Mgmt_Rtg_req"
    fields_desc = [
        # sequence number (1 octet)
        ByteField("transaction_sequence", 0),
        # StartIndex (1 octet)
        ByteField("start_index", 0),
    ]
    def answers(self, other):
        if isinstance(other, ZDPRoutingTableResponse):
            return (self.start_index == other.start_index \
                    and self.transaction_sequence == other.transaction_sequence)
        return 0

### Mgmt_Rtg_rsp Command (2.4.4.3.3) cluster 0x8032 ###
class ZDPRoutingTableResponse(Packet):
    name = "Zigbee ZDP Mgmt_Rtg_rsp"
    fields_desc = [
        # sequence number (1 octet)
        ByteField("transaction_sequence", 0),
        # Status (1 octet)
        ByteEnumField("zdp_status", 0, _zdp_enumerated_stauts_values),
        # Routing Table Entries (1 octet)
        ByteField("routing_table_entries", 0),
        # StartIndex (1 octet)
        ByteField("start_index", 0),
        # Routing Table List Count (1 octet)
        FieldLenField("routing_table_list_count", None,
            count_of="routing_table_list", fmt="B"),
        # Routing Table List (5 octets * routing_table_list_count)
        PacketListField("routing_table_list", [], ZDPRoutingTableListRecord,
            count_from=lambda pkt:pkt.routing_table_list_count),
    ]

### Mgmt_Bind_req (2.4.3.3.4) cluster 0x0033 ###
class ZDPBindingTableRequest(Packet):
    name = "Zigbee ZDP Mgmt_Bind_req"
    fields_desc = [
        # sequence number (1 octet)
        ByteField("transaction_sequence", 0),
        # StartIndex (1 octet)
        ByteField("start_index", 0),
    ]
    def answers(self, other):
        if isinstance(other, ZDPBindingTableResponse):
            return (self.start_index == other.start_index \
                    and self.transaction_sequence == other.transaction_sequence)
        return 0

### Mgmt_Bind_rsp (2.4.4.3.4) cluster 0x8033 ###
class ZDPBindingTableResponse(Packet):
    name = "Zigbee ZDP Mgmt_Bind_rsp"
    fields_desc = [
        # sequence number (1 octet)
        ByteField("transaction_sequence", 0),
        # Status (1 octet)
        ByteEnumField("zdp_status", 0, _zdp_enumerated_stauts_values),
        # Binding Table Entries (1 octet)
        ByteField("binding_table_entries", 0),
        # StartIndex (1 octet)
        ByteField("start_index", 0),
        # Binding Table List Count (1 octet)
        FieldLenField("binding_table_list_count", None,
            count_of="binding_table_list", fmt="B"),
        # Binding Table List (variable octets * binding_table_list_count)
        PacketListField("binding_table_list", [], ZDPBindingTableListRecord,
            count_from=lambda pkt:pkt.binding_table_list_count),
    ]

### Mgmt_Leave_req (2.4.3.3.5) cluster 0x0034 ###
class ZDPLeaveRequest(Packet):
    name = "Zigbee ZDP Mgmt_Leave_req"
    fields_desc = [
        # sequence number (1 octet)
        ByteField("transaction_sequence", 0),
        # Device Address (8 octets)
        dot15d4AddressField("device_addr", 0, adjust=lambda pkt,x: 8),
        # Rejoin (1 Bit)
        BitField("rejoin", 0, 1),
        # Remove Children (1 bit)
        BitField("remove_children", 0, 1),
        # Reserved (6 bits)
        BitField("reserved", 0, 6),
    ]
    def answers(self, other):
        if isinstance(other, ZDPLeaveRequest):
            return self.transaction_sequence == other.transaction_sequence
        return 0

### Mgmt_Leave_rsp (2.4.4.3.5) cluster 0x8034 ###
class ZDPLeaveResponse(Packet):
    name = "Zigbee ZDP Mgmt_Leave_rsp"
    fields_desc = [
        # sequence number (1 octet)
        ByteField("transaction_sequence", 0),
        # Status (1 octet)
        ByteEnumField("zdp_status", 0, _zdp_enumerated_stauts_values),
    ]


class ZigbeeDeviceProfile(Packet):
    name = "Zigbee Device Profile (ZDP) fallback frame"
    fields_desc = [
        # sequence number (1 octet)
        ByteField("transaction_sequence", 0),

        ###### Device and Service Discovery Commands ######

        ###### Bind Management Commands ######

        ### End_Device_Bind_req (2.4.3.2.1) ###
        # TODO: implement

        ### Bind_req (2.4.3.2.2) ###
        # TODO: implement

        ### Unbind_req (2.4.3.2.3) ###
        # TODO: implement

        ### Replace_Device_req ###

        ###### Network Management Commands ######

        ### Mgmt_NWK_Disc_req Command (2.4.3.3.1) ###
        # TODO: implement
        ### Mgmt_NWK_Disc_rsp Command (2.4.4.3.1) ###
        # TODO: implement
        ### Mgmt_Direct_Join_req Command (2.4.3.3.6) ###
        # TODO: implement
        ### Mgmt_Direct_Join_rsp Command (2.4.4.3.6) ###
        # TODO: implement
        ### Mgmt_Permit_Joining_req Command (2.4.3.3.7) ###
        # TODO: implement
        ### Mgmt_Permit_Joining_rsp Command (2.4.4.3.7) ###
        # TODO: implement
        ### Mgmt_Cache_req Command (2.4.3.3.8) ###
        # TODO: implement
        ### Mgmt_Cache_rsp Command (2.4.4.3.8) ###
        # TODO: implement
        ### Mgmt_NWK_Update_req Command (2.4.3.3.9) ###
        # TODO: implement
        ### Mgmt_NWK_Update_rsp Command (2.4.4.3.9) ###
        # TODO: implement

    ]

    def guess_payload_class(self, payload):
    	return Packet.guess_payload_class(self, payload)



### Inter-PAN Transmission ###
class ZigbeeNWKStub(Packet):
    name = "Zigbee Network Layer for Inter-PAN Transmission"
    fields_desc = [
        # NWK frame control
        BitField("reserved", 0, 2), # remaining subfields shall have a value of 0
        BitField("proto_version", 2, 4),
        BitField("frametype", 0b11, 2), # 0b11 (3) is a reserved frame type
        BitField("reserved", 0, 8), # remaining subfields shall have a value of 0
    ]

    def guess_payload_class(self, payload):
        if self.frametype == 0b11:
            return ZigbeeAppDataPayloadStub
        else:
            return Packet.guess_payload_class(self, payload)

class ZigbeeAppDataPayloadStub(Packet):
    name = "Zigbee Application Layer Data Payload for Inter-PAN Transmission"
    fields_desc = [
        FlagsField("frame_control", 0, 4, [ 'reserved1', 'security', 'ack_req', 'extended_hdr' ]),
        BitEnumField("delivery_mode", 0, 2, {0:'unicast', 2:'broadcast', 3:'group'}),
        BitField("frametype", 3, 2), # value 0b11 (3) is a reserved frame type
        # Group Address present only when delivery mode field has a value of 0b11 (group delivery mode)
        ConditionalField(
            XLEShortField("group_addr", 0x0), # 16-bit identifier of the group
            lambda pkt:pkt.getfieldval("delivery_mode") == 0b11
        ),
        # Cluster identifier
        EnumField("cluster", 0, _zcl_cluster_identifier, fmt = "<H"), # unsigned short (little-endian)
        # Profile identifier
        EnumField("profile", 0, _zcl_profile_identifier, fmt = "<H"),
        # ZigBee Payload
#        ConditionalField(
#            ZigbeePayloadField("data", "", length_from=lambda pkt, s:len(s)),
#            lambda pkt:pkt.frametype == 3
#        ),
    ]
    def guess_payload_class(self, payload):
        if self.frametype == 3 and self.profile == 0xc05e and self.cluster == 0x1000:
            return ZigbeeZLLCommissioningCluster
        else:
            return Packet.guess_payload_class(self, payload)

class ZigbeeZLLCommissioningCluster(Packet):
    name = "Zigbee LightLink Commissioning Cluster Frame"
    fields_desc = [
        # Frame control (8 bits)
        BitField("reserved", 0, 3),
        BitField("disable_default_response", 1, 1), # 1 not default response command will be returned
        BitEnumField("direction", 0, 1, ['client2server', 'server2client']),
        BitField("manufacturer_specific", 0, 1), # 0 manufacturer code shall not be included in the ZCL frame
        # Frame Type
        # 0b00 command acts across the entire profile
        # 0b01 command is specific to a cluster
        # 0b10 - 0b11 reserved
        BitField("zcl_frametype", 1, 2),
        # Manufacturer code (0/16 bits) only present then manufacturer_specific field is set to 1
        ConditionalField(XLEShortField("manufacturer_code", 0x0),
            lambda pkt:pkt.getfieldval("manufacturer_specific") == 1
        ),
        # Transaction sequence number (8 bits)
        ByteField("transaction_sequence", 0),
        # Command identifier (8 bits): the cluster command
        ByteEnumField("command_identifier", 0x00, _zll_command_frames),
    ]

    def guess_payload_class(self, payload):
        if self.command_identifier == 0x00:# and pkt.cluster == 0x1000:
            return ZLLScanRequest
        elif self.command_identifier == 0x01:# and pkt.cluster == 0x1000:
            return ZLLScanResponse
        else:
            return Packet.guess_payload_class(self, payload)

class ZLLScanRequest(Packet):
    name = "ZLL: Scan Request"
    fields_desc = [
        # Inter-PAN transaction identifier (4 octets)
        XLEIntField("inter_pan_transaction_id", 0x66666666), # Unsigned 32-bit Integer (4 octets)
	# ZigBee information (1 octet)
        HiddenField(BitField("reserved", 0, 5)),
        BitEnumField("rx_on_when_idle", 1, 1, [False, True]),
        BitEnumField("logical_type", 1, 2, {
            0:"coordinator", 1:"router", 2:"end device", 3:"reserved"}
        ),
	# ZLL information (1 octet)
        #FlagsField("ZLL information", 0, 8, [ 'factory_new', 'address_assignment', 'reserved1', 'reserved2', 'link_initiator', 'undefined', 'reserved3', 'reserved4' ]),
        HiddenField(BitField("reserved1", 0, 2)),
        HiddenField(BitField("undefined", 0, 1)),
        BitEnumField("link_initiator", 0, 1, [False, True]),
        HiddenField(BitField("reserved2", 0, 2)),
        BitEnumField("address_assignment", 0, 1, [False, True]),
        BitEnumField("factory_new", 0, 1, [False, True]),
    ]
    def answers(self, other):
        if isinstance(other, ZLLScanResponse):
            return self.inter_pan_transaction_id == other.inter_pan_transaction_id
        return 0

class ZLLScanResponse(Packet):
    name = "ZLL: Scan Response"
    fields_desc = [
        # Inter-PAN transaction identifier (4 octets)
        XLEIntField("inter_pan_transaction_id", 0x66666666),
        ByteField("rssi_correction", 0x00), # range 0x00 - 0x20 (1 octet)
	# ZigBee information (1 octet)
        # HiddenField(BitField("reserved", 0, 5)),
        BitField("reserved", 0, 5),
        BitEnumField("rx_on_when_idle", 1, 1, [False, True]),
        BitEnumField("logical_type", 1, 2, {
            0:"coordinator", 1:"router", 2:"end device", 3:"reserved"}
        ),
	# ZLL information (1 octet)
        # HiddenField(BitField("reserved1", 0, 2)),
        BitField("reserved1", 0, 2),
        BitEnumField("touchlink_priority_request", 0, 1, [False, True]),
        BitEnumField("touchlink_initiator", 0, 1, [False, True]),
        # HiddenField(BitField("reserved2", 0, 2)),
        BitField("reserved2", 0, 2),
        BitEnumField("address_assignment", 0, 1, [False, True]),
        BitEnumField("factory_new", 0, 1, [False, True]),
        # Key bitmask (2 octets)
        FlagsField("key_bitmask", 0, 16, ["reserved_key_8", "reserved_key_9",
            "reserved_key_10", "reserved_key_11", "reserved_key_12",
            "reserved_key_13", "reserved_key_14", "certification_key",
            "development_key", "reserved_key_1", "reserved_key_2", "reserved_key_3",
            "master_key", "reserved_key_5", "reserved_key_6",
            "reserved_key_7"]),
        # BitField("reserved3", 0, 3),
        # BitEnumField("master_key", 0, 1, [False, True]),
        # BitField("reserved4", 0, 3),
        # BitEnumField("development_key", 0, 1, [False, True]),
        # BitEnumField("certification_key", 0, 1, [False, True]),
        # BitField("reserved5", 0, 3),
        # BitField("reserved6", 0, 4),

        # Response identifier (4 octets)
        XLEIntField("response_id", 0x66666666),
        # Extended PAN identifier (8 octets)
        dot15d4AddressField("pan_id_ext", 0, adjust=lambda pkt,x: 8),
        # Network update identifier (1 octet)
        ByteField("network_update_id", 0),
        # Logical channel (1 octet)
        ByteField("channel", 11),
        # PAN identifier (2 octets)
        XLEShortField("pan_id", 0x0000),
        # Network address (2 octets)
        XLEShortField("network_address", 0xffff),
        # Number of sub-devices (1 octet)
        ByteField("number_of_sub_devices", 1),
        # Total group identifiers (1 octet)
        ByteField("number_of_group_ids", 0),
        # Endpoint identifier (0/1 octets)
        ConditionalField(ByteField("endpoint_id", 0x00), lambda pkt:(pkt.getfieldval("number_of_sub_devices") == 1)),
        # Profile identifier (0/2 octets)
        #ConditionalField(XShortField("profile_id", 0x0000)
        ConditionalField(EnumField("profile_id", 0, _zcl_profile_identifier, fmt = "<H"), lambda pkt:(pkt.getfieldval("number_of_sub_devices") == 1)),
        # Device identifier (0/2 octets)
        ConditionalField(XShortField("device_id", 0x0000), lambda pkt:(pkt.getfieldval("number_of_sub_devices") == 1)),
        # Version (0/1 octets)
        # HiddenField(ConditionalField(BitField("0x0", 0, 4), lambda pkt:(pkt.getfieldval("number_of_sub_devices") == 1))),
        ConditionalField(BitField("0x0", 0, 4), lambda pkt:(pkt.getfieldval("number_of_sub_devices") == 1)),
        ConditionalField(BitField("application_device_version", 2, 4), lambda pkt:(pkt.getfieldval("number_of_sub_devices") == 1)),
        # Group identifier count (0/1 octets)
        ConditionalField(ByteField("group_id_count", 0x00), lambda pkt:(pkt.getfieldval("number_of_sub_devices") == 1)),
    ]

class ZLLDeviceInformationRequest(Packet):
    name = "ZLL: Device Information Request"
    fields_desc = [
        # Inter-PAN transaction identifier (4 octets)
        XLEIntField("inter_pan_transaction_id", 0x66666666),
	# Start index of device table (1 octet)
        ByteField("start_index", 0),
    ]

class ZLLIdentifyRequest(Packet):
    name = "ZLL: Identify Request"
    fields_desc = [
        # Inter-PAN transaction identifier (4 octets)
        XLEIntField("inter_pan_transaction_id", 0x66666666),
        # Identify duration (1 octet):
        #   0x0000: Exit identify mode
        #   0x0001 - 0xfffe: Number of seconds to remain in identify mode
        #   0xffff: Remain in identify mode for a default time known by the receiver
        XLEShortField("identify_duration", 0xffff),
    ]

class ZLLResetToFactoryNewRequest(Packet):
    name = "ZLL: Reset to Factory New Request"
    fields_desc = [
        # Inter-PAN transaction identifier (4 octets)
        XLEIntField("inter_pan_transaction_id", 0x66666666),
    ]

class ZLLNetworkStartRequest(Packet):
    name = "ZLL: Network Start Request"
    fields_desc = [
        # Inter-PAN transaction identifier (4 octets)
        XLEIntField("inter_pan_transaction_id", 0x66666666),
        # Extended PAN identifier (8 octets)
        dot15d4AddressField("pan_id_ext", 0, adjust=lambda pkt,x: 8),
        # Key index (1 octets)
        ByteField("key_index", 4),  # default: Master key
        # Encrypted network key (16 octets)
        XBitField("encrypted_network_key", 0, 128),
        # Logical channel (1 octet)
        ByteField("channel", 0),
        # PAN identifier (2 octets)
        XLEShortField("pan_id", 0x0000),
        # Network address (2 octets)
        XLEShortField("network_address", 0x0001),
        # Group identifiers begin (2 octets)
        XLEShortField("group_id_begin", 0),
        # Group identifiers end (2 octets)
        XLEShortField("group_id_end", 0),
        # Free network address range begin (2 octets)
        XLEShortField("free_network_address_range_begin", 0),
        # Free network address range end (2 octets)
        XLEShortField("free_network_address_range_end", 0),
        # Free group address range begin (2 octets)
        XLEShortField("free_group_address_range_begin", 0),
        # Free group address range end (2 octets)
        XLEShortField("free_group_address_range_end", 0),
        # Initiator IEEE address (8 octet)
        XBitField("initiator_ieee_address", 0, 64),
        # Initiator network address (2 octets)
        XLEShortField("initiator_network_address", 0),
    ]

class ZLLNetworkStartResponse(Packet):
    name = "ZLL: Network Start Response"
    fields_desc = [
        # Inter-PAN transaction identifier (4 octets)
        XLEIntField("inter_pan_transaction_id", 0x66666666),
        # Status (1 octet)
        ByteEnumField("status", 0, {0: "success", 1: "failure",
            2: "reserved_status_2", 3: "reserved_status_3",
            4: "reserved_status_4", 5: "reserved_status_5",
            6: "reserved_status_6", 7: "reserved_status_7",
            8: "reserved_status_8", 9: "reserved_status_9",
            10: "reserved_status_10", 11: "reserved_status_11",
            12: "reserved_status_12", 13: "reserved_status_13",
            14: "reserved_status_14", 15: "reserved_status_15"}),
        # Extended PAN identifier (8 octets)
        dot15d4AddressField("pan_id_ext", 0, adjust=lambda pkt,x: 8),
        # Network update identifier (1 octet)
        ByteField("network_update_id", 0x00),
        # Logical channel (1 octet)
        ByteField("channel", 11),
        # PAN identifier (2 octets)
        XLEShortField("pan_id", 0x0000),
    ]

class ZLLNetworkJoinRouterRequest(Packet):
    name = "ZLL: Network Join Router Request"
    fields_desc = [
        # Inter-PAN transaction identifier (4 octets)
        XLEIntField("inter_pan_transaction_id", 0x66666666),
        # Extended PAN identifier (8 octets)
        dot15d4AddressField("pan_id_ext", 0, adjust=lambda pkt,x: 8),
        # Key index (1 octets)
        ByteField("key_index", 4),  # default: Master key
        # Encrypted network key (16 octets)
        XBitField("encrypted_network_key", 0, 128),
        # Network update identifier (1 octet)
        ByteField("network_update_id", 0x00),
        # Logical channel (1 octet)
        ByteField("channel", 0),
        # PAN identifier (2 octets)
        XLEShortField("pan_id", 0x0000),
        # Network address (2 octets)
        XLEShortField("network_address", 0x0001),
        # Group identifiers begin (2 octets)
        XLEShortField("group_id_begin", 0),
        # Group identifiers end (2 octets)
        XLEShortField("group_id_end", 0),
        # Free network address range begin (2 octets)
        XLEShortField("free_network_address_range_begin", 0),
        # Free network address range end (2 octets)
        XLEShortField("free_network_address_range_end", 0),
        # Free group address range begin (2 octets)
        XLEShortField("free_group_address_range_begin", 0),
        # Free group address range end (2 octets)
        XLEShortField("free_group_address_range_end", 0),
    ]

class ZLLNetworkJoinRouterResponse(Packet):
    name = "ZLL: Network Join Router Response"
    fields_desc = [
        # Inter-PAN transaction identifier (4 octets)
        XLEIntField("inter_pan_transaction_id", 0x66666666),
        # Status (1 octet)
        ByteEnumField("status", 0, {0: "success", 1: "failure",
            2: "reserved_status_2", 3: "reserved_status_3",
            4: "reserved_status_4", 5: "reserved_status_5",
            6: "reserved_status_6", 7: "reserved_status_7",
            8: "reserved_status_8", 9: "reserved_status_9",
            10: "reserved_status_10", 11: "reserved_status_11",
            12: "reserved_status_12", 13: "reserved_status_13",
            14: "reserved_status_14", 15: "reserved_status_15"}),
    ]

class ZLLNetworkUpdateRequest(Packet):
    name = "ZLL: Network Update Request"
    fields_desc = [
        # Inter-PAN transaction identifier (4 octets)
        XLEIntField("inter_pan_transaction_id", 0x66666666),
        # Extended PAN identifier (8 octets)
        dot15d4AddressField("pan_id_ext", 0, adjust=lambda pkt,x: 8),
        # Network update identifier (1 octet)
        ByteField("network_update_id", 0x00),
        # Logical Channel (1 octet)
        ByteField("channel", 11),
        # PAN identifier (2 octets)
        XLEShortField("pan_id", 0x0000),
        # Network address (2 octets)
        XLEShortField("network_address", 0xffff),
    ]
### ZigBee Cluster Library ###

def util_zcl_attribute_value_len(pkt):
    # Calculate the length of the attribute value field
    if ( pkt.attribute_data_type == 0x00 ): # no data
        return 0
    elif ( pkt.attribute_data_type == 0x08 ): # 8-bit data
        return 1
    elif ( pkt.attribute_data_type == 0x09 ): # 16-bit data
        return 2
    elif ( pkt.attribute_data_type == 0x0a ): # 24-bit data
        return 3
    elif ( pkt.attribute_data_type == 0x0b ): # 32-bit data
        return 4
    elif ( pkt.attribute_data_type == 0x0c ): # 40-bit data
        return 5
    elif ( pkt.attribute_data_type == 0x0d ): # 48-bit data
        return 6
    elif ( pkt.attribute_data_type == 0x0e ): # 56-bit data
        return 7
    elif ( pkt.attribute_data_type == 0x0f ): # 64-bit data
        return 8
    elif ( pkt.attribute_data_type == 0x10 ): # boolean
        return 1
    elif ( pkt.attribute_data_type == 0x18 ): # 8-bit bitmap
        return 1
    elif ( pkt.attribute_data_type == 0x19 ): # 16-bit bitmap
        return 2
    elif ( pkt.attribute_data_type == 0x1a ): # 24-bit bitmap
        return 3
    elif ( pkt.attribute_data_type == 0x1b ): # 32-bit bitmap
        return 4
    elif ( pkt.attribute_data_type == 0x1c ): # 40-bit bitmap
        return 5
    elif ( pkt.attribute_data_type == 0x1d ): # 48-bit bitmap
        return 6
    elif ( pkt.attribute_data_type == 0x1e ): # 46-bit bitmap
        return 7
    elif ( pkt.attribute_data_type == 0x1f ): # 64-bit bitmap
        return 8
    elif ( pkt.attribute_data_type == 0x20 ): # Unsigned 8-bit integer
        return 1
    elif ( pkt.attribute_data_type == 0x21 ): # Unsigned 16-bit integer
        return 2
    elif ( pkt.attribute_data_type == 0x22 ): # Unsigned 24-bit integer
        return 3
    elif ( pkt.attribute_data_type == 0x23 ): # Unsigned 32-bit integer
        return 4
    elif ( pkt.attribute_data_type == 0x24 ): # Unsigned 40-bit integer
        return 5
    elif ( pkt.attribute_data_type == 0x25 ): # Unsigned 48-bit integer
        return 6
    elif ( pkt.attribute_data_type == 0x26 ): # Unsigned 56-bit integer
        return 7
    elif ( pkt.attribute_data_type == 0x27 ): # Unsigned 64-bit integer
        return 8
    elif ( pkt.attribute_data_type == 0x28 ): # Signed 8-bit integer
        return 1
    elif ( pkt.attribute_data_type == 0x29 ): # Signed 16-bit integer
        return 2
    elif ( pkt.attribute_data_type == 0x2a ): # Signed 24-bit integer
        return 3
    elif ( pkt.attribute_data_type == 0x2b ): # Signed 32-bit integer
        return 4
    elif ( pkt.attribute_data_type == 0x2c ): # Signed 40-bit integer
        return 5
    elif ( pkt.attribute_data_type == 0x2d ): # Signed 48-bit integer
        return 6
    elif ( pkt.attribute_data_type == 0x2e ): # Signed 56-bit integer
        return 7
    elif ( pkt.attribute_data_type == 0x2f ): # Signed 64-bit integer
        return 8
    elif ( pkt.attribute_data_type == 0x30 ): # 8-bit enumeration
        return 1
    elif ( pkt.attribute_data_type == 0x31 ): # 16-bit enumeration
        return 2
    elif ( pkt.attribute_data_type == 0x38 ): # Semi-precision
        return 2
    elif ( pkt.attribute_data_type == 0x39 ): # Single precision
        return 4
    elif ( pkt.attribute_data_type == 0x3a ): # Double precision
        return 8
    elif ( pkt.attribute_data_type == 0x41 ): # Octet string
        return int(pkt.attribute_value[0]) # defined in first octet
    elif ( pkt.attribute_data_type == 0x42 ): # Character string
        return int(pkt.attribute_value[0]) # defined in first octet
    elif ( pkt.attribute_data_type == 0x43 ): # Long octet string
        return int(pkt.attribute_value[0:2]) # defined in first two octets
    elif ( pkt.attribute_data_type == 0x44 ): # Long character string
        return int(pkt.attribute_value[0:2]) # defined in first two octets
    # TODO implement Ordered sequence & collection
    elif ( pkt.attribute_data_type == 0xe0 ): # Time of day
        return 4
    elif ( pkt.attribute_data_type == 0xe1 ): # Date
        return 4
    elif ( pkt.attribute_data_type == 0xe2 ): # UTCTime
        return 4
    elif ( pkt.attribute_data_type == 0xe8 ): # Cluster ID
        return 2
    elif ( pkt.attribute_data_type == 0xe9 ): # Attribute ID
        return 2
    elif ( pkt.attribute_data_type == 0xea ): # BACnet OID
        return 4
    elif ( pkt.attribute_data_type == 0xf0 ): # IEEE address
        return 8
    elif ( pkt.attribute_data_type == 0xf1 ): # 128-bit security key
        return 16
    elif ( pkt.attribute_data_type == 0xff ): # Unknown
        return 0
    else:
        return 0


class ZCLReadAttributeStatusRecord(Packet):
    name = "ZCL Read Attribute Status Record"
    fields_desc = [
        # Attribute Identifier
        XLEShortField("attribute_identifier", 0),
        # Status
        ByteEnumField("status", 0, _zcl_enumerated_status_values),
        # Attribute data type (0/1 octet), only included if status == 0x00 (SUCCESS)
        ConditionalField(
            ByteEnumField("attribute_data_type", 0, _zcl_attribute_data_types),
            lambda pkt:pkt.status == 0x00
        ),
        # Attribute data (0/variable in size), only included if status == 0x00 (SUCCESS)
        ConditionalField(
            StrLenField("attribute_value", "", length_from=lambda pkt:util_zcl_attribute_value_len(pkt) ),
            lambda pkt:pkt.status == 0x00
        ),
    ]

class ZCLGeneralReadAttributes(Packet):
    name = "General Domain: Command Frame Payload: read_attributes"
    fields_desc = [
        FieldListField("attribute_identifiers", [], XLEShortField("", 0x0000) ),
    ]

class ZCLGeneralReadAttributesResponse(Packet):
    name = "General Domain: Command Frame Payload: read_attributes_response"
    fields_desc = [
        PacketListField("read_attribute_status_record", [], ZCLReadAttributeStatusRecord),
    ]

class ZCLMeteringGetProfile(Packet):
    name = "Metering Cluster: Get Profile Command (Server: Received)"
    fields_desc = [
        # Interval Channel (8-bit Enumeration): 1 octet
        ByteField("Interval_Channel", 0), # 0 == Consumption Delivered ; 1 == Consumption Received
        # End Time (UTCTime): 4 octets
        XLEIntField("End_Time", 0x00000000),
        # NumberOfPeriods (Unsigned 8-bit Integer): 1 octet
        ByteField("NumberOfPeriods", 1), # Represents the number of intervals being requested.
    ]

class ZCLPriceGetCurrentPrice(Packet):
    name = "Price Cluster: Get Current Price Command (Server: Received)"
    fields_desc = [
        BitField("reserved", 0, 7),
        BitField("Requestor_Rx_On_When_Idle", 0, 1),
    ]

class ZCLPriceGetScheduledPrices(Packet):
    name = "Price Cluster: Get Scheduled Prices Command (Server: Received)"
    fields_desc = [
        XLEIntField("start_time", 0x00000000), # UTCTime (4 octets)
        ByteField("number_of_events", 0), # Number of Events (1 octet)
    ]

class ZCLPricePublishPrice(Packet):
    name = "Price Cluster: Publish Price Command (Server: Generated)"
    fields_desc = [
        XLEIntField("provider_id", 0x00000000), # Unsigned 32-bit Integer (4 octets)
        # Rate Label is a UTF-8 encoded Octet String (0-12 octets). The first Octet indicates the length.
        StrLenField("rate_label", "", length_from=lambda pkt:int(pkt.rate_label[0]) ), # TODO verify
        XLEIntField("issuer_event_id", 0x00000000), # Unsigned 32-bit Integer (4 octets)
        XLEIntField("current_time", 0x00000000), # UTCTime (4 octets)
        ByteField("unit_of_measure", 0), # 8 bits enumeration (1 octet)
        XLEShortField("currency", 0x0000), # Unsigned 16-bit Integer (2 octets)
        ByteField("price_trailing_digit", 0), # 8-bit BitMap (1 octet)
        ByteField("number_of_price_tiers", 0), # 8-bit BitMap (1 octet)
        XLEIntField("start_time", 0x00000000), # UTCTime (4 octets)
        XLEShortField("duration_in_minutes", 0x0000), # Unsigned 16-bit Integer (2 octets)
        XLEIntField("price", 0x00000000), # Unsigned 32-bit Integer (4 octets)
        ByteField("price_ratio", 0), # Unsigned 8-bit Integer (1 octet)
        XLEIntField("generation_price", 0x00000000), # Unsigned 32-bit Integer (4 octets)
        ByteField("generation_price_ratio", 0), # Unsigned 8-bit Integer (1 octet)
        XLEIntField("alternate_cost_delivered", 0x00000000), # Unsigned 32-bit Integer (4 octets)
        ByteField("alternate_cost_unit", 0), # 8-bit enumeration (1 octet)
        ByteField("alternate_cost_trailing_digit", 0), # 8-bit BitMap (1 octet)
        ByteField("number_of_block_thresholds", 0), # 8-bit BitMap (1 octet)
        ByteField("price_control", 0), # 8-bit BitMap (1 octet)
    ]

class ZigbeeClusterLibrary(Packet):
    name = "Zigbee Cluster Library (ZCL) Frame"
    fields_desc = [
        # Frame control (8 bits)
        BitField("reserved", 0, 3),
        BitField("disable_default_response", 0, 1), # 0 default response command will be returned
        BitEnumField("direction", 0, 1, ['client2server', 'server2client']),
        BitField("manufacturer_specific", 0, 1), # 0 manufacturer code shall not be included in the ZCL frame
        # Frame Type
        # 0b00 command acts across the entire profile
        # 0b01 command is specific to a cluster
        # 0b10 - 0b11 reserved
        BitField("zcl_frametype", 0, 2),
        # Manufacturer code (0/16 bits) only present then manufacturer_specific field is set to 1
        ConditionalField(XLEShortField("manufacturer_code", 0x0),
            lambda pkt:pkt.getfieldval("manufacturer_specific") == 1
        ),
        ByteField("transaction_sequence", 0),
        # Command identifier (8 bits): the cluster command
        ByteEnumField("command_identifier", 0, _zcl_command_frames),
    ]

    def guess_payload_class(self, payload):
        if isinstance(self.underlayer, ZigbeeAppDataPayload):
            # General Cluster ID Range 0x0000 - 0x00FF
            if self.command_identifier == 0x00 and 0x0000 <= self.underlayer.cluster <= 0x00FF:
                return ZCLGeneralReadAttributes
            elif self.command_identifier == 0x01 and 0x0000 <= self.underlayer.cluster <= 0x00FF:
                return ZCLGeneralReadAttributesResponse
            elif self.command_identifier == 0x00 and self.direction == 0 and self.underlayer.cluster == "price":
                return ZCLPriceGetCurrentPrice
            elif self.command_identifier == 0x01 and self.direction == 0 and self.underlayer.cluster == "price":
                return ZCLPriceGetScheduledPrices
            elif self.command_identifier == 0x00 and self.direction == 1 and self.underlayer.cluster == "price":
                return ZCLPricePublishPrice
        else:
            return Packet.guess_payload_class(self, payload)

### Bindings ###
bind_layers( Dot15d4, Dot15d4Beacon, fcf_frametype=0)
bind_layers( Dot15d4, Dot15d4Data, fcf_frametype=1)
bind_layers( Dot15d4, Dot15d4Ack,  fcf_frametype=2)
bind_layers( Dot15d4, Dot15d4Cmd,  fcf_frametype=3)
bind_layers( Dot15d4FCS, Dot15d4Beacon, fcf_frametype=0)
bind_layers( Dot15d4FCS, Dot15d4Data, fcf_frametype=1)
bind_layers( Dot15d4FCS, Dot15d4Ack,  fcf_frametype=2)
bind_layers( Dot15d4FCS, Dot15d4Cmd,  fcf_frametype=3)
bind_layers( Dot15d4Data, ZigbeeNWK)
bind_layers( Dot15d4Beacon, ZigBeeBeacon )
# bind_layers( ZigbeeAppDataPayload, ZigbeeAppCommandPayload, frametype=1)
# ZLL (Touchlink):
bind_layers( ZigbeeAppDataPayloadStub, ZigbeeZLLCommissioningCluster,
        profile=0xc05e, cluster=0x1000)
bind_layers( ZigbeeZLLCommissioningCluster, ZLLScanRequest,
        command_identifier=0x00, direction=0)
bind_layers( ZigbeeZLLCommissioningCluster, ZLLScanResponse,
        command_identifier=0x01, direction=1)
bind_layers( ZigbeeZLLCommissioningCluster, ZLLDeviceInformationRequest,
        command_identifier=0x03, direction=0)
bind_layers( ZigbeeZLLCommissioningCluster, ZLLIdentifyRequest,
        command_identifier=0x06, direction=0)
bind_layers( ZigbeeZLLCommissioningCluster, ZLLResetToFactoryNewRequest,
        command_identifier=0x07, direction=0)
bind_layers( ZigbeeZLLCommissioningCluster, ZLLNetworkStartRequest,
        command_identifier=0x10, direction=0)
bind_layers( ZigbeeZLLCommissioningCluster, ZLLNetworkStartResponse,
        command_identifier=0x11, direction=1)
bind_layers( ZigbeeZLLCommissioningCluster, ZLLNetworkJoinRouterRequest,
        command_identifier=0x12, direction=0)
bind_layers( ZigbeeZLLCommissioningCluster, ZLLNetworkJoinRouterResponse,
        command_identifier=0x13, direction=1)
bind_layers( ZigbeeZLLCommissioningCluster, ZLLNetworkUpdateRequest,
        command_identifier=0x16, direction=0)

### DLT Types ###
conf.l2types.register(195, Dot15d4FCS)
conf.l2types.register(230, Dot15d4)

