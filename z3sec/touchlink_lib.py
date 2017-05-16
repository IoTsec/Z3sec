#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Create preconfigured touchlink scapy packets for a touchlink transaction as a
initiator.
"""

from random import randrange as r

from scapy.all import *
from scapy.layers.dot15d4 import *

class Transaction():
    """Generate touchlink command frames.

    This class is helpful for performing a touchlink transaction to an other
    device. Addresses and sequence numbers of the initiator (source) are stored
    and inserted into every touchlink command frame during creation. Sequence
    numbers are tracked and increased increased accordingly. All fields of the
    command frames being created can be altered before sending. However, the
    default values should work fine.

    Parameters
    ----------
    seqnum : int, optional
        Initial sequence number.
    src_addr_ext : int, optional
        IEEE/extended/MAC address of the touchlink initiator.
    src_addr : int, optional
        Short address of the touchlink initiator.
    src_pan_id : int, optional
        PAN ID of the touchlink initiator.
    src_pan_id_ext : int, optional
        Extended/long PAN ID of the touchlink initiator.
    transaction_sequence : int, optional
        Initial transaction sequence number.
    inter_pan_transaction_id : int, optional
        Inter-PAN transaction ID.

    Notes
    -----
    All values will be initialized to random values if they are not passed
    during initialization.
    Touchlink command frames need to be sent in the exact order in which they
    are created, otherwise the sequence numbers are in the wrong order.
    """
    def __init__(self, seqnum=None, src_addr_ext=None, src_addr=None,
            src_pan_id=None, src_pan_id_ext=None, transaction_sequence=None,
            inter_pan_transaction_id=None):
        self.seqnum = seqnum if seqnum is not None else r(0,2**8)
        self.src_pan_id = src_pan_id if src_pan_id is not None else r(1,2**16-1)
        self.src_pan_id_ext = src_pan_id_ext if src_pan_id_ext is not None \
                else r(1,2**64-1)
        self.src_addr = src_addr if src_addr is not None else r(1,2**16-1)
        self.src_addr_ext = src_addr_ext if src_addr_ext is not None \
                else r(1,2**64-1)
        self.transaction_sequence = transaction_sequence \
                if transaction_sequence is not None else r(0,2**8)
        self.inter_pan_transaction_id = inter_pan_transaction_id \
                if inter_pan_transaction_id is not None else r(1,2**32)
        print("inter_pan_transaction_id:", self.inter_pan_transaction_id)

    def refresh_inter_pan_transaction_id(self):
        """Randomly generates a new inter-PAN transaction identifier and
        thereby begin a new touchlink transaction.
        """
        self.inter_pan_transaction_id = r(1, 2**32)

    def update_sqn(self):
        """Increment sequence numbers.

        This function is automatically called when a new touchlink command
        frame is created. It it can be manually invoced in order to skip
        sequence numbers.
        """
        self.seqnum = (self.seqnum + 1) % 2**8
        self.transaction_sequence = (self.transaction_sequence + 1) % 2**8

    def create_scan_request(self):
        """Create a touchlink scan request command frame.

        Returns
        -------
        scapy_pkt
        """

        # create IEEE 802.15.4 layer
        mac = Dot15d4FCS() / Dot15d4Data()
        mac.fcf_security = 0
        mac.fcf_ackreq = 0
        mac.fcf_pending = 0
        mac.fcf_panidcompress = 0
        mac.fcf_srcaddrmode = 3  # long
        mac.fcf_destaddrmode = 2  # short
        mac.dest_panid = 0xffff
        mac.seqnum = self.seqnum
        if self.src_pan_id is not None:
            mac.src_panid = self.src_pan_id
        if self.src_addr_ext is not None:
            mac.src_addr = self.src_addr_ext

        # create NWK layer
        nwk = ZigbeeNWKStub()

        # create AppDataPayload layer
        app = ZigbeeAppDataPayloadStub()
        app.delivery_mode = 2  # broadcast

        # create Light Link Commissioning Cluster frame
        com = ZigbeeZLLCommissioningCluster()
        if self.transaction_sequence is not None:
            com.transaction_sequence = self.transaction_sequence

        # create Scan Request command frame
        cmd = ZLLScanRequest()
        if self.inter_pan_transaction_id is not None:
            cmd.inter_pan_transaction_id = self.inter_pan_transaction_id
        # Zigbee information
        cmd.rx_on_when_idle = 1
        cmd.logical_type = 1  # router
        # ZLL information
        cmd.link_initiator = 1
        cmd.address_assignment = 1
        cmd.factory_new = 0

        self.update_sqn()

        return mac / nwk / app / com / cmd

    def create_identify_request(self, dest_addr, duration=0xffff):
        """
        Create a touchlink identify command frame.

        Parameters
        ----------
        dest_addr : int
            The IEEE address of the device to which the command shall be sent.
            This address can be obtained form a scan response frame.
        duration : int, optional
            The duration of the identify operation. A value of 0 aborts a
            previously initiated identify operation, 0xffff lets the target
            identify for a default time. All other values in the range of 0 to
            0xfffe state a identify duration in seconds.

        Returns
        -------
        scapy_pkt
        """
        # create IEEE 802.15.4 layer
        mac = Dot15d4FCS() / Dot15d4Data()
        mac.fcf_security = 0
        mac.fcf_ackreq = 1
        mac.fcf_pending = 0
        mac.fcf_panidcompress = 0
        mac.fcf_srcaddrmode = 3  # long
        mac.fcf_destaddrmode = 3  # long
        mac.dest_panid = 0xffff
        mac.dest_addr = dest_addr
        mac.seqnum = self.seqnum
        mac.src_panid = self.src_pan_id
        mac.src_addr = self.src_addr_ext

        # create NWK layer
        nwk = ZigbeeNWKStub()

        # create AppDataPayload layer
        app = ZigbeeAppDataPayloadStub()
        app.delivery_mode = 0  # unicast

        # create Light Link Commissioning Cluster frame
        com = ZigbeeZLLCommissioningCluster()
        com.transaction_sequence = self.transaction_sequence

        # create Identify Request command frame
        cmd = ZLLIdentifyRequest()
        cmd.inter_pan_transaction_id = self.inter_pan_transaction_id
        cmd.identify_duration = duration

        self.update_sqn()

        return mac / nwk / app / com / cmd

    def create_reset_to_factory_new_request(self, dest_addr):
        """
        Create a touchlink reset command frame.

        Parameters
        ----------
        dest_addr : int
            The IEEE address of the device to which the command shall be sent.
            This address can be obtained form a scan response frame.

        Returns
        -------
        scapy_pkt
        """
        # create IEEE 802.15.4 layer
        mac = Dot15d4FCS() / Dot15d4Data()
        mac.fcf_security = 0
        mac.fcf_ackreq = 1
        mac.fcf_pending = 0
        mac.fcf_panidcompress = 0
        mac.fcf_srcaddrmode = 3  # long
        mac.fcf_destaddrmode = 3  # long
        mac.dest_panid = 0xffff
        mac.dest_addr = dest_addr
        mac.seqnum = self.seqnum
        mac.src_panid = self.src_pan_id
        mac.src_addr = self.src_addr_ext

        # create NWK layer
        nwk = ZigbeeNWKStub()

        # create AppDataPayload layer
        app = ZigbeeAppDataPayloadStub()
        app.delivery_mode = 0  # unicast

        # create Light Link Commissioning Cluster frame
        com = ZigbeeZLLCommissioningCluster()
        com.transaction_sequence = self.transaction_sequence

        # create Reset to Factory New Request command frame
        cmd = ZLLResetToFactoryNewRequest()
        cmd.inter_pan_transaction_id = self.inter_pan_transaction_id

        self.update_sqn()

        return mac / nwk / app / com / cmd


    def create_network_update_request(self, dest_addr, network_update_id,
            channel, pan_id, pan_id_ext, network_address):
        """
        Create a touchlink network update command frame.

        According to the ZLL specification it is only possible to alter the
        channel of the target device along with its network update ID. The
        other values might be used in a plausibility check by the target
        device. It is advised to use the current values of the target.

        Parameters
        ----------
        dest_addr : int
            The IEEE address of the device to which the command shall be sent.
            This address can be obtained form a scan response frame.
        network_update_id : int
            The new network update identifier of the target device. This value
            needs to be bigger than the the current network update identifier
            of the targed which can be obtained from the touchlink scan
            response of the target.
        channel : int
            The channel to which the targed device switches after receiving and
            accepting this command.
        pan_id : int
            The short PAN identifier of the target. This value does not have an
            effect on the target.
        pan_id_ext : int
            The long IEEE PAN identifier of the target. This value does not
            have an effect on the target.
        network_address : int
            The short address of the target. This value does not have an effect
            on the target.

        Returns
        -------
        scapy_pkt
        """

        # create IEEE 802.15.4 layer
        mac = Dot15d4FCS() / Dot15d4Data()
        mac.fcf_security = 0
        mac.fcf_ackreq = 1
        mac.fcf_pending = 0
        mac.fcf_panidcompress = 0
        mac.fcf_srcaddrmode = 3  # long
        mac.fcf_destaddrmode = 3  # long
        mac.dest_panid = 0xffff
        mac.dest_addr = dest_addr
        mac.seqnum = self.seqnum
        mac.src_panid = self.src_pan_id
        mac.src_addr = self.src_addr_ext

        # create NWK layer
        nwk = ZigbeeNWKStub()

        # create AppDataPayload layer
        app = ZigbeeAppDataPayloadStub()
        app.delivery_mode = 0  # unicast

        # create Light Link Commissioning Cluster frame
        com = ZigbeeZLLCommissioningCluster()
        com.transaction_sequence = self.transaction_sequence

        # create Network Update Request command frame
        cmd = ZLLNetworkUpdateRequest()
        cmd.inter_pan_transaction_id = self.inter_pan_transaction_id
        cmd.pan_id_ext = pan_id_ext
        cmd.network_update_id = network_update_id
        cmd.channel = channel
        cmd.pan_id = pan_id
        cmd.network_address = network_address

        self.update_sqn()

        return mac / nwk / app / com / cmd

    def create_network_start_request(self, dest_addr, channel,
            encrypted_network_key, network_address):
        """Create a touchlink network start command frame.

        Request the target device to leave its current network and start a new
        one.

        Parameters
        ----------
        dest_addr : int
            The IEEE address of the device to which the command shall be sent.
            This address can be obtained form a scan response frame.
        channel : int
            The channel to which the targed device switches after receiving and
            accepting this command.
        cnrypted_network_key : byte string (16 bytes)
            The encrypted network key of the new network. Pass random bytes if
            you are not interested in controlling the target device afterwards,
            but want to dissconnect the target from its current network.
        network_address : int
            The short network address the target should use after joining the
            new network. However, the target might ignore this value and assign
            a different address to itself.

        Returns
        -------
        scapy_pkt
        """
        # create IEEE 802.15.4 layer
        mac = Dot15d4FCS() / Dot15d4Data()
        mac.fcf_security = 0
        mac.fcf_ackreq = 1
        mac.fcf_pending = 0
        mac.fcf_panidcompress = 0
        mac.fcf_srcaddrmode = 3  # long
        mac.fcf_destaddrmode = 3  # long
        mac.dest_panid = 0xffff
        mac.dest_addr = dest_addr
        mac.seqnum = self.seqnum
        mac.src_panid = self.src_pan_id
        mac.src_addr = self.src_addr_ext

        # create NWK layer
        nwk = ZigbeeNWKStub()

        # create AppDataPayload layer
        app = ZigbeeAppDataPayloadStub()
        app.delivery_mode = 0  # unicast

        # create Light Link Commissioning Cluster frame
        com = ZigbeeZLLCommissioningCluster()
        com.transaction_sequence = self.transaction_sequence

        # create Network Start Request command frame
        cmd = ZLLNetworkStartRequest()
        cmd.inter_pan_transaction_id = self.inter_pan_transaction_id
        cmd.encrypted_network_key = encrypted_network_key
        cmd.channel = channel
        cmd.network_address = network_address
        cmd.initiator_ieee_address = self.src_addr_ext
        cmd.intitiator_network_address = network_address

        self.update_sqn()

        return mac / nwk / app / com / cmd

    def create_join_router_request(self, dest_addr, channel,
            encrypted_network_key, network_address):
        """Create a touchlink join router command frame.

        Request the target device to leave its current network and join an
        other network.

        Parameters
        ----------
        dest_addr : int
            The IEEE address of the device to which the command shall be sent.
            This address can be obtained form a scan response frame.
        channel : int
            The channel to which the targed device switches after receiving and
            accepting this command.
        cnrypted_network_key : byte string (16 bytes)
            The encrypted network key of the new network. Pass random bytes if
            you are not interested in controlling the target device afterwards,
            but want to dissconnect the target from its current network.
        network_address : int
            The short network address the target should use after joining the
            new network. However, the target might ignore this value and assign
            a different address to itself.

        Returns
        -------
        scapy_pkt
        """
        # create IEEE 802.15.4 layer
        mac = Dot15d4FCS() / Dot15d4Data()
        mac.fcf_security = 0
        mac.fcf_ackreq = 1
        mac.fcf_pending = 0
        mac.fcf_panidcompress = 0
        mac.fcf_srcaddrmode = 3  # long
        mac.fcf_destaddrmode = 3  # long
        mac.dest_panid = 0xffff
        mac.dest_addr = dest_addr
        mac.seqnum = self.seqnum
        mac.src_panid = self.src_pan_id
        mac.src_addr = self.src_addr_ext

        # create NWK layer
        nwk = ZigbeeNWKStub()

        # create AppDataPayload layer
        app = ZigbeeAppDataPayloadStub()
        app.delivery_mode = 0  # unicast

        # create Light Link Commissioning Cluster frame
        com = ZigbeeZLLCommissioningCluster()
        com.transaction_sequence = self.transaction_sequence

        # create Network Join Request command frame
        cmd = ZLLNetworkJoinRouterRequest()
        cmd.inter_pan_transaction_id = self.inter_pan_transaction_id
        cmd.pan_id_ext = self.src_pan_id_ext
        cmd.key_index = 4
        cmd.encrypted_network_key = encrypted_network_key
        cmd.network_update_id = 1
        cmd.channel = channel
        cmd.pan_id = self.src_pan_id
        cmd.network_address = network_address
        cmd.group_id_begin = 0
        cmd.group_id_end = 0
        cmd.free_network_address_range_begin = 0
        cmd.free_network_address_range_end = 0
        cmd.free_group_address_range_begin = 0
        cmd.free_group_address_range_end = 0

        self.update_sqn()

        return mac / nwk / app / com / cmd
