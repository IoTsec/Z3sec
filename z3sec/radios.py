#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Generic interface for communicating with radio devices.

This module provides generic interfaces for different radio devices and pseudo
radios that provide utility functionality. Currently, Gnuradio and KillerBee
radio devices are supported. Furthermore, is possible to combine different radios
devices for sending and receiving packets or to use Wireshark to display all
packets being sent or received in real time.
"""

import errno
import os
import socket
import subprocess
import sys
import time

import killerbee

from scapy.all import *
from scapy.layers.dot15d4 import *

def _disable_print():
    sys.stdout = open(os.devnull, 'w')

def _enable_print():
    sys.stdout = sys.__stdout__

class Radio():
    """Abstract class for radio interfaces. This class should not be
    instantiated.
    """

    def __init__(self):
        pass
    def set_channel(self, channel):
        """Set the Zigbee channel on which the radio device should send or
        sniff.

        Parameters
        ----------
        channel : int
            The channel needs to be in the range of 11 - 25.
        """
        pass
    def recv(self, timeout=None):
        """Sniff a scapy packet.

        Returns
        -------
        scapy_pkt
            Sniffed packet or None if timeout has elapsed and no packet was
            received.
        """
        pass
    def send(self, pkt):
        """Send a single scapy packet."""
        pass
    def sniffer_on(self):
        """Enable sniffing of packets."""
        pass
    def sniffer_off(self):
        """Disable sniffing of packets."""
        pass
    def close(self):
        """Shut down radio."""
        pass

class GnuRadio(Radio):
    """Use a Gnuradio radio device.

    Connect to a running GNURadio instance or starts a new one. With this
    interface it is possible to utilize a software defined radio, like the
    ETTUS B200, for sending and receiving packages.
    """
    def __init__(self):
        load_module('gnuradio')
        switch_radio_protocol('z3sec_zigbee')

        # wait until radio is ready or timeout
        wait_max = 15
        i = 0
        while i < wait_max:
	    i += 1
            try:
                _disable_print()
                gnuradio_set_vars(Channel=11)
                time.sleep(3)
                gnuradio_set_vars(Channel=11)
                _enable_print()
            except socket.error as e:
                _enable_print()
                if e.errno is errno.ECONNREFUSED:
                    if i is 1:
		        print "Waiting for SDR to start up",
                        sys.stdout.flush()
                    else:
                        print ".",
                        sys.stdout.flush()
                    time.sleep(1)
                    continue
                if e.errno is errno.ECONNRESET:
                    print("\nSDR not connected. Exit.")
                    sys.exit()
                else:
                    raise e
            time.sleep(1)
            break
        if i == wait_max:
            print("\nCould not set up SDR within {} seconds. Is radio connected?".format(wait_max))
            sys.exit()

        self.recently_sent_pkt = None
    def set_channel(self, channel):
        """Set the Zigbee channel on which the radio device should send or
        sniff.

        Parameters
        ----------
        channel : int
            The channel needs to be in the range of 11 - 26.
        """
        gnuradio_set_vars(Channel=channel)
    def recv(self, timeout=0.2):
        """Sniff a scapy packet.

        Returns
        -------
        scapy_pkt
            Sniffed packet or None if timeout has elapsed and no packet was
            received.
        """
        recv_list = sniffradio(count=1, timeout=timeout)
        recv_time = time.time()
        if len(recv_list) == 0:
            return None, None
        # check for valid CRC?
        # remove Gnuradio header
        pkt = recv_list[0][GnuradioPacket].payload
        pkt = Dot15d4FCS(str(pkt))  # hack, because has_layer() did not work otherwise
        if self.recently_sent_pkt == str(pkt):
            return None, None
        info = dict()
        info['rssi'] = 0
        info['time'] = recv_time
        return pkt, info
    def send(self, pkt):
        """Send a single scapy packet."""
        self.recently_sent_pkt = str(pkt)
        _disable_print()
        send(pkt)
        # Maybe it is necessary to wait a short time in order to suppress the
        # "Sent 1 packets." message.
        _enable_print()
    def sniffer_on(self):
        """Enable sniffing of packets.

        Notes
        -----
        Not implemented. Sniffer is always on.
        """
        pass
    def sniffer_off(self):
        """Disable sniffing of packets.

        Notes
        -----
        Not implemented.
        """
        pass
    def close(self):
        #self.gnuradio_socket.close()
        pass

# Read packages from a pcap file or write it to a pcap. Intended for testing.
# Not implemented. TODO: Implement.
# class PcapPseudoRadio(Radio):
    # def __init__(pcap_in=None, pcap_out=None):
        # if pcap_in is not None:
            # self.pcap_in = scapy_extensions.kbrdpcap(pcap_in)
    # def set_channel(self, channel):
        # pass
    # def recv(self, timeout=0):
        # if pcap_in is not None:
            # return
    # def send(self, pkt):
        # if pcap_out is not None:
            # pcap_out.
        # pass
    # def sniffer_on(self):
        # pass
    # def sniffer_off(self):
        # pass
    # def close(self):
        # if pcap_in is not None:
            # pcap_in.close()
        # if pcap_out is not None:
            # pcap_out.close()


class Wireshark(Radio):
    """
    Create a Wireshark window and display send and received packets.

    This Radio can be used like a regular (physical) radio device. It passes
    all invocations to its containing radio device.  All packets that traverse
    this radio are intercepted and displayed in a new Wireshark window.  All
    network traffic will be displayed and can be saved for later examination.
    This can be helpful for debugging purposes.

    Parameters:
    -----------
    radio : Radio
        The (physical) radio device that is used for sending and receiving
        packets.
    """
    def __init__(self, radio):
        self.radio = radio

        # start wireshark
        spargs = dict(
            args=['wireshark', '-k', '-i', '-'],  # Read packets from stdin immediately
            stdin=subprocess.PIPE,
            stderr=open(os.devnull, 'w'),
        )
        if os.name == 'posix':
            spargs['preexec_fn'] = os.setpgrp
        elif os.name == 'nt':
            spargs['creationflags'] = subprocess.CREATE_NEW_PROCESS_GROUP

        self.wireshark_proc = subprocess.Popen(**spargs)
        self.pd = killerbee.PcapDumper(killerbee.DLT_IEEE802_15_4, self.wireshark_proc.stdin,)
    def set_channel(self, channel):
        """Set the Zigbee channel on which the radio device should send or
        sniff.

        Parameters:
        -----------
        channel : int
            The channel needs to be in the range of 11 - 25.
        """
        self.radio.set_channel(channel)
    def recv(self, timeout=None):
        """Sniff a scapy packet.

        Returns
        -------
        scapy_pkt
            Sniffed packet or None if timeout has elapsed and no packet was
            received.
        """
        if timeout is None:
            pkt, info = self.radio.recv()
        else:
            pkt, info = self.radio.recv(timeout)
        if pkt is not None:
            self.pd.pcap_dump(str(pkt))
        return pkt, info
    def send(self, pkt):
        """Send a single scapy packet."""
        self.pd.pcap_dump(str(pkt))
        self.radio.send(pkt)
    def sniffer_on(self):
        """Enable sniffing of packets."""
        self.radio.sniffer_on()
    def sniffer_off(self):
        """Disable sniffing of packets."""
        self.radio.sniffer_off()
    def close(self):
        self.radio.close()
        self.pd.close()

class KillerbeeRadio(Radio):
    """
    Use a KillerBee radio device.

    Use a radio that is supportet by KillerBee framework for receiving and
    sending packets.

    Parameters
    ----------
    devstring : str
        The path to a KillerBee device (e.g. "/dev/ttyUSB0").
    """
    def __init__(self, devstring):
        self.kb = killerbee.KillerBee(device=devstring)
        self.sniff = False
    def set_channel(self, channel):
        """Set the Zigbee channel on which the radio device should send or
        sniff.

        Parameters
        ----------
        channel : int
            The channel needs to be in the range of 11 - 25.
        """
        self.kb.set_channel(channel)
    def recv(self, timeout=None):
        """Return a single scapy packet or None if no packet was sniffed until
        the timeout elapsed.
        """
        if timeout is None:
            recv = self.kb.pnext()
        else:
            recv = self.kb.pnext(timeout)
        recv_time = time.time()
        if recv is None or not recv['validcrc']:
            return None, None
        pkt = Dot15d4FCS(recv['bytes'])
        info = dict()
        info['rssi'] = recv['rssi']
        info['time'] = recv_time
        return (pkt, info)
    def send(self, pkt):
        """Send a single scapy packet."""
        if self.sniff is True:
            self.sniffer_off()
            self.kb.inject(str(pkt)[:-2])  # cut off CRC, will be added in Killerbee
            self.sniffer_on()
        else:
            self.kb.inject(str(pkt)[:-2])  # cut off CRC, will be added in Killerbee
    def sniffer_on(self):
        """Enable sniffing of packets."""
        self.sniff = True
        self.kb.sniffer_on()
    def sniffer_off(self):
        """Disable sniffing of packets."""
        self.sniff = False
        self.kb.sniffer_off()
    def close(self):
        """Shut down radio.

        Notes
        -----
        If you do not close a KillerBee radio it may hang itself. Then it has
        to be physically disconnected from the computer in order to work again.
        """
        self.kb.close()

class DualRadio(Radio):
    """Use different Radios for sending and receiving packets.

    This Radio can be used like it is a singe physical radio. All packets being
    passed to it are transmitted by one radio, while another radio is
    simultaneously used for sniffing on the same channel.
    This can be helpful if a single radio needs too long for the transition
    from sending state to receiving state.

    Parameters:
    -----------
    radio_send : Radio
        Radio that is exclusively used for sending packets.
    radio_recv : Radio
        Radio that is exclusively used for receiving packets.
    """
    def __init__(self, radio_send, radio_recv):
        self.radio_send = radio_send
        self.radio_send.sniffer_off()
        self.radio_recv = radio_recv
        self.recently_sent_pkt = None
    def set_channel(self, channel):
        """Set the Zigbee channel on which both radio devices should send or
        sniff.

        Parameters:
        -----------
        channel : int
            The channel needs to be in the range of 11 - 25.
        """
        self.radio_send.set_channel(channel)
        self.radio_recv.set_channel(channel)
    def recv(self, timeout=None):
        """Sniff a scapy packet.

        Notes
        -----
        If the exact same packet is sniffed that was last send, it is filtered
        out. In dual radio setups it is quite common that the radio_recv is
        receiving all packets being send by the radio_send.

        Returns
        -------
        scapy_pkt
            Sniffed packet or None if timeout has elapsed and no packet was
            received.
        """
        if timeout is None:
            pkt = self.radio_recv.recv()
        else:
            pkt = self.radio_recv.recv(timeout)
        # Filter packets that were transmitted by ourself (and received again
        # by (one of) our own radio(s).
        if self.recently_sent_pkt != str(pkt):
            return pkt
        else:
            return self.radio_recv.recv(timeout)
    def send(self, pkt):
        """Send a single scapy packet."""
        self.recently_sent_pkt = str(pkt)
        self.radio_send.send(pkt)
    def sniffer_on(self):
        """Enable sniffing of packets."""
        self.radio_recv.sniffer_on()
    def sniffer_off(self):
        """Disable sniffing of packets."""
        self.radio_recv.sniffer_off()
    def close(self):
        """Close both the radio_send and the radio_recv radio."""
        self.radio_recv.close()
        self.radio_send.close()
