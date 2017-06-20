#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Functions to handle packets relevant for the touchlink key transport. Detect
keytransport packets. Extract network key. Decrypt and encrypt network key.
"""

import ConfigParser
from Crypto.Cipher import AES
import os
import sys
import hashlib

from scapy.all import *
from scapy.layers.dot15d4 import *

CONFIG_PATH = os.environ["HOME"] + "/.config/z3sec/touchlink_crypt.ini"

# Read config
config = ConfigParser.ConfigParser()
if os.path.exists(CONFIG_PATH):
    # Read master keys from config file
    config.read(CONFIG_PATH)
    ZLL_CERTIFICATION_KEY = config.get("master_keys", "zll_certification_key").decode("hex")
    ZLL_MASTER_KEY = config.get("master_keys", "zll_master_key").decode("hex")
    # Check if ZLL_MASTER_KEY is correct by coparing its hash
    md5 = hashlib.md5()
    md5.update(ZLL_MASTER_KEY)
    if md5.hexdigest() != '68eba85ac7514d786fce56731e24f9c8':
        print("Warning: ZLL_MASTER_KEY is not correctly set in  " + CONFIG_PATH + ". This key can be found on Twitter (MayaZigBee). Touchlink key transport encryption and decryption will not work correctly.")
        ZLL_MASTER_KEY = None
else:
    # Create default config file if it does not exist yet
    if not os.path.exists(os.path.dirname(CONFIG_PATH)):
        os.makedirs(os.path.dirname(CONFIG_PATH))
    config.add_section("master_keys")
    config.set("master_keys", "zll_certification_key", "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF")
    config.set("master_keys", "zll_master_key", "")  # Needs to be configured by user
    with open(CONFIG_PATH, 'wb') as configfile:
        config.write(configfile)

def is_keytransport(pkt):
    """Checks if pkt is a touchlink keytransport packet.

    Parameters
    ----------
    pkt : scapy_pkt

    Returns
    -------
    bool
        True if pkt is a touchlink key transport packet, False otherwise.
    """
    if pkt.haslayer(ZLLNetworkStartRequest) \
            or pkt.haslayer(ZLLNetworkJoinRouterRequest):
            # TODO: implement in scapy:
            # or pkt.haslayer(ZLLNetworkJoinEndDeviceRequest):
        print("> Touchlink key transport detected")
        return True
    return False

def is_scan_response(pkt):
    """Checks if pkt is a touchlink scan response packet.

    Inside the of a scan response is the scan response identifier located,
    which is necessary for network key decryption.

    Parameters
    ----------
    pkt : scapy_pkt

    Returns
    -------
    bool
        True if pkt is a touchlink scan response packet, False otherwise.
    """
    return pkt.haslayer(ZLLScanResponse)

def get_response_id(keytransport_pkt, scan_response_pkts):
    """Search for a given keytransport packet the corresponding response
    identifier from a number of scan requests.

    Parameters
    ----------
    keytransport_pkt : scapy_pkt
        Packet containing a key transport.
    scan_responses_pkts : list of scapy_pkt
        Sniffed scan response packets of the same transaction.

    Returns
    -------
    int
        The response identifier if it was found, None otherwise.
    """
    for r in scan_response_pkts:
        if r.inter_pan_transaction_id == keytransport_pkt.inter_pan_transaction_id \
                and r.dest_addr == keytransport_pkt.src_addr:
            return r.response_id
    return None

def extract_encrypted_network_key(pkt):
    """Slice out the encrypted network key field from a touchlink key transport
    packet.

    Parameters
    ----------
    pkt : scapy_pkt
        Touchlink key transport packet.

    Returns
    -------
    str
        Encrypted network key as binary string, or None if pkt was not a
        touchlink key transport packet.
    """
    if pkt.haslayer(ZLLNetworkStartRequest):
        return str(pkt[ZLLNetworkStartRequest])[13:29]
    elif pkt.haslayer(ZLLNetworkJoinRouterRequest):
        return str(pkt[ZLLNetworkJoinRouterRequest])[13:29]
    # TODO: implement ZLLNetworkJoinEndDeviceRequest in scapy
    # elif pkt.haslayer(ZLLNetworkJoinEndDeviceRequest):
        # return str(pkt[ZLLNetworkJoinEndDeviceRequest])[13:29]
    else:
        print("No encrypted network key could be extracted! "
              "Is ZLLNetworkJoinEndDeviceRequest implemented in scapy?")
        return None

def decrypt_network_key(encrypted_network_key, inter_pan_transaction_id,
        response_id, key=None):
    """Decrypt the network key using the transaction and response ids and a
    master key.

    Parameters
    ----------
    encrypted_network_key : byte string
        The sliced out encrypted network key field of a key transport packet.
    inter_pan_transaction_id : byte string or int or long
        Inter-PAN transaction identifier.
    response_id : byte string or int or long
        Response identifier as it can be found by get_response_id().
    key : byte string, optional
        Master key used for decryption. If no key is passed, the development
        key for touchlink is forged and used instead. (In consumer products,
        the developemnt key should not be used.)

    Returns
    -------
    byte string
        Decrypted network key.
    """
    # Convert int to str if necessary
    if type(inter_pan_transaction_id) is int:
        inter_pan_transaction_id = struct.pack(">I", inter_pan_transaction_id)
    if type(inter_pan_transaction_id) is long:
        inter_pan_transaction_id = struct.pack(">L", inter_pan_transaction_id)
    if type(response_id) is int:
        response_id = struct.pack(">I", response_id)
    if type(response_id) is long:
        response_id = struct.pack(">L", response_id)

    if key is None:  # assuming development key (see ZLL 8.7.4 Key index 0)
        print(">> Master key is None. Using development key for decryption")
        transport_key = "PhLi" + inter_pan_transaction_id + "CLSN" + response_id
    else:  # Master or Certification key (see ZLL 8.7.5.2.3)
        expanded_input = inter_pan_transaction_id * 2 + response_id * 2
        transport_key_crypto = AES.new(key, AES.MODE_ECB)
        transport_key = transport_key_crypto.encrypt(expanded_input)

    network_key_crypto = AES.new(transport_key, AES.MODE_ECB)
    return network_key_crypto.decrypt(encrypted_network_key)

def encrypt_network_key(network_key, inter_pan_transaction_id, response_id,
        key=None):
    """Encrypt a network key using the transaction and response ids and a
    master key.

    Parameters
    ----------
    network_key : byte string
        Network key for that shall be encrypted.
    inter_pan_transaction_id : byte string or int or long
        Inter-PAN transaction identifier.
    response_id : byte string or int or long
        Response identifier as it can be found by get_response_id().
    key : byte string, optional
        Master key used for encryption. If no key is passed, the development
        key for touchlink is forged and used instead. (In consumer products,
        the developemnt key should not be used.)

    Returns
    -------
    byte string
        Encrypted network key.
    """
    # Convert int to str if necessary
    if type(inter_pan_transaction_id) is int:
        inter_pan_transaction_id = struct.pack(">I", inter_pan_transaction_id)
    if type(inter_pan_transaction_id) is long:
        inter_pan_transaction_id = struct.pack(">L", inter_pan_transaction_id)
    if type(response_id) is int:
        response_id = struct.pack(">I", response_id)
    if type(response_id) is long:
        response_id = struct.pack(">L", response_id)

    if key is None:  # assuming development key (see ZLL 8.7.4 Key index 0)
        print(">> Master key is None. Using development key for encryption")
        transport_key = "PhLi" + inter_pan_transaction_id + "CLSN" + response_id
    else:  # Master or Certification key (see ZLL 8.7.5.2.3)
        expanded_input = inter_pan_transaction_id * 2 + response_id * 2
        transport_key_crypto = AES.new(key, AES.MODE_ECB)
        transport_key = transport_key_crypto.encrypt(expanded_input)

    network_key_crypto = AES.new(transport_key, AES.MODE_ECB)
    return network_key_crypto.encrypt(network_key)

def extract_network_key(pkt, response_id):
    """Extract and decrypt the network key from a key transport packet.

    Parameters
    ----------
    pkt : scapy_pkt
        Touchlink key transport packet.
    response_id : byste string or int or long
        Response identifier of the target device of touchlink commissioning.

    Returns
    -------
    byte string
        Decrypted network key.
    """
    global ZLL_MASTER_KEY
    global ZLL_CERTIFICATION_KEY

    # extract inter_pan_transaction_id
    inter_pan_transaction_id = pkt.inter_pan_transaction_id

    encrypted_network_key = extract_encrypted_network_key(pkt)
    # select right algorithm for network key decryption
    if pkt.key_index == 0:  # Development key
        print("> Decrypting network key using ZLL development key")
        network_key = decrypt_network_key(encrypted_network_key,
            inter_pan_transaction_id, response_id)
    elif pkt.key_index == 4:  # Master key
        print("> Decrypting network key using ZLL master key")
        network_key = decrypt_network_key(encrypted_network_key,
            inter_pan_transaction_id, response_id, key=ZLL_MASTER_KEY)
    elif pkt.key_index == 15:  # Certification key
        print("> Decrypting network key using ZLL certification key")
        network_key = decrypt_network_key(encrypted_network_key,
            inter_pan_transaction_id, response_id, key=ZLL_CERTIFICATION_KEY)
    else:
        print("Could not extract network key: No algorithm or key for "
              "key_index {}".format(pkt.key_index))
        return None
    print(">>> Extracted network key: {}"
          .format(network_key.encode('hex')))
    return network_key
