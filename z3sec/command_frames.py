"""A small library of Zigbee Light Link (ZLL) command frames / packets.

These commands can be used together with the inject module to control ZLL
devices. (The network key must be known).
"""

from scapy.all import *
from scapy.layers.dot15d4 import *
# from z3sec.dot15d4_zigbee_zll import *

def create_base():
    """Get a packet containing only MAC, NWK, and the Zigbee Security header.

    Returns
    -------
    scapy_pkt
    """
    mac = Dot15d4FCS() / Dot15d4Data()
    mac.fcf_panidcompress = 1
    mac.fcf_ackreq = 1
    mac.fcf_srcaddrmode = "Short"

    nwk = ZigbeeNWK()
    nwk.discover_route = 1
    nwk.flags = "security"
    nwk.radius = 30

    sec = ZigbeeSecurityHeader()
    sec.key_type = 1

    return mac / nwk / sec

def create_on():
    """Get a ZLL command frame for turning a light on.

    Returns
    -------
    scapy_pkt
    """
    base = create_base()

    app = ZigbeeAppDataPayload()
    app.frame_control = 0
    app.dst_endpoint = 255
    app.cluster = "on_off"
    app.profile = "HA_Home_Automation"
    app.src_endpoint = 64

    zcl = ZigbeeClusterLibrary()
    zcl.disable_default_response = 1
    zcl.zcl_frametype = 1
    zcl.command_identifier = 0x01  # on

    return base / app / zcl

def create_off():
    """Get a ZLL command frame for turning a light off.

    Returns
    -------
    scapy_pkt
    """
    base = create_base()

    app = ZigbeeAppDataPayload()
    app.frame_control = 0
    app.dst_endpoint = 255
    app.cluster = "on_off"
    app.profile = "HA_Home_Automation"
    app.src_endpoint = 64

    zcl = ZigbeeClusterLibrary()
    zcl.disable_default_response = 1
    zcl.zcl_frametype = 1
    zcl.command_identifier = 0x00  # off

    return base / app / zcl

def create_color(color, transition_time=10):
    """Get a ZLL command frame for controlling the color of a light.

    Attributes
    ----------
    color : str
        The color as a string: "red", "blue", "green", "white".
    transition_time : int
        The transition time for switching the color in milliseconds.

    Returns
    -------
    scapy_pkt
    """
    if color == "red":
        color_x = 1
        color_y = 0.25
    elif color == "blue":
        color_x = 0
        color_y = 0
    elif color == "green":
        color_x = 0.2
        color_y = 1
    elif color == "white":
        color_x = 0.35
        color_y = 0.35
    else:
        print("No known color. Assuming 'white'")
        color_x = 0.35
        color_y = 0.35

    # norming and pack color
    color_x = struct.pack("H", color_x * 0xffff)
    color_y = struct.pack("H", color_y * 0xffff)

    # pack transistion time
    transition_time = struct.pack("H", transition_time)

    base = create_base()

    app = ZigbeeAppDataPayload()
    app.frame_control = 0
    app.dst_endpoint = 255
    app.cluster = 0x0300  # Color Control
    app.profile = "HA_Home_Automation"
    app.src_endpoint = 64

    zcl = ZigbeeClusterLibrary()
    zcl.disable_default_response = 1
    zcl.zcl_frametype = 1
    zcl.command_identifier = 0x07  # move to color

    payload = color_x + color_y + transition_time

    return base / app / zcl / payload

def create_identify(duration=3):
    """Get a ZLL command frame for identifying a device.

    On receipt of this command, the device identifies itself by blinking.

    Attributes
    ----------
    duration : int
        Identify duration in seconds.

    Returns
    -------
    scapy_pkt
    """

    duration = struct.pack("H", duration)

    base = create_base()

    app = ZigbeeAppDataPayload()
    app.frame_control = 0
    app.dst_endpoint = 255
    app.cluster = 0x0003  # identify cluster
    app.profile = "HA_Home_Automation"
    app.src_endpoint = 64

    zcl = ZigbeeClusterLibrary()
    zcl.disable_default_response = 1
    zcl.zcl_frametype = 1
    zcl.command_identifier = 0x00  # identify

    payload = duration

    return base / app / zcl / payload


# def create_off_broadcast():
    # mac = Dot15d4() / Dot15d4Data()
    # mac.fcf_panidcompress = 1
    # mac.fcf_ackreq = 0
    # mac.fcf_srcaddrmode = "Short"

    # nwk = ZigbeeNWK()
    # nwk.discover_route = 0
    # nwk.flags= "security"
    # nwk.radius = 30

    # sec = ZigbeeSecurityHeader()
    # sec.key_type = 1

    # return mac / nwk / sec

    # app = ZigbeeAppDataPayload()
    # app.frame_control = 0
    # app.dst_endpoint = 255
    # app.cluster = "on_off"
    # app.profile = "HA_Home_Automation"
    # app.src_endpoint = 64

    # zcl = ZigbeeClusterLibrary()
    # zcl.disable_default_response = 1
    # zcl.zcl_frametype = 1
    # zcl.command_identifier = 0x00  # off

    # return base / app / zcl

def create_lqi_req():
    base = create_base()

    app = ZigbeeAppDataPayload()
    app.delivery_mode = "unicast"
    app.frame_control = 0
    app.aps_frametype = "data"
    app.dst_endpoint = 0
    app.cluster = 0x0031
    app.profile = 0
    app.src_endpoint = 0

    zdp = ZDPLqiRequest()

    return base / app / zdp

def create_leave_req(ext_device_addr):
    # TODO: test in real network
    base = create_base()

    app = ZigbeeAppDataPayload()
    app.delivery_mode = "unicast"
    app.frame_control = 0
    app.aps_frametype = "data"
    app.dst_endpoint = 0
    app.cluster = 0x0034
    app.profile = 0
    app.src_endpoint = 0

    zdp = ZDPLeaveRequest()
    zdp.device_addr = ext_device_addr

    return base / app / zdp
