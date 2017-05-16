#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Parser functions (tpyes) for argparse arguments.

Parse strings of addresses, channels, etc., check for validity and return as
approprieate datatypes.
"""
import argparse
import os

CHANNELS_PRIMARY = [11, 15, 20, 25]
CHANNELS_SECONDARY = [12, 13, 14, 16, 17, 18, 19, 21, 22, 23, 24, 26]
CHANNELS_ALL = [11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26]

def number(string, min, max):
    if string.startswith(("0x")):  # hex
        try:
            number = int(string, 16)
        except ValueError:
            msg = "Could not parse %r as hexadecimal number" % string
            raise argparse.ArgumentTypeError(msg)
        if min > number or max < number:
            msg = "%r out of range: %r - %r" % (number, hex(min), hex(max))
            raise argparse.ArgumentTypeError(msg)
        return number
    else:  # decimal
        try:
            number = int(string)
        except ValueError:
            msg = "Could not parse %r as decimal number" % string
            raise argparse.ArgumentTypeError(msg)
        if min > number or max < number:
            msg = "%r out of range: %r - %r" % (number, min, max)
            raise argparse.ArgumentTypeError(msg)
        return number

def duration(string):
    return number(string, 0, 2**16-1)

def channels(string):
    if string == "p" or string == "primary":
        return CHANNELS_PRIMARY
    if string == "s" or string == "secondary":
        return CHANNELS_SECONDARY
    if string == "a" or string == "all":
        return CHANNELS_ALL
    else:
        channels = []
        channels_str_list = string.split(",")
        for c_str in channels_str_list:
            channels.append(channel(c_str))
        return channels

def channel(string):
    try:
        channel = int(string)
        if channel not in CHANNELS_ALL:
            msg = "%r is not a valid ZLL channel (11 - 26)." % channel
            raise argparse.ArgumentTypeError(msg)
        return channel
    except ValueError:
        msg = "%r is not a valid ZLL channel (11 - 26)." % string
        raise argparse.ArgumentTypeError(msg)

def addr_short(string):
    return number(string, 0, 2**16-1)


def addr_long(string):
    if string.count(":") == 7 and len(string) == 23:
        string = string.replace(":", "")
        if string.startswith("0x"):
            return number(string, 0, 2**64-1)
        else:
            return number("0x" + string, 0, 2**64-1)
    if ":" in string:
        msg = "%r has not the right format" % string
        raise argparse.ArgumentTypeError(msg)
    return number(string, 0, 2**64-1)

def network_key(string):
    if len(string) == 2:
        string = string* 16
    if len(string) != 32:
        msg = "%r has not the right length (32 char)." % string
        raise argparse.ArgumentTypeError(msg)
    return string.decode('hex')

def kb_dev(string):
    if not string.startswith("/dev/ttyUSB"):
        msg = "%r does not start with '/dev/ttyUSB'. Use 'zbid' to find a valid device string." % string
        raise argparse.ArgumentTypeError(msg)
    if not os.path.exists(string):
        msg = "%r does not exist. Use 'zbid' to find a valid device string." % string
        raise argparse.ArgumentTypeError(msg)
    return string
