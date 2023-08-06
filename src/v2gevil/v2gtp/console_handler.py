"""
Console handler for V2GTP

This module contains methods for handling printing to console.
This is not used for now, but it will be used in future -maybe-.
Just thinking about it, maybe it will be better to use it for printing
to console, instead of using print in v2gtp.py.
"""
from ..v2gtp import v2gtp


def console_handler():
    """ """
    pass


def console_decode_handler(file: str, packet_num: int):
    """ """
    # TODO: Add some try/except block, if it fails to decode
    #       then print some error message
    # also return from decode_v2gtp_pkt_from_file some decoded message
    # and print it here
    v2gtp.decode_v2gtp_pkt_from_file(file=file, packet_num=packet_num)


def console_extract_handler():
    """ """
    pass
