"""
V2GEvil - Tool for testing and evaluation of V2G communication.
Copyright (C) 2024 Pavel Khunt

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License for more details.
"""

"""
Console handler for V2GTP

This module contains methods for handling printing to console.
This is not used for now, but it will be used in future -maybe-.
Just thinking about it, maybe it will be better to use it for printing
to console, instead of using print in v2gtp.py.
"""

# THIS MODULE IS NOT USED YET
# PROBABLY IT WILL BE DELETED IN FUTURE

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
