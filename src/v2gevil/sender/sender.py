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

"""This module is not used yet. It will be used for sending messages to EVCC/SECC

It will probably required lower layer implementation like data link layer.
"""

from ..v2gtp import v2gtp

# TODO: Probably there will be need for implementing also
# messages for data link layer, ISO 15118-3
# because first has to be initiated data link layer connection
# after that, EVCC shall initiate IP address assigment mechanism
# But for now I have to focus on the higher layers...
# Let me first implement V2GTP, then I will think about it...


def send_v2gtp_exi_msg():
    """Method for sending EXI message"""
    pass


def send_v2gtp_secc_msg():
    """Method for sending SECC message"""
    pass
    # Use send_v2gtp_secc_request_msg and send_v2gtp_secc_response_msg instead


def send_v2gtp_secc_request_msg():
    """Method for sending SECC Discovery Protocol Request message

    SDP client use this protocol to discover SECCs in the network.
    Send SECC discovery request message to server.
    """


def send_v2gtp_secc_response_msg():
    """Method for sending SECC Discovery Protocol Response message

    SDP server use this protocol to respond to SDP client's request.
    Send SECC discovery response message to client.
    """


def send_icmpv6():
    """Method for sending ICMPv6 message"""
    pass
