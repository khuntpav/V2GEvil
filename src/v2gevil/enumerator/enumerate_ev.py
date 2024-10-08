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

"""This module is used to enumerate all possible information about the EV"""

from ..station import station
from ..station.station_enums import EVSEDetails
from .enumerator import EVEnumerator, EVEnumMode


def enumerate_ev(
    interface: str = EVSEDetails.INTERFACE.value,
    accept_security: bool = True,
    enum_mode: EVEnumMode = EVEnumMode.ALL,
):
    """Enumerate EV.

    To end the station press CTRL+C, the enumeration will be printed after station
    is stopped, because enumerator is running in the background and collecting
    all possible information about the EV.

    Args:
        interface (str, optional): Interface to run station on. Defaults to "eth_station".
        accept_security (bool, optional): Station should follow security provided by EVCC. Defaults to True.
        enum_mode (str, optional): Mode of enumeration. Defaults to "all".
            all: Enumerate all possible information about EV
            supported_protocols: Enumerate supported protocols by EV
            tls_check: Check if TLS is required by EV
            tls_recognition: Check if TLS is required by EV and\
                recognize if in this environment is TLS needed.\
                Based on the transmitted messages and information in them.
    """

    ev_enumerator = EVEnumerator()

    # Problem with user input will be a string in modules_tools.py
    # and that's why there is a conversion to enum
    # So here i can use enum directly instead of enum.value
    # Choose which enumeration mode to use
    tls_flag = False
    match enum_mode:
        case None:
            print("EVSE is not connected")
            return
        case EVEnumMode.ALL:
            ev_enumerator.add_all()
            tls_flag = True
        case EVEnumMode.SUPPORTED_PROTOCOLS:
            ev_enumerator.add_supported_protocols_check()
        case EVEnumMode.TLS_CHECK:
            ev_enumerator.add_tls_check()
        case EVEnumMode.TLS_ENUM:
            ev_enumerator.add_tls_enum()
            tls_flag = True

    # Start station
    # Collect all possible information about EV in the station
    # based on ev_enumerator, which is passed to the station
    # try:
    station.start_async(
        interface=interface,
        accept_security=accept_security,
        ev_enumerator=ev_enumerator,
        tls_flag=tls_flag,
    )
    # except KeyboardInterrupt:
    #    print("Stopping station by user - CTRL+C")

    # TODO: Process ev_enumerator and print the results
    match enum_mode:
        case EVEnumMode.ALL:
            ev_enumerator.print_all()
            return
        case EVEnumMode.SUPPORTED_PROTOCOLS:
            ev_enumerator.print_supported_protocols()
            print("EVSE is not connected")
            return
        case EVEnumMode.TLS_CHECK:
            ev_enumerator.print_tls_check_result()
            return
        # TODO:
        case EVEnumMode.TLS_ENUM:
            ev_enumerator.print_tls_enum_result()
            return
