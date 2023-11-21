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
    match enum_mode:
        case None:
            print("EVSE is not connected")
            return
        case EVEnumMode.ALL:
            ev_enumerator.add_all()
        case EVEnumMode.SUPPORTED_PROTOCOLS:
            ev_enumerator.add_supported_protocols_check()
        case EVEnumMode.TLS_CHECK:
            ev_enumerator.add_tls_check()
        case EVEnumMode.TLS_ENUM:
            ev_enumerator.add_tls_enum()

    # Start station
    # Collect all possible information about EV in the station
    # based on ev_enumerator, which is passed to the station
    # Data are saved in the ev_enumerator attributes
    # TODO: Check if KeyboardInterrupt is needed
    # try:
    station.start_async(
        interface=interface,
        accept_security=accept_security,
        ev_enumerator=ev_enumerator,
    )
    # except KeyboardInterrupt:
    #     print("Stopping station by user - CTRL+C")

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
