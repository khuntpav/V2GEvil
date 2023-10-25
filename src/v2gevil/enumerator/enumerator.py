"""This module is used to enumerate all possible information about the EV
and display it to the user.
"""
import logging
from typing import Optional

from ..v2gtp.v2gtp import V2GTPMessage
from ..v2gtp.v2gtp_enums import V2GTPProtocols
from ..messages.AppProtocol import supportedAppProtocolReq
from .enumerator_enums import EVEnumMode


logger = logging.getLogger(__name__)


class EVEnumerator:
    """EV enumerator class."""

    def __init__(self):
        self.sdp_request: Optional[V2GTPMessage] = None
        # Contains name of V2G_Message as a key
        # and as value V2GTPMessage objects for enumeration
        self.v2g_requests_dict: dict[str, V2GTPMessage] = {}
        self.msgs_for_enum = []
        self.enum_modes = set()

    # TODO: Handling is not implemented in the station in sdp server
    def tls_check_only(self):
        """Check if TLS is required by EV and after that stop the station.
        Based on the transmitted messages and information in them.
        """
        self.enum_modes.clear()
        self.enum_modes.add(EVEnumMode.TLS_CHECK_ONLY)
        raise NotImplementedError(
            "Not implemented handling this in station(sdp_server()) yet!"
        )

    def add_supported_protocols_check(self):
        """Enumerate which protocols are supported by EV."""
        # Better to use set, because I don't want to have duplicates
        # and I don't care about order => if statement is not needed
        # if EVEnumMode.SUPPORTED_PROTOCOLS not in self.enum_modes:
        #    self.enum_modes.append(EVEnumMode.SUPPORTED_PROTOCOLS)
        self.enum_modes.add(EVEnumMode.SUPPORTED_PROTOCOLS)
        self.msgs_for_enum.append(supportedAppProtocolReq.__name__)

    def add_tls_check(self):
        """Check if TLS is required by EV."""
        # if EVEnumMode.TLS_CHECK not in self.enum_modes:
        #    self.enum_modes.append(EVEnumMode.TLS_CHECK)
        self.enum_modes.add(EVEnumMode.TLS_CHECK)

    def add_all(self):
        """Add all possible enumeration modes.

        Exclude mutually exclusive => TLS_CHECK_ONLY exclude other modes,
        because after TLS_CHECK_ONLY is done, station should be stopped.
        """
        self.add_supported_protocols_check()
        self.add_tls_check()

    def print_supported_protocols(self) -> None:
        """Print supported protocols."""

        # Get supportedAppProtocolReq as V2GTPMessage instance from the dictionary
        v2gtp_req = self.v2g_requests_dict["supportedAppProtocolReq"]

        # Parse v2gtp_req using V2GTPMessage class method -> parse_v2gtp_exi_msg()
        obj, _ = v2gtp_req.parse_v2gtp_exi_msg()
        assert isinstance(obj, supportedAppProtocolReq)  # Only for IDE/pylance

        # Print all supported protocols by EV
        print("Supported protocols by EV:")
        print(f"Number of supported protocols: {len(obj.app_protocol)}")
        for app_protocol in obj.app_protocol:
            print(
                f"ProtocolNamespace: {app_protocol.proto_ns}, "
                f"VersionMajor: {app_protocol.version_major}, "
                f"VersionMinor: {app_protocol.version_minor}, "
                f"SchemaID: {app_protocol.schema_id}, "
                f"Priority: {app_protocol.priority}"
            )

    def print_tls_check_result(self):
        """Print TLS check result."""

        if self.sdp_request is None:
            print("EV's SDP request is not received!")
            return
        (
            requested_security,
            requested_trans_proto,
        ) = self.sdp_request.parse_v2gtp_sdp_request()

        print("TLS check result:")
        if requested_security == V2GTPProtocols.NO_TLS:
            logger.warning("EV does not require TLS!")
            print("EV does not require TLS! Unsecured communication is used!")

        # I cannot use V2GTPProtocols[], because in this case it's not the same
        # as enum name, but only as enum value
        security = V2GTPProtocols(requested_security).name
        transport_proto = V2GTPProtocols(requested_trans_proto).name

        print(
            f"EV requested security: {security} and as"
            f"trasport protocol: {transport_proto} for communication"
        )

    def print_all(self):
        """Print all enumeration results."""
        self.print_supported_protocols()
        self.print_tls_check_result()


class EVSEEnumerator:
    """EVSE enumerator class."""

    raise NotImplementedError

    def enumerate_supported_proto(self):
        """Enumerate supported protocols."""
