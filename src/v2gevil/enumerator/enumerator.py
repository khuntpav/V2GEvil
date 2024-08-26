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

"""This module is used to enumerate all possible information about the EV
and display it to the user.
"""
import logging
from typing import Optional, List, Tuple

from ..v2gtp.v2gtp import V2GTPMessage
from ..v2gtp.v2gtp_enums import V2GTPProtocols, V2GTPSecurity
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
        self.tls_version: Optional[str] = None  # TLS version
        self.cipher_suite: Optional[
            Tuple[str, str, int]
        ] = None  # Tuple: (cipher_suite_name, version of TLS/SSL, number of secret bits)
        self.shared_ciphers: Optional[
            List[Tuple[str, str, int]]
        ] = None  # list of tuples (defined above)

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

    def add_tls_enum(self):
        """Add TLS enumeration mode."""
        # if EVEnumMode.TLS_ENUM not in self.enum_modes:
        #    self.enum_modes.append(EVEnumMode.TLS_ENUM)
        self.enum_modes.add(EVEnumMode.TLS_ENUM)

    def add_all(self):
        """Add all possible enumeration modes.

        Exclude mutually exclusive => TLS_CHECK_ONLY exclude other modes,
        because after TLS_CHECK_ONLY is done, station should be stopped.
        """
        self.add_supported_protocols_check()
        self.add_tls_check()
        self.add_tls_enum()

    def print_supported_protocols(self) -> None:
        """Print supported protocols."""

        # Get supportedAppProtocolReq as V2GTPMessage instance from the dictionary

        print(80 * "-")
        print("Supported App protocols result:")
        if "supportedAppProtocolReq" not in self.v2g_requests_dict:
            print("Didn't receive supportedAppProtocolReq from EV!")
            return

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

        print(80 * "-")
        print("TLS check result:")
        if self.sdp_request is None:
            print("EV's SDP request is not received!")
            return
        (
            requested_security,
            requested_trans_proto,
        ) = self.sdp_request.parse_v2gtp_sdp_request()

        if requested_security == V2GTPProtocols.NO_TLS:
            logger.warning("EV does not require TLS in SDP request!")
            print("EV does not require TLS! Unsecured communication is used!")

        # I cannot use V2GTPProtocols[], because in this case it's not the same
        # as enum name, but only as enum value
        security = V2GTPSecurity(requested_security).name
        transport_proto = V2GTPProtocols(requested_trans_proto).name

        print(
            f"EV requested security: {security} and as a "
            f"transport protocol: {transport_proto} for communication"
        )

    def print_tls_enum_result(self):
        """Print TLS enumeration result."""
        if self.tls_version is None:
            print("TLS is not used by EV!")
            return
        # Next two conditions are not needed, because if tls_version is None,
        # they are empty
        if self.cipher_suite is None or len(self.cipher_suite) == 0:
            print("NO cipher suite!")
            return
        if self.shared_ciphers is None or len(self.shared_ciphers) == 0:
            print("NO shared ciphers!")
            return

        print(80 * "-")
        print("TLS enumeration result:")
        print(f"TLS negotiated version: {self.tls_version}")
        print(f"TLS negotiated cipher suite: {self.cipher_suite}")
        print(
            f"TLS shared ciphers: {self.shared_ciphers}.\n"
            f"Shared ciphers are ciphers available in both the EV and the EVSE."
        )

        cipher_suites_iso_15118_2_2014 = [
            "ECDH-ECDSA-AES128-SHA256",
            "ECDHE-ECDSA-AES128-SHA256",
        ]

        if (
            self.cipher_suite[0]  # pylint: disable=unsubscriptable-object
            not in cipher_suites_iso_15118_2_2014
        ):
            logger.warning(
                "EV negotiated cipher which is not allowed by ISO 15118-2:2014!"
            )
            print(
                "EV negotiated cipher which is not allowed by ISO 15118-2:2014!"
            )

        for (
            cipher_suite
        ) in self.shared_ciphers:  # pylint: disable=not-an-iterable
            if cipher_suite[0] not in cipher_suites_iso_15118_2_2014:
                logger.warning(
                    "EV offer cipher suite which is not allowed by ISO 15118-2:2014!"
                )
                print(
                    "EV offer cipher suite which is not allowed by ISO 15118-2:2014!"
                )
                print(f"EV offer prohibited cipher suite: {cipher_suite}")

        # Evaluation from ISO 15118-2:2014: Allowed TLS versions and cipher suites
        # Table 7 — Supported cipher suites
        # TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
        #  OpenSSL name: ECDH-ECDSA-AES128-SHA256
        # TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
        #   OpenSSL name: OpenSSL name: ECDHE-ECDSA-AES128-SHA256
        # Weak ciphers:
        #   https://ciphersuite.info/cs/TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256/
        #   https://ciphersuite.info/cs/TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256/
        # TODO: Differ between -2 and -20 version of ISO 15118
        # Different cipher suites requirements and TLS in 20 is mandatory not an option

    def print_all(self):
        """Print all enumeration results."""
        print(80 * "-")
        print("EV enumeration results:")
        self.print_supported_protocols()
        self.print_tls_check_result()
        self.print_tls_enum_result()


class EVSEEnumerator:
    """EVSE enumerator class."""

    def enumerate_supported_proto(self):
        """Enumerate supported protocols."""
        raise NotImplementedError
