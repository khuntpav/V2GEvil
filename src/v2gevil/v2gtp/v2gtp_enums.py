"""Enum for V2GTP"""
from enum import Enum
from enum import IntEnum


class V2GTPMessageType(bytes, Enum):
    """Enum for V2GTP message types."""

    SDP_REQUEST = b"\x90\x00"
    SDP_RESPONSE = b"\x90\x01"
    V2GTP_EXI_MSG = b"\x80\x01"
    # Reserved for future use
    # Reserved for manufacturer proprietary use


class V2GTPProtocols(bytes, Enum):
    """Enum for V2GTP protocols."""

    # Transport protocol for V2GTP
    # TCP byte is 0x01 in SDP request/response
    TCP = b"\x00"
    # UDP byte is 0x00 in SDP request/response
    UDP = b"\x10"

    # Security byte
    TLS = b"\x00"
    NO_TLS = b"\x10"

    # Reserved for future use, for Transport protocol and security byte
    # 0x01-0x0F = reserved
    # 0x11-0xFF = reserved


class V2GTPPorts(IntEnum):
    """Enum for V2GTP ports"""

    # Port number for SDP server
    V2G_UDP_SDP_SERVER = 15118
    # Possible ports for SDP client
    V2G_UDP_SDP_CLIENT_START = 49152
    V2G_UDP_SDP_CLIENT_END = 65535
    # Possible ports for TCP server/client
    V2G_DST_TCP_DATA_START = 49152
    V2G_DST_TCP_DATA_END = 65535
    V2G_SRC_TCP_DATA_START = 49152
    V2G_SRC_TCP_DATA_END = 65535


class V2GTPVersion(bytes, Enum):
    """Enum for V2GTP versions."""

    # V2GTP version 1.0
    V_0_1 = b"\x01"
    # V2GTP version inverse 1.0
    V_0_1_INVERSE = b"\xFE"
    # Reserved for future use
    # Reserved for manufacturer proprietary use
    # Can be changed to support other versions of V2GTP
    CURRENT_VERSION = V_0_1
    CURRENT_VERSION_INVERSE = V_0_1_INVERSE


# Pyhton 3.11 => StrEnum instead of str, Enum
class V2GTPAddress(str, Enum):
    """Enum for V2GTP IPv6 addresses."""

    # Address for SDP server
    MULTICAST_ADDRESS = "ff02::1"
    STATION = "fe80::d237:45ff:fe88:b12b"
    CAR = "fe80::d237:45ff:fe88:b12a"


class V2GTPAppProtocols(str, Enum):
    """Enum for V2GTP application protocols."""

    PROTOCOL_NAMESPACE = "urn:iso:15118:2:2013:MsgDef"
    # Others can be added based on the use case
