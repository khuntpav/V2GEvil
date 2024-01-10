"""Module for V2GTP related commands.

Here is the implementation of the V2GTP protocol,
which is used for communication between EV and EVSE. 
The implementation is based on ISO 15118-2:2014.
"""
import os.path
import logging
import socket
import requests
import random
from typing import Optional, Union

from scapy.plist import PacketList
from scapy.packet import Packet
from scapy.packet import Raw
from scapy.layers.inet import TCP
from scapy.layers.inet import UDP
from scapy.layers.inet6 import IPv6
from scapy.utils import linehexdump
from scapy.all import rdpcap

from ..v2gtp.v2gtp_enums import (
    V2GTPMessageType,
    V2GTPProtocols,
    V2GTPAddress,
    V2GTPVersion,
    V2GTPAppProtocols,
)
from ..messages import messages
from ..messages.MsgBody import (
    SessionSetupReq,
)
from ..messages.MsgDef import V2G_Message
from ..messages.AppProtocol import (
    supportedAppProtocolReq,
    supportedAppProtocolRes,
    responseCodeType as responseCodeTypeAppProto,
)
from ..messages.MsgDef import Header, Body


logger = logging.getLogger(__name__)


class V2GTPMessage:
    """V2GTP message class.

    Class represents V2GTP message.
    Constructor takes V2GTP message as bytes.
    Contains header and payload in bytes.
    """

    def __init__(self, message: bytes = b""):
        """Initialize V2GTP message."""
        self.message = message
        self.header = self.message[:8]
        self.payload = self.message[8:]
        self.payload_type = self.header[2:4]

    # TODO: Maybe this function change to return V2GTPMessage instance
    # and have another method to_bytes() for converting to bytes
    def create_message(self, payload: bytes, payload_type: bytes) -> bytes:
        """Create V2GTP message in bytes"""
        version = V2GTPVersion.CURRENT_VERSION
        inverse_version = V2GTPVersion.CURRENT_VERSION_INVERSE
        payload_length = int.to_bytes(len(payload), length=4, byteorder="big")
        # Header is 8 bytes long
        # 1. byte => version
        # 2. byte => inverse version
        # 3.-4. bytes => payload type
        # 5.-8. bytes => payload length
        header = version + inverse_version + payload_type + payload_length
        message = header + payload
        return message

    def get_payload(self) -> bytes:
        """Get payload."""
        return self.payload

    def get_header(self) -> bytes:
        """Get header."""
        return self.header

    def v2gtp_exi_message(self, payload: bytes) -> bytes:
        """Create V2GTP EXI message."""
        self.message = b""
        return self.message

    def sdp_message(self, payload: bytes) -> bytes:
        """Create SDP message."""
        self.message = b""
        return self.message

    def get_xml(self) -> str:
        """Get XML."""
        # TODO: Add EXI to XML conversion
        return ""

    # Methods for bytes given as data
    # TODO: probably put these methods in Class V2GTPMessage

    def is_v2gtp_sdp_request_data(self) -> bool:
        """Check if given data is V2GTP SDP request."""
        if self.payload_type == V2GTPMessageType.SDP_REQUEST:
            return True

        return False

    def is_v2gtp_sdp_response_data(self) -> bool:
        """Check if given data is V2GTP SDP response."""
        if self.payload_type == V2GTPMessageType.SDP_RESPONSE:
            return True

        return False

    def is_v2gtp_exi_msg_data(self) -> bool:
        """Check if given data is V2GTP EXI message."""
        if self.payload_type == V2GTPMessageType.V2GTP_EXI_MSG:
            return True

        return False

    def decode_v2gtp_exi_msg(self) -> str:
        """Decode V2GTP EXI message."""

        logger.debug("Trying to decode V2GTP message as V2GTP EXI message...")

        try:
            response = requests.post(
                "http://localhost:9000",
                headers={"Format": "EXI"},
                data=self.payload.hex(),
                timeout=10,
            )
            if response.status_code == 200:
                logger.debug("Response from V2GDecoder:\n")
                logger.debug(response.text)
            else:
                logger.warning("Error: %s", response.status_code)
                logger.warning("Error: %s", response.text)
        except requests.exceptions.Timeout:
            logger.error("Timeout! Is V2GDecoder running?")
            exit(1)
        except requests.exceptions.ConnectionError:
            logger.error("Connection refused! Is V2GDecoder running?")
            exit(1)

        return response.text

    def parse_v2gtp_msg(self):
        """Parse V2GTP message."""
        if self.payload_type == V2GTPMessageType.V2GTP_EXI_MSG:
            return self.parse_v2gtp_exi_msg()
        if self.payload_type == V2GTPMessageType.SDP_REQUEST:
            return self.parse_v2gtp_sdp_request()
        if self.payload_type == V2GTPMessageType.SDP_RESPONSE:
            return self.parse_v2gtp_sdp_response()

        return None, None, None, None

    def parse_v2gtp_exi_msg(self):
        """Parse V2GTP EXI message to get obj and obj_name."""

        # Get XML string from EXI payload
        xml_str = self.decode_v2gtp_exi_msg()
        logger.debug("XML string from EXI payload:\n%s", xml_str)

        # Find what kind of req was received
        # Convert XML to data in dictionary => type dict
        obj = messages.xml2class_instance(xml_str)
        # obj_name will be V2G_Message or supportedAppProtocolReq/Res
        obj_name = obj.__class__.__name__
        logger.debug("Object name: %s", obj_name)

        return obj, obj_name

    def parse_v2gtp_sdp_request(self):
        """Parse V2GTP SDP request.

        Returns:
            A tuple contains security byte and transport protocol byte,
            which are received in SDP request.
        """
        security_byte = self.payload[0:1]
        transport_proto_byte = self.payload[1:2]

        return security_byte, transport_proto_byte

    def parse_v2gtp_sdp_response(self):
        """Parse V2GTP SDP response.

        Returns:
            A tuple contains server address bytes, server port bytes,
            security byte and transport protocol byte.
        """
        server_address = self.payload[0:16]
        server_port = self.payload[16:18]
        security_byte = self.payload[18:19]
        transport_proto_byte = self.payload[19:20]

        return server_address, server_port, security_byte, transport_proto_byte

    # TODO: Implement also malicious brother of this method or just made some changes in this method
    # model_construct instead of model_validate, model_dump(warnings=False), etc
    # TODO: Implement this method
    def create_v2gtp_exi_msg_response(
        self,
        messages_dict: Optional[dict] = None,
        enum_flag: bool = False,
        validate_flag: bool = True,
    ) -> Union[tuple[bytes, str], bytes]:
        """Create V2GTP EXI message response.

        Based on the request, create response.

        Based on the enum_flag, if true return tuple of bytes of response\
        and name of request class. If false, return only bytes of response.
        """

        if self.is_v2gtp_exi_msg_data() is False:
            logger.warning("Payload type is not EXI message!")
            raise ValueError("Payload type is not EXI message!")

        payload_type = V2GTPMessageType.V2GTP_EXI_MSG
        response_obj = None

        # Check what type of request was received => need to EXI decode
        req_obj, req_obj_name = self.parse_v2gtp_exi_msg()

        # Based on this mapping request-response, the req_res_map are created
        req_res_map = messages_dict
        if req_res_map is None:
            logger.warning("Responses dictionary is None!")
            raise ValueError("Responses dictionary is None!")

        if isinstance(req_obj, V2G_Message):
            if (
                isinstance(req_obj.body, SessionSetupReq)
                and req_obj.header.session_id == 0
            ):
                # SECC shall generate a new (not stored) SessionID, max. 8 bytes
                # SessionID in hexBinary
                # TODO VULN: potentially send more than 8 bytes to test EVCC
                session_id = random.randbytes(8).hex()

            # Session id in response will be same as in req for all other requests
            session_id = req_obj.header.session_id
            # TODO VULN: add Notification and Signature in response and test it
            header_res = Header(SessionID=session_id)

            # To get name of setted attribute in Body => get request/response class
            # Will be only one every time, so list()[0]
            req_name = list(req_obj.body.model_fields_set)[0]

            # get attribute from body based on the name of attribute from previous step
            # type is some of the classes from MsgBody.py
            req_instance = getattr(req_obj.body, req_name)
            # Just for verification type of attribute
            # print(type(attribute_instance))
            # get name of class for attribute - based on __str__() method in class
            # So to get the class name of attribute use __class__.__name__ or str(attribute)
            # body_type_res = str(attribute_instance)

            # Request class name, for example: 'SessionSetupReq', type is str
            body_type_req = req_instance.__class__.__name__
            # print(body_type_res) is equal to print(attribute_instance)

            # Create instance of Body with proper response class
            # response dictionary is based on the request class name
            # for example: 'SessionSetupReq' =>
            #   {'SessionSetupRes': {'ResponseCode': 'OK', 'EVSEID': 'EVSE1'}}
            # TODO: Think what from this two lines is better
            # body_res = Body(**req_res_map[body_type_res]) -> this showing error in VSCode but it's working
            # the line below is without error in VSCode, also working in runtime
            # req_res_map[body_type_req] => dict for response class
            if validate_flag:
                body_res = Body.model_validate(req_res_map[body_type_req])
            else:
                body_res = Body.model_construct(**req_res_map[body_type_req])

            # Maybe also here can be problem with warnings
            response_obj = V2G_Message(Header=header_res, Body=body_res)

        if isinstance(req_obj, supportedAppProtocolReq):
            # Differ between runtime response and normal response
            # if supportedAppProtocol is in req_res_map dictionary, then use it
            # if not, then use normal response

            if supportedAppProtocolReq.__name__ in req_res_map:
                print("SupportedAppProtocolReq used from dictionary!")
                if validate_flag:
                    response_obj = supportedAppProtocolRes.model_validate(
                        req_res_map[supportedAppProtocolReq.__name__][
                            supportedAppProtocolRes.__name__
                        ]
                    )
                else:
                    response_obj = supportedAppProtocolRes.model_construct(
                        **req_res_map[supportedAppProtocolReq.__name__][
                            supportedAppProtocolRes.__name__
                        ]
                    )
            else:
                print("Runtime SupportedAppProtocolRes used!")
                for app_proto in req_obj.app_protocol:
                    if (
                        app_proto.proto_ns
                        == V2GTPAppProtocols.PROTOCOL_NAMESPACE
                    ):
                        response_obj = supportedAppProtocolRes(
                            ResponseCode=responseCodeTypeAppProto.SUCCESS_NEGOTIATION,
                            SchemaID=app_proto.schema_id,
                        )

        # TODO: Add option based on input parameter malicious_flag => model_construct instead of model_validate
        # also thi param is need to be check when model_dump, => model_dump(warnings=False)
        # Use messages.class_instance2xml() method => get XML from class instance
        logger.debug("Response object:\n%s", response_obj)
        logger.debug("Response object type:\n%s", type(response_obj))
        print("Created response object:")
        if response_obj is not None:
            print(
                response_obj.model_dump(
                    by_alias=True, exclude_unset=True, warnings=False
                )
            )

        response_xml = messages.class_instance2xml(
            response_obj, validate_flag=validate_flag
        )

        # Use messages.xml2exi() to get EXI from XML
        response_exi = messages.xml2exi(response_xml)
        # Get bytes from EXI
        response_exi_bytes = bytes.fromhex(response_exi)

        # Create V2GTP EXI message
        created_message = self.create_message(
            payload=response_exi_bytes, payload_type=payload_type
        )

        # Check if V2G Message or supportedAppProtocolReq/Res was received
        # Based on that create V2G_Message instance or supportedAppProtocolRes/Req instance
        # Then use messages.class_instance2xml() method
        # Then use messages.xml2exi() method or encode() method in this file
        # have bytes from EXI, then use create_message() method and pass EXI bytes as payload
        if enum_flag:
            return created_message, req_obj_name
        return created_message

    def create_v2gtp_sdp_response(
        self,
        ipv6: str = V2GTPAddress.STATION,
        port: int = 15119,
        protocol: bytes = V2GTPProtocols.TCP,
        tls_flag: bool = False,
    ) -> bytes:
        """Create V2GTP SDP response."""

        # TODO: Maybe implement response of TLS based on TLS in SDP request
        ipv6_bytes = socket.inet_pton(socket.AF_INET6, ipv6)
        port_bytes = port.to_bytes(length=2, byteorder="big")
        if tls_flag is True:
            security_byte = V2GTPProtocols.TLS
        else:
            security_byte = V2GTPProtocols.NO_TLS

        payload_type = V2GTPMessageType.SDP_RESPONSE
        # Number of bytes in payload is 20, payload length is from 5. to 8. byte
        # payload_length = int.to_bytes(20, length=4, byteorder="big")

        # Payload is 20 bytes long for SDP response
        # 1.-16. bytes => IPv6 address
        # 17.-18. bytes => port number
        # 19. byte => security byte
        # 20. byte => transport protocol byte
        payload = ipv6_bytes + port_bytes + security_byte + protocol
        created_message = self.create_message(
            payload=payload, payload_type=payload_type
        )

        return created_message

    def create_v2gtp_sdp_request(
        self, protocol: bytes = V2GTPProtocols.TCP, tls_flag: bool = False
    ) -> bytes:
        """Create V2GTP SDP request."""

        # Payload is 2 bytes long for SDP request
        # 1. byte => security byte
        # 2. byte => transport protocol byte
        if tls_flag is True:
            security_byte = V2GTPProtocols.TLS
        else:
            security_byte = V2GTPProtocols.NO_TLS

        payload = security_byte + protocol
        payload_type = V2GTPMessageType.SDP_REQUEST
        created_message = self.create_message(
            payload=payload, payload_type=payload_type
        )

        return created_message

    def create_response(
        self,
        ipv6: str = "",
        port: int = 15119,
        protocol: bytes = V2GTPProtocols.TCP,
        tls_flag: bool = False,
        messages_dict: Optional[dict] = None,
        enum_flag: bool = False,
        validate_flag: bool = False,
    ) -> Union[tuple[bytes, str], bytes]:
        """Create response message.
        
        Based on the enum_flag, if true return tuple of bytes of response\
        and name of request class. If false, return only bytes of response.
        """
        # Check if payload type is V2GTP EXI message or SDP message
        if self.is_v2gtp_exi_msg_data():
            return self.create_v2gtp_exi_msg_response(
                messages_dict=messages_dict,
                enum_flag=enum_flag,
                validate_flag=validate_flag,
            )

        if self.is_v2gtp_sdp_request_data():
            return self.create_v2gtp_sdp_response(
                ipv6=ipv6,
                port=port,
                protocol=protocol,
                tls_flag=tls_flag,
            )

        return b""


# TODO: Create class called V2GTP Packet, ihnerit from scapy.Packet
# Rewrite .show() function to show only V2GTP header and payload
# .decode_payload() function for decoding payload
# @Packet.register_packet_class
# class V2GTP(Packet):
# TODO: is_ functions should return True or False, and also return header and payload
# TODO: Later do from is_methods, maybe also some decode methods
#  => methods for Class V2GTPPacket


# Important: The communication between EV and EVSE is also include other IPv6 packets, not only V2GTP packets
# So if we want whole communication, we need to sniff all IPv6 packets and then check them
# There are ICMPv6 packets, which are used for Neighbor Discovery Protocol (NDP)
# NDP is used for IPv6 address autoconfiguration and for IPv6 router discovery
# NDP is also used for Duplicate Address Detection (DAD)
# There are also UDP packets for SECC Discovery Protocol (SDP)
# This function will extract only V2GTP packets from pcap file not whole IPv6 communication
# To extract whole IPv6 communication, use function "analyze" from sniffer module
def extract_v2gtp_pkts_from_file(file: str):
    """Extract V2GTP packets from pcap file"""
    if os.path.isfile(file) is False:
        logger.error("File doesn't exist!")
        exit(1)
    filtered_packets = extract_v2gtp_pkts(rdpcap(file))
    print(filtered_packets)
    for pkt in filtered_packets:
        # print(pkt.summary())
        print(prn_v2gtp_pkt(pkt=pkt))
        # print(prn_decode_v2gtp_pkt(pkt=pkt))
    # TODO: Add saving of filtered packets to pcap file
    # wrpcap("filtered_packets.pcap", filtered_packets)
    # TODO: Add option for print summary or print v2gtp packet / decoded v2gtp packet


def extract_v2gtp_pkts(packets) -> PacketList:
    """Extract V2GTP packets"""

    filtered_packets = PacketList()
    for pkt in packets:
        if has_v2gtp_layer(pkt):
            pkt_num = packets.index(pkt) + 1
            logger.debug(
                "Packet number: %s has no V2GTP layer (Wireshark num.)",
                pkt_num,
            )
            filtered_packets.append(pkt)
        else:
            pkt_num = packets.index(pkt) + 1
            logger.debug(
                "Packet number: %s has no V2GTP layer (Wireshark num.)",
                pkt_num,
            )
    return filtered_packets


# Following methods with has_ prefix are here because of logging
# Without logging, it's not needed to have them
# And just use pkt.haslayer() instead of has_ functions
# TODO: Probably it will be better to use pkt.haslayer() instead of has_ functions
# TODO: Add rewrite haslayer functions to use logging for my class V2GTPPacket
def has_raw_layer(pkt: Packet):
    """Check if packet has Raw layer. Added because check if Raw layer is in packet is used multiple times"""

    if not pkt.haslayer(Raw):
        # or not Raw in pkt what is more efficient/faster?
        logger.debug("Packet doesn't have Raw layer!")
        return False
        # raise ValueError("Packet doesn't have Raw layer!")
    return True


def has_tcp_layer(pkt: Packet):
    """Check if packet has TCP layer. Added because check if TCP layer is in packet is used multiple times"""
    if not pkt.haslayer(TCP):
        logger.debug("Packet doesn't have TCP layer!")
        return False
    return True


def has_ipv6_layer(pkt: Packet):
    """Check if packet has IPv6 layer. Added because check if IPv6 layer is in packet is used multiple times"""
    if not pkt.haslayer(IPv6):
        logger.debug("Packet doesn't have IPv6 layer!")
        return False
    return True


def has_v2gtp_layer(pkt: Packet):
    """Check if packet has V2GTP layer."""

    # V2GTP uses IPv6 from my understanding of ISO15118-2:2014
    if not has_raw_layer(pkt) or not has_ipv6_layer(pkt):
        logger.debug("Packet doesn't have Raw or IPv6 layer!")
        return False

    # TODO: In future check versions of V2GTP protocol, for now it's only version 1
    # V2GTP Header field: Protocol Version
    v2gtp_version = b"\x01"
    # V2GTP Header field: Inverse Protocol Version
    v2gtp_inverse_version = b"\xFE"
    version_bytes = v2gtp_version + v2gtp_inverse_version

    logger.debug("V2GTP version bytes: %s", version_bytes)

    v2gtp_pdu = pkt[Raw].load
    if v2gtp_pdu.startswith(version_bytes):
        return True
    return False


def is_v2gtp_exi_msg(pkt: Packet):
    """Check if payload type in header is V2GTP EXI message."""

    header, payload = parse_v2gtp_pkt(pkt)
    if header is None or payload is None:
        return False
    # From byte 3 to byte 4 is payload type [2:4] from 2. position to 3. position
    # 4. position is not included, so it's byte 3 and 4
    # Bytes in ISO, number of byte starts from 1, not from 0
    # So byte 3 and 4 is here 2. and 3. position
    payload_type = header[2:4]
    if payload_type == b"\x80\x01":
        return True

    return False


def is_v2gtp_sdp_request(pkt: Packet):
    """Check if payload type in header is V2GTP SDP request."""

    header, payload = parse_v2gtp_pkt(pkt)
    if header is None or payload is None:
        return False
    payload_type = header[2:4]
    if payload_type == b"\x90\x00":
        return True

    return False


def is_v2gtp_sdp_response(pkt: Packet):
    """Check if payload type in header is V2GTP SDP response."""

    header, payload = parse_v2gtp_pkt(pkt)
    if header is None or payload is None:
        return False
    payload_type = header[2:4]
    if payload_type == b"\x90\x01":
        return True

    return False


def is_v2gtp_manufacturer_use(pkt: Packet):
    """Check if payload type in header is V2GTP Manufacturer Specific Use."""

    header, payload = parse_v2gtp_pkt(pkt)
    if header is None or payload is None:
        return False
    payload_type = header[2:4]
    manufacturer_start = b"\xa0\x00"
    manufacturer_end = b"\xff\xff"
    if manufacturer_start <= payload_type <= manufacturer_end:
        logger.debug("Manufacturer specific use payload type!")
        return True


def is_v2gtp_reserved(pkt: Packet):
    """Check if payload type in header is V2GTP Reserved."""

    header, payload = parse_v2gtp_pkt(pkt)
    if header is None or payload is None:
        return False
    payload_type = header[2:4]
    if (
        b"\x00\x00" <= payload_type <= b"\x80\x00"
        or b"\x80\x02" << payload_type <= b"\x8f\xff"
        or b"\x90\x02" << payload_type <= b"\x9f\xff"
    ):
        logger.debug("Reserved payload type!")
        return True

    return False


def check_v2gtp_payload_types(pkt: Packet):
    """Check V2GTP payload type, which is defined in the V2GTP PDU header"""

    if is_v2gtp_exi_msg(pkt):
        payload_type = "exi_message"
        return payload_type
    if is_v2gtp_sdp_request(pkt):
        payload_type = "sdp_request"
        return payload_type
    if is_v2gtp_sdp_response(pkt):
        payload_type = "sdp_response"
        return payload_type
    if is_v2gtp_manufacturer_use(pkt):
        payload_type = "manufacturer_specific_use"
        return payload_type
    if is_v2gtp_reserved(pkt):
        payload_type = "reserved"
        return payload_type

    logger.warning("Unknown payload type!")
    raise ValueError("Unknown payload type!")


def parse_v2gtp_pkt(pkt: Packet):
    """Parse V2GTP packet => Separate the V2GTP header from the payload

    Check if the packet has Raw layer, then check if it's V2GTP packet
    and then separate the V2GTP header from the payload
    """
    # logger.debug("Trying to parse packet as V2GTP packet...")

    if not has_v2gtp_layer(pkt):
        return None, None

    header = pkt[Raw].load[:8]
    payload = pkt[Raw].load[8:]

    return header, payload


# For now use this function for decoding V2GTP packet in combination with
# V2GDecoder.jar
# source of V2GDecoder.jar:
def decode_v2gtp_exi_msg(
    pkt: Packet, header: bytes, payload: bytes
) -> tuple[bytes, bytes, str]:
    """Decode V2GTP EXI message payload type"""

    # Sending separated payload from previous step to V2GDecoder
    # Important! V2GDecoder needs to be first started, before running this command
    # V2GDecoder will be run as a web server by following command:
    # java -jar V2GDecoder.jar -w

    # TODO: Maybe write my own decoder
    if not is_v2gtp_exi_msg(pkt):
        logger.warning("Packet is not V2GTP EXI message!")
        raise ValueError("Packet is not V2GTP EXI message!")

    # Unnecessary check if None,
    # because it's already checked in is_v2gtp_exi_msg function
    # IDE needs it, because it doesn't know that it's already checked
    # cause hex() method is not defined for None
    if header is None or payload is None:
        logger.warning("Header or Payload is None!")
        raise ValueError("Header or Payload is None!")

    # print("Trying to decode packet as V2GTP EXI message...\n")
    logger.debug("Trying to decode packet as V2GTP EXI message...")

    try:
        response = requests.post(
            "http://localhost:9000",
            headers={"Format": "EXI"},
            data=payload.hex(),
            timeout=10,
        )
        if response.status_code == 200:
            logger.debug("Response from V2GDecoder:\n")
            logger.debug(response.text)
        else:
            logger.warning("Error: %s", response.status_code)
            logger.warning("Error: %s", response.text)
    except requests.exceptions.Timeout:
        logger.error("Timeout! Is V2GDecoder running?")
        exit(1)
        # raise requests.exceptions.Timeout("Timeout! Is V2GDecoder running?")
    except requests.exceptions.ConnectionError:
        logger.error("Connection refused! Is V2GDecoder running?")
        exit(1)
        # raise requests.exceptions.ConnectionError(
        #    "Connection refused! Is V2GDecoder running?"
        # )

    return header, payload, response.text


def decode_v2gtp_sdp(security_byte: bytes, transport_proto_byte: bytes) -> str:
    """Method for decode Security and Transport Protocol bytes from SDP"""
    if security_byte == b"\x00":
        security = "0x00 => secured with TLS"
    elif security_byte == b"\x10":
        security = "0x10 => No transport layer security"
    elif (
        b"\x01" <= security_byte <= b"\x0F"
        or b"\x11" <= security_byte <= b"\xFF"
    ):
        logger.debug("Reserved payload type!")
        security = "Reserved payload type!"
    else:
        logger.warning("Unknown security!")
        security = "Unknown security! Not specified in ISO 15118-2:2014"
        raise ValueError("Unknown security!")

    # Check Transport Protocol byte
    if transport_proto_byte == b"\x00":
        transport_proto = "0x00 => TCP"
    elif transport_proto_byte == b"\x01":
        transport_proto = "0x10 => reserved for UDP"
    elif (
        b"\x01" <= transport_proto_byte <= b"\x0F"
        or b"\x11" <= transport_proto_byte <= b"\xFF"
    ):
        logger.debug("Reserved payload type!")
        transport_proto = "Reserved payload type!"
    else:
        logger.warning("Unknown transport layer!")
        transport_proto = (
            "Unknown transport layer! Not specified in ISO 15118-2:2014"
        )
        raise ValueError("Unknown transport layer!")

    decoded = f"Security: {security}\n\t" f"Transport layer: {transport_proto}"

    return decoded


def decode_v2gtp_sdp_request(
    pkt: Packet, header: bytes, payload: bytes
) -> tuple[bytes, bytes, str]:
    """Decode V2GTP SDP request payload type"""
    # TODO: Add decoding of SDP request / or some interpretation of it
    # [0:1] => byte value [0] => otherwise  it's int
    security_byte = payload[0:1]
    transport_proto_byte = payload[1:2]
    decoded_header = "SDP request:\n\t"
    decoded_values = decode_v2gtp_sdp(security_byte, transport_proto_byte)
    decoded = decoded_header + decoded_values
    return header, payload, decoded


def decode_v2gtp_sdp_response(
    pkt: Packet, header: bytes, payload: bytes
) -> tuple[bytes, bytes, str]:
    """Decode V2GTP SDP response payload type"""
    # TODO: Add decoding of SDP response / or some interpretation of it
    ip_address = payload[0:16]
    port = payload[16:18]
    port = int.from_bytes(port, byteorder="big")
    security_byte = payload[18:19]
    transport_proto_byte = payload[19:20]

    decoded_header = "SDP response:\n\t"
    decoded_values = (
        f"IP address: {ip_address.hex()}\n\t"
        f"Port: {port}\n\t"
        f"{decode_v2gtp_sdp(security_byte, transport_proto_byte)}"
    )
    decoded = decoded_header + decoded_values

    return header, payload, decoded


def decode_v2gtp_manufacturer_use(pkt: Packet):
    """Decode V2GTP Manufacturer Specific Use payload type"""
    raise NotImplementedError(
        "Depends on manufacturer docs, so it's not implemented yet! Exiting..."
    )


def decode_v2gtp_reserved(pkt: Packet):
    """Decode V2GTP Reserved payload type"""
    raise NotImplementedError(
        "Reserved payload type by ISO 15118-2:2014, "
        "so it's not implemented yet! Exiting..."
    )


def prn_decode_v2gtp_pkt(pkt: Packet):
    """Method for printing decoded V2GTP packet
    as prn function in scapy sniff function

    Args:
        pkt (Packet): scapy Packet
    """

    logger.debug("prn_decode_v2gtp_pkt function is called!")
    header, payload = parse_v2gtp_pkt(pkt)
    # It means that packet doesn't have v2gtp layer
    if header is None or payload is None:
        logger.debug("Packet doesn't have V2GTP layer!")
        # msg = f"No VTGTP layer for this packet:\n{pkt.summary()}\n"
        # f"{pkt[IPv6].src}:{pkt[TCP]} => {pkt[IPv6].dst}:{pkt[TCP].dport}\n"
        return f"No VTGTP layer for this packet:\n\t{pkt.summary()}\n"

    # TODO: Will be removed once the all decoding methods are implemented
    try:
        decoded = decode_v2gtp_pkt(pkt, payload_type="auto", print_flag=False)
    except Exception as exception:
        logger.warning("Error while decode packet: %s", exception)
        return f"Error while decode packet!:\n\t{pkt.summary()}\n"

    return (
        f"Packet from: {pkt[IPv6].src} to {pkt[IPv6].dst}.\n\t"
        f"V2GTP header: {header.hex()}\n\t"
        f"V2GTP payload: {payload.hex()}\n\t"
        f"Decoded V2GTP packet:\n\t{decoded}\n"
    )


def prn_v2gtp_pkt(pkt: Packet):
    """Methon for printing V2GTP packet as prn function in scapy sniff function

    Method for printing V2GTP packet.
    It will be used as prn function in scapy sniff function.

    Args:
        pkt (Packet): scapy Packet
    """

    header, payload = parse_v2gtp_pkt(pkt)
    # It means that packet doesn't have v2gtp layer
    if header is None or payload is None:
        logger.debug("Packet doesn't have V2GTP layer!")
        return f"No VTGTP layer for this packet:\n\t{pkt.summary()}\n"
    # Differentiate between UDP and TCP, because of ports printing
    if UDP in pkt:
        return (
            f"Packet sent from: "
            f"{pkt[IPv6].src}:{pkt[UDP].sport} => "
            f"{pkt[IPv6].dst}:{pkt[UDP].dport}\n\t"
            f"V2GTP header: {header.hex()}\n\t"
            f"V2GTP payload: {payload.hex()}\n"
        )
    return (
        f"Packet sent from: "
        f"{pkt[IPv6].src}:{pkt[TCP].sport} => "
        f"{pkt[IPv6].dst}:{pkt[TCP].dport}\n\t"
        f"V2GTP header: {header.hex()}\n\t"
        f"V2GTP payload: {payload.hex()}\n"
    )


def decode_v2gtp_pkt(
    pkt, payload_type: str = "auto", print_flag: bool = False
):
    """Decode V2GTP packet as given payload type

    Args:
        pkt (Packet): Packet to decode
        payload_type (str, optional): Payload type to decode. Defaults to "auto".

    """
    header, payload = parse_v2gtp_pkt(pkt)
    if header is None or payload is None:
        logger.warning(
            "Packet doesn't have Raw layer! So, no decoding is possible!"
        )
        return

    data = pkt[Raw].load
    logger.debug("Packet data: %s\n", data)
    logger.debug("Packet data hex(): %s", data.hex())
    logger.debug("V2GTP header: %s", header.hex())
    logger.debug("V2GTP payload: %s", payload.hex())

    if print_flag is True:
        print()
        print("Trying to decode following raw data as V2GTP packet:")
        linehexdump(data)
        print(100 * "-")
        print(prn_v2gtp_pkt(pkt=pkt))

    if payload_type == "auto":
        payload_type = check_v2gtp_payload_types(pkt)
        logger.debug("Payload type: %s", payload_type)

    # Otherwise Pylance will complain about variable is possibly unbound
    decoded = None
    match (payload_type):
        case "exi_message":
            _, _, decoded = decode_v2gtp_exi_msg(
                pkt=pkt, header=header, payload=payload
            )
        case "sdp_request":
            _, _, decoded = decode_v2gtp_sdp_request(
                pkt=pkt, header=header, payload=payload
            )
        case "sdp_response":
            _, _, decoded = decode_v2gtp_sdp_response(
                pkt=pkt, header=header, payload=payload
            )
        case "manufacturer_specific_use":
            decode_v2gtp_manufacturer_use(pkt)
        case "reserved":
            decode_v2gtp_reserved(pkt)
        case _:
            logger.warning("Unknown payload type!")
            raise ValueError("Unknown payload type!")

    if print_flag is True:
        print(
            f"Payload type is: {payload_type}\n"
            f"Decoded V2GTP packet: \n {decoded}"
        )
        print(100 * "-")
    return decoded


def decode_v2gtp_pkt_from_file(file: str, packet_num: int = 0):
    """Decode V2GTP packet from pcap file"""

    if os.path.isfile(file) is False:
        logger.error("File doesn't exist!")
        exit(1)

    packets = rdpcap(file)
    if 0 <= packet_num < len(packets):
        pkt = packets[packet_num]
    else:
        logger.error("Invalid packet number!")
        exit(1)

    decode_v2gtp_pkt(pkt, print_flag=True)


# TODO: Resolve printing of decoded V2GTP packet based on print_flag
def decode_v2gtp_packets(packets, print_flag: bool = False):
    """Decode V2GTP packets"""
    for pkt in packets:
        pkt_num = packets.index(pkt) + 1
        logger.debug(
            "Trying to decode %s. packet(Wireshark numbering style) "
            "as V2GTP packet",
            pkt_num,
        )
        if print_flag is True:
            try:
                decode_v2gtp_pkt(pkt, print_flag=True)
            except Exception as exception:
                logger.warning(
                    "Error while decode packet with number %s: %s",
                    pkt_num,
                    exception,
                )
