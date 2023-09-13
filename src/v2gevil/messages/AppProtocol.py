"""Module for AppProtocol messages.

The implementation is based on ISO 15118-2:2014.
"""

# Pydantic is used for easier dump and load of the messages
# Easy fill objects with data and validate them, also easy to convert to json and then to xml (hopfully)
# Field is used to customize and add metadata to the fields of models

from typing import List
from enum import Enum
from pydantic import BaseModel, Field


# TODO: Add information about fields from ISO 15118-2:2014
# like min and max length, max value, min value, etc.
# For all fields in all classes


class ResponseCodeType(str, Enum):
    """Enum ResponseCodeType.

    Enum for ResponseCodeType.
    """

    SUCCESS_NEGOTIATION = "OK_SuccessfullNegotiation"
    SUCCESS_MINOR_DEVIATION = "OK_SuccessfullNegotiationMinorDeviation"
    FAILED_NEGOTIATION = "FAILED_Negotiation"


class AppProtocol(BaseModel):
    """ComlexType AppProtocol.

    Includes the elements ProtocolNamespace, VersionMajor, VersionMinor, SchemaID and Priority.

    Attributes:
        proto_ns: The namespace URI of the specific protocol (protocol name).
        version_major: The major version number of protocol indicated in the ProtocolNamespace.
        version_minor: The minor version number of protocol indicated in the ProtocolNamespace.
        schema_id: This element is used by EVCC to indicate the SchemaID assigned by the EVCC to the protocol.
        priority: This element is used by EVCC to indicate the priority of the protocol. SECC can select the protocol based on the priority.
    """

    # Three dots (...) means that the field is required and has no default value
    proto_ns: str = Field(..., alias="ProtocolNamespace")
    version_major: int = Field(..., alias="VersionMajor")
    version_minor: int = Field(..., alias="VersionMinor")
    schema_id: int = Field(..., alias="SchemaID")
    priority: int = Field(..., alias="Priority")


# lower case first letter in schemas... only for the req and res messages
# another types of messages are with PascalCase
class supportedAppProtocolReq(BaseModel):
    """Message supportedAppProtocolReq.

    Request message for supportedAppProtocolReq.

    Attributes:
        app_protocol: The AppProtocol element contains the information about the protocol supported by the EVCC.
            The AppProtocol element is a complex type that contains the elements ProtocolNamespace, VersionMajor, VersionMinor, SchemaID and Priority.
    """

    # EVCC requests SECC with the list of protocols supported by EVCC.
    app_protocol: List[AppProtocol] = Field(..., alias="AppProtocol")


class supportedAppProtocolRes(BaseModel):
    """Message supportedAppProtocolRes.

    Response message for supportedAppProtocolRes.

    Attributes:
        response_code: The response code to indicate if at least one of the protocols provides by EVCC is supported by the SECC.

    """

    response_code: ResponseCodeType = Field(..., alias="ResponseCode")
    schema_id: str = Field(None, alias="SchemaID")
