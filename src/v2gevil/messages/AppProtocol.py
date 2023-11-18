"""Module for AppProtocol messages.

The implementation is based on ISO 15118-2:2014.
"""

# Pydantic is used for easier dump and load of the messages
# Easy fill objects with data and validate them, also easy to convert to json and then to xml (hopfully)
# Field is used to customize and add metadata to the fields of models

from typing import List
from enum import Enum
from pydantic import BaseModel, Field, ConfigDict


class responseCodeType(str, Enum):
    """Enum responseCodeType.

    Enum for responseCodeType. xs:string in the schema.
    """

    SUCCESS_NEGOTIATION = "OK_SuccessfullNegotiation"
    SUCCESS_MINOR_DEVIATION = "OK_SuccessfullNegotiationMinorDeviation"
    FAILED_NEGOTIATION = "FAILED_Negotiation"


class AppProtocolType(BaseModel):
    """ComlexType AppProtocol.

    Includes the elements ProtocolNamespace, VersionMajor, VersionMinor, SchemaID and Priority.

    Attributes:
        proto_ns: The namespace URI of the specific protocol (protocol name).
        version_major: The major version number of protocol indicated in the ProtocolNamespace.
        version_minor: The minor version number of protocol indicated in the ProtocolNamespace.
        schema_id: This element is used by EVCC to indicate the SchemaID assigned by the EVCC to the protocol.
        priority: This element is used by EVCC to indicate the priority of the protocol.\
            SECC shall select the protocol based on the priority.\
            The highest priority is indicated by the lowest number(1-20).
    """

    model_config = ConfigDict(use_enum_values=True)

    # Three dots (...) means that the field is required and has no default value
    # ProtocolNamespaceType, is xs:anyURI in the schema, max 100 chars
    proto_ns: str = Field(..., alias="ProtocolNamespace")
    version_major: int = Field(..., alias="VersionMajor")
    version_minor: int = Field(..., alias="VersionMinor")
    # idType, is usignsignedByte in the schema
    schema_id: str = Field(..., alias="SchemaID")
    # priorityType, is xs:unsignedByte in the schema, values: 1-20
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

    model_config = ConfigDict(use_enum_values=True)

    # EVCC requests SECC with the list of protocols supported by EVCC.
    # MinOccurs = 1, MaxOccurs = 20
    app_protocol: List[AppProtocolType] = Field(..., alias="AppProtocol")

    @classmethod
    def response_class_name(cls) -> str:
        """Return the name of the request class.

        Returns:
            str: The name of the request class.
        """
        return cls.__name__.replace("Req", "Res")


class supportedAppProtocolRes(BaseModel):
    """Message supportedAppProtocolRes.

    Response message for supportedAppProtocolRes.

    Attributes:
        response_code: The response code to indicate if at least one\
            of the protocols provides by EVCC is supported by the SECC.
        schema_id: SchemaID of the protocol/schema which is agreed\
            as application protocol for the following communication session.\
            SECC shall select from its own list of supported protocols\
            the protocol with highest Priority indicated by the EVCC.

    """

    model_config = ConfigDict(use_enum_values=True)

    response_code: responseCodeType = Field(..., alias="ResponseCode")
    # idType, is usignsignedByte in the schema, minOccur=0
    schema_id: str = Field(default=None, alias="SchemaID")

    @classmethod
    def request_class_name(cls) -> str:
        """Return the name of the request class.

        Returns:
            str: The name of the request class.
        """
        return cls.__name__.replace("Res", "Req")
