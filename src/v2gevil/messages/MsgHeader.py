from pydantic import BaseModel, Field
from .MsgDataTypes import NotificationType


class Header(BaseModel):
    """Base class for V2G message header.

    Attributes:
        session_id: The session ID of the V2G message.
        notification: The notification of the V2G message.
        session_info: The session info of the V2G message.
    """

    # To inform Pylance (because of pyright implementation) is need
    # to explicitly type Field(default=None,) instead of Field(None,)
    # if the field is Optional

    # sessionIDType, hexbinary, maxlength 8
    session_id: str = Field(..., alias="SessionID")
    # These fields are not required => optional
    notification: NotificationType = Field(default=None, alias="Notification")
    # TODO: SignatureType is not implemented yet, Test how libs for signing XML works
    # xmlsig does not implement ECDSA, pyXMLSecurity neither
    # Need to implement it by myself => in xmlsig-core-schema.py
    signature: str = Field(default=None, alias="Signature")
