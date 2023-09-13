from pydantic import BaseModel, Field


class Header(BaseModel):
    """Base class for V2G message header.

    Attributes:
        session_id: The session ID of the V2G message.
        notification: The notification of the V2G message.
        session_info: The session info of the V2G message.
    """

    session_id: str = Field(..., alias="SessionID")
    # These fields are not required => optional
    # TODO: Maybe use Optional from typing module in combination with Field?
    notification: str = Field(None, alias="Notification")
    session_info: str = Field(None, alias="xmlsig:Signature")
