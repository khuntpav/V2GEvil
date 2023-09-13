"""
Module for V2G message definition
"""
from pydantic import BaseModel, Field
from .MsgHeader import Header
from .MsgBody import Body


class V2GMessage(BaseModel):
    """Base class for V2G messages.

    Attributes:
        header: The header of the V2G message.
        body: The body of the V2G message.
    """

    header: Header = Field(..., alias="Header")
    body: Body = Field(..., alias="Body")
