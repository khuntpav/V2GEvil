"""
Module for V2G message definition
"""
from pydantic import BaseModel, Field, ConfigDict
from .MsgHeader import Header
from .MsgBody import Body


class V2G_Message(BaseModel):
    """Base class for V2G messages.

    Attributes:
        header: The header of the V2G message.
        body: The body of the V2G message.
    """

    header: Header = Field(..., alias="Header")
    body: Body = Field(..., alias="Body")

    def model_dump_with_root(self, **kwargs):
        # Use the model name as the root element
        return {self.__class__.__name__: self.model_dump(**kwargs)}
