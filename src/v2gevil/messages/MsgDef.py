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
