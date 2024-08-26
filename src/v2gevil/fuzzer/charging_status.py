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

"""Fuzzer classes for Charging Status request and response messages."""

from typing import Optional

from .fuzz_datatypes import (
    fuzz_response_code,
    fuzz_evse_id,
    fuzz_sa_schedule_tuple_id,
    fuzz_evse_max_current,
    fuzz_meter_info,
    fuzz_receipt_required,
    fuzz_ac_evse_status,
)
from .fuzz_msg_general import general_msg_fuzzing_method


class FuzzerChargingStatusRes:
    """Fuzzer Class for Charging Status Response message"""

    def __init__(
        self,
        msg_config: Optional[dict] = None,
        msg_fuzz_dict: Optional[dict] = None,
        msg_default_dict: Optional[dict] = None,
    ):
        self.msg_config = msg_config
        self.msg_fuzz_dict = msg_fuzz_dict
        self.msg_default_dict = msg_default_dict

    def fuzz(
        self,
    ) -> dict:
        """Fuzz the message"""

        # Pairs of parameter/field name and fuzzing method
        pairs_name_method = {
            "ResponseCode": fuzz_response_code,
            "EVSEID": fuzz_evse_id,
            "SAScheduleTupleID": fuzz_sa_schedule_tuple_id,
            "EVSEMaxCurrent": fuzz_evse_max_current,
            "MeterInfo": fuzz_meter_info,
            "ReceiptRequired": fuzz_receipt_required,
            "AC_EVSEStatus": fuzz_ac_evse_status,
        }

        # Required fields define in the standard
        required_fields = [
            "ResponseCode",
            "EVSEID",
            "SAScheduleTupleID",
            "MeterInfo",
            "AC_EVSEStatus",
        ]

        # All possible fields (required/optional) define in the standard
        all_fields = list(pairs_name_method.keys())

        # Call general method for fuzzing message
        return general_msg_fuzzing_method(
            required_fields=required_fields,
            all_fields=all_fields,
            msg_config=self.msg_config,
            msg_fuzz_dict=self.msg_fuzz_dict,
            msg_default_dict=self.msg_default_dict,
            pairs_name_method=pairs_name_method,
            class_name=self.__class__.__name__,
        )
