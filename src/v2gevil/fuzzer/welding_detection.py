"""Fuzzer classes for Welding Detection request and response messages."""

from typing import Optional

from .fuzz_datatypes import (
    fuzz_response_code,
    fuzz_dc_evse_status,
    fuzz_evse_present_voltage,
)
from .fuzz_msg_general import general_msg_fuzzing_method


class FuzzerWeldingDetectionRes:
    """Fuzzer class for Welding Detection response message"""

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
            "DC_EVSEStatus": fuzz_dc_evse_status,
            "EVSEPresentVoltage": fuzz_evse_present_voltage,
        }
        # Required fields define in the standard
        required_fields = [
            "ResponseCode",
            "DC_EVSEStatus",
            "EVSEPresentVoltage",
        ]

        # All possible fields (required/optional) define in the standard
        all_fields = list(pairs_name_method.keys())

        return general_msg_fuzzing_method(
            msg_config=self.msg_config,
            msg_fuzz_dict=self.msg_fuzz_dict,
            msg_default_dict=self.msg_default_dict,
            pairs_name_method=pairs_name_method,
            required_fields=required_fields,
            all_fields=all_fields,
        )
