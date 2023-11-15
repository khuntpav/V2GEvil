"""Fuzzer classes for Service Detail request and response messages."""

from typing import Optional
import logging

from .fuzz_params import (
    fuzz_response_code,
    fuzz_service_id,
    fuzz_service_parameter_list,
)

from .fuzz_msg_general import general_msg_fuzzing_method

logger = logging.getLogger(__name__)


class FuzzerServiceDetailRes:
    """Fuzzer Class for Service Detail Response message"""

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
            "ServiceID": fuzz_service_id,
            "ServiceParameterList": fuzz_service_parameter_list,
        }
        # Required fields define in the standard
        required_fields = ["ResponseCode", "ServiceID"]

        # All possible fields (required/optional) define in the standard
        all_fields = ["ResponseCode", "ServiceID", "ServiceParameterList"]

        return general_msg_fuzzing_method(
            required_fields=required_fields,
            all_fields=all_fields,
            msg_config=self.msg_config,
            msg_fuzz_dict=self.msg_fuzz_dict,
            msg_default_dict=self.msg_default_dict,
            pairs_name_method=pairs_name_method,
            class_name=self.__class__.__name__,
        )
