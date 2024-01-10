"""Fuzzer classes for Power Delivery request and response messages."""

from typing import Optional
import logging

from ..station.station_enums import EVSEChargingMode
from .fuzz_datatypes import (
    fuzz_response_code,
    fuzz_ac_evse_status,
    fuzz_dc_evse_status,
)
from .fuzz_msg_general import general_msg_fuzzing_method


logger = logging.getLogger(__name__)


class FuzzerPowerDeliveryRes:
    """Fuzzer Class for Power Delivery Response message"""

    def __init__(
        self,
        msg_config: Optional[dict] = None,
        msg_fuzz_dict: Optional[dict] = None,
        msg_default_dict: Optional[dict] = None,
        charging_mode: Optional[EVSEChargingMode] = EVSEChargingMode.AC,
    ):
        self.msg_config = msg_config
        self.msg_fuzz_dict = msg_fuzz_dict
        self.msg_default_dict = msg_default_dict
        self.charging_mode = charging_mode

    def fuzz(
        self,
    ) -> dict:
        """Fuzz the message"""

        # Pairs of parameter/field name and fuzzing method
        pairs_name_method = {
            "ResponseCode": fuzz_response_code,
        }
        # Required fields define in the standard
        required_fields = ["ResponseCode"]

        # All possible fields (required/optional) define in the standard
        all_fields = ["ResponseCode"]

        if self.charging_mode == EVSEChargingMode.AC:
            required_fields.append("AC_EVSEStatus")
            all_fields.append("AC_EVSEStatus")
            pairs_name_method["AC_EVSEStatus"] = fuzz_ac_evse_status
        elif self.charging_mode == EVSEChargingMode.DC:
            required_fields.append("DC_EVSEStatus")
            all_fields.append("DC_EVSEStatus")
            pairs_name_method["DC_EVSEStatus"] = fuzz_dc_evse_status
        else:
            # Should never happen
            logger.error("Invalid charging mode: %s", self.charging_mode)
            raise ValueError(f"Invalid charging mode: {self.charging_mode}")

        # Fuzz the message
        return general_msg_fuzzing_method(
            msg_config=self.msg_config,
            msg_fuzz_dict=self.msg_fuzz_dict,
            msg_default_dict=self.msg_default_dict,
            pairs_name_method=pairs_name_method,
            required_fields=required_fields,
            all_fields=all_fields,
            class_name=self.__class__.__name__,
        )
