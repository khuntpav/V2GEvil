"""Fuzzer classes for Charge Parameter Discovery request and response messages."""

from typing import Optional
import logging

from ..station.station_enums import EVSEChargingMode
from .fuzz_datatypes import (
    fuzz_response_code,
    fuzz_evse_processing,
    fuzz_sa_schedule_list,
    fuzz_ac_evse_charge_parameter,
    fuzz_dc_evse_charge_parameter,
)
from .fuzz_msg_general import general_msg_fuzzing_method


logger = logging.getLogger(__name__)


class FuzzerChargeParameterDiscoveryRes:
    """Fuzzer Class for Charge Parameter Discovery Response message"""

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
            "EVSEProcessing": fuzz_evse_processing,
            "SAScheduleList": fuzz_sa_schedule_list,
        }
        # Required fields define in the standard
        required_fields = ["ResponseCode", "EVSEProcessing"]

        # All possible fields (required/optional) define in the standard
        all_fields = list(pairs_name_method.keys())

        if self.charging_mode == EVSEChargingMode.AC:
            required_fields.append("AC_EVSEChargeParameter")
            all_fields.append("AC_EVSEChargeParameter")
            pairs_name_method[
                "AC_EVSEChargeParameter"
            ] = fuzz_ac_evse_charge_parameter
        elif self.charging_mode == EVSEChargingMode.DC:
            required_fields.append("DC_EVSEChargeParameter")
            all_fields.append("DC_EVSEChargeParameter")
            pairs_name_method[
                "DC_EVSEChargeParameter"
            ] = fuzz_dc_evse_charge_parameter
        else:
            # Should never happen
            logger.error("Invalid charging mode: %s", self.charging_mode)
            raise ValueError(f"Invalid charging mode: {self.charging_mode}")

        return general_msg_fuzzing_method(
            required_fields=required_fields,
            all_fields=all_fields,
            msg_config=self.msg_config,
            msg_fuzz_dict=self.msg_fuzz_dict,
            msg_default_dict=self.msg_default_dict,
            pairs_name_method=pairs_name_method,
            class_name=self.__class__.__name__,
        )
