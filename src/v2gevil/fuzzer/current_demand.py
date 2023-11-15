"""Fuzzer classes for Current Demand request and response messages."""

from typing import Optional

from .fuzz_params import (
    fuzz_response_code,
    fuzz_dc_evse_status,
    fuzz_evse_present_voltage,
    fuzz_evse_present_current,
    fuzz_evse_current_limit_achieved,
    fuzz_evse_voltage_limit_achieved,
    fuzz_evse_power_limit_achieved,
    fuzz_evse_max_voltage_limit,
    fuzz_evse_max_current_limit,
    fuzz_evse_max_power_limit,
    fuzz_evse_id,
    fuzz_sa_schedule_tuple_id,
    fuzz_meter_info,
    fuzz_receipt_required,
)
from .fuzz_msg_general import general_msg_fuzzing_method


class FuzzerCurrentDemandRes:
    """Fuzzer class for Current Demand response message"""

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
            "EVSEPresentCurrent": fuzz_evse_present_current,
            "EVSECurrentLimitAchieved": fuzz_evse_current_limit_achieved,
            "EVSEVoltageLimitAchieved": fuzz_evse_voltage_limit_achieved,
            "EVSEPowerLimitAchieved": fuzz_evse_power_limit_achieved,
            "EVSEMaximumVoltageLimit": fuzz_evse_max_voltage_limit,
            "EVSEMaximumCurrentLimit": fuzz_evse_max_current_limit,
            "EVSEMaximumPowerLimit": fuzz_evse_max_power_limit,
            "EVSEID": fuzz_evse_id,
            "SAScheduleTupleID": fuzz_sa_schedule_tuple_id,
            "MeterInfo": fuzz_meter_info,
            "ReceiptRequired": fuzz_receipt_required,
        }
        # Required fields define in the standard
        required_fields = [
            "ResponseCode",
            "DC_EVSEStatus",
            "EVSEPresentVoltage",
            "EVSEPresentCurrent",
            "EVSECurrentLimitAchieved",
            "EVSEVoltageLimitAchieved",
            "EVSEPowerLimitAchieved",
            "EVSEID",
            "SAScheduleTupleID",
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
