"""Module for fuzzing different values in the EVSE response messages."""


# TODO: IF user wants runtime generation of messages,
# that messages cannot be in default/fuzzing dict
# have to be remove for dict[req][res]
# this have to be based on config file and mode
# If mode is runtime then it will assing to dict None
# and here will be if None then pop [req][res] from dict

# TODO: Maybe also add to config value = ..., which will override
# the value which is taken from default/fuzzing dict

import logging
from typing import Optional
from enum import Enum
from pathlib import Path
from functools import reduce
import json
import tomli
from ..messages import generator
from ..station.station_enums import EVSEChargingMode, EVSEDetails
from ..station import station
from .fuzzer_enums import EVFuzzMode, MessageName
from .fuzz_params import (
    fuzz_response_code,
    fuzz_evse_id,
    fuzz_evse_timestamp,
    fuzz_service_id,
    fuzz_service_parameter_list,
    fuzz_gen_challenge,
    fuzz_evse_processing,
    fuzz_sa_schedule_list,
    fuzz_ac_evse_charge_parameter,
    fuzz_dc_evse_charge_parameter,
    fuzz_ac_evse_status,
    fuzz_dc_evse_status,
    fuzz_sa_provisioning_certificate_chain,
    fuzz_contract_signature_cert_chain,
    fuzz_contract_signature_encrypted_private_key,
    fuzz_dh_public_key,
    fuzz_emaid,
    fuzz_retry_counter,
    fuzz_sa_schedule_tuple_id,
    fuzz_evse_max_current,
    fuzz_meter_info,
    fuzz_receipt_required,
    fuzz_evse_present_voltage,
    fuzz_evse_present_current,
    fuzz_evse_current_limit_achieved,
    fuzz_evse_voltage_limit_achieved,
    fuzz_evse_power_limit_achieved,
    fuzz_evse_maximum_voltage,
    fuzz_evse_maximum_current,
    fuzz_evse_maximum_power,
)
from .fuzzer_supported_app_protocol import FuzzerSupportedAppProtocolRes
from .session_setup import FuzzerSessionSetupRes
from .service_discovery import FuzzerServiceDiscoveryRes

logger = logging.getLogger(__name__)


class EVFuzzer:
    """EV Fuzzer class.

    This class is used to fuzz EV using the EVSE response messages.

    Attributes:
        default_dict (dict): Dictionary containing all response messages
            for fuzzing. Will not be changed.
        fuzzing_dict (dict): Dictionary containing all response messages
            for fuzzing. Will be changed.
    """

    def __init__(
        self,
        interface: str = EVSEDetails.INTERFACE.value,
        mode: EVFuzzMode = EVFuzzMode.ALL,
        charging_mode: Optional[EVSEChargingMode] = EVSEChargingMode.AC,
        custom_dict_filename: Optional[str] = None,
        config_filename: str = "ev_fuzzer_config_default.toml",
    ):
        logger.debug("Initializing EVFuzzer")
        logger.debug("Charging mode: %s", charging_mode)

        self.default_dict = generator.EVSEMessageGenerator(
            charging_mode=charging_mode
        ).default_dict
        # At the beginning fuzzing_dict is the same as default_dict
        self.fuzzing_dict = self.default_dict
        self.custom_dict_filename = custom_dict_filename

        self.interface = interface
        self.mode = mode
        self.charging_mode = charging_mode
        # TODO: Add loading the config file
        # For messages names and first level parameters it will be
        # handle in this class
        # for parameters in deeper levels it will be handled by methods
        # in fuzz_params.py, it params will be passed as dict to them
        # every method will check if param is in dict and if yes
        # then fuzz it depending on the value for that param in dict
        self.config_filename = config_filename

    # TODO: think about what to fuzz, like what to add to the fuzzing_dict
    def fuzz(self, message_name: str = ""):
        """Fuzz EVSE response messages."""
        # Check which fuzzing mode is selected
        # and call appropriate method
        match self.mode:
            # Fuzz all messages and all possible parameters in messages
            # Fuzzing all, config file or custom dict is NOT used
            # all parameters will be fuzzed, values are random choice
            case EVFuzzMode.ALL:
                self.fuzz_all()
            # For fuzzing use values from custom dictionary
            # This depends only on the provided custom dictionary
            # config file is NOT used
            case EVFuzzMode.CUSTOM:
                self.fuzz_custom()
            # Fuzz only one message, specified by message_name
            # parameters to be fuzzed are chosen based on fuzzer config file
            # This is a combination of user choice and fuzzer config file
            # custom dict is NOT used
            case EVFuzzMode.MESSAGE:
                if message_name == "":
                    logger.error(
                        "Message name is not set. "
                        "Cannot fuzz only one message."
                    )
                    raise ValueError(
                        "Message name is not set. "
                        "Cannot fuzz only one message."
                    )
                self.fuzz_message(message_name=message_name)
            # Which messages and which parameters will be fuzzed depends
            # only on the fuzzer config file
            # custom dict is NOT used
            case EVFuzzMode.CONFIG:
                self.fuzz_config_based()
            case _:
                logger.error("Invalid fuzzing mode: %s", self.mode)
                raise ValueError(f"Invalid fuzzing mode: {self.mode}")

        # TODO: Add method if user wants to fuzz only one parameter in all messages
        # Recursively find all parameters in all messages from default_dict and fuzz them
        # => modify them and replace them in fuzzing_dict

        # For that there is one problem: Not all parameters are set in default_dict
        # but i don't know if it's possible to do with model_json_schema
        # and recursivly iterate over schema and create new message with missing parameter

        # In the end station is started with fuzzing_dict instead of default_dict
        station.start_async(
            interface=self.interface,
            charging_mode=self.charging_mode,
            req_res_map=self.fuzzing_dict,
        )

    def fuzz_all(self):
        """Fuzz all possible messages and all possible parameters in messages."""
        # TODO: Call generator and generate dict for concrete message and
        # replace original one from fuzzing_dict

        # There will be calls for fuzzing methods for each message
        # each fuzzing method will create dict for concrete message
        # then pass to generator and generate new dict for concrete message
        # then replace message in fuzzing_dict with new one

        # If None value is set for params, all possible params will be fuzzed
        self.fuzz_supported_app_protocol_res(msg_config=None)
        self.fuzz_session_setup_res(msg_config=None)
        self.fuzz_service_discovery_res(msg_config=None)
        self.fuzz_service_detail_res(msg_config=None)
        self.fuzz_payment_service_selection_res(msg_config=None)
        self.fuzz_payment_details_res(msg_config=None)
        self.fuzz_authorization_res(msg_config=None)
        self.fuzz_charge_parameter_discovery_res(msg_config=None)
        self.fuzz_power_delivery_res(msg_config=None)
        self.fuzz_metering_receipt_res(msg_config=None)
        self.fuzz_session_stop_res(msg_config=None)
        self.fuzz_certificate_update_res(msg_config=None)
        self.fuzz_certificate_installation_res(msg_config=None)

        # Differ between charging modes
        if self.charging_mode == EVSEChargingMode.AC:
            self.fuzz_charging_status_res(msg_config=None)
        elif self.charging_mode == EVSEChargingMode.DC:
            self.fuzz_cable_check_res(msg_config=None)
            self.fuzz_pre_charge_res(msg_config=None)
            self.fuzz_current_demand_res(msg_config=None)
            self.fuzz_welding_detection_res(msg_config=None)
        else:
            # Should never happen
            logger.error("Invalid charging mode: %s", self.charging_mode)
            raise ValueError(f"Invalid charging mode: {self.charging_mode}")

        # Save custom dict to fuzzing_dict, then return
        # => back to general fuzzing method
        # in general fuzzing methos is the call of station.start_async
        # with fuzzing_dict instead of default_dict

    def fuzz_custom(self):
        """Fuzz messages in fuzzing_dict from custom_dict."""

        # Save custom dict to fuzzing_dict, then return
        # back to general fuzzing method
        self.load_fuzz_dict()
        return

    def fuzz_message(self, message_name: str):
        """Fuzz only specified message in fuzzing_dict. Message is specified by message_name.

        Args:
            message_name (str): Name of message to fuzz.
        """

        # Need conversion to enum, because user input is string
        try:
            message_name = MessageName(message_name)
        except ValueError as exc:
            logger.error("Invalid message name: %s", message_name)
            raise ValueError(f"Invalid message name: {message_name}") from exc

        # Load fuzzer config file in binary mode
        # rb need to be used because of tomli library
        with open(self.config_filename, "rb") as config_file:
            config_data = tomli.load(config_file)

        # Check if message name is in config file
        if message_name not in config_data.keys():
            logger.error(
                "Message name: %s is not in fuzzer config file.", message_name
            )
            logger.error("Fuzzer config file: %s", self.config_filename)
            raise ValueError(
                f"Message name: {message_name} is not in fuzzer config file"
            )

        # Pick only config for specified message
        msg_config = config_data[message_name]

        # Differ in "match case", which fuzz method will be called
        # based on the message name
        match message_name:
            case MessageName.SUPPORTED_APP_PROTOCOL_RES:
                self.fuzz_supported_app_protocol_res(msg_config=msg_config)
            case MessageName.SESSION_SETUP_RES:
                self.fuzz_session_setup_res(msg_config=msg_config)
            case MessageName.SERVICE_DISCOVERY_RES:
                self.fuzz_service_discovery_res(msg_config=msg_config)
            case MessageName.SERVICE_DETAIL_RES:
                self.fuzz_service_detail_res(msg_config=msg_config)
            case MessageName.PAYMENT_SERVICE_SELECTION_RES:
                self.fuzz_payment_service_selection_res(msg_config=msg_config)
            case MessageName.PAYMENT_DETAILS_RES:
                self.fuzz_payment_details_res(msg_config=msg_config)
            case MessageName.AUTHORIZATION_RES:
                self.fuzz_authorization_res(msg_config=msg_config)
            case MessageName.CHARGE_PARAMETER_DISCOVERY_RES:
                self.fuzz_charge_parameter_discovery_res(msg_config=msg_config)
            case MessageName.POWER_DELIVERY_RES:
                self.fuzz_power_delivery_res(msg_config=msg_config)
            case MessageName.METERING_RECEIPT_RES:
                self.fuzz_metering_receipt_res(msg_config=msg_config)
            case MessageName.SESSION_STOP_RES:
                self.fuzz_session_stop_res(msg_config=msg_config)
            case MessageName.CERTIFICATE_UPDATE_RES:
                self.fuzz_certificate_update_res(msg_config=msg_config)
            case MessageName.CERTIFICATE_INSTALLATION_RES:
                self.fuzz_certificate_installation_res(msg_config=msg_config)
            case MessageName.CHARGING_STATUS_RES:
                self.fuzz_charging_status_res(msg_config=msg_config)
            case MessageName.CABLE_CHECK_RES:
                self.fuzz_cable_check_res(msg_config=msg_config)
            case MessageName.PRE_CHARGE_RES:
                self.fuzz_pre_charge_res(msg_config=msg_config)
            case MessageName.CURRENT_DEMAND_RES:
                self.fuzz_current_demand_res(msg_config=msg_config)
            case MessageName.WELDING_DETECTION_RES:
                self.fuzz_welding_detection_res(msg_config=msg_config)
            case _:
                logger.error("Invalid message name: %s", message_name)
                raise ValueError(f"Invalid message name: {message_name}")

    def fuzz_config_based(self):
        """Fuzz messages and parameters in fuzzing_dict based on config file."""
        # Load config file in binary mode
        # rb need to be used because of tomli library
        with open(self.config_filename, "rb") as config_file:
            config_data = tomli.load(config_file)

        # Get all messages names from config file, which should be fuzzed
        message_names = config_data.keys()

        # Pairs message name and fuzzing method
        pairs_message_fuzz_method = {
            MessageName.SUPPORTED_APP_PROTOCOL_RES: self.fuzz_supported_app_protocol_res,
            MessageName.SESSION_SETUP_RES: self.fuzz_session_setup_res,
            MessageName.SERVICE_DISCOVERY_RES: self.fuzz_service_discovery_res,
            MessageName.SERVICE_DETAIL_RES: self.fuzz_service_detail_res,
            MessageName.PAYMENT_SERVICE_SELECTION_RES: self.fuzz_payment_service_selection_res,
            MessageName.PAYMENT_DETAILS_RES: self.fuzz_payment_details_res,
            MessageName.AUTHORIZATION_RES: self.fuzz_authorization_res,
            MessageName.CHARGE_PARAMETER_DISCOVERY_RES: self.fuzz_charge_parameter_discovery_res,
            MessageName.POWER_DELIVERY_RES: self.fuzz_power_delivery_res,
            MessageName.METERING_RECEIPT_RES: self.fuzz_metering_receipt_res,
            MessageName.SESSION_STOP_RES: self.fuzz_session_stop_res,
            MessageName.CERTIFICATE_UPDATE_RES: self.fuzz_certificate_update_res,
            MessageName.CERTIFICATE_INSTALLATION_RES: self.fuzz_certificate_installation_res,
            MessageName.CHARGING_STATUS_RES: self.fuzz_charging_status_res,
            MessageName.CABLE_CHECK_RES: self.fuzz_cable_check_res,
            MessageName.PRE_CHARGE_RES: self.fuzz_pre_charge_res,
            MessageName.CURRENT_DEMAND_RES: self.fuzz_current_demand_res,
            MessageName.WELDING_DETECTION_RES: self.fuzz_welding_detection_res,
        }

        # Iterate over all message names in config file and
        # call appropriate fuzzing method
        for name in message_names:
            # Check if message name is valid
            try:
                name = MessageName(name)
            except ValueError as exc:
                logger.error("Invalid message name: %s in fuzzer config", name)
                raise ValueError(f"Invalid message name: {name}") from exc
            # Call appropriate fuzzing method
            pairs_message_fuzz_method[name](msg_config=config_data[name])

    def fuzz_supported_app_protocol_res(
        self, msg_config: Optional[dict] = None
    ):
        """Fuzz supportedAppProtocolRes message in fuzzing_dict

        Args:
            params (list, optional): List of parameters to fuzz. Defaults to None.
            If None, all parameters will be fuzzed.
                Possible values: SchemaID, ResponseCode
        """
        # self.fuzzing_dict contains all messages
        # pair req and response message {req_name: {res_name: {key: value, key: value, ...}}}
        # => {supportedAppProtocolReq: {supportedAppProtocolRes: {key: value, key: value, ...}}}
        # key is req and value is response dict
        # response dict is {res_name: {key: value, key: value, ...}}
        # It's like this because in create response is also need to know response name
        # because it's needed when Body.model_validate is called
        # => the name of Body attribute is the same as response name
        # but here i need to know only response dict => that's why [req_name][res_name]

        # MODE ALL - all parameters will be fuzzed - msg_config is None
        # Config file is NOT used
        # msg_config is not None for modes: MESSAGE, CONFIG
        # Mode MESSAGE - fuzz only one message params specified in config file
        # Mode CONFIG - fuzz all messages and params specified in config file

        # In dict works without .value
        req_key = MessageName.SUPPORTED_APP_PROTOCOL_REQ
        res_key = MessageName.SUPPORTED_APP_PROTOCOL_RES

        msg_fuzz_dict = self.fuzzing_dict[req_key][res_key]
        # Keep default values for all params in the message
        msg_default_dict = self.default_dict[req_key][res_key]

        msg_fuzzer = FuzzerSupportedAppProtocolRes(
            msg_config=msg_config,
            msg_fuzz_dict=msg_fuzz_dict,
            msg_default_dict=msg_default_dict,
        )

        # Replace message in fuzzing_dict with fuzzed one (msg_dict_to_fuzz)
        self.fuzzing_dict[req_key][res_key] = msg_fuzzer.fuzz()

    def fuzz_session_setup_res(self, msg_config: Optional[dict] = None):
        """Fuzz sessionSetupRes message in fuzzing_dict

        Args:
            params (list, optional): List of parameters to fuzz. Defaults to None.
            If None, all parameters will be fuzzed.
                Possible values: ResponseCode, EVSEID, EVSETimeStamp
        """
        req_key = MessageName.SESSION_SETUP_REQ
        res_key = MessageName.SESSION_SETUP_RES

        msg_dict_to_fuzz = self.fuzzing_dict[req_key][res_key]
        # Keep default values for all params in the message
        msg_default_dict = self.default_dict[req_key][res_key]

        msg_fuzzer = FuzzerSessionSetupRes(
            msg_config=msg_config,
            msg_fuzz_dict=msg_dict_to_fuzz,
            msg_default_dict=msg_default_dict,
        )

        # Replace message in fuzzing_dict with fuzzed one (msg_dict_to_fuzz)
        self.fuzzing_dict[req_key][res_key] = msg_fuzzer.fuzz()

    def fuzz_service_discovery_res(self, msg_config: Optional[dict] = None):
        """Fuzz serviceDiscoveryRes message in fuzzing_dict

        Args:
            params (list, optional): List of parameters to fuzz. Defaults to None.
            If None, all parameters will be fuzzed.
                Possible values: ResponseCode, PaymentOptionList, ChargeService, ServiceList
        """
        req_key = MessageName.SERVICE_DISCOVERY_REQ
        res_key = MessageName.SERVICE_DISCOVERY_RES

        msg_dict_to_fuzz = self.fuzzing_dict[req_key][res_key]
        # Keep default values for all params in the message
        msg_default_dict = self.default_dict[req_key][res_key]

        msg_fuzzer = FuzzerServiceDiscoveryRes(
            msg_config=msg_config,
            msg_fuzz_dict=msg_dict_to_fuzz,
            msg_default_dict=msg_default_dict,
        )

        # Replace message in fuzzing_dict with fuzzed one (msg_dict_to_fuzz)
        self.fuzzing_dict[req_key][res_key] = msg_fuzzer.fuzz()

    def fuzz_service_detail_res(self, msg_config: Optional[dict] = None):
        """Fuzz serviceDetailRes message in fuzzing_dict

        Args:
            params (list, optional): List of parameters to fuzz. Defaults to None.
            If None, all parameters will be fuzzed.
                Possible values: ResponseCode, ServiceID, ServiceParameterList
        """
        req_key = MessageName.SERVICE_DETAIL_REQ
        res_key = MessageName.SERVICE_DETAIL_RES

        msg_dict_to_fuzz = self.fuzzing_dict[req_key][res_key]
        # Keep default values for all params in the message
        msg_default_dict = self.default_dict[req_key][res_key]

        # MODE ALL - all parameters will be fuzzed
        # Config file is NOT used
        if msg_config is None:
            # FUZZ ResponseCode
            # ResponseCode is enum type (in xml schema)
            response_code = fuzz_response_code(mode="random")
            # FUZZ ServiceID
            # ServiceID is type xs:unsignedShort (in xml schema) => 0-65535 (int in python)
            service_id = fuzz_service_id(mode="random")
            # FUZZ ServiceParameterList
            # ServiceParameterList is complexType (in xml schema): ServiceParameterListType
            # TODO: Solved modes {} for all methods with param modes=
            # cause it's need to pass it as {"name1": "random", "name2": "random"}...
            service_parameter_list = fuzz_service_parameter_list(modes={})

        # msg_config is not None for modes: MESSAGE, CONFIG
        # Mode MESSAGE - fuzz only one message params specified in config file
        # Mode CONFIG - fuzz all messages and params specified in config file
        else:
            response_code = fuzz_response_code(
                mode=msg_config["ResponseCode"],
                valid_val=msg_default_dict["ResponseCode"],
            )
            service_id = fuzz_service_id(
                mode=msg_config["ServiceID"],
                valid_val=msg_default_dict["ServiceID"],
            )
            service_parameter_list = fuzz_service_parameter_list(
                modes=msg_config["ServiceParameterList"],
                valid_values=msg_default_dict["ServiceParameterList"],
            )

        # Change values in dict_to_fuzz
        msg_dict_to_fuzz["ResponseCode"] = response_code
        msg_dict_to_fuzz["ServiceID"] = service_id
        msg_dict_to_fuzz["ServiceParameterList"] = service_parameter_list

        # Replace message in fuzzing_dict with fuzzed one (msg_dict_to_fuzz)
        self.fuzzing_dict[req_key][res_key] = msg_dict_to_fuzz

    def fuzz_payment_service_selection_res(
        self, msg_config: Optional[dict] = None
    ):
        """Fuzz paymentServiceSelectionRes message in fuzzing_dict

        Args:
            params (list, optional): List of parameters to fuzz. Defaults to None.
            If None, all parameters will be fuzzed.
                Possible values: ResponseCode
        """
        req_key = MessageName.PAYMENT_SERVICE_SELECTION_REQ
        res_key = MessageName.PAYMENT_SERVICE_SELECTION_RES

        msg_dict_to_fuzz = self.fuzzing_dict[req_key][res_key]
        # Keep default values for all params in the message
        msg_default_dict = self.default_dict[req_key][res_key]

        # MODE ALL - all parameters will be fuzzed
        # Config file is NOT used
        if msg_config is None:
            response_code = fuzz_response_code(mode="random")

        # msg_config is not None for modes: MESSAGE, CONFIG
        # Mode MESSAGE - fuzz only one message params specified in config file
        # Mode CONFIG - fuzz all messages and params specified in config file
        else:
            response_code = fuzz_response_code(
                mode=msg_config["ResponseCode"],
                valid_val=msg_default_dict["ResponseCode"],
            )

        # Change values in dict_to_fuzz
        msg_dict_to_fuzz["ResponseCode"] = response_code

        # Replace message in fuzzing_dict with fuzzed one (msg_dict_to_fuzz)
        self.fuzzing_dict[req_key][res_key] = msg_dict_to_fuzz

    def fuzz_payment_details_res(self, msg_config: Optional[dict] = None):
        """Fuzz paymentDetailRes message in fuzzing_dict

        Args:
            params (list, optional): List of parameters to fuzz. Defaults to None.
            If None, all parameters will be fuzzed.
                Possible values: ResponseCode, GenChallenge, EVSETimeStamp
        """
        req_key = MessageName.PAYMENT_DETAILS_REQ
        res_key = MessageName.PAYMENT_DETAILS_RES

        msg_dict_to_fuzz = self.fuzzing_dict[req_key][res_key]
        # Keep default values for all params in the message
        msg_default_dict = self.default_dict[req_key][res_key]

        # MODE ALL - all parameters will be fuzzed
        # Config file is NOT used
        if msg_config is None:
            # FUZZ ResponseCode
            # ResponseCode is enum type (in xml schema)
            response_code = fuzz_response_code(mode="random")
            # FUZZ GenChallenge
            # GenChallenge is type base64Binary (in xml schema), (length 16)
            # represents Base64-encoded arbitrary binary data
            # Allowed characters are A-Z, a-z, 0-9, +, /, =
            gen_challenge = fuzz_gen_challenge(mode="random")
            # FUZZ EVSETimeStamp
            # EVSETimeStamp is type long (in xml schema)
            # Format is “Unix Time Stamp”
            evse_timestamp = fuzz_evse_timestamp(mode="random")

        # msg_config is not None for modes: MESSAGE, CONFIG
        # Mode MESSAGE - fuzz only one message params specified in config file
        # Mode CONFIG - fuzz all messages and params specified in config file
        else:
            response_code = fuzz_response_code(
                mode=msg_config["ResponseCode"],
                valid_val=msg_default_dict["ResponseCode"],
            )
            gen_challenge = fuzz_gen_challenge(
                mode=msg_config["GenChallenge"],
                valid_val=msg_default_dict["GenChallenge"],
            )
            evse_timestamp = fuzz_evse_timestamp(
                mode=msg_config["EVSETimeStamp"],
                valid_val=msg_default_dict["EVSETimeStamp"],
            )

        # Change values in dict_to_fuzz
        msg_dict_to_fuzz["ResponseCode"] = response_code
        msg_dict_to_fuzz["GenChallenge"] = gen_challenge
        msg_dict_to_fuzz["EVSETimeStamp"] = evse_timestamp

        # Replace message in fuzzing_dict with fuzzed one (msg_dict_to_fuzz)
        self.fuzzing_dict[req_key][res_key] = msg_dict_to_fuzz

    def fuzz_authorization_res(self, msg_config: Optional[dict] = None):
        """Fuzz authorizationRes message in fuzzing_dict

        Args:
            params (list, optional): List of parameters to fuzz. Defaults to None.
            If None, all parameters will be fuzzed.
                Possible values: ResponseCode, EVSEProcessing
        """
        req_key = MessageName.AUTHORIZATION_REQ
        res_key = MessageName.AUTHORIZATION_RES

        msg_dict_to_fuzz = self.fuzzing_dict[req_key][res_key]
        # Keep default values for all params in the message
        msg_default_dict = self.default_dict[req_key][res_key]

        # MODE ALL - all parameters will be fuzzed
        # Config file is NOT used
        if msg_config is None:
            response_code = fuzz_response_code(mode="random")
            evse_processing = fuzz_evse_processing(mode="random")

        # msg_config is not None for modes: MESSAGE, CONFIG
        # Mode MESSAGE - fuzz only one message params specified in config file
        # Mode CONFIG - fuzz all messages and params specified in config file
        else:
            response_code = fuzz_response_code(
                mode=msg_config["ResponseCode"],
                valid_val=msg_default_dict["ResponseCode"],
            )
            evse_processing = fuzz_evse_processing(
                mode=msg_config["EVSEProcessing"],
                valid_val=msg_default_dict["EVSEProcessing"],
            )

        # Change values in dict_to_fuzz
        msg_dict_to_fuzz["ResponseCode"] = response_code
        msg_dict_to_fuzz["EVSEProcessing"] = evse_processing

        # Replace message in fuzzing_dict with fuzzed one (msg_dict_to_fuzz)
        self.fuzzing_dict[req_key][res_key] = msg_dict_to_fuzz

    def fuzz_charge_parameter_discovery_res(
        self, msg_config: Optional[dict] = None
    ):
        """Fuzz chargeParameterDiscoveryRes message in fuzzing_dict

        Args:
            params (list, optional): List of parameters to fuzz. Defaults to None.
            If None, all parameters will be fuzzed.
                Possible values: EVSEProcessing, ResponseCode, SAScheduleList,\
                    AC_EVSEChargeParameter, DC_EVSEChargeParameter\
                    (AC/DC depending on charging mode)
        """
        req_key = MessageName.CHARGE_PARAMETER_DISCOVERY_REQ
        res_key = MessageName.CHARGE_PARAMETER_DISCOVERY_RES

        msg_dict_to_fuzz = self.fuzzing_dict[req_key][res_key]
        # Keep default values for all params in the message
        msg_default_dict = self.default_dict[req_key][res_key]

        # MODE ALL - all parameters will be fuzzed
        # Config file is NOT used

        # TODO: IMPORTANT
        # TODO: Add some check if in modes for that messages
        # param is not in modes and also not in required
        # it will not include it
        # if not in modes but in required it will be fuzzed (with valid value)
        if msg_config is None:
            # FUZZ ResponseCode
            # ResponseCode is enum type (in xml schema)
            response_code = fuzz_response_code(mode="random")
            # FUZZ EVSEProcessing
            # EVSEProcessing is enum type (in xml schema)
            evse_processing = fuzz_evse_processing(mode="random")
            # FUZZ SAScheduleList
            # SAScheduleList is complexType (in xml schema): SAScheduleListType
            sa_schedule_list = fuzz_sa_schedule_list(modes={})
            if self.charging_mode == EVSEChargingMode.AC:
                # FUZZ AC_EVSEChargeParameter
                # AC_EVSEChargeParameter is complexType (in xml schema): AC_EVSEChargeParameterType
                ac_evse_charge_parameter = fuzz_ac_evse_charge_parameter(
                    modes={}
                )
                msg_dict_to_fuzz[
                    "AC_EVSEChargeParameter"
                ] = ac_evse_charge_parameter
            elif self.charging_mode == EVSEChargingMode.DC:
                # FUZZ DC_EVSEChargeParameter
                # DC_EVSEChargeParameter is complexType (in xml schema): DC_EVSEChargeParameterType
                dc_evse_charge_parameter = fuzz_dc_evse_charge_parameter(
                    modes={}
                )
                msg_dict_to_fuzz[
                    "DC_EVSEChargeParameter"
                ] = dc_evse_charge_parameter
            else:
                # Should never happen
                logger.error("Invalid charging mode: %s", self.charging_mode)
                raise ValueError(
                    f"Invalid charging mode: {self.charging_mode}"
                )

        # msg_config is not None for modes: MESSAGE, CONFIG
        # Mode MESSAGE - fuzz only one message params specified in config file
        # Mode CONFIG - fuzz all messages and params specified in config file
        else:
            response_code = fuzz_response_code(
                mode=msg_config["ResponseCode"],
                valid_val=msg_default_dict["ResponseCode"],
            )
            evse_processing = fuzz_evse_processing(
                mode=msg_config["EVSEProcessing"],
                valid_val=msg_default_dict["EVSEProcessing"],
            )
            sa_schedule_list = fuzz_sa_schedule_list(
                modes=msg_config["SAScheduleList"],
                valid_values=msg_default_dict["SAScheduleList"],
            )
            if self.charging_mode == EVSEChargingMode.AC:
                # FUZZ AC_EVSEChargeParameter
                # AC_EVSEChargeParameter is complexType (in xml schema): AC_EVSEChargeParameterType
                ac_evse_charge_parameter = fuzz_ac_evse_charge_parameter(
                    modes=msg_config["AC_EVSEChargeParameter"],
                    valid_values=msg_default_dict["AC_EVSEChargeParameter"],
                )
                msg_dict_to_fuzz[
                    "AC_EVSEChargeParameter"
                ] = ac_evse_charge_parameter
            elif self.charging_mode == EVSEChargingMode.DC:
                # FUZZ DC_EVSEChargeParameter
                # DC_EVSEChargeParameter is complexType (in xml schema): DC_EVSEChargeParameterType
                dc_evse_charge_parameter = fuzz_dc_evse_charge_parameter(
                    modes=msg_config["DC_EVSEChargeParameter"],
                    valid_values=msg_default_dict["DC_EVSEChargeParameter"],
                )
                msg_dict_to_fuzz[
                    "DC_EVSEChargeParameter"
                ] = dc_evse_charge_parameter
            else:
                # Should never happen
                logger.error("Invalid charging mode: %s", self.charging_mode)
                raise ValueError(
                    f"Invalid charging mode: {self.charging_mode}"
                )

        # Change values in dict_to_fuzz
        msg_dict_to_fuzz["ResponseCode"] = response_code
        msg_dict_to_fuzz["EVSEProcessing"] = evse_processing
        msg_dict_to_fuzz["SAScheduleList"] = sa_schedule_list

        # Replace message in fuzzing_dict with fuzzed one (msg_dict_to_fuzz)
        self.fuzzing_dict[req_key][res_key] = msg_dict_to_fuzz

    def fuzz_power_delivery_res(self, msg_config: Optional[dict] = None):
        """Fuzz powerDeliveryRes message in fuzzing_dict

        Args:
            params (list, optional): List of parameters to fuzz. Defaults to None.
            If None, all parameters will be fuzzed.

                Possible values: ResponseCode, AC_EVSEStatus, DC_EVSEStatus\
                    (AC/DC depending on charging mode)
        """
        req_key = MessageName.POWER_DELIVERY_REQ
        res_key = MessageName.POWER_DELIVERY_RES

        msg_dict_to_fuzz = self.fuzzing_dict[req_key][res_key]
        # Keep default values for all params in the message
        msg_default_dict = self.default_dict[req_key][res_key]

        # MODE ALL - all parameters will be fuzzed
        # Config file is NOT used

        # TODO: IMPORTANT
        # TODO: Add some check if in modes for that messages
        # param is not in modes and also not in required
        # it will not include it
        # if not in modes but in required it will be fuzzed (with valid value)
        if msg_config is None:
            # FUZZ ResponseCode
            # ResponseCode is enum type (in xml schema)
            response_code = fuzz_response_code(mode="random")

            if self.charging_mode == EVSEChargingMode.AC:
                # FUZZ AC_EVSEStatus
                # AC_EVSEStatus is complexType (in xml schema): AC_EVSEStatusType
                ac_evse_status = fuzz_ac_evse_status(modes={})
            elif self.charging_mode == EVSEChargingMode.DC:
                # FUZZ DC_EVSEStatus
                # DC_EVSEStatus is complexType (in xml schema): DC_EVSEStatusType
                dc_evse_status = fuzz_dc_evse_status(modes={})
            else:
                # Should never happen
                logger.error("Invalid charging mode: %s", self.charging_mode)
                raise ValueError(
                    f"Invalid charging mode: {self.charging_mode}"
                )

        # msg_config is not None for modes: MESSAGE, CONFIG
        # Mode MESSAGE - fuzz only one message params specified in config file
        # Mode CONFIG - fuzz all messages and params specified in config file
        else:
            response_code = fuzz_response_code(
                mode=msg_config["ResponseCode"],
                valid_val=msg_default_dict["ResponseCode"],
            )

            if self.charging_mode == EVSEChargingMode.AC:
                # FUZZ AC_EVSEStatus
                # AC_EVSEStatus is complexType (in xml schema): AC_EVSEStatusType
                ac_evse_status = fuzz_ac_evse_status(
                    modes=msg_config["AC_EVSEStatus"],
                    valid_values=msg_default_dict["AC_EVSEStatus"],
                )
            elif self.charging_mode == EVSEChargingMode.DC:
                # FUZZ DC_EVSEStatus
                # DC_EVSEStatus is complexType (in xml schema): DC_EVSEStatusType
                dc_evse_status = fuzz_dc_evse_status(
                    modes=msg_config["DC_EVSEStatus"],
                    valid_values=msg_default_dict["DC_EVSEStatus"],
                )
            else:
                # Should never happen
                logger.error("Invalid charging mode: %s", self.charging_mode)
                raise ValueError(
                    f"Invalid charging mode: {self.charging_mode}"
                )

        # Change values in dict_to_fuzz
        msg_dict_to_fuzz["ResponseCode"] = response_code
        # DC_EVSEStatus or AC_EVSEStatus is added to dict_to_fuzz based on charging mode
        # it's above in if/elif/else

        # Replace message in fuzzing_dict with fuzzed one (msg_dict_to_fuzz)
        self.fuzzing_dict[req_key][res_key] = msg_dict_to_fuzz

    def fuzz_certificate_update_res(self, msg_config: Optional[dict] = None):
        """Fuzz certificateUpdateRes message in fuzzing_dict

        Args:
            params (list, optional): List of parameters to fuzz. Defaults to None.
            If None, all parameters will be fuzzed.

                Possible values: ResponseCode, SAProvisioningCertificateChain,\
                ContractSignatureCertChain, ContractSignatureEncryptedPrivateKey,\
                DHpublicKey, eMAID, RetryCounter
        """
        req_key = MessageName.CERTIFICATE_UPDATE_REQ
        res_key = MessageName.CERTIFICATE_UPDATE_RES

        dict_to_fuzz = self.fuzzing_dict[req_key][res_key]

        # FUZZ ResponseCode
        # ResponseCode is enum type (in xml schema)
        response_code = fuzz_response_code()

        # FUZZ SAProvisioningCertificateChain
        # SAProvisioningCertificateChain is type CertificateChainType (in xml schema)
        sa_provisioning_certificate_chain = (
            fuzz_sa_provisioning_certificate_chain()
        )

        # FUZZ ContractSignatureCertChain
        # ContractSignatureCertChain is type CertificateChainType (in xml schema)
        contract_signature_cert_chain = fuzz_contract_signature_cert_chain()

        # FUZZ ContractSignatureEncryptedPrivateKey
        # ContractSignatureEncryptedPrivateKey is ContractSignatureEncryptedPrivateKeyType (in xml schema)
        contract_signature_encrypted_private_key = (
            fuzz_contract_signature_encrypted_private_key()
        )

        # FUZZ DHpublicKey
        # DHpublicKey is DiffieHellmanPublickeyType (in xml schema)
        dh_public_key = fuzz_dh_public_key()

        # FUZZ eMAID
        # eMAID is type EMAIDType (in xml schema)
        emaid = fuzz_emaid()

        # FUZZ RetryCounter
        # RetryCounter is type short (in xml schema) => -32768-32767 (int in python)
        retry_counter = fuzz_retry_counter()

        # TODO

    def fuzz_certificate_installation_res(
        self, msg_config: Optional[dict] = None
    ):
        """Fuzz certificateInstallationRes message in fuzzing_dict

        Args:
            params (list, optional): List of parameters to fuzz. Defaults to None.
            If None, all parameters will be fuzzed.

                Possible values: ResponseCode, SAProvisioningCertificateChain,\
                ContractSignatureCertChain, ContractSignatureEncryptedPrivateKey,\
                DHpublicKey, eMAID
        """
        req_key = MessageName.CERTIFICATE_INSTALLATION_REQ
        res_key = MessageName.CERTIFICATE_INSTALLATION_RES

        dict_to_fuzz = self.fuzzing_dict[req_key][res_key]

        # FUZZ ResponseCode
        # ResponseCode is enum type (in xml schema)
        response_code = fuzz_response_code()

        # FUZZ SAProvisioningCertificateChain
        # SAProvisioningCertificateChain is type CertificateChainType (in xml schema)
        sa_provisioning_certificate_chain = (
            fuzz_sa_provisioning_certificate_chain()
        )

        # FUZZ ContractSignatureCertChain
        # ContractSignatureCertChain is type CertificateChainType (in xml schema)
        contract_signature_cert_chain = fuzz_contract_signature_cert_chain()

        # FUZZ ContractSignatureEncryptedPrivateKey
        # ContractSignatureEncryptedPrivateKey is ContractSignatureEncryptedPrivateKeyType (in xml schema)
        contract_signature_encrypted_private_key = (
            fuzz_contract_signature_encrypted_private_key()
        )

        # FUZZ DHpublicKey
        # DHpublicKey is DiffieHellmanPublickeyType (in xml schema)
        dh_public_key = fuzz_dh_public_key()

        # FUZZ eMAID
        # eMAID is type EMAIDType (in xml schema)
        emaid = fuzz_emaid()

        # TODO

    def fuzz_session_stop_res(self, msg_config: Optional[dict] = None):
        """Fuzz sessionStopRes message in fuzzing_dict

        Args:
            params (list, optional): List of parameters to fuzz. Defaults to None.
            If None, all parameters will be fuzzed.

                Possible values: ResponseCode
        """
        req_key = MessageName.SESSION_STOP_REQ
        res_key = MessageName.SESSION_STOP_RES

        msg_dict_to_fuzz = self.fuzzing_dict[req_key][res_key]
        # Keep default values for all params in the message
        msg_default_dict = self.default_dict[req_key][res_key]

        # MODE ALL - all parameters will be fuzzed
        # Config file is NOT used
        if msg_config is None:
            response_code = fuzz_response_code(mode="random")

        # msg_config is not None for modes: MESSAGE, CONFIG
        # Mode MESSAGE - fuzz only one message params specified in config file
        # Mode CONFIG - fuzz all messages and params specified in config file
        else:
            response_code = fuzz_response_code(
                mode=msg_config["ResponseCode"],
                valid_val=msg_default_dict["ResponseCode"],
            )

        # Change values in dict_to_fuzz
        msg_dict_to_fuzz["ResponseCode"] = response_code

        # Replace message in fuzzing_dict with fuzzed one (msg_dict_to_fuzz)
        self.fuzzing_dict[req_key][res_key] = msg_dict_to_fuzz

    def fuzz_metering_receipt_res(self, msg_config: Optional[dict] = None):
        """Fuzz meteringReceiptRes message in fuzzing_dict

        Args:
            params (list, optional): List of parameters to fuzz. Defaults to None.
            If None, all parameters will be fuzzed.

                Possible values: ResponseCode, AC_EVSEStatus, DC_EVSEStatus\
                    (AC/DC depending on charging mode)
        """
        req_key = MessageName.METERING_RECEIPT_REQ
        res_key = MessageName.METERING_RECEIPT_RES

        msg_dict_to_fuzz = self.fuzzing_dict[req_key][res_key]
        # Keep default values for all params in the message
        msg_default_dict = self.default_dict[req_key][res_key]

        # MODE ALL - all parameters will be fuzzed
        # Config file is NOT used
        if msg_config is None:
            response_code = fuzz_response_code(mode="random")

            # TODO: Implement it as method split for AC/DC, also in other methods
            if self.charging_mode == EVSEChargingMode.AC:
                # FUZZ AC_EVSEStatus
                # AC_EVSEStatus is complexType (in xml schema): AC_EVSEStatusType
                ac_evse_status = fuzz_ac_evse_status(modes={})
                msg_dict_to_fuzz["AC_EVSEStatus"] = ac_evse_status
            elif self.charging_mode == EVSEChargingMode.DC:
                # FUZZ DC_EVSEStatus
                # DC_EVSEStatus is complexType (in xml schema): DC_EVSEStatusType
                dc_evse_status = fuzz_dc_evse_status(modes={})
                msg_dict_to_fuzz["DC_EVSEStatus"] = dc_evse_status

            else:
                # Should never happen
                logger.error("Invalid charging mode: %s", self.charging_mode)
                raise ValueError(
                    f"Invalid charging mode: {self.charging_mode}"
                )

        # msg_config is not None for modes: MESSAGE, CONFIG
        # Mode MESSAGE - fuzz only one message params specified in config file
        # Mode CONFIG - fuzz all messages and params specified in config file
        else:
            # FUZZ ResponseCode
            # ResponseCode is enum type (in xml schema)
            response_code = fuzz_response_code(
                mode=msg_config["ResponseCode"],
                valid_val=msg_default_dict["ResponseCode"],
            )

            if self.charging_mode == EVSEChargingMode.AC:
                # FUZZ AC_EVSEStatus
                # AC_EVSEStatus is complexType (in xml schema): AC_EVSEStatusType
                ac_evse_status = fuzz_ac_evse_status(
                    modes=msg_config["AC_EVSEStatus"],
                    valid_values=msg_default_dict["AC_EVSEStatus"],
                )
                msg_dict_to_fuzz["AC_EVSEStatus"] = ac_evse_status
            elif self.charging_mode == EVSEChargingMode.DC:
                # FUZZ DC_EVSEStatus
                # DC_EVSEStatus is complexType (in xml schema): DC_EVSEStatusType
                dc_evse_status = fuzz_dc_evse_status(
                    modes=msg_config["DC_EVSEStatus"],
                    valid_values=msg_default_dict["DC_EVSEStatus"],
                )
                msg_dict_to_fuzz["DC_EVSEStatus"] = dc_evse_status
            else:
                # Should never happen
                logger.error("Invalid charging mode: %s", self.charging_mode)
                raise ValueError(
                    f"Invalid charging mode: {self.charging_mode}"
                )

        # Change values in dict_to_fuzz
        msg_dict_to_fuzz["ResponseCode"] = response_code
        # DC_EVSEStatus or AC_EVSEStatus is added to dict_to_fuzz based on charging mode
        # it's above in if/elif/else

        self.fuzzing_dict[req_key][res_key] = msg_dict_to_fuzz

    # AC messages START
    def fuzz_charging_status_res(self, msg_config: Optional[dict] = None):
        """Fuzz chargingStatusRes message in fuzzing_dict

        Args:
            params (list, optional): List of parameters to fuzz. Defaults to None.
            If None, all parameters will be fuzzed.

                Possible values: ResponseCode, EVSEID, SAScheduleTupleID,\
                EVSEMaxCurrent, MeterInfo, ReceiptRequired, AC_EVSEStatus
        """
        req_key = MessageName.CHARGING_STATUS_REQ
        res_key = MessageName.CHARGING_STATUS_RES

        msg_dict_to_fuzz = self.fuzzing_dict[req_key][res_key]
        # Keep default values for all params in the message
        msg_default_dict = self.default_dict[req_key][res_key]

        # MODE ALL - all parameters will be fuzzed
        # Config file is NOT used
        if msg_config is None:
            response_code = fuzz_response_code(mode="random")
            # EVSEID is type string (in xml schema), (min length: 7, max length:37)
            evse_id = fuzz_evse_id(mode="random")
            # FUZZ SAScheduleTupleID
            # SAScheduleTupleID is short (in some other message is unsignedByte)
            # => place for mistake in some implementation of this standard
            sa_schedule_tuple_id = fuzz_sa_schedule_tuple_id(mode="random")
            # FUZZ EVSEMaxCurrent
            # EVSEMaxCurrent is complexType (in xml schema): PhysicalValueType
            # Optional parameter
            evse_max_current = fuzz_evse_max_current(modes={})
            # FUZZ MeterInfo
            # MeterInfo is complexType (in xml schema): MeterInfoType
            # Optional parameter
            meter_info = fuzz_meter_info(modes={})
            # FUZZ ReceiptRequired
            # ReceiptRequired is boolean type (in xml schema)
            # Optional parameter
            receipt_required = fuzz_receipt_required(mode="random")
            # FUZZ AC_EVSEStatus
            # AC_EVSEStatus is complexType (in xml schema): AC_EVSEStatusType
            ac_evse_status = fuzz_ac_evse_status(modes={})
        # msg_config is not None for modes: MESSAGE, CONFIG
        # Mode MESSAGE - fuzz only one message params specified in config file
        # Mode CONFIG - fuzz all messages and params specified in config file
        else:
            response_code = fuzz_response_code(
                mode=msg_config["ResponseCode"],
                valid_val=msg_default_dict["ResponseCode"],
            )
            evse_id = fuzz_evse_id(
                mode=msg_config["EVSEID"],
                val_type=msg_config["EVSEID"],
                valid_val=msg_default_dict["EVSEID"],
            )
            sa_schedule_tuple_id = fuzz_sa_schedule_tuple_id(
                mode=msg_config["SAScheduleTupleID"],
                valid_val=msg_default_dict["SAScheduleTupleID"],
            )
            evse_max_current = fuzz_evse_max_current(
                modes=msg_config["EVSEMaxCurrent"],
                valid_values=msg_default_dict["EVSEMaxCurrent"],
            )
            meter_info = fuzz_meter_info(
                modes=msg_config["MeterInfo"],
                valid_values=msg_default_dict["MeterInfo"],
            )
            receipt_required = fuzz_receipt_required(
                mode=msg_config["ReceiptRequired"]
            )
            ac_evse_status = fuzz_ac_evse_status(
                modes=msg_config["AC_EVSEStatus"],
                valid_values=msg_default_dict["AC_EVSEStatus"],
            )

        # Change values in dict_to_fuzz
        msg_dict_to_fuzz["ResponseCode"] = response_code
        msg_dict_to_fuzz["EVSEID"] = evse_id
        msg_dict_to_fuzz["SAScheduleTupleID"] = sa_schedule_tuple_id
        msg_dict_to_fuzz["EVSEMaxCurrent"] = evse_max_current
        msg_dict_to_fuzz["MeterInfo"] = meter_info
        msg_dict_to_fuzz["ReceiptRequired"] = receipt_required
        msg_dict_to_fuzz["AC_EVSEStatus"] = ac_evse_status

        # Replace message in fuzzing_dict with fuzzed one (msg_dict_to_fuzz)
        self.fuzzing_dict[req_key][res_key] = msg_dict_to_fuzz

    # AC messages END
    # DC messages START
    def fuzz_cable_check_res(self, msg_config: Optional[dict] = None):
        """Fuzz cableCheckRes message in fuzzing_dict

        Args:
            params (list, optional): List of parameters to fuzz. Defaults to None.
            If None, all parameters will be fuzzed.

            Possible values:  EVSEProcessing, ResponseCode, DC_EVSEStatus
        """
        req_key = MessageName.CABLE_CHECK_REQ
        res_key = MessageName.CABLE_CHECK_RES

        msg_dict_to_fuzz = self.fuzzing_dict[req_key][res_key]
        # Keep default values for all params in the message
        msg_default_dict = self.default_dict[req_key][res_key]

        # MODE ALL - all parameters will be fuzzed
        # Config file is NOT used
        if msg_config is None:
            # FUZZ EVSEProcessing
            # EVSEProcessing is enum type (in xml schema)
            evse_processing = fuzz_evse_processing(mode="random")

            # FUZZ ResponseCode
            # ResponseCode is enum type (in xml schema)
            response_code = fuzz_response_code(mode="random")

            # FUZZ DC_EVSEStatus
            # DC_EVSEStatus is complexType (in xml schema): DC_EVSEStatusType
            dc_evse_status = fuzz_dc_evse_status(modes={})
        # msg_config is not None for modes: MESSAGE, CONFIG
        # Mode MESSAGE - fuzz only one message params specified in config file
        # Mode CONFIG - fuzz all messages and params specified in config file
        else:
            evse_processing = fuzz_evse_processing(
                mode=msg_config["EVSEProcessing"],
                valid_val=msg_default_dict["EVSEProcessing"],
            )
            response_code = fuzz_response_code(
                mode=msg_config["ResponseCode"],
                valid_val=msg_default_dict["ResponseCode"],
            )
            dc_evse_status = fuzz_dc_evse_status(
                modes=msg_config["DC_EVSEStatus"],
                valid_values=msg_default_dict["DC_EVSEStatus"],
            )

        # Change values in dict_to_fuzz
        msg_dict_to_fuzz["EVSEProcessing"] = evse_processing
        msg_dict_to_fuzz["ResponseCode"] = response_code
        msg_dict_to_fuzz["DC_EVSEStatus"] = dc_evse_status

        # Replace message in fuzzing_dict with fuzzed one (msg_dict_to_fuzz)
        self.fuzzing_dict[req_key][res_key] = msg_dict_to_fuzz

    def fuzz_pre_charge_res(self, msg_config: Optional[dict] = None):
        """Fuzz preChargeRes message in fuzzing_dict

        Args:
            params (list, optional): List of parameters to fuzz. Defaults to None.
            If None, all parameters will be fuzzed.

            Possible values: ResponseCode, DC_EVSEStatus, EVSEPresentVoltage
        """
        req_key = MessageName.PRE_CHARGE_REQ
        res_key = MessageName.PRE_CHARGE_RES

        msg_dict_to_fuzz = self.fuzzing_dict[req_key][res_key]
        # Keep default values for all params in the message
        msg_default_dict = self.default_dict[req_key][res_key]

        # MODE ALL - all parameters will be fuzzed
        # Config file is NOT used
        if msg_config is None:
            # FUZZ ResponseCode
            # ResponseCode is enum type (in xml schema)
            response_code = fuzz_response_code(mode="random")

            # FUZZ DC_EVSEStatus
            # DC_EVSEStatus is complexType (in xml schema): DC_EVSEStatusType
            dc_evse_status = fuzz_dc_evse_status(modes={})

            # FUZZ EVSEPresentVoltage
            # EVSEPresentVoltage is complexType (in xml schema): PhysicalValueType
            evse_present_voltage = fuzz_evse_present_voltage(modes={})

        # msg_config is not None for modes: MESSAGE, CONFIG
        # Mode MESSAGE - fuzz only one message params specified in config file
        # Mode CONFIG - fuzz all messages and params specified in config file
        else:
            response_code = fuzz_response_code(
                mode=msg_config["ResponseCode"],
                valid_val=msg_default_dict["ResponseCode"],
            )
            dc_evse_status = fuzz_dc_evse_status(
                modes=msg_config["DC_EVSEStatus"],
                valid_values=msg_default_dict["DC_EVSEStatus"],
            )
            evse_present_voltage = fuzz_evse_present_voltage(
                modes=msg_config["EVSEPresentVoltage"],
                valid_values=msg_default_dict["EVSEPresentVoltage"],
            )

        # Change values in dict_to_fuzz
        msg_dict_to_fuzz["ResponseCode"] = response_code
        msg_dict_to_fuzz["DC_EVSEStatus"] = dc_evse_status
        msg_dict_to_fuzz["EVSEPresentVoltage"] = evse_present_voltage

        # Replace message in fuzzing_dict with fuzzed one (msg_dict_to_fuzz)
        self.fuzzing_dict[req_key][res_key] = msg_dict_to_fuzz

    def fuzz_current_demand_res(self, msg_config: Optional[dict] = None):
        """Fuzz currentDemandRes message in fuzzing_dict

        Args:
            params (list, optional): List of parameters to fuzz. Defaults to None.
            If None, all parameters will be fuzzed.

            Possible values: ResponseCode, DC_EVSEStatus, EVSEPresentVoltage,\
                EVSEPresentCurrent, EVSECurrentLimitAchieved,\
                EVSEVoltageLimitAchieved, EVSEPowerLimitAchieved,\
                EVSEMaximumVoltage, EVSEMaximumCurrent, EVSEMaximumPower,\
                EVSEID, SAScheduleTupleID, MeterInfo, ReceiptRequired
        """
        req_key = MessageName.CURRENT_DEMAND_REQ
        res_key = MessageName.CURRENT_DEMAND_RES

        msg_dict_to_fuzz = self.fuzzing_dict[req_key][res_key]
        # Keep default values for all params in the message
        msg_default_dict = self.default_dict[req_key][res_key]

        # MODE ALL - all parameters will be fuzzed
        # Config file is NOT used
        if msg_config is None:
            # FUZZ ResponseCode
            # ResponseCode is enum type (in xml schema)
            response_code = fuzz_response_code(mode="random")
            # FUZZ DC_EVSEStatus
            # DC_EVSEStatus is complexType (in xml schema): DC_EVSEStatusType
            dc_evse_status = fuzz_dc_evse_status(modes={})
            # FUZZ EVSEPresentVoltage
            # EVSEPresentVoltage is complexType (in xml schema): PhysicalValueType
            evse_present_voltage = fuzz_evse_present_voltage(modes={})
            # FUZZ EVSEPresentCurrent
            # EVSEPresentCurrent is complexType (in xml schema): PhysicalValueType
            evse_present_current = fuzz_evse_present_current(modes={})
            # FUZZ EVSECurrentLimitAchieved
            # EVSECurrentLimitAchieved is boolean type (in xml schema)
            evse_current_limit_achieved = fuzz_evse_current_limit_achieved(
                mode="random"
            )
            # FUZZ EVSEVoltageLimitAchieved
            # EVSEVoltageLimitAchieved is boolean type (in xml schema)
            evse_voltage_limit_achieved = fuzz_evse_voltage_limit_achieved(
                mode="random"
            )
            # FUZZ EVSEPowerLimitAchieved
            # EVSEPowerLimitAchieved is boolean type (in xml schema)
            evse_power_limit_achieved = fuzz_evse_power_limit_achieved(
                mode="random"
            )
            # FUZZ EVSEMaximumVoltage
            # EVSEMaximumVoltage is complexType (in xml schema): PhysicalValueType
            # Optional parameter
            evse_maximum_voltage = fuzz_evse_maximum_voltage(modes={})
            # FUZZ EVSEMaximumCurrent
            # EVSEMaximumCurrent is complexType (in xml schema): PhysicalValueType
            # Optional parameter
            evse_maximum_current = fuzz_evse_maximum_current(modes={})
            # FUZZ EVSEMaximumPower
            # EVSEMaximumPower is complexType (in xml schema): PhysicalValueType
            # Optional parameter
            evse_maximum_power = fuzz_evse_maximum_power(modes={})
            # FUZZ EVSEID
            # EVSEID is type string (in xml schema), (min length: 7, max length:37)
            # In standard for this message type is: hexBinary max length 32
            # another mistake in standard (previous were string max length 37)
            # every EVSEID defined as simpleType: evseIDType - in schema is string
            # inconsistency in standard
            # If an SECC cannot provide such ID data,
            # the value of the EVSEID is set to zero (00hex).
            evse_id = fuzz_evse_id(mode="random")
            # FUZZ SAScheduleTupleID
            # SAScheduleTupleID is short (in some other message is unsignedByte)
            # => place for mistake in some implementation of this standard
            sa_schedule_tuple_id = fuzz_sa_schedule_tuple_id(mode="random")
            # FUZZ MeterInfo
            # MeterInfo is complexType (in xml schema): MeterInfoType
            # Optional parameter
            meter_info = fuzz_meter_info(modes={})
            # FUZZ ReceiptRequired
            # ReceiptRequired is boolean type (in xml schema)
            # Optional parameter
            receipt_required = fuzz_receipt_required(mode="random")
        # msg_config is not None for modes: MESSAGE, CONFIG
        # Mode MESSAGE - fuzz only one message params specified in config file
        # Mode CONFIG - fuzz all messages and params specified in config file
        else:
            response_code = fuzz_response_code(
                mode=msg_config["ResponseCode"],
                valid_val=msg_default_dict["ResponseCode"],
            )
            dc_evse_status = fuzz_dc_evse_status(
                modes=msg_config["DC_EVSEStatus"],
                valid_values=msg_default_dict["DC_EVSEStatus"],
            )
            evse_present_voltage = fuzz_evse_present_voltage(
                modes=msg_config["EVSEPresentVoltage"],
                valid_values=msg_default_dict["EVSEPresentVoltage"],
            )
            evse_present_current = fuzz_evse_present_current(
                modes=msg_config["EVSEPresentCurrent"],
                valid_values=msg_default_dict["EVSEPresentCurrent"],
            )
            evse_current_limit_achieved = fuzz_evse_current_limit_achieved(
                mode=msg_config["EVSECurrentLimitAchieved"]
            )
            evse_voltage_limit_achieved = fuzz_evse_voltage_limit_achieved(
                mode=msg_config["EVSEVoltageLimitAchieved"]
            )
            evse_power_limit_achieved = fuzz_evse_power_limit_achieved(
                mode=msg_config["EVSEPowerLimitAchieved"]
            )
            evse_maximum_voltage = fuzz_evse_maximum_voltage(
                modes=msg_config["EVSEMaximumVoltage"],
                valid_values=msg_default_dict["EVSEMaximumVoltage"],
            )
            evse_maximum_current = fuzz_evse_maximum_current(
                modes=msg_config["EVSEMaximumCurrent"],
                valid_values=msg_default_dict["EVSEMaximumCurrent"],
            )
            evse_maximum_power = fuzz_evse_maximum_power(
                modes=msg_config["EVSEMaximumPower"],
                valid_values=msg_default_dict["EVSEMaximumPower"],
            )
            evse_id = fuzz_evse_id(
                mode=msg_config["EVSEID"],
                val_type=msg_config["EVSEID"],
                valid_val=msg_default_dict["EVSEID"],
            )
            sa_schedule_tuple_id = fuzz_sa_schedule_tuple_id(
                mode=msg_config["SAScheduleTupleID"],
                valid_val=msg_default_dict["SAScheduleTupleID"],
            )
            meter_info = fuzz_meter_info(
                modes=msg_config["MeterInfo"],
                valid_values=msg_default_dict["MeterInfo"],
            )
            receipt_required = fuzz_receipt_required(
                mode=msg_config["ReceiptRequired"]
            )

        # Change values in dict_to_fuzz
        msg_dict_to_fuzz["ResponseCode"] = response_code
        msg_dict_to_fuzz["DC_EVSEStatus"] = dc_evse_status
        msg_dict_to_fuzz["EVSEPresentVoltage"] = evse_present_voltage
        msg_dict_to_fuzz["EVSEPresentCurrent"] = evse_present_current
        msg_dict_to_fuzz[
            "EVSECurrentLimitAchieved"
        ] = evse_current_limit_achieved
        msg_dict_to_fuzz[
            "EVSEVoltageLimitAchieved"
        ] = evse_voltage_limit_achieved
        msg_dict_to_fuzz["EVSEPowerLimitAchieved"] = evse_power_limit_achieved
        msg_dict_to_fuzz["EVSEMaximumVoltage"] = evse_maximum_voltage
        msg_dict_to_fuzz["EVSEMaximumCurrent"] = evse_maximum_current
        msg_dict_to_fuzz["EVSEMaximumPower"] = evse_maximum_power
        msg_dict_to_fuzz["EVSEID"] = evse_id
        msg_dict_to_fuzz["SAScheduleTupleID"] = sa_schedule_tuple_id
        msg_dict_to_fuzz["MeterInfo"] = meter_info
        msg_dict_to_fuzz["ReceiptRequired"] = receipt_required

        # Replace message in fuzzing_dict with fuzzed one (msg_dict_to_fuzz)
        self.fuzzing_dict[req_key][res_key] = msg_dict_to_fuzz

    def fuzz_welding_detection_res(self, msg_config: Optional[dict] = None):
        """Fuzz weldingDetectionRes message in fuzzing_dict

        Args:
            params (list, optional): List of parameters to fuzz. Defaults to None.
            If None, all parameters will be fuzzed.

            Possible values: ResponseCode, DC_EVSEStatus, EVSEPresentVoltage
        """
        req_key = MessageName.WELDING_DETECTION_REQ
        res_key = MessageName.WELDING_DETECTION_RES

        msg_dict_to_fuzz = self.fuzzing_dict[req_key][res_key]
        # Keep default values for all params in the message
        msg_default_dict = self.default_dict[req_key][res_key]

        # MODE ALL - all parameters will be fuzzed
        # Config file is NOT used
        if msg_config is None:
            # FUZZ ResponseCode
            # ResponseCode is enum type (in xml schema)
            response_code = fuzz_response_code(mode="random")

            # FUZZ DC_EVSEStatus
            # DC_EVSEStatus is complexType (in xml schema): DC_EVSEStatusType
            dc_evse_status = fuzz_dc_evse_status(modes={})

            # FUZZ EVSEPresentVoltage
            # EVSEPresentVoltage is complexType (in xml schema): PhysicalValueType
            evse_present_voltage = fuzz_evse_present_voltage(modes={})
        # msg_config is not None for modes: MESSAGE, CONFIG
        # Mode MESSAGE - fuzz only one message params specified in config file
        # Mode CONFIG - fuzz all messages and params specified in config file
        else:
            response_code = fuzz_response_code(
                mode=msg_config["ResponseCode"],
                valid_val=msg_default_dict["ResponseCode"],
            )
            dc_evse_status = fuzz_dc_evse_status(
                modes=msg_config["DC_EVSEStatus"],
                valid_values=msg_default_dict["DC_EVSEStatus"],
            )
            evse_present_voltage = fuzz_evse_present_voltage(
                modes=msg_config["EVSEPresentVoltage"],
                valid_values=msg_default_dict["EVSEPresentVoltage"],
            )

        # Change values in dict_to_fuzz
        msg_dict_to_fuzz["ResponseCode"] = response_code
        msg_dict_to_fuzz["DC_EVSEStatus"] = dc_evse_status
        msg_dict_to_fuzz["EVSEPresentVoltage"] = evse_present_voltage

        # Replace message in fuzzing_dict with fuzzed one (msg_dict_to_fuzz)
        self.fuzzing_dict[req_key][res_key] = msg_dict_to_fuzz

    # DC messages END

    # TODO find all loading functions from file to dict and replace it
    # with one general function for this purpose

    def load_fuzz_dict(self):
        """Load custom fuzzing dictionary"""
        if self.custom_dict_filename is None:
            logger.error("File for custom dictionary wasn't provided.")
            raise ValueError("Custom fuzzing dictionary is not set.")

        filename = self.custom_dict_filename
        if Path(filename).is_file():
            logger.info("Loading custom dictionary from file: %s", filename)
            # Load file and return dict loaded from file
            with open(filename, "r", encoding="utf-8") as dictionary_file:
                self.fuzzing_dict = json.load(dictionary_file)
                return

        raise FileNotFoundError(
            f"File {filename} does not exist. Cannot load custom dictionary."
        )


# TODO: Implement EVSEFuzzer, not part of the thesis
class EVSEFuzzer:
    """EVSE Fuzzer class.

    This class is used to fuzz EVSE using the EV request messages.
    This class is not implemented yet, because the focus of the thesis
    is to test EV, so fuzzing EVSE is not mandatory.
    """

    def __init__(self):
        raise NotImplementedError()
        self.fuzzing_dict = generator.EVMessageGenerator()
