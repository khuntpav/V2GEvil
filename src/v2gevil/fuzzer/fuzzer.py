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
from pathlib import Path
import json
import tomli
from ..messages import generator
from ..station.station_enums import EVSEChargingMode, EVSEDetails
from ..station import station
from .fuzzer_enums import EVFuzzMode, MessageName
from .fuzz_datatypes import (
    fuzz_response_code,
    fuzz_sa_provisioning_certificate_chain,
    fuzz_contract_signature_cert_chain,
    fuzz_contract_signature_encrypted_private_key,
    fuzz_dh_public_key,
    fuzz_emaid,
    fuzz_retry_counter,
)
from .fuzzer_supported_app_protocol import FuzzerSupportedAppProtocolRes
from .session_setup import FuzzerSessionSetupRes
from .service_discovery import FuzzerServiceDiscoveryRes
from .service_detail import FuzzerServiceDetailRes
from .payment_service_selection import FuzzerPaymentServiceSelectionRes
from .payment_details import FuzzerPaymentDetailsRes
from .authorization import FuzzerAuthorizationRes
from .charge_parameter_discovery import FuzzerChargeParameterDiscoveryRes
from .power_delivery import FuzzerPowerDeliveryRes
from .session_stop import FuzzerSessionStopRes
from .metering_receipt import FuzzerMeteringReceiptRes
from .charging_status import FuzzerChargingStatusRes
from .cable_check import FuzzerCableCheckRes
from .pre_charge import FuzzerPreChargeRes
from .current_demand import FuzzerCurrentDemandRes
from .welding_detection import FuzzerWeldingDetectionRes

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
        self.config_filename = config_filename

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

        # In the end station is started with fuzzing_dict instead of default_dict
        station.start_async(
            interface=self.interface,
            charging_mode=self.charging_mode,
            req_res_map=self.fuzzing_dict,
        )

    def fuzz_all(self):
        """Fuzz all possible messages and all possible parameters in messages."""

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

        msg_fuzzer = FuzzerServiceDetailRes(
            msg_config=msg_config,
            msg_fuzz_dict=msg_dict_to_fuzz,
            msg_default_dict=msg_default_dict,
        )

        # Replace message in fuzzing_dict with fuzzed one (msg_dict_to_fuzz)
        self.fuzzing_dict[req_key][res_key] = msg_fuzzer.fuzz()

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

        msg_fuzzer = FuzzerPaymentServiceSelectionRes(
            msg_config=msg_config,
            msg_fuzz_dict=msg_dict_to_fuzz,
            msg_default_dict=msg_default_dict,
        )

        # Replace message in fuzzing_dict with fuzzed one (msg_dict_to_fuzz)
        self.fuzzing_dict[req_key][res_key] = msg_fuzzer.fuzz()

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

        msg_fuzzer = FuzzerPaymentDetailsRes(
            msg_config=msg_config,
            msg_fuzz_dict=msg_dict_to_fuzz,
            msg_default_dict=msg_default_dict,
        )

        # Replace message in fuzzing_dict with fuzzed one (msg_dict_to_fuzz)
        self.fuzzing_dict[req_key][res_key] = msg_fuzzer.fuzz()

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

        msg_fuzzer = FuzzerAuthorizationRes(
            msg_config=msg_config,
            msg_fuzz_dict=msg_dict_to_fuzz,
            msg_default_dict=msg_default_dict,
        )

        # Replace message in fuzzing_dict with fuzzed one (msg_dict_to_fuzz)
        self.fuzzing_dict[req_key][res_key] = msg_fuzzer.fuzz()

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

        msg_fuzzer = FuzzerChargeParameterDiscoveryRes(
            msg_config=msg_config,
            msg_fuzz_dict=msg_dict_to_fuzz,
            msg_default_dict=msg_default_dict,
            charging_mode=self.charging_mode,
        )

        # Replace message in fuzzing_dict with fuzzed one (msg_dict_to_fuzz)
        self.fuzzing_dict[req_key][res_key] = msg_fuzzer.fuzz()

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

        msg_fuzzer = FuzzerPowerDeliveryRes(
            msg_config=msg_config,
            msg_fuzz_dict=msg_dict_to_fuzz,
            msg_default_dict=msg_default_dict,
            charging_mode=self.charging_mode,
        )

        # Replace message in fuzzing_dict with fuzzed one (msg_dict_to_fuzz)
        self.fuzzing_dict[req_key][res_key] = msg_fuzzer.fuzz()

    # TODO: Implement
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

    # TODO: Implement
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

        msg_fuzzer = FuzzerSessionStopRes(
            msg_config=msg_config,
            msg_fuzz_dict=msg_dict_to_fuzz,
            msg_default_dict=msg_default_dict,
        )

        # Replace message in fuzzing_dict with fuzzed one (msg_dict_to_fuzz)
        self.fuzzing_dict[req_key][res_key] = msg_fuzzer.fuzz()

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

        msg_fuzzer = FuzzerMeteringReceiptRes(
            msg_config=msg_config,
            msg_fuzz_dict=msg_dict_to_fuzz,
            msg_default_dict=msg_default_dict,
            charging_mode=self.charging_mode,
        )

        # Replace message in fuzzing_dict with fuzzed one (msg_dict_to_fuzz)
        self.fuzzing_dict[req_key][res_key] = msg_fuzzer.fuzz()

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

        msg_fuzzer = FuzzerChargingStatusRes(
            msg_config=msg_config,
            msg_fuzz_dict=msg_dict_to_fuzz,
            msg_default_dict=msg_default_dict,
        )

        # Replace message in fuzzing_dict with fuzzed one (msg_dict_to_fuzz)
        self.fuzzing_dict[req_key][res_key] = msg_fuzzer.fuzz()

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

        msg_fuzzer = FuzzerCableCheckRes(
            msg_config=msg_config,
            msg_fuzz_dict=msg_dict_to_fuzz,
            msg_default_dict=msg_default_dict,
        )
        # Replace message in fuzzing_dict with fuzzed one (msg_dict_to_fuzz)
        self.fuzzing_dict[req_key][res_key] = msg_fuzzer.fuzz()

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

        msg_fuzzer = FuzzerPreChargeRes(
            msg_config=msg_config,
            msg_fuzz_dict=msg_dict_to_fuzz,
            msg_default_dict=msg_default_dict,
        )

        # Replace message in fuzzing_dict with fuzzed one
        self.fuzzing_dict[req_key][res_key] = msg_fuzzer.fuzz()

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

        msg_fuzzer = FuzzerCurrentDemandRes(
            msg_config=msg_config,
            msg_fuzz_dict=msg_dict_to_fuzz,
            msg_default_dict=msg_default_dict,
        )

        # Replace message in fuzzing_dict with fuzzed one
        self.fuzzing_dict[req_key][res_key] = msg_fuzzer.fuzz()

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

        msg_fuzzer = FuzzerWeldingDetectionRes(
            msg_config=msg_config,
            msg_fuzz_dict=msg_dict_to_fuzz,
            msg_default_dict=msg_default_dict,
        )

        # Replace message in fuzzing_dict with fuzzed one
        self.fuzzing_dict[req_key][res_key] = msg_fuzzer.fuzz()

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


# Not part of the thesis
class EVSEFuzzer:
    """EVSE Fuzzer class.

    This class is used to fuzz EVSE using the EV request messages.
    This class is not implemented yet, because the focus of the thesis
    is to test EV, so fuzzing EVSE is not mandatory.
    """

    def __init__(self):
        raise NotImplementedError()
        self.fuzzing_dict = generator.EVMessageGenerator()
