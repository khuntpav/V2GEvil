"""This module contains enums used by the fuzzer program."""
from enum import Enum


class EVFuzzMode(str, Enum):
    """Enum for fuzzing mode"""

    ALL = "all"
    CUSTOM = "custom"
    MESSAGE = "message"
    CONFIG = "config"


class ParamFuzzMode(str, Enum):
    """Enum for parameter fuzzing mode

    Working with these modes will be only in fuzz_param.py methods
    and only in method which fuzzes simple type parameters (like int/string),
    not complex types (like list).
    """

    # Valid => Original value will be used
    # This value should be passed to the fuzzer method as dict
    # taken from the fuzzing dictionary
    VALID = "valid"
    # Value will be chosen from invalud values randomly
    RANDOM = "random"
    # Value will be shorter than min length specified in schema
    SHORT_STRING = "short-string"
    # Value will be longer than max length specified in schema
    LONG_STRING = "long-string"
    # Special string value - randomly chosen from list of bash/python/SQL/Java/
    # and other special characters and strings with special meaning
    SPECIAL_STRING = "special-string"
    # Value will be shorter or longer than min/max length
    STRING = "string"
    # INT is used for all integer numbers (int, long, ...)
    # Value will be under min value specified in schema
    OVER_INT = "over-int"
    # Value will be over max value specified in schema
    UNDER_INT = "under-int"
    # Value will be negative int
    NEGATIVE_INT = "negative-int"
    # Over or under int value - randomly chosen
    INT = "int"
    # FLOAT is used for all floating point numbers (float, double, ...)
    # Value will be under min value specified in schema
    OVER_FLOAT = "over-float"
    # Value will be over max value specified in schema
    UNDER_FLOAT = "under-float"
    # Value will be negative float
    NEGATIVE_FLOAT = "negative-float"
    # Over or under float value - randomly chosen
    FLOAT = "float"
    # TODO: Think about modes for hexBinary and base64Binary
    HEX = "hex"
    # hexBinary value will be shorter than min length specified in schema
    SHORT_HEX = "short-hex"
    # hexBinary value will be longer than max length specified in schema
    LONG_HEX = "long-hex"
    # hexBinary value will special value
    SPECIAL_HEX = "special-hex"
    BASE64 = "base64"
    # base64Binary value will be shorter than min length specified in schema
    SHORT_BASE64 = "short-base64"
    # base64Binary value will be longer than max length specified in schema
    LONG_BASE64 = "long-base64"
    # base64Binary value will special value
    SPECIAL_BASE64 = "special-base64"


class MessageName(str, Enum):
    """Enum for message names"""

    SUPPORTED_APP_PROTOCOL_REQ = "supportedAppProtocolReq"
    SUPPORTED_APP_PROTOCOL_RES = "supportedAppProtocolRes"
    SESSION_SETUP_REQ = "SessionSetupReq"
    SESSION_SETUP_RES = "SessionSetupRes"
    SERVICE_DISCOVERY_REQ = "ServiceDiscoveryReq"
    SERVICE_DISCOVERY_RES = "ServiceDiscoveryRes"
    SERVICE_DETAIL_REQ = "ServiceDetailReq"
    SERVICE_DETAIL_RES = "ServiceDetailRes"
    PAYMENT_SERVICE_SELECTION_REQ = "PaymentServiceSelectionReq"
    PAYMENT_SERVICE_SELECTION_RES = "PaymentServiceSelectionRes"
    PAYMENT_DETAILS_REQ = "PaymentDetailsReq"
    PAYMENT_DETAILS_RES = "PaymentDetailsRes"
    AUTHORIZATION_REQ = "AuthorizationReq"
    AUTHORIZATION_RES = "AuthorizationRes"
    CHARGE_PARAMETER_DISCOVERY_REQ = "ChargeParameterDiscoveryReq"
    CHARGE_PARAMETER_DISCOVERY_RES = "ChargeParameterDiscoveryRes"
    POWER_DELIVERY_REQ = "PowerDeliveryReq"
    POWER_DELIVERY_RES = "PowerDeliveryRes"
    METERING_RECEIPT_REQ = "MeteringReceiptReq"
    METERING_RECEIPT_RES = "MeteringReceiptRes"
    SESSION_STOP_REQ = "SessionStopReq"
    SESSION_STOP_RES = "SessionStopRes"
    CERTIFICATE_UPDATE_REQ = "CertificateUpdateReq"
    CERTIFICATE_UPDATE_RES = "CertificateUpdateRes"
    CERTIFICATE_INSTALLATION_REQ = "CertificateInstallationReq"
    CERTIFICATE_INSTALLATION_RES = "CertificateInstallationRes"
    CHARGING_STATUS_REQ = "ChargingStatusReq"
    CHARGING_STATUS_RES = "ChargingStatusRes"
    CABLE_CHECK_REQ = "CableCheckReq"
    CABLE_CHECK_RES = "CableCheckRes"
    PRE_CHARGE_REQ = "PreChargeReq"
    PRE_CHARGE_RES = "PreChargeRes"
    CURRENT_DEMAND_REQ = "CurrentDemandReq"
    CURRENT_DEMAND_RES = "CurrentDemandRes"
    WELDING_DETECTION_REQ = "WeldingDetectionReq"
    WELDING_DETECTION_RES = "WeldingDetectionRes"
