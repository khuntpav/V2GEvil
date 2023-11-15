"""This module contains methods for fuzzing specifig parameters,
which are used by the fuzzer program."""

import random
import logging
from typing import Optional, Union
from ..messages.MsgDataTypes import (
    responseCodeType,
    unitSymbolType,
    serviceCategoryType,
    paymentOptionType,
    EnergyTransferModeType,
    EVSEProcessingType,
    costKindType,
    EVSENotificationType,
    isolationLevelType,
    DC_EVSEStatusCodeType,
)
from .fuzzer_enums import ParamFuzzMode
from .fuzz_types import (
    gen_random_string,
    gen_num,
    gen_invalid_bool,
    gen_invalid_byte,
    gen_invalid_short,
    gen_invalid_unsigned_short,
    gen_invalid_int,
    gen_invalid_unsigned_int,
    gen_invalid_long,
    gen_invalid_unsigned_long,
    gen_invalid_unsigned_byte,
    gen_invalid_string,
    gen_malicous_string,
    gen_invalid_base64_binary,
    gen_malicous_base64,
    gen_invalid_hex_binary,
    gen_malicous_hex,
    gen_invalid_id,
)

logger = logging.getLogger(__name__)


def fuzz_schema_id(
    attr_conf: Optional[dict] = None, valid_values: Optional[int] = None
) -> Union[str, int, float]:
    """Fuzz schema id

    SchemaID is xs:unsignedByte, so valid value is in range 0-255.
    Fuzzer should test values out of range, for example -1, 256,
    or string instead of number.

    Relevant modes: random, string, int, over-int,
        under-int, float, over-float, under-float
    """
    # TODO: IMPORTANT
    # This is end parameter, so there is no passing None/{} to each sub parameter

    # If attr_conf is None => fuzz with random mode
    # if attr_conf is None:
    #     attr_conf = {"Mode": "random"}
    # else:
    #     # attr_conf is not None and attr_conf is empty dict
    #     if not attr_conf:

    # In complex params will be attr_conf dict
    # required_fields =
    # all_fields =
    # if attr_conf is None:
    #     attr_conf = {}
    #     for field in all_fields:
    #         attr_conf[field] = None
    # else:
    #     # attr_conf is empty => pass to all required fields {}
    #     # => fuzz with random mode for end parameter
    #     # {} means random mode for every required field/parameter
    #     if not attr_conf:
    #         for field in required_fields:
    #             attr_conf[field] = {}
    #     else:
    #         # Field is in required_fields
    #         # but user didn't specify mode => pass {} to each parameter
    #         # => fuzz with random mode for end parameter
    #         # So not specified parameter will be fuzzed with random mode
    #         for field in required_fields:
    #             if field not in msg_config:
    #                 msg_config[field] = {}

    # Convert mode to enum
    try:
        mode = ParamFuzzMode(attr_conf["Mode"])
    except ValueError:
        logger.warning(
            "Invalid fuzzing mode. Using random mode for schemaID fuzzing."
        )
        mode = ParamFuzzMode.RANDOM

    return gen_invalid_unsigned_byte(mode=mode, valid_val=valid_values)


def fuzz_response_code(
    mode: str = "valid", valid_val: Optional[str] = None
) -> Union[str, int, float]:
    """Fuzz response code

    ResponseCode is enum, so valid value is one of the enum values responseCodeType.
    Type responseCodeType is in MsgDataTypes.py.
    Fuzzer should test values out of enum values.

    Relevant modes: random, string, special-string,
        int, negative-int, float, negative-float
    """
    # Convert mode to enum
    try:
        mode = ParamFuzzMode(mode)
    except ValueError:
        logger.warning(
            "Invalid fuzzing mode. Using random mode for ResponseCode fuzzing."
        )
        mode = ParamFuzzMode.RANDOM

    match mode:
        case ParamFuzzMode.VALID:
            if valid_val is None:
                logger.warning(
                    "No valid value specified for ResponseCode, "
                    "using default valid value randomly chosen from "
                    "responseCodeType enum."
                )
                return random.choice(list(responseCodeType)).value
            return valid_val
        case ParamFuzzMode.STRING:
            return gen_random_string(random.randint(1, 100))
        case ParamFuzzMode.SPECIAL_STRING:
            # TODO: Add some valid value at the start and append invalid chars to it
            # like responseCodeType.OK.value + r"!@*!*@#" or something like that
            # malicious_string = gen_malicous_string()
            # invalid_enum = (
            #    random.choice(list(responseCodeType)).value + malicious_string
            # )
            return gen_malicous_string()
        case ParamFuzzMode.INT:
            return gen_num()
        case ParamFuzzMode.NEGATIVE_INT:
            return gen_num(negative_flag=True)
        case ParamFuzzMode.FLOAT:
            return gen_num(float_flag=True)
        case ParamFuzzMode.NEGATIVE_FLOAT:
            return gen_num(float_flag=True, negative_flag=True)
        case _:
            if mode is not ParamFuzzMode.RANDOM:
                logger.warning(
                    "Invalid fuzzing mode for parameter with type "
                    "responseCodeType, using random mode."
                )
            invalid_string = gen_random_string(random.randint(1, 100))
            invalid_num = gen_num()
            invalid_neg_num = gen_num(negative_flag=True)
            invalid_float_num = gen_num(float_flag=True)
            invalid_neg_float_num = gen_num(
                float_flag=True, negative_flag=True
            )
            return random.choice(
                [
                    invalid_string,
                    invalid_num,
                    invalid_neg_num,
                    invalid_float_num,
                    invalid_neg_float_num,
                ]
            )


def fuzz_evse_id(
    mode: str = "valid",
    val_type: str = "string",
    valid_val: Optional[str] = None,
) -> Union[str, int, float]:
    """Fuzz evse id

    Inconsistency in the standard. In some messages is EVSEID xs:string
    and in some messages is EVSEID xs:hexBinary.

    EVSEID is type xs:string (in xml schema), (min length: 7, max length:37).
    If an SECC cannot provide such ID data,
    the value of the EVSEID is set to zero ("ZZ00000").
    The above definition is in SessionSetupRes, ChargingStatusRes.

    EVSEID is type: xs:hexBinary, max length 32. (in CurrendDemandRes message).
    If an SECC cannot provide such ID data,
    the value of the EVSEID is set to zero (00hex).

    Args:
        val_type (str): Type of EVSEID. Valid values: string, hexBinary.
            Differ between EVSEID type string and hexBinary based on message.
        mode: Fuzzing mode for EVSEID.
            Relevant modes: random, string, int, negative-int, float,
            negative-float, short-string, long-string, special-string,
            long-hex, special-hex.
            The modes with hex in name are only for EVSEID type hexBinary, but
            if user specify these modes for EVSEID type string, fuzzer will use
            them.
    """

    # Convert mode to enum
    try:
        mode = ParamFuzzMode(mode)
    except ValueError:
        logger.warning(
            "Invalid fuzzing mode. Using random mode for EVSEID fuzzing."
        )
        mode = ParamFuzzMode.RANDOM

    match mode:
        case ParamFuzzMode.VALID:
            if valid_val is None:
                # EVSEID type string
                if val_type == "string":
                    logger.warning(
                        "No valid value specified for EVSEID, "
                        "using default valid value from standard."
                    )
                    return "ZZ00000"
                # EVSEID type hexBinary
                logger.warning(
                    "No valid value specified for EVSEID, "
                    "using default valid value from standard."
                )
                return "00"
            return valid_val
        case ParamFuzzMode.STRING:
            # Length is valid for EVSEID type xs:string
            return gen_random_string(random.randint(7, 37))
        case ParamFuzzMode.SHORT_STRING:
            # Length is randomly chosen from 1-6 (min length is 7)
            return gen_random_string(random.randint(1, 6))
        case ParamFuzzMode.LONG_STRING:
            # Length is randomly chosen from 38-100 (max length is 37)
            return gen_random_string(random.randint(38, 100))
        case ParamFuzzMode.SPECIAL_STRING:
            return gen_malicous_string()
        case ParamFuzzMode.HEX:
            # Length is valid for EVSEID type xs:hexBinary
            return gen_invalid_hex_binary(random.randint(1, 32))
        case ParamFuzzMode.LONG_HEX:
            # valid max length is 32, method will gen > 32 + 1
            return gen_invalid_hex_binary(max_length=32)
        case ParamFuzzMode.SPECIAL_HEX:
            return gen_malicous_hex()
        case ParamFuzzMode.INT:
            return gen_num()
        case ParamFuzzMode.NEGATIVE_INT:
            return gen_num(negative_flag=True)
        case ParamFuzzMode.FLOAT:
            return gen_num(float_flag=True)
        case ParamFuzzMode.NEGATIVE_FLOAT:
            return gen_num(float_flag=True, negative_flag=True)
        case _:
            if mode is not ParamFuzzMode.RANDOM:
                logger.warning(
                    "Invalid fuzzing mode for parameter EVSEID with type "
                    "xs:string or xs:hexBinary, using random mode."
                )
            invalid_values = []
            invalid_num = gen_num()
            invalid_neg_num = gen_num(negative_flag=True)
            invalid_float_num = gen_num(float_flag=True)
            invalid_neg_float_num = gen_num(
                float_flag=True, negative_flag=True
            )
            invalid_values.append(invalid_num)
            invalid_values.append(invalid_neg_num)
            invalid_values.append(invalid_float_num)
            invalid_values.append(invalid_neg_float_num)

            if val_type == "string":
                invalid_string_shorter = gen_random_string(
                    random.randint(1, 6)
                )
                invalid_string_longer = gen_random_string(
                    random.randint(38, 100)
                )
                invalid_values.append(invalid_string_shorter)
                invalid_values.append(invalid_string_longer)
            else:
                # No restriction for min length for hexBinary only for max
                # Max length for hexBinary is 32
                invalid_hex_longer = gen_invalid_hex_binary(max_length=32)
                invalid_values.append(invalid_hex_longer)

            special_string = gen_malicous_string()
            invalid_values.append(special_string)
            special_hex = gen_malicous_hex()
            invalid_values.append(special_hex)

            return random.choice(invalid_values)


def fuzz_evse_timestamp(
    mode: str = "valid", valid_val: Optional[int] = None
) -> Union[str, int, float]:
    """Fuzz evse timestamp

    Valid value is Unix timestamp, xs:long.
    The value can be -9223372036854775808 to 9223372036854775807 for xs:long.

    For Unix timestamp negative value makes no sense, so fuzzer should test it.

    Args:
        mode: Fuzzing mode for EVSETimestamp.
            Relevant modes: random, float, under-float, over-float,
            under-int, over-int, string, special-string,
    """
    # Coverting mode to enum
    try:
        mode = ParamFuzzMode(mode)
    except ValueError:
        logger.warning(
            "Invalid fuzzing mode. Using random mode for EVSETimestamp fuzzing."
        )
        mode = ParamFuzzMode.RANDOM

    return gen_invalid_long(mode=mode, valid_val=valid_val)


# TODO: For complexType, create fuzz method for each element
# => for every simpleType create fuzz method
# This can be a hack for fuzzing only specific elements of complexType
# can be used like accepting names of elements as parameters
# and based on that fuzz only specific elements


def fuzz_payment_option(mode: str = "valid", valid_val: Optional[str] = None):
    """Fuzz payment option.

    PaymentOption is list of enum values.
    Valid values are defined in paymentOptionType enum:
        Contract, ExternalPayment
    """
    # Convert mode to enum
    try:
        mode = ParamFuzzMode(mode)
    except ValueError:
        logger.warning(
            "Invalid fuzzing mode. Using random mode for PaymentOption fuzzing."
        )
        mode = ParamFuzzMode.RANDOM

    match mode:
        case ParamFuzzMode.VALID:
            if valid_val is None:
                logger.warning(
                    "No valid value specified for PaymentOption, "
                    "using default valid value randomly chosen from "
                    "paymentOptionType enum."
                )
                return random.choice(list(paymentOptionType)).value
            return valid_val
        case ParamFuzzMode.STRING:
            return gen_random_string(random.randint(1, 100))
        case ParamFuzzMode.SPECIAL_STRING:
            return gen_malicous_string()
        case ParamFuzzMode.INT:
            return gen_num()
        case ParamFuzzMode.NEGATIVE_INT:
            return gen_num(negative_flag=True)
        case ParamFuzzMode.FLOAT:
            return gen_num(float_flag=True)
        case ParamFuzzMode.NEGATIVE_FLOAT:
            return gen_num(float_flag=True, negative_flag=True)
        case _:
            if mode is not ParamFuzzMode.RANDOM:
                logger.warning(
                    "Invalid fuzzing mode for parameter with type "
                    "paymentOptionType, using random mode."
                )
            invalid_string = gen_random_string(random.randint(1, 100))
            special_string = gen_malicous_string()
            invalid_num = gen_num()
            invalid_neg_num = gen_num(negative_flag=True)
            invalid_float_num = gen_num(float_flag=True)
            invalid_neg_float_num = gen_num(
                float_flag=True, negative_flag=True
            )

            return random.choice(
                [
                    invalid_string,
                    special_string,
                    invalid_num,
                    invalid_neg_num,
                    invalid_float_num,
                    invalid_neg_float_num,
                ]
            )


# Here is not mode, but modes, because keep of consistency with other methods
def fuzz_payment_option_list(
    modes: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz payment option list"""

    if valid_values is None:
        valid_values = {}

    if modes is None:
        modes = {}
    # Here is because of keep consistency with other methods for complexTypes
    for name in ["PaymentOption"]:
        # Attribute is not specified in config dict => don't fuzz it
        # => valid mode
        if name not in modes:
            modes[name] = ParamFuzzMode.VALID.value
        if name not in valid_values:
            valid_values[name] = None

    payment_option = fuzz_payment_option(
        modes["PaymentOption"], valid_val=valid_values["PaymentOption"]
    )
    return {"PaymentOption": payment_option}


def fuzz_energy_transfer_mode(
    mode: str = "valid", valid_val: Optional[str] = None
):
    """Fuzz energy transfer mode.

    EnergyTransferMode enum values.
    """
    # Conver mode to enum
    try:
        mode = ParamFuzzMode(mode)
    except ValueError:
        logger.warning(
            "Invalid fuzzing mode. Using random mode for EnergyTransferMode fuzzing."
        )
        mode = ParamFuzzMode.RANDOM

    match mode:
        case ParamFuzzMode.VALID:
            if valid_val is None:
                logger.warning(
                    "No valid value specified for EnergyTransferMode, "
                    "using default valid value randomly chosen from "
                    "energyTransferModeType enum."
                )
                return random.choice(list(EnergyTransferModeType)).value
            return valid_val
        case ParamFuzzMode.STRING:
            return gen_random_string(random.randint(1, 100))
        case ParamFuzzMode.SPECIAL_STRING:
            return gen_malicous_string()
        case ParamFuzzMode.INT:
            return gen_num()
        case ParamFuzzMode.NEGATIVE_INT:
            return gen_num(negative_flag=True)
        case ParamFuzzMode.FLOAT:
            return gen_num(float_flag=True)
        case ParamFuzzMode.NEGATIVE_FLOAT:
            return gen_num(float_flag=True, negative_flag=True)
        case _:
            if mode is not ParamFuzzMode.RANDOM:
                logger.warning(
                    "Invalid fuzzing mode for parameter with type "
                    "energyTransferModeType, using random mode."
                )
            invalid_string = gen_random_string(random.randint(1, 100))
            special_string = gen_malicous_string()
            invalid_num = gen_num()
            invalid_neg_num = gen_num(negative_flag=True)
            invalid_float_num = gen_num(float_flag=True)
            invalid_neg_float_num = gen_num(
                float_flag=True, negative_flag=True
            )

            return random.choice(
                [
                    invalid_string,
                    special_string,
                    invalid_num,
                    invalid_neg_num,
                    invalid_float_num,
                    invalid_neg_float_num,
                ]
            )


def fuzz_supported_energy_transfer_mode(
    modes: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz supported energy transfer mode"""

    if valid_values is None:
        valid_values = {}
    if modes is None:
        modes = {}

    # Here is because of keep consistency with other methods for complexTypes
    for name in ["EnergyTransferMode"]:
        # Attribute is not specified in config dict => don't fuzz it
        # => valid mode
        if name not in modes:
            modes[name] = ParamFuzzMode.VALID.value
        if name not in valid_values:
            valid_values[name] = None

    energy_transfered_mode = [
        fuzz_energy_transfer_mode(
            mode=modes["EnergyTransferMode"],
            valid_val=valid_values["EnergyTransferMode"],
        )
    ]

    return {"EnergyTransferMode": energy_transfered_mode}


def fuzz_charge_service(
    modes: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz charge service

    ChargeService is extension of ServiceType and combine with
    SupportedEnergyTransferModeType.
    """
    if valid_values is None:
        valid_values = {}
    if modes is None:
        modes = {}

    # Here is because of keep consistency with other methods for complexTypes
    # ServiceType attributes are iterated in fuzz_service method
    for name in ["SupportedEnergyTransferMode"]:
        # Attribute is not specified in config dict => don't fuzz it
        # => valid mode
        if name not in modes:
            modes[name] = ParamFuzzMode.VALID.value
        if name not in valid_values:
            valid_values[name] = None

    service_dict = fuzz_service(modes, valid_values)
    supported_energy_transfer_mode = fuzz_supported_energy_transfer_mode(
        modes["SupportedEnergyTransferMode"],
        valid_values["SupportedEnergyTransferMode"],
    )
    # **service_dict unpacks service_dict
    return {
        **service_dict,
        "SupportedEnergyTransferMode": supported_energy_transfer_mode,
    }


def fuzz_service_id(
    mode: str = "valid", valid_val: Optional[int] = None
) -> Union[str, int, float]:
    """Fuzz service id

    ServiceID is type xs:unsignedShort (in xml schema), so valid values: 0-65535.
    """
    # Convert mode to enum
    try:
        mode = ParamFuzzMode(mode)
    except ValueError:
        logger.warning(
            "Invalid fuzzing mode. Using random mode for ServiceID fuzzing."
        )
        mode = ParamFuzzMode.RANDOM

    return gen_invalid_unsigned_short(mode=mode, valid_val=valid_val)


def fuzz_service_name(
    mode: str = "valid", valid_val: Optional[str] = None
) -> Union[str, int, float]:
    """Fuzz service name

    ServiceName is type xs:string (in xml schema), (maxLength: 32).
    """
    # Convert mode to enum
    try:
        mode = ParamFuzzMode(mode)
    except ValueError:
        logger.warning(
            "Invalid fuzzing mode. Using random mode for ServiceName fuzzing."
        )
        mode = ParamFuzzMode.RANDOM

    match mode:
        case ParamFuzzMode.VALID:
            if valid_val is None:
                logger.warning(
                    "No valid value specified for ServiceName, "
                    "using default valid value randomly generated."
                    "Disclaimer: Generated value - meets the conditions for "
                    "length and type but may not meet the valid "
                    "value for particular parameter."
                )
                return gen_random_string(random.randint(1, 32))
            return valid_val

        case ParamFuzzMode.LONG_STRING:
            return gen_random_string(random.randint(33, 100))
        case ParamFuzzMode.SPECIAL_STRING:
            return gen_malicous_string()
        case ParamFuzzMode.INT:
            return gen_num()
        case ParamFuzzMode.NEGATIVE_INT:
            return gen_num(negative_flag=True)
        case ParamFuzzMode.FLOAT:
            return gen_num(float_flag=True)
        case ParamFuzzMode.NEGATIVE_FLOAT:
            return gen_num(float_flag=True, negative_flag=True)
        case _:
            if mode is not ParamFuzzMode.RANDOM:
                logger.warning(
                    "Invalid fuzzing mode for parameter with type "
                    "xs:string, using random mode."
                )
            invalid_string = gen_random_string(random.randint(33, 100))
            invalid_special_string = gen_malicous_string()
            invalid_num = gen_num()
            invalid_neg_num = gen_num(negative_flag=True)
            invalid_float_num = gen_num(float_flag=True)
            invalid_neg_float_num = gen_num(
                negative_flag=True, float_flag=True
            )

            return random.choice(
                [
                    invalid_string,
                    invalid_special_string,
                    invalid_num,
                    invalid_neg_num,
                    invalid_float_num,
                    invalid_neg_float_num,
                ]
            )


def fuzz_service_category(
    mode: str = "valid", valid_val: Optional[str] = None
) -> Union[str, int, float]:
    """Fuzz service category

    ServiceCategory is type serviceCategoryType,
    xs:string, enum, valid values are:
        EVCharging, Internet, ContractCertificate, OtherCustom
    """
    # Convert mode to enum
    try:
        mode = ParamFuzzMode(mode)
    except ValueError:
        logger.warning(
            "Invalid fuzzing mode. Using random mode for ServiceCategory fuzzing."
        )
        mode = ParamFuzzMode.RANDOM

    match mode:
        case ParamFuzzMode.VALID:
            if valid_val is None:
                logger.warning(
                    "No valid value specified for ServiceCategory, "
                    "using default valid value randomly chosen from "
                    "serviceCategoryType enum."
                )
                return random.choice(list(serviceCategoryType)).value

            return valid_val
        case ParamFuzzMode.STRING:
            return gen_random_string(random.randint(1, 100))
        case ParamFuzzMode.SPECIAL_STRING:
            return gen_malicous_string()
        case ParamFuzzMode.INT:
            return gen_num()
        case ParamFuzzMode.NEGATIVE_INT:
            return gen_num(negative_flag=True)
        case ParamFuzzMode.FLOAT:
            return gen_num(float_flag=True)
        case ParamFuzzMode.NEGATIVE_FLOAT:
            return gen_num(float_flag=True, negative_flag=True)
        case _:
            if mode is not ParamFuzzMode.RANDOM:
                logger.warning(
                    "Invalid fuzzing mode for parameter with type "
                    "serviceCategoryType, using random mode."
                )
            invalid_string = gen_random_string(random.randint(1, 100))
            invalid_special_string = gen_malicous_string()
            invalid_num = gen_num()
            invalid_neg_num = gen_num(negative_flag=True)
            invalid_float_num = gen_num(float_flag=True)
            invalid_neg_float_num = gen_num(
                negative_flag=True, float_flag=True
            )
            return random.choice(
                [
                    invalid_string,
                    invalid_special_string,
                    invalid_num,
                    invalid_neg_num,
                    invalid_float_num,
                    invalid_neg_float_num,
                ]
            )


def fuzz_service(
    modes: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz service"""
    # valid_values dict has to be provided everytime
    # It goes from fuzzer module with values from default dictionary

    # Need to be None, otherwise {} it will be dangerous default value
    # in method definition]

    if valid_values is None:
        valid_values = {}

    if modes is None:
        modes = {}

    for name in ["ServiceID", "ServiceName", "ServiceCategory", "FreeService"]:
        # Attribute is not specified in config dict => don't fuzz it
        # => valid mode
        if name not in modes:
            modes[name] = ParamFuzzMode.VALID.value
        if name not in valid_values:
            valid_values[name] = None

    service_id = fuzz_service_id(mode=modes["ServiceID"])
    service_name = fuzz_service_name(mode=modes["ServiceName"])
    service_category = fuzz_service_category(mode=modes["ServiceCategory"])
    free_service = gen_invalid_bool(mode=modes["FreeService"])

    return {
        "ServiceID": service_id,
        "ServiceName": service_name,
        "ServiceCategory": service_category,
        "FreeService": free_service,
    }


def fuzz_service_list(
    modes: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz service list"""

    # Has to be list of services, also if only one service is provided
    if modes is None:
        modes = {}
    if valid_values is None:
        valid_values = {}
    # Here is because of keep consistency with other methods for complexTypes
    for name in ["Service"]:
        # Attribute is not specified in config dict => don't fuzz it
        # => valid mode
        if name not in modes:
            modes[name] = ParamFuzzMode.VALID.value
        if name not in valid_values:
            valid_values[name] = None

    service = [
        fuzz_service(
            modes=modes["Service"], valid_values=valid_values["Service"]
        )
    ]

    return {"Service": service}


def fuzz_parameter(
    modes: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz parameter

    Parameter is complex type, so it has attributes and elements.
    In XSD defined as: parameterType.
    """
    if modes is None:
        modes = {}
    if valid_values is None:
        valid_values = {}

    for name in ["Name", "Type", "Value"]:
        # Attribute is not specified in config dict => don't fuzz it
        # => valid mode
        if name not in modes:
            modes[name] = ParamFuzzMode.VALID.value
        if name not in valid_values:
            valid_values[name] = None

    # Covert mode for Name to enum
    try:
        modes["Name"] = ParamFuzzMode(modes["Name"])
    except ValueError:
        logger.warning(
            "Invalid fuzzing mode for Parameter, using random mode."
        )
        modes["Name"] = ParamFuzzMode.RANDOM

    # Name is attribute in XSD => @Name
    # type xs:string
    name = gen_invalid_string(
        mode=modes["Name"], valid_val=valid_values["Name"]
    )

    value_types = [
        "boolValue",
        "byteValue",
        "shortValue",
        "intValue",
        "physicalValue",
        "stringValue",
    ]
    # Choose type
    value_type = modes["Type"]

    # First check if random or valid mode
    if value_type in [ParamFuzzMode.RANDOM, ParamFuzzMode.VALID]:
        value_type = random.choice(value_types)  # => value_type is valid

    if value_type not in value_types:
        logger.warning("Invalid value type for Parameter, using random mode.")
        value_type = random.choice(value_types)  # => value_type is valid

    # Convert mode for Value to enum
    try:
        modes["Value"] = ParamFuzzMode(modes["Value"])
    except ValueError:
        logger.warning(
            "Invalid fuzzing mode for Parameter, using random mode."
        )
        modes["Value"] = ParamFuzzMode.RANDOM

    # So the value_type is for sure from value_types
    # raise ValueError should not be possible
    # Generated value based on type
    match value_type:
        case "boolValue":
            value = gen_invalid_bool(mode=modes["Value"])
        case "byteValue":
            value = gen_invalid_byte(mode=modes["Value"])
        case "shortValue":
            value = gen_invalid_short(mode=modes["Value"])
            # xs:int, -2147483648 - 2147483647
        case "intValue":
            value = gen_invalid_int(mode=modes["Value"])
        case "physicalValue":
            value = fuzz_physical_value_type(modes=modes["physicalValue"])
        case "stringValue":
            value = gen_invalid_string(mode=modes["Value"])
        case _:
            raise ValueError("Invalid value type for Parameter.")

    return {"@Name": name, value_type: value}


def fuzz_parameter_set_id(
    mode: str = "valid", valid_val: Optional[int] = None
):
    """Fuzz ParameterSetID"""
    # Convert mode to enum
    try:
        mode = ParamFuzzMode(mode)
    except ValueError:
        logger.warning(
            "Invalid fuzzing mode for ParameterSetID. Using random mode."
        )
        mode = ParamFuzzMode.RANDOM

    return gen_invalid_short(mode=mode, valid_val=valid_val)


def fuzz_parameter_set(
    modes: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz parameter set"""

    if modes is None:
        modes = {}
    if valid_values is None:
        valid_values = {}

    for name in ["ParameterSetID", "Parameter"]:
        # Attribute is not specified in config dict => don't fuzz it
        # => valid mode
        if name not in modes:
            modes[name] = ParamFuzzMode.VALID.value
        if name not in valid_values:
            valid_values[name] = None

    parameter_set_id = fuzz_parameter_set_id(
        mode=modes["ParameterSetID"],
        valid_val=valid_values["ParameterSetID"],
    )
    # List of parameterType
    parameter = [
        fuzz_parameter(
            modes=modes["Parameter"], valid_values=valid_values["Parameter"]
        )
    ]

    return {"ParameterSetID": parameter_set_id, "Parameter": parameter}


def fuzz_service_parameter_list(
    modes: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz service detail list"""

    if modes is None:
        modes = {}
    if valid_values is None:
        valid_values = {}

    for name in ["ParameterSet"]:
        # Attribute is not specified in config dict => don't fuzz it
        # => valid mode
        if name not in modes:
            modes[name] = ParamFuzzMode.VALID.value
        if name not in valid_values:
            valid_values[name] = None

    parameter_set = [
        fuzz_parameter_set(
            modes=modes["ParameterSet"],
            valid_values=valid_values["ParameterSet"],
        )
    ]
    return {"ParameterSet": parameter_set}


def fuzz_gen_challenge(
    mode: str = "valid", valid_val=None
) -> Union[str, int, float]:
    """Fuzz gen challenge

    GenChallenge is type base64Binary (in xml schema), (length 16).
    GenChallenge should be exactly 16 bytes long (128 bits).

    From ISO15118-2 example on page 330, length is length of the data before
    base64 encoding. Use of UTF-8 encoding is required.
    Example: 'U29tZSBSYW5kb20gRGF0YQ==' => 'Some Random Data'
    """

    # str to base64 encoding => str to bytes => bytes to base64 encoding
    # base64.b64encode(str.encode('utf-8')) or base64.b64encode(bytes(str, 'utf-8'))
    # base64 to str => base64 to bytes => bytes to str
    # base64.b64decode(base64_encoded_str).decode('utf-8')
    # Convert mode to enum
    try:
        mode = ParamFuzzMode(mode)
    except ValueError:
        logger.warning(
            "Invalid fuzzing mode for GenChallenge, using random mode."
        )
        mode = ParamFuzzMode.RANDOM

    match mode:
        case ParamFuzzMode.VALID:
            if valid_val is None:
                # Generate valid base64 binary, because the length is 16
                # => valid value is base64 encoded 16 bytes long binary
                return gen_invalid_base64_binary(length=16)
            return valid_val
        case ParamFuzzMode.LONG_BASE64:
            # Generate base64 binary with length > 16
            return gen_invalid_base64_binary(max_length=16)
        case ParamFuzzMode.SHORT_BASE64:
            # Generate base64 binary with length < 16
            return gen_invalid_base64_binary(min_length=16)
        case ParamFuzzMode.SPECIAL_BASE64:
            # TODO: use of valid base64 binary and append invalid chars to it
            return gen_malicous_base64()
        case ParamFuzzMode.INT:
            return gen_num()
        case ParamFuzzMode.NEGATIVE_INT:
            return gen_num(negative_flag=True)
        case ParamFuzzMode.FLOAT:
            return gen_num(float_flag=True)
        case ParamFuzzMode.NEGATIVE_FLOAT:
            return gen_num(float_flag=True, negative_flag=True)
        case ParamFuzzMode.STRING:
            return gen_random_string(random.randint(1, 100))
        case ParamFuzzMode.SPECIAL_STRING:
            return gen_malicous_string()
        case _:
            if mode is not ParamFuzzMode.RANDOM:
                logger.warning(
                    "Invalid fuzzing mode for parameter with type "
                    "base64Binary, using random mode."
                )
            longer_base64 = gen_invalid_base64_binary(max_length=16)
            shorter_base64 = gen_invalid_base64_binary(min_length=16)
            special_base64 = gen_malicous_base64()
            invalid_num = gen_num()
            invalid_neg_num = gen_num(negative_flag=True)
            invalid_float_num = gen_num(float_flag=True)
            invalid_neg_float_num = gen_num(
                negative_flag=True, float_flag=True
            )
            invalid_string = gen_random_string(random.randint(1, 100))
            invalid_special_string = gen_malicous_string()
            return random.choice(
                [
                    longer_base64,
                    shorter_base64,
                    special_base64,
                    invalid_num,
                    invalid_neg_num,
                    invalid_float_num,
                    invalid_neg_float_num,
                    invalid_string,
                    invalid_special_string,
                ]
            )


def fuzz_evse_processing(
    mode: str = "valid", valid_val: Optional[str] = None
) -> Union[str, int, float]:
    """Fuzz evse processing status.

    EVSEProcessing is enum, so valid value is one of the enum values EVSEProcessingType.

    Type EVSEProcessingType is defined in MsgDataTypes.py.
    Fuzzer should test values out of enum values.
    """

    # Convert mode to enum
    try:
        mode = ParamFuzzMode(mode)
    except ValueError:
        logger.warning(
            "Invalid fuzzing mode for EVSEProcessing, using random mode."
        )
        mode = ParamFuzzMode.RANDOM

    match mode:
        case ParamFuzzMode.VALID:
            if valid_val is None:
                logger.warning(
                    "No valid value specified for EVSEProcessing, "
                    "using default valid value randomly chosen from "
                    "EVSEProcessingType enum."
                )
                return random.choice(list(EVSEProcessingType)).value
            return valid_val
        case ParamFuzzMode.STRING:
            return gen_random_string(random.randint(1, 100))
        case ParamFuzzMode.SPECIAL_STRING:
            # TODO: Add some valid value at the start and append invalid chars to it
            # like EVSEProcessingType.FINISHED.value + r"!@*!*@#" or something like that
            # malicious_string = gen_malicous_string()
            # invalid_enum = (
            #    random.choice(list(EVSEProcessingType)).value + malicious_string
            # )
            return gen_malicous_string()
        case ParamFuzzMode.INT:
            return gen_num()
        case ParamFuzzMode.NEGATIVE_INT:
            return gen_num(negative_flag=True)
        case ParamFuzzMode.FLOAT:
            return gen_num(float_flag=True)
        case ParamFuzzMode.NEGATIVE_FLOAT:
            return gen_num(float_flag=True, negative_flag=True)
        case _:
            if mode is not ParamFuzzMode.RANDOM:
                logger.warning(
                    "Invalid fuzzing mode for parameter with type "
                    "EVSEProcessingType, using random mode."
                )
            invalid_string = gen_random_string(random.randint(1, 100))
            invalid_special_string = gen_malicous_string()
            invalid_num = gen_num()
            invalid_neg_num = gen_num(negative_flag=True)
            invalid_float_num = gen_num(float_flag=True)
            invalid_neg_float_num = gen_num(
                negative_flag=True, float_flag=True
            )
            return random.choice(
                [
                    invalid_string,
                    invalid_special_string,
                    invalid_num,
                    invalid_neg_num,
                    invalid_float_num,
                    invalid_neg_float_num,
                ]
            )


def fuzz_time_interval(
    modes: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    if modes is None:
        modes = {}
    if valid_values is None:
        valid_values = {}

    for name in ["start", "duration"]:
        # Attribute is not specified in config dict => don't fuzz it
        # => valid mode
        if name not in modes:
            modes[name] = ParamFuzzMode.VALID.value
        if name not in valid_values:
            valid_values[name] = None

    try:
        modes["start"] = ParamFuzzMode(modes["start"])
    except ValueError:
        logger.warning(
            "Invalid fuzzing mode for TimeInterval, using random mode."
        )
        modes["start"] = ParamFuzzMode.RANDOM

    try:
        modes["duration"] = ParamFuzzMode(modes["duration"])
    except ValueError:
        logger.warning(
            "Invalid fuzzing mode for TimeInterval, using random mode."
        )
        modes["duration"] = ParamFuzzMode.RANDOM

    # start, xs:unsignedInt, minInclusive value="0", maxInclusive value="16777214"
    start = gen_invalid_unsigned_int(
        mode=modes["start"],
        min_val=0,
        max_val=16777214,
        valid_val=valid_values["start"],
    )
    # duration, xs:unsignedInt, minInclusive value="0", maxInclusive value="86400"
    duration = gen_invalid_unsigned_int(
        mode=modes["duration"],
        min_val=0,
        max_val=86400,
        valid_val=valid_values["duration"],
    )

    return {"start": start, "duration": duration}


def fuzz_p_max(
    modes: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz PMax"""

    return fuzz_physical_value_type(
        modes=modes,
        unit_val=unitSymbolType.WATT.value,
        valid_values=valid_values,
    )


def fuzz_p_max_schedule_entry(
    modes: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    if modes is None:
        modes = {}
    if valid_values is None:
        valid_values = {}

    for name in ["TimeInterval", "PMax"]:
        # Attribute is not specified in config dict => don't fuzz it
        # => valid mode
        if name not in modes:
            modes[name] = ParamFuzzMode.VALID.value
        if name not in valid_values:
            valid_values[name] = None

    time_interval = fuzz_time_interval(
        modes=modes["RelativeTimeInterval"],
        valid_values=valid_values["RelativeTimeInterval"],
    )
    p_max = fuzz_p_max(modes=modes["PMax"], valid_values=valid_values["PMax"])

    return {"RelativeTimeInterval": time_interval, "PMax": p_max}


def fuzz_p_max_schedule(
    modes: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    if modes is None:
        modes = {}
    if valid_values is None:
        valid_values = {}

    for name in ["PMaxScheduleEntry"]:
        # Attribute is not specified in config dict => don't fuzz it
        # => valid mode
        if name not in modes:
            modes[name] = [ParamFuzzMode.VALID.value]
        if name not in valid_values:
            valid_values[name] = None

    p_max_schedule_entry = [
        fuzz_p_max_schedule_entry(
            modes=modes["PMaxScheduleEntry"],
            valid_values=valid_values["PMaxScheduleEntry"],
        )
    ]

    return {"PMaxScheduleEntry": p_max_schedule_entry}


def fuzz_id(
    mode: str = "valid", valid_val: Optional[str] = None
) -> Union[str, int, float]:
    """Fuzz Id"""
    # Convert mode to enum
    try:
        mode = ParamFuzzMode(mode)
    except ValueError:
        logger.warning("Invalid fuzzing mode for Id, using random mode.")
        mode = ParamFuzzMode.RANDOM

    return gen_invalid_id(mode=mode, valid_val=valid_val)


def fuzz_sales_tariff_id(
    mode: str = "valid", valid_val: Optional[int] = None
) -> Union[str, int, float]:
    """Fuzz sales tariff id

    SalesTariffID is type xs:unsignedByte (in xml schema), with restriction:
        minInclusive value="1", maxInclusive value="255", valid values: 1-255
    """
    # Convert mode to enum
    try:
        mode = ParamFuzzMode(mode)
    except ValueError:
        logger.warning(
            "Invalid fuzzing mode for SalesTariffID, using random mode."
        )
        mode = ParamFuzzMode.RANDOM

    return gen_invalid_unsigned_byte(
        mode=mode, min_val=1, max_val=255, valid_val=valid_val
    )


def fuzz_sales_tariff_description(
    mode: str = "valid", valid_val: Optional[str] = None
) -> Union[str, int, float]:
    """Fuzz sales tariff description

    SalesTariffDescription is type xs:string (in xml schema), (maxLength: 32).
    """
    # COvert mode to enum
    try:
        mode = ParamFuzzMode(mode)
    except ValueError:
        logger.warning(
            "Invalid fuzzing mode for SalesTariffDescription, using random mode."
        )
        mode = ParamFuzzMode.RANDOM

    return gen_invalid_string(mode=mode, max_len=32, valid_val=valid_val)


def fuzz_num_e_price_levels(
    mode: str = "valid", valid_val: Optional[int] = None
):
    """Fuzz num e price levels

    NumEPriceLevels is type xs:unsignedByte (in xml schema)
    """
    # Convert mode to enum
    try:
        mode = ParamFuzzMode(mode)
    except ValueError:
        logger.warning(
            "Invalid fuzzing mode for NumEPriceLevels, using random mode."
        )
        mode = ParamFuzzMode.RANDOM

    # TODO: maybe add only valid value = 1 => 1 EPriceLevel

    return gen_invalid_unsigned_byte(mode=mode, valid_val=valid_val)


def fuzz_e_price_level(
    mode: str = "valid", valid_val: Optional[int] = None
) -> Union[str, int, float]:
    """Fuzz EPriceLevel

    EPriceLevel is type xs:unsignedByte (in xml schema)
    """
    # Convert mode to enum
    try:
        mode = ParamFuzzMode(mode)
    except ValueError:
        logger.warning(
            "Invalid fuzzing mode for EPriceLevel, using random mode."
        )
        mode = ParamFuzzMode.RANDOM

    # TODO: maybe add only valid value = 1 => 1 EPriceLevel
    return gen_invalid_unsigned_byte(mode=mode, valid_val=valid_val)


# TODO: Convert all fuzz enum methods to use gen_invalid_string
# pass something like possible_values from enum fuzz method to gen_invalid_string


def fuzz_cost_kind(
    mode: str = "valid", valid_val: Optional[str] = None
) -> Union[str, int, float]:
    """Fuzz cost kind

    costKind is enum, so valid value is one of the enum values costKindType.
    """
    # Convert mode to enum
    try:
        mode = ParamFuzzMode(mode)
    except ValueError:
        logger.warning("Invalid fuzzing mode for CostKind, using random mode.")
        mode = ParamFuzzMode.RANDOM

    match mode:
        case ParamFuzzMode.VALID:
            if valid_val is None:
                logger.warning(
                    "No valid value specified for CostKind, "
                    "using default valid value randomly chosen from "
                    "costKindType enum."
                )
                return random.choice(list(costKindType)).value
            return valid_val
        case ParamFuzzMode.STRING:
            return gen_random_string(random.randint(1, 100))
        case ParamFuzzMode.SPECIAL_STRING:
            return gen_malicous_string()
        case ParamFuzzMode.INT:
            return gen_num()
        case ParamFuzzMode.NEGATIVE_INT:
            return gen_num(negative_flag=True)
        case ParamFuzzMode.FLOAT:
            return gen_num(float_flag=True)
        case ParamFuzzMode.NEGATIVE_FLOAT:
            return gen_num(float_flag=True, negative_flag=True)
        case _:
            if mode is not ParamFuzzMode.RANDOM:
                logger.warning(
                    "Invalid fuzzing mode for parameter with type "
                    "costKindType, using random mode."
                )
            invalid_values = [
                gen_random_string(random.randint(1, 100)),
                gen_malicous_string(),
                gen_num(),
                gen_num(negative_flag=True),
                gen_num(float_flag=True),
                gen_num(float_flag=True, negative_flag=True),
            ]
            return random.choice(invalid_values)


def fuzz_amount(mode: str = "valid", valid_val: Optional[int] = None):
    """Fuzz amount

    amount is type xs:unsignedInt (in xml schema)
    """
    # Convert mode to enum
    try:
        mode = ParamFuzzMode(mode)
    except ValueError:
        logger.warning("Invalid fuzzing mode for amount, using random mode.")
        mode = ParamFuzzMode.RANDOM

    return gen_invalid_unsigned_int(mode=mode, valid_val=valid_val)


def fuzz_amount_multiplier(
    mode: str = "valid", valid_val: Optional[int] = None
):
    """Fuzz amount multiplier

    amountMultiplier is type xs:byte (in xml schema), with restrictions:
        minInclusive value="-3", maxInclusive value="3"
    """
    # Convert mode to enum
    try:
        mode = ParamFuzzMode(mode)
    except ValueError:
        logger.warning(
            "Invalid fuzzing mode for amountMultiplier, using random mode."
        )
        mode = ParamFuzzMode.RANDOM

    return gen_invalid_byte(
        mode=mode, min_val=-3, max_val=3, valid_val=valid_val
    )


def fuzz_cost(
    modes: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz cost

    Cost is complex type, so it has elements: costKind, amount, amountMultiplier
    """
    if modes is None:
        modes = {}
    if valid_values is None:
        valid_values = {}

    for name in ["costKind", "amount", "amountMultiplier"]:
        # Attribute is not specified in config dict => don't fuzz it
        # => valid mode
        if name not in modes:
            modes[name] = [ParamFuzzMode.VALID.value]
        if name not in valid_values:
            valid_values[name] = None

    cost_kind = fuzz_cost_kind(
        mode=modes["costKind"], valid_val=valid_values["costKind"]
    )
    amount = fuzz_amount(
        mode=modes["amount"], valid_val=valid_values["amount"]
    )
    amount_multiplier = fuzz_amount_multiplier(
        mode=modes["amountMultiplier"],
        valid_val=valid_values["amountMultiplier"],
    )

    return {
        "costKind": cost_kind,
        "amount": amount,
        "amountMultiplier": amount_multiplier,
    }


def fuzz_consumption_cost(
    modes: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz consumption cost

    ConsumptionCost is complex type, so it has elements: startValue, Cost
    """
    if modes is None:
        modes = {}
    if valid_values is None:
        valid_values = {}

    for name in ["startValue", "Cost"]:
        # Attribute is not specified in config dict => don't fuzz it
        # => valid mode
        if name not in modes:
            modes[name] = [ParamFuzzMode.VALID.value]
        if name not in valid_values:
            valid_values[name] = None

    start_value = fuzz_physical_value_type(
        modes=modes["startValue"], valid_values=valid_values["startValue"]
    )

    cost = [fuzz_cost(modes=modes["Cost"], valid_values=valid_values["Cost"])]

    return {"startValue": start_value, "Cost": cost}


def fuzz_sales_tariff_entry(
    modes: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    if modes is None:
        modes = {}
    if valid_values is None:
        valid_values = {}

    for name in ["RelativeTimeInterval", "EPriceLevel", "ConsumptionCost"]:
        # Attribute is not specified in config dict => don't fuzz it
        # => valid mode
        if name not in modes:
            modes[name] = [ParamFuzzMode.VALID.value]
        if name not in valid_values:
            valid_values[name] = None

    time_interval = fuzz_time_interval(
        modes=modes["RelativeTimeInterval"],
        valid_values=valid_values["RelativeTimeInterval"],
    )
    e_price_level = fuzz_e_price_level(
        mode=modes["EPriceLevel"], valid_val=valid_values["EPriceLevel"]
    )

    consumption_cost = [
        fuzz_consumption_cost(
            modes=modes["ConsumptionCost"],
            valid_values=valid_values["ConsumptionCost"],
        )
    ]

    return {
        "RelativeTimeInterval": time_interval,
        "EPriceLevel": e_price_level,
        "ConsumptionCost": consumption_cost,
    }


def fuzz_sales_tariff(
    modes: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz sales tariff"""

    if modes is None:
        modes = {}
    if valid_values is None:
        valid_values = {}
    for name in [
        "Id",
        "SalesTariffID",
        "SalesTariffDescription",
        "NumEPriceLevels",
        "SalesTariffEntry",
    ]:
        # Attribute is not specified in config dict => don't fuzz it
        # => valid mode
        if name not in modes:
            modes[name] = [ParamFuzzMode.VALID.value]
        if name not in valid_values:
            valid_values[name] = None
    # xs:id
    id = fuzz_id(mode=modes["Id"], valid_val=valid_values["Id"])
    # xs:unsignedByte
    sales_tariff_id = fuzz_sales_tariff_id(
        mode=modes["Id"], valid_val=valid_values["Id"]
    )
    # xs:string
    sales_tariff_description = fuzz_sales_tariff_description(
        mode=modes["SalesTariffDescription"],
        valid_val=valid_values["SalesTariffDescription"],
    )
    # xs:unsignedByte
    num_e_price_levels = fuzz_num_e_price_levels(
        mode=modes["NumEPriceLevels"],
        valid_val=valid_values["NumEPriceLevels"],
    )

    sales_sales_tariff_entry = [fuzz_sales_tariff_entry()]

    return {
        "@Id": id,
        "SalesTariffID": sales_tariff_id,
        "SalesTariffDescription": sales_tariff_description,
        "NumEPriceLevels": num_e_price_levels,
        "SalesTariffEntry": sales_sales_tariff_entry,
    }


def fuzz_sa_schedule_tuple(
    modes: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz sa schedule tuple"""
    if modes is None:
        modes = {}
    if valid_values is None:
        valid_values = {}

    for name in ["SAScheduleTupleID", "PMaxSchedule", "SalesTariff"]:
        # Attribute is not specified in config dict => don't fuzz it
        # => valid mode
        if name not in modes:
            modes[name] = ParamFuzzMode.VALID.value
        if name not in valid_values:
            valid_values[name] = None

    # SAIDType =>  xs:unsignedByte, minInclusive value="1", maxInclusive value="255"
    sa_schedule_tuple_id = fuzz_sa_schedule_tuple_id(
        mode=modes["SAScheduleTupleID"],
        valid_val=valid_values["SAScheduleTupleID"],
    )
    # PMaxScheduled
    p_max_schedule = fuzz_p_max_schedule(
        modes=modes["PMaxSchedule"], valid_values=valid_values["PMaxSchedule"]
    )
    # SalesTariff, minOccurs = 0 => not required
    sales_tafiff = fuzz_sales_tariff(
        modes=modes["SalesTariff"], valid_values=valid_values["SalesTariff"]
    )

    return {
        "SAScheduleTupleID": sa_schedule_tuple_id,
        "PMaxSchedule": p_max_schedule,
        "SalesTariff": sales_tafiff,
    }


def fuzz_sa_schedule_list(
    modes: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz sa schedule list"""

    # TODO: Do this check with if's and for cycle in separate method
    # and call it from every method for complexType
    if modes is None:
        modes = {}
    if valid_values is None:
        valid_values = {}

    for name in ["SAScheduleTuple"]:
        # Attribute is not specified in config dict => don't fuzz it
        # => valid mode
        if name not in modes:
            modes[name] = ParamFuzzMode.VALID.value
        if name not in valid_values:
            valid_values[name] = None

    sa_schedule_tuple = [
        fuzz_sa_schedule_tuple(
            modes=modes["SAScheduleTuple"],
            valid_values=valid_values["SAScheduleTuple"],
        )
    ]

    return {"SAScheduleTuple": sa_schedule_tuple}


def fuzz_evse_nominal_voltage(
    modes: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz evse nominal voltage"""
    if modes is None:
        modes = {}
    if valid_values is None:
        valid_values = {}
    for name in ["EVSENominalVoltage"]:
        # Attribute is not specified in config dict => don't fuzz it
        # => valid mode
        if name not in modes:
            modes[name] = [ParamFuzzMode.VALID.value]
        if name not in valid_values:
            valid_values[name] = None

    return fuzz_physical_value_type(
        modes=modes["EVSENominalVoltage"],
        unit_val=unitSymbolType.VOLT.value,
        valid_values=valid_values["EVSENominalVoltage"],
    )


def fuzz_ac_evse_charge_parameter(
    modes: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz ac evse charge parameter"""

    if modes is None:
        modes = {}
    if valid_values is None:
        valid_values = {}
    for name in ["AC_EVSEStatus", "EVSENominalVoltage", "EVSEMaxCurrent"]:
        # Attribute is not specified in config dict => don't fuzz it
        # => valid mode
        if name not in modes:
            modes[name] = [ParamFuzzMode.VALID.value]
        if name not in valid_values:
            valid_values[name] = None

    ac_evse_status = fuzz_ac_evse_status(
        modes=modes["AC_EVSEStatus"],
        valid_values=valid_values["AC_EVSEStatus"],
    )
    evse_nominal_voltage = fuzz_evse_nominal_voltage(
        modes=modes["EVSENominalVoltage"],
        valid_values=valid_values["EVSENominalVoltage"],
    )
    evse_max_current = fuzz_evse_max_current(
        modes=modes["EVSEMaxCurrent"],
        valid_values=valid_values["EVSEMaxCurrent"],
    )

    return {
        "AC_EVSEStatus": ac_evse_status,
        "EVSENominalVoltage": evse_nominal_voltage,
        "EVSEMaxCurrent": evse_max_current,
    }


def fuzz_evse_max_current_limit(
    modes: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz evse max current limit"""

    if modes is None:
        modes = {}
    if valid_values is None:
        valid_values = {}
    for name in ["EVSEMaxCurrentLimit"]:
        # Attribute is not specified in config dict => don't fuzz it
        # => valid mode
        if name not in modes:
            modes[name] = [ParamFuzzMode.VALID.value]
        if name not in valid_values:
            valid_values[name] = None

    return fuzz_physical_value_type(
        modes=modes["EVSEMaxCurrentLimit"],
        unit_val=unitSymbolType.AMPERE.value,
        valid_values=valid_values["EVSEMaxCurrentLimit"],
    )


def fuzz_evse_max_power_limit(
    modes: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz evse max power limit"""

    if modes is None:
        modes = {}
    if valid_values is None:
        valid_values = {}
    for name in ["EVSEMaxPowerLimit"]:
        # Attribute is not specified in config dict => don't fuzz it
        # => valid mode
        if name not in modes:
            modes[name] = [ParamFuzzMode.VALID.value]
        if name not in valid_values:
            valid_values[name] = None

    return fuzz_physical_value_type(
        modes=modes["EVSEMaxPowerLimit"],
        unit_val=unitSymbolType.WATT.value,
        valid_values=valid_values["EVSEMaxPowerLimit"],
    )


def fuzz_evse_max_voltage_limit(
    modes: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz evse max voltage limit"""

    if modes is None:
        modes = {}
    if valid_values is None:
        valid_values = {}
    for name in ["EVSEMaxVoltageLimit"]:
        # Attribute is not specified in config dict => don't fuzz it
        # => valid mode
        if name not in modes:
            modes[name] = [ParamFuzzMode.VALID.value]
        if name not in valid_values:
            valid_values[name] = None

    return fuzz_physical_value_type(
        modes=modes["EVSEMaxVoltageLimit"],
        unit_val=unitSymbolType.VOLT.value,
        valid_values=valid_values["EVSEMaxVoltageLimit"],
    )


def fuzz_evse_min_current_limit(
    modes: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz evse min current limit"""

    if modes is None:
        modes = {}
    if valid_values is None:
        valid_values = {}
    for name in ["EVSEMinCurrentLimit"]:
        # Attribute is not specified in config dict => don't fuzz it
        # => valid mode
        if name not in modes:
            modes[name] = [ParamFuzzMode.VALID.value]
        if name not in valid_values:
            valid_values[name] = None

    return fuzz_physical_value_type(
        modes=modes["EVSEMinCurrentLimit"],
        unit_val=unitSymbolType.AMPERE.value,
        valid_values=valid_values["EVSEMinCurrentLimit"],
    )


def fuzz_evse_min_voltage_limit(
    modes: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz evse min voltage limit"""

    if modes is None:
        modes = {}
    if valid_values is None:
        valid_values = {}
    for name in ["EVSEMinVoltageLimit"]:
        # Attribute is not specified in config dict => don't fuzz it
        # => valid mode
        if name not in modes:
            modes[name] = [ParamFuzzMode.VALID.value]
        if name not in valid_values:
            valid_values[name] = None

    return fuzz_physical_value_type(
        modes=modes["EVSEMinVoltageLimit"],
        unit_val=unitSymbolType.VOLT.value,
        valid_values=valid_values["EVSEMinVoltageLimit"],
    )


def fuzz_evse_current_regulation_tolerance(
    modes: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz evse current regulation tolerance"""

    if modes is None:
        modes = {}
    if valid_values is None:
        valid_values = {}
    for name in ["EVSECurrentRegulationTolerance"]:
        # Attribute is not specified in config dict => don't fuzz it
        # => valid mode
        if name not in modes:
            modes[name] = ParamFuzzMode.VALID.value
        if name not in valid_values:
            valid_values[name] = None

    return fuzz_physical_value_type(
        modes=modes["EVSECurrentRegulationTolerance"],
        unit_val=unitSymbolType.AMPERE.value,
        valid_values=valid_values["EVSECurrentRegulationTolerance"],
    )


def fuzz_evse_peak_current_ripple(
    modes: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz evse peak current ripple"""

    if modes is None:
        modes = {}
    if valid_values is None:
        valid_values = {}
    for name in ["EVSEPeakCurrentRipple"]:
        # Attribute is not specified in config dict => don't fuzz it
        # => valid mode
        if name not in modes:
            modes[name] = ParamFuzzMode.VALID.value
        if name not in valid_values:
            valid_values[name] = None

    return fuzz_physical_value_type(
        modes=modes["EVSEPeakCurrentRipple"],
        unit_val=unitSymbolType.AMPERE.value,
        valid_values=valid_values["EVSEPeakCurrentRipple"],
    )


def fuzz_evse_energy_to_be_delivered(
    modes: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz evse energy to be delivered"""

    if modes is None:
        modes = {}
    if valid_values is None:
        valid_values = {}
    for name in ["EVSEEnergyToBeDelivered"]:
        # Attribute is not specified in config dict => don't fuzz it
        # => valid mode
        if name not in modes:
            modes[name] = ParamFuzzMode.VALID.value
        if name not in valid_values:
            valid_values[name] = None

    return fuzz_physical_value_type(
        modes=modes["EVSEEnergyToBeDelivered"],
        unit_val=unitSymbolType.WATT_HOUR.value,
        valid_values=valid_values["EVSEEnergyToBeDelivered"],
    )


def fuzz_dc_evse_charge_parameter(
    modes: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz dc evse charge parameter"""

    if modes is None:
        modes = {}
    if valid_values is None:
        valid_values = {}

    for name in [
        "DC_EVSEStatus",
        "EVSEMaxCurrentLimit",
        "EVSEMaxPowerLimit",
        "EVSEMaxVoltageLimit",
        "EVSEMinCurrentLimit",
        "EVSEMinVoltageLimit",
        "EVSECurrentRegulationTolerance",
        "EVSEPeakCurrentRipple",
        "EVSEEnergyToBeDelivered",
    ]:
        # Attribute is not specified in config dict => don't fuzz it
        # => valid mode
        if name not in modes:
            modes[name] = [ParamFuzzMode.VALID.value]
        if name not in valid_values:
            valid_values[name] = None

    dc_evse_status = fuzz_dc_evse_status(
        modes=modes["DC_EVSEStatus"],
        valid_values=valid_values["DC_EVSEStatus"],
    )
    evse_max_current_limit = fuzz_evse_max_current_limit(
        modes=modes["EVSEMaxCurrentLimit"],
        valid_values=valid_values["EVSEMaxCurrentLimit"],
    )

    evse_max_power_limit = fuzz_evse_max_power_limit(
        modes=modes["EVSEMaxPowerLimit"],
        valid_values=valid_values["EVSEMaxPowerLimit"],
    )

    evse_max_voltage_limit = fuzz_evse_max_voltage_limit(
        modes=modes["EVSEMaxVoltageLimit"],
        valid_values=valid_values["EVSEMaxVoltageLimit"],
    )

    evse_min_current_limit = fuzz_evse_min_current_limit(
        modes=modes["EVSEMinCurrentLimit"],
        valid_values=valid_values["EVSEMinCurrentLimit"],
    )

    evse_min_voltage_limit = fuzz_evse_min_voltage_limit(
        modes=modes["EVSEMinVoltageLimit"],
        valid_values=valid_values["EVSEMinVoltageLimit"],
    )

    evse_current_regulation_tolerance = fuzz_evse_current_regulation_tolerance(
        modes=modes["EVSECurrentRegulationTolerance"],
        valid_values=valid_values["EVSECurrentRegulationTolerance"],
    )

    evse_peak_current_ripple = fuzz_evse_peak_current_ripple(
        modes=modes["EVSEPeakCurrentRipple"],
        valid_values=valid_values["EVSEPeakCurrentRipple"],
    )

    evse_energy_to_be_delivered = fuzz_evse_energy_to_be_delivered(
        modes=modes["EVSEEnergyToBeDelivered"],
        valid_values=valid_values["EVSEEnergyToBeDelivered"],
    )

    return {
        "DC_EVSEStatus": dc_evse_status,
        "EVSEMaxCurrentLimit": evse_max_current_limit,
        "EVSEMaxPowerLimit": evse_max_power_limit,
        "EVSEMaxVoltageLimit": evse_max_voltage_limit,
        "EVSEMinCurrentLimit": evse_min_current_limit,
        "EVSEMinVoltageLimit": evse_min_voltage_limit,
        "EVSECurrentRegulationTolerance": evse_current_regulation_tolerance,
        "EVSEPeakCurrentRipple": evse_peak_current_ripple,
        "EVSEEnergyToBeDelivered": evse_energy_to_be_delivered,
    }


def fuzz_notification_max_delay(
    mode: str = "valid", valid_val: Optional[int] = None
) -> Union[str, int, float]:
    """Fuzz Notification max delay

    NotificationMaxDelay is type xs:unsignedShort
    """

    # Convert mode to enum
    try:
        mode = ParamFuzzMode(mode)
    except ValueError:
        logger.warning(
            "Invalid fuzzing mode for NotificationMaxDelay, using random mode."
        )
        mode = ParamFuzzMode.RANDOM

    return gen_invalid_unsigned_short(mode=mode, valid_val=valid_val)


def fuzz_evse_notification(
    mode: str = "valid", valid_val: Optional[str] = None
) -> Union[str, int, float]:
    """Fuzz evse notification

    EVSENotification type is enum, so valid value is one of the enum values EVSENotificationType.
    """
    # Convert mode to enum
    try:
        mode = ParamFuzzMode(mode)
    except ValueError:
        logger.warning(
            "Invalid fuzzing mode for EVSENotification, using random mode."
        )
        mode = ParamFuzzMode.RANDOM

    match mode:
        case ParamFuzzMode.VALID:
            if valid_val is None:
                logger.warning(
                    "No valid value specified for EVSENotification,"
                    "using default valid value randomly chosen "
                    "from EVSENotificationType enum."
                )
                return random.choice(list(EVSENotificationType)).value
            return valid_val
        case ParamFuzzMode.STRING:
            return gen_random_string(random.randint(1, 100))
        case ParamFuzzMode.SPECIAL_STRING:
            return gen_malicous_string()
        case ParamFuzzMode.INT:
            return gen_num()
        case ParamFuzzMode.NEGATIVE_INT:
            return gen_num(negative_flag=True)
        case ParamFuzzMode.FLOAT:
            return gen_num(float_flag=True)
        case ParamFuzzMode.NEGATIVE_FLOAT:
            return gen_num(float_flag=True, negative_flag=True)
        case _:
            if mode is not ParamFuzzMode.RANDOM:
                logger.warning(
                    "Invalid fuzzing mode for parameter with type "
                    "EVSENotificationType, using random mode."
                )
            invalid_values = [
                gen_random_string(random.randint(1, 100)),
                gen_malicous_string(),
                gen_num(),
                gen_num(negative_flag=True),
                gen_num(float_flag=True),
                gen_num(float_flag=True, negative_flag=True),
            ]
            return random.choice(invalid_values)


def fuzz_rcd(
    mode: str = "valid", valid_val: Optional[str] = None
) -> Union[str, int, float]:
    """Fuzz RCD"""

    try:
        mode = ParamFuzzMode(mode)
    except ValueError:
        logger.warning("Invalid fuzzing mode for RCD, using random mode.")
        mode = ParamFuzzMode.RANDOM

    # TODO: Valid val is True or False, not used valid_val for now
    return gen_invalid_bool(mode=mode)


def fuzz_ac_evse_status(
    modes: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz ac evse status"""

    if modes is None:
        modes = {}
    if valid_values is None:
        valid_values = {}
    for name in ["EVSENotification", "EVSENotification", "RCD"]:
        # Attribute is not specified in config dict => don't fuzz it
        # => valid mode
        if name not in modes:
            modes[name] = [ParamFuzzMode.VALID.value]
        if name not in valid_values:
            valid_values[name] = None

    notification_max_delay = fuzz_notification_max_delay(
        mode=modes["NotificationMaxDelay"],
        valid_val=valid_values["NotificationMaxDelay"],
    )

    evse_notification = fuzz_evse_notification(
        mode=modes["EVSENotification"],
        valid_val=valid_values["EVSENotification"],
    )

    rcd = fuzz_rcd(mode=modes["RCD"], valid_val=valid_values["RCD"])

    return {
        "NotificationMaxDelay": notification_max_delay,
        "EVSENotification": evse_notification,
        "RCD": rcd,
    }


def fuzz_evse_isolation_status(
    mode: str = "valid", valid_val: Optional[str] = None
) -> Union[str, int, float]:
    """Fuzz evse isolation status"""

    try:
        mode = ParamFuzzMode(mode)
    except ValueError:
        logger.warning(
            "Invalid fuzzing mode for EVSEIsolationStatus, using random mode."
        )
        mode = ParamFuzzMode.RANDOM

    match mode:
        case ParamFuzzMode.VALID:
            if valid_val is None:
                logger.warning(
                    "No valid value specified for EVSEIsolationStatus,"
                    "using default valid value randomly chosen "
                    "from EVSEIsolationStatusType enum."
                )
                return random.choice(list(isolationLevelType)).value
            return valid_val
        case ParamFuzzMode.STRING:
            return gen_random_string(random.randint(1, 100))
        case ParamFuzzMode.SPECIAL_STRING:
            return gen_malicous_string()
        case ParamFuzzMode.INT:
            return gen_num()
        case ParamFuzzMode.NEGATIVE_INT:
            return gen_num(negative_flag=True)
        case ParamFuzzMode.FLOAT:
            return gen_num(float_flag=True)
        case ParamFuzzMode.NEGATIVE_FLOAT:
            return gen_num(float_flag=True, negative_flag=True)
        case _:
            if mode is not ParamFuzzMode.RANDOM:
                logger.warning(
                    "Invalid fuzzing mode for parameter with type "
                    "EVSEIsolationStatusType, using random mode."
                )
            invalid_values = [
                gen_random_string(random.randint(1, 100)),
                gen_malicous_string(),
                gen_num(),
                gen_num(negative_flag=True),
                gen_num(float_flag=True),
                gen_num(float_flag=True, negative_flag=True),
            ]
            return random.choice(invalid_values)


def fuzz_dc_evse_status_code(
    mode: str = "valid", valid_val: Optional[str] = None
) -> Union[str, int, float]:
    """ "Fuzz DC EVSE Status Code

    DC_EVSEStatusCode is enum, so valid value is one of the enum values DC_EVSEStatusCodeType.
    """
    try:
        mode = ParamFuzzMode(mode)
    except ValueError:
        logger.warning(
            "Invalid fuzzing mode for DC_EVSEStatusCode, using random mode."
        )
        mode = ParamFuzzMode.RANDOM

    match mode:
        case ParamFuzzMode.VALID:
            if valid_val is None:
                logger.warning(
                    "No valid value specified for DC_EVSEStatusCode,"
                    "using default valid value randomly chosen "
                    "from DC_EVSEStatusCodeType enum."
                )
                return random.choice(list(DC_EVSEStatusCodeType)).value
            return valid_val
        case ParamFuzzMode.STRING:
            return gen_random_string(random.randint(1, 100))
        case ParamFuzzMode.SPECIAL_STRING:
            return gen_malicous_string()
        case ParamFuzzMode.INT:
            return gen_num()
        case ParamFuzzMode.NEGATIVE_INT:
            return gen_num(negative_flag=True)
        case ParamFuzzMode.FLOAT:
            return gen_num(float_flag=True)
        case ParamFuzzMode.NEGATIVE_FLOAT:
            return gen_num(float_flag=True, negative_flag=True)
        case _:
            if mode is not ParamFuzzMode.RANDOM:
                logger.warning(
                    "Invalid fuzzing mode for parameter with type "
                    "DC_EVSEStatusCodeType, using random mode."
                )
            invalid_values = [
                gen_random_string(random.randint(1, 100)),
                gen_malicous_string(),
                gen_num(),
                gen_num(negative_flag=True),
                gen_num(float_flag=True),
                gen_num(float_flag=True, negative_flag=True),
            ]
            return random.choice(invalid_values)


def fuzz_dc_evse_status(
    modes: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz dc evse status"""

    if modes is None:
        modes = {}
    if valid_values is None:
        valid_values = {}

    notification_max_delay = fuzz_notification_max_delay(
        mode=modes["NotificationMaxDelay"],
        valid_val=valid_values["NotificationMaxDelay"],
    )

    evse_notification = fuzz_evse_notification(
        mode=modes["EVSENotification"],
        valid_val=valid_values["EVSENotification"],
    )

    evse_isolation_status = fuzz_evse_isolation_status(
        mode=modes["EVSEIsolationStatus"],
        valid_val=valid_values["EVSEIsolationStatus"],
    )

    evse_status_code = fuzz_dc_evse_status_code()

    return {
        "NotificationMaxDelay": notification_max_delay,
        "EVSENotification": evse_notification,
        "EVSEIsolationStatus": evse_isolation_status,
        "DC_EVSEStatusCode": evse_status_code,
    }


def fuzz_sa_provisioning_certificate_chain() -> str:
    """Fuzz sa provisioning certificate chain"""
    raise NotImplementedError


def fuzz_contract_signature_cert_chain() -> str:
    """Fuzz contract signature certificate chain"""
    raise NotImplementedError


def fuzz_contract_signature_encrypted_private_key() -> str:
    """Fuzz contract signature encrypted private key"""
    raise NotImplementedError


def fuzz_dh_public_key() -> str:
    """Fuzz dh public key"""
    raise NotImplementedError


def fuzz_emaid() -> str:
    """Fuzz emaid"""

    # TODO: Differ between EMAIDType and eMAIDType
    raise NotImplementedError


def fuzz_retry_counter(mode: str = "valid") -> Union[str, int, float]:
    """Fuzz retry counter

    If the ResponseCode was 'FAILED_NoCertificateAvailable' or 'FAILED_ContractCanceled',
    this field contains information, when the EVCC should try to get
    the new certificate again.
    Type is xs:short (in xml schema), so valid values: -32768 to 32767, but
    it has restriction.

    The following entries are possible:
        x > 0: after “x” days
        0: immediately (at next charging)
        -1: never

    Use this fuzz method only if ResponseCode is 'FAILED_NoCertificateAvailable'
    or 'FAILED_ContractCanceled'.
    """

    # Convert mode to enum
    try:
        mode = ParamFuzzMode(mode)
    except ValueError:
        logger.warning(
            "Invalid fuzzing mode for RetryCounter, using random mode."
        )
        mode = ParamFuzzMode.RANDOM

    return gen_invalid_short(mode=mode, min_val=-1, max_val=32767)


def fuzz_sa_schedule_tuple_id(
    mode: str = "valid", valid_val: Optional[int] = None
) -> Union[str, int, float]:
    """Fuzz sa schedule tuple id

    SAScheduleTupleID is type SAIDType:
    xs:unsignedByte (0-255) (in xml schema), with restriction
    that value must be in range 1-255.

    But for some message is SAScheduleTupleID type SAIDType and
    short in semantics and type definition for some messages in ISO15118-2.
    """
    # Convert mode to enum
    try:
        mode = ParamFuzzMode(mode)
    except ValueError:
        logger.warning(
            "Invalid fuzzing mode for SAScheduleTupleID, using random mode."
        )
        mode = ParamFuzzMode.RANDOM

    return gen_invalid_unsigned_byte(
        mode=mode, min_val=1, max_val=255, valid_val=valid_val
    )


def fuzz_multiplier(
    mode: str = "valid", valid_val: Optional[int] = None
) -> Union[str, int, float]:
    """Fuzz multiplier

    Multiplier xs:byte, minInclusive value=-3, maxInclusive value=3
    """

    # Convert mode to enum
    try:
        mode = ParamFuzzMode(mode)
    except ValueError:
        logger.warning(
            "Invalid fuzzing mode. Using random mode for Multiplier fuzzing."
        )
        mode = ParamFuzzMode.RANDOM

    # Multiplier is xs:byte, but min value is -3 and max value is 3
    # because of restriction in schema
    return gen_invalid_byte(
        mode=mode, min_val=-3, max_val=3, valid_val=valid_val
    )


def fuzz_unit(
    mode: str = "valid", unit_val: str = "", valid_val: Optional[str] = None
) -> Union[str, int, float]:
    """Fuzz unit

    Unit, unitSymbolType, enumeration, possible values:
    HOURS = "h", MINUTES = "m", SECONDS = "s", AMPERE = "A",
    VOLT = "V", WATT = "W", WATT_HOUR = "Wh".
    """

    # Convert mode to enum
    try:
        mode = ParamFuzzMode(mode)
    except ValueError:
        logger.warning(
            "Invalid fuzzing mode. Using random mode for Unit fuzzing."
        )
        mode = ParamFuzzMode.RANDOM

    match mode:
        case ParamFuzzMode.VALID:
            if valid_val is None:
                logger.warning(
                    "No valid value specified for Unit, "
                    "using default valid value randomly chosen from "
                    "unitSymbolType enum."
                )
                return random.choice(list(unitSymbolType)).value
            return valid_val
        case ParamFuzzMode.STRING:
            return gen_random_string(random.randint(1, 100))
        case ParamFuzzMode.SPECIAL_STRING:
            # TODO: Add something like valid string (maybe some random choice
            # from valid values)
            # and that pass to gen_malicous_string method
            # that method will append some invalid chars to valid string
            # valid_value = unit_val
            return gen_malicous_string()
        case ParamFuzzMode.INT:
            return gen_num()
        case ParamFuzzMode.NEGATIVE_INT:
            return gen_num(negative_flag=True)
        case ParamFuzzMode.FLOAT:
            return gen_num(float_flag=True)
        case ParamFuzzMode.NEGATIVE_FLOAT:
            return gen_num(float_flag=True, negative_flag=True)
        case _:
            if mode is not ParamFuzzMode.RANDOM:
                logger.warning(
                    "Invalid fuzzing mode for parameter with type "
                    "unitSymbolType (enumeration), using random mode."
                )
            invalid_string = gen_random_string(random.randint(1, 100))
            invalid_special_string = gen_malicous_string()
            invalid_num = gen_num()
            invalid_neg_num = gen_num(negative_flag=True)
            invalid_float_num = gen_num(float_flag=True)
            invalid_neg_float_num = gen_num(
                float_flag=True, negative_flag=True
            )
            return random.choice(
                [
                    invalid_string,
                    invalid_special_string,
                    invalid_num,
                    invalid_neg_num,
                    invalid_float_num,
                    invalid_neg_float_num,
                ]
            )


def fuzz_value(
    mode: str = "valid", valid_val: Optional[int] = None
) -> Union[str, int, float]:
    """Fuzz value

    Value is simpleType: xs:short (in xml schema)."""

    # Convert mode to enum
    try:
        mode = ParamFuzzMode(mode)
    except ValueError:
        logger.warning(
            "Invalid fuzzing mode. Using random mode for Value fuzzing."
        )
        mode = ParamFuzzMode.RANDOM

    return gen_invalid_short(mode=mode, valid_val=valid_val)


def fuzz_physical_value_type(
    modes: Optional[dict],
    unit_val: str = "",
    valid_values: Optional[dict] = None,
) -> dict:
    """Fuzz physical value type

    PhysicalValueType is complexType.
    PhysicalValueType contains 3 fields: Multiplier, Unit, Value.

    """
    if modes is None:
        modes = {}
    if valid_values is None:
        valid_values = {}

    for name in ["Multiplier", "Unit", "Value"]:
        # Attribute is not specified in config dict => don't fuzz it
        # => valid mode
        if name not in modes:
            modes[name] = ParamFuzzMode.VALID.value
        if name not in valid_values:
            valid_values[name] = None

    multiplier = fuzz_multiplier(
        modes["Multiplier"], valid_val=valid_values["Multiplier"]
    )
    unit = fuzz_unit(
        modes["Unit"], unit_val=unit_val, valid_val=valid_values["Unit"]
    )
    value = fuzz_value(modes["Value"], valid_val=valid_values["Value"])

    return {"Multiplier": multiplier, "Unit": unit, "Value": value}


def fuzz_evse_max_current(
    modes: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz evse max current.

    EVSEMaxCurrent is complexType: PhysicalValueType."""

    if modes is None:
        modes = {}
    if valid_values is None:
        valid_values = {}
    for name in ["EVSEMaxCurrent"]:
        if name not in modes:
            modes[name] = ParamFuzzMode.VALID.value
        if name not in valid_values:
            valid_values[name] = None

    return fuzz_physical_value_type(
        modes["EVSEMaxCurrent"],
        unit_val=unitSymbolType.AMPERE.value,
        valid_values=valid_values["EVSEMaxCurrent"],
    )


def fuzz_meter_id(mode: str = "valid", valid_val: Optional[int] = None):
    """Fuzz meter id

    MeterID is type xs:unsignedByte (in xml schema).
    """
    # Convert mode to enum
    try:
        mode = ParamFuzzMode(mode)
    except ValueError:
        logger.warning(
            "Invalid fuzzing mode. Using random mode for MeterID fuzzing."
        )
        mode = ParamFuzzMode.RANDOM

    return gen_invalid_unsigned_byte(mode=mode, valid_val=valid_val)


def fuzz_meter_reading(mode: str = "valid", valid_val: Optional[int] = None):
    """Fuzz meter reading

    MeterReading is type xs:unsignedLong (in xml schema).
    """
    # Convert mode to enum
    try:
        mode = ParamFuzzMode(mode)
    except ValueError:
        logger.warning(
            "Invalid fuzzing mode. Using random mode for MeterReading fuzzing."
        )
        mode = ParamFuzzMode.RANDOM

    return gen_invalid_unsigned_long(mode=mode, valid_val=valid_val)


def fuzz_sig_meter_reading(
    mode: str = "valid", valid_val: Optional[str] = None
):
    """Fuzz sig meter reading

    SigMeterReading is type xs:base64Binary, maxLength 64.
    """
    # Convert mode to enum
    try:
        mode = ParamFuzzMode(mode)
    except ValueError:
        logger.warning(
            "Invalid fuzzing mode for SigMeterReading, using random mode."
        )
        mode = ParamFuzzMode.RANDOM

    match mode:
        case ParamFuzzMode.VALID:
            if valid_val is None:
                logger.warning(
                    "No valid value specified for SigMeterReading,"
                    "using default valid value randomly chosen "
                    "from EVSENotificationType enum."
                )
                return random.randbytes(random.randint(1, 64)).hex()
            return valid_val
        case ParamFuzzMode.STRING:
            return gen_random_string(random.randint(1, 100))
        case ParamFuzzMode.SPECIAL_STRING:
            return gen_malicous_string()
        case ParamFuzzMode.LONG_HEX:
            return gen_invalid_base64_binary(max_length=64)
        case ParamFuzzMode.SPECIAL_HEX:
            return gen_malicous_hex()
        case ParamFuzzMode.INT:
            return gen_num()
        case ParamFuzzMode.NEGATIVE_INT:
            return gen_num(negative_flag=True)
        case ParamFuzzMode.FLOAT:
            return gen_num(float_flag=True)
        case ParamFuzzMode.NEGATIVE_FLOAT:
            return gen_num(float_flag=True, negative_flag=True)
        case _:
            if mode is not ParamFuzzMode.RANDOM:
                logger.warning(
                    "Invalid fuzzing mode for parameter with type "
                    "xs:base64Binary, using random mode."
                )
            invalid_string = gen_random_string(random.randint(1, 100))
            invalid_special_string = gen_malicous_string()
            invalid_hex_longer = gen_invalid_base64_binary(max_length=64)
            invalid_special_hex = gen_malicous_hex()
            invalid_num = gen_num()
            invalid_neg_num = gen_num(negative_flag=True)
            invalid_float_num = gen_num(float_flag=True)
            invalid_neg_float_num = gen_num(
                float_flag=True, negative_flag=True
            )

            return random.choice(
                [
                    invalid_string,
                    invalid_special_string,
                    invalid_hex_longer,
                    invalid_special_hex,
                    invalid_num,
                    invalid_neg_num,
                    invalid_float_num,
                    invalid_neg_float_num,
                ]
            )


def fuzz_meter_status(mode: str = "valid", valid_val: Optional[int] = None):
    """Fuzz meter status

    MeterStatus is type xs:short (in xml schema).
    """
    # Convert mode to enum
    try:
        mode = ParamFuzzMode(mode)
    except ValueError:
        logger.warning(
            "Invalid fuzzing mode for MeterStatus, using random mode."
        )
        mode = ParamFuzzMode.RANDOM

    # xs:short => valid values: -32768 to 32767

    return gen_invalid_short(mode=mode, valid_val=valid_val)


def fuzz_t_meter(mode: str = "valid", valid_val: Optional[int] = None):
    """Fuzz t meter

    TMeter is type xs:long (in xml schema).
    """
    # Convert mode to enum
    try:
        mode = ParamFuzzMode(mode)
    except ValueError:
        logger.warning("Invalid fuzzing mode for TMeter, using random mode.")
        mode = ParamFuzzMode.RANDOM

    return gen_invalid_long(mode=mode, valid_val=valid_val)


def fuzz_meter_info(
    modes: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz meter info

    MeterInfo is complexType: MeterInfoType.
    It contains 5 fields: MeterID, MeterReading, SigMeterReading, MeterStatus, TMeter.

    MeterID is type xs:unsignedByte (in xml schema).
    MeterReading is type xs:unsignedLong (in xml schema).
    SigMeterReading is type xs:base64Binary, maxLength 64.
    MeterStatus is type xs:short (in xml schema).
    TMeter is type xs:long (in xml schema).
    """

    if modes is None:
        modes = {}
    if valid_values is None:
        valid_values = {}

    for name in [
        "MeterID",
        "MeterReading",
        "SigMeterReading",
        "MeterStatus",
        "TMeter",
    ]:
        if name not in modes:
            modes[name] = ParamFuzzMode.VALID.value
        if name not in valid_values:
            valid_values[name] = None

    # xs:unsignedByte
    meter_id = fuzz_meter_id(
        modes["MeterID"], valid_val=valid_values["MeterID"]
    )

    # xs:unsignedLong, 0 and 18446744073709551615 are valid values
    meter_reading = fuzz_meter_reading(
        modes["MeterReading"], valid_val=valid_values["MeterReading"]
    )

    # xs:base64Binary, maxLength 64
    # binary datatypes (xs:hexBinary and xs:base64Binary),
    # for which lengths are expressed in number of bytes (8 bits) of binary data
    sig_meter_reading = fuzz_sig_meter_reading(
        modes["SigMeterReading"], valid_val=valid_values["SigMeterReading"]
    )

    # xs:short => valid values: -32768 to 32767
    meter_status = fuzz_meter_status(
        modes["MeterStatus"], valid_val=valid_values["MeterStatus"]
    )

    # xs:long => valid values: -9223372036854775808 to 9223372036854775807
    t_meter = fuzz_t_meter(modes["TMeter"], valid_val=valid_values["TMeter"])

    return {
        "MeterID": meter_id,
        "MeterReading": meter_reading,
        "SigMeterReading": sig_meter_reading,
        "MeterStatus": meter_status,
        "TMeter": t_meter,
    }


def fuzz_receipt_required(mode: str = "valid") -> Union[str, int, float]:
    """Fuzz receipt required

    ReceiptRequired is type xs:boolean (in xml schema).
    """
    # Convert mode to enum
    try:
        mode = ParamFuzzMode(mode)
    except ValueError:
        logger.warning(
            "Invalid fuzzing mode. Using random mode for ReceiptRequired fuzzing."
        )
        mode = ParamFuzzMode.RANDOM

    return gen_invalid_bool(mode=mode)


def fuzz_evse_present_voltage(
    modes: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz evse present voltage

    EVSEPresentVoltage is complexType: PhysicalValueType.
    """
    if modes is None:
        modes = {}
    if valid_values is None:
        valid_values = {}
    for name in ["EVSEPresentVoltage"]:
        if name not in modes:
            modes[name] = ParamFuzzMode.VALID.value
        if name not in valid_values:
            valid_values[name] = None

    return fuzz_physical_value_type(
        modes["EVSEPresentVoltage"],
        unit_val=unitSymbolType.VOLT.value,
        valid_values=valid_values["EVSEPresentVoltage"],
    )


def fuzz_evse_present_current(
    modes: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz evse present current

    EVSEPresentCurrent is complexType: PhysicalValueType.
    """
    # TODO
    # if isinstance(modes, dict):
    #    # If dict is empty
    #    if not modes:
    if modes is None:
        modes = {}
    if valid_values is None:
        valid_values = {}
    for name in ["EVSEPresentCurrent"]:
        if name not in modes:
            modes[name] = ParamFuzzMode.VALID.value
        if name not in valid_values:
            valid_values[name] = None

    return fuzz_physical_value_type(
        modes["EVSEPresentCurrent"],
        unit_val=unitSymbolType.AMPERE.value,
        valid_values=valid_values["EVSEPresentCurrent"],
    )


def fuzz_evse_current_limit_achieved(
    mode: str = "valid",
) -> Union[str, int, float]:
    """Fuzz evse current limit achieved

    EVSECurrentLimitAchieved is type xs:boolean (in xml schema).
    """
    # Convert mode to enum
    try:
        mode = ParamFuzzMode(mode)
    except ValueError:
        logger.warning(
            "Invalid fuzzing mode. Using random mode for EVSECurrentLimitAchieved fuzzing."
        )
        mode = ParamFuzzMode.RANDOM

    return gen_invalid_bool(mode=mode)


def fuzz_evse_voltage_limit_achieved(
    mode: str = "valid",
) -> Union[str, int, float]:
    """Fuzz evse voltage limit achieved

    EVSEVoltageLimitAchieved is type xs:boolean (in xml schema).
    """
    # Convert mode to enum
    try:
        mode = ParamFuzzMode(mode)
    except ValueError:
        logger.warning(
            "Invalid fuzzing mode. Using random mode for EVSEVoltageLimitAchieved fuzzing."
        )
        mode = ParamFuzzMode.RANDOM
    return gen_invalid_bool(mode=mode)


def fuzz_evse_power_limit_achieved(
    mode: str = "valid",
) -> Union[str, int, float]:
    """Fuzz evse power limit achieved

    EVSEPowerLimitAchieved is type xs:boolean (in xml schema).
    """
    # Convert mode to enum
    try:
        mode = ParamFuzzMode(mode)
    except ValueError:
        logger.warning(
            "Invalid fuzzing mode. Using random mode for EVSEPowerLimitAchieved fuzzing."
        )
        mode = ParamFuzzMode.RANDOM
    return gen_invalid_bool(mode=mode)


def fuzz_evse_maximum_voltage(
    modes: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz evse maximum voltage

    EVSEMaximumVoltage is complexType: PhysicalValueType.
    """

    if modes is None:
        modes = {}
    if valid_values is None:
        valid_values = {}

    for name in ["EVSEMaximumVoltage"]:
        if name not in modes:
            modes[name] = ParamFuzzMode.VALID.value
        if name not in valid_values:
            valid_values[name] = None

    return fuzz_physical_value_type(
        modes["EVSEMaximumVoltage"],
        unit_val=unitSymbolType.VOLT.value,
        valid_values=valid_values["EVSEMaximumVoltage"],
    )


def fuzz_evse_maximum_current(
    modes: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz evse maximum current

    EVSEMaximumCurrent is complexType: PhysicalValueType.
    """

    if modes is None:
        modes = {}
    if valid_values is None:
        valid_values = {}

    for name in ["EVSEMaximumVoltage"]:
        if name not in modes:
            modes[name] = ParamFuzzMode.VALID.value
        if name not in valid_values:
            valid_values[name] = None
    return fuzz_physical_value_type(
        modes["EVSEMaximumCurrent"],
        unit_val=unitSymbolType.AMPERE.value,
        valid_values=valid_values["EVSEMaximumCurrent"],
    )


def fuzz_evse_maximum_power(
    modes: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz evse maximum power

    EVSEMaximumPower is complexType: PhysicalValueType.
    """

    if modes is None:
        modes = {}
    if valid_values is None:
        valid_values = {}

    for name in ["EVSEMaximumVoltage"]:
        if name not in modes:
            modes[name] = ParamFuzzMode.VALID.value
        if name not in valid_values:
            valid_values[name] = None
    return fuzz_physical_value_type(
        modes["EVSEMaximumPower"],
        unit_val=unitSymbolType.WATT.value,
        valid_values=valid_values["EVSEMaximumPower"],
    )
