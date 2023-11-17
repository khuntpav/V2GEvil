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


# TODO: Convert all fuzz enum methods to use gen_invalid_string
# pass something like possible_values from enum fuzz method to gen_invalid_string
def fuzz_enum_type(attr_conf: Optional[dict] = None) -> Union[str, int, float]:
    """Fuzz enum type

    Enum type is xs:string, so valid value is string.
    Fuzzer should test values out of enum values.

    Relevant modes: random, string, special-string,
        int, negative-int, float, negative-float
    """
    raise NotImplementedError


def get_attr_conf_mode(
    attr_conf: Optional[dict] = None, attr_name: str = ""
) -> ParamFuzzMode:
    """Get fuzzing mode for attribute/field/parameter
    (these are used interchangeably)"""

    attr_conf = check_attr_conf_mode(attr_conf)
    try:
        mode = ParamFuzzMode(attr_conf["Mode"])
    except ValueError:
        logger.warning(
            "Invalid fuzzing mode for %s, using random mode.", attr_name
        )
        mode = ParamFuzzMode.RANDOM

    return mode


def general_datatype_fuzzing_method(
    required_fields: list,
    all_fields: list,
    attr_conf: Optional[dict] = None,
    valid_values: Optional[dict] = None,
    pairs_name_method: Optional[dict] = None,
    method_name: str = "",
) -> dict:
    """General fuzz method for complex datatype"""

    if attr_conf is None:
        attr_conf = {}
        for field in all_fields:
            attr_conf[field] = None
    # attr_conf is dict => empty or not empty
    else:
        # attr_conf is empty => pass to all required fields {}
        # => fuzz with random mode for end parameter
        # {} means random mode for every required field/parameter
        if not attr_conf:
            for field in required_fields:
                attr_conf[field] = {}
        # attr_conf is not empty
        else:
            # RequiredParams are specified in config => override required_fields
            if "RequiredParams" in attr_conf:
                # Responsibility is up to user
                if all(field in attr_conf for field in required_fields):
                    logger.warning(
                        "Not all required parameters are specified for fuzz in method %s. ",
                        method_name,
                    )
                required_fields = attr_conf["RequiredParams"]
                # Pop RequiredParams from attr_conf if present,
                # because for loop iterates through keys in attr_conf
                # which are Field/Parameter names
                attr_conf.pop("RequiredParams")

            # Field is in required_fields
            # but user didn't specify mode => pass {} to each parameter
            # => fuzz with random mode for end parameter
            # So not specified parameter will be fuzzed with random mode
            for field in required_fields:
                if field not in attr_conf:
                    attr_conf[field] = {}

    if valid_values is None:
        valid_values = {}

    res_dict = {}
    # Here is because of keep consistency with other methods for complexTypes
    for name in attr_conf.keys():
        # Attribute is not specified in config dict => don't fuzz it
        # => valid mode
        if name not in valid_values:
            valid_values[name] = None

        # Should never happen
        assert pairs_name_method is not None
        res_dict[name] = pairs_name_method[name](
            attr_conf=attr_conf[name], valid_values=valid_values[name]
        )

    return res_dict


def check_attr_conf_mode(attr_conf: Optional[dict] = None) -> dict:
    """This method checks if attr_conf is None or empty dict or dict without Mode key."""
    if attr_conf is None or len(attr_conf) == 0:
        attr_conf = {"Mode": "random"}
    elif "Mode" not in attr_conf:
        attr_conf["Mode"] = "random"

    return attr_conf


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

    # This is end parameter, so there is no passing None/{} to each sub parameter
    # => fuzz with random mode for end parameter
    # attr_conf == {}

    mode = get_attr_conf_mode(attr_conf, "SchemaID")

    return gen_invalid_unsigned_byte(mode=mode, valid_val=valid_values)


def fuzz_response_code(
    attr_conf: Optional[dict] = None, valid_values: Optional[str] = None
) -> Union[str, int, float]:
    """Fuzz response code

    ResponseCode is enum, so valid value is one of the enum values responseCodeType.
    Type responseCodeType is in MsgDataTypes.py.
    Fuzzer should test values out of enum values.

    Relevant modes: random, string, special-string,
        int, negative-int, float, negative-float
    """
    # This is end parameter, so there is no passing None/{} to each sub parameter
    # => fuzz with random mode for end parameter
    # attr_conf == {}
    mode = get_attr_conf_mode(attr_conf, "ResponseCode")

    match mode:
        case ParamFuzzMode.VALID:
            if valid_values is None:
                logger.warning(
                    "No valid value specified for ResponseCode, "
                    "using default valid value randomly chosen from "
                    "responseCodeType enum."
                )
                return random.choice(list(responseCodeType)).value
            return valid_values
        case ParamFuzzMode.STRING:
            return gen_random_string(random.randint(1, 100))
        case ParamFuzzMode.SPECIAL_STRING:
            if valid_values is None:
                logger.warning(
                    "No valid value specified for ResponseCode, "
                    "using default valid value randomly chosen from "
                    "responseCodeType enum."
                )
                valid_values = random.choice(list(responseCodeType)).value
            return gen_malicous_string(valid_string=valid_values)
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
    attr_conf: Optional[dict] = None, valid_values: Optional[str] = None
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
    # This is end parameter, so there is no passing None/{} to each sub parameter
    # => fuzz with random mode for end parameter
    mode = get_attr_conf_mode(attr_conf, "EVSEID")
    # After this attr_conf is not None and contains Mode key
    assert attr_conf is not None

    if "Type" not in attr_conf:
        attr_conf["Type"] = "string"
    val_type = attr_conf["Type"]

    match mode:
        case ParamFuzzMode.VALID:
            if valid_values is None:
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
            return valid_values
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
    attr_conf: Optional[dict] = None, valid_values: Optional[int] = None
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

    # This is end parameter, so there is no passing None/{} to each sub parameter
    # => fuzz with random mode for end parameter
    mode = get_attr_conf_mode(attr_conf, "EVSETimestamp")

    return gen_invalid_long(mode=mode, valid_val=valid_values)


def fuzz_payment_option(
    attr_conf: Optional[dict] = None, valid_values: Optional[str] = None
):
    """Fuzz payment option.

    PaymentOption is list of enum values.
    Valid values are defined in paymentOptionType enum:
        Contract, ExternalPayment
    """
    # This is end parameter, so there is no passing None/{} to each sub parameter
    mode = get_attr_conf_mode(attr_conf, "PaymentOption")

    match mode:
        case ParamFuzzMode.VALID:
            if valid_values is None:
                logger.warning(
                    "No valid value specified for PaymentOption, "
                    "using default valid value randomly chosen from "
                    "paymentOptionType enum."
                )
                return random.choice(list(paymentOptionType)).value
            return valid_values
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
    attr_conf: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz payment option list"""

    # This is not end parameter, so there is passing None/{} to each sub parameter

    pairs_name_method = {"PaymentOption": fuzz_payment_option}
    required_fields = ["PaymentOption"]
    all_fields = ["PaymentOption"]

    res_dict = {}
    # Call general method for fuzzing complexType
    res_dict = general_datatype_fuzzing_method(
        required_fields=required_fields,
        all_fields=all_fields,
        attr_conf=attr_conf,
        valid_values=valid_values,
        pairs_name_method=pairs_name_method,
    )

    return res_dict


def fuzz_energy_transfer_mode(
    attr_conf: Optional[dict] = None, valid_values: Optional[str] = None
):
    """Fuzz energy transfer mode.

    EnergyTransferMode enum values.
    """
    # This is end parameter, so there is no passing None/{} to each sub parameter
    mode = get_attr_conf_mode(attr_conf, "EnergyTransferMode")

    match mode:
        case ParamFuzzMode.VALID:
            if valid_values is None:
                logger.warning(
                    "No valid value specified for EnergyTransferMode, "
                    "using default valid value randomly chosen from "
                    "energyTransferModeType enum."
                )
                return random.choice(list(EnergyTransferModeType)).value
            return valid_values
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
    attr_conf: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz supported energy transfer mode"""

    pairs_name_method = {"EnergyTransferMode": fuzz_energy_transfer_mode}
    required_fields = ["EnergyTransferMode"]
    all_fields = ["EnergyTransferMode"]

    res_dict = {}
    # Call general method for fuzzing complexType
    res_dict = general_datatype_fuzzing_method(
        required_fields=required_fields,
        all_fields=all_fields,
        attr_conf=attr_conf,
        valid_values=valid_values,
        pairs_name_method=pairs_name_method,
    )

    # EnergyTransferMode is not list, but it is in SupportedEnergyTransferModeType
    res_dict["EnergyTransferMode"] = [res_dict["EnergyTransferMode"]]

    return res_dict


def fuzz_charge_service(
    attr_conf: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz charge service

    ChargeService is extension of ServiceType and combine with
    SupportedEnergyTransferModeType.
    """

    pairs_name_method = {
        "ServiceID": fuzz_service_id,
        "ServiceName": fuzz_service_name,
        "ServiceCategory": fuzz_service_category,
        "ServiceScope": fuzz_service_scope,
        "FreeService": fuzz_free_service,
        "SupportedEnergyTransferMode": fuzz_supported_energy_transfer_mode,
    }
    required_fields = [
        "ServiceID",
        "ServiceCategory",
        "FreeService",
        "SupportedEnergyTransferMode",
    ]
    all_fields = [
        "ServiceID",
        "ServiceName",
        "ServiceCategory",
        "ServiceScope",
        "FreeService",
        "SupportedEnergyTransferMode",
    ]

    res_dict = {}
    # Call general method for fuzzing complexType
    res_dict = general_datatype_fuzzing_method(
        required_fields=required_fields,
        all_fields=all_fields,
        attr_conf=attr_conf,
        valid_values=valid_values,
        pairs_name_method=pairs_name_method,
    )

    return res_dict


def fuzz_service_id(
    attr_conf: Optional[dict] = None, valid_values: Optional[int] = None
) -> Union[str, int, float]:
    """Fuzz service id

    ServiceID is type xs:unsignedShort (in xml schema), so valid values: 0-65535.
    """

    # This is end parameter, so there is no passing None/{} to each sub parameter
    mode = get_attr_conf_mode(attr_conf, "ServiceID")

    return gen_invalid_unsigned_short(mode=mode, valid_val=valid_values)


def fuzz_service_name(
    attr_conf: Optional[dict] = None, valid_values: Optional[str] = None
) -> Union[str, int, float]:
    """Fuzz service name

    ServiceName is type xs:string (in xml schema), (maxLength: 32).
    """
    # This is end parameter, so there is no passing None/{} to each sub parameter
    mode = get_attr_conf_mode(attr_conf, "ServiceName")

    match mode:
        case ParamFuzzMode.VALID:
            if valid_values is None:
                logger.warning(
                    "No valid value specified for ServiceName, "
                    "using default valid value randomly generated."
                    "Disclaimer: Generated value - meets the conditions for "
                    "length and type but may not meet the valid "
                    "value for particular parameter."
                )
                return gen_random_string(random.randint(1, 32))
            return valid_values

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
    attr_conf: Optional[dict] = None, valid_values: Optional[str] = None
) -> Union[str, int, float]:
    """Fuzz service category

    ServiceCategory is type serviceCategoryType,
    xs:string, enum, valid values are:
        EVCharging, Internet, ContractCertificate, OtherCustom
    """
    # This is end parameter, so there is no passing None/{} to each sub parameter
    mode = get_attr_conf_mode(attr_conf, "ServiceCategory")

    match mode:
        case ParamFuzzMode.VALID:
            if valid_values is None:
                logger.warning(
                    "No valid value specified for ServiceCategory, "
                    "using default valid value randomly chosen from "
                    "serviceCategoryType enum."
                )
                return random.choice(list(serviceCategoryType)).value

            return valid_values
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


def fuzz_service_scope(
    attr_conf: Optional[dict] = None, valid_values: Optional[str] = None
) -> Union[str, int, float]:
    """Fuzz ServiceScope

    serviceScopeType is xs:string in the schema, maxLength 64
    """

    # This is end parameter, so there is no passing None/{} to each sub parameter
    # => fuzz with random mode for end parameter
    mode = get_attr_conf_mode(attr_conf, "ServiceScope")

    match mode:
        case ParamFuzzMode.VALID:
            if valid_values is None:
                logger.warning(
                    "No valid value specified for ServiceName, "
                    "using default valid value randomly generated."
                    "Disclaimer: Generated value - meets the conditions for "
                    "length and type but may not meet the valid "
                    "value for particular parameter."
                )
                return gen_random_string(random.randint(1, 64))
            return valid_values

        case ParamFuzzMode.LONG_STRING:
            return gen_random_string(random.randint(65, 100))
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
            invalid_string = gen_random_string(random.randint(65, 100))
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


def fuzz_free_service(
    attr_conf: Optional[dict] = None, valid_values: Optional[bool] = None
):
    """Fuzz free service"""

    # This is end parameter, so there is no passing None/{} to each sub parameter
    mode = get_attr_conf_mode(attr_conf, "FreeService")

    return gen_invalid_bool(mode=mode)


def fuzz_service(
    attr_conf: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz service"""
    # valid_values dict has to be provided everytime
    # It goes from fuzzer module with values from default dictionary

    # Need to be None, otherwise {} it will be dangerous default value
    # in method definition]

    pairs_name_method = {
        "ServiceID": fuzz_service_id,
        "ServiceName": fuzz_service_name,
        "ServiceCategory": fuzz_service_category,
        "ServiceScope": fuzz_service_scope,
        "FreeService": fuzz_free_service,
    }
    required_fields = [
        "ServiceID",
        "ServiceCategory",
        "FreeService",
    ]
    all_fields = [
        "ServiceID",
        "ServiceName",
        "ServiceCategory",
        "ServiceScope",
        "FreeService",
    ]

    res_dict = {}
    # Call general method for fuzzing complexType
    res_dict = general_datatype_fuzzing_method(
        required_fields=required_fields,
        all_fields=all_fields,
        attr_conf=attr_conf,
        valid_values=valid_values,
        pairs_name_method=pairs_name_method,
    )

    return res_dict


def fuzz_service_list(
    attr_conf: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz service list"""

    pairs_name_method = {
        "Service": fuzz_service,
    }
    required_fields = ["Service"]
    all_fields = ["Service"]

    res_dict = {}
    # Call general method for fuzzing complexType
    res_dict = general_datatype_fuzzing_method(
        required_fields=required_fields,
        all_fields=all_fields,
        attr_conf=attr_conf,
        valid_values=valid_values,
        pairs_name_method=pairs_name_method,
    )

    # Service is not list, but it is in ServiceListType
    res_dict["Service"] = [res_dict["Service"]]

    return res_dict


def fuzz_parameter_name(
    attr_conf: Optional[dict] = None, valid_values: Optional[str] = None
) -> Union[str, int, float]:
    """Fuzz parameter name. In standard is defined as xs:string"""
    # This is end parameter, so there is no passing None/{} to each sub parameter
    mode = get_attr_conf_mode(attr_conf, "Parameter Name")
    # After this attr_conf is not None and contains Mode key
    assert attr_conf is not None

    if attr_conf["Mode"] == ParamFuzzMode.VALID:
        if valid_values is None:
            logger.warning(
                "No valid value specified for Parameter Name, "
                "using default valid value randomly chosen from "
                "parameterType enum."
            )
            valid_values = random.choice(["Protocol", "Port"])

    return gen_invalid_string(mode=mode, valid_val=valid_values)


def fuzz_parameter_type(
    attr_conf: Optional[dict] = None, valid_values: Optional[str] = None
) -> str:
    """Fuzz parameter type, Mode can be valid or random."""

    # Possible values for Parameter Type
    value_types = [
        "boolValue",
        "byteValue",
        "shortValue",
        "intValue",
        "physicalValue",
        "stringValue",
    ]

    # This is end parameter, so there is no passing None/{} to each sub parameter
    mode = get_attr_conf_mode(attr_conf, "Parameter Type")
    # After this attr_conf is not None
    assert attr_conf is not None

    if mode == ParamFuzzMode.VALID:
        if "value" not in attr_conf:
            logger.warning(
                "No valid value specified for Parameter Type, "
                "using default valid value randomly chosen from "
                "parameterType enum."
            )
            value_type = random.choice(value_types)
        value_type = attr_conf["value"]
    else:
        value_type = random.choice(value_types)

    if value_type not in value_types:
        logger.warning("Invalid value type for Parameter, using random mode.")
        value_type = random.choice(value_types)  # => value_type is valid

    return value_type


def fuzz_parameter_bool_value(
    attr_conf: Optional[dict] = None, valid_values: Optional[bool] = None
):
    """Fuzz parameter boolValue"""
    # This is end parameter, so there is no passing None/{} to each sub parameter
    mode = get_attr_conf_mode(attr_conf, "Parameter Value")

    return gen_invalid_bool(mode=mode)


def fuzz_parameter_byte_value(
    attr_conf: Optional[dict] = None, valid_values: Optional[int] = None
):
    """Fuzz parameter byteValue"""
    # This is end parameter, so there is no passing None/{} to each sub parameter
    mode = get_attr_conf_mode(attr_conf, "Parameter Value")

    return gen_invalid_byte(mode=mode, valid_val=valid_values)


def fuzz_parameter_short_value(
    attr_conf: Optional[dict] = None, valid_values: Optional[int] = None
):
    """Fuzz parameter shortValue"""
    # This is end parameter, so there is no passing None/{} to each sub parameter
    mode = get_attr_conf_mode(attr_conf, "Parameter Value")

    return gen_invalid_short(mode=mode, valid_val=valid_values)


def fuzz_parameter_int_value(
    attr_conf: Optional[dict] = None, valid_values: Optional[int] = None
):
    """Fuzz parameter intValue"""
    # This is end parameter, so there is no passing None/{} to each sub parameter
    mode = get_attr_conf_mode(attr_conf, "Parameter Value")

    return gen_invalid_int(mode=mode, valid_val=valid_values)


def fuzz_parameter_string_value(
    attr_conf: Optional[dict] = None, valid_values: Optional[str] = None
):
    """Fuzz parameter stringValue"""
    # This is end parameter, so there is no passing None/{} to each sub parameter
    mode = get_attr_conf_mode(attr_conf, "Parameter Value")

    return gen_invalid_string(mode=mode, valid_val=valid_values)


def fuzz_parameter(
    attr_conf: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz parameter

    Parameter is complex type, so it has attributes and elements.
    In XSD defined as: parameterType.
    """

    pairs_name_method = {
        "@Name": fuzz_parameter_name,
        "boolValue": fuzz_parameter_bool_value,
        "byteValue": fuzz_parameter_byte_value,
        "shortValue": fuzz_parameter_short_value,
        "intValue": fuzz_parameter_int_value,
        "physicalValue": fuzz_physical_value_type,
        "stringValue": fuzz_parameter_string_value,
    }
    required_fields = ["@Name"]
    all_fields = ["@Name"]

    # Based on type add value_type to pairs_name_method

    # Only in conf is "Name", but in XSD is attribute not element
    # therefor change it to @Name
    if attr_conf is None:
        attr_conf = {}
    if "Name" in attr_conf:
        attr_conf["@Name"] = attr_conf.pop("Name")

    value_type = fuzz_parameter_type(attr_conf=attr_conf["Type"])
    required_fields.append(value_type)
    all_fields.append(value_type)
    attr_conf.pop("Type")
    attr_conf[value_type] = attr_conf.pop("Value")
    # After this in attr_conf is only @Name and value_type
    # value_type is one of the value_types => for ex.:
    # attr_conf {"@Name": "Port", "intValue": 12}

    res_dict = {}
    # Call general method for fuzzing complexType
    res_dict = general_datatype_fuzzing_method(
        required_fields=required_fields,
        all_fields=all_fields,
        attr_conf=attr_conf,
        valid_values=valid_values,
        pairs_name_method=pairs_name_method,
    )
    return res_dict


def fuzz_parameter_set_id(
    attr_conf: Optional[dict] = None, valid_values: Optional[int] = None
):
    """Fuzz ParameterSetID"""
    # This is end parameter, so there is no passing None/{} to each sub parameter
    mode = get_attr_conf_mode(attr_conf, "ParameterSetID")

    return gen_invalid_short(mode=mode, valid_val=valid_values)


def fuzz_parameter_set(
    attr_conf: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz parameter set"""

    pairs_name_method = {
        "ParameterSetID": fuzz_parameter_set_id,
        "Parameter": fuzz_parameter,
    }
    required_fields = ["ParameterSetID", "Parameter"]
    all_fields = ["ParameterSetID", "Parameter"]

    res_dict = {}
    # Call general method for fuzzing complexType
    res_dict = general_datatype_fuzzing_method(
        required_fields=required_fields,
        all_fields=all_fields,
        attr_conf=attr_conf,
        valid_values=valid_values,
        pairs_name_method=pairs_name_method,
    )

    # List of parameterType
    res_dict["Parameter"] = [res_dict["Parameter"]]

    return res_dict


def fuzz_service_parameter_list(
    attr_conf: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz service detail list"""

    pairs_name_method = {
        "ParameterSet": fuzz_parameter_set,
    }
    required_fields = ["ParameterSet"]
    all_fields = ["ParameterSet"]

    res_dict = {}
    # Call general method for fuzzing complexType
    res_dict = general_datatype_fuzzing_method(
        required_fields=required_fields,
        all_fields=all_fields,
        attr_conf=attr_conf,
        valid_values=valid_values,
        pairs_name_method=pairs_name_method,
    )

    # List of parameterSetType
    res_dict["ParameterSet"] = [res_dict["ParameterSet"]]
    return res_dict


def fuzz_gen_challenge(
    attr_conf: Optional[dict] = None, valid_values: Optional[str] = None
) -> Union[str, int, float]:
    """Fuzz gen challenge

    GenChallenge is type base64Binary (in xml schema), (length 16).
    GenChallenge should be exactly 16 bytes long (128 bits).

    From ISO15118-2 example on page 330, length is length of the data before
    base64 encoding. Use of UTF-8 encoding is required.
    Example: 'U29tZSBSYW5kb20gRGF0YQ==' => 'Some Random Data'
    """
    # This is end parameter, so there is no passing None/{} to each sub parameter
    mode = get_attr_conf_mode(attr_conf, "GenChallenge")

    # str to base64 encoding => str to bytes => bytes to base64 encoding
    # base64.b64encode(str.encode('utf-8')) or base64.b64encode(bytes(str, 'utf-8'))
    # base64 to str => base64 to bytes => bytes to str
    # base64.b64decode(base64_encoded_str).decode('utf-8')
    # Convert mode to enum

    match mode:
        case ParamFuzzMode.VALID:
            if valid_values is None:
                # Generate valid base64 binary, because the length is 16
                # => valid value is base64 encoded 16 bytes long binary
                return gen_invalid_base64_binary(length=16)
            return valid_values
        case ParamFuzzMode.LONG_BASE64:
            # Generate base64 binary with length > 16
            return gen_invalid_base64_binary(max_length=16)
        case ParamFuzzMode.SHORT_BASE64:
            # Generate base64 binary with length < 16
            return gen_invalid_base64_binary(min_length=16)
        case ParamFuzzMode.SPECIAL_BASE64:
            if valid_values is None:
                valid_values = gen_invalid_base64_binary(length=16)
            return gen_malicous_base64(valid_base64=valid_values)
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
    attr_conf: Optional[dict] = None, valid_values: Optional[str] = None
) -> Union[str, int, float]:
    """Fuzz evse processing status.

    EVSEProcessing is enum, so valid value is one of the enum values EVSEProcessingType.

    Type EVSEProcessingType is defined in MsgDataTypes.py.
    Fuzzer should test values out of enum values.
    """
    # This is end parameter, so there is no passing None/{} to each sub parameter
    mode = get_attr_conf_mode(attr_conf, "EVSEProcessing")

    match mode:
        case ParamFuzzMode.VALID:
            if valid_values is None:
                logger.warning(
                    "No valid value specified for EVSEProcessing, "
                    "using default valid value randomly chosen from "
                    "EVSEProcessingType enum."
                )
                return random.choice(list(EVSEProcessingType)).value
            return valid_values
        case ParamFuzzMode.STRING:
            return gen_random_string(random.randint(1, 100))
        case ParamFuzzMode.SPECIAL_STRING:
            if valid_values is None:
                valid_values = random.choice(list(EVSEProcessingType)).value
            return gen_malicous_string(valid_string=valid_values)
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


def fuzz_start_timeinterval(
    attr_conf: Optional[dict] = None, valid_values: Optional[int] = None
) -> Union[str, int, float]:
    """Fuzz start parameter of time interval"""

    # This is end parameter, so there is passing None/{} to each sub parameter
    start_mode = get_attr_conf_mode(attr_conf, "Start of time interval")

    # start, xs:unsignedInt, minInclusive value="0", maxInclusive value="16777214"
    start = gen_invalid_unsigned_int(
        mode=start_mode,
        min_val=0,
        max_val=16777214,
        valid_val=valid_values,
    )

    return start


def fuzz_duration_timeinterval(
    attr_conf: Optional[dict] = None, valid_values: Optional[int] = None
) -> Union[str, int, float]:
    """Fuzz duration parameter of time interval"""

    # This is end parameter, so there is passing None/{} to each sub parameter
    duration_mode = get_attr_conf_mode(attr_conf, "Duration of time interval")

    # duration, xs:unsignedInt, minInclusive value="0", maxInclusive value="86400"
    duration = gen_invalid_unsigned_int(
        mode=duration_mode,
        min_val=0,
        max_val=86400,
        valid_val=valid_values,
    )

    return duration


def fuzz_time_interval(
    attr_conf: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    pairs_name_method = {
        "start": fuzz_start_timeinterval,
        "duration": fuzz_duration_timeinterval,
    }
    required_fields = ["start"]
    all_fields = ["start", "duration"]

    res_dict = {}
    # Call general method for fuzzing complexType
    res_dict = general_datatype_fuzzing_method(
        required_fields=required_fields,
        all_fields=all_fields,
        attr_conf=attr_conf,
        valid_values=valid_values,
        pairs_name_method=pairs_name_method,
    )

    return res_dict


def fuzz_p_max(
    attr_conf: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz PMax"""

    return fuzz_physical_value_type(
        modes=attr_conf,
        unit_val=unitSymbolType.WATT.value,
        valid_values=valid_values,
    )


def fuzz_p_max_schedule_entry(
    attr_conf: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz PMaxScheduleEntry"""

    pairs_name_method = {
        "TimeInterval": fuzz_time_interval,
        "PMax": fuzz_p_max,
    }
    required_fields = ["TimeInterval", "PMax"]
    all_fields = ["TimeInterval", "PMax"]

    res_dict = {}
    # Call general method for fuzzing complexType
    res_dict = general_datatype_fuzzing_method(
        required_fields=required_fields,
        all_fields=all_fields,
        attr_conf=attr_conf,
        valid_values=valid_values,
        pairs_name_method=pairs_name_method,
    )

    return res_dict


def fuzz_p_max_schedule(
    attr_conf: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz PMaxSchedule"""

    pairs_name_method = {
        "PMaxScheduleEntry": fuzz_p_max_schedule_entry,
    }
    required_fields = ["PMaxScheduleEntry"]
    all_fields = ["PMaxScheduleEntry"]

    res_dict = {}

    # Call general method for fuzzing complexType
    res_dict = general_datatype_fuzzing_method(
        required_fields=required_fields,
        all_fields=all_fields,
        attr_conf=attr_conf,
        valid_values=valid_values,
        pairs_name_method=pairs_name_method,
    )
    # PMaxScheduleEntry is not list, but it is in PMaxScheduleType
    res_dict["PMaxScheduleEntry"] = [res_dict["PMaxScheduleEntry"]]

    return res_dict


def fuzz_id(
    attr_conf: Optional[dict] = None, valid_values: Optional[str] = None
) -> Union[str, int, float]:
    """Fuzz Id"""
    # This is end parameter, so there is no passing None/{} to each sub parameter
    mode = get_attr_conf_mode(attr_conf, "Id")

    return gen_invalid_id(mode=mode, valid_val=valid_values)


def fuzz_sales_tariff_id(
    attr_conf: Optional[dict] = None, valid_values: Optional[int] = None
) -> Union[str, int, float]:
    """Fuzz sales tariff id

    SalesTariffID is type xs:unsignedByte (in xml schema), with restriction:
        minInclusive value="1", maxInclusive value="255", valid values: 1-255
    """
    # This is end parameter, so there is no passing None/{} to each sub parameter
    mode = get_attr_conf_mode(attr_conf, "SalesTariffID")

    return gen_invalid_unsigned_byte(
        mode=mode, min_val=1, max_val=255, valid_val=valid_values
    )


def fuzz_sales_tariff_description(
    attr_conf: Optional[dict] = None, valid_values: Optional[str] = None
) -> Union[str, int, float]:
    """Fuzz sales tariff description

    SalesTariffDescription is type xs:string (in xml schema), (maxLength: 32).
    """
    # This is end parameter, so there is no passing None/{} to each sub parameter
    mode = get_attr_conf_mode(attr_conf, "SalesTariffDescription")

    return gen_invalid_string(mode=mode, max_len=32, valid_val=valid_values)


def fuzz_num_e_price_levels(
    attr_conf: Optional[dict] = None, valid_values: Optional[int] = None
):
    """Fuzz num e price levels

    NumEPriceLevels is type xs:unsignedByte (in xml schema)
    """
    # This is end parameter, so there is no passing None/{} to each sub parameter
    mode = get_attr_conf_mode(attr_conf, "NumEPriceLevels")

    # TODO: maybe add only valid value = 1 => 1 EPriceLevel

    return gen_invalid_unsigned_byte(mode=mode, valid_val=valid_values)


def fuzz_e_price_level(
    attr_conf: Optional[dict] = None, valid_values: Optional[int] = None
) -> Union[str, int, float]:
    """Fuzz EPriceLevel

    EPriceLevel is type xs:unsignedByte (in xml schema)
    """
    # This is end parameter, so there is no passing None/{} to each sub parameter
    mode = get_attr_conf_mode(attr_conf, "EPriceLevel")

    # TODO: maybe add only valid value = 1 => 1 EPriceLevel
    return gen_invalid_unsigned_byte(mode=mode, valid_val=valid_values)


def fuzz_cost_kind(
    attr_conf: Optional[dict] = None, valid_values: Optional[int] = None
) -> Union[str, int, float]:
    """Fuzz cost kind

    costKind is enum, so valid value is one of the enum values costKindType.
    """
    # This is end parameter, so there is no passing None/{} to each sub parameter
    mode = get_attr_conf_mode(attr_conf, "costKind")

    match mode:
        case ParamFuzzMode.VALID:
            if valid_values is None:
                logger.warning(
                    "No valid value specified for CostKind, "
                    "using default valid value randomly chosen from "
                    "costKindType enum."
                )
                return random.choice(list(costKindType)).value
            return valid_values
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


def fuzz_amount(
    attr_conf: Optional[dict] = None, valid_values: Optional[int] = None
):
    """Fuzz amount

    amount is type xs:unsignedInt (in xml schema)
    """
    # This is end parameter, so there is no passing None/{} to each sub parameter
    mode = get_attr_conf_mode(attr_conf, "amount")

    return gen_invalid_unsigned_int(mode=mode, valid_val=valid_values)


def fuzz_amount_multiplier(
    attr_conf: Optional[dict] = None, valid_values: Optional[int] = None
):
    """Fuzz amount multiplier

    amountMultiplier is type xs:byte (in xml schema), with restrictions:
        minInclusive value="-3", maxInclusive value="3"
    """
    # This is end parameter, so there is no passing None/{} to each sub parameter
    mode = get_attr_conf_mode(attr_conf, "amountMultiplier")

    return gen_invalid_byte(
        mode=mode, min_val=-3, max_val=3, valid_val=valid_values
    )


def fuzz_cost(
    attr_conf: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz cost

    Cost is complex type, so it has elements: costKind, amount, amountMultiplier
    """

    pairs_name_method = {
        "costKind": fuzz_cost_kind,
        "amount": fuzz_amount,
        "amountMultiplier": fuzz_amount_multiplier,
    }
    required_fields = ["costKind", "amount", "amountMultiplier"]
    all_fields = ["costKind", "amount", "amountMultiplier"]

    res_dict = {}
    # Call general method for fuzzing complexType
    res_dict = general_datatype_fuzzing_method(
        required_fields=required_fields,
        all_fields=all_fields,
        attr_conf=attr_conf,
        valid_values=valid_values,
        pairs_name_method=pairs_name_method,
    )

    return res_dict


def fuzz_start_value(
    attr_conf: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz startValue from ConsumptionCost

    startValue has WATT as unit (Table 68 in ISO15118-2)
    """
    return fuzz_physical_value_type(
        modes=attr_conf,
        unit_val=unitSymbolType.WATT.value,
        valid_values=valid_values,
    )


def fuzz_consumption_cost(
    attr_conf: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz consumption cost

    ConsumptionCost is complex type, so it has elements: startValue, Cost
    """
    pairs_name_method = {"startValue": fuzz_start_value, "Cost": fuzz_cost}
    required_fields = ["startValue", "Cost"]
    all_fields = ["startValue", "Cost"]

    res_dict = {}
    # Call general method for fuzzing complexType
    res_dict = general_datatype_fuzzing_method(
        required_fields=required_fields,
        all_fields=all_fields,
        attr_conf=attr_conf,
        valid_values=valid_values,
        pairs_name_method=pairs_name_method,
    )

    res_dict["Cost"] = [res_dict["Cost"]]

    return res_dict


def fuzz_sales_tariff_entry(
    attr_conf: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz SalesTariffEntry"""

    pairs_name_method = {
        "RelativeTimeInterval": fuzz_time_interval,
        "EPriceLevel": fuzz_e_price_level,
        "ConsumptionCost": fuzz_consumption_cost,
    }
    required_fields = ["RelativeTimeInterval"]
    all_fields = ["RelativeTimeInterval", "EPriceLevel", "ConsumptionCost"]

    res_dict = {}

    # Call general method for fuzzing complexType
    res_dict = general_datatype_fuzzing_method(
        required_fields=required_fields,
        all_fields=all_fields,
        attr_conf=attr_conf,
        valid_values=valid_values,
        pairs_name_method=pairs_name_method,
    )

    # ConsumptionCost is not list, but it is in SalesTariffEntryType
    res_dict["ConsumptionCost"] = [res_dict["ConsumptionCost"]]

    return res_dict


def fuzz_sales_tariff(
    attr_conf: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz sales tariff"""

    pairs_name_method = {
        "@Id": fuzz_id,
        "SalesTariffID": fuzz_sales_tariff_id,
        "SalesTariffDescription": fuzz_sales_tariff_description,
        "NumEPriceLevels": fuzz_num_e_price_levels,
        "SalesTariffEntry": fuzz_sales_tariff_entry,
    }
    if attr_conf and "Id" in attr_conf:
        attr_conf["@Id"] = attr_conf.pop("Id")

    required_fields = ["@Id", "SalesTariffID", "SalesTariffEntry"]
    all_fields = [
        "@Id",
        "SalesTariffID",
        "SalesTariffDescription",
        "NumEPriceLevels",
        "SalesTariffEntry",
    ]

    res_dict = {}

    res_dict = general_datatype_fuzzing_method(
        required_fields=required_fields,
        all_fields=all_fields,
        attr_conf=attr_conf,
        valid_values=valid_values,
        pairs_name_method=pairs_name_method,
    )

    # SalesTariffEntry is not list, but it is in SalesTariffType
    res_dict["SalesTariffEntry"] = [res_dict["SalesTariffEntry"]]

    return res_dict


def fuzz_sa_schedule_tuple(
    attr_conf: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz sa schedule tuple"""

    pairs_name_method = {
        "SAScheduleTupleID": fuzz_sa_schedule_tuple_id,
        "PMaxSchedule": fuzz_p_max_schedule,
        "SalesTariff": fuzz_sales_tariff,
    }
    required_fields = ["SAScheduleTupleID", "PMaxSchedule", "SalesTariff"]
    all_fields = list(pairs_name_method.keys())

    res_dict = {}

    res_dict = general_datatype_fuzzing_method(
        required_fields=required_fields,
        all_fields=all_fields,
        attr_conf=attr_conf,
        valid_values=valid_values,
        pairs_name_method=pairs_name_method,
    )

    return res_dict


def fuzz_sa_schedule_list(
    attr_conf: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz sa schedule list"""

    pairs_name_method = {"SAScheduleTuple": fuzz_sa_schedule_tuple}
    required_fields = ["SAScheduleTuple"]
    all_fields = ["SAScheduleTuple"]

    res_dict = {}

    res_dict = general_datatype_fuzzing_method(
        required_fields=required_fields,
        all_fields=all_fields,
        attr_conf=attr_conf,
        valid_values=valid_values,
        pairs_name_method=pairs_name_method,
    )

    # SAScheduleTuple is not list, but it is in SAScheduleListType
    res_dict["SAScheduleTuple"] = [res_dict["SAScheduleTuple"]]

    return res_dict


def fuzz_evse_nominal_voltage(
    attr_conf: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz evse nominal voltage"""

    return fuzz_physical_value_type(
        modes=attr_conf,
        unit_val=unitSymbolType.VOLT.value,
        valid_values=valid_values,
    )


def fuzz_ac_evse_charge_parameter(
    attr_conf: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz ac evse charge parameter"""

    pairs_name_method = {
        "AC_EVSEStatus": fuzz_ac_evse_status,
        "EVSENominalVoltage": fuzz_evse_nominal_voltage,
        "EVSEMaxCurrent": fuzz_evse_max_current,
    }
    required_fields = ["AC_EVSEStatus", "EVSENominalVoltage", "EVSEMaxCurrent"]
    all_fields = list(pairs_name_method.keys())

    res_dict = {}

    res_dict = general_datatype_fuzzing_method(
        required_fields=required_fields,
        all_fields=all_fields,
        attr_conf=attr_conf,
        valid_values=valid_values,
        pairs_name_method=pairs_name_method,
    )

    return res_dict


def fuzz_evse_max_current_limit(
    attr_conf: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz evse max current limit"""

    return fuzz_physical_value_type(
        modes=attr_conf,
        unit_val=unitSymbolType.AMPERE.value,
        valid_values=valid_values,
    )


def fuzz_evse_max_power_limit(
    attr_conf: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz evse max power limit"""

    return fuzz_physical_value_type(
        modes=attr_conf,
        unit_val=unitSymbolType.WATT.value,
        valid_values=valid_values,
    )


def fuzz_evse_max_voltage_limit(
    attr_conf: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz evse max voltage limit"""

    return fuzz_physical_value_type(
        modes=attr_conf,
        unit_val=unitSymbolType.VOLT.value,
        valid_values=valid_values,
    )


def fuzz_evse_min_current_limit(
    attr_conf: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz evse min current limit"""

    return fuzz_physical_value_type(
        modes=attr_conf,
        unit_val=unitSymbolType.AMPERE.value,
        valid_values=valid_values,
    )


def fuzz_evse_min_voltage_limit(
    attr_conf: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz evse min voltage limit"""

    return fuzz_physical_value_type(
        modes=attr_conf,
        unit_val=unitSymbolType.VOLT.value,
        valid_values=valid_values,
    )


def fuzz_evse_current_regulation_tolerance(
    attr_conf: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz evse current regulation tolerance"""

    return fuzz_physical_value_type(
        modes=attr_conf,
        unit_val=unitSymbolType.AMPERE.value,
        valid_values=valid_values,
    )


def fuzz_evse_peak_current_ripple(
    attr_conf: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz evse peak current ripple"""

    return fuzz_physical_value_type(
        modes=attr_conf,
        unit_val=unitSymbolType.AMPERE.value,
        valid_values=valid_values,
    )


def fuzz_evse_energy_to_be_delivered(
    attr_conf: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz evse energy to be delivered"""

    return fuzz_physical_value_type(
        modes=attr_conf,
        unit_val=unitSymbolType.WATT_HOUR.value,
        valid_values=valid_values,
    )


def fuzz_dc_evse_charge_parameter(
    attr_conf: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz dc evse charge parameter"""

    pairs_name_method = {
        "DC_EVSEStatus": fuzz_dc_evse_status,
        "EVSEMaxCurrentLimit": fuzz_evse_max_current_limit,
        "EVSEMaxPowerLimit": fuzz_evse_max_power_limit,
        "EVSEMaxVoltageLimit": fuzz_evse_max_voltage_limit,
        "EVSEMinCurrentLimit": fuzz_evse_min_current_limit,
        "EVSEMinVoltageLimit": fuzz_evse_min_voltage_limit,
        "EVSECurrentRegulationTolerance": fuzz_evse_current_regulation_tolerance,
        "EVSEPeakCurrentRipple": fuzz_evse_peak_current_ripple,
        "EVSEEnergyToBeDelivered": fuzz_evse_energy_to_be_delivered,
    }
    required_fields = [
        "DC_EVSEStatus",
        "EVSEMaxCurrentLimit",
        "EVSEMaxPowerLimit",
        "EVSEMaxVoltageLimit",
        "EVSEMinCurrentLimit",
        "EVSEMinVoltageLimit",
        "EVSEPeakCurrentRipple",
    ]
    all_fields = list(pairs_name_method.keys())

    res_dict = {}
    res_dict = general_datatype_fuzzing_method(
        required_fields=required_fields,
        all_fields=all_fields,
        attr_conf=attr_conf,
        valid_values=valid_values,
        pairs_name_method=pairs_name_method,
    )

    return res_dict


def fuzz_notification_max_delay(
    attr_conf: Optional[dict] = None, valid_values: Optional[int] = None
) -> Union[str, int, float]:
    """Fuzz Notification max delay

    NotificationMaxDelay is type xs:unsignedShort
    """
    # This is end parameter, so there is no passing None/{} to each sub parameter
    mode = get_attr_conf_mode(attr_conf, "NotificationMaxDelay")

    return gen_invalid_unsigned_short(mode=mode, valid_val=valid_values)


def fuzz_evse_notification(
    attr_conf: Optional[dict] = None, valid_values: Optional[str] = None
) -> Union[str, int, float]:
    """Fuzz evse notification

    EVSENotification type is enum, so valid value is one of the enum values EVSENotificationType.
    """
    # This is end parameter, so there is no passing None/{} to each sub parameter
    mode = get_attr_conf_mode(attr_conf, "EVSENotification")

    match mode:
        case ParamFuzzMode.VALID:
            if valid_values is None:
                logger.warning(
                    "No valid value specified for EVSENotification,"
                    "using default valid value randomly chosen "
                    "from EVSENotificationType enum."
                )
                return random.choice(list(EVSENotificationType)).value
            return valid_values
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
    attr_conf: Optional[dict] = None, valid_values: Optional[str] = None
) -> Union[str, int, float]:
    """Fuzz RCD"""

    # This is end parameter, so there is no passing None/{} to each sub parameter
    mode = get_attr_conf_mode(attr_conf, "RCD")

    # TODO: Valid val is True or False, not used valid_val for now
    return gen_invalid_bool(mode=mode)


def fuzz_ac_evse_status(
    attr_conf: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz ac evse status"""

    pairs_name_method = {
        "NotificationMaxDelay": fuzz_notification_max_delay,
        "EVSENotification": fuzz_evse_notification,
        "RCD": fuzz_rcd,
    }
    required_fields = ["NotificationMaxDelay", "EVSENotification", "RCD"]
    all_fields = ["EVSENotification", "EVSENotification", "RCD"]

    res_dict = {}
    res_dict = general_datatype_fuzzing_method(
        required_fields=required_fields,
        all_fields=all_fields,
        attr_conf=attr_conf,
        valid_values=valid_values,
        pairs_name_method=pairs_name_method,
    )
    return res_dict


def fuzz_evse_isolation_status(
    attr_conf: Optional[dict] = None, valid_values: Optional[str] = None
) -> Union[str, int, float]:
    """Fuzz evse isolation status"""

    # This is end parameter, so there is no passing None/{} to each sub parameter
    mode = get_attr_conf_mode(attr_conf, "EVSEIsolationStatus")

    match mode:
        case ParamFuzzMode.VALID:
            if valid_values is None:
                logger.warning(
                    "No valid value specified for EVSEIsolationStatus,"
                    "using default valid value randomly chosen "
                    "from EVSEIsolationStatusType enum."
                )
                return random.choice(list(isolationLevelType)).value
            return valid_values
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
    attr_conf: Optional[dict] = None, valid_values: Optional[str] = None
) -> Union[str, int, float]:
    """ "Fuzz DC EVSE Status Code

    DC_EVSEStatusCode is enum, so valid value is one of the enum values DC_EVSEStatusCodeType.
    """
    # This is end parameter, so there is no passing None/{} to each sub parameter
    mode = get_attr_conf_mode(attr_conf, "DC_EVSEStatusCode")

    match mode:
        case ParamFuzzMode.VALID:
            if valid_values is None:
                logger.warning(
                    "No valid value specified for DC_EVSEStatusCode,"
                    "using default valid value randomly chosen "
                    "from DC_EVSEStatusCodeType enum."
                )
                return random.choice(list(DC_EVSEStatusCodeType)).value
            return valid_values
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
    attr_conf: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz dc evse status"""

    pairs_name_method = {
        "NotificationMaxDelay": fuzz_notification_max_delay,
        "EVSENotification": fuzz_evse_notification,
        "EVSEIsolationStatus": fuzz_evse_isolation_status,
        "EVSEStatusCode": fuzz_dc_evse_status_code,
    }
    required_fields = [
        "NotificationMaxDelay",
        "EVSENotification",
        "EVSEStatusCode",
    ]
    all_fields = [
        "NotificationMaxDelay",
        "EVSENotification",
        "EVSEIsolationStatus",
        "EVSEStatusCode",
    ]

    res_dict = {}
    res_dict = general_datatype_fuzzing_method(
        required_fields=required_fields,
        all_fields=all_fields,
        attr_conf=attr_conf,
        valid_values=valid_values,
        pairs_name_method=pairs_name_method,
    )

    return res_dict


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
    attr_conf: Optional[dict] = None, valid_values: Optional[int] = None
) -> Union[str, int, float]:
    """Fuzz sa schedule tuple id

    SAScheduleTupleID is type SAIDType:
    xs:unsignedByte (0-255) (in xml schema), with restriction
    that value must be in range 1-255.

    But for some message is SAScheduleTupleID type SAIDType and
    short in semantics and type definition for some messages in ISO15118-2.
    """
    # This is end parameter, so there is no passing None/{} to each sub parameter
    mode = get_attr_conf_mode(attr_conf, "SAScheduleTupleID")

    return gen_invalid_unsigned_byte(
        mode=mode, min_val=1, max_val=255, valid_val=valid_values
    )


def fuzz_multiplier(
    mode: str = "random", valid_val: Optional[int] = None
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
    mode: str = "random", valid_val: Optional[str] = None
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
            if valid_val is None:
                logger.warning(
                    "No valid value specified for Unit, "
                    "using default valid value randomly chosen from "
                    "unitSymbolType enum."
                )
                valid_val = random.choice(list(unitSymbolType)).value
            return gen_malicous_string(valid_string=valid_val)
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
    mode: str = "random", valid_val: Optional[int] = None
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
            modes[name] = ParamFuzzMode.RANDOM.value
        if name not in valid_values:
            valid_values[name] = None

    multiplier = fuzz_multiplier(
        modes["Multiplier"], valid_val=valid_values["Multiplier"]
    )
    if valid_values["Unit"] is None:
        valid_values["Unit"] = unit_val
    unit = fuzz_unit(modes["Unit"], valid_val=valid_values["Unit"])
    value = fuzz_value(modes["Value"], valid_val=valid_values["Value"])

    return {"Multiplier": multiplier, "Unit": unit, "Value": value}


def fuzz_evse_max_current(
    attr_conf: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz evse max current.

    EVSEMaxCurrent is complexType: PhysicalValueType."""

    return fuzz_physical_value_type(
        modes=attr_conf,
        unit_val=unitSymbolType.AMPERE.value,
        valid_values=valid_values,
    )


def fuzz_meter_id(
    attr_conf: Optional[dict] = None, valid_values: Optional[int] = None
):
    """Fuzz meter id

    MeterID is type xs:unsignedByte (in xml schema).
    """
    # This is end parameter, so there is no passing None/{} to each sub parameter
    mode = get_attr_conf_mode(attr_conf, "MeterID")

    return gen_invalid_unsigned_byte(mode=mode, valid_val=valid_values)


def fuzz_meter_reading(
    attr_conf: Optional[dict] = None, valid_values: Optional[int] = None
):
    """Fuzz meter reading

    MeterReading is type xs:unsignedLong (in xml schema).
    """
    # This is end parameter, so there is no passing None/{} to each sub parameter
    mode = get_attr_conf_mode(attr_conf, "MeterReading")

    return gen_invalid_unsigned_long(mode=mode, valid_val=valid_values)


def fuzz_sig_meter_reading(
    attr_conf: Optional[dict] = None, valid_values: Optional[str] = None
):
    """Fuzz sig meter reading

    SigMeterReading is type xs:base64Binary, maxLength 64.
    """
    # This is end parameter, so there is no passing None/{} to each sub parameter
    mode = get_attr_conf_mode(attr_conf, "SigMeterReading")

    match mode:
        case ParamFuzzMode.VALID:
            if valid_values is None:
                logger.warning(
                    "No valid value specified for SigMeterReading,"
                    "using default valid value randomly chosen "
                    "from EVSENotificationType enum."
                )
                return random.randbytes(random.randint(1, 64)).hex()
            return valid_values
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


def fuzz_meter_status(
    attr_conf: Optional[dict] = None, valid_values: Optional[int] = None
):
    """Fuzz meter status

    MeterStatus is type xs:short (in xml schema).
    """
    # This is end parameter, so there is no passing None/{} to each sub parameter
    mode = get_attr_conf_mode(attr_conf, "MeterStatus")

    # xs:short => valid values: -32768 to 32767
    return gen_invalid_short(mode=mode, valid_val=valid_values)


def fuzz_t_meter(
    attr_conf: Optional[dict] = None, valid_values: Optional[int] = None
):
    """Fuzz t meter

    TMeter is type xs:long (in xml schema).
    """
    # This is end parameter, so there is no passing None/{} to each sub parameter
    mode = get_attr_conf_mode(attr_conf, "TMeter")

    return gen_invalid_long(mode=mode, valid_val=valid_values)


def fuzz_meter_info(
    attr_conf: Optional[dict] = None, valid_values: Optional[dict] = None
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

    pairs_name_method = {
        "MeterID": fuzz_meter_id,
        "MeterReading": fuzz_meter_reading,
        "SigMeterReading": fuzz_sig_meter_reading,
        "MeterStatus": fuzz_meter_status,
        "TMeter": fuzz_t_meter,
    }
    required_fields = ["MeterID"]
    all_fields = [
        "MeterID",
        "MeterReading",
        "SigMeterReading",
        "MeterStatus",
        "TMeter",
    ]

    res_dict = {}
    res_dict = general_datatype_fuzzing_method(
        required_fields=required_fields,
        all_fields=all_fields,
        attr_conf=attr_conf,
        valid_values=valid_values,
        pairs_name_method=pairs_name_method,
    )

    return res_dict


def fuzz_receipt_required(
    attr_conf: Optional[dict] = None, valid_values: Optional[dict] = None
) -> Union[str, int, float]:
    """Fuzz receipt required

    ReceiptRequired is type xs:boolean (in xml schema).
    """
    # valid_values is not used, but have to be there because of general method
    # This is end parameter, so there is no passing None/{} to each sub parameter
    mode = get_attr_conf_mode(attr_conf, "ReceiptRequired")

    return gen_invalid_bool(mode=mode)


def fuzz_evse_present_voltage(
    attr_conf: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz evse present voltage

    EVSEPresentVoltage is complexType: PhysicalValueType.
    """

    return fuzz_physical_value_type(
        modes=attr_conf,
        unit_val=unitSymbolType.VOLT.value,
        valid_values=valid_values,
    )


def fuzz_evse_present_current(
    attr_conf: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz evse present current

    EVSEPresentCurrent is complexType: PhysicalValueType.
    """

    return fuzz_physical_value_type(
        modes=attr_conf,
        unit_val=unitSymbolType.AMPERE.value,
        valid_values=valid_values,
    )


def fuzz_evse_current_limit_achieved(
    attr_conf: Optional[dict] = None, valid_values: Optional[dict] = None
) -> Union[str, int, float]:
    """Fuzz evse current limit achieved

    EVSECurrentLimitAchieved is type xs:boolean (in xml schema).
    """
    # valid_values is not used, but have to be there because of general method
    # This is end parameter, so there is no passing None/{} to each sub parameter
    mode = get_attr_conf_mode(attr_conf, "EVSECurrentLimitAchieved")

    return gen_invalid_bool(mode=mode)


def fuzz_evse_voltage_limit_achieved(
    attr_conf: Optional[dict] = None, valid_values: Optional[dict] = None
) -> Union[str, int, float]:
    """Fuzz evse voltage limit achieved

    EVSEVoltageLimitAchieved is type xs:boolean (in xml schema).
    """
    # valid_values is not used, but have to be there because of general method
    # This is end parameter, so there is no passing None/{} to each sub parameter
    mode = get_attr_conf_mode(attr_conf, "EVSEVoltageLimitAchieved")
    return gen_invalid_bool(mode=mode)


def fuzz_evse_power_limit_achieved(
    attr_conf: Optional[dict] = None, valid_values: Optional[dict] = None
) -> Union[str, int, float]:
    """Fuzz evse power limit achieved

    EVSEPowerLimitAchieved is type xs:boolean (in xml schema).
    """
    # valid_values is not used, but have to be there because of general method
    # This is end parameter, so there is no passing None/{} to each sub parameter
    mode = get_attr_conf_mode(attr_conf, "EVSEPowerLimitAchieved")
    return gen_invalid_bool(mode=mode)


def fuzz_evse_maximum_voltage(
    attr_conf: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz evse maximum voltage

    EVSEMaximumVoltage is complexType: PhysicalValueType.
    """

    return fuzz_physical_value_type(
        modes=attr_conf,
        unit_val=unitSymbolType.VOLT.value,
        valid_values=valid_values,
    )


def fuzz_evse_maximum_current(
    attr_conf: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz evse maximum current

    EVSEMaximumCurrent is complexType: PhysicalValueType.
    """

    return fuzz_physical_value_type(
        modes=attr_conf,
        unit_val=unitSymbolType.AMPERE.value,
        valid_values=valid_values,
    )


def fuzz_evse_maximum_power(
    attr_conf: Optional[dict] = None, valid_values: Optional[dict] = None
) -> dict:
    """Fuzz evse maximum power

    EVSEMaximumPower is complexType: PhysicalValueType.
    """

    return fuzz_physical_value_type(
        modes=attr_conf,
        unit_val=unitSymbolType.WATT.value,
        valid_values=valid_values,
    )
