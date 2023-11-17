"""This module contains the fuzz methods for the different types of data that can be fuzzed.

Methods from this module are used in fuzz_params.py to fuzz the parameters (attributes) in the message.
"""
import random
import logging
import string
from typing import Optional, Union
from base64 import b64encode

from ..fuzzer.fuzzer_enums import ParamFuzzMode

logger = logging.getLogger(__name__)


def gen_random_string(length: int) -> str:
    """Generate random string of given length"""
    # TODO: Maybe use also punctuation (special characters)
    # or all possible characters? string.printable
    if length < 0:
        logger.warning(
            "Length of string is negative, using absolute value of length."
        )
        length = abs(length)
    return "".join(random.choice(string.ascii_letters) for _ in range(length))


def gen_num(
    float_flag: bool = False,
    negative_flag: bool = False,
) -> Union[int, float]:
    """Generate number (int or float)"""
    if float_flag:
        num = random.uniform(-9223372036854775808, 9223372036854775807)

    num = random.randint(-9223372036854775808, 9223372036854775807)

    if negative_flag and num > 0 or not negative_flag and num < 0:
        return -1 * num

    return num


def gen_invalid_num(
    float_flag: bool = False,
    over_flag: bool = False,
    under_flag: bool = False,
    lower_limit_neg: int = -9223372036854775808,
    upper_limit_neg: int = 0,
    lower_limit_pos: int = 0,
    upper_limit_pos: int = 9223372036854775807,
) -> Union[int, float]:
    """General method for generating invalid number (int or float)"""

    if float_flag:
        # Value under range
        if under_flag:
            lower_value = random.uniform(lower_limit_neg, upper_limit_neg)
            return lower_value
        # Value over range
        if over_flag:
            higher_value = random.uniform(lower_limit_pos, upper_limit_pos)
            return higher_value

        # no under or over flag => valid range but float
        # => invalid type from valid range
        invalid_number = random.uniform(
            upper_limit_neg + 1, lower_limit_pos - 1
        )
        return invalid_number

    # int number
    if under_flag:
        lower_value = random.randint(lower_limit_neg, upper_limit_neg)
        return lower_value
    if over_flag:
        higher_value = random.randint(lower_limit_pos, upper_limit_pos)
        return higher_value

    # no under or over flag => random choice
    lower_value = random.randint(lower_limit_neg, upper_limit_neg)
    higher_value = random.randint(lower_limit_pos, upper_limit_pos)
    invalid_number = random.choice([lower_value, higher_value])

    return invalid_number


def gen_invalid_string(
    mode: ParamFuzzMode = ParamFuzzMode.RANDOM,
    valid_val: Optional[str] = None,
    min_len=1,
    max_len=100,
) -> Union[str, int, float]:
    """Generate invalid string"""

    match mode:
        case ParamFuzzMode.VALID:
            if valid_val is None:
                logger.warning(
                    "No valid value specified for string, "
                    "using valid value randomly generated."
                    "Disclaimer: Generated value - meets the conditions for length "
                    "and type but may not meet the valid value for particular parameter."
                )
                return gen_random_string(random.randint(min_len, max_len))
            return valid_val
        case ParamFuzzMode.SHORT_STRING:
            return gen_random_string(random.randint(0, min_len - 1))
        case ParamFuzzMode.LONG_STRING:
            return gen_random_string(
                random.randint(max_len + 1, max_len + 100)
            )
        case ParamFuzzMode.SPECIAL_STRING:
            return gen_malicous_string()
        case ParamFuzzMode.INT:
            return gen_num(float_flag=False, negative_flag=False)
        case ParamFuzzMode.NEGATIVE_INT:
            return gen_num(float_flag=False, negative_flag=True)
        case ParamFuzzMode.FLOAT:
            return gen_num(float_flag=True, negative_flag=False)
        case ParamFuzzMode.NEGATIVE_FLOAT:
            return gen_num(float_flag=True, negative_flag=True)
        case _:
            if mode is not ParamFuzzMode.RANDOM:
                logger.warning(
                    "Invalid fuzzing mode for parameter with type "
                    "string, using random mode."
                )
            # shorter str, longer str, special str, int, negative int, float, negative float
            invalid_values = [
                gen_random_string(random.randint(0, min_len - 1)),
                gen_random_string(random.randint(max_len + 1, max_len + 100)),
                gen_malicous_string(),
                gen_num(float_flag=False, negative_flag=False),
                gen_num(float_flag=False, negative_flag=True),
                gen_num(float_flag=True, negative_flag=False),
                gen_num(float_flag=True, negative_flag=True),
            ]
            return random.choice(invalid_values)


def gen_malicous_string(valid_string: str = "") -> str:
    """Generate malicious string.

    String with special meaning in different context or language like
    bash commands, xml, etc.
    """
    # TODO: Should i also add some more sophisticated invalid values?
    # like string with special meaning some known escaping with bash commands
    # or something like that? Based on what will be chosen invalid value
    # TODO: Add some valid value at the start and append invalid chars to it
    # like responseCodeType.OK.value + r"!@*!*@#" or something like that
    # malicious_string = gen_malicous_string()
    # invalid_enum = (
    #    random.choice(list(responseCodeType)).value + malicious_string
    # )

    raise NotImplementedError


def gen_malicous_hex(valid_hex: str = "") -> str:
    """Generate malicious hex.

    Hex with special meaning in different context or language like
    bash commands, xml, etc.
    """
    # TODO:
    raise NotImplementedError


def gen_malicous_base64(valid_base64: str = "") -> str:
    """Generate malicious base64.

    Base64 with special meaning in different context or language like
    bash commands, xml, etc.
    """
    # TODO:
    raise NotImplementedError


def gen_invalid_int_num(
    float_flag: bool = False,
    under_flag: bool = False,
    over_flag: bool = False,
    min_val: Optional[int] = None,
    max_val: Optional[int] = None,
) -> Union[int, float]:
    """Generate invalid xs:int number

    xs:int, -2147483648 to 2147483647 are valid values
    """

    # Set to -2^63
    lower_limit_neg = -9223372036854775808
    # xs:int min value is -2147483648 => -2147483648 - 1
    if min_val is not None:
        upper_limit_neg = min_val - 1
    else:
        upper_limit_neg = -2147483649
    # xs:int max value is 2147483647 = > 2147483647 + 1
    if max_val is not None:
        lower_limit_pos = max_val + 1
    else:
        lower_limit_pos = 2147483648
    # Set to 2^63 - 1
    upper_limit_pos = 9223372036854775807

    # Call general method for generating invalid number
    invalid_num = gen_invalid_num(
        float_flag=float_flag,
        under_flag=under_flag,
        over_flag=over_flag,
        lower_limit_neg=lower_limit_neg,
        upper_limit_neg=upper_limit_neg,
        lower_limit_pos=lower_limit_pos,
        upper_limit_pos=upper_limit_pos,
    )

    return invalid_num


def gen_invalid_int(
    mode: ParamFuzzMode = ParamFuzzMode.RANDOM,
    min_val: Optional[int] = None,
    max_val: Optional[int] = None,
    valid_val: Optional[int] = None,
) -> Union[str, int, float]:
    """Generate invalid xs:int (type in XML schema)

    xs:int, -2147483648 to 2147483647 are valid values.
    """

    match mode:
        case ParamFuzzMode.VALID:
            if min_val is None:
                min_val = -2147483648
            if max_val is None:
                max_val = 2147483647
            if valid_val is None:
                logger.warning(
                    "No valid value specified for xs:int, "
                    "using valid value randomly generated."
                    "Disclaimer: Generated value - meets the conditions for length "
                    "and type but may not meet the valid value for particular parameter."
                )
                return random.randint(min_val, max_val)
            return valid_val
        case ParamFuzzMode.STRING:
            return gen_random_string(random.randint(1, 100))
        case ParamFuzzMode.SPECIAL_STRING:
            return gen_malicous_string()
        case ParamFuzzMode.UNDER_INT:
            return gen_invalid_int_num(
                float_flag=False,
                under_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
        case ParamFuzzMode.OVER_INT:
            return gen_invalid_int_num(
                float_flag=False,
                over_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
        case ParamFuzzMode.FLOAT:
            return gen_invalid_int_num(
                float_flag=True, min_val=min_val, max_val=max_val
            )
        case ParamFuzzMode.UNDER_FLOAT:
            return gen_invalid_int_num(
                float_flag=True,
                under_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
        case ParamFuzzMode.OVER_FLOAT:
            return gen_invalid_int_num(
                float_flag=True,
                over_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
        case _:
            if mode is not ParamFuzzMode.RANDOM:
                logger.warning(
                    "Invalid fuzzing mode for parameter with type "
                    "xs:int, using random mode."
                )
            # string, special string, under int, over int, float, under float, over float
            invalid_values = [
                gen_random_string(random.randint(1, 100)),
                gen_malicous_string(),
                gen_invalid_int_num(
                    under_flag=True,
                    min_val=min_val,
                    max_val=max_val,
                ),
                gen_invalid_int_num(
                    over_flag=True,
                    min_val=min_val,
                    max_val=max_val,
                ),
                gen_invalid_int_num(
                    float_flag=True,
                    min_val=min_val,
                    max_val=max_val,
                ),
                gen_invalid_int_num(
                    float_flag=True,
                    under_flag=True,
                    min_val=min_val,
                    max_val=max_val,
                ),
                gen_invalid_int_num(
                    float_flag=True,
                    over_flag=True,
                    min_val=min_val,
                    max_val=max_val,
                ),
            ]

            return random.choice(invalid_values)


def gen_invalid_unsigned_int_num(
    float_flag: bool = False,
    under_flag: bool = False,
    over_flag: bool = False,
    min_val: Optional[int] = None,
    max_val: Optional[int] = None,
) -> Union[int, float]:
    """Generate invalid xs:unsignedInt number"""

    # Set to -2^63
    lower_limit_neg = -9223372036854775808
    # xs:int min value is -2147483648 => -2147483648 - 1
    if min_val is not None:
        upper_limit_neg = min_val - 1
    else:
        upper_limit_neg = 0
    # xs:int max value is 2147483647 = > 2147483647 + 1
    if max_val is not None:
        lower_limit_pos = max_val + 1
    else:
        lower_limit_pos = 4294967295
    # Set to 2^63 - 1
    upper_limit_pos = 9223372036854775807

    # Call general method for generating invalid number
    invalid_num = gen_invalid_num(
        float_flag=float_flag,
        under_flag=under_flag,
        over_flag=over_flag,
        lower_limit_neg=lower_limit_neg,
        upper_limit_neg=upper_limit_neg,
        lower_limit_pos=lower_limit_pos,
        upper_limit_pos=upper_limit_pos,
    )

    return invalid_num


def gen_invalid_unsigned_int(
    mode: ParamFuzzMode = ParamFuzzMode.RANDOM,
    min_val: Optional[int] = None,
    max_val: Optional[int] = None,
    valid_val: Optional[int] = None,
) -> Union[str, int, float]:
    """Generate invalid xs:unsignedInt (type in XML schema)

    xs:unsignedInt, 0-4294967295 are valid values
    """
    match mode:
        case ParamFuzzMode.VALID:
            if valid_val is None:
                logger.warning(
                    "No valid value specified for xs:unsignedInt, "
                    "using valid value randomly generated."
                    "Disclaimer: Generated value - meets the conditions for length "
                    "and type but may not meet the valid value for particular parameter."
                )
                if min_val is None:
                    min_val = 0
                if max_val is None:
                    max_val = 4294967295
                return random.randint(min_val, max_val)
            return valid_val
        case ParamFuzzMode.STRING:
            return gen_random_string(random.randint(1, 100))
        case ParamFuzzMode.SPECIAL_STRING:
            return gen_malicous_string()
        case ParamFuzzMode.UNDER_INT:
            return gen_invalid_unsigned_int_num(
                float_flag=False,
                under_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
        case ParamFuzzMode.OVER_INT:
            return gen_invalid_unsigned_int_num(
                float_flag=False,
                over_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
        case ParamFuzzMode.FLOAT:
            return gen_invalid_unsigned_int_num(
                float_flag=True, min_val=min_val, max_val=max_val
            )
        case ParamFuzzMode.UNDER_FLOAT:
            return gen_invalid_unsigned_int_num(
                float_flag=True,
                under_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
        case ParamFuzzMode.OVER_FLOAT:
            return gen_invalid_unsigned_int_num(
                float_flag=True,
                over_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
        case _:
            if mode is not ParamFuzzMode.RANDOM:
                logger.warning(
                    "Invalid fuzzing mode for parameter with type "
                    "xs:unsignedInt, using random mode."
                )
            # string, special string, under int, over int, float, under float, over float
            invalid_values = [
                gen_random_string(random.randint(1, 100)),
                gen_malicous_string(),
                gen_invalid_unsigned_int_num(
                    under_flag=True,
                    min_val=min_val,
                    max_val=max_val,
                ),
                gen_invalid_unsigned_int_num(
                    over_flag=True,
                    min_val=min_val,
                    max_val=max_val,
                ),
                gen_invalid_unsigned_int_num(
                    float_flag=True,
                    min_val=min_val,
                    max_val=max_val,
                ),
                gen_invalid_unsigned_int_num(
                    float_flag=True,
                    under_flag=True,
                    min_val=min_val,
                    max_val=max_val,
                ),
                gen_invalid_unsigned_int_num(
                    float_flag=True,
                    over_flag=True,
                    min_val=min_val,
                    max_val=max_val,
                ),
            ]

            return random.choice(invalid_values)


def gen_invalid_byte_num(
    float_flag: bool = False,
    under_flag: bool = False,
    over_flag: bool = False,
    min_val: Optional[int] = None,
    max_val: Optional[int] = None,
) -> Union[int, float]:
    """Generate invalid xs:byte number

    xs:byte is the integers between -128 and 127

    If min or max is specified, valid values are between min and max (inclusive).
    """
    # Set to -2^63
    lower_limit_neg = -9223372036854775808
    # xs:byte min value is -128 => -128 - 1
    # min specified in schema - restricts value to be >= min
    if min_val is not None:
        upper_limit_neg = min_val - 1
    else:
        upper_limit_neg = -129
    # xs:byte max value is 127 = > 127 + 1
    # max specified in schema - restricts value to be <= max
    if max_val is not None:
        lower_limit_pos = max_val + 1
    else:
        lower_limit_pos = 128
    # Set to 2^63 - 1
    upper_limit_pos = 9223372036854775807

    # Call general method for generating invalid number
    invalid_num = gen_invalid_num(
        float_flag=float_flag,
        under_flag=under_flag,
        over_flag=over_flag,
        lower_limit_neg=lower_limit_neg,
        upper_limit_neg=upper_limit_neg,
        lower_limit_pos=lower_limit_pos,
        upper_limit_pos=upper_limit_pos,
    )

    return invalid_num


def gen_invalid_byte(
    mode: ParamFuzzMode = ParamFuzzMode.RANDOM,
    min_val: Optional[int] = None,
    max_val: Optional[int] = None,
    valid_val: Optional[int] = None,
) -> Union[str, int, float]:
    """Generate invalid xs:byte (type in XML schema)

    xs:byte valid values are between -128 and 127
    If min or max is specified, valid values are between min and max (inclusive).
    Min/max are specified in schema as restriction for value.
    For example: type="xs:byte" minInclusive="-3" maxInclusive="3"
    """

    match mode:
        case ParamFuzzMode.VALID:
            if valid_val is None:
                logger.warning(
                    "No valid value specified for xs:byte, "
                    "using valid value randomly generated."
                    "Disclaimer: Generated value - meets the conditions for length "
                    "and type but may not meet the valid value for particular parameter."
                )
                if min_val is None:
                    min_val = -128
                if max_val is None:
                    max_val = 127
                return random.randint(min_val, max_val)
            return valid_val
        case ParamFuzzMode.STRING:
            return gen_random_string(random.randint(1, 100))
        case ParamFuzzMode.SPECIAL_STRING:
            return gen_malicous_string()
        case ParamFuzzMode.UNDER_INT:
            return gen_invalid_byte_num(
                float_flag=False,
                under_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
        case ParamFuzzMode.OVER_INT:
            return gen_invalid_byte_num(
                float_flag=False,
                over_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
        case ParamFuzzMode.FLOAT:
            return gen_invalid_byte_num(
                float_flag=True, min_val=min_val, max_val=max_val
            )
        case ParamFuzzMode.UNDER_FLOAT:
            return gen_invalid_byte_num(
                float_flag=True,
                under_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
        case ParamFuzzMode.OVER_FLOAT:
            return gen_invalid_byte_num(
                float_flag=True,
                over_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
        case _:
            if mode is not ParamFuzzMode.RANDOM:
                logger.warning(
                    "Invalid fuzzing mode for parameter with type "
                    "xs:byte, using random mode."
                )
            # string, special string, under int, over int, float, under float, over float
            invalid_values = [
                gen_random_string(random.randint(1, 100)),
                gen_malicous_string(),
                gen_invalid_byte_num(
                    under_flag=True, min_val=min_val, max_val=max_val
                ),
                gen_invalid_byte_num(
                    over_flag=True, min_val=min_val, max_val=max_val
                ),
                gen_invalid_byte_num(
                    float_flag=True, min_val=min_val, max_val=max_val
                ),
                gen_invalid_byte_num(
                    float_flag=True,
                    under_flag=True,
                    min_val=min_val,
                    max_val=max_val,
                ),
                gen_invalid_byte_num(
                    float_flag=True,
                    over_flag=True,
                    min_val=min_val,
                    max_val=max_val,
                ),
            ]

            return random.choice(invalid_values)


def gen_invalid_unsigned_byte_num(
    float_flag: bool = False,
    under_flag: bool = False,
    over_flag: bool = False,
    min_val: Optional[int] = None,
    max_val: Optional[int] = None,
) -> Union[int, float]:
    """Generate invalid xs:unsignedByte (type in XML schema)

    Valid xs:unsignedByte is in range 0-255, so invalid value is out of range.
    """
    # Python3 int has no max and min value, so min and max value is
    # randomly generated.
    # Followed values are picked from: C standard library LONG_MIN and LONG_MAX
    # min value is -9223372036854775808 (2**63)
    # max value is 9223372036854775807 (2**63 - 1)

    # Set to -2^63
    lower_limit_neg = -9223372036854775808
    # xs:unsignedByte min value is 0 => -1
    if min_val is not None:
        upper_limit_neg = min_val - 1
    else:
        upper_limit_neg = -1
    # xs:unsignedByte max value is 255 = > 255 + 1
    if max_val is not None:
        lower_limit_pos = max_val + 1
    else:
        lower_limit_pos = 256
    # Set to 2^63 - 1
    upper_limit_pos = 9223372036854775807

    # Call general method for generating invalid number
    invalid_num = gen_invalid_num(
        float_flag=float_flag,
        under_flag=under_flag,
        over_flag=over_flag,
        lower_limit_neg=lower_limit_neg,
        upper_limit_neg=upper_limit_neg,
        lower_limit_pos=lower_limit_pos,
        upper_limit_pos=upper_limit_pos,
    )

    return invalid_num


def gen_invalid_unsigned_byte(
    mode: ParamFuzzMode = ParamFuzzMode.RANDOM,
    min_val: Optional[int] = None,
    max_val: Optional[int] = None,
    valid_val: Optional[int] = None,
) -> Union[str, int, float]:
    """Generate invalid xs:unsignedByte (type in XML schema)

    xs:unsignedByte, 0-255 are valid values
    Randomly choose invalid value - float, string or number out of range

    Relevant modes: random, string, int, over-int,
        under-int, float, over-float, under-float
    """

    match mode:
        case ParamFuzzMode.VALID:
            if valid_val is None:
                logger.warning(
                    "No valid value specified for xs:unsignedByte, "
                    "using valid value randomly generated."
                    "Disclaimer: Generated value - meets the conditions for "
                    "length and type but may not meet the valid "
                    "value for particular parameter."
                )
                if min_val is None:
                    min_val = 0
                if max_val is None:
                    max_val = 255
                return random.randint(min_val, max_val)
            return valid_val
        case ParamFuzzMode.STRING:
            return gen_random_string(random.randint(1, 100))
        case ParamFuzzMode.SPECIAL_STRING:
            # TODO: implement use of valid_val
            return gen_malicous_string()
        case ParamFuzzMode.UNDER_INT:
            return gen_invalid_unsigned_byte_num(
                float_flag=False,
                under_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
        case ParamFuzzMode.OVER_INT:
            return gen_invalid_unsigned_byte_num(
                float_flag=False,
                over_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
        case ParamFuzzMode.INT:
            return gen_invalid_unsigned_byte_num(
                float_flag=False, min_val=min_val, max_val=max_val
            )
        case ParamFuzzMode.FLOAT:
            return gen_invalid_unsigned_byte_num(
                float_flag=True, min_val=min_val, max_val=max_val
            )
        case ParamFuzzMode.UNDER_FLOAT:
            return gen_invalid_unsigned_byte_num(
                float_flag=True,
                under_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
        case ParamFuzzMode.OVER_FLOAT:
            return gen_invalid_unsigned_byte_num(
                float_flag=True,
                over_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
        case _:
            if mode is not ParamFuzzMode.RANDOM:
                logger.warning(
                    "Invalid fuzzing mode for parameter with type "
                    "xs:unsignedByte, using random mode."
                )
            # string, special string, under int, over int, float, under float, over float
            invalid_values = [
                gen_random_string(random.randint(1, 100)),
                gen_malicous_string(),
                gen_invalid_unsigned_byte_num(
                    under_flag=True, max_val=max_val, min_val=min_val
                ),
                gen_invalid_unsigned_byte_num(
                    over_flag=True, max_val=max_val, min_val=min_val
                ),
                gen_invalid_unsigned_byte_num(
                    float_flag=True, max_val=max_val, min_val=min_val
                ),
                gen_invalid_unsigned_byte_num(
                    float_flag=True,
                    under_flag=True,
                    max_val=max_val,
                    min_val=min_val,
                ),
                gen_invalid_unsigned_byte_num(
                    float_flag=True,
                    over_flag=True,
                    max_val=max_val,
                    min_val=min_val,
                ),
            ]

            return random.choice(invalid_values)


def gen_invalid_bool(
    mode: ParamFuzzMode = ParamFuzzMode.RANDOM,
) -> Union[str, int, float]:
    """Generate invalid xs:boolean (type in XML schema)"""

    match mode:
        case ParamFuzzMode.STRING:
            return gen_random_string(random.randint(1, 100))
        case ParamFuzzMode.SPECIAL_STRING:
            return gen_malicous_string()
        case ParamFuzzMode.INT:
            return gen_num(float_flag=False, negative_flag=False)
        case ParamFuzzMode.NEGATIVE_INT:
            return gen_num(float_flag=False, negative_flag=True)
        case ParamFuzzMode.FLOAT:
            return gen_num(float_flag=True, negative_flag=False)
        case ParamFuzzMode.NEGATIVE_FLOAT:
            return gen_num(float_flag=True, negative_flag=True)

        case _:
            if mode is not ParamFuzzMode.RANDOM:
                logger.warning(
                    "Invalid fuzzing mode for parameter with type "
                    "xs:boolean, using random mode."
                )
            # string, special string, int, negative int, float, negative float
            invalid_values = [
                gen_random_string(random.randint(1, 100)),
                gen_malicous_string(),
                gen_num(float_flag=False, negative_flag=False),
                gen_num(float_flag=False, negative_flag=True),
                gen_num(float_flag=True, negative_flag=False),
                gen_num(float_flag=True, negative_flag=True),
            ]

            return random.choice(invalid_values)


def gen_invalid_unsigned_long_num(
    float_flag: bool = False,
    under_flag: bool = False,
    over_flag: bool = False,
    min_val: Optional[int] = None,
    max_val: Optional[int] = None,
) -> Union[int, float]:
    """Generate invalid xs:unsignedLong number

    xs:unsignedLong, 0-18446744073709551615 are valid values
    """

    # Set to -2^127
    lower_limit_neg = -170141183460469231731687303715884105728
    # xs:unsignedLong min value is 0 => -1
    if min_val is not None:
        upper_limit_neg = min_val - 1
    else:
        upper_limit_neg = -1
    # xs:unsignedLong max value is 18446744073709551615 = > 18446744073709551615 + 1
    if max_val is not None:
        lower_limit_pos = max_val + 1
    else:
        lower_limit_pos = 18446744073709551616
    # Set to 2^127 - 1
    upper_limit_pos = 170141183460469231731687303715884105727

    # Call general method for generating invalid number
    invalid_num = gen_invalid_num(
        float_flag=float_flag,
        under_flag=under_flag,
        over_flag=over_flag,
        lower_limit_neg=lower_limit_neg,
        upper_limit_neg=upper_limit_neg,
        lower_limit_pos=lower_limit_pos,
        upper_limit_pos=upper_limit_pos,
    )

    return invalid_num


def gen_invalid_unsigned_long(
    mode: ParamFuzzMode = ParamFuzzMode.RANDOM, valid_val: Optional[int] = None
) -> Union[str, int, float]:
    """Generate invalid xs:unsignedLong (type in XML schema)

    xs:unsignedLong, 0-8446744073709551615 are valid values
    """

    match mode:
        case ParamFuzzMode.VALID:
            if valid_val is None:
                logger.warning(
                    "No valid value specified for xs:unsignedLong, "
                    "using valid value randomly generated."
                    "Disclaimer: Generated value - meets the conditions for length "
                    "and type but may not meet the valid value for particular parameter."
                )
                return random.randint(0, 18446744073709551615)
            return valid_val
        case ParamFuzzMode.STRING:
            return gen_random_string(random.randint(1, 100))
        case ParamFuzzMode.SPECIAL_STRING:
            return gen_malicous_string()
        case ParamFuzzMode.UNDER_INT:
            return gen_invalid_unsigned_long_num(
                float_flag=False, under_flag=True
            )
        case ParamFuzzMode.OVER_INT:
            return gen_invalid_unsigned_long_num(
                float_flag=False, over_flag=True
            )
        case ParamFuzzMode.FLOAT:
            return gen_invalid_unsigned_long_num(float_flag=True)
        case ParamFuzzMode.UNDER_FLOAT:
            return gen_invalid_unsigned_long_num(
                float_flag=True, under_flag=True
            )
        case ParamFuzzMode.OVER_FLOAT:
            return gen_invalid_unsigned_long_num(
                float_flag=True, over_flag=True
            )
        case _:
            if mode is not ParamFuzzMode.RANDOM:
                logger.warning(
                    "Invalid fuzzing mode for parameter with type "
                    "xs:unsignedLong, using random mode."
                )
            # string, special string, under int, over int, float, over float, under float
            invalid_values = [
                gen_random_string(random.randint(1, 100)),
                gen_malicous_string(),
                gen_invalid_unsigned_long_num(over_flag=True),
                gen_invalid_unsigned_long_num(under_flag=True),
                gen_invalid_unsigned_long_num(float_flag=True),
                gen_invalid_unsigned_long_num(float_flag=True, over_flag=True),
                gen_invalid_unsigned_long_num(
                    float_flag=True, under_flag=True
                ),
            ]

            return random.choice(invalid_values)


def gen_invalid_short_num(
    float_flag: bool = False,
    under_flag: bool = False,
    over_flag: bool = False,
    min_val: Optional[int] = None,
    max_val: Optional[int] = None,
) -> Union[int, float]:
    """Generate invalid xs:short number

    xs:short, -32768 to 32767 are valid values
    """

    # Set to -2^63
    lower_limit_neg = -9223372036854775808
    # xs:short min value is -32768 => -32768 - 1
    if min_val is not None:
        upper_limit_neg = min_val - 1
    else:
        upper_limit_neg = -32769
    # xs:short max value is 32767 = > 32767 + 1
    if max_val is not None:
        lower_limit_pos = max_val + 1
    else:
        lower_limit_pos = 32768
    # Set to 2^63 - 1
    upper_limit_pos = 9223372036854775807

    # Call general method for generating invalid number
    invalid_num = gen_invalid_num(
        float_flag=float_flag,
        under_flag=under_flag,
        over_flag=over_flag,
        lower_limit_neg=lower_limit_neg,
        upper_limit_neg=upper_limit_neg,
        lower_limit_pos=lower_limit_pos,
        upper_limit_pos=upper_limit_pos,
    )
    return invalid_num


def gen_invalid_short(
    mode: ParamFuzzMode = ParamFuzzMode.RANDOM,
    min_val: Optional[int] = None,
    max_val: Optional[int] = None,
    valid_val: Optional[int] = None,
) -> Union[str, int, float]:
    """Generate invalid xs:short (type in XML schema)

    xs:short, -32768 to 32767 are valid values

    Args:
        mode (ParamFuzzMode, optional): Fuzzing mode.
            Defaults to ParamFuzzMode.RANDOM.
        min_val (Optional[int], optional): Min valid value specified in schema.
            Defaults to None.
        max_val (Optional[int], optional): Max valid value specified in schema.
            Defaults to None.
    """
    match mode:
        case ParamFuzzMode.VALID:
            if valid_val is None:
                logger.warning(
                    "No valid value specified for xs:short, "
                    "using valid value randomly generated."
                    "Disclaimer: Generated value - meets the conditions for length "
                    "and type but may not meet the valid value for particular parameter."
                )
                low = -32768
                high = 32767
                if min_val is not None:
                    low = min_val
                if max_val is not None:
                    high = max_val
                return random.randint(low, high)
            return valid_val
        case ParamFuzzMode.STRING:
            return gen_random_string(random.randint(1, 100))
        case ParamFuzzMode.SPECIAL_STRING:
            return gen_malicous_string()
        case ParamFuzzMode.UNDER_INT:
            return gen_invalid_short_num(
                float_flag=False,
                under_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
        case ParamFuzzMode.OVER_INT:
            return gen_invalid_short_num(
                float_flag=False,
                over_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
        case ParamFuzzMode.FLOAT:
            return gen_invalid_short_num(
                float_flag=True, min_val=min_val, max_val=max_val
            )
        case ParamFuzzMode.UNDER_FLOAT:
            return gen_invalid_short_num(
                float_flag=True,
                under_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
        case ParamFuzzMode.OVER_FLOAT:
            return gen_invalid_short_num(
                float_flag=True,
                over_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
        case _:
            if mode is not ParamFuzzMode.RANDOM:
                logger.warning(
                    "Invalid fuzzing mode for parameter with type "
                    "xs:short, using random mode."
                )
            # string, special string, under int, over int, float, under float, over float
            invalid_values = [
                gen_random_string(random.randint(1, 100)),
                gen_malicous_string(),
                gen_invalid_short_num(
                    under_flag=True,
                    min_val=min_val,
                    max_val=max_val,
                ),
                gen_invalid_short_num(
                    over_flag=True,
                    min_val=min_val,
                    max_val=max_val,
                ),
                gen_invalid_short_num(
                    float_flag=True,
                    min_val=min_val,
                    max_val=max_val,
                ),
                gen_invalid_short_num(
                    float_flag=True,
                    under_flag=True,
                    min_val=min_val,
                    max_val=max_val,
                ),
                gen_invalid_short_num(
                    float_flag=True,
                    over_flag=True,
                    min_val=min_val,
                    max_val=max_val,
                ),
            ]

            return random.choice(invalid_values)


def gen_invalid_unsigned_short_num(
    float_flag: bool = False, under_flag: bool = False, over_flag: bool = False
) -> Union[int, float]:
    """Generate invalid xs:unsignedShort number

    xs:unsignedShort, 0 to 65535 are valid values
    """
    # Set to -2^63
    lower_limit_neg = -9223372036854775808
    # xs:unsignedShort min value is 0 => -1
    upper_limit_neg = -1
    # xs:unsignedShort max value is 65535 = > 65535 + 1
    lower_limit_pos = 65536
    # Set to 2^63 - 1
    upper_limit_pos = 9223372036854775807

    invalid_num = gen_invalid_num(
        float_flag=float_flag,
        under_flag=under_flag,
        over_flag=over_flag,
        lower_limit_neg=lower_limit_neg,
        upper_limit_neg=upper_limit_neg,
        lower_limit_pos=lower_limit_pos,
        upper_limit_pos=upper_limit_pos,
    )

    return invalid_num


def gen_invalid_unsigned_short(
    mode: ParamFuzzMode = ParamFuzzMode.RANDOM,
    valid_val: Optional[int] = None,
) -> Union[str, int, float]:
    """Generate invalid xs:unsignedShort (type in XML schema)

    xs:unsignedShort, 0 to 65535 are valid values
    """
    match mode:
        case ParamFuzzMode.VALID:
            if valid_val is None:
                logger.warning(
                    "No valid value specified for xs:unsignedShort, "
                    "using valid value randomly generated."
                    "Disclaimer: Generated value - meets the conditions for length "
                    "and type but may not meet the valid value for particular parameter."
                )
                return random.randint(0, 65535)
            return valid_val
        case ParamFuzzMode.STRING:
            return gen_random_string(random.randint(1, 100))
        case ParamFuzzMode.SPECIAL_STRING:
            return gen_malicous_string()
        case ParamFuzzMode.UNDER_INT:
            return gen_invalid_unsigned_short_num(
                float_flag=False, under_flag=True
            )
        case ParamFuzzMode.OVER_INT:
            return gen_invalid_unsigned_short_num(
                float_flag=False, over_flag=True
            )
        case ParamFuzzMode.FLOAT:
            return gen_invalid_unsigned_short_num(float_flag=True)
        case ParamFuzzMode.UNDER_FLOAT:
            return gen_invalid_unsigned_short_num(
                float_flag=True, under_flag=True
            )
        case ParamFuzzMode.OVER_FLOAT:
            return gen_invalid_unsigned_short_num(
                float_flag=True, over_flag=True
            )
        case _:
            if mode is not ParamFuzzMode.RANDOM:
                logger.warning(
                    "Invalid fuzzing mode for parameter with type "
                    "xs:unsignedShort, using random mode."
                )
            # string, special string, under int, over int, float, under float, over float
            invalid_values = [
                gen_random_string(random.randint(1, 100)),
                gen_malicous_string(),
                gen_invalid_unsigned_short_num(under_flag=True),
                gen_invalid_unsigned_short_num(over_flag=True),
                gen_invalid_unsigned_short_num(float_flag=True),
                gen_invalid_unsigned_short_num(
                    float_flag=True, under_flag=True
                ),
                gen_invalid_unsigned_short_num(
                    float_flag=True, over_flag=True
                ),
            ]

            return random.choice(invalid_values)


def gen_invalid_long_num(
    float_flag: bool = False, under_flag: bool = False, over_flag: bool = False
):
    """ "Generate invalid xs:long number

    xs:long, -9223372036854775808 to 9223372036854775807 are valid values (2^63, 2^63 - 1)
    """

    # Set to -2^127
    lower_limit_neg = -170141183460469231731687303715884105728
    # xs:long min value is -9223372036854775808
    upper_limit_neg = -9223372036854775809
    # xs:long max value is 9223372036854775807
    lower_limit_pos = 9223372036854775808
    # Set to 2^127 - 1
    upper_limit_pos = 170141183460469231731687303715884105727

    # Call general method for generating invalid number
    invalid_num = gen_invalid_num(
        float_flag=float_flag,
        under_flag=under_flag,
        over_flag=over_flag,
        lower_limit_neg=lower_limit_neg,
        upper_limit_neg=upper_limit_neg,
        lower_limit_pos=lower_limit_pos,
        upper_limit_pos=upper_limit_pos,
    )

    return invalid_num


def gen_invalid_long(
    mode: ParamFuzzMode = ParamFuzzMode.RANDOM, valid_val: Optional[int] = None
) -> Union[str, int, float]:
    """Generate invalid xs:long type(type in XML schema)

    xs:long, -9223372036854775808 to 9223372036854775807 are valid values (2^63, 2^63 - 1)
    """
    match mode:
        case ParamFuzzMode.VALID:
            if valid_val is None:
                logger.warning(
                    "No valid value specified for xs:long, "
                    "using valid value randomly generated."
                    "Disclaimer: Generated value - meets the conditions for "
                    "length and type but may not meet the valid "
                    "value for particular parameter."
                )
                return random.randint(
                    -9223372036854775808, 9223372036854775807
                )
            return valid_val
        case ParamFuzzMode.STRING:
            return gen_random_string(random.randint(1, 100))
        case ParamFuzzMode.SPECIAL_STRING:
            return gen_malicous_string()
        case ParamFuzzMode.UNDER_INT:
            return gen_invalid_long_num(float_flag=False, under_flag=True)
        case ParamFuzzMode.OVER_INT:
            return gen_invalid_long_num(float_flag=False, over_flag=True)
        case ParamFuzzMode.FLOAT:
            return gen_invalid_long_num(float_flag=True)
        case ParamFuzzMode.UNDER_FLOAT:
            return gen_invalid_long_num(float_flag=True, under_flag=True)
        case ParamFuzzMode.OVER_FLOAT:
            return gen_invalid_long_num(float_flag=True, over_flag=True)

        case _:
            if mode is not ParamFuzzMode.RANDOM:
                logger.warning(
                    "Invalid fuzzing mode for parameter with type "
                    "xs:long, using random mode."
                )
            # string, special string, under int, over int, float, under float, over float
            invalid_values = [
                gen_random_string(random.randint(1, 100)),
                gen_malicous_string(),
                gen_invalid_long_num(under_flag=True),
                gen_invalid_long_num(over_flag=True),
                gen_invalid_long_num(float_flag=True),
                gen_invalid_long_num(float_flag=True, under_flag=True),
                gen_invalid_long_num(float_flag=True, over_flag=True),
            ]
            return random.choice(invalid_values)


def gen_invalid_base64_binary(
    length: Optional[int] = None,
    max_length: Optional[int] = None,
    min_length: Optional[int] = None,
) -> str:
    """Generate invalid xs:base64Binary (type in XML schema)

    Args:
        max_length (int): Max length of valid base64binary.
        min_length (int): Min length of valid base64binary.

    Only one of max_length or min_length can be provided.
    """
    # Specific length of base64binary
    if length is not None:
        bin_value = random.randbytes(length)
        return b64encode(bin_value).decode("utf-8")
    # if max_length is provided generate base64binary with length > max_length
    if max_length is not None:
        bin_value = random.randbytes(max_length + 1)
        # For str_val need to be encoded to bytes => str_val.encode("utf-8")
        # b64encode accepts only bytes
        # type bytes => base64 encoded (type bytes) => type str
        return b64encode(bin_value).decode("utf-8")

    # if min_length is provided generate base64binary with length < min_length
    if min_length is not None:
        bin_value = random.randbytes(min_length - 1)
        return b64encode(bin_value).decode("utf-8")

    # Length is randomly generated
    bin_value = random.randbytes(random.randint(1, 100))
    return b64encode(bin_value).decode("utf-8")


def gen_invalid_hex_binary(
    length: Optional[int] = None,
    max_length: Optional[int] = None,
    min_length: Optional[int] = None,
) -> str:
    """Generate invalid xs:hexBinary (type in XML schema)

    Args:
        max_length (int): Max length of valid hexBinary.
        min_length (int): Min length of valid hexBinary.

    Only one of max_length or min_length can be provided.
    """
    # Specific length of hexBinary
    if length is not None:
        bin_value = random.randbytes(length)
        return bin_value.hex()
    # if max_length is provided generate hexBinary with length > max_length
    if max_length is not None:
        bin_value = random.randbytes(max_length + 1)
        return bin_value.hex()

    # if min_length is provided generate hexBinary with length < min_length
    if min_length is not None:
        bin_value = random.randbytes(min_length - 1)
        return bin_value.hex()

    # Length is randomly generated
    return random.randbytes(random.randint(1, 100)).hex()


def gen_invalid_id(
    mode: ParamFuzzMode = ParamFuzzMode.RANDOM, valid_val: Optional[str] = None
) -> Union[str, int, float]:
    """Fuzz xs:Id

    Should not start with digit and should not contain ':'.
    """

    match mode:
        case ParamFuzzMode.VALID:
            if valid_val is None:
                logger.warning(
                    "No valid value specified for xs:Id, "
                    "using valid value randomly generated."
                    "Disclaimer: Generated value - meets the conditions for length "
                    "and type but may not meet the valid value for particular parameter."
                )
                return "ID00" + str(random.randint(1, 99))
            return valid_val
        case ParamFuzzMode.STRING:
            return gen_random_string(random.randint(1, 100))
        case ParamFuzzMode.SPECIAL_STRING:
            return gen_malicous_string()
        case ParamFuzzMode.INT:
            return gen_num(float_flag=False, negative_flag=False)
        case ParamFuzzMode.NEGATIVE_INT:
            return gen_num(float_flag=False, negative_flag=True)
        case ParamFuzzMode.FLOAT:
            return gen_num(float_flag=True, negative_flag=False)
        case ParamFuzzMode.NEGATIVE_FLOAT:
            return gen_num(float_flag=True, negative_flag=True)
        case _:
            if mode is not ParamFuzzMode.RANDOM:
                logger.warning(
                    "Invalid fuzzing mode for parameter with type "
                    "xs:Id, using random mode."
                )
            # string, special string, int, negative int, float, negative float
            invalid_values = [
                gen_random_string(random.randint(1, 100)),
                gen_malicous_string(),
                gen_num(float_flag=False, negative_flag=False),
                gen_num(float_flag=False, negative_flag=True),
                gen_num(float_flag=True, negative_flag=False),
                gen_num(float_flag=True, negative_flag=True),
            ]

            return random.choice(invalid_values)
