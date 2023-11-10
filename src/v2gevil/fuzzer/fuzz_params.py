"""This module contains methods for fuzzing specifig parameters,
which are used by the fuzzer program."""

import random
import logging
import string
from typing import Optional, Union
from base64 import b64encode
from ..messages.MsgDataTypes import responseCodeType, unitSymbolType
from ..fuzzer.fuzzer_enums import ParamFuzzMode

# TODO: ASK TOM, should be there for fuzz methods some parameters?
# For example schemaID is unsignedByte, so i can test for example
# value out of range or passing string instead of number, etc.
# Have some static values or always generate them?
# Have option to pass custom values?

logger = logging.getLogger(__name__)


def gen_random_string(length: int) -> str:
    """Generate random string of given length"""
    # TODO: Maybe use also punctuation (special characters)
    # or all possible characters? string.printable
    return "".join(random.choice(string.ascii_letters) for _ in range(length))


def gen_invalid_string(
    mode: ParamFuzzMode = ParamFuzzMode.RANDOM,
) -> Union[str, int, float]:
    """Generate invalid string"""

    match mode:
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
            special_string = gen_malicous_string()
            invalid_num = gen_num(float_flag=False, negative_flag=False)
            invalid_neg_num = gen_num(float_flag=False, negative_flag=True)
            invalid_float_num = gen_num(float_flag=True, negative_flag=False)
            invalid_neg_float_num = gen_num(
                float_flag=True, negative_flag=True
            )
            return random.choice(
                [
                    special_string,
                    invalid_num,
                    invalid_neg_num,
                    invalid_float_num,
                    invalid_neg_float_num,
                ]
            )


def gen_malicous_string(valid_string: str = "") -> str:
    """Generate malicious string.

    String with special meaning in different context or language like
    bash commands, xml, etc.
    """
    # TODO: Should i also add some more sophisticated invalid values?
    # like string with special meaning some known escaping with bash commands
    # or something like that? Based on what will be chosen invalid value

    raise NotImplementedError


def gen_malicous_hex() -> str:
    """Generate malicious hex.

    Hex with special meaning in different context or language like
    bash commands, xml, etc.
    """
    # TODO:
    raise NotImplementedError


def gen_malicous_base64() -> str:
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


def gen_invalid_int(
    mode: ParamFuzzMode = ParamFuzzMode.RANDOM,
    min_val: Optional[int] = None,
    max_val: Optional[int] = None,
) -> Union[str, int, float]:
    """Generate invalid xs:int (type in XML schema)

    xs:int, -2147483648 to 2147483647 are valid values.
    """

    match mode:
        case ParamFuzzMode.STRING:
            return gen_random_string(random.randint(1, 100))
        case ParamFuzzMode.SPECIAL_STRING:
            return gen_malicous_string()
        case ParamFuzzMode.OVER_INT:
            return gen_invalid_int_num(
                float_flag=False,
                over_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
        case ParamFuzzMode.UNDER_INT:
            return gen_invalid_int_num(
                float_flag=False,
                under_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
        case ParamFuzzMode.FLOAT:
            return gen_invalid_int_num(
                float_flag=True, min_val=min_val, max_val=max_val
            )
        case ParamFuzzMode.OVER_FLOAT:
            return gen_invalid_int_num(
                float_flag=True,
                over_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
        case ParamFuzzMode.UNDER_FLOAT:
            return gen_invalid_int_num(
                float_flag=True,
                under_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
        case _:
            if mode is not ParamFuzzMode.RANDOM:
                logger.warning(
                    "Invalid fuzzing mode for parameter with type "
                    "xs:int, using random mode."
                )
            invalid_string = gen_random_string(random.randint(1, 100))
            invalid_special_string = gen_malicous_string()
            invalid_over_num = gen_invalid_int_num(
                float_flag=False,
                over_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
            invalid_under_num = gen_invalid_int_num(
                float_flag=False,
                under_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
            invalid_over_float_num = gen_invalid_int_num(
                float_flag=True,
                over_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
            invalid_under_float_num = gen_invalid_int_num(
                float_flag=True,
                under_flag=True,
                min_val=min_val,
                max_val=max_val,
            )

            return random.choice(
                [
                    invalid_string,
                    invalid_special_string,
                    invalid_over_num,
                    invalid_under_num,
                    invalid_over_float_num,
                    invalid_under_float_num,
                ]
            )


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

    if float_flag:
        # Value under range
        if under_flag:
            lower_value = random.uniform(lower_limit_neg, upper_limit_neg)
            return lower_value
        # Value over range
        if over_flag:
            higher_value = random.uniform(lower_limit_pos, upper_limit_pos)
            return higher_value
        # no under or over flag => float value from valid range
        # invalid type from valid range
        invalid_number = random.uniform(upper_limit_neg, lower_limit_pos)
        return invalid_number

    # int number
    if under_flag:
        lower_value = random.randint(lower_limit_neg, upper_limit_neg)
        return lower_value
    if over_flag:
        higher_value = random.randint(lower_limit_pos, upper_limit_pos)
        return higher_value

    # no under or over flag => random choice
    # Normal int is valid choice, so randomly choose from invalid ranges
    lower_value = random.randint(lower_limit_neg, upper_limit_neg)
    higher_value = random.randint(lower_limit_pos, upper_limit_pos)
    invalid_number = random.choice([lower_value, higher_value])

    return invalid_number


def gen_invalid_byte(
    mode: ParamFuzzMode = ParamFuzzMode.RANDOM,
    min_val: Optional[int] = None,
    max_val: Optional[int] = None,
) -> Union[str, int, float]:
    """Generate invalid xs:byte (type in XML schema)

    If min or max is specified, valid values are between min and max (inclusive).
    Min/max are specified in schema as restriction for value.
    For example: type="xs:byte" minInclusive="-3" maxInclusive="3"
    """

    match mode:
        case ParamFuzzMode.STRING:
            return gen_random_string(random.randint(1, 100))
        case ParamFuzzMode.SPECIAL_STRING:
            return gen_malicous_string()
        case ParamFuzzMode.OVER_INT:
            return gen_invalid_byte_num(
                float_flag=False,
                over_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
        case ParamFuzzMode.UNDER_INT:
            return gen_invalid_byte_num(
                float_flag=False,
                under_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
        case ParamFuzzMode.FLOAT:
            return gen_invalid_byte_num(
                float_flag=True, min_val=min_val, max_val=max_val
            )
        case ParamFuzzMode.OVER_FLOAT:
            return gen_invalid_byte_num(
                float_flag=True,
                over_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
        case ParamFuzzMode.UNDER_FLOAT:
            return gen_invalid_byte_num(
                float_flag=True,
                under_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
        case _:
            if mode is not ParamFuzzMode.RANDOM:
                logger.warning(
                    "Invalid fuzzing mode for parameter with type "
                    "xs:byte, using random mode."
                )
            invalid_string = gen_random_string(random.randint(1, 100))
            invalid_special_string = gen_malicous_string()
            invalid_over_num = gen_invalid_byte_num(
                float_flag=False,
                over_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
            invalid_under_num = gen_invalid_byte_num(
                float_flag=False,
                under_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
            invalid_float_num = gen_invalid_byte_num(
                float_flag=True, min_val=min_val, max_val=max_val
            )
            invalid_over_float_num = gen_invalid_byte_num(
                float_flag=True,
                over_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
            invalid_under_float_num = gen_invalid_byte_num(
                float_flag=True,
                under_flag=True,
                min_val=min_val,
                max_val=max_val,
            )

            return random.choice(
                [
                    invalid_string,
                    invalid_special_string,
                    invalid_over_num,
                    invalid_under_num,
                    invalid_float_num,
                    invalid_over_float_num,
                    invalid_under_float_num,
                ]
            )


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

    if float_flag:
        # Value under range
        if under_flag:
            lower_value = random.uniform(lower_limit_neg, upper_limit_neg)
            return lower_value
        # Value over range
        if over_flag:
            higher_value = random.uniform(lower_limit_pos, upper_limit_pos)
            return higher_value
        # no under or over flag => random choice
        # lower_value = random.uniform(lower_limit_neg, upper_limit_neg)
        # higher_value = random.uniform(lower_limit_pos, upper_limit_pos)
        # invalid_number = random.choice([lower_value, higher_value])

        # valid range but float => invalid type from valid range
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
    # Normal int is valid choice, so randomly choose from invalid ranges
    lower_value = random.randint(lower_limit_neg, upper_limit_neg)
    higher_value = random.randint(lower_limit_pos, upper_limit_pos)
    invalid_number = random.choice([lower_value, higher_value])

    return invalid_number


def gen_invalid_unsigned_byte(
    mode: ParamFuzzMode = ParamFuzzMode.RANDOM,
    min_val: Optional[int] = None,
    max_val: Optional[int] = None,
) -> Union[str, int, float]:
    """Generate invalid xs:unsignedByte (type in XML schema)

    xs:unsignedByte, 0-255 are valid values
    Randomly choose invalid value - float, string or number out of range

    Relevant modes: random, string, int, over-int,
        under-int, float, over-float, under-float
    """

    match mode:
        case ParamFuzzMode.STRING:
            return gen_random_string(random.randint(1, 100))
        case ParamFuzzMode.SPECIAL_STRING:
            return gen_malicous_string()
        case ParamFuzzMode.OVER_INT:
            return gen_invalid_unsigned_byte_num(
                float_flag=False,
                over_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
        case ParamFuzzMode.UNDER_INT:
            return gen_invalid_unsigned_byte_num(
                float_flag=False,
                under_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
        case ParamFuzzMode.INT:
            return gen_invalid_unsigned_byte_num(
                float_flag=False, min_val=min_val, max_val=max_val
            )
        case ParamFuzzMode.OVER_FLOAT:
            return gen_invalid_unsigned_byte_num(
                float_flag=True,
                over_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
        case ParamFuzzMode.UNDER_FLOAT:
            return gen_invalid_unsigned_byte_num(
                float_flag=True,
                under_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
        case ParamFuzzMode.FLOAT:
            return gen_invalid_unsigned_byte_num(
                float_flag=True, min_val=min_val, max_val=max_val
            )
        case _:
            if mode is not ParamFuzzMode.RANDOM:
                logger.warning(
                    "Invalid fuzzing mode for parameter with type "
                    "xs:unsignedByte, using random mode."
                )
            invalid_string = gen_random_string(random.randint(1, 100))
            invalid_special_string = gen_malicous_string()
            invalid_over_num = gen_invalid_unsigned_byte_num(
                float_flag=False,
                over_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
            invalid_under_num = gen_invalid_unsigned_byte_num(
                float_flag=False,
                under_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
            invalid_over_float_num = gen_invalid_unsigned_byte_num(
                float_flag=True,
                over_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
            invalid_under_float_num = gen_invalid_unsigned_byte_num(
                float_flag=True,
                under_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
            invalid_float_num = gen_invalid_unsigned_byte_num(
                float_flag=True, min_val=min_val, max_val=max_val
            )

            return random.choice(
                [
                    invalid_string,
                    invalid_special_string,
                    invalid_over_num,
                    invalid_under_num,
                    invalid_over_float_num,
                    invalid_under_float_num,
                    invalid_float_num,
                ]
            )


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
            invalid_string = gen_random_string(random.randint(1, 100))
            special_string = gen_malicous_string()
            invalid_num = gen_num(float_flag=False, negative_flag=False)
            invalid_neg_num = gen_num(float_flag=False, negative_flag=True)
            invalid_float_num = gen_num(float_flag=True, negative_flag=False)
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

    if float_flag:
        # Value under range
        if under_flag:
            lower_value = random.uniform(lower_limit_neg, upper_limit_neg)
            return lower_value
        # Value over range
        if over_flag:
            higher_value = random.uniform(lower_limit_pos, upper_limit_pos)
            return higher_value
        # no under or over flag => random choice
        # lower_value = random.uniform(lower_limit_neg, upper_limit_neg)
        # higher_value = random.uniform(lower_limit_pos, upper_limit_pos)
        # invalid_number = random.choice([lower_value, higher_value])

        # valid range but float => invalid type from valid range
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
    # Normal int is valid choice, so randomly choose from invalid ranges
    lower_value = random.randint(lower_limit_neg, upper_limit_neg)
    higher_value = random.randint(lower_limit_pos, upper_limit_pos)
    invalid_number = random.choice([lower_value, higher_value])

    return invalid_number


def gen_invalid_unsigned_long(
    mode: ParamFuzzMode = ParamFuzzMode.RANDOM,
) -> Union[str, int, float]:
    """Generate invalid xs:unsignedLong (type in XML schema)

    xs:unsignedLong, 0-8446744073709551615 are valid values
    """

    match mode:
        case ParamFuzzMode.STRING:
            return gen_random_string(random.randint(1, 100))
        case ParamFuzzMode.SPECIAL_STRING:
            return gen_malicous_string()
        case ParamFuzzMode.OVER_INT:
            return gen_invalid_unsigned_long_num(
                float_flag=False, over_flag=True
            )
        case ParamFuzzMode.UNDER_INT:
            return gen_invalid_unsigned_long_num(
                float_flag=False, under_flag=True
            )
        case ParamFuzzMode.FLOAT:
            return gen_invalid_unsigned_long_num(float_flag=True)
        case ParamFuzzMode.OVER_FLOAT:
            return gen_invalid_unsigned_long_num(
                float_flag=True, over_flag=True
            )
        case ParamFuzzMode.UNDER_FLOAT:
            return gen_invalid_unsigned_long_num(
                float_flag=True, under_flag=True
            )
        case _:
            if mode is not ParamFuzzMode.RANDOM:
                logger.warning(
                    "Invalid fuzzing mode for parameter with type "
                    "xs:unsignedLong, using random mode."
                )
            invalid_string = gen_random_string(random.randint(1, 100))
            invalid_special_string = gen_malicous_string()
            invalid_over_num = gen_invalid_unsigned_long_num(
                float_flag=False, over_flag=True
            )
            invalid_under_num = gen_invalid_unsigned_long_num(
                float_flag=False, under_flag=True
            )
            invalid_float_num = gen_invalid_unsigned_long_num(float_flag=True)
            invalid_over_float_num = gen_invalid_unsigned_long_num(
                float_flag=True, over_flag=True
            )
            invalid_under_float_num = gen_invalid_unsigned_long_num(
                float_flag=True, under_flag=True
            )

            return random.choice(
                [
                    invalid_string,
                    invalid_special_string,
                    invalid_over_num,
                    invalid_under_num,
                    invalid_float_num,
                    invalid_over_float_num,
                    invalid_under_float_num,
                ]
            )


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


def gen_invalid_short(
    mode: ParamFuzzMode = ParamFuzzMode.RANDOM,
    min_val: Optional[int] = None,
    max_val: Optional[int] = None,
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
        case ParamFuzzMode.STRING:
            return gen_random_string(random.randint(1, 100))
        case ParamFuzzMode.SPECIAL_STRING:
            return gen_malicous_string()
        case ParamFuzzMode.OVER_INT:
            return gen_invalid_short_num(
                float_flag=False,
                over_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
        case ParamFuzzMode.UNDER_INT:
            return gen_invalid_short_num(
                float_flag=False,
                under_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
        case ParamFuzzMode.FLOAT:
            return gen_invalid_short_num(
                float_flag=True, min_val=min_val, max_val=max_val
            )
        case ParamFuzzMode.OVER_FLOAT:
            return gen_invalid_short_num(
                float_flag=True,
                over_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
        case ParamFuzzMode.UNDER_FLOAT:
            return gen_invalid_short_num(
                float_flag=True,
                under_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
        case _:
            if mode is not ParamFuzzMode.RANDOM:
                logger.warning(
                    "Invalid fuzzing mode for parameter with type "
                    "xs:short, using random mode."
                )
            invalid_string = gen_random_string(random.randint(1, 100))
            invalid_special_string = gen_malicous_string()
            invalid_over_num = gen_invalid_short_num(
                float_flag=False,
                over_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
            invalid_under_num = gen_invalid_short_num(
                float_flag=False,
                under_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
            invalid_over_float_num = gen_invalid_short_num(
                float_flag=True,
                over_flag=True,
                min_val=min_val,
                max_val=max_val,
            )
            invalid_under_float_num = gen_invalid_short_num(
                float_flag=True,
                under_flag=True,
                min_val=min_val,
                max_val=max_val,
            )

            return random.choice(
                [
                    invalid_string,
                    invalid_special_string,
                    invalid_over_num,
                    invalid_under_num,
                    invalid_over_float_num,
                    invalid_under_float_num,
                ]
            )


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


def gen_invalid_unsigned_short(
    mode: ParamFuzzMode = ParamFuzzMode.RANDOM,
) -> Union[str, int, float]:
    """Generate invalid xs:unsignedShort (type in XML schema)

    xs:unsignedShort, 0 to 65535 are valid values
    """
    match mode:
        case ParamFuzzMode.STRING:
            return gen_random_string(random.randint(1, 100))
        case ParamFuzzMode.SPECIAL_STRING:
            return gen_malicous_string()
        case ParamFuzzMode.OVER_INT:
            return gen_invalid_unsigned_short_num(
                float_flag=False, over_flag=True
            )
        case ParamFuzzMode.UNDER_INT:
            return gen_invalid_unsigned_short_num(
                float_flag=False, under_flag=True
            )
        case ParamFuzzMode.FLOAT:
            return gen_invalid_unsigned_short_num(float_flag=True)
        case ParamFuzzMode.OVER_FLOAT:
            return gen_invalid_unsigned_short_num(
                float_flag=True, over_flag=True
            )
        case ParamFuzzMode.UNDER_FLOAT:
            return gen_invalid_unsigned_short_num(
                float_flag=True, under_flag=True
            )
        case _:
            if mode is not ParamFuzzMode.RANDOM:
                logger.warning(
                    "Invalid fuzzing mode for parameter with type "
                    "xs:unsignedShort, using random mode."
                )
            invalid_string = gen_random_string(random.randint(1, 100))
            invalid_special_string = gen_malicous_string()
            invalid_over_num = gen_invalid_unsigned_short_num(
                float_flag=False, over_flag=True
            )
            invalid_under_num = gen_invalid_unsigned_short_num(
                float_flag=False, under_flag=True
            )
            invalid_float_num = gen_invalid_unsigned_short_num(float_flag=True)
            invalid_over_float_num = gen_invalid_unsigned_short_num(
                float_flag=True, over_flag=True
            )
            invalid_under_float_num = gen_invalid_unsigned_short_num(
                float_flag=True, under_flag=True
            )
            return random.choice(
                [
                    invalid_string,
                    invalid_special_string,
                    invalid_over_num,
                    invalid_under_num,
                    invalid_float_num,
                    invalid_over_float_num,
                    invalid_under_float_num,
                ]
            )


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


def gen_invalid_long(
    mode: ParamFuzzMode = ParamFuzzMode.RANDOM,
) -> Union[str, int, float]:
    """Generate invalid xs:long type(type in XML schema)

    xs:long, -9223372036854775808 to 9223372036854775807 are valid values (2^63, 2^63 - 1)
    """
    match mode:
        case ParamFuzzMode.STRING:
            return gen_random_string(random.randint(1, 100))
        case ParamFuzzMode.SPECIAL_STRING:
            return gen_malicous_string()
        case ParamFuzzMode.OVER_INT:
            return gen_invalid_long_num(float_flag=False, over_flag=True)
        case ParamFuzzMode.UNDER_INT:
            return gen_invalid_long_num(float_flag=False, under_flag=True)
        case ParamFuzzMode.OVER_FLOAT:
            return gen_invalid_long_num(float_flag=True, over_flag=True)
        case ParamFuzzMode.UNDER_FLOAT:
            return gen_invalid_long_num(float_flag=True, under_flag=True)
        case ParamFuzzMode.FLOAT:
            return gen_invalid_long_num(float_flag=True)
        case _:
            if mode is not ParamFuzzMode.RANDOM:
                logger.warning(
                    "Invalid fuzzing mode for parameter with type "
                    "xs:long, using random mode."
                )
            invalid_string = gen_random_string(random.randint(1, 100))
            invalid_special_string = gen_malicous_string()
            invalid_over_num = gen_invalid_long_num(
                float_flag=False, under_flag=True
            )
            invalid_under_num = gen_invalid_long_num(
                float_flag=False, over_flag=True
            )
            invalid_over_float_num = gen_invalid_long_num(
                float_flag=True, under_flag=True
            )
            invalid_under_float_num = gen_invalid_long_num(
                float_flag=True, over_flag=True
            )
            invalid_float_num = gen_invalid_long_num(float_flag=True)
            return random.choice(
                [
                    invalid_string,
                    invalid_special_string,
                    invalid_over_num,
                    invalid_under_num,
                    invalid_over_float_num,
                    invalid_under_float_num,
                    invalid_float_num,
                ]
            )


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


def fuzz_schema_id(mode: str = "random") -> Union[str, int, float]:
    """Fuzz schema id

    SchemaID is xs:unsignedByte, so valid value is in range 0-255.
    Fuzzer should test values out of range, for example -1, 256,
    or string instead of number.

    Relevant modes: random, string, int, over-int,
        under-int, float, over-float, under-float
    """
    # Convert mode to enum
    try:
        mode = ParamFuzzMode(mode)
    except ValueError:
        logger.warning(
            "Invalid fuzzing mode. Using random mode for schemaID fuzzing."
        )
        mode = ParamFuzzMode.RANDOM

    # TODO: Maybe option for mode with SPECIAL_STRING should be
    # handled here (also for other methods),
    # because it's based on context of parameter

    return gen_invalid_unsigned_byte(mode)


def fuzz_response_code(mode: str = "random") -> Union[str, int, float]:
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
    mode: str = "random", val_type: str = "string"
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
                    "Invalid fuzzing mode for parameter with type "
                    "xs:string, using random mode."
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


def fuzz_evse_timestamp(mode: str = "random") -> Union[str, int, float]:
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

    return gen_invalid_long(mode=mode)


# TODO: For complexType, create fuzz method for each element
# => for every simpleType create fuzz method
# This can be a hack for fuzzing only specific elements of complexType
# can be used like accepting names of elements as parameters
# and based on that fuzz only specific elements


def fuzz_payment_option_list(modes: dict) -> str:
    """Fuzz payment option list"""

    raise NotImplementedError


def fuzz_charge_service() -> str:
    """Fuzz charge service"""
    raise NotImplementedError


def fuzz_service_id(mode: str = "random") -> Union[str, int, float]:
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

    return gen_invalid_unsigned_short(mode=mode)


def fuzz_service_name(mode: str = "random") -> Union[str, int, float]:
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


def fuzz_service_category(mode: str = "random") -> Union[str, int, float]:
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
        case ParamFuzzMode.STRING:
            return gen_random_string(random.randint(1, 100))
        case ParamFuzzMode.SPECIAL_STRING:
            gen_malicous_string()
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


def fuzz_service(modes: dict) -> dict:
    """Fuzz service"""

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


def fuzz_service_list(modes: dict) -> dict:
    """Fuzz service list"""

    # Has to be list of services, also if only one service is provided
    service = [fuzz_service(modes=modes["Service"])]

    return {"Service": service}


def fuzz_parameter(modes: dict) -> dict:
    """Fuzz parameter

    Parameter is complex type, so it has attributes and elements.
    In XSD defined as: parameterType.
    """

    # Name is attribute in XSD => @Name
    # type xs:string
    name = gen_invalid_string(mode=modes["Name"])

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

    # First check if random mode is specified
    if value_type == ParamFuzzMode.RANDOM:
        value_type = random.choice(value_types)  # => value_type is valid

    if value_type not in value_types:
        logger.warning("Invalid value type for Parameter, using random mode.")
        value_type = random.choice(value_types)  # => value_type is valid

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


def fuzz_parameter_set(modes: dict) -> dict:
    """Fuzz parameter set"""

    parameter_set_id = gen_invalid_short(mode=modes["ParameterSetID"])
    # List of parameterType
    parameter = [fuzz_parameter(modes=modes["Parameter"])]

    return {"ParameterSetID": parameter_set_id, "Parameter": parameter}


def fuzz_service_parameter_list(modes: dict) -> dict:
    """Fuzz service detail list"""
    parameter_set = [fuzz_parameter_set(modes=modes["ParameterSet"])]
    return {"ParameterSet": parameter_set}


def fuzz_gen_challenge() -> str:
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

    raise NotImplementedError


def fuzz_evse_processing(mode: str = "random") -> Union[str, int, float]:
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


def fuzz_sa_schedule_list() -> str:
    """Fuzz sa schedule list"""
    raise NotImplementedError


def fuzz_ac_evse_charge_parameter() -> str:
    """Fuzz ac evse charge parameter"""
    raise NotImplementedError


def fuzz_dc_evse_charge_parameter() -> str:
    """Fuzz dc evse charge parameter"""
    raise NotImplementedError


def fuzz_ac_evse_status() -> str:
    """Fuzz ac evse status"""
    raise NotImplementedError


def fuzz_dc_evse_status() -> str:
    """Fuzz dc evse status"""
    raise NotImplementedError


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


def fuzz_retry_counter(mode: str = "random") -> Union[str, int, float]:
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


def fuzz_sa_schedule_tuple_id(mode: str = "random") -> Union[str, int, float]:
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

    return gen_invalid_unsigned_byte(mode=mode, min_val=1, max_val=255)


def fuzz_multiplier(mode: str = "random") -> Union[str, int, float]:
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
    return gen_invalid_byte(mode=mode, min_val=-3, max_val=3)


def fuzz_unit(
    mode: str = "random", unit_val: str = ""
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


def fuzz_value(mode: str = "random") -> Union[str, int, float]:
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

    return gen_invalid_short(mode=mode)


def fuzz_physical_value_type(modes: dict, unit_val: str = "") -> dict:
    """Fuzz physical value type

    PhysicalValueType is complexType.
    PhysicalValueType contains 3 fields: Multiplier, Unit, Value.

    """
    multiplier = fuzz_multiplier(modes["Multiplier"])
    unit = fuzz_unit(modes["Unit"], unit_val=unit_val)
    value = fuzz_value(modes["Value"])

    return {"Multiplier": multiplier, "Unit": unit, "Value": value}


def fuzz_evse_max_current(modes: dict) -> dict:
    """Fuzz evse max current.

    EVSEMaxCurrent is complexType: PhysicalValueType."""

    return fuzz_physical_value_type(
        modes["EVSEMaxCurrent"], unit_val=unitSymbolType.AMPERE.value
    )


def fuzz_meter_id(mode: str = "random"):
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

    return gen_invalid_unsigned_byte(mode=mode)


def fuzz_meter_reading(mode: str = "random"):
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

    return gen_invalid_unsigned_long(mode=mode)


def fuzz_sig_meter_reading(mode: str = "random"):
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


def fuzz_meter_status(mode: str = "random"):
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

    return gen_invalid_short(mode=mode)


def fuzz_t_meter(mode: str = "random"):
    """Fuzz t meter

    TMeter is type xs:long (in xml schema).
    """
    # Convert mode to enum
    try:
        mode = ParamFuzzMode(mode)
    except ValueError:
        logger.warning("Invalid fuzzing mode for TMeter, using random mode.")
        mode = ParamFuzzMode.RANDOM

    return gen_invalid_long(mode=mode)


def fuzz_meter_info(modes: dict) -> dict:
    """Fuzz meter info

    MeterInfo is complexType: MeterInfoType.
    It contains 5 fields: MeterID, MeterReading, SigMeterReading, MeterStatus, TMeter.

    MeterID is type xs:unsignedByte (in xml schema).
    MeterReading is type xs:unsignedLong (in xml schema).
    SigMeterReading is type xs:base64Binary, maxLength 64.
    MeterStatus is type xs:short (in xml schema).
    TMeter is type xs:long (in xml schema).
    """

    # xs:unsignedByte
    meter_id = fuzz_meter_id(modes["MeterID"])

    # xs:unsignedLong, 0 and 18446744073709551615 are valid values
    meter_reading = fuzz_meter_reading(modes["MeterReading"])

    # xs:base64Binary, maxLength 64
    # binary datatypes (xs:hexBinary and xs:base64Binary),
    # for which lengths are expressed in number of bytes (8 bits) of binary data
    sig_meter_reading = fuzz_sig_meter_reading(modes["SigMeterReading"])

    # xs:short, valid values: -32768 to 32767
    meter_status = fuzz_meter_status(modes["MeterStatus"])

    # xs:long, valid values: -9223372036854775808 to 9223372036854775807
    t_meter = fuzz_t_meter(modes["TMeter"])

    return {
        "MeterID": meter_id,
        "MeterReading": meter_reading,
        "SigMeterReading": sig_meter_reading,
        "MeterStatus": meter_status,
        "TMeter": t_meter,
    }


def fuzz_receipt_required(mode: str = "random") -> Union[str, int, float]:
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


def fuzz_evse_present_voltage(modes: dict) -> dict:
    """Fuzz evse present voltage

    EVSEPresentVoltage is complexType: PhysicalValueType.
    """

    return fuzz_physical_value_type(
        modes["EVSEPresentVoltage"], unit_val=unitSymbolType.VOLT.value
    )


def fuzz_evse_present_current(modes: dict) -> dict:
    """Fuzz evse present current

    EVSEPresentCurrent is complexType: PhysicalValueType.
    """

    return fuzz_physical_value_type(
        modes["EVSEPresentCurrent"], unit_val=unitSymbolType.AMPERE.value
    )


def fuzz_evse_current_limit_achieved(
    mode: str = "random",
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
    mode: str = "random",
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
    mode: str = "random",
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


def fuzz_evse_maximum_voltage(modes: dict) -> dict:
    """Fuzz evse maximum voltage

    EVSEMaximumVoltage is complexType: PhysicalValueType.
    """
    return fuzz_physical_value_type(
        modes["EVSEMaximumVoltage"], unit_val=unitSymbolType.VOLT.value
    )


def fuzz_evse_maximum_current(modes: dict) -> dict:
    """Fuzz evse maximum current

    EVSEMaximumCurrent is complexType: PhysicalValueType.
    """
    return fuzz_physical_value_type(
        modes["EVSEMaximumCurrent"], unit_val=unitSymbolType.AMPERE.value
    )


def fuzz_evse_maximum_power(modes: dict) -> dict:
    """Fuzz evse maximum power

    EVSEMaximumPower is complexType: PhysicalValueType.
    """
    return fuzz_physical_value_type(
        modes["EVSEMaximumPower"], unit_val=unitSymbolType.WATT.value
    )
