"""Contains general method for fuzzing message"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


def general_msg_fuzzing_method(
    required_fields: list,
    all_fields: list,
    msg_config: Optional[dict] = None,
    msg_fuzz_dict: Optional[dict] = None,
    msg_default_dict: Optional[dict] = None,
    pairs_name_method: Optional[dict] = None,
    class_name: str = "",
) -> dict:
    """General method for fuzzing message"""

    if msg_default_dict is None:
        logger.warning(
            "Default values for fuzzing in class %s. "
            "Fuzzing with valid_values = None",
            class_name,
        )
        msg_default_dict = {}

    if msg_fuzz_dict is None:
        msg_fuzz_dict = {}

    # Required fields define in the standard
    # required_fields
    # All possible fields (required/optional) define in the standard
    # all_fields

    # if msg_config is None => fuzz all possible fields
    # Passing None to each parameter
    # In each parameter is handled None
    #   - simpleType => fuzz value
    #   - complexType => fuzz each parameter (passing None to each parameter)
    if msg_config is None:
        msg_config = {}
        # Iterate through all parameters
        for field in all_fields:
            # Set None to each parameter art_config
            msg_config[field] = None

    # if msg_config is not None => empty or not empty
    # if empty fuzz all required_fields
    # if not empty fuzz only specified fields
    else:
        # msg_config is empty
        if not msg_config:
            # Passing {} to each parameter
            # In each parameter is handled {}
            #   - simpleType => fuzz value
            #   - complexType => fuzz each parameter (passing {} to each parameter)
            for field in required_fields:
                msg_config[field] = {}
        # msg_config is not empty
        else:
            # TODO: ADD CHECK IF MODE is in msg_config
            # RequiredParams are specified in config => override required_fields
            if "RequiredParams" in msg_config:
                # Responsibility is up to user
                if all(field in msg_config for field in required_fields):
                    logger.warning(
                        "Not all required parameters are specified for fuzz in class %s. ",
                        class_name,
                    )
                required_fields = msg_config["RequiredParams"]
                # Need to remove RequiredParams from config
                # because it is not parameter for message
                msg_config.pop("RequiredParams")

            # Fields is required but not specified in config => add to config
            # with {} => fuzz each parameter or fuzz value (simpleType)
            for field in required_fields:
                if field not in msg_config:
                    msg_config[field] = {}

    # Iterate through all parameters
    for name in msg_config.keys():
        # Check if it has valid_values dict in default_dict
        # If first level parameter is not in default_dict
        # also subparameters are not in default_dict
        if name not in msg_default_dict:
            valid_values = None
        else:
            valid_values = msg_default_dict[name]

        # Should never happen
        assert pairs_name_method is not None
        # Fuzz each parameter/field
        msg_fuzz_dict[name] = pairs_name_method[name](
            attr_conf=msg_config[name], valid_values=valid_values
        )

    # Put back RequiredParams to config ???

    return msg_fuzz_dict
