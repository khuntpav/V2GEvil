"""
V2GEvil - Tool for testing and evaluation of V2G communication.
Copyright (C) 2024 Pavel Khunt

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License for more details.
"""

"""This module contains functions for converting between XML and class instances."""

import logging
from typing import Union
import requests
import xmltodict


from .MsgDef import V2G_Message
from .AppProtocol import supportedAppProtocolReq, supportedAppProtocolRes
from .namespace_map import namespace_map

logger = logging.getLogger(__name__)


def xml2class_instance(
    xml: str,
) -> Union[V2G_Message, supportedAppProtocolReq, supportedAppProtocolRes]:
    """Converts XML to a class instance.

    Args:
        xml (str): XML string to convert.

    Returns:
        class: Class instance.
    """

    # None => to remove the namespace
    xmltodict_namespaces = {
        "urn:iso:15118:2:2013:MsgDef": None,
        "urn:iso:15118:2:2013:MsgHeader": None,
        "urn:iso:15118:2:2013:MsgBody": None,
        "urn:iso:15118:2:2013:MsgDataTypes": None,
        "urn:iso:15118:2:2010:AppProtocol": None,
        "http://www.w3.org/2001/XMLSchema-instance": None,
        "http://www.w3.org/2000/09/xmldsig#": None,
    }

    # Easily delete namespaces from XML => NO NEED FOR any delete_unwanted_prefixes_from_keys_rec
    # At the same time, it deletes namespace attributes from root element
    # And also force_list solve the proble with only one service in the Service list
    # Any list (from MsgDataTypes) should be added to the force_list,
    # because it will prevent from pydantic error
    # by default for one item it will not create list with one item => pydantic error
    dict_data = xmltodict.parse(
        xml,
        dict_constructor=dict,
        process_namespaces=True,
        namespaces=xmltodict_namespaces,
        force_list=(
            "AppProtocol",
            "SelectedService",
            "Parameter",
            "PaymentOption",
            "Service",
            "EnergyTransferMode",
            "ParameterSet",
            "Certificate",  # TODO: Problem, because for some it's as string and for others it's a list, with the same name "Certificate"
            "PMaxScheduleEntry",
            "Cost",
            "ConsumptionCost",
            "SalesTariffEntry",
            "SAScheduleTuple",
            "ProfileEntry",
        ),
    )

    root_element = list(dict_data.keys())[0]
    dict_data = dict_data[root_element]

    logger.debug("XML2class instance root_element: %s", root_element)
    logger.debug("XML2class instance dict_data:")
    logger.debug(dict_data)
    # TODO: Maybe implement something for empty elements/messages
    # to change None to empty dict {}

    # Check if it's V2G_Message or supportedAppProtocolReq/Res
    # Then creates a corresponding instance of the class
    # whose name is the root element of the dictionary
    if root_element == "V2G_Message":
        # V2G_Message
        # Convert dict to class instance
        # V2G_Message.model_validate(dict_data) almost same, boht create class instance
        # TODO: Problem with empty elements or messages like ServiceDiscoveryReq, which can be empty
        empty_messages = ["ServiceDiscoveryReq", "AuthorizationReq"]
        for msg in empty_messages:
            if msg in dict_data["Body"]:
                dict_data["Body"][msg] = {}

        obj = V2G_Message(**dict_data)
        # print(obj)
        # print(type(obj))
        # print(100 * "-")
        print(obj.model_dump(by_alias=True, exclude_unset=True))
        return obj

    if root_element == "supportedAppProtocolReq":
        # supportedAppProtocolReq
        # Convert dict to class instance
        obj = supportedAppProtocolReq(**dict_data)
        # print(obj)
        # print(type(obj))
        # print(100 * "-")
        print(obj.model_dump(by_alias=True, exclude_unset=True))
        print()
        return obj

    if root_element == "supportedAppProtocolRes":
        # supportedAppProtocolRes
        # Convert dict to class instance
        obj = supportedAppProtocolRes(**dict_data)
        # print(obj)
        # print(type(obj))
        # print(100 * "-")
        print(obj.model_dump(by_alias=True, exclude_unset=True))
        return obj

    # Should never happen
    raise ValueError("Unknown root element")


def class_instance2xml(obj: object, validate_flag: bool = True) -> str:
    """Converts class instance of
        V2G_Message or supportedAppProtocolReq/Res to XML.

    Args:
        class_instance (class): Class instance to convert.

    Returns:
        str: XML string.
    """
    logger.debug("Class instance2XML method")
    # V2G communication consists of two different Message Sets:
    #   - V2G application layer protocol handshake messages (refer to 8.2)
    #   - V2G application layer messages (refer to 8.3)

    # Distinguish between V2GMessage and AppProtocol message

    # The root element of the V2G communication message is V2GMessage
    if isinstance(obj, V2G_Message):
        if validate_flag:
            dict_data = obj.model_dump(by_alias=True, exclude_unset=True)
        else:
            dict_data = obj.model_dump(
                by_alias=True, exclude_unset=True, warnings=False
            )

        logger.debug("V2GMessage dict_data: %s", dict_data)

        # New root element
        root_element_name = "V2G_Message"
        # Create a new dictionary with the root element
        dict_data = {root_element_name: dict_data}
        root_element_name_with_ns = "v2gci_d" + ":" + root_element_name

        # Add namespaces to keys
        dict_data = add_namespaces_to_keys(dict_data)

        # xmltodict.unparse() can handle @ as prefix for attributes
        # So this is filling attributes for V2GMessage
        dict_data[root_element_name_with_ns][
            "@xmlns:v2gci_b"
        ] = "urn:iso:15118:2:2013:MsgBody"
        dict_data[root_element_name_with_ns][
            "@xmlns:xmlsig"
        ] = "http://www.w3.org/2000/09/xmldsig#"
        dict_data[root_element_name_with_ns][
            "@xmlns:v2gci_d"
        ] = "urn:iso:15118:2:2013:MsgDef"
        dict_data[root_element_name_with_ns][
            "@xmlns:v2gci_t"
        ] = "urn:iso:15118:2:2013:MsgDataTypes"
        dict_data[root_element_name_with_ns][
            "@xmlns:v2gci_h"
        ] = "urn:iso:15118:2:2013:MsgHeader"
        dict_data[root_element_name_with_ns][
            "@xmlns:xsi"
        ] = "http://www.w3.org/2001/XMLSchema-instance"

        # Convert dict to XML string
        xml_str = xmltodict.unparse(dict_data, pretty=False)
        # Delete new line after xml declaration, because xmltodict adds it
        # XML declaration: <?xml version="1.0" encoding="UTF-8"?>
        xml_str = xml_str.replace("\n", "")

        logger.debug(xml_str)

        return xml_str

    # The root element of the V2G communication message is supportedAppProtocolRes
    if isinstance(obj, supportedAppProtocolRes):
        # Dict to XML as supportedAppProtocolRes
        if validate_flag:
            dict_data = obj.model_dump(by_alias=True, exclude_unset=True)
        else:
            dict_data = obj.model_dump(
                by_alias=True, exclude_unset=True, warnings=False
            )
        logger.debug("supportedAppProtocolRes dict_data: %s", dict_data)
        # New root element
        root_element_name = "supportedAppProtocolRes"
        root_element_name_with_ns = "n1" + ":" + root_element_name

        dict_data = {root_element_name_with_ns: dict_data}

        dict_data[root_element_name_with_ns][
            "@xsi:schemaLocation"
            # "urn:iso:15118:2:2010:AppProtocol ../V2G_CI_AppProtocol.xsd"
        ] = "urn:iso:15118:2:2010:AppProtocol"
        dict_data[root_element_name_with_ns][
            "@xmlns:n1"
        ] = "urn:iso:15118:2:2010:AppProtocol"
        dict_data[root_element_name_with_ns][
            "@xmlns:xsi"
        ] = "http://www.w3.org/2001/XMLSchema-instance"

        # Convert dict to XML string
        logger.debug(
            "supportedAppProtocolRes dict_data after adding ns: %s", dict_data
        )
        xml_str = xmltodict.unparse(dict_data, pretty=False)

        # Delete new line after xml declaration, because xmltodict adds it
        xml_str = xml_str.replace("\n", "")
        logger.debug(xml_str)

        return xml_str

    # The root element of the V2G communication message is supportedAppProtocolReq
    if isinstance(obj, supportedAppProtocolReq):
        # Dict to XML as supportedAppProtocolReq
        dict_data = obj.model_dump(by_alias=True, exclude_unset=True)
        # New root element
        root_element_name = "supportedAppProtocolReq"
        root_element_name_with_ns = "n1" + ":" + root_element_name

        dict_data = {root_element_name_with_ns: dict_data}

        dict_data[root_element_name_with_ns][
            "@xsi:schemaLocation"
        ] = "urn:iso:15118:2:2010:AppProtocol ../V2G_CI_AppProtocol.xsd"
        dict_data[root_element_name_with_ns][
            "@xmlns:n1"
        ] = "urn:iso:15118:2:2010:AppProtocol"
        dict_data[root_element_name_with_ns][
            "@xmlns:xsi"
        ] = "http://www.w3.org/2001/XMLSchema-instance"

        xml_str = xmltodict.unparse(dict_data, pretty=False)

        # Delete new line after xml declaration, because xmltodict adds it
        xml_str = xml_str.replace("\n", "")
        logger.debug(xml_str)

        return xml_str

    # Should never happen
    raise ValueError("Unknown class instance for conversion to XML")


def add_namespaces_to_keys(data) -> dict:
    """Adds namespaces to keys of the dictionary.

    Args:
        data (dict): Dictionary to add namespaces to.

    Returns:
        dict: Dictionary with namespaces.
    """

    data_with_prefixes = dict(
        add_namespaces(data, namespace_map=namespace_map)
    )
    return data_with_prefixes


def add_namespaces(data, namespace_map, parent_namespace=None):
    """Adds namespaces to keys of the dictionary."""
    if isinstance(data, dict):
        new_data = {}
        for key, value in data.items():
            # Determine the namespace for the current key
            for ns, keys in namespace_map.items():
                if key in keys:
                    current_namespace = ns
                    break
            else:
                print(f"Key {key} doesn't belong to any namespace")
                current_namespace = parent_namespace

            # If parrent is v2gci_t, then current_namespace is v2gci_t
            # It's here cause some elements are in v2gci_t and v2gci_b
            # if the parent is v2gci_b, then can be current_namespace is v2gci_b or v2gci_t
            # if the parent is v2gci_t, then can be current_namespace is v2gci_t
            # TODO: Later will be need to check the xmlsig and add xmlsig namespace
            if parent_namespace == "v2gci_t":
                current_namespace = "v2gci_t"

            elif (
                parent_namespace == "v2gci_b"
                and key in namespace_map["v2gci_t"]
            ):
                current_namespace = "v2gci_t"

            # Recursively process the child elements with the determined namespace
            new_data[f"{current_namespace}:{key}"] = add_namespaces(
                value, namespace_map, current_namespace
            )
        return new_data
    elif isinstance(data, list):
        # Handle lists by recursively processing each item in the list
        # parent_namespace = "v2gci_t"
        return [
            add_namespaces(item, namespace_map, parent_namespace)
            for item in data
        ]
    else:
        return data


def xml2exi(xml: str) -> str:
    """Converts XML to EXI.

    Args:
        xml (str): XML string to convert.

    Returns:
        str: EXI string.
    """
    try:
        response = requests.post(
            "http://localhost:9000",
            headers={"Format": "XML"},
            data=xml,
            timeout=10,
        )
        if response.status_code == 200:
            logger.debug("Response from V2GDecoder:")
            logger.debug(response.text)
        else:
            logger.warning("Error: %s", response.status_code)
            logger.warning("Error: %s", response.text)
    except requests.exceptions.Timeout:
        logger.error("Timeout! Is V2GDecoder running?")
        exit(1)
    except requests.exceptions.ConnectionError:
        logger.error("Connection refused! Is V2GDecoder running?")
        exit(1)

    return response.text
