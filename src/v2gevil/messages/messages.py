"""This module contains functions for converting between XML and class instances."""

import logging
import xml.etree.ElementTree as ET
import json
import xmltodict
import time


from .MsgDef import V2G_Message, Header, Body
from .MsgBody import SessionStopRes, ServiceDiscoveryRes
from .MsgDataTypes import (
    responseCodeType,
    paymentOptionType,
    PaymentOptionListType,
    ChargeServiceType,
    ServiceListType,
    ServiceType,
    serviceCategoryType,
    SupportedEnergyTransferModeType,
    EnergyTransferModeType,
)
from .AppProtocol import (
    supportedAppProtocolReq,
    supportedAppProtocolRes,
    AppProtocolType,
    responseCodeType as app_responseCodeType,
)
from .namespace_map import namespace_map

logger = logging.getLogger(__name__)


def testing():
    """Testing"""

    # For testing of V2G_Message as obj
    # obj
    # V2G_Message, with list in dict
    logger.debug(
        "Testing V2G_Message with list object parse to XML to test the add namepaces also for list"
    )
    header = Header(SessionID="678")
    service = ServiceDiscoveryRes(
        ResponseCode=responseCodeType.OK,
        PaymentOptionList=PaymentOptionListType(
            PaymentOption=[
                paymentOptionType.CONTRACT,
                paymentOptionType.EXTERNAL_PAYMENT,
            ]
        ),
        ChargeService=ChargeServiceType(
            ServiceID=2,
            ServiceName="AC charging",
            ServiceScope="Service Scope value",
            ServiceCategory=serviceCategoryType.EV_CHARGING,
            FreeService=True,
            SupportedEnergyTransferMode=SupportedEnergyTransferModeType(
                EnergyTransferMode=[
                    EnergyTransferModeType.AC_SINGLE_PHASE_CORE,
                    EnergyTransferModeType.AC_THREE_PHASE_CORE,
                ]
            ),
        ),
        ServiceList=ServiceListType(
            Service=[
                ServiceType(
                    ServiceID=2,
                    ServiceName="AC charging",
                    ServiceScope="Service Scope value",
                    ServiceCategory=serviceCategoryType.EV_CHARGING,
                    FreeService=True,
                ),
            ]
        ),
    )

    # print(type(service))
    body = Body(ServiceDiscoveryRes=service)
    # print(body.model_dump(by_alias=True))
    # print(body.model_dump(by_alias=True, exclude_unset=True))
    # print(body.model_dump(by_alias=True, exclude_none=True))

    msg = V2G_Message(Header=header, Body=body)

    class_instance2xml(msg)

    return

    # For testing of V2G_Message as obj
    # obj
    # V2G_Message
    logger.debug("Testing V2G_Message object parse to XML")
    header = Header(SessionID="12345678")
    body = Body(
        SessionStopRes=SessionStopRes(ResponseCode=responseCodeType.OK)
    )
    msg = V2G_Message(Header=header, Body=body)
    #
    obj = msg

    class_instance2xml(obj)

    # For testing of supportedAppProtocolReq as obj
    # obj
    # supportedAppProtocolReq

    logger.debug("Testing supportedAppProtocolReq object parse to XML")
    app_protocol_1 = AppProtocolType(
        ProtocolNamespace="urn:iso:15118:2:2013:MsgDef",
        VersionMajor=2,
        VersionMinor=0,
        SchemaID=10,
        Priority=1,
    )
    app_protocol_2 = AppProtocolType(
        ProtocolNamespace="urn:iso:15118:2:2010:MsgDef",
        VersionMajor=1,
        VersionMinor=0,
        SchemaID=20,
        Priority=2,
    )
    app_protocol_list = [app_protocol_1, app_protocol_2]
    obj = supportedAppProtocolReq(AppProtocol=app_protocol_list)

    class_instance2xml(obj)

    # For testing of supportedAppProtocolRes as obj
    # obj
    # supportedAppProtocolRes
    logger.debug("Testing supportedAppProtocolRes object parse to XML")
    supported_app_proto_res = supportedAppProtocolRes(
        ResponseCode=app_responseCodeType.SUCCESS_NEGOTIATION, SchemaID="10"
    )
    obj = supported_app_proto_res
    class_instance2xml(obj)


def testing_xml2class_instance():
    # supportedAppProtocolReq as xml
    xml1 = """<?xml version="1.0" encoding="utf-8"?><n1:supportedAppProtocolReq xsi:schemaLocation="urn:iso:15118:2:2010:AppProtocol ../V2G_CI_AppProtocol.xsd" xmlns:n1="urn:iso:15118:2:2010:AppProtocol" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><AppProtocol><ProtocolNamespace>urn:iso:15118:2:2013:MsgDef</ProtocolNamespace><VersionMajor>2</VersionMajor><VersionMinor>0</VersionMinor><SchemaID>10</SchemaID><Priority>1</Priority></AppProtocol><AppProtocol><ProtocolNamespace>urn:iso:15118:2:2010:MsgDef</ProtocolNamespace><VersionMajor>1</VersionMajor><VersionMinor>0</VersionMinor><SchemaID>20</SchemaID><Priority>2</Priority></AppProtocol></n1:supportedAppProtocolReq>"""

    # dict_data1 = xml2class_instance(xml1)
    # print(type(dict_data1))

    # v2g_message ->  as xml
    xml2 = """<?xml version="1.0" encoding="utf-8"?><v2gci_d:V2G_Message xmlns:v2gci_b="urn:iso:15118:2:2013:MsgBody" xmlns:xmlsig="http://www.w3.org/2000/09/xmldsig#" xmlns:v2gci_d="urn:iso:15118:2:2013:MsgDef" xmlns:v2gci_t="urn:iso:15118:2:2013:MsgDataTypes" xmlns:v2gci_h="urn:iso:15118:2:2013:MsgHeader" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><v2gci_d:Header><v2gci_h:SessionID>12345678</v2gci_h:SessionID></v2gci_d:Header><v2gci_d:Body><v2gci_b:SessionStopRes><v2gci_b:ResponseCode>OK</v2gci_b:ResponseCode></v2gci_b:SessionStopRes></v2gci_d:Body></v2gci_d:V2G_Message>"""

    # dict_data2 = xml2class_instance(xml2)
    # print(type(dict_data2))

    # ServiceDiscoveryRes as xml with only one Service in SeviceList
    # Cause problem => ServiceList is not a list when xmltodict.parse() is used
    # TODO
    # xml3 = """<?xml version="1.0" encoding="utf-8"?><v2gci_d:V2G_Message xmlns:v2gci_b="urn:iso:15118:2:2013:MsgBody" xmlns:xmlsig="http://www.w3.org/2000/09/xmldsig#" xmlns:v2gci_d="urn:iso:15118:2:2013:MsgDef" xmlns:v2gci_t="urn:iso:15118:2:2013:MsgDataTypes" xmlns:v2gci_h="urn:iso:15118:2:2013:MsgHeader" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><v2gci_d:Header><v2gci_h:SessionID>678</v2gci_h:SessionID></v2gci_d:Header><v2gci_d:Body><v2gci_b:ServiceDiscoveryRes><v2gci_b:ResponseCode>OK</v2gci_b:ResponseCode><v2gci_b:PaymentOptionList><v2gci_t:PaymentOption>Contract</v2gci_t:PaymentOption><v2gci_t:PaymentOption>ExternalPayment</v2gci_t:PaymentOption></v2gci_b:PaymentOptionList><v2gci_b:ChargeService><v2gci_t:ServiceID>2</v2gci_t:ServiceID><v2gci_t:ServiceName>AC charging</v2gci_t:ServiceName><v2gci_t:ServiceCategory>EVCharging</v2gci_t:ServiceCategory><v2gci_t:ServiceScope>Service Scope value</v2gci_t:ServiceScope><v2gci_t:FreeService>true</v2gci_t:FreeService><v2gci_t:SupportedEnergyTransferMode><v2gci_t:EnergyTransferMode>AC_single_phase_core</v2gci_t:EnergyTransferMode><v2gci_t:EnergyTransferMode>AC_three_phase_core</v2gci_t:EnergyTransferMode></v2gci_t:SupportedEnergyTransferMode></v2gci_b:ChargeService><v2gci_b:ServiceList><v2gci_t:Service><v2gci_t:ServiceID>2</v2gci_t:ServiceID><v2gci_t:ServiceName>AC charging</v2gci_t:ServiceName><v2gci_t:ServiceCategory>EVCharging</v2gci_t:ServiceCategory><v2gci_t:ServiceScope>Service Scope value</v2gci_t:ServiceScope><v2gci_t:FreeService>true</v2gci_t:FreeService></v2gci_t:Service></v2gci_b:ServiceList></v2gci_b:ServiceDiscoveryRes></v2gci_d:Body></v2gci_d:V2G_Message>"""
    # dict_data3 = xml2class_instance(xml3)

    xml4 = """<?xml version="1.0" encoding="utf-8"?><v2gci_d:V2G_Message xmlns:v2gci_b="urn:iso:15118:2:2013:MsgBody" xmlns:xmlsig="http://www.w3.org/2000/09/xmldsig#" xmlns:v2gci_d="urn:iso:15118:2:2013:MsgDef" xmlns:v2gci_t="urn:iso:15118:2:2013:MsgDataTypes" xmlns:v2gci_h="urn:iso:15118:2:2013:MsgHeader" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><v2gci_d:Header><v2gci_h:SessionID>678</v2gci_h:SessionID></v2gci_d:Header><v2gci_d:Body><v2gci_b:ServiceDiscoveryRes><v2gci_b:ResponseCode>OK</v2gci_b:ResponseCode><v2gci_b:PaymentOptionList><v2gci_t:PaymentOption>Contract</v2gci_t:PaymentOption><v2gci_t:PaymentOption>ExternalPayment</v2gci_t:PaymentOption></v2gci_b:PaymentOptionList><v2gci_b:ChargeService><v2gci_t:ServiceID>2</v2gci_t:ServiceID><v2gci_t:ServiceName>AC charging</v2gci_t:ServiceName><v2gci_t:ServiceCategory>EVCharging</v2gci_t:ServiceCategory><v2gci_t:ServiceScope>Service Scope value</v2gci_t:ServiceScope><v2gci_t:FreeService>true</v2gci_t:FreeService><v2gci_t:SupportedEnergyTransferMode><v2gci_t:EnergyTransferMode>AC_single_phase_core</v2gci_t:EnergyTransferMode><v2gci_t:EnergyTransferMode>AC_three_phase_core</v2gci_t:EnergyTransferMode></v2gci_t:SupportedEnergyTransferMode></v2gci_b:ChargeService><v2gci_b:ServiceList><v2gci_t:Service><v2gci_t:ServiceID>2</v2gci_t:ServiceID><v2gci_t:ServiceName>AC charging</v2gci_t:ServiceName><v2gci_t:ServiceCategory>EVCharging</v2gci_t:ServiceCategory><v2gci_t:ServiceScope>Service Scope value</v2gci_t:ServiceScope><v2gci_t:FreeService>true</v2gci_t:FreeService></v2gci_t:Service><v2gci_t:Service><v2gci_t:ServiceID>3</v2gci_t:ServiceID><v2gci_t:ServiceName>DC charging</v2gci_t:ServiceName><v2gci_t:ServiceCategory>EVCharging</v2gci_t:ServiceCategory><v2gci_t:ServiceScope>Service Scope value</v2gci_t:ServiceScope><v2gci_t:FreeService>true</v2gci_t:FreeService></v2gci_t:Service></v2gci_b:ServiceList></v2gci_b:ServiceDiscoveryRes></v2gci_d:Body></v2gci_d:V2G_Message>"""
    dict_data3 = xml2class_instance(xml4)


def xml2class_instance(xml: str):
    """Converts XML to a class instance.

    Args:
        xml (str): XML string to convert.

    Returns:
        class: Class instance.
    """
    # xml = """<?xml version="1.0" encoding="UTF-8"?>
    # <v2gci_d:V2G_Message xmlns:v2gci_h="urn:iso:15118:2:2013:MsgHeader"
    # xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    # xmlns:v2gci_b="urn:iso:15118:2:2013:MsgBody"
    # xmlns:v2gci_d="urn:iso:15118:2:2013:MsgDef"
    # xmlns:v2gci_t="urn:iso:15118:2:2013:MsgDataTypes"
    # xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    # <v2gci_d:Header>
    # <v2gci_h:SessionID>3031323334353637</v2gci_h:SessionID>
    # </v2gci_d:Header>
    # <v2gci_d:Body>
    # <v2gci_b:ServiceDetailReq>
    # <v2gci_b:ServiceID>2</v2gci_b:ServiceID>
    # </v2gci_b:ServiceDetailReq>
    # </v2gci_d:Body>
    # </v2gci_d:V2G_Message>"""

    # Testing xmltodict library #
    xmltodict_namespaces = {
        "urn:iso:15118:2:2013:MsgBody": None,
        "http://www.w3.org/2000/09/xmldsig#": None,
        "urn:iso:15118:2:2013:MsgDef": None,
        "urn:iso:15118:2:2013:MsgDataTypes": None,
        "urn:iso:15118:2:2013:MsgHeader": None,
        "http://www.w3.org/2001/XMLSchema-instance": None,
    }

    # Easily delete namespaces from XML => NO NEED FOR any delete_unwanted_prefixes_from_keys_rec
    # At the same time, it deletes namespace attributes from root element
    dict_data = xmltodict.parse(
        xml,
        dict_constructor=dict,
        process_namespaces=True,
        namespaces=xmltodict_namespaces,
    )

    print(dict_data)

    root_element = list(dict_data.keys())[0]
    dict_data = dict_data[root_element]
    print(dict_data)

    model = V2G_Message.model_validate(dict_data)

    print(model)

    # Testing xmltodict library #
    exit()

    # Convert XML to data in dictionary => type dict
    dict_data = xmltodict.parse(xml, dict_constructor=dict)
    copy_dict_data = xmltodict.parse(xml, dict_constructor=dict)

    # Convert dictionary to JSON => type str
    # json_data = json.dumps(dict_data)

    logger.debug("Printing XML data converted to dictionary")
    logger.debug(dict_data)
    logger.debug(type(dict_data))
    # logger.debug("Printing XML data converted to JSON")
    # logger.debug(json_data)
    # logger.debug(type(json_data))
    # working with json - testing
    # print(json_data.replace("@xmlns:", ""))

    # Get first key of the dictionary => root element in XML
    # Should be V2G_Message, supportedAppProtocolReq or supportedAppProtocolRes
    print(list(dict_data.keys())[0])
    root_element = list(dict_data.keys())[0]

    logger.debug("Printing root element: %s", root_element)

    # Get namespaces and prefixes from root element
    prefixes = []
    root_attributes_namespaces = []

    for key in dict_data[root_element].keys():
        if key.startswith("@xmlns:") or key.startswith("@xsi:"):
            prefixes.append(key.split(":")[1])
            root_attributes_namespaces.append(key)

    # Delete root attributes namespaces
    for attribute in root_attributes_namespaces:
        dict_data[root_element].pop(attribute)

    # Delete prefixes from all keys ->
    # get all keys recursively
    # def get_all_keys_recursive3(dictionary):
    #    keys = set()
    #
    #    for key, value in dictionary.items():
    #        keys.add(key)
    #        if isinstance(value, dict):
    #            keys.update(get_all_keys_recursive3(value))
    #
    #   return keys

    # all_keys = get_all_keys_recursive3(dict_data)
    # print(all_keys)

    # NO NEED FOR ALL KEYS
    def delete_unwanted_prefixes_from_keys_rec(dictionary, unwanted_prefixes):
        # Create a copy of keys to avoid modification during iteration
        keys = list(dictionary.keys())

        for key in keys:
            new_key = None  # Initialize new_key for potential renaming

            # Check if the current key starts with any unwanted prefix
            for prefix in unwanted_prefixes:
                if key.startswith(prefix):
                    # Remove the prefix and : (that's why + 1) from the key
                    new_key = key[len(prefix) + 1 :]
                    break  # Stop checking prefixes once a match is found

            # If a new key is generated, rename the key in the dictionary
            if new_key is not None:
                dictionary[new_key] = dictionary.pop(key)

            # Check if the value associated with the key is a nested dictionary
            if isinstance(dictionary.get(new_key), dict):
                delete_unwanted_prefixes_from_keys_rec(
                    dictionary[new_key], unwanted_prefixes
                )

    delete_unwanted_prefixes_from_keys_rec(dict_data, prefixes)
    print(dict_data)

    # Attempt to create an instance of the class
    # your_mode = YourMode(**your_dict)
    #
    # your_model = YourMode(**your_dict)
    # your_model = YourMode.parse_obj(your_dict)  parse_obj is deprecated
    # your_model = YourMode.model_validate(your_dict)

    # Need to delete V2G_Message from dict_data, cause it's not a field of V2G_Message
    # TODO: OR implement V2G_MessageBase with V2G_Message field ???
    # and then create instance of V2G_MessageBase
    root_element_no_ns = list(dict_data.keys())[0]
    dict_data = dict_data[root_element_no_ns]
    print(dict_data)

    exit(1)
    model = V2G_Message.model_validate(dict_data)

    print(model)

    return

    def get_all_keys_recursive2(dictionary):
        keys = set()

        for key, value in dictionary.items():
            keys.add(key)
            if isinstance(value, dict):
                keys.update(get_all_keys_recursive2(value))

        return keys

    all_keys = get_all_keys_recursive2(dict_data)
    print(all_keys)

    prefixes = get_ns_prefixes(list(all_keys))
    print(prefixes)

    # List of prefixes which should be delete from whole dictionary for every key
    prefixes2 = []
    # Keys to delete are attributes of root element, which are namespaces
    keys_to_delete = []
    for key, value in dict_data[root_element].items():
        if key.startswith("@xmlns:") or key.startswith("@xsi:"):
            # print(list(key.split(":"))[1])
            print(key.split(":")[1])
            prefixes2.append(list(key.split(":"))[1])
            # add to list keys to delete
            keys_to_delete.append(key)

    print(keys_to_delete, prefixes2)

    start = time.perf_counter()
    # For next processing is easier to work with JSON as string not as dict
    json_data = json.dumps(dict_data)

    # Delete prefixes from all keys
    # print(json_data)
    for prefix in prefixes2:
        json_data = json_data.replace(prefix + ":", "")
    # print(json_data)
    dictionary_asdas = json.loads(json_data)
    end = time.perf_counter()
    print(f"Time to delete prefixes from all keys using JSON: {end - start}")

    # Delete attributes which are namespaces
    for key in keys_to_delete:
        dict_data[root_element].pop(key)

    # for key in all_keys:
    #    if any(key.startswith(prefix) for prefix in prefixes):
    #        print(list(key.split(":"))[1])

    print("ALL keys")
    print(all_keys)
    print("Keys after deleting attributes keys from root element")

    all_keys = all_keys - set(keys_to_delete)
    print(all_keys)

    # Delete prefixes from keys
    def delete_unwanted_keys_rec2(dictionary, unwanted_prefixes):
        keys_to_remove = all_keys  # Create a copy of keys
        new_key = None

        for key in keys_to_remove:
            for prefix in unwanted_prefixes:
                if key.startswith(prefix):
                    new_key = key.split(":")[
                        1
                    ]  # Remove the prefix can be also key[len(prefix) + 1 :]

                    if dictionary.get(key):
                        dictionary[new_key] = dictionary.pop(key)

            if isinstance(dictionary.get(key), dict):
                delete_unwanted_keys_rec2(dictionary[key], unwanted_prefixes)

            if isinstance(dictionary.get(new_key), dict):
                delete_unwanted_keys_rec2(
                    dictionary[new_key], unwanted_prefixes
                )

    start = time.perf_counter()
    delete_unwanted_keys_rec2(dict_data, prefixes2)
    end = time.perf_counter()
    print(f"Time to delete prefixes from all keys using dict: {end - start}")

    print(dict_data)

    return

    prefixes = []
    keys_to_delete = []
    for key, value in dict_data[root_element].items():
        if key.startswith("@xmlns:"):
            print(list(key.split(":"))[1])
            prefixes.append(list(key.split(":"))[1])
            # add to list keys to delete
            keys_to_delete.append(key)

    # delete namespaces as attributes from root element
    for key in keys_to_delete:
        dict_data[root_element].pop(key)

    print(100 * "-")
    print(copy_dict_data)

    prefixes = []
    keys_to_delete = []
    for key, value in copy_dict_data[root_element].items():
        if key.startswith("@xmlns:"):
            print(list(key.split(":"))[1])
            prefixes.append(list(key.split(":"))[1])
            # add to list keys to delete
            keys_to_delete.append(key)

    for key in keys_to_delete:
        copy_dict_data[root_element].pop(key)

    def delete_unwanted_keys_rec(dictionary, unwanted_keys):
        for key, value in dictionary.items():
            if key in unwanted_keys:
                dictionary.pop(key)
                dictionary[key.split(":")[1]] = value
            if isinstance(value, dict):
                delete_unwanted_keys_rec(value, unwanted_keys)

    delete_unwanted_keys_rec(copy_dict_data, prefixes)
    print(copy_dict_data)
    print(100 * "-")

    # DELETE THIS
    # Get all keys from all levels of the dictionary dict_data
    def get_all_keys_recursive(dictionary):
        keys = set()

        for key, value in dictionary.items():
            keys.add(key)
            if isinstance(value, dict):
                keys.update(get_all_keys_recursive(value))

        return keys

    keys = get_all_keys_recursive(dict_data)
    print(keys)

    new_dict = {}
    # TODO: Do it recursively, cause this do it only for 1 level, so only for key V2G_Message
    for key, value in dict_data.items():
        for prefix in prefixes:
            if key.startswith(prefix + ":"):
                new_key = key[len(prefix) + 1 :]
                new_dict[new_key] = value

    print(prefixes)
    print(new_dict)

    # TODO: Think about maybe remove using split and list slicing using : as separator
    # Like this: key.split(":")[1] and update the key with new key
    # TODO: for root element i can delte @ => attributes, but for some elements i can't
    # because they use @ as an attribute like id...

    logger.debug("Printing XML data converted to dictionary after removing")
    logger.debug(dict_data)

    # Think about work with JSON insted of dict
    # Deleting namespaces from keys can be easier with JSON

    return dict_data


def class_instance2xml(obj: object) -> str:
    """Converts class instance of
        V2G_Message or supportedAppProtocolReq/Res to XML.

    Args:
        class_instance (class): Class instance to convert.

    Returns:
        str: XML string.
    """

    # V2G communication consists of two different Message Sets:
    #   - V2G application layer protocol handshake messages (refer to 8.2)
    #   - V2G application layer messages (refer to 8.3)

    # Distinguish between V2GMessage and AppProtocol message

    # The root element of the V2G communication message is V2GMessage
    if isinstance(obj, V2G_Message):
        dict_data = obj.model_dump(by_alias=True, exclude_unset=True)
        # New root element
        root_element_name = "V2G_Message"

        # Create a new dictionary with the root element
        dict_data = {root_element_name: dict_data}

        root_element_name_with_ns = "v2gci_d" + ":" + root_element_name

        # There should be swapping function to swap keys as ns:keys
        # swap keys from V2GMessage to v2gci_d:V2G_Message
        # json_data["v2gci_d:V2G_Message"] = json_data.pop("V2GMessage")
        print(dict_data)

        # Add namespaces to keys
        dict_data = add_namespaces_to_keys(dict_data)
        # TODO: Add namespaces to attributes using xmltodict

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

        print(xml_str)
        return xml_str

    # The root element of the V2G communication message is supportedAppProtocolRes
    if isinstance(obj, supportedAppProtocolRes):
        # Dict to XML as supportedAppProtocolRes
        # Dict to XML as supportedAppProtocolReq
        dict_data = obj.model_dump(by_alias=True, exclude_unset=True)
        # New root element
        root_element_name = "supportedAppProtocolRes"
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

        # Convert dict to XML string
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


# NOT USED
def dict_to_xml(data, parent=None):
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, dict):
                element = ET.Element(key)
                dict_to_xml(value, parent=element)
                if parent is not None:
                    parent.append(element)
            elif isinstance(value, list):
                for item in value:
                    dict_to_xml({key: item}, parent=parent)
            else:
                element = ET.Element(key)
                element.text = str(value)
                if parent is not None:
                    parent.append(element)


def get_ns_prefixes(names: list):
    prefixes = []
    for name in names:
        if name.startswith("@xmlns:"):
            prefixes.append(name.split(":")[1])
    return prefixes
