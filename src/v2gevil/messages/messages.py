"""This module contains functions for converting between XML and class instances."""

import logging
import xml.etree.ElementTree as ET
import requests
import json
import xmltodict
import time
from typing import Union


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


# TODO: Move it to the testing file in tests
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

    obj = xml2class_instance(xml1)
    print(obj.__class__.__name__)
    # print(type(dict_data1))

    # v2g_message ->  as xml
    xml2 = """<?xml version="1.0" encoding="utf-8"?><v2gci_d:V2G_Message xmlns:v2gci_b="urn:iso:15118:2:2013:MsgBody" xmlns:xmlsig="http://www.w3.org/2000/09/xmldsig#" xmlns:v2gci_d="urn:iso:15118:2:2013:MsgDef" xmlns:v2gci_t="urn:iso:15118:2:2013:MsgDataTypes" xmlns:v2gci_h="urn:iso:15118:2:2013:MsgHeader" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><v2gci_d:Header><v2gci_h:SessionID>12345678</v2gci_h:SessionID></v2gci_d:Header><v2gci_d:Body><v2gci_b:SessionStopRes><v2gci_b:ResponseCode>OK</v2gci_b:ResponseCode></v2gci_b:SessionStopRes></v2gci_d:Body></v2gci_d:V2G_Message>"""

    print(xml2exi(xml2))
    print(bytes.fromhex(xml2exi(xml2)))

    obj = xml2class_instance(xml2)
    dict_dataa = obj.model_dump(by_alias=True, exclude_unset=True)
    body_dump = obj.body.model_dump(by_alias=True, exclude_unset=True)
    print(dict_dataa)
    print("Field")
    field = list(obj.body.model_fields_set)[0]
    print(field)
    attribute = getattr(obj.body, field)
    # Later to create a dictionary for all classes of Req and Res
    print(attribute.model_dump(by_alias=True, exclude_unset=False))
    print(type(attribute))
    print("Printing attribute")
    print(attribute)
    print("Class name of attribute")
    print(attribute.__class__.__name__)
    print(type(attribute.__class__.__name__))

    a = Body(**body_dump)
    print("Printing a")
    print(a.model_dump(by_alias=True, exclude_unset=True))

    body_type_res = str(attribute)

    # Dictionary for mapping request to response
    session_id = "0101202"
    header_res = Header(SessionID=session_id)
    responses = {"SessionStopReq": {"SessionStopRes": {"ResponseCode": "OK"}}}
    body_res = Body(**responses["SessionStopReq"])
    msg = V2G_Message(Header=header_res, Body=body_res)
    print("Printing body_res")
    print(body_res.model_dump(by_alias=True, exclude_unset=True))
    print("Printing msg")
    print(msg.model_dump(by_alias=True, exclude_unset=True))
    print("Exiting body res")

    # TO get dictionary => put them in the file for all classes of Req and Res
    # then can be just filled will values
    trala = attribute.model_dump(by_alias=True, exclude_unset=False)
    print(trala)

    dict_dataa = obj.model_dump(by_alias=True, exclude_unset=True)
    print(dict_dataa)
    exit()
    hello = V2G_Message(**dict_dataa)
    # print(type(dict_data2))

    xml3 = """<?xml version="1.0" encoding="utf-8"?><v2gci_d:V2G_Message xmlns:v2gci_b="urn:iso:15118:2:2013:MsgBody" xmlns:xmlsig="http://www.w3.org/2000/09/xmldsig#" xmlns:v2gci_d="urn:iso:15118:2:2013:MsgDef" xmlns:v2gci_t="urn:iso:15118:2:2013:MsgDataTypes" xmlns:v2gci_h="urn:iso:15118:2:2013:MsgHeader" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><v2gci_d:Header><v2gci_h:SessionID>678</v2gci_h:SessionID></v2gci_d:Header><v2gci_d:Body><v2gci_b:ServiceDiscoveryRes><v2gci_b:ResponseCode>OK</v2gci_b:ResponseCode><v2gci_b:PaymentOptionList><v2gci_t:PaymentOption>Contract</v2gci_t:PaymentOption><v2gci_t:PaymentOption>ExternalPayment</v2gci_t:PaymentOption></v2gci_b:PaymentOptionList><v2gci_b:ChargeService><v2gci_t:ServiceID>2</v2gci_t:ServiceID><v2gci_t:ServiceName>AC charging</v2gci_t:ServiceName><v2gci_t:ServiceCategory>EVCharging</v2gci_t:ServiceCategory><v2gci_t:ServiceScope>Service Scope value</v2gci_t:ServiceScope><v2gci_t:FreeService>true</v2gci_t:FreeService><v2gci_t:SupportedEnergyTransferMode><v2gci_t:EnergyTransferMode>AC_single_phase_core</v2gci_t:EnergyTransferMode><v2gci_t:EnergyTransferMode>AC_three_phase_core</v2gci_t:EnergyTransferMode></v2gci_t:SupportedEnergyTransferMode></v2gci_b:ChargeService><v2gci_b:ServiceList><v2gci_t:Service><v2gci_t:ServiceID>2</v2gci_t:ServiceID><v2gci_t:ServiceName>AC charging</v2gci_t:ServiceName><v2gci_t:ServiceCategory>EVCharging</v2gci_t:ServiceCategory><v2gci_t:ServiceScope>Service Scope value</v2gci_t:ServiceScope><v2gci_t:FreeService>true</v2gci_t:FreeService></v2gci_t:Service></v2gci_b:ServiceList></v2gci_b:ServiceDiscoveryRes></v2gci_d:Body></v2gci_d:V2G_Message>"""
    obj = xml2class_instance(xml3)
    print(obj.__class__.__name__)

    xml4 = """<?xml version="1.0" encoding="utf-8"?><v2gci_d:V2G_Message xmlns:v2gci_b="urn:iso:15118:2:2013:MsgBody" xmlns:xmlsig="http://www.w3.org/2000/09/xmldsig#" xmlns:v2gci_d="urn:iso:15118:2:2013:MsgDef" xmlns:v2gci_t="urn:iso:15118:2:2013:MsgDataTypes" xmlns:v2gci_h="urn:iso:15118:2:2013:MsgHeader" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><v2gci_d:Header><v2gci_h:SessionID>678</v2gci_h:SessionID></v2gci_d:Header><v2gci_d:Body><v2gci_b:ServiceDiscoveryRes><v2gci_b:ResponseCode>OK</v2gci_b:ResponseCode><v2gci_b:PaymentOptionList><v2gci_t:PaymentOption>Contract</v2gci_t:PaymentOption><v2gci_t:PaymentOption>ExternalPayment</v2gci_t:PaymentOption></v2gci_b:PaymentOptionList><v2gci_b:ChargeService><v2gci_t:ServiceID>2</v2gci_t:ServiceID><v2gci_t:ServiceName>AC charging</v2gci_t:ServiceName><v2gci_t:ServiceCategory>EVCharging</v2gci_t:ServiceCategory><v2gci_t:ServiceScope>Service Scope value</v2gci_t:ServiceScope><v2gci_t:FreeService>true</v2gci_t:FreeService><v2gci_t:SupportedEnergyTransferMode><v2gci_t:EnergyTransferMode>AC_single_phase_core</v2gci_t:EnergyTransferMode><v2gci_t:EnergyTransferMode>AC_three_phase_core</v2gci_t:EnergyTransferMode></v2gci_t:SupportedEnergyTransferMode></v2gci_b:ChargeService><v2gci_b:ServiceList><v2gci_t:Service><v2gci_t:ServiceID>2</v2gci_t:ServiceID><v2gci_t:ServiceName>AC charging</v2gci_t:ServiceName><v2gci_t:ServiceCategory>EVCharging</v2gci_t:ServiceCategory><v2gci_t:ServiceScope>Service Scope value</v2gci_t:ServiceScope><v2gci_t:FreeService>true</v2gci_t:FreeService></v2gci_t:Service><v2gci_t:Service><v2gci_t:ServiceID>3</v2gci_t:ServiceID><v2gci_t:ServiceName>DC charging</v2gci_t:ServiceName><v2gci_t:ServiceCategory>EVCharging</v2gci_t:ServiceCategory><v2gci_t:ServiceScope>Service Scope value</v2gci_t:ServiceScope><v2gci_t:FreeService>true</v2gci_t:FreeService></v2gci_t:Service></v2gci_b:ServiceList></v2gci_b:ServiceDiscoveryRes></v2gci_d:Body></v2gci_d:V2G_Message>"""
    obj = xml2class_instance(xml4)
    print(obj.__class__.__name__)


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
            "SelectedService",
            "Parameter",
            "PaymentOption",
            "Service",
            "EnergyTransferMode",
            "ParameterSet",
            "Certificate",
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

    # Check if it's V2G_Message or supportedAppProtocolReq/Res
    # Then creates a corresponding instance of the class
    # whose name is the root element of the dictionary
    if root_element == "V2G_Message":
        # V2G_Message
        # Convert dict to class instance
        # V2G_Message.model_validate(dict_data) almost same, boht create class instance
        obj = V2G_Message(**dict_data)
        print(obj)
        print(type(obj))
        print(100 * "-")
        return obj

    if root_element == "supportedAppProtocolReq":
        # supportedAppProtocolReq
        # Convert dict to class instance
        obj = supportedAppProtocolReq(**dict_data)
        print(obj)
        print(type(obj))
        print(100 * "-")
        return obj

    if root_element == "supportedAppProtocolRes":
        # supportedAppProtocolRes
        # Convert dict to class instance
        obj = supportedAppProtocolRes(**dict_data)
        print(obj)
        print(type(obj))
        print(100 * "-")
        return obj

    # Should never happen
    raise ValueError("Unknown root element")


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

        # Add namespaces to keys
        dict_data = add_namespaces_to_keys(dict_data)
        # TODO: Add namespaces to attributes using xmltodict - probably not possible
        # TODO: Do that with lxml lib, cause i need some customization
        # But for lxml lib the imput needs to be string, not dict
        # not only adding namespaces to keys, but also based on its parent

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


# TODO: Work on this later, for now my add prefix function is working
if False:
    from lxml import etree

    # Parse the XML data
    root = etree.fromstring(xml_data)
    root = ET.fromstring(xml_data)

    def add_prefixes_to_elements(element, current_namespace=None):
        # Get the element's tag (name)
        tag = element.tag

        # Determine the namespace prefix for the element's tag
        for namespace, elements in namespace_map.items():
            if tag in elements:
                current_namespace = namespace
                break

        # Add the namespace prefix to the element's tag
        if current_namespace is not None:
            element.tag = f"{current_namespace}:{tag}"

        # Recursively process child elements
        for child in element:
            add_prefixes_to_elements(child, current_namespace)

    # Start adding prefixes from the root element
    add_prefixes_to_elements(root)
