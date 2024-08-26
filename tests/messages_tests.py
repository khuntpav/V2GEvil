"""Module for testing the messages.py module"""

import logging

from src.v2gevil.messages.messages import (
    class_instance2xml,
    xml2class_instance,
    xml2exi,
)

from src.v2gevil.messages.MsgDef import V2G_Message, Header, Body
from src.v2gevil.messages.MsgBody import SessionStopRes, ServiceDiscoveryRes
from src.v2gevil.messages.MsgDataTypes import (
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
from src.v2gevil.messages.AppProtocol import (
    supportedAppProtocolReq,
    supportedAppProtocolRes,
    AppProtocolType,
    responseCodeType as app_responseCodeType,
)

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
