"""This module contains the message generator for the V2G communication.

The message generator is responsible for generating the dictionary,
in which is name of the request message and the corresponding response message
as key-value pair.
The value is a dictionary, which contains the name and value for each field
of the response message.
"""

import time  # for timestamp
import logging
from pathlib import Path
from typing import Union, Optional
import json

# V2G messages schemas
from .AppProtocol import (
    supportedAppProtocolReq,
    supportedAppProtocolRes,
    responseCodeType as appProtocolResponseCodeType,
)
from .MsgBody import (
    BodyBaseType,
    SessionSetupReq,
    SessionSetupRes,
    ServiceDiscoveryReq,
    ServiceDiscoveryRes,
    ServiceDetailReq,
    ServiceDetailRes,
    PaymentServiceSelectionReq,
    PaymentServiceSelectionRes,
    PaymentDetailsReq,
    PaymentDetailsRes,
    AuthorizationReq,
    AuthorizationRes,
    ChargeParameterDiscoveryReq,
    ChargeParameterDiscoveryRes,
    PowerDeliveryReq,
    PowerDeliveryRes,
    MeteringReceiptReq,
    MeteringReceiptRes,
    SessionStopReq,
    SessionStopRes,
    CertificateUpdateReq,
    CertificateUpdateRes,
    CertificateInstallationReq,
    CertificateInstallationRes,
    ChargingStatusReq,
    ChargingStatusRes,
    CableCheckReq,
    CableCheckRes,
    PreChargeReq,
    PreChargeRes,
    CurrentDemandReq,
    CurrentDemandRes,
    WeldingDetectionReq,
    WeldingDetectionRes,
)
from .MsgDataTypes import (
    responseCodeType,
    PaymentOptionListType,
    paymentOptionType,
    ChargeServiceType,
    serviceCategoryType,
    EnergyTransferModeType,
    SupportedEnergyTransferModeType,
    ServiceListType,
    ServiceType,
    ServiceParameterListType,
    ParameterSetType,
    ParameterType,
    EVSEProcessingType,
    AC_EVSEChargeParameterType,
    AC_EVSEStatusType,
    DC_EVSEChargeParameterType,
    DC_EVSEStatusType,
    EVSENotificationType,
    isolationLevelType,
    DC_EVSEStatusCodeType,
    PhysicalValueType,
    unitSymbolType,
    MeterInfoType,
)
from ..station.station_enums import (
    EVSEChargingMode,
    EVSEDetails,
    EVSEDefaultDictPaths,
)


logger = logging.getLogger(__name__)


class EVSEMessageGenerator:
    """
    Message generator class for the station.
    This class is responsible for generating the dictionaries for the
    station.

    Differ between AC or DC charging mode. Default charging mode is AC.
    """

    def __init__(
        self,
        charging_mode: Optional[EVSEChargingMode] = EVSEChargingMode.AC,
        override_flag: bool = False,
    ):
        self.charging_mode = charging_mode
        # generate_default_dict differ between AC or DC charging mode
        self.default_dict = self.generate_default_dict(
            override_flag=override_flag
        )

    def add_model_to_dict(
        self,
        dictionary: dict,
        model_obj: Union[BodyBaseType, supportedAppProtocolRes],
    ) -> dict:
        """
        Add model_dump to dictionary.
        Key is the name of the class of the model object.
        Value is the model_dump of the model object.
        """

        dict_obj = model_obj.model_dump(by_alias=True, exclude_unset=True)
        response_msg_name = model_obj.__class__.__name__
        request_msg_name = model_obj.request_class_name()

        dictionary[request_msg_name] = {response_msg_name: dict_obj}

        logger.debug(dict_obj)
        logger.debug(dictionary)

        return dictionary

    def load_default_dict(self, file_name: EVSEDefaultDictPaths) -> dict:
        """Load default dictionary from file."""

        msg_abs_path = Path(__file__).parent.absolute()
        file_name_path = msg_abs_path.joinpath(file_name.value)
        logger.debug(
            "Trying to load default dictionary from file: %s", file_name_path
        )

        if Path(file_name_path).is_file():
            logger.info(
                "Default dictionary already exists."
                "If you want to override it, set override_flag to True."
            )
            # Load file and return dict loaded from file
            with open(
                file_name_path, "r", encoding="utf-8"
            ) as dictionary_file:
                dictionary = json.load(dictionary_file)
                logger.debug(type(dictionary))
                logger.debug(dictionary)

            return dictionary

        return {}

    def save_default_dict(
        self, file_name: EVSEDefaultDictPaths, dictionary: dict
    ):
        """Save default dictionary to file."""
        # Get absolute path of the file -> to save where the project is
        # located in the right directory
        msg_abs_path = Path(__file__).parent.absolute()
        file_name_path = msg_abs_path.joinpath(file_name.value)
        logger.debug("Saving default dictionary to file: %s", file_name_path)

        with open(file_name_path, "w", encoding="utf-8") as dictionary_file:
            json.dump(dictionary, dictionary_file)

    # Generators for default messages START
    def generate_default_dict_AC(self, override_flag: bool = False) -> dict:
        """Generate default dictionary for AC charging mode.
        
        Generated dictionary is also saved to file\
            if not exists or if override_flag is True.
                    
        Args:
            override_flag (bool, optional): If True, existing file will be overriden.\
                Defaults to False.

        Returns:
            Generated dictionary for AC charging mode.
        """

        default_dict_ac = {}

        if not override_flag:
            default_dict_ac = self.load_default_dict(
                EVSEDefaultDictPaths.AC_MODE_PATH
            )
            # Dict is not empty
            if default_dict_ac:
                return default_dict_ac

        # Override_flag is True or default dictionary is empty

        generator_functions = [
            # Common AC/DC messages START
            self.gen_default_supportedAppProtocolRes,
            self.gen_default_SessionSetupRes,
            self.gen_default_ServiceDiscoveryRes,
            self.gen_default_ServiceDetailRes,
            self.gen_default_PaymentServiceSelectionRes,
            self.gen_default_PaymentDetailsRes,
            self.gen_default_AuthorizationRes,
            self.gen_default_ChargeParameterDiscoveryRes,
            self.gen_default_PowerDeliveryRes,
            self.gen_default_MeteringReceiptRes,
            self.gen_default_SessionStopRes,
            # TODO: Implement following
            self.gen_default_CertificateUpdateRes,
            self.gen_default_CertificateInstallationRes,
            # Common AC/DC messages END
            # AC messages START
            self.gen_default_ChargingStatusRes,
            # AC messages END
        ]

        # Call all generator functions and add the generated response message
        # add the generated response message to the dictionary
        # self.charging_mode is EVSEChargingMode.AC
        # So there is no need to explicitly call methods with charging_mode=AC
        # All method should check if charging_mode in argument is None
        # and if None it will use the self.charging_mode
        for gen_func in generator_functions:
            obj = gen_func()
            default_dict_ac = self.add_model_to_dict(default_dict_ac, obj)

        # Save dictionary to file
        self.save_default_dict(
            EVSEDefaultDictPaths.AC_MODE_PATH, default_dict_ac
        )
        logger.debug(
            "Default dictionary for AC mode is generated: %s", default_dict_ac
        )
        return default_dict_ac

    # TODO: Implement generate_default_dict_DC
    def generate_default_dict_DC(self, override_flag: bool = False) -> dict:
        """Generate default dictionary for DC charging mode.

        Generated dictionory is also saved to file\
            if not exists or if override_flag is True.
        
        Args:
            override_flag (bool, optional): If True, existing file will be overriden.\
                Defaults to False.

        Returns:
            Generated dictionary for DC charging mode.
        """
        default_dict_dc = {}

        if not override_flag:
            default_dict_dc = self.load_default_dict(
                EVSEDefaultDictPaths.DC_MODE_PATH
            )
            # Dict is not empty
            if default_dict_dc:
                return default_dict_dc

        generator_functions = [
            # Common AC/DC messages START
            self.gen_default_supportedAppProtocolRes,
            self.gen_default_SessionSetupRes,
            self.gen_default_ServiceDiscoveryRes,
            self.gen_default_ServiceDetailRes,
            self.gen_default_PaymentServiceSelectionRes,
            self.gen_default_PaymentDetailsRes,
            self.gen_default_AuthorizationRes,
            self.gen_default_ChargeParameterDiscoveryRes,
            self.gen_default_PowerDeliveryRes,
            self.gen_default_MeteringReceiptRes,
            self.gen_default_SessionStopRes,
            # TODO: Implement following
            self.gen_default_CertificateUpdateRes,
            self.gen_default_CertificateInstallationRes,
            # Common AC/DC messages END
            # DC messages START
            self.gen_default_CableCheckRes,
            self.gen_default_PreChargeRes,
            self.gen_default_CurrentDemandRes,
            self.gen_default_WeldingDetectionRes,
            # DC messages END
        ]
        # Call all generator functions and add the generated response message
        # add the generated response message to the dictionary
        for gen_func in generator_functions:
            obj = gen_func()
            default_dict_dc = self.add_model_to_dict(default_dict_dc, obj)

        # Save dictionary to file
        self.save_default_dict(
            EVSEDefaultDictPaths.DC_MODE_PATH, default_dict_dc
        )
        logger.debug(
            "Default dictionary for DC mode is generated: %s", default_dict_dc
        )
        return default_dict_dc

    def generate_default_dict(self, override_flag: bool = False) -> dict:
        """Generate default dictionary for all messages.
        
        Save generated default dictionary into the file\
            if not exists or if override_flag is True

        Args:
            override_flag (bool, optional): If True, existing file will be overriden.\
                Defaults to False.

        Returns:
            Generated dictionary for AC or DC charging mode, based on the\
                charging mode of the class.
        """

        if self.charging_mode == EVSEChargingMode.AC:
            return self.generate_default_dict_AC(override_flag)
        if self.charging_mode == EVSEChargingMode.DC:
            return self.generate_default_dict_DC(override_flag)

        # Charging mode is not supported
        logger.error("Charging mode %s is not supported.", self.charging_mode)
        logger.error("Default dictionary can not be generated.")
        raise ValueError(
            f"Charging mode {self.charging_mode} is not supported."
        )

    def gen_default_supportedAppProtocolRes(self) -> supportedAppProtocolRes:
        """Generate default supportedAppProtocolRes message.

        This method will generate the default response message for the
        supportedAppProtocolReq message.
        This message is generated the same way for both charging modes.

        For this message is charging mode irrelevant, parameters and values\
        does not depend on the charging mode.

        Note: This default message covers all fields of the message.
        """
        obj = supportedAppProtocolRes(
            ResponseCode=appProtocolResponseCodeType.SUCCESS_NEGOTIATION,
            SchemaID=EVSEDetails.SCHEMA_ID,
        )
        return obj

    def gen_default_SessionSetupRes(self) -> SessionSetupRes:
        """Generate default SessionSetupRes message.

        This method will generate the default response message for the
        SessionSetupReq message.
        This message is generated the same way for both charging modes.

        For this message is charging mode irrelevant, parameters and values\
        does not depend on the charging mode.

        Note: This default message covers all fields of the message.
        """

        obj = SessionSetupRes(
            ResponseCode=responseCodeType.OK,
            EVSEID=EVSEDetails.EVSE_ID,
            # get current time in UNIX timestamp, convert to int
            EVSETimeStamp=int(time.time()),
        )
        return obj

    def gen_default_ServiceDiscoveryRes(self) -> ServiceDiscoveryRes:
        """Generate default ServiceDiscoveryRes message.

        This method will generate the default response message for the
        ServiceDiscoveryReq message.

        This message is generated the same way for both charging modes.
        
        Notes: For now this message is generated for AC and DC in the same way.\
            All supported charging services as defined by SupportedEnergyTransferMode.
        """
        # This message:
        # - offers payment options: Contract and External payment
        # - offers AC and DC charging
        # - offers Services:
        #   - Internet Access - ServiceID: 3
        #   - Certificate handling - ServiceID: 2
        # Details about the services 167, 168, 169 in ISO 15118-2
        # Definition of the services (page 168 in ISO 15118-2):
        # ServiceID: 1, Name: AC_DC_Charging
        # ServiceID: 2, Name: Certificate
        # ServiceID: 3, Name: InternetAccess
        # ServiceID: 4, Name: UseCaseInformation
        # ServiceID: 5-60000, Reserved by ISO/IEC
        # ServiceID: 60001-65535, Implementation specific use
        obj = ServiceDiscoveryRes(
            ResponseCode=responseCodeType.OK,
            PaymentOptionList=PaymentOptionListType(
                PaymentOption=[
                    paymentOptionType.CONTRACT,
                    paymentOptionType.EXTERNAL_PAYMENT,
                ]
            ),
            ChargeService=ChargeServiceType(
                ServiceID=1,
                ServiceName="AC_DC_Charging",
                ServiceCategory=serviceCategoryType.EV_CHARGING,
                FreeService=True,
                SupportedEnergyTransferMode=SupportedEnergyTransferModeType(
                    EnergyTransferMode=[
                        EnergyTransferModeType.AC_THREE_PHASE_CORE,
                        EnergyTransferModeType.DC_EXTENDED,
                    ]
                ),
            ),
            ServiceList=ServiceListType(
                Service=[
                    ServiceType(
                        ServiceID=3,
                        ServiceName="Fast Internet",
                        ServiceCategory=serviceCategoryType.INTERNET,
                        FreeService=True,
                    ),
                    ServiceType(
                        ServiceID=2,
                        ServiceName="Certificate",
                        ServiceCategory=serviceCategoryType.CONTRACT_CERTIFICATE,
                        FreeService=True,
                    ),
                ]
            ),
        )
        return obj

    def gen_default_ServiceDetailRes(self) -> ServiceDetailRes:
        """Generate default ServiceDetailRes message.

        This method will generate the default response message for the
        ServiceDetailReq message.
        This message is generated the same way for both charging modes.

        For this message is charging mode irrelevant, parameters and values\
        does not depend on the charging mode.
        """
        # This message:
        #   - assumes that EVCC wants to use see details about the InternetAccess service
        #   - responds for ServiceDetailReq for ServiceID: 3
        # ParameterSetID: 1 indicates ftp via port 20 (usually used as data channel)
        # ParameterSetID: 2 indicates ftp via port 21 (usually used as control channel)
        # ParameterSetID: 3 indicates http via port 80
        # ParameterSetID: 4 indicates https via port 443
        # ParameterSetID: 5-65535 service name according to IANA Service&PortRegistry
        obj = ServiceDetailRes(
            ResponseCode=responseCodeType.OK,
            ServiceID=3,
            ServiceParameterList=ServiceParameterListType(
                ParameterSet=[
                    ParameterSetType(
                        ParameterSetID=3,
                        Parameter=[
                            ParameterType(name="Protocol", stringValue="http"),
                            ParameterType(name="Port", intValue=80),
                        ],
                    ),
                    ParameterSetType(
                        ParameterSetID=4,
                        Parameter=[
                            ParameterType(
                                name="Protocol", stringValue="https"
                            ),
                            ParameterType(name="Port", intValue=443),
                        ],
                    ),
                ]
            ),
        )
        # For ServiceID: 2 indicates Certificate service
        # ParameterSetID: 1 indicates Installation
        # ParameterSetID: 2 indicates Update
        # ParameterSetID: 0, 4-60000 Reserved by ISO/IEC
        # ParameterSetID: 60001 – 65535 Implementation specific use
        # TODO: Maybe implement also fro Certificate service
        return obj

    def gen_default_PaymentServiceSelectionRes(
        self,
    ) -> PaymentServiceSelectionRes:
        """Generate default PaymentServiceSelectionRes message.

        This method will generate the default response message for the
        PaymentServiceSelectionReq message.
        This message is generated the same way for both charging modes.

        For this message is charging mode irrelevant, parameters and values\
        does not depend on the charging mode.

        Note: This default message covers all fields of the message.
        """
        obj = PaymentServiceSelectionRes(ResponseCode=responseCodeType.OK)
        return obj

    def gen_default_PaymentDetailsRes(self) -> PaymentDetailsRes:
        """Generate default PaymentDetailsRes message.

        This method will generate the default response message for the
        PaymentDetailsReq message.
        This message is generated the same way for both charging modes.

        For this message is charging mode irrelevant, parameters and values\
        does not depend on the charging mode.
        """
        obj = PaymentDetailsRes(
            ResponseCode=responseCodeType.OK,
            # base64Binary, MTExMTAxMQ==, bin= 1111011, int= 123
            GenChallenge="MTExMTAxMQ==",
            # get current time in UNIX timestamp
            EVSETimeStamp=int(time.time()),
        )
        return obj

    def gen_default_AuthorizationRes(self) -> AuthorizationRes:
        """Generate default AuthorizationRes message.

        This method will generate the default response message for the
        AuthorizationReq message.
        This message is generated the same way for both charging modes.

        For this message is charging mode irrelevant, parameters and values\
        does not depend on the charging mode.

        Note: This default message covers all fields of the message.
        """
        obj = AuthorizationRes(
            ResponseCode=responseCodeType.OK,
            EVSEProcessing=EVSEProcessingType.FINISHED,
        )
        return obj

    def gen_default_ChargeParameterDiscoveryRes(
        self, charging_mode: Optional[EVSEChargingMode] = None
    ) -> ChargeParameterDiscoveryRes:
        """Generate default ChargeParameterDiscoveryRes message.

        This method will generate the default response message for the
        ChargeParameterDiscoveryReq message. Used parameters and values are based on
        charging mode value.
        This message can be generated for AC or DC charging mode.

        Args:
            charging_mode (EVSEChargingMode, optional): Charging mode indicator,\
                depending on the charging mode, parameters and values\
                may differ in the generated message.\
                Defaults to None.\
        """
        # Charging mode is not specified, use the charging mode of the class
        if charging_mode is None:
            charging_mode = self.charging_mode

        # SAScheduleList is not included in this message

        if charging_mode == EVSEChargingMode.AC:
            obj = ChargeParameterDiscoveryRes(
                ResponseCode=responseCodeType.OK,
                EVSEProcessing=EVSEProcessingType.FINISHED,
                AC_EVSEChargeParameter=AC_EVSEChargeParameterType(
                    AC_EVSEStatus=AC_EVSEStatusType(
                        NotificationMaxDelay=10,
                        EVSENotification=EVSENotificationType.NONE,
                        RCD=False,
                    ),
                    EVSENominalVoltage=PhysicalValueType(
                        Multiplier=1, Unit=unitSymbolType.VOLT, Value=230
                    ),
                    EVSEMaxCurrent=PhysicalValueType(
                        Multiplier=1, Unit=unitSymbolType.AMPERE, Value=15
                    ),
                ),
            )
            return obj

        if charging_mode == EVSEChargingMode.DC:
            obj = ChargeParameterDiscoveryRes(
                ResponseCode=responseCodeType.OK,
                EVSEProcessing=EVSEProcessingType.FINISHED,
                DC_EVSEChargeParameter=DC_EVSEChargeParameterType(
                    DC_EVSEStatus=DC_EVSEStatusType(
                        NotificationMaxDelay=10,
                        EVSENotification=EVSENotificationType.NONE,
                        EVSEIsolationStatus=isolationLevelType.VALID,
                        EVSEStatusCode=DC_EVSEStatusCodeType.EVSE_READY,
                    ),
                    EVSEMaximumCurrentLimit=PhysicalValueType(
                        Multiplier=1, Unit=unitSymbolType.AMPERE, Value=15
                    ),
                    EVSEMaximumPowerLimit=PhysicalValueType(
                        Multiplier=1, Unit=unitSymbolType.WATT, Value=230
                    ),
                    EVSEMaximumVoltageLimit=PhysicalValueType(
                        Multiplier=1, Unit=unitSymbolType.VOLT, Value=230
                    ),
                    EVSEMinimumCurrentLimit=PhysicalValueType(
                        Multiplier=1, Unit=unitSymbolType.AMPERE, Value=15
                    ),
                    EVSEMinimumVoltageLimit=PhysicalValueType(
                        Multiplier=1, Unit=unitSymbolType.VOLT, Value=230
                    ),
                    EVSECurrentRegulationTolerance=PhysicalValueType(
                        Multiplier=1, Unit=unitSymbolType.AMPERE, Value=15
                    ),
                    EVSEPeakCurrentRipple=PhysicalValueType(
                        Multiplier=1, Unit=unitSymbolType.AMPERE, Value=15
                    ),
                    EVSEEnergyToBeDelivered=PhysicalValueType(
                        Multiplier=1, Unit=unitSymbolType.WATT_HOUR, Value=15
                    ),
                ),
            )
            return obj

        # Should not happen
        raise ValueError("Charging mode is not supported.")

    def gen_default_PowerDeliveryRes(
        self, charging_mode: Optional[EVSEChargingMode] = None
    ) -> PowerDeliveryRes:
        """Generate default PowerDeliveryRes message.

        This method will generate the default response message for the
        PowerDeliveryReq message. Used parameters and values are based on
        charging mode value.
        This message can be generated for AC or DC charging mode.

        Args:
            charging_mode (EVSEChargingMode, optional): Charging mode indicator,\
                depending on the charging mode, parameters and values\
                may differ in the generated message.\
                Defaults to EVSEChargingMode.AC.\
        """
        # Charging mode is not specified, use the charging mode of the class
        if charging_mode is None:
            charging_mode = self.charging_mode

        if charging_mode == EVSEChargingMode.AC:
            obj = PowerDeliveryRes(
                ResponseCode=responseCodeType.OK,
                AC_EVSEStatus=AC_EVSEStatusType(
                    NotificationMaxDelay=10,
                    EVSENotification=EVSENotificationType.NONE,
                    RCD=False,
                ),
            )
            return obj

        if charging_mode == EVSEChargingMode.DC:
            obj = PowerDeliveryRes(
                ResponseCode=responseCodeType.OK,
                DC_EVSEStatus=DC_EVSEStatusType(
                    NotificationMaxDelay=10,
                    EVSENotification=EVSENotificationType.NONE,
                    EVSEIsolationStatus=isolationLevelType.VALID,
                    EVSEStatusCode=DC_EVSEStatusCodeType.EVSE_READY,
                ),
            )
            return obj

        # Should not happen
        raise ValueError("Charging mode is not supported.")

    def gen_default_MeteringReceiptRes(
        self, charging_mode: Optional[EVSEChargingMode] = None
    ) -> MeteringReceiptRes:
        """Generate default MeteringReceiptRes message.

        This method will generate the default response message for the
        MeteringReceiptReq message. Used parameters and values are based on
        charging mode value.
        This message can be generated for AC or DC charging mode.

        Args:
            charging_mode (EVSEChargingMode, optional): Charging mode indicator,\
                depending on the charging mode, parameters and values\
                may differ in the generated message.\
                Defaults to EVSEChargingMode.AC.\
        """
        # Charging mode is not specified, use the charging mode of the class
        if charging_mode is None:
            charging_mode = self.charging_mode

        if charging_mode == EVSEChargingMode.AC:
            obj = MeteringReceiptRes(
                ResponseCode=responseCodeType.OK,
                AC_EVSEStatus=AC_EVSEStatusType(
                    NotificationMaxDelay=10,
                    EVSENotification=EVSENotificationType.STOP_CHARGING,
                    RCD=False,
                ),
            )
            return obj

        if charging_mode == EVSEChargingMode.DC:
            obj = MeteringReceiptRes(
                ResponseCode=responseCodeType.OK,
                DC_EVSEStatus=DC_EVSEStatusType(
                    NotificationMaxDelay=10,
                    EVSENotification=EVSENotificationType.STOP_CHARGING,
                    EVSEIsolationStatus=isolationLevelType.VALID,
                    EVSEStatusCode=DC_EVSEStatusCodeType.EVSE_READY,
                ),
            )
            return obj

        # Should not happen
        raise ValueError("Charging mode is not supported.")

    def gen_default_SessionStopRes(self) -> SessionStopRes:
        """Generate default SessionStopRes message.

        This method will generate the default response message for the
        SessionStopReq message.
        This message is generated the same way for both charging modes.

        For this message is charging mode irrelevant, parameters and values\
        does not depend on the charging mode.

        Note: This default message covers all fields of the message.
        """
        obj = SessionStopRes(ResponseCode=responseCodeType.OK)
        return obj

    def gen_default_CertificateUpdateRes(self) -> CertificateUpdateRes:
        """Generate default CertificateUpdateRes message.

        This method will generate the default response message for the
        CertificateUpdateReq message.
        This message is generated the same way for both charging modes.

        For this message is charging mode irrelevant, parameters and values\
        does not depend on the charging mode.
        """

        # If responseCodeType.FAILED_CERT_EXPIRED is used,
        # then EVCC ignore all other fields except RetryCounter
        # IMPORTANT if model_construct is used, use_enum_values is not working
        obj = CertificateUpdateRes.model_construct(
            ResponseCode=responseCodeType.FAILED_CERT_EXPIRED.value,
            RetryCounter=0,
        )
        # TODO: Implement probably in module for testing certificates
        # obj = CertificateUpdateRes(
        #    ResponseCode=responseCodeType.OK,
        #    ContractSignatureCertChain="",
        #    ContractSignatureEncryptedPrivateKey="",
        #    DHpublickey="",
        #    eMAID="",
        #    RetryCounter=0,
        # )
        return obj

    def gen_default_CertificateInstallationRes(
        self,
    ) -> CertificateInstallationRes:
        """Generate default CertificateInstallationRes message.

        This method will generate the default response message for the
        CertificateInstallationReq message.
        This message is generated the same way for both charging modes.

        For this message is charging mode irrelevant, parameters and values\
        does not depend on the charging mode.
        """
        # TODO: Implement probably in module for testing certificates
        # IMPORTANT if model_construct is used, use_enum_values is not working
        obj = CertificateInstallationRes.model_construct(
            ResponseCode=responseCodeType.FAILED_CERT_EXPIRED.value
        )
        # obj = CertificateInstallationRes(ResponseCode=responseCodeType.OK,
        #                                 SAProvisioningCertificateChain="",
        #                                 ContractSignatureCertChain="",
        #                                 ContractSignatureEncryptedPrivateKey="",
        #                                 DHpublickey="",
        #                                 eMAID="",)
        return obj

    # AC messages START
    def gen_default_ChargingStatusRes(self) -> ChargingStatusRes:
        """Generate default ChargingStatusRes message.

        This method will generate the default response message for the
        ChargingStatusReq message.
        This message can be generated only for AC charging mode.

        For this message is charging mode irrelevant, it has to be only AC.
        """
        obj = ChargingStatusRes(
            ResponseCode=responseCodeType.OK,
            EVSEID=EVSEDetails.EVSE_ID,
            SAScheduleTupleID=1,
            MeterInfo=MeterInfoType(MeterID=1),
            ReceiptRequired=False,
            AC_EVSEStatus=AC_EVSEStatusType(
                NotificationMaxDelay=10,
                EVSENotification=EVSENotificationType.NONE,
                RCD=False,
            ),
        )
        return obj

    # AC messages END

    # DC messages START
    def gen_default_CableCheckRes(self) -> CableCheckRes:
        """Generate default CableCheckRes message.

        This method will generate the default response message for the
        CableCheckReq message.
        This message can be generated only for DC charging mode.

        For this message is charging mode irrelevant, it has to be DC.
        """
        obj = CableCheckRes(
            ResponseCode=responseCodeType.OK,
            DC_EVSEStatus=DC_EVSEStatusType(
                NotificationMaxDelay=10,
                EVSENotification=EVSENotificationType.NONE,
                EVSEIsolationStatus=isolationLevelType.VALID,
                EVSEStatusCode=DC_EVSEStatusCodeType.EVSE_READY,
            ),
            EVSEProcessing=EVSEProcessingType.FINISHED,
        )
        return obj

    def gen_default_PreChargeRes(self) -> PreChargeRes:
        """Generate default PreChargeRes message.

        This method will generate the default response message for the
        PreChargeReq message.
        This message can be generated only for DC charging mode.

        For this message is charging mode irrelevant, it has to be DC.
        """
        obj = PreChargeRes(
            ResponseCode=responseCodeType.OK,
            DC_EVSEStatus=DC_EVSEStatusType(
                NotificationMaxDelay=10,
                EVSENotification=EVSENotificationType.NONE,
                EVSEIsolationStatus=isolationLevelType.VALID,
                EVSEStatusCode=DC_EVSEStatusCodeType.EVSE_READY,
            ),
            EVSEPresentVoltage=PhysicalValueType(
                Multiplier=1, Unit=unitSymbolType.VOLT, Value=230
            ),
        )
        return obj

    def gen_default_CurrentDemandRes(self) -> CurrentDemandRes:
        """Generate default CurrentDemandRes message.

        This method will generate the default response message for the
        CurrentDemandReq message.
        This message can be generated only for DC charging mode.

        For this message is charging mode irrelevant, it has to be DC.
        """
        obj = CurrentDemandRes(
            ResponseCode=responseCodeType.OK,
            DC_EVSEStatus=DC_EVSEStatusType(
                NotificationMaxDelay=10,
                EVSENotification=EVSENotificationType.NONE,
                EVSEIsolationStatus=isolationLevelType.VALID,
                EVSEStatusCode=DC_EVSEStatusCodeType.EVSE_READY,
            ),
            EVSEPresentVoltage=PhysicalValueType(
                Multiplier=1, Unit=unitSymbolType.VOLT, Value=300
            ),
            EVSEPresentCurrent=PhysicalValueType(
                Multiplier=1, Unit=unitSymbolType.AMPERE, Value=100
            ),
            EVSECurrentLimitAchieved=False,
            EVSEVoltageLimitAchieved=False,
            EVSEPowerLimitAchieved=False,
            EVSEMaximumVoltageLimit=PhysicalValueType(
                Multiplier=1, Unit=unitSymbolType.VOLT, Value=1000
            ),
            EVSEMaximumCurrentLimit=PhysicalValueType(
                Multiplier=1, Unit=unitSymbolType.AMPERE, Value=400
            ),
            EVSEMaximumPowerLimit=PhysicalValueType(
                Multiplier=1, Unit=unitSymbolType.WATT, Value=200000
            ),
            EVSEID=EVSEDetails.EVSE_ID,
            SAScheduleTupleID=1,
        )
        return obj

    def gen_default_WeldingDetectionRes(self) -> WeldingDetectionRes:
        """Generate default WeldingDetectionRes message.

        This method will generate the default response message for the
        WeldingDetectionReq message.
        This message can be generated only for DC charging mode.

        For this message is charging mode irrelevant, it has to be DC.

        """
        obj = WeldingDetectionRes(
            ResponseCode=responseCodeType.OK,
            DC_EVSEStatus=DC_EVSEStatusType(
                NotificationMaxDelay=10,
                EVSENotification=EVSENotificationType.NONE,
                EVSEIsolationStatus=isolationLevelType.VALID,
                EVSEStatusCode=DC_EVSEStatusCodeType.EVSE_READY,
            ),
            EVSEPresentVoltage=PhysicalValueType(
                Multiplier=1, Unit=unitSymbolType.VOLT, Value=230
            ),
        )
        return obj

    # DC messages END
    # Generators for default messages END

    def generate(self, msg_name: str, params_dict: dict) -> dict:
        """Will generate only dictionary for correspodnig response message.

        Will load the default dict and pop the corresponding request message
        and replace it with the generated response message.

        Based on the msg_name will call the corresponding generate method.

        and based on the message the procedure will be check if user
        specify correct parameters which are from that message
        and generator will generate values for that parameters if they exist.
        """
        # msg_name is not in the default dict, so we can not generate response
        if not msg_name in self.default_dict:
            logger.error(
                "Message %s is not in the default dictionary.", msg_name
            )
            return {}

        # TODO: Based on the prompted message name, call the corresponding generate method

        # Check if all keys in params_dict are in the default dict for the msg_name
        # TODO: think about this...

        return {}

    # Every method should first load the default dict for the specifig response message
    # and then it should change only values for the fields which are
    # specified by the user/module which is used by the user.

    # TODO: Implement following methods, for now just some methods needed for proper
    #  communication -> for ex.: supportedAppProtocolRes
    # Following messages will generated dynamically based on the request message
    # some info will be taken from the default dictionary

    def gen_supportedAppProtocolRes(
        self, req_msg: Union[supportedAppProtocolReq, None] = None
    ) -> dict:
        """Generate supportedAppProtocolRes message.

        This method will generate the response message for the
        supportedAppProtocolReq message.

        Args:
            req_msg (Union[supportedAppProtocolReq, None], optional): [description]. Defaults to None.
            config (dict):
        """

        # res_msg = supportedAppProtocolRes(**config)
        if req_msg is None:
            # Generate response message statically based on the input config dict

            return {}

        # TODO: Generate response message dynamically, based on the request message

        return {}

    def gen_SessionSetupRes(
        self,
        msg: Union[SessionSetupReq, None] = None,
    ) -> dict:
        """Generate SessionSetupRes message.

        This method will generate the response message for the
        SessionSetupReq message.
        """
        return {}

    def gen_ServiceDiscoveryRes(
        self, msg: Union[ServiceDiscoveryReq, None] = None
    ) -> dict:
        """Generate ServiceDiscoveryRes message.

        This method will generate the response message for the
        ServiceDiscoveryReq message.
        """
        return {}

    def gen_ServiceDetailRes(
        self, msg: Union[ServiceDetailReq, None] = None
    ) -> dict:
        """Generate ServiceDetailRes message.

        This method will generate the response message for the
        ServiceDetailReq message.
        """
        return {}

    def gen_PaymentServiceSelectionRes(
        self, msg: Union[PaymentServiceSelectionReq, None] = None
    ) -> dict:
        """Generate PaymentServiceSelectionRes message.

        This method will generate the response message for the
        PaymentServiceSelectionReq message.
        """
        return {}

    def gen_PaymentDetailsRes(
        self, msg: Union[PaymentDetailsReq, None] = None
    ) -> dict:
        """Generate PaymentDetailsRes message.

        This method will generate the response message for the
        PaymentDetailsReq message.
        """
        return {}

    def gen_AuthorizationRes(
        self, msg: Union[AuthorizationReq, None] = None
    ) -> dict:
        """Generate AuthorizationRes message.

        This method will generate the response message for the
        AuthorizationReq message.
        """
        return {}

    def gen_ChargeParameterDiscoveryRes(
        self, msg: Union[ChargeParameterDiscoveryReq, None] = None
    ) -> dict:
        """Generate ChargeParameterDiscoveryRes message.

        This method will generate the response message for the
        ChargeParameterDiscoveryReq message.
        """
        return {}

    def gen_PowerDeliveryRes(
        self, msg: Union[PowerDeliveryReq, None] = None
    ) -> dict:
        """Generate PowerDeliveryRes message.

        This method will generate the response message for the
        PowerDeliveryReq message.
        """
        return {}

    def gen_MeteringReceiptRes(
        self, msg: Union[MeteringReceiptReq, None] = None
    ) -> dict:
        """Generate MeteringReceiptRes message.

        This method will generate the response message for the
        MeteringReceiptReq message.
        """
        return {}

    def gen_SessionStopRes(
        self, msg: Union[SessionStopReq, None] = None
    ) -> dict:
        """Generate SessionStopRes message.

        This method will generate the response message for the
        SessionStopReq message.
        """
        return {}

    def gen_CertificateUpdateRes(
        self, msg: Union[CertificateUpdateReq, None] = None
    ) -> dict:
        """Generate CertificateUpdateRes message.

        This method will generate the response message for the
        CertificateUpdateReq message.
        """
        return {}

    def gen_CertificateInstallationRes(
        self, msg: Union[CertificateInstallationReq, None] = None
    ) -> dict:
        """Generate CertificateInstallationRes message.

        This method will generate the response message for the
        CertificateInstallationReq message.
        """
        return {}

    def gen_ChargingStatusRes(
        self, msg: Union[ChargingStatusReq, None] = None
    ) -> dict:
        """Generate ChargingStatusRes message.

        This method will generate the response message for the
        ChargingStatusReq message.
        """
        return {}

    def gen_CableCheckRes(
        self, msg: Union[CableCheckReq, None] = None
    ) -> dict:
        """Generate CableCheckRes message.

        This method will generate the response message for the
        CableCheckReq message.
        """
        return {}

    def gen_PreChargeRes(self, msg: Union[PreChargeReq, None] = None) -> dict:
        """Generate PreChargeRes message.

        This method will generate the response message for the
        PreChargeReq message.
        """
        return {}

    def gen_CurrentDemandRes(
        self, msg: Union[CurrentDemandReq, None] = None
    ) -> dict:
        """Generate CurrentDemandRes message.

        This method will generate the response message for the
        CurrentDemandReq message.
        """
        return {}

    def gen_WeldingDetectionRes(
        self, msg: Union[WeldingDetectionReq, None] = None
    ) -> dict:
        """Generate WeldingDetectionRes message.

        This method will generate the response message for the
        WeldingDetectionReq message.
        """
        return {}


class EVMessageGenerator:
    """Message generator class for EV(car).

    This class is responsible for generating the dictionaries for the
    car.

    This class is not implemented yet, because the focus of the thesis
    is to test EV, so the message generator for the EV is not needed.
    """

    def __init__(self):
        raise NotImplementedError()
        self.default_dict = None
