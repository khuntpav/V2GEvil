from abc import ABC
from pydantic import BaseModel, Field, ConfigDict
from typing import Union, List
from .MsgDataTypes import (
    responseCodeType,
    serviceCategoryType,
    paymentOptionType,
    PaymentOptionListType,
    ServiceListType,
    ChargeServiceType,
    ServiceParameterListType,
    SelectedServiceListType,
    CertificateChainType,
    EVSEProcessingType,
    AC_EVChargeParameterType,
    DC_EVChargeParameterType,
    EVSEChargeParameterType,
    AC_EVSEChargeParameterType,
    DC_EVSEChargeParameterType,
    EnergyTransferModeType,
    SAScheduleListType,
    chargeProgressType,
    ChargingProfileType,
    DC_EVPowerDeliveryParameterType,
    AC_EVSEStatusType,
    DC_EVSEStatusType,
    MeterInfoType,
    chargingSessionType,
    ListOfRootCertificateIDsType,
    ContractSignatureEncryptedPrivateKeyType,
    DiffieHellmanPublickeyType,
    EMAIDType,
    PhysicalValueType,
    DC_EVStatusType,
)

# To inform Pylance (because of pyright implementation) is need
# to explicitly type Field(default=None,) instead of Field(None,)
# if the field is Optional


class BodyBaseType(ABC, BaseModel):
    """Base class for V2G message body.

    Abstract class.
    """

    # To avoid print 'ResponseCode': <responseCodeType.OK: 'OK'>
    # cause i want only 'ResponseCode': 'OK'
    model_config = ConfigDict(use_enum_values=True)

    def __str__(self) -> str:
        return self.__class__.__name__

    # To avoid print 'ResponseCode': <responseCodeType.OK: 'OK'>
    # cause i want only 'ResponseCode': 'OK'
    # Modify of Model Config
    # Behaviour of Pydantic can be controlled via the BaseModel.model_config
    # before V2 was used Config class, now is deprecated and prefered to use
    # model_config class attribute
    # class Config:
    #    """Config class for BodyBaseType."""
    #
    #    use_enum_values = True
    @classmethod
    def response_class_name(cls) -> str:
        """Return the name of the response class.

        Returns:
            str: The name of the response class.
        """
        return cls.__name__.replace("Req", "Res")

    @classmethod
    def request_class_name(cls) -> str:
        """Return the name of the request class.

        Returns:
            str: The name of the request class.
        """
        return cls.__name__.replace("Res", "Req")


"""Here I need to define all types of messages as classes. Inherits from BodyBaseType.

These classes are used in Body class as attributes. Only one attribute can be set at a time.
These classes are used as BodyElement, which is abstract element.
Following classes are in substitution group of BodyElement:
Any of these classes can be substituted for a head BodyElement.
"""


# ISO 15118-2:2014, messages END
# Common Messages AC/DC
class SessionSetupReq(BodyBaseType):
    """Representation of V2GMessage SessionSetupReq."""

    # evccIDType, xs:hexBinary, maxlength 6 bytes
    evcc_id: str = Field(..., alias="EVCCID")


class SessionSetupRes(BodyBaseType):
    """Representation of V2GMessage SessionSetupRes."""

    # responseCodeType, enum values
    response_code: responseCodeType = Field(..., alias="ResponseCode")
    # evseIDType, xs:string, minLength 7, maxLength 37
    evse_id: str = Field(..., alias="EVSEID")
    # EVSETimeStamp, xs:long, minOccurs 0 => not required
    # Timestamp of the current SECC time. Format is “Unix Time Stamp”.
    evse_timestamp: int = Field(default=None, alias="EVSETimeStamp")


class ServiceDiscoveryReq(BodyBaseType):
    """Representation of V2GMessage ServiceDiscoveryReq."""

    # serviceScopeType, xs:string, maxLength 64, minOccurs 0 => not required
    service_scope: str = Field(default=None, alias="ServiceScope")
    # ServiceCategoryType, xs:string, enum values, minOccurs 0 => not required
    service_category: serviceCategoryType = Field(
        default=None, alias="ServiceCategory"
    )


class ServiceDiscoveryRes(BodyBaseType):
    """Representation of V2GMessage ServiceDiscoveryRes."""

    # responseCodeType, enum values, minOccurs 1 => required
    response_code: responseCodeType = Field(..., alias="ResponseCode")
    # PayementOptionListType, minOccurs 1, maxOccurs 1
    payement_option_list: PaymentOptionListType = Field(
        ..., alias="PaymentOptionList"
    )
    # ChargeServiceType, minOccurs 1 => required
    charge_service: ChargeServiceType = Field(..., alias="ChargeService")
    # ServiceListType, minOccurs 0 => not required
    service_list: ServiceListType = Field(default=None, alias="ServiceList")


class ServiceDetailReq(BodyBaseType):
    """Representation of V2GMessage ServiceDetailReq."""

    # serviceIDType, unsignedShort, minOccurs 1 => required
    service_id: int = Field(..., alias="ServiceID")


class ServiceDetailRes(BodyBaseType):
    """Representation of V2GMessage ServiceDetailRes."""

    # responseCodeType, enum values, minOccurs 1 => required
    response_code: responseCodeType = Field(..., alias="ResponseCode")
    # serviceIDType, unsignedShort, minOccurs 1 => required
    service_id: int = Field(..., alias="ServiceID")
    # ServiceParameterListType, minOccurs 0 => not required
    service_parameter_list: ServiceParameterListType = Field(
        default=None, alias="ServiceParameterList"
    )


class PaymentServiceSelectionReq(BodyBaseType):
    """Representation of V2GMessage PaymentServiceSelectionReq."""

    # SelectedPaymentOptionType, minOccurs 1 => required
    selected_payment_option: paymentOptionType = Field(
        ..., alias="SelectedPaymentOption"
    )
    # SelectedServiceListType, minOccurs 0 => not required
    selected_service_list: SelectedServiceListType = Field(
        ..., alias="SelectedServiceList"
    )


class PaymentServiceSelectionRes(BodyBaseType):
    """Representation of V2GMessage PaymentServiceSelectionRes."""

    # responseCodeType, enum values, minOccurs 1 => required
    response_code: responseCodeType = Field(..., alias="ResponseCode")


class PaymentDetailsReq(BodyBaseType):
    """Representation of V2GMessage PaymentDetailsReq."""

    # eMAIDType, xs:string, minLength 14, maxLength 15, minOccurs 1 => required
    e_maid: str = Field(..., alias="eMAID")
    # CertificateChainType, minOccurs 1 => required
    contract_signature_cert_chain: CertificateChainType = Field(
        ..., alias="ContractSignatureCertChain"
    )


class PaymentDetailsRes(BodyBaseType):
    """Representation of V2GMessage PaymentDetailsRes."""

    # responseCodeType, enum values, minOccurs 1 => required
    response_code: responseCodeType = Field(..., alias="ResponseCode")
    # genChallengeType, xs:base64Binary, length 16, minOccurs 1 => required
    # Challenge sent by SECC to EVCC, generated random number
    # [V2G2-825] The GenChallenge field shall be exactly 128 bits long
    gen_challenge: str = Field(..., alias="GenChallenge")
    # xs:long, minOccurs 1 => required
    evse_timestamp: int = Field(..., alias="EVSETimeStamp")


class AuthorizationReq(BodyBaseType):
    """Representation of V2GMessage AuthorizationReq."""

    model_config = ConfigDict(populate_by_name=True)

    # Id, xs:ID, attribute in XSD not element => need to add @
    id: str = Field(..., serialization_alias="@Id", validation_alias="@Id")
    # genChallengeType, xs:base64Binary, length 16, minOccurs 0 => required
    gen_challenge: str = Field(default=None, alias="GenChallenge")


class AuthorizationRes(BodyBaseType):
    """Representation of V2GMessage AuthorizationRes."""

    # responseCodeType, enum values, minOccurs 1 => required
    response_code: responseCodeType = Field(..., alias="ResponseCode")
    # EVSEProcessingType, xs:string, enum values, minOccurs 1 => required
    evse_processing: EVSEProcessingType = Field(..., alias="EVSEProcessing")


class ChargeParameterDiscoveryReq(BodyBaseType):
    """Representation of V2GMessage ChargeParameterDiscoveryReq."""

    # MaxEntriesSAScheduleTuple, unsignedShort, minOccurs 0 => required
    max_entries_sascheduletuple: int = Field(
        None, alias="MaxEntriesSAScheduleTuple"
    )
    # RequestedEnergyTransferMode, minOccurs 1 => required
    requested_energy_transfer_mode: EnergyTransferModeType = Field(
        ..., alias="RequestedEnergyTransferMode"
    )
    # EVChargeParameter is abstract type
    # EVChargeParameterType, minOccurs 1 => required
    # at least one of these two attributes must be set
    ac_ev_charge_parameter: AC_EVChargeParameterType = Field(
        default=None, alias="AC_EVChargeParameter"
    )
    dc_ev_charge_parameter: DC_EVChargeParameterType = Field(
        default=None, alias="DC_EVChargeParameter"
    )


class ChargeParameterDiscoveryRes(BodyBaseType):
    """Representation of V2GMessage ChargeParameterDiscoveryRes.

    At least one of these two attributes
    (AC_EVSEChargeParameter, DC_EVSEChargeParameter) must be set
    """

    # responseCodeType, enum values, minOccurs 1 => required
    response_code: responseCodeType = Field(..., alias="ResponseCode")
    # EVSEProcessingType, xs:string, enum values, minOccurs 1 => required
    evse_processing: EVSEProcessingType = Field(..., alias="EVSEProcessing")
    # SASchedulesType, minOccurs 0 => not required
    sa_schedules: SAScheduleListType = Field(
        default=None, alias="SAScheduleList"
    )
    # EVChargeParameter is abstract type
    # EVChargeParameterType, minOccurs 1 => required
    # at least one of these two attributes must be set
    ac_ev_charge_parameter: AC_EVSEChargeParameterType = Field(
        default=None, alias="AC_EVSEChargeParameter"
    )
    dc_ev_charge_parameter: DC_EVSEChargeParameterType = Field(
        default=None, alias="DC_EVSEChargeParameter"
    )


class PowerDeliveryReq(BodyBaseType):
    """Representation of V2GMessage PowerDeliveryReq."""

    # ChargeProgress, minOccurs 1 => required
    # chargeProgressType, xs:string, enum values
    charge_progress: chargeProgressType = Field(..., alias="ChargeProgress")
    # SAScheduleTupleID, minOccurs 1 => required
    # SAIDType, xs:unsignedByte, minInclusive 1, maxInclusive 255
    sa_schedule_tuple_id: int = Field(..., alias="SAScheduleTupleID")
    # ChargingProfile, minOccurs 0 => not required
    # ChargingProfileType,
    charging_profile: ChargingProfileType = Field(
        default=None, alias="ChargingProfile"
    )
    # EVPowerDeliveryParameter (abstract), minOccurs 0 => not required
    # DC_EVPowerDeliveryParameterType
    dc_ev_power_delivery_parameter: DC_EVPowerDeliveryParameterType = Field(
        default=None, alias="DC_EVPowerDeliveryParameter"
    )


class PowerDeliveryRes(BodyBaseType):
    """Representation of V2GMessage PowerDeliveryRes."""

    # ResponseCode, minOccurs 1 => required
    # responseCodeType, enum values, minOccurs 1 => required
    response_code: responseCodeType = Field(..., alias="ResponseCode")
    # EVSEStatus, minOccurs 1 => required, AC_EVSEStatus or DC_EVSEStatus
    # AC_EVSEStatus
    # AC_EVSEStatusType,
    ac_evse_status: AC_EVSEStatusType = Field(
        default=None, alias="AC_EVSEStatus"
    )
    # DC_EVSEStatusType,
    dc_evse_status: DC_EVSEStatusType = Field(
        default=None, alias="DC_EVSEStatus"
    )


class MeteringReceiptReq(BodyBaseType):
    """Representation of V2GMessage MeteringReceiptReq."""

    model_config = ConfigDict(populate_by_name=True)

    # Id, xs:ID, attribute in XSD not element => need to add @
    id: str = Field(..., serialization_alias="@Id", validation_alias="@Id")
    # SessionID,
    # sessionIDType, xs:hexbinary, maxlength 8
    session_id: str = Field(..., alias="SessionID")
    # SAScheduleTupleID, minOccurs 0 => not required
    # SAIDType, xs:unsignedByte, minInclusive 1, maxInclusive 255
    sa_schedule_tuple_id: int = Field(default=None, alias="SAScheduleTupleID")
    # MeterInfo, minOccurs 1 => required
    # MeterInfoType
    meter_info: MeterInfoType = Field(..., alias="MeterInfo")


class MeteringReceiptRes(BodyBaseType):
    """Representation of V2GMessage MeteringReceiptRes."""

    # ResponseCode, minOccurs 1 => required
    # responseCodeType, enum values, minOccurs 1 => required
    response_code: responseCodeType = Field(..., alias="ResponseCode")
    # EVSEStatus, minOccurs 1 => required, AC_EVSEStatus or DC_EVSEStatus
    # AC_EVSEStatus
    # AC_EVSEStatusType,
    ac_evse_status: AC_EVSEStatusType = Field(
        default=None, alias="AC_EVSEStatus"
    )
    # DC_EVSEStatus
    # DC_EVSEStatusType,
    dc_evse_status: DC_EVSEStatusType = Field(
        default=None, alias="DC_EVSEStatus"
    )


class SessionStopReq(BodyBaseType):
    """Representation of V2GMessage SessionStopReq."""

    # ChargingSession, minOccurs 1 => required
    # chargingSessionType, enum values
    charging_session: chargingSessionType = Field(..., alias="ChargingSession")


class SessionStopRes(BodyBaseType):
    """Representation of V2GMessage SessionStopRes."""

    # ResponseCode, minOccurs 1 => required
    # responseCodeType, enum values, minOccurs 1 => required
    response_code: responseCodeType = Field(..., alias="ResponseCode")

    # To avoid print 'ResponseCode': <responseCodeType.OK: 'OK'>
    # cause i want only 'ResponseCode': 'OK'
    # Added to BodyBaseType class Config: use_enum_values = True
    # class Config:
    #    use_enum_values = True


class CertificateUpdateReq(BodyBaseType):
    """Representation of V2GMessage CertificateUpdateReq."""

    model_config = ConfigDict(populate_by_name=True)

    # Id, xs:ID, attribute in XSD not element => need to add @
    id: str = Field(..., serialization_alias="@Id", validation_alias="@Id")
    # ContractSignatureCertChain, minOccurs 1 => required
    contract_signature_cert_chain: CertificateChainType = Field(
        ..., alias="ContractSignatureCertChain"
    )
    # eMAID, minOccurs 1 => required
    # xs:string, minLength 14, maxLength 15
    e_maid: str = Field(..., alias="eMAID")
    # ListOfRootCertificateIDs
    list_of_root_certificate_ids: ListOfRootCertificateIDsType = Field(
        ..., alias="ListOfRootCertificateIDs"
    )


class CertificateUpdateRes(BodyBaseType):
    """Representation of V2GMessage CertificateUpdateRes."""

    # ResponseCode, minOccurs 1 => required
    # responseCodeType, enum values, minOccurs 1 => required
    response_code: responseCodeType = Field(..., alias="ResponseCode")
    # SAProvisioningCertificateChain, minOccurs 1 => required
    # ContractSignatureCertChain
    contract_signature_cert_chain: CertificateChainType = Field(
        ..., alias="ContractSignatureCertChain"
    )
    # ContractSignatureEncryptedPrivateKey, minOccurs 1 => required
    contract_signature_encrypted_private_key: ContractSignatureEncryptedPrivateKeyType = Field(
        ..., alias="ContractSignatureEncryptedPrivateKey"
    )
    # DHpublicKey, minOccurs 1 => required
    dh_public_key: DiffieHellmanPublickeyType = Field(..., alias="DHpublickey")
    # eMAID, minOccurs 1 => required
    # type EMAIDType which is extension of eMAIDType
    # but in this case is in XSD attribute Id, so need to be implemented
    # as EMAIDType with attribute Id and value of eMAID to simulate it's extension
    e_maid: EMAIDType = Field(..., alias="eMAID")
    # RetryCounter, minOccurs 0 => not required
    # xs:short
    # The following entries are possible:
    # x > 0: after “x” days
    # 0: immediately (at next charging)
    # -1: never
    retry_counter: int = Field(default=None, alias="RetryCounter")


class CertificateInstallationReq(BodyBaseType):
    """Representation of V2GMessage CertificateInstallationReq."""

    model_config = ConfigDict(populate_by_name=True)

    # Id, xs:ID, attribute in XSD not element => need to add @
    id: str = Field(..., serialization_alias="@Id", validation_alias="@Id")
    # OEMProvisioningCert, minOccurs 1 => required
    # certificateType => xs:base64Binary, maxLength 800
    oem_provisioning_cert: str = Field(..., alias="OEMProvisioningCert")
    # ListOfRootCertificateIDs, minOccurs 1 => required
    # ListOfRootCertificateIDsType
    list_of_root_certificate_ids: ListOfRootCertificateIDsType = Field(
        ..., alias="ListOfRootCertificateIDs"
    )


class CertificateInstallationRes(BodyBaseType):
    """Representation of V2GMessage CertificateInstallationRes."""

    # ResponseCode, minOccurs 1 => required
    # responseCodeType, enum values, minOccurs 1 => required
    response_code: responseCodeType = Field(..., alias="ResponseCode")
    # SAProvisioningCertificateChain, minOccurs 1 => required
    # CertificateChainType
    sa_provisioning_certificate_chain: CertificateChainType = Field(
        ..., alias="SAProvisioningCertificateChain"
    )
    # ContractSignatureCertChain, minOccurs 1 => required
    # CertificateChainType
    contract_signature_cert_chain: CertificateChainType = Field(
        ..., alias="ContractSignatureCertChain"
    )
    # ContractSignatureEncryptedPrivateKey, minOccurs 1 => required
    # ContractSignatureEncryptedPrivateKeyType
    contract_signature_encrypted_private_key: ContractSignatureEncryptedPrivateKeyType = Field(
        ..., alias="ContractSignatureEncryptedPrivateKey"
    )
    # DHpublickey, minOccurs 1 => required
    # DiffieHellmanPublickeyType
    dh_public_key: DiffieHellmanPublickeyType = Field(..., alias="DHpublickey")
    # eMAID, minOccurs 1 => required
    # EMAIDType
    e_maid: EMAIDType = Field(..., alias="eMAID")


# AC Messages
class ChargingStatusReq(BodyBaseType):
    """Representation of V2GMessage ChargingStatusReq."""

    # CharingStatusReq is empty


class ChargingStatusRes(BodyBaseType):
    """Representation of V2GMessage ChargingStatusRes."""

    # ResponseCode, minOccurs 1 => required
    # responseCodeType, enum values, minOccurs 1 => required
    response_code: responseCodeType = Field(..., alias="ResponseCode")
    # EVSEID, minOccurs 1 => required
    # evseIDType => xs:string, minLength 7, maxLength 37
    evse_id: str = Field(..., alias="EVSEID")
    # SAScheduleTupleID, minOccurs 1 => required
    # SAIDType => xs:unsignedByte, minInclusive 1, maxInclusive 255
    sa_schedule_tuple_id: int = Field(..., alias="SAScheduleTupleID")
    # EVSEMaxCurrent, minOccurs 0 => not required
    # PhysicalValueType
    evse_max_current: PhysicalValueType = Field(
        default=None, alias="EVSEMaxCurrent"
    )
    # MeterInfo, minOccurs 0 => not required
    # MeterInfoType
    meter_info: MeterInfoType = Field(..., alias="MeterInfo")
    # ReceiptRequired, minOccurs 0 => not required
    # xs:boolean
    receipt_required: bool = Field(default=None, alias="ReceiptRequired")
    # AC_EVSEStatus, minOccurs 1 => required
    # AC_EVSEStatusType
    ac_evse_status: AC_EVSEStatusType = Field(..., alias="AC_EVSEStatus")


# DC Messages
class CableCheckReq(BodyBaseType):
    """Representation of V2GMessage CableCheckReq."""

    # DC_EVStatus, minOccurs 1 => required
    # DC_EVStatusType
    dc_ev_status: DC_EVStatusType = Field(..., alias="DC_EVStatus")


class CableCheckRes(BodyBaseType):
    """Representation of V2GMessage CableCheckRes."""

    # ResponseCode, minOccurs 1 => required
    # responseCodeType, enum values, minOccurs 1 => required
    response_code: responseCodeType = Field(..., alias="ResponseCode")
    # DC_EVSEStatus, minOccurs 1 => required
    # DC_EVSEStatusType
    dc_evse_status: DC_EVSEStatusType = Field(..., alias="DC_EVSEStatus")
    # EVSEProcessing, minOccurs 1 => required
    # EVSEProcessingType, enum values
    evse_processing: EVSEProcessingType = Field(..., alias="EVSEProcessing")


class PreChargeReq(BodyBaseType):
    """Representation of V2GMessage PreChargeReq."""

    # DC_EVStatus, minOccurs 1 => required
    # DC_EVStatusType
    dc_ev_status: DC_EVStatusType = Field(..., alias="DC_EVStatus")
    # EVTargetVolatage, minOccurs 1 => required
    # PhysicalValueType
    ev_target_voltage: PhysicalValueType = Field(..., alias="EVTargetVoltage")
    # EVTargetCurrent, minOccurs 1 => required
    # PhysicalValueType
    ev_target_current: PhysicalValueType = Field(..., alias="EVTargetCurrent")


class PreChargeRes(BodyBaseType):
    """Representation of V2GMessage PreChargeRes."""

    # ResponseCode, minOccurs 1 => required
    # responseCodeType, enum values, minOccurs 1 => required
    response_code: responseCodeType = Field(..., alias="ResponseCode")
    # DC_EVSEStatus, minOccurs 1 => required
    # DC_EVSEStatusType
    dc_evse_status: DC_EVSEStatusType = Field(..., alias="DC_EVSEStatus")
    # EVSEPresentVolatage, minOccurs 1 => required
    # PhysicalValueType
    evse_present_voltage: PhysicalValueType = Field(
        ..., alias="EVSEPresentVoltage"
    )


class CurrentDemandReq(BodyBaseType):
    """Representation of V2GMessage CurrentDemandReq."""

    # DC_EVStatus, minOccurs 1 => required
    # DC_EVStatusType
    dc_ev_status: DC_EVStatusType = Field(..., alias="DC_EVStatus")
    # EVTargetCurrent, minOccurs 1 => required
    # PhysicalValueType
    ev_target_current: PhysicalValueType = Field(..., alias="EVTargetCurrent")
    # EVMaximumVoltageLimit, minOccurs 0 => not required
    # PhysicalValueType
    ev_maximum_voltage_limit: PhysicalValueType = Field(
        default=None, alias="EVMaximumVoltageLimit"
    )
    # EVMaximumPowerLimit, minOccurs 0 => not required
    # PhysicalValueType
    ev_maximum_power_limit: PhysicalValueType = Field(
        default=None, alias="EVMaximumPowerLimit"
    )
    # BulkChargingComplete, minOccurs 0 => not required
    # xs:boolean
    bulk_charging_complete: bool = Field(
        default=None, alias="BulkChargingComplete"
    )
    # ChargingComplete, minOccurs 1 => required
    # xs:boolean
    charging_complete: bool = Field(..., alias="ChargingComplete")
    # RemainingTimeToFullSoC, minOccurs 0 => not required
    # PhysicalValueType
    remaining_time_to_full_soc: PhysicalValueType = Field(
        default=None, alias="RemainingTimeToFullSoC"
    )
    # RemainingTimeToBulkSoC, minOccurs 0 => not required
    # PhysicalValueType
    remaining_time_to_bulk_soc: PhysicalValueType = Field(
        default=None, alias="RemainingTimeToBulkSoC"
    )
    # EVTargetVoltage, minOccurs 1 => required
    # PhysicalValueType
    ev_target_voltage: PhysicalValueType = Field(..., alias="EVTargetVoltage")


class CurrentDemandRes(BodyBaseType):
    """Representation of V2GMessage CurrentDemandRes."""

    # ResponseCode, minOccurs 1 => required
    # responseCodeType, enum values, minOccurs 1 => required
    response_code: responseCodeType = Field(..., alias="ResponseCode")
    # DC_EVSEStatus, minOccurs 1 => required
    # DC_EVSEStatusType
    dc_evse_status: DC_EVSEStatusType = Field(..., alias="DC_EVSEStatus")
    # EVSEPresentVoltage, minOccurs 1 => required
    # PhysicalValueType
    evse_present_voltage: PhysicalValueType = Field(
        ..., alias="EVSEPresentVoltage"
    )
    # EVSEPresetCurrent, minOccurs 1 => required
    # PhysicalValueType
    evse_present_current: PhysicalValueType = Field(
        ..., alias="EVSEPresentCurrent"
    )
    # EVSECurrentLimitAchieved, minOccurs 1 => required
    # xs:boolean
    evse_current_limit_achieved: bool = Field(
        ..., alias="EVSECurrentLimitAchieved"
    )
    # EVSEVoltageLimitAchieved, minOccurs 1 => required
    # xs:boolean
    evse_voltage_limit_achieved: bool = Field(
        ..., alias="EVSEVoltageLimitAchieved"
    )
    # EVSEPowerLimitAchieved, minOccurs 1 => required
    # xs:boolean
    evse_power_limit_achieved: bool = Field(
        ..., alias="EVSEPowerLimitAchieved"
    )
    # EVSEMaximumVoltageLimit, minOccurs 0 => not required
    # PhysicalValueType
    evse_maximum_voltage_limit: PhysicalValueType = Field(
        default=None, alias="EVSEMaximumVoltageLimit"
    )
    # EVSEMaximumCurrentLimit, minOccurs 0 => not required
    # PhysicalValueType
    evse_maximum_current_limit: PhysicalValueType = Field(
        default=None, alias="EVSEMaximumCurrentLimit"
    )
    # EVSEMaximumPowerLimit, minOccurs 0 => not required
    # PhysicalValueType
    evse_maximum_power_limit: PhysicalValueType = Field(
        default=None, alias="EVSEMaximumPowerLimit"
    )
    # EVSEID, minOccurs 1 => required
    # evseIDType => xs:string, minLength 7, maxLength 37
    evse_id: str = Field(..., alias="EVSEID")
    # SAScheduleTupleID, minOccurs 1 => required
    # SAIDType => xs:unsignedByte, minInclusive 1, maxInclusive 255
    sa_schedule_tuple_id: int = Field(..., alias="SAScheduleTupleID")
    # MeterInfo, minOccurs 0 => not required
    # MeterInfoType
    meter_info: MeterInfoType = Field(default=None, alias="MeterInfo")
    # ReceiptRequired, minOccurs 0 => not required
    # xs:boolean
    receipt_required: bool = Field(default=None, alias="ReceiptRequired")


class WeldingDetectionReq(BodyBaseType):
    """Representation of V2GMessage WeldingDetectionReq."""

    # DC_EVStatus, minOccurs 1 => required
    # DC_EVStatusType
    dc_ev_status: DC_EVStatusType = Field(..., alias="DC_EVStatus")


class WeldingDetectionRes(BodyBaseType):
    """Representation of V2GMessage WeldingDetectionRes."""

    # ResponseCode, minOccurs 1 => required
    # responseCodeType, enum values, minOccurs 1 => required
    response_code: responseCodeType = Field(..., alias="ResponseCode")
    # DC_EVSEStatus, minOccurs 1 => required
    # DC_EVSEStatusType
    dc_evse_status: DC_EVSEStatusType = Field(..., alias="DC_EVSEStatus")
    # EVSEPresentVoltage, minOccurs 1 => required
    # PhysicalValueType
    evse_present_voltage: PhysicalValueType = Field(
        ..., alias="EVSEPresentVoltage"
    )


# ISO 15118-2:2014, messages END


# Need to be every type of message as an attribute in Body class
# because is in the XSD schema as Body subelement
# and I need for every type of message a class and alias for later parsing to XML
class Body(BaseModel):
    """Base class for V2G message body.

    This class contains BodyElement in the XSD schema as attributes.
    BodyElement is abstract type in the XSD schema, so it can be any type of message.
    This abstract type is represented by BodyBaseType class in this module.
    The attribute will be only one, because it indicates the type of message.

    Attributes:
        body: The body of the V2G message.
    """

    # body: Union[SessionSetupReq, SessionSetupRes, SessionStopReq, SessionStopRes] = Field(None)

    # Common Messages (AC/DC) - START
    # SessionSetup
    session_setup_req: SessionSetupReq = Field(
        default=None, alias="SessionSetupReq"
    )
    session_setup_res: SessionSetupRes = Field(
        default=None, alias="SessionSetupRes"
    )

    # ServiceDiscovery
    service_discovery_req: ServiceDiscoveryReq = Field(
        default=None, alias="ServiceDiscoveryReq"
    )
    service_discovery_res: ServiceDiscoveryRes = Field(
        default=None, alias="ServiceDiscoveryRes"
    )

    # ServiceDetail
    service_detail_req: ServiceDetailReq = Field(
        default=None, alias="ServiceDetailReq"
    )
    service_detail_res: ServiceDetailRes = Field(
        default=None, alias="ServiceDetailRes"
    )

    # PaymentServiceSelection
    payment_service_sel_req: PaymentServiceSelectionReq = Field(
        default=None, alias="PaymentServiceSelectionReq"
    )
    payment_service_sel_res: PaymentServiceSelectionRes = Field(
        default=None, alias="PaymentServiceSelectionRes"
    )

    # PaymentDetails
    payment_details_req: PaymentDetailsReq = Field(
        default=None, alias="PaymentDetailsReq"
    )
    payment_details_res: PaymentDetailsRes = Field(
        default=None, alias="PaymentDetailsRes"
    )

    # Authorization
    authorization_req: AuthorizationReq = Field(
        default=None, alias="AuthorizationReq"
    )
    authorization_res: AuthorizationRes = Field(
        default=None, alias="AuthorizationRes"
    )

    # ChargeParameterDiscovery
    charge_param_discovery_req: ChargeParameterDiscoveryReq = Field(
        default=None, alias="ChargeParameterDiscoveryReq"
    )
    charge_param_discovery_res: ChargeParameterDiscoveryRes = Field(
        default=None, alias="ChargeParameterDiscoveryRes"
    )

    # PowerDelivery
    power_delivery_req: PowerDeliveryReq = Field(
        default=None, alias="PowerDeliveryReq"
    )
    power_delivery_res: PowerDeliveryRes = Field(
        default=None, alias="PowerDeliveryRes"
    )

    # MeteringReceipt
    metering_receipt_req: MeteringReceiptReq = Field(
        default=None, alias="MeteringReceiptReq"
    )
    metering_receipt_res: MeteringReceiptRes = Field(
        default=None, alias="MeteringReceiptRes"
    )

    # SessionStop
    session_stop_req: SessionStopReq = Field(
        default=None, alias="SessionStopReq"
    )
    session_stop_res: SessionStopRes = Field(
        default=None, alias="SessionStopRes"
    )

    # CertificateUpdate
    certificate_update_req: CertificateUpdateReq = Field(
        default=None, alias="CertificateUpdateReq"
    )
    certificate_update_res: CertificateUpdateRes = Field(
        default=None, alias="CertificateUpdateRes"
    )

    # CertificateInstallation
    certificate_installation_req: CertificateInstallationReq = Field(
        default=None, alias="CertificateInstallationReq"
    )
    certificate_installation_res: CertificateInstallationRes = Field(
        default=None, alias="CertificateInstallationRes"
    )
    # Common Messages (AC/DC) - END

    # AC Messages - START
    # ChargingStatus
    charging_status_req: ChargingStatusReq = Field(
        default=None, alias="ChargingStatusReq"
    )
    charging_status_res: ChargingStatusRes = Field(
        default=None, alias="ChargingStatusRes"
    )
    # AC Messages - END

    # DC Messages - START
    # CableCheck
    cable_check_req: CableCheckReq = Field(default=None, alias="CableCheckReq")
    cable_check_res: CableCheckRes = Field(default=None, alias="CableCheckRes")

    # PreCharge
    pre_charge_req: PreChargeReq = Field(default=None, alias="PreChargeReq")
    pre_charge_res: PreChargeRes = Field(default=None, alias="PreChargeRes")

    # CurrentDemand
    current_demand_req: CurrentDemandReq = Field(
        default=None, alias="CurrentDemandReq"
    )
    current_demand_res: CurrentDemandRes = Field(
        default=None, alias="CurrentDemandRes"
    )

    # WeldingDetection
    welding_detection_req: WeldingDetectionReq = Field(
        default=None, alias="WeldingDetectionReq"
    )
    welding_detection_res: WeldingDetectionRes = Field(
        default=None, alias="WeldingDetectionRes"
    )
    # DC Messages - END
