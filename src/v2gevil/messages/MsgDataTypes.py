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

"""This module is for defining all types which are used in V2G messages.

Based on the XSD schema: V2G_CI_MsgDataTypes.xsd

simple types: starts with lower case letter
    - I implement as class only simple types which are enums => contains only values
    - Other simple types, where is only restriction and info about the type, I don't implement as separate class
    - Update:
    - There was a need to implement some of the simple types as class, cause they are used by complex types
    - These simple types are implemented as class, but they are abstract, cause they are extended by other types
    - simpleTypes: eMAIDType, dHpublickeyType, privateKeyType
    - complexTypes that use these simpleTypes: EMADType, DiffieHellmanPublickeyType, ContractSignatureEncryptedPrivateKeyType, 
complex types: starts with UPPER case letter

"""
from pydantic import BaseModel, Field, ConfigDict
from typing import List
from enum import Enum
from abc import ABC


class serviceCategoryType(str, Enum):
    """Enumerated values for serviceCategoryType"""

    EV_CHARGING = "EVCharging"
    INTERNET = "Internet"
    CONTRACT_CERTIFICATE = "ContractCertificate"
    OTHER_CUSTOM = "OtherCustom"


# To inform Pylance (because of pyright implementation) is need
# to explicitly type Field(default=None,) instead of Field(None,)
# if the field is Optional


class ServiceType(BaseModel):
    """ComplexType ServiceType."""

    # To avoid print 'ResponseCode': <responseCodeType.OK: 'OK'>
    # cause i want only 'ResponseCode': 'OK' in dump of the model
    model_config = ConfigDict(use_enum_values=True)

    # serviceIDType, unsignedShort
    service_id: int = Field(..., alias="ServiceID")
    # service_name minOccurs = 0, serviceNameType, xs:string, maxLength 32
    service_name: str = Field(default=None, alias="ServiceName")
    # service_category minOccurs = 1, serviceCategoryType is enum
    service_category: serviceCategoryType = Field(..., alias="ServiceCategory")
    # serviceScopeType is xs:string in the schema, maxLength 64
    # service_scope minOccurs = 0, xs:string, maxLegth 64
    service_scope: str = Field(default=None, alias="ServiceScope")
    # xs:boolean
    free_service: bool = Field(..., alias="FreeService")


class SelectedServiceType(BaseModel):
    """ "ComplexType SelectedServiceType."""

    # serviceIDType, xs:unsignedShort
    service_id: int = Field(..., alias="ServiceID")
    # service_name minOccurs = 0, type xs:short
    parameter_set_id: int = Field(default=None, alias="ParameterSetID")


class SelectedServiceListType(BaseModel):
    """ComplexType SelectedServiceListType."""

    # SelectedServiceType, minOccurs = 1 => required, maxOccurs = 16
    selected_service: List[SelectedServiceType] = Field(
        ..., alias="SelectedService"
    )


class unitSymbolType(str, Enum):
    """simpleType unitSymbolType"""

    # Time in hours
    HOURS = "h"
    # Time in minutes
    MINUTES = "m"
    # Time in seconds
    SECONDS = "s"
    # Current in Ampere
    AMPERE = "A"
    # Voltage in Volt
    VOLT = "V"
    # Active power in Watt
    WATT = "W"
    # Real energy in Watt hours
    WATT_HOUR = "Wh"


class PhysicalValueType(BaseModel):
    """ComplexType PhysicalValueType.
    
    Value range and unit definition for message elements using PhysicalValueType\
    Table 68, page 110
    """

    model_config = ConfigDict(use_enum_values=True)

    # multiplier, xs:byte, minInclusive value="-3", maxInclusive value="3"
    multiplier: int = Field(..., alias="Multiplier")
    # unit, type unitSymbolType, xs:string
    unit: unitSymbolType = Field(..., alias="Unit")
    # value, xs:short
    value: int = Field(..., alias="Value")


class ParameterType(BaseModel):
    """ComplexType ParameterType."""

    model_config = ConfigDict(populate_by_name=True)

    # name, xs:string, in XSD is defined as attribute => need to add
    # populating by name in ConfigDict and serialization and validation alias
    # instead of alias, if only alias is used, it's working but pylance is complaining
    name: str = Field(
        ..., serialization_alias="@Name", validation_alias="@Name"
    )
    # From attributes below is used only one, cause in XSD is defined as choice
    # type, xs:boolean
    bool_value: bool = Field(default=None, alias="boolValue")
    # type, xs:byte -> is a signed 8-bit integer data type.
    # It represents whole numbers in the range from -128 to 127.
    byte_value: int = Field(default=None, alias="byteValue")
    # type, xs:short
    short_value: int = Field(default=None, alias="shortValue")
    # type, xs:int
    int_value: int = Field(default=None, alias="intValue")
    # PhysicalValueType,
    physical_value: PhysicalValueType = Field(
        default=None, alias="physicalValue"
    )
    # type, xs:string
    string_value: str = Field(default=None, alias="stringValue")


class ParameterSetType(BaseModel):
    """ComplexType ParameterSetType."""

    # service_name minOccurs = 1, type xs:short
    parameter_set_id: int = Field(..., alias="ParameterSetID")
    # ParameterType minOccurs = 1, maxOccurs = 16
    parameter: List[ParameterType] = Field(..., alias="Parameter")


class faultCodeType(str, Enum):
    """Enumerated values for faultCodeType"""

    PARSING_ERROR = "ParsingError"
    # Probabaly typo in XSD file => Certificat instead of Certificate
    NO_TLS_ROOT_CERT_AVAILABLE = "NoTLSRootCertificatAvailable"
    UNKNOWN_ERROR = "UnknownError"


class NotificationType(BaseModel):
    """ComplexType NotificationType."""

    #
    fault_code: faultCodeType = Field(..., alias="FaultCode")
    # minOccurs = 0 => not required, type xs:string, maxLength 64
    fault_msg: str = Field(default=None, alias="FaultMsg")


class responseCodeType(str, Enum):
    """Enumerated values for responseCodeType, simpleType responseCodeType"""

    OK = "OK"
    OK_NEW_SESSION_ESTABLISHED = "OK_NewSessionEstablished"
    OK_OLD_SESSION_ESTABLISHED = "OK_OldSessionJoined"
    OK_CERT_EXPIRES_SOON = "OK_CertificateExpiresSoon"
    FAILED = "FAILED"
    FAILED_SEQUENCE_ERROR = "FAILED_SequenceError"
    FAILED_SERVICE_ID_INVALIED = "FAILED_ServiceIDInvalid"
    FAILED_UNKNOWN_SESSION = "FAILED_UnknownSession"
    FAILED_SERVICE_SEL_INVALID = "FAILED_ServiceSelectionInvalid"
    FAILED_PAYNMENT_SEL_INVALID = "FAILED_PaymentSelectionInvalid"
    FAILED_CERT_EXPIRED = "FAILED_CertificateExpired"
    FAILED_SIGNATURE_ERROR = "FAILED_SignatureError"
    FAILED_NO_CERT_AVAILABLE = "FAILED_NoCertificateAvailable"
    FAILED_CERT_CHAIN_ERROR = "FAILED_CertChainError"
    FAILED_CHALLENGE_INVALID = "FAILED_ChallengeInvalid"
    FAILED_CONTRACT_CANCELED = "FAILED_ContractCanceled"
    FAILED_WRONG_CHARGE_PARAM = "FAILED_WrongChargeParameter"
    FAILED_POWER_DELIVERY_NOT_APPLIED = "FAILED_PowerDeliveryNotApplied"
    FAILED_TARIFF_SEL_INVALID = "FAILED_TariffSelectionInvalid"
    FAILED_CHARGING_PROFILE_INVALID = "FAILED_ChargingProfileInvalid"
    FAILED_METERING_SIGNATURE_NOT_VALID = "FAILED_MeteringSignatureNotValid"
    FAILED_NO_CHARGE_SERVICE_SEL = "FAILED_NoChargeServiceSelected"
    FAILED_WRONG_ENERGY_TRANSFER_MODE = "FAILED_WrongEnergyTransferMode"
    FAILED_CONTRACTOR_ERROR = "FAILED_ContactorError"
    FAILED_CERT_NOT_ALLOWED_AT_THIS_EVSE = (
        "FAILED_CertificateNotAllowedAtThisEVSE"
    )
    FAILED_CERT_REVOKED = "FAILED_CertificateRevoked"


class paymentOptionType(str, Enum):
    """Enumerated values for paymentOptionListType"""

    CONTRACT = "Contract"
    EXTERNAL_PAYMENT = "ExternalPayment"


class PaymentOptionListType(BaseModel):
    """ComplexType PaymentOptionListType."""

    model_config = ConfigDict(use_enum_values=True)

    # paymentOptionType, minOccurs = 1 => required, maxOccurs = 2 => 1-2 items in list
    payment_option: List[paymentOptionType] = Field(..., alias="PaymentOption")


class ServiceListType(BaseModel):
    """ComplexType ServiceListType."""

    # ServiceType, minOccurs = 1 => required, maxOccurs = 8, 1-8 items in list
    service: List[ServiceType] = Field(..., alias="Service")


class EnergyTransferModeType(str, Enum):
    """Enumerated values for EnergyTransferModeType"""

    AC_SINGLE_PHASE_CORE = "AC_single_phase_core"
    AC_THREE_PHASE_CORE = "AC_three_phase_core"
    DC_CORE = "DC_core"
    DC_EXTENDED = "DC_extended"
    DC_COMBO_CORE = "DC_combo_core"
    DC_UNIQUE = "DC_unique"


class SupportedEnergyTransferModeType(BaseModel):
    """ComplexType SupportedEnergyTransferModeType."""

    model_config = ConfigDict(use_enum_values=True)

    # EnergyTransferModeType, minOccurs = 1, maxOccurs = 6
    energy_transfered_mode: List[EnergyTransferModeType] = Field(
        ..., alias="EnergyTransferMode"
    )


# in XSD is defined as extension of ServiceType
class ChargeServiceType(ServiceType):
    """ComplexType ChargeServiceType."""

    # SupportedEnergyTransferModeType, minOccurs = 1 => required
    supported_energy_transfer_mode: SupportedEnergyTransferModeType = Field(
        ..., alias="SupportedEnergyTransferMode"
    )


class ServiceParameterListType(BaseModel):
    """ComplexType ServiceParameterListType."""

    # ParameterSetType, minOccurs = 1 => required, maxOccurs = 255
    parameter_set: List[ParameterSetType] = Field(..., alias="ParameterSet")


class SubCertificatesType(BaseModel):
    # certificateType is xs:base64Binary, maxLength 800
    # base64 encoded certificate, certificate in bytes
    # maxOccurs = 4 => 1-4 items in list
    certificate: List[str] = Field(..., alias="Certificate")


class CertificateChainType(BaseModel):
    """ComplexType CertificateChainType."""

    model_config = ConfigDict(populate_by_name=True)

    # attribute Id, xs:ID, in XSD is defined as attribute (need @ in json) =>
    # need to add populating by name in ConfigDict and serialization and validation alias
    # instead of alias, if only alias is used, it's working but pylance is complaining
    # not required in XSD
    id: str = Field(
        default=None, serialization_alias="@Id", validation_alias="@Id"
    )
    # certificateType, minOccurs = 1 => required
    # certificateType is xs:base64Binary, maxLength 800
    # base64 encoded certificate, certificate in bytes
    certificate: str = Field(..., alias="Certificate")
    # SubCertificatesType, minOccurs = 0 => not required
    sub_certificates: SubCertificatesType = Field(
        default=None, alias="SubCertificates"
    )


class EVSEProcessingType(str, Enum):
    """Enumerated values for EVSEProcessingType, simpleType EVSEProcessingType"""

    ONGOING = "Ongoing"
    FINISHED = "Finished"
    ONGOING_WAITING_FOR_CUSTOMER_INTERACTION = (
        "OngoingWaitingForCustomerInteraction"
    )


class EVSENotificationType(str, Enum):
    """enumerated values for EVSENotificationType"""

    NONE = "None"
    STOP_CHARGING = "StopCharging"
    RE_NEGOTIATION = "ReNegotiation"


class EVSEStatusType(ABC, BaseModel):
    """complexType EVSEStatusType. Abstract class - abstract in XSD"""

    model_config = ConfigDict(use_enum_values=True)

    # NotificationMaxDelay, minOccurs = 1 => required
    # xs:unsignedShort
    notification_max_delay: int = Field(..., alias="NotificationMaxDelay")
    # EVSENotification, EVSENotificationType, minOccurs = 1 => required
    evse_notification: EVSENotificationType = Field(
        ..., alias="EVSENotification"
    )


class AC_EVSEStatusType(EVSEStatusType):
    """complexType AC_EVSEStatusType"""

    # RCD, Residual Current Device
    # True => RCD detected and error, False => RCD has not detected an error
    # xs:boolean
    rcd: bool = Field(..., alias="RCD")


class isolationLevelType(str, Enum):
    """enumerated values for isolationLevelType"""

    INVALID = "Invalid"
    VALID = "Valid"
    WARNING = "Warning"
    FAULT = "Fault"
    NO_IMD = "No_IMD"


class DC_EVSEStatusCodeType(str, Enum):
    EVSE_NOT_READY = "EVSE_NotReady"
    EVSE_READY = "EVSE_Ready"
    EVSE_SHUTDOWN = "EVSE_Shutdown"
    EVSE_UTILITY_INTERRUPT_EVENT = "EVSE_UtilityInterruptEvent"
    EVSE_ISOLATION_MONITORING_ACTIVE = "EVSE_IsolationMonitoringActive"
    EVSE_EMERGENCY_SHUTDOWN = "EVSE_EmergencyShutdown"
    EVSE_MALFUNCTION = "EVSE_Malfunction"
    RESERVED_8 = "Reserved_8"
    RESERVED_9 = "Reserved_9"
    RESERVED_A = "Reserved_A"
    RESERVED_B = "Reserved_B"
    RESERVED_C = "Reserved_C"


class DC_EVSEStatusType(EVSEStatusType):
    """complexType DC_EVSEStatusType"""

    # EVSEIsolationStatus, minOccurs = 0 => not required
    evse_isolation_status: isolationLevelType = Field(
        default=None, alias="EVSEIsolationStatus"
    )
    # EVSEStatusCode, minOccurs = 1 => required
    evse_status_code: DC_EVSEStatusCodeType = Field(
        ..., alias="EVSEStatusCode"
    )


class EVSEChargeParameterType(ABC, BaseModel):
    """complexType EVSEChargeParameterType. Abstract class - abstract in XSD"""


class AC_EVSEChargeParameterType(EVSEChargeParameterType):
    """complexType AC_EVSEChargeParameterType"""

    ac_evse_status: AC_EVSEStatusType = Field(..., alias="AC_EVSEStatus")
    evse_nominal_voltage: PhysicalValueType = Field(
        ..., alias="EVSENominalVoltage"
    )
    evse_max_current: PhysicalValueType = Field(..., alias="EVSEMaxCurrent")


class DC_EVSEChargeParameterType(EVSEChargeParameterType):
    """complexType DC_EVSEChargeParameterType"""

    dc_evse_status: DC_EVSEStatusType = Field(..., alias="DC_EVSEStatus")
    evse_max_current_limit: PhysicalValueType = Field(
        ..., alias="EVSEMaximumCurrentLimit"
    )
    evse_max_power_limit: PhysicalValueType = Field(
        ..., alias="EVSEMaximumPowerLimit"
    )
    evse_max_voltage_limit: PhysicalValueType = Field(
        ..., alias="EVSEMaximumVoltageLimit"
    )
    evse_min_current_limit: PhysicalValueType = Field(
        ..., alias="EVSEMinimumCurrentLimit"
    )
    evse_min_voltage_limit: PhysicalValueType = Field(
        ..., alias="EVSEMinimumVoltageLimit"
    )
    evse_current_regulation_tolerance: PhysicalValueType = Field(
        default=None, alias="EVSECurrentRegulationTolerance"
    )
    evse_peak_current_ripple: PhysicalValueType = Field(
        ..., alias="EVSEPeakCurrentRipple"
    )
    evse_energy_to_be_delivered: PhysicalValueType = Field(
        default=None, alias="EVSEEnergyToBeDelivered"
    )


class EVChargeParameterType(ABC, BaseModel):
    """complexType EVChargeParameterType. Abstract class - abstract in XSD"""

    # DepartureTime, xs:unsignedInt, minOccurs = 0 => not required
    departure_time: int = Field(default=None, alias="DepartureTime")


class AC_EVChargeParameterType(EVChargeParameterType):
    """complexType AC_EVChargeParameterType"""

    # in XSD: substitutionGroup="EVChargeParameter"

    # EAmount
    e_amount: PhysicalValueType = Field(..., alias="EAmount")
    # EVMaxVoltage
    ev_max_voltage: PhysicalValueType = Field(..., alias="EVMaxVoltage")
    # EVMaxCurrent
    ev_max_current: PhysicalValueType = Field(..., alias="EVMaxCurrent")
    # EVMinCurrent
    ev_min_current: PhysicalValueType = Field(..., alias="EVMinCurrent")


class DC_EVErrorCodeType(str, Enum):
    """enumerated values for DC_EVErrorCodeType"""

    NO_ERROR = "NO_ERROR"
    FAILED_RESS_TEMP_INHIBIT = "FAILED_RESSTemperatureInhibit"
    FAILED_EV_SHIFT_POS = "FAILED_EVShiftPosition"
    FAILED_CHARGER_CONNECTOR_LOCK_FAULT = "FAILED_ChargerConnectorLockFault"
    FAILED_EV_RESS_MALFUNCTION = "FAILED_EVRESSMalfunction"
    FAILED_CHARGING_CURR_DIFF = "FAILED_ChargingCurrentdifferential"
    FAILED_CHARGING_VOLT_OUT_OF_RANGE = "FAILED_ChargingVoltageOutOfRange"
    RESERVED_A = "Reserved_A"
    RESERVED_B = "Reserved_B"
    RESERVED_C = "Reserved_C"
    FAILED_CHARGING_SYSTEM_INCOMPATIBILITY = (
        "FAILED_ChargingSystemIncompatibility"
    )
    NO_DATA = "NoData"


class DC_EVStatusType(BaseModel):
    """complexType DC_EVStatusType"""

    # EVReady type="xs:boolean"
    ev_ready: bool = Field(..., alias="EVReady")
    # EVErrorCode type="DC_EVErrorCodeType"
    ev_error_code: DC_EVErrorCodeType = Field(..., alias="EVErrorCode")
    # EVRESSSOC" type="percentValueType"
    # percentValueType => xs:byte, minInclusive value="0", maxInclusive value="100"
    ev_ress_soc: int = Field(..., alias="EVRESSSOC")


class DC_EVChargeParameterType(EVChargeParameterType):
    """complexType DC_EVChargeParameterType"""

    # in XSD: substitutionGroup="EVChargeParameter"
    # DC_EVStatus type="DC_EVStatusType"
    dc_ev_status: DC_EVStatusType = Field(..., alias="DC_EVStatus")
    # EVMaximumCurrentLimit type="PhysicalValueType"
    ev_maximum_current_limit: PhysicalValueType = Field(
        ..., alias="EVMaximumCurrentLimit"
    )
    # EVMaximumPowerLimit type="PhysicalValueType" minOccurs="0"
    ev_maximum_power_limit: PhysicalValueType = Field(
        None, alias="EVMaximumPowerLimit"
    )
    # EVMaximumVoltageLimit type="PhysicalValueType"
    ev_maximum_voltage_limit: PhysicalValueType = Field(
        ..., alias="EVMaximumVoltageLimit"
    )
    # EVEnergyCapacity type="PhysicalValueType" minOccurs="0"
    ev_energy_capacity: PhysicalValueType = Field(
        None, alias="EVEnergyCapacity"
    )
    # EVEnergyRequest type="PhysicalValueType" minOccurs="0"
    ev_energy_request: PhysicalValueType = Field(
        default=None, alias="EVEnergyRequest"
    )
    # FullSOC type="percentValueType" minOccurs="0"
    # percentValueType => xs:byte, minInclusive value="0", maxInclusive value="100"
    full_soc: int = Field(default=None, alias="FullSOC")
    # BulkSOC type="percentValueType" minOccurs="0"
    # percentValueType => xs:byte, minInclusive value="0", maxInclusive value="100"
    bulk_soc: int = Field(default=None, alias="BulkSOC")


class IntervalType(ABC, BaseModel):
    """complexType IntervalType. Abstract class - abstract in XSD"""


class RelativeTimeIntervalType(IntervalType):
    """complexType RelativeTimeIntervalType"""

    # start, xs:unsignedInt, minInclusive value="0", maxInclusive value="16777214"
    start: int = Field(..., alias="start")
    # duration, xs:unsignedInt, minInclusive value="0", maxInclusive value="86400"
    # minOccurs = 0 => not required
    duration: str = Field(default=None, alias="duration")


class EntryType(ABC, BaseModel):
    """complexType EntryType. Abstract class - abstract in XSD"""

    time_interval: IntervalType = Field(..., alias="TimeInterval")


class PMaxScheduleEntryType(BaseModel):
    # TimeInterval
    time_interval: RelativeTimeIntervalType = Field(
        ..., alias="RelativeTimeInterval"
    )
    # PMax type="PhysicalValueType"
    p_max: PhysicalValueType = Field(..., alias="PMax")


class PMaxScheduleType(BaseModel):
    """complexType PMaxScheduleType"""

    # PMaxScheduleEntryType, minOccurs = 1 => required, maxOccurs = 1024
    p_max_schedule_entry: List[PMaxScheduleEntryType] = Field(
        ..., alias="PMaxScheduleEntry"
    )


class costKindType(str, Enum):
    RELATIVE_PRICE_PERCENTAGE = "relativePricePercentage"
    RENEWABLE_GENERATION_PERCENTAGE = "RenewableGenerationPercentage"
    CARBON_DIOXIDE_EMISSIONS = "CarbonDioxideEmissions"


class CostType(BaseModel):
    # costKind, xs:unsignedByte, minInclusive value="0", maxInclusive value="255"
    cost_kind: costKindType = Field(..., alias="costKind")
    # xs:unsignedInt, minOccurs = 1 => required
    amount: int = Field(..., alias="amount")
    # unitMultiplierType, xs:byte, minInclusive value="-3", maxInclusive value="3"
    amount_multiplier: int = Field(..., alias="amountMultiplier")


class ConsumptionCostType(BaseModel):
    # startValue
    start_value: PhysicalValueType = Field(..., alias="startValue")
    # cost, minOccurs = 1 => required, maxOccurs = 3
    cost: List[CostType] = Field(..., alias="Cost")


class SalesTariffEntryType(BaseModel):
    # TimeInterval, minOccurs = 1 => required
    time_interval: RelativeTimeIntervalType = Field(
        ..., alias="RelativeTimeInterval"
    )
    # EPriceLevel, xs:unsignedByte, minOccurs = 0 => not required
    e_price_level: int = Field(default=None, alias="EPriceLevel")
    # ConsumptionCost, minOccurs = 0 => not required, maxOccurs = 3
    consumption_cost: List[ConsumptionCostType] = Field(
        None, alias="ConsumptionCost"
    )


class SalesTariffType(BaseModel):
    """complexType SalesTariffType"""

    model_config = ConfigDict(populate_by_name=True)

    # xs:ID, Id, attribute in XSD => need to add
    id: str = Field(..., serialization_alias="@Id", validation_alias="@Id")
    # SalesTariffID, xs:unsignedByte, minInclusive value="1", maxInclusive value="255"
    sales_tariff_id: int = Field(..., alias="SalesTariffID")
    # SalesTariffDescription, minOccurs = 0 => not required
    # tariffDescriptionType, xs:string, maxLength 32
    sales_tariff_description: str = Field(
        default=None, alias="SalesTariffDescription"
    )
    # NumEPriceLevels, xs:unsignedByte, minOccurs = 0 => not required
    num_e_price_levels: int = Field(default=None, alias="NumEPriceLevels")
    # SalesTariffEntry, maxOccurs = 1024
    # SalesTariffEntryType, minOccurs = 1 => required, maxOccurs = 1024
    sales_tariff_entry: List[SalesTariffEntryType] = Field(
        ..., alias="SalesTariffEntry"
    )


class SAScheduleTupleType(BaseModel):
    """complexType SAScheduleTupleType"""

    # SAScheduleTupleID,
    # SAIDType =>  xs:unsignedByte, minInclusive value="1", maxInclusive value="255"
    sa_schedule_tuple_id: int = Field(..., alias="SAScheduleTupleID")
    # PMaxSchedule
    p_max_schedule: PMaxScheduleType = Field(..., alias="PMaxSchedule")
    # SalesTariff, minOccurs = 0 => not required
    sales_tafiff: SalesTariffType = Field(..., alias="SalesTariff")


class SAScheduleListType(BaseModel):
    """complexType SAScheduleListType"""

    # SAScheduleTupleType, minOccurs = 1 => required
    # in list can be 1-3 items
    sa_schedule_tuple: List[SAScheduleTupleType] = Field(
        ..., alias="SAScheduleTuple"
    )


class chargeProgressType(str, Enum):
    """Enumerated values for chargeProgressType"""

    START = "Start"
    STOP = "Stop"
    RENEGOTIATE = "Renegotiate"


class ProfileEntryType(BaseModel):
    """ "complexType ProfileEntryType"""

    # ChargingProfileEntryStart, xs:unsignedInt, minOccurs = 1 => required
    charging_profile_entry_start: int = Field(
        ..., alias="ChargingProfileEntryStart"
    )
    # ChargingProfileEntryMaxPower
    # PhysicalValueType, minOccurs = 1 => required
    charging_profile_entry_max_power: PhysicalValueType = Field(
        ..., alias="ChargingProfileEntryMaxPower"
    )
    # ChargingProfileEntryMaxNumberOfPhasesInUse, minOccurs = 0 => not required
    # xs:byte, minInclusive value="1", maxInclusive value="3"
    charging_profile_entry_max_number_of_phases_in_use: int = Field(
        None, alias="ChargingProfileEntryMaxNumberOfPhasesInUse"
    )


class ChargingProfileType(BaseModel):
    """complexType ChargingProfileType"""

    # ProfileEntryType, minOccurs = 1 => required, maxOccurs = 24
    # 1-24 items in list
    profile_entry: List[ProfileEntryType] = Field(..., alias="ProfileEntry")


class EVPowerDeliveryParameterType(ABC, BaseModel):
    """complexType EVPowerDeliveryParameterType. Abstract class - abstract in XSD"""


class DC_EVPowerDeliveryParameterType(EVPowerDeliveryParameterType):
    """complexType DC_EVPowerDeliveryParameterType,"""

    # DC_EVStatus
    dc_ev_status: DC_EVStatusType = Field(..., alias="DC_EVStatus")
    # BulkChargingComplete, minOccurs = 0 => not required
    # xs:boolean
    bulk_charging_complete: bool = Field(
        default=None, alias="BulkChargingComplete"
    )
    # ChargingComplete, minOccurs = 1 => required
    # xs:boolean
    charging_complete: bool = Field(..., alias="ChargingComplete")


class MeterInfoType(BaseModel):
    """complexType MeterInfoType"""

    # MeterID, minOccurs = 1 => required
    # xs:unsignedByte
    meter_id: int = Field(..., alias="MeterID")
    # MeterReading, minOccurs = 0 => not required
    # xs:unsignedLong
    meter_reading: int = Field(default=None, alias="MeterReading")
    # SigMeterReading, minOccurs = 0 => not required
    # xs:base64Binary, maxLength 64
    sig_meter_reading: str = Field(default=None, alias="SigMeterReading")
    # MeterStatus, minOccurs = 0 => not required
    # xs:short
    meter_status: int = Field(default=None, alias="MeterStatus")
    # TMeter, minOccurs = 0 => not required
    # xs:long
    t_meter: int = Field(default=None, alias="TMeter")


class chargingSessionType(str, Enum):
    """enumerated values for chargingSessionType"""

    TERMINATE = "Terminate"
    PAUSE = "Pause"


class ListOfRootCertificateIDsType(BaseModel):
    """complexType ListOfRootCertificateIDsType"""

    # RootCertificateID, minOccurs = 1
    # X509IssuerSerialType in list can be 1-20 items
    # TODO: solve with XMLSIG lib
    # root_certificate_id: List[X509IssuerSerialType] = Field(
    #    ..., alias="RootCertificateID"
    # )


class privateKeyType(ABC, BaseModel):
    """simpleType privateKeyType"""

    # in XSD is defined only as xs:base64Binary, maxLength 48
    # but It's need for the next class to have the value
    # xs:base64Binary, maxLength 48
    # so base64 encode private key in bytes
    # to get bytes base64.b64encode(value)
    value: str = Field(..., alias="value")


class ContractSignatureEncryptedPrivateKeyType(privateKeyType):
    """is extension of privateKeyType"""

    # Id, xs:ID, it's a attribute in XSD not element
    model_config = ConfigDict(populate_by_name=True)

    # attribute Id, xs:ID, in XSD is defined as attribute => need to add
    # populating by name in ConfigDict and serialization and validation alias
    # instead of alias, if only alias is used, it's working but pylance is complaining
    id: str = Field(..., serialization_alias="@Id", validation_alias="@Id")


class dHpublickeyType(ABC, BaseModel):
    """simpleType dHpublickeyType"""

    # Has to be implement although it's a simple type, cause it has an extension
    # in XSD is defined only as xs:base64Binary, maxLength 65
    # but It's need for the next class to have the value
    # xs:base64Binary, maxLength 65
    value: str = Field(..., alias="value")


class DiffieHellmanPublickeyType(dHpublickeyType):
    """is extension of dHpublickeyType"""

    model_config = ConfigDict(populate_by_name=True)

    # attribute Id, xs:ID, in XSD is defined as attribute => need to add
    # populating by name in ConfigDict and serialization and validation alias
    # instead of alias, if only alias is used, it's working but pylance is complaining
    # Id, xs:ID, it's a attribute in XSD not element
    id: str = Field(..., serialization_alias="@Id", validation_alias="@Id")


class eMAIDType(ABC, BaseModel):
    """simpleType eMAIDType"""

    # Has to be implement although it's a simple type, cause it has an extension
    # in XSD is defined only as xs:string, minLength 14, maxLength 15
    # but It's need for the next class to have the value
    # xs:string, minLength 14, maxLength 15
    value: str = Field(..., alias="value")


class EMAIDType(eMAIDType):
    """is extension of eMAIDType"""

    model_config = ConfigDict(populate_by_name=True)

    # attribute Id, xs:ID, in XSD is defined as attribute => need to add
    # populating by name in ConfigDict and serialization and validation alias
    # instead of alias, if only alias is used, it's working but pylance is complaining
    # Id, xs:ID, it's a attribute in XSD not element
    id: str = Field(..., serialization_alias="@Id", validation_alias="@Id")
