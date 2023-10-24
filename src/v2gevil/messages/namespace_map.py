# Define a dictionary mapping namespaces to their corresponding keys
namespace_map = {
    "v2gci_d": ["V2G_Message", "Header", "Body"],
    "v2gci_h": ["SessionID", "Notification"],
    "v2gci_b": [
        "AuthorizationReq",
        "AuthorizationRes",
        "CableCheckReq",
        "CableCheckRes",
        "CertificateInstallationReq",
        "CertificateInstallationRes",
        "CertificateUpdateReq",
        "CertificateUpdateRes",
        "ChargeParameterDiscoveryReq",
        "ChargeParameterDiscoveryRes",
        "ChargingStatusReq",
        "ChargingStatusRes",
        "CurrentDemandReq",
        "CurrentDemandRes",
        "MeteringReceiptReq",
        "MeteringReceiptRes",
        "PaymentDetailsReq",
        "PaymentDetailsRes",
        "PaymentServiceSelectionReq",
        "PaymentServiceSelectionRes",
        "PowerDeliveryReq",
        "PowerDeliveryRes",
        "PreChargeReq",
        "PreChargeRes",
        "ServiceDetailReq",
        "ServiceDetailRes",
        "ServiceDiscoveryReq",
        "ServiceDiscoveryRes",
        "SessionSetupReq",
        "SessionSetupRes",
        "SessionStopReq",
        "SessionStopRes",
        "WeldingDetectionReq",
        "WeldingDetectionRes",
        "ResponseCode",
        "GenChallenge",
        "EVSEProcessing",
        "OEMProvisioningCert",
        "ListOfRootCertificateIDs",
        "SAProvisioningCertificateChain",
        "ContractSignatureCertChain",
        "ContractSignatureEncryptedPrivateKey",
        "DHpublickey",
        "eMAID",
        "RequestedEnergyTransferMode",
        "EVSEID",
        "MeterInfo",
        "EVTargetCurrent",
        "RemainingTimeToFullSoC",
        "RemainingTimeToBulkSoC",
        "EVTargetVoltage",
        "EVSEPresentVoltage",
        "EVSEPresentCurrent",
        "SelectedPaymentOption",
        "SelectedServiceList",
        "ChargeProgress",
        "ChargingProfile",
        "ServiceParameterList",
        "PaymentOptionList",
        "ChargeService",
        "ServiceList",
        "EVCCID",
        "ChargingSession",
        "EVMaximumVoltageLimit",
        "EVSECurrentLimitAchieved",
        "ServiceID",
        "EVSEVoltageLimitAchieved",
        "EVSEMaxCurrent",
        "SAScheduleTupleID",
        "EVSEPowerLimitAchieved",
        "EVSETimeStamp",
        "ChargingComplete",
        "EVSEMaximumCurrentLimit",
        "ServiceScope",
        "MaxEntriesSAScheduleTuple",
        "EVSEMaximumVoltageLimit",
        "EVSEMaximumPowerLimit",
        "DC_EVSEStatus",
        "ServiceCategory",
        "AC_EVSEStatus",
        "BulkChargingComplete",
        "SessionID",
        "ReceiptRequired",
        "EVMaximumPowerLimit",
        "EVMaximumCurrentLimit",
        "DC_EVStatus",
        "RetryCounter",
    ],
    "v2gci_t": [
        "DC_EVStatus",
        "DC_EVSEStatus",
        "EVChargeParameter",
        "SASchedules",
        "EVSEChargeParameter",
        "SAScheduleTupleID",
        "EVSEMaxCurrent",
        "AC_EVSEStatus",
        "EVMaximumVoltageLimit",
        "EVMaximumCurrentLimit",
        "EVMaximumPowerLimit",
        "EVSEMaximumVoltageLimit",
        "EVSEMaximumCurrentLimit",
        "EVSEMaximumPowerLimit",
        "EVSEStatus",
        "EVPowerDeliveryParameter",
        "ServiceID",
        "ServiceScope",
        "ServiceCategory",
        "physicalValue",
        "SigMeterReading",
        "Parameter",
        "RCD",
        "ChargingProfileEntryMaxPower",
        "FreeService",
        "MeterReading",
        "EVErrorCode",
        "ParameterSetID",
        "MeterStatus",
        "SelectedService",
        "EVSENotification",
        "ChargingProfileEntryMaxNumberOfPhasesInUse",
        "intValue",
        "EVRESSSOC",
        "ParameterSet",
        "ProfileEntry",
        "Multiplier",
        "byteValue",
        "stringValue",
        "SupportedEnergyTransferMode",
        "EVSEStatusCode",
        "boolValue",
        "ServiceName",
        "PaymentOption",
        "shortValue",
        "ChargingProfileEntryStart",
        "EnergyTransferMode",
        "EVReady",
        "Value",
        "SubCertificates",
        "Service",
        "Certificate",
        "MeterID",
        "RootCertificateID",
        "TMeter",
        "NotificationMaxDelay",
        "Unit",
        "EVSEIsolationStatus",
        "Entry",
        "EVStatus",
        "PMaxSchedule",
        "TimeInterval",
        "EVEnergyCapacity",
        "EVMinCurrent",
        "AC_EVChargeParameter",
        "start",
        "DC_EVChargeParameter",
        "AC_EVSEChargeParameter",
        "BulkChargingComplete",
        "FullSOC",
        "DepartureTime",
        "duration",
        "ChargingComplete",
        "SalesTariff",
        "NumEPriceLevels",
        "EVSEEnergyToBeDelivered",
        "SalesTariffID",
        "EAmount",
        "RelativeTimeInterval",
        "EVSENominalVoltage",
        "EVSEMinimumCurrentLimit",
        "EVSECurrentRegulationTolerance",
        "DC_EVSEChargeParameter",
        "SalesTariffEntry",
        "SAScheduleTuple",
        "EVSEPeakCurrentRipple",
        "EVMaxCurrent",
        "BulkSOC",
        "EVMaxVoltage",
        "EVEnergyRequest",
        "DC_EVPowerDeliveryParameter",
        "PMaxScheduleEntry",
        "EVSEMinimumVoltageLimit",
        "SAScheduleList",
        "SalesTariffDescription",
    ],
    "xmlsig": [
        "Signature",
        "SignedInfo",
        "CanonicalizationMethod",
        "SignatureMethod",
        "Reference",
        "Transforms",
        "Transform",
        "DigestMethod",
        "DigestValue",
        "SignatureValue",
    ],
}
