//! The protocol the driver reports in describe (`xdr_schema.protocol`): the highest protocol it can
//! prove the crate's generated XDR reaches. The orchestrator excuses a refusal of a newer variant as
//! beyond the column's reach only below that protocol, so the driver must never claim more than the
//! probes prove, nor a ceiling for a crate whose XDR is newer than the driver knows. Shared by the
//! driver and its self-test.

use stellar_xdr::{
    ConfigSettingId, ContractCostType, ContractExecutableType, EnvelopeType, HostFunctionType,
    LedgerEntryType, LedgerUpgradeType, OperationType, ScAddressType, ScValType, StellarValueType,
};

/// The newest protocol whose definitions the probes and the ceiling below describe.
pub const KNOWN_PROTOCOL: u32 = 30; // pin:protocol.max_supported

/// The highest member of each sentinel enum in the pinned definitions. A protocol nearly always
/// adds a member to one of them, so a crate that declares a member above one carries newer XDR than
/// this driver can bound. The values are generated from the XDR definitions (`make xdr-ceilings`;
/// `make test` fails when they drift); add or remove an enum by hand, never edit a value.
pub const CEILING: [(&str, i32); 11] = [
    // BEGIN generated: xdrcheck xdr ceilings (stellar-xdr v30.0)
    ("ContractCostType", 94),
    ("ConfigSettingId", 20),
    ("ContractExecutableType", 2),
    ("EnvelopeType", 10),
    ("HostFunctionType", 3),
    ("LedgerEntryType", 9),
    ("LedgerUpgradeType", 7),
    ("OperationType", 26),
    ("ScAddressType", 5),
    ("ScValType", 22),
    ("StellarValueType", 4),
    // END generated: xdrcheck xdr ceilings
];

/// The member values of the crate's generated enum of that name.
pub fn crate_values(name: &str) -> Vec<i32> {
    fn all<T: Copy + Into<i32>>(v: &[T]) -> Vec<i32> {
        v.iter().map(|x| (*x).into()).collect()
    }
    match name {
        "ContractCostType" => all(&ContractCostType::VARIANTS),
        "ConfigSettingId" => all(&ConfigSettingId::VARIANTS),
        "ContractExecutableType" => all(&ContractExecutableType::VARIANTS),
        "EnvelopeType" => all(&EnvelopeType::VARIANTS),
        "HostFunctionType" => all(&HostFunctionType::VARIANTS),
        "LedgerEntryType" => all(&LedgerEntryType::VARIANTS),
        "LedgerUpgradeType" => all(&LedgerUpgradeType::VARIANTS),
        "OperationType" => all(&OperationType::VARIANTS),
        "ScAddressType" => all(&ScAddressType::VARIANTS),
        "ScValType" => all(&ScValType::VARIANTS),
        "StellarValueType" => all(&StellarValueType::VARIANTS),
        _ => panic!("no ceiling enum {name}"),
    }
}

/// The sentinel enums in which the crate (`values` lists an enum's member values) declares a
/// member above the ceiling.
pub fn beyond_known(values: impl Fn(&str) -> Vec<i32>) -> Vec<String> {
    CEILING
        .iter()
        .flat_map(|(e, max)| {
            values(e)
                .into_iter()
                .filter(move |v| v > max)
                .map(move |v| format!("{e} {v}"))
        })
        .collect()
}

/// `KNOWN_PROTOCOL` when every probe passes, else the protocol before the oldest feature whose
/// probe fails; each probe is given with the protocol that introduced its feature. `None` when the
/// crate declares enum members above the ceiling: its XDR is newer than the probes, and a reported
/// `KNOWN_PROTOCOL` would excuse its refusals of newer variants.
pub fn schema_protocol(probes: &[(u32, bool)], beyond: &[String]) -> Option<u32> {
    if !beyond.is_empty() {
        return None;
    }
    Some(
        probes
            .iter()
            .filter(|(_, ok)| !ok)
            .map(|(introduced, _)| introduced - 1)
            .fold(KNOWN_PROTOCOL, u32::min),
    )
}
