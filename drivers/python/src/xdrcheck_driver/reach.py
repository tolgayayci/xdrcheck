"""The protocol the driver reports in describe (xdr_schema.protocol): the highest protocol it can prove the
SDK's generated XDR reaches. The orchestrator excuses a refusal of a newer variant as beyond the column's
reach only below that protocol, so the driver must never claim more than the probes prove, nor a ceiling for
an SDK whose XDR is newer than the driver knows. Imports nothing from the SDK, so the tests can load it."""

from __future__ import annotations

from typing import Callable, Iterable, Mapping, Optional

# The newest protocol whose definitions the probes and the ceiling below describe.
KNOWN_PROTOCOL = 30  # pin:protocol.max_supported

# The highest member of each sentinel enum in the pinned definitions. A protocol nearly always adds a member
# to one of them, so an SDK that declares a member above one carries newer XDR than this driver can bound.
# Names are the SDK's. The values are generated from the XDR definitions (`make xdr-ceilings`; `make test`
# fails when they drift); add or remove an enum by hand, never edit a value.
CEILING = {
    # BEGIN generated: xdrcheck xdr ceilings (stellar-xdr v30.0)
    "ContractCostType": 94, "ConfigSettingID": 20, "ContractExecutableType": 2, "EnvelopeType": 10,
    "HostFunctionType": 3, "LedgerEntryType": 9, "LedgerUpgradeType": 7, "OperationType": 26,
    "SCAddressType": 5, "SCValType": 22, "StellarValueType": 4,
    # END generated: xdrcheck xdr ceilings
}


def beyond_known(values: Callable[[str], Iterable[int]]) -> list[str]:
    """The sentinel enums in which the SDK declares a member above the ceiling; values(name) lists the member
    values of the SDK's enum of that name."""
    return [f"{e} {v}" for e, top in CEILING.items() for v in sorted(values(e)) if v > top]


# The protocol that introduced each probed feature; a probe not listed is a KNOWN_PROTOCOL one.
PROBE_PROTOCOL = {"sc_address_type_muxed_contract": 30, "stellar_value_signed_ms": 30}


def schema_protocol(probes: Mapping[str, bool], beyond: list[str]) -> Optional[int]:
    """KNOWN_PROTOCOL when every probe passes, else the protocol before the oldest feature whose probe fails;
    None when the SDK declares enum members above the ceiling: its XDR is newer than the probes, and a reported
    KNOWN_PROTOCOL would excuse its refusals of newer variants."""
    if beyond:
        return None
    failed = [PROBE_PROTOCOL.get(name, KNOWN_PROTOCOL) - 1 for name, ok in probes.items() if not ok]
    return min([KNOWN_PROTOCOL, *failed])
