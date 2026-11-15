// The protocol the driver reports in describe (xdr_schema.protocol): the highest protocol it can prove the
// SDK's generated XDR reaches. The orchestrator excuses a refusal of a newer variant as beyond the column's
// reach only below that protocol, so it must never claim more than the probes prove, nor a ceiling for an
// SDK whose XDR is newer than the driver knows.

// The newest protocol whose definitions the probes and the ceiling below describe.
export const KNOWN_PROTOCOL = 30; // pin:protocol.max_supported

// The highest member of each sentinel enum in the pinned definitions. A protocol nearly always adds a member
// to one of them, so an SDK that declares a member above one carries newer XDR than this driver can bound.
// The values are generated from the XDR definitions (`make xdr-ceilings`; `make test` fails when they drift);
// add or remove an enum by hand, never edit a value.
export const CEILING = {
  // BEGIN generated: xdrcheck xdr ceilings (stellar-xdr v30.0)
  ContractCostType: 94, ConfigSettingId: 20, ContractExecutableType: 2, EnvelopeType: 10, HostFunctionType: 3,
  LedgerEntryType: 9, LedgerUpgradeType: 7, OperationType: 26, ScAddressType: 5, ScValType: 22, StellarValueType: 4,
  // END generated: xdrcheck xdr ceilings
};

// The sentinel enums in which the SDK declares a member above the Protocol 30 ceiling; values(name) lists the
// member values of the SDK's enum of that name.
export function beyondKnown(values) {
  return Object.entries(CEILING).flatMap(([e, max]) => values(e).filter((v) => v > max).map((v) => `${e} ${v}`));
}

// The protocol that introduced each probed feature; a probe not listed is a KNOWN_PROTOCOL one.
export const PROBE_PROTOCOL = { sc_address_type_muxed_contract: 30, stellar_value_signed_ms: 30 };

// KNOWN_PROTOCOL when every probe passes, else the protocol before the oldest feature whose probe fails;
// undefined when the SDK declares enum members above the ceiling: its XDR is newer than the probes, and a
// reported KNOWN_PROTOCOL would excuse its refusals of newer variants.
export function schemaProtocol(probes, beyond) {
  if (beyond.length > 0) return undefined;
  let p = KNOWN_PROTOCOL;
  for (const [name, ok] of Object.entries(probes)) {
    if (!ok) p = Math.min(p, (PROBE_PROTOCOL[name] ?? KNOWN_PROTOCOL) - 1);
  }
  return p;
}
