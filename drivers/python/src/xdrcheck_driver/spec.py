"""The spec level: the SDK's contract-spec reader (stellar_sdk.sep.contract_spec.ContractSpec: from_wasm on a Wasm
module, from_xdr_bytes on a bare SCSpecEntry stream) and its entries in the neutral rendering of
docs/conformance-protocol.md (spec level), read from the SDK's own XDR objects. The driver never decodes the
bytes itself."""
from __future__ import annotations


def _raw(x) -> bytes:
    for attr in ("sc_symbol", "string32", "string64", "string60", "value"):
        if hasattr(x, attr) and isinstance(getattr(x, attr), (bytes, str)):
            x = getattr(x, attr)
            break
    return x.encode() if isinstance(x, str) else bytes(x)


def name_text(x) -> str:
    """The text of a name: the string when its bytes are UTF-8, else SEP-51 escaped (\\xNN)."""
    b = _raw(x)
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        return "".join(chr(c) if 0x20 <= c < 0x7F and c != 0x5C else f"\\x{c:02x}" for c in b)


def _int(x) -> int:
    return x if isinstance(x, int) else int(getattr(x, "uint32", getattr(x, "value", x)))


def type_text(t) -> str:
    name = t.type.name.removeprefix("SC_SPEC_TYPE_").lower()
    if name == "option":
        return f"option<{type_text(t.option.value_type)}>"
    if name == "result":
        return f"result<{type_text(t.result.ok_type)},{type_text(t.result.error_type)}>"
    if name == "vec":
        return f"vec<{type_text(t.vec.element_type)}>"
    if name == "map":
        return f"map<{type_text(t.map.key_type)},{type_text(t.map.value_type)}>"
    if name == "tuple":
        return "tuple<" + ",".join(type_text(x) for x in t.tuple.value_types) + ">"
    if name == "bytes_n":
        return f"bytes_n<{_int(t.bytes_n.n)}>"
    if name == "udt":
        return "udt:" + name_text(t.udt.name)
    return name


def _arg(name, ty: str) -> dict:
    return {"name": name_text(name), "type": ty}


def entry_fact(e) -> dict:
    kind = e.kind.name
    if kind == "SC_SPEC_ENTRY_FUNCTION_V0":
        f = e.function_v0
        return {"kind": "function", "name": name_text(f.name), "args": [_arg(i.name, type_text(i.type)) for i in f.inputs],
                "outputs": [type_text(o) for o in f.outputs]}
    if kind == "SC_SPEC_ENTRY_UDT_STRUCT_V0":
        s = e.udt_struct_v0
        return {"kind": "struct", "name": name_text(s.name), "args": [_arg(f.name, type_text(f.type)) for f in s.fields]}
    if kind == "SC_SPEC_ENTRY_UDT_UNION_V0":
        u = e.udt_union_v0
        args = []
        for c in u.cases:
            if c.kind.name == "SC_SPEC_UDT_UNION_CASE_VOID_V0":
                args.append(_arg(c.void_case.name, "void"))
            else:
                args.append(_arg(c.tuple_case.name, "tuple<" + ",".join(type_text(x) for x in c.tuple_case.type) + ">"))
        return {"kind": "union", "name": name_text(u.name), "args": args}
    if kind in ("SC_SPEC_ENTRY_UDT_ENUM_V0", "SC_SPEC_ENTRY_UDT_ERROR_ENUM_V0"):
        u = e.udt_enum_v0 if kind == "SC_SPEC_ENTRY_UDT_ENUM_V0" else e.udt_error_enum_v0
        return {"kind": "enum" if kind == "SC_SPEC_ENTRY_UDT_ENUM_V0" else "error_enum", "name": name_text(u.name),
                "args": [_arg(c.name, f"={_int(c.value)}") for c in u.cases]}
    if kind == "SC_SPEC_ENTRY_EVENT_V0":
        ev = e.event_v0
        loc = lambda p: "topic_list" if p.location.name.endswith("TOPIC_LIST") else "data"  # noqa: E731
        return {"kind": "event", "name": name_text(ev.name), "args": [_arg(p.name, f"{type_text(p.type)}@{loc(p)}") for p in ev.params]}
    raise ValueError(f"unknown SCSpecEntry kind {kind}")


def read_spec(data: bytes, container: str):
    """(entry point, entries) from the SDK's reader; raises what the SDK raised."""
    from stellar_sdk.sep.contract_spec import ContractSpec

    if container == "wasm":
        return "ContractSpec.from_wasm", ContractSpec.from_wasm(data).entries
    return "ContractSpec.from_xdr_bytes", ContractSpec.from_xdr_bytes(data).entries


def refusal_code(err: BaseException, data: bytes, container: str, decode_code) -> str:
    """The reason code of a refusal, from the error's type and what it was raised from, never from its message:
    more than one contractspecv0 section (counted with the SDK's own section reader), a malformed Wasm module, or
    the XDR error under the SDK's InvalidWasmError (classified by decode_code)."""
    from stellar_sdk.sep._wasm import CONTRACT_SPEC_SECTION_NAME, get_wasm_custom_sections
    from stellar_sdk.sep.exceptions import InvalidWasmError

    if container == "wasm":
        try:
            if len(get_wasm_custom_sections(data, CONTRACT_SPEC_SECTION_NAME)) > 1:
                return "spec_sections"
        except InvalidWasmError:
            return "decode_error"
    if isinstance(err, InvalidWasmError):
        return decode_code(err.__cause__) if err.__cause__ is not None else "decode_error"
    return decode_code(err)
