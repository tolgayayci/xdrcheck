"""Typed reasons for what the SDK raised.

stellar-sdk raises plain ValueError for nearly every refusal (xdrlib3 adds EOFError and ConversionError), so
the reason code is read from the exception's type, its text, its cause chain and, for undeclared enum values,
from where in the generated code it was raised; the text itself is passed on untouched in reason.message. A
code is only a refinement of "the SDK refused": anything not recognised is decode_error (decoding) or the
caller's fallback.
"""
from __future__ import annotations

import enum

from .schema import shape

MESSAGE_MAX = 500


def chain(err: BaseException):
    """The exception and everything it was raised from or while handling."""
    seen = set()
    while err is not None and id(err) not in seen:
        seen.add(id(err))
        yield err
        err = err.__cause__ or err.__context__


def is_fault(err: BaseException) -> bool:
    """A fault-class error (conformance runner, driver obligations): never reported as reject, also when an
    SDK wrapper re-raised it as something else."""
    return any(isinstance(e, (RecursionError, MemoryError)) for e in chain(err))


def fault_code(err: BaseException) -> str:
    for e in chain(err):
        if isinstance(e, RecursionError):
            return "stack_overflow"
        if isinstance(e, MemoryError):
            return "out_of_memory"
    return "internal_error"


def trim(s: str, n: int = MESSAGE_MAX) -> str:
    s = str(s)
    return s if len(s) <= n else s[: n - 1] + "…"


def _enum_is_union_switch(err: BaseException) -> bool:
    """Was this undeclared enum value read as a union's discriminant (rather than as a plain enum field)? The
    generated enum's unpack raised it; the frame that called it belongs to the class that read the value."""
    frames = []
    tb = err.__traceback__
    while tb is not None:
        frames.append(tb.tb_frame)
        tb = tb.tb_next
    for i in range(len(frames) - 1, 0, -1):
        cls = frames[i].f_locals.get("cls")
        if isinstance(cls, type) and issubclass(cls, enum.Enum) and frames[i].f_code.co_name == "unpack":
            parent = frames[i - 1].f_locals.get("cls")
            if not isinstance(parent, type) or not hasattr(parent, "__doc__"):
                return False
            try:
                s = shape(parent)
            except Exception:
                return False
            return s.kind == "union" and s.disc is not None and s.disc.type.name == shape(cls).name
    return False


def decode_code(err: BaseException) -> str:
    """Classify an error raised while decoding XDR."""
    for e in chain(err):
        m = str(e)
        if isinstance(e, EOFError):
            return "length_exceeds_input"
        if "Maximum decoding depth" in m:
            return "depth"
        if "Unexpected trailing" in m:
            return "trailing_bytes"
        if "exceeds remaining input" in m:
            return "length_exceeds_input"
        if "The maximum length of" in m or "exceeds maximum" in m:
            return "length_exceeds_max"
        if "0 or 1 expected" in m:
            return "optional_flag_range"
        if isinstance(e, ValueError) and " is not a valid " in m:
            return "union_arm_undeclared" if _enum_is_union_switch(e) else "enum_undeclared"
        if isinstance(e, ValueError) and m.startswith("Invalid ") and m.endswith("."):
            # a generated union's unpack: a declared discriminant with no case
            return "union_arm_undeclared"
    return "decode_error"


def object_code(err: BaseException, fallback: str) -> str:
    """Classify an error from the SDK's object, native or builder layer."""
    for e in chain(err):
        m = str(e)
        if "lexicographic order" in m:
            return "ordering"
        if "nsupported address type" in m or "nsupported SCAddress" in m:
            return "unsupported_address_type"
        if "non-negative" in m or "out of range" in m or "must be between" in m or "should be in" in m:
            return "value_out_of_range"
    d = decode_code(err)
    return d if d != "decode_error" else fallback


def native_code(err: BaseException) -> str:
    """Classify an error from a native conversion (L3): bytes that do not decode as UTF-8 are refused, not
    converted lossily, so a UnicodeDecodeError anywhere in the chain is lossy_conversion_refused."""
    if any(isinstance(e, UnicodeDecodeError) for e in chain(err)):
        return "lossy_conversion_refused"
    return object_code(err, "other")


def strkey_code(err: BaseException) -> str:
    """Classify a strkey refusal from the cause the SDK's wrapper chained."""
    for e in chain(err):
        m = str(e)
        if isinstance(e, UnicodeError):
            return "strkey_noncanonical"
        if "Invalid version byte" in m:
            return "strkey_version"
        if m.startswith("Invalid length") or "Incorrect padding" in m:
            return "strkey_length"
        if "Invalid checksum" in m:
            return "strkey_checksum"
        if "Invalid encoded bytes" in m or "Non-base32" in m:
            return "strkey_noncanonical"
        if "claimable balance type" in m:
            return "strkey_payload"
        if "Signed Payload" in m and e is not err:
            return "strkey_payload"
    return "other"


def reason(code: str, err: BaseException | None = None, entry_point: str | None = None) -> dict:
    r = {"code": code}
    if err is not None:
        r["message"] = trim(str(err) or type(err).__name__)
        r["error_class"] = type(err).__name__
    if entry_point:
        r["entry_point"] = entry_point
    return r
