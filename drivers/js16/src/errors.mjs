// Typed reasons for what the v16 SDK threw. The codes and the object-layer and strkey classifiers are those of
// the v17 driver (drivers/js/src/errors.mjs); what is specific here is the decode layer. @stellar/js-xdr 4 throws
// XdrReaderError (a TypeError whose message starts "XDR Read Error:") for most decode failures and a plain
// TypeError "Bad union switch" for an undeclared integer discriminant. Its messages name no path, so two of them
// are refined by locate(): "got 2 when trying to read a bool" is the same text for a bool field and for an
// optional's presence flag, and "unknown X member for value N" the same for a plain enum field and for a union's
// discriminant. The text itself is passed on untouched in reason.message; a code is only a refinement of "the
// SDK refused", and anything not recognised is decode_error or the caller's fallback.

/** A fault-class error: never reported as reject (conformance runner, driver obligations). */
export function isFault(err) {
  return err instanceof RangeError && /Maximum call stack size exceeded/.test(err.message);
}

export function faultCode(err) {
  return /call stack/.test(String(err && err.message)) ? "stack_overflow" : "internal_error";
}

/** Trim to at most n code points. */
export function trim(s, n) {
  s = String(s);
  const cps = Array.from(s);
  return cps.length <= n ? s : cps.slice(0, n - 1).join("") + "…";
}

/** Classify a strkey refusal. */
export function strkeyCode(err) {
  const m = String(err && err.message);
  if (/invalid encoded string length/.test(m)) return "strkey_length";
  if (/invalid encoded string/.test(m)) return "strkey_noncanonical";
  if (/invalid version byte/.test(m)) return "strkey_version";
  if (/invalid checksum/.test(m)) return "strkey_checksum";
  if (/non-zero padding/.test(m)) return "strkey_padding";
  if (/signed payload|claimable balance|payload/.test(m)) return "strkey_payload";
  if (/base32|character|alphabet/i.test(m)) return "strkey_noncanonical";
  return "other";
}

/** The reason object for an error and a code. */
export function reason(code, err, entryPoint) {
  const r = { code };
  if (err !== undefined) {
    r.message = trim(err instanceof Error ? err.message : String(err), 500);
    if (err instanceof Error && err.constructor && err.constructor.name) r.error_class = err.constructor.name;
  }
  if (entryPoint) r.entry_point = entryPoint;
  return r;
}

/** An error from js-xdr 4's decoder. */
export function isXdrReadError(err) {
  if (!(err instanceof TypeError)) return false;
  const m = String(err.message);
  return m.startsWith("XDR Read Error:") || /^Bad union switch/.test(m);
}

/**
 * Classify a decode error. locate() (optional) re-reads the input to tell which construct failed: it returns
 * bool_range / optional_flag_range / enum_undeclared / union_arm_undeclared, or undefined.
 */
export function decodeCode(err, locate) {
  const m = String(err && err.message);
  if (!isXdrReadError(err)) return "decode_error";
  if (/when trying to read a bool/.test(m)) return (locate && locate()) || "bool_range";
  if (/invalid padding/.test(m)) return "nonzero_padding";
  if (/not entirely consumed/.test(m)) return "trailing_bytes";
  if (/max decoding depth/.test(m)) return "depth";
  if (/saw \d+ length \w+, max allowed/.test(m)) return "length_exceeds_max";
  if (/exceeds remaining|outside the boundary/.test(m)) return "length_exceeds_input";
  if (/^Bad union switch/.test(m)) return "union_arm_undeclared";
  if (/unknown \w+ member for value/.test(m)) return (locate && locate()) || "enum_undeclared";
  return "decode_error";
}

/** Classify an error from the SDK's object, native or builder layer (a decode error inside it included). */
export function objectCodeOf(err, fallback) {
  const m = String(err && err.message);
  if (isXdrReadError(err)) return decodeCode(err);
  if (/lexicographic order|must be <=/.test(m)) return "ordering";
  if (/more than one key that converts/.test(m)) return "lossy_conversion_refused";
  if (/[Uu]nsupported address type/.test(m)) return "unsupported_address_type";
  if (/safe integer|out of range|not a valid u?int\d*|must be a string of decimal digits|must be non-negative|negative/.test(m))
    return "value_out_of_range";
  return fallback;
}

class Located extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

/**
 * Which construct a refused decode failed at: reads the bytes again along the SDK's own type graph (struct
 * `_fields`, union `_switchOn`/`armForSwitch`, `_childType`), with the SDK's own reader and primitive readers,
 * stopping at the first invalid bool, optional flag, enum value or union discriminant. Returns the reason code,
 * or undefined when the failure is something else.
 */
export function locate(T, bytes, XdrReader) {
  const r = new XdrReader(bytes);
  const scan = (t, depth) => {
    if (depth > 4096) throw new Error("too deep");
    if (Array.isArray(t?._fields)) {
      for (const [, ft] of t._fields) scan(ft, depth + 1);
      return;
    }
    if (t?._switchOn) {
      let sw;
      try {
        sw = t._switchOn.read(r);
      } catch (e) {
        if (/member for value|Bad union switch/.test(String(e?.message))) throw new Located("union_arm_undeclared");
        throw e;
      }
      let arm;
      try {
        arm = t.armForSwitch(sw);
      } catch {
        throw new Located("union_arm_undeclared");
      }
      scan(typeof arm === "string" ? t._arms[arm] : arm, depth + 1);
      return;
    }
    if (t?._members && typeof t.read === "function") {
      try {
        t.read(r);
      } catch (e) {
        if (/member for value/.test(String(e?.message))) throw new Located("enum_undeclared");
        throw e;
      }
      return;
    }
    if (typeof t === "function" && t.name === "Bool") {
      const v = r.readInt32BE();
      if (v !== 0 && v !== 1) throw new Located("bool_range");
      return;
    }
    switch (t?.constructor?.name) {
      case "Option": {
        const f = r.readInt32BE();
        if (f !== 0 && f !== 1) throw new Located("optional_flag_range");
        if (f === 1) scan(t._childType, depth + 1);
        return;
      }
      case "VarArray": {
        const n = r.readUInt32BE();
        if (n > t._maxLength || n > r.remainingBytes()) throw new Error("length");
        for (let i = 0; i < n; i++) scan(t._childType, depth + 1);
        return;
      }
      case "Array":
        for (let i = 0; i < t._length; i++) scan(t._childType, depth + 1);
        return;
    }
    t.read(r);
  };
  try {
    scan(T, 0);
  } catch (e) {
    if (e instanceof Located) return e.code;
  }
  return undefined;
}
