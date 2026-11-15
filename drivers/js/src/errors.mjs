// Typed reasons for what the SDK threw. JavaScript gives one error class for every XDR decode failure
// (XdrError) and plain Error for the object and builder layers, so the reason code is read from the error's
// shape and text here, once, and the text itself is passed on untouched in reason.message. A code is only a
// refinement of "the SDK refused": anything not recognised is decode_error (decoding) or other.

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

function isXdrError(err) {
  return err instanceof Error && err.name === "XdrError";
}

/**
 * Classify a decode error. unionKeyAt(path) tells whether the dotted path an XdrError names ends at a union's
 * discriminant (an undeclared union arm) rather than at a plain enum field (an undeclared enum value).
 */
export function decodeCode(err, unionKeyAt) {
  const m = String(err && err.message);
  if (!isXdrError(err)) return "decode_error";
  if (/invalid bool discriminant/.test(m)) return /\.present: /.test(m) ? "optional_flag_range" : "bool_range";
  if (/non-zero XDR padding/.test(m)) return "nonzero_padding";
  if (/trailing \d+ byte/.test(m)) return "trailing_bytes";
  if (/max recursion depth/.test(m)) return "depth";
  if (/exceeds maximum/.test(m)) return "length_exceeds_max";
  if (/exceeds remaining|incomplete XDR data/.test(m)) return "length_exceeds_input";
  if (/no case for union discriminator/.test(m)) return "union_arm_undeclared";
  if (/unknown enum value/.test(m)) {
    const path = m.slice(0, m.indexOf(": "));
    return unionKeyAt && unionKeyAt(path) ? "union_arm_undeclared" : "enum_undeclared";
  }
  if (/out of range|expected integer in range|expected bigint in range/.test(m)) return "value_out_of_range";
  return "decode_error";
}

/** Classify an error from the SDK's object, native or builder layer. */
export function objectCode(err, fallback) {
  const m = String(err && err.message);
  if (isXdrError(err)) return decodeCode(err);
  if (/lexicographic order|must be <=/.test(m)) return "ordering";
  if (/more than one key that converts/.test(m)) return "lossy_conversion_refused";
  if (/[Uu]nsupported address type/.test(m)) return "unsupported_address_type";
  if (/safe integer|out of range|not a valid u?int\d*|must be a string of decimal digits|must be non-negative|negative/.test(m))
    return "value_out_of_range";
  return fallback;
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
    if (err instanceof Error && err.constructor && err.constructor.name) r.error_class = err.name === "XdrError" ? "XdrError" : err.constructor.name;
  }
  if (entryPoint) r.entry_point = entryPoint;
  return r;
}
