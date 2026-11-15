"""The shape of the SDK's generated XDR classes, read from the SDK itself.

stellar_sdk.xdr generates one Python class per XDR definition and puts the definition's XDR source text in the
class docstring ("XDR Source Code:: ..."). The classes carry no other machine-readable schema, and their
annotations cannot tell an `int` from a `hyper` or an `opaque<>` from a `string<>`. So this module parses that
XDR text (a small XDR-language parser: struct, union, enum, typedef, inline struct/union bodies, optional,
fixed and variable arrays) and pairs every declaration with the Python attribute that holds it, positionally,
from the generated __init__ signature: a struct's parameters are its fields in order; a union's are the
discriminant followed by each distinct non-void arm in case order; a typedef's is its single value.

shape(cls) returns a Shape for a generated class, or raises SchemaError when the docstring and the signature
do not agree (a driver bug to fix, never an SDK outcome).
"""
from __future__ import annotations

import enum
import inspect
import re
from dataclasses import dataclass, field

PRIMITIVES = {"int", "uint", "hyper", "uhyper", "bool", "float", "double", "opaque", "string"}


class SchemaError(Exception):
    pass


@dataclass
class TypeRef:
    """One declared type: base is a primitive kind, "named" (name holds the XDR type name) or "inline"
    (an anonymous struct or union, generated as its own class). array is None, "fixed" or "var" for
    arrays of non-byte types; for opaque and string the bracket is the length, not an array."""

    base: str
    name: str | None = None
    optional: bool = False
    array: str | None = None


@dataclass
class Decl:
    name: str  # the XDR identifier
    type: TypeRef
    attr: str | None = None  # the Python attribute, filled in when paired with the class


@dataclass
class Case:
    labels: list[str]  # case labels as written (identifiers or numbers); ["default"] for the default arm
    decl: Decl | None  # None: a void arm


@dataclass
class Shape:
    kind: str  # struct, union, enum, typedef
    name: str | None
    fields: list[Decl] = field(default_factory=list)  # struct
    disc: Decl | None = None  # union
    cases: list[Case] = field(default_factory=list)  # union
    members: list[tuple[str, str]] = field(default_factory=list)  # enum: (name, value text)
    value: Decl | None = None  # typedef


# ---- tokenizer and parser -------------------------------------------------------------------------------------

_TOKEN = re.compile(r"\s*(?:(//[^\n]*|/\*.*?\*/)|([A-Za-z_][A-Za-z0-9_]*)|(-?0x[0-9A-Fa-f]+|-?[0-9]+)|(.))", re.S)


def _tokens(text: str) -> list[str]:
    out = []
    pos = 0
    text = text.rstrip()
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            break
        pos = m.end()
        if m.group(1):
            continue
        tok = m.group(2) or m.group(3) or m.group(4)
        if tok and not tok.isspace():
            out.append(tok)
    return out


class _Parser:
    def __init__(self, toks: list[str]):
        self.t = toks
        self.i = 0

    def peek(self) -> str | None:
        return self.t[self.i] if self.i < len(self.t) else None

    def next(self) -> str:
        if self.i >= len(self.t):
            raise SchemaError("unexpected end of XDR text")
        tok = self.t[self.i]
        self.i += 1
        return tok

    def expect(self, tok: str) -> None:
        got = self.next()
        if got != tok:
            raise SchemaError(f"expected {tok!r}, got {got!r}")

    def maybe(self, tok: str) -> bool:
        if self.peek() == tok:
            self.i += 1
            return True
        return False

    def definition(self) -> Shape:
        kw = self.next()
        if kw == "typedef":
            d = self.decl()
            if d is None:
                raise SchemaError("typedef void")
            return Shape("typedef", d.name, value=d)
        if kw in ("struct", "union", "enum"):
            name = None
            if self.peek() not in ("{", "switch"):
                name = self.next()
            s = self.body(kw)
            s.name = name
            return s
        raise SchemaError(f"unknown definition keyword {kw!r}")

    def body(self, kw: str) -> Shape:
        if kw == "struct":
            self.expect("{")
            fields = []
            while not self.maybe("}"):
                d = self.decl()
                self.expect(";")
                if d is not None:
                    fields.append(d)
            return Shape("struct", None, fields=fields)
        if kw == "union":
            self.expect("switch")
            self.expect("(")
            disc = self.decl()
            self.expect(")")
            self.expect("{")
            cases: list[Case] = []
            labels: list[str] = []
            while not self.maybe("}"):
                tok = self.next()
                if tok == "case":
                    labels.append(self.next())
                    self.expect(":")
                    if self.peek() == "case":
                        continue
                elif tok == "default":
                    self.expect(":")
                    labels.append("default")
                else:
                    raise SchemaError(f"unexpected {tok!r} in union body")
                d = self.decl()
                self.expect(";")
                cases.append(Case(labels, d))
                labels = []
            return Shape("union", None, disc=disc, cases=cases)
        if kw == "enum":
            self.expect("{")
            members = []
            while not self.maybe("}"):
                name = self.next()
                value = ""
                if self.maybe("="):
                    value = self.next()
                members.append((name, value))
                self.maybe(",")
            return Shape("enum", None, members=members)
        raise SchemaError(kw)

    def decl(self) -> Decl | None:
        tok = self.next()
        if tok == "void":
            return None
        if tok == "unsigned":
            nxt = self.peek()
            if nxt in ("int", "hyper"):
                self.next()
                t = TypeRef("uint" if nxt == "int" else "uhyper")
            else:
                t = TypeRef("uint")
        elif tok in ("int", "hyper", "bool", "float", "double", "opaque", "string"):
            t = TypeRef(tok)
        elif tok in ("struct", "union", "enum"):
            self.body(tok)  # generated as a class of its own; the field's annotation names it
            t = TypeRef("inline")
        else:
            t = TypeRef("named", name=tok)
        if self.maybe("*"):
            t.optional = True
        name = self.next()
        if self.maybe("["):
            self.next()
            self.expect("]")
            if t.base not in ("opaque", "string"):
                t.array = "fixed"
        elif self.maybe("<"):
            if self.peek() != ">":
                self.next()
            self.expect(">")
            if t.base not in ("opaque", "string"):
                t.array = "var"
        return Decl(name, t)


def parse(text: str) -> Shape:
    p = _Parser(_tokens(text))
    s = p.definition()
    p.maybe(";")
    return s


# ---- pairing with the generated classes ---------------------------------------------------------------------

_SOURCE = "XDR Source Code::"
_cache: dict[type, Shape] = {}


def is_generated(obj: object) -> bool:
    """Is obj an instance of a generated XDR class (struct, union, typedef) or enum?"""
    cls = type(obj)
    return cls.__module__.startswith("stellar_sdk.xdr.") and _SOURCE in (cls.__doc__ or "")


def shape(cls: type) -> Shape:
    s = _cache.get(cls)
    if s is not None:
        return s
    doc = cls.__doc__ or ""
    i = doc.find(_SOURCE)
    if i < 0:
        raise SchemaError(f"{cls.__name__} has no XDR source text")
    s = parse(doc[i + len(_SOURCE):])
    if issubclass(cls, enum.Enum):
        if s.kind != "enum":
            raise SchemaError(f"{cls.__name__} is an enum class but its XDR is a {s.kind}")
        _cache[cls] = s
        return s
    params = [p for p in inspect.signature(cls.__init__).parameters][1:]
    if s.kind == "struct":
        decls = s.fields
    elif s.kind == "typedef":
        decls = [s.value]
    elif s.kind == "union":
        decls = [s.disc]
        seen = set()
        for c in s.cases:
            if c.decl is not None and c.decl.name not in seen:
                seen.add(c.decl.name)
                decls.append(c.decl)
    else:
        raise SchemaError(f"{cls.__name__}: {s.kind} is not a class shape")
    if len(decls) != len(params):
        raise SchemaError(f"{cls.__name__}: {len(decls)} XDR declarations, {len(params)} constructor parameters")
    by_name = {}
    for d, p in zip(decls, params):
        d.attr = p
        by_name[d.name] = p
    if s.kind == "union":
        for c in s.cases:
            if c.decl is not None:
                c.decl.attr = by_name[c.decl.name]
    _cache[cls] = s
    return s


def union_case(s: Shape, disc: object) -> Case | None:
    """The case of a union a discriminant value selects: labels are enum member names or numbers."""
    name = disc.name if isinstance(disc, enum.Enum) else None
    value = int(disc) if isinstance(disc, int) else None
    default = None
    for c in s.cases:
        for label in c.labels:
            if label == "default":
                default = c
            elif name is not None and label == name:
                return c
            elif value is not None and re.fullmatch(r"-?(0x[0-9A-Fa-f]+|[0-9]+)", label) and int(label, 0) == value:
                return c
    return default
