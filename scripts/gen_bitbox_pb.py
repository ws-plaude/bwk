#!/usr/bin/env python3
"""Rewrite the prost-generated BitBox protobuf module into plain Rust.

The prost attributes carry every field number and wire type, so this reads them
and emits the same types with encode/decode written against `crate::pb_codec`.
Nothing has to run a proc macro at build time.

Usage: scripts/gen_bitbox_pb.py <prost_source.rs> <output.rs>
"""
import re
import sys

FIELD = re.compile(r'pub (?P<name>(?:r#)?[A-Za-z_][A-Za-z0-9_]*): (?P<ty>.+),$')
VARIANT = re.compile(r'(?P<name>[A-Za-z_][A-Za-z0-9_]*)\((?P<ty>.+)\),$')
ENUM_VARIANT = re.compile(r'(?P<name>[A-Za-z_][A-Za-z0-9_]*) = (?P<value>-?\d+),$')

VARINT = {"uint32", "uint64", "int32", "bool", "enumeration"}


def _split_outside_quotes(spec):
    """Split an attribute spec on commas, ignoring those inside `tags = "2, 3"`."""
    parts, current, in_str = [], "", False
    for c in spec:
        if c == '"':
            in_str = not in_str
            current += c
        elif c == "," and not in_str:
            parts.append(current.strip())
            current = ""
        else:
            current += c
    if current.strip():
        parts.append(current.strip())
    return parts


class Field:
    def __init__(self, spec, name, ty):
        self.name = name
        self.ty = ty
        parts = _split_outside_quotes(spec)
        self.repeated = "repeated" in parts
        self.optional = "optional" in parts
        self.boxed = "boxed" in parts
        self.unit = ty == "()"
        self.kind = None
        self.tag = None
        self.tags = []
        self.oneof = None
        for p in parts:
            if p.startswith("tag ="):
                self.tag = int(p.split('"')[1])
            elif p.startswith("tags ="):
                self.tags = [int(t) for t in p.split('"')[1].split(",")]
            elif p.startswith("oneof ="):
                self.oneof = p.split('"')[1]
                self.kind = "oneof"
            elif p.startswith("enumeration ="):
                self.kind = "enumeration"
            elif p.startswith("bytes"):
                self.kind = "bytes"
            elif p in ("string", "uint32", "uint64", "int32", "bool", "message"):
                self.kind = p


def clean_ty(ty):
    return (ty.replace("::prost::alloc::vec::Vec", "Vec")
              .replace("::prost::alloc::string::String", "String")
              .replace("::prost::alloc::boxed::Box", "Box")
              .replace("::core::option::Option", "Option"))


def brace_delta(line):
    """Brace balance of a line, ignoring string bodies."""
    depth, in_str, esc = 0, False, False
    for c in line:
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            continue
        if c == '"':
            in_str = True
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
    return depth


def collect_bracketed(lines, start, opener="{", closer="}"):
    """Collect an item spanning balanced delimiters; return (lines, index after)."""
    depth, j, item = 0, start, []
    while j < len(lines):
        depth += lines[j].count(opener) - lines[j].count(closer)
        item.append(lines[j])
        j += 1
        if depth <= 0 and item[-1].strip():
            break
    return item, j


def parse(src):
    """Return (messages, oneofs, enums, output_lines).

    Module membership is tracked by brace depth: `pub mod X {` pushes X, popped
    once the depth returns to what it was before the module opened.
    """
    lines = src.split("\n")
    messages, oneofs, enums = [], [], []
    out, i = [], 0
    mods, depth = [], 0

    def indent_of(line):
        return line[: len(line) - len(line.lstrip())]

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if stripped.startswith("//"):
            out.append(line)
            i += 1
            continue

        if stripped.startswith("#[derive("):
            block, j = collect_bracketed(lines, i, "(", ")")
            derive = "\n".join(block)
            keeps = [d for d in ("Clone", "Copy", "PartialEq", "Eq", "Hash", "PartialOrd", "Ord")
                     if re.search(rf"\b{d}\b", derive)]
            pad = indent_of(block[0])
            path = [m[0] for m in mods]

            if "::prost::Message" in derive or "::prost::Oneof" in derive:
                item, after = collect_bracketed(lines, j)
                is_msg = "::prost::Message" in derive
                parsed = (_parse_message(item, path, keeps) if is_msg
                          else _parse_oneof(item, path, keeps))
                parsed["indent"] = pad
                (messages if is_msg else oneofs).append(parsed)
                out.append(("MESSAGE" if is_msg else "ONEOF", parsed))
                for k in range(i, after):
                    depth += brace_delta(lines[k])
                i = after
                continue

            if "::prost::Enumeration" in derive:
                # keep the enum and its inherent impl verbatim, but record it so
                # the i32 conversions prost used to derive can be emitted
                # the enum is preceded by #[repr(i32)], which carries no braces
                k = j
                while k < len(lines) and "pub enum" not in lines[k]:
                    k += 1
                item, _ = collect_bracketed(lines, k)
                enums.append(_parse_enum(item, path))
                out.append(pad + "#[derive(" + ", ".join(keeps + ["Debug"]) + ")]")
                for k in range(i, j):
                    depth += brace_delta(lines[k])
                i = j
                continue

            out.append(derive)
            for k in range(i, j):
                depth += brace_delta(lines[k])
            i = j
            continue

        m = re.match(r"\s*pub mod (\w+) \{", line)
        if m:
            mods.append((m.group(1), depth))
            depth += brace_delta(line)
            out.append(clean_ty(line))
            i += 1
            continue

        depth += brace_delta(line)
        while mods and depth <= mods[-1][1]:
            mods.pop()
        out.append(clean_ty(line))
        i += 1

    return messages, oneofs, enums, out


def _join_wrapped(lines):
    """rustfmt wraps long field declarations over several lines; put them back."""
    out, i = [], 0
    while i < len(lines):
        line = lines[i]
        if re.match(r"\s*pub (?:r#)?\w+:", line) and not line.rstrip().endswith(","):
            merged = line.rstrip()
            i += 1
            while i < len(lines):
                merged += " " + lines[i].strip()
                i += 1
                if merged.endswith(",") and merged.count("<") == merged.count(">"):
                    break
            out.append(re.sub(r"\s*,\s*>", ">", merged))
            continue
        out.append(line)
        i += 1
    return out


def _fields_from(item, matcher):
    """Pair each (possibly wrapped) #[prost(..)] attribute with the item below it."""
    lines = _join_wrapped("\n".join(item).split("\n"))
    found, pending, i = [], None, 0
    while i < len(lines):
        s = lines[i].strip()
        if s.startswith("#[prost("):
            attr, j = collect_bracketed(lines, i, "(", ")")
            spec = " ".join(a.strip() for a in attr)
            spec = spec[spec.index("(") + 1: spec.rindex(")")]
            pending = spec
            i = j
            continue
        m = matcher.match(s)
        if m and pending is not None:
            found.append(Field(pending, m.group("name"), clean_ty(m.group("ty"))))
            pending = None
        i += 1
    return found


def _parse_message(item, path, keeps):
    return {"name": re.search(r"pub struct (\w+)", item[0]).group(1), "path": list(path),
            "fields": _fields_from(item, FIELD), "keeps": keeps, "kind": "message"}


def _parse_oneof(item, path, keeps):
    return {"name": re.search(r"pub enum (\w+)", item[0]).group(1), "path": list(path),
            "variants": _fields_from(item, VARIANT), "keeps": keeps, "kind": "oneof"}


def _parse_enum(item, path):
    variants = []
    for line in item:
        m = ENUM_VARIANT.match(line.strip())
        if m:
            variants.append((m.group("name"), int(m.group("value"))))
    return {"name": re.search(r"pub enum (\w+)", item[0]).group(1),
            "path": list(path), "variants": variants}


def qual(item):
    return "::".join(item["path"] + [item["name"]])


def render_struct(m):
    keeps = m["keeps"] + ["Debug", "Default"]
    pad = m.get("indent", "")
    lines = [f"{pad}#[derive({', '.join(keeps)})]", f"{pad}pub struct {m['name']} {{"]
    for f in m["fields"]:
        lines.append(f"{pad}    pub {f.name}: {f.ty},")
    lines.append(pad + "}")
    return "\n".join(lines)


def render_oneof(o):
    keeps = o["keeps"] + ["Debug"]
    pad = o.get("indent", "")
    lines = [f"{pad}#[derive({', '.join(keeps)})]", f"{pad}pub enum {o['name']} {{"]
    for v in o["variants"]:
        lines.append(f"{pad}    {v.name}({v.ty}),")
    lines.append(pad + "}")
    return "\n".join(lines)


def encode_one(kind, tag, expr, boxed=False):
    """Emit the encode call for a single (already dereferenced) value."""
    if kind in ("uint32", "uint64"):
        return f"crate::pb_codec::encode_varint_field({tag}, {expr} as u64, buf);"
    if kind in ("int32", "enumeration"):
        return f"crate::pb_codec::encode_varint_field({tag}, {expr} as i64 as u64, buf);"
    if kind == "bool":
        return f"crate::pb_codec::encode_varint_field({tag}, u64::from({expr}), buf);"
    if kind == "string":
        return f"crate::pb_codec::encode_bytes_field({tag}, {expr}.as_bytes(), buf);"
    if kind == "bytes":
        return f"crate::pb_codec::encode_bytes_field({tag}, {expr}, buf);"
    if kind == "message":
        return f"crate::pb_codec::encode_message_field({tag}, {'&**' if boxed else ''}{expr}, buf);"
    raise SystemExit(f"unhandled encode kind {kind}")


def render_encode(m):
    body = []
    # prost emits fields in tag order, not declaration order; a oneof sits at
    # the lowest tag it can carry. Match that so the bytes are identical.
    fields = sorted(m["fields"], key=lambda f: min(f.tags) if f.kind == "oneof" else f.tag)
    for f in fields:
        t = f.tag
        if f.kind == "oneof":
            body += [f"        if let Some(v) = &self.{f.name} {{",
                     "            v.encode_raw(buf);",
                     "        }"]
        elif f.repeated:
            if f.kind in VARINT:
                body += [f"        if !self.{f.name}.is_empty() {{",
                         f"            crate::pb_codec::encode_packed_varints({t}, self.{f.name}.iter().map(|v| *v as u64), buf);",
                         "        }"]
            else:
                body += [f"        for v in &self.{f.name} {{",
                         f"            {encode_one(f.kind, t, 'v')}",
                         "        }"]
        elif f.optional or f.kind == "message":
            expr = "v" if f.kind in ("message", "bytes", "string") else "*v"
            body += [f"        if let Some(v) = &self.{f.name} {{",
                     f"            {encode_one(f.kind, t, expr, boxed=f.boxed)}",
                     "        }"]
        else:
            cond = {
                "bool": f"self.{f.name}",
                "string": f"!self.{f.name}.is_empty()",
                "bytes": f"!self.{f.name}.is_empty()",
            }.get(f.kind, f"self.{f.name} != 0")
            expr = f"&self.{f.name}" if f.kind == "bytes" else f"self.{f.name}"
            body += [f"        if {cond} {{",
                     f"            {encode_one(f.kind, t, expr)}",
                     "        }"]
    return "\n".join(body)


DECODE_SCALAR = {
    "uint32": "crate::pb_codec::decode_varint(buf)? as u32",
    "uint64": "crate::pb_codec::decode_varint(buf)?",
    "int32": "crate::pb_codec::decode_varint(buf)? as i32",
    "enumeration": "crate::pb_codec::decode_varint(buf)? as i32",
    "bool": "crate::pb_codec::decode_varint(buf)? != 0",
    "string": "crate::pb_codec::decode_string(buf)?",
    "bytes": "crate::pb_codec::decode_bytes(buf)?",
}


def render_merge(m):
    arms = []
    for f in m["fields"]:
        if f.kind == "oneof":
            # the attribute path is relative to the module holding the message
            path = "::".join(m["path"] + [f.oneof])
            tags = " | ".join(str(t) for t in f.tags)
            arms.append(f"            {tags} => {path}::merge(&mut self.{f.name}, tag, wire, buf)?,")
            continue
        t = f.tag
        if f.repeated:
            if f.kind in VARINT:
                arms.append(f"            {t} => crate::pb_codec::merge_packed_varints(wire, buf, &mut self.{f.name}, |v| v as u32)?,")
            elif f.kind == "message":
                arms.append(f"            {t} => self.{f.name}.push(crate::pb_codec::decode_message(buf)?),")
            elif f.kind == "bytes":
                arms.append(f"            {t} => self.{f.name}.push(crate::pb_codec::decode_bytes(buf)?),")
            else:
                raise SystemExit(f"unhandled repeated kind {f.kind}")
        elif f.kind == "message":
            inner = ("Box::new(crate::pb_codec::decode_message(buf)?)" if f.boxed
                     else "crate::pb_codec::decode_message(buf)?")
            arms.append(f"            {t} => self.{f.name} = Some({inner}),")
        elif f.optional:
            arms.append(f"            {t} => self.{f.name} = Some({DECODE_SCALAR[f.kind]}),")
        else:
            arms.append(f"            {t} => self.{f.name} = {DECODE_SCALAR[f.kind]},")
    arms.append("            _ => crate::pb_codec::skip_field(wire, buf)?,")
    return "\n".join(arms)


def render_message_impl(m):
    encode = render_encode(m)
    buf_param = "buf" if encode else "_buf"
    return f"""impl crate::pb_codec::Message for {qual(m)} {{
    fn encode_raw(&self, {buf_param}: &mut Vec<u8>) {{
{encode}
    }}

    fn merge_field(
        &mut self,
        tag: u32,
        wire: u8,
        buf: &mut &[u8],
    ) -> Result<(), crate::pb_codec::DecodeError> {{
        match tag {{
{render_merge(m)}
        }}
        Ok(())
    }}
}}"""


def render_oneof_impl(o):
    q = qual(o)
    enc, mrg = [], []
    for v in o["variants"]:
        t = v.tag
        if v.unit:
            # an empty message: a zero-length length-delimited field
            enc.append(f"            {q}::{v.name}(()) => crate::pb_codec::encode_bytes_field({t}, &[], buf),")
            mrg.append(f"            {t} => {{ crate::pb_codec::decode_bytes(buf)?; *field = Some({q}::{v.name}(())); }}")
            continue
        if v.kind == "message":
            enc.append(f"            {q}::{v.name}(v) => crate::pb_codec::encode_message_field({t}, v, buf),")
            mrg.append(f"            {t} => *field = Some({q}::{v.name}(crate::pb_codec::decode_message(buf)?)),")
        elif v.kind == "bytes":
            enc.append(f"            {q}::{v.name}(v) => crate::pb_codec::encode_bytes_field({t}, v, buf),")
            mrg.append(f"            {t} => *field = Some({q}::{v.name}(crate::pb_codec::decode_bytes(buf)?)),")
        elif v.kind == "string":
            enc.append(f"            {q}::{v.name}(v) => crate::pb_codec::encode_bytes_field({t}, v.as_bytes(), buf),")
            mrg.append(f"            {t} => *field = Some({q}::{v.name}(crate::pb_codec::decode_string(buf)?)),")
        elif v.kind == "bool":
            enc.append(f"            {q}::{v.name}(v) => crate::pb_codec::encode_varint_field({t}, u64::from(*v), buf),")
            mrg.append(f"            {t} => *field = Some({q}::{v.name}(crate::pb_codec::decode_varint(buf)? != 0)),")
        elif v.kind in ("uint32", "uint64", "int32", "enumeration"):
            cast = {"uint32": "u32", "uint64": "u64", "int32": "i32", "enumeration": "i32"}[v.kind]
            as_u64 = "*v as u64" if v.kind in ("uint32", "uint64") else "*v as i64 as u64"
            enc.append(f"            {q}::{v.name}(v) => crate::pb_codec::encode_varint_field({t}, {as_u64}, buf),")
            mrg.append(f"            {t} => *field = Some({q}::{v.name}(crate::pb_codec::decode_varint(buf)? as {cast})),")
        else:
            raise SystemExit(f"unhandled oneof kind {v.kind}")
    return f"""impl {q} {{
    pub(crate) fn encode_raw(&self, buf: &mut Vec<u8>) {{
        match self {{
{chr(10).join(enc)}
        }}
    }}

    pub(crate) fn merge(
        field: &mut Option<{q}>,
        tag: u32,
        wire: u8,
        buf: &mut &[u8],
    ) -> Result<(), crate::pb_codec::DecodeError> {{
        match tag {{
{chr(10).join(mrg)}
            _ => crate::pb_codec::skip_field(wire, buf)?,
        }}
        Ok(())
    }}
}}"""


def render_enum_impl(e):
    q = qual(e)
    arms = "\n".join(f"            {v} => Ok({q}::{n})," for n, v in e["variants"])
    return f"""impl From<{q}> for i32 {{
    fn from(value: {q}) -> i32 {{
        value as i32
    }}
}}

impl TryFrom<i32> for {q} {{
    type Error = crate::pb_codec::UnknownEnumValue;

    fn try_from(value: i32) -> Result<Self, Self::Error> {{
        match value {{
{arms}
            _ => Err(crate::pb_codec::UnknownEnumValue(value)),
        }}
    }}
}}"""


def main():
    src = open(sys.argv[1]).read()
    messages, oneofs, enums, out = parse(src)

    body = []
    for entry in out:
        if isinstance(entry, tuple):
            kind, item = entry
            body.append(render_struct(item) if kind == "MESSAGE" else render_oneof(item))
        else:
            body.append(entry)

    impls = ([render_message_impl(m) for m in messages]
             + [render_oneof_impl(o) for o in oneofs]
             + [render_enum_impl(e) for e in enums])

    header = (
        "// Generated by scripts/gen_bitbox_pb.py from the BitBox protobuf schema.\n"
        "// Do not edit by hand; re-run the script instead.\n"
    )
    open(sys.argv[2], "w").write(header + "\n".join(body) + "\n\n" + "\n\n".join(impls) + "\n")
    print(f"{len(messages)} messages, {len(oneofs)} oneofs, {len(enums)} enums")


if __name__ == "__main__":
    main()
