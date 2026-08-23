# bwk-qr: design plan

The QR feature spans two crates of the `bwk` workspace: `bwk-qr` (`bwk/qr/`) and
`bwk-qr-protocol` (`bwk/qr-protocol/`). It has **two goals**:

1. **QR generation and scanning** behind two traits. `bwk-qr` declares
   `gen::Generator` and `scan::Scanner`, implements them over `qrcodegen` (Project
   Nayuki's own Rust port) and `quircs` (a `quirc` port), and drives them with the
   rest of the transport: the rasterization policy, BBQR framing and the
   `Encoder`/`Decoder` orchestration.
2. **Implement the QR-based signing-flow protocol** for the miniscript context
   specified in [`ENCODING.md`](../qr-protocol/ENCODING.md): the request/response
   payloads (Get Xpubs, Register Descriptor, Address Verification, Signing),
   serialized with our own hand-rolled, versioned binary encoding and chunked across
   animated QR frames using BBQR generic-binary framing.

The two goals are layered and independently usable: a consumer takes `bwk-qr` with
`gen` alone and calls `Encoder::encode_text` for a plain QR, `gen` and `scan` for the
framed transport whatever the payload is, and `protocol` for the signing flow. The
first consumer is the Silent wallet, which reaches `bwk-qr` through Silent's existing
CXX (C++ <-> Rust) bridge. A C signer takes `bwk-qr-protocol` alone and frames the
bytes with its own QR code (section 9.2).

> Status: both crates are implemented. `bwk-qr-protocol` carries the codec and its C
> binding; `bwk-qr` carries the transport, the two traits and their backends. The
> wire magic still uses `BIPXXX` until a BIP number is assigned.

---

## 1. Scope

### In scope
- Goal 1: the two backend seams (text -> QR modules, frame -> payloads) with one
  implementation each over the pure-Rust `qrcodegen` and `quircs`, plus the
  transport that drives them (`Image`, `Config`, rasterization, BBQR).
- Goal 2: typed protocol messages for the four payload pairs; our own versioned
  binary wire format; BBQR framing/reassembly; a streaming
  decoder for animated multi-part scans; a C binding over the codec, so a signer
  with no Rust still gets the message layer.

### Out of scope
- No camera capture, windowing, or UI. The consumer owns capture and rendering.
- No signing, PSBT finalization, or descriptor evaluation. The protocol layer
  *carries* PSBTs/descriptors; their semantics live in the consumer (Silent's
  `account.rs` / `bwk-sp`, or a hardware device).
- No UR (`ur:...`) framing in v1. BBQR is the chosen multi-part format.
- No async, no threads, no global state. The only stateful type is the decoder,
  which holds the BBQR joiner.

### A note on the protocol's maturity
The protocol is an explicit **draft**. `bwk-qr-protocol` defines its own wire format
(section 4.2) and `bwk-qr` its framing (BBQR); the authoritative byte-level contract
is `ENCODING.md`. The format carries a version and is append-only, so it can evolve
without an external schema and stay independent of any third-party serialization.
New fields are added by appending (see the candidates listed in `ENCODING.md`).

---

## 2. Design principles

**Layer 1 (the QR transport) is dependency-minimal and firm:**
1. Pure Rust: generation via `qrcodegen` (Nayuki's own port, **zero dependencies**),
   scanning via `quircs` (a faithful `quirc` port). No vendored C, no FFI, no `cc`,
   no system libs, no submodules.
2. No `unsafe` in `bwk-qr`. The only `unsafe` is `bwk-qr-protocol`'s C binding,
   behind the `ffi` feature.
3. The `gen` feature adds a **zero-dependency** crate. The `scan` feature adds only
   `quircs` and its small tree (`num-derive`, `num-traits`, `thiserror`); no `image`
   at runtime. `thiserror` is there either way, since `bwk-qr` is `std` and its
   errors use it. Both are on by default, so a consumer that wants generation alone
   builds with `--no-default-features --features gen`.
4. Both libraries are 1:1 ports of the C ones first considered, so behaviour is on
   par: multi-code-per-frame is preserved; inverted (white-on-black) QRs are not
   auto-detected, so the pipeline inverts and rescans when `scan_inverted` is set.

**Layer 2 (the protocol) stays independent too:**
5. The wire encoding is **hand-rolled binary**, defined here. No `serde`, no CBOR,
   no external serialization crate. We own the byte layout and the versioning.
6. `bwk-qr` depends on `bwk-qr-protocol` only behind its `protocol` feature, and the
   transport carries any payload, so a consumer framing another protocol over QR
   never pulls the codec in. The codec carries `Psbt`, `Xpub`, `Fingerprint` and
   `DerivationPath` as their byte serializations rather than as `bitcoin` types, so
   only `protocol` turns the adapters on and a generation-only consumer leaves them
   off. Descriptors are carried as validated strings (the device parses them), so no
   `miniscript` dependency either.

**Both layers:** portable across the targets Silent ships (Linux, Windows/mingw,
macOS x86_64/arm64) under the existing Nix toolchain, with no per-target C tweaks.

---

## 3. Goal 1: the QR backends and the pipeline they plug into

### 3.1 Crates
- **Generation, `qrcodegen` 1.8.0** (MIT): Nayuki's own Rust port, **zero runtime
  dependencies**. `QrCode::encode_segments_advanced` for every symbol, at a free or
  a pinned version; `get_module(x, y) -> bool` and `size() -> i32` to fill the
  module matrix. Behind `bwk-qr`'s `gen` feature.
- **Scanning, `quircs` 0.10.3** (MIT): a faithful `quirc` port.
  `Quirc::identify(width, height, &[u8])` consumes a raw 8-bit grayscale frame (no
  `image` crate) and yields an iterator of codes; `Code::decode()` returns the
  payload as `Vec<u8>`, so binary content is preserved. Adds `num-derive`,
  `num-traits`, `thiserror`. Behind `bwk-qr`'s `scan` feature.

Both are 1:1 ports of the C libraries first considered (Nayuki qrcodegen, quirc), so
behaviour parity is high. Neither pulls `image`, `nalgebra`, or a C toolchain. BBQR
generic-binary framing is implemented in `bwk-qr` because the published `bbqr` crate
does not expose the generic binary file type.

### 3.2 Implementation notes
- **Generation:** qrcodegen returns an owned `QrCode`; `Qrcodegen::generate` copies
  its modules (`get_module`) into a `gen::Modules` matrix and stops there. Turning
  that matrix into a grayscale raster is `Modules::render`'s job, one layer down.
  A plain payload takes the smallest version that fits within
  `Config::max_qr_version`; a BBQR part is pinned at `max_qr_version` so every
  animated frame renders at the same size. Payloads too large for one code are
  chunked at the BBQR layer, not here. `DataTooLong` -> `gen::Error::TooLong`.
- **Scanning:** `Decoder::process` checks `data.len() == width * height` and the
  `max_image_pixels` bound before the scanner sees the frame, and answers
  `Error::BadFrame` otherwise, so a backend never gets an inconsistent one.
  `Quircs::scan` feeds it to `Quirc::identify` and returns the raw payload of every
  `Code` that decodes; a candidate that does not is skipped, since a camera frame
  routinely holds partial or blurred codes. quircs does not auto-detect inverted
  (white-on-black) frames, so with `Config::scan_inverted` the pipeline inverts the
  buffer, rescans and drops the payloads it already had.

### 3.3 The two backend seams

The seams sit in `bwk-qr`, next to the two implementations and the pipeline they
plug into. A caller with another QR library implements them and builds an
`Encoder`/`Decoder` over it; `bwk-qr-protocol` stays a codec and knows nothing of QR.

```rust
// bwk_qr::gen
pub enum Correction { Low, Medium, Quartile, High }
pub struct Params {
    pub min_version: u8, pub max_version: u8,
    pub correction: Correction, pub boost_correction: bool,
}
pub struct Modules { /* size: u16, dark: Vec<bool>, both private */ }
impl Modules {
    pub fn new(size: u16, dark: Vec<bool>) -> Result<Self, Error>;
    pub fn size(&self) -> u16;
    pub fn is_dark(&self, x: u16, y: u16) -> bool;
    pub fn render(&self) -> Image;
}
pub trait Generator {
    fn generate(&self, text: &str, params: Params) -> Result<Modules, Error>;
}
pub fn is_alphanumeric(text: &str) -> bool;

// bwk_qr::scan
pub struct Frame<'a> { pub data: &'a [u8], pub width: u32, pub height: u32 }
pub trait Scanner {
    fn scan(&mut self, frame: Frame<'_>) -> Result<Vec<Vec<u8>>, Error>;
}
```

A generator returns the bit matrix, not an `Image`. Rasterization is pure policy
(`QUIET_ZONE = 4`, `MODULE_SCALE = 4`, dark `0`, light `255`) and stays below the
seam, in `Modules::render`, so "an `Encoder` frame is readable by a `Decoder`" is an
invariant of the pipeline rather than of each implementation: a backend rendering at
scale 1 would otherwise produce frames nothing can scan. `Modules::new` validates the
size against `MAX_MODULES` and the run length against `size * size`, so a backend
that misreports its matrix gets an error rather than an out-of-bounds read.

One `Params` covers both modes: `encode_text` asks for `1..=max_qr_version` with
boosting on, a BBQR part for `max_qr_version` pinned with boosting off. There is no
segment-mode field, since a BBQR part is alphanumeric by construction and `Encoder`
checks that with `gen::is_alphanumeric` before it calls the backend at all.

A scanner returns raw payloads. The pipeline bounds the frame first, dedupes across
the inverted rescan, and decides what is a BBQR part and what is plain text, so a
backend holds no state of its own. `Scanner` takes `&mut self` so an implementation
may reuse a scan buffer across frames; `Generator` takes `&self`.

`Image` is an 8-bit grayscale raster, row-major, `width * height` bytes: a camera
frame in, a QR frame out. It is the single raw-data type crossing the API in both
directions.

---

## 4. Goal 2: the signing-flow protocol

### 4.1 Payload model (from ENCODING.md)
Four request/response pairs. Software wallet -> device for all requests. Field
names mirror ENCODING.md; the leaf types are the byte-level ones from
`qr-protocol/src/types.rs`, with `bitcoin` adapters behind a feature.

1. **Get Xpubs**
   - Request: `derivation_paths: Vec<DerivationPath>`
   - Response: `xpubs: Vec<Xpub>` (78 bytes each, order matches request), `fingerprint:
     Fingerprint`, `model: String` (16-byte NUL-padded), `version: Version { major:
     u16, minor: u16, patch: u32, flag: ReleaseFlag }`, `capabilities: Capabilities`
     (32-bit flags). All mandatory.
2. **Register Descriptor**
   - Request: `descriptor_alias: String`, `descriptor: Option<DescriptorBody>`
     (absent = status query); `DescriptorBody` is a `FORM` (BIP-380 descriptor, or
     BIP-388 wallet policy = keys vector + policy template) plus its body
   - Response: `descriptor_alias: String`, `registered: Option<bool>`,
     `stored: Option<bool>` (device persisted the descriptor under the alias, so
     later requests may reference it by alias alone; absent means the device does
     not report it and the wallet must assume it did not), `por: Option<Vec<u8>>`
     (proof of registration). A failed registration is an error response, not a
     body field.
3. **Address Verification**
   - Request: `descriptor_alias: String`, `deriv: DerivationPath`,
     `address: Option<String>`, `descriptor: Option<DescriptorBody>`,
     `por: Option<Vec<u8>>`
   - Response: `uri: Option<String>` (BIP-21)
4. **Signing**
   - Request: `descriptors: Vec<Descriptor { alias: String, body: DescriptorBody,
     por: Option<Vec<u8>> }>`, `psbt: Vec<u8>` (BIP-174), `want_kind: Option<Kind>`
   - Response (either `Kind`):
     - `Psbt(Vec<u8>)`, full PSBT with partial sigs and, for silent-payment sends, the
       BIP-375 shares/proofs and derived output scripts, or
     - `Signatures(Vec<SignatureEntry>)`. `SignatureEntry` carries the key material
       the coordinator needs to place the signature in its PSBT, so its fields depend
       on the kind: `Ecdsa { input, public_key, signature }`, `TapKey { input,
       signature }`, `TapScript { input, xonly_public_key, tap_leaf_hash, signature
       }`. No control block is sent, the coordinator rebuilds it from the descriptor
       at finalize time. A silent-payment send has no signatures-only form, so the
       signer answers it with the `Psbt` variant whatever `want_kind` asked for

Modeled in Rust as a request id paired with a body enum, plus the payload structs:
```rust
// lib.rs
pub struct RequestId(pub [u8; 16]);
pub struct Request  { pub id: RequestId, pub body: request::Body }
pub struct Response { pub id: RequestId, pub body: response::Body }

// request.rs
pub enum Body { GetXpubs(..), RegisterDescriptor(..), VerifyAddress(..), Sign(..) }

// response.rs
pub enum Body {
    Xpubs(..), Registration(..), AddressUri(..), Signed(..), Error(ErrorBody)
}
```
The responder echoes the request id, so a wallet can pair a response with the
request it sent. `response::Body::Error` encodes with the `STATUS` bit set and the
standard error body (`ENCODING.md`); the ok variants encode with `STATUS` = 0.
`ErrorCode` is typed: the eleven standard codes, `Vendor` (always `0xFF`, meaning
carried by the message), and `Unknown(u8)` for a code reserved for a future
version, which decodes and re-encodes unchanged so an older parser never rejects
a newer signer's code.

### 4.2 Wire format (hand-rolled, versioned, append-only)

We define our own binary encoding. It is independent (no serialization crate),
compact, and forward/backward compatible by construction. **`ENCODING.md` is the
authoritative, transport-agnostic byte-level contract**; this section is only a
design summary, so any discrepancy resolves in favor of `ENCODING.md`.

In brief (full detail in `ENCODING.md`):
- A message is `MAGIC` (ASCII "BIPXXX") + `VERSION` (1 byte) + `MSG_TYPE` (1 byte)
  + `REQUEST_ID` (16 opaque bytes, echoed by the responder) + a per-type `BODY`.
- `MSG_TYPE` packs `DIRECTION` (bit 7) | `STATUS` (bit 6, ok/error) | `TYPE` (bits
  5-0). An error response (`STATUS` = 1) carries the standard error body: a 1-byte
  `ERROR` (global table, `0xFF` vendor-specific) + a 32-byte NUL-padded
  `ERROR_MESSAGE`.
- Counts and lengths use compact size; fixed multi-byte integers are big-endian;
  optional fields use a 1-byte presence prefix; vectors use a compact-size count.
- Domain fields: `STRING`/`BYTES` (compact-size length + bytes), `FINGERPRINT` (4),
  `XPUB` (78, BIP-32), `PSBT` (BIP-174 bytes), `DERIVATION_PATH` (1-byte child count
  + 4-byte big-endian children), `MODEL` (16-byte NUL-padded), `VERSION` (8-byte
  semver), `CAPABILITIES` (4-byte bitfield), `DESCRIPTOR_BODY` (`FORM` + body).
- `BODY` is append-only: fields ordered by their introduction version; a decoder
  reads the fields it knows and ignores trailing bytes from newer versions. New
  versions may only append fields.

The message bodies, value tables (`TYPE`, `FORM`, `KIND`, `SIG_KIND`, error codes,
capability bits), the versioning and error rules, and worked byte examples are all in
`ENCODING.md`.

### 4.3 Framing: BBQR generic binary
`bwk_qr::bbqr` ships a small generic-binary BBQR subset using hex encoding and the
`B` file type because the published `bbqr` crate does not yet expose
`FileType::Binary`. Raw PSBT framing can be added once a fixed upstream or pinned
fork is available.

Reassembly accepts shuffled frames, rejects conflicting duplicates, and hands the
joined bytes back as `Decoded::Bytes` without looking at them. Completing a message
clears the reassembly state, so the same `Decoder` can take the next message
straight away.

### 4.4 External API

`Config` plus a generic encoder and decoder, in `bwk_qr`. Rust callers get `Result`
and typed decoded values.

```rust
#[derive(Debug, Clone)]
pub struct Config { pub max_qr_version: u8, /* part size, scan bounds, ... */ }
impl Default for Config { /* sane density defaults */ }

// Build the frames for a payload.
pub struct Encoder<G> { /* ... */ }
impl<G: Generator> Encoder<G> {
    pub fn with_generator(cfg: Config, generator: G) -> Result<Self, Error>;
    pub fn encode_text(&self, s: &str) -> Result<Image, Error>;
    pub fn encode_bytes(&self, data: &[u8]) -> Result<Vec<Image>, Error>;
    // feature protocol
    pub fn encode_request(&self, req: &Request) -> Result<Vec<Image>, Error>;
    pub fn encode_response(&self, res: &Response) -> Result<Vec<Image>, Error>;
}
impl<G: Generator + Default> Encoder<G> {
    pub fn new(cfg: Config) -> Result<Self, Error>;
}

// Feed grayscale camera frames; scans QR -> reassembles BBQR -> yields Decoded.
pub struct Decoder<S> { /* ... */ }
impl<S: Scanner> Decoder<S> {
    pub fn with_scanner(cfg: Config, scanner: S) -> Result<Self, Error>;
    pub fn config(&self) -> &Config;
    pub fn process(&mut self, frame: &Image) -> Result<Vec<Decoded>, Error>;
    pub fn progress(&self) -> Option<Progress>;
    pub fn reset(&mut self);
}
impl<S: Scanner + Default> Decoder<S> {
    pub fn new(cfg: Config) -> Result<Self, Error>;
}
```

The crate root binds both to its own backends as
`type Encoder = encoder::Encoder<gen::Qrcodegen>` and
`type Decoder = decoder::Decoder<scan::Quircs>`, so a Rust caller writes
`Encoder::new(Config::default())` and never names a backend. `with_generator` and
`with_scanner` are for a backend with no `Default`, which is what the test fakes are.

`encode_bytes` returns one `Image` per animated frame, ready to blit, and dims travel
with each `Image`. `Decoder::process` takes one grayscale camera frame and returns
`Decoded::Text` for a plain QR or `Decoded::Bytes` for a reassembled payload; the
transport never parses what it carries, so the caller decodes those bytes with
whichever codec it speaks. Use `encode_text` for plain address QRs and, with
`protocol`, `encode_request`/`encode_response` for signing-flow messages.

---

## 5. Crate layout

The codec lives in its own crate so a bare-metal signer can take it without a QR
library, and so a consumer that already frames and scans on its own takes it alone.

```
bwk/qr/
  Cargo.toml
  PLAN.md            <- this file
  ROADMAP.md         <- the living checklist
  src/
    lib.rs           <- re-exports, the Encoder/Decoder aliases, crate docs
    image.rs         <- Image, the one raw-data type crossing the API
    config.rs        <- Config (QR density and scan bounds)
    gen.rs           <- Generator, Params, Modules, rasterization; Qrcodegen (gen)
    scan.rs          <- Scanner, Frame; Quircs                          (scan)
    bbqr.rs          <- BBQR generic-binary split/join
    encoder.rs       <- Encoder<G> (text, bytes and protocol -> frames)
    decoder.rs       <- Decoder<S> (frames -> Decoded, BBQR join)
    error.rs         <- Error, what a caller sees
  tests/
    plain.rs         <- plain text render -> scan round-trip
    gen.rs           <- generation known vectors
    scan.rs          <- render -> grayscale -> decode round-trip
    pipeline.rs      <- the orchestration over fake backends   (feature: protocol)
    protocol.rs      <- encode -> render -> scan -> reassemble  (feature: protocol)

bwk/qr-protocol/
  Cargo.toml
  ENCODING.md        <- the authoritative wire format
  include/
    bwk_qr_protocol.h  <- hand-written C header       (feature: ffi)
  examples/
    signer.c         <- hand-compiled C codec smoke test
  src/
    lib.rs           <- envelope types, Message, free encode/decode fns
    types.rs         <- the byte-level leaf types, plus bitcoin adapters
    request.rs       <- request payload structs (plain types, no serde)
    response.rs      <- response payload structs (plain types, no serde)
    reader.rs        <- byte cursor + compactsize
    encode.rs        <- hand-rolled binary encode
    decode.rs        <- hand-rolled binary decode + version rule
    ffi/             <- the C binding                 (feature: ffi)
      mod.rs         <- the four exported functions and the binding's own errors
      types.rs       <- #[repr(C)] mirrors of the message tree
      owned.rs       <- the handle backing a decoded request
      read.rs        <- reads a C response back into the Rust types
  tests/
    codec.rs         <- codec round-trip, version compat, rejection cases
    vectors.rs       <- the ENCODING.md test vectors, checked both directions
    ffi.rs           <- the C binding, over the #[repr(C)] types  (feature: ffi)
    layout.rs        <- pins the C layout so the header cannot drift
    *.json           <- the vectors themselves, one file per message group
```

---

## 6. Cargo manifests

```toml
# qr-protocol/Cargo.toml
[features]
default = []
bitcoin = ["dep:bitcoin"]
ffi     = []       # the C binding over the codec

[dependencies]
bitcoin = { workspace = true, optional = true }
```

```toml
# qr/Cargo.toml
[features]
default  = ["gen", "scan", "protocol"]
gen      = ["dep:qrcodegen"]             # zero-dependency generation
scan     = ["dep:quircs"]                # quirc port; adds num-* and thiserror
protocol = ["gen", "scan", "dep:bwk-qr-protocol"]

[dependencies]
bwk-qr-protocol = { workspace = true, features = ["bitcoin"], optional = true }
qrcodegen = { workspace = true, optional = true }
quircs    = { workspace = true, optional = true }
thiserror.workspace = true
```

- `bwk-qr-protocol` is optional because the transport is payload agnostic: with
  `--no-default-features --features gen,scan` the codec is not in the dependency
  graph, and a consumer frames whatever it speaks with `encode_bytes`.
- `protocol` implies `gen` and `scan` and turns the codec's `bitcoin` adapters on,
  which drag in `secp256k1-sys` and its vendored C, so the Silent Receive screen
  takes `gen` alone.
- `ffi` is a `bwk-qr-protocol` feature nothing in the workspace enables, since it
  exports `#[no_mangle]` symbols.
- No `serde`, no CBOR, no C toolchain, no build script on either side.
- A fixed `bbqr` release or pinned fork can replace the internal framing later.

---

## 7. Build

Both `qrcodegen` and `quircs` are pure Rust: no `build.rs`, no `cc`, no C toolchain.
The feature-gated optional deps keep unused code out (`gen` -> `qrcodegen`, `scan` ->
`quircs`, `protocol` -> `bwk-qr-protocol` and `bitcoin`). Cross-compilation to the
Silent targets is whatever `cargo` does for a pure-Rust crate, nothing
target-specific.

`bwk-qr-protocol` goes further: it is `no_std` plus `alloc` with no dependency in its
default configuration, and the `ffi` feature adds none, so the codec cross-compiles
to a bare-metal signer target. That is why it carries its own byte-level types
instead of the `bitcoin` ones, which would drag in `secp256k1-sys` and its vendored
C.

---

## 8. Errors

The two crates report failures differently, because one is `std` and the other is
not.

`bwk-qr` uses `thiserror` with interpolated messages: `gen::Error`, `scan::Error`,
`bbqr::Error`, and the crate-level `Error` a caller sees, which wraps those three
and, with `protocol`, the codec's `encode::Error`.

```rust
pub enum Error {
    BadFrame,                                   // length or pixel bound
    QrVersion(u8),                              // max_qr_version outside 1..=40
    ZeroPartSize,
    ZeroImageLimit,
    PartTooLarge { bytes: usize, version: u8 },
    PartNotAlphanumeric,
    Gen(gen::Error),
    Scan(scan::Error),
    Bbqr(bbqr::Error),
    Encode(encode::Error),                      // feature protocol
}
```

`bwk-qr-protocol` is `no_std`, where `thiserror` is unavailable, so each of its enums
lives next to the code that raises it and carries an `info() -> (i32, &'static str)`:
a stable numeric code and its message, the message ending in a nul so the C binding
hands out the very same literal. `Display` and `core::error::Error` come from
`error_display!`, a `macro_rules!` at the crate root that reads `info()`. Because the
message is a `&'static str` it never interpolates the variant's fields. The fields
stay for Rust callers to match on; only the printed text is fixed.

```
+-----------+---------------+---------------------------------------------+
| Code      | Enum          | Raised by                                   |
+-----------+---------------+---------------------------------------------+
| 100..=111 | reader::Error | the byte cursor                             |
| 200..=206 | decode::Error | wire decoding                               |
| 300..=307 | encode::Error | payload validation on encode                |
| 400..=407 | ffi::Error    | the C boundary itself                       |
+-----------+---------------+---------------------------------------------+
```

---

## 9. Consumer integration

### 9.1 Silent (existing CXX bridge)
C++ never links `bwk-qr` directly. Silent's `silent` crate depends on `bwk-qr`
and re-exposes a thin surface in its `#[cxx::bridge]` (`silent/src/lib.rs`, impl in
`account.rs`), per Silent's FFI rules (no `Result` across the bridge;
sentinel/empty returns). Planned surface (added per phase):
- `struct Image { data: Vec<u8>, width: u32, height: u32 }` + `fn qr_encode(data:
  &str) -> Image`, implemented via `Encoder::encode_text`; the Receive screen blits
  the raster.
- `fn qr_decode_grayscale(gray: &[u8], width: u32, height: u32) -> Vec<String>` for
  the camera scanner, implemented via a `Decoder` (`process` the frame).
- Signing-flow surface: build a `Sign` request -> `Encoder::encode_request` -> frames
  to animate; an opaque `Box<Decoder>` (`process`/`progress`) to
  reassemble the response; then `Account::broadcast_signed_psbt(psbt: Vec<u8>)`.

Each bwk change bumps the pinned `bwk` git `rev` in `silent/Cargo.toml`, refreshes
`Cargo.lock`, and updates `flake.lock` + the `importCargoLock` `outputHashes`.

### 9.2 A C signer
Firmware links `bwk-qr-protocol` (feature `ffi`) as an rlib from its own `staticlib`
crate, which supplies the global allocator and the panic handler a library cannot.
`include/bwk_qr_protocol.h` covers the signer direction: decode a request, encode a
response. Four functions do it, `bwk_qr_request_decode` with `bwk_qr_request_free`
and `bwk_qr_response_encode` with `bwk_qr_buf_free`. QR rendering, QR scanning and
BBQR framing stay on the firmware side, so no QR logic crosses the boundary and the
codec serves a consumer that speaks other protocols over the same C layer.

The library never frees consumer memory, and the consumer never frees library memory
except through the two `_free` functions; on encode the C struct is borrowed for the
duration of the call only. Nothing may panic: `no_std` has no unwinding, so a panic
would reach the firmware's handler instead of returning a code. The direction stays
signer-only: a response handed to `bwk_qr_request_decode` is rejected with 406. See
`qr-protocol/README.md` and `examples/signer.c`.

### 9.3 Other Rust callers
```rust
// plain QR (--no-default-features --features gen, only qrcodegen and thiserror):
use bwk_qr::{Config, Encoder};
let frame = Encoder::new(Config::default())?.encode_text("bc1q...")?;

// any payload, framed (--no-default-features --features gen,scan):
let frames = Encoder::new(Config::default())?.encode_bytes(&payload)?;

// the signing flow (default features):
let frames = Encoder::new(Config::default())?.encode_request(&req)?;
```

---

## 10. Testing

Each layer is tested where it lives.

- **The codec** (`qr-protocol/tests/`): `codec.rs` round-trips every message, checks
  version compatibility both ways (a v1 parser reads a synthetic newer blob and
  ignores its tail, a newer parser reads a v1 blob) and the rejection cases;
  `vectors.rs` replays the `ENCODING.md` vectors in both directions from the JSON
  files beside it.
- **The transport** (`qr/tests/pipeline.rs`): a fake generator and a fake scanner
  drive the orchestration with no rendering and no image decoding at all, which is
  also the only way to reach some of it. Out-of-order, duplicate and back-to-back
  messages, the progress counts, the `Params` each mode asks for, the constructor
  rejections (`QrVersion`, `ZeroPartSize`, `ZeroImageLimit`), `PartTooLarge` at
  encode time, the alphanumeric guard, `BadFrame` on both bounds, and the inverted
  rescan with its dedupe. `src/gen.rs` and `src/bbqr.rs` keep inline unit tests for
  rasterization and for the raw part strings (`B$`, generic binary file type `B`),
  neither of which is reachable from outside.
- **The backends** (`qr/tests/`): `gen.rs` pins the rendered size per version and the
  `Error::Gen(gen::Error::TooLong)` cap; `scan.rs` and `plain.rs` round-trip real
  rendering into real scanning, including inverted frames, a frame with no code and
  the pixel bound; `protocol.rs` round-trips every message pair through both
  backends, which is the regression guard for the whole stack.
- **The C binding** (`qr-protocol/tests/`, feature `ffi`): `ffi.rs` drives the four
  functions over the `#[repr(C)]` types, including the failure paths, so CI needs no
  C toolchain. `layout.rs` pins every size and alignment against the hand-written
  header. `examples/signer.c` is compiled by hand.
- Offline and deterministic. The workspace `cargo test --features test` misses the
  `ffi` feature, which nothing else turns on, so CI also runs
  `cargo clippy -p bwk-qr-protocol --all-targets --all-features` and
  `cargo test -p bwk-qr-protocol --all-features`. `bwk-qr` must not enable `ffi` to
  get that for free: the module exports `#[no_mangle]` symbols that have no business
  in every Rust binary linking `bwk-qr`.

---

## 11. Risks and open questions

- **Protocol is a draft.** Several fields are our choice; bump the wire `version`
  and only append fields. Add the candidates listed in `ENCODING.md` (spend-path
  selection, multi-descriptor registration) as new versions.
- **Wire-format spec discipline.** The append-only rule only holds if existing
  fields are never reordered or resized; enforce this in review. `qr-protocol/src/lib.rs`
  states the convention at the top: everything there is version 1, and a field added later
  is appended at the end of its body with a `// since vN` marker.
- **External BBQR implementation.** Replace the internal generic-binary subset only
  when a fixed release or pinned fork exposes the `B` file type and safe parsing.
- **`bitcoin` byte serializations.** Use stable forms (BIP-174 PSBT, 78-byte `Xpub`,
  4-byte `Fingerprint`); keep these out of the version-evolving region by treating
  them as opaque `bytes`/fixed fields. The codec models them exactly that way, which
  is what lets it drop the `bitcoin` dependency.
- **UR support** deferred; revisit if a target signer needs `ur:` instead of BBQR.
