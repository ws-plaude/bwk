# bwk-qr

`bwk-qr` is the QR transport: the `gen::Generator` and `scan::Scanner` traits, one
implementation each, BBQR framing and the `Encoder`/`Decoder` that drive them. The
payload is opaque to it, so a consumer frames whatever it speaks over the same
pipeline.

One implementation per seam:

- `Qrcodegen` implements `Generator` over `qrcodegen`, turning text into a QR
  module matrix. It does not rasterize: the quiet zone and the module scale live
  in `Modules::render`, so every backend renders frames a `Decoder` can read.
- `Quircs` implements `Scanner` over `quircs`, reading the QR symbols out of an
  8-bit grayscale frame. Candidates that fail to decode are skipped, since a
  camera frame routinely holds blurred or partial ones.

`Encoder` and `Decoder` are type aliases binding the pipeline to those two, so a
caller never names them. `Encoder::with_generator` and `Decoder::with_scanner`
take another QR library instead.

`Decoder::process` answers `Decoded::Text` for a plain QR and `Decoded::Bytes` for
a reassembled BBQR payload. The transport does not know what the bytes carry, so
the caller hands them to whichever codec it speaks.

Features:

- `gen` pulls `qrcodegen` and enables `Encoder`.
- `scan` pulls `quircs` and enables `Decoder`.
- `protocol` implies both and pulls `bwk-qr-protocol` for the signing flow: the
  `protocol` re-export plus `Encoder::encode_request` and
  `Encoder::encode_response`. It turns the codec's `bitcoin` adapters on, which
  drag in `secp256k1-sys` and its vendored C. With `--no-default-features
  --features gen,scan` the codec is not in the dependency graph at all.

## Usage

```rust
use bwk_qr::{Config, Decoded, Decoder, Encoder};

let encoder = Encoder::new(Config::default())?;
let single = encoder.encode_text("bc1q...")?;
let frames = encoder.encode_bytes(&payload)?;

let mut decoder = Decoder::new(Config::default())?;
for decoded in decoder.process(&frame)? {
    match decoded {
        Decoded::Text(text) => { /* a plain QR, an address for instance */ }
        Decoded::Bytes(data) => { /* a reassembled BBQR payload */ }
    }
}
```

With `protocol`, a signing-flow message goes through the same framing:

```rust
use bwk_qr::protocol;

let frames = Encoder::new(Config::default())?.encode_request(&request)?;
let message = protocol::decode(&data)?;
```
