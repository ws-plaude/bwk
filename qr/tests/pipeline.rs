#![cfg(feature = "protocol")]

use std::{cell::RefCell, collections::VecDeque, rc::Rc};

use bwk_qr::{
    bbqr,
    decoder::Decoder,
    encoder::Encoder,
    gen::{self, Correction, Generator, Modules, Params},
    protocol::{
        encode_request, encode_response, request, response, types::XPUB_LEN, Fingerprint, Request,
        RequestId, Response, SignResponseKind, Xpub, REQUEST_ID_LEN,
    },
    scan::{self, Frame, Scanner},
    Config, Decoded, Error, Image, Progress,
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct GenCall {
    text: String,
    params: Params,
}

/// Records what the encoder asks for and hands back a matrix of the smallest
/// version, so nothing here depends on real rendering.
#[derive(Debug, Clone)]
struct FakeGenerator {
    capacity: usize,
    calls: Rc<RefCell<Vec<GenCall>>>,
}

impl FakeGenerator {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            calls: Rc::new(RefCell::new(Vec::new())),
        }
    }

    fn calls(&self) -> Vec<GenCall> {
        self.calls.borrow().clone()
    }
}

impl Generator for FakeGenerator {
    fn generate(&self, text: &str, params: Params) -> Result<Modules, gen::Error> {
        self.calls.borrow_mut().push(GenCall {
            text: text.to_string(),
            params,
        });
        if text.len() > self.capacity {
            return Err(gen::Error::TooLong);
        }
        Modules::new(21, vec![false; 21 * 21])
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ScanCall {
    data: Vec<u8>,
    width: u32,
    height: u32,
}

/// Replays one scripted batch of payloads per call, so the frames themselves carry
/// no QR at all.
#[derive(Debug, Clone)]
struct FakeScanner {
    batches: Rc<RefCell<VecDeque<Vec<Vec<u8>>>>>,
    calls: Rc<RefCell<Vec<ScanCall>>>,
}

impl FakeScanner {
    fn new(batches: Vec<Vec<Vec<u8>>>) -> Self {
        Self {
            batches: Rc::new(RefCell::new(batches.into())),
            calls: Rc::new(RefCell::new(Vec::new())),
        }
    }

    fn calls(&self) -> Vec<ScanCall> {
        self.calls.borrow().clone()
    }
}

impl Scanner for FakeScanner {
    fn scan(&mut self, frame: Frame<'_>) -> Result<Vec<Vec<u8>>, scan::Error> {
        self.calls.borrow_mut().push(ScanCall {
            data: frame.data.to_vec(),
            width: frame.width,
            height: frame.height,
        });
        Ok(self.batches.borrow_mut().pop_front().unwrap())
    }
}

fn id() -> RequestId {
    RequestId([42; REQUEST_ID_LEN])
}

fn sign_request() -> Request {
    Request {
        id: id(),
        body: request::Body::Sign(request::Sign {
            descriptors: vec![request::Descriptor {
                alias: "main".to_string(),
                body: request::DescriptorBody::Bip380(
                    "wpkh([00000000/84h/1h/0h]xpub/0/*)".to_string(),
                ),
                proof: None,
            }],
            psbt: vec![0x70; 48],
            want_kind: Some(SignResponseKind::Psbt),
        }),
    }
}

fn xpubs_response() -> Response {
    Response {
        id: id(),
        body: response::Body::Xpubs(response::Xpubs {
            xpubs: vec![Xpub([7; XPUB_LEN]), Xpub([9; XPUB_LEN])],
            fingerprint: Fingerprint([0xde, 0xad, 0xbe, 0xef]),
            model: "bwk-signer".to_string(),
            version: response::FirmwareVersion {
                major: 1,
                minor: 7,
                patch: 0x00ab_cdef,
                flag: response::ReleaseFlag::ReleaseCandidate,
            },
            capabilities: response::Capabilities(0x0000_000b),
        }),
    }
}

// small parts force a message across several BBQR frames
fn parts(data: &[u8]) -> Vec<String> {
    bbqr::split(data, 16).unwrap().parts
}

fn one_per_frame(parts: &[String]) -> Vec<Vec<Vec<u8>>> {
    parts
        .iter()
        .map(|part| vec![part.as_bytes().to_vec()])
        .collect()
}

// the payloads come from the script, so any well-formed frame does
fn frame() -> Image {
    Image {
        data: vec![0; 4],
        width: 2,
        height: 2,
    }
}

fn decoder(scanner: FakeScanner) -> Decoder<FakeScanner> {
    Decoder::with_scanner(
        Config {
            scan_inverted: false,
            ..Config::default()
        },
        scanner,
    )
    .unwrap()
}

fn decode_frames(decoder: &mut Decoder<FakeScanner>, count: usize) -> Vec<Decoded> {
    let mut decoded = Vec::new();
    for _ in 0..count {
        decoded.extend(decoder.process(&frame()).unwrap());
    }
    decoded
}

#[test]
fn frames_out_of_order_decode() {
    let request = sign_request();
    let parts = parts(&encode_request(&request).unwrap());
    assert_eq!(parts.len(), 8);
    // even indices first, then odd ones
    let shuffled = (0..parts.len())
        .step_by(2)
        .chain((1..parts.len()).step_by(2))
        .map(|index| parts[index].clone())
        .collect::<Vec<_>>();
    let mut decoder = decoder(FakeScanner::new(one_per_frame(&shuffled)));
    assert_eq!(
        decode_frames(&mut decoder, 8),
        vec![Decoded::Bytes(encode_request(&request).unwrap())]
    );
}

#[test]
fn duplicate_frame_is_ignored() {
    let request = sign_request();
    let parts = parts(&encode_request(&request).unwrap());
    assert_eq!(parts.len(), 8);
    let mut replayed = vec![parts[0].clone()];
    replayed.extend(parts.iter().cloned());
    let mut decoder = decoder(FakeScanner::new(one_per_frame(&replayed)));

    assert_eq!(decoder.process(&frame()).unwrap(), vec![]);
    assert_eq!(decoder.process(&frame()).unwrap(), vec![]);
    assert_eq!(decoder.progress(), Some(Progress { seen: 1, total: 8 }));
    assert_eq!(
        decode_frames(&mut decoder, 7),
        vec![Decoded::Bytes(encode_request(&request).unwrap())]
    );
}

#[test]
fn progress_reports_seen_and_total() {
    let parts = parts(&encode_request(&sign_request()).unwrap());
    assert_eq!(parts.len(), 8);
    let mut decoder = decoder(FakeScanner::new(one_per_frame(&parts)));
    assert_eq!(decoder.progress(), None);
    for index in 0..8 {
        decoder.process(&frame()).unwrap();
        assert_eq!(
            decoder.progress(),
            Some(Progress {
                seen: index + 1,
                total: 8,
            })
        );
    }
}

#[test]
fn decoder_handles_two_messages_without_reset() {
    let request = sign_request();
    let response = xpubs_response();
    let request_parts = parts(&encode_request(&request).unwrap());
    let response_parts = parts(&encode_response(&response).unwrap());
    assert_eq!(request_parts.len(), 8);
    assert_eq!(response_parts.len(), 14);

    let mut script = request_parts;
    script.extend(response_parts);
    let mut decoder = decoder(FakeScanner::new(one_per_frame(&script)));
    assert_eq!(
        decode_frames(&mut decoder, 8),
        vec![Decoded::Bytes(encode_request(&request).unwrap())]
    );
    assert_eq!(
        decode_frames(&mut decoder, 14),
        vec![Decoded::Bytes(encode_response(&response).unwrap())]
    );
}

#[test]
fn text_is_rendered_with_a_free_version() {
    let generator = FakeGenerator::new(4096);
    let encoder = Encoder::with_generator(Config::default(), generator.clone()).unwrap();
    encoder.encode_text("BC1QXY").unwrap();
    assert_eq!(
        generator.calls(),
        vec![GenCall {
            text: "BC1QXY".to_string(),
            params: Params {
                min_version: 1,
                max_version: 27,
                correction: Correction::Low,
                boost_correction: true,
            },
        }]
    );
}

#[test]
fn a_bbqr_part_is_pinned_to_the_max_version() {
    let generator = FakeGenerator::new(4096);
    let encoder = Encoder::with_generator(
        Config {
            max_qr_version: 12,
            ..Config::default()
        },
        generator.clone(),
    )
    .unwrap();
    encoder.encode_response(&xpubs_response()).unwrap();

    let calls = generator.calls();
    assert_eq!(calls.len(), 1);
    assert!(calls[0].text.starts_with("B$HB0100"));
    assert_eq!(
        calls[0].params,
        Params {
            min_version: 12,
            max_version: 12,
            correction: Correction::Low,
            boost_correction: false,
        }
    );
}

#[test]
fn a_part_that_does_not_fit_the_version_is_rejected() {
    let generator = FakeGenerator::new(16);
    let encoder = Encoder::with_generator(Config::default(), generator).unwrap();
    assert_eq!(
        encoder.encode_response(&xpubs_response()).unwrap_err(),
        Error::PartTooLarge {
            bytes: 1024,
            version: 27,
        }
    );
}

#[test]
fn a_version_cap_alone_does_not_block_construction() {
    // nothing is rendered at construction, so a generator that renders nothing still builds
    let generator = FakeGenerator::new(0);
    assert!(Encoder::with_generator(
        Config {
            max_qr_version: 10,
            ..Config::default()
        },
        generator.clone(),
    )
    .is_ok());
    assert_eq!(generator.calls(), vec![]);
}

#[test]
fn every_bbqr_part_satisfies_the_alphanumeric_guard() {
    let parts = bbqr::split(&[0x00, 0x7f, 0xff, 0xa5], 3).unwrap().parts;
    assert_eq!(parts, vec!["B$HB0200007FFF", "B$HB0201A5"]);
    assert!(gen::is_alphanumeric(&parts[0]));
    assert!(gen::is_alphanumeric(&parts[1]));
}

#[test]
fn constructors_reject_an_invalid_config() {
    let generator = FakeGenerator::new(4096);
    assert_eq!(
        Encoder::with_generator(
            Config {
                max_qr_version: 0,
                ..Config::default()
            },
            generator.clone(),
        )
        .unwrap_err(),
        Error::QrVersion(0)
    );
    assert_eq!(
        Encoder::with_generator(
            Config {
                max_qr_version: 41,
                ..Config::default()
            },
            generator.clone(),
        )
        .unwrap_err(),
        Error::QrVersion(41)
    );
    assert_eq!(
        Encoder::with_generator(
            Config {
                bbqr_part_bytes: 0,
                ..Config::default()
            },
            generator,
        )
        .unwrap_err(),
        Error::ZeroPartSize
    );
    assert_eq!(
        Decoder::with_scanner(
            Config {
                max_image_pixels: 0,
                ..Config::default()
            },
            FakeScanner::new(vec![]),
        )
        .unwrap_err(),
        Error::ZeroImageLimit
    );
}

#[test]
fn a_malformed_frame_is_rejected_before_the_scanner() {
    let scanner = FakeScanner::new(vec![]);
    let mut short = Decoder::with_scanner(Config::default(), scanner.clone()).unwrap();
    assert_eq!(
        short.process(&Image {
            data: vec![0; 3],
            width: 2,
            height: 2,
        }),
        Err(Error::BadFrame)
    );

    let mut bounded = Decoder::with_scanner(
        Config {
            max_image_pixels: 3,
            ..Config::default()
        },
        scanner.clone(),
    )
    .unwrap();
    assert_eq!(bounded.process(&frame()), Err(Error::BadFrame));

    assert_eq!(scanner.calls(), vec![]);
}

#[test]
fn the_inverted_rescan_dedupes_a_repeated_payload() {
    let scanner = FakeScanner::new(vec![
        vec![b"ONE".to_vec()],
        vec![b"ONE".to_vec(), b"TWO".to_vec()],
    ]);
    let mut decoder = Decoder::with_scanner(Config::default(), scanner.clone()).unwrap();
    let image = Image {
        data: vec![0, 64, 200, 255],
        width: 2,
        height: 2,
    };
    assert_eq!(
        decoder.process(&image).unwrap(),
        vec![
            Decoded::Text("ONE".to_string()),
            Decoded::Text("TWO".to_string()),
        ]
    );
    assert_eq!(
        scanner.calls(),
        vec![
            ScanCall {
                data: vec![0, 64, 200, 255],
                width: 2,
                height: 2,
            },
            ScanCall {
                data: vec![255, 191, 55, 0],
                width: 2,
                height: 2,
            },
        ]
    );
}

#[test]
fn the_scanner_runs_once_when_inversion_is_off() {
    let scanner = FakeScanner::new(vec![vec![b"ONE".to_vec()]]);
    let mut decoder = decoder(scanner.clone());
    assert_eq!(
        decoder.process(&frame()).unwrap(),
        vec![Decoded::Text("ONE".to_string())]
    );
    assert_eq!(
        scanner.calls(),
        vec![ScanCall {
            data: vec![0; 4],
            width: 2,
            height: 2,
        }]
    );
}
