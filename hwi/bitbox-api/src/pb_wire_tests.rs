//! Wire-compatibility tests for the generated codec.
//!
//! The expected bytes were produced by prost from the same schema before it was
//! replaced, so a mismatch here means the hand-rolled codec diverges from a
//! reference protobuf implementation on a message the device actually sees.

use crate::pb;
use crate::pb_codec::Message;

fn assert_wire(actual: &[u8], expected_hex: &str) {
    assert_eq!(hex::encode(actual), expected_hex);
}

#[test]
fn btc_pub_request_matches_prost() {
    let msg = pb::BtcPubRequest {
        coin: pb::BtcCoin::Tbtc as i32,
        keypath: vec![84 + 0x80000000, 1 + 0x80000000, 0x80000000, 0, 5],
        display: true,
        output: Some(pb::btc_pub_request::Output::XpubType(
            pb::btc_pub_request::XPubType::Vpub as i32,
        )),
    };
    assert_wire(
        &msg.encode_to_vec(),
        "08011211d48080800881808080088080808008000518042801",
    );
}

#[test]
fn default_message_encodes_to_nothing() {
    // proto3 omits every field left at its default.
    let msg = pb::BtcPubRequest {
        coin: 0,
        keypath: vec![],
        display: false,
        output: None,
    };
    assert!(msg.encode_to_vec().is_empty());
}

#[test]
fn key_origin_info_matches_prost() {
    let msg = pb::KeyOriginInfo {
        root_fingerprint: vec![0x12, 0xa2, 0xc1, 0x89],
        keypath: vec![0x80000030, 1, 300, 70000],
        xpub: Some(pb::XPub {
            depth: vec![3],
            parent_fingerprint: vec![1, 2, 3, 4],
            child_num: 2147483648,
            chain_code: vec![0xaa; 32],
            public_key: vec![0x02; 33],
        }),
    };
    assert_wire(
        &msg.encode_to_vec(),
        "0a0412a2c189120bb08080800801ac02f0a2041a540a01031204010203041880808080082220aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a21020202020202020202020202020202020202020202020202020202020202020202",
    );
}

#[test]
fn nested_message_in_oneof_matches_prost() {
    let msg = pb::BtcScriptConfig {
        config: Some(pb::btc_script_config::Config::Multisig(
            pb::btc_script_config::Multisig {
                threshold: 2,
                xpubs: vec![
                    pb::XPub {
                        depth: vec![1],
                        parent_fingerprint: vec![9, 9, 9, 9],
                        child_num: 7,
                        chain_code: vec![0xbb; 32],
                        public_key: vec![0x03; 33],
                    },
                    pb::XPub::default(),
                ],
                our_xpub_index: 1,
                script_type: pb::btc_script_config::multisig::ScriptType::P2wsh as i32,
            },
        )),
    };
    assert_wire(
        &msg.encode_to_vec(),
        "1258080212500a010112040909090918072220bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb2a2103030303030303030303030303030303030303030303030303030303030303030312001801",
    );
}

#[test]
fn request_wrapper_matches_prost() {
    let msg = pb::Request {
        request: Some(pb::request::Request::Fingerprint(
            pb::RootFingerprintRequest {},
        )),
    };
    assert_wire(&msg.encode_to_vec(), "c20100");
}

#[test]
fn device_info_response_matches_prost() {
    let msg = pb::DeviceInfoResponse {
        name: "my BitBox".into(),
        initialized: true,
        version: "9.13.1".into(),
        mnemonic_passphrase_enabled: false,
        monotonic_increments_remaining: 4294967295,
        securechip_model: "ATECC608B".into(),
    };
    assert_wire(
        &msg.encode_to_vec(),
        "0a096d7920426974426f7810011a06392e31332e3128ffffffff0f3209415445434336303842",
    );
}

#[test]
fn every_fixture_round_trips_through_decode() {
    let request = pb::Request {
        request: Some(pb::request::Request::Fingerprint(
            pb::RootFingerprintRequest {},
        )),
    };
    let bytes = request.encode_to_vec();
    assert_eq!(pb::Request::decode(&bytes[..]).unwrap(), request);

    let info = pb::KeyOriginInfo {
        root_fingerprint: vec![0x12, 0xa2, 0xc1, 0x89],
        keypath: vec![0x80000030, 1, 300, 70000],
        xpub: Some(pb::XPub {
            depth: vec![3],
            parent_fingerprint: vec![1, 2, 3, 4],
            child_num: 2147483648,
            chain_code: vec![0xaa; 32],
            public_key: vec![0x02; 33],
        }),
    };
    let bytes = info.encode_to_vec();
    assert_eq!(pb::KeyOriginInfo::decode(&bytes[..]).unwrap(), info);
}

#[test]
fn response_decodes_from_device_bytes() {
    // Bytes prost produces for a root-fingerprint response.
    let raw = hex::decode("62060a046d0f2a1c").unwrap();
    match pb::Response::decode(&raw[..]).unwrap().response {
        Some(pb::response::Response::Fingerprint(f)) => {
            assert_eq!(f.fingerprint, vec![0x6d, 0x0f, 0x2a, 0x1c]);
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[test]
fn string_response_decodes_and_re_encodes() {
    let raw = hex::decode("2a0e0a0c74707562444558414d504c45").unwrap();
    let decoded = pb::Response::decode(&raw[..]).unwrap();
    match &decoded.response {
        Some(pb::response::Response::Pub(p)) => assert_eq!(p.r#pub, "tpubDEXAMPLE"),
        other => panic!("unexpected response: {other:?}"),
    }
    assert_eq!(hex::encode(decoded.encode_to_vec()), hex::encode(&raw));
}

#[test]
fn sign_next_response_matches_prost() {
    let msg = pb::BtcSignNextResponse {
        r#type: pb::btc_sign_next_response::Type::Input as i32,
        index: 3,
        has_signature: true,
        signature: vec![0xab; 64],
        prev_index: 0,
        anti_klepto_signer_commitment: Some(pb::AntiKleptoSignerCommitment {
            commitment: vec![0xcd; 33],
        }),
        generated_output_pkscript: vec![],
        silent_payment_dleq_proof: vec![],
    };
    assert_wire(
        &msg.encode_to_vec(),
        "100318012240abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab32230a21cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
    );
}

#[test]
fn empty_nested_request_matches_prost() {
    let msg = pb::Request {
        request: Some(pb::request::Request::DeviceInfo(pb::DeviceInfoRequest {})),
    };
    assert_wire(&msg.encode_to_vec(), "2200");
}

#[test]
fn unit_oneof_variant_matches_prost() {
    // `Bip39(())` is an empty message, so it still occupies a length-delimited field.
    let msg = pb::Bip85Request {
        app: Some(pb::bip85_request::App::Bip39(())),
    };
    assert_wire(&msg.encode_to_vec(), "0a00");
    assert_eq!(
        pb::Bip85Request::decode(&hex::decode("0a00").unwrap()[..]).unwrap(),
        msg
    );
}

#[test]
fn multibyte_varints_match_prost() {
    let msg = pb::CardanoSignTransactionRequest {
        network: pb::CardanoNetwork::CardanoMainnet as i32,
        inputs: vec![],
        outputs: vec![],
        fee: 170000,
        ttl: 0,
        certificates: vec![],
        withdrawals: vec![],
        validity_interval_start: 41000000,
        allow_zero_ttl: true,
        tag_cbor_sets: false,
    };
    assert_wire(&msg.encode_to_vec(), "2090b00a40c0b8c6134801");
}

#[test]
fn unknown_fields_are_skipped_not_rejected() {
    // Forward compatibility: a newer firmware may add fields we do not know.
    let mut bytes = pb::DeviceInfoResponse {
        name: "bb".into(),
        initialized: true,
        version: String::new(),
        mnemonic_passphrase_enabled: false,
        monotonic_increments_remaining: 0,
        securechip_model: String::new(),
    }
    .encode_to_vec();
    // field 99, varint
    bytes.extend_from_slice(&[0xd8, 0x06, 0x2a]);
    let decoded = pb::DeviceInfoResponse::decode(&bytes[..]).unwrap();
    assert_eq!(decoded.name, "bb");
    assert!(decoded.initialized);
}

#[test]
fn truncated_message_is_rejected() {
    let full = pb::KeyOriginInfo {
        root_fingerprint: vec![1, 2, 3, 4],
        keypath: vec![1, 2, 3],
        xpub: Some(pb::XPub::default()),
    }
    .encode_to_vec();
    assert!(pb::KeyOriginInfo::decode(&full[..full.len() - 1]).is_err());
}

#[test]
fn unpacked_repeated_varints_decode_too() {
    // protobuf allows either encoding on the wire; prost accepts both.
    let packed = pb::Keypath {
        keypath: vec![1, 300],
    }
    .encode_to_vec();
    assert_eq!(hex::encode(&packed), "0a03 01 ac02".replace(' ', ""));

    let unpacked = hex::decode("0801 08ac02".replace(' ', "")).unwrap();
    let decoded = pb::Keypath::decode(&unpacked[..]).unwrap();
    assert_eq!(decoded.keypath, vec![1, 300]);
}
