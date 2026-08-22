//! Minimal protobuf wire codec for the BitBox schema.
//!
//! Covers only what that schema uses: varints, length-delimited fields, packed
//! repeated varints and oneofs. There are no fixed-width, zigzag, map or group
//! fields, so those wire types are only recognised well enough to be skipped.

pub const WIRE_VARINT: u8 = 0;
pub const WIRE_I64: u8 = 1;
pub const WIRE_LEN: u8 = 2;
pub const WIRE_I32: u8 = 5;

/// The buffer was truncated, malformed, or used a wire type the schema never has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeError;

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "malformed protobuf message")
    }
}

impl std::error::Error for DecodeError {}

/// A protobuf enum field carried a value the schema does not define.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownEnumValue(pub i32);

impl std::fmt::Display for UnknownEnumValue {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "unknown enum value: {}", self.0)
    }
}

impl std::error::Error for UnknownEnumValue {}

pub trait Message: Default {
    fn encode_raw(&self, buf: &mut Vec<u8>);

    fn merge_field(&mut self, tag: u32, wire: u8, buf: &mut &[u8]) -> Result<(), DecodeError>;

    fn encode_to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode_raw(&mut buf);
        buf
    }

    fn decode(mut buf: &[u8]) -> Result<Self, DecodeError> {
        let mut msg = Self::default();
        merge_into(&mut msg, &mut buf)?;
        Ok(msg)
    }
}

fn merge_into<M: Message>(msg: &mut M, buf: &mut &[u8]) -> Result<(), DecodeError> {
    while !buf.is_empty() {
        let key = decode_varint(buf)?;
        let tag = u32::try_from(key >> 3).map_err(|_| DecodeError)?;
        let wire = (key & 0b111) as u8;
        if tag == 0 {
            return Err(DecodeError);
        }
        msg.merge_field(tag, wire, buf)?;
    }
    Ok(())
}

pub fn encode_varint(mut value: u64, buf: &mut Vec<u8>) {
    while value >= 0x80 {
        buf.push((value as u8) | 0x80);
        value >>= 7;
    }
    buf.push(value as u8);
}

pub fn decode_varint(buf: &mut &[u8]) -> Result<u64, DecodeError> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let byte = *buf.first().ok_or(DecodeError)?;
        *buf = &buf[1..];
        value |= u64::from(byte & 0x7f) << shift;
        if byte < 0x80 {
            return Ok(value);
        }
    }
    Err(DecodeError)
}

fn encode_key(tag: u32, wire: u8, buf: &mut Vec<u8>) {
    encode_varint((u64::from(tag) << 3) | u64::from(wire), buf);
}

pub fn encode_varint_field(tag: u32, value: u64, buf: &mut Vec<u8>) {
    encode_key(tag, WIRE_VARINT, buf);
    encode_varint(value, buf);
}

pub fn encode_bytes_field(tag: u32, value: &[u8], buf: &mut Vec<u8>) {
    encode_key(tag, WIRE_LEN, buf);
    encode_varint(value.len() as u64, buf);
    buf.extend_from_slice(value);
}

pub fn encode_message_field<M: Message>(tag: u32, msg: &M, buf: &mut Vec<u8>) {
    // Nested messages are length-prefixed, so the body has to exist before the
    // length can be written.
    let body = msg.encode_to_vec();
    encode_bytes_field(tag, &body, buf);
}

/// proto3 packs repeated scalars into a single length-delimited field.
pub fn encode_packed_varints<I: Iterator<Item = u64>>(tag: u32, values: I, buf: &mut Vec<u8>) {
    let mut body = Vec::new();
    for value in values {
        encode_varint(value, &mut body);
    }
    encode_bytes_field(tag, &body, buf);
}

fn take<'a>(buf: &mut &'a [u8], len: usize) -> Result<&'a [u8], DecodeError> {
    if buf.len() < len {
        return Err(DecodeError);
    }
    let (head, tail) = buf.split_at(len);
    *buf = tail;
    Ok(head)
}

fn decode_len_delimited<'a>(buf: &mut &'a [u8]) -> Result<&'a [u8], DecodeError> {
    let len = usize::try_from(decode_varint(buf)?).map_err(|_| DecodeError)?;
    take(buf, len)
}

pub fn decode_bytes(buf: &mut &[u8]) -> Result<Vec<u8>, DecodeError> {
    Ok(decode_len_delimited(buf)?.to_vec())
}

pub fn decode_string(buf: &mut &[u8]) -> Result<String, DecodeError> {
    String::from_utf8(decode_len_delimited(buf)?.to_vec()).map_err(|_| DecodeError)
}

pub fn decode_message<M: Message>(buf: &mut &[u8]) -> Result<M, DecodeError> {
    let mut body = decode_len_delimited(buf)?;
    let mut msg = M::default();
    merge_into(&mut msg, &mut body)?;
    Ok(msg)
}

/// Accepts both the packed and the unpacked encoding, as protobuf requires.
pub fn merge_packed_varints<T, F: Fn(u64) -> T>(
    wire: u8,
    buf: &mut &[u8],
    out: &mut Vec<T>,
    convert: F,
) -> Result<(), DecodeError> {
    if wire == WIRE_LEN {
        let mut body = decode_len_delimited(buf)?;
        while !body.is_empty() {
            out.push(convert(decode_varint(&mut body)?));
        }
    } else {
        out.push(convert(decode_varint(buf)?));
    }
    Ok(())
}

pub fn skip_field(wire: u8, buf: &mut &[u8]) -> Result<(), DecodeError> {
    match wire {
        WIRE_VARINT => {
            decode_varint(buf)?;
        }
        WIRE_I64 => {
            take(buf, 8)?;
        }
        WIRE_LEN => {
            decode_len_delimited(buf)?;
        }
        WIRE_I32 => {
            take(buf, 4)?;
        }
        _ => return Err(DecodeError),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints_round_trip() {
        for value in [0u64, 1, 127, 128, 300, u32::MAX as u64, u64::MAX] {
            let mut buf = Vec::new();
            encode_varint(value, &mut buf);
            let mut slice = &buf[..];
            assert_eq!(decode_varint(&mut slice).unwrap(), value);
            assert!(slice.is_empty());
        }
    }

    #[test]
    fn varint_encoding_matches_the_spec() {
        let mut buf = Vec::new();
        encode_varint(300, &mut buf);
        assert_eq!(buf, vec![0xac, 0x02]);
    }

    #[test]
    fn key_packs_tag_and_wire_type() {
        let mut buf = Vec::new();
        encode_key(1, WIRE_LEN, &mut buf);
        assert_eq!(buf, vec![0x0a]);
    }

    #[test]
    fn truncated_varint_is_an_error() {
        let mut slice = &[0x80u8][..];
        assert_eq!(decode_varint(&mut slice), Err(DecodeError));
    }

    #[test]
    fn varint_longer_than_ten_bytes_is_an_error() {
        let raw = [0x80u8; 11];
        let mut slice = &raw[..];
        assert_eq!(decode_varint(&mut slice), Err(DecodeError));
    }

    #[test]
    fn length_beyond_the_buffer_is_an_error() {
        let mut slice = &[0x05u8, 0x01, 0x02][..];
        assert_eq!(decode_bytes(&mut slice), Err(DecodeError));
    }

    #[test]
    fn non_utf8_string_is_an_error() {
        let mut slice = &[0x02u8, 0xff, 0xfe][..];
        assert_eq!(decode_string(&mut slice), Err(DecodeError));
    }

    #[test]
    fn skip_advances_past_each_wire_type() {
        let mut slice = &[0xac, 0x02][..];
        skip_field(WIRE_VARINT, &mut slice).unwrap();
        assert!(slice.is_empty());

        let mut slice = &[0x02, 0xaa, 0xbb][..];
        skip_field(WIRE_LEN, &mut slice).unwrap();
        assert!(slice.is_empty());

        let mut slice = &[0u8; 4][..];
        skip_field(WIRE_I32, &mut slice).unwrap();
        assert!(slice.is_empty());

        let mut slice = &[0u8; 8][..];
        skip_field(WIRE_I64, &mut slice).unwrap();
        assert!(slice.is_empty());
    }

    #[test]
    fn unknown_wire_type_is_an_error() {
        let mut slice = &[0u8; 4][..];
        assert_eq!(skip_field(6, &mut slice), Err(DecodeError));
    }

    #[test]
    fn packed_repeated_varints_round_trip() {
        let mut buf = Vec::new();
        encode_packed_varints(2, [1u64, 300, 70000].into_iter(), &mut buf);
        let mut slice = &buf[..];
        let key = decode_varint(&mut slice).unwrap();
        assert_eq!(key >> 3, 2);
        assert_eq!(key & 0b111, u64::from(WIRE_LEN));
        let mut out: Vec<u32> = Vec::new();
        merge_packed_varints(WIRE_LEN, &mut slice, &mut out, |v| v as u32).unwrap();
        assert_eq!(out, vec![1, 300, 70000]);
    }

    #[test]
    fn unpacked_repeated_varints_are_also_accepted() {
        let mut out: Vec<u32> = Vec::new();
        let mut slice = &[0xac, 0x02][..];
        merge_packed_varints(WIRE_VARINT, &mut slice, &mut out, |v| v as u32).unwrap();
        assert_eq!(out, vec![300]);
    }

    #[test]
    fn tag_zero_is_rejected() {
        #[derive(Debug, Default, PartialEq)]
        struct Empty;
        impl Message for Empty {
            fn encode_raw(&self, _: &mut Vec<u8>) {}
            fn merge_field(
                &mut self,
                _: u32,
                wire: u8,
                buf: &mut &[u8],
            ) -> Result<(), DecodeError> {
                skip_field(wire, buf)
            }
        }
        assert!(Empty::decode(&[0x00, 0x00]).is_err());
    }
}
