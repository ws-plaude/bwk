//! APDU command and answer, previously provided by the `ledger-apdu` crate.

use std::ops::Deref;

/// A command sent to the device.
#[derive(Debug, Clone)]
pub struct APDUCommand<B> {
    /// An incorrect class prevents any communication with the device.
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub data: B,
}

impl<B> APDUCommand<B>
where
    B: Deref<Target = [u8]>,
{
    pub fn serialize(&self) -> Vec<u8> {
        let mut v = vec![self.cla, self.ins, self.p1, self.p2, self.data.len() as u8];
        v.extend(self.data.iter());
        v
    }
}

/// An answer from the device, whose last two bytes are the return code.
#[derive(Debug)]
pub struct APDUAnswer<B> {
    data: B,
    retcode: u16,
}

#[derive(Debug, PartialEq, Eq)]
pub struct APDUAnswerTooShort;

impl<B> APDUAnswer<B>
where
    B: Deref<Target = [u8]>,
{
    pub fn from_answer(answer: B) -> Result<Self, APDUAnswerTooShort> {
        let len = answer.len();
        if len < 2 {
            return Err(APDUAnswerTooShort);
        }
        let retcode = u16::from_be_bytes([answer[len - 2], answer[len - 1]]);

        Ok(APDUAnswer {
            data: answer,
            retcode,
        })
    }

    /// The payload, without the return code.
    pub fn data(&self) -> &[u8] {
        &self.data[..self.data.len() - 2]
    }

    pub fn retcode(&self) -> u16 {
        self.retcode
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_serialization() {
        let command = APDUCommand {
            cla: 0xe0,
            ins: 0x01,
            p1: 0x02,
            p2: 0x03,
            data: vec![0xaa, 0xbb],
        };
        assert_eq!(
            command.serialize(),
            vec![0xe0, 0x01, 0x02, 0x03, 0x02, 0xaa, 0xbb]
        );
    }

    #[test]
    fn command_serialization_without_data() {
        let command = APDUCommand {
            cla: 0xe0,
            ins: 0x01,
            p1: 0x02,
            p2: 0x03,
            data: Vec::new(),
        };
        assert_eq!(command.serialize(), vec![0xe0, 0x01, 0x02, 0x03, 0x00]);
    }

    #[test]
    fn answer_splits_payload_from_retcode() {
        let answer = APDUAnswer::from_answer(vec![0xde, 0xad, 0x90, 0x00]).unwrap();
        assert_eq!(answer.retcode(), 0x9000);
        assert_eq!(answer.data(), &[0xde, 0xad]);
    }

    #[test]
    fn answer_with_only_a_retcode_has_no_payload() {
        let answer = APDUAnswer::from_answer(vec![0x6d, 0x00]).unwrap();
        assert_eq!(answer.retcode(), 0x6d00);
        assert!(answer.data().is_empty());
    }

    #[test]
    fn answer_shorter_than_a_retcode_is_rejected() {
        assert_eq!(
            APDUAnswer::from_answer(vec![0x90]).unwrap_err(),
            APDUAnswerTooShort
        );
        assert_eq!(
            APDUAnswer::from_answer(Vec::new()).unwrap_err(),
            APDUAnswerTooShort
        );
    }
}
