#![allow(clippy::uninlined_format_args)]
#![allow(clippy::io_other_error)]

pub mod bip389;
#[cfg(feature = "bitbox")]
pub mod bitbox;
#[cfg(feature = "coldcard")]
pub mod coldcard;
#[cfg(feature = "jade")]
pub mod jade;
#[cfg(feature = "ledger")]
pub mod ledger;
#[cfg(feature = "service")]
pub mod service;
#[cfg(feature = "specter")]
pub mod specter;
pub mod utils;

use bitcoin::{
    bip32::{ChildNumber, DerivationPath, Fingerprint, Xpub},
    psbt::Psbt,
};

use std::{cmp::Ordering, fmt::Debug, str::FromStr};

#[allow(dead_code)]
const RECV_INDEX: ChildNumber = ChildNumber::Normal { index: 0 };
#[allow(dead_code)]
const CHANGE_INDEX: ChildNumber = ChildNumber::Normal { index: 1 };

#[derive(Debug, Clone)]
pub enum Error {
    ParsingPolicy(bip389::ParseError),
    MissingPolicy,
    UnsupportedVersion,
    UnsupportedInput,
    InvalidParameter(&'static str, String),
    UnimplementedMethod,
    DeviceDisconnected,
    DeviceNotFound,
    DeviceDidNotSign,
    Device(String),
    Unexpected(&'static str),
    UserRefused,
    NetworkMismatch,
    Bip86ChangeIndex,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::ParsingPolicy(e) => write!(f, "{e}"),
            Error::MissingPolicy => write!(f, "Missing policy"),
            Error::UnsupportedVersion => write!(f, "Unsupported version"),
            Error::UnsupportedInput => write!(f, "Unsupported input"),
            Error::UnimplementedMethod => write!(f, "Unimplemented method"),
            Error::DeviceDisconnected => write!(f, "Device disconnected"),
            Error::DeviceNotFound => write!(f, "Device not found"),
            Error::DeviceDidNotSign => write!(f, "Device did not sign"),
            Error::Device(e) => write!(f, "{e}"),
            Error::InvalidParameter(param, e) => write!(f, "Invalid parameter {param}: {e}"),
            Error::Unexpected(e) => write!(f, "{e}"),
            Error::UserRefused => write!(f, "User refused operation"),
            Error::NetworkMismatch => write!(f, "Device network is different"),
            Error::Bip86ChangeIndex => {
                write!(f, "Ledger devices only accept 0 or 1 as`change` index value for BIP86 derivation path")
            }
        }
    }
}

impl From<bip389::ParseError> for Error {
    fn from(value: bip389::ParseError) -> Self {
        Error::ParsingPolicy(value)
    }
}

impl std::error::Error for Error {}

/// HWI is the common Hardware Wallet Interface.
pub trait HWI: Debug {
    /// Return the device kind
    fn device_kind(&self) -> DeviceKind;
    /// Application version or OS version.
    fn get_version(&self) -> Result<Version, Error>;
    /// Get master fingerprint.
    fn get_master_fingerprint(&self) -> Result<Fingerprint, Error>;
    /// Get the xpub with the given derivation path.
    fn get_extended_pubkey(&self, path: &DerivationPath) -> Result<Xpub, Error>;
    /// Register a new wallet policy.
    fn register_wallet(&self, name: &str, policy: &str) -> Result<Option<[u8; 32]>, Error>;
    /// Returns true if the wallet is registered on the device.
    fn is_wallet_registered(&self, name: &str, policy: &str) -> Result<bool, Error>;
    /// Display address on the device screen.
    fn display_address(&self, script: &AddressScript) -> Result<(), Error>;
    /// Sign a partially signed bitcoin transaction (PSBT).
    fn sign_tx(&self, tx: &mut Psbt) -> Result<(), Error>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressScript {
    /// Must be a bip86 path.
    P2TR(DerivationPath),
    /// Miniscript requires the policy be loaded into the device.
    Miniscript { index: u32, change: bool },
}

#[derive(PartialEq, Eq, Debug, Clone, Default)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub prerelease: Option<String>,
}

/// A semver numeric identifier: `0`, or a digit string with no leading zero.
fn numeric_ident(s: &str) -> Result<u32, Error> {
    let leading_zero = s.len() > 1 && s.starts_with('0');
    if s.is_empty() || leading_zero || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::UnsupportedVersion);
    }
    u32::from_str(s).map_err(|_| Error::UnsupportedVersion)
}

/// A semver prerelease identifier: a numeric one, or alphanumerics and hyphens
/// with at least one character that is not a digit.
fn is_prerelease_ident(s: &str) -> bool {
    let alphanumeric = !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    alphanumeric && (!s.bytes().all(|b| b.is_ascii_digit()) || numeric_ident(s).is_ok())
}

/// A semver build identifier: alphanumerics and hyphens, leading zeros allowed.
fn is_build_ident(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Parse a device version, following <https://semver.org/> with the patch
/// number optional and the build metadata discarded.
pub fn parse_version(s: &str) -> Result<Version, Error> {
    let s = s
        .trim_start_matches('v')
        // Coldcard Q does not follow semver format
        .trim_end_matches("QX")
        // Coldcard mk4 does not follow semver format
        .trim_end_matches('X');

    let (s, build) = match s.split_once('+') {
        Some((s, build)) => (s, Some(build)),
        None => (s, None),
    };
    if build.is_some_and(|b| !b.split('.').all(is_build_ident)) {
        return Err(Error::UnsupportedVersion);
    }

    let (core, prerelease) = match s.split_once('-') {
        Some((core, prerelease)) => (core, Some(prerelease)),
        None => (s, None),
    };
    if prerelease.is_some_and(|p| !p.split('.').all(is_prerelease_ident)) {
        return Err(Error::UnsupportedVersion);
    }

    let mut core = core.split('.');
    let (major, minor, patch, extra) = (core.next(), core.next(), core.next(), core.next());
    if extra.is_some() {
        return Err(Error::UnsupportedVersion);
    }
    Ok(Version {
        major: numeric_ident(major.ok_or(Error::UnsupportedVersion)?)?,
        minor: numeric_ident(minor.ok_or(Error::UnsupportedVersion)?)?,
        patch: patch.map(numeric_ident).transpose()?.unwrap_or(0),
        prerelease: prerelease.map(str::to_string),
    })
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match self.major.cmp(&other.major) {
            Ordering::Equal => match self.minor.cmp(&other.minor) {
                Ordering::Equal => match self.patch.cmp(&other.patch) {
                    Ordering::Equal => {
                        match (&self.prerelease, &other.prerelease) {
                            // Cannot compare versions at this point.
                            (Some(_), Some(_)) => None,
                            (Some(_), None) => Some(Ordering::Greater),
                            (None, Some(_)) => Some(Ordering::Less),
                            (None, None) => Some(Ordering::Equal),
                        }
                    }
                    other => Some(other),
                },
                other => Some(other),
            },
            other => Some(other),
        }
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if let Some(prerelease) = &self.prerelease {
            write!(
                f,
                "{}.{}.{}-{}",
                self.major, self.minor, self.patch, prerelease
            )
        } else {
            write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
        }
    }
}

/// DeviceType is the result of the following process:
/// If it is talking like a Duck© hardware wallet it is a Duck© hardware wallet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeviceKind {
    BitBox02,
    Coldcard,
    Specter,
    SpecterSimulator,
    Ledger,
    LedgerSimulator,
    Jade,
}

impl std::fmt::Display for DeviceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            DeviceKind::BitBox02 => write!(f, "bitbox02"),
            DeviceKind::Coldcard => write!(f, "coldcard"),
            DeviceKind::Specter => write!(f, "specter"),
            DeviceKind::SpecterSimulator => write!(f, "specter-simulator"),
            DeviceKind::Ledger => write!(f, "ledger"),
            DeviceKind::LedgerSimulator => write!(f, "ledger-simulator"),
            DeviceKind::Jade => write!(f, "jade"),
        }
    }
}

impl std::str::FromStr for DeviceKind {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "bitbox02" => Ok(DeviceKind::BitBox02),
            "specter" => Ok(DeviceKind::Specter),
            "specter-simulator" => Ok(DeviceKind::SpecterSimulator),
            "ledger" => Ok(DeviceKind::Ledger),
            "ledger-simulator" => Ok(DeviceKind::LedgerSimulator),
            "jade" => Ok(DeviceKind::Jade),
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_version_defaults_a_missing_patch_to_zero() {
        assert_eq!(
            parse_version("0.1").unwrap(),
            Version {
                major: 0,
                minor: 1,
                patch: 0,
                prerelease: None
            }
        );
    }

    #[test]
    fn parse_version_keeps_the_whole_prerelease_and_drops_the_build() {
        assert_eq!(
            parse_version("1.2.3-rc.1+build.7").unwrap(),
            Version {
                major: 1,
                minor: 2,
                patch: 3,
                prerelease: Some("rc.1".to_string())
            }
        );
    }

    #[test]
    fn parse_version_rejects_malformed_input() {
        for s in [
            "",                // nothing at all
            "1",               // no minor
            "1.2.3.4",         // too many numbers
            "1.",              // empty minor
            "01.2",            // leading zero
            "1.2.03",          // leading zero in the patch
            "1.2-",            // empty prerelease
            "1.2+",            // empty build
            "1.2.3-01",        // numeric prerelease with a leading zero
            "1.2.3-a..b",      // empty prerelease identifier
            "1.2.3+a+b",       // a build identifier cannot hold a plus
            "1.2.3-a+b+c",     // nor can it after a prerelease
            "-1.2",            // no version core
            "1.2.3 ",          // trailing space
            "99999999999.0.0", // past u32
        ] {
            assert!(parse_version(s).is_err(), "{s:?} must be refused");
        }
    }

    #[test]
    fn parse_version_strips_the_prefixes_the_devices_add() {
        let expected = Version {
            major: 5,
            minor: 0,
            patch: 7,
            prerelease: None,
        };
        // Ledger prefixes with `v`, Coldcard mk4 suffixes `X` and the Q `QX`.
        assert_eq!(parse_version("v5.0.7").unwrap(), expected);
        assert_eq!(parse_version("5.0.7X").unwrap(), expected);
        assert_eq!(parse_version("5.0.7QX").unwrap(), expected);
    }

    #[test]
    fn parse_version_accepts_a_hyphen_inside_a_prerelease() {
        assert_eq!(
            parse_version("1.2.3--a-b").unwrap(),
            Version {
                major: 1,
                minor: 2,
                patch: 3,
                prerelease: Some("-a-b".to_string())
            }
        );
    }

    #[test]
    fn test_parse_version() {
        let test_cases = [
            (
                "v2.1.0",
                Version {
                    major: 2,
                    minor: 1,
                    patch: 0,
                    prerelease: None,
                },
            ),
            (
                "v1.0",
                Version {
                    major: 1,
                    minor: 0,
                    patch: 0,
                    prerelease: None,
                },
            ),
            (
                "3.0-rc2",
                Version {
                    major: 3,
                    minor: 0,
                    patch: 0,
                    prerelease: Some("rc2".to_string()),
                },
            ),
            (
                "0.1.0-ALPHA",
                Version {
                    major: 0,
                    minor: 1,
                    patch: 0,
                    prerelease: Some("ALPHA".to_string()),
                },
            ),
            (
                "6.2.1X",
                Version {
                    major: 6,
                    minor: 2,
                    patch: 1,
                    prerelease: None,
                },
            ),
            (
                "6.3.3QX",
                Version {
                    major: 6,
                    minor: 3,
                    patch: 3,
                    prerelease: None,
                },
            ),
        ];
        for (s, v) in test_cases {
            assert_eq!(v, parse_version(s).unwrap());
        }
    }

    #[test]
    fn test_partial_ord_version() {
        let test_cases = [
            ("v2.1.0", "v3.1.0"),
            ("v0.0.1", "v0.1"),
            ("v0.1", "v1.0.1"),
            ("v2.0.1", "v2.1.0"),
            ("v2.1.1", "v3.0-rc1"),
            ("v3.0-rc1", "v3.0.1"),
            ("v3.0", "v3.0-rc1"),
        ];
        for (l, r) in test_cases {
            let v1 = parse_version(l).unwrap();
            let v2 = parse_version(r).unwrap();
            assert!(v1 < v2);
        }

        // We cannot compare prerelease of the same version.
        let v1 = parse_version("v2.0-rc1weirdstuff").unwrap();
        let v2 = parse_version("v2.0-rc1weirderstuff").unwrap();
        assert!(v1.partial_cmp(&v2).is_none());
    }
}
