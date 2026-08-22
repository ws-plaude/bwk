use std::{cmp::Ordering, collections::BTreeMap, str::FromStr};

use bitcoin::{
    bip32::{ChildNumber, DerivationPath, KeySource},
    psbt::Psbt,
    secp256k1::PublicKey,
};

use crate::{Error, HWI};

pub struct Bip32DerivationFilter<'a> {
    psbt: &'a mut Psbt,
    ignored_bip32_derivations: Vec<BTreeMap<PublicKey, KeySource>>,
}

impl<'a> Bip32DerivationFilter<'a> {
    pub fn new(psbt: &'a mut Psbt) -> Self {
        Self {
            ignored_bip32_derivations: psbt.inputs.iter().map(|_| BTreeMap::new()).collect(),
            psbt,
        }
    }
    // Bitbox and Coldcard sign with the first bip32_derivation that matches its fingerprint.
    // In order to to multiple round of signing the bip32_derivation of keys that
    // signed the psbt must be removed then appended once the tx is signed.
    pub fn ignore_signed_key_derivation(mut self) -> Self {
        for (i, input) in self.psbt.inputs.iter_mut().enumerate() {
            for key in input.partial_sigs.keys() {
                if let Some(derivation) = input.bip32_derivation.remove(&key.inner) {
                    self.ignored_bip32_derivations[i].insert(key.inner, derivation);
                }
            }
        }
        self
    }

    // Input may have multiple derivation with the same fingerprint and different derivation
    // for example:
    // Input A: fg/0/0, fg/1/0 and Input B fg/0/1, fg/1/1.
    // We want for this first round of signature to have A: fg/0/0 and fg/0/1
    pub fn ignore_same_fg_bip32_derivations(mut self) -> Self {
        let mut priority_order = Vec::<KeySource>::new();
        for input in &self.psbt.inputs {
            for source in input.bip32_derivation.values() {
                priority_order.push(source.clone());
            }
        }
        priority_order.sort_by(|(fg1, path1), (fg2, path2)| match fg1.cmp(fg2) {
            Ordering::Less => Ordering::Less,
            Ordering::Greater => Ordering::Greater,
            Ordering::Equal => path2.cmp(path1),
        });

        for (i, input) in self.psbt.inputs.iter_mut().enumerate() {
            let mut to_remove = Vec::<PublicKey>::new();
            for (key1, source1) in &input.bip32_derivation {
                for (key2, source2) in &input.bip32_derivation {
                    if source1.0 == source2.0 && source1.1 != source2.1 {
                        if priority_order.iter().position(|s| s == source1)
                            < priority_order.iter().position(|s| s == source2)
                        {
                            to_remove.push(*key2);
                        } else {
                            to_remove.push(*key1);
                        }
                    }
                }
            }
            for key in to_remove {
                if let Some(derivation) = input.bip32_derivation.remove(&key) {
                    self.ignored_bip32_derivations[i].insert(key, derivation);
                }
            }
        }

        self
    }

    /// Signs the psbt with the HWI interface and puts back the ignored bip32 derivations
    pub fn sign_psbt<T: HWI>(mut self, device: &T) -> Result<(), Error> {
        device.sign_tx(self.psbt)?;

        for (i, input) in self.psbt.inputs.iter_mut().enumerate() {
            input
                .bip32_derivation
                .append(&mut self.ignored_bip32_derivations[i]);
        }

        Ok(())
    }
}

pub fn merge_signatures(psbt: &mut Psbt, signed_psbt: &Psbt) {
    for i in 0..signed_psbt.inputs.len() {
        let psbtin = match psbt.inputs.get_mut(i) {
            Some(psbtin) => psbtin,
            None => continue,
        };
        let signed_psbtin = match signed_psbt.inputs.get(i) {
            Some(signed_psbtin) => signed_psbtin,
            None => continue,
        };
        psbtin
            .partial_sigs
            .extend(&mut signed_psbtin.partial_sigs.iter());
        psbtin
            .tap_script_sigs
            .extend(&mut signed_psbtin.tap_script_sigs.iter());
        if let Some(sig) = signed_psbtin.tap_key_sig {
            psbtin.tap_key_sig = Some(sig);
        }
    }
}

pub fn bip86_path_child_numbers(path: DerivationPath) -> Result<Vec<ChildNumber>, Error> {
    let children: Vec<ChildNumber> = path.into();
    if children.len() != 5
        || children[0] != ChildNumber::from_hardened_idx(86).unwrap()
        || children[1].is_normal()
        || children[2].is_normal()
        || children[3].is_hardened()
        || children[4].is_hardened()
    {
        Err(Error::InvalidParameter(
            "derivation_path",
            "path is not bip86 compatible".to_string(),
        ))
    } else {
        Ok(children)
    }
}

/// Base58 as Bitcoin defines it: no `0`, `O`, `I` or `l`.
fn is_base58(c: char) -> bool {
    c.is_ascii_alphanumeric() && !matches!(c, '0' | 'O' | 'I' | 'l')
}

/// An extended key body is the version prefix plus 79 to 108 base58 characters,
/// which covers every prefix the supported devices emit.
const XKEY_BODY_MIN: usize = 79;
const XKEY_BODY_MAX: usize = 108;

/// Version prefixes an extended key can carry, mainnet and testnet, across the
/// script types the devices report.
const XKEY_PREFIXES: [&str; 10] = [
    "xpub", "ypub", "Ypub", "zpub", "Zpub", "tpub", "upub", "Upub", "vpub", "Vpub",
];

/// End offset of the extended key at `at`, which must start with a version
/// prefix, or `None` if none does.
fn xkey_body_end(s: &str, at: usize) -> Option<usize> {
    let rest = s.get(at..)?;
    let prefix = XKEY_PREFIXES.iter().find(|p| rest.starts_with(**p))?;
    let len = rest[prefix.len()..]
        .chars()
        .take_while(|c| is_base58(*c))
        .take(XKEY_BODY_MAX)
        .count();
    (len >= XKEY_BODY_MIN).then_some(at + prefix.len() + len)
}

/// End offset of the extended key starting at `at`, origin prefix included, or
/// `None` if none starts there.
fn xkey_end(s: &str, at: usize) -> Option<usize> {
    if s[at..].starts_with('[') {
        let tail = &s[at + 1..];
        // An origin is the shortest bracketed run that a key actually follows,
        // so keep trying closing brackets rather than stopping at the first.
        for (offset, _) in tail.match_indices(']') {
            if offset == 0 {
                continue;
            }
            if tail[..offset].contains('\n') {
                break;
            }
            if let Some(end) = xkey_body_end(s, at + offset + 2) {
                return Some(end);
            }
        }
    }
    xkey_body_end(s, at)
}

/// Every extended key in `s`, each with its `[fingerprint/path]` origin when it
/// has one, in order of appearance and without duplicates.
pub fn find_xkeys(s: &str) -> Vec<&str> {
    let mut keys: Vec<&str> = Vec::new();
    let mut at = 0;
    while at < s.len() {
        match xkey_end(s, at) {
            Some(end) => {
                let key = &s[at..end];
                if !keys.contains(&key) {
                    keys.push(key);
                }
                at = end;
            }
            // Not a key here: advance one character, not one byte.
            None => at += s[at..].chars().next().map_or(1, char::len_utf8),
        }
    }
    keys
}

pub fn extract_keys_and_template<T: FromStr>(policy: &str) -> Result<(String, Vec<T>), Error> {
    let mut descriptor_template = policy.to_string();
    let pubkeys_str = find_xkeys(policy);

    let mut pubkeys: Vec<T> = Vec::new();
    for (i, key_str) in pubkeys_str.iter().enumerate() {
        descriptor_template = descriptor_template.replace(key_str, &format!("@{i}"));
        let pubkey = T::from_str(key_str).map_err(|_| Error::UnsupportedInput)?;
        pubkeys.push(pubkey);
    }

    // Do not include the hash in the descriptor template.
    if let Some((descriptor_template, _hash)) = descriptor_template.rsplit_once('#') {
        Ok((descriptor_template.to_string(), pubkeys))
    } else {
        Ok((descriptor_template, pubkeys))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn find_xkeys_reads_keys_with_and_without_an_origin() {
        let policy = "wsh(or_d(pk([f5acc2fd/49'/1'/0']tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP/**),and_v(v:pkh(tpubDDtb2WPYwEWw2WWDV7reLV348iJHw2HmhzvPysKKrJw3hYmvrd4jasyoioVPdKGQqjyaBMEvTn1HvHWDSVqQ6amyyxRZ5YjpPBBGjJ8yu8S/**),older(100))))";
        assert_eq!(
            find_xkeys(policy),
            vec![
                "[f5acc2fd/49'/1'/0']tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP",
                "tpubDDtb2WPYwEWw2WWDV7reLV348iJHw2HmhzvPysKKrJw3hYmvrd4jasyoioVPdKGQqjyaBMEvTn1HvHWDSVqQ6amyyxRZ5YjpPBBGjJ8yu8S",
            ]
        );
    }

    #[test]
    fn find_xkeys_drops_repeats_and_keeps_first_seen_order() {
        let policy = format!("wsh(multi(2,tpubDDtb2WPYwEWw2WWDV7reLV348iJHw2HmhzvPysKKrJw3hYmvrd4jasyoioVPdKGQqjyaBMEvTn1HvHWDSVqQ6amyyxRZ5YjpPBBGjJ8yu8S/<0;1>/*,tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP/<0;1>/*,tpubDDtb2WPYwEWw2WWDV7reLV348iJHw2HmhzvPysKKrJw3hYmvrd4jasyoioVPdKGQqjyaBMEvTn1HvHWDSVqQ6amyyxRZ5YjpPBBGjJ8yu8S/<2;3>/*))");
        assert_eq!(find_xkeys(&policy), vec!["tpubDDtb2WPYwEWw2WWDV7reLV348iJHw2HmhzvPysKKrJw3hYmvrd4jasyoioVPdKGQqjyaBMEvTn1HvHWDSVqQ6amyyxRZ5YjpPBBGjJ8yu8S", "tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP"]);
    }

    #[test]
    fn find_xkeys_accepts_every_version_prefix() {
        for prefix in XKEY_PREFIXES {
            let key = format!("{prefix}{}", "1".repeat(XKEY_BODY_MIN));
            assert_eq!(find_xkeys(&key), vec![key.as_str()], "prefix {prefix}");
        }
        let unknown = format!("wpub{}", "1".repeat(XKEY_BODY_MIN));
        assert!(find_xkeys(&unknown).is_empty());
    }

    #[test]
    fn find_xkeys_holds_to_the_body_length_bounds() {
        let short = format!("xpub{}", "1".repeat(XKEY_BODY_MIN - 1));
        assert!(find_xkeys(&short).is_empty());

        let exact = format!("xpub{}", "1".repeat(XKEY_BODY_MIN));
        assert_eq!(find_xkeys(&exact), vec![exact.as_str()]);

        // Past the maximum the key is still read, truncated to the bound.
        let long = format!("xpub{}", "1".repeat(XKEY_BODY_MAX + 5));
        let expected = format!("xpub{}", "1".repeat(XKEY_BODY_MAX));
        assert_eq!(find_xkeys(&long), vec![expected.as_str()]);
    }

    #[test]
    fn find_xkeys_rejects_non_base58_in_the_body() {
        // `0`, `O`, `I` and `l` are not base58, so each cuts the body short.
        for excluded in ['0', 'O', 'I', 'l'] {
            let key = format!(
                "xpub{}{excluded}{}",
                "1".repeat(10),
                "1".repeat(XKEY_BODY_MIN)
            );
            assert!(find_xkeys(&key).is_empty(), "stopped at {excluded}");
        }
    }

    #[test]
    fn find_xkeys_skips_an_empty_origin() {
        let key = format!("[]xpub{}", "1".repeat(XKEY_BODY_MIN));
        assert_eq!(find_xkeys(&key), vec![&key[2..]]);
    }

    #[test]
    fn find_xkeys_scans_past_a_bracket_no_key_follows() {
        // The first `]` is not the origin's: the key sits after the second.
        let key = format!("[aa]]xpub{}", "1".repeat(XKEY_BODY_MIN));
        assert_eq!(find_xkeys(&key), vec![key.as_str()]);
    }

    #[test]
    fn find_xkeys_stops_an_origin_at_a_newline() {
        let key = format!("[aa\n]xpub{}", "1".repeat(XKEY_BODY_MIN));
        assert_eq!(find_xkeys(&key), vec![&key[5..]]);
    }

    #[test]
    fn test_sort_bip32_derivations() {
        let mut psbt = Psbt::from_str("cHNidP8BAHsCAAAAAh/15kGCwOjLZaE7ZHgyFCC23/gtSrNzMbaU3QVoObVMAAAAAAADAAAAaZVnLM/0m8tO/hQYbcj/8cgQDPShGTvdLLP92IuMY+AAAAAAAAMAAAABcqvYAAAAAAAWABRfpun7hibqOdLheZS5uMK6vaGGeAAAAAAAAQDNAgAAAAABAUqXyx/ZvZ9g3I3UQAJBdQpXhb9zsX3wAz3diqSUZdSEAAAAAAD9////AsCRIQAAAAAAIgAgZoVtQhlntZMrf59q18ZXcloS7zuTNwzWlk2ue6AfYXjXcgYBAAAAACJRILI06l4ffy8TFU9JkuhqITsXQG7WgAKfAqsE9+6RXs25AUCCBQQeiXDedRVQrEzGpbOAN3nBeHi684grThlBnWITpQwg0uuTZWOWXvUi+sCjbkp7rawKVJHmbcm3goo7z8wfXXMCAAEBK8CRIQAAAAAAIgAgZoVtQhlntZMrf59q18ZXcloS7zuTNwzWlk2ue6AfYXgBBcNjdqkUhtUCeSdV6c+JD+NjgK9q9x+NERyIrVOyZ1MhAvTnwl5frCTq8VBSwbjFeGVJSWI7szRmUpXeYqGNeMvBIQKKGzJgCMHoYVY3PuOHqRckVeu/AMZZYAojg5l4c6Xs7CEDALj4eSgv/8PDJfr7FafHbp37eRAFNu35j6YjjUQBg9VTrnNkdqkUWDsIsNNHqVv+BBFWsJv4HNq59yOIrGt2qRSbRhlpvcv4kmaQX0KfZQeWD1asqoisbJNSiFKyaGgiBgKKGzJgCMHoYVY3PuOHqRckVeu/AMZZYAojg5l4c6Xs7Bx1iX/UMAAAgAEAAIAAAACAAgAAgAAAAAABAAAAIgYCk+Xw5l/SoRp3VEc0tKQcxl/RZTryWMGYBNwZg/oDS+ccdYl/1DAAAIABAACAAAAAgAIAAIAEAAAAAQAAACIGAvTnwl5frCTq8VBSwbjFeGVJSWI7szRmUpXeYqGNeMvBHP/WPI0wAACAAQAAgAAAAIACAACAAAAAAAEAAAAiBgMAuPh5KC//w8Ml+vsVp8dunft5EAU27fmPpiONRAGD1Rx1iX/UMAAAgAEAAIAAAACAAgAAgAIAAAABAAAAIgYDbARMwQol143Bct+i8beurng64VfQEAa5o3O/TZ2XqjUc/9Y8jTAAAIABAACAAAAAgAIAAIACAAAAAQAAACIGA6yo/OGt6/JdectW46LtBYWAqhZp84Ztb84y2EducD1mHHWJf9QwAACAAQAAgAAAAIACAACABgAAAAEAAAAAAQDNAgAAAAABASDM44ZcYGmQVLiLUOidUWAdw5ZkyYgPXN1hK7jJzP0eAQAAAAD9////AgAbtwAAAAAAIgAgo8c5Xz17pAzNYmajjIQL6DkxUl9wfQ8VXIIClqe/AVwxlEIAAAAAACJRIEN+NDMo013uK2NVEdeUr6ecvUP+vZ6b3vxjejUOG9w0AUA7UnrKHjcNmj1V7zLvz1200fkPD+Txvx311R1IAlri6jLqfzIUGpf9CGlKVMvPbuJ0+ECps33w1jksdkS6CFlrXXMCAAEBKwAbtwAAAAAAIgAgo8c5Xz17pAzNYmajjIQL6DkxUl9wfQ8VXIIClqe/AVwBBcNjdqkUHd0i2ARsVhXSntL3fHZPWINkiZyIrVOyZ1MhAvFlw9KXZJK7Qr0ifD1vq1NeRxYt6/wfKCfFlZyJwOzaIQI+6wL/2TYIzi2s3ip62Oty8akWAiJYnq8DA926Nht9miECNIQ4reK+jlbcH5+2wTRydMhyTDwBsG/QqP3DO16/MdBTrnNkdqkUf7VSsOgGBaVnRiMtnUIBNtt4czGIrGt2qRQMzc1qzPlNlGdGO8Qvb9lZwoCtN4isbJNSiFKyaGgiBgI0hDit4r6OVtwfn7bBNHJ0yHJMPAGwb9Co/cM7Xr8x0Bx1iX/UMAAAgAEAAIAAAACAAgAAgAIAAAAAAAAAIgYCPusC/9k2CM4trN4qetjrcvGpFgIiWJ6vAwPdujYbfZocdYl/1DAAAIABAACAAAAAgAIAAIAAAAAAAAAAACIGAvFlw9KXZJK7Qr0ifD1vq1NeRxYt6/wfKCfFlZyJwOzaHP/WPI0wAACAAQAAgAAAAIACAACAAAAAAAAAAAAiBgL49k5PF36Iw1rYreP9EqXpMRkXeqJivuS5m0y27+8+1Bz/1jyNMAAAgAEAAIAAAACAAgAAgAIAAAAAAAAAIgYDMXho4P8Cpef7vKUcJ2vFgzI/sw/g6FTlQ50inCJbvRkcdYl/1DAAAIABAACAAAAAgAIAAIAGAAAAAAAAACIGA+9UvfTcxQxAxacrHDyD9mLDrDFCGi9SDdEIJK6SG0ZsHHWJf9QwAACAAQAAgAAAAIACAACABAAAAAAAAAAAAA==").unwrap();
        assert_eq!(psbt.inputs[0].bip32_derivation.len(), 6);
        assert_eq!(psbt.inputs[1].bip32_derivation.len(), 6);
        let filter = Bip32DerivationFilter::new(&mut psbt).ignore_same_fg_bip32_derivations();
        assert_eq!(filter.ignored_bip32_derivations[0].len(), 4);
        assert_eq!(filter.ignored_bip32_derivations[1].len(), 4);
        assert_eq!(psbt.inputs[0].bip32_derivation.len(), 2);
        assert_eq!(psbt.inputs[1].bip32_derivation.len(), 2);
    }

    #[test]
    fn test_extract_keys_and_template() {
        let res = extract_keys_and_template::<String>("wsh(or_d(pk([f5acc2fd/49'/1'/0']tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP/**),and_v(v:pkh(tpubDDtb2WPYwEWw2WWDV7reLV348iJHw2HmhzvPysKKrJw3hYmvrd4jasyoioVPdKGQqjyaBMEvTn1HvHWDSVqQ6amyyxRZ5YjpPBBGjJ8yu8S/**),older(100))))").unwrap();
        assert_eq!(res.0, "wsh(or_d(pk(@0/**),and_v(v:pkh(@1/**),older(100))))");
        assert_eq!(res.1.len(), 2);
        assert_eq!(res.1[0], "[f5acc2fd/49'/1'/0']tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP".to_string());
        assert_eq!(res.1[1], "tpubDDtb2WPYwEWw2WWDV7reLV348iJHw2HmhzvPysKKrJw3hYmvrd4jasyoioVPdKGQqjyaBMEvTn1HvHWDSVqQ6amyyxRZ5YjpPBBGjJ8yu8S".to_string());

        let res = extract_keys_and_template::<String>("wsh(or_d(multi(2,[b0822927/48'/1'/0'/2']tpubDEvZxV86Br8Knbm9tWcr5Hvmg5cYTYsg92vinqH6Bie6U8ix8CsoN9W11NQygdqVwmHUJpsHXxNsi5gXn36g4xNfLWkMqPuFhRZAmMQ7jjQ/<0;1>/*,[7fc39c07/48'/1'/0'/2']tpubDEvjgXtrUuH3Qtkapny9aE8gN847xiXsf9MDM5XueGf9nrvStqAuBSva3ajGyTvtp8Ti55FvVXsgYSXuS1tQkBeopFuodx2hRUDmQbvKxbZ/<0;1>/*),and_v(v:thresh(2,pkh([b0822927/48'/1'/0'/2']tpubDEvZxV86Br8Knbm9tWcr5Hvmg5cYTYsg92vinqH6Bie6U8ix8CsoN9W11NQygdqVwmHUJpsHXxNsi5gXn36g4xNfLWkMqPuFhRZAmMQ7jjQ/<2;3>/*),a:pkh([7fc39c07/48'/1'/0'/2']tpubDEvjgXtrUuH3Qtkapny9aE8gN847xiXsf9MDM5XueGf9nrvStqAuBSva3ajGyTvtp8Ti55FvVXsgYSXuS1tQkBeopFuodx2hRUDmQbvKxbZ/<2;3>/*),a:pkh([1a1ffd98/48'/1'/0'/2']tpubDFZqzTvGijYb13BC73CkS1er8DrP5YdzMhziN3kWCKUFaW51Yj6ggvf99YpdrkTJy4RT85mxQMHXDiFAKRxzf6BykQgT4pRRBNPshSJJcKo/<0;1>/*)),older(300))))#wp0w3hlw").unwrap();
        assert_eq!(res.0, "wsh(or_d(multi(2,@0/<0;1>/*,@1/<0;1>/*),and_v(v:thresh(2,pkh(@0/<2;3>/*),a:pkh(@1/<2;3>/*),a:pkh(@2/<0;1>/*)),older(300))))");
        assert_eq!(res.1.len(), 3);
        assert_eq!(res.1[0], "[b0822927/48'/1'/0'/2']tpubDEvZxV86Br8Knbm9tWcr5Hvmg5cYTYsg92vinqH6Bie6U8ix8CsoN9W11NQygdqVwmHUJpsHXxNsi5gXn36g4xNfLWkMqPuFhRZAmMQ7jjQ".to_string());
        assert_eq!(res.1[1], "[7fc39c07/48'/1'/0'/2']tpubDEvjgXtrUuH3Qtkapny9aE8gN847xiXsf9MDM5XueGf9nrvStqAuBSva3ajGyTvtp8Ti55FvVXsgYSXuS1tQkBeopFuodx2hRUDmQbvKxbZ".to_string());
        assert_eq!(res.1[2], "[1a1ffd98/48'/1'/0'/2']tpubDFZqzTvGijYb13BC73CkS1er8DrP5YdzMhziN3kWCKUFaW51Yj6ggvf99YpdrkTJy4RT85mxQMHXDiFAKRxzf6BykQgT4pRRBNPshSJJcKo".to_string());
    }
}
