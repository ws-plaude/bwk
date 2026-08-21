pub fn remove_leading_zeroes(list: &[u8]) -> Vec<u8> {
    if let Some(first_non_zero) = list.iter().position(|&x| x != 0) {
        list[first_non_zero..].to_vec()
    } else {
        Vec::new()
    }
}

pub trait Threading: Send + Sync {}

/// Seconds to add to UTC to get local time, as the device expects it. Falls back to UTC when
/// the platform will not tell us.
pub fn local_utc_offset_secs() -> i32 {
    #[cfg(unix)]
    {
        let now = unsafe { libc::time(std::ptr::null_mut()) };
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        if unsafe { libc::localtime_r(&now, &mut tm) }.is_null() {
            return 0;
        }
        tm.tm_gmtoff as i32
    }

    #[cfg(windows)]
    {
        use windows_sys::Win32::System::{
            SystemServices::{TIME_ZONE_ID_DAYLIGHT, TIME_ZONE_ID_STANDARD},
            Time::{GetTimeZoneInformation, TIME_ZONE_ID_INVALID, TIME_ZONE_INFORMATION},
        };

        let mut info: TIME_ZONE_INFORMATION = unsafe { std::mem::zeroed() };
        // Windows reports how many minutes to add to local time to get UTC, so the sign flips.
        let bias = match unsafe { GetTimeZoneInformation(&mut info) } {
            TIME_ZONE_ID_STANDARD => info.Bias + info.StandardBias,
            TIME_ZONE_ID_DAYLIGHT => info.Bias + info.DaylightBias,
            TIME_ZONE_ID_INVALID => return 0,
            _ => info.Bias,
        };
        -bias * 60
    }
}
