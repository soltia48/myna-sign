//! The clock.
//!
//! A signature records time in more formats than is comfortable: a PDF date string, an ASN.1
//! `UTCTime`, an OpenPGP creation time, and `myna-card`'s [`Date`] for checking a certificate's
//! validity. They are all the same instant, so they are all derived here from one Unix timestamp
//! rather than each being read off the system clock separately.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use myna_card::Date;

use crate::error::{Error, Result};

/// Seconds Japan Standard Time runs ahead of UTC.
const JST_OFFSET: i64 = 9 * 3600;

/// An instant, as seconds since the Unix epoch.
///
/// Held as a signed count so that a certificate's `notBefore` — which may predate 1970 in
/// principle, and certainly predates *now* — is representable without a special case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(i64);

impl Timestamp {
    /// The current time, from the system clock.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if the system clock is before the Unix epoch.
    pub fn now() -> Result<Self> {
        let d = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::malformed("the system clock is before 1970"))?;
        Ok(Timestamp(d.as_secs() as i64))
    }

    /// From seconds since the Unix epoch.
    pub const fn from_unix_seconds(seconds: i64) -> Self {
        Timestamp(seconds)
    }

    /// Seconds since the Unix epoch.
    pub const fn unix_seconds(self) -> i64 {
        self.0
    }

    /// As a [`SystemTime`], for the crates that want one.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if the instant is before the Unix epoch, which those crates cannot
    /// represent here.
    pub fn to_system_time(self) -> Result<SystemTime> {
        u64::try_from(self.0)
            .ok()
            .and_then(|s| UNIX_EPOCH.checked_add(Duration::from_secs(s)))
            .ok_or_else(|| Error::malformed(format!("{} is not representable", self.0)))
    }

    /// As `myna-card`'s calendar date, for checking certificate validity.
    pub fn to_date(self) -> Date {
        Date::from_unix_seconds(self.0)
    }

    /// As a PDF date string, `D:YYYYMMDDHHmmSS+00'00'`.
    ///
    /// Always written in UTC. A local offset would say where the signer was, which is more than
    /// the document needs to carry.
    pub fn to_pdf_date(self) -> String {
        let (y, mo, d, h, mi, s) = self.civil();
        format!("D:{y:04}{mo:02}{d:02}{h:02}{mi:02}{s:02}+00'00'")
    }

    /// The same instant in Japan Standard Time, `YYYY-MM-DD HH:MM JST`.
    ///
    /// JST is UTC+9 the whole year round — Japan has had no daylight saving since 1951 — so this
    /// is a fixed offset and needs no timezone database. Seconds are dropped: this is for a person
    /// to read, and the exact instant is in the signature.
    pub fn to_jst_minutes(self) -> String {
        let (y, mo, d, h, mi, _) = Timestamp(self.0 + JST_OFFSET).civil();
        format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02} JST")
    }

    /// As RFC 3339, for display and for JSON going to the front end.
    pub fn to_rfc3339(self) -> String {
        let (y, mo, d, h, mi, s) = self.civil();
        format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
    }

    /// Read a PDF date string, `D:YYYYMMDDHHmmSSOHH'mm'`.
    ///
    /// Everything after the year is optional, and the offset may be `Z`, `+`, `-`, or absent. The
    /// result is UTC, so a caller does not have to carry the offset around: it is the same instant
    /// either way, and every other time in this crate is UTC too.
    pub fn parse_pdf_date(text: &str) -> Option<Self> {
        let digits = text.strip_prefix("D:").unwrap_or(text);
        let number =
            |from: usize, len: usize| -> Option<i64> { digits.get(from..from + len)?.parse().ok() };

        let year = number(0, 4)?;
        let month = number(4, 2).unwrap_or(1).clamp(1, 12);
        let day = number(6, 2).unwrap_or(1).clamp(1, 31);
        let hour = number(8, 2).unwrap_or(0);
        let minute = number(10, 2).unwrap_or(0);
        let second = number(12, 2).unwrap_or(0);

        // Howard Hinnant's days_from_civil, the inverse of `civil`.
        let y = year - i64::from(month <= 2);
        let era = y.div_euclid(400);
        let yoe = y - era * 400;
        let mp = (month + 9) % 12;
        let doy = (153 * mp + 2) / 5 + day - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        let days = era * 146_097 + doe - 719_468;
        let mut seconds = days * 86_400 + hour * 3600 + minute * 60 + second;

        // The trailing offset says what that clock reading was relative to.
        if let Some(sign) = digits.as_bytes().get(14) {
            let offset_hours = number(15, 2).unwrap_or(0);
            let offset_minutes = digits
                .get(18..20)
                .and_then(|m| m.parse::<i64>().ok())
                .unwrap_or(0);
            let offset = offset_hours * 3600 + offset_minutes * 60;
            match sign {
                b'+' => seconds -= offset,
                b'-' => seconds += offset,
                _ => {}
            }
        }
        Some(Timestamp(seconds))
    }

    /// Year, month, day, hour, minute, second in UTC.
    ///
    /// Howard Hinnant's `civil_from_days`, the same algorithm `myna-card`'s [`Date`] uses; the
    /// time of day is what it drops and this keeps.
    fn civil(self) -> (i64, u8, u8, u8, u8, u8) {
        let days = self.0.div_euclid(86_400);
        let secs = self.0.rem_euclid(86_400);
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = (doy - (153 * mp + 2) / 5 + 1) as u8;
        let month = if mp < 10 { mp + 3 } else { mp - 9 } as u8;
        let year = yoe + era * 400 + i64::from(month <= 2);
        (
            year,
            month,
            day,
            (secs / 3600) as u8,
            (secs / 60 % 60) as u8,
            (secs % 60) as u8,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_a_known_instant_in_every_format() {
        // 2026-08-15T06:26:28Z — the genTime one of the design's trial timestamps came back with.
        let t = Timestamp::from_unix_seconds(1_786_775_188);
        assert_eq!(t.to_rfc3339(), "2026-08-15T06:26:28Z");
        assert_eq!(t.to_pdf_date(), "D:20260815062628+00'00'");
        let date = t.to_date();
        assert_eq!((date.year, date.month, date.day), (2026, 8, 15));
    }

    #[test]
    fn renders_japan_standard_time() {
        // 2026-08-15T06:26:28Z is 15:26 in Tokyo.
        let t = Timestamp::from_unix_seconds(1_786_775_188);
        assert_eq!(t.to_rfc3339(), "2026-08-15T06:26:28Z");
        assert_eq!(t.to_jst_minutes(), "2026-08-15 15:26 JST");

        // And it crosses the date, which a naive hour-only conversion would get wrong.
        let evening = Timestamp::from_unix_seconds(1_786_775_188 + 10 * 3600);
        assert_eq!(evening.to_rfc3339(), "2026-08-15T16:26:28Z");
        assert_eq!(evening.to_jst_minutes(), "2026-08-16 01:26 JST");
    }

    #[test]
    fn handles_the_epoch_and_a_leap_day() {
        assert_eq!(
            Timestamp::from_unix_seconds(0).to_rfc3339(),
            "1970-01-01T00:00:00Z"
        );
        // 2024-02-29T23:59:59Z
        assert_eq!(
            Timestamp::from_unix_seconds(1_709_251_199).to_rfc3339(),
            "2024-02-29T23:59:59Z"
        );
    }

    #[test]
    fn reads_the_dates_pdfs_write() {
        // What this program writes.
        assert_eq!(
            Timestamp::parse_pdf_date("D:20260815062628+00'00'")
                .unwrap()
                .to_rfc3339(),
            "2026-08-15T06:26:28Z"
        );
        // A local offset, which most producers write. 15:26 in Tokyo is the same instant.
        assert_eq!(
            Timestamp::parse_pdf_date("D:20260815152628+09'00'")
                .unwrap()
                .to_rfc3339(),
            "2026-08-15T06:26:28Z"
        );
        assert_eq!(
            Timestamp::parse_pdf_date("D:20260815012628-05'00'")
                .unwrap()
                .to_rfc3339(),
            "2026-08-15T06:26:28Z"
        );
        // Truncated forms are legal.
        assert_eq!(
            Timestamp::parse_pdf_date("D:20260815")
                .unwrap()
                .to_rfc3339(),
            "2026-08-15T00:00:00Z"
        );
        assert_eq!(Timestamp::parse_pdf_date("nonsense"), None);
    }

    #[test]
    fn round_trips_through_system_time() {
        let t = Timestamp::from_unix_seconds(1_786_775_188);
        let back = t
            .to_system_time()
            .unwrap()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(back as i64, t.unix_seconds());
    }
}
