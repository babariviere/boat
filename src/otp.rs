//! This module implements all OTP implementation needed for boat.

use byteorder::{BigEndian, ByteOrder};
use chrono::NaiveDateTime;
use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::sha1::Sha1;

/// hotp generate a 2FA code using HMAC based one time password algorithm
pub fn hotp(key: &[u8], counter: u64, digit: u8) -> u32 {
    let mut hmac = Hmac::new(Sha1::new(), key);

    // compute hmac
    let mut msg = [0; 8];
    BigEndian::write_u64(&mut msg, counter);
    hmac.input(&msg);
    let hmac_res = hmac.result();
    let hs = hmac_res.code();

    // compute HOTP value
    let offset = (hs[hs.len() - 1] & (hs.len() as u8 - 5)) as usize;
    let snum = (hs[offset] as u32 & 0x7f) << 24
        | (hs[offset + 1] as u32 & 0xff) << 16
        | (hs[offset + 2] as u32 & 0xff) << 8
        | (hs[offset + 3] as u32 & 0xff);
    snum % 10u32.pow(digit as u32)
}

/// totp generate a 2FA code using Time based one time password algorithm
pub fn totp(key: &[u8], time: NaiveDateTime, digit: u8) -> u32 {
    let timestamp = time.timestamp() as u64;
    hotp(key, timestamp / 30, digit)
}

#[cfg(test)]
mod tests {
    use super::*;

    // These values are taken from RFC 4226:
    // https://tools.ietf.org/html/rfc4226#page-32
    const SECRET: &str = "12345678901234567890";
    const EXPECT: &[u32] = &[
        755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489,
    ];

    #[test]
    fn test_hotp() {
        for (i, e) in EXPECT.iter().enumerate() {
            let result = hotp(SECRET.as_bytes(), i as u64, 6);
            assert_eq!(*e, result);
        }
    }

    #[test]
    fn test_totp() {
        for (i, e) in EXPECT.iter().enumerate() {
            for j in 0..30 {
                let time = NaiveDateTime::from_timestamp(i as i64 * 30 + j, 0);
                let result = totp(SECRET.as_bytes(), time, 6);
                assert_eq!(*e, result);
            }
        }
    }
}
