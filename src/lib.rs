//! Library for boat program.

pub mod otp;
pub mod storage;

/// Token used to generate OTP code
pub struct Token {
    // Unique identifier to retrieve token
    id: String,
    // Name of the token
    name: String,
    // Logo URL
    logo: Option<String>,
    // Secret to generate OTP code
    secret: Vec<u8>,
    // Length of the OTP code to generate
    digit: u8,
}
