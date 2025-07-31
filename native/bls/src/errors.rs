use rustler::{Atom, Env};

#[derive(Debug)]
pub enum CryptoError {
    /// Cryptographic invalidity
    InvalidSignature,
    InvalidPoint,
    ZeroSizedInput,
    InvalidSeed,
    VerificationFailed,
}

impl CryptoError {
    pub fn to_atom<'a>(self, env: Env<'a>) -> Atom {
        return match self {
            CryptoError::InvalidPoint => Atom::from_str(env, "invalid_point").unwrap(),
            CryptoError::InvalidSignature => Atom::from_str(env, "invalid_signature").unwrap(),
            CryptoError::ZeroSizedInput =>  Atom::from_str(env, "zero_sized_input").unwrap(),
            CryptoError::InvalidSeed =>  Atom::from_str(env, "invalid_seed").unwrap(),
            CryptoError::VerificationFailed =>  Atom::from_str(env, "verification_failed").unwrap(),
        }
    }
}
