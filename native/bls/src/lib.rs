use bls12_381::hash_to_curve::*;
use bls12_381::*;

use group::Curve;
use pairing::PairingCurveAffine;

//use rayon::prelude::*;

mod errors;

use rustler::types::{Binary, OwnedBinary};
use rustler::{Encoder, Env, Term};

use bls12_381::{multi_miller_loop, Gt, G1Affine, G2Affine, G2Projective, G2Prepared};
use std::sync::OnceLock;
use sha2::Sha256;

static G1_GEN: OnceLock<G1Affine> = OnceLock::new();

rustler::init!("Elixir.BlsEx.Native");

mod atoms {
    rustler::atoms! {
        ok,
        error
    }
}

#[rustler::nif]
pub fn get_public_key<'a>(env: Env<'a>, seed: Binary) -> Term<'a> {
    match parse_secret_key(seed.as_slice()) {
        Ok(sk) => {
            let g1 = G1Projective::generator() * sk;
            let g1_bytes = g1.to_affine().to_compressed();
            let mut bin = OwnedBinary::new(g1_bytes.len()).unwrap();
            bin.as_mut_slice().copy_from_slice(&g1_bytes);
            (atoms::ok(), Binary::from_owned(bin, env)).encode(env)
        },
        Err(e) => (atoms::error(), e.to_atom(env)).encode(env)
    }
}

#[rustler::nif]
pub fn sign<'a>(env: Env<'a>, seed: Binary, message: Binary, dst: Binary) -> Term<'a> {
    match parse_secret_key(seed.as_slice()) {
        Ok(sk) => {
            let h_g2 = <G2Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(
                [message.as_slice()],
                dst.as_slice(),
            );
            let signature_bytes = (h_g2 * sk).to_affine().to_compressed();

            let mut bin = OwnedBinary::new(signature_bytes.len()).unwrap();
            bin.as_mut_slice().copy_from_slice(&signature_bytes);
            (atoms::ok(), Binary::from_owned(bin, env)).encode(env)
        },
        Err(e) => (atoms::error(), e.to_atom(env)).encode(env)
    }
}

#[rustler::nif]
pub fn verify<'a>(env: Env<'a>, public_key: Binary, signature: Binary, message: Binary, dst: Binary) -> Term<'a> {
    let pk_aff: G1Affine = match parse_public_key(public_key.as_slice()) {
        Ok(pk_proj) => pk_proj.to_affine(),
        Err(e)      => return (atoms::error(), e.to_atom(env)).encode(env),
    };
    let sig_prep: G2Prepared = match parse_signature(signature.as_slice()) {
        Ok(sig_proj) => sig_proj.to_affine().into(),
        Err(e)       => return (atoms::error(), e.to_atom(env)).encode(env),
    };

    // 1) hash-to-curve with the passed-in DST, negate, then prepare
    let h_neg_prep: G2Prepared = {
        let h_proj: G2Projective =
            <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(
                &[message.as_slice()],
                dst.as_slice(),
            );
        let mut h_aff = h_proj.to_affine();
        h_aff = -h_aff;
        h_aff.into()
    };

    // 2) lazily init & reuse the G1 generator affine
    let g1_gen: &G1Affine = G1_GEN.get_or_init(|| G1Affine::generator());
    // 3) two Miller loops + one final exponentiation
    let acc = multi_miller_loop(&[
        (g1_gen,      &sig_prep),
        (&pk_aff,     &h_neg_prep),
    ])
    .final_exponentiation();

    if acc == Gt::identity() {
        (atoms::ok(), true).encode(env)
    } else {
        (atoms::error(), errors::CryptoError::InvalidSignature.to_atom(env)).encode(env)
    }
}

pub fn verify_old<'a>(env: Env<'a>, public_key: Binary, signature: Binary, message: Binary, dst: Binary) -> Term<'a> {
    match parse_public_key(public_key.as_slice()) {
        Ok(public_key) => {
            match parse_signature(signature.as_slice()) {
                Ok(signature) => {
                    let h_g2 = <G2Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(
                        [message.as_slice()],
                        dst.as_slice(),
                    );
                    let p1 = signature.to_affine().pairing_with(&G1Affine::generator());
                    let p2 = h_g2.to_affine().pairing_with(&public_key.to_affine());

                    if p1 == p2 {
                        (atoms::ok(), true).encode(env)
                    } else {
                        (atoms::error(), errors::CryptoError::InvalidSignature.to_atom(env)).encode(env)
                    }
                },
                Err(e) => (atoms::error(), e.to_atom(env)).encode(env)
            }
        },
        Err(e) => (atoms::error(), e.to_atom(env)).encode(env)
    }
}

#[rustler::nif]
pub fn aggregate_public_keys<'a>(env: Env<'a>, public_keys: Term) -> Term<'a> {
    let public_keys: Vec<Binary> = public_keys.decode().unwrap();

    if public_keys.is_empty() {
        return (atoms::error(), errors::CryptoError::ZeroSizedInput.to_atom(env)).encode(env);
    }

    public_keys.iter()
        .map(|bin| parse_public_key(bin.as_slice()))
        .collect::<Result<Vec<G1Projective>, errors::CryptoError>>() // short-circuits on first Err
        .map(|parsed_pks| {
            let sum = parsed_pks
                .into_iter()
                .reduce(|acc, next| acc + next)
                .unwrap_or_default(); // identity if empty

            let sum_bytes = sum.to_affine().to_compressed();
            let mut bin = OwnedBinary::new(sum_bytes.len()).unwrap();
            bin.as_mut_slice().copy_from_slice(&sum_bytes);

            (atoms::ok(), Binary::from_owned(bin, env)).encode(env)
        })
        .unwrap_or_else(|e| (atoms::error(), e.to_atom(env)).encode(env))
}

#[rustler::nif]
pub fn aggregate_signatures<'a>(env: Env<'a>, signatures: Term) -> Term<'a> {
    let signatures: Vec<Binary> = signatures.decode().unwrap();

    if signatures.is_empty() {
        return (atoms::error(), errors::CryptoError::ZeroSizedInput.to_atom(env)).encode(env);
    }

    signatures.iter()
        .map(|bin| parse_signature(bin.as_slice()))
        .collect::<Result<Vec<G2Projective>, errors::CryptoError>>() // short-circuits on first Err
        .map(|parsed_sigs| {
            let sum = parsed_sigs
                .into_iter()
                .reduce(|acc, next| acc + next)
                .unwrap_or_default(); // identity if empty

            let sum_bytes = sum.to_affine().to_compressed();
            let mut bin = OwnedBinary::new(sum_bytes.len()).unwrap();
            bin.as_mut_slice().copy_from_slice(&sum_bytes);

            (atoms::ok(), Binary::from_owned(bin, env)).encode(env)
        })
        .unwrap_or_else(|e| (atoms::error(), e.to_atom(env)).encode(env))
}

#[rustler::nif]
pub fn get_shared_secret<'a>(env: Env<'a>, public_key: Binary, seed: Binary) -> Term<'a> {
    match parse_secret_key(seed.as_slice()) {
        Ok(sk) => {
            //This function guarantees public_key is valid
            match parse_public_key(public_key.as_slice()) {
                Ok(pk_g1) => {
                    let shared_secret_bytes = (pk_g1 * sk).to_affine().to_compressed();

                    let mut bin = OwnedBinary::new(shared_secret_bytes.len()).unwrap();
                    bin.as_mut_slice().copy_from_slice(&shared_secret_bytes);
                    (atoms::ok(), Binary::from_owned(bin, env)).encode(env)
                },
                Err(e) => (atoms::error(), e.to_atom(env)).encode(env)
            }
        },
        Err(e) => (atoms::error(), e.to_atom(env)).encode(env)
    }
}

#[rustler::nif]
pub fn validate_public_key<'a>(env: Env<'a>, public_key: Binary) -> Term<'a> {
    match parse_public_key(public_key.as_slice()) {
        Ok(_) => {
            atoms::ok().encode(env)
        },
        Err(e) => (atoms::error(), e.to_atom(env)).encode(env)
    }
}

fn parse_public_key(bytes: &[u8]) -> Result<G1Projective, errors::CryptoError> {
    if bytes.len() != 48 {
        return Err(errors::CryptoError::InvalidPoint);
    }
    let mut res = [0u8; 48];
    res.as_mut().copy_from_slice(bytes);

    match Option::<G1Affine>::from(G1Affine::from_compressed(&res)) {
        Some(affine) => {
            let projective = G1Projective::from(affine);
            if g1_projective_is_valid(&projective) {
                Ok(projective)
            } else {
                Err(errors::CryptoError::InvalidPoint)
            }
        }

        None => Err(errors::CryptoError::InvalidPoint)
    }
}

fn parse_signature(bytes: &[u8]) -> Result<G2Projective, errors::CryptoError> {
    if bytes.len() != 96 {
        return Err(errors::CryptoError::InvalidPoint);
    }
    let mut res = [0u8; 96];
    res.as_mut().copy_from_slice(bytes);

    match Option::from(G2Affine::from_compressed(&res)) {
        Some(affine) => {
            if g2_affine_is_valid(&affine) {
                let projective = G2Projective::from(affine);
                Ok(projective)
            } else {
                Err(errors::CryptoError::InvalidPoint)
            }
        }
        None => Err(errors::CryptoError::InvalidPoint)
    }
}

fn g1_projective_is_valid(projective: &G1Projective) -> bool {
    let is_identity: bool = projective.is_identity().into();
    let is_on_curve = projective.is_on_curve().into();
    let is_torsion_free = projective.to_affine().is_torsion_free().into();
    !is_identity && is_on_curve && is_torsion_free
}

fn g2_affine_is_valid(projective: &G2Affine) -> bool {
    let is_identity: bool = projective.is_identity().into();
    let is_on_curve = projective.is_on_curve().into();
    let is_torsion_free = projective.is_torsion_free().into();
    !is_identity && is_on_curve && is_torsion_free
}

fn parse_secret_key(seed: &[u8]) -> Result<Scalar, errors::CryptoError> {
    if let Ok(bytes_64) = seed.try_into() as Result<[u8; 64], _> {
        return Ok(Scalar::from_bytes_wide(&bytes_64));
    }
    if let Ok(bytes_32) = seed.try_into() as Result<[u8; 32], _> {
        let ct_scalar = Scalar::from_bytes(&bytes_32);
        if ct_scalar.is_some().unwrap_u8() == 1 {
            return Ok(ct_scalar.unwrap());
        } else {
            return Err(errors::CryptoError::InvalidSeed);
        }
    }
    // Otherwise, it's invalid
    Err(errors::CryptoError::InvalidSeed)
}
