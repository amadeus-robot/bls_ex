use bls12_381::hash_to_curve::*;
use bls12_381::*;

use group::Curve;
use pairing::PairingCurveAffine;

use rayon::prelude::*;

mod errors;

use rustler::types::{Binary, OwnedBinary};
use rustler::{Encoder, Error, Env, Term, NifResult, ResourceArc, Resource};

use reed_solomon_simd::{ReedSolomonDecoder, ReedSolomonEncoder};
use std::collections::HashMap;
use std::sync::Mutex;

pub struct ReedSolomonResource {
    pub p_encoder: Mutex<ReedSolomonEncoder>,
    pub p_decoder: Mutex<ReedSolomonDecoder>,
}

rustler::init!(
    "Elixir.BlsEx.Native",
    [
        create_resource,
    ],
    load = on_load
);

fn on_load(env: Env, _info: Term) -> bool {
    rustler::resource!(ReedSolomonResource, env);
    true
}

mod atoms {
    rustler::atoms! {
        ok,
        error
    }
}

#[rustler::nif]
pub fn create_resource(data_shards: usize, recovery_shards: usize, size_shard: usize) -> NifResult<ResourceArc<ReedSolomonResource>> {
    let encoder = ReedSolomonEncoder::new(data_shards, recovery_shards, size_shard)
        .map_err(|_| Error::BadArg)?;
    let decoder = ReedSolomonDecoder::new(data_shards, recovery_shards, size_shard)
        .map_err(|_| Error::BadArg)?;
    let resource = ReedSolomonResource {
        p_encoder: Mutex::new(encoder),
        p_decoder: Mutex::new(decoder),
    };
    Ok(ResourceArc::new(resource))
    //println!("1");
}

#[rustler::nif]
pub fn encode_shards<'a>(env: Env<'a>, resource: ResourceArc<ReedSolomonResource>, data: Binary) -> Result<rustler::Term<'a>, rustler::Error> {
    let chunk_size = 1024;

    let mut encoder_lock = resource.p_encoder.lock().map_err(|_| Error::Term(Box::new("Poisoned mutex")))?;

    let chunk_count = (data.len() + 1023) / 1024;
    let mut encoded_shards = Vec::with_capacity(chunk_count * 2);
    let mut itr = 0;

    // Step through `data` in increments of `chunk_size`.
    for chunk_start in (0..data.len()).step_by(chunk_size) {
        let chunk_end = (chunk_start + chunk_size).min(data.len());
        let chunk = &data[chunk_start..chunk_end];

        // Create a 1024-byte buffer initialized to 0.
        let mut buffer = [0u8; 1024];
        buffer[..chunk.len()].copy_from_slice(chunk);

        encoder_lock.add_original_shard(&buffer).map_err(|_| Error::BadArg)?;

        let mut bin = OwnedBinary::new(chunk_size).unwrap();
        bin.as_mut_slice().copy_from_slice(&buffer);
        encoded_shards.push((itr, Binary::from_owned(bin, env)));
        itr += 1;
    }
    
    let result = encoder_lock.encode().map_err(|_| Error::BadArg)?;
    let recovery: Vec<_> = result.recovery_iter().collect();
    for recovered_shard in recovery {
        let mut bin = OwnedBinary::new(recovered_shard.len()).unwrap();
        bin.as_mut_slice().copy_from_slice(recovered_shard);
        encoded_shards.push((itr, Binary::from_owned(bin, env)));
        itr += 1;
    }

    Ok(encoded_shards.encode(env))
}

#[rustler::nif]
pub fn decode_shards<'a>(env: Env<'a>, resource: ResourceArc<ReedSolomonResource>, shards_term: Term<'a>, 
    total_shards: usize, original_size: usize) -> Result<rustler::Term<'a>, rustler::Error> 
{
    let shards: Vec<(usize, Binary<'a>)> = shards_term.decode().map_err(|_| Error::BadArg)?;

    let mut decoder_lock = resource.p_decoder.lock().map_err(|_| Error::Term(Box::new("Poisoned mutex")))?;

    let mut combined = vec![0u8; original_size];

    let half = total_shards / 2;
    for (index, bin) in shards {
        let idx_usize = index as usize;
        if idx_usize < half {
            let shard_data = bin.as_slice();

            let offset = idx_usize * 1024;
            // Protect against going past original_size
            let end = (offset + shard_data.len()).min(original_size);
            combined[offset..end].copy_from_slice(&shard_data[..(end - offset)]);

            decoder_lock.add_original_shard(index, shard_data).map_err(|_| Error::BadArg)?;
        } else {
            decoder_lock.add_recovery_shard(index-half, bin.as_slice()).map_err(|_| Error::BadArg)?;
        }
    }
    let result = decoder_lock.decode().map_err(|_| Error::BadArg)?;

    for idx in 0..half {
        if let Some(shard_data) = result.restored_original(idx) {
            let offset = idx * 1024;
            let end = (offset + shard_data.len()).min(original_size);
            combined[offset..end].copy_from_slice(&shard_data[..(end - offset)]);
        }
    }

    let mut out_bin = OwnedBinary::new(combined.len()).unwrap();
    out_bin.as_mut_slice().copy_from_slice(&combined);
    Ok(Binary::from_owned(out_bin, env).encode(env))
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
            match parse_public_key(public_key.as_slice()) {
                Ok(pk_g1) => {
                    if !g1_projective_is_valid(&pk_g1) {
                        return (atoms::error(), "invalid_public_key").encode(env);
                    }
                                        
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
