use hpke_rs_crypto::{error::Error, types::KemAlgorithm, HpkeCrypto};
use crate::{
    kdf::{labeled_expand, labeled_extract},
    kem::*,
};

fn oqs_kem_name(alg:KemAlgorithm) -> Result<oqs::kem::Algorithm,Error> {
    match alg {
        KemAlgorithm::Kyber512 => Ok(oqs::kem::Algorithm::Kyber512),
        _ => Err(Error::UnknownKemAlgorithm)
    }
}



pub(super) fn key_gen<Crypto: HpkeCrypto>(
    alg:KemAlgorithm,
) -> Result<(Vec<u8>, Vec<u8>), Error> {

    let kem_name = oqs_kem_name(alg)?;

    let kemalg = match oqs::kem::Kem::new(kem_name) {
        Ok(k) => k,
        Err(_) => return Err(Error::CryptoLibraryError(format!("Failed to initialize liboqs KEM"))),
    };

    let (pk, sk) = match kemalg.keypair() {
        Ok(keys) => keys,
        Err(_) => return Err(Error::CryptoLibraryError(format!("liboqs key generation failed"))),
    };
    Ok((sk.into_vec(), pk.into_vec()))
}



pub(super) fn derive_key_pair<Crypto: HpkeCrypto>(
    alg:KemAlgorithm,
    suite_id: &[u8],
    ikm: &[u8],
) -> Result<(PublicKey, PrivateKey), Error> {

    let kem_name = oqs_kem_name(alg)?;

    // Turn the ikm into a standard 64 bytes
    let prk = labeled_extract::<Crypto>(alg.into(), &[], suite_id, "dkp_prk", &ikm);
    let dpk_ikm = match labeled_expand::<Crypto>(alg.into(), &prk, suite_id, "dkp_ikm", &[], 64) {
        Ok(k) => k,
        Err(_) => return Err(Error::CryptoLibraryError(format!("Failed to derive initial key material"))),
    };


    let kemalg = match oqs::kem::Kem::new(kem_name) {
        Ok(k) => k,
        Err(_) => return Err(Error::CryptoLibraryError(format!("Failed to initialize liboqs KEM"))),
    };

    let (pk, sk) = match kemalg.derive_keypair(&dpk_ikm) {
        Ok(keys) => keys,
        Err(_) => return Err(Error::CryptoLibraryError(format!("liboqs deriving keypair failed"))),
    };
    Ok((pk.into_vec(), sk.into_vec()))
}

pub(super) fn encaps<Crypto: HpkeCrypto>(
    alg:KemAlgorithm,
    pk_r: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let kem_name = oqs_kem_name(alg)?;
    let kemalg = match oqs::kem::Kem::new(kem_name) {
        Ok(k) => k,
        Err(_) => return Err(Error::CryptoLibraryError(format!("Failed to initialize liboqs KEM"))),
    };

    let pubkey = match kemalg.public_key_from_bytes(pk_r) {
        Some(pk) => pk,
        None => return Err(Error::CryptoLibraryError(format!("Failed to build public key from bytes"))),
    };

    let (kem_ct, kem_ss) = match kemalg.encapsulate(&pubkey) {
        Ok(r) => r,
        Err(_) => return Err(Error::CryptoLibraryError(format!("Failed to run liboqs encapsulate"))),
    };

    Ok((kem_ss.into_vec(), kem_ct.into_vec()))

}

pub(super) fn decaps<Crypto: HpkeCrypto>(
    alg: KemAlgorithm,
    enc: &[u8],
    sk_r: &[u8],
) -> Result<Vec<u8>, Error> {
    let kem_name = oqs_kem_name(alg)?;
    let kemalg = match oqs::kem::Kem::new(kem_name) {
        Ok(k) => k,
        Err(_) => return Err(Error::CryptoLibraryError(format!("Failed to initialize liboqs KEM"))),
    };

    let seckey = match kemalg.secret_key_from_bytes(sk_r) {
        Some(sk) => sk,
        None => return Err(Error::CryptoLibraryError(format!("Failed to build secret key from bytes"))),
    };

    let ctxt = match kemalg.ciphertext_from_bytes(enc) {
        Some(ct) => ct,
        None => return Err(Error::CryptoLibraryError(format!("Failed to build ciphertext from bytes"))),
    };

    let kem_ss = match kemalg.decapsulate(&seckey, &ctxt) {
        Ok(ss) => ss,
        Err(_) => return Err(Error::CryptoLibraryError(format!("Failed to run liboqs decapsulate"))),
    };

    Ok(kem_ss.into_vec())
}