use crate::{
    kdf::{labeled_expand, labeled_extract},
    kem::*,
};
use hpke_rs_crypto::{error::Error, types::KemAlgorithm, HpkeCrypto};

pub(super) fn key_gen<Crypto: HpkeCrypto>(
    prng: &mut Crypto::HpkePrng,
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let kp = pqc_kyber::keypair(prng);
    println!("KEY GEN sk: {}, pk: {}", kp.secret.len(), kp.public.len());
    Ok((kp.secret.to_vec(), kp.public.to_vec()))
}

pub(super) fn derive_key_pair<Crypto: HpkeCrypto>(
    alg: KemAlgorithm,
    suite_id: &[u8],
    ikm: &[u8],
) -> Result<(PublicKey, PrivateKey), Error> {
    println!("KDF !!!");

    const SEED_SIZE: usize = 64;
    const KYBER512_PK_SIZE: usize = 800;
    const KYBER512_SK_SIZE: usize = 1632;

    // Turn the ikm into a standard 64 bytes
    let prk = labeled_extract::<Crypto>(alg.into(), &[], suite_id, "dkp_prk", &ikm);
    let dpk_ikm = labeled_expand::<Crypto>(alg.into(), &prk, suite_id, "dkp_ikm", &[], SEED_SIZE)
        .map_err(|e| {
        Error::CryptoLibraryError(format!(
            "Failed to derive initial key material because {e:?}"
        ))
    })?;

    // TODO: wrongly implemented
    let mut pk = [0u8; KYBER512_PK_SIZE];
    pqc_kyber::kdf(&mut pk, &dpk_ikm[..], KYBER512_PK_SIZE);
    let mut sk = [0u8; KYBER512_SK_SIZE];
    pqc_kyber::kdf(&mut sk, &dpk_ikm[..], KYBER512_SK_SIZE);
    Ok((pk.to_vec(), sk.to_vec()))
}

pub(super) fn encaps<Crypto: HpkeCrypto>(
    pk_r: &[u8],
    prng: &mut Crypto::HpkePrng,
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let (ct, ss) = pqc_kyber::encapsulate(pk_r, prng).map_err(|e| {
        Error::CryptoLibraryError(format!("Failed KEM encapsulation because {e:?}"))
    })?;
    println!(
        "ENCAPSULATE !!! pk: {} (expected {}), ct: {}, ss: {}",
        pk_r.len(),
        pqc_kyber::KYBER_PUBLICKEYBYTES,
        ct.len(),
        ss.len()
    );
    Ok((ss.to_vec(), ct.to_vec()))
}

pub(super) fn decaps<Crypto: HpkeCrypto>(ct: &[u8], sk_r: &[u8]) -> Result<Vec<u8>, Error> {
    println!(
        "DECAPSULATE ct: {} (expected {}), sk: {} (expected {})",
        ct.len(),
        pqc_kyber::KYBER_CIPHERTEXTBYTES,
        sk_r.len(),
        pqc_kyber::KYBER_SECRETKEYBYTES
    );
    let kem_ss = pqc_kyber::decapsulate(ct, sk_r)
        .map_err(|e| Error::CryptoLibraryError(format!("Failed KEM decapsulate because {e:?}")))?;

    Ok(kem_ss.to_vec())
}
