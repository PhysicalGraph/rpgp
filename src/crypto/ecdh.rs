use block_padding::{Padding, Pkcs7};
use generic_array::{typenum::U8, GenericArray};
use rand::{CryptoRng, Rng};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{
    aes_kw,
    ecc_curve::{self, ECCCurve},
    public_key::PublicKeyAlgorithm,
    sym::SymmetricKeyAlgorithm,
};
use crate::errors::Result;
use crate::types::{ECDHSecretKey, Mpi, PlainSecretParams, PublicParams};

use super::hash::HashAlgorithm;

/// 20 octets representing "Anonymous Sender    ".
const ANON_SENDER: [u8; 20] = [
    0x41, 0x6E, 0x6F, 0x6E, 0x79, 0x6D, 0x6F, 0x75, 0x73, 0x20, 0x53, 0x65, 0x6E, 0x64, 0x65, 0x72,
    0x20, 0x20, 0x20, 0x20,
];

const SECRET_KEY_LENGTH: usize = 32;
const BLOCK_SIZE: usize = 8;

struct KeyPair {
    p: Vec<u8>,
    q: Vec<u8>,
}

/// Generate an ECDH KeyPair.
/// Currently only support X25519.
pub fn generate_key<R: Rng + CryptoRng>(rng: &mut R) -> (PublicParams, PlainSecretParams) {
    _generate_key(rng, ECCCurve::Curve25519, SymmetricKeyAlgorithm::AES128)
}

/// Generate an ECDH KeyPair.
/// Currently only support X25519 & NIST P-521.
fn _generate_key<R: Rng + CryptoRng>(
    rng: &mut R,
    curve: ECCCurve,
    alg_sym: SymmetricKeyAlgorithm,
) -> (PublicParams, PlainSecretParams) {
    let KeyPair { p, q } = match curve {
        ECCCurve::Curve25519 => generate_x25519_key(rng),
        ECCCurve::P521 => generate_p521_key(rng),
        _ => panic!("Unsupported curve: {:?}", curve),
    };

    // TODO: make these configurable and/or check for good defaults
    let hash = HashAlgorithm::default();
    (
        PublicParams::ECDH {
            curve,
            p: p.into(),
            hash,
            alg_sym,
        },
        PlainSecretParams::ECDH(Mpi::from_raw(q)),
    )
}

fn generate_x25519_key<R: Rng + CryptoRng>(rng: &mut R) -> KeyPair {
    let mut secret_key_bytes = Zeroizing::new([0u8; SECRET_KEY_LENGTH]);
    rng.fill_bytes(&mut *secret_key_bytes);

    let secret = StaticSecret::from(*secret_key_bytes);
    let public = PublicKey::from(&secret);

    // public key
    let p_raw = public.to_bytes();

    let mut p = Vec::with_capacity(33);
    p.push(0x40);
    p.extend_from_slice(&p_raw);

    // secret key
    // Clamp, as `to_bytes` does not clamp.
    let q_raw = curve25519_dalek::scalar::clamp_integer(secret.to_bytes());
    // Big Endian
    let q = q_raw.into_iter().rev().collect::<Vec<u8>>();

    KeyPair { p, q }
}

fn generate_p521_key<R: Rng + CryptoRng>(rng: &mut R) -> KeyPair {
    use elliptic_curve::{scalar::Scalar, sec1::ToEncodedPoint, Field};
    use p521::{AffinePoint, NistP521};

    let private_key_scalar = Scalar::<NistP521>::random(rng);
    let private_bytes = private_key_scalar.to_bytes();

    let base_point = AffinePoint::GENERATOR;
    let public_key_point = base_point * private_key_scalar;

    KeyPair {
        p: public_key_point.to_encoded_point(false).to_bytes().to_vec(),
        q: private_bytes.to_vec(),
    }
}

/// Build param for ECDH algorithm (as defined in RFC 6637)
/// https://tools.ietf.org/html/rfc6637#section-8
pub fn build_ecdh_param(
    oid: &[u8],
    alg_sym: SymmetricKeyAlgorithm,
    hash: HashAlgorithm,
    fingerprint: &[u8],
) -> Vec<u8> {
    let kdf_params = vec![
        0x03, // length of the following fields
        0x01, // reserved for future extensions
        hash as u8,
        alg_sym as u8,
    ];

    let oid_len = [oid.len() as u8];

    let values: Vec<&[u8]> = vec![
        &oid_len,
        oid,
        &[PublicKeyAlgorithm::ECDH as u8],
        &kdf_params,
        &ANON_SENDER[..],
        fingerprint,
    ];

    values.concat()
}

/// ECDH decryption.
pub fn decrypt(priv_key: &ECDHSecretKey, mpis: &[Mpi], fingerprint: &[u8]) -> Result<Vec<u8>> {
    debug!("ECDH decrypt");

    let param = build_ecdh_param(&priv_key.oid, priv_key.alg_sym, priv_key.hash, fingerprint);

    match ecc_curve::ecc_curve_from_oid(&priv_key.oid) {
        Some(ECCCurve::Curve25519) => decrypt_x25519(priv_key, mpis, &param),
        Some(ECCCurve::P521) => decrypt_p521(priv_key, mpis, &param),
        other => bail!("unsupported curve: {:?}", other),
    }
}

fn decrypt_x25519(priv_key: &ECDHSecretKey, mpis: &[Mpi], param: &[u8]) -> Result<Vec<u8>> {
    // 33 = 0x40 + 32bits
    ensure_eq!(mpis.len(), 3);
    ensure_eq!(mpis[0].len(), 33, "invalid public point");
    ensure_eq!(priv_key.secret().len(), 32, "invalid secret point");

    let their_public = {
        // public part of the ephemeral key (removes 0x40 prefix)
        let ephemeral_public_key = &mpis[0].as_bytes()[1..];

        // create montgomery point
        let mut ephemeral_public_key_arr = [0u8; 32];
        ephemeral_public_key_arr[..].copy_from_slice(ephemeral_public_key);

        x25519_dalek::PublicKey::from(ephemeral_public_key_arr)
    };

    let our_secret = {
        // private key of the recipient.
        let private_key = &priv_key.secret();

        // create scalar and reverse to little endian
        let mut private_key_le = private_key.iter().rev().cloned().collect::<Vec<u8>>();
        let mut private_key_arr = [0u8; 32];
        private_key_arr[..].copy_from_slice(&private_key_le);
        private_key_le.zeroize();

        StaticSecret::from(private_key_arr)
    };

    // derive shared secret
    let shared_secret = our_secret.diffie_hellman(&their_public);

    // Perform key derivation
    let z = kdf(
        priv_key.hash,
        shared_secret.as_bytes(),
        priv_key.alg_sym.key_size(),
        param,
    )?;

    aes_key_unwrap(mpis, &z)
}

fn decrypt_p521(priv_key: &ECDHSecretKey, mpis: &[Mpi], param: &[u8]) -> Result<Vec<u8>> {
    use cipher::Unsigned;
    use p521::{
        elliptic_curve::{ecdh, Curve, NonZeroScalar},
        NistP521, PublicKey,
    };

    ensure_eq!(mpis.len(), 3);
    // 66 = ((521 + 7) / 8)
    ensure_eq!(
        priv_key.secret().len(),
        <NistP521 as Curve>::FieldBytesSize::USIZE,
        "invalid secret point"
    );

    let Ok(their_public) = PublicKey::from_sec1_bytes(mpis[0].as_bytes()) else {
        bail!("invalid public key");
    };

    let our_secret = GenericArray::from_slice(priv_key.secret()).to_owned();
    let Some(private_scalar): Option<NonZeroScalar::<_>> = NonZeroScalar::<p521::NistP521>::from_repr(our_secret).into() else {
        bail!("invalid private scalar");
    };

    let public_affine = their_public.as_affine();
    let shared_secret = ecdh::diffie_hellman(private_scalar, public_affine);

    // Perform key derivation
    let z = kdf(
        priv_key.hash,
        shared_secret.raw_secret_bytes().as_slice(),
        priv_key.alg_sym.key_size(),
        param,
    )?;

    aes_key_unwrap(mpis, &z)
}

/// Key Derivation Function for ECDH (as defined in RFC 6637).
/// <https://tools.ietf.org/html/rfc6637#section-7>
fn kdf(hash: HashAlgorithm, x: &[u8], length: usize, param: &[u8]) -> Result<Vec<u8>> {
    let prefix = [0, 0, 0, 1];

    let values: [&[u8]; 3] = [&prefix, x, param];
    let data = values.concat();

    let mut digest = hash.digest(&data)?;
    digest.truncate(length);

    Ok(digest)
}

/// Perform AES Key Unwrap
fn aes_key_unwrap(mpis: &[Mpi], z: &[u8]) -> Result<Vec<u8>> {
    // encrypted and wrapped value derived from the session key
    let encrypted_session_key = mpis[2].as_bytes();

    let encrypted_key_len: usize = match mpis[1].first() {
        Some(l) => *l as usize,
        None => 0,
    };

    let mut encrypted_session_key_vec = vec![0; encrypted_key_len];
    encrypted_session_key_vec[(encrypted_key_len - encrypted_session_key.len())..]
        .copy_from_slice(encrypted_session_key);

    let mut decrypted_key_padded = aes_kw::unwrap(z, &encrypted_session_key_vec)?;
    // PKCS5 unpadding (PKCS5 is PKCS7 with a blocksize of 8)
    {
        let len = decrypted_key_padded.len();
        ensure!(len % BLOCK_SIZE == 0, "invalid key length {}", len);
        ensure!(!decrypted_key_padded.is_empty(), "empty key is not valid");

        // grab the last block
        let offset = len - BLOCK_SIZE;
        let last_block = GenericArray::<u8, U8>::from_slice(&decrypted_key_padded[offset..]);
        let unpadded_last_block = Pkcs7::unpad(last_block)?;
        let unpadded_len = offset + unpadded_last_block.len();
        decrypted_key_padded.truncate(unpadded_len);
    }

    Ok(decrypted_key_padded)
}

struct EncryptionOutput {
    encoded_public: Vec<u8>,
    encrypted_key_len: Vec<u8>,
    encrypted_key: Vec<u8>,
}

/// ECDH encryption.
pub fn encrypt<R: CryptoRng + Rng>(
    rng: &mut R,
    curve: &ECCCurve,
    alg_sym: SymmetricKeyAlgorithm,
    hash: HashAlgorithm,
    fingerprint: &[u8],
    q: &[u8],
    plain: &[u8],
) -> Result<Vec<Vec<u8>>> {
    debug!("ECDH encrypt");

    // can't fit more size wise
    let max_size = 239;
    ensure!(
        plain.len() < max_size,
        "unable to encrypt larger than {} bytes",
        max_size
    );

    let param = build_ecdh_param(&curve.oid(), alg_sym, hash, fingerprint);

    let EncryptionOutput {
        encoded_public,
        encrypted_key_len,
        encrypted_key,
    } = match curve {
        ECCCurve::Curve25519 => encrypt_x25519(rng, alg_sym, hash, q, plain, &param)?,
        ECCCurve::P521 => encrypt_p521(rng, alg_sym, hash, q, plain, &param)?,
        _ => bail!("unsupported curve"),
    };

    Ok(vec![encoded_public, encrypted_key_len, encrypted_key])
}

fn encrypt_x25519<R: CryptoRng + Rng>(
    rng: &mut R,
    alg_sym: SymmetricKeyAlgorithm,
    hash: HashAlgorithm,
    q: &[u8],
    plain: &[u8],
    param: &[u8],
) -> Result<EncryptionOutput> {
    ensure_eq!(q.len(), 33, "invalid public key");

    let their_public = {
        // public part of the ephemeral key (removes 0x40 prefix)
        let public_key = &q[1..];

        // create montgomery point
        let mut public_key_arr = [0u8; 32];
        public_key_arr[..].copy_from_slice(public_key);

        x25519_dalek::PublicKey::from(public_key_arr)
    };

    let mut our_secret_key_bytes = Zeroizing::new([0u8; SECRET_KEY_LENGTH]);
    rng.fill_bytes(&mut *our_secret_key_bytes);
    let our_secret = StaticSecret::from(*our_secret_key_bytes);

    // derive shared secret
    let shared_secret = our_secret.diffie_hellman(&their_public);

    // Perform key derivation
    let z = kdf(hash, shared_secret.as_bytes(), alg_sym.key_size(), param)?;

    let mut plain_padded = plain.to_vec();
    let plain_padded_ref = pad(&mut plain_padded)?;

    // Peform AES Key Wrap
    let encrypted_key = aes_kw::wrap(&z, plain_padded_ref)?;

    // Encode public point: prefix with 0x40
    let mut encoded_public = Vec::with_capacity(33);
    encoded_public.push(0x40);
    encoded_public.extend(x25519_dalek::PublicKey::from(&our_secret).as_bytes().iter());

    let encrypted_key_len = vec![u8::try_from(encrypted_key.len())?];

    Ok(EncryptionOutput {
        encoded_public,
        encrypted_key_len,
        encrypted_key,
    })
}

fn encrypt_p521<R: CryptoRng + Rng>(
    rng: &mut R,
    alg_sym: SymmetricKeyAlgorithm,
    hash: HashAlgorithm,
    q: &[u8],
    plain: &[u8],
    param: &[u8],
) -> Result<EncryptionOutput> {
    use p521::{ecdh::EphemeralSecret, EncodedPoint, PublicKey};

    let their_public = PublicKey::from_sec1_bytes(q)?;

    let our_secret = EphemeralSecret::random(rng);

    // derive shared secret
    let shared_secret = our_secret.diffie_hellman(&their_public);

    let z = kdf(
        hash,
        shared_secret.raw_secret_bytes().as_ref(),
        alg_sym.key_size(),
        param,
    )?;

    let mut plain_padded = plain.to_vec();
    let plain_padded_ref = pad(&mut plain_padded)?;

    // Perform AES Key Wrap
    let encrypted_key = aes_kw::wrap(&z, plain_padded_ref)?;

    // Public point gets encoded with prefix with 0x04
    let encoded_public = EncodedPoint::from(PublicKey::from(&our_secret))
        .to_bytes()
        .to_vec();

    let encrypted_key_len = vec![u8::try_from(encrypted_key.len())?];

    Ok(EncryptionOutput {
        encoded_public,
        encrypted_key_len,
        encrypted_key,
    })
}

/// PKCS5 pads the plaintext and returns the block-aligned slice of the padded plaintext
fn pad(plain: &mut Vec<u8>) -> Result<&[u8]> {
    // PKCS5 padding (PKCS5 is PKCS7 with a blocksize of 8)
    let len = plain.len();
    plain.resize(len + BLOCK_SIZE, 0);

    let pos = len;
    let bs = BLOCK_SIZE * (pos / BLOCK_SIZE);
    if plain.len() < bs || plain.len() - bs < BLOCK_SIZE {
        bail!("unable to pad");
    }
    let buf = GenericArray::<u8, U8>::from_mut_slice(&mut plain[bs..][..BLOCK_SIZE]);
    Pkcs7::pad(buf, pos - bs);
    Ok(&plain[..bs + BLOCK_SIZE])
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaChaRng;

    use crate::types::{PublicParams, SecretKeyRepr};

    fn encrypt_decrypt<F>(key_gen: F, curve: ECCCurve, alg_sym: SymmetricKeyAlgorithm)
    where
        F: FnOnce(
            &mut ChaChaRng,
            ECCCurve,
            SymmetricKeyAlgorithm,
        ) -> (PublicParams, PlainSecretParams),
    {
        let mut rng = ChaChaRng::from_seed([1u8; 32]);

        let (pkey, skey) = key_gen(&mut rng, curve, alg_sym);

        for text_size in 1..239 {
            for _i in 0..10 {
                let mut fingerprint = vec![0u8; 20];
                rng.fill_bytes(&mut fingerprint);

                let mut plain = vec![0u8; text_size];
                rng.fill_bytes(&mut plain);

                let mpis = match pkey {
                    PublicParams::ECDH {
                        ref curve,
                        ref p,
                        hash,
                        alg_sym,
                    } => encrypt(
                        &mut rng,
                        curve,
                        alg_sym,
                        hash,
                        &fingerprint,
                        p.as_bytes(),
                        &plain[..],
                    )
                    .unwrap(),
                    _ => panic!("invalid key generated"),
                };

                let mpis = mpis.into_iter().map(Into::into).collect::<Vec<Mpi>>();

                let decrypted = match skey.as_ref().as_repr(&pkey).unwrap() {
                    SecretKeyRepr::ECDH(ref skey) => decrypt(skey, &mpis, &fingerprint).unwrap(),
                    _ => panic!("invalid key generated"),
                };

                assert_eq!(&plain[..], &decrypted[..]);
            }
        }
    }

    #[test]
    fn test_encrypt_decrypt_x25519_aes128() {
        // Ensure that we still exercise the publicly exposed [`generate_key`].
        let key_gen = |rng: &mut ChaChaRng, _curve: _, _sym_alg: _| generate_key(rng);
        encrypt_decrypt(key_gen, ECCCurve::Curve25519, SymmetricKeyAlgorithm::AES128);
    }

    #[test]
    fn test_encrypt_decrypt_x25519_aes192() {
        encrypt_decrypt(
            _generate_key,
            ECCCurve::Curve25519,
            SymmetricKeyAlgorithm::AES192,
        );
    }

    #[test]
    fn test_encrypt_decrypt_x25519_aes256() {
        encrypt_decrypt(
            _generate_key,
            ECCCurve::Curve25519,
            SymmetricKeyAlgorithm::AES128,
        );
    }

    #[test]
    fn test_encrypt_decrypt_p521_aes128() {
        encrypt_decrypt(_generate_key, ECCCurve::P521, SymmetricKeyAlgorithm::AES128);
    }

    #[test]
    fn test_encrypt_decrypt_p521_aes192() {
        encrypt_decrypt(_generate_key, ECCCurve::P521, SymmetricKeyAlgorithm::AES192);
    }

    #[test]
    fn test_encrypt_decrypt_p521_aes256() {
        encrypt_decrypt(_generate_key, ECCCurve::P521, SymmetricKeyAlgorithm::AES256);
    }
}
