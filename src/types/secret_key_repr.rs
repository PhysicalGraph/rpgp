use std::fmt;

use cipher::Unsigned;
use num_bigint::BigUint;
use p521::{elliptic_curve::Curve, NistP521};
use rsa::RsaPrivateKey;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::ecc_curve::ECCCurve;
use crate::crypto::hash::HashAlgorithm;
use crate::crypto::sym::SymmetricKeyAlgorithm;

use super::Mpi;

/// The version of the secret key that is actually exposed to users to do crypto operations.
#[allow(clippy::large_enum_variant)] // FIXME
#[derive(Debug, ZeroizeOnDrop)]
pub enum SecretKeyRepr {
    RSA(RsaPrivateKey),
    DSA(DSASecretKey),
    ECDSA(ECDSASecretKey),
    ECDH(ECDHSecretKey),
    EdDSA(EdDSASecretKey),
}

/// Secret key for ECDH with Curve25519 or P-521, the only combinations we currently support.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ECDHSecretKey {
    /// The secret point.
    pub secret: ECDHSecretPoint,
    pub hash: HashAlgorithm,
    pub oid: Vec<u8>,
    pub alg_sym: SymmetricKeyAlgorithm,
}

impl ECDHSecretKey {
    pub fn secret(&self) -> &[u8] {
        self.secret.secret()
    }
}

impl fmt::Debug for ECDHSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ECDHSecretKey")
            .field("secret", &self.secret)
            .field("hash", &self.hash)
            .field("oid", &hex::encode(&self.oid))
            .field("alg_sym", &self.alg_sym)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub enum ECDHSecretPoint {
    Cv25519([u8; 32]),
    P521([u8; <NistP521 as Curve>::FieldBytesSize::USIZE]),
}

impl ECDHSecretPoint {
    pub fn secret(&self) -> &[u8] {
        match self {
            Self::Cv25519(secret) => secret,
            Self::P521(secret) => secret,
        }
    }
}

impl fmt::Debug for ECDHSecretPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cv25519(_) => f.debug_tuple("Cv25519"),
            Self::P521(_) => f.debug_tuple("P521"),
        }
        .field(&"&[..]")
        .finish()
    }
}

/// Secret key for EdDSA with Curve25519, the only combination we currently support.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct EdDSASecretKey {
    /// The secret point.
    pub secret: [u8; 32],
    pub oid: Vec<u8>,
}

impl fmt::Debug for EdDSASecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EdDSASecretKey")
            .field("secret", &"[..]")
            .field("oid", &hex::encode(&self.oid))
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub enum ECDSASecretKey {
    P256(p256::SecretKey),
    P384(p384::SecretKey),
    Unsupported {
        /// The secret point.
        x: Mpi,
        #[zeroize(skip)]
        curve: ECCCurve,
    },
}

impl fmt::Debug for ECDSASecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ECDSASecretKey::P256(_) => write!(f, "ECDSASecretKey::P256([..])"),
            ECDSASecretKey::P384(_) => write!(f, "ECDSASecretKey::P384([..])"),
            ECDSASecretKey::Unsupported { curve, .. } => f
                .debug_struct("ECDSASecretKey::Unsupported")
                .field("x", &"[..]")
                .field("curve", &curve)
                .finish(),
        }
    }
}

/// Secret key for DSA.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct DSASecretKey {
    x: BigUint,
}

impl fmt::Debug for DSASecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DSASecretKey").field("x", &"[..]").finish()
    }
}
