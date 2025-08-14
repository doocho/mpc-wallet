use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey};
use k256::elliptic_curve::PrimeField;
use k256::{FieldBytes, Scalar};
use rand::rngs::OsRng;

pub trait Threshold {
    fn keygen(&mut self) -> anyhow::Result<(Vec<u8>, FieldBytes, FieldBytes)>;
    fn sign_digest(
        &self,
        digest32: &[u8],
        client_share: &FieldBytes,
        server_share: &FieldBytes,
    ) -> anyhow::Result<Signature>;
}

pub struct LocalAdditiveTss;

impl LocalAdditiveTss {
    pub fn new() -> Self {
        Self
    }
}

impl Threshold for LocalAdditiveTss {
    fn keygen(&mut self) -> anyhow::Result<(Vec<u8>, FieldBytes, FieldBytes)> {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let pub_uncompressed = verifying_key.to_encoded_point(false).as_bytes().to_vec();
        let sk_bytes = signing_key.to_bytes();
        let x_ct = Scalar::from_repr(sk_bytes);
        let x = if bool::from(x_ct.is_some()) {
            x_ct.unwrap()
        } else {
            anyhow::bail!("invalid scalar repr")
        };
        let x1 = Scalar::generate_vartime(&mut OsRng);
        let x2 = x - x1;
        Ok((pub_uncompressed, x1.to_bytes(), x2.to_bytes()))
    }
    fn sign_digest(
        &self,
        digest32: &[u8],
        client_share: &FieldBytes,
        server_share: &FieldBytes,
    ) -> anyhow::Result<Signature> {
        if digest32.len() != 32 {
            anyhow::bail!("digest must be 32 bytes");
        }
        let x1_ct = Scalar::from_repr(*client_share);
        let x1 = if bool::from(x1_ct.is_some()) {
            x1_ct.unwrap()
        } else {
            anyhow::bail!("invalid client share")
        };
        let x2_ct = Scalar::from_repr(*server_share);
        let x2 = if bool::from(x2_ct.is_some()) {
            x2_ct.unwrap()
        } else {
            anyhow::bail!("invalid server share")
        };
        let x = x1 + x2;
        let sk = SigningKey::from_slice(x.to_bytes().as_slice()).expect("key from scalar");
        Ok(sk.sign_prehash(digest32).expect("sign"))
    }
}

#[cfg(feature = "tss_gg18")]
/// GG18-backed TSS (delegates to LocalAdditiveTss until external GG18 crate is wired)
pub struct Gg18Tss {
    inner: LocalAdditiveTss,
}

#[cfg(feature = "tss_gg18")]
impl Gg18Tss {
    pub fn new() -> Self {
        Self { inner: LocalAdditiveTss::new() }
    }
}

#[cfg(feature = "tss_gg18")]
impl Threshold for Gg18Tss {
    fn keygen(&mut self) -> anyhow::Result<(Vec<u8>, FieldBytes, FieldBytes)> {
        self.inner.keygen()
    }
    fn sign_digest(
        &self,
        digest32: &[u8],
        client_share: &FieldBytes,
        server_share: &FieldBytes,
    ) -> anyhow::Result<Signature> {
        self.inner.sign_digest(digest32, client_share, server_share)
    }
}

pub fn make_default_tss() -> Box<dyn Threshold + Send> {
    #[cfg(feature = "tss_gg18")]
    {
        Box::new(Gg18Tss::new())
    }
    #[cfg(not(feature = "tss_gg18"))]
    {
        Box::new(LocalAdditiveTss::new())
    }
}
