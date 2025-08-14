use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;

use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use clap::{Parser, Subcommand};
use k256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey, VerifyingKey};
use k256::elliptic_curve::{Field, PrimeField};
use k256::{FieldBytes, Scalar};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

#[derive(Debug, Serialize, Deserialize)]
struct KeyShareFile {
    // For MVP scaffold, this file stores one additive share (not a full key).
    // Real TSS should replace this with protocol-specific share and metadata.
    encrypted: Vec<u8>,
    nonce: [u8; 12],
    kdf_salt: Vec<u8>,
    public_key: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SignatureOut {
    r: String,
    s: String,
    v: u8,
}

#[derive(Parser, Debug)]
#[command(name = "mpc", version, about = "MPC 2-of-2 Wallet (MVP scaffold)")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate key material and store encrypted share files
    Keygen {
        /// Output path for client share file
        #[arg(long, default_value = "client_share.enc.json")]
        out_client: PathBuf,
        /// Output path for server share file
        #[arg(long, default_value = "server_share.enc.json")]
        out_server: PathBuf,
        /// Passphrase for encryption (applied to both shares in MVP)
        #[arg(long, env = "MPC_PASSPHRASE")]
        passphrase: String,
    },
    /// Show EVM address derived from stored share
    Address {
        /// Share file path
        #[arg(long, default_value = "client_share.enc.json")]
        share: PathBuf,
        /// Passphrase
        #[arg(long, env = "MPC_PASSPHRASE")]
        passphrase: String,
    },
    /// Sign a 32-byte digest and output r,s,v (requires both client & server shares)
    Sign {
        /// Client share file path
        #[arg(long, default_value = "client_share.enc.json")]
        share_client: PathBuf,
        /// Server share file path
        #[arg(long, default_value = "server_share.enc.json")]
        share_server: PathBuf,
        /// Client passphrase
        #[arg(long, env = "MPC_PASSPHRASE_CLIENT")]
        passphrase_client: String,
        /// Server passphrase
        #[arg(long, env = "MPC_PASSPHRASE_SERVER")]
        passphrase_server: String,
        /// Hex-encoded 32-byte digest (0x... or hex)
        #[arg(long)]
        digest: String,
        /// Output JSON file for signature
        #[arg(long, default_value = "sig.json")]
        out: PathBuf,
    },
    /// Health check (local only)
    Health,
}

fn derive_key_from_passphrase(passphrase: &str, salt: &[u8]) -> Key {
    let argon2 = Argon2::default();
    let mut derived = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut derived)
        .expect("argon2 should not fail");
    *Key::from_slice(&derived)
}

fn encrypt_private_key(passphrase: &str, secret_key_bytes: &[u8]) -> (Vec<u8>, [u8; 12], Vec<u8>) {
    use rand::RngCore;
    let mut salt_bytes = vec![0u8; 16];
    OsRng.fill_bytes(&mut salt_bytes);
    let key = derive_key_from_passphrase(passphrase, &salt_bytes);
    let cipher = ChaCha20Poly1305::new(&key);
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, secret_key_bytes)
        .expect("encryption failure");
    (ciphertext, nonce_bytes, salt_bytes)
}

fn decrypt_private_key(
    passphrase: &str,
    ciphertext: &[u8],
    nonce: &[u8; 12],
    salt: &[u8],
) -> Vec<u8> {
    let key = derive_key_from_passphrase(passphrase, salt);
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, ciphertext)
        .expect("decryption failure")
}

fn evm_address_from_pubkey(uncompressed_pubkey: &[u8]) -> String {
    // Uncompressed secp256k1 pubkey is 65 bytes starting with 0x04
    let hash = Keccak256::digest(&uncompressed_pubkey[1..]);
    let addr = &hash[12..];
    format!("0x{}", hex::encode(addr))
}

fn save_share(filepath: &PathBuf, share: &KeyShareFile) -> anyhow::Result<()> {
    let serialized = serde_json::to_vec_pretty(share)?;
    let mut file = fs::File::create(filepath)?;
    file.write_all(&serialized)?;
    Ok(())
}

fn load_share(filepath: &PathBuf) -> anyhow::Result<KeyShareFile> {
    let mut buf = Vec::new();
    fs::File::open(filepath)?.read_to_end(&mut buf)?;
    let share: KeyShareFile = serde_json::from_slice(&buf)?;
    Ok(share)
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Keygen {
            out_client,
            out_server,
            passphrase,
        } => {
            // Generate ECDSA keypair
            let signing_key = SigningKey::random(&mut OsRng);
            let verifying_key = VerifyingKey::from(&signing_key);
            let pub_uncompressed = verifying_key.to_encoded_point(false).as_bytes().to_vec();

            // Split private key x into x1, x2 with x = x1 + x2 (mod n)
            let sk_bytes = signing_key.to_bytes();
            let x = Scalar::from_repr_vartime(sk_bytes).expect("scalar repr");
            let x1 = Scalar::random(&mut OsRng);
            let x2 = x - x1;
            let x1_bytes: FieldBytes = x1.to_bytes();
            let x2_bytes: FieldBytes = x2.to_bytes();

            // Encrypt each share separately (using same passphrase for MVP)
            let (ct1, n1, s1) = encrypt_private_key(&passphrase, x1_bytes.as_slice());
            let (ct2, n2, s2) = encrypt_private_key(&passphrase, x2_bytes.as_slice());

            let share_client = KeyShareFile {
                encrypted: ct1,
                nonce: n1,
                kdf_salt: s1,
                public_key: pub_uncompressed.clone(),
            };
            let share_server = KeyShareFile {
                encrypted: ct2,
                nonce: n2,
                kdf_salt: s2,
                public_key: pub_uncompressed.clone(),
            };

            save_share(&out_client, &share_client)?;
            save_share(&out_server, &share_server)?;

            let address = evm_address_from_pubkey(&pub_uncompressed);
            println!("{}", serde_json::json!({"address": address}));
        }
        Commands::Address { share, passphrase } => {
            let share = load_share(&share)?;
            let _ =
                decrypt_private_key(&passphrase, &share.encrypted, &share.nonce, &share.kdf_salt);
            let address = evm_address_from_pubkey(&share.public_key);
            println!("{}", serde_json::json!({"address": address}));
        }
        Commands::Sign {
            share_client,
            share_server,
            passphrase_client,
            passphrase_server,
            digest,
            out,
        } => {
            let sc = load_share(&share_client)?;
            let ss = load_share(&share_server)?;
            // Recombine x = x1 + x2 (mod n)
            let x1_bytes =
                decrypt_private_key(&passphrase_client, &sc.encrypted, &sc.nonce, &sc.kdf_salt);
            let x2_bytes =
                decrypt_private_key(&passphrase_server, &ss.encrypted, &ss.nonce, &ss.kdf_salt);

            let mut fb1 = FieldBytes::default();
            fb1.copy_from_slice(&x1_bytes);
            let mut fb2 = FieldBytes::default();
            fb2.copy_from_slice(&x2_bytes);

            let x1 = Scalar::from_repr_vartime(fb1)
                .ok_or_else(|| anyhow::anyhow!("invalid client share"))?;
            let x2 = Scalar::from_repr_vartime(fb2)
                .ok_or_else(|| anyhow::anyhow!("invalid server share"))?;
            let x: Scalar = x1 + x2;
            let x_bytes = x.to_bytes();
            let signing_key =
                SigningKey::from_slice(x_bytes.as_slice()).expect("invalid key bytes");

            let d = digest.trim_start_matches("0x").to_string();
            if d.len() != 64 {
                anyhow::bail!("digest must be 32 bytes hex");
            }
            let digest_bytes = hex::decode(&d)?;
            let sig: Signature = signing_key.sign_prehash(&digest_bytes).expect("sign");

            let out_sig = SignatureOut {
                r: format!("0x{:064x}", sig.r()),
                s: format!("0x{:064x}", sig.s()),
                v: 27,
            };
            let json = serde_json::to_string_pretty(&out_sig)?;
            fs::write(out, json)?;
            println!("{}", serde_json::json!({"status": "ok"}));
        }
        Commands::Health => {
            println!("{}", serde_json::json!({"status": "ok"}));
        }
    }
    Ok(())
}
