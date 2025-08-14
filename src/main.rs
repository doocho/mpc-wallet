use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;

use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use clap::{Parser, Subcommand};
use k256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use zeroize::Zeroize;

#[derive(Debug, Serialize, Deserialize)]
struct KeyShareFile {
    // In a real TSS this would be a partial share. For MVP scaffold, we store a full private key
    // to unblock CLI flows. Replace with TSS integration later.
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
        /// Output path for server share file (simulated)
        #[arg(long, default_value = "server_share.enc.json")]
        out_server: PathBuf,
        /// Passphrase for encryption
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
    /// Sign a 32-byte digest and output r,s,v
    Sign {
        /// Share file path
        #[arg(long, default_value = "client_share.enc.json")]
        share: PathBuf,
        /// Passphrase
        #[arg(long, env = "MPC_PASSPHRASE")]
        passphrase: String,
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

fn decrypt_private_key(passphrase: &str, ciphertext: &[u8], nonce: &[u8; 12], salt: &[u8]) -> Vec<u8> {
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
        Commands::Keygen { out_client, out_server, passphrase } => {
            // Scaffold: generate one ECDSA keypair; store the same encrypted key twice to simulate 2-of-2 parties.
            let signing_key = SigningKey::random(&mut OsRng);
            let verifying_key = VerifyingKey::from(&signing_key);
            let pub_uncompressed = verifying_key.to_encoded_point(false).as_bytes().to_vec();
            let mut sk_bytes = signing_key.to_bytes().to_vec();
            let (ciphertext, nonce, salt) = encrypt_private_key(&passphrase, &sk_bytes);
            let share = KeyShareFile {
                encrypted: ciphertext.clone(),
                nonce,
                kdf_salt: salt.clone(),
                public_key: pub_uncompressed.clone(),
            };
            save_share(&out_client, &share)?;
            save_share(&out_server, &share)?;

            // Zeroize secret from memory
            sk_bytes.zeroize();

            let address = evm_address_from_pubkey(&pub_uncompressed);
            println!("{}", serde_json::json!({"address": address}));
        }
        Commands::Address { share, passphrase } => {
            let share = load_share(&share)?;
            let _ = decrypt_private_key(&passphrase, &share.encrypted, &share.nonce, &share.kdf_salt);
            let address = evm_address_from_pubkey(&share.public_key);
            println!("{}", serde_json::json!({"address": address}));
        }
        Commands::Sign { share, passphrase, digest, out } => {
            let share = load_share(&share)?;
            let sk_bytes = decrypt_private_key(&passphrase, &share.encrypted, &share.nonce, &share.kdf_salt);
            let signing_key = SigningKey::from_slice(&sk_bytes).expect("invalid key bytes");

            let mut d = digest.trim_start_matches("0x").to_string();
            if d.len() != 64 {
                anyhow::bail!("digest must be 32 bytes hex");
            }
            let digest_bytes = hex::decode(&d)?;
            let sig: Signature = signing_key.sign_prehash(&digest_bytes).expect("sign");

            // EVM v calculation naive (no chain id/EIP-155 here; assuming 27/28 based on recovery id)
            // k256 doesn't expose recovery id from prehash sign; this is a simplified output for MVP.
            // We set v to 27 for now.
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
