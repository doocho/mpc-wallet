use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;

use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use clap::{Parser, Subcommand};
use k256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey, VerifyingKey};
use k256::elliptic_curve::PrimeField;
use k256::{FieldBytes, Scalar};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::sync::Arc;
use tiny_http::{Header, Method, Response, Server, StatusCode};

mod tss;
use tss::{LocalAdditiveTss, Threshold};

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
        /// Client passphrase for encryption
        #[arg(long, env = "MPC_PASSPHRASE_CLIENT")]
        passphrase_client: String,
        /// Server passphrase for encryption
        #[arg(long, env = "MPC_PASSPHRASE_SERVER")]
        passphrase_server: String,
    },
    /// Show EVM address derived from stored share
    Address {
        /// Share file path
        #[arg(long, default_value = "client_share.enc.json")]
        share: PathBuf,
        /// Passphrase (if omitted, falls back to env MPC_PASSPHRASE_CLIENT then MPC_PASSPHRASE_SERVER)
        #[arg(long)]
        passphrase: Option<String>,
    },
    /// Sign a 32-byte digest and output r,s,v (requires both client & server shares)
    Sign {
        /// Client share file path
        #[arg(long, default_value = "client_share.enc.json")]
        share_client: PathBuf,
        /// Server share file path (required only if --cosigner-url is not provided)
        #[arg(long)]
        share_server: Option<PathBuf>,
        /// Client passphrase
        #[arg(long, env = "MPC_PASSPHRASE_CLIENT")]
        passphrase_client: String,
        /// Server passphrase (required only if --cosigner-url is not provided)
        #[arg(long, env = "MPC_PASSPHRASE_SERVER")]
        passphrase_server: Option<String>,
        /// Optional co-signer URL (if provided, use HTTP instead of local server share file)
        #[arg(long)]
        cosigner_url: Option<String>,
        /// Hex-encoded 32-byte digest (0x... or hex)
        #[arg(long)]
        digest: String,
        /// Output JSON file for signature
        #[arg(long, default_value = "sig.json")]
        out: PathBuf,
    },
    /// Run local co-signer service on host:port, serving partial signing
    Serve {
        /// Server share file path
        #[arg(long, default_value = "server_share.enc.json")]
        share_server: PathBuf,
        /// Server passphrase
        #[arg(long, env = "MPC_PASSPHRASE_SERVER")]
        passphrase_server: String,
        /// Bind address, e.g., 127.0.0.1:8080
        #[arg(long, default_value = "127.0.0.1:8080")]
        bind: String,
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
            passphrase_client,
            passphrase_server,
        } => {
            // Use TSS abstraction for keygen
            let mut tss = LocalAdditiveTss::new();
            let (pub_uncompressed, x1_bytes, x2_bytes) = tss.keygen()?;

            // Encrypt each share separately with its own passphrase
            let (ct1, n1, s1) = encrypt_private_key(&passphrase_client, x1_bytes.as_slice());
            let (ct2, n2, s2) = encrypt_private_key(&passphrase_server, x2_bytes.as_slice());

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
            let pass = if let Some(p) = passphrase {
                p
            } else {
                std::env::var("MPC_PASSPHRASE_CLIENT").ok()
                    .or_else(|| std::env::var("MPC_PASSPHRASE_SERVER").ok())
                    .ok_or_else(|| anyhow::anyhow!("passphrase not provided; set --passphrase or MPC_PASSPHRASE_CLIENT/SERVER"))?
            };
            let _ = decrypt_private_key(&pass, &share.encrypted, &share.nonce, &share.kdf_salt);
            let address = evm_address_from_pubkey(&share.public_key);
            println!("{}", serde_json::json!({"address": address}));
        }
        Commands::Sign {
            share_client,
            share_server,
            passphrase_client,
            passphrase_server,
            cosigner_url,
            digest,
            out,
        } => {
            if let Some(url) = cosigner_url {
                use std::io::Write as IoWrite;
                use std::net::TcpStream;
                let url = url.trim_end_matches('/').to_string();
                let host_port = url.trim_start_matches("http://");
                let sc = load_share(&share_client)?;
                let x1_bytes =
                    decrypt_private_key(&passphrase_client, &sc.encrypted, &sc.nonce, &sc.kdf_salt);
                let d = digest.trim_start_matches("0x").to_string();
                if d.len() != 64 {
                    anyhow::bail!("digest must be 32 bytes hex");
                }
                let body = serde_json::json!({
                    "x1": hex::encode(x1_bytes),
                    "digest": d,
                })
                .to_string();
                let req = format!(
                    "POST /partial_sign HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {len}\r\n\r\n{body}",
                    host=host_port,
                    len=body.len(),
                    body=body
                );
                let mut stream = TcpStream::connect(host_port)?;
                stream.write_all(req.as_bytes())?;
                let mut resp = String::new();
                use std::io::Read as IoRead;
                stream.read_to_string(&mut resp)?;
                if let Some(idx) = resp.find("\r\n\r\n") {
                    let body = &resp[idx + 4..];
                    let sig: SignatureOut = serde_json::from_str(body)?;
                    let json = serde_json::to_string_pretty(&sig)?;
                    fs::write(out, json)?;
                    println!("{}", serde_json::json!({"status": "ok"}));
                    return Ok(());
                } else {
                    anyhow::bail!("bad http response");
                }
            }
            // Local mode: use TSS abstraction to sign
            let ss_path = share_server.ok_or_else(|| {
                anyhow::anyhow!("--share-server is required without --cosigner-url")
            })?;
            let pass_server = passphrase_server.ok_or_else(|| {
                anyhow::anyhow!("--passphrase-server is required without --cosigner-url")
            })?;
            let sc = load_share(&share_client)?;
            let ss = load_share(&ss_path)?;

            let x1_bytes =
                decrypt_private_key(&passphrase_client, &sc.encrypted, &sc.nonce, &sc.kdf_salt);
            let x2_bytes =
                decrypt_private_key(&pass_server, &ss.encrypted, &ss.nonce, &ss.kdf_salt);
            let mut fb1 = FieldBytes::default();
            fb1.copy_from_slice(&x1_bytes);
            let mut fb2 = FieldBytes::default();
            fb2.copy_from_slice(&x2_bytes);

            let d = digest.trim_start_matches("0x").to_string();
            if d.len() != 64 {
                anyhow::bail!("digest must be 32 bytes hex");
            }
            let digest_bytes = hex::decode(&d)?;

            let tss = LocalAdditiveTss::new();
            let sig: Signature = tss.sign_digest(&digest_bytes, &fb1, &fb2)?;

            let out_sig = SignatureOut {
                r: format!("0x{:064x}", sig.r()),
                s: format!("0x{:064x}", sig.s()),
                v: 27,
            };
            let json = serde_json::to_string_pretty(&out_sig)?;
            fs::write(out, json)?;
            println!("{}", serde_json::json!({"status": "ok"}));
        }
        Commands::Serve {
            share_server,
            passphrase_server,
            bind,
        } => {
            let ss = Arc::new(load_share(&share_server)?);
            let pass = Arc::new(passphrase_server);
            let server = Server::http(&bind).expect("bind server");
            println!("{}", serde_json::json!({"status":"listening","bind":bind}));
            for mut req in server.incoming_requests() {
                let method = req.method().clone();
                let url = req.url().to_string();
                match (method, url.as_str()) {
                    (Method::Get, "/healthz") => {
                        let mut resp = Response::from_string("{\"status\":\"ok\"}")
                            .with_status_code(StatusCode(200));
                        let _ = resp.add_header(
                            Header::from_bytes(&b"Connection"[..], &b"close"[..]).unwrap(),
                        );
                        let _ = req.respond(resp);
                    }
                    (Method::Post, "/partial_sign") => {
                        let mut body = String::new();
                        if let Err(_) = req.as_reader().read_to_string(&mut body) {
                            let mut resp = Response::from_string("bad request")
                                .with_status_code(StatusCode(400));
                            let _ = resp.add_header(
                                Header::from_bytes(&b"Connection"[..], &b"close"[..]).unwrap(),
                            );
                            let _ = req.respond(resp);
                            continue;
                        }
                        let v: serde_json::Value = match serde_json::from_str(&body) {
                            Ok(v) => v,
                            Err(_) => {
                                let mut resp = Response::from_string("bad json")
                                    .with_status_code(StatusCode(400));
                                let _ = resp.add_header(
                                    Header::from_bytes(&b"Connection"[..], &b"close"[..]).unwrap(),
                                );
                                let _ = req.respond(resp);
                                continue;
                            }
                        };
                        let x1_hex = v.get("x1").and_then(|x| x.as_str()).unwrap_or("");
                        let digest_hex = v.get("digest").and_then(|x| x.as_str()).unwrap_or("");
                        let passphrase_server = pass.clone();

                        // decrypt server share (x2)
                        let x2_bytes = decrypt_private_key(
                            &passphrase_server,
                            &ss.encrypted,
                            &ss.nonce,
                            &ss.kdf_salt,
                        );
                        let mut fb2 = FieldBytes::default();
                        fb2.copy_from_slice(&x2_bytes);
                        let x1_vec = match hex::decode(x1_hex) {
                            Ok(b) => b,
                            Err(_) => {
                                let mut resp = Response::from_string("bad x1")
                                    .with_status_code(StatusCode(400));
                                let _ = resp.add_header(
                                    Header::from_bytes(&b"Connection"[..], &b"close"[..]).unwrap(),
                                );
                                let _ = req.respond(resp);
                                continue;
                            }
                        };
                        if x1_vec.len() != 32 || digest_hex.len() != 64 {
                            let mut resp = Response::from_string("bad lengths")
                                .with_status_code(StatusCode(400));
                            let _ = resp.add_header(
                                Header::from_bytes(&b"Connection"[..], &b"close"[..]).unwrap(),
                            );
                            let _ = req.respond(resp);
                            continue;
                        }
                        let mut fb1 = FieldBytes::default();
                        fb1.copy_from_slice(&x1_vec);

                        let tss = LocalAdditiveTss::new();
                        let digest_bytes = match hex::decode(digest_hex) {
                            Ok(b) => b,
                            Err(_) => {
                                let mut resp = Response::from_string("bad digest")
                                    .with_status_code(StatusCode(400));
                                let _ = resp.add_header(
                                    Header::from_bytes(&b"Connection"[..], &b"close"[..]).unwrap(),
                                );
                                let _ = req.respond(resp);
                                continue;
                            }
                        };
                        let sig: Signature = match tss.sign_digest(&digest_bytes, &fb1, &fb2) {
                            Ok(s) => s,
                            Err(_) => {
                                let mut resp = Response::from_string("sign error")
                                    .with_status_code(StatusCode(500));
                                let _ = resp.add_header(
                                    Header::from_bytes(&b"Connection"[..], &b"close"[..]).unwrap(),
                                );
                                let _ = req.respond(resp);
                                continue;
                            }
                        };
                        let out_sig = SignatureOut {
                            r: format!("0x{:064x}", sig.r()),
                            s: format!("0x{:064x}", sig.s()),
                            v: 27,
                        };
                        let mut resp =
                            Response::from_string(serde_json::to_string(&out_sig).unwrap())
                                .with_status_code(StatusCode(200));
                        let _ = resp.add_header(
                            Header::from_bytes(&b"Connection"[..], &b"close"[..]).unwrap(),
                        );
                        let _ = req.respond(resp);
                    }
                    _ => {
                        let mut resp =
                            Response::from_string("not found").with_status_code(StatusCode(404));
                        let _ = resp.add_header(
                            Header::from_bytes(&b"Connection"[..], &b"close"[..]).unwrap(),
                        );
                        let _ = req.respond(resp);
                    }
                }
            }
        }
        Commands::Health => {
            println!("{}", serde_json::json!({"status": "ok"}));
        }
    }
    Ok(())
}
