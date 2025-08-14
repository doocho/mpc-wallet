## MPC 2-of-2 Wallet (MVP scaffold)

A Rust CLI that follows the PRD to demonstrate a local MPC-style wallet flow. The current MVP is a scaffold that uses a single ECDSA keypair under the hood to unblock the CLI and storage flows. It encrypts the key at rest, derives an EVM-compatible address, signs a provided 32-byte digest, and prints JSON outputs for scripting.

### Status
- Implements CLI commands: `keygen`, `address`, `sign`, `health`
- Encrypted-at-rest key storage (Argon2 KDF + ChaCha20-Poly1305)
- EVM address derivation from secp256k1 public key
- JSON outputs for easy scripting
- Note: Real 2-of-2 threshold signing is not yet integrated; both `client_share` and `server_share` files are identical placeholders for now

## Requirements
- Rust (stable) and Cargo installed

## Build
```bash
cargo build --release
```

The compiled binary will be at `target/release/mpc-wallet`.

## Quick start
Set a passphrase (can also be provided with `--passphrase`):
```bash
export MPC_PASSPHRASE="change-me"
```

### Generate key material
```bash
cargo run -- keygen --out-client client_share.enc.json --out-server server_share.enc.json
```
Output (example):
```json
{"address":"0xabc123..."}
```

### Show address from a share
```bash
cargo run -- address --share client_share.enc.json
```
Output:
```json
{"address":"0xabc123..."}
```

### Sign a 32-byte digest
- Provide a 32-byte hex string (with or without `0x` prefix)
```bash
cargo run -- sign --share client_share.enc.json --digest 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef --out sig.json
```
Console output:
```json
{"status":"ok"}
```
File `sig.json` example:
```json
{
  "r": "0x...",
  "s": "0x...",
  "v": 27
}
```

### Health check
```bash
cargo run -- health
```
Output:
```json
{"status":"ok"}
```

## Command reference
- `keygen`
  - `--out-client <PATH>`: output path for client share file (default `client_share.enc.json`)
  - `--out-server <PATH>`: output path for server share file (default `server_share.enc.json`)
  - `--passphrase <STRING>` or env `MPC_PASSPHRASE`: passphrase for encryption

- `address`
  - `--share <PATH>`: share file path (default `client_share.enc.json`)
  - `--passphrase <STRING>` or env `MPC_PASSPHRASE`

- `sign`
  - `--share <PATH>`: share file path (default `client_share.enc.json`)
  - `--passphrase <STRING>` or env `MPC_PASSPHRASE`
  - `--digest <HEX>`: 32-byte digest to sign
  - `--out <PATH>`: output JSON file for signature (default `sig.json`)

- `health`: prints `{"status":"ok"}`

## Configuration
- `MPC_PASSPHRASE`: passphrase for encrypting/decrypting the share file

## Data and storage
- The share files are JSON with the following fields:
  - `encrypted`: ciphertext bytes (base-10 JSON array)
  - `nonce`: 12-byte AEAD nonce
  - `kdf_salt`: random salt used for Argon2
  - `public_key`: uncompressed secp256k1 public key (65 bytes, JSON array)

These are meant for programmatic use; do not edit manually.

## Security notes
- Secrets are never stored in plaintext on disk; they are encrypted with `Argon2` + `ChaCha20-Poly1305`
- This scaffold uses a single-party key internally; the `server_share` file is a placeholder. Real 2-of-2 MPC/TSS will replace this with proper partial shares and interactive protocols
- Avoid committing share files; keep passphrases out of shell history when possible

## Roadmap (from PRD)
- M1: Local MPC keygen (current scaffold in place; upgrade to real TSS next)
- M2: Signing with TSS producing `(r, s, v)`
- M3: Broadcast via EVM JSON-RPC
- M4: Backup export/import flows
- M5: Optional local HTTP service for key flows

### Known limitations
- `v` is currently fixed to `27`. EIP-155 and recovery-id handling to be added with broadcast flow
- No RPC/broadcast yet
- No backup import/export CLI yet

## Development
Run with live builds:
```bash
cargo run -- <args>
```
Run tests (add as features are implemented):
```bash
cargo test
```

## License
MIT


