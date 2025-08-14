## MPC 2-of-2 Wallet (MVP scaffold)

A Rust CLI that follows the PRD to demonstrate a local MPC-style wallet flow. The current MVP enforces 2-of-2 participation by splitting the private key into two additive shares and requiring both to sign. This is a scaffold; actual interactive TSS (e.g., GG18/GG20) is not yet integrated.

### Status
- CLI: `keygen`, `address`, `sign`, `health`
- 2-of-2 enforcement: private key split into two scalar shares x1, x2 with x = x1 + x2 (mod n); both are required for signing (recombined in-memory)
- Storage: encrypted-at-rest (Argon2 KDF + ChaCha20-Poly1305)
- Address: EVM-compatible derivation from secp256k1 uncompressed public key
- Output: JSON for scripting

## Requirements
- Rust (stable) and Cargo

## Build
```bash
cargo build --release
```
Binary: `target/release/mpc-wallet`

## Quick start

### 1) Generate key material (creates two encrypted shares)
- Uses a single passphrase for both shares in the current MVP
```bash
export MPC_PASSPHRASE="change-me"

cargo run -- keygen \
  --out-client client_share.enc.json \
  --out-server server_share.enc.json
```
Output:
```json
{"address":"0xabc123..."}
```

### 2) Show address from a share
```bash
cargo run -- address --share client_share.enc.json
```
Output:
```json
{"address":"0xabc123..."}
```

### 3) Sign a 32-byte digest (requires both shares)
- Provide 32-byte hex digest (with or without `0x` prefix)
- Use separate env vars for each share’s passphrase when signing
```bash
export MPC_PASSPHRASE_CLIENT="pass-client"
export MPC_PASSPHRASE_SERVER="pass-server"

cargo run -- sign \
  --share-client client_share.enc.json \
  --share-server server_share.enc.json \
  --digest 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --out sig.json
```
Console:
```json
{"status":"ok"}
```
File `sig.json`:
```json
{"r":"0x...","s":"0x...","v":27}
```

### 4) Health check
```bash
cargo run -- health
```
Output:
```json
{"status":"ok"}
```

## Command reference
- keygen
  - `--out-client <PATH>`: client share output (default `client_share.enc.json`)
  - `--out-server <PATH>`: server share output (default `server_share.enc.json`)
  - `--passphrase <STRING>` or env `MPC_PASSPHRASE`: passphrase for encryption (applied to both shares in MVP)

- address
  - `--share <PATH>`: share file path (default `client_share.enc.json`)
  - `--passphrase <STRING>` or env `MPC_PASSPHRASE`

- sign
  - `--share-client <PATH>`: client share (default `client_share.enc.json`)
  - `--share-server <PATH>`: server share (default `server_share.enc.json`)
  - `--passphrase-client <STRING>` or env `MPC_PASSPHRASE_CLIENT`
  - `--passphrase-server <STRING>` or env `MPC_PASSPHRASE_SERVER`
  - `--digest <HEX>`: 32-byte digest
  - `--out <PATH>`: output signature JSON (default `sig.json`)

- health
  - Prints `{"status":"ok"}`

## Configuration
- `MPC_PASSPHRASE`: passphrase for encrypting/decrypting shares at keygen/address
- `MPC_PASSPHRASE_CLIENT`, `MPC_PASSPHRASE_SERVER`: passphrases for sign step

## Data and storage
- `KeyShareFile` (JSON):
  - `encrypted`: ciphertext bytes (JSON array)
  - `nonce`: 12-byte AEAD nonce
  - `kdf_salt`: 16-byte Argon2 salt
  - `public_key`: uncompressed secp256k1 pubkey (65 bytes, JSON array)
- `keygen` stores two different encrypted shares representing x1 and x2. Both are required to sign.

## Security notes
- At rest: no plaintext secret storage; Argon2 + ChaCha20-Poly1305
- 2-of-2 enforcement: both shares required; this MVP recombines locally in memory for signing
- Scaffold: not a real TSS protocol; replace with audited threshold ECDSA (GG18/GG20) in future
- Keep passphrases secure; avoid committing share files

## Roadmap (per PRD)
- M1: Local MPC keygen (current scaffold with additive shares)
- M2: Threshold signing producing `(r, s, v)` with real TSS
- M3: Broadcast via EVM JSON-RPC
- M4: Backup export/import flows
- M5: Optional local HTTP service

### Known limitations
- `v` fixed to 27 (no EIP-155 nor recovery-id handling yet)
- No RPC/broadcast, no backup import/export, no HTTP service yet
- Share recombination is local (not interactive MPC)

## Development
```bash
cargo run -- <args>
cargo test
```

## License
MIT
