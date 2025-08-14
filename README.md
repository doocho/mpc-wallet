## MPC 2-of-2 Wallet (MVP scaffold)

A Rust CLI that follows the PRD to demonstrate a local MPC-style wallet flow. The current MVP enforces 2-of-2 participation by splitting the private key into two additive shares and requiring both to sign. This is a scaffold; actual interactive TSS (e.g., GG18/GG20) is not yet integrated.

### Status
- CLI: `keygen`, `address`, `sign`, `health`, `serve`
- 2-of-2 enforcement: private key split into two scalar shares x1, x2 with x = x1 + x2 (mod n); both are required for signing (recombined in-memory or via local HTTP cosigner)
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
- Uses separate passphrases for each share
```bash
export MPC_PASSPHRASE_CLIENT="change-me1"
export MPC_PASSPHRASE_SERVER="change-me2"

cargo run -- keygen \
  --out-client client_share.enc.json \
  --out-server server_share.enc.json \
  --passphrase-client $MPC_PASSPHRASE_CLIENT \
  --passphrase-server $MPC_PASSPHRASE_SERVER
```
Output:
```json
{"address":"0xabc123..."}
```

### 2) Show address from a share
```bash
cargo run -- address --share client_share.enc.json --passphrase $MPC_PASSPHRASE_CLIENT
```
Note: If `--passphrase` is omitted, the command will try `MPC_PASSPHRASE_CLIENT` and then `MPC_PASSPHRASE_SERVER` from the environment.

Output:
```json
{"address":"0xabc123..."}
```

### 3) Sign a 32-byte digest (requires both shares)
- Provide 32-byte hex digest (with or without `0x` prefix)
- Use separate env vars for each share’s passphrase when signing
```bash
export MPC_PASSPHRASE_CLIENT="change-me1"
export MPC_PASSPHRASE_SERVER="change-me2"

cargo run -- sign \
  --share-client client_share.enc.json \
  --share-server server_share.enc.json \
  --passphrase-client $MPC_PASSPHRASE_CLIENT \
  --passphrase-server $MPC_PASSPHRASE_SERVER \
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

## Local HTTP co-signer (optional)

### Start the co-signer service
```bash
export MPC_PASSPHRASE_SERVER="change-me2"

cargo run -- serve \
  --share-server server_share.enc.json \
  --passphrase-server $MPC_PASSPHRASE_SERVER \
  --bind 127.0.0.1:8080
```
- Endpoints:
  - GET `/healthz` → `{ "status": "ok" }`
  - POST `/partial_sign` with body:
    ```json
    { "x1": "<hex-32-bytes>", "digest": "<64-hex>" }
    ```
    Returns:
    ```json
    { "r": "0x...", "s": "0x...", "v": 27 }
    ```

### Sign using HTTP co-signer
```bash
export MPC_PASSPHRASE_CLIENT="change-me1"

cargo run -- sign \
  --share-client client_share.enc.json \
  --cosigner-url http://127.0.0.1:8080 \
  --passphrase-client $MPC_PASSPHRASE_CLIENT \
  --digest 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --out sig.json
```

## Command reference
- keygen
  - `--out-client <PATH>`: client share output (default `client_share.enc.json`)
  - `--out-server <PATH>`: server share output (default `server_share.enc.json`)
  - `--passphrase-client <STRING>` or env `MPC_PASSPHRASE_CLIENT`
  - `--passphrase-server <STRING>` or env `MPC_PASSPHRASE_SERVER`

- address
  - `--share <PATH>`: share file path (default `client_share.enc.json`)
  - `--passphrase <STRING>` or env fallback: `MPC_PASSPHRASE_CLIENT` → `MPC_PASSPHRASE_SERVER`

- sign
  - `--share-client <PATH>`: client share (default `client_share.enc.json`)
  - `--share-server <PATH>`: server share (default `server_share.enc.json`)
  - `--passphrase-client <STRING>` or env `MPC_PASSPHRASE_CLIENT`
  - `--passphrase-server <STRING>` or env `MPC_PASSPHRASE_SERVER`
  - Optional: `--cosigner-url <http://host:port>`: use HTTP co-signer instead of local server share file
  - `--digest <HEX>`: 32-byte digest
  - `--out <PATH>`: output signature JSON (default `sig.json`)

- serve
  - `--share-server <PATH>`: server share file (default `server_share.enc.json`)
  - `--passphrase-server <STRING>` or env `MPC_PASSPHRASE_SERVER`
  - `--bind <ADDR:PORT>`: bind address (default `127.0.0.1:8080`)

## Data and storage
- `KeyShareFile` (JSON):
  - `encrypted`: ciphertext bytes (JSON array)
  - `nonce`: 12-byte AEAD nonce
  - `kdf_salt`: 16-byte Argon2 salt
  - `public_key`: uncompressed secp256k1 pubkey (65 bytes, JSON array)
- `keygen` stores two different encrypted shares representing x1 and x2. Both are required to sign.

## Security notes
- At rest: no plaintext secret storage; Argon2 + ChaCha20-Poly1305
- 2-of-2 enforcement: both shares required; this MVP recombines locally in memory for signing (or via local HTTP)
- Scaffold: not a real TSS protocol; replace with audited threshold ECDSA (GG18/GG20) in future
- Keep passphrases secure; avoid committing share files

## Roadmap (per PRD)
- M1: Local MPC keygen (current scaffold with additive shares)
- M2: Threshold signing producing `(r, s, v)` with real TSS
- M3: Broadcast via EVM JSON-RPC
- M4: Backup export/import flows
- M5: Optional local HTTP service

## Development
```bash
cargo run -- <args>
cargo test
```

## License
MIT
