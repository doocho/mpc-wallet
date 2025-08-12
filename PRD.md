## MPC 2-of-2 Wallet — Product Requirements Document (PRD)

### Overview
An MPC (Multi-Party Computation) 2-of-2 wallet that splits a single ECDSA private key into two cryptographic key-shares held by separate parties (Client and Co-signer Service). All transactions require both parties to participate in a threshold ECDSA signing protocol; neither party ever reconstructs the full private key. The MVP targets a local demo with a CLI and optional local HTTP service, signing transactions on an EVM testnet (e.g., Sepolia).

### Goals
- **Security by design**: Private key never exists in full; only MPC key-shares are stored and used.
- **Usability**: Simple CLI for keygen, address viewing, and signing; optional local HTTP API.
- **Deterministic multi-account**: Support derivation of multiple addresses from a single key-share set.
- **Auditable flows**: Clear logs and reproducible flows for development/testing.
- **Portable implementation**: Rust library with clean interfaces for reuse in other apps.

### Non-Goals
- Custodial features, KYC/AML, or production multi-tenant backend.
- Browser/mobile UI (CLI only for MVP).
- Cross-chain support beyond a single EVM testnet for MVP.
- Social recovery, 2-of-3, or policy engine; only 2-of-2 threshold.

### Personas
- **Developer/Integrator**: Wants a reliable library and CLI to integrate secure signing into services.
- **Power User**: Comfortable with CLI; wants higher security than single-key wallets.

### User Stories
- As a developer, I can generate a 2-of-2 key-share set so that no single device has the full key.
- As a user, I can view my wallet address derived from the MPC public key.
- As a user, I can sign and broadcast an EVM transaction, requiring both parties’ participation.
- As an operator, I can backup/restore encrypted key-shares locally.
- As an operator, I can rotate key-shares while preserving the public address (if supported by the scheme) or migrate balances safely if not.

### Scope
- **MVP**
  - Local 2-party key generation (Client + Co-signer Service) for threshold ECDSA over secp256k1.
  - Address derivation compatible with EVM chains.
  - Signing of basic EVM transactions (transfer ETH, ERC-20 transfer via prepared calldata).
  - CLI and optional local HTTP service; JSON outputs for scripting.
  - Encrypted-at-rest storage of key-shares.
  - Basic observability (structured logs) and health checks.
- **vNext (Out of MVP)**
  - Remote co-signer service with authentication/attestation.
  - Policy engine (limits, whitelists), session approvals.
  - Multiple chains (Bitcoin, other ECDSA/Schnorr chains), ERC-4337 support, batch flows.

### Functional Requirements
- **Key generation**
  - Two parties jointly run a threshold ECDSA keygen protocol; output is `(public_key, client_share, server_share)`.
  - Neither party can derive the full private key from its share.
- **Address derivation**
  - Compute standard EVM address from the aggregated public key.
  - Optional deterministic child key derivation for multiple accounts (MVP may use index-based re-keying rather than full BIP32-TSS).
- **Signing**
  - Both parties run an interactive threshold ECDSA signing protocol to produce an ECDSA signature compatible with EVM.
  - Provide signature as `r, s, v` for EVM transaction signing.
- **Backup/restore**
  - Export/import encrypted key-share files with passphrase.
- **CLI**
  - Commands: `keygen`, `address`, `sign`, `broadcast`, `backup export`, `backup import`, `health`.
- **Local HTTP service (optional)**
  - Endpoints for keygen, address, sign, and health checks (JSON in/out).

### Non-Functional Requirements
- **Security**: No plaintext key-share storage; memory zeroization where possible; constant-time crypto primitives from vetted libraries.
- **Privacy**: No external telemetry in MVP; local logs only.
- **Performance**: Single-sign under 1s on modern laptops for typical transaction sizes.
- **Reliability**: Clear error messages, idempotent operations where possible.
- **Portability**: Builds on macOS/Linux via `cargo`.

### Architecture
- **Components**
  - `Client`: CLI + local library handling one key-share and initiating flows.
  - `Co-signer Service`: Local process holding the second key-share and participating in MPC.
  - `RPC Provider`: EVM JSON-RPC endpoint (e.g., Sepolia) for chain data and broadcasts.
- **Process Boundaries**
  - Client and Co-signer communicate via localhost (IPC/HTTP/WebSocket).
  - All MPC messages are ephemeral and not persisted.

### Protocol Flows (High-Level)
- **Key Generation (2-of-2)**
  1) Client starts keygen, generates commitment/nonce material.
  2) Co-signer responds with its commitments.
  3) Parties exchange proofs and compute public key; each stores its encrypted share.
- **Transaction Signing**
  1) Client prepares transaction digest (`keccak256(EIP-155 payload)` or typed data hash).
  2) Client and Co-signer run threshold ECDSA signing (nonce generation, zero-knowledge checks, partial signatures).
  3) Client combines partial signatures to `(r, s)` and computes `v`.
  4) Client assembles raw signed transaction and optionally broadcasts via RPC.
- **Key Rotation (optional MVP)**
  - Re-run keygen to produce a new key; migrate funds by sending from old to new address.

### APIs
- **CLI (examples)**
  - `mpc keygen --out client_share.json` (starts local co-signer and completes)
  - `mpc address --share client_share.json`
  - `mpc sign --share client_share.json --tx tx.json --out sig.json`
  - `mpc broadcast --raw raw_tx.hex`
  - `mpc backup export --share client_share.json --out client_share.enc`
  - `mpc backup import --in client_share.enc --out client_share.json`
- **Local HTTP (optional)**
  - `POST /keygen/init` → `{ session_id }`
  - `POST /keygen/complete` → `{ public_key, address }`
  - `POST /address` → `{ address }`
  - `POST /tx/prepare` → `{ tx_hash }`
  - `POST /tx/sign` → `{ r, s, v }`
  - `GET /healthz` → `{ status: "ok" }`
- **Rust library (high-level traits)**
  - `trait KeyShareStore { fn save(&self, share: KeyShare) -> Result<()>; fn load(&self) -> Result<KeyShare>; }`
  - `trait ThresholdSigner { fn keygen(&self) -> Result<(PublicKey, KeyShare)>; fn sign(&self, digest: [u8; 32]) -> Result<Signature>; }`

### Data Model & Storage
- **KeyShare**: Holder’s partial secret, plus MPC metadata (commitments, verification data).
- **Encryption**: AES-GCM or ChaCha20-Poly1305 with passphrase-based KDF (Argon2id). Salt and nonce stored alongside ciphertext.
- **Files**: `client_share.enc`, `server_share.enc` stored locally on respective processes.

### Security & Threat Model
- **Assumptions**
  - Client and Co-signer run on separate logical processes with isolated storage.
  - Attacker cannot compromise both parties simultaneously for the duration of signing.
- **Threats & Mitigations**
  - Single-party compromise: 2-of-2 prevents unilateral signing.
  - Key-share theft at rest: Encrypt shares with strong KDF; use OS-secret storage if available.
  - MITM on local channel: Use authenticated channels (localhost + optional mutual auth tokens).
  - Side-channel/leakage: Use constant-time crypto libraries; avoid verbose secrets in logs.
  - DoS by unresponsive party: Surface clear errors; allow retries; document availability risk inherent to 2-of-2.
- **Crypto Hygiene**
  - Use vetted threshold ECDSA protocol (e.g., GG18/GG20 implementation). No custom crypto.
  - Zeroize sensitive buffers when possible.

### Observability & Logging
- Structured logs (JSON) with correlation IDs per MPC session.
- `GET /healthz` and CLI `health` command.

### Error Handling
- Clear, actionable errors for: invalid shares, failed MPC rounds, RPC failures, chain reorgs on broadcast.
- Retries for transient RPC failures with exponential backoff.

### Performance Targets
- Keygen < 3s on a modern laptop.
- Signing < 1s per transaction under normal load.

### Compliance & Licensing
- MIT license for the codebase (unless specified otherwise).
- No PII collection; local-only operation in MVP.

### Milestones
- **M0 — PRD**: This document checked in.
- **M1 — Local MPC keygen**: CLI generates and stores encrypted key-shares; address derivation works.
- **M2 — Signing**: CLI signs a prepared EVM transaction and outputs `(r, s, v)`.
- **M3 — Broadcast**: CLI broadcasts to Sepolia and returns tx hash.
- **M4 — Backups**: Export/Import encrypted share files; passphrase flows.
- **M5 — Optional HTTP**: Local service exposing key flows with JSON.

### Acceptance Criteria (MVP)
- `mpc keygen` produces `client_share.enc`, `server_share.enc`, and prints the EVM address.
- `mpc sign` with a valid `tx.json` yields a correct ECDSA signature accepted by an EVM RPC when broadcast.
- Shares are encrypted at rest; no plaintext secrets persisted.
- Logs show MPC session IDs and round transitions without leaking secrets.
- Health check returns `ok` while the co-signer is operational.

### Risks & Mitigations
- 2-of-2 availability risk: Any party offline blocks signing → document and provide retries.
- Implementation complexity of TSS: Use existing, audited libraries where possible; add tests and property checks.
- Misconfiguration of RPC endpoints: Validate chain ID and gas settings; provide sensible defaults.

### Open Questions
- Choice of threshold ECDSA library in Rust (availability, license).
- Deterministic derivation: adopt BIP32-TSS now vs. simple index-based separate keys.
- Remote co-signer hardening (authentication, attestation) in vNext.

### Assumptions
- EVM testnet (Sepolia) is available; RPC endpoint configured via env var.
- Local filesystem is writable for encrypted share storage.

### Glossary
- **MPC/TSS**: Multi-Party Computation / Threshold Signature Scheme.
- **2-of-2**: Both parties must participate to produce a valid signature.
- **Share**: A party’s secret material that cannot alone produce signatures.
- **EVM**: Ethereum Virtual Machine compatible chain.


