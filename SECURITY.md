# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

### Supported Python runtimes

| Python | Supported |
|--------|-----------|
| 3.10 – 3.12 | Yes |

This package starts at `requires-python >=3.10`, aligned with the family baseline
from `presidio-hardened-ikigov-assess` v0.9.0 (Python 3.9 is upstream end-of-life and
leaves the dev/audit dependency tree pinned to a vulnerable `urllib3`).

## Reporting a Vulnerability

Please report security vulnerabilities by opening a private GitHub Security Advisory
(via the "Security" tab → "Report a vulnerability") rather than a public issue.

Include: a description, steps to reproduce, potential impact, and a suggested fix if
any. You will receive an acknowledgement within 5 business days; we aim to release a
patch within 30 days of a confirmed vulnerability.

## Security Design

`presidio-hardened-ai` implements the following controls in P1 (v0.1.0):

- **Tamper-evident ledger** — every entry is HMAC-SHA256-chained to its predecessor.
  Any insertion, deletion, reorder, or in-place edit breaks the chain and is detected
  by `pai verify` (timing-safe MAC comparison). A keyed MAC is mandatory; there is no
  unkeyed mode.
- **Commitments only, never content** — the ledger, the exported evidence file, and
  the security log carry hashes, counts, and structural metadata exclusively. Raw PII
  and organisational data never enter any persisted artifact. The ingest path enforces
  this by construction (only `sha256` commitments and per-entity counts are recorded).
- **PII scrub on ingest** — Presidio (NLP extra) or curated regex detection, with
  `redact` / `block` / `warn` actions. Detection favours precision; differential
  privacy is the planned mathematical backstop (P2) for residual recall.
- **Input validation & output escaping** — identifiers and paths are length-bounded
  and rejected on control/NUL bytes; free-text is HTML-escaped before any rendering.
- **Structural-only security log** — `~/.presidio-ai/security.log` records event name,
  counts, and mode flags only; never content or `ledger_ref` values. Logging is
  best-effort and never breaks the operation.
- **Per-session abuse guard** — a configurable maximum number of operations per session
  (`PRESIDIO_AI_MAX_OPS`, default 1000).
- **Restricted file permissions** — the ledger file and `~/.presidio-ai/` are created
  `0600` / `0700`.


### Differential-privacy budget (v0.2.0)

- **Privacy parameters are evidence, not PII.** ε, δ, noise multiplier, sampling rate, and
  step count are recorded to the ledger by design — they are accounting facts required to
  make the guarantee auditable, and contain no organisational data.
- **Tamper-evident budget.** The org ε budget is re-derived from the MAC-verified ledger
  chain; a tampered ledger fails closed (no spend figure is returned). An over-budget
  charge is rejected and recorded nowhere.
- **Sound accounting.** Integer-order subsampled-Gaussian RDP (Mironov–Talwar–Zhang 2019)
  composed over steps, converted via Mironov (2017) — a sound upper bound on ε.

### Evidence signatures

Exported `EvidenceRef` objects carry a detached HMAC-SHA256 signature over the
content hash, bound to a signer id (the v0.9.0 family baseline). Verification is
fail-closed. A public-key scheme (sigstore/minisign) can be layered later without
changing the `EvidenceRef` shape, which matches the
`presidio-hardened-ikigov-assess` v0.13.0 contract verbatim.


### High-ε authorization (v0.3.0)

- **n-of-m approval** gates budget charges at/above a configured ε threshold, reusing the
  x402 multi-party-authorization design (HMAC-SHA256 countersignatures).
- **Replay-bound** — an approval signs the canonical authorization request (job id + the
  job's privacy parameters), so it cannot be replayed onto a different job or (ε, δ).
- **Local trust** — approver keys are a local verifier trust store; no network resolution.
  The recorded `mpa-authorized` ledger entry holds approver ids and the request hash only.
- **Fail-closed** — insufficient or invalid approval rejects the charge and records nothing
  (CLI exit 3); over-budget is exit 2.


### Federated learning (v0.5.0)

- **Data stays in the silo.** Only DP-noised model updates are shared with the coordinator;
  raw silo data never leaves it.
- **Per-client differential privacy** bounds each silo's contribution and composes over
  rounds × local steps (accounted per client).
- **Secure aggregation** (`--secure-agg`) hides individual silo updates from the
  coordinator via zero-sum additive masking; it recovers only the combined update. The
  reference uses a seedable PRNG — a production deployment uses pairwise-exchanged mask
  seeds and a CSPRNG.


### DP randomness & Opacus backend (v0.6.0)

- **CSPRNG noise option.** The reference trainer's `secure_rng=True` draws DP noise from an
  `os.urandom`-backed CSPRNG (`random.SystemRandom`), closing the earlier seedable-PRNG
  caveat; the default remains a seeded PRNG for reproducible testing only.
- **Opacus backend** uses `PrivacyEngine(secure_mode=...)` and is verified in a dedicated
  torch CI lane that cross-validates Opacus' privacy accountant against this suite's
  `dpsgd_epsilon` — so the accounting cannot silently diverge between backends.


### Public-key evidence signing (v0.7.0–v0.8.0)

- **Ed25519 (RFC 8032)** detached signatures are available alongside HMAC for evidence,
  over the same canonical `{content_hash, signer}` message (drop-in at the wire level).
- **Asymmetric trust:** the producer holds the private key; a verifier holds only the
  public key. The signing algorithm is a property of the verifier's trust entry, so the
  `EvidenceRef` contract is unchanged.
- **Ed25519 is the default (v0.8.0)**, coordinated with ikigov v0.14.0 public-key
  verification; HMAC remains available via `--algorithm hmac-sha256`. Deploy the v0.14.0
  verifier before/with this flip so the live loop never sees evidence it cannot check.
- `cryptography` is an optional `[crypto]` extra; Ed25519 calls raise a clear ImportError
  without it. A fixed-key golden vector locks the wire format across repos.

## Secure Aggregation & Consortium Rounds (P4, v0.11.0–v0.14.0)

Multi-party consortium training (ADR-0001) lets mutually-distrusting parties compute an
aggregate model update such that the coordinator — and any colluding minority below the
threshold — learns only the aggregate, never an individual party's update. Controls:

- **Secure aggregation by additive masking** (`fl.secure_agg`) — antisymmetric pairwise
  masks cancel in the sum; per-party self-masks close the dropped-party stripping window.
  All masking and reconstruction are **exact in GF(prime)** (v0.12.0): no floating-point
  cancellation error, no overflow within the documented fixed-point range.
- **Dropout recovery via Shamir t-of-n** — self/pairwise seeds are secret-shared; the
  coordinator reconstructs only what is needed to strip masks. **Fail-closed:** fewer than
  `threshold` survivors cannot reconstruct and the round aborts rather than leaking.
- **Authenticated key agreement** (`fl.keyagreement`, `[mpc]` extra) — pairwise seeds come
  from X25519 ECDH → HKDF-SHA256, domain-separated per round. Each DH public key is
  **Ed25519-signed** under the party's identity key and verified against a local trust
  store; an unsigned, mis-signed, or unknown key is rejected, defeating a coordinator that
  tries to MITM the exchange by substituting its own DH key. Seeds are drawn from a CSPRNG.
- **Governed rounds** (`fl.consortium`) — a round runs only after n-of-m MPA authorization
  (gated on the worst-case per-party ε, recorded to the ledger first); each silo's (ε, δ)
  is charged to its own tamper-evident budget; and exactly one signed **D4** EvidenceRef is
  emitted, committing to the **aggregate only** (its field-domain hash) plus the worst-case
  bound — never an individual update. Commitments-only, like every other ledger event.
- **Transport** (`fl.transport`, `[mpc]` extra) — the masked vectors are exactly what the
  coordinator is permitted to see; the wire decoder validates party id, dimension, and that
  every element is a canonical field element, fail-closed. TLS and bind address are
  deployment configuration.

**Threat model (v1, ADR-0001).** Honest-but-curious coordinator + ≤`t` colluding parties.

## Malicious-Security Hardening (P4, v0.16.0–v0.18.0, ADR-0002)

ADR-0002 extends the model to a **deviating** coordinator or colluding parties, with
**security-with-abort**. Three composable, ledger-anchored mechanisms, each closing a named
attack:

- **Signed survivor-set agreement** (`sign_survivor_set`/`verify_survivor_set`) — before any
  dropout-recovery share is revealed, the coordinator must present `≥t` party signatures
  over the **exact** survivor set, recorded on the ledger. Because each signature binds the
  specific alive-set, a coordinator cannot obtain `t` signatures over two different sets, so
  it cannot lie about who dropped to **unmask** a live party (the Bonawitz attack). Fail-closed.
- **Verifiable secret sharing** (Feldman VSS, `fl.commit`) — mask-seed shares carry public
  `g^{a_i}` coefficient commitments; a shareholder rejects an inconsistent share, so a
  malicious dealer cannot corrupt reconstruction. Verified during reconstruction in
  verifiable-mode `SecureAggregationSession`; a bad share aborts the round.
- **Homomorphically-committed inputs** (Pedersen, `fl.commit`) — each party publishes a
  Pedersen commitment to its input; the product of commitments is a commitment to the sum,
  so a party checks the coordinator's returned aggregate and aborts on a **false aggregate**.
  Commitments are bound to the ledger (as a digest, commitments-only).

The group is a pure-Python prime-order Schnorr group over the RFC 3526 MODP-2048 safe prime
(no new binary dependency; the modulus' primality is re-verified in tests). Only the
seed-sharing exponent field moves to `Z_q`; the additive masking stays exact in GF(2⁶¹−1).

**Threat model now.** Confidentiality + **integrity-or-abort** against a malicious
coordinator (equivocation, false aggregate) and a malicious minority of parties
(inconsistent shares). **Out of scope** (separate ADRs): input poisoning — a *well-formed
but adversarial* update needs bounded-norm zero-knowledge proofs (Byzantine robustness, not
secure aggregation) — and **liveness/DoS**: a cheater can force a clean, attributable abort.
Guaranteed output delivery and removing the collusion bound `t` are likewise future work.

## Bounded-Norm Input Validation (P4, v0.19.0–v0.20.0, ADR-0003)

A malicious party can submit a *well-formed but out-of-norm* update to dominate or poison
the aggregate — and since secure aggregation hides individual updates, the coordinator
cannot clip it. `fl.zk` lets a party prove **in zero knowledge** that its committed update
is within a norm bound, without revealing it:

- **Transparent ZK range proof** (Pedersen bit-decomposition over the prime-order MODP-2048
  group; no trusted setup): a per-bit Chaum–Pedersen OR-proof, bound to the commitment by
  `Π C_i^{2^i} == C`, with a Fiat–Shamir transcript binding the commitment, the bound, and
  all bit commitments (no weak-FS). An **L∞ bounded-norm** proof extends it to a vector.
- **Admission gate.** `run_secure_consortium_round(clip_bound=…)` verifies each contribution's
  bounded-norm proof against the **same** input commitments before aggregation; a poisoning
  update is rejected and the proven outcome is recorded on the ledger (`sensitivity_proven`).
- **Sensitivity becomes proven, not assumed.** The bound is the DP clip sensitivity, so the
  per-client `(ε, δ)` the accountant reports holds even against a malicious client — closing
  the gap between assumed and enforced clipping.

**Scope / deviation.** ADR-0003 recommended Bulletproofs over Ristretto255; neither is
available in this environment (no Ristretto255 in the libsodium build; no vetted Python
Bulletproofs library). v1 therefore uses a textbook, fully-tested range proof over the
already-vetted MODP-2048 group (same ZK guarantee; `O(n)` proof rather than `O(log n)`). The
Ristretto255 + Bulletproofs performance backend (reserved `[zk]` extra), the **L2** bound,
and *semantic* robustness against in-norm backdoors are future work.

## Differential-Privacy Accounting (P2, v0.15.0)

The DP-SGD ε reported by the accountant and charged to budgets is a sound upper bound. As
of v0.15.0 it is minimised over a grid that includes **fractional Rényi orders** (the
TF-Privacy/Opacus log-A series, pure stdlib), which can only lower the bound — so the
reported ε is **≤** the integer-only result and never overstated-low. The fractional
series is validated to converge to the exact integer closed form as the order approaches
an integer, and is cross-validated against Opacus in the torch CI lane.

## Software Development Lifecycle

Developed under the Presidio hardened-family SDLC:
<https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/sdlc-report.md>.
