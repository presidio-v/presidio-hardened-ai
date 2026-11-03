# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.32.x  | Yes       |
| < 0.32  | No (never published; 0.32.0 is the first public release) |

### Supported Python runtimes

| Python | Supported |
|--------|-----------|
| 3.11 – 3.13 | Yes |
| ≤ 3.10 | No (end of life) |

Since 0.32.0 the package requires Python 3.11 or newer (`requires-python >=3.11`), the
same floor as presidio-evidence and ikigov-assess. CI runs the full gate on 3.11 and the
test suite on 3.12 and 3.13.

## Reporting a Vulnerability

Please report security vulnerabilities by opening a private GitHub Security Advisory
(via the "Security" tab → "Report a vulnerability", or
[report a vulnerability](https://github.com/presidio-v/presidio-hardened-ai/security/advisories/new))
rather than a public issue. You can also email security@presidio-group.eu.

Include: a description, steps to reproduce, potential impact, and a suggested fix if
any. You will receive an acknowledgement within 5 business days; we aim to release a
patch within 30 days of a confirmed vulnerability.

Reporters are credited in the advisory and in the `CHANGELOG.md` entry for the fix unless
they ask not to be. A flaw in a signed payload schema or in the evidence wire format can
affect the verifiers that consume this package's evidence (presidio-hardened-ikigov-assess,
presidio-evidence), so we coordinate the fix with them before disclosure.

## Security Design

`presidio-hardened-ai` implements the following controls in P1 (v0.1.0):

- **Tamper-evident ledger** — every entry is HMAC-SHA256-chained to its predecessor.
  Anyone without the key who inserts, reorders, edits or deletes an interior entry
  breaks the chain, and `pai verify` detects it (timing-safe MAC comparison). A keyed
  MAC is mandatory; there is no unkeyed mode. **Limit:** dropping trailing entries or
  the whole file leaves a valid shorter chain. It is detected only against an anchor
  known from elsewhere: `pai verify --expect-entry SEQ:HEX` (for example the O5 head of
  a verified signed export) or `--min-entries N`, the live `Ledger` object, or
  `EpsilonBudget(anchor=…)`. A missing ledger fails `pai verify` (since 0.32.0). The key
  holder can rewrite the whole chain; only signed exports held by others constrain that.
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
  chain; a tampered ledger fails closed (no spend figure is returned). Since 0.32.0 the
  chain is also checked against the `Ledger` object's own tail, so truncating or deleting
  the ledger while the budget is in use raises instead of refunding spend; a fresh
  process needs an external anchor (`EpsilonBudget(anchor=…)`) for the same guarantee.
  An over-budget charge is rejected and recorded nowhere.
- **Sound accounting.** Integer-order subsampled-Gaussian RDP (Mironov–Talwar–Zhang 2019)
  composed over steps, converted via Mironov (2017) — a sound upper bound on ε.

### Evidence signatures

Exported `EvidenceRef` objects carry a detached HMAC-SHA256 signature over the
content hash, bound to a signer id (the v0.9.0 family baseline). Verification is
fail-closed. A public-key scheme (sigstore/minisign) can be layered later without
changing the `EvidenceRef` shape, which matches the
`presidio-hardened-ikigov-assess` v0.13.0 contract verbatim.


### Canonical encoding and provenance (v0.31.0)

- **Strict canonical JSON.** Every new hash, ledger MAC and authorization request is
  computed over the family Layer-0 strict profile (floats and NaN rejected), checked
  against presidio-evidence's golden vectors. Privacy parameters are decimal strings at
  declared precisions; a non-zero delta or sample rate that would round to zero is
  refused rather than recorded as a stronger guarantee.
- **No silent downgrade.** Ledger entries carry a MAC-covered `canon: 1` tag. Since 0.32
  (#74) there is one canonicaliser in the trust path: an untagged (pre-0.31) entry, any
  other tag, an untagged authorization request and approvals over one all fail closed.
- **One implementation of the evidence contract.** Since 0.32 canonical JSON, the
  evidence signing message, HMAC/Ed25519 signing and verification and the envelope come
  from `presidio-evidence`; this repository's pinned copies of its golden vectors are
  checked against both the code and the installed library.
- **Provenance parents** are validated (lowercase hex, 8 to 128 chars) before any ledger
  write and sit inside the hashed content, so rewiring lineage breaks the hash and the
  signature. The producer does not resolve them.

### Verified gate certificates (v0.32.0)

- **The gate edge is verified, not asserted.** `--gate-certificate` on `dp-train`,
  `dp-charge` and `consortium-round` accepts an ikigov-assess `gate-certificate@1` only
  after ikigov's own `verify_certificate` passes against the `--gate-trust` store
  (issuer signature, predicate, expiry, every embedded evidence-ref, recomputed
  decision) and the decision is `OPEN`. Only then does its identity become a parent.
- **Fail closed before side effects.** Any refusal, a certificate without a trust store,
  a trust store without a certificate, a missing `[gate]` extra, or a file that is not a
  regular UTF-8 JSON file of at most 1 MiB (non-finite numbers rejected) exits 1 before
  the ledger is opened for writing. Security events record counts only, never paths or
  certificate content.
- **Trust is the operator's.** The trust store decides which issuers and evidence
  signers count; a certificate never vouches for itself.

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
  `os.urandom`-backed CSPRNG (`random.SystemRandom`). The library default remains a seeded
  PRNG for reproducible testing only. Since 0.32.1 `pai dp-train` and `pai fl-train` draw
  noise from the CSPRNG unless `--seed` is given; a seeded run warns that its noise is
  predictable and its ε does not hold against anyone who knows the seed.
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
  (gated on the worst-case per-party ε, recorded to the ledger first). Since 0.32.1 this
  holds for all three round types: the secure and GOD rounds authorize before any
  survivor-set anchoring, dealing or aggregation; each silo's (ε, δ)
  is charged to its own tamper-evident budget; and exactly one signed **D4** EvidenceRef is
  emitted, committing to the **aggregate only** (its field-domain hash) plus the worst-case
  bound — never an individual update. Commitments-only, like every other ledger event.
- **Transport** (`fl.transport`, `[mpc]` extra) — the masked vectors are exactly what the
  coordinator is permitted to see; the wire decoder validates party id, dimension, and that
  every element is a canonical field element, fail-closed. Since 0.32.0 every message is
  Ed25519-signed with the sender's identity key, and `RoundCoordinator` (served by
  `serve()`) accepts one submission per party, aggregates exactly once and serves only that
  cached result, so no caller can obtain two aggregates over different survivor sets. The
  session itself pins the survivor set at the first aggregation. TLS, bind address and rate
  limiting are deployment configuration.

**Threat model (v1, ADR-0001).** Honest-but-curious coordinator + ≤`t` colluding parties.

## Malicious-Security Hardening (P4, v0.16.0–v0.18.0, ADR-0002)

ADR-0002 extends the model to a **deviating** coordinator or colluding parties, with
**security-with-abort**. Three composable, ledger-anchored mechanisms, each closing a named
attack:

- **Signed survivor-set agreement** (`SurvivorSetSigner`/`verify_survivor_set`) — before any
  dropout-recovery share is revealed, the coordinator must present `≥t` **Ed25519** party
  signatures over the exact survivor set and round attempt, made with each party's identity
  key and checked against public keys only. Only parties in the alive set and the session
  count. The signatures are stored in the ledger entry, so anyone with the public keys can
  check them. An honest party's `SurvivorSetSigner` signs at most one set per round attempt;
  with an honest majority the coordinator therefore cannot collect `t` signatures on two
  different sets, so it cannot lie about who dropped to **unmask** a live party (the
  Bonawitz attack). Fail-closed. Until 0.32.0 these were HMACs under keys the coordinator
  had to hold, so they did not bind the coordinator. **Limit:** the coordinator holds the
  ledger, so equivocation is provable only by someone who obtains both signed sets.
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
  all bit commitments (no weak-FS). An **L∞ bounded-norm** proof extends it to a vector by
  range-proving both `u_k + B` and `B − u_k` for every coordinate (two-sided since 0.32.0;
  before, only `u_k + B` was proven, which admitted coordinates up to about `3B`).
- **Admission gate.** `run_secure_consortium_round(clip_bound=…)` verifies each contribution's
  bounded-norm proof against the **same** input commitments before aggregation; a poisoning
  update is rejected and the proven norm and bound are recorded on the ledger and in the
  signed D4 commitment (`proven_norm`, `norm_bound`).
- **Sensitivity is proven only by the L2 gate.** An L∞ bound `B` allows an L2 norm of up to
  `B·sqrt(dim)`, so the L∞ gate bounds poisoning but records `sensitivity_proven = false`.
  The L2 gate (`l2_bound=…`, ADR-0005) records `sensitivity_proven = true`; that supports
  the accountant's `(ε, δ)` against a malicious client only when `l2_bound` is the clip
  norm the noise was calibrated to, which an auditor checks from the recorded bound. (Until
  0.32.0 the L∞ gate also recorded `true`.)
- **L2 proof soundness.** The L2 proof also proves `|x_k| ≤ B` for every coordinate and
  requires `dim·B² < q`, so no square can wrap modulo the group order. Without it, a large
  coordinate could be cancelled by another whose square is `≡ −x² + small (mod q)` (fixed in
  0.32.0).

**Scope / deviation.** ADR-0003 recommended Bulletproofs over Ristretto255; neither is
available in this environment (no Ristretto255 in the libsodium build; no vetted Python
Bulletproofs library). v1 therefore uses a textbook, fully-tested range proof over the
already-vetted MODP-2048 group (same ZK guarantee; `O(n)` proof rather than `O(log n)`). The
**Ristretto255 + Bulletproofs** performance backend exists behind the `[zk]` extra (ADR-0004): a pluggable `ProofBackend` selects the dalek-based native backend when its wheel is installed and otherwise falls back to the pure-Python MODP proofs. **Before 0.32.0 the native crate did not compile** (its `bulletproofs 4.0` dependency is built on `curve25519-dalek-ng`), had the same one-sided L∞ range check, and padded differently on the prover and verifier sides; 0.32.0 moves to `bulletproofs 5.0` and `pyo3 0.29`, makes the check two-sided, binds the bound and length into the transcript, and runs the `ci-zk` lane on pull requests, where it cross-validates *decision equivalence* with the MODP backend. **L2** bounded-norm proofs (the exact DP clip norm, via a square-correctness Σ-proof + a squared-norm range proof) ship on both backends (ADR-0005); the consortium gate enforces `‖x‖₂ ≤ C` and records the proven norm. *Semantic* robustness against in-norm backdoors remains future work.

## Differential-Privacy Accounting (P2, v0.15.0)

The DP-SGD ε reported by the accountant and charged to budgets is a sound upper bound. As
of v0.15.0 it is minimised over a grid that includes **fractional Rényi orders** (the
TF-Privacy/Opacus log-A series, pure stdlib), which can only lower the bound — so the
reported ε is **≤** the integer-only result and never overstated-low. The fractional
series is validated to converge to the exact integer closed form as the order approaches
an integer, and is cross-validated against Opacus in the torch CI lane.

## Guaranteed Output Delivery (P4, v0.25.0–v0.27.0, ADR-0006)

ADR-0002 gives security-with-abort; ADR-0006 adds **guaranteed output delivery (GOD)** — the
round delivers the correct aggregate even when a minority of parties (or the coordinator)
actively misbehave, so one bad member cannot deny service to the consortium.

- **Honest-majority robust secret-sharing aggregation** (`fl.god`) — each party Feldman-VSS-
  shares its update; shares add locally (the sum of shares is a sharing of the sum); the
  aggregate is **robustly reconstructed** (`robust_reconstruct`): verify each share against
  the homomorphically-combined commitments, discard the invalid, interpolate from a valid
  quorum. A **malicious dealer** is excluded, including one whose input is malformed for the
  round (wrong dimension or degree, missing holders, non-group commitments; checked since
  0.32.0, before which such a dealer could abort the round or corrupt the sum); a
  **malicious holder** is discarded; and there is **no coordinator** to halt the round.
- **Exclude-and-retry interim** (`run_consortium_round_with_retry`) — for deployments not yet
  on the GOD path, the ADR-0002 round plus attributable cheater exclusion gives liveness under
  bounded cheating with no new crypto. Each retry is a new signed round attempt. **Limit:**
  comparing the aggregate before and after an exclusion reveals the excluded party's update;
  that party is a cryptographically attributed cheater, so the leak is limited to it.

**Trust premise.** GOD is achievable **only under an honest majority** (`n ≥ 2t+1`); a dishonest
majority can always withhold the output. Adopting GOD therefore means the consortium accepts a
majority-honest assumption — stricter than the ADR-0001/0002 collusion bound. Outside honest
majority, fall back to ADR-0002 security-with-abort (the round aborts attributably).

## Byzantine-ML Robustness Posture (P4, v0.30.0, ADR-0007)

Norm bounds + protocol honesty + delivery do not stop a *well-formed, in-norm* but adversarial
update (a backdoor / targeted poison). Classical Byzantine-robust rules inspect individual
updates — which secure aggregation hides — so this is handled as a **layered, privacy-preserving
posture** (none of which sees an individual update), not as detection-and-attribution:

- **Influence-bounding by construction** — the proven L2 norm (ADR-0005) and per-client DP both
  bound any single client's effect on the model (recognised poisoning mitigations).
- **Accountability** — known participants + n-of-m MPA + signed/ledgered contributions make an
  attack attributable and forensically traceable.
- **Aggregate validation gate + rollback** (`fl.robustness`) — each round's candidate aggregate
  is scored against a consortium-supplied clean validation set + a canary/trigger suite; a round
  that fails (low score, regression, a non-finite score, or a canary result other than `True`)
  is **rolled back** — its aggregate is
  not applied, **no DP budget is charged**, no evidence is emitted — and a flag is recorded on the
  ledger.

**Residual (stated, not claimed away):** a stealthy, low-deviation backdoor that does not move the
validation/canary metrics can still pass; v1 *contains and attributes* rather than *detects*. The
escalation path is a per-party cosine-band ZK proof (ADR-0007 B) and, for a malicious majority of
contributions, robust aggregation under MPC (ADR-0007 A). The consortium owns the clean validation
set and canary suite (the suite ships no data).

## Assurance case

The consolidated assurance case (threat model, trust boundaries, secure-design argument,
how common implementation weaknesses are countered, and the known limits above) is in
[ASSURANCE.md](ASSURANCE.md); components, data flow and trust boundaries are in
[ARCHITECTURE.md](ARCHITECTURE.md).

## Test keys in this repository

`tests/vectors/signing/` holds presidio-evidence's golden vectors, copied verbatim (see
`tests/vectors/PROVENANCE.txt`). They contain well-known test keys on purpose: the Ed25519
private key `01`×32 and the HMAC key `shared-key`. The test suite and the fuzz harnesses
also use fixed literal keys. These are published fixtures that make the vectors
reproducible across repositories, not secrets. Never use them outside tests.

## Verifying releases and obtaining public signing keys

Releases are cut from an SSH-signed `v*` tag by `.github/workflows/publish.yml`, which
checks that the tag matches the package version, builds with a hash-pinned toolchain and
publishes to PyPI through Trusted Publishing (OIDC, no stored API token). The publish job
runs in the `release` environment, which requires a maintainer's approval, so a pushed tag
alone cannot publish. There is no key to fetch by hand for artefact verification.

- **PyPI files** carry PEP 740 attestations from that workflow; PyPI shows them on each
  file's page.
- **GitHub release assets** (wheel, sdist, CycloneDX SBOM `sbom.cdx.json`) carry
  build-provenance attestations:

  ```bash
  gh attestation verify presidio_hardened_ai-<version>-py3-none-any.whl --repo presidio-v/presidio-hardened-ai
  gh attestation verify sbom.cdx.json --repo presidio-v/presidio-hardened-ai
  ```

  Each asset's provenance bundle is also attached to the release as `<asset>.intoto.jsonl`,
  so it can be verified without querying GitHub's attestation store:

  ```bash
  gh attestation verify sbom.cdx.json --bundle sbom.cdx.json.intoto.jsonl --repo presidio-v/presidio-hardened-ai
  ```

  The SBOM describes the wheel and its runtime dependencies as installed in a clean
  environment, not the build tooling.

- **Release tags** are SSH-signed with the organisation's release key, registered as a
  signing key on the maintainer's GitHub account, so each tag shows as **Verified**:

  ```bash
  gh api repos/presidio-v/presidio-hardened-ai/git/tags/<sha> --jq .verification.verified
  ```

  The public key is in [`allowed_signers`](allowed_signers). To verify a tag locally:

  ```bash
  git -c gpg.ssh.allowedSignersFile=allowed_signers verify-tag <tag>
  ```

## Software Development Lifecycle

Developed under the Presidio hardened-family SDLC:
<https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/sdlc-report.md>.
