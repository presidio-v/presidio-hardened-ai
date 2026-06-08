# presidio-hardened-ai — Product & Architecture Plan

> Status: draft v0.1 · 2026-06-08 · Owner: Vladimir (presidio-group.eu)
> Part of the [`presidio-hardened-*`](https://github.com/presidio-v) toolkit family.

---

## 1. Thesis

**Architecture is the only defense.** Privacy and compliance guarantees that rest on
policy or trust are not guarantees. `presidio-hardened-ai` provides *training-time*
privacy for organisations that fine-tune models on sensitive data, backed by
mathematical (differential privacy) and cryptographic (signed, tamper-evident lineage)
evidence — not promises.

It is the **training-time member** of the `presidio-hardened-*` family. It does not
reinvent the family's substrate; it extends it to a new class of privacy-sensitive
action: the training job.

### The unifying family primitive

> Every privacy-sensitive action emits a **signed, Presidio-screened, policy-checked,
> optionally multi-party-authorized ledger entry.**

| Family member | Action governed | Status |
|---|---|---|
| `presidio-hardened-ikigov-assess` | AI **governance assessment** — the governance *spine* | Published v0.8.0 (CLI + MCP); implements the IKI-Gov-Referenzmodell (Stantchev) |
| `presidio-hardened-x402` | Agentic **payments** | Published v0.4.0 (PyPI, IEEE/arXiv) |
| `presidio-hardened-ai` | Model **training / fine-tuning** | This plan — new |
| `presidio-hardened-arch-translucency` | Runtime architecture (SLO broker) | Referenced (x402 v0.6 roadmap) |

ikigov is the **governance spine**: it defines the lifecycle (G0–G5), the six maturity
dimensions (M1–M6), the 25-item checklist, and the mappings to ISO/IEC 42001 and EU AI
Act Art. 9–17. x402 and `hardened-ai` are **technical controls** that produce signed
evidence which ikigov consumes. This is the suite's structure: one framework, many
evidence-emitting controls.

---

## 2. Scope & threat model (v1)

**Locked decisions:** training-time wedge · regulated EU enterprise → **financial
services** design partner · **sovereign / on-prem** · **LLM fine-tuning** · positioning =
**compliance evidence**.

### In scope

- Fine-tuning open-weight base models (Llama / Mistral-class) inside the customer VPC.
- PII discovery, classification, lawful-basis tagging, and scrub/pseudonymisation on
  ingest.
- Differential privacy during fine-tuning (DP-SGD), with per-job ε accounting against an
  org-wide budget.
- Tamper-evident lineage + privacy dossier suitable for EU AI Act (Art. 10/11) and the
  bank's existing Model Risk Management (MRM) validation pipeline.

### Out of scope for v1 (deliberately)

- **SMPC / multi-party** — no counterparty exists for a single org training on its own
  data. Park for the consortium phase (§6, Phase 4).
- **Federated learning** — only earns its place when data legally cannot be centralised
  *even internally* (cross-border group entities). Phase 3.
- **Inference-time security** (dual-LLM, prompt-injection, tool-use sandboxing) — a
  different threat model and a different product. Out of this wedge entirely.
- **Hosted / SaaS training** — contradicts the sovereign pitch; we are never the data
  custodian.

### Forced architectural constraint

DP-SGD requires gradient access, and a bank will not send transaction data to a hosted
frontier API. Therefore **v1 is an open-weights play, in-VPC, by construction.** This is
not a limitation to apologise for — it *is* the sovereignty story.

### Adversaries and the matched defense

| Adversary | Defense | Why this one, not more |
|---|---|---|
| Model memorising & leaking training records (membership inference / extraction) | **DP-SGD** with bounded ε | The only mechanism giving a *provable* leakage bound |
| Cloud / vendor seeing raw data | **On-prem in-VPC** deployment | Data never leaves the silo |
| Imperfect PII scrubbing (recall < 100%) | **DP as backstop** behind Presidio scrub | Defense-in-depth that is actually justified: scrub kills the obvious, DP bounds the residual |
| Tampering with the audit/evidence trail | **HMAC-chained signed ledger** (family substrate) | Evidence must be tamper-evident to satisfy a regulator |
| Insider over-spend of privacy budget | **n-of-m multi-party authorization** on high-ε jobs | Same primitive x402 uses for high-value payments |

Anything else on the menu (SMPC, FL, exotic crypto) would be cost without a matching
adversary in this wedge.

---

## 3. Positioning

**Lead with compliance evidence, not algorithms.** Regulated buyers purchase *evidence*,
not privacy math.

- **Economic buyer:** Chief Risk Officer / Head of Model Risk + Data Protection Officer.
  CISO and Head of AI/Data Science are influencers, not signatories.
- **Wedge into the org:** plug into the **Model Risk Management** discipline FS already
  runs (ECB internal-models culture; the SR 11-7 mindset). We do not ask the bank to
  adopt a new process — we feed privacy evidence into the validation pipeline they
  already run and currently cannot populate.
- **CRO-native framing:** express the org's **ε privacy budget as a board-set risk
  appetite limit**, spent down through signed, countersigned ledger entries. A CRO
  understands this instantly.
- **Ownable narrative — the LLM right-to-erasure problem (GDPR Art. 17):** you cannot
  surgically unlearn one customer from a fine-tuned model. DP materially weakens
  membership-inference, supporting the argument that the model does not meaningfully
  "contain" any individual; the ledger documents lineage and retraining cadence. No
  compliance vendor sells this cleanly today.

---

## 4. v1 architecture

Three layers, all in the customer VPC. **Bold = new build; the rest is family lift.**

### Layer 1 — Ingest & PII (family lift)

Presidio-based discovery + classification, lawful-basis/consent tagging, and
scrub/pseudonymisation. Reuses the same Presidio config and the hosted
`screen.presidio-group.eu` screening backend already shipped in x402 v0.4.0 (with local
regex/NLP fallback so a screening outage never hard-fails a job). Every decision is
written to the ledger.

### Layer 2 — **DP fine-tune harness (new)**

DP-SGD (Opacus-style) wrapping the fine-tune of an open base model.

- **Utility-preserving pattern:** never apply DP globally. Pre-train / start from the
  public base, then **DP-fine-tune only the sensitive delta** (or only the upper layers).
  This is the single most important mitigation for DP's accuracy hit, which is the known
  adoption killer.
- **ε-budget accountant (new):** every job debits a per-job ε from an org-wide budget;
  the running total is a first-class, auditable resource.
- High-ε jobs gated behind **n-of-m multi-party authorization** — the exact MPA primitive
  from x402, with "privacy budget" substituted for "dollars."

### Layer 3 — Privacy ledger = extended family audit log (mostly lift)

The HMAC-chained, append-only JSON-L audit log from the family, **extended with
ε-accounting fields and model-artifact lineage**, exportable as an AI Act / MRM dossier.

- **Critical security rule:** the ledger holds **commitments and lineage refs, never raw
  PII** — salted hashes, not records. Otherwise the audit log becomes a brand-new breach
  surface. The data stays in the silo; the ledger only *proves things about it*.
- Emits the same Prometheus metric style x402 already ships, and targets the same audit
  sinks the family is standardising on (S3 / Splunk / Datadog — x402 v0.5.0 roadmap).

### What is genuinely new vs. reused

| Component | New build | Family lift |
|---|---|---|
| PII discovery / scrub / screening | | ✅ (Presidio + `screen.presidio-group.eu`) |
| Tamper-evident audit log | extend w/ ε + lineage | ✅ (HMAC-chained JSON-L) |
| Policy-as-code (JSON Schema) | ε-budget policy schema | ✅ (pattern) |
| Multi-party authorization | wire to ε gate | ✅ (n-of-m, webhook + crypto) |
| Metrics / audit sinks | | ✅ (Prometheus, S3/Splunk/Datadog) |
| **DP-SGD fine-tune harness** | ✅ | |
| **ε-budget accountant** | ✅ | |
| **AI Act / MRM dossier exporter** | ✅ | |

The net new surface is three components. Everything else is shared substrate — the
perfectionist coherence play, and a real moat (suite-wide network effect).

---

## 5. Family integrations (later, by design)

Sequenced *after* the standalone v1 lands, but architected for from day one.

### ikigov (highest-value tie) — now concrete

**The insight.** ikigov scores governance maturity from **human self-attestation**:
`iga assess --affirm S1,S2,D1,…` — each checklist item is a *boolean someone ticks*. The
inherent weakness of any GRC/maturity tool is exactly this: an affirmation is trust, not
proof. `hardened-ai` converts the subset of items that are **technical controls** from
self-attestation into **cryptographically signed evidence**. That is the suite's real
differentiator: **evidence-backed affirmation** — turning a maturity questionnaire into a
machine-verifiable conformity trail.

**It targets ikigov's weakest dimensions.** The items `hardened-ai` can evidence cluster
in M2 (Data Quality & Lineage), M4 (Security & Robustness) and M5/M6 (Compliance Evidence
/ audit) — precisely the dimensions that score lowest under self-attestation (the README's
own example shows M5 at 30%, M3 at 40%). We strengthen exactly where the questionnaire is
weakest.

**Checklist items `hardened-ai` can sign evidence for** (IDs verified against
`checklist.py`):

| Item | Checklist text (abridged) | Gate(s) | Evidence `hardened-ai` emits | Strength |
|---|---|---|---|---|
| **D1** | All data sources inventoried; lineage documented end-to-end to origin | G1, G2 | Ingest lineage ledger (source → scrub → training set) | Strong |
| **D4** | DPIA (GDPR Art. 35) completed and risks mitigated | G2 | DP ε-guarantee + PII-scrub logs as DPIA inputs | Strong (input, not the DPIA itself) |
| **O5** | Immutable audit log of decisions/events/parameter changes, auditor-accessible | G4, G5 | The HMAC-chained training ledger *is* this for training-time | Strong — near-exact match |
| **T5** | Security review of model pipeline, infra, and all dependencies | G3 | Family SDLC + SLSA build provenance + dependency CVE scan | Medium–Strong |
| **T4** | Adversarial robustness + input validation + output sanitisation | G3 | DP-bounded membership-inference resistance | Medium |
| **D2** | Data quality assessment (completeness, accuracy, timeliness) | G2 | Ingest profiling stats logged to ledger | Medium |
| **I4** | Lifecycle documented per ISO/IEC 42001 8.3–8.6 | G5 | Ledger documents the development phase | Medium |

**EU AI Act articles it feeds** (via `euaiact.EU_AI_ACT_ARTICLE_GATES`): **Art. 10** (Data
governance, G1) and **Art. 12** (Record-keeping / logging, G4) are direct hits — Art. 12 is
literally automatic lifetime logging, which the ledger provides. **Art. 9** (risk
management — ε-budget as risk appetite), **Art. 11** (technical documentation — the
dossier), and **Art. 15** (accuracy/robustness/cybersecurity — DP + pipeline security) are
secondary feeds.

**Integration contract** (the surface already exists):

1. *Near-term, zero-change to ikigov:* a bridge maps each signed `hardened-ai` attestation
   to the item IDs it evidences and calls ikigov's MCP `iga_assess(affirmed=[...])`; the
   returned `build_payload` JSON is the assessment. `hardened-ai` should expose its own MCP
   server (family consistency) so an agent can chain `hardened-ai → ikigov` in one session.
2. *The joint enhancement (proposed):* extend ikigov's affirmation model from a boolean to
   **affirmed-by-evidence** — an item carries an optional ledger ref + content hash. The
   report then distinguishes "ticked" from "cryptographically proven," and an auditor can
   verify the hash against the ledger. This upgrade makes *both* tools stronger and is the
   moat of the suite. **Specified in ikigov's `PRESIDIO-REQ.md` as v0.13.0** ("External
   Evidence-Backed Affirmation"), building on ikigov v0.9.0 (signed evidence-pack manifest);
   the `EvidenceRef` schema there is the cross-repo contract `hardened-ai` exports against
   from day one.

### x402 (data-acquisition rail, Phase 3+)

When an agent **pays for external training data**, x402 already (a) redacts PII from
payment metadata, (b) enforces spend policy + n-of-m approval, and (c) writes a
tamper-evident payment record. That payment record links to the `hardened-ai` lineage
entry for the data it bought — provenance from purchase through training. x402's v0.6
**SLO payment broker** (compute as micropayment bids) is a candidate funding rail for
federated / secure compute.

### Shared substrate to standardise now

Adopt the family conventions from the first commit so integrations are config, not rework.
Verified across x402 and ikigov: HMAC-chained audit log; Presidio screening
(`screen.presidio-group.eu` + local fallback); policy-as-code JSON Schema; n-of-m MPA;
Prometheus metrics; an **MCP server front-end** (ikigov ships `iga-mcp`; x402 ships
adapters — `hardened-ai` should expose one too); `SECURITY.md` + `PRESIDIO-REQ.md`
deliberation log; **structural-metadata-only logging** (ikigov's `security.log` logs "no
content, structural metadata only" — this *is* the family's "ledger holds commitments, not
PII" rule, already in production); `pip-audit` CVE gate; session rate-limiting; strict
input validation + output sanitisation; and the family SDLC (`presidio-hardened-docs`).

---

## 6. Roadmap

| Phase | Milestone | New build | Outcome |
|---|---|---|---|
| **P1 — Evidence layer** | On-prem **ingest + privacy ledger** wrapped around a fine-tuning project the bank is *already* running. No DP yet. | dossier exporter (v0) | Lands the first FS logo at lowest research risk; AI Act / MRM value immediately |
| **P2 — The moat** | **DP-SGD harness + ε-budget accountant**, n-of-m gate on high-ε jobs, full signed dossier | DP harness, ε accountant | Provable leakage bound — the differentiator |
| **P3 — Federated** | Cross-border / cross-silo FL for banking groups (EU + non-EU entities that cannot centralise) | FL coordinator | Expands ACV within the same account |
| **P4 — Consortium (pull-only)** | Multi-party **AML / fraud** models several banks train without sharing customer data (SMPC + FL) | SMPC | The platform prize FS will pull you toward |

Integrations (ikigov dossier feed; x402 data-acquisition rail) slot in from P2–P3.

---

## 7. Target groups

**Primary (v1):** EU financial services — banks and large FS groups with mature MRM
functions, fine-tuning open-weight LLMs on customer/transaction data in-VPC.

- **Buyer:** CRO / Head of Model Risk + DPO. **Influencers:** CISO, Head of AI/Data
  Science.
- **Trigger:** an EU AI Act high-risk obligation or a supervisory model-validation
  requirement they cannot currently evidence for privacy.

**Adjacent expansion (later):** insurance (actuarial/underwriting, similar audit culture,
less vendor-crowded); public sector / sovereign (the ikigov + sovereignty angle,
reference-generating). Healthcare/life-sciences pulls FL forward sooner but is more
sensitive to DP accuracy loss — revisit after P2.

---

## 8. Key risks & open questions

**Risks**

- **DP accuracy loss** is the adoption killer → mitigated by public-base/private-delta
  fine-tuning; must be benchmarked early on a representative FS task.
- **Ledger as a breach surface** if PII ever leaks into it → enforce commitments-only,
  reuse the family's vetted HMAC-chain.
- **Open-weights ceiling** → some buyers will want frontier-model quality; be explicit
  that the privacy guarantee requires in-VPC gradient access, which frontier APIs do not
  permit. Frame as a deliberate trade, not a gap.
- **Scope creep into inference security** → keep it firmly out of this wedge.

**Open questions**

1. *(Resolved.)* ikigov data model is known and the enhancement is now specified as
   **ikigov v0.13.0** in its `PRESIDIO-REQ.md`. Open sub-decision left to the author: pull
   v0.13.0 forward to right after v0.9.0, or keep it after the planned v0.10–v0.12.
2. Which open base model(s) to support first, and at what parameter scale, for the FS
   design partner?
3. DP accounting method (Rényi DP / PRV) and the org-budget ε/δ defaults to propose to a
   CRO.
4. Do we reuse `screen.presidio-group.eu` for on-prem deployments, or ship a fully
   air-gapped screening bundle? (Sovereign FS buyers will likely forbid the remote call.)
5. Design-partner identification and the P1 "evidence layer" pilot scope.
6. Confirm the exact `hardened-ai → ikigov` item evidence map (the table in §5) with the
   IKI-Gov book author before hard-coding it — D-series and O5 are confident; T4/D2/I4 are
   "partial credit" and should be labelled as such in the export.

---

*Next: resolve the open questions, then break P1 into an ADR + reference architecture
under the family SDLC. The `hardened-ai → ikigov` evidence map (§5) is the highest-leverage
artifact to lock first — it defines the export schema and the v1 demo.*
