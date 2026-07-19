# ZORTHEX™ ZTR — Zorthex Temporal Registry
### A demonstrability instrument for professional verification duties

Independent project — 2026 · Powered by Claude — Renato Santi
**Private repository — confidential. Not for public release.**

---

## What This Is

An on-premise system that produces **contemporaneous records**: dated, immutable, judgment-free evidence that a verification step occurred — **which checks were executed, when, and against which norm in force**.

It does not attest that anyone acted correctly. It proves that the verification process happened, at a certain time, under a certain rule — and what was or was not checked at that time. The assessment stays with the firm; only the fact of the process is recorded.

Built on the Zorthex™ L₂ research framework — an empirical methodology for measuring the interval between a norm entering into force and the first documented failure of its application.

## The Problem

Courts have started asking a new question. Not "did you lie?" but **"can you demonstrate that verification occurred — and when?"** Recent primary sources show the pattern:

- A US federal court converted the *absence* of a contemporaneous record into evidence of guilt (adverse inference for destroyed AI usage history; six-month suspension — for the missing record, not the error).
- A state court ordered a firm, *after* the incident, to audit its knowledge base and report on the process used — demonstrability demanded retroactively.
- Firms' own dated internal AI policies are quoted verbatim in federal sanction orders as the measure of what should have been known.

No existing tool produces that proof *in advance*. Cloud AI detectors cannot operate in privileged environments; surface-level detection fails against edited output; and no record exists that a human gate was actually passed.

## Architecture — three layers, one honest posture

**1. Scanner (v0.4) — local assessment.**
Two independent axes: *temporal* (document date vs. the most specific applicable policy anchor — national norm, forum precedent, or the client's own dated internal policy) and *structural* (deep patterns of unsupervised AI generation, calibrated on real sanctioned filings). Output stays with the firm. Never notarised.

**2. Temporal Registry (capsule v1.2) — the contemporaneous record.**
The document is hashed (SHA-256) and discarded — it never leaves the client's infrastructure and is never stored. The capsule contains facts only: document hash, policy identity/hash/date, temporal window, and a **verification manifest** declaring which checks were executed — including what is deliberately out of scope. No verdicts: the capsule of a clean document and a problematic one are byte-for-byte indistinguishable (enforced in code; a judgment term entering the capsule halts the system). HMAC-sealed.

**3. Qualified timestamp (RFC 3161 / eIDAS).**
Each capsule is stamped by a Qualified Trust Service Provider (eIDAS): the time is legally presumed accurate and opposable to third parties across the EU (recognised under UK eIDAS as well), with 30-year archival by the TSA. Honest states are enforced: without a qualified stamp, the capsule itself declares it is not admissible as dated proof. The system never pretends.

- On-premise MCP Server (FastMCP / Python) · plug-and-play with Claude Desktop / Enterprise
- Zero data leak: only a 64-character hash ever leaves the document's machine — and only towards the TSA
- Policy contexts: foundational (2023–24), ABA 512 (2024+), forum anchors (e.g. N.D. Ala. published precedent), client internal policies, PQC/NIST

## Declared Perimeter (verified, not hidden)

The scanner detects **Mode 1**: unreviewed AI output pasted into filings (structural anomalies). It does **not** detect **Mode 2**: fabricated citations woven into human-written prose — verified empirically on two real sanctioned filings (Mata v. Avianca Doc #21; Miller/Harp Doc #23: both structurally clean by construction). No on-premise tool can verify citation existence without leaving the infrastructure. Mode 2 coverage is what the **Registry** provides: dated proof that the required human verification gate was passed. The perimeter is declared inside the record itself.

## Calibration & Case Foundation

- Test set: 10 verified cases from primary sources (5 sanctioned / 5 clean). **Accuracy 90%, zero false positives.** Declared threshold stays 90% regardless of future runs (under-promise policy). Composition review in progress; a real sanctioned party filing (Miller Doc #23) added.
- Sources: PACER (USA), BAILII (UK), OSCN, courts.ca.gov, Charlotin AI Hallucinations Database (~1,600 cases, June 2026).
- **L₂ metric: L₂f = t_incident − t_policy (months).** Verified at full depth (both endpoints, primary sources, Level A):
  - Cork v. Smith (UK): Ayinde → incident, **9.8 months**
  - Johnson v. Dunn / OBA v. Reeves chain (USA): internal dated policies + ABA 512 → **4.2 / 10.2 / 23 months**
  - Miller v. Regions Bank (USA): published forum precedent → **4.3 months** (17 from ABA 512)
- Observed pattern (declared as observation, n small, survivorship bias stated; never predictive on the single case): the closer the anchor, the shorter the window — and transmission fails anyway. Sanctions published in one case become the policy anchor of the next: the propagation chain is documented inside the orders themselves, identically in the UK and the US.

## Status

- Scanner v0.4 · Capsule v1.2 (verification manifest + qualified timestamp) — functional, calibrated, English output
- Full test suite green (registry, manifest, date handling, tamper detection, honest-fallback paths)
- First qualified (eIDAS) capsule produced: July 2026
- External installation verified on independent hardware
- Public release: **not planned** — this layer is under confidential legal review

---

## Remote MCP Connector

### What This Adds

A remote deployment mode for the Temporal Registry, designed for the **Anthropic Connectors Directory** (Claude Cowork / Claude Web).

The on-premise mode (existing) runs everything locally:

```
Claude Desktop → local MCP → scanner + registry on client machine
```

The remote mode exposes **only the Temporal Registry** via HTTPS:

```
Claude Cowork → HTTPS → temporalregistry.com → registry only
```

The scanner remains on-premise. Only the verification receipt layer is exposed remotely. The document is hashed server-side and immediately discarded — never stored, never logged.

### File

`ztr_remote_connector.py` — standalone FastAPI server, derived from capsule v1.2 logic. Same SHA-256, same Aruba PEC TSA, same eIDAS qualification. Adds: HTTP transport, receipt storage (SQLite), OAuth readiness, Anthropic directory compliance.

### Tools Exposed

| Tool | Action | Read/Write |
|------|--------|------------|
| `verify_document` | Hash + timestamp + receipt | Write |
| `check_receipt` | Retrieve a receipt by ID | Read |
| `list_receipts` | List user's receipts | Read |

### Deployment

```bash
# Install dependencies
pip install fastapi uvicorn requests

# Run locally for testing
python ztr_remote_connector.py

# Deploy to temporalregistry.com via Railway/Render
# See ZTR_MCP_ROADMAP.md for full deployment guide
```

### Relationship to On-Premise Mode

| Feature | On-Premise | Remote |
|---------|-----------|--------|
| Scanner | ✅ Local | ❌ Not exposed |
| Registry / Capsule | ✅ Local | ✅ Via HTTPS |
| Document storage | ❌ Never | ❌ Never |
| TSA (eIDAS) | ✅ Aruba PEC | ✅ Aruba PEC |
| Verdict / judgment | ✅ Local only | ❌ Not available |
| User auth | N/A (local) | OAuth 2.0 |
| Anthropic Directory | ❌ | ✅ Submitted |

### Requirements (remote mode only)

```
fastapi>=0.115.0
uvicorn>=0.30.0
requests>=2.32.0
```

Core dependencies (hashlib, sqlite3, json, subprocess) are Python stdlib.

---

## Parent Project

Derivative application of the Zorthex™ research framework (public track):
live app & reports: https://zorthex.com · dataset: https://doi.org/10.5281/zenodo.20589503
Main repository: https://github.com/zorthex2026/zorthex-diffusion-lag

## License

Proprietary — All rights reserved. Not licensed for use, reproduction, or distribution without explicit written permission.
© 2026 Renato Santi — ZORTHEX™ (Trademark UIBM N.302026000090628)
