# ZORTHEX™ Enterprise Legal Scanner
*Independent project — June 2026*
*Powered by Claude — Renato Santi*

---

## What This Is

An on-premise MCP Server designed to identify documents produced during the structural risk window between formal AI policy adoption and operational behavioral change in legal practice.

Built on the Zorthex™ ZTR (Zorthex Temporal Registry) framework — an empirical methodology for measuring institutional adaptation latency.

---

## The Problem

Existing AI content detectors look for surface signals. They fail because:

1. Professionals learn to clean AI output at the surface level while structural anomalies remain
2. No existing tool correlates document production timing with documented policy propagation failures
3. Enterprise-grade legal environments cannot upload documents to external cloud services (confidentiality, NDA, professional privilege)

---

## The Approach

This scanner operates on two independent axes:

**Temporal:** Documents are evaluated against documented policy milestones (e.g. ABA Formal Opinion 512, July 2024) to determine whether they were produced inside the structural blind window — the interval between policy issuance and operational behavioral change.

**Structural:** Documents are analyzed for deep structural patterns associated with unsupervised AI generation — not keyword matching, but citation density anomalies, formulaic boilerplate distribution, and citation-to-analysis ratios calibrated against real sanctioned cases.

---

## Architecture

- On-premise MCP Server (FastMCP / Python)
- Zero data leak — documents never leave client infrastructure
- Plug-and-play with Claude Desktop and Claude Enterprise
- Three policy contexts: AI_LEGAL_EARLY (2023-2024), AI_LEGAL (ABA 512, 2024+), PQC_CRYPTO (NIST FIPS, 2024+)

---

## Calibration

Calibrated against real judicial decisions from PACER (USA), BAILII (UK), and the Charlotin AI Hallucinations Database (n=1,522 cases as of May 2026).

Test set: 10 verified cases (5 sanctioned, 5 clean). Accuracy: 90%. Zero false positives on clean documents.

The single remaining error is a human-authored declaration of admission — the system correctly identified it as human-written text, confirming methodological precision.

---

## Theoretical Foundation

Built on the ZTR L₂ metric:

**L₂f = t_incident − t_policy (months)**

Empirically observed: systemic boundary at 22 months across the May 2026 USA cluster (ABA Opinion 512 as t_policy anchor, n=6 verified cases).

Cross-jurisdictional reference: Cork v. Smith (UK, Chancery Division, May 2026) — L₂f = 19 months.

Full methodology: [zorthex.com/methodology](https://zorthex.com/methodology)
Dataset DOI: [10.5281/zenodo.20374051](https://doi.org/10.5281/zenodo.20374051)

---

## Status

- [x] Prototype v0.3 — functional and calibrated
- [x] Test set verified on real court documents
- [ ] Public release — pending Zorthex v2.0 deployment (August 2026)
- [ ] Enterprise DOI — pending

---

## Parent Project

This is a derivative application of the Zorthex™ research framework.

Main repository: [github.com/zorthex2026/zorthex-diffusion-lag](https://github.com/zorthex2026/zorthex-diffusion-lag)

---

## License

Proprietary — All rights reserved. Not licensed for use, reproduction, or distribution without explicit written permission.

© 2026 Renato Santi — ZORTHEX™ (Trademark UIBM N.302026000090628)

---

*Zorthex is descriptive only and does not constitute legal advice.*
