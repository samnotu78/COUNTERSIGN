# COUNTERSIGN Architectural Decisions

## 1. AI as Untrusted Sensor, Not Authority
**Decision**: AI sensor performs interpretation/extraction only; deterministic verifier produces VERIFIED verdicts.

**Why**: The core product identity is "AI SENSOR + CRYPTOGRAPHIC PROVENANCE + DETERMINISTIC POLICY VERIFICATION". If AI produced VERIFIED, the product would be a generic AI assistant. By making AI strictly an sensor, we guarantee that compromise of the AI cannot manufacture trust. The rule "AI MAY NEVER CREATE TRUST" is enforced by architecture, not policy.

**Rejected**: AI-generated verdicts, AI-trusted identities, AI-decided trust, LLM-made security decisions.

## 2. Ed25519 as Preferred Cryptographic Primitive
**Decision**: Use Ed25519 (NaCl/PyNaCl) as the sole signature algorithm for the prototype.

**Why**: Ed25519 offers: small key size (32 bytes), fast verification, deterministic signatures, no reliance on nonce generation (no rogue key attacks), and established security. It's a well-understood primitive we can thoroughly test. The specification explicitly says "Do NOT invent a new cryptographic algorithm" and "Preferred direction: Ed25519".

**Rejected**: RSA, DSA, ECDSA, elliptic curves with cofactors, custom algorithms, multiple-algorithm negotiation.

## 3. Canonical JSON with Exact Signed-Field Verification
**Decision**: Sign canonical JSON with exact field verification; reject "message contains valid signature" approach.

**Why**: The central demonstration is "₹4,200 → ₹42,000 → SIGNATRE INVALID FIELD: AMOUNT". If we sign the whole message, changing one field wouldn't invalidate the signature. By signing exact fields with canonical JSON, we guarantee that tampering with any signed field invalidates verification (Invariant G6). This is the key product differentiator.

**Rejected**: Signing entire natural-language message, signature-over-hash-only, approximate field matching.

## 4. Three-Verdict System (VERIFIED/CONTRADICTS POLICY/UNVERIFIABLE)
**Decision**: Exactly three verdicts, no arbitrary AI-generated security states.

**Why**: The specification defines exactly three verdicts. This constrains the system to deterministic behavior:
- VERIFIED: all crypto + policy checks pass
- CONTRADICTS POLICY: AI identified action, policy says no
- UNVERIFIABLE: insufficient evidence, AI failure, malformed input

Any more would allow arbitrary AI-generated security states. Any fewer would lose the policy contradiction capability.

**Rejected**: Five-vote systems, continuous trust scales, AI-confidence-based verdicts, probabilistic trust.

## 5. Fail-Closed Security Model
**Decision**: All errors, uncertainties, and failures → UNVERIFIABLE; nothing produces VERIFIED by default.

**Why**: Invariants G4 and G7 formalize this. If any error category could produce VERIFIED, an attacker could exploit it. Fail-closed is the only secure option for a security product. The AI may be wrong, the input may be ambiguous, the crypto may have edge cases — all must fail closed.

**Rejected**: Error categories that produce VERIFIED, probabilistic VERIFIED, default-trust-when-uncertain.

## 6. Field-Scoped VERIFIED, Not Message-Scoped
**Decision**: VERIFIED applies to exact signed fields, not the entire message or document.

**Why**: Invariant G6 and the core demo require this. Example: "The existence of a valid signed payment token does NOT make the OTP instruction trusted." A message may contain both verified and untrusted components. VERIFIED must be scoped to individually signed fields, allowing the UI to display "✓ SIGNED BY ISSUER" next to specific fields while marking surrounding text as AI interpretation.

**Rejected**: Message-scoped VERIFIED, all-or-nothing trust, trust-the-whole-document.

## 7. Strict Schema Enforcement with Pyd Pydantic
**Decision**: Use Pydantic (or equivalent) for all structural validation — AI output, token format, policy rules, API requests/responses.

**Why**: Deterministic, strict validation is the backbone of the crypto trust model. Pydantic provides: type enforcement, required field checking, extra-field rejection, duplicate field detection, JSON schema integration, and conversion errors to human-readable validation failures. This enables Invariant G2 (VERIFIED depends only on deterministic inputs) by making the parsing step pure and reproducible.

**Rejected**: Dynamic typing, loose schema validation, no validation at boundary, manual field checking.

## 8. Trust Directory as Signed Snapshot, Not Live DB
**Decision**: Trust directory is a signed snapshot (ID + hash + date), not a live database that can be modified without detection.

**Why**: Invariant G5 (unknown identity cannot become VERIFIED) and the threat model require that trust directory freshness and integrity be provable. A live DB could be silently modified. A signed snapshot that must be presented with each verification round ensures: (a) the directory is current, (b) it's signed by the master key, (c) any change requires signed update. This makes trust directory governance tractable for a prototype.

**Rejected**: Live trust directory database, mutable trust store, no versioning, unsigned directory.

## 9. Short-Lived Token Keys with Signed Rotation
**Decision**: Token signing keys are short-lived; key rotation is accomplished via signed trust directory updates.

**Why**: Key separation (different keys for different purposes) and replay protection (jti) require that keys have limited lifetimes. If keys are permanent, revocation becomes the only mechanism — but revocation lists grow indefinitely and become unmanageable. Short-lived keys with signed rotation means: (a) compromise window is limited, (b) key rotation is a natural operation, (c) each rotation is cryptographically verified, (d) the trust directory snapshot inherently carries the current key set.

**Rejected**: Permanent signing keys, key rotation via unsigned notifications, no key separation.

## 10. Grounding as Prerequisite for Any AI Output Consideration
**Decision**: Every AI claim must include source-span grounding (start/end positions in original input). Without grounding, claim is abtained/UNVERIFIABLE.

**Why**: Invariant G7 and threat T20. The AI sensor may extract claims, but if those claims cannot be grounded to exact positions in the original input, they cannot be used for VERIFIED determination. This prevents AI hallucination from creating trust — a hallucinated claim without grounding is simply discarded. Grounding also enables the UI to show "AI interprets ₹4,200 from position X-Y" while knowing it's untrusted.

**Rejected**: AI claims without grounding, AI confidence scores used for trust, AI output believed by default.

## 11. Visually Distinct Verified/Evidence vs AI Interpretation UI
**Decision**: UI must visually distinguish VERIFIED EVIDENCE (✓ SIGNED BY ISSUER) from AI INTERPRETATION (⚠ AI INTERPRETATION UNTRUSTED).

**Why**: The product direction explicitly requires this distinction. Visual design must reinforce the security model. If the UI looks the same for verified and untrusted, users will confuse them. The demo's strongest moment ("SIGNATURE INVALID FIELD: AMOUNT") only works if the UI clearly shows what was verified vs what was AI.

**Rejected**: Unified display, AI-trust-as-default styling, no visual distinction.

## 12. Fictional Organizations Only for Prototype
**Decision**: Use fictional organizations; no real banks, financial institutions, payment processors, or government entities.

**Why**: The specification explicitly requires this. Real-world identity governance is a production-level problem. Using real organizations would: (a) create legal/ compliance issues, (b) imply COUNTERSIGN solves identity governance (which it doesn't), (c) limit the demo to specific domains, (d) raise real privacy and security concerns. Fictional orgs with fictional names allow demonstration of the core architecture without these problems.

**Rejected**: Real organizations, real financial accounts, real payment processors, real government credentials.

## 13. $0 Constraint — No Paid Services
**Decision**: Core architecture must remain buildable at $0 out-of-pocket; no paid APIs, paid databases, payment processing, or proprietary security services.

**Why**: Hackathon constraint. The prototype must be functional without ongoing costs. All chosen technologies (Python, FastAPI, PyNaCl, Pydantic, SQLite, Pytest, React + Vite, shadcn/ui) are open source with no per-use costs. This constrains dependency choices but ensures the project is accessible and demonstratable without budget.

**Rejected**: Paid LLMs, paid databases, proprietary verification services, cloud infrastructure costs, per-token AI costs charged to user.

## 14. React + Vite + shadcn/ui for Frontend
**Decision**: Frontend stack: React, Vite, shadcn/ui component library.

**Why**: Lightweight, modern, no build overhead (Vite HMR), shadcn/ui provides accessible, customizable components without the bloat of full design-system frameworks. The UI must be premium/technical/calm/trustworthy without looking like a generic chatbot. React + Vite + shadcn/ui allows custom component design that breaks away from the "CRUD app + chat box" pattern.

**Rejected**: Next.js (overkill for this), Create React App (deprecated), full design systems (too generic), React Native (mobile only), frameworks that enforce chatbot UI patterns.

## 15. Adversarial Testing Embedded in Architecture
**Decision**: Adversarial testing is not an afterthought — it's embedded in the architecture from Day 1, with dedicated test strategies for each threat T1-T20.

**Why**: The product identity includes "ADVERSARIAL TESTING". If the system isn't tested against attacks, we cannot guarantee the invariants. Building the test infrastructure alongside the implementation ensures: (a) each threat has a known mitigation, (b) property-based tests verify invariants, (c) the demo can show adversarial resistance, (d) regression tests catch violations as the code evolves.

**Rejected**: Testing only "happy path", ad-hoc manual testing, security as QA-phase-only activity.

---
ARCHITECTURAL DECISIONS G1-G15 DOCUMENTED