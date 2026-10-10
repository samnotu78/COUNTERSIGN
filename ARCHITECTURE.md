# COUNTERSIGN Architecture

## 1. Product Overview

COUNTERSIGN is an adversarially tested verification layer that separates what AI interprets from what cryptography can actually prove. The system helps users recognize, verify, and respond to scams, impersonation, and fraud involving modern digital communication.

**Core philosophy**: AI may interpret and extract claims, but ONLY deterministic cryptographic verification may produce "VERIFIED" results. If the AI is completely compromised, it must still be impossible for the AI to manufacture a VERIFIED result.

**Tagline**: "Don't trust the AI. Verify the evidence."

## 2. Core Principle

**AI SENSOR + CRYPTOGRAPHIC PROVENANCE + DETERMINISTIC POLICY VERIFICATION + FAIL-CLOSED SECURITY + ADVERSARIAL TESTING**

- AI may interpret, extract claims, increase suspicion
- AI MAY NEVER create trust or produce VERIFIED results
- Only deterministic cryptographic verification may produce VERIFIED
- If AI is completely compromised, it must still be impossible to manufacture VERIFIED
- VERIFIED must be field-scoped, not message-scoped

## 3. System Architecture

```
UNTRUSTED INPUT → AI SENSOR → STRUCTURED CLAIM → DETERMINISTIC VERIFIER → FIELD-SCOPED VERDICT
```

Verdicts: VERIFIED, CONTRADICTS POLICY, UNVERIFIABLE

**Key separation**: AI interpretation (sensor) vs cryptographic trust (verifier). Hard security boundary between them.

## 4. Component Architecture

| Component | Responsibility | Trust Boundary |
|-----------|---------------|----------------|
| AI Sensor | Organization mention extraction, requested action extraction, payment claim extraction, suspicious instruction extraction, code-mixing handling, transliteration handling, paraphrase handling, obfuscation handling, split-message handling, decoy mention identification, source-span grounding, structured claim generation, adversarial mutation generation | Output is UNTRUSTED - never VERIFIED |
| Structured Claim | Schema-defined claim container with source-span grounding | Input-marked, output-grounded |
| Deterministic Verifier | Signature validation, algorithm allowlist, field verification, key freshness, revocation check, expiry check, policy evaluation | Cryptographic only - never depends on AI output |
| Policy Engine | Versioned policy storage, policy evaluation, contradiction detection | Deterministic, closed system |
| Verdict Engine | Verdict determination (VERIFIED/CONTRADICTS POLICY/UNVERIFIABLE), fail-closed behavior | Output-bounded |

## 5. Trust Boundaries

**Hard boundary between AI INTERPRETATION and CRYPTOGRAPHIC TRUST:**

AI must NEVER:
- decide that something is VERIFIED
- generate a trusted identity
- generate trusted cryptographic evidence
- modify cryptographic evidence
- choose which key is trusted
- decide whether a signature is valid
- decide whether a token is expired
- decide whether a key is revoked
- relax a security policy
- create a trusted organization
- modify the trust directory

**Cryptographic verifier must NOT depend on LLM output.** It must operate from deterministic inputs only.

## 6. Data Flow

```
1. User provides untrusted input (text, document, QR code, etc.)
2. AI SENSOR processes input → extracts structured claims with source-span grounding
   AI claims are forwarded to the INTERPRETATION / POLICY CONTRADICTION layer only.
   They are NOT consulted by the cryptographic verifier.
3. SIGNED PAYLOAD is extracted from the original input and passed independently
   to the DETERMINISTIC VERIFIER. The verifier does not consult AI claims at any
   step.
4. DETERMINISTIC VERIFIER independently:
   a. Parses the signed payload as canonical JSON
   b. Resolves the trusted key from the trust directory (signed snapshot)
   c. Verifies the Ed25519 signature over exact signed fields
   d. Validates freshness (expiry), revocation, policy version, replay protection
   e. Determines verified fields from the cryptographic evidence alone
5. VERDICT ENGINE determines: VERIFIED / CONTRADICTS_POLICY / UNVERIFIABLE
   - VERIFIED: based solely on steps 4a-4e, independent of AI output
   - CONTRADICTS_POLICY: AI-identified action conflicts with deterministic policy
   - UNVERIFIABLE: insufficient crypto evidence, missing grounding, or AI failure
6. UI displays: verified evidence from cryptographic payload + AI interpretation
   as separate, visually distinct layers.
```

**Critical**: The cryptographic verifier in step 4 operates independently of AI output.
AI claims may trigger policy evaluation but may never create or modify cryptographic evidence.

## 7. Cryptographic Trust Model

**Preferred algorithm**: Ed25519

**Canonical JSON representation** of signed claims with strict schemas.

**Verification pipeline**:
1. Parse JSON (reject alg:none, reject unsupported algorithms)
2. Check for duplicate JSON fields
3. Validate schema compliance (Pydantic or equivalent)
4. Verify Ed25519 signature over exact signed fields
5. Check key freshness (short-lived token keys)
6. Check key revocation against trust directory snapshot
7. Check expiry timestamp
8. Check policy version compliance
9. Check replay protection (nonce/timestamp freshness)

**Key principles**:
- Exact signed-field verification (not "message contains valid signature")
- Key separation (different keys for different purposes)
- Short-lived token keys
- Signed trust-directory snapshot
- Policy version tracking
- Replay protection

## 8. Token Model

**Token structure**:
- `iss` (issuer identifier, signed)
- `exp` (expiry, signed)
- `nbf` (not before, signed)
- `iat` (issued at, signed)
- `jti` (JWT ID, included in payload for identifier purposes)
- `ver` (policy version, signed)
- `fields` (map of field_name → signed_value)

**Replay protection**: The `jti` field alone is NOT sufficient for replay prevention.
For the prototype, replay prevention requires server-side state tracking of previously
accepted token identifiers, bound to issuer/context where appropriate, with expiry cleanup.
Each verified token's `jti` is recorded with a timestamp; subsequent presentations
with the same `jti` within the validity window are rejected as replays.

**Token validation**:
- Verify Ed25519 signature over exact canonical JSON
- Reject if any required field missing
- Reject if `exp` is in the past
- Reject if `ver` (policy version) is stale
- Server-side check: if `jti` has been previously accepted for this `iss`/`context` → REPLAY
- Field-level verification: each signed field validated independently

**Key separation**:
- Organization master key signs trust directory snapshots
- Per-token keys sign individual tokens
- Key rotation with signed directory updates

## 9. Trust Directory

**Controlled prototype trust root** for hackathon prototype.

**Structure**:
- `organization_id` → `public_key` (Ed25519)
- `policy_version` → `effective_date` + `policy_text`
- `key_id` → `revocation_status` + `revocation_date`
- `snapshot_id` → `snapshot_hash` + `snapshot_date`

**Explicit acknowledgment**: Real-world directory governance and identity establishment are production-level problems. COUNTERSIGN does not claim to solve them.

**For prototype**: Fictional organizations only. No real banks, financial institutions, payment processors, government organizations, company credentials, or financial accounts.

## 10. Policy Engine

**Deterministic policy evaluation**:

```
AI SENSOR extracts:  organization=ExampleBank, requested_action=OTP_DISCLOSURE
Policy check:          NEVER_REQUEST_OTP_DISCLOSURE
Result:                CONTRADICTS POLICY
```

**Policy versioning**:
- Policies have explicit version numbers
- Policies may become stricter over time
- AI must never weaken or silently modify policy
- Policy changes require signed trust directory update

**Baseline dangerous actions**:
- OTP disclosure
- PIN disclosure
- CVV disclosure
- Password disclosure
- Remote-access software installation
- Gift-card payment

**Policy engine is closed and deterministic**: No AI involvement in policy evaluation.

## 11. AI Sensor

**AI is a SENSOR**: Its job is interpretation, not authority.

**Possible responsibilities**:
- Organization mention extraction
- Requested action extraction
- Payment claim extraction (UNTRUSTED interpretation)
- Suspicious instruction extraction
- Code-mixing handling
- Transliteration handling
- Paraphrase handling
- Obfuscation handling
- Split-message handling
- Decoy mention identification
- Source-span grounding
- Structured claim generation
- Adversarial mutation generation

**Important**: AI-extracted payment_claim values are UNTRUSTED interpretations.

They must NEVER be used as the source of a VERIFIED amount/payee/currency.

Verified fields (amount, payee, currency) MUST originate from the independently verified
signed payload (Ed25519 signature over canonical JSON). The AI sensor may suggest
payment details for the user's awareness, but the VERDICT of VERIFIED and the display
of verified amount/payee/currency must come from the cryptographic verification in step 4
of the data flow, not from AI extraction.

**Output schema** (structured, every claim contains grounding information pointing back to original input):

```json
{
  "organization": "string | null",
  "requested_action": "string | null",
  "payment_claim": { "amount": "string", "payee": "string", "currency": "string" } | null,
  "suspicious_instruction": "string | null",
  "grounding": { "start": int, "end": int, "type": "extraction" },
  "confidence": "float"  // AI-internal, not used for trust
}
```

**If grounding cannot be established**: ABSTAIN / UNVERIFIABLE.

**AI must never invent evidence.**

## 12. Verdict Engine

**Exactly three top-level verdicts** (no others):

1. **VERIFIED** - All deterministic checks pass: valid Ed25519 signature over exact signed fields,
   fresh key from current trust directory snapshot, unrevoked, within expiry, policy-compliant,
   field-scoped. Based solely on cryptographic evidence.

2. **CONTRADICTS_POLICY** - AI identified action, deterministic policy engine says it violates
   issuer policy. The AI identifies the action; the policy engine decides the contradiction.

3. **UNVERIFIABLE** - Insufficient evidence for VERIFIED or CONTRADICTS_POLICY. This category
   absorbs all cryptographic failures, missing grounding, malformed input, unsupported algorithms,
   and AI failure modes.

**Cryptographic failures are represented as**: verdict = UNVERIFIABLE
with structured reason/field metadata:

```
verdict: UNVERIFIABLE
reason: SIGNATURE_INVALID
field: AMOUNT
```

The UI may present the reason prominently (e.g., "SIGNATURE INVALID FIELD: AMOUNT"), but
the top-level verdict remains UNVERIFIABLE. SIGNATURE_INVALID is NOT a fourth top-level
verdict; it is metadata within UNVERIFIABLE.

**Fail-closed**: AI uncertainty or disagreement results in UNVERIFIABLE, never trust.

## 13. API Architecture

**REST API** (FastAPI/Python):

```
POST /verify          → verify untrusted input against cryptographic policies
GET /health           → health check
GET /policies         → list available policies (admin)
POST /policies        → add new policy (signed directory update)
GET /trust-directory  → get current trust directory snapshot
POST /tokens          → validate token
```

**Request format**:
```json
{
  "input": "user text or document",
  "token": "optional JWT for authenticated org context"
}
```

**Response format**:
```json
{
  "verdict": "VERIFIED | CONTRADICTS POLICY | UNVERIFIABLE",
  "evidence": {
    "verified_fields": ["AMOUNT", "PAYEE", "REFERENCE", "EXPIRY"],
    "signed_values": { "AMOUNT": "₹4,200", "PAYEE": "merchant@example.test" },
    "ai_interpretation": { ... },  // unmarked, not trusted
    "verdict_reason": "string"
  },
  "request_id": "uuid"
}
```

## 14. Data Model

**Core types**:

```pydantic
class VerificationVerdict(BaseModel):
    verdict: Verdict  # VERIFIED / CONTRADICTS_POLICY / UNVERIFIABLE
    verified_fields: List[str]
    signed_values: Dict[str, str]
    ai_interpretation: AIOutput  # structured, untrusted
    verdict_reason: str

class AIOutput(BaseModel):
    organization: Optional[str]
    requested_action: Optional[str]
    payment_claim: Optional[PaymentClaim]
    suspicious_instruction: Optional[str]
    grounding: Grounding  # start/end positions in input

class PaymentClaim(BaseModel):
    amount: PositiveDecimal
    payee: EmailOrNull
    currency: CurrencyCode

class PolicyViolation(BaseModel):
    action: str
    policy_rule: str
    severity: "dangerous" | "moderate" | "low"
```

## 15. Threat Model Summary

See THREAT_MODEL.md for detailed threats.

**20 defined threats** (T1-T20) covering: compromised AI, prompt injection, signed-field tampering, signature substitution, key substitution, expired tokens, revoked keys, replay, algorithm downgrade, alg:none, duplicate JSON fields, parser confusion, Unicode homoglyphs, lookalike organizations, decoy organizations, policy downgrade, stale directory, malformed requests, AI hallucination, missing grounding.

## 16. Security Invariants

See SECURITY_INVARIANTS.md for formal properties.

**G1-G7** defined in the architecture specification.

## 17. Testing Architecture

**Test types**:
- Unit tests (Pytest)
- Integration tests
- Property-based tests (Hypothesis)
- Adversarial tests
- Cryptographic tests
- Parser tests
- Policy tests
- AI sensor tests
- Mutation tests
- Regression tests

**Key test infrastructure**:
- Pytest test suite
- Hypothesis for property-based testing
- Mock AI sensor (deterministic stand-in)
- Cryptographic test vectors (valid/tampered/expired/revoked)
- Adversarial mutation generator

## 18. Adversarial Testing

**AI sensor testing with**:
- Paraphrases of the same claim
- Transliteration between scripts
- Code-mixed languages (e.g., Hinglish)
- Homoglyph Unicode tricks
- Zero-width characters
- Spacing manipulation
- Split messages across SMS/WhatsApp
- Omissions of critical fields
- Prompt injection attempts
- Decoy organization names

**Deterministic verifier testing with**:
- Field tampering (changing signed values)
- Key substitution (using wrong key)
- Signature substitution (forging signature)
- Replay (resending old token)
- Expired tokens
- Revoked keys
- Algorithm downgrade (forcing weak alg)
- alg:none attacks
- Duplicate JSON fields
- Malformed payloads
- Unknown field handling

## 19. Benchmark Strategy

**Project should eventually compare**:

RULES-ONLY BASELINE vs AI SENSOR + DETERMINISTIC VERIFIER

**Potential metrics**:
- false VERIFIED rate
- dangerous miss rate
- claim precision
- claim recall
- false CONTRADICTS rate
- abstention rate
- latency
- model cost

**Important properties** (must hold):
- Changing a signed field must never remain VERIFIED
- Changing the signer must never remain VERIFIED
- Expired tokens must never become VERIFIED
- Unsupported algorithms must never become VERIFIED
- alg:none must never become VERIFIED
- Manipulating AI output must never create VERIFIED
- Malformed input must fail closed
- Unknown lookalike identities must never become VERIFIED

If rules baseline performs similarly, report honestly.

## 20. UI Architecture

**Visual design principles**:
- Premium, precise, technical, calm, trustworthy
- Must NOT look like generic AI SaaS, chatbot, admin dashboard, ChatGPT clone, ordinary CRUD app

**Visual distinctions**:
- VERIFIED EVIDENCE: shown with ✓ SIGNED BY ISSUER marker, derived from cryptographic payload
- AI INTERPRETATION: shown with ⚠ AI INTERPRETATION / UNTRUSTED, never with ✓ marker

**Example display**:
```
AMOUNT ₹4,200 ✓ SIGNED BY ISSUER
```
vs.

```
"Your account will be suspended..."
⚠ AI INTERPRETATION UNTRUSTED
```

**UI must reinforce security model**: Visual design must not obscure security information. No visual effects that confuse the verified/unverified distinction.

## 21. Demo Architecture

**Demo sequence** (8 scenes):

1. **Valid signed request** - Proper Ed25519-signed payload → VERIFIED
2. **Tampered signed request** - Amount changed → SIGNATURE INVALID / FIELD: AMOUNT
3. **AI extracts suspicious instruction** - AI identifies OTP_DISCLOSURE → CONTRADICTS POLICY
4. **Deterministic policy contradiction** - Policy engine blocks action
5. **Compromised AI demonstration** - AI lies/hallucinates → still UNVERIFIABLE
6. **AI failure → UNVERIFIABLE** - No valid evidence → abstention
7. **Policy version change** - Policy updated, old tokens rejected
8. **Adversarial mutation benchmark** - Full attack surface demonstration

**Strongest crypto demonstration**:
```
LEGITIMATE REQUEST ₹4,200 ✓ SIGNED BY ISSUER

Attacker changes: ₹4,200 → ₹42,000

Result: SIGNATURE INVALID FIELD: AMOUNT
```

This demonstrates: AI does not decide trust. Cryptographic evidence does.

## 22. Seven-Day Implementation Plan

**Day 1**: Repository setup, cryptography primitives, Ed25519 implementation, Pydantic schemas, basic token model

**Day 2**: AI sensor module (structured output schema, grounding), mock deterministic verifier, basic policy engine

**Day 3**: Verdict engine, verification pipeline, API scaffold (FastAPI), unit test framework

**Day 4**: Trust directory, token validation, policy versioning, cryptographic edge cases

**Day 5**: Adversarial mutation generator, parser security tests, input validation

**Day 6**: UI scaffolding (React + Vite + shadcn/ui), verified/unverified visual distinction, basic demo flows

**Day 7**: full regression testing, adversarial red-team testing, security invariant verification,
performance sanity checks, demo rehearsal, README/submission preparation, final freeze

## 23. Definition of Done

- [x] ARCHITECTURE.md created with all 26 sections
- [x] THREAT_MODEL.md created with all T1-T20 threats
- [x] SECURITY_INVARIANTS.md created with all G1-G7 invariants
- [x] DECISIONS.md created with architectural decisions
- [ ] Ed25519 cryptographic verification implemented (PyNaCl or equivalent)
- [ ] AI sensor structured output schema
- [ ] Deterministic verifier with schema validation and signature checks
- [ ] Policy engine with versioned policies
- [ ] Verdict engine with 3 verdicts
- [ ] API endpoint /verify
- [ ] Unit tests passing
- [ ] Adversarial test suite running
- [ ] UI demonstrates verified/unverified distinction
- [ ] Demo script walkthrough working
- [ ] All invariants verified

## 24. Non-Goals

- Do NOT add: blockchain, voice authentication, mobile app, browser extension, real banking integration, real payment processing, real financial credentials, real bank verification, custom model training, unnecessary microservices, unnecessary cloud infrastructure, generic AI chat, generic RAG, generic dashboard features
- Do NOT expand beyond core product
- Do NOT claim features implemented before they are
- Do NOT install unnecessary packages

## 25. Known Limitations

- Prototype trust directory is fictional/controlled, not a real PKI
- AI sensor is a simulated interpretation layer, not a production LLM integration
- Policy engine has limited rule set for hackathon prototype
- No real organizational identity verification (fictional orgs only)
- No real replay/downgrade resistance without deployed trust infrastructure
- UI is minimal scaffolding, not a production design

## 26. Production Risks

- AI sensor integration with production LLM may have unpredictable output
- Real-world trust directory governance is complex and organization-specific
- Policy version management at scale requires organizational coordination
- Cryptographic key management in production requires HSMs and rotation procedures
- Adversarial attacks may evolve beyond prototype test suite
- UI/UX must consistently reinforce the verified/unverified distinction under user stress
- Performance at scale (signature validation, policy evaluation) not proven
- Compliance with real jurisdictional requirements not addressed in prototype

---
ARCHITECTURE READY FOR REVIEW