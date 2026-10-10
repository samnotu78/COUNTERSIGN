# COUNTERSIGN Security Invariants

## G1: VERIFIED(field) implies valid signature
```
VERIFIED(field)
implies:
  A valid signature exists over the exact field
  under a recognized, valid, fresh and unrevoked key.
```
**Formal**: For any field `f` where verdict is VERIFIED, there exists an Ed25519 signature `σ` such that:
- `σ` validates over canonical JSON representation of `f`
- The signing key `k` is in the current trust directory snapshot
- `k` is not revoked (revocation_status ≠ "revoked")
- `k` is within its validity period (token exp not past)
- The signature is over the exact field, not a superset/subset

**Violation consequence**: Verdict must be CONTRADICTS POLICY or UNVERIFIABLE, never VERIFIED.

## G2: VERIFIED depends only on deterministic verification inputs
```
VERIFIED outcome is function of:
  - canonical JSON payload (exact field values)
  - Ed25519 signature (exact byte match)
  - current trust directory snapshot (signed, current)
  - policy version (current, signed)
  - expiry check against current time
  - replay protection (jti uniqueness)
```
**NOT a function of**:
- AI output or interpretation
- Natural language content
- AI confidence scores
- AI-suggested organizations
- AI-identified actions

**Formal**: VERIFIED = F(canonical_json, signature, trust_dir_snapshot, policy_version, time, jti)

## G3: AI output cannot create VERIFIED
```
¬(AI_output ⊢ VERIFIED)
```
****: No AI-generated content, on its own, can cause a VERDICT of VERIFIED.

**Formal**: The verdict engine's output relation is:
- VERIFIED ← (cryptographic checks pass) ∧ (policy checks pass)
- VERIFIED ← NOT (AI_output → VERIFIED)

**Implementation**: Verdict engine never consults AI output when determining VERIFIED. AI output is only used for CONTRADICTS POLICY determination (what action is being requested), and even then the policy decision is deterministic and independent.

## G4: Cryptographic, parsing, freshness and trust-directory errors fail closed
```
All error categories → UNVERIFIABLE (never VERIFIED):
  - Invalid JSON parsing
  - Schema validation failure
  - Unsupported algorithm
  - alg:none rejection
  - Signature invalid
  - Key revoked
  - Key expired
  - Policy version stale
  - Replay detected (duplicate jti)
  - Untrusted key (not in directory)
  - Freshness violation (out-of-window timestamps)
```

**Formal**: ∀e ∈ ErrorCategories: verdict(e) = UNVERIFIABLE

**No error category** may produce VERIFIED.

## G5: Unknown identity cannot become VERIFIED
```
¬(identity_not_in_trust_directory ⊢ VERIFIED)
```
****: An identity absent from the current trust directory snapshot cannot produce a VERIFIED verdict, regardless of AI input.

**Formal**: If org_id ∉ dom(trust_directory_snapshot), then ∀tokens signed_by_org: verdict(token) ≠ VERIFIED

**Implementation**: Trust directory lookup is a hard requirement before any VERIFIED determination. AI may suggest organizations, but VERIFIED requires cryptographic proof against a key in the current directory.

## G6: Tampering with a signed field invalidates its verification
```
∀f ∈ signed_fields:
  modify(f, value') →
  verdict(field_f) = SIGNATURE_INVALID or UNVERIFIABLE
```
****: Changing any signed field value invalidates the signature over that field.

**Formal**: If original canonical JSON has signature σ over fields F, and field f ∈ F changes to value f', then:
- Re-validate σ over modified JSON → signature mismatch
- Verdict for field f becomes SIGNATURE_INVALID
- Overall verdict becomes UNVERIFIABLE (field-level tampering)

**Demonstration**: ₹4,200 → ₹42,000 → SIGNATURE INVALID, FIELD: AMOUNT

## G7: AI uncertainty or disagreement results in abstention/unverifiable
```
AI_uncertainty ∨ AI_disagreement → verdict = UNVERIFIABLE
```
****: If AI cannot ground claims in input, or if its claims conflict, the verdict must be UNVERIFIABLE, not VERIFIED.

**Formal**: 
- If AI output.grounding.start/end cannot be determined from input → AI_output.grounding = null
- If AI_output.organization ≠ any org in trust directory → UNVERIFIABLE
- If AI_output.requested_action cannot be mapped to policy → CONTRADICTS POLICY or UNVERIFIABLE
- AI must never output VERIFIED as a claim; AI output schema has no "verified" field

**Implementation**: AI output includes grounding info; verdict engine checks grounding before any VERIFIED determination. Missing/weak grounding → UNVERIFIABLE.

---
SECURITY INVARIANTS G1-G7 FORMALIZED