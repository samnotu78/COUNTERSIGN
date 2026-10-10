// Exact TypeScript mirror of COUNTERSIGN backend API contract
// Source: countersign_api/app.py, countersign_crypto/errors.py

// ============================================
// VERDICT & ERROR CODES (closed enums)
// ============================================

export type Verdict = 'VERIFIED' | 'CONTRADICTS_POLICY' | 'UNVERIFIABLE';

export type ErrorCode =
  // Cryptographic failures
  | 'SIGNATURE_INVALID'
  | 'KEY_UNKNOWN'
  | 'KEY_REVOKED'
  | 'KEY_NOT_YET_VALID'
  | 'KEY_EXPIRED'
  // Token failures
  | 'TOKEN_EXPIRED'
  | 'TOKEN_NOT_YET_VALID'
  | 'TOKEN_TIMESTAMP_INVALID'
  // Directory/Trust failures
  | 'DIRECTORY_INVALID'
  | 'DIRECTORY_SIGNATURE_INVALID'
  | 'DIRECTORY_EXPIRED'
  // Algorithm failures
  | 'ALG_UNSUPPORTED'
  | 'ALG_NONE'
  // Structural failures
  | 'MALFORMED_TOKEN'
  | 'DUPLICATE_FIELD'
  | 'UNKNOWN_FIELD'
  | 'INVALID_FIELD_TYPE'
  | 'INVALID_CANONICAL_ENCODING'
  // Policy failures
  | 'POLICY_VERSION_TOO_OLD'
  | 'POLICY_CONTRADICTION'
  | 'POLICY_NOT_FOUND'
  | 'POLICY_AMBIGUOUS'
  | 'UNSUPPORTED_ACTION'
  | 'MALFORMED_POLICY'
  | 'POLICY_TAMPERED'
  // Replay failures
  | 'REPLAY_DETECTED'
  // Directory trust failures
  | 'DIRECTORY_NOT_TRUSTED'
  | 'DIRECTORY_NOT_YET_ACTIVE'
  | 'DIRECTORY_VERSION_DOWNGRADE'
  | null;

// ============================================
// REQUEST
// ============================================

export type FixtureId =
  | 'valid'
  | 'tampered'
  | 'compromised_ai'
  | 'contradictory_claim'
  | 'ungrounded_ai';

export interface VerifyRequest {
  fixture_id?: FixtureId;
  signed_token_b64?: string;
}

// ============================================
// RESPONSE - CRYPTOGRAPHIC EVIDENCE
// ============================================

export interface CryptographicEvidenceMetadata {
  key_id?: string;
  issuer?: string;
  jti?: string;
  policy_version?: number;
  algorithm?: string;
  directory_version?: string;
  verification_time?: string;
}

export interface CryptographicEvidence {
  verified_fields: string[];
  signed_values: Record<string, string>;
  metadata: CryptographicEvidenceMetadata;
}

// ============================================
// RESPONSE - AI INTERPRETATION
// ============================================

export interface Grounding {
  start: number;
  end: number;
  type: 'extraction';
}

export interface AIClaims {
  organization: string | null;
  requested_action: string | null;
  payment_claim: string | null;
  suspicious_instruction: string | null;
  confidence: number;
  grounding: Grounding | null;
}

export interface AIInterpretation {
  trusted: false; // Always false per architecture
  status: 'grounded' | 'ungrounded_or_invalid' | 'not_used';
  claims: AIClaims;
}

// ============================================
// RESPONSE - POLICY
// ============================================

export interface PolicyResult {
  evaluated: boolean;
  result: Verdict | null; // VerificationResult name or null
  error_code: ErrorCode;
}

// ============================================
// RESPONSE - MAIN
// ============================================

export interface VerifyResponse {
  request_id: string;
  verdict: Verdict;
  error_code: ErrorCode;
  explanation: string;
  cryptographic_evidence: CryptographicEvidence;
  ai_interpretation: AIInterpretation;
  policy: PolicyResult;
}

// ============================================
// HEALTH
// ============================================

export interface HealthResponse {
  status: 'ok';
  service: 'countersign';
}

// ============================================
// API ERROR
// ============================================

export class APIError extends Error {
  constructor(
    public readonly status: number,
    message: string,
    public readonly detail?: string
  ) {
    super(message);
    this.name = 'APIError';
  }
}

// ============================================
// TYPE GUARDS
// ============================================

export function isVerified(verdict: Verdict): boolean {
  return verdict === 'VERIFIED';
}

export function isContradictsPolicy(verdict: Verdict): boolean {
  return verdict === 'CONTRADICTS_POLICY';
}

export function isUnverifiable(verdict: Verdict): boolean {
  return verdict === 'UNVERIFIABLE';
}

export function hasErrorCode(response: VerifyResponse): response is VerifyResponse & { error_code: Exclude<ErrorCode, null> } {
  return response.error_code !== null;
}