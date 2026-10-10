// Minimal native-fetch API client for COUNTERSIGN backend
// Uses Vite dev proxy: /verify -> http://127.0.0.1:8000/verify, /health -> http://127.0.0.1:8000/health

import type {
  VerifyRequest,
  VerifyResponse,
  HealthResponse,
  FixtureId,
} from '../types/api';
import { APIError } from '../types/api';

function getErrorMessage(status: number, detail?: string): string {
  switch (status) {
    case 422:
      return 'Invalid request - check fixture_id or signed_token_b64 format';
    case 500:
      return 'Server error - backend unavailable';
    case 0:
    case 503:
      return 'Cannot reach backend - is the API server running on port 8000?';
    default:
      return detail || `Request failed with status ${status}`;
  }
}

async function handleResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    let detail: string | undefined;
    try {
      const errorBody = await response.json();
      detail = errorBody.detail;
    } catch {
      // Ignore parse errors
    }
    throw new APIError(response.status, getErrorMessage(response.status, detail), detail);
  }
  return response.json();
}

export async function checkHealth(): Promise<HealthResponse> {
  const response = await fetch('/health', {
    method: 'GET',
    headers: { 'Content-Type': 'application/json' },
  });
  return handleResponse<HealthResponse>(response);
}

export async function verifyRequest(request: VerifyRequest): Promise<VerifyResponse> {
  const response = await fetch('/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
  });
  return handleResponse<VerifyResponse>(response);
}

// Convenience helpers for fixture-based verification
export async function verifyFixture(fixtureId: FixtureId): Promise<VerifyResponse> {
  return verifyRequest({ fixture_id: fixtureId });
}

export async function verifyToken(signedTokenB64: string): Promise<VerifyResponse> {
  return verifyRequest({ signed_token_b64: signedTokenB64 });
}

// ============================================
// VALIDATION HELPERS (mirror backend strictness)
// ============================================

export function validateVerifyRequest(request: unknown): request is VerifyRequest {
  if (!request || typeof request !== 'object') return false;
  const req = request as Record<string, unknown>;
  const hasFixture = typeof req.fixture_id === 'string';
  const hasToken = typeof req.signed_token_b64 === 'string';
  // Exactly one required (mirror backend model_validator)
  return hasFixture !== hasToken;
}

export function isValidFixtureId(value: unknown): value is FixtureId {
  return typeof value === 'string' &&
    ['valid', 'tampered', 'compromised_ai', 'contradictory_claim', 'ungrounded_ai'].includes(value);
}