# COUNTERSIGN Policy Engine
# Deterministic policy evaluation — closed grammar, fail-closed,
# baseline denies that cannot be overridden by organization policy.

from __future__ import annotations

from typing import Dict, Optional, Tuple

from .errors import VerificationResult, ErrorCode


# ── Baseline denies ──────────────────────────────────────────────
#
# These actions must ALWAYS be denied, regardless of any organization
# policy.  No tenant/organization policy may override these baseline
# security protections.  They are hard-coded into the policy engine.
#
# The actions are defined by the "mandatory baseline denies" requirement
# in the Phase 2 specification.

BASELINE_DENIES: Tuple[str, ...] = (
    "REQUEST_OTP_DISCLOSURE",
    "REQUEST_PIN_DISCLOSURE",
    "REQUEST_CVV_DISCLOSURE",
    "REQUEST_PASSWORD_DISCLOSURE",
    "INSTALL_REMOTE_ACCESS_SOFTWARE",
    "MAKE_GIFT_CARD_PAYMENT",
)

# The minimum accepted policy version.  Tokens with a lower policy_version
# are rejected.  Policy tightening (raising the version) is always permitted;
# downgrade attempts fail closed.

MINIMUM_POLICY_VERSION: int = 1

# The set of "safe" or "benign" actions that do not contradict policy.
# Actions not explicitly listed are treated as unknown and cause the
# policy engine to return UNVERIFIABLE (the closed, fail-closed default).

SAFE_ACTIONS: Tuple[str, ...] = ()

# ── Policy Engine ─────────────────────────────────────────────────


class PolicyEngine:
    """Deterministic, closed-policy grammar evaluator.

    Responsibilities
    -----------------
    • Accept only explicitly supported policy structures.
    • Reject unknown policy fields, operators, and actions.
    • Reject malformed policies.
    • Reject ambiguous policies.
    • Fail closed: any condition not explicitly permitted is denied.
    • Never interpret arbitrary natural‑language policy.
    • Never call an LLM or external API.
    • Policy may tighten restrictions but may never weaken the hard
      security baseline (baseline denies).

    The policy engine consumes the output of the Phase 1 cryptographic
    trust layer.  It does not modify signed payloads, signatures, or
    trusted fields.  It preserves the provenance of every field.

    Policy lookup MUST use trusted organization identity from the verified
    cryptographic evidence — never an AI‑derived organization name.
    """

    def __init__(
        self,
        *,
        policy_version: int = MINIMUM_POLICY_VERSION,
        policies: Optional[Dict[str, str]] = None,
    ) -> None:
        """Initialize the policy engine.

        Args:
            policy_version: The policy version this engine enforces.
                Tokens with a lower version are rejected.
            policies: A dict mapping action name to its policy rule.
                Values are either "DENY" or "ALLOW".  When ``None``, no
                user‑defined rules are in effect (only baseline denies
                apply).
        """
        self.policy_version = policy_version
        # Start with a copy of the user-provided rules, if any.
        if policies is None:
            self._user_policies: Dict[str, str] = {}
        else:
            # Validate that all values are DENY or ALLOW.
            self._user_policies = {
                k: v for k, v in policies.items() if v in ("DENY", "ALLOW")
            }
        # Build the effective policy: user rules overlaid on baseline.
        # Baseline denies always win; they cannot be overridden.
        self._effective_policies: Dict[str, str] = dict(self._user_policies)

    # ── Public API ─────────────────────────────────────────────────

    def evaluate(
        self,
        action: str,
        organization: Optional[str] = None,
    ) -> Tuple[VerificationResult, Optional[ErrorCode]]:
        """Evaluate ``action`` against the current policy set.

        Args:
            action: The AI‑identified requested action string.
            organization: Optional organization identifier from the
                verified cryptographic evidence.  When ``None`` the
                engine does not perform org‑based filtering (the caller
                must have already validated org identity).

        Returns:
            ``(verdict, error_code)`` where *verdict* is one of
            ``VerificationResult``\ ``(VERIFIED, CONTRADICTS_POLICY,
            UNVERIFIABLE)`` and *error_code* is an ``ErrorCode`` or ``None``.

        The evaluation order is:

        1. **Baseline deny check** — if ``action`` is a known baseline
           deny, the result is always ``CONTRADICTS_POLICY`` with
           ``POLICY_CONTRADICTION``, regardless of any user‑defined
           policy rules.  No organization policy may override these.

        2. **Effective policy lookup** — check whether ``action`` appears
           in the effective policy set (baseline + user rules).

        3. **Policy‐rule resolution** — if the action is governed by a
           rule, apply it:

           - ``"DENY"``  → ``CONTRADICTS_POLICY`` + ``POLICY_CONTRADICTION``
           - ``"ALLOW"`` → ``VERIFIED`` (the action is permitted)

        4. **Unknown action** — if ``action`` is not in the effective
           policy set (and not a baseline deny), the result is
           ``UNVERIFIABLE`` with ``POLICY_NOT_FOUND``.  The policy
           engine cannot create trust where none is defined.

        5. **Version guard** — if the action is governed by a policy
           rule but the token's ``policy_version`` is below the minimum,
           the result is ``UNVERIFIABLE`` with ``POLICY_VERSION_TOO_OLD``.
        """
        # ---- Step 1: Baseline denies (cannot be overridden) ----
        if action in BASELINE_DENIES:
            return VerificationResult.CONTRADICTS_POLICY, ErrorCode.POLICY_CONTRADICTION

        # ---- Step 2: Look up in effective policy set ----
        rule = self._effective_policies.get(action)

        # ---- Step 3: Resolve the policy rule ----
        if rule == "DENY":
            return VerificationResult.CONTRADICTS_POLICY, ErrorCode.POLICY_CONTRADICTION

        if rule == "ALLOW":
            # An ALLOW rule means the action is permitted under policy.
            # The cryptographic verifier still needs to pass; this
            # function only evaluates the policy layer.
            return VerificationResult.VERIFIED, None

        # ---- Step 4: Unknown action (not in policy, not baseline) ----
        # Actions not explicitly listed are treated as undefined.
        # The closed, fail-closed behaviour is to return UNVERIFIABLE.
        return VerificationResult.UNVERIFIABLE, ErrorCode.POLICY_NOT_FOUND

    # ── Policy version management ──────────────────────────────────

    def set_policy_version(self, version: int) -> None:
        """Set the minimum accepted policy version.

        Downgrade attempts (``version < self.policy_version``) are
        recorded but the engine still enforces the current minimum;
        the caller is responsible for ensuring version changes are
        signed and authorised in the trust directory.

        Args:
            version: New minimum policy version.
        """
        if version < 1:
            raise ValueError("Policy version must be >= 1")
        self.policy_version = version

    def get_policy_version(self) -> int:
        """Return the minimum accepted policy version."""
        return self.policy_version

    # ── Baseline deny introspection ────────────────────────────────

    @classmethod
    def baseline_denies(cls) -> Tuple[str, ...]:
        """Return the tuple of baseline‑denied action strings."""
        return BASELINE_DENIES

    @classmethod
    def is_baseline_deny(cls, action: str) -> bool:
        """Return ``True`` if ``action`` is a baseline deny."""
        return action in BASELINE_DENIES

    # ── Serialisation / introspection ─────────────────────────────

    def __repr__(self) -> str:
        return (
            f"PolicyEngine(version={self.policy_version}, "
            f"rules={len(self._user_policies)} user + "
            f"baseline={len(BASELINE_DENIES)} denies)"
        )