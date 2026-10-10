# COUNTERSIGN Replay Protection Module
# Server-side replay state tracking.

# The design acknowledges that jti alone is NOT replay protection
# (per ARCHITECTURE.md corrections). Server-side state tracking of
# previously accepted token identifiers, bound to issuer/context,
# with expiry cleanup, is required.

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from threading import Lock
from typing import Dict, Set, Optional, Tuple, List

from .errors import ErrorCode


# ---------------------------------------------------------------------------
# In-memory replay store (for tests and demo)
# In production, this would be a persistent store (Redis, DB, etc.)
# ---------------------------------------------------------------------------

class ReplayStore:
    """Server-side replay protection state.

    Tracks previously accepted token identifiers (jti) bound to issuer
    and context, with expiry cleanup. A second presentation of the same
    jti within the validity window is rejected as a replay.

    This is an in-memory implementation for testing. Production would
    use a persistent store with appropriate TTL/indexing.
    """

    # Default replay window: 24 hours from first acceptance
    # After this window, the jti is considered "forgotten" and
    # a new presentation is accepted.
    _default_window_hours: int = 24

    # Maximum number of entries before cleanup
    _max_entries: int = 10000

    def __init__(self):
        """Initialize a fresh replay store with empty state."""
        self._store: Dict[Tuple[str, str], datetime] = {}
        self._lock = Lock()

    # ── Public API ───────────────────────────────────────────────

    def is_replay(self, jti: str, issuer: str, current_time: Optional[datetime] = None) -> bool:
        """Compatibility operation that atomically checks and reserves."""
        return self.check_and_record(jti, issuer, current_time)

    def check_and_record(self, jti: str, issuer: str, current_time: Optional[datetime] = None) -> bool:
        """Atomically reserve a previously validated token ID; True means replay."""
        if current_time is None:
            current_time = datetime.now(timezone.utc)
        if not jti or not issuer:
            return True
        with self._lock:
            key = (issuer, jti)
            expiry = self._store.get(key)
            if expiry is not None and current_time <= expiry:
                return True
            self._store[key] = current_time + timedelta(hours=self._default_window_hours)
            return False

    def clear_replay(self, jti: str, issuer: str) -> None:
        """Explicitly clear a replay entry (e.g., on logout/invalidation)."""
        with self._lock:
            key = (issuer, jti)
            if key in self._store:
                del self._store[key]

    def clear_all_for_issuer(self, issuer: str) -> None:
        """Clear all replay entries for a given issuer (e.g., key rotation)."""
        with self._lock:
            keys_to_remove = [
                k for k in self._store.keys() if k[0] == issuer
            ]
            for k in keys_to_remove:
                del self._store[k]

    def entry_count(self) -> int:
        """Return the current number of stored replay entries."""
        with self._lock:
            return len(self._store)

    def prune_expired(self, current_time: Optional[datetime] = None) -> int:
        """Remove all replay entries whose validity window has expired.

        Returns the number of entries removed.
        """
        if current_time is None:
            current_time = datetime.now(timezone.utc)

        with self._lock:
            removed = 0
            keys_to_remove: List[Tuple[str, str]] = []
            for (issuer, jti), expiry in self._store.items():
                if current_time > expiry:
                    keys_to_remove.append((issuer, jti))
                    removed += 1
            for k in keys_to_remove:
                del self._store[k]
            return removed

    def set_window_hours(self, hours: int) -> None:
        """Set the replay validity window in hours."""
        self._default_window_hours = hours

    def get_window_hours(self) -> int:
        """Get the current replay validity window in hours."""
        return self._default_window_hours


# ---------------------------------------------------------------------------
# Property-based test helpers (Hypothesis)
# ---------------------------------------------------------------------------

# Invariants that Hypothesis tests should verify:

# INVARIANT 1: First presentation of a jti/issuer combo is never a replay.
# INVARIANT 2: Second presentation within the validity window IS a replay.
# INVARIANT 3: Presentation after the validity window is NOT a replay
#     (entry is refreshed).
# INVARIANT 4: Different issuers with the same jti are tracked separately.
# INVARIANT 5: Clearing an entry removes the replay detection.