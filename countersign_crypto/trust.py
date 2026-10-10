"""Pinned-root authenticated trust-directory snapshots."""
from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .errors import ErrorCode


def _utc(value: Any) -> Any:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    return value


class TrustDirectorySnapshot(BaseModel):
    """A root-signed immutable snapshot. `signature` signs `signed_bytes()`."""
    model_config = ConfigDict(extra="forbid", strict=True)

    snapshot_id: str = Field(min_length=1, max_length=128)
    version: str = Field(min_length=1, max_length=64)
    effective_from: datetime = Field(default_factory=lambda: datetime.now(timezone.utc) - timedelta(minutes=1))
    expires_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc) + timedelta(days=365))
    keys: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    root_key_fingerprint: str = Field(min_length=1, max_length=128)
    signature: str = Field(min_length=1)
    min_policy_version: int = Field(default=1, ge=1)

    @field_validator("effective_from", "expires_at", mode="before")
    @classmethod
    def ensure_utc(cls, value: Any) -> Any:
        return _utc(value)

    @field_validator("version")
    @classmethod
    def valid_version(cls, value: str) -> str:
        if not re.fullmatch(r"[1-9][0-9]*(?:\.[0-9]+)*", value):
            raise ValueError("version must be a positive dotted numeric version")
        return value

    @model_validator(mode="after")
    def valid_snapshot(self) -> "TrustDirectorySnapshot":
        if self.expires_at <= self.effective_from:
            raise ValueError("snapshot expiry must follow activation")
        for kid, props in self.keys.items():
            if not kid or not isinstance(props, dict):
                raise ValueError("invalid key entry")
            required = {"revoked", "valid_from", "valid_until", "public_key_b64", "trusted_organization"}
            if set(props) != required:
                raise ValueError("key entry has missing or unknown fields")
            if not isinstance(props["revoked"], bool) or not isinstance(props["trusted_organization"], str) or not props["trusted_organization"]:
                raise ValueError("invalid key authorization")
            try:
                pk = base64.b64decode(props["public_key_b64"], validate=True)
            except Exception as exc:
                raise ValueError("invalid public key encoding") from exc
            if len(pk) != 32:
                raise ValueError("Ed25519 public key must be 32 bytes")
            for name in ("valid_from", "valid_until"):
                if props[name] is not None:
                    parsed = _utc(props[name])
                    if not isinstance(parsed, datetime):
                        parsed = datetime.fromisoformat(parsed.replace("Z", "+00:00"))
                    props[name] = _utc(parsed)
            if props["valid_from"] and props["valid_until"] and props["valid_until"] <= props["valid_from"]:
                raise ValueError("key expiry must follow key activation")
        return self

    def signed_payload(self) -> Dict[str, Any]:
        payload = self.model_dump(mode="json", exclude={"signature"})
        return payload

    def signed_bytes(self) -> bytes:
        return json.dumps(self.signed_payload(), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")

    def version_tuple(self) -> tuple[int, ...]:
        return tuple(int(part) for part in self.version.split("."))

    def lookup_key(self, key_id: str) -> Optional[Dict[str, Any]]:
        return self.keys.get(key_id)

    def get_min_policy_version(self) -> int:
        return self.min_policy_version

    def is_stale(self, current_time: Optional[datetime] = None) -> bool:
        now = _utc(current_time or datetime.now(timezone.utc))
        return now >= self.expires_at

    def is_active(self, current_time: Optional[datetime] = None) -> bool:
        now = _utc(current_time or datetime.now(timezone.utc))
        return now >= self.effective_from


class TrustDirectory:
    """Current snapshot checked against an out-of-band pinned root key."""
    _snapshot: Optional[TrustDirectorySnapshot] = None
    _pinned_root_public_key: Optional[bytes] = None
    _highest_version: Optional[tuple[int, ...]] = None

    @classmethod
    def set_pinned_root_key(cls, public_key: bytes) -> None:
        if not isinstance(public_key, bytes) or len(public_key) != 32:
            raise ValueError("pinned Ed25519 root public key must be 32 bytes")
        cls._pinned_root_public_key = bytes(public_key)

    @classmethod
    def set_pinned_root_fingerprint(cls, fingerprint: str) -> None:
        # Kept for compatibility only; a fingerprint is not a trust anchor.
        raise ValueError("a fingerprint cannot authenticate a directory; pin the root public key")

    @classmethod
    def get_pinned_root_fingerprint(cls) -> str:
        if cls._pinned_root_public_key is None:
            return ""
        return hashlib.sha256(cls._pinned_root_public_key).hexdigest()

    @classmethod
    def initialize_with_snapshot(cls, snapshot: TrustDirectorySnapshot) -> None:
        # Preserve the last authenticated version against rollback attempts.
        reason = cls.directory_rejected_reason(snapshot)
        if reason is not None:
            cls._snapshot = snapshot
            return
        version = snapshot.version_tuple()
        if cls._highest_version is not None and version < cls._highest_version:
            cls._snapshot = snapshot
            return
        cls._highest_version = version
        cls._snapshot = snapshot

    @classmethod
    def current_snapshot(cls) -> Optional[TrustDirectorySnapshot]:
        return cls._snapshot

    @classmethod
    def is_current(cls, current_time: Optional[datetime] = None) -> bool:
        snap = cls._snapshot
        return bool(snap is not None and snap.is_active(current_time) and not snap.is_stale(current_time))

    @classmethod
    def verify_directory_signature(cls, snapshot: TrustDirectorySnapshot, expected_fingerprint: Optional[str] = None) -> bool:
        root = cls._pinned_root_public_key
        if root is None:
            return False
        if expected_fingerprint is not None and hashlib.sha256(root).hexdigest() != expected_fingerprint:
            return False
        if snapshot.root_key_fingerprint != hashlib.sha256(root).hexdigest():
            return False
        try:
            from nacl.signing import VerifyKey
            signature = base64.b64decode(snapshot.signature, validate=True)
            if len(signature) != 64:
                return False
            VerifyKey(root).verify(snapshot.signed_bytes(), signature)
            return True
        except Exception:
            return False

    @classmethod
    def directory_rejected_reason(cls, snapshot: Optional[TrustDirectorySnapshot], current_time: Optional[datetime] = None) -> Optional[ErrorCode]:
        if snapshot is None:
            return ErrorCode.DIRECTORY_INVALID
        if cls._pinned_root_public_key is None:
            return ErrorCode.DIRECTORY_NOT_TRUSTED
        if not cls.verify_directory_signature(snapshot):
            return ErrorCode.DIRECTORY_SIGNATURE_INVALID
        now = _utc(current_time or datetime.now(timezone.utc))
        if now < snapshot.effective_from:
            return ErrorCode.DIRECTORY_NOT_YET_ACTIVE
        if snapshot.is_stale(now):
            return ErrorCode.DIRECTORY_EXPIRED
        if cls._highest_version is not None and snapshot.version_tuple() < cls._highest_version:
            return ErrorCode.DIRECTORY_VERSION_DOWNGRADE
        return None

    @classmethod
    def lookup_key(cls, key_id: str) -> Optional[Dict[str, Any]]:
        snap = cls._snapshot
        if snap is None:
            return None
        return snap.lookup_key(key_id)

    @classmethod
    def get_key_properties(cls, key_id: str) -> Optional[Dict[str, Any]]:
        return cls.lookup_key(key_id)

    @classmethod
    def get_min_policy_version(cls) -> int:
        snap = cls._snapshot
        return snap.get_min_policy_version() if snap else 1
