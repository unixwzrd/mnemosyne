"""Bounded host-facing labels for a policy vocabulary.

These definitions are descriptive metadata only. They do not authenticate an
administrator, grant administrative capability, or authorize content access.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Tuple

from mnemosyne.core.policy import PolicyDefinition


PROFILE_CONTRACT_VERSION = 1
PROFILE_TERMINOLOGY_FIELDS = (
    "classification",
    "clearance",
    "compartment",
    "audience",
    "purpose",
    "destination",
)
MAX_PROFILE_ID_LENGTH = 128
MAX_LABEL_LENGTH = 128
MAX_TERM_LENGTH = 64
MAX_TERMINOLOGY_FIELDS = len(PROFILE_TERMINOLOGY_FIELDS)


def _bounded_text(value: object, name: str, maximum: int) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in value)
    ):
        raise ValueError(f"{name} must be bounded nonblank text without surrounding whitespace or controls")
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise ValueError(f"{name} must be valid Unicode text") from None
    return value


def _exact_dict(value: object, expected: set[str], name: str) -> dict:
    if type(value) is not dict:
        raise TypeError(f"{name} must be a dict")
    keys = set(value)
    if keys != expected:
        missing = expected - keys
        unknown = keys - expected
        raise ValueError(f"{name} keys mismatch (missing={sorted(missing)}, unknown={sorted(unknown)})")
    return value


@dataclass(frozen=True, repr=False)
class LevelDisplayMetadata:
    """Independent end-user and administrator labels for one policy level."""

    level_id: str
    user_label: str
    admin_label: str

    def __post_init__(self) -> None:
        _bounded_text(self.level_id, "level_id", 64)
        _bounded_text(self.user_label, "user_label", MAX_LABEL_LENGTH)
        _bounded_text(self.admin_label, "admin_label", MAX_LABEL_LENGTH)

    def to_dict(self) -> dict[str, str]:
        return {
            "admin_label": self.admin_label,
            "level_id": self.level_id,
            "user_label": self.user_label,
        }

    @classmethod
    def from_dict(cls, data: object) -> "LevelDisplayMetadata":
        values = _exact_dict(data, {"level_id", "user_label", "admin_label"}, "level metadata")
        return cls(level_id=values["level_id"], user_label=values["user_label"], admin_label=values["admin_label"])


@dataclass(frozen=True, repr=False)
class ProfileDefinition:
    """Immutable display vocabulary bound exactly to a policy definition."""

    profile_id: str
    version: int
    policy: PolicyDefinition
    levels: Tuple[LevelDisplayMetadata, ...]
    terminology: Tuple[Tuple[str, str, str], ...]

    def __post_init__(self) -> None:
        _bounded_text(self.profile_id, "profile_id", MAX_PROFILE_ID_LENGTH)
        if type(self.version) is not int or not 1 <= self.version <= 2**63 - 1:
            raise ValueError("version must be a bounded positive integer")
        if type(self.policy) is not PolicyDefinition:
            raise TypeError("policy must be an exact PolicyDefinition")
        if (type(self.policy.policy_id) is not str or type(self.policy.levels) is not tuple
                or any(type(level) is not str for level in self.policy.levels)):
            raise TypeError("policy vocabulary must contain exact builtin values")
        if type(self.levels) is not tuple or not 1 <= len(self.levels) <= 64:
            raise ValueError("levels must be a tuple of 1..64 display metadata records")
        if any(type(level) is not LevelDisplayMetadata for level in self.levels):
            raise TypeError("levels must contain exact LevelDisplayMetadata records")
        ids = tuple(level.level_id for level in self.levels)
        if ids != self.policy.levels:
            raise ValueError("display level IDs must exactly match policy levels in order")
        if type(self.terminology) is not tuple or len(self.terminology) > MAX_TERMINOLOGY_FIELDS:
            raise ValueError("terminology must be a bounded tuple of allowlisted field/value pairs")
        normalized = []
        seen = set()
        for pair in self.terminology:
            if type(pair) is not tuple or len(pair) != 3:
                raise ValueError("each terminology entry must be a (field, user_label, admin_label) tuple")
            field, user_label, admin_label = pair
            _bounded_text(field, "terminology field", MAX_TERM_LENGTH)
            if field not in PROFILE_TERMINOLOGY_FIELDS:
                raise ValueError("terminology field is not allowlisted")
            if field in seen:
                raise ValueError("terminology fields must not repeat")
            seen.add(field)
            _bounded_text(user_label, "user terminology label", MAX_LABEL_LENGTH)
            _bounded_text(admin_label, "administrator terminology label", MAX_LABEL_LENGTH)
            normalized.append((field, user_label, admin_label))
        object.__setattr__(self, "levels", tuple(self.levels))
        object.__setattr__(self, "terminology", tuple(sorted(normalized)))

    def to_dict(self) -> dict:
        return {
            "contract_version": PROFILE_CONTRACT_VERSION,
            "levels": [level.to_dict() for level in self.levels],
            "policy": {
                "levels": list(self.policy.levels),
                "policy_id": self.policy.policy_id,
                "version": self.policy.version,
            },
            "profile_id": self.profile_id,
            "terminology": {field: {"user_label": user_label, "admin_label": admin_label}
                            for field, user_label, admin_label in self.terminology},
            "version": self.version,
        }

    @classmethod
    def from_dict(cls, data: object) -> "ProfileDefinition":
        values = _exact_dict(
            data,
            {"contract_version", "profile_id", "version", "policy", "levels", "terminology"},
            "profile definition",
        )
        if type(values["contract_version"]) is not int or values["contract_version"] != PROFILE_CONTRACT_VERSION:
            raise ValueError("unsupported profile contract version")
        policy_data = _exact_dict(values["policy"], {"policy_id", "version", "levels"}, "policy")
        if type(policy_data["levels"]) is not list or not 1 <= len(policy_data["levels"]) <= 64:
            raise TypeError("policy levels must be a JSON array")
        policy = PolicyDefinition(
            policy_id=policy_data["policy_id"],
            version=policy_data["version"],
            levels=tuple(policy_data["levels"]),
        )
        if type(values["levels"]) is not list or not 1 <= len(values["levels"]) <= 64:
            raise TypeError("levels must be a JSON array")
        if type(values["terminology"]) is not dict or len(values["terminology"]) > MAX_TERMINOLOGY_FIELDS:
            raise TypeError("terminology must be a JSON object")
        terminology = values["terminology"]
        unknown = set(terminology) - set(PROFILE_TERMINOLOGY_FIELDS)
        if unknown:
            raise ValueError(f"terminology has unknown fields: {sorted(unknown)}")
        terms = []
        for field in PROFILE_TERMINOLOGY_FIELDS:
            if field in terminology:
                labels = _exact_dict(terminology[field], {"user_label", "admin_label"}, "terminology labels")
                terms.append((field, labels["user_label"], labels["admin_label"]))
        return cls(
            profile_id=values["profile_id"],
            version=values["version"],
            policy=policy,
            levels=tuple(LevelDisplayMetadata.from_dict(item) for item in values["levels"]),
            terminology=tuple(terms),
        )

    def canonical_bytes(self) -> bytes:
        """Return canonical ASCII JSON; it contains metadata and no request context."""
        return json.dumps(
            self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ).encode("ascii")
