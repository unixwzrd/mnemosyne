"""Pure metadata contract tests; no stores, providers, or host authority."""

import json
from dataclasses import FrozenInstanceError

import pytest

from mnemosyne.core.host_profile import LevelDisplayMetadata, ProfileDefinition
from mnemosyne.core.policy import PolicyDefinition


def profile(**changes):
    values = {
        "profile_id": "synthetic-host",
        "version": 1,
        "policy": PolicyDefinition("synthetic-policy", 1, ("low", "high")),
        "levels": (
            LevelDisplayMetadata("low", "Everyday", "Tier A"),
            LevelDisplayMetadata("high", "Restricted", "Tier B"),
        ),
        "terminology": (("classification", "sensitivity", "record tier"), ("destination", "recipient", "egress")),
    }
    values.update(changes)
    return ProfileDefinition(**values)


def test_round_trip_and_canonical_ascii_bytes():
    value = profile(levels=(
        LevelDisplayMetadata("low", "Café", "Tier A"),
        LevelDisplayMetadata("high", "Restricted", "Tier B"),
    ))
    encoded = value.canonical_bytes()
    assert encoded.isascii()
    assert encoded == json.dumps(value.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    assert ProfileDefinition.from_dict(json.loads(encoded)) == value
    assert ProfileDefinition.from_dict(value.to_dict()).canonical_bytes() == encoded


def test_user_and_admin_labels_are_independent_metadata():
    value = profile(levels=(
        LevelDisplayMetadata("low", "For you", "Operator band 1"),
        LevelDisplayMetadata("high", "Private", "Operator band 2"),
    ))
    assert value.levels[0].user_label != value.levels[0].admin_label
    assert value.to_dict()["levels"][0]["admin_label"] == "Operator band 1"


@pytest.mark.parametrize("ids", [("high", "low"), ("low",), ("low", "high", "extra"), ("low", "low")])
def test_display_level_ids_must_match_policy_exactly(ids):
    policy = PolicyDefinition("p", 1, ("low", "high"))
    with pytest.raises(ValueError, match="exactly match"):
        profile(
            policy=policy,
            levels=tuple(LevelDisplayMetadata(level, level, level) for level in ids),
        )


def test_bounded_vocabulary_and_strict_exact_types():
    with pytest.raises(ValueError, match="1..64"):
        ProfileDefinition("p", 1, PolicyDefinition("p", 1, tuple(f"l{i}" for i in range(65))), (), ())
    with pytest.raises(ValueError, match="allowlisted"):
        profile(terminology=(("role", "administrator", "operator"),))
    with pytest.raises(ValueError, match="must not repeat"):
        profile(terminology=(("purpose", "one", "admin one"), ("purpose", "two", "admin two")))
    with pytest.raises(TypeError, match="exact PolicyDefinition"):
        profile(policy=type("DerivedPolicy", (PolicyDefinition,), {})("p", 1, ("low", "high")))
    with pytest.raises(TypeError, match="exact LevelDisplayMetadata"):
        profile(levels=("low", "high"))
    with pytest.raises(ValueError, match="bounded nonblank"):
        profile(profile_id=" host")


@pytest.mark.parametrize("mutation", [
    lambda data: data.update(extra=True),
    lambda data: data.pop("version"),
    lambda data: data.update(contract_version=True),
    lambda data: data["policy"].update(extra=True),
    lambda data: data["levels"][0].update(extra=True),
    lambda data: data["terminology"].update(role="admin"),
])
def test_parser_rejects_unknown_missing_and_wrong_contract_types(mutation):
    data = profile().to_dict()
    mutation(data)
    with pytest.raises((TypeError, ValueError)):
        ProfileDefinition.from_dict(data)


def test_frozen_profile_and_no_authority_claims_in_wire_schema():
    value = profile()
    with pytest.raises(FrozenInstanceError):
        value.profile_id = "changed"
    serialized = value.to_dict()
    assert set(serialized) == {"contract_version", "profile_id", "version", "policy", "levels", "terminology"}
    assert not {"admin_grant", "authenticated", "permissions", "content_access"} & serialized.keys()


def test_terminology_order_normalizes_without_changing_semantics():
    value = profile(terminology=(("destination", "recipient", "egress"), ("classification", "sensitivity", "record tier")))
    assert value == profile()
    assert ProfileDefinition.from_dict(value.to_dict()) == value


def test_user_and_administrator_field_terminology_are_independent():
    value = profile()
    terms = value.to_dict()["terminology"]
    assert terms["classification"] == {"user_label": "sensitivity", "admin_label": "record tier"}
    assert ProfileDefinition.from_dict(value.to_dict()) == value


@pytest.mark.parametrize("value", ["\ud800", "\udfff", "control\x00"])
def test_invalid_unicode_and_controls_refuse(value):
    with pytest.raises(ValueError):
        LevelDisplayMetadata("low", value, "Admin")


def test_tuple_subclasses_are_not_trusted_metadata_containers():
    class DerivedTuple(tuple):
        pass

    with pytest.raises(ValueError):
        profile(terminology=DerivedTuple())
    with pytest.raises(ValueError):
        profile(levels=DerivedTuple(profile().levels))


@pytest.mark.parametrize("field", ["levels", "policy", "terminology"])
def test_parser_checks_collection_limits_before_constructing_members(field):
    data = profile().to_dict()
    if field == "levels":
        data["levels"] = [object()] * 65
    elif field == "policy":
        data["policy"]["levels"] = [object()] * 65
    else:
        data["terminology"] = {str(i): object() for i in range(7)}
    with pytest.raises(TypeError):
        ProfileDefinition.from_dict(data)
