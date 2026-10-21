"""Atomic synthetic host snapshots; no live adapter identities or banks."""

from dataclasses import replace

import pytest

from mnemosyne.core.policy import PolicyDefinition, PolicyRefusal
from mnemosyne.core.policy_host import (
    HostPolicySnapshot,
    ParticipantGrant,
    ProtectedHostAdapter,
)
from mnemosyne.runtime_context import get_access_context
from tests.test_policy_read import context, fixture as fixture
from tests.test_policy_evidence import evidence as evidence
from tests.test_snapshot_authority import authority as authority
from tests.test_protected_repository import repository as repository
from tests.test_protected_session import session as session


def grant(principal="person:a", **changes):
    values = dict(
        principal_id=principal,
        authority_epoch=1,
        classification_ceiling="team",
        banks={"bank:a"},
        owners={"person:a"},
        tenants={"tenant:a"},
        compartments={"work"},
        audiences={"internal"},
        purposes={"engineering"},
        operations={"read:bank"},
        destinations={"channel:a"},
        bank_wide=True,
    )
    values.update(changes)
    return ParticipantGrant(**values)


def snapshot(**changes):
    values = dict(
        context=context(),
        definition=PolicyDefinition("test", 1, ("open", "team", "sealed")),
        grants=(grant(),),
        store_id="a" * 32,
        domain_id="domain:a",
        bank="bank:a",
        destination="channel:a",
        lifecycle_epoch=0,
    )
    values.update(changes)
    return HostPolicySnapshot(**values)


def test_agent_broader_independent_grants_never_expand_human_ceiling():
    ctx = context(
        principals={"person:a", "agent:a"},
        classification_ceiling="sealed",
        banks={"bank:a", "bank:private"},
        compartments={"work", "private"},
        audiences={"internal", "secret"},
        operations={"read:bank", "create:working_memory"},
    )
    broad = grant(
        "agent:a",
        classification_ceiling="sealed",
        banks=ctx.banks,
        owners={"person:a", "person:b"},
        compartments=ctx.compartments,
        audiences=ctx.audiences,
        operations=ctx.operations,
    )
    effective, owners, tenants = snapshot(
        context=ctx, grants=(grant(), broad)
    ).effective()
    assert effective.classification_ceiling == "team"
    assert effective.principals == {"person:a", "agent:a"}
    assert effective.banks == {"bank:a"} and effective.compartments == {"work"}
    assert effective.audiences == {"internal"} and effective.operations == {"read:bank"}
    assert owners == {"person:a"} and tenants == {"tenant:a"}


@pytest.mark.parametrize(
    "kind",
    [
        "unknown",
        "extra",
        "duplicate",
        "epoch",
        "classification",
        "bank",
        "destination",
        "purpose",
        "operation",
        "assurance",
    ],
)
def test_incomplete_invalid_or_stale_authority_fails_closed(kind):
    item = snapshot()
    if kind == "unknown":
        item = replace(item, context=context(principals={"person:a", "unknown"}))
    elif kind == "extra":
        item = replace(item, grants=(grant(), grant("extra")))
    elif kind == "duplicate":
        item = replace(item, grants=(grant(), grant()))
    elif kind == "epoch":
        item = replace(item, grants=(grant(authority_epoch=0),))
    elif kind == "classification":
        item = replace(item, grants=(grant(classification_ceiling="unknown"),))
    elif kind == "bank":
        item = replace(item, grants=(grant(banks=set()),))
    elif kind == "destination":
        item = replace(item, grants=(grant(destinations=set()),))
    elif kind == "purpose":
        item = replace(item, grants=(grant(purposes=set()),))
    elif kind == "operation":
        item = replace(item, grants=(grant(operations=set()),))
    else:
        item = replace(item, context=context(assurance="asserted"))
    with pytest.raises(PolicyRefusal):
        item.effective()


def test_project_grants_cannot_turn_empty_selection_into_bank_wide():
    item = snapshot(grants=(grant(projects={"project:a"}, bank_wide=False),))
    with pytest.raises(PolicyRefusal):
        item.effective()
    ctx = context(projects={"project:a"}, operations={"read:projects"})
    item = replace(
        item,
        context=ctx,
        grants=(
            grant(
                projects={"project:a"}, bank_wide=False, operations={"read:projects"}
            ),
        ),
    )
    assert item.effective()[0].projects == {"project:a"}
    with pytest.raises(PolicyRefusal):
        replace(item, context=replace(ctx, projects={"project:other"})).effective()


def test_disjoint_owner_audience_and_compartments_stay_empty():
    ctx = context(principals={"person:a", "person:b"})
    other = grant(
        "person:b",
        owners={"person:b"},
        audiences={"different"},
        compartments={"different"},
    )
    effective, owners, _ = snapshot(context=ctx, grants=(grant(), other)).effective()
    assert not owners and not effective.audiences and not effective.compartments


@pytest.fixture
def host(session, repository):
    memory, audit, *_ = session
    request = object()
    state = {"snapshot": snapshot(), "calls": []}

    def load(actual):
        state["calls"].append(actual)
        return state["snapshot"] if actual is request else None

    def resolve(store_id):
        assert store_id == "a" * 32
        return repository[0], audit

    adapter = ProtectedHostAdapter(
        adapter_id="synthetic-sdk",
        issuer="test-host",
        load_snapshot=load,
        resolve_store=resolve,
    )
    return adapter, request, state


def invoke(host, record="w"):
    seen = []
    host[0].invoke(
        host[1], "get", {"kind": "working_memory", "record_id": record}, seen.append
    )
    return seen[0]


def test_host_authenticated_request_routes_and_preserves_outer_context(host):
    before = get_access_context(required=True)
    assert invoke(host).content == "PRIVATE-REPOSITORY-CANARY"
    assert get_access_context(required=True) is before
    assert len(host[2]["calls"]) > 3
    with pytest.raises(PolicyRefusal):
        host[0].invoke(
            object(),
            "get",
            {"kind": "working_memory", "record_id": "w"},
            lambda _: pytest.fail("unauthenticated output"),
        )


@pytest.mark.parametrize(
    "adapter_id", ["sdk", "cli-reference", "mcp-reference", "hermes-reference"]
)
def test_reference_frontends_use_same_host_route_and_reader(
    host, repository, session, adapter_id
):
    # Labels do not claim live CLI/MCP/Hermes wiring; this is the common API.
    adapter = ProtectedHostAdapter(
        adapter_id=adapter_id,
        issuer="test-host",
        load_snapshot=lambda request: (
            host[2]["snapshot"] if request is host[1] else None
        ),
        resolve_store=lambda identity: (repository[0], session[1]),
    )
    assert invoke((adapter, host[1], host[2])).record_id == "w"


def test_a_b_a_and_shared_participant_intersection_through_actual_reference_dispatch(
    host,
):
    adapter, request, state = host
    original = state["snapshot"]
    assert invoke(host).record_id == "w"
    b = context(context_id="ctx:b", principals={"person:b"})
    state["snapshot"] = snapshot(
        context=b, grants=(grant("person:b", owners={"person:b"}),)
    )
    assert invoke(host) is None
    assert invoke(host, "denied").content == "DENIED-SESSION-CANARY"
    shared = context(context_id="ctx:shared", principals={"person:a", "person:b"})
    state["snapshot"] = snapshot(
        context=shared, grants=(grant(), grant("person:b", owners={"person:b"}))
    )
    assert invoke(host) is None and invoke(host, "denied") is None
    state["snapshot"] = original
    assert invoke(host).content == "PRIVATE-REPOSITORY-CANARY"


@pytest.mark.parametrize(
    "key",
    [
        "context",
        "bank",
        "destination",
        "projects",
        "store_id",
        "key",
        "profile",
        "consumer",
        "producer",
        "verify_context",
        "repository",
    ],
)
def test_model_supplied_scope_or_callback_is_not_a_host_authority(host, key):
    with pytest.raises(PolicyRefusal, match="access_denied"):
        host[0].invoke(
            host[1], "get", {key: "forged"}, lambda _: pytest.fail("scope override")
        )
    assert not host[2]["calls"]


def test_host_epoch_or_participants_change_during_audit_blocks_output(
    host, session, monkeypatch
):
    audit = session[1]
    admit = audit.admit

    def change(*args, **kwargs):
        result = admit(*args, **kwargs)
        old = host[2]["snapshot"]
        host[2]["snapshot"] = replace(
            old,
            context=replace(old.context, epoch=2),
            grants=(grant(authority_epoch=2),),
        )
        return result

    monkeypatch.setattr(audit, "admit", change)
    seen = []
    with pytest.raises(PolicyRefusal, match="access_denied"):
        host[0].invoke(
            host[1], "get", {"kind": "working_memory", "record_id": "w"}, seen.append
        )
    assert seen == []


def test_snapshot_dictionary_is_not_an_authenticated_host_claim(host):
    host[2]["snapshot"] = {"context": "asserted-by-model"}
    with pytest.raises(PolicyRefusal, match="access_denied"):
        invoke(host)


def test_wrong_host_issuer_is_refused(host):
    host[2]["snapshot"] = replace(snapshot(), context=context(issuer="wrong-host"))
    with pytest.raises(PolicyRefusal, match="access_denied"):
        invoke(host)


@pytest.mark.parametrize(
    "operation", ["export", "graph", "derive", "deliver", "stream", "prepare", None, []]
)
def test_unsupported_frontend_operations_never_reach_consumer(host, operation):
    with pytest.raises(PolicyRefusal, match="unsupported_surface"):
        host[0].invoke(
            host[1], operation, {}, lambda _: pytest.fail("unsupported output")
        )
