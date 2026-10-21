"""Fingerprint bytes remain stable; fresh permission checks are never cached."""

from concurrent.futures import ThreadPoolExecutor
import copy
from dataclasses import asdict, dataclass, field, fields, replace
import gc
import hashlib
import json
import pickle
import weakref

import pytest

from mnemosyne.core import policy as module
from mnemosyne.core.policy import AccessContext
from tests.test_policy_contracts import context


def original_fingerprint(ctx):
    values = {f.name:getattr(ctx,f.name) for f in fields(ctx)}
    for name,value in values.items():
        if isinstance(value,frozenset):
            values[name]=sorted(value)
    value=json.dumps([module.POLICY_CONTRACT_VERSION,values],sort_keys=True,separators=(",",":"))
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def test_repeated_fingerprint_serializes_once_without_dataclass_changes(monkeypatch):
    ctx=context()
    expected=original_fingerprint(ctx)
    before=asdict(ctx),fields(ctx),hash(ctx)
    dumps=module.json.dumps
    calls=[]
    def count(*args,**kwargs):
        calls.append(True)
        return dumps(*args,**kwargs)
    monkeypatch.setattr(module.json,"dumps",count)
    assert [ctx.fingerprint() for _ in range(100)]==[expected]*100
    assert len(calls)==1
    assert (asdict(ctx),fields(ctx),hash(ctx))==before
    assert "_policy_fingerprint_cache" not in asdict(ctx)


@pytest.mark.parametrize("name,value", [
    ("context_id","ctx:changed"),("epoch",2),("policy_id","other"),("policy_version",2),
    ("issuer","other"),("platform","other"),("principals",frozenset({"other"})),
    ("classification_ceiling","open"),("purpose","other"),("assurance","owner"),
    ("banks",frozenset()),("projects",frozenset()),("compartments",frozenset()),
    ("audiences",frozenset()),("operations",frozenset()),("destinations",frozenset()),
    ("channel_id",None),("conversation_id",None),
])
def test_even_forced_field_replacement_invalidates_cache(name,value):
    ctx=context()
    before=ctx.fingerprint()
    object.__setattr__(ctx,name,value)
    assert ctx.fingerprint()==original_fingerprint(ctx) and ctx.fingerprint()!=before


def test_contract_version_change_invalidates_existing_context(monkeypatch):
    ctx=context()
    before=ctx.fingerprint()
    monkeypatch.setattr(module,"POLICY_CONTRACT_VERSION",2)
    assert ctx.fingerprint()==original_fingerprint(ctx) and ctx.fingerprint()!=before


def test_older_shorter_field_cache_cannot_match_a_new_context_layout():
    ctx=context()
    expected=ctx.fingerprint()
    version,values,_=ctx.__dict__["_policy_fingerprint_cache"]
    object.__setattr__(ctx,"_policy_fingerprint_cache",(version,values[:-1],"0"*64))
    assert ctx.fingerprint()==original_fingerprint(ctx)==expected


@pytest.mark.parametrize("operation", [copy.copy,copy.deepcopy,lambda c:pickle.loads(pickle.dumps(c)),lambda c:replace(c),lambda c:c.narrow()])
def test_copy_and_reconstruction_match_original_algorithm(operation):
    ctx=context()
    before=ctx.fingerprint()
    reconstructed=operation(ctx)
    assert reconstructed.fingerprint()==original_fingerprint(reconstructed)==before
    changed=replace(reconstructed,epoch=2)
    assert changed.fingerprint()==original_fingerprint(changed)!=before


def test_subclass_mutable_extra_fields_are_not_cached():
    @dataclass(frozen=True,repr=False)
    class Extended(AccessContext):
        notes:list[str]=field(default_factory=list)
    ctx=Extended(**asdict(context()))
    before=ctx.fingerprint()
    ctx.notes.append("new")
    assert ctx.fingerprint()==original_fingerprint(ctx)!=before
    assert "_policy_fingerprint_cache" not in ctx.__dict__


def test_string_subclasses_keep_uncached_semantics():
    class Nonstandard(str):
        def __eq__(self,other):
            return True
        __hash__=str.__hash__
    ctx=replace(context(),context_id=Nonstandard("ctx:one"))
    before=ctx.fingerprint()
    assert "_policy_fingerprint_cache" not in ctx.__dict__
    object.__setattr__(ctx,"context_id",Nonstandard("ctx:two"))
    assert ctx.fingerprint()==original_fingerprint(ctx)!=before


def test_unordered_inputs_and_unicode_keep_canonical_bytes():
    ctx=context(principals=["person:z","person:a"],projects=["z","a"],context_id="ctx:\u00e9")
    assert ctx.fingerprint()==original_fingerprint(ctx)
    assert replace(ctx,projects=["a","z"]).fingerprint()==ctx.fingerprint()


def test_per_instance_cache_does_not_keep_context_alive():
    ctx=context()
    ctx.fingerprint()
    ref=weakref.ref(ctx)
    del ctx
    gc.collect()
    assert ref() is None


def test_concurrent_same_context_has_no_shared_global_cache():
    ctx=context()
    expected=original_fingerprint(ctx)
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert list(pool.map(lambda _:ctx.fingerprint(),range(100)))==[expected]*100
    assert len(ctx.__dict__["_policy_fingerprint_cache"])==3
    other=context()
    assert "_policy_fingerprint_cache" not in other.__dict__
