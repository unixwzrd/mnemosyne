"""Opt-in qualification of real Hermes discovery/MemoryManager dispatch.

This is deliberately not a Gateway/AIAgent cache acceptance test. The host
checkout is caller-supplied and pinned explicitly; no live services are used.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from packaging.specifiers import SpecifierSet

try:
    import tomllib
except ImportError:
    import tomli as tomllib


@pytest.mark.parametrize("layout", ["separate-homes", "same-home-banks"])
def test_real_host_discovery_and_interleaved_dispatch(tmp_path, layout):
    configured = os.environ.get("MNEMOSYNE_Q1_HERMES_SOURCE")
    if not configured:
        pytest.skip("set MNEMOSYNE_Q1_HERMES_SOURCE and MNEMOSYNE_Q1_HERMES_REVISION")
    expected = os.environ.get("MNEMOSYNE_Q1_HERMES_REVISION", "")
    assert len(expected) == 40, "an exact Hermes commit must be supplied"
    host = Path(configured).resolve()
    actual = subprocess.check_output(
        ["git", "-C", str(host), "rev-parse", "HEAD"], text=True,
    ).strip()
    assert actual == expected, "Hermes checkout does not match the qualification pin"
    contract = tomllib.loads((host / "pyproject.toml").read_text(encoding="utf-8"))
    required = contract["project"]["requires-python"]
    if ".".join(map(str, sys.version_info[:3])) not in SpecifierSet(required):
        pytest.skip(f"pinned Hermes requires Python {required}; core qualification is separate")
    for options in (["diff", "--quiet"], ["diff", "--cached", "--quiet"]):
        subprocess.run(["git", "-C", str(host), *options], check=True)
    assert not subprocess.check_output(
        ["git", "-C", str(host), "ls-files", "--others", "--exclude-standard"], text=True,
    ).strip(), "untracked host files could change import/dispatch behavior"
    candidate = Path(__file__).resolve().parents[3]
    candidate_head = subprocess.check_output(
        ["git", "-C", str(candidate), "rev-parse", "HEAD"], text=True,
    ).strip()
    candidate_dirty = bool(subprocess.check_output(
        ["git", "-C", str(candidate), "status", "--porcelain"], text=True,
    ).strip())

    script = r'''
import json
import os
import sqlite3
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from pathlib import Path

candidate = Path(os.environ["Q1_CANDIDATE"])
host = Path(os.environ["MNEMOSYNE_Q1_HERMES_SOURCE"])
sys.path[:0] = [str(candidate), str(candidate / "integrations/hermes/src"),
                str(host), str(candidate / "scripts")]
from qualification_benchmark import backend_guard, module_record, offline_guard
guards = ExitStack()
network_attempts = guards.enter_context(offline_guard())
backend_attempts, boundaries = guards.enter_context(backend_guard())

import agent.memory_manager as manager_module
import mnemosyne_hermes as adapter_module
import mnemosyne.core.beam as beam_module
from hermes_constants import reset_hermes_home_override, set_hermes_home_override
from hermes_cli.profiles import get_active_profile_name
from agent.memory_manager import MemoryManager
from plugins.memory import load_memory_provider

provenance = {
    "candidate_commit": os.environ["Q1_CANDIDATE_HEAD"],
    "candidate_dirty": os.environ["Q1_CANDIDATE_DIRTY"] == "1",
    "host_commit": os.environ["MNEMOSYNE_Q1_HERMES_REVISION"],
    "python": sys.version,
    "imported_sources": {
        module.__name__: module_record(module, candidate)
        for module in (adapter_module, beam_module)
    },
    "host_manager": module_record(manager_module, host),
}
root = Path(os.environ["HOME"])
shared = root / ".hermes"
layout = os.environ["Q1_LAYOUT"]
homes = [shared / "profiles" / name for name in ("profile_a", "profile_b")]
if layout == "same-home-banks":
    homes = [shared, shared]
for home in set(homes):
    home.mkdir(parents=True, exist_ok=True)
    (home / "config.yaml").write_text(
        "memory:\n  provider: mnemosyne\n  mnemosyne:\n"
        "    profile_isolation: " + str(layout == "same-home-banks").lower()
        + "\n    default_scope: global\n", encoding="utf-8",
    )

def bound(home, action):
    token = set_hermes_home_override(home)
    try:
        return action()
    finally:
        reset_hermes_home_override(token)

managers, providers, paths, host_names = [], [], [], []
for index, home in enumerate(homes):
    identity = ("profile_a", "profile_b")[index]
    def initialize():
        provider = load_memory_provider("mnemosyne", register_skills=False)
        assert provider is not None, "real Hermes discovery returned no provider"
        # Hermes deliberately loads user providers under a private module name.
        # Verify the actual loaded file, not its synthetic module identifier.
        loaded = module_record(sys.modules[type(provider).__module__], candidate)
        assert loaded == provenance["imported_sources"]["mnemosyne_hermes"], loaded
        manager = MemoryManager()
        manager.add_provider(provider)
        manager.initialize_all(
            "session-" + identity, hermes_home=str(home), agent_identity=identity,
            agent_context="primary", platform="cli",
        )
        assert provider._beam is not None, "provider initialization failed"
        assert manager.has_tool("mnemosyne_remember_canonical")
        return manager, provider, provider._beam.db_path, get_active_profile_name()
    manager, provider, db_path, host_name = bound(home, initialize)
    managers.append(manager)
    providers.append(provider)
    paths.append(Path(db_path))
    host_names.append(host_name)
assert providers[0] is not providers[1], "fresh discoveries reused one provider"
assert paths[0] != paths[1], "distinct profile targets resolved to one database"
assert all(path.is_relative_to(root) for path in paths)

def write(index, name):
    def dispatch():
        result = json.loads(managers[index].handle_tool_call(
            "mnemosyne_remember_canonical",
            {"category": "q1", "name": name, "body": "synthetic evidence " + name},
        ))
        assert result.get("status") in ("created", "unchanged"), result
        return result
    return bound(homes[index], dispatch)

if layout == "same-home-banks":
    # This host derives profile identity from the home. Two labels supplied to
    # initialize() cannot turn its default identity into two trusted callers.
    # Characterize the real refusal, not an invented bank-authorization path.
    try:
        for index in range(2):
            result = bound(homes[index], lambda: json.loads(
                managers[index].handle_tool_call(
                    "mnemosyne_remember_canonical",
                    {"category": "q1", "name": "denied", "body": "synthetic denied write"},
                )
            ))
            assert result.get("status") == "canonical_owner_mismatch", result
        for path in paths:
            with sqlite3.connect(path) as db:
                exists = db.execute(
                    "SELECT 1 FROM sqlite_master WHERE name='canonical_facts'"
                ).fetchone()
                assert not exists or db.execute(
                    "SELECT COUNT(*) FROM canonical_facts WHERE category='q1'"
                ).fetchone()[0] == 0
        print(json.dumps({
            "layout": layout, "result": "refused_layout",
            "reason": "host default identity does not match bound named owner",
            "non_target_store_checks": True, "gateway_cache_acceptance": False,
            "provenance": provenance,
        }))
    finally:
        for index, manager in enumerate(managers):
            bound(homes[index], manager.shutdown_all)
        guards.close()
    raise SystemExit(0)

# Pause A after the real manager dispatches, immediately before provider code.
# B completes while A is parked; returning A reuses its original manager.
entered, release = threading.Event(), threading.Event()
original = providers[0].handle_tool_call
def parked(name, args, **kwargs):
    if args.get("name") == "a1":
        entered.set()
        assert release.wait(15), "B never released the parked A call"
    return original(name, args, **kwargs)
providers[0].handle_tool_call = parked
try:
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(write, 0, "a1")
        try:
            assert entered.wait(15), "A never reached real provider dispatch"
            write(1, "b1")
        finally:
            release.set()
        future.result(timeout=15)
    write(0, "a2")
    for index, path in enumerate(paths):
        with sqlite3.connect(path) as db:
            rows = db.execute(
                "SELECT name, owner_id, writer_id, writer_home FROM canonical_facts "
                "WHERE category='q1' AND valid_until IS NULL ORDER BY name"
            ).fetchall()
        expected_names = ["a1", "a2"] if index == 0 else ["b1"]
        assert [row[0] for row in rows] == expected_names, rows
        for _, owner, writer, writer_home in rows:
            assert owner == ("profile_a", "profile_b")[index], rows
            assert writer == host_names[index], rows
            assert Path(writer_home) == homes[index], rows
    print(json.dumps({
        "layout": layout, "result": "qualified_manager_path", "discovery": "real Hermes loader",
        "dispatch": "real MemoryManager", "distinct_providers": True,
        "overlap": "A parked, B writes, A resumes and returns",
        "non_target_store_checks": True,
        "gateway_cache_acceptance": False,
        "same_home_writer_identity_distinguished": layout != "same-home-banks",
        "provenance": provenance,
    }))
finally:
    release.set()
    for index, manager in enumerate(managers):
        bound(homes[index], manager.shutdown_all)
    guards.close()
'''
    env = {
        "PATH": os.environ.get("PATH", os.defpath),
        "HOME": str(tmp_path),
        "TMPDIR": str(tmp_path),
        "HERMES_HOME": str(tmp_path / ".hermes"),
        "MNEMOSYNE_DATA_DIR": str(tmp_path / "core-data"),
        "MNEMOSYNE_NO_EMBEDDINGS": "1",
        "MNEMOSYNE_LLM_ENABLED": "false",
        "MNEMOSYNE_HOST_LLM_ENABLED": "false",
        "MNEMOSYNE_AUTO_SLEEP_ENABLED": "false",
        "MNEMOSYNE_Q1_HERMES_SOURCE": str(host),
        "MNEMOSYNE_Q1_HERMES_REVISION": expected,
        "Q1_CANDIDATE": str(candidate), "Q1_CANDIDATE_HEAD": candidate_head,
        "Q1_CANDIDATE_DIRTY": "1" if candidate_dirty else "0",
        "Q1_LAYOUT": layout,
    }
    completed = subprocess.run(
        [sys.executable, "-c", script], cwd=tmp_path, env=env,
        capture_output=True, text=True, timeout=90,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    report = json.loads(completed.stdout.strip().splitlines()[-1])
    assert report["layout"] == layout
    assert report["result"] == (
        "qualified_manager_path" if layout == "separate-homes" else "refused_layout"
    )
    assert report["non_target_store_checks"] is True
    assert report["gateway_cache_acceptance"] is False
    assert report["provenance"]["candidate_commit"] == candidate_head
    assert report["provenance"]["candidate_dirty"] is candidate_dirty
    assert report["provenance"]["host_commit"] == expected
    assert set(report["provenance"]["imported_sources"]) == {
        "mnemosyne.core.beam", "mnemosyne_hermes",
    }
    # Retain validated provenance with `pytest -s` or in a failure report.
    print(json.dumps(report, sort_keys=True))
