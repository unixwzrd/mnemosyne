"""Executable API documentation with an isolated child HOME and no defaults."""

import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys


def test_complete_disposable_protected_example(tmp_path):
    root = Path(__file__).resolve().parents[1]
    env = dict(
        PATH=os.defpath,
        HOME=str(tmp_path),
        MNEMOSYNE_DATA_DIR=str(tmp_path / "data"),
        MNEMOSYNE_NO_EMBEDDINGS="1",
        MNEMOSYNE_LLM_ENABLED="false",
        PYTHONPATH=str(root),
        TMPDIR=str(tmp_path),
    )
    bootstrap = """
import os, runpy, socket, sqlite3, sys
from pathlib import Path
def forbidden(*args, **kwargs):
    raise AssertionError('example network/provider attempt')
socket.socket.connect = socket.socket.connect_ex = socket.getaddrinfo = forbidden
connect = sqlite3.connect
def confined(database, *args, **kwargs):
    assert database == ':memory:' or Path(database).resolve().is_relative_to(Path(os.environ['TMPDIR']).resolve())
    return connect(database, *args, **kwargs)
sqlite3.connect = confined
runpy.run_path(sys.argv[1], run_name='__main__')
"""
    result = subprocess.run(
        [
            sys.executable,
            "-B",
            "-c",
            bootstrap,
            str(root / "examples/protected_memory_demo.py"),
        ],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        timeout=30,
    )
    if not hasattr(sqlite3.Connection, "serialize"):
        assert result.returncode != 0 and "unsupported_surface" in result.stderr
        return
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["synthetic_only"] and report["broader_agent_did_not_expand_access"]
    assert report["denied_matches_absent"] and report["old_host_epoch_refused"]
    assert report["fresh_request_succeeded"] and report["effective_ceiling"] == "team"
    assert report["exact_wire_byte_tokens"] <= report["token_budget"]
    assert report["default_banks_opened"] == report["model_or_source_fetch_calls"] == 0
    assert not list(tmp_path.iterdir())
