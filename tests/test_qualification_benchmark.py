"""Keep the optional offline qualification runner bounded and accountable."""

import json
import importlib.util
import hashlib
import os
import subprocess
import sys
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "qualification_benchmark.py"


def test_offline_benchmark_reports_samples_and_invariants(tmp_path):
    env = {
        "PATH": os.environ.get("PATH", os.defpath), "HOME": str(tmp_path),
        "HERMES_HOME": str(tmp_path / ".hermes"), "TMPDIR": str(tmp_path),
        "PYTHONPATH": str(SCRIPT.parents[1]),
    }
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--samples", "20", "--corpus-size", "128"],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=60,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    report = json.loads(completed.stdout)
    assert report["embedding_calls"] == report["model_calls"] == 0
    assert report["network_attempts"] == 0
    assert report["backend_tripwires"]
    assert report["imported_sources"]["mnemosyne.core.beam"]["path"] == "mnemosyne/core/beam.py"
    assert report["working_rows"] == 128 + report["writes_including_warmup"]
    expected_matches = sorted(
        f"Synthetic engine decision {i}: component sector3 uses sqlite."
        for i in range(128) if i % 8 == 3
    )
    expected_digest = hashlib.sha256(json.dumps(expected_matches, sort_keys=True).encode()).hexdigest()
    assert report["operations"]["recall_match"]["output_sha256"] == expected_digest
    assert report["protected_mode"] == "not implemented; not benchmarked"
    assert len(report["operations"]) == 4
    for operation in report["operations"].values():
        assert len(operation["samples_ms"]) == 20
        assert operation["p50_ms"] <= operation["p95_ms"] <= operation["p99_ms"]
        assert operation["operations_per_second"] > 0
        assert len(operation["output_sha256"]) == 64


@pytest.mark.parametrize("args", [["--samples", "0"], ["--corpus-size", "1001"]])
def test_offline_benchmark_rejects_unbounded_or_empty_workloads(args):
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), *args], capture_output=True, text=True, timeout=10,
    )
    assert completed.returncode != 0
    assert "samples must be 20..1000 and corpus size 32..1000" in completed.stderr


@pytest.mark.parametrize("regression", ["empty-measured-match", "false-miss", "wrong-hash", "wrong-write"])
def test_benchmark_rejects_stable_but_incorrect_results(tmp_path, regression):
    script = '''
import qualification_benchmark as q
from mnemosyne.core.beam import BeamMemory
from mnemosyne.core.media import MediaStore
mode = sys.argv[1]
original_recall = BeamMemory.recall
calls = 0
def recall(self, query, *args, **kwargs):
    global calls
    if query == "sector3":
        calls += 1
        if mode == "empty-measured-match" and calls >= 7:
            return []
    if mode == "false-miss" and query == "nonexistentquasar":
        return [{"content": "unrelated row"}]
    return original_recall(self, query, *args, **kwargs)
BeamMemory.recall = recall
if mode == "wrong-hash":
    MediaStore.get_asset = lambda *args, **kwargs: {"content_hash": "b" * 64}
if mode == "wrong-write":
    original_write = BeamMemory.remember
    def write(self, content, *args, **kwargs):
        return original_write(self, "incorrect write", *args, **kwargs)
    BeamMemory.remember = write
q.benchmark(samples=20, corpus_size=32)
'''
    env = {
        "PATH": os.environ.get("PATH", os.defpath), "HOME": str(tmp_path),
        "HERMES_HOME": str(tmp_path / ".hermes"), "MNEMOSYNE_DATA_DIR": str(tmp_path / "data"),
        "MNEMOSYNE_NO_EMBEDDINGS": "1", "MNEMOSYNE_LLM_ENABLED": "false",
        "PYTHONPATH": os.pathsep.join([str(SCRIPT.parent), str(SCRIPT.parents[1])]),
    }
    completed = subprocess.run(
        [sys.executable, "-c", "import sys\n" + script, regression],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=60,
    )
    assert completed.returncode != 0
    assert "AssertionError" in completed.stderr, completed.stdout + completed.stderr


def load_runner():
    spec = importlib.util.spec_from_file_location("q1_runner", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("method", ["connect_ex", "sendto", "getaddrinfo"])
def test_network_tripwires_catch_attempts_and_restore_methods(method):
    import socket

    owner = socket if method == "getaddrinfo" else socket.socket
    original = getattr(owner, method)
    with pytest.raises(AssertionError, match="network tripwire triggered"):
        with load_runner().offline_guard() as attempts:
            with pytest.raises(AssertionError, match="network access is forbidden"):
                if method == "getaddrinfo":
                    socket.getaddrinfo("example.invalid", 443)
                else:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
                        if method == "sendto":
                            connection.sendto(b"test", ("127.0.0.1", 9))
                        else:
                            connection.connect_ex(("127.0.0.1", 9))
            assert attempts == ["socket"]
    assert getattr(owner, method) is original


@pytest.mark.parametrize("kind", ["embedding", "model"])
def test_backend_tripwires_detect_attempts_even_when_caught(kind):
    from mnemosyne.core import embeddings, local_llm

    with pytest.raises(AssertionError, match="backend tripwire triggered"):
        with load_runner().backend_guard() as (attempts, boundaries):
            with pytest.raises(AssertionError, match=f"{kind} backend is forbidden"):
                if kind == "embedding":
                    embeddings._embed_api(["synthetic"])
                else:
                    local_llm._call_remote_llm_with_model("synthetic", "synthetic")
            assert attempts[kind] == 1
            assert boundaries
