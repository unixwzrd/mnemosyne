"""Small, offline baseline. Emits samples, invariants and provenance as JSON."""

from __future__ import annotations

import argparse
from contextlib import contextmanager, ExitStack
import hashlib
import json
import math
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

try:
    import resource
except ImportError:
    resource = None


def percentile(values, percent):
    return sorted(values)[max(0, math.ceil(len(values) * percent / 100) - 1)]


def module_record(module, repository):
    path = Path(module.__file__).resolve()
    assert path.is_relative_to(repository), f"unexpected imported source: {path}"
    return {"path": str(path.relative_to(repository)), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


@contextmanager
def offline_guard():
    """Python socket tripwires, not an OS/process-level network sandbox."""
    import socket

    attempts = []

    def forbidden(*args, **kwargs):
        attempts.append("socket")
        raise AssertionError("network access is forbidden in Q1 qualification")

    with ExitStack() as stack:
        for name in ("connect", "connect_ex", "send", "sendall", "sendto", "sendmsg"):
            if hasattr(socket.socket, name):
                stack.enter_context(patch.object(socket.socket, name, forbidden))
        for name in ("create_connection", "getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr"):
            stack.enter_context(patch.object(socket, name, forbidden))
        yield attempts
        assert not attempts, f"network tripwire triggered {len(attempts)} time(s)"


@contextmanager
def backend_guard():
    from mnemosyne.core import embeddings, llm_backends, local_llm

    attempts = {"embedding": 0, "model": 0}
    targets = {
        "embedding": [(embeddings, "_get_model"), (embeddings, "_embed_api")],
        "model": [(local_llm, name) for name in (
            "_download_model", "_load_llm_llamacpp", "_load_llm_ctransformers",
            "_call_remote_llm_with_model",
        )] + [(llm_backends, "call_host_llm")],
    }

    def forbidden(kind):
        def call(*args, **kwargs):
            attempts[kind] += 1
            raise AssertionError(f"{kind} backend is forbidden in Q1 qualification")
        return call

    with ExitStack() as stack:
        for kind, boundaries in targets.items():
            for module, name in boundaries:
                stack.enter_context(patch.object(module, name, forbidden(kind)))
        yield attempts, [f"{module.__name__}.{name}" for boundaries in targets.values() for module, name in boundaries]
        assert not any(attempts.values()), f"backend tripwire triggered: {attempts}"


def benchmark(samples=100, corpus_size=128, source=None):
    if not 20 <= samples <= 1000 or not 32 <= corpus_size <= 1000:
        raise ValueError("samples must be 20..1000 and corpus size 32..1000")
    runner = Path(__file__).resolve()
    repository = Path(source).expanduser().resolve() if source is not None else runner.parents[1]
    if not (repository / "mnemosyne/core/beam.py").is_file():
        raise ValueError("source must be a Mnemosyne Git checkout")
    with ExitStack() as guards, tempfile.TemporaryDirectory(prefix="mnemosyne-q1-") as temporary:
        root = Path(temporary)
        # Select only disposable storage BEFORE importing the engine.
        guards.enter_context(patch.dict(os.environ, {
            "PATH": os.environ.get("PATH", os.defpath),
            "HOME": str(root), "HERMES_HOME": str(root / ".hermes"),
            "MNEMOSYNE_DATA_DIR": str(root / "data"),
            "MNEMOSYNE_NO_EMBEDDINGS": "1", "MNEMOSYNE_LLM_ENABLED": "false",
            "MNEMOSYNE_HOST_LLM_ENABLED": "false", "MNEMOSYNE_AUTO_SLEEP_ENABLED": "false",
        }, clear=True))
        guards.enter_context(patch.object(sys, "path", [str(repository), *sys.path]))
        network_attempts = guards.enter_context(offline_guard())
        from mnemosyne.core import beam as beam_module, embeddings, local_llm, media as media_module
        from mnemosyne import __version__
        from mnemosyne.core.beam import BeamMemory
        from mnemosyne.core.media import MediaStore

        imported = {module.__name__: module_record(module, repository) for module in (
            beam_module, embeddings, local_llm, media_module,
        )}
        backend_attempts, boundaries = guards.enter_context(backend_guard())

        beam = BeamMemory(session_id="qualification", db_path=root / "memory.db")
        guards.callback(beam.conn.close)
        items = [{
            "content": f"Synthetic engine decision {i}: component sector{i % 8} uses sqlite.",
            "source": "qualification", "importance": 0.5,
        } for i in range(corpus_size)]
        beam.remember_batch(items)
        media = MediaStore(db_path=root / "media.db")
        guards.callback(media.conn.close)
        asset = media.upsert_asset(
            ref_kind="url", ref_value="https://example.invalid/evidence",
            modality="document", content_hash="a" * 64,
        )
        writes = 0

        def write():
            nonlocal writes
            writes += 1
            result = beam.remember(
                f"Synthetic qualification addition {writes} about retention.",
                source="qualification", scope="global",
            )
            return result

        expected_match = {item["content"] for item in items if "sector3" in item["content"]}

        def validate(name, result):
            if name == "recall_match":
                assert len(result) == len(expected_match) and set(result) == expected_match, result
                # Equal-relevance ties may have a different order in fresh stores.
                # Compare the full known match set, not a varying top-k subset.
                return sorted(result)
            elif name == "recall_no_lexical_match":
                assert result == [], result
            elif name == "reference_lookup":
                assert result == "a" * 64, result
            else:
                assert result is not None, "write returned no ID"
                row = beam.conn.execute(
                    "SELECT content, source, scope, session_id FROM working_memory WHERE id=?", (result,),
                ).fetchone()
                assert tuple(row or ()) == (
                    f"Synthetic qualification addition {writes} about retention.",
                    "qualification", "global", "qualification",
                ), row
                # Normalize the deliberately unique ID only AFTER validating its row.
                return "stored"
            return result

        operations = {
            "recall_match": lambda: [row["content"] for row in beam.recall(
                "sector3", top_k=len(expected_match), _track_recall=False,
            )],
            "recall_no_lexical_match": lambda: [row["content"] for row in beam.recall(
                "nonexistentquasar", top_k=5, _track_recall=False,
            )],
            "reference_lookup": lambda: media.get_asset(asset.asset_id)["content_hash"],
            "write": write,
        }
        measurements = {}
        for name, operation in operations.items():
            cold_start = time.perf_counter_ns()
            cold_result = operation()
            cold_ms = (time.perf_counter_ns() - cold_start) / 1e6
            validate(name, cold_result)
            for _ in range(5):
                validate(name, operation())
            durations, digests = [], set()
            for _ in range(samples):
                start = time.perf_counter_ns()
                result = operation()
                durations.append((time.perf_counter_ns() - start) / 1e6)
                normalized = validate(name, result)
                digests.add(hashlib.sha256(json.dumps(normalized, sort_keys=True).encode()).hexdigest())
            assert len(digests) == 1, f"unstable output from {name}"
            measurements[name] = {
                "first_call_ms": cold_ms, "samples_ms": durations,
                "p50_ms": statistics.median(durations),
                "p95_ms": percentile(durations, 95), "p99_ms": percentile(durations, 99),
                "operations_per_second": samples / (sum(durations) / 1000),
                "output_sha256": next(iter(digests)),
            }
        count = beam.conn.execute("SELECT COUNT(*) FROM working_memory").fetchone()[0]
        assert count == corpus_size + writes, (count, corpus_size, writes)
        head = subprocess.check_output(
            ["git", "-C", str(repository), "rev-parse", "HEAD"], text=True,
        ).strip()
        dirty = bool(subprocess.check_output(
            ["git", "-C", str(repository), "status", "--porcelain"], text=True,
        ).strip())
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss if resource else None
        report = {
            "schema": 1, "source_commit": head, "source_dirty": dirty,
            "runner_sha256": hashlib.sha256(runner.read_bytes()).hexdigest(),
            "imported_sources": imported,
            "package_version": __version__, "python": platform.python_version(),
            "platform": platform.platform(), "machine": platform.machine(),
            "dataset_sha256": hashlib.sha256(json.dumps(items, sort_keys=True).encode()).hexdigest(),
            "corpus_size": corpus_size, "samples_per_operation": samples,
            "policy_mode": "legacy", "query_mode": "lexical; embeddings disabled",
            "embedding_calls": backend_attempts["embedding"], "model_calls": backend_attempts["model"],
            "backend_tripwires": boundaries, "network_attempts": len(network_attempts),
            "isolation_note": "Python socket/backend tripwires; not a process sandbox",
            "injected_tokens": None, "injected_tokens_note": "not a prompt-packing workload",
            "working_rows": count, "writes_including_warmup": writes,
            "database_bytes": sum(p.stat().st_size for p in root.rglob("*.db*")),
            "peak_process_bytes": peak if peak is None or sys.platform == "darwin" else peak * 1024,
            "peak_process_note": "unavailable on this platform" if peak is None else "process high-water mark, not per-operation allocation",
            "quality": "per-call synthetic match/miss/hash and stored-row oracles; deterministic output hashes",
            "protected_mode": "not implemented; not benchmarked",
            "operations": measurements,
        }
        return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=100)
    parser.add_argument("--corpus-size", type=int, default=128)
    parser.add_argument("--source", type=Path, help="explicit candidate Git checkout; defaults to this repository")
    args = parser.parse_args()
    print(json.dumps(benchmark(args.samples, args.corpus_size, args.source), indent=2))
