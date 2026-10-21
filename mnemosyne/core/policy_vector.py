"""Bounded authorized native vector recall; no global KNN or activation."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Tuple

from mnemosyne.core.policy import AdapterCapabilities, PolicyRefusal, PolicySurface, RefusalReason, _number, _text
from mnemosyne.core.policy_lexical import MAX_SCORING_CHARACTERS
from mnemosyne.core.policy_read import AuthorizedMemory, PolicyReader, _guard_policy_output
from mnemosyne.core.policy_store import PolicyStoreError, RecordKind, StoreErrorCode


CAPABILITIES = AdapterCapabilities("beam-authorized-vector", {PolicySurface.VECTOR})


@dataclass(frozen=True, repr=False)
class AuthorizedVectorHit(AuthorizedMemory):
    score: float
    content_truncated: bool


@dataclass(frozen=True, repr=False)
class AuthorizedVectorRecall:
    hits: Tuple[AuthorizedVectorHit, ...]
    eligible_records: int
    scored_vectors: int
    missing_vectors: int
    embedding_model: str
    embedding_dimension: int
    context_id: str
    context_epoch: int
    decision_id: str


def _require_vector_type(conn, table, dimension):
    row = conn.execute("SELECT sql FROM main.sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
    match = re.search(
        rf"\bUSING\s+vec0\s*\(\s*embedding\s+(float32|int8)\s*\[\s*{dimension}\s*\]\s*\)\s*$",
        row[0], re.I,
    ) if row is not None and row[0] else None
    if match is None:
        raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
    # Exercise the actual extension, not only a DDL string or a default type.
    conn.execute(f"SELECT rowid,embedding FROM main.{table} LIMIT 0")
    if not conn.execute("SELECT vec_version()").fetchone()[0]:
        raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
    return match[1].lower()


@_guard_policy_output
def recall_authorized_vector(beam, query_embedding, *, embedding_model, reader, destination,
                             projects=None, top_k=20, scan_limit=1000):
    from mnemosyne.core.beam import (
        EMBEDDING_DIM, BeamMemory, _cap_recall_content, _embeddings,
        _episodic_recall_where, _vec_float32_blob_cosine, _vec_int8_blob_cosine,
    )

    from .policy_read import AuthorizedRetrievalSession
    if not isinstance(beam, (BeamMemory, AuthorizedRetrievalSession)) or not isinstance(reader, PolicyReader) or reader._store.conn is not beam.conn:
        raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
    _number(top_k, "top_k")
    _number(scan_limit, "scan_limit")
    if not top_k <= 100 or not top_k <= scan_limit <= 1000:
        raise ValueError("top_k and scan_limit exceed supported bounds")
    context, grant, selection = reader._decision(destination, projects)
    if context.conversation_id != beam.session_id or "recall:vector" not in context.operations:
        raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
    if _text(embedding_model, "embedding_model") != _embeddings._DEFAULT_MODEL:
        raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
    if not 1 <= EMBEDDING_DIM <= 4096 or type(query_embedding) not in (list, tuple) or len(query_embedding) != EMBEDDING_DIM:
        raise ValueError("query_embedding must match the bounded configured dimension")
    if any(type(v) not in (float, int) or abs(v) > 3.4028234663852886e38 or not math.isfinite(v) for v in query_embedding):
        raise ValueError("query_embedding must contain finite float32-range numbers")
    if not any(query_embedding):
        raise ValueError("query_embedding must have a nonzero norm")
    try:
        import numpy as np
    except ImportError:
        raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE) from None
    query = np.array(query_embedding, dtype=np.float32).astype(np.float64)
    if not np.any(query):
        raise ValueError("query_embedding must remain nonzero in float32")
    now = datetime.now(timezone.utc).isoformat()
    ranked, eligible_count, scored_count = [], 0, 0
    query_int8 = None
    with reader._store._transaction():
        for kind, table in ((RecordKind.WORKING, "vec_working"), (RecordKind.EPISODIC, "vec_episodes")):
            vector_type = _require_vector_type(beam.conn, table, EMBEDDING_DIM)
            if vector_type == "int8" and query_int8 is None:
                # The SQL quantizer expects unit input; its 'unit' argument is
                # a range declaration, not normalization (sqlite-vec 0.1.9).
                unit = (query / np.linalg.norm(query)).astype(np.float32)
                query_int8 = beam.conn.execute("SELECT vec_quantize_int8(?, 'unit')", (unit.tobytes(),)).fetchone()[0]
                if type(query_int8) is not bytes or len(query_int8) != EMBEDDING_DIM or not np.any(np.frombuffer(query_int8, dtype=np.int8)):
                    raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
            sql, params = reader._selection(kind, context, grant, projects=selection)
            native_where, native_params = _episodic_recall_where(session_id=beam.session_id, now_iso=now, cross_session=False)
            sql += f""", native_eligible AS MATERIALIZED (
                SELECT n.id AS native_id,n.rowid AS native_rowid,e.binding_id,e.policy_id,e.policy_version,e.classification
                FROM eligible AS e JOIN main.{kind.value} AS n ON n.id=e.record_id AND CAST(n.id AS TEXT)=e.record_id
                WHERE {native_where})"""
            params.extend(native_params)
            beam.conn.execute(f"SELECT content FROM main.{kind.value} LIMIT 0")
            ids = beam.conn.execute(sql + " SELECT native_id FROM native_eligible ORDER BY native_id LIMIT ?",
                                    (*params, scan_limit + 1)).fetchall()
            if len(ids) > scan_limit:
                raise PolicyRefusal(RefusalReason.RESOURCE_LIMIT)
            eligible_count += len(ids)
            # CROSS JOIN fixes the authorized outer loop. vec0 receives an exact
            # rowid lookup, never a globally ranked pool followed by filtering.
            vectors = beam.conn.execute(sql + f""" SELECT ne.native_id,ne.binding_id,ne.policy_id,ne.policy_version,ne.classification,
                CASE WHEN typeof(v.embedding)='blob' AND length(v.embedding)=? THEN v.embedding ELSE NULL END
                FROM native_eligible AS ne CROSS JOIN main.{table} AS v ON v.rowid=ne.native_rowid
                ORDER BY ne.native_id""", (*params, (4 if vector_type == "float32" else 1) * EMBEDDING_DIM)).fetchall()
            for row in vectors:
                if row[5] is None:
                    raise PolicyStoreError(StoreErrorCode.INCOMPATIBLE)
                values = np.frombuffer(row[5], dtype=np.float32 if vector_type == "float32" else np.int8)
                if not np.isfinite(values).all() or not np.any(values):
                    raise PolicyStoreError(StoreErrorCode.INCOMPATIBLE)
                score = (_vec_float32_blob_cosine(query, row[5]) if vector_type == "float32"
                         else _vec_int8_blob_cosine(query_int8, row[5]))
                scored_count += 1
                if score > 0:
                    ranked.append((score, kind, tuple(row[:5]), sql, params))
        ranked.sort(key=lambda item: (-item[0], item[1].value, item[2][0]))
        hits = []
        for score, kind, metadata, sql, params in ranked[:top_k]:
            row = beam.conn.execute(sql + f""" SELECT CASE
                WHEN typeof(n.content)='text' AND instr(n.content,char(0))=0 AND length(n.content)<=? THEN n.content ELSE NULL END,
                typeof(n.content),length(n.content),instr(n.content,char(0))
                FROM native_eligible AS ne JOIN main.{kind.value} AS n ON n.id=ne.native_id WHERE ne.native_id=?""",
                (*params, MAX_SCORING_CHARACTERS, metadata[0])).fetchone()
            if row is None or row[1] != "text" or row[3] != 0:
                raise PolicyStoreError(StoreErrorCode.INCOMPATIBLE)
            if row[2] > MAX_SCORING_CHARACTERS:
                raise PolicyRefusal(RefusalReason.RESOURCE_LIMIT)
            content = _cap_recall_content(row[0])
            hits.append(AuthorizedVectorHit(kind, metadata[0], reader._bank, *metadata[1:], grant.decision_id,
                                            context.context_id, context.epoch, content, score, len(content) < len(row[0]),
                                            lifecycle_epoch=grant.lifecycle_epoch))
        final = reader._release(context, grant, selection, destination)
        if grant.lifecycle_epoch is not None:
            hits = [replace(hit, decision_id=final.decision_id) for hit in hits]
        grant = final
    return AuthorizedVectorRecall(tuple(hits), eligible_count, scored_count, eligible_count - scored_count,
                                  embedding_model, EMBEDDING_DIM, context.context_id, context.epoch, grant.decision_id)
