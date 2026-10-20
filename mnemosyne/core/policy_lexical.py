"""Explicit authorized native FTS recall; no hybrid activation or global ranks."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Tuple

from mnemosyne.core.policy import AdapterCapabilities, PolicyRefusal, PolicySurface, RefusalReason, _number, _text
from mnemosyne.core.policy_read import AuthorizedMemory, PolicyReader
from mnemosyne.core.policy_store import PolicyStoreError, RecordKind, StoreErrorCode


CAPABILITIES = AdapterCapabilities("beam-authorized-lexical", {PolicySurface.LEXICAL})
MAX_SCORING_CHARACTERS = 16384


@dataclass(frozen=True, repr=False)
class AuthorizedLexicalHit(AuthorizedMemory):
    score: float
    content_truncated: bool


@dataclass(frozen=True, repr=False)
class AuthorizedLexicalRecall:
    hits: Tuple[AuthorizedLexicalHit, ...]
    candidate_limit: int
    examined_candidates: int
    truncated: bool
    context_id: str
    context_epoch: int
    decision_id: str


def recall_authorized_lexical(beam, query, *, reader, destination, projects=None, top_k=20, candidate_limit=200):
    # Imports are lazy: legacy initialization and direct policy reads do not
    # acquire a dependency on BEAM's optional retrieval backends.
    from mnemosyne.core.beam import (
        BeamMemory, _cap_recall_content, _episodic_recall_where, _fts_precise_terms,
        _fts_query_terms, _has_cjk, _has_cyrillic, _is_bare_literal_flag_collision,
        _lexical_relevance_for_query, _minimum_recall_relevance, _prepare_lexical_query,
        _recall_tokens, _symbolic_code_tokens,
    )

    if not isinstance(beam, BeamMemory) or not isinstance(reader, PolicyReader) or reader._store.conn is not beam.conn:
        raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
    if not isinstance(query, str) or len(query) > 4096:
        raise ValueError("query must be bounded nonblank text")
    query = _text(query.strip(), "query", 4096)
    _number(top_k, "top_k")
    _number(candidate_limit, "candidate_limit")
    if not top_k <= 100 or not top_k <= candidate_limit <= 1000:
        raise ValueError("top_k and candidate_limit exceed supported bounds")
    context, grant, selection = reader._decision(destination, projects)
    if context.conversation_id != beam.session_id or "recall:lexical" not in context.operations:
        raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
    terms = _fts_query_terms(query)
    if len(terms) > 128:
        raise PolicyRefusal(RefusalReason.RESOURCE_LIMIT)
    precise = _fts_precise_terms(query)
    stages = [(terms, candidate_limit)]
    if precise and precise != terms:
        stages = [(_fts_precise_terms(query, widen=False), max(1, candidate_limit // 3)),
                  (precise, max(1, candidate_limit // 2)), (terms, candidate_limit)]
    prepared = _prepare_lexical_query(_recall_tokens(query.lower()), query.lower())
    threshold = _minimum_recall_relevance(_recall_tokens(query.lower()))
    now = datetime.now(timezone.utc).isoformat()
    hits, examined, truncated = [], 0, False
    conn = beam.conn
    with reader._store._transaction():
        for kind, fts, fts_key in ((RecordKind.WORKING, "fts_working", "id"), (RecordKind.EPISODIC, "fts_episodes", "rowid")):
            sql, params = reader._selection(kind, context, grant, projects=selection)
            native_where, native_params = _episodic_recall_where(session_id=beam.session_id, now_iso=now, cross_session=False)
            sql += f""", native_eligible AS MATERIALIZED (
                SELECT n.id AS native_id,n.rowid AS native_rowid,e.binding_id,e.policy_id,e.policy_version,e.classification
                FROM eligible AS e JOIN main.{kind.value} AS n ON n.id=e.record_id AND CAST(n.id AS TEXT)=e.record_id
                WHERE {native_where})"""
            params.extend(native_params)
            # Verify required native mappings even for a valid empty query.
            conn.execute(sql + " SELECT native_id FROM native_eligible LIMIT 0", params)
            conn.execute(f"SELECT {fts_key} FROM main.{fts} LIMIT 0")
            if not terms:
                if _has_cjk(query) or _has_cyrillic(query) or _symbolic_code_tokens(query):
                    raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
                continue
            ordered, seen = [], set()
            native_key = "native_id" if fts_key == "id" else "native_rowid"
            for stage_terms, budget in stages:
                if len(ordered) >= budget:
                    continue
                match_sql = sql + f""" SELECT DISTINCT ne.native_id FROM native_eligible AS ne
                    JOIN main.{fts} ON {fts}.{fts_key}=ne.{native_key}
                    WHERE {fts} MATCH ? ORDER BY ne.native_id LIMIT ?"""
                rows = conn.execute(match_sql, (*params, " OR ".join(stage_terms), budget + 1)).fetchall()
                truncated = truncated or len(rows) > budget
                for row in rows[:budget]:
                    if row[0] not in seen:
                        seen.add(row[0])
                        ordered.append(row[0])
                    if len(ordered) >= budget:
                        break
            examined += len(ordered)
            # Keep combined grant/query parameters below SQLite's historical
            # variable limit, without truncating grants or dropping predicates.
            for start in range(0, len(ordered), 64):
                chunk = ordered[start:start + 64]
                placeholders = ",".join("?" for _ in chunk)
                content_sql = sql + f""" SELECT ne.native_id,ne.binding_id,ne.policy_id,ne.policy_version,ne.classification,
                    CASE WHEN typeof(n.content)='text' AND length(n.content)<=? THEN n.content ELSE NULL END,
                    typeof(n.content),length(n.content)
                    FROM native_eligible AS ne JOIN main.{kind.value} AS n ON n.id=ne.native_id
                    WHERE ne.native_id IN ({placeholders}) ORDER BY ne.native_id"""
                for row in conn.execute(content_sql, (*params, MAX_SCORING_CHARACTERS, *chunk)).fetchall():
                    if row[6] != "text":
                        raise PolicyStoreError(StoreErrorCode.INCOMPATIBLE)
                    if row[7] > MAX_SCORING_CHARACTERS:
                        raise PolicyRefusal(RefusalReason.RESOURCE_LIMIT)
                    text = row[5]
                    score = _lexical_relevance_for_query(prepared, text)
                    if score <= 0 or score < threshold or _is_bare_literal_flag_collision(query, text):
                        continue
                    content = _cap_recall_content(text)
                    hits.append(AuthorizedLexicalHit(kind, row[0], reader._bank, *row[1:5], grant.decision_id,
                                                      context.context_id, context.epoch, content, score, len(content) < len(text)))
    hits.sort(key=lambda hit: (-hit.score, hit.record_kind.value, hit.record_id))
    return AuthorizedLexicalRecall(tuple(hits[:top_k]), candidate_limit, examined, truncated,
                                   context.context_id, context.epoch, grant.decision_id)
