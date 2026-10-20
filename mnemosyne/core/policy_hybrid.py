"""Explicit authorized lexical/vector fusion, never legacy four-voice recall."""

from dataclasses import dataclass
import inspect

from .policy import AdapterCapabilities, PolicyRefusal, PolicySurface, RefusalReason, _number, _text
from .policy_lexical import recall_authorized_lexical
from .policy_read import AuthorizedMemory, BankReadGrant, PolicyReader
from .policy_vector import recall_authorized_vector
from .source_expansion import _clear_traceback_frames
from ..runtime_context import get_access_context


CAPABILITIES = AdapterCapabilities("beam-authorized-hybrid", {PolicySurface.HYBRID, PolicySurface.LEXICAL, PolicySurface.VECTOR})


@dataclass(frozen=True, repr=False)
class AuthorizedHybridHit(AuthorizedMemory):
    score: float
    lexical_rank: int | None
    vector_rank: int | None
    content_truncated: bool


@dataclass(frozen=True, repr=False)
class AuthorizedHybridRecall:
    hits: tuple[AuthorizedHybridHit, ...]
    lexical_examined: int
    lexical_truncated: bool
    vector_eligible: int
    vector_scored: int
    vector_missing: int
    embedding_model: str
    embedding_dimension: int
    context_id: str
    context_epoch: int
    decision_id: str


def _scope(grant):
    return (grant.domain_id, grant.bank, grant.destination, grant.owners, grant.tenants,
            getattr(grant, "projects", None), grant.lifecycle_epoch)


def recall_authorized_hybrid(beam, query, query_embedding, *, embedding_model, reader, destination,
                             projects=None, top_k=20, candidate_limit=200, scan_limit=1000):
    # The worker has unwound before cleanup, so its retained branch hits can
    # actually be released rather than remaining in an active handler frame.
    try:
        return _recall_authorized_hybrid(beam, query, query_embedding, embedding_model=embedding_model,
            reader=reader, destination=destination, projects=projects, top_k=top_k,
            candidate_limit=candidate_limit, scan_limit=scan_limit)
    except BaseException as error:
        _clear_traceback_frames(error)
        raise


def _recall_authorized_hybrid(beam, query, query_embedding, *, embedding_model, reader, destination,
                              projects=None, top_k=20, candidate_limit=200, scan_limit=1000):
    from .beam import BeamMemory

    if not isinstance(beam, BeamMemory) or not isinstance(reader, PolicyReader) or reader._store.conn is not beam.conn:
        raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
    if not isinstance(query, str) or len(query) > 4096:
        raise ValueError("query must be bounded nonblank text")
    query = _text(query.strip(), "query", 4096)
    for name, value in (("top_k", top_k), ("candidate_limit", candidate_limit), ("scan_limit", scan_limit)):
        _number(value, name)
    if not 1 <= top_k <= 100 or not top_k <= candidate_limit <= 1000 or not top_k <= scan_limit <= 1000:
        raise ValueError("hybrid candidate limits exceed supported bounds")
    context, grant, _ = reader._decision(destination, projects)
    if context.conversation_id != beam.session_id or not {
        "recall:hybrid", "recall:lexical", "recall:vector"
    } <= context.operations:
        raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
    fingerprint, scope = context.fingerprint(), _scope(grant)

    def verify(current, **intent):
        fresh = reader._verify(current, **intent)
        if inspect.isawaitable(fresh):
            if inspect.iscoroutine(fresh):
                fresh.close()
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        bound = get_access_context(required=True)
        if (not isinstance(fresh, BankReadGrant) or current.fingerprint() != fingerprint
            or bound.fingerprint() != fingerprint or _scope(fresh) != scope):
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        return fresh

    pinned = PolicyReader(reader._store, bank=reader._bank, verify_context=verify)
    with reader._store._transaction():
        # These native paths each generate authorized candidates before content
        # or scores. The pinned verifier refuses scope changes before their SQL.
        vector = recall_authorized_vector(beam, query_embedding, embedding_model=embedding_model,
            reader=pinned, destination=destination, projects=projects, top_k=top_k, scan_limit=scan_limit)
        pinned._decision(destination, projects)
        lexical = recall_authorized_lexical(beam, query, reader=pinned, destination=destination,
            projects=projects, top_k=top_k, candidate_limit=candidate_limit)
        pinned._decision(destination, projects)
        combined = {}
        for voice, hits in (("lexical", lexical.hits), ("vector", vector.hits)):
            for rank, hit in enumerate(hits, 1):
                key = (hit.record_kind, hit.record_id)
                metadata = (hit.bank, hit.binding_id, hit.policy_id, hit.policy_version, hit.classification,
                            hit.context_id, hit.context_epoch, hit.content, hit.content_truncated, hit.lifecycle_epoch)
                if key in combined:
                    entry = combined[key]
                    if entry[0] != metadata:
                        raise PolicyRefusal(RefusalReason.POLICY_MISMATCH)
                else:
                    entry = combined[key] = [metadata, hit, {}, 0.0]
                entry[2][voice] = rank
                entry[3] += 1.0 / (60 + rank)
        _, final_grant, _ = pinned._decision(destination, projects)
        ranked = sorted(combined.items(), key=lambda item: (-item[1][3], item[0][0].value, str(item[0][1])))
        result = []
        for _, (_, hit, ranks, score) in ranked[:top_k]:
            result.append(AuthorizedHybridHit(hit.record_kind, hit.record_id, hit.bank, hit.binding_id,
                hit.policy_id, hit.policy_version, hit.classification, final_grant.decision_id,
                context.context_id, context.epoch, hit.content, score,
                ranks.get("lexical"), ranks.get("vector"), hit.content_truncated, lifecycle_epoch=final_grant.lifecycle_epoch))
        return AuthorizedHybridRecall(tuple(result), lexical.examined_candidates, lexical.truncated,
            vector.eligible_records, vector.scored_vectors, vector.missing_vectors,
            vector.embedding_model, vector.embedding_dimension, context.context_id, context.epoch,
            final_grant.decision_id)
