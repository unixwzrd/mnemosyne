"""Budgeted authorized evidence delivery, not a summary or a source fetch."""

from dataclasses import asdict, dataclass
import inspect
import json

from .evidence_packs import build_evidence_pack
from .policy import PolicyRefusal, RefusalReason, _number, _text
from .policy_evidence import EvidenceLease, PolicyEvidence, _consume, _require_consumer
from .policy_read import AuthorizedMemory, _guard_policy_output
from .protected_session import ProtectedSession
from ..runtime_context import get_access_context


@dataclass(frozen=True, repr=False)
class CompactCandidate:
    """Host-supplied, already authorized provenance; never an access grant."""

    lease: EvidenceLease
    group_id: str | None = None
    timestamp: str | None = None

    def __post_init__(self):
        if type(self.lease) is not EvidenceLease:
            raise TypeError("exact evidence lease required")
        if self.group_id is not None:
            _text(self.group_id, "group_id")
        if self.timestamp is not None:
            _text(self.timestamp, "timestamp", 128)


@dataclass(frozen=True, repr=False)
class CompactRecallReceipt:
    tokenizer_id: str
    tokens: int
    primary_items: int
    supplemental_items: int
    omitted_items: int
    excerpt_characters: int
    scope_fingerprint: str


def _candidate_rows(values):
    if (
        type(values) not in (tuple, list)
        or len(values) > 32
        or any(type(value) is not CompactCandidate for value in values)
    ):
        raise TypeError("explicit bounded compact candidates required")
    return [
        {
            "id": value.lease.record_id,
            "tier": value.lease.record_kind.value,
            "group_id": value.group_id,
            "timestamp": value.timestamp,
            "candidate": value,
        }
        for value in values
    ]


class CompactRecall:
    """Use exact host token counting and fresh evidence checks before delivery.

    A trusted tokenizer identity and synchronous deterministic counter must be
    supplied explicitly. There is no estimated-token fallback or provider call.
    """

    def __init__(self, evidence, *, tokenizer_id, count_tokens):
        if type(evidence) not in (PolicyEvidence, ProtectedSession):
            raise TypeError("explicit policy evidence or protected session required")
        _text(tokenizer_id, "tokenizer_id")
        if not callable(count_tokens) or any(
            check(target)
            for target in (count_tokens, getattr(count_tokens, "__call__", None))
            for check in (
                inspect.iscoroutinefunction,
                inspect.isgeneratorfunction,
                inspect.isasyncgenfunction,
            )
        ):
            raise TypeError("trusted synchronous token counter required")
        self._evidence = evidence
        self._tokenizer_id = tokenizer_id
        self._count_tokens = count_tokens

    def _count(self, wire):
        value = self._count_tokens(wire)
        if inspect.iscoroutine(value) or inspect.isgenerator(value):
            value.close()
        if type(value) is not int or not 0 <= value <= 2**63 - 1:
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        return value

    def _wire(self, primary, supplemental, totals):
        return json.dumps(
            {
                "version": 1,
                "tokenizer_id": self._tokenizer_id,
                "primary": primary,
                "evidence_pack": supplemental,
                "omitted_primary": totals[0] - len(primary),
                "omitted_supplemental": totals[1] - len(supplemental),
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )

    def _connection(self):
        conn = (
            self._evidence.reader._store.conn
            if type(self._evidence) is PolicyEvidence
            else self._evidence._conn
        )
        if conn is None:
            raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)
        if conn.in_transaction:
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        return conn

    def _batch(self, candidates):
        # Match the existing cooperative stream's native-change fence. A later
        # lease read must not hide a correction to an earlier checked record.
        conn = self._connection()

        def version():
            return (
                conn.execute("PRAGMA main.data_version").fetchone()[0],
                conn.execute("PRAGMA main.schema_version").fetchone()[0],
                conn.total_changes,
            )

        before = version()
        values = tuple(
            self._evidence.resolve(candidate.lease) for candidate in candidates
        )
        if before != version() or self._connection() is not conn:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        return values

    @_guard_policy_output
    def deliver(
        self,
        primary,
        candidates,
        consumer,
        *,
        token_budget=4096,
        max_supplemental=5,
        max_excerpt_characters=4096,
    ):
        _require_consumer(consumer)
        for name, value, maximum in (
            ("token_budget", token_budget, 65536),
            ("max_excerpt_characters", max_excerpt_characters, 16384),
        ):
            if _number(value, name) > maximum:
                raise ValueError("compact recall budget exceeds supported bounds")
        if type(max_supplemental) is not int or not 0 <= max_supplemental <= 32:
            raise ValueError("invalid supplemental limit")
        primary_rows, candidate_rows = (
            _candidate_rows(primary),
            _candidate_rows(candidates),
        )
        supplied = [*primary, *candidates]
        if not 1 <= len(supplied) <= 32:
            raise ValueError("compact recall requires 1..32 explicit candidates")
        keys = [(v.lease.record_kind, v.lease.record_id) for v in supplied]
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate compact evidence identity")
        first = supplied[0].lease
        if any(
            (
                v.lease.scope_fingerprint,
                v.lease.bank,
                v.lease.destination,
                v.lease.projects,
                v.lease.lifecycle_epoch,
            )
            != (
                first.scope_fingerprint,
                first.bank,
                first.destination,
                first.projects,
                first.lifecycle_epoch,
            )
            for v in supplied
        ):
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        fingerprint = get_access_context(required=True).fingerprint()
        # No arbitrary result dictionary or caller-provided excerpt is trusted.
        # Resolve every supplied lease, including candidates later not selected.
        hits = {}
        for hit in self._batch(supplied):
            if type(hit) is not AuthorizedMemory:
                raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
            if type(hit.content) is not str or len(hit.content) > 16384:
                raise PolicyRefusal(RefusalReason.RESOURCE_LIMIT)
            hits[(hit.record_kind.value, hit.record_id)] = hit
        pack = build_evidence_pack(
            primary_rows,
            candidate_rows,
            max_items=max_supplemental,
            group_key="group_id",
        )
        totals = (len(pack["primary"]), len(candidate_rows))
        output = {"primary": [], "evidence_pack": []}
        initial = self._wire([], [], totals)
        if self._count(initial) > token_budget:
            raise PolicyRefusal(RefusalReason.RESOURCE_LIMIT)
        selected = []
        for section in ("primary", "evidence_pack"):
            for row in pack[section]:
                candidate = row["candidate"]
                lease = candidate.lease
                hit = hits[(row["tier"], row["id"])]
                metadata = asdict(lease)
                metadata["record_kind"] = lease.record_kind.value
                metadata["projects"] = (
                    None if lease.projects is None else sorted(lease.projects)
                )
                length = min(len(hit.content), max_excerpt_characters)
                while True:
                    item = {
                        "lease": metadata,
                        "group_id": candidate.group_id,
                        "timestamp": candidate.timestamp,
                        "excerpt": hit.content[:length],
                        "original_characters": len(hit.content),
                        "content_truncated": length < len(hit.content),
                    }
                    trial = {name: list(values) for name, values in output.items()}
                    trial[section].append(item)
                    wire = self._wire(trial["primary"], trial["evidence_pack"], totals)
                    if self._count(wire) <= token_budget:
                        output = trial
                        selected.append(candidate)
                        break
                    if length <= 1:
                        break
                    # BPE lengths are not monotone in character-prefix length.
                    # This is bounded geometric clipping, not binary search or
                    # a claim of maximal budget utilization. Every trial is exact.
                    length //= 2
        wire = self._wire(output["primary"], output["evidence_pack"], totals)
        tokens = self._count(wire)
        if tokens > token_budget or self._count(wire) != tokens:
            raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)
        # Tokenizers and packing are host callbacks/work: reauthorize after all
        # of it. No prior successful lookup grants delivery under a new ceiling.
        self._batch(supplied)
        if get_access_context(required=True).fingerprint() != fingerprint:
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        _consume(consumer, wire)
        return CompactRecallReceipt(
            self._tokenizer_id,
            tokens,
            len(output["primary"]),
            len(output["evidence_pack"]),
            len(supplied) - len(selected),
            sum(len(item["excerpt"]) for values in output.values() for item in values),
            first.scope_fingerprint,
        )
