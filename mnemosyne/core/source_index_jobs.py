"""Explicit model-bound owner jobs; no implicit providers or protected mode."""

from dataclasses import dataclass, field, replace
import hashlib
import json

from .source_embedding_store import EmbeddingContract, SourceEmbeddingStore, _contract
from .source_index_generations import IndexGeneration, SourceIndexGenerations, _decode, _digest, _sql_ascii
from .source_index_store import SourceIndexStoreError, _key, _shape, _sql_int


_JOBS = "media_source_index_embedding_jobs"
_DDL = f"""CREATE TABLE {_JOBS} (
    generation_id TEXT PRIMARY KEY NOT NULL REFERENCES media_source_index_generations(generation_id),
    job_key TEXT NOT NULL,
    sharing_domain TEXT NOT NULL,
    model_identity TEXT NOT NULL,
    dimensions INTEGER NOT NULL,
    preprocessing_sha256 TEXT NOT NULL
)"""


def _generation_key(source_key, job_key, contract):
    payload = ["source-index-job:v1", source_key, job_key, contract.sharing_domain,
               contract.model_identity, contract.dimensions, contract.preprocessing_sha256]
    return "embedding:" + hashlib.sha256(json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("ascii")).hexdigest()


@dataclass(frozen=True)
class SourceIndexJob:
    generation: IndexGeneration = field(repr=False)
    contract: EmbeddingContract = field(repr=False)
    job_key: str = field(repr=False)
    embedding_ready: bool = False


@dataclass(frozen=True)
class IndexJobWrite:
    job: SourceIndexJob = field(repr=False)
    status: str
    transaction_state: str


class SourceIndexJobs:
    """Owner orchestration over immutable evidence, artifacts and checkpoints."""

    def __init__(self, conn):
        self.generations = SourceIndexGenerations(conn)
        self.embeddings = SourceEmbeddingStore(conn)
        self.store = self.embeddings.store
        self.conn = conn

    def _schema(self, *, create=False):
        if self.conn.execute("SELECT 1 FROM temp.sqlite_master WHERE name=?", (_JOBS,)).fetchone():
            raise SourceIndexStoreError("incompatible-index-job-schema")
        row = self.conn.execute("SELECT type,sql FROM main.sqlite_master WHERE name=?", (_JOBS,)).fetchone()
        if not self.generations._schema():
            if row is not None:
                raise SourceIndexStoreError("invalid-index-job-record")
            return False
        if row is None:
            if not create:
                return False
            self.conn.execute(_DDL.replace("CREATE TABLE ", "CREATE TABLE main.", 1))
            return self._schema()
        if row[0] != "table" or _shape(row[1]) != _shape(_DDL):
            raise SourceIndexStoreError("incompatible-index-job-schema")
        for schema in ("main", "temp"):
            if self.conn.execute(f"SELECT 1 FROM {schema}.sqlite_master WHERE tbl_name=? "
                "AND (type='trigger' OR (type='index' AND sql IS NOT NULL)) LIMIT 1", (_JOBS,)).fetchone():
                raise SourceIndexStoreError("incompatible-index-job-schema")
        if self.conn.execute(f"SELECT 1 FROM main.{_JOBS} j WHERE NOT EXISTS "
            "(SELECT 1 FROM main.media_source_index_generations g WHERE g.generation_id=j.generation_id) LIMIT 1").fetchone():
            raise SourceIndexStoreError("invalid-index-job-record")
        return True

    def _record(self, generation_id):
        generation = self.generations.get(generation_id)
        if generation is None:
            return None
        row = self.conn.execute(f"""SELECT {_sql_ascii('job_key', 128)}, {_sql_ascii('sharing_domain', 128)},
            {_sql_ascii('model_identity', 256)}, {_sql_int('dimensions')}, {_sql_ascii('preprocessing_sha256', 64)}
            FROM main.{_JOBS} WHERE generation_id=?""", (generation_id,)).fetchone()
        if row is None:
            if generation.generation_key.startswith("embedding:"):
                raise SourceIndexStoreError("invalid-index-job-record")
            return None
        try:
            job_key, domain, model, preprocessing = map(_decode, (row[0], row[1], row[2], row[4]))
            _key(job_key)
            contract = EmbeddingContract(domain, model, row[3], preprocessing)
            if generation.generation_key != _generation_key(generation.source_key, job_key, contract):
                raise ValueError
        except (TypeError, ValueError, SourceIndexStoreError):
            raise SourceIndexStoreError("invalid-index-job-record") from None
        return SourceIndexJob(generation, contract, job_key)

    def begin(self, source_key, job_key, fingerprints, *, contract):
        source_key, job_key, contract = _key(source_key), _key(job_key), _contract(contract)
        with self.store._transaction(write=True) as owns:
            # Audit reserved objects before native begin could create schema.
            self._schema()
            receipt = self.generations.begin(source_key, _generation_key(source_key, job_key, contract), fingerprints)
            self._schema(create=True)
            if receipt.status == "created":
                self.conn.execute(f"INSERT INTO main.{_JOBS} VALUES(?,?,?,?,?,?)", (receipt.generation_id, job_key,
                    contract.sharing_domain, contract.model_identity, contract.dimensions, contract.preprocessing_sha256)).fetchall()
            job = self._record(receipt.generation_id)
            if job is None:
                raise SourceIndexStoreError("invalid-index-job-record")
            if job.job_key != job_key or job.contract != contract:
                raise SourceIndexStoreError("index-job-conflict")
            return IndexJobWrite(job, receipt.status, "committed" if owns else "pending")

    def get(self, generation_id):
        generation_id = _digest(generation_id)
        with self.store._transaction():
            if not self._schema():
                generation = self.generations.get(generation_id)
                if generation is not None and generation.generation_key.startswith("embedding:"):
                    raise SourceIndexStoreError("invalid-index-job-record")
                return None
            return self._record(generation_id)

    def exclude(self, generation_id, fingerprint, *, reason):
        with self.store._transaction(write=True) as owns:
            if self.get(generation_id) is None:
                raise SourceIndexStoreError("index-job-not-found")
            receipt = self.generations.checkpoint(generation_id, fingerprint, state="excluded", reason=reason)
            return replace(receipt, transaction_state="committed" if owns else "pending")

    def _check_item(self, job, fingerprint):
        plan = self.store.get_plan(fingerprint)
        if plan is None:
            raise SourceIndexStoreError("index-job-incomplete")
        plans = self.store._audit(job.generation.source_key)[1]
        if fingerprint not in plans:
            raise SourceIndexStoreError("index-job-incomplete")
        for ordinal in range(len(plan.excerpts)):
            artifact = self.embeddings.get(job.generation.source_key, fingerprint, ordinal, contract=job.contract)
            if artifact is None or not self.conn.execute(
                "SELECT 1 FROM main.media_source_embedding_bindings WHERE fingerprint=? AND ordinal=? AND cache_id=?",
                (fingerprint, ordinal, artifact.cache_id),
            ).fetchone():
                raise SourceIndexStoreError("index-job-incomplete")

    def _ready(self, job):
        for item in job.generation.items:
            if item.state == "excluded":
                continue
            if item.state != "completed":
                raise SourceIndexStoreError("index-job-incomplete")
            self._check_item(job, item.fingerprint)
        return replace(job, embedding_ready=True)

    def current(self, source_key):
        source_key = _key(source_key)
        with self.store._transaction():
            exists = self._schema()
            generation = self.generations.current(source_key)
            if generation is None:
                return None
            if not exists:
                if generation.generation_key.startswith("embedding:"):
                    raise SourceIndexStoreError("invalid-index-job-record")
                return None
            if (job := self._record(generation.generation_id)) is None:
                return None
            return self._ready(job)

    def run(self, generation_id, *, compute):
        if self.conn.in_transaction:
            raise SourceIndexStoreError("index-job-callback-in-transaction")
        if not callable(compute):
            raise SourceIndexStoreError("invalid-index-job-input")
        job = self.get(generation_id)
        if job is None:
            raise SourceIndexStoreError("index-job-not-found")
        current = self.generations.current(job.generation.source_key)
        current_id = current.generation_id if current else None
        if job.generation.state == "published":
            if current_id != generation_id:
                raise SourceIndexStoreError("stale-generation-parent")
            active = self.current(job.generation.source_key)
            if active is None or active.generation.generation_id != generation_id:
                raise SourceIndexStoreError("stale-generation-parent")
            return active
        if current_id != job.generation.parent_id:
            raise SourceIndexStoreError("stale-generation-parent")
        for item in job.generation.items:
            if item.state == "excluded":
                continue
            try:
                plan = self.store.get_plan(item.fingerprint)
                if plan is None:
                    raise SourceIndexStoreError("index-job-incomplete")
                for ordinal in range(len(plan.excerpts)):
                    self.embeddings.materialize(job.generation.source_key, item.fingerprint, ordinal,
                                                contract=job.contract, compute=compute)
                with self.store._transaction(write=True):
                    self._check_item(job, item.fingerprint)
                    self.generations.checkpoint(generation_id, item.fingerprint)
            except BaseException as error:
                if not self.conn.in_transaction:
                    try:
                        self.generations.checkpoint(generation_id, item.fingerprint, state="failed",
                            reason="unavailable" if isinstance(error, Exception) else "interrupted")
                    except BaseException:
                        pass
                raise
        with self.store._transaction(write=True):
            fresh = self.get(generation_id)
            if fresh is None:
                raise SourceIndexStoreError("index-job-not-found")
            ready = self._ready(fresh)
            self.generations.publish(generation_id)
            return replace(ready, generation=self.generations.get(generation_id))
