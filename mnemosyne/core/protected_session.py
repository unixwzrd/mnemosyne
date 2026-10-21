"""Explicit audited owner reads; no legacy handler or automatic adapter fallback."""

import inspect
import sqlite3
import uuid

from .policy import AdapterCapabilities, PolicyRefusal, PolicySurface, RefusalReason
from .policy_audit import PolicyAudit, PolicyAuditEvent
from .policy_evidence import PolicyEvidence, _consume, _require_consumer
from .policy_read import (
    AuthorizedRetrievalSession,
    BankReadGrant,
    PolicyReader,
    ProjectReadGrant,
    _guard_policy_output,
)
from .policy_store import PolicyStore
from .protected_repository import ProtectedRepository
from ..runtime_context import get_access_context


class ProtectedSession:
    """Owner-only read facade over one exact encrypted generation.

    Construction requires authenticated host context and current host grants.
    No key, SQL, raw connection, policy mutation or legacy adapter is exposed by
    the dispatch allowlist. The caller closes this session, including on cancel.
    """

    capabilities = AdapterCapabilities(
        "protected-owner-session",
        {
            PolicySurface.DIRECT,
            PolicySurface.CACHE,
            PolicySurface.INJECT,
            PolicySurface.LEXICAL,
            PolicySurface.VECTOR,
            PolicySurface.HYBRID,
        },
    )

    def __init__(
        self, repository, store_id, *, destination, verify_context, audit, projects=None
    ):
        if (
            type(repository) is not ProtectedRepository
            or type(audit) is not PolicyAudit
        ):
            raise TypeError("explicit owner repository and audit required")
        if not callable(verify_context) or inspect.iscoroutinefunction(verify_context):
            raise TypeError("trusted synchronous host verifier required")
        self._conn = None
        self._repository = repository
        self._checkpoint = repository._current(store_id)
        self._verify_host = verify_context
        self._audit = audit
        self._destination = destination
        ctx = get_access_context(required=True)
        self._projects = (
            None if projects is None else ctx.narrow(projects=projects).projects
        )
        bank = self._checkpoint.identity.bank
        operation = "read:bank" if self._projects is None else "read:projects"
        if (
            ctx.assurance != "authenticated"
            or bank not in ctx.banks
            or destination not in ctx.destinations
            or operation not in ctx.operations
            or (self._projects is None and ctx.projects)
            or audit._bank != bank
            or audit._domain_id != self._checkpoint.identity.domain_id
        ):
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        # Authenticate and narrow using metadata before decrypting any memory.
        self._verify(
            ctx,
            bank=bank,
            destination=destination,
            **({} if self._projects is None else {"projects": self._projects}),
        )
        conn, checkpoint = repository.open_current(store_id)
        try:
            if checkpoint != self._checkpoint:
                raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
            reader = PolicyReader(
                PolicyStore(conn), bank=bank, verify_context=self._verify
            )
            reader._decision(destination, self._projects)
            self._reader = reader
            self._evidence = PolicyEvidence(reader)
            self._conn = conn
        except BaseException:
            conn.close()
            raise

    def _current(self):
        if (
            self._repository._current(self._checkpoint.identity.store_id)
            != self._checkpoint
        ):
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)

    def _verify(self, context, **intent):
        self._current()
        try:
            grant = self._verify_host(context, **intent)
        except PolicyRefusal:
            raise
        except Exception:
            raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE) from None
        if inspect.isawaitable(grant):
            if inspect.iscoroutine(grant):
                grant.close()
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        identity = self._checkpoint.identity
        if (
            not isinstance(grant, BankReadGrant)
            or grant.context_fingerprint != context.fingerprint()
            or get_access_context(required=True).fingerprint() != context.fingerprint()
            or (grant.domain_id, grant.bank, grant.destination, grant.lifecycle_epoch)
            != (
                identity.domain_id,
                identity.bank,
                self._destination,
                identity.lifecycle_epoch,
            )
        ):
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        selection = intent.get("projects")
        if (selection is None and isinstance(grant, ProjectReadGrant)) or (
            selection is not None
            and (not isinstance(grant, ProjectReadGrant) or grant.projects != selection)
        ):
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)
        self._current()
        return grant

    def close(self):
        conn, self._conn = self._conn, None
        if conn is not None:
            conn.close()

    def __enter__(self):
        if self._conn is None:
            raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)
        self._current()
        return self

    def __exit__(self, *args):
        self.close()

    def _event(self, context, grant, operation, surface, *, reason=None):
        return PolicyAuditEvent.from_context(
            context,
            event_id="event:" + uuid.uuid4().hex,
            decision_id=grant.decision_id,
            surface=surface,
            bank=self._checkpoint.identity.bank,
            destination=self._destination,
            lifecycle_epoch=self._checkpoint.identity.lifecycle_epoch,
            result="allow" if reason is None else "deny",
            operation=operation,
            reason=reason,
        )

    def _admit(self, operation, surface):
        if self._conn is None:
            raise PolicyRefusal(RefusalReason.CONTEXT_UNAVAILABLE)
        context, grant, selection = self._reader._decision(
            self._destination, self._projects
        )
        event = self._event(context, grant, operation, surface)
        self._audit.admit(event, lambda _: None)
        # Audit I/O may yield time for a grant/generation change. Check again
        # before entering the candidate generator or handing bytes to a consumer.
        fresh = self._reader._release(context, grant, selection, self._destination)
        return context, fresh, selection

    @_guard_policy_output
    def _run(self, operation, surface, action):
        context, grant, selection = self._admit(operation, surface)
        try:
            result = action()
            self._reader._release(context, grant, selection, self._destination)
            return result
        except PolicyRefusal as error:
            try:
                self._audit.admit(
                    self._event(
                        context, grant, operation, surface, reason=error.reason
                    ),
                    lambda _: None,
                )
            except PolicyRefusal as denial:
                if denial.reason is not RefusalReason.ACCESS_DENIED:
                    raise
            raise

    def get(self, kind, record_id):
        return self._run(
            "get",
            PolicySurface.DIRECT,
            lambda: self._reader.get(
                kind, record_id, destination=self._destination, projects=self._projects
            ),
        )

    def candidates(self, kind, *, limit=100, offset=0):
        return self._run(
            "candidates",
            PolicySurface.DIRECT,
            lambda: self._reader.candidate_ids(
                kind,
                destination=self._destination,
                projects=self._projects,
                limit=limit,
                offset=offset,
            ),
        )

    def source_metadata(self, revision_id):
        if self._projects is not None:
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        return self._run(
            "source_metadata",
            PolicySurface.DIRECT,
            lambda: self._reader.get_source_revision(
                revision_id, destination=self._destination
            ),
        )

    def _native(self):
        conversation = get_access_context(required=True).conversation_id
        if conversation is None:
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        return AuthorizedRetrievalSession(self._conn, conversation)

    def _vector_extension(self):
        try:
            import sqlite_vec
        except ImportError:
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE) from None
        try:
            self._conn.enable_load_extension(True)
            sqlite_vec.load(self._conn)
        except (AttributeError, sqlite3.Error):
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE) from None
        finally:
            self._conn.enable_load_extension(False)

    def lexical(self, query, *, top_k=20, candidate_limit=200):
        from .policy_lexical import recall_authorized_lexical

        return self._run(
            "lexical",
            PolicySurface.LEXICAL,
            lambda: recall_authorized_lexical(
                self._native(),
                query,
                reader=self._reader,
                destination=self._destination,
                projects=self._projects,
                top_k=top_k,
                candidate_limit=candidate_limit,
            ),
        )

    def vector(self, query_embedding, *, embedding_model, top_k=20, scan_limit=1000):
        from .policy_vector import recall_authorized_vector

        def recall():
            self._vector_extension()
            return recall_authorized_vector(
                self._native(),
                query_embedding,
                embedding_model=embedding_model,
                reader=self._reader,
                destination=self._destination,
                projects=self._projects,
                top_k=top_k,
                scan_limit=scan_limit,
            )

        return self._run("vector", PolicySurface.VECTOR, recall)

    def hybrid(
        self,
        query,
        query_embedding,
        *,
        embedding_model,
        top_k=20,
        candidate_limit=200,
        scan_limit=1000,
    ):
        from .policy_hybrid import recall_authorized_hybrid

        def recall():
            self._vector_extension()
            return recall_authorized_hybrid(
                self._native(),
                query,
                query_embedding,
                embedding_model=embedding_model,
                reader=self._reader,
                destination=self._destination,
                projects=self._projects,
                top_k=top_k,
                candidate_limit=candidate_limit,
                scan_limit=scan_limit,
            )

        return self._run("hybrid", PolicySurface.HYBRID, recall)

    def issue(self, kind, record_id):
        return self._run(
            "issue",
            PolicySurface.DIRECT,
            lambda: self._evidence.issue(
                kind, record_id, destination=self._destination, projects=self._projects
            ),
        )

    def _lease_scope(self, lease):
        from .policy_evidence import EvidenceLease

        if type(lease) is not EvidenceLease:
            raise TypeError("exact evidence lease required")
        if (lease.bank, lease.destination, lease.projects) != (
            self._checkpoint.identity.bank,
            self._destination,
            self._projects,
        ):
            raise PolicyRefusal(RefusalReason.ACCESS_DENIED)

    def resolve(self, lease):
        self._lease_scope(lease)
        return self._run(
            "resolve", PolicySurface.CACHE, lambda: self._evidence.resolve(lease)
        )

    def deliver(self, lease, consumer):
        self._lease_scope(lease)
        _require_consumer(consumer)

        def output(hit):
            self._admit("deliver", PolicySurface.INJECT)
            # Reauthorization must follow audit I/O too: a changed grant must
            # not deliver bytes resolved before the new effective ceiling.
            _consume(consumer, self._evidence.resolve(lease))

        return self._run(
            "deliver",
            PolicySurface.INJECT,
            lambda: self._evidence.deliver(lease, output),
        )

    async def stream(self, leases, producer, consumer, *, limits=None):
        from .policy_stream import _leases

        leases = _leases(leases)
        for lease in leases:
            self._lease_scope(lease)
        _require_consumer(consumer)
        self._admit("stream", PolicySurface.INJECT)

        def output(chunk):
            self._admit("stream", PolicySurface.INJECT)
            for lease in leases:
                self._evidence.resolve(lease)
            _consume(consumer, chunk)

        return await self._evidence.stream(leases, producer, output, limits=limits)

    def dispatch(self, operation, **arguments):
        """One allowlist for adapters; never route unknown operations to legacy."""
        methods = {
            "get": self.get,
            "candidates": self.candidates,
            "source_metadata": self.source_metadata,
            "issue": self.issue,
            "resolve": self.resolve,
            "deliver": self.deliver,
            "lexical": self.lexical,
            "vector": self.vector,
            "hybrid": self.hybrid,
        }
        if type(operation) is not str or operation not in methods:
            raise PolicyRefusal(RefusalReason.UNSUPPORTED_SURFACE)
        return methods[operation](**arguments)
