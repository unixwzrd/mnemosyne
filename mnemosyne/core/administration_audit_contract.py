"""Bounded administrative attribution, never credentials or memory content."""

from dataclasses import asdict, dataclass

from .host_configuration import ConfigurationRevision
from .host_profile import _bounded_text, _exact_dict
from .policy import _number
from .snapshot_authority import _store_id


def _digest(value):
    if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("exact SHA-256 required")
    return value


def _revision(data):
    return ConfigurationRevision(**_exact_dict(data, {"authority_id", "generation", "sha256"}, "revision"))


@dataclass(frozen=True, repr=False)
class AdministrativeActor:
    issuer: str
    principal_id: str
    separation_id: str
    authorization_revision: str
    epoch: int
    claim_sha256: str

    def __post_init__(self):
        for name in ("issuer", "principal_id", "separation_id"):
            _bounded_text(getattr(self, name), name, 128)
        _digest(self.authorization_revision)
        _digest(self.claim_sha256)
        _number(self.epoch, "epoch")

    @classmethod
    def from_dict(cls, data):
        return cls(**_exact_dict(data, set(cls.__dataclass_fields__), "actor attribution"))


@dataclass(frozen=True, repr=False)
class AdministrationIntent:
    operation_id: str
    plan_sha256: str
    previous: ConfigurationRevision
    candidate: ConfigurationRevision
    principal_id: str
    store_id: str
    proposer: AdministrativeActor
    approver: AdministrativeActor

    def __post_init__(self):
        _bounded_text(self.operation_id, "operation_id", 128)
        _bounded_text(self.principal_id, "principal_id", 128)
        _store_id(self.store_id)
        _digest(self.plan_sha256)
        if (type(self.previous) is not ConfigurationRevision or type(self.candidate) is not ConfigurationRevision
                or self.previous.authority_id != self.candidate.authority_id
                or self.candidate.generation != self.previous.generation + 1):
            raise ValueError("exact same-authority successor required")
        if (type(self.proposer) is not AdministrativeActor or type(self.approver) is not AdministrativeActor
                or self.proposer.issuer != self.approver.issuer
                or self.proposer.principal_id == self.approver.principal_id
                or self.proposer.separation_id == self.approver.separation_id
                or self.proposer.epoch != self.approver.epoch
                or self.proposer.authorization_revision != self.approver.authorization_revision):
            raise ValueError("distinct same-epoch administrative actors required")

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, data):
        values = dict(_exact_dict(data, set(cls.__dataclass_fields__), "administrative intent"))
        for name in ("previous", "candidate"):
            values[name] = _revision(values[name])
        for name in ("proposer", "approver"):
            values[name] = AdministrativeActor.from_dict(values[name])
        return cls(**values)


@dataclass(frozen=True, repr=False)
class AdministrationJournalRead:
    """Whole-journal host authorization; grant/profile capabilities do not imply it."""

    issuer: str
    principal_id: str
    authority_id: str
    journal_id: str
    destination: str
    authorization_revision: str
    epoch: int
    capabilities: frozenset[str]

    def __post_init__(self):
        for name in ("issuer", "principal_id", "destination"):
            _bounded_text(getattr(self, name), name, 128)
        _store_id(self.authority_id)
        _store_id(self.journal_id)
        _digest(self.authorization_revision)
        _number(self.epoch, "epoch")
        if type(self.capabilities) is not frozenset or self.capabilities != frozenset({"admin-journal:read"}):
            raise ValueError("explicit administrative journal capability required")


@dataclass(frozen=True, repr=False)
class AdministrationJournalRecord:
    sequence: int
    recorded_at: str
    operation_id: str
    kind: str
    candidate: ConfigurationRevision
    intent_sha256: str
    intent: AdministrationIntent | None
