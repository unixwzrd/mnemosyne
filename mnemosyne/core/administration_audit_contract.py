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


def _intent_fields(intent):
    _bounded_text(intent.operation_id, "operation_id", 128)
    _digest(intent.plan_sha256)
    if (type(intent.previous) is not ConfigurationRevision or type(intent.candidate) is not ConfigurationRevision
            or intent.previous.authority_id != intent.candidate.authority_id
            or intent.candidate.generation != intent.previous.generation + 1):
        raise ValueError("exact same-authority successor required")
    if (type(intent.proposer) is not AdministrativeActor or type(intent.approver) is not AdministrativeActor
            or intent.proposer.issuer != intent.approver.issuer
            or intent.proposer.principal_id == intent.approver.principal_id
            or intent.proposer.separation_id == intent.approver.separation_id
            or intent.proposer.epoch != intent.approver.epoch
            or intent.proposer.authorization_revision != intent.approver.authorization_revision):
        raise ValueError("distinct same-epoch administrative actors required")


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
        _intent_fields(self)
        _bounded_text(self.principal_id, "principal_id", 128)
        _store_id(self.store_id)

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
class RegistryAdministrationIntent:
    operation_id: str
    plan_sha256: str
    previous: ConfigurationRevision
    candidate: ConfigurationRevision
    target_kind: str
    target_id: str
    proposer: AdministrativeActor
    approver: AdministrativeActor

    def __post_init__(self):
        _intent_fields(self)
        if type(self.target_kind) is not str or self.target_kind not in ("principals", "stores", "destinations", "conversations"):
            raise ValueError("supported registry target required")
        _bounded_text(self.target_id, "target_id", 128)
        if self.target_kind == "stores":
            _store_id(self.target_id)

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, data):
        values = dict(_exact_dict(data, set(cls.__dataclass_fields__), "registry administrative intent"))
        for name in ("previous", "candidate"):
            values[name] = _revision(values[name])
        for name in ("proposer", "approver"):
            values[name] = AdministrativeActor.from_dict(values[name])
        return cls(**values)


@dataclass(frozen=True, repr=False)
class ProfileAdministrationIntent:
    operation_id: str
    plan_sha256: str
    previous: ConfigurationRevision
    candidate: ConfigurationRevision
    profile_id: str
    proposer: AdministrativeActor
    approver: AdministrativeActor

    def __post_init__(self):
        _intent_fields(self)
        _bounded_text(self.profile_id, "profile_id", 128)

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, data):
        values = dict(_exact_dict(data, set(cls.__dataclass_fields__), "profile administrative intent"))
        for name in ("previous", "candidate"):
            values[name] = _revision(values[name])
        for name in ("proposer", "approver"):
            values[name] = AdministrativeActor.from_dict(values[name])
        return cls(**values)


def _intent(data):
    if type(data) is not dict:
        raise TypeError("exact intent object required")
    cls = (RegistryAdministrationIntent if "target_kind" in data else
           ProfileAdministrationIntent if "profile_id" in data else AdministrationIntent)
    return cls.from_dict(data)


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
    intent: AdministrationIntent | RegistryAdministrationIntent | ProfileAdministrationIntent | None
