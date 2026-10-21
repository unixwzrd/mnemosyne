# Host Profile Metadata Contract

Status: proposed, bounded metadata contract. This module is descriptive only. It does not authenticate an administrator, issue or validate administrative capability, grant access to policy configuration, or authorize access to memory content. Constructing or parsing a `ProfileDefinition` makes no authority claim. Persistence, authenticated administration, authorization, and enforcement are outside this contract and remain with the owning host architecture.

## Model

`ProfileDefinition` is a frozen record containing a bounded `profile_id`, positive integer `version`, the exact `PolicyDefinition` vocabulary, ordered per-level display metadata, and optional UI terminology overrides. Its level records contain `level_id`, `user_label`, and `admin_label`; the two labels are independent presentation strings and convey no privilege. Display level IDs must match the policy's ordered levels exactly, with no omission, addition, repetition, or reordering.

The only terminology fields are `classification`, `clearance`, `compartment`, `audience`, `purpose`, and `destination`. Each may be omitted or assigned independent bounded user/admin labels, represented in Python as `(field, user_label, admin_label)` tuples and in the serialized object as named `user_label`/`admin_label` fields. These are vocabulary/UI terms, not capabilities. There are no baked-in jurisdictional classification labels or role names.

The implementation uses exact `PolicyDefinition` and metadata record types, bounded nonblank strings without control characters, at most 64 policy levels, and an immutable tuple representation. No callbacks, providers, request context, credentials, or executable configuration are accepted.

## Serialization

`to_dict()` emits the exact versioned schema; `from_dict(data)` accepts only an exact dictionary with all required keys and rejects unknown/missing keys, unsupported contract versions, and incorrect JSON container types. Policy values serialize under `policy` as `policy_id`, `version`, and the ordered `levels` array. Level records serialize with all three required fields. Terminology is an object keyed only by allowlisted field names.

`canonical_bytes()` emits UTF-8-compatible ASCII JSON bytes using sorted object keys, compact separators, and JSON ASCII escaping. The array order of policy and display levels is significant. Terminology entries are normalized independently of their constructor order. Invalid Unicode surrogate strings, control characters and subclassed containers refuse. The serializer contains only this metadata and is not an authorization token, signature, freshness proof, or authenticated administrative declaration.

## Boundary

This contract deliberately contains no administrative declaration record. Admin authentication and grants belong to the host authority layer; a display label such as “admin” would not establish either. UI labels may be used by a future host to render vocabulary independently for end users and administrators, but may not be interpreted as grants or content-access rules. No persistence or production configuration is introduced here.
