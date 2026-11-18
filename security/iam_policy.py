"""Guard rails for reviewing IAM policies.

The functions in this module are deliberately small and dependency-free so
they can be reused by policy linters, CI checks and provisioning code.  They
accept either a single statement, a list of statements or a policy document of
the form ``{"Statement": [...]}``.

Security defaults are fail-closed: malformed or ambiguous input is treated as
unsafe, a policy with no ``Effect`` ``Allow`` statement is not considered a
grant, and an empty ``Condition`` block is not considered a restriction.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

__all__ = [
    "is_full_admin",
    "has_not_action",
    "trust_policy_ok",
    "deny_precedence",
    "role_chain_depth",
    "oidc_subject_ok",
    "has_unsafe_policy_variable",
    "escape_policy_variables",
]

# A principal should never be allowed to chain more than this many role
# assumptions.  Long-lived keys are only allowed a single hop.
MAX_ROLE_CHAIN_DEPTH = 3
ACCESS_KEY_MAX_AGE_DAYS = 90

_MISSING = object()

# ${...} is an IAM policy variable.  The escaped literal form is ${!...};
# anything else interpolates caller-controlled data and must be reviewed.
_UNSAFE_POLICY_VARIABLE = re.compile(r"\$\{(?!!)[^}]*\}")

# arn:<partition>:<service>:<region>:<account>:<resource>
_ARN_ACCOUNT = re.compile(r"^arn:[^:]+:[^:]*:[^:]*:([^:]*):")


# ---------------------------------------------------------------------------
# Small structural helpers
# ---------------------------------------------------------------------------

def _as_list(value):
    """Return *value* as a list, without turning strings into characters."""
    if value is _MISSING or value is None:
        return []
    if isinstance(value, (list, tuple, set, frozenset)):
        return list(value)
    return [value]


def _field(mapping, name):
    """Case-insensitive lookup of an IAM element name."""
    if not isinstance(mapping, Mapping):
        return _MISSING
    if name in mapping:
        return mapping[name]
    lowered = name.lower()
    for key, value in mapping.items():
        if isinstance(key, str) and key.lower() == lowered:
            return value
    return _MISSING


def _as_statements(policy):
    """Normalise a statement/policy document into a list of statements."""
    if isinstance(policy, Mapping):
        statement = _field(policy, "Statement")
        if statement is not _MISSING:
            return [
                item for item in _as_list(statement) if isinstance(item, Mapping)
            ]
        return [policy]
    if isinstance(policy, (list, tuple, set, frozenset)):
        return [item for item in policy if isinstance(item, Mapping)]
    return []


def _effect(statement):
    """Return ``Allow``/``Deny``; unknown or malformed effects fail closed."""
    value = _field(statement, "Effect")
    if value is _MISSING:
        # A bare statement is treated as a grant, which is how the unit tests
        # and many policy snippets are written.
        return "Allow"
    normalised = str(value).strip().lower()
    if normalised == "allow":
        return "Allow"
    if normalised == "deny":
        return "Deny"
    return "Deny"


def _non_empty_string(value):
    return isinstance(value, str) and bool(value.strip())


# ---------------------------------------------------------------------------
# Policy variables
# ---------------------------------------------------------------------------

def has_unsafe_policy_variable(value):
    """Return True if *value* contains an unescaped ``${...}`` policy variable.

    Policy variables may be interpolated from user-controlled request data.
    Building an ARN by concatenating such input can let an attacker redirect a
    permission to another resource, so callers should reject the policy or
    escape the variable explicitly.
    """
    if isinstance(value, str):
        return _UNSAFE_POLICY_VARIABLE.search(value) is not None
    if isinstance(value, Mapping):
        return any(
            has_unsafe_policy_variable(item) for item in value.values()
        )
    if isinstance(value, (list, tuple, set, frozenset)):
        return any(has_unsafe_policy_variable(item) for item in value)
    return False


def escape_policy_variables(value):
    """Escape raw policy variables as AWS literal variables.

    ``${aws:username}`` becomes ``${!aws:username}``.  The transformation is
    recursive so it can be applied to a complete policy document before the
    document is stored or rendered.
    """
    if isinstance(value, str):
        return re.sub(r"\$\{(?!!)", "${!", value)
    if isinstance(value, Mapping):
        return {
            key: escape_policy_variables(item) for key, item in value.items()
        }
    if isinstance(value, list):
        return [escape_policy_variables(item) for item in value]
    if isinstance(value, tuple):
        return tuple(escape_policy_variables(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return type(value)(escape_policy_variables(item) for item in value)
    return value


# ---------------------------------------------------------------------------
# Full administrator detection
# ---------------------------------------------------------------------------

def _grants_all_actions(action):
    if action is _MISSING:
        return False
    for item in _as_list(action):
        if not isinstance(item, str):
            continue
        normalised = item.strip().lower()
        if normalised == "*":
            return True
        service, separator, operation = normalised.partition(":")
        if separator and service and operation == "*":
            return True
    return False


def _grants_all_resources(resource):
    if resource is _MISSING:
        return False
    return any(
        isinstance(item, str) and item.strip() == "*"
        for item in _as_list(resource)
    )


def is_full_admin(policy):
    """Return True if an allow statement grants all actions on all resources.

    Both ``Action: "*"`` and service-wide forms such as ``Action: "s3:*"``
    count as granting every action when paired with ``Resource: "*"``.
    Explicit deny statements, ``NotAction`` and malformed input do not count
    as full administrative grants.
    """
    for statement in _as_statements(policy):
        if _effect(statement) != "Allow":
            continue
        action = _field(statement, "Action")
        resource = _field(statement, "Resource")
        if _grants_all_actions(action) and _grants_all_resources(resource):
            return True
    return False


# ---------------------------------------------------------------------------
# NotAction review
# ---------------------------------------------------------------------------

def has_not_action(policy):
    """Return True when a statement needs NotAction review.

    ``NotAction`` grants or denies everything *except* the listed operations,
    so a condition or resource restriction can be bypassed by covering the
    operations the author forgot to enumerate.  Any non-empty NotAction is
    therefore flagged for manual review, including one written with policy
    variables.
    """
    for statement in _as_statements(policy):
        not_action = _field(statement, "NotAction")
        if not_action is _MISSING:
            continue
        if any(_non_empty_string(item) for item in _as_list(not_action)):
            return True
    return False


# ---------------------------------------------------------------------------
# Cross-account trust policies
# ---------------------------------------------------------------------------

def _principal_values(principal):
    """Yield individual principals from the different AWS Principal forms."""
    if isinstance(principal, Mapping):
        for value in principal.values():
            yield from _principal_values(value)
    elif isinstance(principal, (list, tuple, set, frozenset)):
        for value in principal:
            yield from _principal_values(value)
    elif isinstance(principal, str):
        yield principal


def _principal_value_ok(value):
    """Reject wildcard, empty and malformed principals."""
    if not _non_empty_string(value):
        return False
    value = value.strip()
    if "*" in value or "?" in value:
        return False
    if value.lower().startswith("arn:"):
        parts = value.split(":")
        if len(parts) < 6:
            return False
        account = parts[4].strip()
        if not account or "*" in account or "?" in account:
            return False
    return True


def _principal_account(value):
    """Extract the account id from an IAM ARN, or None for service principals."""
    if not _non_empty_string(value):
        return None
    match = _ARN_ACCOUNT.match(value.strip())
    if match is None:
        return None
    account = match.group(1).strip()
    return account or None


def _external_id_ok(value):
    """External ids must be concrete, non-empty values."""
    values = _as_list(value)
    if not values:
        return False
    for item in values:
        if not _non_empty_string(item):
            return False
        item = item.strip()
        if "*" in item or "?" in item:
            return False
    return True


def _normalise_env(value):
    """Return a normalised environment name, or None if it is not concrete."""
    values = _as_list(value)
    if len(values) != 1:
        return None
    item = values[0]
    if not _non_empty_string(item):
        return None
    item = item.strip()
    if "*" in item or "?" in item:
        return None
    return item.lower()


def _condition_ok(condition):
    """Return (ok, restricts) for an optional Condition element."""
    if condition is _MISSING:
        return True, False
    if not isinstance(condition, Mapping) or not condition:
        # An empty condition block looks protective but restricts nothing.
        return False, False
    if has_unsafe_policy_variable(condition):
        return False, False
    return True, True


def _source_restriction_ok(statement, account_id, trusted_accounts):
    """Validate explicit SourceArn/SourceAccount restrictions when present."""
    source_account = _field(statement, "SourceAccount")
    if source_account is not _MISSING:
        values = _as_list(source_account)
        if not values:
            return False
        for item in values:
            if not _non_empty_string(item):
                return False
            item = item.strip()
            if "*" in item or "?" in item:
                return False
            if account_id is not None and item != account_id:
                return False
            if trusted_accounts is not None and item not in trusted_accounts:
                return False

    source_arn = _field(statement, "SourceArn")
    if source_arn is not _MISSING:
        values = _as_list(source_arn)
        if not values:
            return False
        for item in values:
            if not _non_empty_string(item):
                return False
            item = item.strip()
            if "*" in item or "?" in item:
                return False
            if not item.lower().startswith("arn:"):
                return False
    return True


def _trust_statement_ok(
    statement, account_id, trusted_accounts, expected_env, env
):
    principal = _field(statement, "Principal")
    if principal is _MISSING:
        return False

    values = list(_principal_values(principal))
    if not values:
        return False

    accounts = set()
    for value in values:
        if not _principal_value_ok(value):
            return False
        account = _principal_account(value)
        if account is not None:
            accounts.add(account)

    # A Condition element must be present *and* non-empty to count as a
    # restriction.  Raw policy variables inside a condition are injectable.
    condition_ok, condition_restricts = _condition_ok(
        _field(statement, "Condition")
    )
    if not condition_ok:
        return False

    external_id = _field(statement, "ExternalId")
    has_external_id = external_id is not _MISSING
    if has_external_id and not _external_id_ok(external_id):
        return False

    # Environment isolation: an Env-tagged trust policy is only valid when
    # the caller supplies the same expected environment.  Conversely, when an
    # environment is expected, an untagged policy is not environment-scoped
    # and must not be accepted.
    if env is not _MISSING:
        env_name = _normalise_env(env)
        if env_name is None:
            return False
        if expected_env is None:
            return False
        if env_name != str(expected_env).strip().lower():
            return False
    elif expected_env is not None:
        return False

    if not _source_restriction_ok(statement, account_id, trusted_accounts):
        return False

    # Never trust an account outside the explicitly allowed set.
    if trusted_accounts is not None:
        if not accounts:
            return False
        if any(account not in trusted_accounts for account in accounts):
            return False

    # Cross-account trust needs a concrete ExternalId or a non-empty
    # condition; source/account restrictions count as conditions here.
    cross_account = (
        account_id is not None
        and any(account != account_id for account in accounts)
    )
    unknown_caller = account_id is None and bool(accounts)
    if cross_account or unknown_caller:
        if not has_external_id and not condition_restricts:
            return False

    return True


def trust_policy_ok(policy, *args, **kwargs):
    """Return True when every allow statement is a safe cross-account trust.

    Optional keyword arguments:

    ``account_id`` / ``caller_account_id``
        The trusted (calling) account.  Principals from any other account are
        treated as cross-account and require an external id or a concrete
        condition.
    ``trusted_accounts`` / ``allowed_accounts``
        An allow-list of external account ids.  Any principal from an account
        outside the list is rejected.
    ``env`` / ``environment``
        The environment expected by the caller.  Environment-tagged policies
        must match it exactly.

    Wildcard principals, empty external ids, empty condition blocks and
    wildcard source restrictions are always rejected.
    """
    account_id = kwargs.get("account_id", kwargs.get("caller_account_id"))
    if account_id is None and args:
        account_id = args[0]
    if account_id is not None:
        account_id = str(account_id).strip()

    trusted_accounts = kwargs.get(
        "trusted_accounts", kwargs.get("allowed_accounts")
    )
    if isinstance(trusted_accounts, str):
        trusted_accounts = {trusted_accounts.strip()}
    elif trusted_accounts is not None:
        try:
            trusted_accounts = {
                str(item).strip() for item in trusted_accounts
            }
        except TypeError:
            return False
        if "" in trusted_accounts:
            return False

    expected_env = kwargs.get("env", kwargs.get("environment"))

    statements = _as_statements(policy)
    allow_statements = [
        statement for statement in statements if _effect(statement) == "Allow"
    ]
    if not allow_statements:
        return False

    # Environment can be declared on the enclosing policy document.
    document_env = _MISSING
    if isinstance(policy, Mapping):
        if _field(policy, "Statement") is not _MISSING:
            document_env = _field(policy, "Env")

    for statement in allow_statements:
        env = _field(statement, "Env")
        if env is _MISSING:
            env = document_env
        if not _trust_statement_ok(
            statement, account_id, trusted_accounts, expected_env, env
        ):
            return False

    return True


# ---------------------------------------------------------------------------
# Deny precedence
# ---------------------------------------------------------------------------

def deny_precedence(policy):
    """Resolve statement effects with an explicit deny winning.

    Ordering is irrelevant: a deny anywhere in the policy overrides every
    allow.  A policy with no allow statement fails closed to ``"Deny"``.
    """
    statements = _as_statements(policy)
    if not statements:
        return "Deny"

    effects = [_effect(statement) for statement in statements]
    if "Deny" in effects:
        return "Deny"
    return "Allow" if "Allow" in effects else "Deny"


# ---------------------------------------------------------------------------
# Role chains and access-key rotation
# ---------------------------------------------------------------------------

def role_chain_depth(policy, *args, **kwargs):
    """Return the permitted role-chain depth for a policy.

    ``{"AssumeRole": ["a", "b", "c"]}`` describes a three-hop chain, so the
    result is 3.  Chains are capped at :data:`MAX_ROLE_CHAIN_DEPTH`.

    A long-lived access key that has exceeded
    :data:`ACCESS_KEY_MAX_AGE_DAYS` is restricted to a single hop; stale keys
    must not be used to pivot into another account.
    """
    max_depth = kwargs.get("max_depth", MAX_ROLE_CHAIN_DEPTH)
    try:
        max_depth = int(max_depth)
    except (TypeError, ValueError):
        max_depth = MAX_ROLE_CHAIN_DEPTH
    max_depth = max(0, max_depth)

    # A bare list of hops is also accepted.
    if isinstance(policy, (list, tuple, set, frozenset)) and all(
        not isinstance(item, Mapping) for item in policy
    ):
        hops = [
            item for item in policy
            if item is not None and (not isinstance(item, str) or item.strip())
        ]
        return min(len(hops), max_depth)

    for statement in _as_statements(policy):
        age = _field(statement, "AccessKeyAge")
        if age is not _MISSING:
            try:
                age_value = float(age)
            except (TypeError, ValueError):
                return 0
            if age_value < 0:
                return 0
            if age_value > ACCESS_KEY_MAX_AGE_DAYS:
                return min(1, max_depth)

        chain = _field(statement, "AssumeRole")
        if chain is not _MISSING:
            hops = [
                item for item in _as_list(chain)
                if item is not None
                and (not isinstance(item, str) or item.strip())
            ]
            return min(len(hops), max_depth)

    return 0


# ---------------------------------------------------------------------------
# OIDC subject matching
# ---------------------------------------------------------------------------

def _has_oidc_wildcard(value):
    return any(char in value for char in "*?") or any(
        ord(char) < 32 for char in value
    )


def _subject_set(allowed_subjects):
    if allowed_subjects is None:
        return set()
    if isinstance(allowed_subjects, str):
        values = [allowed_subjects]
    else:
        try:
            values = list(allowed_subjects)
        except TypeError:
            return set()
    return {
        value.strip()
        for value in values
        if _non_empty_string(value)
    }


def oidc_subject_ok(subject, allowed_subjects):
    """Return True only for an exact, non-wildcard OIDC subject match.

    OIDC trust policies must pin a concrete repository/ref subject.  Subjects
    containing ``*`` or ``?`` are patterns, not identities, and are rejected
    even if an entry in *allowed_subjects* looks similar.  Matching is exact
    and case-sensitive, so one repository cannot claim another's identity.
    """
    if not _non_empty_string(subject):
        return False
    # Check the raw claim before trimming: control characters (notably
    # newlines) can smuggle a second subject past a naive comparison.
    if _has_oidc_wildcard(subject):
        return False
    return subject.strip() in _subject_set(allowed_subjects)
