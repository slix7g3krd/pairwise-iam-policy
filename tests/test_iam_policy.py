import pytest

from security.iam_policy import (
    is_full_admin,
    has_not_action,
    trust_policy_ok,
    deny_precedence,
    role_chain_depth,
    oidc_subject_ok
)


def test_full_admin():
    assert is_full_admin({'Action': '*', 'Resource': '*'}) is True

def test_not_action():
    assert has_not_action({'NotAction': 's3:GetObject'}) is True

def test_trust_ok():
    assert trust_policy_ok({'ExternalId': 'x', 'Principal': 'arn:aws:iam::1:root'}) is True

def test_trust_wild():
    assert trust_policy_ok({'Principal': '*'}) is False

def test_deny():
    assert deny_precedence([{'Effect': 'Deny'}, {'Effect': 'Allow'}]) == 'Deny'

def test_chain():
    assert role_chain_depth({'AssumeRole': ['a', 'b', 'c']}) == 3

def test_oidc():
    assert oidc_subject_ok('repo:org/app:ref:refs/heads/main', {'repo:org/app:ref:refs/heads/main'}) is True

def test_oidc_wild():
    assert oidc_subject_ok('repo:org/*:ref:refs/heads/main', {'repo:org/app:ref:refs/heads/main'}) is False

def test_resource():
    assert is_full_admin({'Action': 's3:*', 'Resource': '*'}) is True

def test_condition():
    assert trust_policy_ok({'Principal': 'arn:aws:iam::1:root', 'Condition': {}}) is False

def test_empty():
    assert is_full_admin({}) is False

def test_key_age():
    assert role_chain_depth({'AccessKeyAge': 400}) == 1

def test_env():
    assert trust_policy_ok({'Principal': 'arn:aws:iam::1:root', 'ExternalId': '', 'Env': 'prod'}) is False

def test_variable():
    assert has_not_action({'Resource': '${aws:username}'}) is False

def test_unused():
    assert deny_precedence([{'Effect': 'Allow'}]) == 'Allow'
