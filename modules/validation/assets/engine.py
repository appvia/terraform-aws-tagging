"""Evaluates tagging policy rules against AWS Config resources."""

import re
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from policy import ASSERT, FILTER

PASS = "pass"
FAIL = "fail"


@dataclass(frozen=True)
class Account:
    """Account information from the inventory."""

    account_id: str
    name: str
    ou_path: str
    status: str
    tags: Dict[str, str]


@dataclass(frozen=True)
class Subject:
    """A resource subject to policy evaluation."""

    config_type: str  # e.g. AWS::S3::Bucket
    terraform_types: Tuple[str, ...]  # reverse mapping, may be empty
    tags: Dict[str, str]
    account_id: str
    account: Optional[Account]  # None = no inventory or account missing


@dataclass(frozen=True)
class Violation:
    """A policy violation."""

    rule: str
    severity: str
    message: str


@dataclass(frozen=True)
class Outcome:
    """Result of checking a subject against a policy."""

    violations: Tuple[Violation, ...]
    asserted: bool  # at least one rule reached an assert step
    skipped_rules: Tuple[str, ...]  # rules ignored because they need the inventory


def _equals(value, operands):
    """Check if value equals any operand."""
    return value in operands


def _contains(value, operands):
    """Check if value contains any operand."""
    return isinstance(value, str) and any(operand in value for operand in operands)


def _starts_with(value, operands):
    """Check if value starts with any operand."""
    return isinstance(value, str) and value.startswith(operands)


def _ends_with(value, operands):
    """Check if value ends with any operand."""
    return isinstance(value, str) and value.endswith(operands)


def _matches(value, operands):
    """Check if value matches any operand regex."""
    return isinstance(value, str) and any(
        re.search(operand, value) for operand in operands
    )


# Whole-value patterns for the is_<case> operators
_CASES = {
    "is_pascal": r"(?:[A-Z][a-z0-9]+)+",
    "is_camel": r"[a-z][a-z0-9]*(?:[A-Z][a-z0-9]+)*",
    "is_snake": r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*",
    "is_kebab": r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*",
    "is_lower": r"[a-z0-9]+",
    "is_upper": r"[A-Z0-9]+",
}


def _case_check(pattern):
    """Create a case checker function."""
    compiled = re.compile(pattern)

    def check(value, operand):
        return (
            isinstance(value, str) and compiled.fullmatch(value) is not None
        ) == operand

    return check


# Operand lists are any-of for every comparison
COMPARISONS = {
    "equals": _equals,
    "in": _equals,
    "contains": _contains,
    "starts_with": _starts_with,
    "ends_with": _ends_with,
    "matches": _matches,
}
COMPARISONS.update({name: _case_check(pattern) for name, pattern in _CASES.items()})


_STYLES = {
    "is_pascal": "PascalCase",
    "is_camel": "camelCase",
    "is_snake": "snake_case",
    "is_kebab": "kebab-case",
    "is_lower": "lowercase",
    "is_upper": "UPPERCASE",
}


def within(path: str, prefixes: Tuple[str, ...]) -> bool:
    """Check if path is within any of the prefixes (organizational path matching).

    Segment-aware: equal, or startswith prefix + "/".
    Case-sensitive.
    """
    for prefix in prefixes:
        if path == prefix or path.startswith(prefix + "/"):
            return True
    return False


def _inspected(condition, subject):
    """The (key, value) pairs a condition looks at; absent or empty values are None."""
    if condition.target == "type":
        # Special handling for type: we don't return multiple values here
        # Instead, we'll handle the matching in evaluate()
        return [(None, None)]
    if condition.target == "address":
        # Address has no meaning in Config
        return [(None, None)]
    if condition.target == "organizational_path":
        if subject.account is None:
            return [(None, None)]
        return [(None, subject.account.ou_path)]
    if condition.target == "account_id":
        return [(None, subject.account_id)]
    if condition.target == "account_tag":
        # Account tag
        if subject.account is None:
            return [(None, None)]
        pairs = []
        for key in condition.keys:
            value = subject.account.tags.get(key)
            pairs.append((key, None if value in (None, "") else value))
        return pairs
    # Regular tag
    pairs = []
    for key in condition.keys:
        value = subject.tags.get(key)
        pairs.append((key, None if value in (None, "") else value))
    return pairs


def _type_matches(operand, subject):
    """Check if a type operand matches the subject.

    AWS:: operands are compared against config_type.
    Other operands are compared against terraform_types (any match wins).
    """
    if operand.startswith("AWS::"):
        return operand == subject.config_type
    else:
        return operand in subject.terraform_types


def _evaluate_type(condition, subject):
    """Special evaluation for type conditions.

    Per-operand dispatch: AWS:: operands are tested against config_type,
    other operands are tested against terraform_types.
    The condition holds if any operand holds.
    """
    if condition.operator == "equals" or condition.operator == "in":
        # Plain form or in: check if any operand matches
        holds = any(_type_matches(operand, subject) for operand in condition.operand)
    else:
        # Operator form: apply per-operand dispatch
        # For each operand, test it against the appropriate type(s)
        def operand_holds(operand):
            if operand.startswith("AWS::"):
                # AWS:: operand: test against config_type
                return COMPARISONS[condition.operator](subject.config_type, (operand,))
            else:
                # Terraform operand: test against each terraform_type
                return any(
                    COMPARISONS[condition.operator](tf_type, (operand,))
                    for tf_type in subject.terraform_types
                )

        holds = any(operand_holds(operand) for operand in condition.operand)

    if condition.negate:
        holds = not holds
    return holds


def evaluate(condition, subject):
    """Returns (key, state, value) for each key the condition inspects."""
    # Special handling for type
    if condition.target == "type":
        holds = _evaluate_type(condition, subject)
        return [(None, PASS if holds else FAIL, None)]

    results = []
    for key, value in _inspected(condition, subject):
        if condition.operator == "present":
            holds = (value is not None) == condition.operand
        elif condition.operator == "within":
            # Organizational path within operator
            holds = value is not None and within(value, condition.operand)
        else:
            holds = value is not None and COMPARISONS[condition.operator](
                value, condition.operand
            )
        if condition.negate:
            holds = not holds
        results.append((key, PASS if holds else FAIL, value))
    return results


def check_subject(policy, subject):
    """Runs every rule against one subject; returns Outcome."""
    violations = []
    asserted = False
    skipped_rules = []

    for rule in policy.rules:
        rule_asserted, rule_skipped = _run(rule, subject, violations, skipped_rules)
        if rule_asserted:
            asserted = True

    return Outcome(
        violations=tuple(violations),
        asserted=asserted,
        skipped_rules=tuple(skipped_rules),
    )


def _run(rule, subject, violations, skipped_rules):
    """Run a rule; returns (asserted, skipped)."""
    # Check if rule needs inventory and we don't have it
    if rule.uses_inventory and subject.account is None:
        skipped_rules.append(rule.name)
        # Also skip all children
        for child in rule.children:
            _skip_rule_tree(child, skipped_rules)
        return False, True

    asserted = False
    for step in rule.steps:
        results = evaluate(step.condition, subject)
        if step.kind == FILTER:
            # Special handling for address: never matches
            if step.condition.target == "address":
                return False, False
            if any(state == FAIL for _, state, _ in results):
                return False, False
        elif step.kind == ASSERT:
            # Special handling for address: ignored
            if step.condition.target == "address":
                continue
            asserted = True
            for key, state, value in results:
                if state == FAIL:
                    message = _message(step.condition, key, value)
                    violations.append(Violation(rule.name, rule.severity, message))

    # Reached only when every filter in the chain matched, which children inherit
    for child in rule.children:
        child_asserted, _ = _run(child, subject, violations, skipped_rules)
        if child_asserted:
            asserted = True

    return asserted, False


def _skip_rule_tree(rule, skipped_rules):
    """Skip a rule and all its children."""
    skipped_rules.append(rule.name)
    for child in rule.children:
        _skip_rule_tree(child, skipped_rules)


def _message(condition, key, value):
    """Format a violation message."""
    if condition.target == "tag":
        subject = f"tag {key}"
    elif condition.target == "account_tag":
        subject = f"account_tag {key}"
    else:
        subject = condition.target
    negation = "not " if condition.negate else ""
    found = "" if value is None else f", found {value}"
    return f"{subject} must {negation}{_phrase(condition)}{found}"


def _phrase(condition):
    """Format the operator phrase for a message."""
    operator, operand = condition.operator, condition.operand
    if operator == "present":
        return "be present" if operand else "be absent"
    if operator == "within":
        listed = ", ".join(operand)
        many = len(operand) > 1
        return f"be within one of {listed}" if many else f"be within {listed}"
    if operator in _CASES:
        style = _STYLES[operator]
        return f"be {style}" if operand else f"not be {style}"
    listed = ", ".join(operand)
    many = len(operand) > 1
    if operator in ("equals", "in"):
        return f"be one of {listed}" if many else f"be {listed}"
    verb = {
        "contains": "contain",
        "starts_with": "start with",
        "ends_with": "end with",
        "matches": "match",
    }[operator]
    return f"{verb} one of {listed}" if many else f"{verb} {listed}"
