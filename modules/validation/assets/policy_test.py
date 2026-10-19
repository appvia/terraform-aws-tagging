import tempfile
from pathlib import Path

import pytest

from policy import Condition, PolicyError, load_policy, parse_policy, load_policy_text


def policy_with(*rules, **extra):
    return {"version": 1, "rules": list(rules), **extra}


def rule(*steps, name="r", **extra):
    return {"name": name, "steps": list(steps), **extra}


def assert_step(**condition):
    return {"assert": condition}


def filter_step(**condition):
    return {"filter": condition}


def _one(*steps):
    """Build a minimal policy with one rule containing the given steps."""
    return {"version": 1, "rules": [{"name": "r", "steps": list(steps)}]}


def _cond(c):
    """Return the first condition of a policy with one filter step."""
    return parse_policy(_one({"filter": c})).rules[0].steps[0].condition


class TestParsePolicy:
    def test_parses_a_chain(self):
        policy = parse_policy(
            policy_with(
                rule(
                    filter_step(type=["aws_instance", "aws_ebs_volume"]),
                    filter_step(tag="Environment", equals="Development"),
                    assert_step(
                        tag="Schedule", **{"in": ["UkWorkingHours", "AlwaysOn"]}
                    ),
                    name="dev-schedule",
                    description="Dev needs a schedule",
                    severity="warning",
                ),
                exclude_resource_types=["aws_x"],
            )
        )
        assert policy.exclude_resource_types == frozenset({"aws_x"})
        parsed = policy.rules[0]
        assert (parsed.name, parsed.severity) == ("dev-schedule", "warning")
        assert parsed.description == "Dev needs a schedule"
        assert [s.kind for s in parsed.steps] == ["filter", "filter", "assert"]
        assert parsed.steps[0].condition == Condition(
            "type", (), "equals", ("aws_instance", "aws_ebs_volume")
        )
        assert parsed.steps[1].condition == Condition(
            "tag", ("Environment",), "equals", ("Development",)
        )
        assert parsed.steps[2].condition == Condition(
            "tag", ("Schedule",), "in", ("UkWorkingHours", "AlwaysOn")
        )

    def test_defaults(self):
        parsed = parse_policy(
            policy_with(rule(assert_step(tag="A", present=True)))
        ).rules[0]
        assert (parsed.severity, parsed.description, parsed.children) == (
            "error",
            "",
            (),
        )

    def test_tag_key_list_and_not(self):
        step = (
            parse_policy(
                policy_with(
                    rule(assert_step(tag=["A", "B"], present=True, **{"not": True}))
                )
            )
            .rules[0]
            .steps[0]
        )
        assert step.condition == Condition("tag", ("A", "B"), "present", True, True)

    def test_type_and_address_mapping_form(self):
        rules = parse_policy(
            policy_with(
                rule(
                    filter_step(type={"starts_with": "aws_s3_"}),
                    filter_step(
                        address={"starts_with": "module.data"}, **{"not": True}
                    ),
                )
            )
        ).rules[0]
        assert rules.steps[0].condition == Condition(
            "type", (), "starts_with", ("aws_s3_",)
        )
        assert rules.steps[1].condition == Condition(
            "address", (), "starts_with", ("module.data",), True
        )

    def test_nested_rules_get_path_names(self):
        policy = parse_policy(
            policy_with(
                rule(
                    filter_step(type="aws_instance"),
                    name="ec2",
                    rules=[
                        rule(assert_step(tag="Backup", present=True), name="backup")
                    ],
                )
            )
        )
        assert policy.rules[0].children[0].name == "ec2/backup"

    def test_matches_parses_for_tags_and_types(self):
        parsed = parse_policy(
            policy_with(
                rule(
                    filter_step(type={"matches": "^aws_s3_"}),
                    assert_step(tag="Name", matches=["^a", "b$"]),
                )
            )
        ).rules[0]
        assert parsed.steps[0].condition == Condition(
            "type", (), "matches", ("^aws_s3_",)
        )
        assert parsed.steps[1].condition == Condition(
            "tag", ("Name",), "matches", ("^a", "b$")
        )

    def test_empty_rule_list_is_valid(self):
        assert parse_policy(policy_with()).rules == ()


class TestInvalidPolicy:
    def assertInvalid(self, data, fragment):
        with pytest.raises(PolicyError) as raised:
            parse_policy(data)
        assert fragment in str(raised.value)

    def test_top_level(self):
        self.assertInvalid(None, "mapping")
        self.assertInvalid({"rules": []}, "version")
        self.assertInvalid({"version": 2, "rules": []}, "version")
        self.assertInvalid({"version": True, "rules": []}, "version")
        self.assertInvalid({"version": 1}, "rules must be a list")
        self.assertInvalid(policy_with(extra=1), "unknown field")
        self.assertInvalid(
            policy_with(exclude_resource_types="aws_x"), "exclude_resource_types"
        )

    def test_rule_shape(self):
        ok = assert_step(tag="A", present=True)
        self.assertInvalid(policy_with("nope"), "mapping")
        self.assertInvalid(policy_with({"steps": [ok]}), "name")
        self.assertInvalid(policy_with(rule(ok, name="a/b")), "name")
        self.assertInvalid(
            policy_with(rule(ok, name="a"), rule(ok, name="a")), "duplicate rule name"
        )
        self.assertInvalid(policy_with(rule(ok, bogus=1)), "rule r: unknown field")
        self.assertInvalid(policy_with(rule(ok, severity="fatal")), "severity")
        self.assertInvalid(policy_with(rule(ok, description=3)), "description")
        self.assertInvalid(
            policy_with(rule()), "rule r: steps must be a non-empty list"
        )
        self.assertInvalid(policy_with({"name": "r"}), "steps")
        self.assertInvalid(policy_with(rule(ok, rules="x")), "rules")

    def test_nested_duplicate_names_are_scoped_to_the_parent(self):
        ok = assert_step(tag="A", present=True)
        parsed = parse_policy(
            policy_with(
                rule(ok, name="a", rules=[rule(ok, name="x")]),
                rule(ok, name="b", rules=[rule(ok, name="x")]),
            )
        )
        assert [c.name for r in parsed.rules for c in r.children] == ["a/x", "b/x"]
        self.assertInvalid(
            policy_with(
                rule(ok, name="a", rules=[rule(ok, name="x"), rule(ok, name="x")])
            ),
            "duplicate rule name",
        )

    def test_step_shape(self):
        ok = {"tag": "A", "present": True}
        self.assertInvalid(policy_with(rule("nope")), "mapping")
        self.assertInvalid(policy_with(rule({})), "exactly one of 'filter' or 'assert'")
        self.assertInvalid(
            policy_with(rule({"filter": ok, "assert": ok})), "exactly one"
        )
        self.assertInvalid(policy_with(rule({"filter": ok, "extra": 1})), "exactly one")

    def test_condition_shape(self):
        self.assertInvalid(
            policy_with(rule(assert_step())), "exactly one of type, address, tag"
        )
        self.assertInvalid(
            policy_with(rule(assert_step(tag="A", type="x", present=True))),
            "exactly one of type",
        )
        self.assertInvalid(
            policy_with(rule(assert_step(tag="A"))), "exactly one operator"
        )
        self.assertInvalid(
            policy_with(rule(assert_step(tag="A", present=True, equals="x"))),
            "exactly one operator",
        )
        self.assertInvalid(
            policy_with(rule(assert_step(tag="A", bogus="x"))), "unknown field"
        )
        self.assertInvalid(
            policy_with(rule(assert_step(tag="A", present=True, **{"not": "yes"}))),
            "'not'",
        )
        self.assertInvalid(
            policy_with(rule(assert_step(type="x", equals="y"))), "type: value"
        )
        self.assertInvalid(
            policy_with(rule(assert_step(type={"bogus": "x"}))), "operator"
        )
        self.assertInvalid(
            policy_with(rule(assert_step(type={"present": True}))), "operator"
        )
        self.assertInvalid(
            policy_with(rule(assert_step(type={"equals": "x", "contains": "y"}))),
            "operator",
        )

    def test_operand_types(self):
        self.assertInvalid(
            policy_with(rule(assert_step(tag="A", present="yes"))), "present"
        )
        self.assertInvalid(
            policy_with(rule(assert_step(tag="A", equals=[]))), "non-empty list"
        )
        self.assertInvalid(
            policy_with(rule(assert_step(tag="A", equals=[1]))), "list of strings"
        )
        self.assertInvalid(policy_with(rule(assert_step(tag="A", equals=""))), "string")
        self.assertInvalid(policy_with(rule(assert_step(tag=[], present=True))), "tag")
        self.assertInvalid(policy_with(rule(assert_step(type=3))), "type")

    def test_invalid_regular_expression_is_rejected(self):
        self.assertInvalid(
            policy_with(rule(assert_step(tag="A", matches="("))),
            "invalid regular expression",
        )
        self.assertInvalid(
            policy_with(rule(assert_step(tag="A", matches=["ok", "["]))),
            "invalid regular expression",
        )
        self.assertInvalid(
            policy_with(rule(filter_step(type={"matches": "*"}))),
            "invalid regular expression",
        )

    def test_unquoted_scalar_operand_is_rejected(self):
        # YAML parses yes/no/on/off as booleans and 1 as an integer
        self.assertInvalid(
            policy_with(rule(assert_step(tag="A", equals=True))), "equals"
        )
        self.assertInvalid(policy_with(rule(assert_step(tag="A", equals=1))), "equals")


class TestLoadPolicy:
    def test_loads_yaml(self, tmp_path):
        path = tmp_path / "policy.yaml"
        path.write_text(
            "version: 1\nrules:\n  - name: r\n    steps:\n      - assert: {tag: A, present: true}\n"
        )
        assert load_policy(str(path)).rules[0].name == "r"

    def test_non_utf8_file_is_a_policy_error(self, tmp_path):
        path = tmp_path / "policy.yaml"
        path.write_bytes(b"\xff\xfe\x00")
        with pytest.raises(PolicyError):
            load_policy(str(path))

    def test_unreadable_and_malformed_files(self, tmp_path):
        with pytest.raises(PolicyError):
            load_policy("/nonexistent/policy.yaml")
        path = tmp_path / "bad.yaml"
        path.write_text("version: [1\n")
        with pytest.raises(PolicyError):
            load_policy(str(path))
        empty_path = tmp_path / "empty.yaml"
        empty_path.write_text("")
        with pytest.raises(PolicyError):
            load_policy(str(empty_path))


def test_accepts_shipped_action_policy():
    """Test that we can parse the action's reference policy."""
    policy_path = Path(__file__).parent / "testdata" / "tagging-policy.yaml"
    policy = load_policy(str(policy_path))
    assert len(policy.rules) == 11


# New tests for account targets
def test_organizational_path_plain_is_within():
    c = (
        parse_policy(_one({"filter": {"organizational_path": ["root/workloads"]}}))
        .rules[0]
        .steps[0]
        .condition
    )
    assert (c.target, c.operator, c.operand) == (
        "organizational_path",
        "within",
        ("root/workloads",),
    )


def test_organizational_path_mapping_form():
    c = _cond({"organizational_path": {"matches": "^root/sandbox"}})
    assert (c.operator, c.operand) == ("matches", ("^root/sandbox",))


def test_account_id_plain_is_equals():
    assert _cond({"account_id": "123456789012"}).operand == ("123456789012",)


def test_account_tag_takes_operator_like_tag():
    c = _cond({"account_tag": "CostCentre", "present": True})
    assert (c.target, c.keys, c.operator, c.operand) == (
        "account_tag",
        ("CostCentre",),
        "present",
        True,
    )


def test_within_is_not_a_written_operator():
    with pytest.raises(PolicyError):
        _cond({"organizational_path": {"within": "root"}})


def test_rule_uses_inventory():
    p = parse_policy(
        _one(
            {"filter": {"organizational_path": "root/a"}},
            {"assert": {"tag": "X", "present": True}},
        )
    )
    assert p.rules[0].uses_inventory is True


def test_unquoted_yes_rejected():
    with pytest.raises(PolicyError, match="quote values such as yes or 1"):
        load_policy_text(
            "version: 1\nrules:\n- name: a\n  steps:\n  - assert: {tag: X, in: [yes, no]}\n"
        )


def test_aws_and_terraform_types_accepted_together():
    assert _cond({"type": ["aws_s3_bucket", "AWS::DynamoDB::Table"]}).operand == (
        "aws_s3_bucket",
        "AWS::DynamoDB::Table",
    )


@pytest.mark.parametrize("value", ["/", "//", ["root/a", "/"]])
def test_organizational_path_empty_after_strip_rejected(value):
    with pytest.raises(PolicyError, match="organizational_path"):
        _cond({"organizational_path": value})
