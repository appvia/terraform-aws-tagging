"""Tests for the engine module."""

import unittest
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from engine import Account, Outcome, Subject, Violation, check_subject, within
from policy import parse_policy


def subject(
    tags=None,
    config_type="AWS::S3::Bucket",
    terraform_types=(),
    account_id="111111111111",
    account=None,
):
    """Create a test Subject."""
    return Subject(
        config_type=config_type,
        terraform_types=tuple(terraform_types) if terraform_types else (),
        tags=tags or {},
        account_id=account_id,
        account=account,
    )


def policy(*rules):
    """Create a test policy."""
    return parse_policy({"version": 1, "rules": list(rules)})


def rule(*steps, name="r", **extra):
    """Create a test rule."""
    return {"name": name, "steps": list(steps), **extra}


def assert_tag(tag, **operator):
    """Create an assert step for a tag."""
    return {"assert": {"tag": tag, **operator}}


def filter_tag(tag, **operator):
    """Create a filter step for a tag."""
    return {"filter": {"tag": tag, **operator}}


def filter_type(value):
    """Create a filter step for type."""
    return {"filter": {"type": value}}


def violations(pol, subj):
    """Get violations from check_subject."""
    return check_subject(pol, subj).violations


def _run(filter_cond, **subject_overrides):
    """Helper: run a rule with the given filter condition then assert {tag: Env, present: true}."""
    pol = policy(rule({"filter": filter_cond}, assert_tag("Env", present=True)))
    subj = subject(**subject_overrides)
    return check_subject(pol, subj)


def _assert_only(assert_cond, **subject_overrides):
    """Helper: run a rule with only the given assert condition."""
    pol = policy(rule({"assert": assert_cond}))
    subj = subject(**subject_overrides)
    return check_subject(pol, subj)


class OperatorTest(unittest.TestCase):
    """Test operators from the action."""

    CASES = [
        # (operator, operand, tags, holds)
        ("present", True, {"T": "x"}, True),
        ("present", True, {}, False),
        ("present", True, {"T": ""}, False),
        ("present", False, {}, True),
        ("present", False, {"T": ""}, True),
        ("present", False, {"T": "x"}, False),
        ("equals", "x", {"T": "x"}, True),
        ("equals", "x", {"T": "xy"}, False),
        ("equals", "x", {}, False),
        ("equals", ["x", "y"], {"T": "y"}, True),
        ("equals", ["x", "y"], {"T": "z"}, False),
        ("in", ["a", "b"], {"T": "b"}, True),
        ("in", ["a", "b"], {"T": "B"}, False),
        ("contains", "bc", {"T": "abcd"}, True),
        ("contains", "bc", {"T": "acbd"}, False),
        ("contains", ["zz", "cd"], {"T": "abcd"}, True),
        ("contains", "a", {}, False),
        ("starts_with", "ab", {"T": "abcd"}, True),
        ("starts_with", "bc", {"T": "abcd"}, False),
        ("starts_with", ["zz", "ab"], {"T": "abcd"}, True),
        ("ends_with", "cd", {"T": "abcd"}, True),
        ("ends_with", "bc", {"T": "abcd"}, False),
        ("ends_with", ["zz", "cd"], {"T": "abcd"}, True),
        ("matches", "^ab.d$", {"T": "abcd"}, True),
        ("matches", "bc", {"T": "abcd"}, True),
        ("matches", "^bc", {"T": "abcd"}, False),
        ("matches", ["^zz", "d$"], {"T": "abcd"}, True),
        ("matches", "a", {}, False),
        ("is_pascal", True, {"T": "CostCentre"}, True),
        ("is_pascal", True, {"T": "Production"}, True),
        ("is_pascal", True, {"T": "Team2Name"}, True),
        ("is_pascal", True, {"T": "costCentre"}, False),
        ("is_pascal", True, {"T": "cost-centre"}, False),
        ("is_pascal", True, {"T": "Cost_Centre"}, False),
        ("is_pascal", True, {"T": "AWSAccount"}, False),
        ("is_pascal", True, {"T": "2Cost"}, False),
        ("is_pascal", True, {"T": 123}, False),
        ("is_pascal", True, {}, False),
        ("is_camel", True, {"T": "costCentre"}, True),
        ("is_camel", True, {"T": "cost"}, True),
        ("is_camel", True, {"T": "CostCentre"}, False),
        ("is_snake", True, {"T": "cost_centre"}, True),
        ("is_snake", True, {"T": "cost"}, True),
        ("is_snake", True, {"T": "cost__centre"}, False),
        ("is_snake", True, {"T": "Cost_centre"}, False),
        ("is_snake", True, {"T": "cost-centre"}, False),
        ("is_kebab", True, {"T": "cost-centre"}, True),
        ("is_kebab", True, {"T": "cost_centre"}, False),
        ("is_kebab", True, {"T": "cost-"}, False),
        ("is_lower", True, {"T": "prod1"}, True),
        ("is_lower", True, {"T": "Prod"}, False),
        ("is_lower", True, {"T": "pro-d"}, False),
        ("is_upper", True, {"T": "PROD1"}, True),
        ("is_upper", True, {"T": "Prod"}, False),
        ("is_upper", False, {"T": "Prod"}, True),
        ("is_pascal", False, {"T": "cost-centre"}, True),
        ("is_pascal", False, {"T": "CostCentre"}, False),
    ]

    def test_assert_operators(self):
        """Test all operators with various operands and tags."""
        for operator, operand, tags, holds in self.CASES:
            with self.subTest(operator=operator, operand=operand, tags=tags):
                found = violations(
                    policy(rule(assert_tag("T", **{operator: operand}))), subject(tags)
                )
                self.assertEqual(bool(found), not holds)

    def test_not_inverts_including_absent_targets(self):
        """Test that 'not' inverts the condition including when the target is absent."""
        pol = policy(
            rule(assert_tag("Environment", equals="Production", **{"not": True}))
        )
        self.assertEqual(violations(pol, subject({})), ())
        self.assertEqual(violations(pol, subject({"Environment": "Development"})), ())
        self.assertEqual(
            len(violations(pol, subject({"Environment": "Production"}))), 1
        )

    def test_non_string_values_do_not_raise(self):
        """Test that non-string values don't raise errors."""
        for operator in ("contains", "starts_with", "ends_with", "matches"):
            with self.subTest(operator=operator):
                pol = policy(rule(assert_tag("T", **{operator: "1"})))
                self.assertEqual(len(violations(pol, subject({"T": 123}))), 1)

    def test_environment_must_not_equal_the_application_name(self):
        """Test that 'not' works with equals."""
        pol = policy(
            rule(assert_tag("Environment", equals="APPLICATION_NAME", **{"not": True}))
        )
        self.assertEqual(violations(pol, subject({"Environment": "Production"})), ())
        found = violations(pol, subject({"Environment": "APPLICATION_NAME"}))
        self.assertEqual(
            tuple(v.message for v in found),
            ("tag Environment must not be APPLICATION_NAME, found APPLICATION_NAME",),
        )

    def test_multiple_tag_keys_each_must_hold(self):
        """Test that multiple tag keys are each checked."""
        pol = policy(rule(assert_tag(["A", "B", "C"], present=True)))
        found = violations(pol, subject({"A": "1"}))
        self.assertEqual(
            tuple(v.message for v in found),
            ("tag B must be present", "tag C must be present"),
        )


class TargetTest(unittest.TestCase):
    """Test target types from the action."""

    def test_type_shorthand_and_list(self):
        """Test type filter with shorthand and list."""
        pol = policy(
            rule(
                filter_type(["aws_instance", "aws_s3_bucket"]),
                assert_tag("T", present=True),
            )
        )
        self.assertEqual(
            len(
                violations(
                    pol,
                    subject(
                        config_type="AWS::S3::Bucket",
                        terraform_types=("aws_s3_bucket",),
                    ),
                )
            ),
            1,
        )
        self.assertEqual(
            violations(
                pol,
                subject(
                    config_type="AWS::IAM::Role", terraform_types=("aws_iam_role",)
                ),
            ),
            (),
        )

    def test_type_operator_mapping(self):
        """Test type filter with operator mapping."""
        pol = policy(
            rule(filter_type({"starts_with": "aws_s3_"}), assert_tag("T", present=True))
        )
        self.assertEqual(
            len(
                violations(
                    pol,
                    subject(
                        config_type="AWS::S3::BucketPolicy",
                        terraform_types=("aws_s3_bucket_policy",),
                    ),
                )
            ),
            1,
        )
        self.assertEqual(
            violations(
                pol,
                subject(
                    config_type="AWS::EC2::Instance",
                    terraform_types=("aws_instance",),
                ),
            ),
            (),
        )

    def test_rule_without_filter_applies_to_everything(self):
        """Test that rules without filters apply to everything."""
        pol = policy(rule(assert_tag("T", present=True)))
        self.assertEqual(
            len(violations(pol, subject(config_type="AWS::Anything::Thing"))), 1
        )


class ChainTest(unittest.TestCase):
    """Test filter chains from the action."""

    def dev_schedule(self):
        """Create a test policy with chained filters."""
        return policy(
            rule(
                filter_type("aws_instance"),
                filter_tag("Environment", equals="Development"),
                assert_tag("Schedule", **{"in": ["UkWorkingHours", "AlwaysOn"]}),
                name="dev-schedule",
            )
        )

    def test_chain_applies_only_when_every_filter_matches(self):
        """Test that chains apply only when every filter matches."""
        pol = self.dev_schedule()
        instance_config = "AWS::EC2::Instance"
        instance_tf = ("aws_instance",)
        self.assertEqual(
            violations(
                pol,
                subject(
                    {"Environment": "Production"},
                    config_type=instance_config,
                    terraform_types=instance_tf,
                ),
            ),
            (),
        )
        self.assertEqual(
            violations(
                pol,
                subject(
                    {"Environment": "Development"},
                    config_type="AWS::S3::Bucket",
                    terraform_types=("aws_s3_bucket",),
                ),
            ),
            (),
        )
        self.assertEqual(
            violations(
                pol,
                subject(
                    {"Environment": "Development", "Schedule": "AlwaysOn"},
                    config_type=instance_config,
                    terraform_types=instance_tf,
                ),
            ),
            (),
        )

    def test_violation_details_and_messages(self):
        """Test violation details and messages."""
        pol = self.dev_schedule()
        instance_config = "AWS::EC2::Instance"
        instance_tf = ("aws_instance",)
        missing = violations(
            pol,
            subject(
                {"Environment": "Development"},
                config_type=instance_config,
                terraform_types=instance_tf,
            ),
        )
        self.assertEqual(len(missing), 1)
        self.assertEqual(missing[0].rule, "dev-schedule")
        self.assertEqual(missing[0].severity, "error")
        self.assertEqual(
            missing[0].message, "tag Schedule must be one of UkWorkingHours, AlwaysOn"
        )
        wrong = violations(
            pol,
            subject(
                {"Environment": "Development", "Schedule": "Weekdays"},
                config_type=instance_config,
                terraform_types=instance_tf,
            ),
        )
        self.assertEqual(
            wrong[0].message,
            "tag Schedule must be one of UkWorkingHours, AlwaysOn, found Weekdays",
        )

    def test_message_phrasing(self):
        """Test message phrasing."""
        cases = [
            (assert_tag("T", present=True), {}, "tag T must be present"),
            (
                assert_tag("T", present=False),
                {"T": "x"},
                "tag T must be absent, found x",
            ),
            (assert_tag("T", equals="a"), {"T": "b"}, "tag T must be a, found b"),
            (
                assert_tag("T", contains="a"),
                {"T": "b"},
                "tag T must contain a, found b",
            ),
            (
                assert_tag("T", starts_with=["a", "b"]),
                {"T": "c"},
                "tag T must start with one of a, b, found c",
            ),
            (
                assert_tag("T", ends_with="a", **{"not": True}),
                {"T": "xa"},
                "tag T must not end with a, found xa",
            ),
            (
                assert_tag("T", matches="^a"),
                {"T": "b"},
                "tag T must match ^a, found b",
            ),
        ]
        for step, tags, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(
                    violations(policy(rule(step)), subject(tags))[0].message, expected
                )

    def test_every_failing_assert_is_reported(self):
        """Test that every failing assert is reported."""
        pol = policy(
            rule(
                assert_tag("A", present=True),
                assert_tag("B", present=True),
                name="both",
            )
        )
        self.assertEqual(
            tuple(v.message for v in violations(pol, subject({}))),
            ("tag A must be present", "tag B must be present"),
        )

    def test_filter_after_assert_still_gates_later_steps(self):
        """Test that filters after asserts still gate later steps."""
        pol = policy(
            rule(
                assert_tag("A", present=True),
                filter_tag("Environment", equals="Development"),
                assert_tag("B", present=True),
            )
        )
        self.assertEqual(
            tuple(v.message for v in violations(pol, subject({"Environment": "Prod"}))),
            ("tag A must be present",),
        )
        self.assertEqual(
            tuple(
                v.message
                for v in violations(pol, subject({"Environment": "Development"}))
            ),
            ("tag A must be present", "tag B must be present"),
        )

    def test_severity_is_carried_from_the_rule(self):
        """Test that severity is carried from the rule."""
        pol = policy(rule(assert_tag("A", present=True), severity="warning"))
        self.assertEqual(violations(pol, subject({}))[0].severity, "warning")


class NestingTest(unittest.TestCase):
    """Test nested rules from the action."""

    def ec2(self):
        """Create a test policy with nested rules."""
        return policy(
            rule(
                filter_type("aws_instance"),
                assert_tag("Own", present=True),
                name="ec2",
                rules=[
                    rule(assert_tag("Backup", present=True), name="backup"),
                    rule(
                        filter_tag("Environment", equals="Development"),
                        assert_tag("Schedule", present=True),
                        name="schedule",
                    ),
                ],
            )
        )

    def test_children_inherit_parent_filters(self):
        """Test that children inherit parent filters."""
        pol = self.ec2()
        self.assertEqual(
            violations(
                pol,
                subject(
                    {},
                    config_type="AWS::S3::Bucket",
                    terraform_types=("aws_s3_bucket",),
                ),
            ),
            (),
        )
        found = violations(
            pol,
            subject(
                {"Own": "1"},
                config_type="AWS::EC2::Instance",
                terraform_types=("aws_instance",),
            ),
        )
        self.assertEqual(
            tuple((v.rule, v.message) for v in found),
            (("ec2/backup", "tag Backup must be present"),),
        )

    def test_child_filters_apply_only_to_that_child(self):
        """Test that child filters apply only to that child."""
        found = violations(
            self.ec2(),
            subject(
                {"Own": "1", "Backup": "1", "Environment": "Development"},
                config_type="AWS::EC2::Instance",
                terraform_types=("aws_instance",),
            ),
        )
        self.assertEqual(tuple(v.rule for v in found), ("ec2/schedule",))

    def test_parent_asserts_run_for_the_parent_only(self):
        """Test that parent asserts run for the parent only."""
        found = violations(
            self.ec2(),
            subject(
                {"Backup": "1"},
                config_type="AWS::EC2::Instance",
                terraform_types=("aws_instance",),
            ),
        )
        self.assertEqual(tuple(v.rule for v in found), ("ec2",))


class NewTargetsTest(unittest.TestCase):
    """Test new targets: organizational_path, account_id, account_tag."""

    def test_within_segment_boundaries(self):
        """Test within function with segment boundaries (Review Focus 4)."""
        assert within("root/workloads", ("root/workloads",))
        assert within("root/workloads/prod", ("root/workloads",))
        assert not within("root/workloads-legacy", ("root/workloads",))
        assert not within("root/Workloads/prod", ("root/workloads",))

    def test_type_aws_operand_matches_config_type(self):
        """Test that AWS:: operand matches config_type."""
        assert _run({"type": "AWS::S3::Bucket"}, config_type="AWS::S3::Bucket").asserted

    def test_type_terraform_operand_matches_via_reverse_mapping(self):
        """Test that Terraform operand matches via reverse mapping."""
        assert _run(
            {"type": "aws_s3_bucket"},
            config_type="AWS::S3::Bucket",
            terraform_types=("aws_s3_bucket",),
        ).asserted

    def test_type_starts_with_applies_to_terraform_names(self):
        """Test that starts_with applies to Terraform names."""
        assert _run(
            {"type": {"starts_with": "aws_s3_"}},
            terraform_types=("aws_s3_bucket",),
        ).asserted

    def test_type_starts_with_aws_operand_uses_config_type(self):
        """Test that AWS:: operand uses config_type even with terraform_types present."""
        assert _run(
            {"type": {"starts_with": "AWS::S3::"}},
            config_type="AWS::S3::Bucket",
            terraform_types=("aws_s3_bucket",),
        ).asserted

    def test_type_terraform_operand_no_reverse_mapping_never_matches(self):
        """Test that Terraform operand with no reverse mapping never matches."""
        assert not _run(
            {"type": {"starts_with": "aws_s3_"}},
            config_type="AWS::S3::Bucket",
            terraform_types=(),
        ).asserted

    def test_type_mixed_operands_any_of(self):
        """Test that mixed AWS:: and Terraform operands work (any-of)."""
        # DynamoDB subject with no terraform_types
        assert _run(
            {"type": ["AWS::DynamoDB::Table", "aws_s3_bucket"]},
            config_type="AWS::DynamoDB::Table",
            terraform_types=(),
        ).asserted
        # S3 subject with terraform_types
        assert _run(
            {"type": ["AWS::DynamoDB::Table", "aws_s3_bucket"]},
            config_type="AWS::S3::Bucket",
            terraform_types=("aws_s3_bucket",),
        ).asserted

    def test_address_filter_never_matches(self):
        """Test that address filter never matches."""
        assert not _run({"address": {"matches": ".*"}}).asserted

    def test_address_assert_ignored(self):
        """Test that address assert is ignored."""
        assert _assert_only({"address": "x"}).violations == ()

    def test_inventory_rules_skipped_without_account(self):
        """Test that inventory rules are skipped without account."""
        out = _run({"organizational_path": "root/workloads"}, account=None)
        assert out.skipped_rules == ("r",) and not out.asserted

    def test_account_id_rule_runs_without_inventory(self):
        """Test that account_id rule runs without inventory."""
        assert _run(
            {"account_id": "111111111111"}, account=None, account_id="111111111111"
        ).asserted

    def test_account_tag_filter(self):
        """Test account_tag filter."""
        acct = Account("1", "a", "root", "ACTIVE", {"CostCentre": "42"})
        assert _run({"account_tag": "CostCentre", "in": ["42"]}, account=acct).asserted

    def test_skipped_parent_skips_children(self):
        """Test that skipped parent skips children."""
        pol = policy(
            rule(
                {"filter": {"organizational_path": "root/workloads"}},
                assert_tag("A", present=True),
                name="parent",
                rules=[rule(assert_tag("B", present=True), name="child")],
            )
        )
        out = check_subject(pol, subject(account=None))
        self.assertEqual(out.skipped_rules, ("parent", "parent/child"))
        self.assertFalse(out.asserted)


class WithinTest(unittest.TestCase):
    """Test the within function with trailing slash handling."""

    def test_organizational_path_trailing_slash_matches_end_to_end(self):
        """Test that 'root/workloads/' written in a policy matches 'root/workloads/prod'."""
        # The parser strips trailing slash, so we test the end-to-end behavior
        pol = policy(
            rule(
                {"filter": {"organizational_path": "root/workloads/"}},
                assert_tag("Env", present=True),
                name="workloads",
            )
        )
        acct = Account("1", "test", "root/workloads/prod", "ACTIVE", {})
        # Should match because the parser normalized "root/workloads/" to "root/workloads"
        out = check_subject(pol, subject({"Env": "prod"}, account=acct))
        self.assertTrue(out.asserted)
        self.assertEqual(out.violations, ())


if __name__ == "__main__":
    unittest.main()
