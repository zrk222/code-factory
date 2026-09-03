"""Small native-engine controls; these prove adapters can be fed by real executions."""
from hypothesis import settings
from hypothesis.stateful import RuleBasedStateMachine, invariant, precondition, rule, run_state_machine_as_test
import pytest


class SafePayments(RuleBasedStateMachine):
    def __init__(self):
        super().__init__(); self.captured = 0; self.refunded = 0

    @rule()
    def capture(self):
        self.captured = 10

    @precondition(lambda self: self.captured > self.refunded)
    @rule()
    def refund(self):
        self.refunded += min(6, self.captured - self.refunded)

    @invariant()
    def refund_never_exceeds_capture(self):
        assert self.refunded <= self.captured


class BrokenPayments(SafePayments):
    @precondition(lambda self: self.captured > 0)
    @rule()
    def duplicate_refund(self):
        self.refunded += 6


def test_native_hypothesis_control_accepts_safe_and_kills_known_bad_machine():
    profile = settings(max_examples=30, stateful_step_count=12, derandomize=True, deadline=None)
    run_state_machine_as_test(SafePayments, settings=profile)
    with pytest.raises(AssertionError):
        run_state_machine_as_test(BrokenPayments, settings=profile)
