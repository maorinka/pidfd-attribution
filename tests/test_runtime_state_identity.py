# SPDX-License-Identifier: GPL-2.0-only
"""Exercise the userspace rejection contract, not actual lifecycle callbacks."""

from dataclasses import replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from runtime_state_identity_model import (
    BindingWitness,
    OwnerIdentity,
    RuntimeStateIdentity,
    StateIdentity,
    UNKNOWN,
)


class RuntimeStateIdentityTests(unittest.TestCase):
    def setUp(self):
        self.model = RuntimeStateIdentity()
        self.mm = 0x1000
        self.generation = self.model.begin_runtime(self.mm)
        self.state = StateIdentity(self.mm, 0x2000, 1, 0x3000, self.generation)
        self.owner = OwnerIdentity((41 << 32) | 42, 100)

    def observe(
        self,
        state=None,
        owner=None,
        native_tid=42,
        observed_native_tid=42,
        complete=True,
    ):
        state = state or self.state
        owner = owner or self.owner
        token = self.model.begin_binding(
            state, owner, native_tid=native_tid, observed_native_tid=observed_native_tid
        )
        return self.model.observe_binding(
            BindingWitness(
                state, owner, native_tid, observed_native_tid, complete, token
            )
        )

    def pending_witness(self, state=None, owner=None):
        state, owner = state or self.state, owner or self.owner
        token = self.model.begin_binding(
            state, owner, native_tid=42, observed_native_tid=42
        )
        self.assertIsNotNone(token)
        return BindingWitness(state, owner, 42, 42, True, token)

    def test_missing_marker_never_assigns_from_matching_native_id(self):
        # Repeated scans cannot turn the candidate into observed ownership.
        for _ in range(3):
            self.assertFalse(self.model.snapshot(self.state, self.owner))
        self.assertTrue(self.observe())
        self.assertTrue(self.model.snapshot(self.state, self.owner))

    def test_same_tid_with_new_birth_rejects_retained_state(self):
        self.assertTrue(self.observe())
        recycled = replace(self.owner, birth=self.owner.birth + 1)
        self.assertFalse(self.model.snapshot(self.state, recycled))
        # Only an explicitly observed completion can associate the new birth.
        self.assertTrue(self.observe(owner=recycled))
        self.assertTrue(self.model.snapshot(self.state, recycled))
        self.assertFalse(self.model.snapshot(self.state, self.owner))

    def test_full_pid_tid_and_birth_are_required(self):
        self.observe()
        for owner in (
            replace(self.owner, pid_tid=(99 << 32) | 42),
            replace(self.owner, pid_tid=(41 << 32) | 43),
            replace(self.owner, birth=101),
        ):
            with self.subTest(owner=owner):
                self.assertFalse(self.model.snapshot(self.state, owner))

    def test_every_state_identity_field_is_checked(self):
        self.observe()
        for field in (
            "mm",
            "state",
            "state_id",
            "interpreter",
            "runtime_generation",
            "interpreter_id",
        ):
            changed = replace(self.state, **{field: getattr(self.state, field) + 1})
            with self.subTest(field=field):
                self.assertFalse(self.model.snapshot(changed, self.owner))

    def test_creator_cannot_claim_worker_binding(self):
        creator = OwnerIdentity((41 << 32) | 41, 90)
        self.assertFalse(self.observe(owner=creator, observed_native_tid=41))
        self.assertFalse(self.model.snapshot(self.state, creator))
        self.assertFalse(self.model.snapshot(self.state, self.owner))
        self.assertTrue(self.observe())
        self.assertTrue(self.model.snapshot(self.state, self.owner))

    def test_namespace_native_id_is_separate_from_initial_namespace_tid(self):
        # A qualified nested namespace may report7 for kernel initial TID42.
        self.assertTrue(self.observe(native_tid=7, observed_native_tid=7))
        self.assertTrue(self.model.snapshot(self.state, self.owner))
        self.assertFalse(self.observe(native_tid=7, observed_native_tid=42))
        self.assertTrue(self.model.snapshot(self.state, self.owner))

    def test_clear_invalidation_precedes_teardown_callback(self):
        self.observe()
        self.model.clear_state(self.mm, self.state.state)
        # This is the callback interval before user flags or memory change.
        self.assertFalse(self.model.snapshot(self.state, self.owner))
        self.model.clear_state(self.mm, self.state.state)  # Idempotent delete.
        self.assertFalse(self.model.snapshot(self.state, self.owner))

    def test_finalize_invalidation_precedes_callback_and_blocks_late_return(self):
        self.observe()
        self.model.finalize_runtime(self.mm)
        self.assertFalse(self.model.snapshot(self.state, self.owner))
        self.assertFalse(self.observe())  # Old pending completion cannot restore.
        self.assertFalse(self.model.snapshot(self.state, self.owner))

    def test_same_mm_reinitialize_cannot_reuse_state_id_and_owner(self):
        self.observe()
        self.model.finalize_runtime(self.mm)
        generation = self.model.begin_runtime(self.mm)
        self.assertGreater(generation, self.generation)
        reinitialized = replace(self.state, runtime_generation=generation)
        self.assertFalse(self.model.snapshot(self.state, self.owner))
        self.assertFalse(self.model.snapshot(reinitialized, self.owner))
        self.assertFalse(self.observe())  # Stale return from previous runtime.
        self.assertTrue(self.observe(state=reinitialized))
        self.assertTrue(self.model.snapshot(reinitialized, self.owner))

    def test_begin_invalidates_without_requiring_finalize_event(self):
        self.observe()
        generation = self.model.begin_runtime(self.mm)
        self.assertFalse(self.model.snapshot(self.state, self.owner))
        self.assertFalse(self.observe())
        self.assertFalse(
            self.model.snapshot(
                replace(self.state, runtime_generation=generation), self.owner
            )
        )

    def test_mm_address_reuse_gets_fresh_generation(self):
        self.observe()
        self.model.finalize_runtime(self.mm)
        # Another runtime can exist in the meantime; retirement never resets ID.
        other = self.model.begin_runtime(0x4000)
        reused = self.model.begin_runtime(self.mm)
        self.assertGreater(reused, other)
        self.assertFalse(self.model.snapshot(self.state, self.owner))

    def test_clear_one_state_and_finalize_one_mm_preserve_unrelated_marker(self):
        other_generation = self.model.begin_runtime(0x4000)
        other = replace(self.state, mm=0x4000, runtime_generation=other_generation)
        self.observe()
        self.assertTrue(self.observe(state=other))
        self.model.clear_state(self.mm, self.state.state)
        self.assertTrue(self.model.snapshot(other, self.owner))
        self.model.finalize_runtime(self.mm)
        self.assertTrue(self.model.snapshot(other, self.owner))

    def test_pointer_reuse_requires_new_state_id_marker(self):
        self.observe()
        self.model.clear_state(self.mm, self.state.state)
        reused = replace(self.state, state_id=2)
        self.assertFalse(self.model.snapshot(reused, self.owner))
        self.assertTrue(self.observe(state=reused))
        self.assertTrue(self.model.snapshot(reused, self.owner))
        self.assertFalse(self.model.snapshot(self.state, self.owner))

    def test_incomplete_witness_cannot_seed_owner(self):
        for complete in (False, None, 1):
            self.assertFalse(self.observe(complete=complete))
            self.assertIs(self.model.snapshot(self.state, self.owner), UNKNOWN)
        self.assertTrue(self.observe())
        self.assertEqual(self.model.snapshot(self.state, self.owner), self.state)

    def test_reused_subinterpreter_address_and_local_state_id_are_rejected(self):
        self.observe()
        # State IDs are per interpreter: a recreated interpreter may reuse1.
        recreated = replace(self.state, interpreter_id=1)
        self.assertIs(self.model.snapshot(recreated, self.owner), UNKNOWN)
        self.assertTrue(self.observe(state=recreated))
        self.assertIs(self.model.snapshot(self.state, self.owner), UNKNOWN)

    def test_snapshot_before_clear_does_not_authorize_later_capture(self):
        self.observe()
        before = self.model.snapshot(self.state, self.owner)
        self.assertEqual(before, self.state)
        self.model.clear_state(self.mm, self.state.state)
        self.assertIs(self.model.snapshot(before, self.owner), UNKNOWN)

    def test_clear_rejects_replay_of_previously_completed_witness(self):
        witness = self.pending_witness()
        self.assertTrue(self.model.observe_binding(witness))
        self.model.clear_state(self.mm, self.state.state)
        self.assertFalse(self.model.observe_binding(witness))
        self.assertIs(self.model.snapshot(self.state, self.owner), UNKNOWN)

    def test_clear_invalidates_pending_binding_without_published_marker(self):
        witness = self.pending_witness()
        self.assertIs(self.model.snapshot(self.state, self.owner), UNKNOWN)
        self.model.clear_state(self.mm, self.state.state)
        # No user status or identity fields have changed yet.
        self.assertFalse(self.model.observe_binding(witness))
        self.assertIs(self.model.snapshot(self.state, self.owner), UNKNOWN)

    def test_fresh_new_state_binding_survives_old_late_completion(self):
        old = self.pending_witness()
        self.model.clear_state(self.mm, self.state.state)
        new_state = replace(self.state, state_id=2)
        fresh = self.pending_witness(state=new_state)
        self.assertNotEqual(old.pending_token, fresh.pending_token)
        self.assertFalse(self.model.observe_binding(old))
        self.assertIs(self.model.snapshot(new_state, self.owner), UNKNOWN)
        self.assertTrue(self.model.observe_binding(fresh))
        self.assertEqual(self.model.snapshot(new_state, self.owner), new_state)
        self.assertIs(self.model.snapshot(self.state, self.owner), UNKNOWN)

    def test_finalize_and_reinitialize_invalidate_unpublished_pending_binding(self):
        old = self.pending_witness()
        self.model.finalize_runtime(self.mm)
        new_generation = self.model.begin_runtime(self.mm)
        fresh_state = replace(self.state, runtime_generation=new_generation)
        fresh = self.pending_witness(state=fresh_state)
        self.assertFalse(self.model.observe_binding(old))
        self.assertTrue(self.model.observe_binding(fresh))
        self.assertEqual(self.model.snapshot(fresh_state, self.owner), fresh_state)

    def test_newer_pending_entry_replaces_older_instance_conservatively(self):
        older = self.pending_witness()
        newer = self.pending_witness()
        self.assertFalse(self.model.observe_binding(older))
        self.assertTrue(self.model.observe_binding(newer))
        self.assertFalse(self.model.observe_binding(newer))  # Consumed token.

    def test_complete_flag_without_pending_token_cannot_seed(self):
        witness = BindingWitness(self.state, self.owner, 42, 42, True)
        self.assertFalse(self.model.observe_binding(witness))
        self.assertIs(self.model.snapshot(self.state, self.owner), UNKNOWN)

    def test_mismatched_completion_consumes_token_without_publishing(self):
        witness = self.pending_witness()
        changed = replace(witness, owner=replace(self.owner, birth=101))
        self.assertFalse(self.model.observe_binding(changed))
        self.assertFalse(self.model.observe_binding(witness))
        self.assertIs(self.model.snapshot(self.state, self.owner), UNKNOWN)

    def test_invalid_or_incomplete_identity_is_rejected(self):
        for value in (0, -1, True, "1", 1 << 64):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    replace(self.state, state_id=value)
                with self.assertRaises(ValueError):
                    replace(self.owner, birth=value)
        for pid_tid in (42, 41 << 32):
            with self.assertRaises(ValueError):
                replace(self.owner, pid_tid=pid_tid)
        self.assertIs(self.model.snapshot(self.state, 42), UNKNOWN)
        self.assertFalse(self.model.observe_binding(None))
        self.assertFalse(
            self.model.observe_binding(BindingWitness(self.state, 42, 42, 42, True))
        )
        with self.assertRaises(ValueError):
            self.observe(native_tid=0)


if __name__ == "__main__":
    unittest.main()
