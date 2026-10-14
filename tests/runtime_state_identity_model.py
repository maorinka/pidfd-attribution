# SPDX-License-Identifier: GPL-2.0-only
"""Test-only userspace model of observed ownership; not a callback observer or BPF selector.

Only a complete qualified binding witness matching a current pending lifecycle
token may populate the model. Clear invalidates both pending and published state.
Witness completeness is assumed input, not something this model discovers.
Matching is one identity guard: callers must still validate live state status,
namespace identity, complete scan uniqueness and source capture consistency.
No callbacks, thread births or runtime transitions are discovered here.
"""

from dataclasses import dataclass


UINT64_MAX = (1 << 64) - 1
UINT32_MAX = (1 << 32) - 1


def _positive_integer(value, maximum=UINT64_MAX):
    if type(value) is not int or not 0 < value <= maximum:
        raise ValueError("Identity must be a positive bounded integer")


@dataclass(frozen=True)
class OwnerIdentity:
    pid_tid: int
    birth: int

    def __post_init__(self):
        _positive_integer(self.pid_tid)
        _positive_integer(self.birth)
        if not self.pid_tid >> 32 or not self.pid_tid & UINT32_MAX:
            raise ValueError("Owner must contain both PID and TID")


@dataclass(frozen=True)
class StateIdentity:
    mm: int
    state: int
    state_id: int
    interpreter: int
    runtime_generation: int
    interpreter_id: int = 0

    def __post_init__(self):
        for value in (
            self.mm,
            self.state,
            self.state_id,
            self.interpreter,
            self.runtime_generation,
        ):
            _positive_integer(value)
        if type(self.interpreter_id) is not int or not 0 <= self.interpreter_id < (
            1 << 63
        ):
            raise ValueError("Interpreter ID must be a bounded nonnegative integer")


@dataclass(frozen=True)
class BindingWitness:
    identity: StateIdentity
    owner: OwnerIdentity
    native_tid: int
    observed_native_tid: int
    complete: bool
    pending_token: int | None = None


UNKNOWN = None


@dataclass(frozen=True)
class _BirthMarker:
    identity: StateIdentity
    owner: OwnerIdentity


class RuntimeStateIdentity:
    """Synchronous qualification model; no concurrency or loss-free guarantee.

    Generations are model-owned and never reused, including reused mm addresses.
    begin_runtime and finalize_runtime represent ENTRY invalidations, before
    initialization or teardown can reset IDs or run native callbacks. A missed
    transition is not detectable by this model and must not be claimed safe.
    """

    def __init__(self):
        self._generation = 0
        self._runtimes = {}
        self._markers = {}
        self._pending = {}
        self._binding_token = 0

    def _invalidate_mm(self, mm):
        self._runtimes.pop(mm, None)
        for table in (self._markers, self._pending):
            for key in tuple(table):
                if key[0] == mm:
                    del table[key]

    def begin_runtime(self, mm):
        """Invalidate old ownership first; issue a fresh trusted generation."""
        _positive_integer(mm)
        self._invalidate_mm(mm)
        if self._generation == UINT64_MAX:
            raise OverflowError("Runtime generation exhausted")
        self._generation += 1
        self._runtimes[mm] = self._generation
        return self._generation

    def finalize_runtime(self, mm):
        """Invalidate before teardown; also models retirement of an mm."""
        _positive_integer(mm)
        self._invalidate_mm(mm)

    def clear_state(self, mm, state):
        """Invalidate at Clear/Delete entry, including another owner's state."""
        _positive_integer(mm)
        _positive_integer(state)
        self._markers.pop((mm, state), None)
        self._pending.pop((mm, state), None)

    def begin_binding(self, identity, owner, *, native_tid, observed_native_tid):
        """Model an observed lifecycle entry with a known state identity.

        A newer entry replaces any older pending instance for this state. This
        conservative model does not implement nested return-instance tracking
        or entry paths whose eventual state pointer is not yet known.
        """
        if not isinstance(identity, StateIdentity) or not isinstance(
            owner, OwnerIdentity
        ):
            return UNKNOWN
        _positive_integer(native_tid, UINT32_MAX)
        _positive_integer(observed_native_tid, UINT32_MAX)
        if (
            native_tid != observed_native_tid
            or self._runtimes.get(identity.mm) != identity.runtime_generation
        ):
            return UNKNOWN
        key = (identity.mm, identity.state)
        self.clear_state(*key)
        if self._binding_token == UINT64_MAX:
            raise OverflowError("Binding token exhausted")
        self._binding_token += 1
        token = self._binding_token
        self._pending[key] = BindingWitness(
            identity, owner, native_tid, observed_native_tid, False, token
        )
        return token

    def observe_binding(self, witness):
        """Accept supplied evidence of a completed qualified owner binding.

        complete represents all required external guards, including actual
        lifecycle completion and namespace-qualified ID correspondence. It is
        never derived here from matching IDs or from a runtime scan alone.
        """
        if not isinstance(witness, BindingWitness):
            return False
        identity, owner = witness.identity, witness.owner
        if not isinstance(identity, StateIdentity) or not isinstance(
            owner, OwnerIdentity
        ):
            return False
        if type(witness.pending_token) is not int:
            return False
        key = (identity.mm, identity.state)
        pending = self._pending.get(key)
        if pending is None or pending.pending_token != witness.pending_token:
            return False
        # Consume a matching completion even on failed qualification; a return
        # cannot be replayed, and a fresh lifecycle must get a new token.
        del self._pending[key]
        if (
            witness.complete is not True
            or pending.identity != identity
            or pending.owner != owner
            or pending.native_tid != witness.native_tid
            or pending.observed_native_tid != witness.observed_native_tid
            or self._runtimes.get(identity.mm) != identity.runtime_generation
        ):
            return False
        self._markers[(identity.mm, identity.state)] = _BirthMarker(identity, owner)
        return True

    def snapshot(self, identity, owner):
        """Return the exact marked identity or UNKNOWN; never create a marker.

        This synchronous snapshot does not imply atomic process-memory capture.
        A caller must revalidate again after frame reads; invalidation can occur
        between the initial and final snapshots.
        """
        if not isinstance(identity, StateIdentity) or not isinstance(
            owner, OwnerIdentity
        ):
            return UNKNOWN
        marker = self._markers.get((identity.mm, identity.state))
        if self._runtimes.get(
            identity.mm
        ) == identity.runtime_generation and marker == _BirthMarker(identity, owner):
            return identity
        return UNKNOWN
