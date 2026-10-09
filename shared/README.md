# Shared primitives

Backend-local symlinks point to the common architecture adapter, CPython layout
generator, offset probe, dependency installer, and wire-v1 fixture decoder.
Keep the full repository checkout when building any backend. Build staging copies
the actual header/source bytes, so installed binaries do not depend on symlinks.
The install script uses the invoked backend path for its local `.deps` directory.

The BPF programs and ring consumers remain distinct implementations: the module
backend uses custom kfuncs, the upstream backend uses BPF helpers, and the
continuous service adds admission policy and wire v2. These differences require
separate verifier/attachment and correctness checks; they are not interchangeable
copies. Broad BPF unification is a separate change.
