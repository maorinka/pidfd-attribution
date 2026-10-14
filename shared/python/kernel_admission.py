# SPDX-License-Identifier: GPL-2.0-only
"""Load-time checks for the collector's per-CPU scratch execution model."""

from pathlib import Path
import errno
import gzip
import os
import re
import stat

TRANSIENT_STARTUP_ERRNOS = frozenset(
    (errno.EIO, errno.ENOMEM, errno.EAGAIN, errno.EINTR, errno.ETIMEDOUT, errno.EBUSY)
)


def _is_regular_file(path):
    """Preserve I/O errors that newer Path.is_file() turns into absence."""
    try:
        return stat.S_ISREG(path.stat().st_mode)
    except (FileNotFoundError, NotADirectoryError):
        return False


def validate_preemption(config_text=None, dynamic_text=None):
    if config_text is None:
        path = Path("/boot/config-" + os.uname().release)
        if _is_regular_file(path):
            config_text = path.read_text()
        elif _is_regular_file(Path("/proc/config.gz")):
            config_text = gzip.decompress(Path("/proc/config.gz").read_bytes()).decode()
        else:
            raise ValueError("Cannot verify kernel preemption configuration")
    if re.search(r"^CONFIG_PREEMPT_RT=y$", config_text, re.M):
        raise ValueError("PREEMPT_RT is unsupported by the per-CPU scratch backend")
    if re.search(r"^CONFIG_PREEMPT_DYNAMIC=y$", config_text, re.M):
        if dynamic_text is None:
            path = Path("/sys/kernel/debug/sched/preempt")
            try:
                if not _is_regular_file(path):
                    raise ValueError("Cannot verify active dynamic preemption mode")
                dynamic_text = path.read_text()
            except OSError as error:
                if error.errno in TRANSIENT_STARTUP_ERRNOS:
                    raise
                raise ValueError(
                    "Cannot verify active dynamic preemption under the current "
                    "lockdown/debugfs policy: " + str(error)
                ) from error
        selected = re.findall(r"\((none|voluntary|full)\)", dynamic_text)
        if len(selected) != 1 or selected[0] not in ("none", "voluntary"):
            raise ValueError("Full or unknown dynamic preemption is unsupported")
        return selected[0]
    for mode, symbol in (
        ("none", "CONFIG_PREEMPT_NONE"),
        ("voluntary", "CONFIG_PREEMPT_VOLUNTARY"),
    ):
        if re.search(r"^" + symbol + r"=y$", config_text, re.M):
            return mode
    raise ValueError("Full or unknown kernel preemption is unsupported")
