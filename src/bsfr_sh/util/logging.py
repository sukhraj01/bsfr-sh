"""Structured logging with a run identifier.

There is no `print` anywhere in this project (CLAUDE.md §7), and this module is the reason. A
`print` produces a line that cannot be filtered by level, cannot be correlated with the run that
emitted it, and is invisible to `results/logs/`. Every claim in `results/` has to trace back to a
run log with a config hash and a seed (CLAUDE.md §2), which only works if every component logs
through one configured logger carrying one `run_id`.

Output is one JSON object per line: greppable by a human, parseable by the bench emitters without
a regex.

Usage::

    from bsfr_sh.util import logging as log

    run_id = log.configure(level="INFO")
    logger = log.get_logger(__name__)
    log.event(logger, "block_appended", chain="BC_DTBU", height=7, tx=100)
"""

from __future__ import annotations

import json
import logging
import os
import sys
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import IO, Any, Final

__all__ = [
    "ROOT_LOGGER_NAME",
    "StructuredFormatter",
    "configure",
    "current_run_id",
    "env_snapshot",
    "event",
    "get_logger",
    "is_configured",
    "new_run_id",
]

ROOT_LOGGER_NAME: Final = "bsfr_sh"

#: Set by `configure()`. Read by the bench sidecar writer (M6) so that a figure and the log lines
#: that produced it carry the same identifier.
_RUN_ID: str | None = None

#: Keys that `logging` puts on every record. Anything outside this set was added by a caller via
#: `extra=`, and is emitted as a structured field.
_STANDARD_RECORD_KEYS: Final[frozenset[str]] = frozenset(
    {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "module",
        "msecs",
        "message",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "taskName",
        "thread",
        "threadName",
    }
)


def new_run_id(*, now: datetime | None = None) -> str:
    """Mint a run identifier: UTC timestamp plus a short random suffix.

    Timestamp first so that `ls results/logs/` sorts chronologically; random suffix so that two
    runs started in the same second do not overwrite each other's sidecar.
    """
    moment = now or datetime.now(UTC)
    return f"{moment.strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"


class StructuredFormatter(logging.Formatter):
    """Format a record as a single JSON object.

    `sort_keys=True` keeps the field order stable so that two runs of the same code produce
    diffable logs; `default=str` means an unexpected object degrades to its string form instead
    of killing the run inside a log call.
    """

    def __init__(self, run_id: str) -> None:
        super().__init__()
        self.run_id = run_id

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "run_id": self.run_id,
            "logger": record.name,
            "event": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _STANDARD_RECORD_KEYS and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, sort_keys=True, default=str)


def configure(
    *,
    run_id: str | None = None,
    level: int | str = "INFO",
    stream: IO[str] | None = None,
) -> str:
    """Configure the `bsfr_sh` logger tree and return the active `run_id`.

    Idempotent: calling it again replaces the handler rather than adding a second one, so a
    script that configures logging and then imports a module that also configures it does not
    emit every line twice.

    Logs go to stderr, keeping stdout free for machine-readable output from `scripts/`.
    """
    global _RUN_ID
    _RUN_ID = run_id or new_run_id()

    logger = logging.getLogger(ROOT_LOGGER_NAME)
    logger.setLevel(level)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()
    handler = logging.StreamHandler(stream if stream is not None else sys.stderr)
    handler.setFormatter(StructuredFormatter(_RUN_ID))
    logger.addHandler(handler)
    # Do not also emit through the root logger's default handler.
    logger.propagate = False
    return _RUN_ID


def current_run_id() -> str:
    """The active run id, configuring logging with a fresh one if that has not happened yet."""
    if _RUN_ID is None:
        return configure()
    return _RUN_ID


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a logger under the `bsfr_sh` tree.

    Pass `__name__`; a module outside the package gets attached to the tree anyway so its output
    still carries the run id.
    """
    if not name or name == ROOT_LOGGER_NAME:
        return logging.getLogger(ROOT_LOGGER_NAME)
    if name.startswith(f"{ROOT_LOGGER_NAME}."):
        return logging.getLogger(name)
    return logging.getLogger(f"{ROOT_LOGGER_NAME}.{name}")


def event(
    logger: logging.Logger,
    name: str,
    /,
    *,
    level: int = logging.INFO,
    **fields: Any,
) -> None:
    """Log a structured event.

    The message is an event *name* (`block_appended`, `consensus_commit`), not a sentence, and
    the data goes in keyword fields. Sentences are for humans reading one line; names and fields
    are for grepping ten thousand.
    """
    logger.log(level, name, extra=_sanitise(fields))


def _sanitise(fields: Mapping[str, Any]) -> dict[str, Any]:
    """Rename any field that would collide with a `LogRecord` attribute.

    `logging` raises `KeyError` on `extra={"name": ...}` or `extra={"module": ...}`, which would
    turn a logging call into a crash at exactly the moment something interesting was happening.
    """
    out: dict[str, Any] = {}
    for key, value in fields.items():
        out[f"{key}_" if key in _STANDARD_RECORD_KEYS else key] = value
    return out


def is_configured() -> bool:
    """Whether `configure()` has run in this process."""
    return _RUN_ID is not None


def env_snapshot() -> dict[str, str]:
    """Environment facts worth recording once per run in the sidecar (docs/EXPERIMENTS.md)."""
    return {
        "python_version": sys.version.split()[0],
        "platform": sys.platform,
        "pythonhashseed": os.environ.get("PYTHONHASHSEED", "<unset>"),
    }
