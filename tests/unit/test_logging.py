"""Structured logging: one run id, one handler, machine-readable lines."""

from __future__ import annotations

import io
import json
import logging as stdlib_logging
from collections.abc import Iterator

import pytest

from bsfr_sh.util import logging as log


@pytest.fixture(autouse=True)
def _reset_logger() -> Iterator[None]:
    yield
    logger = stdlib_logging.getLogger(log.ROOT_LOGGER_NAME)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()


def _configured() -> tuple[io.StringIO, stdlib_logging.Logger, str]:
    stream = io.StringIO()
    run_id = log.configure(run_id="test-run", stream=stream, level="DEBUG")
    return stream, log.get_logger("test.module"), run_id


def test_event_emits_one_json_object_per_line() -> None:
    stream, logger, run_id = _configured()
    log.event(logger, "block_appended", chain="BC_DTBU", height=7, tx=100)
    lines = stream.getvalue().strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["event"] == "block_appended"
    assert record["run_id"] == run_id == "test-run"
    assert record["level"] == "INFO"
    assert record["logger"] == "bsfr_sh.test.module"
    assert record["chain"] == "BC_DTBU"
    assert record["height"] == 7
    assert "ts" in record


def test_run_id_is_shared_by_every_logger_in_the_tree() -> None:
    stream, _, run_id = _configured()
    log.event(log.get_logger("a"), "one")
    log.event(log.get_logger("b.c"), "two")
    ids = {json.loads(line)["run_id"] for line in stream.getvalue().strip().splitlines()}
    assert ids == {run_id}
    assert log.current_run_id() == run_id


def test_reconfiguring_does_not_duplicate_output() -> None:
    # A script that configures logging and then imports something that configures it again must
    # not double every line — duplicated run logs are worse than none, they inflate counts.
    stream = io.StringIO()
    log.configure(run_id="one", stream=stream)
    log.configure(run_id="two", stream=stream)
    log.event(log.get_logger("m"), "once")
    lines = stream.getvalue().strip().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["run_id"] == "two"


def test_fields_colliding_with_logrecord_attributes_do_not_crash() -> None:
    # `extra={"name": ...}` raises KeyError inside stdlib logging; a log call must never be the
    # thing that kills a run.
    stream, logger, _ = _configured()
    log.event(logger, "collision", name="not-the-logger", module="mine", height=1)
    record = json.loads(stream.getvalue().strip())
    assert record["name_"] == "not-the-logger"
    assert record["module_"] == "mine"
    assert record["height"] == 1


def test_level_filtering_works() -> None:
    stream = io.StringIO()
    log.configure(run_id="lvl", stream=stream, level="WARNING")
    logger = log.get_logger("m")
    log.event(logger, "quiet", level=stdlib_logging.DEBUG)
    log.event(logger, "loud", level=stdlib_logging.ERROR)
    events = [json.loads(line)["event"] for line in stream.getvalue().strip().splitlines()]
    assert events == ["loud"]


def test_new_run_ids_are_unique_and_sort_chronologically() -> None:
    ids = {log.new_run_id() for _ in range(50)}
    assert len(ids) == 50
    assert all(len(run_id.split("-")) == 2 for run_id in ids)


def test_env_snapshot_records_what_the_sidecar_needs() -> None:
    snapshot = log.env_snapshot()
    assert set(snapshot) == {"python_version", "platform", "pythonhashseed"}


def test_exceptions_are_captured_as_a_field() -> None:
    stream, logger, _ = _configured()
    try:
        raise ValueError("boom")
    except ValueError:
        logger.exception("failed")
    record = json.loads(stream.getvalue().strip())
    assert "ValueError: boom" in record["exc"]
