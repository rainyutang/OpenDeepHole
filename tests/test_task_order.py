import pytest

from backend.task_order import MISSING_TASK_TIME, task_sort_time


@pytest.mark.parametrize("fraction,expected_fraction", [
    ("", "000000"), (".1", "100000"), (".12", "120000"), (".123", "123000"),
    (".1234", "123400"), (".12345", "123450"), (".123456", "123456"),
])
@pytest.mark.parametrize("clock,offset", [("00", "Z"), ("00", "+00:00"), ("08", "+08:00"), ("00", "")])
def test_task_time_and_generated_cursor_round_trip(fraction, expected_fraction, clock, offset):
    value = f"2026-09-09T{clock}:34:56{fraction}{offset}"
    expected = f"2026-09-09T00:34:56.{expected_fraction}Z"
    assert task_sort_time(value) == expected
    # The API validates the first page's canonical key on the next request.
    assert task_sort_time(expected) == expected


@pytest.mark.parametrize("value", [None, 42, "", "now", "2026-02-30T00:00:00Z",
                                  "2026-09-09T24:00:00Z", "2026-09-09T00:00:60Z",
                                  "2026-09-09T00:00:00.1234567Z"])
def test_invalid_task_time_uses_start_time_or_missing_key(value):
    assert task_sort_time(value) == MISSING_TASK_TIME
    assert task_sort_time(value, "2026-09-09 00:00:00.1Z") == "2026-09-09T00:00:00.100000Z"


def test_negative_offset_normalizes_across_utc_day_boundary():
    assert task_sort_time("2026-09-08T23:34:56.12345-01:00") == "2026-09-09T00:34:56.123450Z"
