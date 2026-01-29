import re
import uuid
import pytest

from app import (
    parse_int, as_int, _as_int,
    allowed_file, unique_filename,
    User
)


# ----------------------------
# parse_int
# ----------------------------
@pytest.mark.parametrize("value, default, expected", [
    ("123", None, 123),
    (123, None, 123),
    (" 7 ", 0, 7),
    ("-5", 99, -5),
    (None, 42, 42),
    ("abc", 42, 42),
    ("", 10, 10),
])
def test_parse_int(value, default, expected):
    assert parse_int(value, default) == expected


# ----------------------------
# as_int
# ----------------------------
@pytest.mark.parametrize("value, default, expected", [
    ("10", 1, 10),
    (10, 1, 10),
    ("1", 5, 1),
    ("0", 5, 5),      # <=0 -> default
    ("-3", 5, 5),     # <=0 -> default
    ("abc", 7, 7),    # мусор -> default
    (None, 9, 9),     # None -> default
])
def test_as_int(value, default, expected):
    assert as_int(value, default) == expected


# ----------------------------
# _as_int (внутренняя для catalog)
# ----------------------------
@pytest.mark.parametrize("value, default, expected", [
    ("3", 1, 3),
    ("0", 2, 2),
    ("-1", 2, 2),
    ("abc", 4, 4),
    (None, 5, 5),
])
def test__as_int(value, default, expected):
    assert _as_int(value, default) == expected


# ----------------------------
# allowed_file
# ----------------------------
@pytest.mark.parametrize("filename, expected", [
    ("avatar.png", True),
    ("avatar.jpg", True),
    ("avatar.jpeg", True),
    ("avatar.gif", True),
    ("avatar.webp", True),
    ("AVATAR.PNG", True),     # регистр расширения
    ("avatar.exe", False),
    ("avatar", False),        # нет расширения
    ("", False),
    (None, False),
])
def test_allowed_file(filename, expected):
    assert allowed_file(filename) is expected


# ----------------------------
# unique_filename
# ----------------------------
def test_unique_filename_keeps_extension_and_uuid(monkeypatch):
    class FakeUUID:
        hex = "a" * 32

    monkeypatch.setattr(uuid, "uuid4", lambda: FakeUUID())

    out = unique_filename("My Cool File.PNG")
    assert out == f"{'a'*32}.png"


def test_unique_filename_defaults_to_jpg_when_no_extension(monkeypatch):
    class FakeUUID:
        hex = "b" * 32

    monkeypatch.setattr(uuid, "uuid4", lambda: FakeUUID())

    out = unique_filename("no_extension")
    assert out == f"{'b'*32}.jpg"


def test_unique_filename_output_format(monkeypatch):
    class FakeUUID:
        hex = "c" * 32

    monkeypatch.setattr(uuid, "uuid4", lambda: FakeUUID())

    out = unique_filename("x.JpEg")
    # строгая проверка формата: 32 hex + .jpeg
    assert re.fullmatch(r"[0-9a-f]{32}\.jpeg", out) is not None


# ----------------------------
# User password methods
# ----------------------------
def test_user_password_check_positive():
    u = User(username="tester", email="t@example.com", password_hash="x")
    u.set_password("secret123")
    assert u.check_password("secret123") is True


def test_user_password_check_negative():
    u = User(username="tester", email="t@example.com", password_hash="x")
    u.set_password("secret123")
    assert u.check_password("wrong") is False
