
import pytest

from secrets_cli.ignore import IgnoreRules


@pytest.fixture
def root(tmp_path):
    return tmp_path


def test_no_ignore_file(root):
    rules = IgnoreRules(root)
    p = root / "config.py"
    p.touch()
    assert not rules.is_ignored(p)


def test_ignore_by_filename(root):
    (root / ".secretsignore").write_text("config.py\n")
    rules = IgnoreRules(root)
    assert rules.is_ignored(root / "config.py")


def test_ignore_by_wildcard(root):
    (root / ".secretsignore").write_text("tests/*\n")
    rules = IgnoreRules(root)
    (root / "tests").mkdir()
    assert rules.is_ignored(root / "tests" / "fixture.py")


def test_always_skip_git_dir(root):
    rules = IgnoreRules(root)
    (root / ".git").mkdir()
    assert rules.is_ignored(root / ".git" / "config")


def test_always_skip_node_modules(root):
    rules = IgnoreRules(root)
    (root / "node_modules").mkdir()
    assert rules.is_ignored(root / "node_modules" / "package.json")


def test_always_skip_png(root):
    rules = IgnoreRules(root)
    p = root / "image.png"
    p.touch()
    assert rules.is_ignored(p)


def test_skip_example_suffix(root):
    rules = IgnoreRules(root)
    p = root / ".env.example"
    p.touch()
    assert rules.is_ignored(p)


def test_nosecrets_inline(root):
    rules = IgnoreRules(root)
    assert rules.is_suppressed_line("API_KEY = 'AKIA...'  # nosecrets")
    assert not rules.is_suppressed_line("API_KEY = 'AKIA...'")


def test_binary_detection(root):
    rules = IgnoreRules(root)
    p = root / "binary.bin"
    p.write_bytes(b"\x00\x01\x02some data")
    assert rules.is_binary(p)


def test_text_not_binary(root):
    rules = IgnoreRules(root)
    p = root / "script.py"
    p.write_text("print('hello')")
    assert not rules.is_binary(p)
