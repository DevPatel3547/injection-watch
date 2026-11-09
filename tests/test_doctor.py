import json
import subprocess
import sys

from injectionwatch import doctor
from injectionwatch.cli import main

from .conftest import ROOT


def _base_env():
    import os

    return {k: v for k, v in os.environ.items() if k in ("PATH", "SYSTEMROOT", "TEMP", "TMP", "LANG")}

SECRET = "sk-ant-not-a-real-key-0123456789abcdef"


def test_doctor_exits_0_and_prints_table(capsys, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert main(["doctor", "--no-chromium"]) == 0
    out = capsys.readouterr().out
    for name in ("python", "core deps", "detector self-test", "extra: mcp", "ANTHROPIC_API_KEY", "cache dir"):
        assert name in out
    assert "core install: OK" in out


def test_missing_key_names_the_fix(capsys, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "")
    assert main(["doctor", "--no-chromium"]) == 0          # optional component: still exit 0
    out = capsys.readouterr().out
    assert "ANTHROPIC_API_KEY" in out and "not set" in out and "export ANTHROPIC_API_KEY=" in out
    assert main(["doctor", "--no-chromium", "--require", "anthropic"]) == 1


def test_key_is_never_printed(capsys, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", SECRET)
    assert main(["doctor", "--no-chromium"]) == 0
    assert main(["doctor", "--no-chromium", "--json"]) == 0
    out = capsys.readouterr().out
    assert SECRET not in out and SECRET[:12] not in out and "set (value not shown)" in out


def test_json_is_valid(capsys, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert main(["doctor", "--json", "--no-chromium"]) == 0
    d = json.loads(capsys.readouterr().out)
    assert d["ok"] is True and d["exit_code"] == 0
    assert {"name", "status", "detail", "fix", "component"} <= set(d["checks"][0])
    assert {c["status"] for c in d["checks"]} <= {"ok", "warn", "fail", "skip"}


def test_failures_and_require_logic():
    checks = [doctor.Check("a", doctor.OK, ""), doctor.Check("b", doctor.WARN, "", "fix it", "render")]
    assert doctor.exit_code(checks) == 0 and doctor.exit_code(checks, ["render"]) == 1
    assert doctor.exit_code([*checks, doctor.Check("c", doctor.FAIL, "")]) == 1
    table = doctor.format_table([*checks, doctor.Check("c", doctor.FAIL, "broken", "do x")], color=True)
    assert "To fix:" in table and "do x" in table and "1 blocking problem" in table


def test_chromium_env_and_bad_path(monkeypatch):
    monkeypatch.setenv("INJECTIONWATCH_CHROMIUM", "/definitely/not/here")
    st, detail, fix = doctor._chromium()
    assert st == doctor.FAIL and "missing" in detail and "playwright install chromium" in fix
    monkeypatch.setenv("INJECTIONWATCH_CHROMIUM", sys.executable)          # any existing file
    assert doctor._chromium()[0] == doctor.OK


def test_rosetta_and_mac_hints(monkeypatch):
    monkeypatch.setattr(doctor.sys, "platform", "darwin")
    monkeypatch.setattr(doctor.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 0, "1\n", ""))
    plat = next(c for c in doctor.check_python() if c.name == "platform")
    assert plat.status == doctor.WARN and "Rosetta" in plat.detail and "brew install python@3.12" in plat.fix
    monkeypatch.setattr(doctor.shutil, "which", lambda n: None)
    assert "brew install node" in doctor.check_node().fix


def test_network_checks_are_offline_safe(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("INJECTIONWATCH_LLM_BASE_URL", "http://127.0.0.1:9/v1")
    monkeypatch.setattr(doctor, "_http_get", lambda url, headers=None, timeout=8.0: (None, "ConnectionError"))
    by = {c.name: c for c in doctor.check_network()}
    assert by["Anthropic API"].status == doctor.SKIP and by["local LLM (Ollama)"].status == doctor.SKIP
    assert by["Common Crawl"].status == doctor.WARN


def test_network_check_against_fake_anthropic(monkeypatch):
    from .fakes.anthropic_server import FakeAnthropic

    with FakeAnthropic(valid_keys=("good-test-key",)) as fake:
        monkeypatch.setenv("ANTHROPIC_BASE_URL", fake.base_url)
        monkeypatch.setattr(doctor, "_http_get", lambda url, headers=None, timeout=8.0: (200, ""))
        monkeypatch.setenv("ANTHROPIC_API_KEY", "good-test-key")
        assert {c.name: c for c in doctor.check_network()}["Anthropic API"].status == doctor.OK
        monkeypatch.setenv("ANTHROPIC_API_KEY", "bad-test-key")
        bad = {c.name: c for c in doctor.check_network()}["Anthropic API"]
        assert bad.status == doctor.FAIL and "401" in bad.detail and "bad-test-key" not in bad.detail


def test_doctor_as_subprocess():
    p = subprocess.run([sys.executable, "-m", "injectionwatch", "doctor", "--json", "--no-chromium"],
                       capture_output=True, text=True, timeout=120, cwd=ROOT,
                       env={**_base_env(), "PYTHONPATH": str(ROOT), "HOME": str(ROOT / "build")})
    assert p.returncode == 0, p.stderr
    assert json.loads(p.stdout)["version"]
