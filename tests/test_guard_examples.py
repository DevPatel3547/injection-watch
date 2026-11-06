"""The offline examples in examples/ must keep working."""
import subprocess
import sys

import pytest

from .conftest import ROOT


def _base_env():
    import os

    return {k: v for k, v in os.environ.items() if k in ("PATH", "SYSTEMROOT", "TEMP", "TMP", "LANG")}


@pytest.mark.parametrize("name,expect", [("guard_basics.py", "refused: refusing to fetch 169.254.169.254"),
                                         ("wrap_any_tool.py", "blocked: possible prompt injection"),
                                         ("langchain_rag.py", "Refund policy: 30 days.")])
def test_example_runs(name, expect):
    if name == "langchain_rag.py":
        pytest.importorskip("langchain_core")
    p = subprocess.run([sys.executable, str(ROOT / "examples" / name)], capture_output=True, text=True, timeout=120,
                       env={**_base_env(), "PYTHONPATH": str(ROOT), "NO_PROXY": "*"})
    assert p.returncode == 0, p.stderr
    assert expect in p.stdout
    assert "ignore all previous" not in p.stdout.lower().split("refused:")[0]
