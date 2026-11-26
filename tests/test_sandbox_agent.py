"""Chạy toàn bộ kịch bản sandbox với agent browser-use KỊCH BẢN (không gọi LLM, không ra Internet).

Bật bằng:  IPGUARD_SANDBOX=1 python -m pytest -q tests/test_sandbox_agent.py
Cần: pip install -e .[agent] và Chrome + Chromium (`browser-use install`).
Muốn dùng LLM thật: python -m sandbox.run_agent (xem README).
"""
import asyncio
import os

import pytest

pytestmark = pytest.mark.skipif(os.environ.get("IPGUARD_SANDBOX") != "1",
                                reason="đặt IPGUARD_SANDBOX=1 để chạy agent trong sandbox")


@pytest.fixture(scope="module")
def env():
    from sandbox.infra import Sandbox
    from sandbox.run_agent import REQ, install_leak_trap
    from sandbox.scripted_llm import scripted_model
    saved = dict(os.environ)
    sb = Sandbox.start()
    install_leak_trap(sb, None)
    yield sb, scripted_model(REQ)
    sb.stop()
    os.environ.clear()
    os.environ.update(saved)


def _cases():
    from sandbox.run_agent import CASES
    return list(CASES)


@pytest.mark.parametrize("case", _cases())
def test_case(env, case):
    from sandbox.run_agent import run_case
    sb, llm = env
    rep = asyncio.run(run_case(case, sb, llm, headed=False))
    failed = [c["msg"] for c in rep["checks"] if not c["ok"]]
    assert rep["ok"], f"{case}: {failed}\n{rep['error'] or ''}"
