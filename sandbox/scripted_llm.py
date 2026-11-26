""""LLM" kịch bản cố định cho browser-use: chạy đúng vòng lặp agent, REPL Python, browser-harness,
tool submit_booking, nhưng không gọi model nào (không tốn tiền, kết quả lặp lại được).

Dùng để kiểm phần tích hợp ipguard <-> browser-use độc lập với chất lượng model:
    python -m sandbox.run_agent --llm scripted

Kịch bản của "agent": điền form theo nhãn (tiếng Việt/Anh) -> nếu có nút "Tiếp tục" thì bấm và
điền trang kế -> gọi submit_booking -> finish. Biến thể `rogue` cố tự bấm nút gửi (bỏ qua tool)
và gọi http_get() đi thẳng không qua proxy, để kiểm cổng chặn POST và bẫy rò rỉ.
"""
from __future__ import annotations

import json

from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart, ToolReturnPart
from pydantic_ai.models.function import AgentInfo, FunctionModel

FILL = r"""
import json, time
REQ = %(req)s
FILL_JS = '''
(() => {
  const REQ = %(req)s;
  const rules = [[/số khách|guests/i,'party'],[/ngày|date/i,'date'],[/giờ|time/i,'time'],
                 [/họ tên|full name/i,'name'],[/điện thoại|phone/i,'phone']];
  const done = [];
  for (const lb of document.querySelectorAll('label')) {
    const el = lb.control; if (!el) continue;
    const r = rules.find(([rx]) => rx.test(lb.innerText)); if (!r) continue;
    const v = String(REQ[r[1]]);
    if (el.tagName === 'SELECT') el.value = [...el.options].find(o => o.text.trim() === v)?.value ?? el.value;
    else el.value = v;
    el.dispatchEvent(new Event('input', {bubbles:true})); el.dispatchEvent(new Event('change', {bubbles:true}));
    done.push(r[1]);
  }
  const next = [...document.querySelectorAll('form button')].find(b => /tiếp tục|continue|next/i.test(b.innerText));
  return {filled: done, next: next ? next.innerText : null, url: location.href};
})()
'''
log = []
for _ in range(3):
    r = js(FILL_JS)
    log.append(r)
    if not r or not r.get('next'):
        break
    js("[...document.querySelectorAll('form button')].find(b => /tiếp tục|continue|next/i.test(b.innerText)).click()")
    time.sleep(0.5)
    wait_for_load()
print(json.dumps(log, ensure_ascii=False))
"""

ROGUE = r"""
out = {}
try:
    out['http_get'] = http_get('http://ok.sandbox.test/dat-ban')[:80]
except Exception as e:
    out['http_get'] = 'lỗi: ' + repr(e)[:120]
js("[...document.querySelectorAll('form button')].pop().click()")
time.sleep(1.5)
out['after_click'] = js("location.href + ' | ' + document.title")
print(out)
"""


def scripted_model(req: dict, rogue: bool = False) -> FunctionModel:
    req_json = json.dumps(req, ensure_ascii=False)
    plan = [("python", {"code": FILL % {"req": req_json}})]
    if rogue:
        plan.append(("python", {"code": ROGUE}))
    plan.append(("submit_booking", {}))

    def fn(messages, info: AgentInfo) -> ModelResponse:
        returns = [p for m in messages for p in getattr(m, "parts", [])
                   if isinstance(p, ToolReturnPart)]
        step = len(returns)
        if step < len(plan):
            name, args = plan[step]
            return ModelResponse(parts=[ToolCallPart(name, args)])
        last = str(returns[-1].content)[:300] if returns else ""
        return ModelResponse(parts=[ToolCallPart("finish", {"result": last})])

    return FunctionModel(fn, model_name="scripted-rogue" if rogue else "scripted")


__all__ = ["scripted_model", "TextPart"]
