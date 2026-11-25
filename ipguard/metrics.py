"""Số liệu theo dõi: tín hiệu theo domain/engine, kết quả lượt đặt, nhật ký sự kiện."""
from __future__ import annotations

from collections import defaultdict
from typing import Callable

ALERT_KINDS = {"ip_retired", "breaker_open", "health_issue", "ip_changed", "proxy_cooldown"}


class Metrics:
    def __init__(self, clock: Callable[[], float], max_events: int = 200):
        self.clock = clock
        self.max_events = max_events
        self.since = clock()
        self.signals: dict[str, int] = defaultdict(int)    # "domain|engine|signal" -> n
        self.outcomes: dict[str, int] = defaultdict(int)   # "domain|outcome" -> n
        self.events: list[dict] = []

    def observe(self, domain: str, engine: str, signal: str) -> None:
        self.signals[f"{domain}|{engine}|{signal}"] += 1

    def outcome(self, domain: str, outcome: str) -> None:
        self.outcomes[f"{domain}|{outcome}"] += 1

    def event(self, kind: str, data: dict) -> dict:
        ev = {"ts": self.clock(), "kind": kind, **data}
        self.events.append(ev)
        del self.events[:-self.max_events]
        return ev

    def by_domain(self) -> dict:
        out: dict = defaultdict(lambda: {"pages": defaultdict(lambda: defaultdict(int)),
                                         "outcomes": defaultdict(int)})
        for k, n in self.signals.items():
            dm, eng, sig = k.split("|", 2)
            out[dm]["pages"][eng][sig] += n
        for k, n in self.outcomes.items():
            dm, oc = k.split("|", 1)
            out[dm]["outcomes"][oc] += n
        res = {}
        for dm, v in out.items():
            pages = {e: dict(s) for e, s in v["pages"].items()}
            total = sum(sum(s.values()) for s in pages.values())
            bad = lambda name: sum(s.get(name, 0) for s in pages.values())  # noqa: E731
            res[dm] = {
                "pages": pages,
                "outcomes": dict(v["outcomes"]),
                "challenge_rate": round(bad("soft_challenge") / total, 3) if total else 0.0,
                "captcha_rate": round(bad("captcha") / total, 3) if total else 0.0,
                "block_rate": round((bad("blocked") + bad("rate_limited")) / total, 3)
                if total else 0.0,
            }
        return res

    def reset(self) -> None:
        self.since = self.clock()
        self.signals.clear()
        self.outcomes.clear()

    def to_dict(self) -> dict:
        return {"since": self.since, "signals": dict(self.signals),
                "outcomes": dict(self.outcomes), "events": list(self.events)}

    def from_dict(self, data: dict, live: bool = False) -> None:
        self.since = data.get("since", self.since)
        self.signals = defaultdict(int, data.get("signals", {}))
        self.outcomes = defaultdict(int, data.get("outcomes", {}))
        self.events = list(data.get("events", []))[-self.max_events:]
