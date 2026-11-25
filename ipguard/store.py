"""Trạng thái dùng chung giữa nhiều worker.

Mô hình: toàn bộ trạng thái (pool, cầu dao, nhịp, request_id, số liệu) là một bản JSON.
Mỗi thao tác quan trọng (cấp IP, giữ chỗ lượt tải trang, trả IP, ghi tín hiệu) chạy trong
một khóa toàn cụm: tải bản mới nhất -> sửa -> lưu. Khối lượng đặt bàn thấp (vài thao tác/
phút/domain) nên cách này đơn giản và đủ nhanh; lease có hạn để worker chết không giữ IP mãi.
"""
from __future__ import annotations

import asyncio
import time
import uuid
from contextlib import asynccontextmanager
from typing import Optional


class _LoopLock:
    """asyncio.Lock gắn với event loop đang chạy (tạo lại nếu loop đổi)."""

    def __init__(self):
        self._lock: Optional[asyncio.Lock] = None
        self._loop = None

    def get(self) -> asyncio.Lock:
        loop = asyncio.get_running_loop()
        if self._lock is None or self._loop is not loop:
            self._lock, self._loop = asyncio.Lock(), loop
        return self._lock


class SharedStore:
    """Giao diện: khóa toàn cụm + đọc/ghi một bản JSON."""

    @asynccontextmanager
    async def lock(self):
        raise NotImplementedError
        yield  # pragma: no cover

    async def load(self) -> Optional[str]:
        raise NotImplementedError

    async def save(self, raw: str) -> None:
        raise NotImplementedError


class InMemoryStore(SharedStore):
    """Dùng chung trong một process (test, hoặc nhiều IPGuard trong cùng app)."""

    def __init__(self):
        self.raw: Optional[str] = None
        self._lock = _LoopLock()

    @asynccontextmanager
    async def lock(self):
        async with self._lock.get():
            yield

    async def load(self) -> Optional[str]:
        return self.raw

    async def save(self, raw: str) -> None:
        self.raw = raw


_UNLOCK = """
if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) end
return 0
"""


class RedisStore(SharedStore):
    """Cần `pip install redis` (redis.asyncio). Khóa: SET NX PX + xóa có kiểm tra token."""

    def __init__(self, client, key: str = "ipguard", lock_ttl_ms: int = 10_000,
                 retry_s: float = 0.05, timeout_s: float = 30.0):
        self.r = client
        self.key, self.lock_key = key, f"{key}:lock"
        self.lock_ttl_ms, self.retry_s, self.timeout_s = lock_ttl_ms, retry_s, timeout_s

    @classmethod
    def from_url(cls, url: str, **kw) -> "RedisStore":
        try:
            import redis.asyncio as aioredis
        except ImportError as e:  # pragma: no cover
            raise ImportError("RedisStore cần: pip install redis") from e
        return cls(aioredis.from_url(url), **kw)

    @asynccontextmanager
    async def lock(self):
        token = uuid.uuid4().hex
        deadline = time.monotonic() + self.timeout_s
        while not await self.r.set(self.lock_key, token, nx=True, px=self.lock_ttl_ms):
            if time.monotonic() > deadline:
                raise TimeoutError(f"không lấy được khóa {self.lock_key}")
            await asyncio.sleep(self.retry_s)
        try:
            yield
        finally:
            await self.r.eval(_UNLOCK, 1, self.lock_key, token)

    async def load(self) -> Optional[str]:
        v = await self.r.get(self.key)
        if v is None:
            return None
        return v.decode("utf-8") if isinstance(v, (bytes, bytearray)) else v

    async def save(self, raw: str) -> None:
        await self.r.set(self.key, raw)
