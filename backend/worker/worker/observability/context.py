"""Per-request context, carried implicitly so call sites don't have to thread it.

Every log line needs to answer "which request?" and "which user?". Passing those
through every function signature would be invasive, so they live in
``contextvars`` -- which, unlike thread-locals, propagate correctly across
``await`` boundaries and into tasks spawned from a request.
"""

from __future__ import annotations

import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Iterator

_request_id: ContextVar[str | None] = ContextVar("request_id", default=None)
_user_id: ContextVar[str | None] = ContextVar("user_id", default=None)


def new_request_id() -> str:
    return uuid.uuid4().hex[:16]


def get_request_id() -> str | None:
    return _request_id.get()


def get_user_id() -> str | None:
    return _user_id.get()


def bind_user(user_id: str) -> None:
    """Attach the (already hashed) user id to the current context.

    Called once authentication has resolved, so log lines emitted before that
    simply carry no user -- which is itself accurate.
    """
    _user_id.set(user_id)


@contextmanager
def request_context(request_id: str | None = None) -> Iterator[str]:
    """Bind a request id for the duration of the block.

    Also used by background work, which runs after the HTTP response and would
    otherwise lose the request that started it.
    """
    rid = request_id or new_request_id()
    token_r = _request_id.set(rid)
    token_u = _user_id.set(_user_id.get())
    try:
        yield rid
    finally:
        _request_id.reset(token_r)
        _user_id.reset(token_u)
