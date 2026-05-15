# SPDX-License-Identifier: Apache-2.0
"""Python wrapper for the sandlock Handler ABI.

The C ABI (see ``crates/sandlock-ffi/include/sandlock.h``) is mapped via
ctypes; this module exposes a pythonic Handler base class and a
NotifAction value-object.

The wrapper is strictly minimal — ergonomic helpers (path readers,
preset handlers, asyncio adapters) are deferred to a follow-up.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass


# Discriminant values mirror SANDLOCK_ACTION_* in sandlock.h.
class _ActionKind(enum.IntEnum):
    UNSET = 0
    CONTINUE = 1
    ERRNO = 2
    RETURN_VALUE = 3
    INJECT_FD_SEND = 4
    INJECT_FD_SEND_TRACKED = 5  # reserved; setter not exposed
    HOLD = 6
    KILL = 7


@dataclass(frozen=True)
class NotifAction:
    """Decision returned from a Python ``Handler.handle`` call.

    Construct via the factory classmethods (``NotifAction.continue_()``,
    ``NotifAction.errno(13)``, etc.); do not instantiate directly.

    Field semantics depend on ``kind``:

    - CONTINUE: no payload fields used.
    - ERRNO: ``errno_value`` set.
    - RETURN_VALUE: ``return_value`` set (factory: ``return_value_``).
    - INJECT_FD_SEND: ``srcfd``, ``newfd_flags`` set; the supervisor
      takes ownership of the fd on dispatch.
    - HOLD: no payload fields used.
    - KILL: ``sig``, ``pgid`` set. ``pgid == 0`` substitutes the
      supervisor-resolved child pgid; if the supervisor cannot safely
      resolve one, the action is refused and the exception policy
      applies.

    ``srcfd`` defaults to ``-1`` (not a valid fd) for every action
    kind other than INJECT_FD_SEND.
    """

    kind: int  # discriminant; values from _ActionKind / sandlock_action_kind_t
    errno_value: int = 0
    return_value: int = 0
    srcfd: int = -1
    newfd_flags: int = 0
    sig: int = 0
    pgid: int = 0

    @classmethod
    def continue_(cls) -> "NotifAction":
        return cls(kind=int(_ActionKind.CONTINUE))

    @classmethod
    def errno(cls, value: int) -> "NotifAction":
        return cls(kind=int(_ActionKind.ERRNO), errno_value=value)

    @classmethod
    def return_value_(cls, value: int) -> "NotifAction":
        return cls(kind=int(_ActionKind.RETURN_VALUE), return_value=value)

    @classmethod
    def hold(cls) -> "NotifAction":
        return cls(kind=int(_ActionKind.HOLD))

    @classmethod
    def kill(cls, sig: int, pgid: int = 0) -> "NotifAction":
        return cls(kind=int(_ActionKind.KILL), sig=sig, pgid=pgid)

    @classmethod
    def inject_fd_send(cls, srcfd: int, newfd_flags: int = 0) -> "NotifAction":
        """Inject a file descriptor into the child.

        Ownership of ``srcfd`` transfers to the supervisor on successful
        dispatch. The Python caller must NOT close ``srcfd`` after
        returning this action, regardless of whether the dispatch
        actually fires (the supervisor handles cleanup on all paths).
        """
        return cls(
            kind=int(_ActionKind.INJECT_FD_SEND),
            srcfd=srcfd,
            newfd_flags=newfd_flags,
        )
