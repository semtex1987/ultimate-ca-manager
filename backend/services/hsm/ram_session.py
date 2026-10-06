"""Per-custodian RAMOverHTTP session rendezvous.

One live client per custodian slot. APDU queues in both directions; an empty
request template is the keepalive. A second client for the same slot is refused.
Dropping a session mid-ceremony fails pending work and triggers wipe hooks.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional, Set

from services.hsm.ram_protocol import (
    InitiationRequest,
    RamProtocolError,
    RequestTemplate,
    ResponseTemplate,
)

logger = logging.getLogger(__name__)


class SessionState(str, Enum):
    WAITING = 'waiting'
    CONNECTED = 'connected'
    CLOSED = 'closed'


class SessionBusyError(RuntimeError):
    """A second ram-client tried to claim an occupied custodian slot."""


class SessionDropError(RuntimeError):
    """A custodian session dropped while a ceremony depended on it."""


@dataclass
class PendingApdu:
    """One CAPDU waiting for a RAPDU from the client."""
    apdu: bytes
    event: threading.Event = field(default_factory=threading.Event)
    response: Optional[bytes] = None
    error: Optional[BaseException] = None
    # Set once this command has been placed in a request template. A response
    # that arrives before that belongs to the previous keepalive and must not
    # be paired with this command.
    sent: bool = False
    # The waiter gave up after the command was sent. The matching RAPDU is
    # still consumed so it is not applied to the next command.
    abandoned: bool = False


@dataclass
class RamSession:
    custodian_id: str
    connect_token: str
    state: SessionState = SessionState.WAITING
    atr: Optional[bytes] = None
    session_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    created_at: float = field(default_factory=time.monotonic)
    last_seen: float = field(default_factory=time.monotonic)
    readable: bool = False
    probe_error: Optional[str] = None
    probe_sw: Optional[str] = None
    logged_probe_sw: Optional[str] = None
    last_probe_at: float = 0.0
    hsm_selected: bool = False
    card_state: Optional[str] = None
    card_ready: bool = False
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _wait_request: threading.Event = field(default_factory=threading.Event, repr=False)
    _pending: List[PendingApdu] = field(default_factory=list, repr=False)
    _outbound: Optional[RequestTemplate] = field(default=None, repr=False)
    _closed: bool = False
    _drop_callbacks: List[Callable[['RamSession'], None]] = field(default_factory=list, repr=False)

    def on_drop(self, callback: Callable[['RamSession'], None]) -> None:
        self._drop_callbacks.append(callback)

    def mark_connected(self, atr: bytes) -> None:
        with self._lock:
            if self._closed:
                raise SessionDropError(f'session {self.custodian_id} already closed')
            self.atr = atr
            self.state = SessionState.CONNECTED
            self.last_seen = time.monotonic()
            self.readable = False
            self.probe_error = None
            self.probe_sw = None
            self.logged_probe_sw = None
            self.last_probe_at = 0.0
            self.hsm_selected = False
            self.card_state = None
            self.card_ready = False

    def record_probe(self, readable: bool, error: Optional[str] = None, probe_sw: Optional[str] = None) -> None:
        with self._lock:
            self.readable = bool(readable)
            self.probe_error = (error or None)
            if self.probe_error and len(self.probe_error) > 80:
                self.probe_error = self.probe_error[:80]
            self.probe_sw = probe_sw
            self.last_probe_at = time.monotonic()
            self.last_seen = self.last_probe_at

    def close(self, reason: str = '') -> None:
        callbacks: List[Callable[['RamSession'], None]] = []
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self.state = SessionState.CLOSED
            for pending in self._pending:
                pending.error = SessionDropError(reason or 'session closed')
                pending.event.set()
            self._pending.clear()
            self._wait_request.set()
            callbacks = list(self._drop_callbacks)
        for cb in callbacks:
            try:
                cb(self)
            except Exception:  # noqa: BLE001 — drop hooks must not raise into close
                logger.exception('session drop callback failed for %s', self.custodian_id)

    @property
    def connected(self) -> bool:
        return self.state == SessionState.CONNECTED and not self._closed

    def queue_transmit(self, apdu: bytes, timeout: float = 30.0) -> bytes:
        """Queue a CAPDU and block until the client returns a RAPDU."""
        pending = PendingApdu(apdu=apdu)
        with self._lock:
            if self._closed or self.state != SessionState.CONNECTED:
                raise SessionDropError(f'custodian {self.custodian_id} not connected')
            self._pending.append(pending)
            self._wait_request.set()
        if not pending.event.wait(timeout):
            with self._lock:
                if pending.event.is_set():
                    pass
                elif pending.sent:
                    pending.abandoned = True
                elif pending in self._pending:
                    self._pending.remove(pending)
                    if not self._pending:
                        self._wait_request.clear()
            if not pending.event.is_set():
                raise TimeoutError(f'APDU timeout for custodian {self.custodian_id}')
        if pending.error is not None:
            raise pending.error
        if pending.response is None:
            raise SessionDropError(f'no RAPDU for custodian {self.custodian_id}')
        return pending.response

    def queue_reset(self, timeout: float = 30.0) -> bytes:
        """Ask the client to reset the card; return the new ATR."""
        # Encode as a RESET command in the next request template.
        pending = PendingApdu(apdu=b'')  # empty marks RESET
        pending._is_reset = True  # type: ignore[attr-defined]
        with self._lock:
            if self._closed or self.state != SessionState.CONNECTED:
                raise SessionDropError(f'custodian {self.custodian_id} not connected')
            self._pending.append(pending)
            self._wait_request.set()
        if not pending.event.wait(timeout):
            with self._lock:
                if pending.event.is_set():
                    pass
                elif pending.sent:
                    pending.abandoned = True
                elif pending in self._pending:
                    self._pending.remove(pending)
                    if not self._pending:
                        self._wait_request.clear()
            if not pending.event.is_set():
                raise TimeoutError(f'reset timeout for custodian {self.custodian_id}')
        if pending.error is not None:
            raise pending.error
        if pending.response is None:
            raise SessionDropError('reset returned no ATR')
        self.atr = pending.response
        return pending.response

    def build_request(self, *, keepalive_if_idle: bool = True) -> RequestTemplate:
        """Drain pending CAPDUs into a request template (or empty keepalive)."""
        with self._lock:
            self.last_seen = time.monotonic()
            if not self._pending:
                self._wait_request.clear()
                return RequestTemplate.keepalive() if keepalive_if_idle else RequestTemplate()
            pending = self._pending[0]
            if pending.sent:
                # The client still owes a response for this command. Another
                # CAPDU in this template would make the next body ambiguous.
                return RequestTemplate.keepalive() if keepalive_if_idle else RequestTemplate()
            pending.sent = True
            tmpl = RequestTemplate()
            # One CAPDU or one RESET per template.
            if getattr(pending, '_is_reset', False):
                tmpl.add_reset()
            else:
                tmpl.add_capdu(pending.apdu)
            return tmpl

    def apply_response(self, response: ResponseTemplate) -> None:
        close = response.close()
        with self._lock:
            self.last_seen = time.monotonic()
            pending = self._pending[0] if self._pending else None
            if pending is not None and pending.sent and pending.abandoned:
                self._pending.pop(0)
                if self._pending:
                    self._wait_request.set()
                pending = None
            elif pending is not None and not pending.sent:
                # Body is the reply to a keepalive sent before this command.
                pending = None
            if pending is not None:
                if getattr(pending, '_is_reset', False):
                    atr = response.atr()
                    if atr is None:
                        pending.error = RamProtocolError('RESET response missing ATR')
                    else:
                        pending.response = atr
                        self.atr = atr
                else:
                    rapdus = response.rapdus()
                    if not rapdus:
                        pending.error = RamProtocolError('CAPDU response missing RAPDU')
                    else:
                        pending.response = rapdus[0]
                self._pending.pop(0)
                pending.event.set()
        if close is not None:
            self.close(reason=close.message or 'client close')

    def wait_for_work(self, timeout: float) -> bool:
        """Block until a CAPDU is queued or the session closes. Returns True if work."""
        return self._wait_request.wait(timeout)


class RamSessionManager:
    """Registry of custodian slots → live sessions."""

    def __init__(self):
        self._lock = threading.Lock()
        self._by_token: Dict[str, RamSession] = {}
        self._by_custodian: Dict[str, RamSession] = {}
        self._ceremony_active = False
        self._on_mid_ceremony_drop: Optional[Callable[[RamSession], None]] = None

    def set_ceremony_active(self, active: bool) -> None:
        with self._lock:
            self._ceremony_active = active

    def on_mid_ceremony_drop(self, callback: Callable[[RamSession], None]) -> None:
        self._on_mid_ceremony_drop = callback

    def register_slot(self, custodian_id: str, connect_token: str) -> None:
        """Declare a custodian slot that may connect (idempotent)."""
        with self._lock:
            existing = self._by_token.get(connect_token)
            if existing and existing.connected:
                raise SessionBusyError(
                    f'custodian {custodian_id} already has a connected ram-client'
                )
            # Keep a placeholder so begin_ceremony can list expected slots.
            if connect_token not in self._by_token:
                session = RamSession(custodian_id=custodian_id, connect_token=connect_token)
                self._by_token[connect_token] = session
                self._by_custodian[custodian_id] = session

    def accept_client(self, connect_token: str, initiation: InitiationRequest) -> RamSession:
        with self._lock:
            session = self._by_token.get(connect_token)
            if session is None:
                raise KeyError('unknown connect token')
            if session.connected:
                raise SessionBusyError(
                    f'custodian {session.custodian_id} already connected'
                )
            # Replace a stale WAITING/CLOSED placeholder with a fresh session.
            if session.state == SessionState.CLOSED:
                session = RamSession(
                    custodian_id=session.custodian_id,
                    connect_token=connect_token,
                )
                self._by_token[connect_token] = session
                self._by_custodian[session.custodian_id] = session
            ceremony = self._ceremony_active
            drop_cb = self._on_mid_ceremony_drop

        def _drop(s: RamSession) -> None:
            if ceremony and drop_cb is not None:
                drop_cb(s)

        session.on_drop(_drop)
        session.mark_connected(initiation.atr)
        return session

    def get_by_token(self, connect_token: str) -> Optional[RamSession]:
        with self._lock:
            return self._by_token.get(connect_token)

    def get_by_custodian(self, custodian_id: str) -> Optional[RamSession]:
        with self._lock:
            return self._by_custodian.get(custodian_id)

    def connected_custodians(self) -> Set[str]:
        with self._lock:
            return {
                s.custodian_id for s in self._by_custodian.values() if s.connected
            }

    def status(self) -> Dict[str, dict]:
        with self._lock:
            return {
                cid: {
                    'state': s.state.value,
                    'connected': s.connected,
                    'session_id': s.session_id if s.connected else None,
                    'has_atr': bool(s.atr),
                    'readable': bool(s.readable) if s.connected else False,
                    'probe_error': s.probe_error if s.connected else None,
                    'probe_sw': s.probe_sw if s.connected else None,
                    'card_state': s.card_state if s.connected else None,
                    'card_ready': bool(s.card_ready) if s.connected else False,
                }
                for cid, s in self._by_custodian.items()
            }

    def drop_all(self, reason: str = 'end_ceremony') -> None:
        with self._lock:
            sessions = list(self._by_token.values())
        for session in sessions:
            session.close(reason=reason)

    def clear(self) -> None:
        self.drop_all('clear')
        with self._lock:
            self._by_token.clear()
            self._by_custodian.clear()
            self._ceremony_active = False
