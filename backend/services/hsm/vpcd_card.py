"""Virtual-card (vpicc) side of the vpcd framing.

The bookworm ``vsmartcard-vpcd`` IFD listens on port **35963**. This module
connects *to* that port and speaks the card side — the same role as
``vicc`` in frankmorgner/vsmartcard.

Framing: big-endian uint16 length + payload.

Control opcodes (single-byte payload from vpcd):
  VPCD_CTRL_OFF   = 0  power off
  VPCD_CTRL_ON    = 1  power on
  VPCD_CTRL_RESET = 2  reset
  VPCD_CTRL_ATR   = 4  get ATR

Any longer payload is a CAPDU; we reply with a RAPDU frame.
"""

from __future__ import annotations

import logging
import socket
import struct
import threading
import time
from typing import Callable, Optional

logger = logging.getLogger(__name__)

VPCD_CTRL_OFF = 0
VPCD_CTRL_ON = 1
VPCD_CTRL_RESET = 2
VPCD_CTRL_ATR = 4

DEFAULT_VPCD_HOST = '127.0.0.1'
DEFAULT_VPCD_PORT = 35963


class VpcdCardError(RuntimeError):
    pass


def encode_frame(payload: bytes) -> bytes:
    if len(payload) > 0xFFFF:
        raise VpcdCardError('payload too large for vpcd frame')
    return struct.pack('!H', len(payload)) + payload


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise VpcdCardError('vpcd peer closed')
        buf.extend(chunk)
    return bytes(buf)


def recv_frame(sock: socket.socket) -> bytes:
    header = recv_exact(sock, 2)
    (length,) = struct.unpack('!H', header)
    if length == 0:
        return b''
    return recv_exact(sock, length)


def send_frame(sock: socket.socket, payload: bytes) -> None:
    sock.sendall(encode_frame(payload))


TransmitFn = Callable[[bytes], bytes]
ResetFn = Callable[[], bytes]


class VpcdVirtualCard:
    """Card-side handler for one vpcd connection."""

    def __init__(
        self,
        *,
        atr: bytes,
        transmit: TransmitFn,
        reset: Optional[ResetFn] = None,
        powered: bool = False,
    ):
        if not atr:
            raise ValueError('ATR is required')
        self._atr = atr
        self._transmit = transmit
        self._reset = reset
        self._powered = powered

    @property
    def atr(self) -> bytes:
        return self._atr

    @property
    def powered(self) -> bool:
        return self._powered

    def handle_payload(self, payload: bytes) -> Optional[bytes]:
        """Process one vpcd message; return response payload or None (no reply)."""
        if len(payload) == 1:
            ctrl = payload[0]
            if ctrl == VPCD_CTRL_OFF:
                self._powered = False
                return None
            if ctrl == VPCD_CTRL_ON:
                self._powered = True
                return None
            if ctrl == VPCD_CTRL_RESET:
                self._powered = True
                if self._reset is not None:
                    self._atr = self._reset()
                return None
            if ctrl == VPCD_CTRL_ATR:
                return self._atr
            raise VpcdCardError(f'unknown vpcd control 0x{ctrl:02X}')
        if not self._powered:
            self._powered = True
        return self._transmit(payload)

    def serve_socket(self, sock: socket.socket) -> None:
        sock.settimeout(120.0)
        try:
            while True:
                payload = recv_frame(sock)
                reply = self.handle_payload(payload)
                if reply is not None:
                    send_frame(sock, reply)
        except (VpcdCardError, OSError, TimeoutError) as exc:
            logger.info('vpcd/vpicc session ended: %s', exc)


class VpcdClient:
    """Connect to local vpcd (IFD) and serve the virtual card.

    Default: ``127.0.0.1:35963`` — the bookworm ``vsmartcard-vpcd`` port.
    """

    def __init__(
        self,
        host: str = DEFAULT_VPCD_HOST,
        port: int = DEFAULT_VPCD_PORT,
        card_factory: Optional[Callable[[], VpcdVirtualCard]] = None,
        reconnect_delay: float = 2.0,
    ):
        self.host = host
        self.port = port
        self.card_factory = card_factory
        self.reconnect_delay = reconnect_delay
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._sock: Optional[socket.socket] = None

    @property
    def connected(self) -> bool:
        return self._sock is not None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run_loop, name='vpcd-vpicc', daemon=True,
        )
        self._thread.start()
        logger.info('vpicc client targeting vpcd at %s:%s', self.host, self.port)

    def stop(self) -> None:
        self._stop.set()
        sock = self._sock
        self._sock = None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def _connect(self) -> socket.socket:
        sock = socket.create_connection((self.host, self.port), timeout=5.0)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return sock

    def _run_loop(self) -> None:
        while not self._stop.is_set():
            if self.card_factory is None:
                time.sleep(self.reconnect_delay)
                continue
            try:
                sock = self._connect()
            except OSError as exc:
                logger.debug('vpcd not ready at %s:%s (%s)', self.host, self.port, exc)
                self._stop.wait(self.reconnect_delay)
                continue
            self._sock = sock
            logger.info('vpicc connected to vpcd %s:%s', self.host, self.port)
            try:
                card = self.card_factory()
                card.serve_socket(sock)
            except Exception:  # noqa: BLE001
                logger.exception('vpicc session error')
            finally:
                self._sock = None
                try:
                    sock.close()
                except OSError:
                    pass
            if not self._stop.is_set():
                self._stop.wait(self.reconnect_delay)
