"""Live capture.

A thin wrapper over ``AF_PACKET`` (Linux) that writes a classic pcap file. No
libpcap, no BPF program compiler: the tool captures everything the interface
sees and lets the analysis decide what matters. That is a deliberate limit and
it is stated in the README, because a capture filter that silently drops the
traffic you needed is worse than a larger file.

Requires root or ``CAP_NET_RAW``. On any other platform the command says so
plainly instead of failing with an ``OSError`` from the middle of a loop.
"""

from __future__ import annotations

import socket
import struct
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from .pcap import LINKTYPE_ETHERNET, PcapWriter

__all__ = ["CollectResult", "collect", "iface_exists"]

_ETH_P_ALL = 0x0003
_SOL_PACKET = 263
_PACKET_ADD_MEMBERSHIP = 1
_PACKET_MR_PROMISC = 1


class CaptureNotPermitted(RuntimeError):
    """Live capture is unavailable, with a reason a user can act on."""


@dataclass(slots=True)
class CollectResult:
    path: str
    packets: int
    bytes: int
    duration_s: float
    stopped_by: str  # "duration", "count", or "interrupt"


def iface_exists(name: str) -> bool:
    return Path("/sys/class/net", name).exists()


def _enable_promiscuous(sock: socket.socket, iface: str) -> bool:
    """Best effort: promiscuous mode needs a packet membership request."""
    try:
        index = socket.if_nametoindex(iface)
        mreq = struct.pack("=IHH8s", index, _PACKET_MR_PROMISC, 0, b"\x00" * 8)
        sock.setsockopt(_SOL_PACKET, _PACKET_ADD_MEMBERSHIP, mreq)
        return True
    except (OSError, AttributeError):
        return False


def collect(
    iface: str,
    out: str | Path,
    *,
    duration: float | None = None,
    count: int | None = None,
    snaplen: int = 262144,
    promiscuous: bool = True,
) -> CollectResult:
    """Capture frames from ``iface`` into ``out`` until a limit is reached.

    ``duration`` and ``count`` are both optional; with neither, capture runs
    until interrupted, which is what Ctrl-C is for.
    """
    if not sys.platform.startswith("linux"):
        raise CaptureNotPermitted(
            f"live capture uses AF_PACKET sockets, so it needs Linux; this is {sys.platform}. "
            "Analyze a capture file instead, or capture on the target host with tcpdump."
        )
    if not iface_exists(iface):
        raise CaptureNotPermitted(
            f"interface {iface!r} does not exist (known interfaces: {', '.join(sorted(_interfaces()))})"
        )

    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(_ETH_P_ALL))
    except PermissionError:
        raise CaptureNotPermitted(
            "live capture needs root or CAP_NET_RAW; try `sudo netwatch collect ...` "
            "or `sudo setcap cap_net_raw+eip $(command -v netwatch)`"
        ) from None
    except OSError as exc:
        raise CaptureNotPermitted(f"could not open a raw socket: {exc}") from exc

    out = Path(out).expanduser()
    if out.parent and not out.parent.exists():
        out.parent.mkdir(parents=True, exist_ok=True)

    packets = 0
    total_bytes = 0
    started = time.monotonic()
    stopped_by = "interrupt"
    try:
        sock.bind((iface, 0))
        if promiscuous:
            _enable_promiscuous(sock, iface)
        sock.settimeout(0.5)
        with out.open("wb") as handle:
            writer = PcapWriter(handle, linktype=LINKTYPE_ETHERNET, snaplen=snaplen)
            while True:
                if duration is not None and time.monotonic() - started >= duration:
                    stopped_by = "duration"
                    break
                if count is not None and packets >= count:
                    stopped_by = "count"
                    break
                try:
                    frame, _address = sock.recvfrom(snaplen)
                except socket.timeout:
                    continue
                writer.write(time.time_ns(), frame)
                packets += 1
                total_bytes += len(frame)
            writer.close()
    except KeyboardInterrupt:
        stopped_by = "interrupt"
    finally:
        sock.close()

    return CollectResult(
        path=str(out),
        packets=packets,
        bytes=total_bytes,
        duration_s=round(time.monotonic() - started, 3),
        stopped_by=stopped_by,
    )


def _interfaces() -> list[str]:
    try:
        return [child.name for child in Path("/sys/class/net").iterdir()]
    except OSError:
        return []
