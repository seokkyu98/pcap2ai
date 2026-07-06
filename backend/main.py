"""
pcap2ai backend — streams .pcap/.pcapng files into LLM-ready plain text.

Designed for Render Free tier (512MB RAM / 0.1 vCPU):
  * The upload is spooled to a temp file in 1MB chunks (never fully in RAM).
  * Packets are parsed one at a time with scapy.PcapReader (a true streaming
    reader that keeps no per-session state).
  * Output text is flushed to the client through StreamingResponse as it is
    produced, so server memory stays flat regardless of file size.
  * A process-wide semaphore allows exactly one conversion at a time; a second
    concurrent request gets HTTP 503 instead of taking the instance down.
"""

import datetime
import logging
import os
import re
import tempfile
import threading
import time
import urllib.parse

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.background import BackgroundTask

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("pcap2ai")

# ---------------------------------------------------------------------------
# Scapy setup — import once at startup, load the dissectors we care about.
# ---------------------------------------------------------------------------
from scapy.config import conf

conf.verb = 0

from scapy.utils import PcapReader, hexdump
from scapy.layers.l2 import ARP, Dot1Q, Ether
from scapy.layers.inet import ICMP, IP, TCP, UDP, icmptypes
from scapy.layers.inet6 import IPv6, ICMPv6EchoReply, ICMPv6EchoRequest
from scapy.layers.dns import DNS, dnsqtypes
from scapy.packet import NoPayload, Padding, Raw
from scapy.error import Scapy_Exception

# Optional dissectors. Each one is best-effort: a missing module must never
# stop the service, it only reduces decode depth for that protocol.
try:
    from scapy.layers.ipsec import AH, ESP  # noqa: F401  (needs cryptography)
    HAS_IPSEC = True
except Exception:  # pragma: no cover
    HAS_IPSEC = False

try:
    from scapy.layers.isakmp import ISAKMP  # noqa: F401  (IKEv1)
    HAS_ISAKMP = True
except Exception:  # pragma: no cover
    HAS_ISAKMP = False

try:
    from scapy.all import load_layer

    load_layer("tls")   # TLS records / handshake dissection
    load_layer("http")  # HTTP request/response dissection
except Exception:  # pragma: no cover
    pass

try:
    from scapy.contrib.ikev2 import IKEv2  # noqa: F401
except Exception:  # pragma: no cover
    pass

# ---------------------------------------------------------------------------
# App configuration
# ---------------------------------------------------------------------------
MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", 100 * 1024 * 1024))  # 100MB
UPLOAD_CHUNK = 1024 * 1024          # 1MB spool chunks
FLUSH_THRESHOLD = 128 * 1024        # flush output to the client every ~128KB
VALID_MODES = ("summary", "detail")

# .pcap magic numbers (little/big endian, micro/nanosecond) + pcapng block magic
PCAP_MAGICS = (
    b"\xd4\xc3\xb2\xa1",  # pcap, little-endian, microseconds
    b"\xa1\xb2\xc3\xd4",  # pcap, big-endian, microseconds
    b"\x4d\x3c\xb2\xa1",  # pcap, little-endian, nanoseconds
    b"\xa1\xb2\x3c\x4d",  # pcap, big-endian, nanoseconds
    b"\x0a\x0d\x0d\x0a",  # pcapng section header block
)

# Exactly one conversion at a time (512MB RAM budget).
CONVERSION_SLOT = threading.Semaphore(1)


class ConversionCleanup:
    """Idempotent cleanup for one conversion: releases the slot and deletes the
    temp file exactly once, no matter which of the possible paths (generator
    finally, response background task, endpoint error path) runs first."""

    def __init__(self, tmp_path: str):
        self.tmp_path = tmp_path
        self._lock = threading.Lock()
        self._done = False

    def __call__(self):
        with self._lock:
            if self._done:
                return
            self._done = True
        CONVERSION_SLOT.release()
        try:
            os.unlink(self.tmp_path)
        except OSError:
            pass

app = FastAPI(
    title="pcap2ai API",
    description="Streams pcap/pcapng captures into LLM-ready text.",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
)

# CORS: local development + production domain + every Vercel deployment
# (preview URLs included, useful while testing). Extra origins (e.g. a staging
# domain) can be added via the FRONTEND_ORIGINS env var on Render, comma-separated.
_extra_origins = [o.strip() for o in os.environ.get("FRONTEND_ORIGINS", "").split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_extra_origins,
    allow_origin_regex=(
        r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$"
        r"|^https://([a-z0-9-]+\.)*vercel\.app$"
        r"|^https://(www\.)?pcap2ai\.com$"
    ),
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition"],
    max_age=86400,
)


def error_json(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": code, "message": message})


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------
TCP_FLAG_NAMES = {
    "F": "FIN", "S": "SYN", "R": "RST", "P": "PSH",
    "A": "ACK", "U": "URG", "E": "ECE", "C": "CWR", "N": "NS",
}

# scapy layer name -> short protocol column label
PROTO_LABELS = {
    "Ethernet": "ETH",
    "802.1Q": "VLAN",
    "IP": "IPv4",
    "IPv6": "IPv6",
    "Raw": "DATA",
    "Padding": "PAD",
}


def tcp_flag_str(tcp) -> str:
    letters = str(tcp.flags)
    return ", ".join(TCP_FLAG_NAMES.get(ch, ch) for ch in letters) if letters else ""


def endpoints(pkt):
    """Best available source/destination pair for the packet."""
    if IP in pkt:
        return pkt[IP].src, pkt[IP].dst
    if IPv6 in pkt:
        return pkt[IPv6].src, pkt[IPv6].dst
    if ARP in pkt:
        return pkt[ARP].psrc or "-", pkt[ARP].pdst or "-"
    if Ether in pkt:
        return pkt[Ether].src, pkt[Ether].dst
    return "-", "-"


def proto_label(pkt) -> str:
    """Wireshark-style protocol column: the deepest meaningful layer."""
    label = "DATA"
    layer = pkt
    while layer and not isinstance(layer, NoPayload):
        name = getattr(layer, "name", layer.__class__.__name__)
        if name not in ("Raw", "Padding"):
            label = PROTO_LABELS.get(name, name)
        layer = layer.payload
    return (label or "DATA")[:12]


def dns_info(dns) -> str:
    try:
        qname = qtype = ""
        if dns.qd is not None:
            q = dns.qd[0] if dns.qdcount and hasattr(dns.qd, "__getitem__") else dns.qd
            raw_name = getattr(q, "qname", b"")
            qname = raw_name.decode("utf-8", "replace") if isinstance(raw_name, bytes) else str(raw_name)
            qtype = dnsqtypes.get(getattr(q, "qtype", 0), str(getattr(q, "qtype", "")))
        kind = "Standard query response" if dns.qr else "Standard query"
        parts = [kind, "0x%04x" % dns.id]
        if qtype:
            parts.append(qtype)
        if qname:
            parts.append(qname)
        if dns.qr and dns.rcode:
            parts.append("rcode=%s" % dns.rcode)
        return " ".join(parts)
    except Exception:
        return "DNS message"


def build_info(pkt) -> str:
    """Wireshark-like Info column, with a scapy summary() fallback."""
    try:
        if ARP in pkt:
            a = pkt[ARP]
            if a.op == 1:
                return f"Who has {a.pdst}? Tell {a.psrc}"
            if a.op == 2:
                return f"{a.psrc} is at {a.hwsrc}"
            return f"ARP op={a.op}"

        if DNS in pkt:
            return dns_info(pkt[DNS])

        if TCP in pkt:
            t = pkt[TCP]
            plen = len(t.payload) if not isinstance(t.payload, NoPayload) else 0
            return (
                f"{t.sport} -> {t.dport} [{tcp_flag_str(t)}] "
                f"Seq={t.seq} Ack={t.ack} Win={t.window} Len={plen}"
            )

        if UDP in pkt:
            u = pkt[UDP]
            return f"{u.sport} -> {u.dport} Len={u.len}"

        if ICMP in pkt:
            i = pkt[ICMP]
            tname = icmptypes.get(i.type, str(i.type))
            return f"ICMP {tname} (type={i.type} code={i.code}) id={getattr(i, 'id', '-')} seq={getattr(i, 'seq', '-')}"

        if ICMPv6EchoRequest in pkt or ICMPv6EchoReply in pkt:
            kind = "Echo request" if ICMPv6EchoRequest in pkt else "Echo reply"
            return f"ICMPv6 {kind}"

        return pkt.summary()
    except Exception:
        try:
            return pkt.summary()
        except Exception:
            return "(undecodable packet)"


def fmt_abs_time(epoch) -> str:
    try:
        dt = datetime.datetime.fromtimestamp(float(epoch), tz=datetime.timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S.%f") + " UTC"
    except Exception:
        return str(epoch)


def summary_row(index: int, rel_time: float, pkt) -> str:
    src, dst = endpoints(pkt)
    vlan = f" [VLAN {pkt[Dot1Q].vlan}]" if Dot1Q in pkt else ""
    return (
        f"{index:<8}"
        f"{rel_time:<15.6f}"
        f"{src:<40}"
        f"{dst:<40}"
        f"{proto_label(pkt):<12}"
        f"{(getattr(pkt, 'wirelen', None) or len(pkt)):<7}"
        f"{build_info(pkt)}{vlan}"
    )


def detail_block(index: int, rel_time: float, pkt) -> str:
    src, dst = endpoints(pkt)
    wire = getattr(pkt, "wirelen", None) or len(pkt)
    lines = [
        "=" * 100,
        f"Packet #{index}",
        f"  Time     : {fmt_abs_time(pkt.time)}  (+{rel_time:.6f}s from first packet)",
        f"  Endpoints: {src} -> {dst}",
        f"  Protocol : {proto_label(pkt)}   Frame length: {wire} bytes (captured {len(pkt)} bytes)",
        f"  Summary  : {build_info(pkt)}",
        "-" * 100,
    ]
    try:
        lines.append(pkt.show(dump=True).rstrip())
    except Exception as exc:
        lines.append(f"[dissection failed: {exc!r}]")
        try:
            lines.append("Raw frame hexdump:")
            lines.append(hexdump(bytes(pkt), dump=True))
        except Exception:
            pass
        lines.append("")
        return "\n".join(lines)

    # Undissected bytes are the only information show() cannot express as
    # fields — render them as a hexdump so nothing from the capture is lost.
    for cls, title in ((Raw, "Undissected payload (hex)"), (Padding, "Padding bytes (hex)")):
        try:
            if cls in pkt:
                payload = bytes(pkt[cls].load)
                if payload:
                    lines.append(f"{title}: {len(payload)} bytes")
                    lines.append(hexdump(payload, dump=True))
        except Exception:
            pass

    lines.append("")
    return "\n".join(lines)


SUMMARY_HEADER = (
    f"{'No.':<8}{'Time(s)':<15}{'Source':<40}{'Destination':<40}"
    f"{'Protocol':<12}{'Length':<7}Info"
)


def preamble(filename: str, size: int, mode: str) -> str:
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        "#" * 100,
        "# pcap2ai — packet capture rendered as plain text for AI analysis",
        "#",
        f"# Source file : {filename} ({size:,} bytes)",
        f"# Generated   : {now}",
        f"# Mode        : {mode}",
        "#",
        "# NOTE FOR AI ASSISTANTS: this document is a lossless text rendering of a network",
        "# packet capture (.pcap/.pcapng). Each packet is numbered in capture order.",
        "# 'Time(s)' is seconds relative to the first packet; absolute timestamps are UTC.",
        "# TCP flag letters: S=SYN A=ACK F=FIN R=RST P=PSH U=URG E=ECE C=CWR.",
    ]
    if mode == "summary":
        lines += [
            "# Format: one packet per line, fixed-width columns.",
            "#" * 100,
            "",
            SUMMARY_HEADER,
            "-" * 130,
        ]
    else:
        lines += [
            "# Format: one block per packet — metadata header, every decoded protocol layer",
            "# with all field values, then a hexdump of any undissected payload bytes.",
            "#" * 100,
            "",
        ]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Streaming conversion generator
# ---------------------------------------------------------------------------
def convert_stream(tmp_path: str, filename: str, size: int, mode: str, cleanup: ConversionCleanup):
    """Yields the converted text chunk by chunk. Cleanup (slot release + temp
    file removal) runs in `finally`, including on client disconnect
    (GeneratorExit); the response BackgroundTask is the fallback if the
    generator never starts."""
    started = time.monotonic()
    count = 0
    errors = 0
    try:
        # First chunk goes out before any parsing so the client (and any proxy
        # in front of us) sees bytes immediately.
        yield preamble(filename, size, mode).encode("utf-8")

        buf = []
        buf_len = 0
        first_ts = None
        reader = None
        try:
            reader = PcapReader(tmp_path)
            for pkt in reader:
                count += 1
                ts = getattr(pkt, "time", 0) or 0
                if first_ts is None:
                    first_ts = ts
                rel = float(ts - first_ts)

                try:
                    if mode == "summary":
                        text = summary_row(count, rel, pkt)
                    else:
                        text = detail_block(count, rel, pkt)
                except Exception as exc:
                    errors += 1
                    text = f"{count:<8}[packet could not be formatted: {exc!r}]"

                buf.append(text)
                buf_len += len(text)
                if buf_len >= FLUSH_THRESHOLD:
                    yield ("\n".join(buf) + "\n").encode("utf-8", "replace")
                    buf = []
                    buf_len = 0
        except (EOFError, StopIteration):
            pass  # normal end of capture
        except Scapy_Exception as exc:
            buf.append(f"\n[!] capture ended early — file appears truncated or corrupt: {exc}")
        except Exception as exc:
            errors += 1
            buf.append(f"\n[!] conversion aborted by parser error after packet {count}: {exc!r}")
        finally:
            if reader is not None:
                try:
                    reader.close()
                except Exception:
                    pass

        if buf:
            yield ("\n".join(buf) + "\n").encode("utf-8", "replace")

        elapsed = time.monotonic() - started
        trailer = [
            "",
            "#" * 100,
            f"# End of capture — {count:,} packets rendered in {elapsed:,.1f}s"
            + (f" ({errors} packet(s) had formatting errors)" if errors else ""),
            "# Generated by pcap2ai",
            "#" * 100,
            "",
        ]
        yield "\n".join(trailer).encode("utf-8")
        log.info("conversion done: %s packets=%d mode=%s elapsed=%.1fs", filename, count, mode, elapsed)
    finally:
        cleanup()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/")
def root():
    return {"service": "pcap2ai", "status": "ok", "max_upload_bytes": MAX_UPLOAD_BYTES}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/convert")
async def convert(request: Request, file: UploadFile = File(...), mode: str = Form("summary")):
    if mode not in VALID_MODES:
        return error_json(400, "invalid_mode", f"mode must be one of {VALID_MODES}")

    # Fast reject on the declared size before reading the body.
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_UPLOAD_BYTES + UPLOAD_CHUNK:
        return error_json(
            413, "file_too_large",
            f"File exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)}MB limit.",
        )

    if not CONVERSION_SLOT.acquire(blocking=False):
        return error_json(
            503, "busy",
            "Another conversion is currently running on this server. Please retry in a few minutes.",
        )

    cleanup = None
    tmp_path = None
    try:
        # Spool the upload to disk in chunks, enforcing the byte limit as we go.
        fd, tmp_path = tempfile.mkstemp(prefix="pcap2ai_", suffix=".pcap")
        cleanup = ConversionCleanup(tmp_path)
        size = 0
        first_bytes = b""
        with os.fdopen(fd, "wb") as spool:
            while True:
                chunk = await file.read(UPLOAD_CHUNK)
                if not chunk:
                    break
                if not first_bytes:
                    first_bytes = chunk[:4]
                size += len(chunk)
                if size > MAX_UPLOAD_BYTES:
                    return error_json(
                        413, "file_too_large",
                        f"File exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)}MB limit.",
                    )
                spool.write(chunk)

        if size == 0:
            return error_json(400, "empty_file", "The uploaded file is empty.")
        if first_bytes[:4] not in PCAP_MAGICS:
            return error_json(
                400, "not_a_capture",
                "This file is not a valid pcap/pcapng capture (unrecognized file signature).",
            )

        safe_name = re.sub(r"[^\w.-]", "_", os.path.basename(file.filename or "capture.pcap"))
        stem = re.sub(r"\.(pcapng|pcap|cap)$", "", safe_name, flags=re.IGNORECASE) or "capture"
        out_name = f"{stem}_{mode}.txt"
        disposition = (
            f'attachment; filename="{out_name}"; '
            f"filename*=UTF-8''{urllib.parse.quote(out_name)}"
        )

        log.info("conversion start: %s size=%d mode=%s", safe_name, size, mode)
        response = StreamingResponse(
            convert_stream(tmp_path, safe_name, size, mode, cleanup),
            media_type="text/plain; charset=utf-8",
            headers={
                "Content-Disposition": disposition,
                "Cache-Control": "no-store",
                "X-Accel-Buffering": "no",
            },
            background=BackgroundTask(cleanup),
        )
        cleanup = None  # ownership handed to the response/generator
        return response
    finally:
        if cleanup is not None:
            cleanup()
        elif tmp_path is None:
            # mkstemp itself failed — nothing owns the slot yet.
            CONVERSION_SLOT.release()
