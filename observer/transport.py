"""Small bounded HTTPS transport; TLS must complete before abort evidence counts."""

from dataclasses import dataclass, field
import http.client
import ipaddress
import socket
import ssl
import struct
import time
from urllib.parse import urlsplit

MAX_BODY = 16384


@dataclass
class Response:
    kind: str
    tls: bool = False
    status: int = 0
    headers: dict = field(default_factory=dict)
    body: bytes = b""
    latency_ms: int = 0


def endpoint(url):
    if not isinstance(url, str) or len(url) > 2048:
        raise ValueError("invalid endpoint")
    if any(ord(c) < 33 or ord(c) > 126 for c in url):
        raise ValueError("endpoint must be encoded ASCII without control characters")
    p = urlsplit(url)
    if (p.scheme != "https" or not p.hostname or p.username is not None
            or p.password is not None or p.fragment or p.query):
        raise ValueError("endpoint must be HTTPS without credentials, query or fragment")
    host = p.hostname.encode("idna").decode("ascii")
    if len(host) > 253 or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789.-" for c in host.lower()):
        raise ValueError("endpoint requires a DNS hostname")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("endpoint requires DNS, not an address literal")
    path = p.path or "/"
    if any(ord(c) < 33 or ord(c) > 126 for c in path):
        raise ValueError("endpoint path must be encoded ASCII")
    port = p.port if p.port is not None else 443
    if not 1 <= port <= 65535:
        raise ValueError("invalid HTTPS port")
    return host, port, path


def recv_exact(sock, count):
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise OSError("proxy EOF")
        data += chunk
    return data


def socks_connect(sock, host, port):
    """RFC1928 CONNECT with ATYP=DOMAINNAME: destination DNS stays in proxy."""
    name = host.encode("idna")
    sock.sendall(b"\x05\x01\x00")
    if recv_exact(sock, 2) != b"\x05\x00":
        raise OSError("proxy authentication refused")
    sock.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + struct.pack("!H", port))
    reply = recv_exact(sock, 4)
    if reply[:3] != b"\x05\x00\x00":
        raise OSError("proxy connection refused")
    if reply[3] == 1:
        count = 4
    elif reply[3] == 4:
        count = 16
    elif reply[3] == 3:
        count = recv_exact(sock, 1)[0]
    else:
        raise OSError("invalid proxy reply")
    recv_exact(sock, count + 2)


class LimitedFile:
    """Bound cumulative HTTP headers, not just individual http.client lines."""
    def __init__(self, fp):
        self.fp = fp
        self.header_bytes = 0

    def readline(self, limit=-1):
        value = self.fp.readline(min(8193, limit) if limit > 0 else 8193)
        self.header_bytes += len(value)
        if len(value) > 8192 or self.header_bytes > 16384:
            raise ValueError("headers too large")
        return value

    def read(self, count=-1):
        return self.fp.read(count)

    def readinto(self, buffer):
        return self.fp.readinto(buffer)

    def flush(self):
        self.fp.flush()

    def close(self):
        self.fp.close()


class HTTPStream:
    def __init__(self, sock):
        self.sock = sock

    def makefile(self, *args, **kwargs):
        return LimitedFile(self.sock.makefile(*args, **kwargs))


def request(url, *, timeout=8, headers=None, payload=None, proxy=None, negative=False):
    started = time.monotonic()
    result = Response("network_error")
    raw = secured = response = None
    try:
        host, port, path = endpoint(url)
        # Direct public probes never use HTTP(S)_PROXY or ALL_PROXY environment values.
        raw = socket.create_connection(("127.0.0.1", proxy) if proxy else (host, port), timeout)
        if proxy:
            socks_connect(raw, host, port)
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        secured = context.wrap_socket(raw, server_hostname=host, suppress_ragged_eofs=False)
        result.tls = True
        fields = {"Host": host if port == 443 else f"{host}:{port}",
                  "Connection": "close", "Accept": "application/json", "Cache-Control": "no-cache"}
        fields.update(headers or {})
        if payload is not None:
            fields.update({"Content-Type": "application/json", "Content-Length": str(len(payload))})
        if any("\r" in str(v) or "\n" in str(v) for v in fields.values()):
            raise ValueError("invalid request header")
        method = "POST" if payload is not None else "GET"
        wire = f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in fields.items()) + "\r\n"
        secured.sendall(wire.encode("ascii") + (payload or b""))
        response = http.client.HTTPResponse(HTTPStream(secured))
        response.begin()
        result.status = response.status
        # Duplicate headers are rejected rather than silently overriding freshness controls.
        pairs = response.getheaders()
        if len({k.lower() for k, _ in pairs}) != len(pairs):
            raise ValueError("duplicate headers")
        result.headers = {k.lower(): v for k, v in pairs}
        result.kind = "http"
        if negative:
            return result  # No response body retained for negative exposure probes.
        if result.headers.get("content-encoding", "identity").lower() != "identity":
            raise ValueError("compressed response refused")
        result.body = response.read(MAX_BODY + 1)
        if len(result.body) > MAX_BODY:
            raise ValueError("body too large")
    except http.client.RemoteDisconnected:
        result.kind = "post_tls_eof" if result.tls else "network_error"
    except ssl.SSLEOFError:
        result.kind = "post_tls_eof" if result.tls else "tls_error"
    except ConnectionResetError:
        result.kind = "post_tls_reset" if result.tls else "network_error"
    except (TimeoutError, socket.timeout):
        result.kind = "timeout"
    except ssl.SSLError:
        result.kind = "tls_error"
    except (ValueError, http.client.HTTPException, UnicodeError):
        result.kind = "invalid_response"
    except OSError:
        result.kind = "network_error"
    finally:
        if response:
            response.close()
        if secured:
            secured.close()
        elif raw:
            raw.close()
        result.latency_ms = round((time.monotonic() - started) * 1000)
    return result
