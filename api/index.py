import secrets
import socket
import struct
import time
import hashlib
import asyncio
from Crypto.Cipher import AES
from Crypto.Util import Counter
from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse, JSONResponse, Response
import httpx

app = FastAPI()

# ---------------- MTProto DC relay ----------------

DC_IPS = {
    1: "149.154.175.50",
    2: "149.154.167.51",
    3: "149.154.175.100",
    4: "149.154.167.91",
    5: "149.154.171.5",
}

FORBIDDEN = (0xDDDDDDDD, 0xEEEEEEEE, 0x44414548, 0x54534F50, 0x20544547, 0x4954504F, 0x47525650, 0x02010316)


class DcConn:
    """One obfuscated abridged MTProto TCP connection. Standard obfuscated2
    (Telethon ConnectionTcpObfuscated): raw CTR keys derived from the init,
    abridged framing inside. One frame per request, then closed."""

    def __init__(self, dc: int):
        self.ip = DC_IPS[dc]
        self.sock = socket.create_connection((self.ip, 443), timeout=10)
        self.sock.settimeout(25)

        while True:
            init = bytearray(secrets.token_bytes(64))
            first = struct.unpack("<I", init[:4])[0]
            if (
                init[0] == 0xEF
                or first in FORBIDDEN
                or init[4:8] == b"\x00\x00\x00\x00"
            ):
                continue
            break
        init[56:60] = b"\xef\xef\xef\xef"

        self.enc = self._ctr(bytes(init[8:40]), bytes(init[40:56]))
        rev = bytes(init[8:56])[::-1]
        self.dec = self._ctr(rev[:32], rev[32:48])

        full = self.enc.encrypt(bytes(init))
        wire = bytes(init[:56]) + full[56:64]
        self.sock.sendall(wire)

    @staticmethod
    def _ctr(key: bytes, iv: bytes) -> AES:
        return AES.new(key, AES.MODE_CTR, counter=Counter.new(128, initial_value=int.from_bytes(iv, "big")))

    def send_frame(self, payload: bytes) -> None:
        words = len(payload) // 4
        header = bytes([words]) if words < 0x7F else b"\x7f" + words.to_bytes(3, "little")
        self.sock.sendall(self.enc.encrypt(header + payload))

    def recv_frame(self) -> bytes:
        buf = b""
        while True:
            if buf:
                first = buf[0]
                if first & 0x80:
                    if len(buf) < 4:
                        buf += self._read()
                        continue
                    buf = buf[4:]
                    continue
                if first == 0x7F:
                    if len(buf) < 4:
                        buf += self._read()
                        continue
                    words = int.from_bytes(buf[1:4], "little")
                    header_len = 4
                else:
                    words = first
                    header_len = 1
                total = header_len + words * 4
                if len(buf) >= total:
                    return buf[header_len:total]
            buf += self._read()

    def _read(self) -> bytes:
        chunk = self.sock.recv(65536)
        if not chunk:
            raise ConnectionError("dc closed connection")
        return self.dec.decrypt(chunk)

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def msg_id() -> int:
    return ((int(time.time()) << 32) | secrets.randbits(32)) & 0xFFFFFFFFFFFFFFFF


class ProxyConn(DcConn):
    """MTProto proxy connection (Telethon TcpMTProxy): obfuscated2 with the
    proxy secret in the key derivation, DC id at init bytes 60-61."""

    def __init__(self, server: str, port: int, secret16: bytes, dc: int):
        self.sock = socket.create_connection((server, port), timeout=5)
        self.sock.settimeout(6)

        while True:
            init = bytearray(secrets.token_bytes(64))
            first = struct.unpack("<I", init[:4])[0]
            if (
                init[0] == 0xEF
                or first in FORBIDDEN
                or init[4:8] == b"\x00\x00\x00\x00"
            ):
                continue
            break
        init[56:60] = b"\xef\xef\xef\xef"
        init[60:62] = struct.pack("<h", dc)

        rev = bytes(init[8:56])[::-1]
        self.enc = self._ctr(hashlib.sha256(bytes(init[8:40]) + secret16).digest(), bytes(init[40:56]))
        self.dec = self._ctr(hashlib.sha256(rev[:32] + secret16).digest(), rev[32:48])

        full = self.enc.encrypt(bytes(init))
        wire = bytes(init[:56]) + full[56:64]
        self.sock.sendall(wire)

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def _req_pq_plain() -> bytes:
    req_pq = struct.pack("<I", 0xBE7E8EF1) + secrets.token_bytes(16)
    return b"\x00" * 8 + struct.pack("<QQ", msg_id(), len(req_pq)) + req_pq


@app.get("/api/mt/test/{dc}")
async def mt_test(dc: int):
    try:
        conn = DcConn(dc)
    except Exception as e:  # noqa: BLE001
        return JSONResponse({"ok": False, "stage": "connect", "error": repr(e)})
    try:
        conn.send_frame(_req_pq_plain())
        resp = conn.recv_frame()
        body = resp[20 : 20 + struct.unpack("<I", resp[16:20])[0]]
        return JSONResponse(
            {
                "ok": True,
                "dc": dc,
                "ip": conn.ip,
                "resp_len": len(resp),
                "body_head": body[:48].hex(),
                "is_respq": body[:4] == struct.pack("<I", 0x83C09AEC),
            }
        )
    except Exception as e:  # noqa: BLE001
        return JSONResponse({"ok": False, "stage": "rpc", "error": repr(e)})
    finally:
        conn.close()
@app.post("/api/mt/proxytest/{dc}")
async def mt_proxytest(dc: int, request: Request):
    data = await request.json()
    proxies = data.get("proxies", [])
    from concurrent.futures import ThreadPoolExecutor
    proxies = proxies[:20]
    with ThreadPoolExecutor(max_workers=8) as pool:
        futs = [pool.submit(_proxy_test_one, p["server"], p["port"], p["secret"], dc) for p in proxies]
        results = [f.result() for f in futs]
    wins = [r for r in results if r.get("ok")]
    return JSONResponse({"tested": len(results), "wins": wins, "results": results})


# ---------------- Bot API reverse proxy (catch-all, MUST be last) ----------------

@app.post("/api/mt/{dc}")
async def mt_relay(dc: int, request: Request):
    if dc not in DC_IPS:
        return JSONResponse({"ok": False, "error": "unknown dc"}, status_code=400)
    body = await request.body()
    if not body or len(body) % 4 != 0:
        return JSONResponse({"ok": False, "error": "body must be non-empty multiple of 4"}, status_code=400)
    try:
        conn = DcConn(dc)
    except Exception as e:  # noqa: BLE001
        return JSONResponse({"ok": False, "error": repr(e)}, status_code=502)
    try:
        conn.send_frame(body)
        resp = conn.recv_frame()
        return Response(content=resp, media_type="application/octet-stream")
    except Exception as e:  # noqa: BLE001
        return JSONResponse({"ok": False, "error": repr(e)}, status_code=502)
    finally:
        conn.close()

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def proxy(request: Request, path: str):
    target_url = f"https://api.telegram.org/{path}"
    body = await request.body()
    headers = dict(request.headers)
    headers.pop("host", None)
    
    async with httpx.AsyncClient() as client:
        response = await client.request(
            method=request.method,
            url=target_url,
            headers=headers,
            content=body,
            params=dict(request.query_params),
            timeout=30.0
        )
        return StreamingResponse(
            response.aiter_bytes(),
            status_code=response.status_code,
            headers=dict(response.headers)
        )
