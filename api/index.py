"""Vercel entrypoint: Bot API reverse proxy + MTProto DC relay + MTProxy test."""
import asyncio
import hashlib
import httpx
import secrets
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor
from Crypto.Cipher import AES
from Crypto.Util import Counter
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

app = FastAPI()

DC_IPS = {
    1: "149.154.175.50",
    2: "149.154.167.51",
    3: "149.154.175.100",
    4: "149.154.167.91",
    5: "149.154.171.5",
}

FORBIDDEN = (0xDDDDDDDD, 0xEEEEEEEE, 0x44414548, 0x54534F50, 0x20544547, 0x4954504F, 0x47525650, 0x02010316)


def _ctr(key: bytes, iv: bytes) -> AES:
    return AES.new(key, AES.MODE_CTR, counter=Counter.new(128, initial_value=int.from_bytes(iv, "big")))


def _msg_id() -> int:
    return ((int(time.time()) << 32) | secrets.randbits(32)) & 0xFFFFFFFFFFFFFFFF


def _req_pq_plain() -> bytes:
    req_pq = struct.pack("<I", 0xBE7E8EF1) + secrets.token_bytes(16)
    return b"\x00" * 8 + struct.pack("<QQ", _msg_id(), len(req_pq)) + req_pq


class DcConn:
    """Obfuscated abridged MTProto TCP connection, standard obfuscated2."""

    def __init__(self, dc: int):
        self._open(DC_IPS[dc], 443, secret=None, dc_id=None)

    def _open(self, host: str, port: int, secret: bytes | None, dc_id: int | None):
        self.sock = socket.create_connection((host, port), timeout=10)
        self.sock.settimeout(25)
        while True:
            init = bytearray(secrets.token_bytes(64))
            first = struct.unpack("<I", init[:4])[0]
            if init[0] == 0xEF or first in FORBIDDEN or init[4:8] == b"\x00\x00\x00\x00":
                continue
            break
        init[56:60] = b"\xef\xef\xef\xef"
        if dc_id is not None:
            init[60:62] = struct.pack("<h", dc_id)

        enc_key = bytes(init[8:40])
        enc_iv = bytes(init[40:56])
        rev = bytes(init[8:56])[::-1]
        dec_key = rev[:32]
        dec_iv = rev[32:48]
        if secret is not None:
            enc_key = hashlib.sha256(enc_key + secret).digest()
            dec_key = hashlib.sha256(dec_key + secret).digest()

        self.enc = _ctr(enc_key, enc_iv)
        self.dec = _ctr(dec_key, dec_iv)
        full = self.enc.encrypt(bytes(init))
        self.sock.sendall(bytes(init[:56]) + full[56:64])

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
            raise ConnectionError("peer closed connection")
        return self.dec.encrypt(chunk)

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


class ProxyConn(DcConn):
    """MTProto proxy connection (Telethon TcpMTProxy): obfuscated2 with the
    proxy secret, DC id at init bytes 60-61."""

    def __init__(self, server: str, port: int, secret16: bytes, dc: int):
        self._open(server, int(port), secret=secret16, dc_id=dc)


def _proxy_test_one(server: str, port: int, secret: str, dc: int) -> dict:
    if secret.startswith("ee"):
        return {"server": server, "port": port, "error": "ee/faketls skipped"}
    if secret.startswith("dd"):
        secret = secret[2:]
    if len(secret) < 32:
        return {"server": server, "port": port, "error": "bad secret"}
    secret16 = bytes.fromhex(secret[:32])
    conn = None
    try:
        conn = ProxyConn(server, port, secret16, dc)
        conn.send_frame(_req_pq_plain())
        resp = conn.recv_frame()
        body = resp[20 : 20 + struct.unpack("<I", resp[16:20])[0]]
        is_respq = body[:4] == struct.pack("<I", 0x83C09AEC)
        return {"server": server, "port": port, "ok": is_respq, "resp": body[:8].hex()}
    except Exception as e:  # noqa: BLE001
        return {"server": server, "port": port, "error": repr(e)}
    finally:
        if conn:
            conn.close()


# ---------------- MTProto endpoints (registered BEFORE the catch-all) --------

@app.get("/api/mt/version")
async def mt_version():
    return JSONResponse({"ok": True, "version": "v4-clean"})


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
    try:
        data = await request.json()
    except Exception as e:  # noqa: BLE001
        return JSONResponse({"ok": False, "error": "bad json: " + repr(e)}, status_code=400)
    proxies = data.get("proxies", [])[:20]

    def run_all():
        with ThreadPoolExecutor(max_workers=8) as pool:
            futs = [pool.submit(_proxy_test_one, p["server"], p["port"], p["secret"], dc) for p in proxies]
            return [f.result() for f in futs]

    import anyio

    try:
        results = await anyio.to_thread.run_sync(run_all)
    except Exception:  # noqa: BLE001
        import traceback

        return JSONResponse({"ok": False, "error": traceback.format_exc()[-1200:]}, status_code=200)
    wins = [r for r in results if r.get("ok")]
    return JSONResponse({"tested": len(results), "wins": wins, "results": results})


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


# ---------------- Bot API reverse proxy (catch-all, MUST stay last) ---------

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
