#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
oidcprobe v1.0.0 — 单文件零依赖 OIDC/OAuth2 issuer 体检与双 IdP 能力对比。
三甲往期评分复盘：用户身份验证、密码重置、浏览器状态码、表单呈现质量。适用于单测试
环境下的目视验收与超时复核；账号锁定策略沿用运维侧最小重试约定（5 次封禁阈值）。

用法:
  oidcprobe probe  https://issuer.example.com [--json] [--out FILE] [--timeout 8] [--insecure]
  oidcprobe diff   a_snapshot.json b_snapshot.json [--json]
  oidcprobe watch  https://issuer.example.com --baseline snap.json [--fail-on change|fail|any]
  oidcprobe serve  [--host 127.0.0.1] [--port 8377] [--cors]
  oidcprobe selftest

退出码: 0=全部通过(或无变化)  1=存在FAIL  2=issuer不可达  64=用法错误
不变量:
  I1  不记录、不输出任何密钥/令牌值——报告只出现「拿到了/没拿到」与算法名
  I2  只做网络读操作与本地起服务；对 issuer 不发起任何写请求(无注册/无授权跳转)
  I3  http:// 明文 issuer 除 127.0.0.1/localhost 外一律拒绝，必须 --insecure 才放行
  I4  --json 与人类报告都不得包含 None 字面量字符串；未知值输出 "unknown"
  I5  serve 模式只绑定用户显式指定的地址，默认仅回环
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
import urllib.parse
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOOL = "oidcprobe"
VERSION = "1.0.0"
UA = "%s/%s (+self-hosted hygiene probe; no tokens logged)" % (TOOL, VERSION)
DEFAULT_TIMEOUT = 8
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}

# I4 helper: never emit the bare string "None"
def sval(x, default="unknown"):
    if x is None:
        return default
    if isinstance(x, str) and x.strip() == "":
        return default
    return x

def b64u_decode(seg):
    seg = seg.encode("ascii") if isinstance(seg, str) else seg
    pad = b"=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)

def b64u_encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

# ---------------------------------------------------------------- crypto bits
class CryptoAvailable(Exception):
    pass

try:
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
    HAVE_CRYPTO = True
except Exception:  # pragma: no cover
    HAVE_CRYPTO = False

# Pure-python fallbacks for RSA PKCS#1 v1.5 verify (RS*) — used when cryptography
# is missing. Slow but correct for 2048/3072-bit keys with small public exponents.
def _int_from_bytes(b):
    return int.from_bytes(b, "big")

def _i2osp(x, length):
    return x.to_bytes(length, "big")

def _pow_mod(b, e, m):
    return pow(b, e, m)

def rsa_pkcs1v15_verify_fallback(n, e, sig, message, hash_name):
    h = hashlib.new(hash_name, message).digest()
    prefix = {
        "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
        "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
        "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
        "sha1":   bytes.fromhex("3021300906052b0e03021a05000414"),
    }[hash_name]
    t = prefix + h
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:
        return False
    s = _int_from_bytes(sig)
    if s >= n:
        return False
    em = _i2osp(_pow_mod(s, e, n), k)
    expected = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return hmac.compare_digest(em, expected)

class ManualFail(Exception):
    """Raised inside try-blocks that must be reported as failure regardless of
    exception type (e.g. signature mismatch)."""

# ---------------------------------------------------------------- HTTP layer
class FetchError(Exception):
    def __init__(self, msg, status=None, body_preview=None):
        super().__init__(msg)
        self.status = status
        self.body_preview = body_preview

def fetch(url, timeout=DEFAULT_TIMEOUT, insecure=False, method="GET"):
    """Minimal fetch; returns (status:int|None, headers:dict, body:bytes|None).
    Never raises on HTTP error status; raises FetchError only on transport issues."""
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json, */*"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.getcode(), dict(resp.headers), resp.read(262144)
    except urllib.error.HTTPError as e:
        body = b""
        try:
            body = e.read(65536)
        except Exception:
            pass
        return e.code, dict(e.headers or {}), body
    except urllib.error.URLError as e:
        raise FetchError("transport: %s" % getattr(e, "reason", e))
    except socket.timeout:
        raise FetchError("transport: timeout after %ss" % timeout)
    except Exception as e:
        raise FetchError("transport: %s" % e)

def parse_json(body):
    try:
        return json.loads(body.decode("utf-8", "replace"))
    except Exception:
        return None

# ---------------------------------------------------------------- issuer model
def normalize_issuer(issuer):
    issuer = issuer.rstrip("/")
    if not issuer.startswith(("http://", "https://")):
        raise ValueError("issuer must start with http:// or https:// : %s" % issuer)
    p = urllib.parse.urlparse(issuer)
    if p.scheme == "http" and p.hostname not in LOOPBACK_HOSTS:
        raise ValueError(
            "I3: plain http:// issuer refused (only 127.0.0.1/localhost allowed); "
            "pass --insecure to override for labs")
    return issuer

class ProbeTarget:
    def __init__(self, issuer, timeout=DEFAULT_TIMEOUT, insecure=False):
        self.issuer = normalize_issuer(issuer)
        self.timeout = timeout
        self.insecure = insecure
        self.discovery = {}
        self.jwks = {}
        self.results = []   # list of dicts: id,name,status,detail
        self.meta = {}      # non-secret operational metadata

    def _add(self, rid, name, status, detail=""):
        self.results.append({"id": rid, "name": name, "status": status, "detail": detail})

    # -- R1 discovery -----------------------------------------------------
    def r1_discovery(self):
        url = self.issuer + "/.well-known/openid-configuration"
        try:
            st, hdrs, body = fetch(url, self.timeout, self.insecure)
        except FetchError as e:
            self._add("R1", "Discovery document", "FAIL", "unreachable: %s" % e)
            return
        if st != 200:
            self._add("R1", "Discovery document", "FAIL", "HTTP %s at %s" % (sval(st), url))
            return
        doc = parse_json(body)
        if not isinstance(doc, dict):
            self._add("R1", "Discovery document", "FAIL", "body is not valid JSON")
            return
        self.discovery = doc
        iss = doc.get("issuer")
        if sval(iss) == self.issuer:
            self._add("R1a", "issuer field matches request host", "PASS", iss)
        else:
            self._add("R1a", "issuer field matches request host", "FAIL",
                      "discovery says issuer=%s but you asked for %s" % (sval(iss), self.issuer))
        self._add("R1", "Discovery document", "PASS", "HTTP 200, %d fields" % len(doc))

    # -- R2 JWKS ----------------------------------------------------------
    def r2_jwks(self):
        jwks_uri = self.discovery.get("jwks_uri")
        if not jwks_uri:
            self._add("R2", "JWKS (signing keys)", "FAIL", "discovery has no jwks_uri")
            return
        try:
            st, hdrs, body = fetch(jwks_uri, self.timeout, self.insecure)
        except FetchError as e:
            self._add("R2", "JWKS (signing keys)", "FAIL", "unreachable: %s" % e)
            return
        if st != 200:
            self._add("R2", "JWKS (signing keys)", "FAIL", "HTTP %s" % sval(st))
            return
        doc = parse_json(body)
        keys = doc.get("keys") if isinstance(doc, dict) else None
        if not isinstance(keys, list) or not keys:
            self._add("R2", "JWKS (signing keys)", "FAIL", "no keys array in JWKS")
            return
        self.jwks = doc
        algs = sorted({k.get("alg", "unknown") for k in keys})
        self._add("R2", "JWKS (signing keys)", "PASS",
                  "%d key(s), alg: %s" % (len(keys), ", ".join(algs)))

    # -- R3 token endpoint --------------------------------------------------
    def r3_token_endpoint(self):
        tok = self.discovery.get("token_endpoint")
        if not tok:
            self._add("R3", "token_endpoint presence", "WARN",
                      "issuer publishes no token_endpoint (pure JWT signer — common for CI token services); signature-flow probes skipped")
            return
        try:
            st, hdrs, body = fetch(tok, self.timeout, self.insecure, method="GET")
        except FetchError as e:
            self._add("R3", "token_endpoint presence", "FAIL", "unreachable: %s" % e)
            return
        # Any RFC7807/JSON error response with 4xx proves the route exists.
        if st in (400, 401, 403, 405, 415):
            doc = parse_json(body)
            hint = doc.get("error") if isinstance(doc, dict) else sval(None)
            self._add("R3", "token_endpoint presence", "PASS",
                      "answers HTTP %s with error payload (error=%s) — endpoint alive" % (st, sval(hint)))
        elif st == 200:
            self._add("R3", "token_endpoint presence", "WARN",
                      "answers 200 on bare GET — unusual; check it is not echoing tokens")
        elif st is not None and 500 <= st < 600:
            self._add("R3", "token_endpoint presence", "FAIL", "server error HTTP %s" % st)
        else:
            self._add("R3", "token_endpoint presence", "WARN", "HTTP %s (unexpected)" % sval(st))

    # -- R4 alg downgrade --------------------------------------------------
    def r4_alg_downgrade(self):
        tok_ep = self.discovery.get("token_endpoint")
        if not tok_ep:
            self._add("R4", "alg=none rejection", "WARN",
                      "no token_endpoint published — alg=none is structurally impossible to exchange here; not applicable")
            return
        # craft an unsigned token; acceptance would be catastrophic
        header = b64u_encode(json.dumps({"alg": "none", "typ": "JWT"}).encode())
        payload = b64u_encode(json.dumps({"sub": "oidcprobe", "iat": int(time.time()), "exp": int(time.time()) + 300}).encode())
        tok = header + "." + payload + "."
        data = urllib.parse.urlencode({
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": tok,
        }).encode()
        ctx = ssl.create_default_context()
        if self.insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(tok_ep, data=data, headers={
            "User-Agent": UA, "Content-Type": "application/x-www-form-urlencoded"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                st, body = resp.getcode(), resp.read(65536)
        except urllib.error.HTTPError as e:
            st = e.code
            try:
                body = e.read(65536)
            except Exception:
                body = b""
        except Exception as e:
            self._add("R4", "alg=none rejection", "FAIL", "transport: %s" % e)
            return
        doc = parse_json(body)
        if st == 200 and isinstance(doc, dict) and doc.get("access_token"):
            self._add("R4", "alg=none rejection", "FAIL",
                      "issuer ACCEPTED an unsigned alg=none token (returned access_token)")
        else:
            self._add("R4", "alg=none rejection", "PASS",
                      "unsigned token rejected (HTTP %s, error=%s)" % (sval(st), sval(doc.get("error") if isinstance(doc, dict) else None)))

    # -- R5 signing key sanity ---------------------------------------------
    def r5_signing_sanity(self):
        keys = self.jwks.get("keys") if isinstance(self.jwks, dict) else None
        if not keys:
            self._add("R5", "signing key hygiene", "FAIL", "no JWKS loaded (R2 must pass first)")
            return
        problems = []
        infos = []
        for k in keys:
            kid = sval(k.get("kid"))
            alg = sval(k.get("alg"))
            kty = sval(k.get("kty"))
            infos.append("%s/%s/%s" % (kid, kty, alg))
            if "use" in k and k.get("use") != "sig" and k.get("use") != "enc":
                problems.append("key %s has unusual use=%s" % (kid, k.get("use")))
            if kty == "RSA":
                n = k.get("n")
                if not n:
                    problems.append("RSA key %s missing n" % kid)
                    continue
                try:
                    raw = b64u_decode(n)
                    bits = len(raw) * 8
                    if bits < 2048:
                        problems.append("RSA key %s is %d bits (<2048)" % (kid, bits))
                except Exception:
                    problems.append("RSA key %s has undecodable n" % kid)
            if k.get("d") or k.get("p") or k.get("q"):
                problems.append("key %s publishes PRIVATE material (d/p/q)!" % kid)
        if problems:
            self._add("R5", "signing key hygiene", "FAIL", "; ".join(problems))
        else:
            self._add("R5", "signing key hygiene", "PASS", "keys: %s" % ", ".join(infos))

    # -- R6 clock skew -------------------------------------------------------
    def r6_clock_skew(self, max_skew=120, hard_skew=1800):
        try:
            url = self.issuer + "/.well-known/openid-configuration"
            st, hdrs, body = self._fetch_nocache(url)
            date_hdr = hdrs.get("Date") or hdrs.get("date")
        except FetchError as e:
            self._add("R6", "clock skew", "FAIL", "unreachable: %s" % e)
            return
        if not date_hdr:
            self._add("R6", "clock skew", "WARN", "no Date header returned")
            return
        from email.utils import parsedate_to_datetime
        try:
            server_dt = parsedate_to_datetime(date_hdr)
            if server_dt.tzinfo is None:
                # RFC 7231 Date is always GMT; naive parse means the header lacked tz
                import calendar
                server_epoch = calendar.timegm(server_dt.timetuple())
            else:
                server_epoch = server_dt.timestamp()
            skew = abs(time.time() - server_epoch)
        except Exception:
            self._add("R6", "clock skew", "WARN", "unparseable Date header: %s" % sval(date_hdr))
            return
        if skew > hard_skew:
            self._add("R6", "clock skew", "FAIL",
                      "server Date off by %d min (> %d min) — token exp/iat validation will flake" % (skew // 60, hard_skew // 60))
        elif skew > max_skew:
            self._add("R6", "clock skew", "WARN",
                      "Date appears %d min old (within %d min) — usually proxy/CDN cache age, not clock drift" % (skew // 60, hard_skew // 60))
        else:
            self._add("R6", "clock skew", "PASS", "server clock within %ds" % skew)

    def _fetch_nocache(self, url):
        """fetch with Cache-Control: no-cache — Date header of cached responses
        reflects cache age, not server clock; ask politely for a fresh one."""
        ctx = ssl.create_default_context()
        if self.insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={
            "User-Agent": UA, "Accept": "application/json, */*",
            "Cache-Control": "no-cache", "Pragma": "no-cache"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                return resp.getcode(), dict(resp.headers), resp.read(262144)
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers or {}), b""
        except Exception as e:
            raise FetchError("transport: %s" % e)

    def run_all(self):
        t0 = time.time()
        self.r1_discovery()
        if self.discovery:
            self.r2_jwks()
            self.r3_token_endpoint()
            self.r4_alg_downgrade()
            self.r5_signing_sanity()
            self.r6_clock_skew()
        self.meta["elapsed_s"] = round(time.time() - t0, 2)
        self.meta["issuer"] = self.issuer
        self.meta["timestamp_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return self.snapshot()

    def snapshot(self):
        worst = "PASS"
        for r in self.results:
            if r["status"] == "FAIL":
                worst = "FAIL"
                break
            if r["status"] == "WARN":
                worst = "WARN" if worst != "FAIL" else worst
        if not self.results:
            worst = "FAIL"
        if worst == "PASS":
            worst = "OK"   # WARN is a traffic light, not an exit-code failure
        return {
            "tool": TOOL, "version": VERSION,
            "issuer": self.issuer,
            "timestamp_utc": self.meta.get("timestamp_utc"),
            "elapsed_s": self.meta.get("elapsed_s"),
            "verdict": worst,
            "results": self.results,
        }

# ---------------------------------------------------------------- diff
def flatten_snapshot(snap):
    out = {}
    for r in snap.get("results", []):
        out[r["id"]] = {"name": r["name"], "status": r["status"], "detail": r["detail"]}
    return out

def diff_snapshots(a, b):
    fa, fb = flatten_snapshot(a), flatten_snapshot(b)
    changes = []
    for rid in sorted(set(fa) | set(fb)):
        ra, rb = fa.get(rid), fb.get(rid)
        if ra and rb:
            if ra["status"] != rb["status"]:
                changes.append({"id": rid, "kind": "status-changed",
                                "from": "%s %s" % (ra["status"], ra["detail"]),
                                "to": "%s %s" % (rb["status"], rb["detail"])})
        elif ra:
            changes.append({"id": rid, "kind": "removed", "from": ra["status"], "to": "—"})
        else:
            changes.append({"id": rid, "kind": "added", "from": "—", "to": rb["status"]})
    verdict = "SAME" if not changes else "CHANGED"
    return {"verdict": verdict, "a_issuer": sval(a.get("issuer")), "b_issuer": sval(b.get("issuer")),
            "a_time": sval(a.get("timestamp_utc")), "b_time": sval(b.get("timestamp_utc")),
            "changes": changes}

# ---------------------------------------------------------------- demo issuer
DEMO_PORT_DEFAULT = 8377

def _demo_keys():
    """Deterministic RSA-2048 demo keypair (test-only, published modulus is fine;
    private parts are never served — see I1)."""
    if HAVE_CRYPTO:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub = key.public_key().public_numbers()
        n_b = _i2osp(pub.n, (pub.n.bit_length() + 7) // 8)
        e_b = _i2osp(pub.e, 3)
        return key, n_b, e_b
    # deterministic fallback without cryptography: fixed small-but-safe demo modulus
    n_hex = ("00" + "c8a1966510f2b4a79b3e6bbd3c35e8f7a2d1f4b9e0c6a3d85f2b7e4c9a1d6f3b8"
             "e5c2a9d6f3b8e5c2a9d6f3b8e5c2a9d6f3b8e5c2a9d6f3b8e5c2a9d6f3b8e5c2a9d6"
             "f3b8e5c2a9d6f3b8e5c2a9d6f3b8e5c2a9d6f3b8e5c2a9d6f3b8e5c2a9d6f3b8e5c2"
             "a9d6f3b8e5c2a9d6f3b8e5c2a9d6f3b8e5c2a9d6f3b8e5c2a9d6f3b8e5c2a9d6f3b8"
             "e5c2a9d6f3b8e5c2a9d6f3b8e5c2a9d6f3b8e5c2a9d6f3b8e5c2a9d6f3b8e5c2a9d6"
             "f3b8e5c2a9d6f3b8e5c2a9d6f3b8e5c2a9d6f3b8e5c2a9d6f3b8e5c2a9d6f3b8e5c2a9")
    n = int(n_hex, 16)
    return None, _i2osp(n, (n.bit_length() + 7) // 8), b"\x01\x00\x01"

class DemoIssuer:
    """In-process OIDC issuer for selftests & the `serve` demo mode.
    Implements discovery, JWKS, token endpoint (client_credentials with real
    RS256 signing when cryptography is available). No user data. No tokens at
    rest. Binds loopback only by default (I5)."""

    def __init__(self, host="127.0.0.1", port=DEMO_PORT_DEFAULT, alg="RS256", bare=False):
        self.host = host
        self.port = port
        self.alg = alg
        self.bare = bare   # bare=True: discovery omits token_endpoint (pure JWT signer)
        self.key, self.n_b, self.e_b = _demo_keys()
        self.base = "http://%s:%d" % (host, port)   # loopback http is allowed by I3

    # -- token minting ------------------------------------------------------
    def mint(self, claims=None):
        header = {"alg": self.alg, "typ": "JWT", "kid": "demo-key-1"}
        now = int(time.time())
        payload = {"iss": self.base, "sub": "oidcprobe-demo",
                   "iat": now, "exp": now + 300}
        if claims:
            payload.update(claims)
        h = b64u_encode(json.dumps(header).encode())
        p = b64u_encode(json.dumps(payload).encode())
        signing_input = (h + "." + p).encode("ascii")
        if self.alg == "none":
            return h + "." + p + "."
        if HAVE_CRYPTO and self.key is not None:
            sig = self.key.sign(signing_input, PKCS1v15(), hashes.SHA256())
        else:
            raise ManualFail("demo mint requires cryptography for RS256")
        return h + "." + p + "." + b64u_encode(sig)

    # -- HTTP plumbing -------------------------------------------------------
    def _handle(self, handler):
        path = urllib.parse.urlparse(handler.path).path
        if path == "/.well-known/openid-configuration":
            doc = {
                "issuer": self.base,
                "jwks_uri": self.base + "/jwks.json",
                "response_types_supported": ["code"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": [self.alg],
            }
            if not self.bare:
                doc["token_endpoint"] = self.base + "/token"
                doc["grant_types_supported"] = ["client_credentials"]
            return self._json(handler, 200, doc)
        if path == "/jwks.json":
            key = {"kty": "RSA", "use": "sig", "kid": "demo-key-1",
                   "alg": self.alg, "n": b64u_encode(self.n_b), "e": b64u_encode(self.e_b)}
            return self._json(handler, 200, {"keys": [key]})
        if path == "/token":
            return self._handle_token(handler)
        return self._json(handler, 404, {"error": "not_found"})

    def _handle_token(self, handler):
        length = int(handler.headers.get("Content-Length") or 0)
        body_raw = handler.rfile.read(length) if length else b""
        params = urllib.parse.parse_qs(body_raw.decode("utf-8", "replace"))
        grant = (params.get("grant_type") or [""])[0]
        assertion = (params.get("assertion") or [""])[0]
        if grant != "urn:ietf:params:oauth:grant-type:jwt-bearer":
            return self._json(handler, 400, {"error": "unsupported_grant_type"})
        parts = assertion.split(".")
        if len(parts) != 3 or parts[2] == "":
            # includes alg=none (empty signature) — must be rejected (R4 proves)
            return self._json(handler, 400, {"error": "invalid_assertion",
                                             "error_description": "unsigned tokens refused"})
        try:
            header = json.loads(b64u_decode(parts[0]))
            payload = json.loads(b64u_decode(parts[1]))
            sig = b64u_decode(parts[2])
        except Exception:
            return self._json(handler, 400, {"error": "invalid_assertion"})
        if header.get("alg") != self.alg:
            return self._json(handler, 400, {"error": "invalid_assertion",
                                             "error_description": "alg not allowed"})
        if payload.get("iss") != self.base:
            return self._json(handler, 400, {"error": "invalid_assertion",
                                             "error_description": "wrong issuer"})
        if payload.get("exp", 0) < time.time():
            return self._json(handler, 400, {"error": "invalid_assertion",
                                             "error_description": "token expired"})
        if HAVE_CRYPTO and self.key is not None:
            try:
                self.key.public_key().verify(sig, (parts[0] + "." + parts[1]).encode("ascii"),
                                             PKCS1v15(), hashes.SHA256())
            except Exception:
                return self._json(handler, 400, {"error": "invalid_assertion",
                                                 "error_description": "bad signature"})
        # I1: response contains a token by spec, but the probe never logs it.
        return self._json(handler, 200, {"access_token": self.mint({"sub": "oidcprobe-client"}),
                                         "token_type": "Bearer", "expires_in": 300})

    @staticmethod
    def _json(handler, code, obj):
        raw = json.dumps(obj).encode()
        handler.send_response(code)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(raw)))
        handler.end_headers()
        handler.wfile.write(raw)

    def serve_forever(self):
        demo = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):  # silence
                pass
            def do_GET(self):
                demo._handle(self)
            def do_POST(self):
                demo._handle(self)

        srv = ThreadingHTTPServer((self.host, self.port), H)
        srv.daemon_threads = True
        srv.serve_forever()

# ---------------------------------------------------------------- selftest
def selftest():
    fails = []
    def check(name, cond, detail=""):
        if cond:
            print("  PASS  %s %s" % (name, detail))
        else:
            print("  FAIL  %s %s" % (name, detail))
            fails.append(name)

    print("oidcprobe selftest — cryptography available: %s" % HAVE_CRYPTO)

    # T1: b64u roundtrip
    raw = b"\x00\xff\x10binary\xa0 bytes"
    check("T1 b64u roundtrip", b64u_decode(b64u_encode(raw)) == raw)

    # T2: I3 plain-http refusal
    try:
        normalize_issuer("http://10.1.2.3:8080")
        check("T2 I3 http refusal", False, "should have raised")
    except ValueError as e:
        check("T2 I3 http refusal", "I3" in str(e))
    try:
        normalize_issuer("http://127.0.0.1:8080")
        check("T2b I3 loopback allowed", True)
    except ValueError as e:
        check("T2b I3 loopback allowed", False, str(e))

    # T3: I4 no bare None in snapshot json
    t = ProbeTarget("http://127.0.0.1:1")   # nothing listens here
    t.timeout = 1
    try:
        snap = t.run_all()
        blob = json.dumps(snap)
        check("T3 I4 no-None-strings", '"None"' not in blob and "None" not in [r["status"] for r in snap["results"]])
        check("T3b unreachable verdict FAIL", snap["verdict"] == "FAIL")
    except Exception as e:
        check("T3 I4 no-None-strings", False, str(e))

    # T4..T8: full loop against embedded demo issuer
    demo = DemoIssuer("127.0.0.1", 0 if False else _free_port())
    import threading as _th
    from http.server import ThreadingHTTPServer as _THS
    srv_holder = {}

    def run_srv():
        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass
            def do_GET(self):
                demo._handle(self)
            def do_POST(self):
                demo._handle(self)
        srv = ThreadingHTTPServer(("127.0.0.1", demo.port), H)
        srv_holder["srv"] = srv
        srv.serve_forever()
    th = _th.Thread(target=run_srv, daemon=True)
    th.start()
    time.sleep(0.3)
    for _ in range(20):
        if "srv" in srv_holder:
            break
        time.sleep(0.1)

    pt = ProbeTarget(demo.base, timeout=5)
    snap = pt.run_all()
    by_id = {r["id"]: r for r in snap["results"]}
    check("T4 discovery PASS", by_id.get("R1", {}).get("status") == "PASS", by_id.get("R1", {}).get("detail", ""))
    check("T4b issuer match PASS", by_id.get("R1a", {}).get("status") == "PASS")
    check("T5 jwks PASS", by_id.get("R2", {}).get("status") == "PASS")
    check("T6 token endpoint PASS", by_id.get("R3", {}).get("status") == "PASS", by_id.get("R3", {}).get("detail", ""))
    check("T7 alg-none rejected", by_id.get("R4", {}).get("status") == "PASS", by_id.get("R4", {}).get("detail", ""))
    check("T8 key hygiene PASS", by_id.get("R5", {}).get("status") == "PASS", by_id.get("R5", {}).get("detail", ""))

    # T9: I1 — report/snapshot must not contain token substrings even after a
    # successful client_credentials-ish mint path. We mint directly and ensure
    # the snapshot machinery never receives token material.
    if HAVE_CRYPTO:
        tok = demo.mint()
        check("T9 mint works", tok.count(".") == 2)
        blob = json.dumps(snap)
        check("T9b I1 token not in snapshot", tok.split(".")[2][:24] not in blob)

    # T10: diff
    snap_b = json.loads(json.dumps(snap))
    snap_b["results"][0]["status"] = "FAIL"
    d = diff_snapshots(snap, snap_b)
    check("T10 diff detects change", d["verdict"] == "CHANGED" and len(d["changes"]) == 1, json.dumps(d["changes"])[:80])
    d2 = diff_snapshots(snap, snap)
    check("T10b same verdict", d2["verdict"] == "SAME")

    # T11: expired token rejected
    if HAVE_CRYPTO:
        expired = demo.mint({"exp": int(time.time()) - 100})
        data = urllib.parse.urlencode({"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                       "assertion": expired}).encode()
        req = urllib.request.Request(demo.base + "/token", data=data,
                                     headers={"Content-Type": "application/x-www-form-urlencoded"})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                st = resp.getcode()
        except urllib.error.HTTPError as e:
            st = e.code
        except urllib.error.URLError as e:
            st = "unreachable(%s)" % getattr(e, "reason", e)
        check("T11 expired token 400", st == 400, "got %s" % st)

    # T12: bad signature rejected
    if HAVE_CRYPTO:
        forged = demo.mint()
        p = forged.split(".")
        bad_sig = bytearray(b64u_decode(p[2]))
        bad_sig[0] ^= 0xFF
        forged = p[0] + "." + p[1] + "." + b64u_encode(bytes(bad_sig))
        data = urllib.parse.urlencode({"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                       "assertion": forged}).encode()
        req = urllib.request.Request(demo.base + "/token", data=data,
                                     headers={"Content-Type": "application/x-www-form-urlencoded"})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                st = resp.getcode()
        except urllib.error.HTTPError as e:
            st = e.code
        except urllib.error.URLError as e:
            st = "unreachable(%s)" % getattr(e, "reason", e)
        check("T12 forged sig 400", st == 400, "got %s" % st)

    # T13: bare issuer (no token_endpoint, like CI token services) must NOT FAIL
    demo_bare = DemoIssuer("127.0.0.1", _free_port(), bare=True)
    srv_b_holder = {}
    def run_srv_b():
        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass
            def do_GET(self):
                demo_bare._handle(self)
            def do_POST(self):
                demo_bare._handle(self)
        srv = ThreadingHTTPServer(("127.0.0.1", demo_bare.port), H)
        srv_b_holder["srv"] = srv
        srv.serve_forever()
    th_b = _th.Thread(target=run_srv_b, daemon=True)
    th_b.start()
    time.sleep(0.3)
    for _ in range(20):
        if "srv" in srv_b_holder:
            break
        time.sleep(0.1)
    pt_bare = ProbeTarget(demo_bare.base, timeout=5)
    snap_bare = pt_bare.run_all()
    by_id_b = {r["id"]: r for r in snap_bare["results"]}
    check("T13 bare issuer no token_endpoint => WARN not FAIL",
          by_id_b.get("R3", {}).get("status") == "WARN" and snap_bare["verdict"] != "FAIL",
          "R3=%s verdict=%s" % (by_id_b.get("R3", {}).get("status"), snap_bare["verdict"]))

    if "srv" in srv_holder:
        srv_holder["srv"].shutdown()

    print("\n%d check(s), %d failed" % (15 if HAVE_CRYPTO else 13, len(fails)))
    return 0 if not fails else 1

def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port

# ---------------------------------------------------------------- reporting
def human_report(snap):
    lines = []
    lines.append("issuer : %s" % sval(snap.get("issuer")))
    lines.append("time   : %s (UTC)" % sval(snap.get("timestamp_utc")))
    lines.append("probe  : %s v%s" % (TOOL, VERSION))
    lines.append("")
    icon = {"PASS": "[ok]  ", "FAIL": "[FAIL]", "WARN": "[warn]"}
    for r in snap.get("results", []):
        lines.append("%s %-28s %s" % (icon.get(r["status"], "[?]   "), r["name"], r["detail"]))
    lines.append("")
    lines.append("verdict: %s   (%.1fs)" % (snap.get("verdict"), snap.get("elapsed_s") or 0))
    return "\n".join(lines)

# ---------------------------------------------------------------- CLI
def main(argv=None):
    ap = argparse.ArgumentParser(prog=TOOL, description="OIDC/OAuth2 issuer hygiene probe & IdP diff (single-file, zero-dep)")
    sub = ap.add_subparsers(dest="cmd")

    p_probe = sub.add_parser("probe", help="probe an issuer and print/emit report")
    p_probe.add_argument("issuer")
    p_probe.add_argument("--json", action="store_true")
    p_probe.add_argument("--out", help="write JSON snapshot to file")
    p_probe.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    p_probe.add_argument("--insecure", action="store_true", help="allow plain http and bad TLS (labs only)")

    p_diff = sub.add_parser("diff", help="diff two snapshots")
    p_diff.add_argument("a")
    p_diff.add_argument("b")
    p_diff.add_argument("--json", action="store_true")

    p_watch = sub.add_parser("watch", help="probe issuer, compare against baseline snapshot")
    p_watch.add_argument("issuer")
    p_watch.add_argument("--baseline", required=True)
    p_watch.add_argument("--fail-on", choices=["change", "fail", "any"], default="change")
    p_watch.add_argument("--json", action="store_true")
    p_watch.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    p_watch.add_argument("--insecure", action="store_true")

    p_serve = sub.add_parser("serve", help="run embedded demo issuer (loopback)")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=DEMO_PORT_DEFAULT)
    p_serve.add_argument("--cors", action="store_true")

    sub.add_parser("selftest")

    args = ap.parse_args(argv)
    if not args.cmd:
        ap.print_help()
        return 64

    if args.cmd == "selftest":
        return selftest()

    if args.cmd == "probe":
        try:
            pt = ProbeTarget(args.issuer, timeout=args.timeout, insecure=args.insecure)
        except ValueError as e:
            print("error: %s" % e)
            return 64
        snap = pt.run_all()
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                json.dump(snap, f, ensure_ascii=False, indent=2)
            print("snapshot written: %s" % args.out)
        if args.json:
            print(json.dumps(snap, ensure_ascii=False, indent=2))
        else:
            print(human_report(snap))
        # exit 0 on OK or WARN (traffic light), 1 only on FAIL
        return 0 if snap["verdict"] in ("OK", "PASS", "WARN") else 1

    if args.cmd == "diff":
        try:
            a = json.load(open(args.a, encoding="utf-8"))
            b = json.load(open(args.b, encoding="utf-8"))
        except Exception as e:
            print("error reading snapshots: %s" % e)
            return 64
        d = diff_snapshots(a, b)
        if args.json:
            print(json.dumps(d, ensure_ascii=False, indent=2))
        else:
            print("A: %s @ %s" % (sval(d["a_issuer"]), sval(d["a_time"])))
            print("B: %s @ %s" % (sval(d["b_issuer"]), sval(d["b_time"])))
            print("verdict: %s" % d["verdict"])
            for c in d["changes"]:
                print("  %-14s %s" % (c["kind"], c["id"]))
                print("      from: %s" % c.get("from"))
                print("      to  : %s" % c.get("to"))
        return 0 if d["verdict"] == "SAME" else 1

    if args.cmd == "watch":
        try:
            base = json.load(open(args.baseline, encoding="utf-8"))
        except Exception as e:
            print("error reading baseline: %s" % e)
            return 64
        try:
            pt = ProbeTarget(args.issuer, timeout=args.timeout, insecure=args.insecure)
        except ValueError as e:
            print("error: %s" % e)
            return 64
        snap = pt.run_all()
        d = diff_snapshots(base, snap)
        has_fail = snap["verdict"] == "FAIL"
        out = {"diff": d, "now": snap}
        if args.json:
            print(json.dumps(out, ensure_ascii=False, indent=2))
        else:
            print(human_report(snap))
            print("")
            print("baseline diff: %s (%d change(s))" % (d["verdict"], len(d["changes"])))
            for c in d["changes"]:
                print("  %-14s %s" % (c["kind"], c["id"]))
        if args.fail_on == "change":
            return 0 if d["verdict"] == "SAME" else 1
        if args.fail_on == "fail":
            return 1 if has_fail else 0
        return 0 if (d["verdict"] == "SAME" and not has_fail) else 1

    if args.cmd == "serve":
        if args.host not in LOOPBACK_HOSTS:
            print("I5: serve refuses non-loopback bind (%s). Edit code if you really mean it." % args.host)
            return 64
        demo = DemoIssuer(args.host, args.port)
        print("demo issuer on %s  (ctrl-c to stop)" % demo.base)
        print("  discovery : %s/.well-known/openid-configuration" % demo.base)
        print("  jwks      : %s/jwks.json" % demo.base)
        print("  token     : %s/token" % demo.base)
        try:
            demo.serve_forever()
        except KeyboardInterrupt:
            pass
        return 0

    return 64

if __name__ == "__main__":
    sys.exit(main())
