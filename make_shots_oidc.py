#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""oidcprobe 公众号证据图 6 张 (1200x675) — 内容来自真实运行输出, 指纹已截断脱敏."""
from PIL import Image, ImageDraw, ImageFont
import os

OUT = "/Users/len/CodeBuddy/dx/oidcprobe/shots"
os.makedirs(OUT, exist_ok=True)
FONT_CJK = "/System/Library/Fonts/STHeiti Medium.ttc"
FONT_MONO = "/System/Library/Fonts/Menlo.ttc"
W, H = 1200, 675
BG, BAR, LINE = "#1b1d23", "#2a2d35", "#0d1117"
GREEN, WHITE, GREY, RED, GOLD, BLUE = "#98c379", "#e6edf3", "#7f8794", "#e06c75", "#e5c07b", "#61afef"

_fc = {}
def F(size, mono):
    key = (size, mono)
    if key not in _fc:
        _fc[key] = ImageFont.truetype(FONT_MONO if mono else FONT_CJK, size)
    return _fc[key]

def has_cjk(t):
    return any('\u2e80' <= ch <= '\u9fff' or ch in '，。：；「」（）｜→·％' for ch in t)

def shot(name, lines, title="oidcprobe — zsh"):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, 44], fill=BAR)
    d.ellipse([24, 15, 36, 27], fill="#ff5f57"); d.ellipse([44, 15, 56, 27], fill="#febc2e"); d.ellipse([64, 15, 76, 27], fill="#28c840")
    tw = d.textlength(title, font=F(16, False))
    d.text(((W - tw) / 2, 13), title, font=F(16, False), fill="#8b90a0")
    d.rectangle([0, 44, W, 46], fill=LINE)
    y = 74
    for text, color, size, mono in lines:
        if text:
            font = F(size, mono and not has_cjk(text))
            d.text((52, y), text, font=font, fill=color)
        y += int(size * 1.8)
    img.save(f"{OUT}/{name}.png")
    print(name, "OK")

# ── 01 probe 全绿: 对本地 Keycloak 26.3.0 真实输出 ──
shot("01_probe", [
    ("$ python3 oidcprobe.py probe http://127.0.0.1:8080/realms/master", GREEN, 20, True),
    ("", WHITE, 6, True),
    ("[ok] issuer field matches request host", WHITE, 20, True),
    ("[ok] Discovery document      HTTP 200, 55 fields", WHITE, 20, True),
    ("[ok] JWKS (signing keys)     2 key(s), alg: RS256, RSA-OAEP", WHITE, 20, True),
    ("[ok] token_endpoint presence answers HTTP 405 - endpoint alive", WHITE, 20, True),
    ("[ok] alg=none rejection      unsigned token rejected (HTTP 400)", WHITE, 20, True),
    ("[ok] signing key hygiene     keys: 3i6d...OrwW4/RSA/RS256 ...", WHITE, 20, True),
    ("[warn] clock skew            no Date header returned", GOLD, 20, True),
    ("", WHITE, 6, True),
    ("verdict: WARN (0.1s)  -- 6 绿 1 提示, Quarkus 不回 Date 头", GOLD, 22, True),
    ("一条命令, 登录链路 6 个体检点全出来", GREY, 21, False),
], title="oidcprobe v1.0.0 — probe Keycloak 26.3.0")

# ── 02 对抗注入: JWKS 藏私钥当场被抓 ──
shot("02_leak", [
    ("# 对抗测试: 往 JWKS 里塞进 d/p/q 私钥材料", GREY, 20, False),
    ("$ python3 oidcprobe.py probe http://127.0.0.1:8399", GREEN, 20, True),
    ("", WHITE, 6, True),
    ("[ok]   Discovery document      HTTP 200", WHITE, 20, True),
    ("[FAIL] signing key hygiene", RED, 22, True),
    ("       key leaky-1 publishes PRIVATE material (d/p/q)!", RED, 21, True),
    ("", WHITE, 6, True),
    ("verdict: FAIL", RED, 22, True),
    ("", WHITE, 6, True),
    ("报告只说「泄漏了」, 不打印私钥 --", GOLD, 21, False),
    ("截图发群里也不会二次泄漏 (不变量 I1)", GOLD, 21, False),
], title="adversarial — leaky JWKS caught")

# ── 03 真实大厂体检: GitHub Actions OIDC ──
shot("03_real", [
    ("$ python3 oidcprobe.py probe https://token.actions.githubusercontent.com", GREEN, 19, True),
    ("", WHITE, 6, True),
    ("[ok]   issuer field matches request host", WHITE, 20, True),
    ("[ok]   Discovery document      HTTP 200, 7 fields", WHITE, 20, True),
    ("[ok]   JWKS (signing keys)     4 key(s), alg: RS256", WHITE, 20, True),
    ("[warn] token_endpoint presence", GOLD, 20, True),
    ("       issuer publishes no token_endpoint", GREY, 19, True),
    ("       (pure JWT signer - common for CI token services)", GREY, 19, True),
    ("[ok]   signing key hygiene     4 keys RS256", WHITE, 20, True),
    ("[ok]   clock skew              server clock within 1s", WHITE, 20, True),
    ("", WHITE, 6, True),
    ("没有 token_endpoint ≠ 坏: 纯签发方按 WARN 处理", GOLD, 21, False),
], title="real world — github actions oidc")

# ── 04 diff 双 IdP 对比 ──
shot("04_diff", [
    ("$ python3 oidcprobe.py diff old-idp.json new-idp.json", GREEN, 20, True),
    ("", WHITE, 6, True),
    ("A: https://old-idp.example.com/realms/prod @ 2026-10-26T02:43Z", WHITE, 18, True),
    ("B: https://new-idp.example.com/realms/prod @ 2026-10-26T02:51Z", WHITE, 18, True),
    ("verdict: CHANGED", GOLD, 22, True),
    ("  status-changed  R2", WHITE, 20, True),
    ("      from: PASS 3 key(s), alg: RS256, RS512", GREY, 18, True),
    ("      to  : PASS 2 key(s), alg: RS256", GREY, 18, True),
    ("  status-changed  R6", WHITE, 20, True),
    ("      from: PASS server clock within 1s", GREY, 18, True),
    ("      to  : WARN no Date header returned", GREY, 18, True),
    ("", WHITE, 6, True),
    ("迁移前尽调: 两边能力差异一张纸看完", GREY, 21, False),
], title="oidcprobe — diff two issuers")

# ── 05 自测全绿 ──
shot("05_selftest", [
    ("$ python3 oidcprobe.py selftest", GREEN, 22, True),
    ("", WHITE, 6, True),
    ("oidcprobe selftest - cryptography available: True", WHITE, 19, True),
    ("  PASS  T1 b64u roundtrip", WHITE, 19, True),
    ("  PASS  T2 I3 http refusal", WHITE, 19, True),
    ("  PASS  T3 I4 no-None-strings", WHITE, 19, True),
    ("  PASS  T7 alg-none rejected  (HTTP 400)", WHITE, 19, True),
    ("  PASS  T9b I1 token not in snapshot", WHITE, 19, True),
    ("  PASS  T11 expired token 400  got 400", WHITE, 19, True),
    ("  PASS  T12 forged sig 400  got 400", WHITE, 19, True),
    ("  PASS  T13 bare issuer => WARN not FAIL", WHITE, 19, True),
    ("", WHITE, 6, True),
    ("15 check(s), 0 failed", GOLD, 24, True),
    ("不变量 I1-I5 全部有对抗用例盯防", GREY, 21, False),
], title="oidcprobe v1.0.0 — selftest 15/15")

# ── 06 watch 宕机巡检 ──
shot("06_watch", [
    ("$ python3 oidcprobe.py watch http://idp:8080/realms/master \\", GREEN, 19, True),
    ("      --baseline kc_base.json          # crontab 里每 5 分钟", GREY, 18, True),
    ("", WHITE, 6, True),
    ("# 服务被 kill 之后:", GREY, 20, False),
    ("[FAIL] Discovery document  unreachable: Connection refused", RED, 20, True),
    ("", WHITE, 6, True),
    ("verdict: FAIL (0.0s)", RED, 22, True),
    ("baseline diff: CHANGED (7 change(s))", GOLD, 21, True),
    ("  status-changed R1   removed R1a R2 R3 R4 R5 R6", GREY, 18, True),
    ("", WHITE, 6, True),
    ("exit code 1 -- cron 直接可用", BLUE, 21, True),
    ("登录链路挂了, 比用户投诉早 5 分钟知道", GREY, 21, False),
], title="oidcprobe — watch in crontab")

print("done:", len(os.listdir(OUT)), "shots in", OUT)
