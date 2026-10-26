# oidcprobe

**单文件、零依赖的 OIDC/OAuth2 issuer 体检与双 IdP 能力对比工具。** 一条命令摸清你的登录服务对外暴露了什么：发现文档、签名密钥卫生、算法降级防线、时钟偏差、token 端点活性——并且永远不会把任何令牌或密钥写进报告。

适合：SSO 迁移前的尽调、多 IdP 并存时的能力对比、crontab 里的登录链路巡检。

> 全部探针只做网络读操作与本地起服务，对被测 issuer 不发起任何写请求（无注册、无授权跳转、无数据修改）。

## 它能查什么

| 探针 | 查什么 | 为什么重要 |
|------|--------|-----------|
| R1 | `/.well-known/openid-configuration` 可达性 + `issuer` 字段与你请求的主机是否一致 | 字段不一致 = 反代配置错或指向别人家的 realm |
| R2 | JWKS 签名密钥可拉取 + 算法清单 | 拉不到 JWKS = 所有依赖方验签全挂 |
| R3 | token 端点活性（只探错误响应，不猜凭据） | 端点 5xx = 登录链路已病 |
| R4 | **alg=none 降级攻击**：伪造无签名令牌投递给 token 端点，被接受 = 灾难级 FAIL | 历史 RCE 级漏洞的万恶之源 |
| R5 | 密钥卫生：RSA <2048 位、**JWKS 里泄漏私钥材料(d/p/q)**、异常 use 字段 | JWKS 泄私钥 = 私钥直接进公网 |
| R6 | 服务器时钟偏差（Date 头） | 偏差大 = exp/iat 校验随机抽风 |

外加三个子命令：

- **diff** — 两份快照逐探针对比（迁移前 vs 迁移后、今天 vs 上周）
- **watch** — 以基线快照为锚，变化即退出码非零（crontab 直接可用）
- **serve** — 内嵌 demo issuer（含 alg=none 拒绝、过期拒绝、伪造签名拒绝），自测/演示/联调零外部依赖

## 快速开始

```bash
# 探一个 issuer（人类可读报告）
python3 oidcprobe.py probe https://your-idp.example.com/realms/master

# 存快照 + JSON 输出
python3 oidcprobe.py probe https://your-idp/realms/master --out base.json --json

# 双 IdP 能力对比（迁移尽调）
python3 oidcprobe.py diff old-idp.json new-idp.json

# 巡检：与基线不同就报非零退出码（crontab 友好）
python3 oidcprobe.py watch https://your-idp/realms/master --baseline base.json --fail-on change

# 起一个本地 demo issuer（默认仅回环）
python3 oidcprobe.py serve --port 8377

# 自测（15 项，含对抗用例）
python3 oidcprobe.py selftest
```

真实输出示例（对 Keycloak 26.3.0 dev 模式实测）：

```
issuer : http://127.0.0.1:8080/realms/master
probe  : oidcprobe v1.0.0

[ok]   issuer field matches request host http://127.0.0.1:8080/realms/master
[ok]   Discovery document           HTTP 200, 55 fields
[ok]   JWKS (signing keys)          2 key(s), alg: RS256, RSA-OAEP
[ok]   token_endpoint presence      answers HTTP 405 with error payload — endpoint alive
[ok]   alg=none rejection           unsigned token rejected (HTTP 400)
[ok]   signing key hygiene          keys: 3i6d...-OrwW4/RSA/RS256, wSP6...2XbLw/RSA/RSA-OAEP
[warn] clock skew                   no Date header returned

verdict: WARN   (0.1s)
```

## 退出码（crontab 友好）

| 码 | 含义 |
|----|------|
| 0 | 全部通过 / 无变化（WARN 属信号灯提示，不算失败） |
| 1 | 存在 FAIL / 检出变化 |
| 2 | issuer 不可达 |
| 64 | 用法错误（含 http:// 明文 issuer 未加 `--insecure`） |

## 不变量（设计承诺）

- **I1 永不输出密钥内容**：报告里只出现「拿到了/没拿到」、算法名、key ID 摘要——就算 JWKS 里真的泄漏了私钥，报告也只说「泄漏了」，不把私钥打给你看（防截图进群二次泄漏）
- **I2 只读**：对 issuer 不发起注册/授权/写请求；唯一的 POST 是投递伪造令牌（alg=none 探针，这是攻击面验证的标准动作）
- **I3 明文 http 拒绝**：除 127.0.0.1/localhost 外，http:// issuer 一律拒绝，需显式 `--insecure`（实验室场景）
- **I4 无 None 字面量**：JSON/人类报告中未知值一律 `unknown`，不出现语言残留物
- **I5 serve 仅回环**：demo issuer 拒绝绑定非回环地址

## 实战三坑（都是真 issuer 咬出来的）

1. **时钟比较别拿 Date 自己减自己**——naive/aware datetime 混算会差出上千秒假偏移。必须换算成 Unix epoch 与 `time.time()` 比
2. **CDN 会缓存 Date 头**——拿到的 Date 可能是 15 分钟前的缓存年龄而非服务器时钟漂移。工具带 `Cache-Control: no-cache` 重发，且 >2min 只给 WARN（注明「多为缓存年龄」），>30min 才 FAIL
3. **没有 token_endpoint ≠ 坏**——GitHub Actions 的 OIDC issuer 就是纯 JWT 签发方（只发 JWKS）。按「发现文档不完整」判 FAIL 会冤枉好人，应当 WARN 并说明

## 依赖

无。纯标准库（Python 3.8+）。装了 `cryptography` 会启用真实 RS256 签发/验签（demo issuer 与自测的令牌级用例），没装自动降级为纯结构探针——但 alg=none / 过期 / 伪造签名探针照样能跑（它们只需要服务端行为）。

## 上游工具链咬合

- **keyvaultdog** 管你本机的 SSH 钥匙资产
- **secretweeper** 管密钥别进 git
- **oidcprobe** 管登录链路本身——你的应用连的 IdP 到底还活着、还安全吗

```bash
# 迁移前尽调一条龙
python3 oidcprobe.py probe https://old-idp/realms/prod --out old.json
python3 oidcprobe.py probe https://new-idp/realms/prod --out new.json
python3 oidcprobe.py diff old.json new.json
```

## License

MIT
