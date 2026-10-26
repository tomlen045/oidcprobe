# Changelog

## 1.0.0 — 2026-10-26

首发。

- `probe` 子命令：6 探针（发现/JWKS/token 活性/alg=none 拒绝/密钥卫生/时钟偏差）+ issuer 字段一致性
- `diff` 子命令：两份快照逐探针对比
- `watch` 子命令：基线锚定巡检，`--fail-on change|fail|any`
- `serve` 子命令：内嵌 demo issuer（RS256 真实签发/验签，需 cryptography；alg=none 拒绝、过期拒绝、伪造签名拒绝全部实装）
- `selftest`：15 项自测，含私钥泄漏注入、bare issuer 语义、令牌不落报告三类对抗用例
- 不变量 I1–I5 全部落地并有测试覆盖

实战咬出的 bug（本版本修复过程）：

1. R6 时钟偏移 naive/aware datetime 混算产生千秒级假偏移 → 改 epoch 锚定
2. CDN 缓存 Date 头被误判时钟漂移 → no-cache 重发 + 30 分钟硬阈值
3. GitHub Actions 类「纯 JWT 签发方」被误判 FAIL → WARN + 语义说明
