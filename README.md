# maskhub 外发数据水印

数据脱敏平台的**外发追溯**模块：每次导出嵌入一枚不可见水印，泄露发生后能从疑似副本
还原出"这是哪一次外发"，并出具可留档、可验签、不暴露接收方的证据报告。

## 需求与设计的对照

| 需求 | 设计 |
| --- | --- |
| 每次导出嵌入可追溯水印 | 每个外发批次有独立 `batch_id`，批次密钥 `K_b = HMAC(主密钥, "export:"+batch_id)` 驱动嵌入 |
| 扛行序调整 | 载体行由 `HMAC(K_b, 主键)` 选出，与行在文件中的位置无关 |
| 扛少量改动 | 水印是成百上千个载体比特的统计指纹，二项检验容忍部分比特被翻转、删除或擦除 |
| 认出是哪次外发 | 对登记簿中每个批次逐一打分（命中数/载体数 → p 值），最显著者命中 |
| 不破坏格式和校验 | 数值列只动末位（保持小数位、min/max、容差）；类别列只在同义词对内切换；行校验列改动后自动重算 |
| 两次外发不互相覆盖 | 每批次独立密钥 → 独立的载体集合与比特位；且嵌入永远从原始母版出发 |
| 证据留档 | 报告含检材 SHA-256、命中批次、载体/命中统计、p 值、置信度，整体 HMAC 签名防篡改 |
| 不暴露接收方 | 数据里**零 payload**——不写任何批次号或接收方标识；接收方只存于内部登记簿；对外报告自动脱敏并重签 |

## 工作原理

水印不携带任何信息，它只是一个统计事实：

1. **选载体**：对每行计算 `token = HMAC(K_b, 主键)`，`token % carrier_mod == 0` 的行是载体
   （默认约 1/4 的行）。
2. **定位置**：`token` 的高位决定改写哪一个可标记列、嵌入什么比特。
3. **嵌比特**：数值列把量化整数的最低位调成目标比特（如 `100.31 → 100.30`，
   保持小数精度，违反 min/max/容差则放弃该格）；类别列在同义词对间切换（如 `线上 ↔ 在线`）。
4. **还原**：对登记簿里每个批次，统计疑似副本中"载体单元格的比特与期望一致"的比例。
   零假设下命中率是 50%，命中批次会显著偏离（如 284/285，p≈4.6e-84）。

误伤保护：数值改动永远是最小量化单位（±1 个末位），且可配 `abs_tol`/`rel_tol`/上下界；
无法安全改写的格子会被跳过而不是硬改。

## 快速开始

```bash
python3 -m unittest discover -s tests -v   # 19 个测试
python3 scripts/watermark_demo.py          # 端到端演示（嵌入→泄露→还原→证据）
MASKHUB_DATA_DIR=data python3 -m maskhub   # 启动控制台，默认 :8080
```

API 调用序列（curl 示例）：

```bash
# 1. 登记数据源、数据集（沿用既有控制面）
curl -X POST :8080/sources  -d '{"identifier":"warehouse","kind":"rdbms","endpoint":"db://1"}'
curl -X POST :8080/datasets -d '{"identifier":"orders","source":"warehouse","owner":"data-team","fields":[{"name":"amount","sensitivity":"public"}]}'

# 2. 配置水印档案：主键、可标记列及其约束、行校验列
curl -X POST :8080/watermark/profile -d '{
  "dataset":"orders","primary_key":"order_id","carrier_mod":4,"min_carriers":30,
  "columns":[
    {"name":"amount","kind":"numeric","minimum":0,"maximum":100000},
    {"name":"channel","kind":"category","pairs":{"线上":"在线"}}
  ],
  "checksum":{"name":"row_crc","algorithm":"crc32","columns":["order_id","amount","channel"]}}'

# 3. 外发：嵌入水印并登记批次（rows 为导出行）
curl -X POST :8080/watermark/export -d '{"dataset":"orders","recipient":"乙方-物流","rows":[...]}'

# 4. 泄露还原：对疑似副本打分，返回签名证据报告
curl -X POST :8080/watermark/detect -d '{"dataset":"orders","rows":[...]}'

# 5. 证据：验签 / 生成对外脱敏版
curl -X POST :8080/watermark/report/verify -d '{"report_id":"wr..."}'
curl -X POST :8080/watermark/report/redact -d '{"report_id":"wr..."}'
```

## 证据报告与置信度

报告正文包含：检材 SHA-256 与行数、命中批次及导出时间、载体数/命中数/命中率、
随机巧合概率（二项检验 p 值）、置信度分级、前 5 名候选批次，以及一段可直接引用的
中文结论陈述。报告用派生签名密钥做 HMAC 密封，任何事后改动都会验签失败。

置信度分级（载体数须 ≥ `min_carriers`，否则结论为"样本不足"）：

| p 值 | 置信度 |
| --- | --- |
| < 1e-6 | 极高 |
| < 1e-4 | 高（命中阈值） |
| < 1e-2 | 中 |
| 其他 | 不显著 |

留档建议：报告与检材哈希一并归档，必要时对检材哈希做可信时间戳/公证；
审计日志（`watermark.export` / `watermark.detect`）与批次登记簿是证据链的一部分，
需与报告一起备份。

## 隐私边界

- 泄露副本本身**无法**反推接收方：数据中没有批次号，只有持主密钥者能对登记簿逐一验证。
- 接收方仅出现在内部登记簿与内部版报告中；`/watermark/report/redact` 生成的对外版
  会把所有接收方替换为 `***` 并重新签名，结论陈述本身从不含接收方。
- 主密钥当前存于记录存储（`watermark.master`），生产环境应迁入 KMS/HSM。

## 威胁模型与局限

能抵御：行序任意调整、删行（实测删 15% 仍 p<1e-30）、少量单元格篡改、追加伪造行
（只会稀释命中率）、单副本比特翻转攻击（攻击者不知道哪些格子是载体）。

需要注意：

- **必须始终从原始母版出数**。对已加水印的副本再次嵌入，后一批次可能覆盖前一批次
  落在同一单元格的标记。
- 主键必须存在且基本唯一；主键被整列删除或重哈希后无法还原（可扩展为整行哈希兜底）。
- 攻击者若把所有可标记列整体清空/重编码，水印会被擦除——这是所有被动水印的共有限制，
  此时证据链应转向导出日志与访问审计。
- 多方合谋（两个接收方逐格比对副本）能定位部分差异单元格；提高 `carrier_mod` 可增大
  合谋成本，但根本缓解依赖外发最小化与合同约束。
- 单批次的结论强度依赖载体数量：行数太少的导出（载体 < `min_carriers`）不出具结论。

## 代码结构

```
maskhub/watermark/
  keys.py      主密钥保管与批次密钥派生
  profile.py   水印档案（可标记列、约束、校验列）及其注册表
  core.py      嵌入/还原核心：载体选择、比特读写、二项检验
  batch.py     外发批次登记簿（批次 → 接收方，仅内部）
  report.py    证据报告：生成、签名、验签、脱敏
maskhub/console/handlers/watermark.py   HTTP 端点
tests/test_watermark.py                 19 个测试（含端到端泄露场景）
scripts/watermark_demo.py               演示脚本
```
