# Threat Feed IOC Engine

本地单机可复现的威胁情报 IOC 摄取与检测引擎。所有数据均为本地样例，不依赖外部服务或真实凭据。

## 运行

```bash
mvn spring-boot:run          # 启动服务（随机端口，见 application.properties）
mvn test                     # 运行全部测试（27 个）
```

## 支持的摄取格式

通过 `POST /api/feeds/{format}?batchId=<id>` 摄取，请求体为原始内容。

### `json` — JSON Lines（每行一个指标对象）

```json
{"type":"ipv4","value":"203.0.113.10","source":"internal","confidence":90,"first_seen":"2026-01-05T00:00:00Z","expires_at":"2027-01-05T00:00:00Z"}
```

### `csv` — 带表头的 CSV

必需列：`type,value,source`；可选列：`confidence,first_seen,expires_at`；多余列忽略。

### 字段语义

| 字段 | 必需 | 说明 |
|---|---|---|
| `type` | 是 | `ipv4`/`domain`/`url`/`md5`/`sha1`/`sha256`/`email`（含常见别名，大小写不敏感） |
| `value` | 是 | 指标值，摄取时归一化（域名/哈希/邮箱小写、FQDN 尾点去除等） |
| `source` | 是 | 来源标识，用于优先级裁决 |
| `confidence` | 否 | 0–100 整数，缺省 50 |
| `first_seen` | 否 | ISO-8601 时间戳，缺省 `1970-01-01T00:00:00Z` |
| `expires_at` | 否 | ISO-8601 时间戳，缺省永不过期 |

## 拒绝原因（可区分、可回查）

畸形条目不会静默丢弃。每条拒绝都带机器可区分的 `reason`、人类可读 `detail` 和**原始内容** `rawContent`，
可通过 `GET /api/feeds/rejections` 回查全部历史拒绝记录。

| reason | 含义 |
|---|---|
| `MALFORMED_FORMAT` | 行/记录结构无法解析（坏 JSON、CSV 列数不足） |
| `MISSING_FIELD` | 缺少必需字段（type/value/source） |
| `UNSUPPORTED_TYPE` | type 不在支持集合内 |
| `INVALID_VALUE` | value 不符合所声明类型的格式 |
| `INVALID_TIMESTAMP` | 时间戳字段不是合法 ISO-8601 |
| `INVALID_CONFIDENCE` | confidence 不是 [0,100] 整数 |

## 合并、优先级与时效语义

- **指标身份**：`(type, 归一化 value)`。同一指标可被多个来源重复报告。
- **来源优先级**：由配置 `ioc.source-priority` 指定，如
  `ioc.source-priority=internal:100,partner:50`；未配置的来源优先级为 0。
- **胜者裁决（全序，确定且与摄取顺序无关）**：
  1. 来源优先级高者胜；
  2. 并列则 confidence 高者胜；
  3. 再并列则有效期晚者胜（永不过期视为最晚）；
  4. 再并列则来源名字典序。
- **时效**：`expires_at <= now` 的指标视为过期，**永不命中**；若高优先级来源的记录已过期，
  自动回退到仍生效的低优先级来源记录。
- **同一来源重复报告**：新观察替换旧记录（源内最新为准）。
- **批次幂等**：`batchId` 已摄取过时整个批次为 no-op——重复导入不产生重复状态或重复计数，
  响应中 `duplicateBatch=true`、`accepted=0`。

## 匹配与解释

`POST /api/events/match`，请求体为事件原文。引擎用正则提取事件中的 IOC 候选
（URL/邮箱/IP/哈希/域名，URL 与邮箱覆盖的域名不重复报告），对每个候选做 **O(1) 哈希查找**，
耗时与情报总量无关（不随总量线性劣化，见 `PerformanceTest`）。

每个命中返回判定依据：

```json
{
  "hit": true, "type": "IPV4", "value": "203.0.113.10",
  "source": "internal", "confidence": 90, "expiresAt": "2027-01-05T00:00:00Z",
  "explanation": "matched IPV4 '203.0.113.10' reported by source 'internal' with confidence 90/100, expires at 2027-01-05T00:00:00Z (evaluated at ...)"
}
```

同一事件中同一指标只产生一条判定（无重复命中）。

## 并发一致性

- 存储为 `ConcurrentHashMap<指标, 不可变记录列表>`，合并时在 `compute` 内**整体替换**不可变快照，
  读者永远读到一致快照，不会读到中间态。
- 摄取与查询可并发进行：不漏检、不重复命中（见 `ConcurrencyTest`）。

## 本地样例数据与验证

`src/main/resources/sample-data/`：

- `feed-internal.json` / `feed-partner.csv`：两个来源、两种格式，含冲突指标
  （`203.0.113.10` 两来源置信度与有效期不同）与已过期指标（`198.51.100.77`）。
- `events.txt`：6 条待检测事件（含命中、未命中、过期指标）。

验证方法：

```bash
mvn test          # 全部单测；日志打印输入与判定依据（java.util.logging）
```

测试覆盖：

| 测试 | 覆盖点 |
|---|---|
| `JsonFeedParserTest` / `CsvFeedParserTest` | 格式畸形、字段缺失、时间戳非法、类型不支持、值非法、置信度非法；拒绝原因可区分、原始内容可回查 |
| `IocStoreTest` | 来源冲突裁决、优先级 vs 置信度、顺序无关确定性、过期不命中、过期回退、批次幂等、源内替换 |
| `IocMatcherTest` | 命中解释（来源/置信度/有效期）、过期不命中、事件内去重、URL/邮箱/域名不重叠 |
| `ConcurrencyTest` | 并发摄取+查询：无漏检、无重复命中、无中间态 |
| `PerformanceTest` | 20 万指标下匹配耗时不随总量线性劣化 |
| `EndToEndIT` | 样例数据端到端：双源双格式摄取、冲突结论、重复导入 no-op、过期不命中、畸形条目拒绝分类 |
