# Threat Feed IOC Engine (Java)

本地单机可复现的威胁情报 IOC 摄取与检测流程。不依赖任何外部服务或真实凭据：
多来源情报以本地 JSON/CSV 文本模拟，待检测事件通过内存匹配服务或本地 HTTP 接口判定。

## 构建与验证

```bash
mvn test          # 运行全部单元测试（解析、合并、过期、并发、性能、端到端）
mvn spring-boot:run   # 本地启动 HTTP 服务（可选）
```

HTTP 入口（`IocController`）：

- `POST /ioc/ingest`，请求头 `X-Batch-Id: <批次号>`，请求体为原始情报文本（JSON 数组或 CSV）。
  返回 `IngestionResult`：`accepted / duplicates / superseded / rejected[]`。
- `GET /ioc/match?type=ip&value=1.2.3.4`，返回 `MatchResult`：`matched / explanation / indicator`。

来源优先级通过配置项 `ioc.source-priority` 指定（默认 `feedA,feedB,feedC`，越靠前优先级越高）。

## 支持的情报格式

### JSON（数组，每条一个对象）

```json
[
  {"type": "ip", "value": "203.0.113.7", "source": "cert-feed",
   "confidence": 90, "validFrom": "2026-01-01T00:00:00Z", "validUntil": "2027-01-01T00:00:00Z"}
]
```

### CSV（首行为表头）

```
type,value,source,confidence,validFrom,validUntil
domain,evil.example.com,community-feed,95,2027-01-01T00:00:00Z,
```

- 必填字段：`type`、`value`、`source`；`confidence` 缺省为 50；`validFrom`/`validUntil` 可空。
- 支持的 `type`：`ip`（IPv4/IPv6）、`domain`、`url`、`email`、`md5`、`sha1`、`sha256`（大小写不敏感，常见别名自动归一）。
- 值会被归一化为小写等规范形式，并按类型校验（如 IPv4 各段 ≤255、哈希长度与字符集）。

## 拒绝语义（不静默丢弃）

任何无法入库的记录都会以 `RejectedRecord(rawContent, reason, detail)` 返回，
`rawContent` 保留该条目的原始文本以便回查。`reason` 可区分：

| reason | 含义 |
|---|---|
| `MALFORMED_FORMAT` | 整体载荷不是合法 JSON/CSV，或 JSON 记录不是对象 |
| `MISSING_FIELD` | 缺少必填字段（type/value/source 或 CSV 必需列） |
| `UNSUPPORTED_TYPE` | 类型标记不受支持 |
| `INVALID_VALUE` | 值未通过该类型的校验/归一化 |
| `INVALID_TIMESTAMP` | 时间戳不是合法 ISO-8601 instant |
| `INVALID_CONFIDENCE` | 置信度不是 [0,100] 的整数 |

## 合并与优先级规则（确定且可复现）

同一 `(type, value)` 来自多个来源时，胜者按如下全序确定，与摄取顺序无关：

1. **来源优先级**高者胜（`ioc.source-priority` 中越靠前越高；未列出的来源最低）；
2. 并列时 **置信度** 高者胜；
3. 再并列时 `validUntil` 更晚者胜（`null` 表示永不过期，视为最晚）；
4. 再并列时来源名字典序小者胜（保证全序稳定）。

重复导入同一批次是**幂等**的：以 `(type, value, source, batchId)` 去重，
重复记录计入 `duplicates`，不产生重复状态或重复计数；`superseded` 统计
被更高优先级/置信度记录取代的次数。

## 时效语义

- `validFrom`/`validUntil` 为 ISO-8601 时间戳；窗口为 `[validFrom, validUntil)`，左闭右开。
- `validFrom = null` 表示立即生效；`validUntil = null` 表示永不过期。
- 判定以查询时刻为准（`MatchService` 注入 `Clock`，测试中用固定时钟保证可复现）：
  **已过期或尚未生效的指标不会被命中**。

## 匹配与解释

`MatchService.match(type, value)` 基于哈希索引做 O(1) 查找，命中结果包含判定依据：
来源、置信度、有效期窗口与判定时刻，例如：

```
matched IP=1.2.3.4 | source=cert-feed | confidence=90 | validFrom=2026-01-01T00:00:00Z | validUntil=2027-01-01T00:00:00Z | evaluatedAt=2026-09-26T12:00:00Z
```

未命中也会说明原因（未知或已过期）。

## 并发与性能

- 存储使用读写锁：一个批次在写锁内**原子**合并，读者不会看到中间态；
  摄取与查询并发进行时不漏检、不重复命中（见 `ConcurrencyTest`）。
- 匹配为哈希查找，耗时显著优于逐条遍历，且不随情报总量线性劣化（见 `PerformanceTest`，
  断言哈希查找至少快 10 倍，且 10 倍数据量下单次查询耗时增长远低于线性）。

## 测试覆盖

| 测试类 | 覆盖点 |
|---|---|
| `FeedParserTest` | JSON/CSV 解析、归一化、各类畸形输入的拒绝原因分类与原始内容回查 |
| `IndicatorStoreTest` | 来源冲突（优先级>置信度）、顺序无关的可复现结论、过期/未生效不命中、幂等重导、superseded 计数 |
| `ConcurrencyTest` | 并发摄取+查询下无漏检、无中间态、提交后必命中确定胜者 |
| `PerformanceTest` | 10 万级指标下哈希匹配 vs 线性扫描，规模增长不线性劣化 |
| `EndToEndFlowTest` | 多来源（JSON+CSV）端到端流程：冲突、过期、畸形、幂等重导，日志打印输入与判定依据 |

单测日志（SLF4J）会打印输入载荷与每条判定的依据，可用 `mvn test` 直接观察。
