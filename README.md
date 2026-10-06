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
- `POST /ioc/detect`，请求体为**事件原文**（纯文本），返回 `EventVerdict`（见下文「事件原文检测」）。
- `POST /ioc/detect/batch`，请求体为 JSON 字符串数组，批量检测，按输入顺序返回 `EventVerdict` 列表。
- `POST /ioc/false-positive`，请求体 JSON：
  `{"type":"domain","value":"cdn.example.com","reason":"...","validUntil":"2026-11-01T00:00:00Z"}`，
  将指标标记为误报（见下文「误报处置」）。
- `DELETE /ioc/false-positive?type=domain&value=cdn.example.com`，撤销误报处置，返回 `{"revoked": true/false}`。

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

## 事件原文检测

`EventDetectionService`（HTTP：`POST /ioc/detect` 与 `POST /ioc/detect/batch`）直接接收事件原文：

1. **提取**（`IocExtractor`）：从文本中识别 IPv4、域名、URL、邮箱、MD5/SHA1/SHA256。
   候选值用与摄取完全相同的 `FeedParser.normalize` 规则归一化与校验，
   因此提取出的值与库中存储形式必然可比。URL 末尾常见的句读符号（`.,;:!?'"`）会被剥离。
   自由文本中不提取 IPv6（歧义过大）；IPv6 情报的摄取与单指标查询不受影响。
2. **去重**：同一 `(type, value)` 在一条事件里出现多少次都只判定一次，
   结果按首次出现位置排序；同一输入的提取结果完全一致（可复现）。
3. **逐条判定**：每个指标复用 `MatchService` 的判定与解释（来源、置信度、有效期、判定时刻）。
   整条事件在同一个 `evaluatedAt` 时刻评估，保证结论一致。
4. **总体结论**（`EventVerdict.verdict`）：

   | verdict | 含义 |
   |---|---|
   | `HIT` | 至少一个指标命中生效情报（未被误报抑制） |
   | `SUPPRESSED` | 无有效命中，但至少一个命中被按误报抑制 |
   | `NO_HIT` | 提取到了指标，但无一命中生效情报 |
   | `NO_INDICATORS` | 事件原文中没有任何可检测指标（明确结论，不是空结果或错误） |

## 误报处置（分析人员加白）

`FalsePositiveRegistry`（HTTP：`POST/DELETE /ioc/false-positive`）支持对误报指标做处置：

- **标记**：必须给出 `reason`（原因）与 `validUntil`（生效截止，左闭右开）。
  同一指标重复标记会覆盖旧处置。
- **抑制语义**：被处置的指标再次被检测到时，结论为 `SUPPRESSED`——
  **命中情报本身（来源/置信度/有效期）仍然完整展示**，并附误报原因与抑制截止时刻，
  不会直接消失或无从区分。总体结论中，只要还有一个未抑制的有效命中，事件仍为 `HIT`。
- **到期自动恢复**：判定时刻越过 `validUntil` 后抑制立即失效，结论自动恢复正常，
  过期条目被惰性清理，无需人工干预。
- **撤销**：`revoke` 立即恢复正常判定。
- **作用域**：抑制精确作用于某个 `(type, value)`，不影响同事件里的其他指标。
- **并发**：标记/撤销是单次原子 map 操作；已提交的处置对任何并发检测要么完全可见、
  要么完全不可见，不存在中间态（见 `FalsePositiveTest` 的并发用例）。

**判定优先级**：先按时效与合并规则选出命中情报，再应用误报抑制；
误报抑制只改变结论的呈现（HIT → SUPPRESSED），不改变命中所依据的情报记录。

## 兼容范围（既有行为保持不变）

- 摄取格式、拒绝语义、幂等重导、合并优先级全序、单指标 `GET /ioc/match` 的判定与解释格式均不变。
- 过期/未生效情报永不命中——这一点不变；唯一的细化是：同一 `(type, value)` 存在多条记录时，
  胜者现在在**仍生效的记录**中选出，已过期的高优先级记录不再遮蔽其他来源仍生效的记录
  （此前该组合会被判为未命中）。所有既有测试用例的结论不受影响。
- 性能与并发模型不变：摄取仍在写锁内原子合并，匹配仍是 O(1) 哈希查找；
  事件检测只是对提取出的每个指标各做一次同样的查找。

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
| `IocExtractorTest` | 事件原文多类型指标提取、重复指标只提取一次、无指标文本、非法候选过滤、归一化与摄取一致、提取可复现 |
| `EventDetectionTest` | 多指标事件逐条判定与总体结论、重复指标只判一次、无指标事件返回 `NO_INDICATORS`、多来源叠加部分过期落在生效记录、全过期不命中、批量检测保序、重复检测结论一致 |
| `FalsePositiveTest` | 误报标记后结论为 `SUPPRESSED` 且命中情报仍可见、到期自动恢复、撤销立即恢复、抑制只作用于指定指标、并发检测下已提交处置无中间态 |
| `ConcurrencyTest` | 并发摄取+查询下无漏检、无中间态、提交后必命中确定胜者 |
| `PerformanceTest` | 10 万级指标下哈希匹配 vs 线性扫描，规模增长不线性劣化 |
| `EndToEndFlowTest` | 多来源（JSON+CSV）端到端流程：冲突、过期、畸形、幂等重导，日志打印输入与判定依据 |

单测日志（SLF4J）会打印输入载荷与每条判定的依据，可用 `mvn test` 直接观察。
例如事件检测日志会打印每个提取指标的 `HIT/SUPPRESSED/MISS` 状态、命中情报的
来源/置信度/有效期，以及整条事件的汇总（指标数、命中数、抑制数、总体结论）。
