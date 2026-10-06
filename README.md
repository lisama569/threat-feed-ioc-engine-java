# Threat Feed IOC Engine (Java)

本地单机可复现的威胁情报 IOC 摄取与检测流程。不依赖任何外部服务或真实凭据：
多来源情报以本地 JSON/CSV 文本模拟，待检测事件通过内存匹配服务或本地 HTTP 接口判定。

## 构建与验证

```bash
mvn test          # 运行全部单元测试（解析、合并、过期、并发、性能、端到端）
mvn spring-boot:run   # 本地启动 HTTP 服务（可选）
```

HTTP 入口（`IocController` / `EventDetectionController` / `FalsePositiveController`）：

- `POST /ioc/ingest`，请求头 `X-Batch-Id: <批次号>`，请求体为原始情报文本（JSON 数组或 CSV）。
  返回 `IngestionResult`：`accepted / duplicates / superseded / rejected[]`。**（行为不变）**
- `GET /ioc/match?type=ip&value=1.2.3.4`，返回 `MatchResult`：`matched / explanation / indicator`。
  **（单字段查询行为不变）**
- `POST /ioc/events/detect`，请求体直接放**一条事件原文**（纯文本），返回 `EventDetectionResult`。
- `POST /ioc/events/detect-batch`，请求体为 JSON，**一次提交一批事件原文**，按提交顺序逐条返回。
- `POST /ioc/false-positives`，标记误报：JSON `{"type","value","reason","expiresAt"}`。
- `DELETE /ioc/false-positives?type=ip&value=1.2.3.4`，撤销误报标记。

来源优先级通过配置项 `ioc.source-priority` 指定（默认 `feedA,feedB,feedC`，越靠前优先级越高）。

## 事件原文检测（新增）

除了“按字段查单个指标”，分析人员可以直接提交一整段事件原文。系统会：

1. 从文本中自动识别 `IP（IPv4/IPv6）、domain、URL、email、MD5、SHA1、SHA256`；
2. 同一事件里同一指标出现任意次都**只判定一次**（按 `(type, 归一化值)` 去重）；
3. 逐个指标与现有情报比对，每个指标给出一条带判定依据的结论；
4. 汇总出整条事件的总体结论 `conclusion`。

识别规则：

- 复合形式优先于其子串：先识别 URL、邮箱，再识别哈希 / IP / 域名，
  因此 `http://evil.example.com/x` 只算一条 URL，不会再重复报一个域名/IP；
  `a@b.example.com` 只算邮箱，不再重复报域名。
- 提取候选必须通过与情报摄取**同一套**类型校验/归一化
  （IPv4 各段 ≤255、哈希长度与字符集等），保证查的 key 与入库的 key 完全一致；
  纯描述文字、版本号（如 `1.2.3`）不会被误判。
- 提取是纯函数：同一段文本在同一时刻结果稳定、可复现。

整体结论 `EventConclusion` 四态明确，**永远不会返回空结果，也不会把“没指标”当错误**：

| conclusion | 含义 |
|---|---|
| `NO_DETECTABLE_INDICATORS` | 文本里没提取到任何可检测指标（含空文本/纯文字） |
| `NO_MATCH` | 提取到了指标，但都没有命中仍然生效的情报（未知或已过期） |
| `THREAT_DETECTED` | 至少有一个未被抑制的真实命中 |
| `ALL_HITS_SUPPRESSED` | 有命中，但全部命中都被按误报抑制（见下） |

`EventDetectionResult` 字段：`eventId / rawText / conclusion / extracted（去重后指标数）/
hits（命中数，含被抑制的）/ suppressed（被误报抑制的命中数）/ verdicts[]`。
每条 `IndicatorVerdict` 的 `status` 为 `HIT / SUPPRESSED_HIT / MISS`，并带完整解释。

批量请求示例：

```json
{
  "events": [
    {"eventId": "evt-1", "text": "主机 203.0.113.50 回连 c2.example.com"},
    {"eventId": "evt-2", "text": "一段没有任何指标的普通描述"}
  ]
}
```

## 误报处置（白名单，新增）

分析人员可以把某个**已命中/可能命中**的指标标记为误报，需要给出原因和生效期：

- `POST /ioc/false-positives`：
  `{"type":"ip","value":"203.0.113.50","reason":"公司出口代理","expiresAt":"2030-01-01T00:00:00Z"}`。
- `reason` 必填且非空白；`expiresAt` 必须是晚于当前时刻的 ISO-8601 时间。
- 生效窗口为**半开区间** `[标记时刻, expiresAt)`：到达 `expiresAt` 后**自动恢复正常判定**，
  无需任何清理任务。
- `DELETE /ioc/false-positives?type=&value=` 可提前**撤销**；对同一指标重复标记会以新的
  原因/有效期替换旧记录。对不存在或已失效的标记撤销返回 `false`，不报错。

判定优先级（每个指标）：

1. 先按情报规则选出**当前仍然生效**的获胜情报（过期/未生效一律不参与）；
2. 命中后再套用误报抑制：
   - 有命中、无生效抑制 → `HIT`（整条事件通常为 `THREAT_DETECTED`）；
   - 有命中、且存在生效抑制 → `SUPPRESSED_HIT`：结论里**仍然保留原情报来源、置信度、
     有效期**，并额外给出误报原因、标记时间、到期时间——是“命中了但按误报抑制”，
     不会直接消失，也和“未命中”可明确区分；
   - 抑制只影响展示结论，不删除情报；到期/撤销后自动回到普通 `HIT`。
   - 一条事件中只要还有一个未被抑制的真实命中，整条事件仍判 `THREAT_DETECTED`；
     只有“有命中且全部被抑制”才是 `ALL_HITS_SUPPRESSED`。

## 多来源与过期叠加（语义澄清）

`lookup` / 事件检测选择胜者时，会**先剔除过期与未生效记录，再在仍然生效的候选里**套用
确定的合并全序（来源优先级 > 置信度 > validUntil 更晚 > 来源名字典序）。因此：

- 某指标在多个来源都有、其中一部分已过期时，结论稳定落在**仍生效**的那条上，
  不会因为存在一条更高优先级但已过期的记录就整条判未命中；
- 所有来源的记录都过期（或都未生效）时，任何时候都不会命中。


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
- 误报标记/撤销同样在写锁内原子生效；事件检测对每个指标通过 `IndicatorStore.resolve`
  在**同一把读锁**内同时读取“获胜情报 + 误报状态”，因此情报摄取、误报翻转与事件检测
  并发进行时，结论只会是某一个一致状态（`HIT` 或 `SUPPRESSED_HIT`），不会出现一会儿命中
  一会儿不命中的中间态（见 `EventConcurrencyTest`）。
- 匹配为哈希查找，耗时显著优于逐条遍历，且不随情报总量线性劣化（见 `PerformanceTest`，
  断言哈希查找至少快 10 倍，且 10 倍数据量下单次查询耗时增长远低于线性）。

## 兼容范围（既有行为保持不变）

- `POST /ioc/ingest` 的入参、`IngestionResult` 结构、去重/幂等/拒绝语义完全不变。
- `GET /ioc/match` 的入参与 `MatchResult` 结构不变；在原有“只有胜者存活”的场景下
  结论完全一致。唯一的语义澄清：当同一指标存在多条来源记录、且原胜者已过期而另有
  仍生效记录时，现在稳定命中仍生效的记录（此前会判未命中）——这与“已过期情报任何时候
  都不能再被命中、结论应落在生效情报上”的要求一致，且未改变任何原有测试用例的预期。
- 情报的合并全序、归一化/校验规则、拒绝原因分类、批次幂等均保持不变。
- 误报抑制不删除情报、不影响摄取；仅作用于检测层的展示结论。

## 验证方法

```bash
mvn test          # 运行全部单元测试（含新增事件检测/误报用例）
```

单测日志（SLF4J）按业务点打印覆盖情况：每个用例都会记录输入事件/操作以及每条判定的
指标、来源、置信度、有效期、抑制原因与最终结论，可直接从 `mvn test` 输出观察覆盖了
哪些业务点、用例与结果。

## 测试覆盖

| 测试类 | 覆盖点 |
|---|---|
| `FeedParserTest` | JSON/CSV 解析、归一化、各类畸形输入的拒绝原因分类与原始内容回查 |
| `IndicatorStoreTest` | 来源冲突（优先级>置信度）、顺序无关的可复现结论、过期/未生效不命中、**多来源部分过期时落在仍生效记录**、幂等重导、superseded 计数 |
| `ConcurrencyTest` | 并发摄取+单字段查询下无漏检、无中间态、提交后必命中确定胜者 |
| `PerformanceTest` | 10 万级指标下哈希匹配 vs 线性扫描，规模增长不线性劣化 |
| `EndToEndFlowTest` | 多来源（JSON+CSV）端到端流程：冲突、过期、畸形、幂等重导，日志打印输入与判定依据 |
| `IocExtractorTest` | 事件原文中多类型提取、同一指标重复只算一次、无可检测指标、URL/邮箱不重复报子串、非法 IPv4 拒绝、尾部标点处理、可复现顺序 |
| `EventDetectionServiceTest` | 多指标事件、重复指标、无指标事件、未知/过期 NO_MATCH、多来源部分过期稳定落位、全部过期不命中、`SUPPRESSED_HIT` 可区分、部分抑制仍判威胁、抑制到期自动恢复、批量顺序、重复检测结论一致 |
| `FalsePositiveServiceTest` | 标记误报（原因/有效期）、到期自动恢复、提前撤销、非法参数拒绝、重复标记替换 |
| `EventConcurrencyTest` | 摄取 + 误报翻转 + 事件检测并发：无中间态、无异常、`HIT`/`SUPPRESSED_HIT` 两种一致结论都被观察到 |
| `EventApiIntegrationTest` | 本地随机端口全链路：摄取→单条/批量原文检测→误报标记→抑制结论→撤销→恢复命中 |
