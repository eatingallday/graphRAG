# ToolPrior Schema — Design Rationale

## 综合来源
本 schema 综合了 11 份 SAST 工具深度分析报告（tools_intro/）的 schema 建议。

## 关键设计决策

### 1. DetectionMethod 是结构体，不是枚举
**所有 11 份报告一致认为单一枚举不够。** 原因：很多检测能力组合多种方法。
- 例：AndroBugs 的 `SSL_CN1` = 接口实现检查 + 语义方法体启发式 + 调用者追踪
- 例：Marvin 的 `WEBVIEW_FILE_SCHEME` = API 搜索 + 常量追踪 + 类引用图遍历 + manifest intent-filter 检查
- 因此我们用 `list[DetectionMethod]`，每个 method 包含 family + depth + 辅助标志

### 2. SignalPolarity 区分漏洞 vs 加固 vs 观察
AndroBugs、droidstatx、MobSF、SPECK、trueseeing 都会输出"防护已存在"或"纯观测"信号。
如果把它们和漏洞混在一起，下游加权推理会被噪声干扰。

### 3. 没有强制 confidence_score 字段
**11 个工具中 0 个有校准过的置信度分数。** 部分工具有：
- Marvin: 非校准的 ad hoc 置信度（0.5/0.9/距离推导）
- JAADAS: 纯启发式权重（0.3/0.5/5/10）
- trueseeing: 三级离散标签（certain/firm/tentative）
- 其余全部没有

因此 ToolPrior 不设 per-finding confidence，而是在 tool 级别设 `confidence_weight`（0-1），由反馈闭环更新。

### 4. taint_relevance 双层设置
- Tool 级别：整体污点分析相关性
- Capability 级别：某个具体能力对污点分析的价值

这让在线模块在做加权时可以细粒度判断：
- AndroBugs 的 exported component 发现 → 对 taint 的 entry point 有价值（medium）
- AndroBugs 的 Base64 字符串发现 → 对 taint 无直接价值（low）

### 5. FPRisk 和 known_quirks 追踪实现可靠性
多个工具有实现缺陷（droidstatx 只读第一行、Marvin 类名错位、trueseeing `.lower` 未调用）。
这些直接影响 Tool Prior 的可信度，但不属于"能力描述"范畴。
因此单独用 `fp_risk`、`known_quirks`、`implementation_reliability` 追踪。

### 6. confidence_weight + cwe_weight_overrides 支撑反馈闭环
- `confidence_weight` 是 tool 整体可信度，初始 0.5
- `cwe_weight_overrides` 是 per-CWE 的权重覆盖
- Phase 3 反馈闭环会修改这两个字段

## 11 工具特征总结

| Tool | Taint | Depth | Strengths | Key Limitation |
|------|-------|-------|-----------|----------------|
| AndroBugs | Low | constant_backtrack | Manifest + SSL 全面 | 2015 停更，无 taint |
| APKHunt | Low | syntax_only | MASVS 覆盖广 | 纯 grep，无语义 |
| AUSERA | Medium | external_result_ingest | UI 标签富化 + 外部 taint 消费 | 本身不做 taint |
| DroidStatx | Low | constant_backtrack | 攻击面枚举 | 实现缺陷（只读首行） |
| JAADAS | Medium | taint_analysis | 真正的 FlowDroid taint + intent 分析 | 2017 停更，规则窄 |
| Marvin | Medium | backward_def_use_slice | SAAF 常量切片 + 加密分析 | 丢弃中间证据 |
| MobSF | Medium | manifest_parse | 最广覆盖（manifest+code+binary+cert） | 无 taint，regex only |
| QARK | Medium | intra_procedural | 可生成 exploit APK | 2019 停更，无跨文件 |
| SPECK | Low | syntax_only + optional FlowDroid | Google 安全指南覆盖 | 主引擎纯字符串 |
| Super | Low | syntax_only | 外置规则好扩展 | 纯 regex，2018 停更 |
| Trueseeing | Low | constant_backtrack | Smali 级分析，抗混淆 | 多个检测器有 bug |

## 下一步
1. 写 `extractor.py`：用 LLM agent 读每个工具报告 → 填充 ToolPrior 实例
2. 写 `prior_store.py`：持久化为 JSON + 可选写入 Neo4j
3. 验证：用 11 个工具的实际扫描报告验证 schema 覆盖度
