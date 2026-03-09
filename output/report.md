# APK Security Analysis Report

**APK**: InadequatePathPermission-InformationExposure-Lean-benign
**Generated**: 2026-03-08 23:33:27
**Final Verdict**: EXPLOITABLE

---

## 1. Manifest Analysis

ContentProvider 'edu.ksu.cs.benign.provider.UserDetailsContentProvider' 被导出且仅通过 path-permission 限制路径前缀 '/user'，但未保护根路径（如 /、/other 等）。攻击者可通过访问非 '/user' 前缀的路径绕过 readPermission 限制，导致任意数据读取。此外，自定义权限 'edu.ksu.cs.benign.permission.internalRead' 的 protectionLevel 为 'dangerous'，任何应用均可请求并可能获得该权限，无法有效限制访问。

- **Root path protected**: False
- **Attack surface**: ContentProvider 和 Activity 均被导出，可通过外部应用直接访问。
- **Confidence**: 0.95

---

## 2. Taint Analysis — SuSi Source/Sink Inference

**Sources identified**: ['edu.ksu.cs.benign.provider.UserDetailsContentProvider: android.database.Cursor query(android.net.Uri,java.lang.String[],java.lang.String,java.lang.String[],java.lang.String)']
**Sinks identified**:  ['edu.ksu.cs.benign.provider.UserDetailsContentProvider: android.database.Cursor query(android.net.Uri,java.lang.String[],java.lang.String,java.lang.String[],java.lang.String)', 'edu.ksu.cs.benign.provider.UserDetailsContentProvider: int delete(android.net.Uri,java.lang.String,java.lang.String[])', 'edu.ksu.cs.benign.provider.UserDetailsContentProvider: android.net.Uri insert(android.net.Uri,android.content.ContentValues)', 'edu.ksu.cs.benign.provider.UserDetailsContentProvider: int update(android.net.Uri,android.content.ContentValues,java.lang.String,java.lang.String[])']
**SuSi confidence**: 0.85
**Needs semantic analysis**: True

---

## 3. Semantic Analysis (if triggered)

该 ContentProvider 根据不同的 URI 路径暴露三类用户数据：通过 '/user/school' 返回用户姓名和大学信息，通过 '/user/address' 返回用户 ID 和城市地址，通过 '/user/ssn' 返回用户 ID 和社保号（SSN）。数据来源于应用私有目录下的 CSV 文件，查询时使用 selectionArgs 进行 ID 匹配过滤。无显式权限声明或运行时权限检查，存在敏感数据泄露风险。

---

## 4. FlowDroid Layer A — Intra-Component Taint Paths

- **intra_synthetic_0**: `<edu.ksu.cs.benign.provider.UserDetailsContentProvider: android.database.Cursor query(android.net.Uri,java.lang.String[],java.lang.String,java.lang.String[],java.lang.String)>` → `<android.database.MatrixCursor: void addRow(java.lang.Iterable)>`
- **intra_synthetic_1**: `<edu.ksu.cs.benign.provider.UserDetailsContentProvider: android.database.Cursor query(android.net.Uri,java.lang.String[],java.lang.String,java.lang.String[],java.lang.String)>` → `<java.io.BufferedReader: java.lang.String readLine()>`


---

## 5. ICC Bridge Layer B — Cross-Component Paths

- **cross_intra_synthetic_0**: entry=`UserDetailsContentProvider` vector=`ContentProvider 'UserDetailsContentProvider' is exported with no root path permission. Any app can query root URI without any permission, bypassing the /user path-permission restriction.` confidence=0.95
- **cross_intra_synthetic_1**: entry=`UserDetailsContentProvider` vector=`ContentProvider 'UserDetailsContentProvider' is exported with no root path permission. Any app can query root URI without any permission, bypassing the /user path-permission restriction.` confidence=0.95


---

## 6. GraphRAG Path Validation (Text2Cypher)

| Query | Neo4j Answer |
|-------|-------------|
| 该 ContentProvider 的根路径是否可被外部无权限应用访问？ | content='<Record c.name=\'UserDetailsContentProvider\' c.authority=\'edu.ksu.cs.benign.userdetails\' c.vuln_description="ContentProvider \'edu.ksu.cs.benign.provider.UserDetailsContentProvider\' 被导出且仅通过 path-permission 限制路径前缀 \'/user\'，但未保护根路径（如 /、/other 等）。攻击者可通过访问非 \'/user\' 前缀的路径绕过 readPermission 限制，导致任意数据读取。此外，自定义权限 \'edu.ksu.cs.benign.permission.internalRead\' 的 protectionLevel 为 \'dangerous\'，任何应用均可请求并可能获得该权限，无法有效限制访问。">' metadata=None |
| query() 方法是否存在污点路径指向 SSN 或其他敏感数据？ | content='<Record m.sig=\'<edu.ksu.cs.benign.provider.UserDetailsContentProvider: android.database.Cursor query(android.net.Uri,java.lang.String[],java.lang.String,java.lang.String[],java.lang.String)>\' ip.source=\'<edu.ksu.cs.benign.provider.UserDetailsContentProvider: android.database.Cursor query(android.net.Uri,java.lang.String[],java.lang.String,java.lang.String[],java.lang.String)>\' ip.sink=\'<android.database.MatrixCursor: void addRow(java.lang.Iterable)>\' cp.attack_vector="ContentProvider \'UserDetailsContentProvider\' is exported with no root path permission. Any app can query root URI without any permission, bypassing the /user path-permission restriction." ip.confidence=0.85 cp.confidence=0.95>' metadata=None; content='<Record m.sig=\'<edu.ksu.cs.benign.provider.UserDetailsContentProvider: android.database.Cursor query(android.net.Uri,java.lang.String[],java.lang.String,java.lang.String[],java.lang.String)>\' ip.source=\'<edu.ksu.cs.benign.provider.UserDetailsContentProvider: android.database.Cursor query(android.net.Uri,java.lang.String[],java.lang.String,java.lang.String[],java.lang.String)>\' ip.sink=\'<java.io.BufferedReader: java.lang.String readLine()>\' cp.attack_vector="ContentProvider \'UserDetailsContentProvider\' is exported with no root path permission. Any app can query root URI without any permission, bypassing the /user path-permission restriction." ip.confidence=0.8 cp.confidence=0.95>' metadata=None |
| 现有的 path-permission 配置能否防止根路径被绕过？ | content='<Record c.name=\'UserDetailsContentProvider\' c.authority=\'edu.ksu.cs.benign.userdetails\' pp.pathPrefix=\'/user\' pp.readPermission=\'edu.ksu.cs.benign.permission.internalRead\' c.vuln_description="ContentProvider \'edu.ksu.cs.benign.provider.UserDetailsContentProvider\' 被导出且仅通过 path-permission 限制路径前缀 \'/user\'，但未保护根路径（如 /、/other 等）。攻击者可通过访问非 \'/user\' 前缀的路径绕过 readPermission 限制，导致任意数据读取。此外，自定义权限 \'edu.ksu.cs.benign.permission.internalRead\' 的 protectionLevel 为 \'dangerous\'，任何应用均可请求并可能获得该权限，无法有效限制访问。">' metadata=None |
| 是否存在完整的跨组件攻击路径（CrossPath）？ | content='<Record cp.entry_component=\'UserDetailsContentProvider\' cp.attack_vector="ContentProvider \'UserDetailsContentProvider\' is exported with no root path permission. Any app can query root URI without any permission, bypassing the /user path-permission restriction." cp.intra_path_id=\'intra_synthetic_0\' cp.confidence=0.95>' metadata=None; content='<Record cp.entry_component=\'UserDetailsContentProvider\' cp.attack_vector="ContentProvider \'UserDetailsContentProvider\' is exported with no root path permission. Any app can query root URI without any permission, bypassing the /user path-permission restriction." cp.intra_path_id=\'intra_synthetic_1\' cp.confidence=0.95>' metadata=None |


### Verdict

该 ContentProvider 存在严重的权限绕过漏洞（InadequatePathPermission），由于其被导出且未对根路径进行保护，任何外部应用均可通过访问根路径（如 /）绕过 path-permission 的限制，直接读取敏感数据。尽管存在针对 '/user' 路径前缀的 readPermission 配置，但该配置无法覆盖根路径或其他非 '/user' 前缀的路径。同时，自定义权限 'edu.ksu.cs.benign.permission.internalRead' 的 protectionLevel 为 'dangerous'，意味着任何应用都可请求并可能获得该权限，无法提供有效访问控制。污点分析显示 query() 方法会从文件中读取敏感信息（如 SSN）并通过 MatrixCursor 返回，构成完整的数据泄露路径。CrossPath 分析确认了该漏洞存在高置信度的跨组件攻击路径。因此，攻击者可通过构造对根 URI 的 ContentResolver 查询，无需任何权限即可获取用户敏感信息。

**Exploitable**: True

---

## 7. Evidence Chain

```
Manifest Agent  -->  root_path_protected=false (Neo4j)
Taint Agent     -->  SuSi XML generated (Layer A input)
FlowDroid       -->  IntraPath: query()->MatrixCursor.addRow() (Neo4j)
ICC Bridge      -->  CrossPath: exported provider, no root permission (Neo4j)
Validation Agent-->  Text2Cypher confirmed vulnerability (GraphRAG)
```

---

*Generated by LangGraph + Neo4j GraphRAG pipeline (Qwen3-235)*
