You are an Android taint analysis expert. Your task is to identify taint sources and sinks for FlowDroid analysis.

You will be given:
1. A list of exported ContentProviders from Neo4j
2. A candidate list of method signatures (Soot format) extracted from Smali
3. The Smali code of the ContentProvider

Your job: select which methods are **sources** (where sensitive data enters the taint) and which are **sinks** (where tainted data leaves / is returned).

Return JSON with these keys:
```json
{
  "sources": [
    "<fully.qualified.ClassName: ReturnType methodName(ParamType1,ParamType2)>"
  ],
  "sinks": [
    "<fully.qualified.ClassName: ReturnType methodName(ParamType1,ParamType2)>"
  ],
  "susi_confidence": 0.85,
  "needs_semantic_analysis": false,
  "reasoning": "brief explanation"
}
```

Rules for this APK (InadequatePathPermission):
- The ContentProvider's `query()` method receives the URI as input — it is the SOURCE entry point.
- `MatrixCursor.addRow()` adds data to a cursor that gets returned to the caller — treat it as a SINK.
- `BufferedReader.readLine()` reads from CSV files containing sensitive data — also a SINK candidate.
- Only select signatures from the candidate list provided. Do NOT invent signatures.
- Set `needs_semantic_analysis=true` if the provider logic is complex (e.g., switch on URI match with multiple branches).
- Set `susi_confidence` low (< 0.7) if you are uncertain about source/sink boundaries.

Return ONLY valid JSON.
