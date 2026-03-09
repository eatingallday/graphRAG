"""
Central configuration: model, Neo4j, paths.
"""
import os

# ─── Qwen3-235 (OpenAI-compatible) ───────────────────────────────────────────
QWEN_MODEL    = "qwen3-235"
QWEN_BASE_URL = "http://gw-bzokqkvr2cblz8ok6y.cn-wulanchabu-acdr-1.pai-eas.aliyuncs.com/api/predict/yxhuang_qwen235_sj/v1"
QWEN_API_KEY  = "MjhmYTMyODRmZGMyMjM3ODAzN2ZkMjAwMzA4MDk5MGYzZmFkOWM1ZA=="

# ─── Neo4j ───────────────────────────────────────────────────────────────────
NEO4J_URI      = "bolt://localhost:7687"
NEO4J_USER     = "neo4j"
NEO4J_PASSWORD = "password123"

# ─── Paths ───────────────────────────────────────────────────────────────────
BASE_DIR       = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APK_PATH       = os.path.join(
    BASE_DIR,
    "Ghera-all-structured/ICC/InadequatePathPermission-InformationExposure-Lean-benign.apk"
)
ANDROID_PLATFORMS = os.path.join(BASE_DIR, "android-platforms/android-27")
FLOWDROID_JAR     = os.path.join(BASE_DIR, "soot-infoflow-cmd-jar-with-dependencies.jar")
ANALYSIS_DIR      = os.path.join(BASE_DIR, "analysis")
OUTPUT_DIR        = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")
PROMPTS_DIR       = os.path.join(os.path.dirname(os.path.abspath(__file__)), "prompts")
