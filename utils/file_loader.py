"""
Load APK analysis artifacts from the decompiled analysis/ directory.
Filters out third-party libraries (android/support/, com/google/, etc.).

Fixed directory structure:
  {analysis_dir}/apktool/AndroidManifest.xml
  {analysis_dir}/apktool/smali/**/*.smali
  {analysis_dir}/jadx/sources/**/*.java   (optional)
"""
import os
import glob as _glob

THIRD_PARTY_PREFIXES = (
    "android/support/",
    "android/arch/",
    "com/google/",
    "com/android/",
    "androidx/",
    "kotlin/",
    "kotlinx/",
    "org/apache/",
)


def _is_third_party(path: str) -> bool:
    for pfx in THIRD_PARTY_PREFIXES:
        if pfx in path.replace("\\", "/"):
            return True
    return False


def load_apk_artifacts(analysis_dir: str) -> tuple[str, dict, dict]:
    """
    从 analysis_dir 加载 APK 产物。固定目录结构：
      {analysis_dir}/apktool/AndroidManifest.xml
      {analysis_dir}/apktool/smali/**/*.smali
      {analysis_dir}/jadx/sources/**/*.java   （可选）

    Returns:
        manifest_xml : str           — raw AndroidManifest.xml content
        app_smali    : dict[str,str] — {relative_class_path: smali_text}
        app_java     : dict[str,str] — {relative_class_path: java_text}  (may be empty)
    """
    smali_root    = os.path.join(analysis_dir, "apktool", "smali")
    manifest_path = os.path.join(analysis_dir, "apktool", "AndroidManifest.xml")
    java_root     = os.path.join(analysis_dir, "jadx", "sources")

    if not os.path.exists(manifest_path):
        raise FileNotFoundError(
            f"[file_loader] 找不到 AndroidManifest.xml: {manifest_path}"
        )

    with open(manifest_path, encoding="utf-8") as f:
        manifest_xml = f.read()

    app_smali: dict[str, str] = {}
    for path in _glob.glob(os.path.join(smali_root, "**", "*.smali"), recursive=True):
        rel = os.path.relpath(path, smali_root)
        if not _is_third_party(rel):
            key = rel.replace(os.sep, "/").replace(".smali", "")
            with open(path, encoding="utf-8", errors="replace") as f:
                app_smali[key] = f.read()

    app_java: dict[str, str] = {}
    if os.path.isdir(java_root):
        for path in _glob.glob(os.path.join(java_root, "**", "*.java"), recursive=True):
            rel = os.path.relpath(path, java_root)
            if not _is_third_party(rel):
                key = rel.replace(os.sep, "/").replace(".java", "")
                with open(path, encoding="utf-8", errors="replace") as f:
                    app_java[key] = f.read()

    return manifest_xml, app_smali, app_java
