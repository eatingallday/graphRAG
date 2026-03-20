"""
One-shot script: re-run the 4 diagnostic APKs with detailed trace logging.
"""
import os, sys, json, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

GHERA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "Ghera")

TARGET_APKS = [
    ("Storage",    "SQLlite-SQLInjection-Lean-benign"),
    ("System",     "CheckPermission-PrivilegeEscalation-Lean-benign"),
    ("Networking", "CheckValidity-InformationExposure-Lean-benign"),
    ("Web",        "WebView-CookieOverwrite-Lean-benign"),
]

def main():
    from run_ghera_experiment import run_single
    output_base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output", "ghera")

    for vtype, name in TARGET_APKS:
        apk_dir    = os.path.join(GHERA_DIR, vtype, name)
        analysis   = os.path.join(apk_dir, "analysis")
        reports    = os.path.join(apk_dir, "reports")
        apk_info   = {"type": vtype, "name": name,
                      "analysis_dir": analysis, "reports_dir": reports}

        print(f"\n{'='*70}")
        print(f"  {vtype}/{name}")
        print(f"{'='*70}")

        result = run_single(apk_info, output_base)
        icon = "✅" if result["exploitable"] is True else "❌"
        print(f"\n  → {icon} exploitable={result['exploitable']}  ({result['duration_s']:.0f}s)")

    print("\nDone. Check output/ghera/<type>/<name>/pipeline_trace_*.jsonl for detailed logs.")

if __name__ == "__main__":
    main()
