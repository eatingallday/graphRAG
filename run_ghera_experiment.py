"""
Batch experiment runner for Ghera dataset.
Runs the full pipeline on each APK and collects results.

Usage:
    conda run -n graph-vuls python run_ghera_experiment.py
    conda run -n graph-vuls python run_ghera_experiment.py --type ICC
    conda run -n graph-vuls python run_ghera_experiment.py --resume
"""
import os
import sys
import json
import time
import argparse
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

GHERA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "Ghera")
RESULTS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output", "ghera_experiment_results.json")


def find_all_apks(ghera_dir: str, filter_type: str = None) -> list[dict]:
    """Discover all Ghera APK directories."""
    apks = []
    for vtype in sorted(os.listdir(ghera_dir)):
        type_dir = os.path.join(ghera_dir, vtype)
        if not os.path.isdir(type_dir):
            continue
        if filter_type and vtype != filter_type:
            continue
        for apk_name in sorted(os.listdir(type_dir)):
            apk_dir = os.path.join(type_dir, apk_name)
            analysis_dir = os.path.join(apk_dir, "analysis")
            reports_dir = os.path.join(apk_dir, "reports")
            if os.path.isdir(analysis_dir) and os.path.isdir(reports_dir):
                apks.append({
                    "type": vtype,
                    "name": apk_name,
                    "analysis_dir": analysis_dir,
                    "reports_dir": reports_dir,
                    "readme": os.path.join(apk_dir, "README.md"),
                })
    return apks


def run_single(apk_info: dict, output_base: str) -> dict:
    """Run the full pipeline on a single APK. Returns result dict."""
    from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD
    from utils.file_loader import load_apk_artifacts
    from utils.debug_logger import (
        init_trace_for_run,
        log_file_output,
        summarize_state,
        trace_event,
    )
    from hpg.builder import build_hpg
    from graph import build_graph

    output_dir = os.path.join(output_base, apk_info["type"], apk_info["name"])
    os.makedirs(output_dir, exist_ok=True)
    trace_path = init_trace_for_run(output_dir=output_dir, apk_name=apk_info["name"])
    print(f"[trace] Writing detailed trace to: {trace_path}")

    t0 = time.time()
    result = {
        "type": apk_info["type"],
        "name": apk_info["name"],
        "exploitable": None,
        "verdict": "",
        "status": "error",
        "error": "",
        "duration_s": 0,
        "node_stats": {},
    }
    trace_event(
        "run_single_start",
        {
            "apk_info": apk_info,
            "output_dir": output_dir,
            "trace_path": trace_path,
        },
    )

    try:
        # Load artifacts
        manifest_xml, app_smali, app_java = load_apk_artifacts(apk_info["analysis_dir"])
        result["node_stats"]["smali_files"] = len(app_smali)
        result["node_stats"]["java_files"] = len(app_java)
        trace_event(
            "artifacts_loaded",
            {
                "manifest_chars": len(manifest_xml),
                "smali_files": len(app_smali),
                "java_files": len(app_java),
            },
        )

        # Build HPG (clears Neo4j first)
        build_hpg(analysis_dir=apk_info["analysis_dir"], smali_map=app_smali)
        trace_event("hpg_built", {"analysis_dir": apk_info["analysis_dir"]})

        # Build fresh graph (avoid stale compiled graph)
        app = build_graph()
        trace_event("graph_built", {"graph": "langgraph_compiled"})

        # Run pipeline
        initial_state = {
            "apk_name": apk_info["name"],
            "analysis_dir": apk_info["analysis_dir"],
            "sast_reports_dir": apk_info["reports_dir"],
            "manifest_xml": manifest_xml,
            "app_smali": app_smali,
            "app_java": app_java,
            "manifest_result": None,
            "ui_semantic_result": None,
            "taint_result": None,
            "semantic_result": None,
            "flowdroid_result": None,
            "icc_bridge_result": None,
            "validation_result": None,
            "sast_prior_result": None,
            "final_report": None,
        }
        trace_event("initial_state", summarize_state(initial_state))

        # Temporarily override OUTPUT_DIR for this run
        import config
        orig_output = config.OUTPUT_DIR
        config.OUTPUT_DIR = output_dir
        # Also need to re-import flowdroid_node to pick up new OUTPUT_DIR
        import agents.flowdroid_node as fd_mod
        fd_mod.os.makedirs(output_dir, exist_ok=True)

        try:
            final_state = app.invoke(initial_state)
        finally:
            config.OUTPUT_DIR = orig_output
        trace_event("final_state", summarize_state(dict(final_state)))

        # Extract results
        val = final_state.get("validation_result") or {}
        taint = final_state.get("taint_result") or {}
        sast = final_state.get("sast_prior_result") or {}
        fd = final_state.get("flowdroid_result") or {}
        icc = final_state.get("icc_bridge_result") or {}

        result["exploitable"] = val.get("exploitable", None)
        result["verdict"] = val.get("final_verdict", "")
        result["status"] = "success"
        result["node_stats"].update({
            "sources": len(taint.get("sources", [])),
            "sinks": len(taint.get("sinks", [])),
            "sast_findings": sast.get("stats", {}).get("total_ingested", 0),
            "sast_aligned": sast.get("stats", {}).get("aligned", 0),
            "flowdroid_status": fd.get("status", ""),
            "intra_paths": len(fd.get("intra_paths", [])),
            "cross_paths": len(icc.get("cross_paths", [])),
        })

        # Save state dump
        try:
            from utils.report_generator import generate_report
            generate_report(dict(final_state), output_dir)
            log_file_output(os.path.join(output_dir, "report.md"), label="report_markdown")
            log_file_output(os.path.join(output_dir, "state_dump.json"), label="state_dump")
            log_file_output(os.path.join(output_dir, "flowdroid_results.xml"), label="flowdroid_xml")
            log_file_output(os.path.join(output_dir, "SourcesAndSinks.txt"), label="susi_sources_sinks")
        except Exception:
            pass

    except Exception as e:
        result["error"] = f"{type(e).__name__}: {str(e)[:500]}"
        result["status"] = "error"
        trace_event(
            "run_single_error",
            {"error": result["error"], "traceback": traceback.format_exc()},
        )
        traceback.print_exc()

    result["duration_s"] = round(time.time() - t0, 1)
    trace_event("run_single_end", result)
    return result


def load_existing_results(path: str) -> dict:
    """Load previously saved results for resume support."""
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return {r["name"]: r for r in data.get("results", [])}
    return {}


def print_summary(results: list[dict]):
    """Print a summary table grouped by vulnerability type."""
    from collections import defaultdict
    by_type = defaultdict(list)
    for r in results:
        by_type[r["type"]].append(r)

    print("\n" + "=" * 80)
    print(f"  GHERA EXPERIMENT RESULTS — {len(results)} APKs")
    print("=" * 80)

    total_tp, total_fn, total_err = 0, 0, 0
    for vtype in sorted(by_type):
        items = by_type[vtype]
        tp = sum(1 for r in items if r["exploitable"] is True)
        fn = sum(1 for r in items if r["exploitable"] is False)
        err = sum(1 for r in items if r["status"] == "error")
        total_tp += tp
        total_fn += fn
        total_err += err

        print(f"\n  [{vtype}] — {tp}/{len(items)} detected (TP={tp}, FN={fn}, ERR={err})")
        for r in items:
            icon = "✅" if r["exploitable"] is True else ("❌" if r["exploitable"] is False else "💥")
            short_name = r["name"][:55]
            dur = f"{r['duration_s']:.0f}s"
            extra = ""
            if r["status"] == "error":
                extra = f" [{r['error'][:60]}]"
            else:
                stats = r.get("node_stats", {})
                extra = f" src={stats.get('sources',0)} snk={stats.get('sinks',0)} fd={stats.get('flowdroid_status','?')}"
            print(f"    {icon} {short_name:<55} {dur:>5}{extra}")

    print(f"\n  TOTAL: {total_tp}/{len(results)} detected "
          f"(TP={total_tp}, FN={total_fn}, ERR={total_err}, "
          f"Recall={total_tp/max(total_tp+total_fn,1)*100:.0f}%)")
    print("=" * 80)


def main():
    parser = argparse.ArgumentParser(description="Ghera batch experiment")
    parser.add_argument("--type", default=None, help="Filter by vulnerability type (e.g. ICC)")
    parser.add_argument("--resume", action="store_true", help="Skip already-completed APKs")
    args = parser.parse_args()

    # Discover APKs
    apks = find_all_apks(GHERA_DIR, filter_type=args.type)
    print(f"Found {len(apks)} APKs" + (f" (type={args.type})" if args.type else ""))

    # Resume support
    existing = load_existing_results(RESULTS_FILE) if args.resume else {}
    if existing:
        print(f"Resuming: {len(existing)} already completed")

    output_base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output", "ghera")
    results = []

    for i, apk in enumerate(apks):
        # Skip if already done
        if apk["name"] in existing:
            results.append(existing[apk["name"]])
            continue

        print(f"\n{'='*60}")
        print(f"  [{i+1}/{len(apks)}] {apk['type']}/{apk['name']}")
        print(f"{'='*60}")

        result = run_single(apk, output_base)
        results.append(result)

        icon = "✅" if result["exploitable"] is True else ("❌" if result["exploitable"] is False else "💥")
        print(f"\n  → {icon} exploitable={result['exploitable']} ({result['duration_s']:.0f}s)")

        # Save incrementally
        os.makedirs(os.path.dirname(RESULTS_FILE), exist_ok=True)
        with open(RESULTS_FILE, "w", encoding="utf-8") as f:
            json.dump({"results": results, "total": len(apks)}, f, indent=2, ensure_ascii=False)

    print_summary(results)


if __name__ == "__main__":
    main()
