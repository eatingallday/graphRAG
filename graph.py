"""
LangGraph StateGraph definition.

Full pipeline:
  manifest_agent → taint_agent → [semantic_agent?] → flowdroid_node
  → icc_bridge_node → validation_agent → report_generator → END
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from langgraph.graph import StateGraph, END
from state import AnalysisState
from agents.manifest_agent     import run_manifest_agent
from agents.ui_semantic_agent  import run_ui_semantic_agent
from agents.taint_agent        import run_taint_agent
from agents.semantic_agent     import run_semantic_agent
from agents.flowdroid_node     import run_flowdroid
from agents.icc_bridge         import run_icc_bridge
from agents.validation_agent   import run_validation_agent
from config import OUTPUT_DIR
from utils.report_generator  import generate_report


def run_report_generator(state: AnalysisState) -> dict:
    """LangGraph wrapper for the report generator."""
    report = generate_report(dict(state), OUTPUT_DIR)
    return {"final_report": report}


def _should_run_semantic(state: AnalysisState) -> str:
    """
    Conditional edge: if susi_confidence < 0.7 or needs_semantic_analysis=True
    → run semantic agent before FlowDroid.
    """
    taint = state.get("taint_result") or {}
    if taint.get("susi_confidence", 1.0) < 0.7 or taint.get("needs_semantic_analysis", False):
        print("[graph] Routing to semantic_agent (low confidence or complex logic)")
        return "semantic_agent"
    print("[graph] Routing directly to flowdroid_node")
    return "flowdroid_node"


def build_graph() -> StateGraph:
    workflow = StateGraph(AnalysisState)

    workflow.add_node("manifest_agent",    run_manifest_agent)
    workflow.add_node("ui_semantic_agent", run_ui_semantic_agent)
    workflow.add_node("taint_agent",       run_taint_agent)
    workflow.add_node("semantic_agent",    run_semantic_agent)
    workflow.add_node("flowdroid_node",    run_flowdroid)
    workflow.add_node("icc_bridge_node",   run_icc_bridge)
    workflow.add_node("validation_agent",  run_validation_agent)
    workflow.add_node("report_generator",  run_report_generator)

    workflow.set_entry_point("manifest_agent")
    workflow.add_edge("manifest_agent",    "ui_semantic_agent")
    workflow.add_edge("ui_semantic_agent", "taint_agent")

    workflow.add_conditional_edges(
        "taint_agent",
        _should_run_semantic,
        {
            "semantic_agent": "semantic_agent",
            "flowdroid_node": "flowdroid_node",
        }
    )

    workflow.add_edge("semantic_agent",   "flowdroid_node")
    workflow.add_edge("flowdroid_node",   "icc_bridge_node")
    workflow.add_edge("icc_bridge_node",  "validation_agent")
    workflow.add_edge("validation_agent", "report_generator")
    workflow.add_edge("report_generator", END)

    return workflow.compile()


app = build_graph()
