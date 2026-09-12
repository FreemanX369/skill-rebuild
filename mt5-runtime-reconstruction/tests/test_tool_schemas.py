from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def collect_property_names(node):
    found = set()
    if isinstance(node, dict):
        props = node.get("properties")
        if isinstance(props, dict):
            found.update(props)
        for value in node.values():
            found.update(collect_property_names(value))
    elif isinstance(node, list):
        for value in node:
            found.update(collect_property_names(value))
    return found


def test_tip026r3_public_tool_schemas_do_not_expose_process_primitives():
    spec = json.loads((ROOT / "references" / "tip026r3-tool-schemas.json").read_text(encoding="utf-8"))
    tools = {tool["name"]: tool for tool in spec["tools"]}
    assert set(tools) == {"capture_runtime_snapshot", "compare_runtime_snapshots"}

    forbidden = {"pid", "process_name", "address", "command", "shell", "executable"}
    for tool in tools.values():
        names = collect_property_names(tool["inputSchema"])
        assert not (names & forbidden)
        assert tool["inputSchema"]["additionalProperties"] is False


def test_proposed_tool_counts_match_two_new_model_visible_tools():
    runtime = json.loads((ROOT / "references" / "tip026r3-tool-schemas.json").read_text(encoding="utf-8"))[
        "proposed_runtime"
    ]
    assert runtime["server_tool_count"] == 48
    assert runtime["model_visible_tool_count"] == 47
    assert runtime["server_tool_count"] - runtime["model_visible_tool_count"] == len(runtime["app_only_tools"])
