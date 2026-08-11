"""Tests for stage 2's deterministic rendering and repair.

The subagent writes Mermaid as prose, and stage 3 reads element types out of node
shape — so a diagram that came out wrong costs findings with no error anywhere. These
cover the safety net: render the graph JSON ourselves when the diagram is unusable.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from main.mermaid import parse_mermaid
from main.stage2_dfds import add_file_hints, render_mermaid, verify_and_repair

GRAPH = {
    "use_case_id": "UC-LOGIN",
    "name": "Login",
    "nodes": [
        {"id": "CUST", "type": "external_entity", "name": "Customer"},
        {"id": "LOGIN", "type": "process", "name": "Login Handler", "file": "routes/login.ts"},
        {"id": "USERS", "type": "data_store", "name": "User Table", "file": "models/user.ts"},
    ],
    "edges": [
        {"from": "CUST", "to": "LOGIN", "description": "Submits email and password"},
        {"from": "LOGIN", "to": "USERS", "description": "Queries user by email"},
    ],
}


@pytest.fixture
def tree(tmp_path: pathlib.Path) -> pathlib.Path:
    (tmp_path / "graphs").mkdir()
    (tmp_path / "dfds").mkdir()
    (tmp_path / "graphs" / "UC-LOGIN.json").write_text(json.dumps(GRAPH))
    return tmp_path


# --- rendering --------------------------------------------------------------


def test_render_produces_the_shapes_stage_three_reads():
    parsed = parse_mermaid(render_mermaid(GRAPH))
    assert [e["name"] for e in parsed["external_entities"]] == ["Customer"]
    assert [e["name"] for e in parsed["processes"]] == ["Login Handler"]
    assert [e["name"] for e in parsed["data_stores"]] == ["User Table"]
    assert parsed["warnings"] == []


def test_render_emits_file_hints_from_the_graph():
    parsed = parse_mermaid(render_mermaid(GRAPH))
    assert parsed["file_hints"] == {"LOGIN": ["routes/login.ts"], "USERS": ["models/user.ts"]}


def test_render_drops_an_edge_to_an_undeclared_node():
    """A dangling edge would otherwise make the whole diagram unparseable."""
    graph = {**GRAPH, "edges": [*GRAPH["edges"], {"from": "LOGIN", "to": "GHOST", "description": "x"}]}
    assert len(parse_mermaid(render_mermaid(graph))["data_flows"]) == 2


def test_render_survives_hostile_ids_and_labels():
    graph = {
        "nodes": [
            {"id": "A B!", "type": "process", "name": "Weird [Name] | here"},
            {"id": "9start", "type": "external_entity", "name": "Client"},
            {"id": "", "type": "data_store", "name": ""},
        ],
        "edges": [{"from": "A B!", "to": "9start", "description": "a|b [c]"}],
    }
    parsed = parse_mermaid(render_mermaid(graph))
    assert len(parsed["processes"]) == 1
    assert len(parsed["external_entities"]) == 1
    assert len(parsed["data_stores"]) == 1
    assert not any("no nodes recognized" in w for w in parsed["warnings"])


def test_render_skips_an_unknown_node_type():
    graph = {"nodes": [*GRAPH["nodes"], {"id": "X", "type": "trust_boundary", "name": "DMZ"}], "edges": []}
    names = [e["name"] for g in ("external_entities", "processes", "data_stores")
             for e in parse_mermaid(render_mermaid(graph))[g]]
    assert "DMZ" not in names


# --- hint injection ---------------------------------------------------------


def test_hints_are_appended_to_a_subagent_diagram():
    diagram = "flowchart LR\n  CUST[Customer]\n  LOGIN(Login Handler)\n  CUST -->|creds| LOGIN\n"
    assert "%% file: LOGIN routes/login.ts" in add_file_hints(diagram, GRAPH)


def test_hints_are_not_duplicated():
    diagram = "flowchart LR\n  LOGIN(Login Handler)\n  %% file: LOGIN routes/login.ts\n"
    assert add_file_hints(diagram, GRAPH).count("%% file: LOGIN") == 1


def test_hints_skip_nodes_the_diagram_never_declared():
    diagram = "flowchart LR\n  CUST[Customer]\n"
    assert "USERS" not in add_file_hints(diagram, GRAPH)


# --- repair -----------------------------------------------------------------


def test_a_missing_diagram_is_rendered(tree):
    notes = verify_and_repair(tree)
    assert (tree / "dfds" / "UC-LOGIN.mmd").exists()
    assert any("was not produced" in n for n in notes)


def test_an_all_rectangles_diagram_is_re_rendered(tree):
    """Mermaid's default shape reads as external entity, so five letters would go quiet."""
    (tree / "dfds" / "UC-LOGIN.mmd").write_text(
        "flowchart LR\n  A[One]-->B[Two]\n  B-->C[Three]\n  C-->D[Four]\n"
    )
    notes = verify_and_repair(tree)
    assert any("re-rendered" in n for n in notes)
    assert len(parse_mermaid((tree / "dfds" / "UC-LOGIN.mmd").read_text())["processes"]) == 1


def test_an_unparseable_diagram_is_re_rendered(tree):
    (tree / "dfds" / "UC-LOGIN.mmd").write_text("Here is your diagram!\n")
    verify_and_repair(tree)
    assert "flowchart" in (tree / "dfds" / "UC-LOGIN.mmd").read_text()


def test_a_good_diagram_is_kept_and_only_gains_hints(tree):
    good = "flowchart LR\n  CUST[Customer]\n  LOGIN(Login Handler)\n  CUST -->|creds| LOGIN\n"
    (tree / "dfds" / "UC-LOGIN.mmd").write_text(good)
    verify_and_repair(tree)
    result = (tree / "dfds" / "UC-LOGIN.mmd").read_text()
    assert "CUST -->|creds| LOGIN" in result, "the subagent's own diagram must survive"
    assert "%% file: LOGIN routes/login.ts" in result


def test_unreadable_graph_json_is_reported_not_raised(tree):
    (tree / "graphs" / "broken.json").write_text("{not json")
    assert any("unreadable graph JSON" in n for n in verify_and_repair(tree))
