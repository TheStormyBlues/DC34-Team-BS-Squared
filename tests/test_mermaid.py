"""Tests for the Mermaid DFD parser.

The parser recovers element types from node shape, because the STRIDE skills analyze
only certain element types and Mermaid carries no type information of its own. A
regression here is silent: threats stop being raised rather than an error appearing.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from main.mermaid import parse_mermaid, render_inventory

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = pathlib.Path(__file__).parent / "fixtures"

CANONICAL = """flowchart LR
  subgraph TB_NET[Internet -> Application Server]
    CUST[Customer]
  end
  subgraph TB_APP[Application Server]
    LOGIN(Login Handler)
    TOKEN(Token Issuer)
  end
  subgraph TB_DB[Application Server -> Database]
    USERS[(User Table)]
  end
  CUST -->|credentials| LOGIN
  LOGIN -->|lookup by email| USERS
  LOGIN -->|identity claims| TOKEN
  TOKEN -->|signed JWT| CUST
"""


@pytest.fixture
def canonical() -> dict:
    return parse_mermaid(CANONICAL)


# --- the convention ---------------------------------------------------------


def test_canonical_diagram_parses_without_warnings(canonical):
    assert canonical["warnings"] == []


def test_shapes_map_to_element_types(canonical):
    assert [e["name"] for e in canonical["external_entities"]] == ["Customer"]
    assert [e["name"] for e in canonical["processes"]] == ["Login Handler", "Token Issuer"]
    assert [e["name"] for e in canonical["data_stores"]] == ["User Table"]


def test_subgraphs_become_trust_boundaries(canonical):
    assert "Internet -> Application Server" in canonical["trust_boundaries"]
    assert canonical["external_entities"][0]["trust_boundary"] == "Internet -> Application Server"


def test_subgraph_title_is_not_mistaken_for_a_node(canonical):
    names = [e["name"] for group in ("external_entities", "processes", "data_stores") for e in canonical[group]]
    assert "Internet -> Application Server" not in names


def test_edges_become_data_flows_with_resolved_names(canonical):
    flows = {(f["from"], f["to"]): f["name"] for f in canonical["data_flows"]}
    assert flows[("Customer", "Login Handler")] == "credentials"
    assert flows[("Login Handler", "User Table")] == "lookup by email"


def test_unlabelled_edge_gets_a_generated_name():
    parsed = parse_mermaid("flowchart TD\n  A[Customer] --> B(Handler)\n")
    assert parsed["data_flows"][0]["name"] == "Customer to Handler"


def test_node_ids_are_preserved_for_file_hint_lookup(canonical):
    assert {e["id"] for e in canonical["processes"]} == {"LOGIN", "TOKEN"}


# --- tolerated variants -----------------------------------------------------


@pytest.mark.parametrize(
    "diagram,group,count",
    [
        ("flowchart TD\n  A{Store}\n", "data_stores", 1),
        ("flowchart TD\n  A{{Store}}\n", "data_stores", 1),
        ("flowchart TD\n  A([Proc])\n", "processes", 1),
        ("flowchart TD\n  A((Proc))\n", "processes", 1),
        ("flowchart TD\n  A[/Ext/]\n", "external_entities", 1),
        ("flowchart TD\n  A[\\Ext\\]\n", "external_entities", 1),
    ],
)
def test_shape_variants(diagram, group, count):
    assert len(parse_mermaid(diagram)[group]) == count


def test_arrows_without_surrounding_spaces_still_find_both_nodes():
    """`A-->B[X]` must not hide B behind the arrowhead."""
    parsed = parse_mermaid("flowchart TD\n  CUST[Customer]-->LOGIN(Handler)\n  LOGIN-->USERS[(Users)]\n")
    assert len(parsed["external_entities"]) == 1
    assert len(parsed["processes"]) == 1
    assert len(parsed["data_stores"]) == 1
    assert not any("never declared" in w for w in parsed["warnings"])


def test_class_tag_overrides_shape():
    parsed = parse_mermaid("flowchart TD\n  A[(Store)]:::process --> B(P)\n")
    assert len(parsed["processes"]) == 2
    assert any("trusting the tag" in w for w in parsed["warnings"])


def test_class_statement_form_is_honoured():
    parsed = parse_mermaid("flowchart TD\n  A[X]\n  B[Y]\n  A --> B\n  class B datastore\n")
    assert len(parsed["data_stores"]) == 1


# --- diagnostics ------------------------------------------------------------


def test_all_rectangles_is_flagged():
    """Mermaid's default shape is `[]`, so an unconventional diagram reads as all
    external entities and five letters silently return nothing."""
    parsed = parse_mermaid("flowchart TD\n  A[One]-->B[Two]\n  B-->C[Three]\n  C-->D[Four]\n")
    assert any("did not follow the shape convention" in w for w in parsed["warnings"])


def test_two_rectangles_does_not_false_alarm():
    parsed = parse_mermaid("flowchart TD\n  A[Customer]-->B[(Store)]\n")
    assert not any("did not follow" in w for w in parsed["warnings"])


def test_missing_processes_warns_about_elevation():
    parsed = parse_mermaid("flowchart TD\n  A[Customer]-->B[(Store)]\n")
    assert any("Elevation of Privilege" in w for w in parsed["warnings"])


def test_missing_external_entities_warns_about_spoofing():
    parsed = parse_mermaid("flowchart TD\n  A(Handler)-->B[(Store)]\n")
    assert any("Spoofing" in w for w in parsed["warnings"])


def test_unknown_class_tag_warns_and_falls_back():
    parsed = parse_mermaid("flowchart TD\n  A[X]:::widget --> B(Y)\n")
    assert any("unrecognized class tag" in w for w in parsed["warnings"])
    assert len(parsed["external_entities"]) == 1


@pytest.mark.parametrize("diagram", ["", "   ", "\n\n"])
def test_empty_diagram(diagram):
    assert parse_mermaid(diagram)["warnings"] == ["diagram is empty"]


def test_header_only_diagram_reports_no_nodes():
    assert any("no nodes recognized" in w for w in parse_mermaid("flowchart LR\n")["warnings"])


def test_parser_never_raises():
    """Mid-run, a bad diagram must degrade rather than end the run."""
    for junk in ["}{][", "flowchart\n  -->\n", "A" * 5000, "subgraph\nend\nend\n"]:
        assert isinstance(parse_mermaid(junk), dict)


# --- rendering --------------------------------------------------------------


def test_render_inventory_groups_by_type(canonical):
    rendered = render_inventory(canonical)
    assert "External entities:" in rendered
    assert "Processes:" in rendered
    assert "  - Login Handler" in rendered


def test_render_inventory_includes_file_hints():
    parsed = parse_mermaid("flowchart TD\n  A(Handler)\n")
    parsed["processes"][0]["file_hints"] = ["routes/login.ts"]
    assert "routes/login.ts" in render_inventory(parsed)


# --- file hints -------------------------------------------------------------


def test_file_hint_comments_are_parsed():
    parsed = parse_mermaid(
        "flowchart TD\n  LOGIN(Handler)\n  %% file: LOGIN routes/login.ts\n"
    )
    assert parsed["file_hints"] == {"LOGIN": ["routes/login.ts"]}


def test_file_hint_accepts_several_paths():
    parsed = parse_mermaid(
        "flowchart TD\n  U[(Users)]\n  %% file: U models/user.ts, models/session.ts\n"
    )
    assert parsed["file_hints"]["U"] == ["models/user.ts", "models/session.ts"]


def test_file_hint_for_an_undrawn_node_warns():
    parsed = parse_mermaid("flowchart TD\n  A(Handler)\n  %% file: GHOST routes/nope.ts\n")
    assert any("never drawn" in w for w in parsed["warnings"])


def test_ordinary_comments_are_ignored():
    parsed = parse_mermaid("flowchart TD\n  %% just a note\n  A(Handler)\n")
    assert parsed["file_hints"] == {}
    assert len(parsed["processes"]) == 1


# --- the shipped examples ---------------------------------------------------

EXAMPLE = ROOT / "output" / "_example"


def test_example_diagram_parses_cleanly():
    """The file teammates copy must itself be exemplary."""
    parsed = parse_mermaid((EXAMPLE / "dfds" / "UC-LOGIN.mmd").read_text())
    assert parsed["warnings"] == [], parsed["warnings"]
    assert parsed["processes"], "no processes — Elevation of Privilege would return nothing"
    assert parsed["external_entities"], "no external entities — Spoofing coverage would be thin"
    assert parsed["data_stores"]


def test_example_diagram_hints_resolve_to_real_node_ids():
    parsed = parse_mermaid((EXAMPLE / "dfds" / "UC-LOGIN.mmd").read_text())
    ids = {e["id"] for g in ("external_entities", "processes", "data_stores") for e in parsed[g]}
    for hinted in parsed["file_hints"]:
        assert hinted in ids, f"file hint {hinted!r} is not a node id ({sorted(ids)})"


def test_example_header_comments_are_not_parsed_as_elements():
    """The example carries a long `%%` preamble; none of it may become an element."""
    parsed = parse_mermaid((EXAMPLE / "dfds" / "UC-LOGIN.mmd").read_text())
    assert len(parsed["external_entities"]) == 1
    assert [e["name"] for e in parsed["processes"]] == ["Login Handler", "Token Issuer"]
