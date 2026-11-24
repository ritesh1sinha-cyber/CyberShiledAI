"""The benchmark generators may only write what they measured.

Both scripts once wrote constant scores into the artifact for rows no metric produced:
judge blocks the model never judged, and on a failed single-agent run an invented
ROUGE 0.05/0.01/0.03 and cosine 0.55. Those numbers reached row 4 of the published
scorecard, so the scripts are checked here at source level rather than by trusting a
docstring.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = (
    ROOT / "scripts" / "benchmark_all_5_iterations_live.py",
    ROOT / "scripts" / "benchmark_single_agent_live.py",
)


def judge_values(path: Path) -> list[ast.expr]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return [
        value
        for node in ast.walk(tree)
        if isinstance(node, ast.Dict)
        for key, value in zip(node.keys, node.values)
        if isinstance(key, ast.Constant) and key.value == "judge"
    ]


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_no_judge_field_is_written_with_a_number(script):
    values = judge_values(script)
    assert values, f"{script.name} no longer writes a judge field; update this test"
    for value in values:
        assert isinstance(value, ast.Constant) and value.value is None, (
            f"{script.name}:{value.lineno} puts a score in `judge` that no judge produced"
        )


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_the_placeholder_metric_constants_are_gone(script):
    """The numbers the failed-run branch used to write are not in the source at all.

    Read from the syntax tree, not the text: the scripts explain those constants in
    comments, and a comment is not a value being written.
    """
    tree = ast.parse(script.read_text(encoding="utf-8"))
    floats = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, float)
    }
    assert not floats & {0.05, 0.01, 0.03, 0.55}, f"{script.name} still writes a placeholder metric"
    keys = {
        key.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Dict)
        for key in node.keys
        if isinstance(key, ast.Constant) and isinstance(key.value, str)
    }
    assert not keys & {"factual_correctness", "groundedness"}, f"{script.name} still writes a judge score"


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_a_failed_run_is_recorded_as_an_error(script):
    source = script.read_text(encoding="utf-8")
    assert '"error"' in source, f"{script.name} must store an error, not a score"


def test_the_prompting_rows_store_the_text_they_were_scored_on():
    """ROUGE and cosine are taken on a flattened rendering, not the raw model string.

    With only the raw answer in the artifact those columns could not be recomputed
    from it, which is how an invented value sat unnoticed in row 4 for a run.
    """
    script = SCRIPTS[0]
    tree = ast.parse(script.read_text(encoding="utf-8"))
    written = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Dict)
        and any(isinstance(k, ast.Constant) and k.value == "scored_text" for k in node.keys)
    ]
    assert written, f"{script.name} no longer records the text it scored"
    for node in written:
        keys = {k.value for k in node.keys if isinstance(k, ast.Constant)}
        assert {"actual_response", "rouge", "semantic_cosine"} <= keys
        scored = next(
            value
            for key, value in zip(node.keys, node.values)
            if isinstance(key, ast.Constant) and key.value == "scored_text"
        )
        assert isinstance(scored, ast.Name) and scored.id == "flat_text"
