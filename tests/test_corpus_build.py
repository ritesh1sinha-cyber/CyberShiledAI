from scripts.build_corpus import (
    MAX_CHARS,
    OVERLAP_CHARS,
    attack_document,
    chunk_nist,
    clean_attack,
    is_table,
    pack,
    parse_mitigations,
    split_paragraphs,
)

CWE_RAW = (
    "::PHASE:Implementation:DESCRIPTION:Validate all input.::"
    "::PHASE:Implementation System Configuration:DESCRIPTION:Use a default deny policy.::"
)

TABLE = """| CONTROL NUMBER | CONTROL NAME | LOW | MOD | HIGH |
| --- | --- | --- | --- | --- |
| AC-1 | Policy and Procedures | x | x | x |
| AC-2 | Account Management | x | x | x |"""


def test_parse_mitigations_splits_phases_and_strips_markup():
    pairs = parse_mitigations(CWE_RAW)
    assert pairs == [
        ("Implementation", "Validate all input."),
        ("Implementation System Configuration", "Use a default deny policy."),
    ]


def test_clean_attack_drops_citation_tags_and_markdown_links():
    text = "Obfuscate traffic.(Citation: Vendor 2020) See [the docs](https://example.com)."
    cleaned = clean_attack(text)
    assert "Citation" not in cleaned
    assert "https://" not in cleaned
    assert "See the docs." in cleaned


def test_attack_document_keeps_technique_identity():
    row = {
        "technique_id": "T1001",
        "name": "Data Obfuscation",
        "description": "Hide traffic.",
        "tactics": ["command-and-control"],
        "platforms": ["Linux", "Windows"],
        "is_subtechnique": False,
    }
    doc = attack_document(row)
    assert doc.startswith("T1001 Data Obfuscation")
    assert "Tactics: command-and-control" in doc


def test_is_table_requires_pipe_grid():
    assert is_table(TABLE)
    assert not is_table("A normal paragraph with | a pipe inside.")


def test_pack_keeps_table_whole_even_when_larger_than_overlap():
    text = f"{'Heading'}\n\n" + TABLE + "\n\n" + " ".join(["filler"] * 900)
    chunks = pack(split_paragraphs(text))
    table_chunks = [c for c in chunks if TABLE.splitlines()[0] in c["text"]]
    assert table_chunks, "table missing from output"
    assert any(c["has_table"] for c in chunks)
    for chunk in table_chunks:
        assert TABLE in chunk["text"], "table was split across chunks"


def test_pack_never_duplicates_an_atomic_table_as_overlap():
    text = ("word " * 300).strip() + "\n\n" + TABLE + "\n\n" + ("word " * 300).strip()
    chunks = pack(split_paragraphs(text))
    occurrences = sum(chunk["text"].count(TABLE.splitlines()[0]) for chunk in chunks)
    assert occurrences == 1


def test_pack_respects_target_size_for_prose():
    text = "\n\n".join(" ".join(["token"] * 120) for _ in range(10))
    chunks = pack(split_paragraphs(text))
    assert len(chunks) > 1
    assert all(len(chunk["text"]) <= MAX_CHARS + OVERLAP_CHARS + 200 for chunk in chunks)


def test_chunk_nist_keeps_table_rows_together():
    table = TABLE
    text = (
        "3.1 ACCESS CONTROL FAMILY\n\n"
        + ("Intro sentence about baselines. " * 40).strip()
        + "\n\n"
        + table
        + "\n\n"
        + ("Closing prose about tailoring. " * 40).strip()
    )
    start = text.index(table)
    row = {"doc_id": "TEST", "title": "Test Pub", "text": text}
    chunks = chunk_nist(row, [(start, start + len(table))])
    assert any(chunk["has_table"] for chunk in chunks)
    combined = "\n".join(chunk["text"] for chunk in chunks)
    assert "| AC-1 | Policy and Procedures | x | x | x |" in combined