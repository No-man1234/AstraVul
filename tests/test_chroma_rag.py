"""
Tests for ChromaDB Vector Knowledge Store and Expanded AST Slicing.
"""

import pytest
from src.parser.slicer import ASTSlicer, CodeSlice
from src.rag.store import RAGKnowledgeStore
from src.triage.engine import LocalTriageEngine
from src.triage.schemas import ExploitabilityVerdict


@pytest.fixture
def rag_store():
    return RAGKnowledgeStore()


@pytest.fixture
def triage_engine():
    return LocalTriageEngine()


def test_chroma_cwe_query(rag_store):
    """Verifies that ChromaDB can retrieve relevant CWEs using vector similarity."""
    assert rag_store.cwe_collection is not None
    assert rag_store.cwe_collection.count() >= 900

    results = rag_store.cwe_collection.query(
        query_texts=["format string vulnerability in printf"],
        n_results=1
    )
    assert len(results["ids"][0]) > 0
    assert "CWE-134" in results["ids"][0]


def test_chroma_retrieve_format_string(rag_store):
    """Verifies retrieval for format string slice."""
    slice_obj = CodeSlice(
        slice_id="s_fmt_1",
        source_file="fmt.c",
        sink_function="printf",
        sink_line=12,
        taint_variable="user_buf",
        slice_code="12: printf(user_buf);",
        slice_tokens=8,
        line_numbers=[12],
        cwe_candidate="CWE-134"
    )
    context = rag_store.retrieve(slice_obj)
    assert context.cwe_id == "CWE-134"
    assert "Format String" in context.cwe_name


def test_slicer_and_triage_format_string(triage_engine, rag_store):
    """Verifies end-to-end detection of format string vulnerability."""
    slicer = ASTSlicer()
    vulnerable_code = """
    #include <stdio.h>
    void test_func(char *user_input) {
        printf(user_input);
    }
    """
    slices = slicer.slice_code(vulnerable_code, source_file="vuln_fmt.c")
    assert len(slices) >= 1
    fmt_slice = [s for s in slices if s.sink_function == "printf"][0]
    assert fmt_slice.cwe_candidate == "CWE-134"

    context = rag_store.retrieve(fmt_slice)
    report = triage_engine.triage(fmt_slice, context)
    assert report.is_vulnerable is True
    assert report.exploitability_verdict == ExploitabilityVerdict.CONFIRMED_EXPLOITABLE
    assert report.remediation_patch is not None


def test_slicer_and_triage_safe_format_string(triage_engine, rag_store):
    """Verifies benign suppression for safe literal format string."""
    slicer = ASTSlicer()
    safe_code = """
    #include <stdio.h>
    void test_func(char *user_input) {
        printf("%s\\n", user_input);
    }
    """
    slices = slicer.slice_code(safe_code, source_file="safe_fmt.c")
    assert len(slices) >= 1
    fmt_slice = [s for s in slices if s.sink_function == "printf"][0]

    context = rag_store.retrieve(fmt_slice)
    report = triage_engine.triage(fmt_slice, context)
    assert report.is_vulnerable is False
    assert report.exploitability_verdict == ExploitabilityVerdict.BENIGN_FALSE_POSITIVE


def test_slicer_and_triage_path_traversal(triage_engine, rag_store):
    """Verifies detection of path traversal without bounds check."""
    slicer = ASTSlicer()
    vuln_path_code = """
    #include <stdio.h>
    void open_file(char *filename) {
        FILE *fp = fopen(filename, "r");
    }
    """
    slices = slicer.slice_code(vuln_path_code, source_file="traversal.c")
    assert len(slices) >= 1
    path_slice = [s for s in slices if s.sink_function == "fopen"][0]
    assert path_slice.cwe_candidate == "CWE-22"

    context = rag_store.retrieve(path_slice)
    report = triage_engine.triage(path_slice, context)
    assert report.is_vulnerable is True
    assert report.exploitability_verdict == ExploitabilityVerdict.CONFIRMED_EXPLOITABLE
