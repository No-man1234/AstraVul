import pytest
from src.parser.slicer import CodeSlice
from src.rag.store import RAGKnowledgeStore


@pytest.fixture
def rag_store():
    return RAGKnowledgeStore()


def test_rag_cwe_retrieval(rag_store):
    dummy_slice = CodeSlice(
        slice_id="s1",
        source_file="main.c",
        sink_function="strcpy",
        sink_line=15,
        taint_variable="buffer",
        slice_code="strcpy(buffer, input);",
        slice_tokens=10,
        line_numbers=[15],
        cwe_candidate="CWE-120"
    )
    context = rag_store.retrieve(dummy_slice)
    assert context.cwe_id == "CWE-120"
    assert "Buffer Copy" in context.cwe_name
    assert len(context.preconditions) > 0
    assert len(context.historical_patches) > 0


def test_rag_uaf_retrieval(rag_store):
    dummy_slice = CodeSlice(
        slice_id="s2",
        source_file="cleanup.c",
        sink_function="free",
        sink_line=20,
        taint_variable="ptr",
        slice_code="free(ptr);",
        slice_tokens=8,
        line_numbers=[20],
        cwe_candidate="CWE-416"
    )
    context = rag_store.retrieve(dummy_slice)
    assert context.cwe_id == "CWE-416"
    assert "Use After Free" in context.cwe_name
