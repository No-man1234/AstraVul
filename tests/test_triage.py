import pytest
from src.parser.slicer import CodeSlice
from src.rag.store import RAGKnowledgeStore
from src.triage.engine import LocalTriageEngine
from src.triage.schemas import ExploitabilityVerdict, VulnerabilityTriageReport


@pytest.fixture
def triage_engine():
    return LocalTriageEngine()


@pytest.fixture
def rag_store():
    return RAGKnowledgeStore()


def test_triage_vulnerable_buffer(triage_engine, rag_store):
    code_slice = CodeSlice(
        slice_id="vuln_slice",
        source_file="test.c",
        sink_function="strcpy",
        sink_line=12,
        taint_variable="dest",
        slice_code="char dest[16];\nstrcpy(dest, src);",
        slice_tokens=14,
        line_numbers=[11, 12],
        cwe_candidate="CWE-120"
    )
    context = rag_store.retrieve(code_slice)
    report = triage_engine.triage(code_slice, context)

    assert isinstance(report, VulnerabilityTriageReport)
    assert report.is_vulnerable is True
    assert report.exploitability_verdict == ExploitabilityVerdict.CONFIRMED_EXPLOITABLE
    assert report.cwe_id == "CWE-120"
    assert report.remediation_patch is not None
    assert "strncpy" in report.remediation_patch


def test_triage_safe_buffer_suppression(triage_engine, rag_store):
    code_slice = CodeSlice(
        slice_id="safe_slice",
        source_file="test.c",
        sink_function="strcpy",
        sink_line=14,
        taint_variable="dest",
        slice_code="char dest[16];\nif (strlen(src) < sizeof(dest)) {\n    strcpy(dest, src);\n}",
        slice_tokens=25,
        line_numbers=[10, 12, 14],
        cwe_candidate="CWE-120"
    )
    context = rag_store.retrieve(code_slice)
    report = triage_engine.triage(code_slice, context)

    assert isinstance(report, VulnerabilityTriageReport)
    assert report.is_vulnerable is False
    assert report.exploitability_verdict == ExploitabilityVerdict.BENIGN_FALSE_POSITIVE
    assert report.remediation_patch is None
