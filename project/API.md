# Interface & API Specifications

## Project: AST-Guided RAG Software Vulnerability Detection and Triage
**Document Version:** 1.0.0  
**Supported Interfaces:** Command Line Interface (CLI), Python Core API, and RESTful Microservice  

---

## 1. Command Line Interface (CLI)

The CLI acts as the primary developer interface and integrates directly into CI/CD build scripts (GitHub Actions, GitLab CI).

### Command: `ast-rag scan`
Scans a C/C++ source file or directory, performs AST slicing, executes RAG retrieval, and generates a triage report.

```bash
ast-rag scan [OPTIONS] TARGET_PATH
```

#### Options:
* `--model TEXT`: Model name or path to GGUF weights. Default: `models/qwen2.5-coder-7b-instruct-q4_k_m.gguf`.
* `--db-path PATH`: Path to local vector store directory. Default: `data/vector_store/`.
* `--output PATH` / `-o PATH`: Destination for the structured JSON report. Default: `stdout`.
* `--format [json|sarif|text]`: Output serialization format. Default: `json`.
* `--threshold FLOAT`: Minimum exploitability confidence threshold ($0.0 - 1.0$). Default: `0.70`.
* `--gpu-layers INT`: Number of layers to offload to GPU via `llama.cpp`. Default: `-1` (all layers if GPU available).
* `--verbose` / `-v`: Enable debug logging and AST traversal trace output.

#### Example Usage:
```bash
ast-rag scan ./src/network_parser.c --output ./reports/audit.json --format json
```

---

### Command: `ast-rag index`
Ingests CWE descriptions, DiverseVul commits, and CVEfixes patches to construct or update local vector stores.

```bash
ast-rag index [OPTIONS]
```

#### Options:
* `--cwe-xml PATH`: Path to official NIST CWE XML/JSON catalog file.
* `--cve-dir PATH`: Directory containing DiverseVul / CVEfixes JSONL datasets.
* `--out-dir PATH`: Output directory for the persistent vector database.
* `--rebuild`: Force a complete rebuild of the vector index.

---

### Command: `ast-rag evaluate`
Runs an automated benchmark comparing AST-Guided RAG against SAST tools (Cppcheck, Flawfinder) and raw LLMs.

```bash
ast-rag evaluate --dataset [juliet|diversevul] --benchmark-dir ./data/benchmarks/
```

---

## 2. Python Internal API Contracts

Developers extending the platform or embedding it into custom Python security frameworks can interact with the core classes directly:

```python
from typing import List, Optional
from pydantic import BaseModel, Field
from enum import Enum

# --- Data Models ---

class ExploitabilityVerdict(str, Enum):
    CONFIRMED_EXPLOITABLE = "CONFIRMED_EXPLOITABLE"
    SUSPICIOUS_UNVERIFIED = "SUSPICIOUS_UNVERIFIED"
    BENIGN_FALSE_POSITIVE = "BENIGN_FALSE_POSITIVE"

class CodeSlice(BaseModel):
    slice_id: str
    source_file: str
    sink_function: str
    sink_line: int
    source_function: Optional[str] = None
    slice_tokens: int
    slice_code: str
    taint_variable: str

class RAGContext(BaseModel):
    cwe_id: str
    cwe_name: str
    cwe_rule_summary: str
    preconditions: List[str]
    analogous_cve_diffs: List[str]

class VulnerabilityTriageReport(BaseModel):
    file_path: str
    is_vulnerable: bool
    confidence: float = Field(ge=0.0, le=1.0)
    cwe_id: Optional[str] = None
    cwe_name: Optional[str] = None
    vulnerable_lines: List[int]
    exploitability_verdict: ExploitabilityVerdict
    root_cause_analysis: str
    remediation_patch: Optional[str] = None
    token_usage: dict

# --- Service Interfaces ---

class ASTSlicer:
    def __init__(self, language: str = "c"): ...
    def extract_slices(self, file_path: str) -> List[CodeSlice]: ...

class KnowledgeRetriever:
    def __init__(self, db_path: str, embedding_model: str = "microsoft/unixcoder-base"): ...
    def retrieve(self, slice_obj: CodeSlice, top_k: int = 3) -> RAGContext: ...

class LocalTriageEngine:
    def __init__(self, model_path: str, temperature: float = 0.0): ...
    def triage(self, slice_obj: CodeSlice, context: RAGContext) -> VulnerabilityTriageReport: ...
```

---

## 3. RESTful Microservice API (FastAPI)

For enterprise microservice deployment, an optional FastAPI daemon is provided.

### `POST /api/v1/scan/file`
Uploads a C/C++ source file for asynchronous or synchronous security triage.

#### Request:
* `Content-Type: multipart/form-data`
* Body parameter `file`: The `.c` or `.cpp` source file.
* Form parameter `confidence_threshold` (optional, float): Default `0.7`.

#### Response (200 OK):
```json
{
  "scan_id": "scan_9f83a21b",
  "status": "COMPLETED",
  "file_analyzed": "network_parser.c",
  "total_slices_extracted": 3,
  "vulnerabilities_detected": 1,
  "results": [
    {
      "is_vulnerable": true,
      "confidence": 0.94,
      "cwe_id": "CWE-120",
      "cwe_name": "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')",
      "vulnerable_lines": [42, 43, 47],
      "exploitability_verdict": "CONFIRMED_EXPLOITABLE",
      "root_cause_analysis": "Untrusted input received from recv() at line 42 is copied into fixed-size buffer 'dest' via strcpy() at line 47 without validating that input length is strictly bounded by sizeof(dest).",
      "remediation_patch": "--- network_parser.c\n+++ network_parser.c\n@@ -47,1 +47,2 @@\n-    strcpy(dest, packet_payload);\n+    strncpy(dest, packet_payload, sizeof(dest) - 1);\n+    dest[sizeof(dest) - 1] = '\\0';",
      "token_usage": {
        "slice_tokens": 84,
        "rag_context_tokens": 142,
        "output_tokens": 128
      }
    }
  ]
}
```

### `GET /api/v1/health`
Health check endpoint returning hardware accelerator status.

```json
{
  "status": "HEALTHY",
  "engine": "llama.cpp",
  "model_loaded": "Qwen2.5-Coder-7B-Instruct-Q4_K_M.gguf",
  "gpu_acceleration": true,
  "vram_allocated_mb": 4780,
  "vector_db_records": 18970
}
```
