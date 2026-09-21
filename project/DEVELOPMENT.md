# Developer Setup & Contribution Guide

## Project: AST-Guided RAG Software Vulnerability Detection and Triage
**Document Version:** 1.0.0  

---

## 1. Local Environment Setup

### 1.1 Prerequisites
Ensure your development environment contains:
* **Python:** `3.10` or `3.11`
* **Git** with LFS support
* **C/C++ Compiler:** MSVC (Visual Studio 2022 Build Tools) on Windows, or GCC 11+ / Clang on Linux
* **CMake 3.22+**

### 1.2 Virtual Environment & Dependency Installation

#### On Windows (PowerShell):
```powershell
# Navigate to project root
cd "d:\Varsity Documents\12th Trimester\Computer Security\CS Project"

# Create and activate virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Upgrade pip and install wheel
python -m pip install --upgrade pip setuptools wheel

# Install dependencies
pip install -r requirements.txt
```

#### On Linux / macOS:
```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

### 1.3 Downloading Model Weights
We utilize `Qwen2.5-Coder-7B-Instruct-Q4_K_M.gguf` for quantized local execution:

```bash
mkdir -p models
# Using huggingface-cli
huggingface-cli download Qwen/Qwen2.5-Coder-7B-Instruct-GGUF \
  qwen2.5-coder-7b-instruct-q4_k_m.gguf \
  --local-dir ./models/ \
  --local-dir-use-symlinks False
```

---

## 2. Codebase Organization

The repository follows a clean, decoupled architecture:

```
src/
├── __init__.py
├── cli.py                  # CLI entry point (Click / Argparse)
├── config.py               # Global settings, paths, and thresholds
├── parser/                 # Stage 1: Deterministic Static Analysis
│   ├── __init__.py
│   ├── tree_sitter_c.py    # Tree-sitter AST wrapper & grammar loaders
│   ├── source_sink.py      # Taint registry (untrusted sources & dangerous sinks)
│   ├── dataflow.py         # Data Flow Graph (DFG) definition-use tracker
│   └── slicer.py           # Backward/forward program slicing engine (<=150 tokens)
├── rag/                    # Stage 2: Knowledge Retrieval
│   ├── __init__.py
│   ├── embedder.py         # microsoft/unixcoder-base embedding wrapper
│   ├── indexer.py          # Vector store ingestion (CWE XML, DiverseVul JSONL)
│   └── retriever.py        # Top-k multi-view context search (k=3)
├── triage/                 # Stage 3: Local LLM Verification & Triage
│   ├── __init__.py
│   ├── prompt_builder.py   # Dynamic context assembler (Slice + CWE + Patch Diffs)
│   ├── schemas.py          # Pydantic v2 data models for triage reports
│   ├── grammar.py          # Strict GBNF / JSON constrained grammar enforcer
│   └── llm_runner.py       # llama-cpp-python / vLLM local execution engine
├── evaluation/             # Evaluation & Benchmarks
│   ├── __init__.py
│   ├── baseline_sast.py    # Automated Cppcheck / Flawfinder harness
│   ├── juliet_eval.py      # NIST Juliet Test Suite v1.3 runner
│   ├── diversevul_eval.py  # DiverseVul real-world benchmark runner
│   └── metrics.py          # Precision, Recall, F1, and FDR calculator
└── server/                 # REST Microservice (FastAPI)
    ├── __init__.py
    └── app.py              # FastAPI endpoints (/scan, /health)
```

---

## 3. Development Workflows & Quality Assurance

### Code Formatting & Linting
We enforce strict PEP-8 and modern Python typing conventions:
```bash
# Format code
black src/ tests/

# Run fast linter
ruff check src/ tests/

# Type checking
mypy src/ --strict
```

### Running Automated Unit Tests
```bash
# Run all unit tests
pytest tests/ -v

# Run with test coverage report
pytest --cov=src tests/ --cov-report=term-missing
```

---

## 4. Benchmarking & Experimental Replication

To reproduce the experimental results reported in our literature review:

### Step 1: Run Static Baselines (Cppcheck & Flawfinder)
```bash
python -m src.evaluation.baseline_sast \
  --target-dir data/benchmarks/juliet_sample/ \
  --output reports/cppcheck_baseline.json
```

### Step 2: Run AST-Guided RAG Pipeline
```bash
python -m src.cli scan \
  --target data/benchmarks/juliet_sample/ \
  --output reports/ast_rag_juliet.json \
  --model models/qwen2.5-coder-7b-instruct-q4_k_m.gguf
```

### Step 3: Compute Comparative Metrics
```bash
python -m src.evaluation.metrics \
  --ground-truth data/benchmarks/juliet_sample/labels.json \
  --prediction reports/ast_rag_juliet.json \
  --baseline reports/cppcheck_baseline.json
```
This generates comparative confusion matrices, Precision, Recall, F1-Score, and False Discovery Rate ($\text{FDR}$).
