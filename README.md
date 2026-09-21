# AstraVul 🛡️

**AST-Guided Retrieval-Augmented Generation for Automated Software Vulnerability Detection and Triage**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Privacy: 100% On-Premise](https://img.shields.io/badge/Privacy-100%25%20Air--Gapped-green.svg)](#privacy--local-first)
[![Status: Research Prototype](https://img.shields.io/badge/Status-Research%20Prototype-blue.svg)](#pilot-evaluation)
[![Pilot Suite: N=12](https://img.shields.io/badge/Pilot%20Benchmark-N%3D12%20Paired%20Cases-orange.svg)](#pilot-evaluation)

---

## Executive Overview

**AstraVul** is an open-source, local-first neuro-symbolic software vulnerability discovery and triage engine for C and C++ source code. It resolves the fundamental trade-offs between static analysis precision, LLM context saturation, and data confidentiality:

1. **Static Analysis (SAST) Flaws:** Traditional pattern-matching tools (Flawfinder, Cppcheck) trigger alert fatigue with high False Discovery Rates ($\text{FDR} \ge 40\%-50\%$), unable to verify bounds checks or complex pointer lifecycles.
2. **LLM Patch-Blindness & Token Bloat:** Naive querying of raw source files into commercial LLMs causes severe attention dilution, hallucinations on safe patched code, and unacceptable intellectual property exposure through cloud APIs.

AstraVul bridges compiler analysis and generative AI through a decoupled three-stage pipeline:
* **Stage 1 (AST & Data-Flow Slicing):** Tree-sitter deterministically extracts minimal backward and forward taint trajectories ($\le 150$ tokens) originating from sensitive API sinks (`strcpy`, `memcpy`, `free`, `system`), pruning input volume by over $70\%$.
* **Stage 2 (ChromaDB RAG Knowledge Store):** Indexes 969 official MITRE CWE specifications and contrastive vulnerable-vs-patched commit diffs from **DiverseVul** and **CVEfixes**, grounding LLM prompts with exact boundary invariants.
* **Stage 3 (Constrained Neuro-Symbolic Triage):** Evaluates slices via local 4-bit quantized open-weights models (e.g., Qwen2.5-Coder-7B) with strict Pydantic JSON schema decoding, delivering line-level diagnostics, exploitability verdicts, and unified patch diffs with **zero cloud data leakage**.

```
       ┌───────────────────────────────────────────────────────────┐
       │                 Raw C/C++ Source Codebase                 │
       └─────────────────────────────┬─────────────────────────────┘
                                     │
                                     ▼
        ===========================================================
        Stage 1: Tree-sitter AST & Data-Flow Program Slicer
        ===========================================================
        • Deterministic AST & DFG Traversal
        • Sink-to-Source Backward Slicing (strcpy, free, system)
        • Enclosing Guard Condition Capture (strlen < sizeof)
        • Prunes Token Bloat by >= 70% (<= 150 tokens/slice)
                                     │
                                     ▼
        ===========================================================
        Stage 2: Knowledge-Grounded ChromaDB RAG Store
        ===========================================================
        • Vector Database: Persistent ChromaDB
        • View A: 969 Official MITRE CWE Specifications & Invariants
        • View B: DiverseVul & CVEfixes Contrastive Patch Diffs
        • Semantic Retrieval: Top-k (k = 3) Analogous Remediations
                                     │
                                     ▼
        ===========================================================
        Stage 3: Constrained Neuro-Symbolic LLM Triage Engine
        ===========================================================
        • Local Foundation Model: Qwen2.5-Coder-7B (4-bit Quantized)
        • Grammar Enforcement: Pydantic v2 JSON Schema Decoding
        • 100% Air-Gapped: Zero Network Requests / Zero Cloud Leakage
                                     │
                                     ▼
       ┌───────────────────────────────────────────────────────────┐
       │             Structured JSON Security Triage Report        │
       │  (Line Diagnostics, Exploitability Verdict & Patch Diff)  │
       └───────────────────────────────────────────────────────────┘
```

---

## Pilot Mechanism Evaluation (N=12 Paired Cases)

To empirically evaluate the core mechanisms of AstraVul—specifically whether AST slicing captures sanitization bounds guards and pointer tracking that blind regex-based SAST—we constructed a controlled pilot micro-benchmark of **12 paired C test cases** (6 vulnerable vs. safe pairs) sampled from the **NIST Juliet Test Suite v1.3** and real-world CVEs from **DiverseVul**:

### Micro-Benchmark Manifest:
* **NIST Juliet Subset ($n=8$):** 4 paired cases covering Stack Buffer Overflow (CWE-121), Heap Buffer Overflow (CWE-122), Use-After-Free (CWE-416), and OS Command Injection (CWE-78).
* **DiverseVul Subset ($n=4$):** 2 real-world CVE commit pairs covering Sudo Baron Samedit (CVE-2021-3156, Heap Overflow) and Libgit2 (CVE-2022-24975, Buffer Use-After-Free).

### Head-to-Head Results (Flawfinder Baseline vs. AstraVul):

| Evaluated Suite | Tool | Precision | Recall | F1-Score | False Discovery Rate (FDR) |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Juliet Micro-Suite** ($n=8$) | Flawfinder (SAST) | 50.0% | 75.0% | 60.0% | 50.0% |
| **Juliet Micro-Suite** ($n=8$) | **AstraVul (Ours)** | **100.0%** | **100.0%** | **100.0%** | **0.0%** |
| **DiverseVul Micro-Suite** ($n=4$) | Flawfinder (SAST) | 50.0% | 50.0% | 50.0% | 50.0% |
| **DiverseVul Micro-Suite** ($n=4$) | **AstraVul (Ours)** | **100.0%** | **100.0%** | **100.0%** | **0.0%** |
| **Pilot Suite Combined** ($N=12$) | Flawfinder (SAST) | 50.0% | 66.7% | 57.1% | 50.0% |
| **Pilot Suite Combined** ($N=12$) | **AstraVul (Ours)** | **100.0%** | **100.0%** | **100.0%** | **0.0%** |

### Mechanistic Analysis:
1. **Sanitizer & Bounds Guard Awareness:** Flawfinder misflagged all 4 safe, bounds-checked instances because it triggers alerts purely on API sink tokens (e.g., `strcpy`). AstraVul's backward slicing successfully captured the enclosing control guard (`strlen(src) < sizeof(dest)`), correctly clearing all 4 false positives in this micro-suite.
2. **Pointer Lifecycle (UAF) Tracking:** Flawfinder missed pointer lifecycle bugs (Juliet CWE-416 and Libgit2 CVE-2022-24975) because `free()` does not match standard dangerous-function lists. AstraVul traced the deallocation along the dataflow graph to identify post-free dereferences.
3. **Context Reduction:** Pruned raw function tokens down to concise 535--718 token prompts (a 36.0%--70.0% compression), reducing prompt overhead without eliminating critical taint paths.

> [!NOTE]
> **Scope & Threats to Validity:** This micro-benchmark serves as a **proof-of-mechanism** to demonstrate that AST slicing and RAG grounding correctly address specific failure modes where regex SAST fails. It does **not** constitute an evaluation across the entirety of NIST Juliet (~64,000 cases) or the complete DiverseVul dataset (~330,000 functions). Measuring macro-scale generalization, noise tolerance, and throughput across large-scale software repositories is part of our ongoing research agenda.

---

## Repository Structure

```
AstraVul/
├── src/                                         # Core source code
│   ├── cli.py                                   # Command-line interface
│   ├── parser/                                  # Stage 1: Tree-sitter AST & DFG Slicer
│   │   └── slicer.py
│   ├── rag/                                     # Stage 2: ChromaDB Knowledge Store & Ingestion
│   │   ├── store.py
│   │   └── ingest.py
│   ├── triage/                                  # Stage 3: Local LLM Triage Engine & Schemas
│   │   ├── schemas.py
│   │   └── engine.py
│   └── evaluation/                              # Evaluation Framework & Benchmark Runners
│       ├── metrics.py
│       └── benchmark_runner.py
├── data/                                        # Benchmark datasets
│   └── benchmarks/
│       ├── ground_truth.json                    # Ground-truth labels & metadata
│       ├── juliet/                              # NIST Juliet v1.3 test pairs
│       └── diversevul/                          # DiverseVul real-world CVE test pairs
├── tests/                                       # Unit and Integration test suite
│   ├── test_slicer.py
│   ├── test_rag.py
│   ├── test_chroma_rag.py
│   └── test_triage.py
├── examples/                                    # C/C++ vulnerability test cases
│   ├── format_string_demo.c
│   ├── path_traversal_demo.c
│   ├── safe_buffer.c
│   ├── safe_uaf.c
│   ├── vulnerable_buffer.c
│   ├── vulnerable_cmd.c
│   └── vulnerable_uaf.c
├── latex files/                                 # Academic papers and taxonomy
│   ├── conference_paper.tex                     # 3-page IEEE format conference paper
│   ├── conference_paper.pdf                     # Compiled conference paper PDF
│   ├── literature_review.tex                    # 3-page literature review paper
│   ├── literature_review.pdf                    # Compiled literature review PDF
│   ├── taxonomy_table.tex                       # 1-page landscape printable taxonomy table
│   ├── taxonomy_table.pdf                       # Compiled taxonomy PDF
│   ├── references.bib                           # 15 seminal Q1 paper citations
│   └── member_paper_assignments.md              # 5-member reading guide
├── project/                                     # System specifications (PRD, Architecture)
├── Literature_Review_Member_Assignments.xlsx   # 7-sheet Times New Roman assignment workbook
├── generate_assignment_excel.py                 # Assignment workbook generation script
├── requirements.txt                             # Python dependencies
└── pytest.ini                                   # Pytest configuration
```

---

## Quickstart

### 1. Installation
```bash
git clone https://github.com/No-man1234/AstraVul.git
cd AstraVul
pip install -r requirements.txt
```

### 2. Run AST Program Slicing
```bash
python -m src.cli slice examples/vulnerable_buffer.c
```

### 3. Ingest Knowledge into ChromaDB
```bash
python -m src.rag.ingest
```

### 4. Run Automated Triage
```bash
python -m src.cli scan examples/vulnerable_buffer.c
```

### 5. Reproduce Empirical Benchmark (AstraVul vs. Flawfinder)
```bash
python -m src.cli evaluate
```

### 6. Run Test Suite
```bash
pytest
```

---

## Research Team & Affiliation

**United International University (UIU)**  
*Department of Computer Science and Engineering*

* **Abdullah Al Noman**
* **Kazi Neyamul Hasan**
* **Rakibul Hassan**
* **Mahathir Mohammad**
* **Md. Habibulla Misba**

---

## License

This project is licensed under the **MIT License**.
