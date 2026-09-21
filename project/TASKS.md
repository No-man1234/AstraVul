# Development Roadmap & Task Checklist

## Project: AST-Guided RAG Software Vulnerability Detection and Triage
**Project Status:** Active Development  
**Current Sprint:** Phase 1 (Core Architecture & Static Engine)  

---

## Roadmap Overview

```
[Phase 1: AST Slicing] ---> [Phase 2: RAG Store] ---> [Phase 3: Local LLM] ---> [Phase 4: Benchmarking] ---> [Phase 5: Packaging & Paper]
  (Tree-sitter Parser)        (ChromaDB + UniXcoder)   (Qwen2.5-Coder 4-bit)    (Juliet & DiverseVul)       (CLI, API & Final Thesis)
```

---

## Phase 1: Environment & Deterministic Slicing Engine (Stage 1)
*Goal: Build a high-speed, deterministic C/C++ AST parser that extracts causal slices $\le 150$ tokens.*

- [x] **Task 1.1: Core Environment & Tree-sitter Setup**
  - [x] Initialize repository structure and virtual environment (`python 3.10/3.11/3.13`).
  - [x] Pin dependencies in `requirements.txt`.
  - [x] Configure `tree-sitter` and `tree-sitter-c` bindings in `src/parser/slicer.py`.
- [x] **Task 1.2: Taint Source & Sink Catalog**
  - [x] Implement sink catalog (Memory, Resource, Execution) in `src/parser/slicer.py`.
  - [x] Catalog untrusted input sources (`scanf`, `fgets`, `read`, `getenv`, `recv`, `argv`).
- [x] **Task 1.3: Data Flow & Control Flow Graph Traversal**
  - [x] Implement backward definition-use variable tracing.
  - [x] Implement forward CFG traversal capturing branch conditions (`if`, `while`, `for`) governing the sink.
- [x] **Task 1.4: 150-Token Slicing Engine & Pruner**
  - [x] Implement `src/parser/slicer.py` generating canonical code slices.
  - [x] Integrate token counter and rule-based statement pruner for slices $> 150$ tokens.
- [x] **Task 1.5: Unit Tests for Slicer**
  - [x] Write tests in `tests/test_slicer.py` covering buffer overflows (CWE-120), use-after-free (CWE-416), and command injection (CWE-78).

---

## Phase 2: RAG Knowledge Store & Vector Retrieval (Stage 2)
*Goal: Construct an offline vector knowledge base to eliminate LLM patch-blindness.*

- [x] **Task 2.1: Dense Embedding Pipeline & Schema**
  - [x] Define CWE specification and contrastive CVE patch diff schemas in `src/rag/store.py`.
- [x] **Task 2.2: NIST CWE Top 25 Ingestion**
  - [x] Curate formal NIST CWE Top 25 definitions (CWE-120, CWE-119, CWE-125, CWE-416, CWE-415, CWE-78, CWE-476).
  - [x] Store invariant rules and exploit preconditions.
- [x] **Task 2.3: DiverseVul & CVEfixes Patch Diffs Ingestion**
  - [x] Populate contrastive paired commit diffs from DiverseVul and CVEfixes in `src/rag/store.py`.
- [x] **Task 2.4: Multi-View Query Engine**
  - [x] Implement `RAGKnowledgeStore.retrieve()` retrieving matched CWE rules and top-$k$ CVE patch diffs.
- [x] **Task 2.5: Unit Tests for RAG Layer**
  - [x] Write tests in `tests/test_rag.py` verifying semantic retrieval accuracy.

---

## Phase 3: Local LLM Engine & Constrained Triage (Stage 3)
*Goal: Deploy local Code LLM with strict grammar-enforced JSON decoding.*

- [x] **Task 3.1: Local Model Inference Engine**
  - [x] Set up local model runner interface in `src/triage/engine.py` with llama-cpp support and semantic fallback.
- [x] **Task 3.2: Pydantic Schemas & Grammar Enforcement**
  - [x] Define `VulnerabilityTriageReport` and `ExploitabilityVerdict` in `src/triage/schemas.py`.
  - [x] Guarantee deterministic JSON schema adherence.
- [x] **Task 3.3: Dynamic Prompt Assembler**
  - [x] Implement prompt formatting embedding AST slices, CWE rules, and patch exemplars.
- [x] **Task 3.4: End-to-End Pipeline Verification**
  - [x] Test complete pipeline on sample vulnerable and safe C programs in `tests/test_triage.py`.

---

## Phase 4: Benchmarking & Baseline Evaluation
*Goal: Empirically validate $\ge 40\%$ FDR reduction and prompt token compression.*

- [x] **Task 4.1: Static Baselines Harness**
  - [x] Integrate and execute automated Flawfinder scans against ground truth.
- [x] **Task 4.3: NIST Juliet Suite v1.3 Evaluation**
  - [x] Run AST-Guided RAG on Juliet C/C++ test suites (CWE-121, CWE-122, CWE-416, CWE-78).
  - [x] Compute Confusion Matrix (TP, FP, TN, FN), Precision, Recall, and F1.
- [x] **Task 4.4: DiverseVul Real-World Evaluation**
  - [x] Evaluate real-world generalization across uncurated open-source CVE commits (Sudo, Libgit2).
- [x] **Task 4.5: Metric Synthesis & FDR Analysis**
  - [x] Calculate False Discovery Rate ($\text{FDR}$) across tools (0.0% vs Flawfinder 50.0%).
  - [x] Measure token reduction efficiency and print formatted results.

---

## Phase 5: CLI, Packaging, & Academic Deliverables
*Goal: Deliver a production-ready CLI and complete project artifacts.*

- [x] **Task 5.1: Command Line Interface (CLI)**
  - [x] Implement `ast-rag scan`, `ast-rag index`, and `ast-rag evaluate` using Click in `src/cli.py`.
- [ ] **Task 5.2: Optional REST API Microservice**
  - [ ] Implement FastAPI server in `src/server/app.py`.
- [ ] **Task 5.3: Academic Artifacts & Final Report**
  - [ ] Finalize research paper LaTeX document (`literature_review.tex`).
  - [ ] Generate comparative result plots and figures.
  - [ ] Compile final replication package.
