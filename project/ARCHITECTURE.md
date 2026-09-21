# System Architecture Document

## Project: AST-Guided RAG Software Vulnerability Detection and Triage
**Document Version:** 1.0.0  
**Status:** Approved Architecture Blueprint  

---

## 1. High-Level System Architecture

The AST-Guided RAG architecture operates as a coupled, three-tier neuro-symbolic pipeline. It systematically bridges deterministic static code analysis, semantic vector retrieval, and generative AI triage:

```
+--------------------------------------------------------------------------------------------------+
|                                    1. DETERMINISTIC STATIC ENGINE                                |
|                                                                                                  |
|   +-------------------+       +-----------------------+       +------------------------------+   |
|   | Raw C/C++ Source  | ----> | Tree-sitter AST Parser| ----> | Taint Tracer & Slicer Engine |   |
|   +-------------------+       +-----------------------+       +------------------------------+   |
|                                                                              |                   |
|                                                                              | Slices <= 150 toks|
|                                                                              v                   |
+------------------------------------------------------------------------------+-------------------+
                                                                               |
+------------------------------------------------------------------------------v-------------------+
|                                  2. KNOWLEDGE RETRIEVAL LAYER (RAG)                              |
|                                                                                                  |
|   +-----------------------+         +-----------------------+       +------------------------+   |
|   | microsoft/unixcoder   | <------ | Extracted Code Slice  | ----> | FAISS / ChromaDB Index |   |
|   | Dense Vector (d=768)  |         +-----------------------+       +------------------------+   |
|   +-----------------------+                                                      |               |
|               |                                                                  v               |
|               +-----------------------------------------------------> [Top-k Similar Matches]   |
|                                                                         - NIST CWE Top 25 Rules  |
|                                                                         - Paired CVE Commit Diffs|
+----------------------------------------------------------------------------------+---------------+
                                                                                   |
+----------------------------------------------------------------------------------v---------------+
|                                  3. LOCAL INFERENCE & TRIAGE ENGINE                              |
|                                                                                                  |
|   +--------------------+       +-----------------------+       +-----------------------------+   |
|   | Dynamic Augmented  | ----> | Local Quantized LLM   | ----> | Strict Grammar Enforcer     |   |
|   | Prompt Assembler   |       | (Qwen2.5-Coder-7B-4b) |       | (Pydantic v2 Schema Filter) |   |
|   +--------------------+       +-----------------------+       +-----------------------------+   |
|                                                                              |                   |
|                                                                              v                   |
|                                                                +-----------------------------+   |
|                                                                | Structured JSON Triage      |   |
|                                                                | - Exploitability Verdict    |   |
|                                                                | - Vulnerable Line Indices   |   |
|                                                                | - Remediation Patch Diff    |   |
|                                                                +-----------------------------+   |
+--------------------------------------------------------------------------------------------------+
```

---

## 2. Detailed Subsystem Specifications

### Subsystem 1: Deterministic AST Parsing & Program Slicing
* **Purpose:** Reduce code noise by $\ge 70\%$, discard irrelevant logic, and construct a causal statement chain linking untrusted user inputs to critical operations.
* **Component 1.1: Parser Engine:**
  * Uses `tree-sitter` and `tree-sitter-c` / `tree-sitter-cpp` bindings.
  * In-memory Concrete Syntax Tree (CST) and AST generation without requiring complete compiler toolchains or missing header resolution.
* **Component 1.2: Taint Source & Sink Catalog:**
  * *Untrusted Sources:* Functions that accept external input (`scanf`, `fgets`, `read`, `recv`, `getenv`, `argv`, `fread`).
  * *Critical Sinks:* Operations vulnerable to memory corruption and command injection (`strcpy`, `strcat`, `sprintf`, `memcpy`, `free`, `system`, `popen`, pointer dereference `*ptr`).
* **Component 1.3: Slicing Traversal Algorithm:**
  1. Locate target sink node $S$ in the AST.
  2. Perform **Backward Data-Flow Traversal:** Traverse the Data Flow Graph (DFG) upward to locate all definitions, mutations, allocations, and pointer aliases impacting the sink operands.
  3. Perform **Forward Control-Flow Traversal:** Traverse the Control Flow Graph (CFG) to capture branch conditions, loop guards, and boundary checks (`if (len < MAX)`, `while (...)`) that govern the sink's execution.
  4. **Context Reduction Filter:** Prune unreferenced statements. If the slice exceeds 150 tokens, apply priority pruning: retain (1) sink invocation, (2) source invocation, (3) direct bounds checks, and (4) mutating assignments.

### Subsystem 2: Contrastive Vector Retrieval (RAG Layer)
* **Purpose:** Solve LLM "patch-blindness" and grounding deficits by fetching analogous vulnerability mechanisms and remediating diffs.
* **Component 2.1: Dual Knowledge Base Structure:**
  * **Collection A: `cwe_catalog`**
    * Ingestion: NIST CWE Top 25 specifications.
    * Fields: `cwe_id`, `name`, `description`, `exploit_mechanism`, `preconditions`, `remediation_invariants`.
  * **Collection B: `cve_patch_pairs`**
    * Ingestion: Mined commits from DiverseVul (RAID '23) and CVEfixes (MSR '21).
    * Fields: `cve_id`, `vulnerable_slice`, `patched_slice`, `commit_diff`, `cwe_id`, `vuln_type`.
* **Component 2.2: Dense Embedding Pipeline:**
  * Model: `microsoft/unixcoder-base` ($d=768$).
  * Handles code token sequences and AST structures seamlessly using 1-to-1 attention masks.
  * Distance Metric: Flat Inner Product (Cosine Similarity) or HNSW cosine metric.
* **Component 2.3: Query Strategy:**
  * The extracted slice is embedded and queried against both collections ($k=1$ for CWE definition, $k=2$ for contrastive CVE patch diffs).
  * Output: Context block containing formal CWE rule invariants and real-world patch examples demonstrating how similar flaws were remediated.

### Subsystem 3: Local LLM Verification & Constrained Triage
* **Purpose:** Analyze the code slice alongside retrieved security context to verify whether the flaw is genuinely exploitable, pinpoint line locations, and synthesize fix patches.
* **Component 3.1: Model & Runtime Configuration:**
  * Model: `Qwen2.5-Coder-7B-Instruct` or `DeepSeek-Coder-6.7B-Instruct`.
  * Runtime: `llama-cpp-python` (with AVX2/AVX-512 or CUDA offloading) or `vLLM` (AWQ/GPTQ).
  * Quantization: 4-bit `Q4_K_M` GGUF. Memory footprint: $\approx 4.8\text{ GB}$ VRAM / RAM.
* **Component 3.2: Grammar-Constrained Decoding:**
  * Decoding is constrained using Pydantic v2 schemas and GBNF grammars.
  * The model cannot emit conversational text (e.g., *"Certainly! Here is my analysis..."*); it is mathematically constrained to valid JSON matching `VulnerabilityTriageReport`.
* **Component 3.3: Output Schema Attributes:**
  * `is_vulnerable`: Boolean flag.
  * `cwe_id`: Matched CWE identifier.
  * `vulnerable_lines`: Exact line indices in the original source file.
  * `exploitability`: `CONFIRMED_EXPLOITABLE` | `SUSPICIOUS_UNVERIFIED` | `BENIGN_FALSE_POSITIVE`.
  * `root_cause`: Causal explanation of why existing guards fail.
  * `remediation_patch`: Unified diff format illustrating code modifications.

---

## 3. End-to-End Sequence Flow

```
[Developer / CI-CD]    [Stage 1: Slicer]     [Stage 2: RAG]       [Stage 3: Local LLM]
         |                     |                    |                     |
         |--- 1. Submit Code ->|                    |                     |
         |    (main.c)         |                    |                     |
         |                     |-- 2. Parse AST --->|                     |
         |                     |-- 3. Taint Trace ->|                     |
         |                     |   (Slice <= 150t)  |                     |
         |                     |                    |                     |
         |                     |--- 4. Query Vec -->|                     |
         |                     |    (Slice Vector)  |                     |
         |                     |                    |-- 5. Fetch Top-k -->|
         |                     |                    |   (CWE + Patch Diff)|
         |                     |                    |                     |
         |                     |---------------- 6. Assemble Prompt ----->|
         |                     |                    |  (Slice + Context)  |
         |                     |                    |                     |
         |                     |                    |                     |-- 7. Constrained
         |                     |                    |                     |      Inference
         |                     |                    |                     |      (JSON Schema)
         |                     |                    |                     |
         |<---------------- 8. Validated JSON Triage Report --------------|
         |    (Verdict, Lines, Patch, Exploitability)
```

---

## 4. Architectural Design Decisions & Trade-Offs

| Decision | Alternative Considered | Chosen Approach | Justification |
| :--- | :--- | :--- | :--- |
| **AST Parser** | Clang LibTooling | Tree-sitter | Clang requires full compilation environment (header resolution, build flags). Tree-sitter is error-tolerant, works on partial/isolated files, and executes in microseconds. |
| **Embedding Model** | OpenAI `text-embedding-3-small`, BGE-Large | `microsoft/unixcoder-base` | Generic text models fail on syntactic code differences. UniXcoder unifies AST and code tokens via cross-modal pre-training (ACL 2022). |
| **Vector Engine** | Pinecone, Milvus | ChromaDB / FAISS | Embedded, zero-cloud dependency, runs in-memory or on local NVMe disk, ensures air-gapped security. |
| **Inference Mode** | Cloud GPT-4o API | Local Quantized Qwen2.5-Coder-7B | Sending enterprise code to commercial APIs violates privacy/IP compliance. Local 4-bit models preserve data sovereignty with near-zero latency. |
| **Output Format** | Freeform Markdown | Pydantic JSON Schema Enforcer | Eliminates model hallucinations, ensures 100% parseability in automated CI/CD security quality gates. |

---

## 5. Security and Air-Gap Architecture

1. **Zero External Network Egress:** All models, embeddings, and vector stores execute in an offline loop.
2. **Deterministic Reproducibility:** Sampling temperature is fixed to $T = 0.0$ with deterministic greedy search.
3. **Memory Isolation:** Vector index and model weights reside within dedicated process boundaries, preventing cross-tenant data contamination.
