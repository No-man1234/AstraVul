# System Requirements & Dependencies

## Project: AST-Guided RAG Software Vulnerability Detection and Triage
**Document Version:** 1.0.0  
**Target Environment:** Local Workstations, Lab Servers, and Air-Gapped Environments  

---

## 1. Hardware Resource Requirements

The system is engineered to run flexibly across two distinct hardware tiers without compromising detection accuracy.

### Tier 1: Minimum Feasible Setup (Student / Laptop Tier)
*Suitable for running local 4-bit CPU quantized models and in-memory vector search.*
* **Processor (CPU):** 6-Core / 12-Thread x86-64 processor (Intel Core i5 11th Gen+ or AMD Ryzen 5 5000+). Must support **AVX2** or **AVX-512** instruction sets.
* **System RAM:** 16 GB DDR4 / DDR5.
  * Allocation: 6 GB for 4-bit GGUF model execution, 3 GB for In-Memory Vector Store (FAISS/ChromaDB), 4 GB for OS and IDE, 3 GB reserved buffer.
* **Dedicated GPU:** None required (Pure CPU quantized inference via `llama.cpp`).
* **Inference Throughput:** $\approx 8 - 14\text{ tokens/sec}$ (sufficient for slices $\le 150$ tokens, average triage latency: $2.5 - 4.0\text{ seconds}$).
* **Storage Space:** 25 GB free NVMe / SATA SSD space (for GGUF model weights, embeddings cache, and datasets).

### Tier 2: Recommended Research Setup (Lab Workstation / Cloud VM Tier)
*Optimized for high-throughput batch evaluation across large datasets (NIST Juliet, DiverseVul).*
* **Processor (CPU):** 8-Core / 16-Thread processor (AMD Ryzen 7 / Intel Core i7 13th Gen+).
* **System RAM:** 32 GB DDR5 RAM.
* **Dedicated GPU:** NVIDIA GPU with $\ge 8\text{ GB}$ VRAM (e.g., RTX 3060 / 4060 / 4080 or NVIDIA T4 / A10 / A100).
* **Inference Throughput:** $\approx 45 - 75\text{ tokens/sec}$ with full GPU layer offloading.
* **Storage Space:** 50 GB free NVMe M.2 SSD space (PCIe 4.0).

---

## 2. Operating System & Platform Support

| Operating System | Support Status | Notes |
| :--- | :---: | :--- |
| **Windows 10 / 11 (64-bit)** | Fully Supported | Supported natively via PowerShell or via WSL2 (Ubuntu 22.04 LTS). |
| **Linux (Ubuntu 20.04 / 22.04 LTS)** | Fully Supported | Primary production and CI/CD target. |
| **macOS (Apple Silicon M1/M2/M3)** | Supported | Supports Metal Performance Shaders (MPS) in `llama.cpp` and PyTorch. |

---

## 3. Core Software Stack & Version Pins

### Programming Language & Runtime
* **Python:** `3.10.x` or `3.11.x` (Python 3.12 is currently avoided due to certain tree-sitter binary wheel incompatibilities).
* **C/C++ Toolchain:** GCC 11+ or Clang 14+ with CMake 3.22+ (for building tree-sitter parsers and native llama.cpp bindings).

### Python Dependencies (`requirements.txt`)

```text
# --- Core Data Science & Parsing ---
tree-sitter>=0.21.3
tree-sitter-c>=0.21.0
tree-sitter-cpp>=0.21.0
numpy>=1.24.3,<2.0.0
pandas>=2.0.3
scikit-learn>=1.3.0

# --- Vector Database & Embeddings (RAG) ---
chromadb>=0.4.24
faiss-cpu>=1.8.0
sentence-transformers>=2.6.1
transformers>=4.38.2
torch>=2.2.0

# --- LLM Serving & Grammar Enforcement ---
llama-cpp-python>=0.2.56
pydantic>=2.6.4
pydantic-core>=2.16.3

# --- Utilities & CLI ---
rich>=13.7.1
click>=8.1.7
tqdm>=4.66.2
pyyaml>=6.0.1

# --- Evaluation & Baseline Tools ---
flawfinder>=2.0.19
pytest>=8.0.0
pytest-cov>=4.1.0
```

---

## 4. Storage & Asset Footprint

| Asset Name | Source / Provider | Storage Size | Purpose |
| :--- | :--- | :---: | :--- |
| `Qwen2.5-Coder-7B-Instruct-Q4_K_M.gguf` | HuggingFace / Qwen | $\approx 4.68\text{ GB}$ | Primary 4-bit local reasoning and triage model. |
| `unixcoder-base` | `microsoft/unixcoder-base` | $\approx 490\text{ MB}$ | Dense embedding model for code slices ($d=768$). |
| `cwe_catalog.index` | Internal / NIST CWE XML | $\approx 15\text{ MB}$ | Vector index of Top 25 CWE rules and invariants. |
| `cve_patch_pairs.index` | DiverseVul \& CVEfixes | $\approx 1.2\text{ GB}$ | Vector index of curated vulnerability-patch pairs. |
| `juliet_v1.3_c_cpp/` | NIST SAMATE Benchmark | $\approx 4.5\text{ GB}$ | Synthetic ground-truth validation suite. |
| `diversevul_test/` | RAID 2023 Benchmark | $\approx 2.1\text{ GB}$ | Real-world wild vulnerability benchmark. |
| **Total Disk Allocation** | -- | **$\approx 13.0\text{ GB}$** | Complete self-contained offline installation. |

---

## 5. Security & Isolation Constraints

1. **Air-Gap Compliance:** The deployment script must disable all telemetry and telemetry-reporting libraries (`huggingface_hub` telemetry disabled via `HF_HUB_DISABLE_TELEMETRY=1`).
2. **Deterministic Randomness:** All embedding similarity searches and model sampling routines must accept fixed seeds (`seed = 42`) and temperature $T = 0.0$ to guarantee academic reproducibility.
3. **No Dynamic Code Execution:** Code slices submitted for inspection are treated strictly as passive text data; the engine shall under no circumstances compile, link, or dynamically execute analyzed input files.
