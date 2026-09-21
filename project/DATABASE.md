# Vector Database & Knowledge Store Specifications

## Project: AST-Guided RAG Software Vulnerability Detection and Triage
**Document Version:** 1.0.0  
**Storage Engine:** ChromaDB (Embedded) / FAISS (FlatIP & HNSW)  

---

## 1. Storage Strategy & Architectural Overview

To eliminate dependency on cloud-managed vector databases and satisfy air-gap security constraints, the RAG knowledge store uses a local, embedded vector database.

* **Embedded Vector Store:** **ChromaDB** with SQLite persistent storage, augmented with **FAISS-CPU** for high-throughput batch vector similarity lookups.
* **Dense Embedding Model:** `microsoft/unixcoder-base` ($d = 768$).
* **Distance Metric:** **Cosine Similarity** ($\text{Sim}(u, v) = \frac{u \cdot v}{\|u\|_2 \|v\|_2}$).
* **Index Acceleration:** Hierarchical Navigable Small World (HNSW) indexing ($M=16, efConstruction=64, efSearch=40$) or Flat Inner Product (FlatIP) on normalized vectors.

```
+-----------------------------------------------------------------------------------------+
|                               LOCAL KNOWLEDGE VECTOR STORE                              |
|                                                                                         |
|   +---------------------------------------+   +-------------------------------------+   |
|   |         Collection 1: cwe_catalog     |   |      Collection 2: cve_patch_pairs  |   |
|   |---------------------------------------|   |-------------------------------------|   |
|   | • NIST CWE Top 25 Specifications      |   | • 18,000+ DiverseVul Commit Diffs   |   |
|   | • Structural Flaw Invariants          |   | • Curated CVEfixes Function Pairs   |   |
|   | • Precondition / Consequence Semantics|   | • Vulnerable vs. Remediated Diffs   |   |
|   | • Vector: UniXcoder (d = 768)         |   | • Vector: UniXcoder (d = 768)       |   |
|   +---------------------------------------+   +-------------------------------------+   |
|                                                                                         |
|   +---------------------------------------------------------------------------------+   |
|   |                   Collection 3: slice_cache (Metadata & LRU Cache)              |   |
|   |---------------------------------------------------------------------------------|   |
|   | • Hash(AST Slice) -> Triage Verdict, Timestamp, Model Version                   |   |
|   +---------------------------------------------------------------------------------+   |
+-----------------------------------------------------------------------------------------+
```

---

## 2. Collection Schemas & Data Models

### Collection 1: `cwe_catalog`
Contains structured, formal definitions of standard weakness classes, with an emphasis on memory safety flaws.

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "CWEEntry",
  "type": "object",
  "properties": {
    "cwe_id": { "type": "string", "example": "CWE-119" },
    "name": { "type": "string", "example": "Improper Restriction of Operations within the Bounds of a Memory Buffer" },
    "abstraction": { "type": "string", "enum": ["Class", "Base", "Variant"] },
    "description": { "type": "string" },
    "exploit_preconditions": { "type": "array", "items": { "type": "string" } },
    "consequences": { "type": "array", "items": { "type": "string" } },
    "remediation_guidance": { "type": "string" },
    "representative_sinks": { "type": "array", "items": { "type": "string" } },
    "embedded_text": { "type": "string", "description": "Concatenated semantic representation for vectorization" }
  },
  "required": ["cwe_id", "name", "description", "remediation_guidance"]
}
```

### Collection 2: `cve_patch_pairs`
Stores paired before-and-after slices and commit diffs to explicitly prevent the LLM from suffering from patch-blindness (Du et al., ACM TOSEM '24).

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "CVEPatchPair",
  "type": "object",
  "properties": {
    "id": { "type": "string", "example": "cve_diff_18293" },
    "cve_id": { "type": "string", "example": "CVE-2021-3156" },
    "cwe_id": { "type": "string", "example": "CWE-122" },
    "project_name": { "type": "string", "example": "sudo" },
    "commit_hash": { "type": "string" },
    "vulnerable_slice": { "type": "string", "description": "Extracted AST slice prior to patch" },
    "patched_slice": { "type": "string", "description": "Extracted AST slice after patch" },
    "unified_diff": { "type": "string", "description": "Git unified diff of the security fix" },
    "data_source": { "type": "string", "enum": ["diversevul", "cvefixes"] },
    "vector_embedding": { "type": "array", "items": { "type": "number" }, "minItems": 768, "maxItems": 768 }
  },
  "required": ["id", "cve_id", "cwe_id", "vulnerable_slice", "unified_diff"]
}
```

### Collection 3: `slice_cache`
An SQLite-backed LRU key-value cache preventing redundant vector queries and LLM invocations across re-runs.

* **Primary Key:** `SHA256(canonical_ast_slice_tokens)`
* **Columns:**
  * `slice_hash` (TEXT, Primary Key)
  * `cwe_predicted` (TEXT)
  * `is_vulnerable` (BOOLEAN)
  * `triage_json` (TEXT)
  * `model_version` (TEXT)
  * `created_at` (TIMESTAMP)

---

## 3. Embedding Pipeline (`microsoft/unixcoder-base`)

`UniXcoder` (Guo et al., ACL 2022) is selected because it unifies source code, AST paths, and natural language within a single 12-layer Transformer encoder:

1. **Input Preprocessing:**
   * AST slices are formatted with language prefix tags:
     `"<encoder-only> </s> <c> " + canonical_slice_text`
2. **Tokenization:**
   * Maximum sequence length: $512$ tokens.
   * Special tokens: `<s>`, `</s>`, `<c>`, `<cpp>`.
3. **Pooling:**
   * Mean pooling across last hidden states, followed by $L_2$ normalization:
     $$\mathbf{v} = \frac{\sum_{i=1}^L \mathbf{h}_i}{\|\sum_{i=1}^L \mathbf{h}_i\|_2}$$

---

## 4. Query & Retrieval Strategy

When an input code slice $\mathbf{s}$ is extracted in Stage 1:

1. Compute embedding vector $\mathbf{v}_s = \text{UniXcoder}(\mathbf{s})$.
2. **Step 1 (CWE Rule Grounding):** Query `cwe_catalog` with $\mathbf{v}_s$ for top-$1$ match ($k=1$).
   * Returns formal weakness definition, bounds check invariants, and typical attack prerequisites.
3. **Step 2 (Contrastive Patch Retrieval):** Query `cve_patch_pairs` with $\mathbf{v}_s$ for top-$2$ matches ($k=2$).
   * Returns real-world instances where structurally similar slices were patched, providing the LLM with direct exemplars of vulnerable code alongside its corresponding fix.
4. **Similarity Threshold Filtering:**
   * Matches with cosine similarity $\cos(\theta) < 0.65$ are dropped to avoid injecting irrelevant out-of-distribution noise into the prompt.

---

## 5. Ingestion Pipeline & Data Sanitization

To avoid the data snooping and contamination pitfalls highlighted by Arp et al. (*Chasing Shadows*, NDSS 2026):

* **Exact Deduplication:** SHA-256 hashing across all function slices removes exact duplicates between datasets.
* **Near-Duplicate Filtering:** MinHash LSH (Jaccard similarity threshold $0.85$) purges near-identical synthetically generated samples.
* **Test Split Isolation:** The validation benchmarks (NIST Juliet test partition and DiverseVul holdout split) are strictly excised from the vector indexing corpora to guarantee zero train/test contamination.
