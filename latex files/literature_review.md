# AST-Guided Retrieval-Augmented Generation for Automated Software Vulnerability Detection and Triage: A Literature Review

**Research & Development Group**  
Department of Computer Science and Engineering  
United International University (UIU)

---

## Abstract
Automated vulnerability detection is essential for modern software security. Traditional Static Application Security Testing (SAST) suffers from high False Discovery Rates ($\text{FDR} \ge 40\%$), while naive querying of Large Language Models (LLMs) on raw source code introduces intellectual property risks, attention saturation over long contexts, and hallucinated reports. Recent research converges on hybrid neuro-symbolic paradigms: deterministic program slicing via Abstract Syntax Trees (AST) combined with knowledge-level Retrieval-Augmented Generation (RAG) and local, privacy-preserving LLM verification. This paper synthesizes 15 foundational and state-of-the-art Q1 papers (including USENIX Security, NDSS, ICSE, ACM TOSEM, IEEE TDSC, NeurIPS, and ACL) into a unified taxonomy, identifying critical research gaps and establishing the foundation for a token-efficient, high-precision triage pipeline.

**Keywords:** Vulnerability Detection, Abstract Syntax Tree, Program Slicing, Retrieval-Augmented Generation, Large Language Models, Neuro-Symbolic Security.

---

## 1. Introduction
Modern software repositories face escalating security challenges from memory corruption (e.g., CWE-119, CWE-416) and injection flaws (e.g., CWE-78). Automated vulnerability discovery has evolved through three main phases:
1. **Heuristic Static Analysis (SAST):** Scanners such as Flawfinder and Cppcheck scan tokens against regex patterns. While lightweight, they lack path sensitivity and exhibit high False Discovery Rates ($\text{FDR} \ge 40\%$).
2. **Deep Learning on Graphs:** Approaches like VulDeePecker (NDSS 2018) and Devign (NeurIPS 2019) model semantic graphs, but act as uninterpretable black boxes that degrade under out-of-distribution code shifts.
3. **Code LLMs:** While generative models excel at code comprehension, recent Q1 empirical studies (ICSE 2025, NDSS 2026) demonstrate that raw LLM querying suffers from context saturation, patch-blindness, and enterprise confidentiality risks when using cloud APIs.

To resolve these challenges, recent literature motivates an AST-guided, local RAG framework.

---

## 2. Literature Review
Automated vulnerability detection research spans deterministic program slicing, empirical LLM realities, retrieval-augmented generation, and neuro-symbolic triage.

**Program Slicing and Graph Representations:**  
Vulnerabilities propagate along localized data- and control-dependency trajectories. Li et al. (NDSS 2018) pioneered *code gadgets* in VulDeePecker, showing that slicing statements around sensitive API sinks outperforms full-function learning. Li et al. (IEEE TDSC 2021) expanded this in SySeVR by formalizing bidirectional slicing across CFG and DFG to discover 15 zero-day vulnerabilities. Zhou et al. (NeurIPS 2019) in Devign established that composite Code Property Graphs (AST, CFG, DFG) are required for multi-factor flaws like use-after-free. Steenhoek et al. (ICSE 2024) in DeepDFA integrated dataflow facts into bit-vectors to suppress superficial token bias. Recently, Lekssays et al. (USENIX Security 2025) in LLMxCPG demonstrated that deterministic CPG slicing reduces input code volume by 67.8%--90.9% while boosting downstream LLM F1-scores by 15%--40% and conferring adversarial robustness.

**Empirical Pitfalls and LLM Fragility:**  
Despite high zero-shot reasoning capabilities, LLMs exhibit severe fragility when evaluated on rigorous benchmarks. In PrimeVul, Zhang et al. (ICSE 2025) discovered that 7B-parameter LLMs achieving 68.3% F1 on historical datasets collapsed to 3.1% F1 on debiased real-world data, frequently performing no better than random guessers without structural context. Arp et al. (NDSS 2026) in *Chasing Shadows* formalized nine systemic research pitfalls across 72 papers, demonstrating that standard Precision/Recall mask operational failures; researchers must track the False Discovery Rate ($\text{FDR} = \text{FP}/(\text{TP} + \text{FP})$). Chakraborty et al. (ICSE 2021) in ReVeal further established that synthetic suites like Juliet fail to mirror real-world vulnerability distributions, requiring validation on wild corpora such as DiverseVul (Chen et al., RAID 2023) and commit-level patch diffs from CVEfixes (Bhandari et al., MSR 2021).

**Knowledge Retrieval and Neuro-Symbolic Verification:**  
A fundamental limitation of LLMs is "patch-blindness"—the inability to distinguish a vulnerable function from a secure patch sharing identical syntax. Du et al. (ACM TOSEM 2024) solved this in Vul-RAG by injecting CWE taxonomies and historical CVE diffs, improving accuracy by 16%--24%. Semantic retrieval relies on dense encoders: Guo et al. (ACL 2022) in UniXcoder unified AST prefixes and comments via multi-modal attention, while Liu et al. (ICSE 2024) in PDBERT pre-trained on program dependencies to achieve 23$\times$ higher throughput than static graph analyzers. In neuro-symbolic verification, Sun et al. (ICSE 2024) in GPTScan combined static candidate identification with LLM constraint validation ($>90\%$ precision), while Fu and Tantithamthavorn (MSR 2022) in LineVul proved that line-level localization reduces inspection effort by over 80% compared to function-level alarms.

### Systematic Comparative Taxonomy of Reviewed Literature

| Paper / System | Approach Paradigm | Slicing / AST | RAG | Privacy / Local | Key Addressed Limitation |
| :--- | :--- | :---: | :---: | :--- | :--- |
| **VulDeePecker** | Deep Learning (BLSTM) | API Sinks | No | Offline Model | Coarse file-level analysis |
| **SySeVR** | Deep Learning (BBiRNN) | AST+CFG+DFG | No | Offline Model | Missing control-flow context |
| **Devign** | Graph Neural Net (GGNN) | Composite CPG | No | Offline Model | Syntax-only representation |
| **ReVeal** | Graph DL / Empirical | Graph Slices | No | Offline Model | Exposed synthetic dataset bias |
| **UniXcoder** | Cross-Modal Pre-training | AST Flattening | No | Local Weights | Semantic code embedding gap |
| **LineVul** | Transformer (CodeBERT) | Token Sequence | No | Local Weights | Coarse function-level alerts |
| **CVEfixes** | Curated Security Corpus | Function/Diff | No | N/A | Ground-truth CVE-to-fix mapping |
| **DiverseVul** | Benchmark Evaluation | Function Level | No | N/A | Mitigated label noise across 150 CWEs |
| **GPTScan** | Neuro-Symbolic Hybrid | Static Analysis | No | Cloud API (GPT-3.5) | $>90\%$ precision in logic flaw verification |
| **DeepDFA** | Neuro-Symbolic / GNN | Dataflow Vectors | No | Local Weights | Injected symbolic dataflow into embeddings |
| **PDBERT** | Pre-trained Transformer | Program Dep. | No | Local Weights | $23\times$ faster dependency-aware throughput |
| **Vul-RAG** | Retrieval-Augmented LLM | No | Yes | Cloud API (GPT-4) | Overcame LLM patch-blindness (+16--24\%) |
| **LLMxCPG** | Neuro-Symbolic Hybrid | CPG Slicing | No | Local Fine-Tuning | 68--91\% code reduction; +15--40\% F1 score |
| **PrimeVul** | Empirical Benchmarking | Function Level | No | Local \& Cloud LLMs | Proved raw LLMs fail on debiased datasets |
| **Chasing Shadows** | Systematic Review | N/A | No | N/A | Formalized 9 pitfalls; highlighted FDR metric |
| **Proposed System** | **AST-Guided RAG+LLM** | **AST+DFG ($\le 150$t)** | **Yes** | **Local 4-bit Quant.** | **Resolves FDR, hallucination, \& privacy** |

**Research Gaps and Proposed Architecture:**  
This synthesis exposes three central gaps: (1) *Context Saturation:* Raw file prompts dilute attention; deterministic Tree-sitter AST slicing prunes $\ge 70\%$ of unneeded tokens into minimal $\le 150$-token slices. (2) *Patch-Blindness:* General LLMs hallucinate false alarms on patched code; grounding slices via ChromaDB/FAISS indexed with NIST CWE specifications and DiverseVul/CVEfixes diffs provides explicit boundary invariants. (3) *Privacy and Hallucination:* Cloud LLM reliance risks code leaks; local 4-bit quantized models (Qwen2.5-Coder-7B) coupled with Pydantic JSON schema decoding guarantee verifiable, zero-leakage triage reports.

---

## 3. Conclusion
This literature review establishes the foundation for AST-guided RAG in software vulnerability detection. Uniting deterministic AST program slicing, semantic knowledge retrieval, and local constrained LLM triage directly resolves the core trade-offs between precision, speed, explainability, and code privacy.

---

## References (15 Q1 Papers)
1. **VulDeePecker:** Z. Li et al., NDSS 2018.
2. **SySeVR:** Z. Li et al., IEEE TDSC 2021.
3. **Devign:** Y. Zhou et al., NeurIPS 2019.
4. **ReVeal:** S. Chakraborty et al., ICSE 2021.
5. **LineVul:** M. Fu & C. Tantithamthavorn, MSR 2022.
6. **UniXcoder:** D. Guo et al., ACL 2022.
7. **CVEfixes:** G. Bhandari et al., MSR 2021.
8. **DiverseVul:** Y. Chen et al., RAID 2023.
9. **GPTScan:** Y. Sun et al., ICSE 2024.
10. **DeepDFA:** B. Steenhoek et al., ICSE 2024.
11. **PDBERT:** Z. Liu et al., ICSE 2024.
12. **Vul-RAG:** X. Du et al., ACM TOSEM 2024.
13. **LLMxCPG:** A. Lekssays et al., USENIX Security 2025.
14. **PrimeVul:** Y. Zhang et al., ICSE 2025.
15. **Chasing Shadows:** D. Arp et al., NDSS 2026.
