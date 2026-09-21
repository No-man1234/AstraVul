# Group Reading & Literature Review Assignment Guide
**Project:** AstraVul — AST-Guided Retrieval-Augmented Generation for Automated Software Vulnerability Detection and Triage  
**Department of Computer Science and Engineering, United International University (UIU)**  
**Target:** 5 Members $\times$ 3 Papers each = 15 Premier Q1 Papers

---

## Instructions for Each Member
1. Read the 3 papers assigned to your theme.
2. Prepare a **1 to 2 page individual report** summarizing:
   - **Core Findings:** What did each paper discover, invent, or prove?
   - **Critical Limitations:** What are the drawbacks, failure modes, or research gaps left unsolved?
   - **Project Connection:** How does your set of papers justify our project's 3-stage architecture (Tree-sitter AST Slicer $\rightarrow$ ChromaDB RAG $\rightarrow$ Local LLM Triage)?

---

## Member 1: Abdullah Al Noman — Foundational Program Slicing & Graph Deep Learning
*Focus: Tracing vulnerability flows using program slices and graph neural networks.*

### 1. VulDeePecker (NDSS 2018)
* **Title:** VulDeePecker: A Deep Learning-Based System for Vulnerability Detection
* **Authors:** Z. Li, D. Zou, S. Xu, X. Ou, H. Jin, S. Wang, Z. Deng, Y. Zhong
* **Core Findings:** First system to prove that deep learning on localized **"code gadgets"** (backward slices extracted around library/API call sinks) dramatically outperforms classifying entire functions.
* **Limitations:** Only monitors library API function calls (ignoring user-defined functions); restricted to sequential dataflow without control-dependency awareness.

### 2. SySeVR (IEEE TDSC 2021)
* **Title:** SySeVR: A Framework for Using Deep Learning to Detect Software Vulnerabilities
* **Authors:** Z. Li, D. Zou, S. Xu, Z. Chen, Y. Zhu, H. Jin
* **Core Findings:** Generalized VulDeePecker by formalizing **Syntax-, Semantics-, and Vulnerability-related Slices (SeVCs)**. Used bidirectional slicing across both Control Flow Graphs (CFG) and Data Flow Graphs (DFG), successfully detecting 15 zero-day vulnerabilities in production code.
* **Limitations:** Relies on sequential neural networks (BBiRNN/BLSTM) which lose long-range graph topologies; lacks semantic reasoning about complex logic or exploitability.

### 3. Devign (NeurIPS 2019)
* **Title:** Devign: Effective Vulnerability Identification by Learning Comprehensive Program Semantics via Graph Neural Networks
* **Authors:** Y. Zhou, S. Liu, J. Siow, X. Du, Y. Liu
* **Core Findings:** Proved that ASTs alone are insufficient. Devign unified AST, CFG, DFG, and natural code sequences into a single **Composite Code Property Graph (CPG)**, trained via Gated Graph Neural Networks (GGNN) to identify intricate memory corruption flaws.
* **Limitations:** High computational overhead to generate complete CPGs; operates as an uninterpretable black box without generating human-readable root-cause explanations or fixes.

---

## Member 2: Kazi Neyamul Hasan — Benchmark Realities, Dataset Biases & Real-World CVEs
*Focus: Why synthetic benchmarks fail and how real-world CVE commit diffs expose model flaws.*

### 4. ReVeal (ICSE 2021)
* **Title:** Deep Learning for Vulnerability Detection: Are We There Yet?
* **Authors:** S. Chakraborty, R. Krishna, Y. Ding, B. Ray
* **Core Findings:** Conducted the first rigorous reality-check of DL vulnerability detectors. Discovered that models trained on synthetic benchmarks (e.g., NIST Juliet) drastically overfit to artificial syntax patterns and experience catastrophic drops in precision when tested on real-world repositories (Chromium, Debian).
* **Limitations:** Identified the severe fragility and false positive problem of graph models, but did not propose an actionable remediation or triage architecture.

### 5. CVEfixes (MSR 2021)
* **Title:** CVEfixes: Automated Collection of Vulnerabilities and Their Fixes from Open-Source Software
* **Authors:** G. Bhandari, A. Naseer, L. Moonen
* **Core Findings:** Built an automated collection engine that maps CVE records from the National Vulnerability Database (NVD) directly to their security fix commit diffs (5,495 CVEs across 11,000 commits), establishing a standardized benchmark for vulnerability remediation.
* **Limitations:** Uncurated raw commit diffs contain substantial noise (e.g., refactorings, style edits, and documentation updates bundled together with security patches).

### 6. DiverseVul (RAID 2023)
* **Title:** DiverseVul: A New Vulnerable Source Code Dataset for Deep Learning Based Vulnerability Detection
* **Authors:** Y. Chen, Z. Ding, L. Chelly, D. Lo
* **Core Findings:** Analyzed 7.5k commits across 150 CWEs and revealed that **up to 48% of labels in previous datasets (like Big-Vul) were noisy or incorrect**. DiverseVul established the largest curated real-world C/C++ dataset (18,945 vulnerable functions).
* **Limitations:** Provides whole-function level samples rather than precise line-level or slice-level annotations, requiring downstream tools to perform their own causal localization.

---

## Member 3: Rakibul Hassan — Code Embeddings, Pre-training & Line-Level Localization
*Focus: Representing code semantics densely and pinpointing exact vulnerable lines.*

### 7. UniXcoder (ACL 2022)
* **Title:** UniXcoder: Unified Cross-Modal Pre-training for Code Representation
* **Authors:** D. Guo, S. Lu, N. Duan, Y. Wang, M. Zhou, J. Yin
* **Core Findings:** Developed a state-of-the-art multi-modal pre-trained encoder that unifies code comments, AST prefix sequences, and tokens using structured cross-attention masks, setting high benchmarks in dense code-to-code similarity search.
* **Limitations:** General-purpose code representation model; lacks domain-specific taint analysis or exploitability reasoning required for security auditing.

### 8. LineVul (MSR 2022)
* **Title:** LineVul: A Transformer-based Line-level Vulnerability Prediction
* **Authors:** M. Fu, C. Tantithamthavorn
* **Core Findings:** Demonstrated that function-level vulnerability alerts are too coarse for developers. LineVul leverages CodeBERT self-attention weights to localize flaws to exact source code lines, reducing manual inspection effort by over 80%.
* **Limitations:** Operates purely on lexical token sequences without formal compiler dataflow tracking; can be deceived when a flaw’s root cause is structurally distant from the flagged line.

### 9. PDBERT (ICSE 2024)
* **Title:** Pre-training by Predicting Program Dependencies for Vulnerability Analysis Tasks
* **Authors:** Z. Liu, Z. Tang, J. Zhang, X. Xia, X. Yang
* **Core Findings:** Proposed a pre-training objective based on Program Dependence: Control Dependency Prediction (CDP) and Data Dependency Prediction (DDP). Achieved **23$\times$ higher throughput** than heavy static analyzers (like Joern) while retaining graph-aware understanding.
* **Limitations:** Focuses on pre-training representations; still requires task-specific downstream classifiers or LLMs to determine whether an active exploit path exists.

---

## Member 4: Mahathir Mohammad — Neuro-Symbolic Hybrids & Compiler-Guided Slicing
*Focus: Combining static compiler tools with LLMs to eliminate hallucinations and token waste.*

### 10. GPTScan (ICSE 2024)
* **Title:** GPTScan: Detecting Logic Vulnerabilities in Smart Contracts by Combining GPT with Program Analysis
* **Authors:** Y. Sun, D. Wu, Y. Xue, H. Liu, H. Wang, Z. Xu, Y. Liu
* **Core Findings:** Pioneered a neuro-symbolic hybrid pipeline: static analysis scans for candidate vulnerability scenarios, and an LLM evaluates logic constraints and exploitability, achieving $>90\%$ precision.
* **Limitations:** Built for smart contracts; relied on closed proprietary cloud APIs (GPT-3.5), exposing proprietary code and risking intellectual property leakage.

### 11. DeepDFA (ICSE 2024)
* **Title:** Dataflow Analysis-Inspired Deep Learning for Efficient Vulnerability Detection
* **Authors:** B. Steenhoek, H. Gao, W. Le
* **Core Findings:** Integrated formal compiler dataflow facts (reaching definitions and def-use chains) as compact bit-vectors into neural graph representations, preventing deep models from learning superficial token shortcuts.
* **Limitations:** Focuses on discriminative classification; cannot generate actionable remediation patches or explain the underlying failure modes.

### 12. LLMxCPG (USENIX Security 2025)
* **Title:** LLMxCPG: Context-Aware Vulnerability Detection through Code Property Graph-Guided Large Language Models
* **Authors:** A. Lekssays et al.
* **Core Findings:** Proved that passing entire raw files into LLMs degrades performance. Querying Code Property Graphs to extract minimal cross-function slices **pruned 67.8%–90.9% of code volume**, improved downstream LLM F1-scores by 15%–40%, and conferred adversarial robustness.
* **Limitations:** Generating full CPGs across entire repositories remains computationally intensive; lacks external RAG knowledge integration to verify patch boundaries.

---

## Member 5: Md. habibulla Misba — RAG, LLM Pitfalls & False Discovery Rate (FDR)
*Focus: Why raw LLMs collapse and how Retrieval-Augmented Generation solves patch-blindness.*

### 13. Vul-RAG (ACM TOSEM 2024)
* **Title:** Vul-RAG: Enhancing LLM-Based Vulnerability Detection via Knowledge-Level RAG
* **Authors:** X. Du, X. Xu, Y. Wang et al.
* **Core Findings:** Identified **"patch-blindness"**—the failure of LLMs to distinguish vulnerable code from safe, patched code. Vul-RAG solved this by retrieving NIST CWE rules, CVE descriptions, and patch diffs into the LLM context, boosting accuracy by 16%–24%.
* **Limitations:** Fed whole raw functions into cloud GPT-4, incurring high token costs, latency bottlenecks, and zero confidentiality for proprietary code.

### 14. PrimeVul / "How Far Are We?" (ICSE 2025)
* **Title:** Vulnerability Detection with Code Language Models: How Far Are We?
* **Authors:** Y. Zhang, W. Wang et al.
* **Core Findings:** Benchmarked modern code LLMs on a rigorously debiased real-world dataset. Found that a 7B LLM achieving 68.3% F1 on historical datasets collapsed to a mere **3.1% F1 on debiased real-world data**, with zero-shot LLMs performing near random guessing without explicit structural context.
* **Limitations:** Validated that raw LLM querying is unreliable for security auditing, providing the critical justification for our hybrid slicing + RAG approach.

### 15. Chasing Shadows (NDSS 2026)
* **Title:** Chasing Shadows: Pitfalls in LLM Security Research
* **Authors:** D. Arp, E. Quiring et al.
* **Core Findings:** Systematically audited 72 peer-reviewed security papers and exposed **9 major methodological pitfalls** (data leakage, improper metric optimization). Mandated that security systems must report and minimize the **False Discovery Rate (FDR)** ($\frac{\text{FP}}{\text{TP} + \text{FP}}$).
* **Limitations:** A meta-evaluation and critique paper; defines the rigorous evaluation standards that modern tools must fulfill.
