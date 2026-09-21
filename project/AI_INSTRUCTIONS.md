# AI Agent & Subagent Operational Instructions

## Project: AST-Guided RAG Software Vulnerability Detection and Triage
**Target Audience:** Autonomous AI Assistants, Pair Programmers, and LLM Subagents  

---

## 1. Core Architectural Directives

When modifying, extending, or maintaining this codebase, all AI agents must strictly adhere to the following architectural invariants:

### Invariant 1: Pure Determinism in Stage 1
* **Rule:** Stage 1 (AST parsing and program slicing) must remain **100% deterministic and algorithmic**.
* **Forbidden:** Never use an LLM or heuristic probabilistic model to generate, guess, or filter code slices.
* **Requirement:** All AST traversals, taint source-to-sink tracking, and backward/forward slice extractions must be implemented via `tree-sitter` and deterministic graph algorithms (DFG/CFG traversals).

### Invariant 2: The 150-Token Slicing Invariant
* **Rule:** Slices produced by `src/parser/slicer.py` should target $\le 150\text{ tokens}$ (hard limit: 200 tokens).
* **Rationale:** As proven by *LLMxCPG* (USENIX Security 2025) and *PrimeVul* (ICSE 2025), prompt bloat degrades LLM self-attention and spikes hallucinated findings.
* **Pruning Hierarchy:** If a slice exceeds 150 tokens:
  1. Retain the sink invocation and immediate operands.
  2. Retain the untrusted source call.
  3. Retain branch control guards (`if`, `while`) governing the sink.
  4. Retain pointer allocations (`malloc`, `calloc`) and deallocations (`free`).
  5. Prune all independent intermediate computations, logging statements, and unrelated assignments.

### Invariant 3: Contrastive RAG Grounding
* **Rule:** Never submit a raw code slice to the LLM without external grounding.
* **Requirement:** The prompt must inject:
  1. Formal structural rules from NIST CWE Top 25 (invariants, preconditions, failure modes).
  2. At least one real-world vulnerability-patch commit diff from `cve_patch_pairs`.
* **Rationale:** *Vul-RAG* (ACM TOSEM 2024) proved that LLMs suffer from "patch-blindness" unless explicitly shown how similar code was remediated.

### Invariant 4: Zero Freeform Conversational Prose
* **Rule:** The LLM inference engine must strictly enforce constrained decoding via Pydantic v2 schemas and GBNF grammars.
* **Forbidden:** Never allow the model to prepend or append conversational prose (e.g., *"Sure! Here is the vulnerability report:"* or *"In conclusion, the code is safe."*).
* **Output Format:** Output must parse directly as a valid instance of `VulnerabilityTriageReport`.

### Invariant 5: Air-Gap & Privacy Preservation
* **Rule:** Under no circumstances should proprietary commercial cloud APIs (OpenAI GPT-4, Anthropic Claude, Google Gemini) be introduced into the core scan pipeline.
* **Requirement:** All inference must execute via local, quantized open-weight models (`Qwen2.5-Coder-7B-Instruct` or `DeepSeek-Coder-6.7B-Instruct`) hosted via `llama-cpp-python`, `Ollama`, or `vLLM`.

---

## 2. Standardized Prompt Template Specification

When assembling prompts in `src/triage/prompt_builder.py`, agents must follow this exact prompt structure:

```text
[SYSTEM PROMPT]
You are a deterministic, precision-oriented software security triage engine.
Your sole function is to evaluate the provided C/C++ AST code slice against the retrieved Common Weakness Enumeration (CWE) specifications and historical CVE patch patterns.
You must output ONLY a valid JSON object matching the requested schema. No conversational prose is permitted.

[SECURITY KNOWLEDGE CONTEXT]
Weakness Class: {cwe_id} - {cwe_name}
Vulnerability Invariant: {cwe_rule_summary}
Preconditions for Exploitability:
{cwe_preconditions}

Historical Remediated Example:
```c
{historical_patch_diff}
```

[ANALYZED PROGRAM SLICE]
File: {source_file}
Target Sink: {sink_function} at line {sink_line}
Tainted Variable: {taint_variable}
Source Code Slice:
```c
{slice_code}
```

[TASK]
1. Determine if an attacker can control {taint_variable} reaching {sink_function} without adequate sanitization or boundary verification.
2. Confirm exploitability: Is this a genuine exploitable vulnerability, a suspicious unverified risk, or a benign false positive?
3. Pinpoint exact line numbers in the original file.
4. Provide an actionable unified remediation patch.
```

---

## 3. Code Generation & Refactoring Standards

When writing Python code for this repository:
1. **Typing:** Use Python 3.10+ union types (`int | None`) and strict type annotations across all function signatures.
2. **Pydantic Models:** Use Pydantic v2 syntax (`model_validate_json`, `Field(default=...)`, `model_dump()`).
3. **Error Resilience:** Tree-sitter AST nodes may occasionally encounter syntax errors in incomplete code snippets. All node traversal functions must guard against `node is None` and handle `ERROR` AST nodes gracefully without unhandled exceptions.
4. **Unit Tests:** Any new feature in `parser/`, `rag/`, or `triage/` must be accompanied by corresponding unit tests in `tests/`.
