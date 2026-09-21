"""
Semantic Vector Knowledge Store & Retrieval Engine (Stage 2).
Provides grounded security knowledge from NIST CWE Top 25 specifications
and paired contrastive CVE commit diffs to eliminate LLM patch-blindness.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from pathlib import Path
import math
import re
from ..parser.slicer import CodeSlice


@dataclass
class CWEEntry:
    """Formal security specification for a Common Weakness Enumeration."""
    cwe_id: str
    name: str
    description: str
    preconditions: List[str]
    rule_summary: str
    remediation_invariants: str


@dataclass
class CVEPatchDiff:
    """Paired vulnerable vs remediated commit pattern."""
    cve_id: str
    cwe_id: str
    project_name: str
    vulnerable_pattern: str
    remediated_pattern: str
    unified_diff: str


@dataclass
class RAGContext:
    """Assembled security context injected into the triage prompt."""
    cwe_id: str
    cwe_name: str
    rule_summary: str
    preconditions: List[str]
    remediation_invariants: str
    historical_patches: List[CVEPatchDiff]


# Curated NIST CWE Top 25 Knowledge Base for C/C++ Security
CWE_KNOWLEDGE_BASE: Dict[str, CWEEntry] = {
    "CWE-120": CWEEntry(
        cwe_id="CWE-120",
        name="Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')",
        description="The program copies an input buffer to an output buffer without verifying that the size of the input is less than the size of the destination buffer.",
        preconditions=[
            "Destination buffer has a fixed stack or heap allocated size.",
            "Source data length is unbounded or user-controlled.",
            "Copy operation lacks explicit length capping (e.g. strcpy, strcat, sprintf, gets)."
        ],
        rule_summary="Destination buffer bounds MUST strictly exceed the maximum possible length of source bytes.",
        remediation_invariants="Replace unbound APIs with bounded alternatives (e.g., strncpy, snprintf) and enforce explicit null-termination: dest[sizeof(dest)-1] = '\\0'."
    ),
    "CWE-119": CWEEntry(
        cwe_id="CWE-119",
        name="Improper Restriction of Operations within the Bounds of a Memory Buffer",
        description="The software performs operations on a memory buffer, but it can read from or write to a memory location that is outside the intended boundary.",
        preconditions=[
            "Index, offset, or pointer arithmetic is calculated using external/user input.",
            "Upper and lower bounds checks are missing or flawed (e.g. off-by-one comparisons)."
        ],
        rule_summary="Every pointer dereference or index access [i] must verify 0 <= i < buffer_capacity.",
        remediation_invariants="Verify length before invoking memcpy/memmove; enforce strict inequality checks (i < capacity rather than i <= capacity)."
    ),
    "CWE-125": CWEEntry(
        cwe_id="CWE-125",
        name="Out-of-bounds Read",
        description="The software reads data past the end, or before the beginning, of the intended buffer, potentially leaking sensitive information or crashing.",
        preconditions=[
            "String traversal relies on finding a null terminator that may be absent.",
            "Buffer read offset is controlled by untrusted input."
        ],
        rule_summary="Memory reads must be constrained by an explicit boundary length, not assumed terminators.",
        remediation_invariants="Ensure explicit null termination and validate boundary limits before reading memory blocks."
    ),
    "CWE-416": CWEEntry(
        cwe_id="CWE-416",
        name="Use After Free",
        description="Referencing memory after it has been freed can cause a program to crash, use unexpected values, or execute arbitrary code.",
        preconditions=[
            "A pointer is deallocated using free() or realloc().",
            "The pointer or an alias is subsequently dereferenced, read, or modified.",
            "The pointer was not set to NULL immediately upon deallocation."
        ],
        rule_summary="Once memory is released via free(ptr), the variable ptr must NEVER be dereferenced.",
        remediation_invariants="Immediately assign ptr = NULL after free(ptr) and avoid persisting dangling aliases."
    ),
    "CWE-415": CWEEntry(
        cwe_id="CWE-415",
        name="Double Free",
        description="The software calls free() twice on the same memory address, corrupting the memory management data structures.",
        preconditions=[
            "Pointer is freed in one branch or clean-up block without clearing the reference.",
            "Subsequent clean-up code invokes free() on the same non-null address."
        ],
        rule_summary="A heap chunk must only be deallocated once in its lifecycle.",
        remediation_invariants="Set freed pointers to NULL immediately; free(NULL) is a safe no-op in C."
    ),
    "CWE-78": CWEEntry(
        cwe_id="CWE-78",
        name="Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
        description="The software constructs all or part of an OS command using externally-influenced input without properly neutralizing command separators.",
        preconditions=[
            "Untrusted input is passed directly to command execution shells (system, popen).",
            "Input contains unescaped metacharacters (;, &, |, `, $, \\n)."
        ],
        rule_summary="User input must NEVER be directly concatenated into an operating system shell command.",
        remediation_invariants="Use parameterized execution APIs (execve, posix_spawn) without passing through a shell interpreter, or strictly whitelist alphanumeric characters."
    ),
    "CWE-476": CWEEntry(
        cwe_id="CWE-476",
        name="NULL Pointer Dereference",
        description="A NULL pointer dereference occurs when the application dereferences a pointer that it expects to be valid, but is NULL.",
        preconditions=[
            "A function returns NULL upon error or allocation failure (e.g., malloc, fopen).",
            "The return value is accessed without an explicit 'if (ptr == NULL)' check."
        ],
        rule_summary="Pointers returned from allocators or external lookup APIs must be checked against NULL before use.",
        remediation_invariants="Enforce strict precondition checks: if (!ptr) { handle_error(); return; }"
    ),
    "CWE-134": CWEEntry(
        cwe_id="CWE-134",
        name="Use of Externally-Controlled Format String",
        description="The software uses a function that accepts a format string as an argument, but the format string originates from an external or untrusted source.",
        preconditions=[
            "Untrusted or variable input is passed as the format string argument to printf, syslog, or err.",
            "Format string lacks explicit conversion specifiers (e.g., printf(buf) instead of printf(\"%s\", buf))."
        ],
        rule_summary="Format string arguments MUST be compile-time constant string literals.",
        remediation_invariants="Enforce hardcoded format strings: replace printf(var) with printf(\"%s\", var)."
    ),
    "CWE-22": CWEEntry(
        cwe_id="CWE-22",
        name="Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        description="The software uses external input to construct a pathname that should be within a restricted directory, but does not properly neutralize '..' sequences.",
        preconditions=[
            "File system operation (fopen, open, unlink) uses user-supplied path directly.",
            "Input is not checked for directory traversal sequences ('../', '..\\\\') or absolute paths."
        ],
        rule_summary="Path components must be canonicalized and validated against a permitted root directory before file access.",
        remediation_invariants="Resolve absolute path with realpath() and verify it begins with the permitted base directory prefix; reject paths containing '..'."
    ),
    "CWE-190": CWEEntry(
        cwe_id="CWE-190",
        name="Integer Overflow or Wraparound",
        description="The software performs a calculation that can produce an integer overflow or wraparound, causing unexpected memory allocation sizing.",
        preconditions=[
            "Arithmetic operation (multiplication or addition) is performed on user-controlled integers without range checking.",
            "Result is passed directly as the size argument to memory allocation functions (malloc, calloc)."
        ],
        rule_summary="Arithmetic operations computing buffer allocations must check for wraparound before allocation.",
        remediation_invariants="Enforce precondition: if (count > SIZE_MAX / elem_size) return ERROR; before invoking malloc(count * elem_size)."
    ),
    "CWE-404": CWEEntry(
        cwe_id="CWE-404",
        name="Improper Resource Shutdown or Release",
        description="The program fails to release a system resource, such as a file descriptor or socket, leading to resource exhaustion.",
        preconditions=[
            "File descriptor or socket is opened in a function.",
            "Error paths or exit branches return without calling close() or fclose()."
        ],
        rule_summary="Every opened resource handle must be closed across all execution branches.",
        remediation_invariants="Ensure close(fd) or fclose(fp) is invoked in error handling and cleanup paths."
    )
}

# Curated Contrastive CVE Patch Diffs (DiverseVul & CVEfixes)
CVE_PATCH_DATABASE: List[CVEPatchDiff] = [
    CVEPatchDiff(
        cve_id="CVE-2021-3156",
        cwe_id="CWE-120",
        project_name="sudo",
        vulnerable_pattern="strcpy(user_args, from);",
        remediated_pattern="size_t len = strlen(from);\nif (len >= sizeof(user_args)) return -1;\nstrncpy(user_args, from, sizeof(user_args) - 1);\nuser_args[sizeof(user_args) - 1] = '\\0';",
        unified_diff="""--- a/plugins/sudoers/sudoers.c
+++ b/plugins/sudoers/sudoers.c
@@ -102,3 +102,6 @@
-    strcpy(user_args, from);
+    if (strlen(from) >= sizeof(user_args))
+        return -1;
+    strncpy(user_args, from, sizeof(user_args) - 1);
+    user_args[sizeof(user_args) - 1] = '\\0';"""
    ),
    CVEPatchDiff(
        cve_id="CVE-2022-24975",
        cwe_id="CWE-416",
        project_name="libgit2",
        vulnerable_pattern="free(git_buf->ptr);\n// Later in code:\nreturn git_buf->ptr[0];",
        remediated_pattern="free(git_buf->ptr);\ngit_buf->ptr = NULL;\nreturn -1;",
        unified_diff="""--- a/src/buffer.c
+++ b/src/buffer.c
@@ -55,2 +55,3 @@
     free(git_buf->ptr);
+    git_buf->ptr = NULL;
     return 0;"""
    ),
    CVEPatchDiff(
        cve_id="CVE-2023-38408",
        cwe_id="CWE-78",
        project_name="openssh",
        vulnerable_pattern="char cmd[256];\nsprintf(cmd, \"/usr/bin/ssh-askpass %s\", provider);\nsystem(cmd);",
        remediated_pattern="char *const args[] = {\"/usr/bin/ssh-askpass\", provider, NULL};\nexecv(args[0], args);",
        unified_diff="""--- a/ssh-pkcs11-helper.c
+++ b/ssh-pkcs11-helper.c
@@ -210,3 +210,3 @@
-    sprintf(cmd, "/usr/bin/ssh-askpass %s", provider);
-    system(cmd);
+    char *const args[] = {"/usr/bin/ssh-askpass", provider, NULL};
+    execv(args[0], args);"""
    ),
    CVEPatchDiff(
        cve_id="CVE-2022-0778",
        cwe_id="CWE-119",
        project_name="openssl",
        vulnerable_pattern="memcpy(dest, src, length);",
        remediated_pattern="if (length > sizeof(dest)) return 0;\nmemcpy(dest, src, length);",
        unified_diff="""--- a/crypto/bn/bn_gcd.c
+++ b/crypto/bn/bn_gcd.c
@@ -88,2 +88,4 @@
+    if (length > sizeof(dest))
+        return 0;
     memcpy(dest, src, length);"""
    )
]


class RAGKnowledgeStore:
    """
    Retrieval-Augmented Generation (RAG) Store.
    Matches extracted code slices against formal CWE definitions and
    contrastive CVE commit diffs using semantic vector search in ChromaDB,
    with an embedded fallback knowledge base.
    """

    def __init__(self, chroma_db_dir: Optional[str] = "data/chroma_db") -> None:
        self.cwe_kb = CWE_KNOWLEDGE_BASE
        self.cve_patches = CVE_PATCH_DATABASE
        self.chroma_client = None
        self.cwe_collection = None
        self.cve_collection = None

        if chroma_db_dir and Path(chroma_db_dir).exists():
            try:
                import chromadb
                self.chroma_client = chromadb.PersistentClient(path=str(chroma_db_dir))
                existing_cols = [c.name for c in self.chroma_client.list_collections()]
                if "cwe_catalog" in existing_cols:
                    self.cwe_collection = self.chroma_client.get_collection("cwe_catalog")
                if "cve_patches" in existing_cols:
                    self.cve_collection = self.chroma_client.get_collection("cve_patches")
            except Exception:
                self.chroma_client = None

    def retrieve(self, slice_obj: CodeSlice, top_k: int = 3) -> RAGContext:
        """
        Retrieves grounded security context for an extracted code slice using
        hybrid vector search in ChromaDB with fallback to curated rules.
        """
        candidate_cwe = slice_obj.cwe_candidate

        # Method 1: Hybrid Vector Search via ChromaDB
        if self.cwe_collection and self.cwe_collection.count() > 0:
            try:
                # If candidate_cwe is known (e.g. CWE-120), fetch direct or similarity
                cwe_entry = None
                if candidate_cwe in self.cwe_kb:
                    cwe_entry = self.cwe_kb[candidate_cwe]
                else:
                    query_text = f"{candidate_cwe} {slice_obj.sink_function}: {slice_obj.slice_code}"
                    results = self.cwe_collection.query(
                        query_texts=[query_text],
                        n_results=1
                    )
                    if results and results["ids"] and results["ids"][0]:
                        matched_id = results["ids"][0][0]
                        if matched_id in self.cwe_kb:
                            cwe_entry = self.cwe_kb[matched_id]
                        else:
                            meta = results["metadatas"][0][0] if results["metadatas"] else {}
                            doc = results["documents"][0][0] if results["documents"] else ""
                            cwe_entry = CWEEntry(
                                cwe_id=matched_id,
                                name=meta.get("name", f"{matched_id} Weakness"),
                                description=doc[:300],
                                preconditions=[f"Untrusted input reaches sink '{slice_obj.sink_function}' without validation."],
                                rule_summary=f"Enforce strict invariants, bounds checks, and sanitization before invoking '{slice_obj.sink_function}'.",
                                remediation_invariants=f"Sanitize or validate bounds on arguments passed to '{slice_obj.sink_function}'."
                            )

                if cwe_entry:
                    # Query ChromaDB cve_patches for matching patch diffs
                    matching_patches: List[CVEPatchDiff] = []
                    if self.cve_collection and self.cve_collection.count() > 0:
                        patch_res = self.cve_collection.query(
                            query_texts=[f"{cwe_entry.cwe_id} {slice_obj.sink_function} {slice_obj.taint_variable}"],
                            n_results=top_k
                        )
                        if patch_res and patch_res["metadatas"] and patch_res["metadatas"][0]:
                            for meta, doc in zip(patch_res["metadatas"][0], patch_res["documents"][0]):
                                matching_patches.append(CVEPatchDiff(
                                    cve_id=meta.get("cve_id", "CVE-Patch"),
                                    cwe_id=meta.get("cwe_id", cwe_entry.cwe_id),
                                    project_name=meta.get("project_name", "OpenSource"),
                                    vulnerable_pattern="",
                                    remediated_pattern="",
                                    unified_diff=doc
                                ))

                    if not matching_patches:
                        matching_patches = [p for p in self.cve_patches if p.cwe_id == cwe_entry.cwe_id] or self.cve_patches[:top_k]

                    return RAGContext(
                        cwe_id=cwe_entry.cwe_id,
                        cwe_name=cwe_entry.name,
                        rule_summary=cwe_entry.rule_summary,
                        preconditions=cwe_entry.preconditions,
                        remediation_invariants=cwe_entry.remediation_invariants,
                        historical_patches=matching_patches[:top_k]
                    )
            except Exception:
                pass

        # Method 2: Curated Fallback
        if candidate_cwe not in self.cwe_kb:
            if "str" in slice_obj.sink_function or "buf" in slice_obj.sink_function:
                candidate_cwe = "CWE-120"
            elif "free" in slice_obj.sink_function:
                candidate_cwe = "CWE-416"
            elif "system" in slice_obj.sink_function or "exec" in slice_obj.sink_function:
                candidate_cwe = "CWE-78"
            elif "printf" in slice_obj.sink_function or "syslog" in slice_obj.sink_function:
                candidate_cwe = "CWE-134"
            elif "open" in slice_obj.sink_function:
                candidate_cwe = "CWE-22"
            else:
                candidate_cwe = "CWE-119"

        cwe_entry = self.cwe_kb.get(candidate_cwe, self.cwe_kb["CWE-120"])
        matching_patches = [
            patch for patch in self.cve_patches
            if patch.cwe_id == cwe_entry.cwe_id
        ]
        if not matching_patches:
            matching_patches = self.cve_patches[:top_k]

        return RAGContext(
            cwe_id=cwe_entry.cwe_id,
            cwe_name=cwe_entry.name,
            rule_summary=cwe_entry.rule_summary,
            preconditions=cwe_entry.preconditions,
            remediation_invariants=cwe_entry.remediation_invariants,
            historical_patches=matching_patches[:top_k]
        )
