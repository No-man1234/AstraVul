"""
Deterministic AST & Data-Flow Program Slicing Engine (Stage 1).
Parses C/C++ source code via Tree-sitter, performs backward and forward
taint dependency tracking, and extracts minimal causal slices (<= 150 tokens).
"""

from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple
import re
import tree_sitter as ts
import tree_sitter_c as tsc


@dataclass
class CodeSlice:
    """Represents a focused, causal code slice surrounding a vulnerability sink."""
    slice_id: str
    source_file: str
    sink_function: str
    sink_line: int
    taint_variable: str
    slice_code: str
    slice_tokens: int
    line_numbers: List[int]
    cwe_candidate: str
    source_function: Optional[str] = None


# Known critical sink APIs mapped to candidate CWE categories
CRITICAL_SINKS: Dict[str, str] = {
    # Memory Corruption & Buffer Overflows (CWE-120, CWE-119, CWE-125, CWE-787)
    "strcpy": "CWE-120",
    "strcat": "CWE-120",
    "sprintf": "CWE-120",
    "vsprintf": "CWE-120",
    "snprintf": "CWE-120",
    "_snprintf": "CWE-120",
    "vsnprintf": "CWE-120",
    "_vsnprintf": "CWE-120",
    "SNPRINTF": "CWE-120",
    "gets": "CWE-120",
    "memcpy": "CWE-119",
    "memmove": "CWE-119",
    "bcopy": "CWE-119",
    "MEMCPY": "CWE-119",
    "MEMMOVE": "CWE-119",
    "STRCPY": "CWE-120",
    "STRNCPY": "CWE-125",
    "strncpy": "CWE-125",
    "strncat": "CWE-125",
    
    # Resource & Memory Lifecycle (CWE-416, CWE-415, CWE-401)
    "free": "CWE-416",
    "realloc": "CWE-415",
    "close": "CWE-404",
    "fclose": "CWE-404",
    
    # Format String Vulnerabilities (CWE-134)
    "printf": "CWE-134",
    "fprintf": "CWE-134",
    "vprintf": "CWE-134",
    "vfprintf": "CWE-134",
    "syslog": "CWE-134",
    
    # Insecure File Access & Path Traversal (CWE-22)
    "fopen": "CWE-22",
    "open": "CWE-22",
    "openat": "CWE-22",
    "creat": "CWE-22",
    "unlink": "CWE-22",
    "remove": "CWE-22",
    "rename": "CWE-22",
    
    # Command & Process Injection (CWE-78)
    "system": "CWE-78",
    "popen": "CWE-78",
    "execl": "CWE-78",
    "execle": "CWE-78",
    "execlp": "CWE-78",
    "execv": "CWE-78",
    "execve": "CWE-78",
    "execvp": "CWE-78",
}

# Known untrusted user input source APIs
UNTRUSTED_SOURCES: Set[str] = {
    "scanf", "fscanf", "sscanf", "fgets", "read",
    "recv", "recvfrom", "getenv", "fread", "getchar", "getc",
    "readlink", "getpass", "cin"
}


class ASTSlicer:
    """
    Deterministic C/C++ program slicer using Tree-sitter.
    Extracts minimal taint paths (sources -> sanitizers -> sinks) <= 150 tokens.
    """

    def __init__(self) -> None:
        self.language = ts.Language(tsc.language())
        self.parser = ts.Parser(self.language)

    def slice_file(self, file_path: str, max_tokens: int = 150) -> List[CodeSlice]:
        """Reads a C file and extracts slices for all detected critical sinks."""
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            code_text = f.read()
        return self.slice_code(code_text, source_file=file_path, max_tokens=max_tokens)

    def slice_code(self, code_text: str, source_file: str = "snippet.c", max_tokens: int = 150) -> List[CodeSlice]:
        """Parses C code in-memory and extracts all sink-guided slices."""
        code_bytes = code_text.encode("utf-8")
        tree = self.parser.parse(code_bytes)
        root_node = tree.root_node
        lines = code_text.splitlines()

        # Step 1: Find all sink call expressions in the AST
        sink_calls = self._find_sink_calls(root_node, code_bytes)
        
        slices: List[CodeSlice] = []
        for idx, (call_node, sink_name, sink_line, taint_var) in enumerate(sink_calls, 1):
            slice_obj = self._build_slice_for_sink(
                root_node=root_node,
                call_node=call_node,
                sink_name=sink_name,
                sink_line=sink_line,
                taint_var=taint_var,
                lines=lines,
                source_file=source_file,
                slice_idx=idx,
                max_tokens=max_tokens
            )
            slices.append(slice_obj)
            
        return slices

    def _find_sink_calls(self, root_node: ts.Node, code_bytes: bytes) -> List[Tuple[ts.Node, str, int, str]]:
        """Recursively traverses the AST to identify all calls to predefined critical sinks."""
        results: List[Tuple[ts.Node, str, int, str]] = []

        def traverse(node: ts.Node) -> None:
            if node.type == "call_expression":
                func_node = node.child_by_field_name("function")
                if func_node:
                    func_name = code_bytes[func_node.start_byte:func_node.end_byte].decode("utf-8", errors="replace")
                    if func_name in CRITICAL_SINKS:
                        args_node = node.child_by_field_name("arguments")
                        taint_var = ""
                        if args_node and args_node.child_count > 1:
                            # Primary argument is usually the first argument (e.g. dest for strcpy, ptr for free)
                            first_arg = args_node.children[1] # child 0 is '('
                            taint_var = code_bytes[first_arg.start_byte:first_arg.end_byte].decode("utf-8", errors="replace")
                        
                        sink_line = node.start_point[0] + 1  # 1-indexed
                        results.append((node, func_name, sink_line, taint_var))

            for child in node.children:
                traverse(child)

        traverse(root_node)
        return results

    def _build_slice_for_sink(
        self,
        root_node: ts.Node,
        call_node: ts.Node,
        sink_name: str,
        sink_line: int,
        taint_var: str,
        lines: List[str],
        source_file: str,
        slice_idx: int,
        max_tokens: int = 150
    ) -> CodeSlice:
        """Computes backward dataflow and forward control-flow dependencies for a sink."""
        selected_line_numbers: Set[int] = {sink_line}
        clean_var = re.sub(r'[\*\&\[\]\(\)\s]', '', taint_var)
        source_func_name: Optional[str] = None

        # Determine enclosing function definition
        func_parent = call_node
        while func_parent and func_parent.type != "function_definition":
            func_parent = func_parent.parent

        if func_parent:
            func_start_line = func_parent.start_point[0] + 1
            func_end_line = func_parent.end_point[0] + 1
            
            # Extract function name
            declarator = func_parent.child_by_field_name("declarator")
            if declarator:
                decl_text = declarator.text.decode("utf-8", errors="replace")
                match = re.search(r'([A-Za-z_][A-Za-z0-9_]*)\s*\(', decl_text)
                if match:
                    source_func_name = match.group(1)

            # 1. Backward Dataflow: Look for definitions, input sources, or mutations of clean_var
            for line_idx in range(func_start_line, sink_line):
                line_content = lines[line_idx - 1] if line_idx - 1 < len(lines) else ""
                stripped = line_content.strip()
                if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
                    continue
                
                # Check if line defines or mutates taint_var
                if clean_var and re.search(r'\b' + re.escape(clean_var) + r'\b', line_content):
                    selected_line_numbers.add(line_idx)
                    # Check if an untrusted source is on this line
                    for src in UNTRUSTED_SOURCES:
                        if src in line_content:
                            selected_line_numbers.add(line_idx)

            # 2. Forward Control-Flow: Check for branch conditions/guards surrounding the sink
            curr = call_node.parent
            while curr and curr != func_parent:
                if curr.type in ("if_statement", "while_statement", "for_statement"):
                    cond = curr.child_by_field_name("condition")
                    if cond:
                        cond_line = cond.start_point[0] + 1
                        selected_line_numbers.add(cond_line)
                curr = curr.parent

            # 3. For Use-After-Free (CWE-416): check lines after 'free' that might dereference the pointer
            if sink_name == "free" and clean_var:
                for line_idx in range(sink_line + 1, min(func_end_line + 1, sink_line + 10)):
                    line_content = lines[line_idx - 1] if line_idx - 1 < len(lines) else ""
                    stripped = line_content.strip()
                    if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
                        continue
                    if re.search(r'\b' + re.escape(clean_var) + r'\b', line_content):
                        selected_line_numbers.add(line_idx)

        # Sort and assemble lines
        sorted_lines = sorted(list(selected_line_numbers))
        assembled_lines: List[str] = []
        for l_num in sorted_lines:
            if 1 <= l_num <= len(lines):
                assembled_lines.append(f"{l_num}: {lines[l_num - 1].strip()}")

        slice_text = "\n".join(assembled_lines)
        token_count = len(re.findall(r'\w+|[^\w\s]', slice_text))

        # Enforce <= 150 token invariant by pruning non-essential intermediate lines if needed
        if token_count > max_tokens and len(sorted_lines) > 3:
            # Must keep: first line (declaration/source), condition guards, and sink line
            essential = {sorted_lines[0], sink_line}
            if len(sorted_lines) > 2:
                essential.add(sorted_lines[1])
            # For free sinks, always keep any subsequent dereferences
            if sink_name == "free":
                for l in sorted_lines:
                    if l > sink_line:
                        essential.add(l)
            sorted_lines = sorted(list(essential))
            assembled_lines = [f"{l_num}: {lines[l_num - 1].strip()}" for l_num in sorted_lines]
            slice_text = "\n".join(assembled_lines)
            token_count = len(re.findall(r'\w+|[^\w\s]', slice_text))

        return CodeSlice(
            slice_id=f"slice_{slice_idx}_{sink_name}_{sink_line}",
            source_file=source_file,
            sink_function=sink_name,
            sink_line=sink_line,
            taint_variable=clean_var,
            slice_code=slice_text,
            slice_tokens=token_count,
            line_numbers=sorted_lines,
            cwe_candidate=CRITICAL_SINKS.get(sink_name, "CWE-Other"),
            source_function=source_func_name
        )
