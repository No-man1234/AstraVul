"""
Live Test Suite Benchmarking Harness for NIST Juliet v1.3 and DiverseVul.
Enables evaluating AstraVul against raw, uncurated test cases directly from
NIST SAMATE / Juliet repositories or real DiverseVul JSON dataset dumps.
"""

import os
import sys
import json
import re
import tempfile
import urllib.request
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from ..parser.slicer import ASTSlicer
from ..rag.store import RAGKnowledgeStore
from ..triage.engine import LocalTriageEngine
from .benchmark_runner import run_flawfinder_on_file
from .metrics import calculate_metrics

console = Console()

# GitHub raw base URL for NIST Juliet Test Suite v1.3 (C)
JULIET_API_BASE = "https://api.github.com/repos/arichardson/juliet-test-suite-c/contents/testcases"
JULIET_RAW_BASE = "https://raw.githubusercontent.com/arichardson/juliet-test-suite-c/master/testcases"


def split_juliet_source(content: str) -> Tuple[str, str]:
    """
    Separates a raw Juliet test case into pure vulnerable (bad) and safe (good) files
    according to NIST SAMATE OMITBAD / OMITGOOD macro semantics.
    """
    bad_lines = []
    good_lines = []
    is_in_bad = False
    is_in_good = False

    for line in content.splitlines():
        if "#ifndef OMITBAD" in line or "#ifdef INCLUDEMAIN" in line and "bad" in line:
            is_in_bad = True
            continue
        elif "#endif /* OMITBAD */" in line:
            is_in_bad = False
            continue
        elif "#ifndef OMITGOOD" in line:
            is_in_good = True
            continue
        elif "#endif /* OMITGOOD */" in line:
            is_in_good = False
            continue

        if not is_in_bad and not is_in_good:
            bad_lines.append(line)
            good_lines.append(line)
        elif is_in_bad:
            bad_lines.append(line)
        elif is_in_good:
            good_lines.append(line)

    bad_src = "\n".join(bad_lines)
    good_src = "\n".join(good_lines)
    return bad_src, good_src


def fetch_juliet_file_list(cwe_dir: str = "CWE121_Stack_Based_Buffer_Overflow/s04", limit: int = 20) -> List[Dict[str, str]]:
    """Fetches a list of real C test cases from GitHub for a Juliet CWE category."""
    url = f"{JULIET_API_BASE}/{cwe_dir}"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (AstraVul-Benchmark-Runner)"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        c_files = [item for item in data if item["name"].endswith(".c") and not item["name"].endswith(".tmpl.c")]
        return c_files[:limit]
    except Exception as e:
        console.print(f"[red]Error fetching Juliet manifest from GitHub: {e}[/red]")
        return []


def download_file(download_url: str, local_path: Path) -> str:
    """Downloads a raw file if not already cached locally."""
    if local_path.exists():
        with open(local_path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()

    local_path.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(download_url, headers={"User-Agent": "Mozilla/5.0 (AstraVul-Benchmark-Runner)"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        content = resp.read().decode("utf-8", errors="replace")
    with open(local_path, "w", encoding="utf-8") as f:
        f.write(content)
    return content


def run_real_juliet_benchmark(
    count: int = 20,
    cwe: str = "CWE121",
    local_dir: Optional[str] = None,
    model_path: Optional[str] = None
) -> Dict[str, Any]:
    """
    Executes real, uncurated benchmarking on NIST Juliet Test Suite v1.3 test cases.
    Automatically evaluates both vulnerable and safe variants of each testcase.
    """
    cwe_map = {
        "CWE121": "CWE121_Stack_Based_Buffer_Overflow/s04",
        "CWE122": "CWE122_Heap_Based_Buffer_Overflow/s01",
        "CWE134": "CWE134_Uncontrolled_Format_String/s01",
    }
    cwe_target = cwe_map.get(cwe.upper(), "CWE121_Stack_Based_Buffer_Overflow/s04")

    console.print(Panel.fit(
        f"[bold cyan]NIST Juliet v1.3 Real-World Benchmark Runner[/bold cyan]\n"
        f"Evaluating [bold]{count}[/bold] uncurated test files ({count * 2} bad/good paired instances)\n"
        f"Target Suite: [green]{cwe_target}[/green]\n"
        f"Comparison: [bold]Flawfinder v2.0.20[/bold] vs. [bold green]AstraVul[/bold green]",
        border_style="cyan"
    ))

    # Determine files to evaluate
    cache_dir = Path("data/benchmarks/juliet_cache") / cwe.upper()
    cache_dir.mkdir(parents=True, exist_ok=True)

    files_to_eval: List[Tuple[str, str]] = [] # (file_name, file_content)

    if local_dir and Path(local_dir).exists():
        found = list(Path(local_dir).glob("**/*.c"))[:count]
        for p in found:
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                files_to_eval.append((p.name, f.read()))
    else:
        with console.status("[cyan]Fetching test case manifest from NIST Juliet repository..."):
            file_manifest = fetch_juliet_file_list(cwe_target, limit=count)
        if not file_manifest:
            console.print("[yellow]Could not retrieve remote files. Using cached local benchmark files.[/yellow]")
            return {}

        with console.status(f"[cyan]Downloading {len(file_manifest)} real Juliet files..."):
            for item in file_manifest:
                local_p = cache_dir / item["name"]
                content = download_file(item["download_url"], local_p)
                files_to_eval.append((item["name"], content))

    slicer = ASTSlicer()
    rag = RAGKnowledgeStore()
    engine = LocalTriageEngine(model_path=model_path)

    ast_metrics = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    sast_metrics = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    eval_log = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Evaluating real testcases...", total=len(files_to_eval) * 2)

        for filename, raw_content in files_to_eval:
            bad_src, good_src = split_juliet_source(raw_content)

            # Test 1: Vulnerable Instance (Ground Truth = True)
            with tempfile.NamedTemporaryFile(suffix="_bad.c", delete=False, mode="w", encoding="utf-8") as f:
                f.write(bad_src)
                bad_temp = f.name

            sast_bad = run_flawfinder_on_file(bad_temp)
            ast_bad_slices = slicer.slice_code(bad_src, source_file=f"{filename}__bad.c")
            ast_bad = any(engine.triage(s, rag.retrieve(s)).is_vulnerable for s in ast_bad_slices)
            os.unlink(bad_temp)

            # Record metrics for bad
            if sast_bad: sast_metrics["tp"] += 1
            else: sast_metrics["fn"] += 1

            if ast_bad: ast_metrics["tp"] += 1
            else: ast_metrics["fn"] += 1

            eval_log.append({
                "case": f"{filename[:35]}... (BAD)",
                "actual": "Vulnerable",
                "sast": "FLAGGED" if sast_bad else "PASS",
                "ast": "FLAGGED" if ast_bad else "PASS"
            })
            progress.advance(task)

            # Test 2: Safe Instance (Ground Truth = False)
            with tempfile.NamedTemporaryFile(suffix="_good.c", delete=False, mode="w", encoding="utf-8") as f:
                f.write(good_src)
                good_temp = f.name

            sast_good = run_flawfinder_on_file(good_temp)
            ast_good_slices = slicer.slice_code(good_src, source_file=f"{filename}__good.c")
            ast_good = any(engine.triage(s, rag.retrieve(s)).is_vulnerable for s in ast_good_slices)
            os.unlink(good_temp)

            # Record metrics for good
            if sast_good: sast_metrics["fp"] += 1
            else: sast_metrics["tn"] += 1

            if ast_good: ast_metrics["fp"] += 1
            else: ast_metrics["tn"] += 1

            eval_log.append({
                "case": f"{filename[:35]}... (GOOD)",
                "actual": "Safe",
                "sast": "FLAGGED (FP)" if sast_good else "PASS (TN)",
                "ast": "FLAGGED (FP)" if ast_good else "PASS (TN)"
            })
            progress.advance(task)

    # Compute Statistics
    sast_scores = calculate_metrics(sast_metrics["tp"], sast_metrics["fp"], sast_metrics["tn"], sast_metrics["fn"])
    ast_scores = calculate_metrics(ast_metrics["tp"], ast_metrics["fp"], ast_metrics["tn"], ast_metrics["fn"])

    # Render Summary Table
    table = Table(title=f"Live Uncurated Benchmark Results: NIST Juliet v1.3 ({len(files_to_eval) * 2} instances)", show_header=True)
    table.add_column("System / Tool", style="bold", width=25)
    table.add_column("TP", justify="center")
    table.add_column("FP", justify="center")
    table.add_column("TN", justify="center")
    table.add_column("FN", justify="center")
    table.add_column("Precision", justify="right")
    table.add_column("Recall", justify="right")
    table.add_column("F1-Score", justify="right")
    table.add_column("FDR (False Alarms)", justify="right", style="bold")

    table.add_row(
        "Flawfinder v2.0.20 (SAST)",
        str(sast_metrics["tp"]),
        str(sast_metrics["fp"]),
        str(sast_metrics["tn"]),
        str(sast_metrics["fn"]),
        f"{sast_scores['precision'] * 100:.1f}%",
        f"{sast_scores['recall'] * 100:.1f}%",
        f"{sast_scores['f1'] * 100:.1f}%",
        f"{sast_scores['fdr'] * 100:.1f}%"
    )

    fdr_color = "green" if ast_scores['fdr'] < sast_scores['fdr'] else "yellow"
    table.add_row(
        "AstraVul (AST-Guided RAG)",
        str(ast_metrics["tp"]),
        str(ast_metrics["fp"]),
        str(ast_metrics["tn"]),
        str(ast_metrics["fn"]),
        f"{ast_scores['precision'] * 100:.1f}%",
        f"{ast_scores['recall'] * 100:.1f}%",
        f"{ast_scores['f1'] * 100:.1f}%",
        f"[{fdr_color}]{ast_scores['fdr'] * 100:.1f}%[/{fdr_color}]"
    )

    console.print(table)
    return {"sast": sast_scores, "ast": ast_scores}


def run_diversevul_benchmark(
    json_path: str,
    samples: int = 50,
    model_path: Optional[str] = None
) -> Dict[str, Any]:
    """
    Executes real benchmarking on an external DiverseVul JSON export.
    Iterates over uncurated real-world Git commit functions.
    """
    p = Path(json_path)
    if not p.exists():
        console.print(f"[red]DiverseVul JSON file not found at: {json_path}[/red]")
        console.print("[dim]Download the dataset from https://github.com/wagner-group/diversevul[/dim]")
        return {}

    console.print(Panel.fit(
        f"[bold cyan]DiverseVul Real-World Benchmark Runner[/bold cyan]\n"
        f"Evaluating [bold]{samples}[/bold] uncurated real-world C/C++ functions from {p.name}\n"
        f"Comparison: [bold]Flawfinder v2.0.20[/bold] vs. [bold green]AstraVul[/bold green]",
        border_style="cyan"
    ))

    slicer = ASTSlicer()
    rag = RAGKnowledgeStore()
    engine = LocalTriageEngine(model_path=model_path)

    ast_metrics = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    sast_metrics = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}

    evaluated = 0
    with open(p, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if evaluated >= samples:
                break
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line) if line.startswith("{") else None
                if not record and line.endswith("}"):
                    record = json.loads(line)
            except Exception:
                continue

            if not record or "func" not in record or "target" not in record:
                continue

            func_code = record["func"]
            is_vuln_actual = bool(record["target"] == 1)

            # Flawfinder evaluation via temp file
            with tempfile.NamedTemporaryFile(suffix=".c", delete=False, mode="w", encoding="utf-8") as tf:
                tf.write(func_code)
                tf_name = tf.name

            sast_flagged = run_flawfinder_on_file(tf_name)
            os.unlink(tf_name)

            # AstraVul evaluation
            slices = slicer.slice_code(func_code, source_file=f"sample_{evaluated}.c")
            ast_flagged = any(engine.triage(s, rag.retrieve(s)).is_vulnerable for s in slices)

            # Accumulate metrics
            if is_vuln_actual:
                if sast_flagged: sast_metrics["tp"] += 1
                else: sast_metrics["fn"] += 1
                if ast_flagged: ast_metrics["tp"] += 1
                else: ast_metrics["fn"] += 1
            else:
                if sast_flagged: sast_metrics["fp"] += 1
                else: sast_metrics["tn"] += 1
                if ast_flagged: ast_metrics["fp"] += 1
                else: ast_metrics["tn"] += 1

            evaluated += 1

    sast_scores = calculate_metrics(sast_metrics["tp"], sast_metrics["fp"], sast_metrics["tn"], sast_metrics["fn"])
    ast_scores = calculate_metrics(ast_metrics["tp"], ast_metrics["fp"], ast_metrics["tn"], ast_metrics["fn"])

    table = Table(title=f"Live DiverseVul Benchmark Results ({evaluated} functions)", show_header=True)
    table.add_column("System / Tool", style="bold", width=25)
    table.add_column("TP", justify="center")
    table.add_column("FP", justify="center")
    table.add_column("TN", justify="center")
    table.add_column("FN", justify="center")
    table.add_column("Precision", justify="right")
    table.add_column("Recall", justify="right")
    table.add_column("F1-Score", justify="right")
    table.add_column("FDR (False Alarms)", justify="right", style="bold")

    table.add_row(
        "Flawfinder v2.0.20 (SAST)",
        str(sast_metrics["tp"]),
        str(sast_metrics["fp"]),
        str(sast_metrics["tn"]),
        str(sast_metrics["fn"]),
        f"{sast_scores['precision'] * 100:.1f}%",
        f"{sast_scores['recall'] * 100:.1f}%",
        f"{sast_scores['f1'] * 100:.1f}%",
        f"{sast_scores['fdr'] * 100:.1f}%"
    )

    table.add_row(
        "AstraVul (AST-Guided RAG)",
        str(ast_metrics["tp"]),
        str(ast_metrics["fp"]),
        str(ast_metrics["tn"]),
        str(ast_metrics["fn"]),
        f"{ast_scores['precision'] * 100:.1f}%",
        f"{ast_scores['recall'] * 100:.1f}%",
        f"{ast_scores['f1'] * 100:.1f}%",
        f"{ast_scores['fdr'] * 100:.1f}%"
    )

    console.print(table)
    return {"sast": sast_scores, "ast": ast_scores}
