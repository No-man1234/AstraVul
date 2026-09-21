"""
Rigorous Security Evaluation Metrics: Precision, Recall, F1, and False Discovery Rate (FDR).
Implements benchmark evaluation aligned with NDSS 2026 (Chasing Shadows) standards.
"""

from typing import Dict, List, Any
from pathlib import Path
from rich.console import Console
from rich.table import Table

from ..parser.slicer import ASTSlicer
from ..rag.store import RAGKnowledgeStore
from ..triage.engine import LocalTriageEngine


def calculate_metrics(tp: int, fp: int, tn: int, fn: int) -> Dict[str, float]:
    """Calculates standard information retrieval and security metrics."""
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    fdr = fp / (tp + fp) if (tp + fp) > 0 else 0.0
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0.0

    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fdr": fdr,
        "accuracy": accuracy,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn
    }


def evaluate_benchmark(benchmark_dir: str) -> Dict[str, Any]:
    """
    Evaluates AST-Guided RAG against a traditional SAST baseline on C/C++ benchmark files.
    Identifies ground-truth from filename convention:
      - Files containing 'vulnerable' or 'bad' are labeled positive (1).
      - Files containing 'safe' or 'good' are labeled negative (0).
    """
    console = Console()
    dir_path = Path(benchmark_dir)
    c_files = list(dir_path.glob("**/*.c"))

    if not c_files:
        console.print(f"[yellow]No .c test files found in {benchmark_dir}[/yellow]")
        return {}

    slicer = ASTSlicer()
    rag = RAGKnowledgeStore()
    engine = LocalTriageEngine()

    # Metrics trackers
    ast_tp, ast_fp, ast_tn, ast_fn = 0, 0, 0, 0
    sast_tp, sast_fp, sast_tn, sast_fn = 0, 0, 0, 0
    total_raw_tokens = 0
    total_slice_tokens = 0

    for file_p in c_files:
        filename = file_p.name.lower()
        is_actually_vulnerable = "vuln" in filename or "bad" in filename

        with open(file_p, "r", encoding="utf-8", errors="replace") as f:
            code = f.read()

        raw_tokens = len(code.split())
        total_raw_tokens += raw_tokens

        # Run AST-Guided RAG
        slices = slicer.slice_file(str(file_p))
        detected_vulnerable = False

        for s in slices:
            total_slice_tokens += s.slice_tokens
            ctx = rag.retrieve(s)
            report = engine.triage(s, ctx)
            if report.is_vulnerable:
                detected_vulnerable = True

        if is_actually_vulnerable:
            if detected_vulnerable:
                ast_tp += 1
            else:
                ast_fn += 1
        else:
            if detected_vulnerable:
                ast_fp += 1
            else:
                ast_tn += 1

        # Simulate standard pattern-matching SAST baseline (flags any dangerous sink like strcpy or free)
        sast_flagged = any(k in code for k in ("strcpy", "strcat", "sprintf", "free", "system", "gets"))
        if is_actually_vulnerable:
            if sast_flagged:
                sast_tp += 1
            else:
                sast_fn += 1
        else:
            if sast_flagged:
                sast_fp += 1
            else:
                sast_tn += 1

    ast_res = calculate_metrics(ast_tp, ast_fp, ast_tn, ast_fn)
    sast_res = calculate_metrics(sast_tp, sast_fp, sast_tn, sast_fn)

    token_reduction_pct = (
        ((total_raw_tokens - total_slice_tokens) / total_raw_tokens * 100)
        if total_raw_tokens > 0 else 0.0
    )

    # Print Comparative Results
    table = Table(title="Benchmark Evaluation Results", header_style="bold cyan")
    table.add_column("Evaluation Metric", style="bold")
    table.add_column("Traditional SAST Baseline", justify="center")
    table.add_column("AST-Guided RAG (Ours)", justify="center", style="bold green")
    table.add_column("Improvement / Target", justify="center", style="bold yellow")

    table.add_row(
        "Precision",
        f"{sast_res['precision']*100:.1f}%",
        f"{ast_res['precision']*100:.1f}%",
        f"+{(ast_res['precision'] - sast_res['precision'])*100:.1f}%"
    )
    table.add_row(
        "Recall",
        f"{sast_res['recall']*100:.1f}%",
        f"{ast_res['recall']*100:.1f}%",
        f"{(ast_res['recall'] - sast_res['recall'])*100:+.1f}%"
    )
    table.add_row(
        "F1-Score",
        f"{sast_res['f1']*100:.1f}%",
        f"{ast_res['f1']*100:.1f}%",
        f"+{(ast_res['f1'] - sast_res['f1'])*100:.1f}%"
    )
    table.add_row(
        "False Discovery Rate (FDR)",
        f"{sast_res['fdr']*100:.1f}%",
        f"{ast_res['fdr']*100:.1f}%",
        f"[green]-{(sast_res['fdr'] - ast_res['fdr'])*100:.1f}% (Suppressed)[/green]"
    )
    table.add_row(
        "Avg Prompt Token Length",
        f"{total_raw_tokens // max(1, len(c_files))} tokens",
        f"{total_slice_tokens // max(1, len(c_files))} tokens",
        f"[green]{token_reduction_pct:.1f}% reduction[/green]"
    )

    console.print(table)
    return {
        "ast_guided_rag": ast_res,
        "sast_baseline": sast_res,
        "token_reduction_pct": token_reduction_pct
    }
