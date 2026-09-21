"""
Command Line Interface for AST-Guided RAG Vulnerability Triage.
Provides 'scan', 'index', and 'evaluate' commands with rich terminal formatting.
"""

import os
import sys
import json
from pathlib import Path
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax

if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    __package__ = "src"

from .parser.slicer import ASTSlicer
from .rag.store import RAGKnowledgeStore
from .triage.engine import LocalTriageEngine
from .triage.schemas import VulnerabilityTriageReport, ExploitabilityVerdict

console = Console()


@click.group()
@click.version_option(version="1.0.0")
def cli() -> None:
    """AST-Guided RAG Software Vulnerability Detection & Triage."""
    pass


@cli.command()
@click.argument("target", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), default=None, help="Save JSON report to file.")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table", help="Output format.")
@click.option("--model", "-m", type=click.Path(), default=None, help="Path to local GGUF model weights.")
@click.option("--verbose", "-v", is_flag=True, help="Display detailed slice and prompt information.")
def scan(target: str, output: str | None, fmt: str, model: str | None, verbose: bool) -> None:
    """Scans a C/C++ file or directory for exploitable vulnerabilities."""
    target_path = Path(target)
    files_to_scan = []

    if target_path.is_file():
        files_to_scan.append(target_path)
    else:
        for ext in ("*.c", "*.cpp", "*.cc", "*.h", "*.hpp"):
            files_to_scan.extend(target_path.glob(f"**/{ext}"))

    if not files_to_scan:
        console.print(f"[yellow]No C/C++ source files found in {target}[/yellow]")
        return

    console.print(Panel.fit(
        f"[bold cyan]AST-Guided RAG Vulnerability Scanner[/bold cyan]\n"
        f"Scanning [bold]{len(files_to_scan)}[/bold] file(s) in [dim]{target}[/dim]",
        border_style="cyan"
    ))

    slicer = ASTSlicer()
    rag = RAGKnowledgeStore()
    engine = LocalTriageEngine(model_path=model)

    all_reports: list[VulnerabilityTriageReport] = []

    for file_p in files_to_scan:
        try:
            slices = slicer.slice_file(str(file_p))
            for s in slices:
                ctx = rag.retrieve(s)
                report = engine.triage(s, ctx)
                all_reports.append(report)
                
                if verbose:
                    console.print(f"\n[bold green]Slice Extracted:[/bold green] {s.slice_id} ({s.slice_tokens} tokens)")
                    console.print(Syntax(s.slice_code, "c", line_numbers=True))
        except Exception as e:
            console.print(f"[red]Error analyzing {file_p}: {e}[/red]")

    # Output Formatting
    if fmt == "table":
        table = Table(title="Vulnerability Triage Summary", show_header=True, header_style="bold magenta")
        table.add_column("File", style="dim", width=20)
        table.add_column("Sink / Line", justify="center")
        table.add_column("CWE", justify="center")
        table.add_column("Verdict", justify="center")
        table.add_column("Confidence", justify="right")
        table.add_column("Root Cause", width=35)

        for rep in all_reports:
            verdict_color = "red" if rep.is_vulnerable else "green"
            sink_str = f"L{rep.vulnerable_lines[0] if rep.vulnerable_lines else '?'}"
            table.add_row(
                Path(rep.file_path).name,
                sink_str,
                rep.cwe_id,
                f"[{verdict_color}]{rep.exploitability_verdict.value}[/{verdict_color}]",
                f"{rep.confidence * 100:.1f}%",
                rep.root_cause_analysis
            )

        console.print(table)
        
        # Print Patch details for confirmed vulnerabilities
        for rep in all_reports:
            if rep.is_vulnerable and rep.remediation_patch:
                console.print(Panel(
                    Syntax(rep.remediation_patch, "diff"),
                    title=f"[bold green]Suggested Patch ({rep.cwe_id} at {Path(rep.file_path).name})[/bold green]",
                    border_style="green"
                ))
    else:
        json_output = json.dumps([r.model_dump() for r in all_reports], indent=2)
        if not output:
            print(json_output)

    if output:
        out_path = Path(output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump([r.model_dump() for r in all_reports], f, indent=2)
        console.print(f"\n[green]Saved report to {out_path}[/green]")


@cli.command()
@click.option("--full", is_flag=True, help="Download & index all 969 official MITRE CWEs and DiverseVul patches into ChromaDB.")
@click.option("--diversevul", type=click.Path(exists=True), default=None, help="Path to external DiverseVul JSON export.")
def index(full: bool, diversevul: str | None) -> None:
    """Builds and refreshes the persistent ChromaDB vector knowledge base."""
    console.print(Panel.fit(
        "[bold cyan]Vector Knowledge Base Ingestion (ChromaDB)[/bold cyan]\n"
        "Indexing NIST CWE Specifications & DiverseVul Contrastive CVE Patches",
        border_style="cyan"
    ))

    if full or diversevul:
        from .rag.ingest import run_full_ingestion
        with console.status("[bold green]Ingesting datasets into ChromaDB..."):
            stats = run_full_ingestion(external_diversevul_path=diversevul)
        console.print(f"[bold green]Successfully indexed {stats['cwe_catalog_count']} MITRE CWEs into 'cwe_catalog'[/bold green]")
        console.print(f"[bold green]Successfully indexed {stats['cve_patches_count']} security patches into 'cve_patches'[/bold green]")
    else:
        rag = RAGKnowledgeStore()
        if rag.cwe_collection:
            cwe_cnt = rag.cwe_collection.count()
            cve_cnt = rag.cve_collection.count() if rag.cve_collection else 0
            console.print(f"[green]ChromaDB is active with {cwe_cnt} indexed CWEs and {cve_cnt} CVE patches.[/green]")
        else:
            console.print(f"[green]Indexed {len(rag.cwe_kb)} NIST CWE specifications (in-memory mode).[/green]")
            console.print(f"[green]Indexed {len(rag.cve_patches)} paired CVE commit diffs.[/green]")
            console.print("[dim]Run 'python src/cli.py index --full' to download all 969 MITRE CWEs into ChromaDB.[/dim]")

    console.print("[bold green]Vector knowledge store ready![/bold green]")


@cli.command()
@click.option("--benchmark-dir", type=click.Path(exists=True), default="examples", help="Directory of test samples.")
@click.option("--full", is_flag=True, help="Execute full benchmark across NIST Juliet and DiverseVul test suites.")
@click.option("--model", "-m", type=click.Path(), default=None, help="Path to local GGUF model weights (optional).")
def evaluate(benchmark_dir: str, full: bool, model: str | None) -> None:
    """Evaluates Precision, Recall, F1, and FDR on benchmark samples."""
    if full or Path("data/benchmarks/ground_truth.json").exists():
        from .evaluation.benchmark_runner import run_full_benchmark
        run_full_benchmark("data/benchmarks/ground_truth.json", model_path=model)
    else:
        from .evaluation.metrics import evaluate_benchmark
        console.print(f"[cyan]Evaluating benchmarks in {benchmark_dir}...[/cyan]")
        evaluate_benchmark(benchmark_dir)


if __name__ == "__main__":
    cli()
