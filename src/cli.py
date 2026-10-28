"""Command-line interface for the Malware Analysis Agent."""

import json
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

import typer

from src.ai.local_llm import (
    DEFAULT_BASE_URL,
    DEFAULT_MODEL,
    DEFAULT_TIMEOUT_SECONDS,
    explain_report,
)
from src.analyzers.import_analyzer import (
    ImportAnalysisError,
    analyze_imports_exports,
)
from src.analyzers.pe_analyzer import PEAnalysisError, analyze_pe
from src.analyzers.section_analyzer import analyze_sections
from src.analyzers.string_analyzer import StringAnalysisError, analyze_strings
from src.detection.attack_mapper import AttackMappingError, map_attack_candidates
from src.detection.capability_mapper import collect_evidence
from src.detection.evidence import EVIDENCE_SCHEMA_VERSION
from src.detection.ioc_extractor import IOCExtractionError, extract_iocs
from src.detection.rule_engine import RuleEngineError, evaluate_rules
from src.reporting import (
    ReportValidationError,
    render_json_report,
    render_markdown_report,
    validate_report,
)
from src.safety import (
    DEFAULT_MAX_FILE_SIZE,
    InputValidationError,
    identity_to_dict,
    inspect_input,
)

app = typer.Typer(
    name="malware-agent",
    help="Local-first defensive static analysis of Windows PE files.",
    no_args_is_help=True,
)


@app.callback()
def main() -> None:
    """Local-first defensive static analysis of Windows PE files."""


def get_tool_version() -> str:
    """Return the installed package version."""
    try:
        return version("malware-analysis-agent")
    except PackageNotFoundError:
        return "0.1.0"


@app.command()
def analyze(
    file_path: Path = typer.Argument(
        ...,
        help="Path to the Windows PE file to inspect.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Optional report output file. Existing files are not overwritten.",
    ),
    max_size_mib: int = typer.Option(
        DEFAULT_MAX_FILE_SIZE // (1024 * 1024),
        "--max-size-mib",
        min=1,
        help="Maximum accepted input size in MiB.",
    ),
    report_format: str = typer.Option(
        "json",
        "--format",
        help="Report format: json or markdown.",
        case_sensitive=False,
    ),
    explain: bool = typer.Option(
        False,
        "--explain",
        help="Add an optional evidence-bounded local AI explanation.",
    ),
    model: str = typer.Option(
        DEFAULT_MODEL,
        "--model",
        help="Local Ollama model name used with --explain.",
    ),
    model_url: str = typer.Option(
        DEFAULT_BASE_URL,
        "--model-url",
        help="Local Ollama base URL used with --explain.",
    ),
    ai_timeout: float = typer.Option(
        DEFAULT_TIMEOUT_SECONDS,
        "--ai-timeout",
        min=0.1,
        max=120.0,
        help="Local AI request timeout in seconds.",
    ),
) -> None:
    """Validate an input, parse PE metadata, and report the results."""
    report_format = report_format.lower()
    if report_format not in {"json", "markdown"}:
        typer.echo("Unsupported format: choose json or markdown.", err=True)
        raise typer.Exit(code=2)

    try:
        identity = inspect_input(
            file_path,
            max_file_size=max_size_mib * 1024 * 1024,
        )
    except InputValidationError as exc:
        typer.echo(f"Input rejected: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    try:
        pe_metadata = analyze_pe(
            file_path,
            max_file_size=max_size_mib * 1024 * 1024,
        )
    except PEAnalysisError as exc:
        typer.echo(f"PE analysis rejected: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    try:
        section_analysis = analyze_sections(
            file_path,
            max_file_size=max_size_mib * 1024 * 1024,
        )
    except PEAnalysisError as exc:
        typer.echo(f"Section analysis rejected: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    try:
        import_analysis = analyze_imports_exports(
            file_path,
            max_file_size=max_size_mib * 1024 * 1024,
        )
    except ImportAnalysisError as exc:
        typer.echo(f"Import/export analysis rejected: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    try:
        string_analysis = analyze_strings(
            file_path,
            max_file_size=max_size_mib * 1024 * 1024,
        )
    except StringAnalysisError as exc:
        typer.echo(f"String analysis rejected: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    try:
        ioc_analysis = extract_iocs(string_analysis["strings"])
    except IOCExtractionError as exc:
        typer.echo(f"IOC extraction rejected: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    input_identity = identity_to_dict(identity)

    try:
        evidence_records = collect_evidence(
            file_identity=input_identity,
            pe_metadata=pe_metadata,
            section_analysis=section_analysis,
            import_analysis=import_analysis,
            string_analysis=string_analysis,
            ioc_analysis=ioc_analysis,
        )
        triage = evaluate_rules(evidence_records)
    except (ValueError, RuleEngineError) as exc:
        typer.echo(f"Evidence/rule evaluation failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    evidence = [record.model_dump(mode="json") for record in evidence_records]

    findings = triage["findings"]

    try:
        attack_candidates = map_attack_candidates(findings, evidence)
    except AttackMappingError as exc:
        typer.echo(f"ATT&CK mapping failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    warnings = [
        "PE metadata is static evidence, not proof of malicious behavior.",
        "PE timestamps are untrusted and may be forged.",
        "Import names are static evidence and do not prove runtime behavior.",
        (
            "Extracted strings and IOCs are static indicators, "
            "not proof of maliciousness."
        ),
        "Section entropy is a heuristic, not proof of maliciousness.",
        "Passing static analysis does not establish that a file is safe.",
        *triage["warnings"],
    ]

    report = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "analysis_status": "completed",
        "file": {
            "name": input_identity["filename"],
            "size_bytes": input_identity["size_bytes"],
            "sha256": input_identity["sha256"],
            "format": pe_metadata.get("format", "unknown"),
        },
        "evidence": evidence,
        "findings": findings,
        "attack_candidates": attack_candidates,
        "triage": triage,
        "tool": {
            "name": "malware-analysis-agent",
            "version": get_tool_version(),
        },
        "status": "static_analysis_completed",
        "input": input_identity,
        "pe_metadata": pe_metadata,
        "section_analysis": section_analysis,
        "import_analysis": import_analysis,
        "string_analysis": string_analysis,
        "ioc_analysis": ioc_analysis,
        "warnings": warnings,
    }

    # AI is strictly opt-in and cannot modify deterministic analysis fields.
    if explain:
        report["ai_explanation"] = explain_report(
            report,
            model=model,
            base_url=model_url,
            timeout=ai_timeout,
        )

    try:
        # Both output formats must pass the canonical report schema first.
        validate_report(report)
        if report_format == "json":
            rendered = render_json_report(report)
        else:
            rendered = render_markdown_report(report)
    except ReportValidationError as exc:
        typer.echo(f"Report validation failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    if output is None:
        typer.echo(rendered)
        return

    destination = output.expanduser().resolve()
    source = Path(identity.path).resolve()

    if destination == source:
        typer.echo(
            "Output rejected: report destination cannot be the input file.",
            err=True,
        )
        raise typer.Exit(code=2)

    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        # Exclusive creation prevents overwriting an existing report.
        with destination.open("x", encoding="utf-8") as report_file:
            report_file.write(rendered + "\n")
    except FileExistsError as exc:
        typer.echo(
            f"Output rejected: destination already exists: {destination}",
            err=True,
        )
        raise typer.Exit(code=2) from exc
    except OSError as exc:
        typer.echo(f"Cannot write report: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    typer.echo(f"{report_format.upper()} report written to: {destination}")


@app.command("validate-report")
def validate_report_command(
    report_path: Path = typer.Argument(
        ...,
        help="Path to an existing JSON analysis report.",
    ),
) -> None:
    """Validate a JSON report against the canonical report schema."""
    try:
        resolved = report_path.expanduser().resolve()
        report = json.loads(resolved.read_text(encoding="utf-8"))
        if not isinstance(report, dict):
            raise ReportValidationError("Report root must be a JSON object.")
        validate_report(report)
    except (OSError, json.JSONDecodeError) as exc:
        typer.echo(f"Cannot read JSON report: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    except ReportValidationError as exc:
        typer.echo(f"Report validation failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    typer.echo(f"Report is valid: {resolved}")


if __name__ == "__main__":
    app()
