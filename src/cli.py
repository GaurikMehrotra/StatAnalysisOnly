"""Command-line interface for the Malware Analysis Agent."""

import json
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

import typer

from src.analyzers.import_analyzer import (
    ImportAnalysisError,
    analyze_imports_exports,
)
from src.analyzers.pe_analyzer import PEAnalysisError, analyze_pe
from src.analyzers.section_analyzer import analyze_sections
from src.analyzers.string_analyzer import StringAnalysisError, analyze_strings
from src.detection.ioc_extractor import IOCExtractionError, extract_iocs
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
        help="Path to the Windows executable to inspect.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Optional JSON output file. Existing files are not overwritten.",
    ),
    max_size_mib: int = typer.Option(
        DEFAULT_MAX_FILE_SIZE // (1024 * 1024),
        "--max-size-mib",
        min=1,
        help="Maximum accepted input size in MiB.",
    ),
) -> None:
    """Validate an input, parse PE metadata, and report the results."""
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

    report = {
        "tool": {
            "name": "malware-analysis-agent",
            "version": get_tool_version(),
        },
        "status": "static_analysis_completed",
        "input": identity_to_dict(identity),
        "pe_metadata": pe_metadata,
        "section_analysis": section_analysis,
        "import_analysis": import_analysis,
        "string_analysis": string_analysis,
        "ioc_analysis": ioc_analysis,
        "warnings": [
            "PE metadata is static evidence, not proof of malicious behavior.",
            "PE timestamps are untrusted and may be forged.",
            "Import names are static evidence and do not prove runtime behavior.",
            (
                "Extracted strings and IOCs are static indicators, "
                "not proof of maliciousness."
            ),
            "Section entropy is a heuristic, not proof of maliciousness.",
            "Passing static analysis does not establish that a file is safe.",
        ],
    }

    rendered = json.dumps(report, indent=2, sort_keys=True)

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

    typer.echo(f"JSON report written to: {destination}")


if __name__ == "__main__":
    app()
