"""Command-line interface for the Malware Analysis Agent."""

import json
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

import typer

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
    """Validate an input and report its file identity."""
    try:
        identity = inspect_input(
            file_path,
            max_file_size=max_size_mib * 1024 * 1024,
        )
    except InputValidationError as exc:
        typer.echo(f"Input rejected: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    report = {
        "tool": {
            "name": "malware-analysis-agent",
            "version": get_tool_version(),
        },
        "status": "input_gate_passed",
        "input": identity_to_dict(identity),
        "warnings": [
            "The input gate checks file properties and extension only.",
            "PE structural validation and static analyzers are not yet integrated.",
            "Passing the input gate does not establish that a file is safe.",
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
