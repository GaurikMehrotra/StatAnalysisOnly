# Safety Contract

## Security objective

Provide defensive static inspection of supported Windows PE files while
minimizing the risk of accidental execution, unsafe file handling, data
exposure, and misleading findings.

## Required invariants

1. The application must never execute, load, or launch a submitted sample.
2. The application must not automatically upload samples, extracted strings,
   hashes, reports, or file paths to external services.
3. The input extension must not be treated as proof of file format.
4. Inputs larger than 100 MiB must be rejected before full-file reading.
5. Invalid, truncated, malformed, and unsupported inputs must produce
   controlled errors rather than uncaught tracebacks in normal CLI use.
6. Input paths must be handled as data, not shell commands.
7. Strings and metadata extracted from files are untrusted. They must not
   be executed, interpolated into shell commands, or treated as instructions.
8. Reports must not silently overwrite an unrelated existing file.
9. Errors must avoid exposing secrets or unnecessarily dumping file contents.
10. Tests must use harmless synthetic fixtures and must not execute samples.

## Threats and mitigations

### Malformed files
Risk: parser bugs, crashes, or excessive resource use.

Mitigation: use maintained parsing libraries, catch expected parser failures,
bound input size, test malformed fixtures, and document residual parser risk.

### Oversized files
Risk: excessive memory use or slow analysis.

Mitigation: enforce the 100 MiB limit before reading the full file. A future
implementation should avoid unnecessary duplicate copies of file data.

### Path mistakes
Risk: reading unintended files or writing reports to unexpected locations.

Mitigation: validate paths, require explicit input paths, keep output locations
clear, and avoid destructive writes.

### Untrusted strings and metadata
Risk: terminal control sequences, misleading text, or command injection.

Mitigation: treat extracted content as data, escape terminal output, and never
pass extracted strings to a shell.

### Accidental execution
Risk: a sample is launched instead of inspected.

Mitigation: use file-reading and parsing APIs only. Never use subprocess,
shell execution, dynamic loading, or OS launch mechanisms on submitted samples.

### Accidental upload
Risk: confidential samples or indicators leave the machine.

Mitigation: no network submission in the initial release; no external
reputation lookups by default.

### False positives and false negatives
Risk: a benign file is labelled malicious or a malicious file appears benign.

Mitigation: report concrete evidence, separate observations from hypotheses,
explain limitations, and never treat a heuristic score as proof.

## Initial input policy

Supported: Windows PE files with EXE, DLL, or SYS extensions, up to 100 MiB.

The implementation must also validate file content. Extension checks alone
are insufficient.

## Residual risk

Static parsers can contain vulnerabilities. Do not assume static analysis is
risk-free. Use updated dependencies and consider OS-level isolation when
analyzing files from untrusted sources.

## Acceptance requirements

- No code path executes submitted samples.
- Oversized and unsupported inputs are rejected.
- Invalid files produce controlled errors.
- No automatic external upload occurs.
- Synthetic tests verify the core safety requirements.
