# govulncheckignore

A lightweight CLI tool for filtering Go vulnerability findings reported by [`govulncheck`](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck).

`govulncheckignore` lets you explicitly ignore known vulnerabilities by Go vulnerability ID (`GO-...`) or CVE ID (`CVE-...`), while preserving a non-zero exit status for other reachable vulnerabilities.

Designed for CI/CD pipelines where selected vulnerabilities have been reviewed and accepted.

## Features

- Ignore vulnerabilities by `GO-...` or `CVE-...` identifiers.
- Support for a `.govulncheckignore` file.
- Repeatable `--ignore` CLI flags.
- Automatic matching against OSV vulnerability aliases.
- Distinguish reachable vulnerabilities from informational findings.
- Deterministic, sorted output.
- CI-friendly exit codes.
- No runtime dependencies.

## Installation

Install the latest version using Go:

```bash
go install github.com/pixel365/govulncheckignore@latest
```

Or install a specific release:

```bash
go install github.com/pixel365/govulncheckignore@v1.0.0
```

Prebuilt binaries for Linux, macOS, and Windows (amd64 and arm64) are available on the [Releases](https://github.com/pixel365/govulncheckignore/releases) page.

## Usage

Run `govulncheck` in JSON mode and pipe its output to `govulncheckignore`:

```bash
set -o pipefail

govulncheck -json ./... | govulncheckignore
```

> **Important:** Enable `pipefail` when using shell pipelines to ensure failures from `govulncheck` are not hidden by the exit status of the filtering tool.

### Ignore a vulnerability

Specify a vulnerability ID using `--ignore`:

```bash
govulncheck -json ./... | govulncheckignore --ignore GO-2026-1234
```

Multiple IDs can be specified:

```bash
govulncheck -json ./... | govulncheckignore \
  --ignore GO-2026-1234 \
  --ignore CVE-2026-12345
```

Identifiers are case-insensitive, and surrounding whitespace is ignored.

### Use an ignore file

Create a `.govulncheckignore` file in your project root:

```text
# Accepted vulnerabilities

GO-2026-1234  # Reviewed and accepted
CVE-2026-12345
```

Then run:

```bash
govulncheck -json ./... | govulncheckignore
```

If `.govulncheckignore` exists in the current working directory, it is loaded automatically.

Specify a custom file with:

```bash
govulncheck -json ./... | govulncheckignore \
  --ignore-file config/vulnerabilities.ignore
```

CLI `--ignore` flags and entries from the ignore file are combined.

### Match CVE aliases

A single vulnerability may be identified by a Go vulnerability ID and one or more CVE aliases.

For example, if `govulncheck` reports a vulnerability as `GO-2026-1234` with alias `CVE-2026-12345`, either identifier can be used to ignore it.

The resulting output uses the primary OSV vulnerability ID.

## How it works

`govulncheckignore` reads the JSON output of `govulncheck` from standard input and processes its OSV records and vulnerability findings.

Findings are classified into three levels:

| Level     | Meaning                                                         | Blocks CI |
| --------- | --------------------------------------------------------------- | --------- |
| `module`  | A vulnerable module was detected                                | No        |
| `package` | A vulnerable package was detected                               | No        |
| `called`  | A vulnerable function is reachable according to static analysis | Yes       |

When multiple findings reference the same vulnerability, the highest detected level is used.

Ignored vulnerabilities do not block the pipeline, regardless of their finding level.

**Example output:**

```text
SKIPPED  GO-2026-1234
FOUND    GO-2026-2345 (called)
INFO     GO-2026-3456 (package)

Summary: 1 found, 1 ignored, 1 informational
```

- `SKIPPED`: a vulnerability matched an ignore rule.
- `FOUND`: a non-ignored, reachable vulnerability.
- `INFO`: a non-ignored vulnerability without a reachable vulnerable function.

A `called` finding indicates that static analysis found a call path to a vulnerable symbol. It does not necessarily mean the vulnerability is exploitable in the application's runtime environment.

## Exit codes

| Code | Description                                                                |
| ---- | -------------------------------------------------------------------------- |
| `0`  | No non-ignored reachable vulnerabilities were found                        |
| `1`  | One or more non-ignored reachable vulnerabilities were found               |
| `2`  | Invalid input, unsupported scan configuration, or another processing error |

Only `called` findings cause exit code `1`.

Informational findings are reported without failing the pipeline.

## CI/CD integration

### GitHub Actions

Example step:

```yaml
- name: Scan for vulnerabilities
  shell: bash
  run: |
    set -euo pipefail
    govulncheck -json ./... | govulncheckignore
```

Both tools must be installed before this step executes.

Store reviewed exceptions in `.govulncheckignore` and commit the file alongside your project.

**Recommendation:** Document why each vulnerability is ignored and review exceptions periodically. An ignored vulnerability remains ignored even if later scans classify it as reachable.

## Command-line options

| Flag                 | Description                                        |
| -------------------- | -------------------------------------------------- |
| `--ignore ID`        | Ignore a vulnerability by GO or CVE ID; repeatable |
| `--ignore-file PATH` | Read vulnerability IDs from a specified file       |
| `--version`          | Print version, commit, and build date              |
| `--help`             | Display command-line help                          |

The default ignore file is `.govulncheckignore` in the current working directory, if present.

An explicitly specified ignore file must exist and be readable.

## Supported input

`govulncheckignore` accepts the newline-delimited JSON output produced by:

```bash
govulncheck -json ./...
```

The following scan configuration is supported:

| Field              | Required value |
| ------------------ | -------------- |
| `protocol_version` | `v1.0.0`       |
| `scan_mode`        | `source`       |
| `scan_level`       | `symbol`       |

Other protocol versions, scan modes, and scan levels are rejected.

The tool reads standard input; it does not execute `govulncheck` itself.

## Security considerations

Ignoring a vulnerability does not fix it.

Use ignore rules only for vulnerabilities that have been assessed and explicitly accepted. An ignored ID suppresses blocking for all findings associated with that vulnerability, including future reachable findings.

For reliable CI results, always check the exit status of the upstream `govulncheck` command using `pipefail` or equivalent pipeline error handling.

## License

See [LICENSE](LICENSE) for details.
