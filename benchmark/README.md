# Detection benchmark

Measures how many known issues of public vulnerable APIs VulnAPI detects, as an end-to-end regression suite.

```sh
go test -tags benchmark -count=1 -timeout 60m -v ./benchmark/...
```

Requires Docker, `curl` and `jq`. The targets in `compose.yaml` are started with Docker Compose; api-vulns-challenges is cloned at the commit pinned in `challenges/expected.yaml` (or set `CHALLENGES_DIR` to a checkout). The summary is written to `results/summary.md`.

| Variable | Effect |
|---|---|
| `BENCHMARK_TARGETS` | Comma-separated target directories to run, e.g. `vampi,dvga` |
| `BENCHMARK_DOCS=true` | Also regenerate `docs/*/benchmark.mdx` |
| `BENCHMARK_COMPOSE=false` | Use targets already running |
| `BENCHMARK_KEEP=true` | Leave the targets running after the run |
| `VULNAPI_BIN` | Scan with this binary instead of building the repository |
| `VULNAPI_VERSION` | Version shown in the summary |

## Manifests

`<target>/expected.yaml` lists the known issues of a target, per scan:

- `check`: the check ID expected to report it. The run fails when it is not reported.
- `notCovered`: no check covers it yet; links the issue tracking one.
- `knownMiss`: with `check`, the check misses it today; links the issue tracking the fix. The run logs when it becomes detected.

Findings with a CVSS score that no issue expects are counted as unexpected, to review as false-positive candidates. They do not fail the run.

Every new check adds a line to a manifest, or flips a `notCovered` line to `check`.
