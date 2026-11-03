# Hash-pinned release toolchains

These `*.txt` files are `--require-hashes` lockfiles for everything the release
workflow installs with `pip`. Pinning by hash satisfies the OpenSSF Scorecard
**Pinned-Dependencies** check and stops a compromised package index from
substituting the build backend, the metadata checker or the SBOM generator.

| File | Contents | Used by |
|---|---|---|
| `release-build.txt` | pip, build, hatchling | `publish.yml` (build) |
| `twine.txt` | twine | `publish.yml` (metadata check) |
| `cyclonedx.txt` | cyclonedx-bom | `publish.yml` (SBOM) |
| `runtime.txt` | the package's runtime dependencies | `publish.yml` (runtime environment the SBOM describes) |

## Regenerate

```bash
cd .github/constraints
for base in release-build twine cyclonedx; do
  uv pip compile --generate-hashes --universal --python-version 3.11 \
    --annotation-style=line "$base.in" -o "$base.txt"
done
uv pip compile --generate-hashes --universal --python-version 3.11 \
  --annotation-style=line ../../pyproject.toml -o runtime.txt
```

Add `--upgrade` to move existing pins to the newest allowed versions (without
it, uv keeps the pins already in the output file). Re-run the `runtime.txt` line
whenever `[project] dependencies` in `pyproject.toml` changes.

Bump a tool by editing the matching `*.in` and re-running the loop. Keep the
hatchling range in `release-build.in` in step with `[build-system] requires` in
`pyproject.toml`.
